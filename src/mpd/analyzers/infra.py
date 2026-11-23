"""IoC extraction and known-abuse-infrastructure detection.

Two jobs:
  1. Record every external URL / host / IP in code as an IoC so that campaigns can later be
     clustered by shared attacker infrastructure (see campaigns.py).
  2. Flag infrastructure that is overwhelmingly used for exfiltration and staging:
     chat webhooks, out-of-band interaction (OAST) domains, tunnels, anonymous drop sites.

We deliberately do NOT treat "unknown domain" as suspicious by itself: almost every
package talks to some domain. Only infrastructure with a known abuse profile is scored, and
the abuse patterns are matched against extracted URLs, not raw text, so prose that merely
mentions a service ("transfer.sh" in a docstring) does not count.
"""

from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlsplit

from ..models import Severity as S
from .base import ScanContext

URL_RE = re.compile(r"""(?i)\b(?:https?|ftp|wss?)://[^\s'"<>`\\)\]},;|]+""")
QUOTED_IPV4 = re.compile(
    r"""["']((?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d))(?::\d+)?["']""")

_HOST = r"([a-z0-9][a-z0-9-]*(?:\.[a-z0-9-]+)*\.[a-z]{2,})"
HOST_KEYWORD = re.compile(r"""(?i)\b(?:hostname|host|servername|domain)["']?\s*[:=]\s*["']""" + _HOST + r"""["']""")
HOST_CALL = re.compile(
    r"""(?i)\b(?:connect|create_connection|HTTPS?Connection|gethostbyname|createConnection)\(\s*\(?\s*["']""" + _HOST + r"""["']""")

# Hosts that appear in nearly every package and carry no signal. Suffix match.
BENIGN_HOST_SUFFIXES = (
    "pypi.org", "pythonhosted.org", "python.org", "npmjs.org", "npmjs.com", "nodejs.org",
    "github.com", "githubusercontent.com", "gitlab.com", "bitbucket.org", "readthedocs.io",
    "readthedocs.org", "w3.org", "apache.org", "opensource.org", "creativecommons.org",
    "mozilla.org", "wikipedia.org", "stackoverflow.com", "sphinx-doc.org", "microsoft.com",
    "google.com", "googleapis.com", "gnu.org", "eclipse.org", "mit.edu", "yarnpkg.com",
    "example.com", "example.org", "example.net", "localhost", "schemas.xmlsoap.org",
    "json-schema.org", "docs.python.org", "pypa.io", "packaging.python.org", "twitter.com",
    "shields.io", "img.shields.io", "badge.fury.io", "codecov.io", "travis-ci.org",
    "travis-ci.com", "circleci.com", "azure.com", "amazonaws.com", "cloudfront.net",
)

# Raw hosting is also used legitimately, so it only earns a LOW signal.
# NOTE: patterns that start with ``\.`` are anchored on the literal domain suffix on purpose.
# An earlier version began with an unbounded ``[\w.-]+`` and backtracked quadratically on long
# runs of word characters (minified JS, base64 blobs) - a ReDoS in the detector itself. Never
# start a pattern with an unbounded repeat that the rest of the pattern can fail after.
_ABUSE_INFRA: list[tuple[str, S, re.Pattern[str]]] = [
    ("webhook", S.HIGH, re.compile(
        r"(?i)discord(?:app)?\.com/api/webhooks/\d+/[\w-]+|hooks\.slack\.com/services/|"
        r"api\.telegram\.org/bot\d")),
    ("oast", S.MEDIUM, re.compile(
        r"(?i)\.(?:oast\.(?:pro|live|site|me|online|fun)|interact\.sh|"
        r"burpcollaborator\.net|dnslog\.cn|ceye\.io|pipedream\.net)\b")),
    ("tunnel", S.MEDIUM, re.compile(
        r"(?i)\.(?:ngrok(?:-free)?\.(?:io|app|dev)|trycloudflare\.com|serveo\.net|"
        r"loca\.lt|localtunnel\.me)\b")),
    ("dropsite", S.MEDIUM, re.compile(
        r"(?i)pastebin\.com/raw|paste\.ee/r|//transfer\.sh|//file\.io|webhook\.site|"
        r"//requestbin\.|//0x0\.st|//temp\.sh|hastebin\.com/raw|anonfiles\.")),
    ("raw-hosting", S.LOW, re.compile(r"(?i)//(?:raw|gist)\.githubusercontent\.com")),
]
_WEBHOOK_RX = _ABUSE_INFRA[0][2]

DOC_EXTENSIONS = (".md", ".rst", ".txt", ".html", ".htm", ".license", ".lic", ".csv")
DOC_NAMES = ("license", "licence", "copying", "notice", "authors", "changelog", "changes",
             "pkg-info", "metadata", "readme", "history")


def is_doc_file(path: str) -> bool:
    base = path.rsplit("/", 1)[-1].lower()
    return base.endswith(DOC_EXTENSIONS) or base.split(".")[0] in DOC_NAMES


def defang(value: str) -> str:
    """Make an IoC safe to paste into a report or chat: hxxp://evil[.]example/x"""
    v = re.sub(r"(?i)^http", "hxxp", value)
    v = re.sub(r"(?i)^ftp", "fxp", v)
    return v.replace(".", "[.]")


def host_is_benign(host: str) -> bool:
    host = host.lower().rstrip(".")
    return any(host == s or host.endswith("." + s) for s in BENIGN_HOST_SUFFIXES)


def _ip_is_noise(ip: str) -> bool:
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return True
    # Loopback / RFC1918 / link-local / unspecified are never attacker infrastructure.
    # (Documentation ranges are kept: they are used as stand-ins in test fixtures.)
    if a.is_loopback or a.is_unspecified or a.is_link_local or a.is_multicast:
        return True
    for net in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"):
        if a in ipaddress.ip_network(net):
            return True
    return False


def scan_infra(ctx: ScanContext, path: str, text: str, via_decoding: bool = False) -> None:
    if is_doc_file(ctx.real_path(path)) and not via_decoding:
        return
    n = 0
    flagged: set[str] = set()
    for m in URL_RE.finditer(text):
        url = m.group().rstrip(".:'\"")
        line = text.count("\n", 0, m.start()) + 1
        # 1) abuse-infrastructure check runs on every URL, benign-host allowlist or not
        for category, severity, rx in _ABUSE_INFRA:
            if category in flagged:
                continue
            hit = rx.search(url)
            if hit:
                flagged.add(category)
                ctx.add(f"IOC-ABUSE-INFRA-{category.upper()}",
                        f"References {category} infrastructure commonly used for staging/exfiltration",
                        severity, path, line=line, tactic="T1567", evidence=url[:120],
                        via_decoding=via_decoding)
                if category == "webhook":
                    ctx.add_ioc("webhook", hit.group(), path, via_decoding)
        # 2) IoC recording, skipping universally-benign hosts
        try:
            host = (urlsplit(url).hostname or "").lower()
        except ValueError:          # e.g. "http://[" - malformed URLs must never crash a scan
            continue
        if not host or host_is_benign(host):
            continue
        ctx.add_ioc("url", url, path, via_decoding)
        try:
            ipaddress.ip_address(host)
            if not _ip_is_noise(host):
                ctx.add_ioc("ip", host, path, via_decoding)
        except ValueError:
            ctx.add_ioc("domain", host, path, via_decoding)
        n += 1
        if n >= 200:
            break
    for m in QUOTED_IPV4.finditer(text):
        if not _ip_is_noise(m.group(1)):
            ctx.add_ioc("ip", m.group(1), path, via_decoding)
    # Hosts given without a scheme: {hostname: 'c2.example'}, connect(("c2.example", 443)), ...
    for rx in (HOST_KEYWORD, HOST_CALL):
        for m in rx.finditer(text):
            host = m.group(1).lower()
            if not host_is_benign(host):
                ctx.add_ioc("domain", host, path, via_decoding)
    # Webhook endpoints built by string concatenation lose their scheme; the pattern is specific
    # and linear, so it is also applied to the raw text.
    if "webhook" not in flagged:
        hit = _WEBHOOK_RX.search(text)
        if hit:
            ctx.add("IOC-ABUSE-INFRA-WEBHOOK",
                    "References webhook infrastructure commonly used for staging/exfiltration",
                    S.HIGH, path, line=text.count("\n", 0, hit.start()) + 1, tactic="T1567",
                    evidence=hit.group(), via_decoding=via_decoding)
            ctx.add_ioc("webhook", hit.group(), path, via_decoding)
