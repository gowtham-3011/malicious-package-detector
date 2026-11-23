"""Pattern analysis for shell / PowerShell command text.

Used for npm lifecycle script commands, ``.sh``/``.ps1`` files, strings handed to
``os.system`` / ``subprocess`` / ``child_process``, and decoded payloads that turn out to
be shell. Everything here is a *detection* pattern over text; nothing is executed.
"""

from __future__ import annotations

import re

from ..models import Severity as S
from .base import ScanContext

_I = re.IGNORECASE
_PIPE_TO_INTERP = r"\|\s*(?:sudo\s+(?:-\S+\s+)*)?(?:(?:ba|z|da|k)?sh|python[23]?|node|perl|ruby|iex|invoke-expression)\b"

# (rule_id, severity, tactic, title, patterns)
_RULES: list[tuple[str, S, str, str, list[re.Pattern[str]]]] = [
    ("SH-DOWNLOAD-EXEC", S.HIGH, "T1105", "Downloads remote content and runs it", [
        re.compile(r"\b(?:curl|wget|iwr|irm|invoke-webrequest|invoke-restmethod)\b[^\n|;]*" + _PIPE_TO_INTERP, _I),
        re.compile(r"\b(?:ba)?sh\s+-c\s+[\"']?\$\(\s*(?:curl|wget)", _I),
        re.compile(r"\biex\s*\(\s*(?:new-object\s+net\.webclient|iwr|irm|invoke-webrequest)", _I),
        re.compile(r"\bcertutil\b[^\n]*-urlcache", _I),
        re.compile(r"\bbitsadmin\s+/transfer", _I),
        re.compile(r"\b(?:curl|wget)\b[^\n;&|]*(?:-o|-O|--output|>)\s*\S+[^\n]*?(?:&&|;)\s*"
                   r"(?:chmod\s+\+?[0-7x]+\s+\S+|(?:ba)?sh\s+\S+|\./\S+)", _I),
    ]),
    ("SH-ENCODED-EXEC", S.HIGH, "T1027", "Executes an encoded command", [
        re.compile(r"base64\s+(?:-d|--decode|-D)\b[^\n|]*\|\s*(?:ba|z)?sh", _I),
        re.compile(r"\bpowershell(?:\.exe)?\b[^\n]*\s-(?:e|enc|encodedcommand)\b", _I),
        re.compile(r"\beval\s*\$\(\s*(?:echo\s+)?[^)]*(?:base64|curl|wget)", _I),
        re.compile(r"\becho\s+[A-Za-z0-9+/=]{20,}\s*\|\s*base64", _I),
    ]),
    ("SH-REVERSE-SHELL", S.CRITICAL, "T1059.004", "Reverse-shell pattern", [
        re.compile(r"/dev/tcp/\d"),
        re.compile(r"\bnc(?:at)?\b[^\n]*\s-(?:e|c)\s", _I),
        re.compile(r"\bbash\s+-i\s*>&", _I),
        re.compile(r"\bsocat\b[^\n]*exec:", _I),
        re.compile(r"\bpython[23]?\s+-c\s+[\"'][^\n]*socket[^\n]*(?:dup2|pty\.spawn)", _I),
    ]),
    ("SH-EXFIL", S.HIGH, "T1041", "Sends local secrets/environment to a remote host", [
        re.compile(r"\b(?:env|printenv|set)\b\s*\|\s*(?:curl|wget|nc)\b", _I),
        re.compile(r"\bcat\s+\S*(?:\.ssh/|\.aws/credentials|\.npmrc|\.netrc|/etc/shadow)[^\n]*\|\s*(?:curl|wget|nc|base64)", _I),
        re.compile(r"\b(?:curl|wget)\b[^\n]*(?:--data(?:-binary|-raw|-urlencode)?|\s-d|\s-F|\s-T|--upload-file|--post-file)"
                   r"\s*[=@]?\S*(?:\$\(\s*(?:env|printenv)|\.ssh|\.aws|\.npmrc|/etc/passwd)", _I),
    ]),
    ("SH-PERSISTENCE", S.MEDIUM, "T1546", "Installs persistence", [
        re.compile(r">>\s*~?/?(?:[\w./$-]*/)?\.(?:bashrc|profile|zshrc|bash_profile)\b", _I),
        re.compile(r"\bcrontab\s+-", _I),
        re.compile(r"/etc/cron\.", _I),
        re.compile(r"\bsystemctl\s+(?:--user\s+)?enable\b", _I),
        re.compile(r"\blaunchctl\s+load\b", _I),
        re.compile(r"\bschtasks\s+/create\b", _I),
        re.compile(r"\breg\s+add\b[^\n]*\\Run\b", _I),
    ]),
    ("SH-CRED-ACCESS", S.MEDIUM, "T1552.001", "Touches credential files", [
        re.compile(r"(?:~|\$HOME|%USERPROFILE%)/?\.(?:ssh|aws|npmrc|pypirc|netrc|git-credentials|kube)\b", _I),
        re.compile(r"/etc/shadow"),
    ]),
]

# --- rule set v4: gaps found on real malicious packages (install-script beacons, process substitution) -------
_IDENT = (r"(?:\$\(|`|\$\{?(?:USER|USERNAME|HOSTNAME|HOME|LOGNAME)\b|%(?:USERNAME|COMPUTERNAME|USERDOMAIN)%|"
          r"\$env:(?:USERNAME|COMPUTERNAME)|\bwhoami\b|\bhostname\b|\buname\b)")
_NET_TOOL = r"\b(?:curl|wget|nslookup|dig|ping|invoke-webrequest|iwr|irm)\b"
_RULES_V4: list[tuple[str, S, str, str, list[re.Pattern[str]]]] = [
    ("SH-BEACON", S.MEDIUM, "T1082", "Network call carrying host identity (beacon)", [
        re.compile(_NET_TOOL + r"[^\n;|&]*" + _IDENT, _I),
        re.compile(r"\b(?:whoami|hostname|uname)\b[^\n]*\|\s*(?:curl|wget|nc|nslookup)\b", _I),
    ]),
    ("SH-DOWNLOAD-EXEC-SUBST", S.HIGH, "T1105", "Runs a script fetched through process substitution", [
        re.compile(r"\b(?:ba|z)?sh\s+<\(\s*(?:curl|wget)", _I),
        re.compile(r"\b(?:source|\.)\s+<\(\s*(?:curl|wget)", _I),
        re.compile(r"\beval\s+\"?\$\(\s*(?:curl|wget)", _I),
    ]),
    ("SH-NETWORK-AT-INSTALL", S.LOW, "T1105", "Network tool invoked from an install-time command", [
        re.compile(r"\b(?:curl|wget|nslookup|invoke-webrequest|iwr|certutil|bitsadmin)\b", _I),
    ]),
]


def analyze_shell(ctx: ScanContext, path: str, text: str, *, phase: str | None = None,
                  via_decoding: bool = False, line_offset: int = 0) -> None:
    if not ctx.enabled("shell"):
        return
    for rule_id, severity, tactic, title, patterns in (_RULES + (_RULES_V4 if ctx.v4 else [])):
        if rule_id == "SH-NETWORK-AT-INSTALL" and phase != "install":
            continue
        if rule_id == "SH-BEACON" and phase not in ("install", "import"):
            continue      # beacons matter where code runs automatically; runtime shell helpers use $(...) legitimately
        for rx in patterns:
            m = rx.search(text)
            if m:
                line = text.count("\n", 0, m.start()) + 1 + line_offset
                ctx.add(rule_id, title, severity, path, line=line, phase=phase, tactic=tactic,
                        evidence=m.group(), via_decoding=via_decoding)
                break
