"""Metadata anomalies that an offline scan can see.

Honest scope note: real dependency-confusion detection needs registry context this tool does
not have (is the name also in the victim's private index? when was it first published? who
maintains it?). What we can see offline is the *shape*: an absurdly high version number,
which is how the attack wins version resolution, and npm dependencies that bypass the
registry entirely.
"""

from __future__ import annotations

import re
from urllib.parse import urlsplit

from ..models import Severity as S
from .base import ScanContext

_REGISTRY_BYPASS_OK_HOSTS = ("github.com", "gitlab.com", "bitbucket.org", "codeload.github.com")


def _major(version: str) -> int | None:
    m = re.match(r"\s*v?(\d+)", version or "")
    return int(m.group(1)) if m else None


def _version_anomalous(major: int) -> bool:
    # CalVer majors (2024.x, 20240101) are normal. 99.x / 9999.x are the dependency-confusion tell.
    return 90 <= major < 1900 or 3000 <= major < 19_000_000


def run(ctx: ScanContext) -> None:
    if not ctx.enabled("metadata"):
        return
    pkg = ctx.pkg
    major = _major(pkg.version)
    if major is not None and _version_anomalous(major):
        ctx.add("PKG-VERSION-ANOMALY", f"Implausibly high version {pkg.version} (dependency-confusion pattern)",
                S.MEDIUM, "<metadata>", phase="install", tactic="T1195.001", evidence=pkg.version)
    if pkg.ecosystem == "npm":
        pj = pkg.metadata.get("package_json") or {}
        for section in ("dependencies", "optionalDependencies", "devDependencies"):
            deps = pj.get(section)
            if not isinstance(deps, dict):
                continue
            for dep, spec in deps.items():
                if not isinstance(spec, str):
                    continue
                if re.match(r"^(?:https?|git\+https?|git|git\+ssh)://", spec):
                    try:
                        host = (urlsplit(spec.replace("git+", "")).hostname or "").lower()
                    except ValueError:
                        host = ""
                    benign = any(host == h or host.endswith("." + h) for h in _REGISTRY_BYPASS_OK_HOSTS)
                    ctx.add("NPM-REMOTE-DEP", f"Dependency '{dep}' is fetched from a URL, bypassing the registry",
                            S.LOW if benign else S.MEDIUM, "package.json", phase="install",
                            tactic="T1195.001", evidence=f"{dep}: {spec}")
                    break
