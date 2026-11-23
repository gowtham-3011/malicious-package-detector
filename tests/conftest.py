from __future__ import annotations

import pytest

from mpd.loader import package_from_files
from mpd.scanner import scan_package


def make_pkg(files: dict, ecosystem: str = "pypi", name: str = "demo-pkg", version: str = "1.0.0"):
    files = dict(files)
    if ecosystem == "pypi" and "PKG-INFO" not in files and not any(k.endswith("METADATA") for k in files):
        files["PKG-INFO"] = f"Metadata-Version: 2.1\nName: {name}\nVersion: {version}\n"
    if ecosystem == "npm" and "package.json" not in files:
        files["package.json"] = f'{{"name": "{name}", "version": "{version}"}}'
    raw = {p: (d.encode() if isinstance(d, str) else d) for p, d in files.items()}
    return package_from_files(raw, ecosystem)


@pytest.fixture
def scan():
    def _scan(files: dict, ecosystem: str = "pypi", rules: int = 2, **kw):
        return scan_package(make_pkg(files, ecosystem, **kw), rules_version=rules)
    return _scan


def rule_ids(result) -> set[str]:
    return {f.rule_id for f in result.findings}
