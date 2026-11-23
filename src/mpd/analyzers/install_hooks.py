"""Install-time execution: which code runs the moment a victim installs the package?

This is the highest-leverage analysis in the tool. The same ``requests.post`` is routine
in a library and alarming in a ``postinstall`` script, because install-time code runs
before anyone has reviewed it, with the installer's privileges, often in CI with secrets
in the environment. This module decides each file's *phase* (install / import / runtime)
so the scorer can weigh findings accordingly.

npm   : preinstall / install / postinstall / prepare scripts, and files they invoke.
PyPI  : setup.py, ``.pth`` files (executed on every interpreter start), sitecustomize,
        an in-tree PEP 517 build backend.
"""

from __future__ import annotations

import ast
import re
import warnings

from ..models import Severity as S
from .base import ScanContext
from .python_ast import analyze_python
from .shell import analyze_shell

NPM_LIFECYCLE = ("preinstall", "install", "postinstall", "prepublish", "preprepare", "prepare", "postprepare")

# Lifecycle commands that are overwhelmingly legitimate (native builds, git hooks, banners).
_BENIGN_LIFECYCLE = re.compile(
    r"^\s*(?:node-gyp(?:\s+rebuild)?|node-gyp-build|prebuild-install(?:\s*\|\|\s*node-gyp\s+rebuild)?|"
    r"husky(?:\s+install)?|is-ci\s*\|\|\s*husky(?:\s+install)?|patch-package|tsc(?:\s+[\w./-]+)*|"
    r"npm\s+run\s+build|npx\s+only-allow\s+\w+|opencollective-postinstall|cmake-js\s+\w+|"
    r"electron-builder\s+install-app-deps|echo\s+[^|&;<>$`]*)\s*$", re.I)

_FILE_REF = re.compile(
    r"(?:^|[\s;&|])(?:node|nodejs|bash|sh|zsh|python3?|ts-node|npx\s+\S+)\s+(?:-{1,2}\S+\s+)*"
    r"[\"']?(\.?/?[\w./@-]+\.(?:js|cjs|mjs|sh|py|ts|ps1))[\"']?")
_BARE_REF = re.compile(r"(?:^|[\s;&|])\./([\w./@-]+\.(?:sh|js|py))")
_RUN_REF = re.compile(r"\b(?:npm|yarn|pnpm)\s+(?:run\s+)?([\w:-]+)")

_DANGEROUS_PTH = re.compile(r"exec\s*\(|eval\s*\(|b64decode|base64|subprocess|urllib|socket|os\.system|compile\s*\(")

_PY_TOP_EXCLUDE = {"tests", "test", "docs", "doc", "examples", "example", "scripts", "build", "dist",
                   "benchmarks", "tools", "venv", "env"}


def _json_line(text: str, key: str) -> int:
    m = re.search(r'"%s"\s*:' % re.escape(key), text)
    return text.count("\n", 0, m.start()) + 1 if m else 0


def _norm(path: str) -> str:
    p = path.replace("\\", "/")
    while p.startswith("./"):
        p = p[2:]
    return p.lstrip("/")


# ------------------------------------------------------------------------------ npm
def _npm(ctx: ScanContext) -> None:
    pkg = ctx.pkg
    pj = pkg.metadata.get("package_json") or {}
    scripts = pj.get("scripts") if isinstance(pj.get("scripts"), dict) else {}
    raw = pkg.text("package.json") if "package.json" in pkg.files else ""
    seen_runs: set[str] = set()

    def register_command(label: str, cmd: str, line: int) -> None:
        for rx in (_FILE_REF, _BARE_REF):
            for m in rx.finditer(cmd):
                ref = _norm(m.group(1))
                if ref in pkg.files:
                    ctx.install_files.add(ref)
        for m in _RUN_REF.finditer(cmd):
            target = m.group(1)
            if target in scripts and target not in seen_runs and target != label:
                seen_runs.add(target)
                register_command(target, str(scripts[target]), line)

    for name in NPM_LIFECYCLE:
        cmd = scripts.get(name)
        if not isinstance(cmd, str) or not cmd.strip():
            continue
        line = _json_line(raw, name)
        if _BENIGN_LIFECYCLE.match(cmd):
            continue
        ctx.add("NPM-LIFECYCLE-SCRIPT", f"Runs a `{name}` script at install time", S.LOW,
                "package.json", line=line, phase="install", tactic="T1195.002", evidence=f"{name}: {cmd}")
        analyze_shell(ctx, "package.json", cmd, phase="install", line_offset=line - 1)
        register_command(name, cmd, line)

    if "binding.gyp" in pkg.files and not scripts.get("install"):
        ctx.notes.append("binding.gyp present: node-gyp build runs implicitly at install")

    main = pj.get("main") if isinstance(pj.get("main"), str) else "index.js"
    candidates = [main, main + ".js", "index.js"]
    bins = pj.get("bin")
    if isinstance(bins, str):
        candidates.append(bins)
    elif isinstance(bins, dict):
        candidates.extend(v for v in bins.values() if isinstance(v, str))
    for c in candidates:
        c = _norm(c)
        if c in pkg.files and c not in ctx.install_files:
            ctx.import_files.add(c)


# ----------------------------------------------------------------------------- pypi
def _setup_cmdclass(ctx: ScanContext, text: str) -> None:
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            tree = ast.parse(text)
    except (SyntaxError, ValueError, RecursionError, MemoryError):
        return
    mentions =any(isinstance(n, ast.keyword) and n.arg == "cmdclass" for n in ast.walk(tree)) or any(
        isinstance(n, ast.Name) and n.id == "cmdclass" for n in ast.walk(tree))
    if not mentions:
        return
    for n in ast.walk(tree):
        if isinstance(n, ast.Dict):
            keys = [k.value for k in n.keys if isinstance(k, ast.Constant) and isinstance(k.value, str)]
            hot = [k for k in keys if k in ("install", "develop", "egg_info")]
            if hot:
                ctx.add("PYPI-CMDCLASS-INSTALL-OVERRIDE",
                        "setup.py overrides the install/develop/egg_info command", S.MEDIUM, "setup.py",
                        line=n.lineno, phase="install", tactic="T1195.002", evidence=f"cmdclass keys: {hot}")
                return


def _top_level_import_files(ctx: ScanContext) -> None:
    files = ctx.pkg.files
    roots = [""]
    if any(p.startswith("src/") for p in files):
        roots.append("src/")
    for root in roots:
        pkgs: set[str] = set()
        for p in files:
            if not p.startswith(root):
                continue
            rest = p[len(root):]
            parts = rest.split("/")
            if len(parts) >= 2 and parts[-1] == "__init__.py" and len(parts) == 2:
                if parts[0] not in _PY_TOP_EXCLUDE and not parts[0].startswith("."):
                    pkgs.add(parts[0])
        for name in pkgs:
            for fn in ("__init__.py", "__main__.py"):
                path = f"{root}{name}/{fn}"
                if path in files and path not in ctx.install_files:
                    ctx.import_files.add(path)
        if root == "":
            for p in files:
                if "/" not in p and p.endswith(".py") and p not in (
                        "setup.py", "conftest.py", "noxfile.py", "tasks.py", "fabfile.py"):
                    if p not in ctx.install_files:
                        ctx.import_files.add(p)


def _pypi(ctx: ScanContext) -> None:
    files = ctx.pkg.files
    if "setup.py" in files:
        ctx.install_files.add("setup.py")
        _setup_cmdclass(ctx, ctx.pkg.text("setup.py"))
    for name in ("sitecustomize.py", "usercustomize.py"):
        if name in files:
            ctx.install_files.add(name)
            ctx.add("PYPI-SITECUSTOMIZE", f"Ships {name}, which runs on every interpreter start", S.MEDIUM,
                    name, line=1, phase="install", tactic="T1546")
    # PEP 517 in-tree backend: arbitrary code at build time.
    if "pyproject.toml" in files:
        text = ctx.pkg.text("pyproject.toml")
        m = re.search(r"backend-path\s*=\s*\[([^\]]*)\]", text)
        if m:
            ctx.add("PYPI-INTREE-BACKEND", "pyproject.toml uses an in-tree build backend", S.LOW,
                    "pyproject.toml", line=text.count("\n", 0, m.start()) + 1, phase="install",
                    tactic="T1195.002", evidence=m.group())
            for d in re.findall(r"""["']([^"']+)["']""", m.group(1)):
                prefix = _norm(d).rstrip("/") + "/"
                for p in files:
                    if p.startswith(prefix) and p.endswith(".py"):
                        ctx.install_files.add(p)
    # .pth files: lines starting with "import" are executed by site.py on every interpreter start.
    for path, data in files.items():
        if not path.endswith(".pth"):
            continue
        ctx.install_files.add(path)
        text = data.decode("utf-8", errors="replace")
        for i, line in enumerate(text.splitlines()):
            if not re.match(r"^import[ \t]", line):
                continue
            dangerous = bool(_DANGEROUS_PTH.search(line))
            ctx.add("PTH-EXEC-LINE", "Executable line in a .pth file (runs on every interpreter start)",
                    S.MEDIUM if dangerous else S.LOW, path, line=i + 1, phase="install",
                    tactic="T1546", evidence=line)
            analyze_python(ctx, path, "\n" * i + line, "install")
    _top_level_import_files(ctx)


def run(ctx: ScanContext) -> None:
    if not ctx.enabled("hooks"):
        return
    if ctx.pkg.ecosystem == "npm":
        _npm(ctx)
    else:
        _pypi(ctx)
    ctx.install_entry = set(ctx.install_files)   # before reachability widens install_files
    from . import reachability   # local import keeps module load order simple
    reachability.run(ctx)
