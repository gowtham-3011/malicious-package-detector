"""Import-graph reachability: which files actually run as a consequence of install or import?

A payload hidden in ``pkg/_helper.py`` never looks like install-time code on its own. But if
``pkg/__init__.py`` imports it, it runs the moment anyone imports the package. We walk the
package-internal import graph outward from the entrypoint files so that code inherits the
phase of whatever pulls it in. (This is a small cousin of what a code-context graph does
for reachability of vulnerabilities, applied to behaviour instead of CVEs.)

Limits, stated plainly: no cross-module data-flow, no dynamic imports, and only imports that
resolve to files inside this package are followed.
"""

from __future__ import annotations

import ast
import posixpath
import re
import warnings
from collections import deque

from .base import ScanContext

MAX_HOPS = 6
_JS_IMPORT = re.compile(r"""(?:require\(|from\s+|import\()\s*['"](\.{1,2}/[^'"]+)['"]""")
_JS_SUFFIXES = ("", ".js", ".cjs", ".mjs", "/index.js")


_STMT_FIELDS = ("body", "orelse", "finalbody", "handlers", "cases")


def _iter_statements(tree: ast.AST):
    """Yield statement nodes only. Imports are statements, so there is no need to descend into
    expressions - which is where the bulk of a huge generated data module lives."""
    stack = [tree]
    while stack:
        n = stack.pop()
        yield n
        for f in _STMT_FIELDS:
            kids = getattr(n, f, None)
            if isinstance(kids, list):
                stack.extend(k for k in kids if isinstance(k, ast.AST))


def _py_targets(files: dict[str, bytes], importer: str, tree: ast.AST) -> set[str]:
    found: set[str] = set()
    importer_dir = posixpath.dirname(importer)

    def probe(base: str, dotted: str) -> None:
        rel = dotted.replace(".", "/")
        path = posixpath.normpath(posixpath.join(base, rel)) if base else rel
        for cand in (f"{path}.py", f"{path}/__init__.py"):
            if cand in files:
                found.add(cand)

    for n in _iter_statements(tree):
        if isinstance(n, ast.Import):
            for a in n.names:
                for base in ("", "src"):
                    probe(base, a.name)
        elif isinstance(n, ast.ImportFrom):
            if n.level > 0:
                base = importer_dir
                for _ in range(n.level - 1):
                    base = posixpath.dirname(base)
                bases = [base]
            else:
                bases = ["", "src"]
            for base in bases:
                if n.module:
                    probe(base, n.module)
                    for a in n.names:
                        probe(base, f"{n.module}.{a.name}")
                else:
                    for a in n.names:
                        probe(base, a.name)
    return found


def _js_targets(files: dict[str, bytes], importer: str, text: str) -> set[str]:
    found: set[str] = set()
    importer_dir = posixpath.dirname(importer)
    for m in _JS_IMPORT.finditer(text):
        base = posixpath.normpath(posixpath.join(importer_dir, m.group(1)))
        for suf in _JS_SUFFIXES:
            if base + suf in files:
                found.add(base + suf)
                break
    return found


def _closure(ctx: ScanContext, seeds: set[str], blocked: set[str]) -> set[str]:
    files = ctx.pkg.files
    seen = set(seeds)
    queue = deque((s, 0) for s in seeds)
    reached: set[str] = set()
    while queue:
        path, hops = queue.popleft()
        if hops >= MAX_HOPS or path not in files:
            continue
        text = files[path].decode("utf-8", errors="replace")
        if path.endswith(".py"):
            try:
                with warnings.catch_warnings():
                    warnings.simplefilter("ignore")
                    targets = _py_targets(files, path, ast.parse(text))
            except (SyntaxError, ValueError, RecursionError, MemoryError):
                continue
        elif path.endswith((".js", ".cjs", ".mjs")):
            targets = _js_targets(files, path, text)
        else:
            continue
        for t in targets:
            if t not in seen:
                seen.add(t)
                if t not in blocked:
                    reached.add(t)
                queue.append((t, hops + 1))
    return reached


def run(ctx: ScanContext) -> None:
    if not ctx.enabled("hooks"):
        return
    # Whatever install-time code imports is itself install-time code.
    ctx.install_files |= _closure(ctx, set(ctx.install_files), set())
    # Whatever import-time entrypoints pull in runs on import (unless already install-time).
    ctx.import_files |= _closure(ctx, set(ctx.import_files), ctx.install_files)
    ctx.import_files -= ctx.install_files
