"""AST-based analysis of Python source. The source is parsed, never executed.

Design:
  * **Taint-lite.** A name is "tainted" if it is assigned from a decode call (base64,
    zlib, marshal, ...), a network fetch, or a socket read. ``exec`` of a tainted value is
    the classic dropper shape and is reported even when the payload itself is not visible.
  * **Behaviour combinations, per scope.** One signal is weak, two together are strong:
    reading ~/.aws/credentials is normal for a cloud SDK, sending HTTP is normal for a
    client, doing BOTH in one function is a stealer. Flags are collected per function and
    combined when the scope closes.
  * **Phase.** Findings inherit when the code runs (install / import / runtime) from the
    entrypoint analysis in install_hooks.py. Top-level statements of any module run at
    import time, so module scope in an otherwise-runtime file is promoted to "import".
"""

from __future__ import annotations

import ast
import base64
import binascii
import codecs
import re
import warnings
from collections import Counter

from ..deobfuscate import _decompress
from ..models import Severity as S
from .base import MAX_DEPTH, ScanContext, short
from .shell import analyze_shell

DECODE_SOURCES = frozenset({
    "base64.b64decode", "base64.urlsafe_b64decode", "base64.b32decode", "base64.b16decode",
    "base64.a85decode", "base64.b85decode", "base64.decodebytes",
    "binascii.unhexlify", "binascii.a2b_base64", "binascii.a2b_hex",
    "zlib.decompress", "gzip.decompress", "bz2.decompress", "lzma.decompress",
    "marshal.loads", "pickle.loads", "codecs.decode", "bytes.fromhex", "bytearray.fromhex",
})
FETCH_FUNCS = frozenset({
    "urllib.request.urlopen", "urllib.request.urlretrieve", "urllib2.urlopen", "urllib.urlopen",
    "urllib.urlretrieve", "requests.get", "httpx.get",
})
EGRESS_PREFIXES = (
    "requests.", "httpx.", "urllib.request.", "urllib2.", "urllib.urlopen", "urllib.urlretrieve",
    "http.client.", "aiohttp.", "smtplib.", "ftplib.", "telnetlib.", "websocket.",
    "socket.create_connection", "socket.gethostbyname", "socket.getaddrinfo", "socket.socket",
    "dns.resolver.",
)
MAX_AST_BYTES = 500_000
RECON_FUNCS = frozenset({
    "socket.gethostname", "getpass.getuser", "platform.node", "os.getlogin", "os.uname",
    "socket.getfqdn", "platform.uname",
})
# --- rule set v4 -------------------------------------------------------------------------------------------
SHELL_SINKS_V4 = frozenset({
    "os.startfile", "ctypes.windll.shell32.ShellExecuteW", "ctypes.windll.shell32.ShellExecuteA", "os.spawnlp",
    "os.spawnvp", "os.execvp", "os.execlp", "webbrowser.open",
})
RECON_V4 = frozenset({"os.getcwd", "platform.system", "platform.platform", "platform.release", "platform.machine",
                      "uuid.getnode", "socket.gethostbyname", "os.getuid", "os.cpu_count"})
IP_LOOKUP_RE = re.compile(r"(?i)ipify|ifconfig\.me|ip-api|icanhazip|checkip|ipinfo\.io|myexternalip|ident\.me")
STEALER_PATH_RE = re.compile(
    r"(?i)local storage[/\\]leveldb|login data|google[/\\]chrome[/\\]user data|[/\\]discord(?:canary|ptb)?[/\\]|"
    r"mozilla[/\\]firefox[/\\]profiles|telegram desktop[/\\]tdata|exodus[/\\]exodus\.wallet|electrum[/\\]wallets|"
    r"bravesoftware[/\\]brave-browser|microsoft[/\\]edge[/\\]user data")
TOKEN_REGEX_RE = re.compile(r"\{24\}\\?\.[^\n]{0,20}\{6\}|mfa\\?\.\[")

CODE_EXEC_SINKS = frozenset({"exec", "eval", "compile", "builtins.exec", "builtins.eval", "builtins.compile"})
SHELL_SINKS = frozenset({
    "os.system", "os.popen", "os.execv", "os.execve", "os.execl", "os.execlp", "os.spawnl",
    "subprocess.run", "subprocess.call", "subprocess.check_call", "subprocess.check_output",
    "subprocess.Popen", "subprocess.getoutput", "subprocess.getstatusoutput", "pty.spawn",
})

SENSITIVE_PATH_RE = re.compile(
    r"(?i)(?:\.ssh[/\\]|id_rsa|id_ed25519|\.aws[/\\](?:credentials|config)|\.npmrc|\.pypirc|"
    r"\.git-credentials|\.netrc|\.docker[/\\]config\.json|\.kube[/\\]config|/etc/(?:passwd|shadow)|"
    r"login data|cookies\.sqlite|chrome[/\\]user data|\.mozilla[/\\]firefox|local storage[/\\]leveldb|"
    r"\.config[/\\]gcloud|wallet\.dat|\.electrum|\.bash_history)")
PERSIST_RE = re.compile(
    r"(?i)(?:\.bashrc|\.zshrc|\.bash_profile|\.profile\b|crontab|/etc/cron|start menu[/\\]programs[/\\]startup|"
    r"currentversion[/\\]run|\.config/autostart|launchagents|systemd/user)")

# --- rule set v2 additions (every use below is gated on ctx.v2) ------------------------------
SENSITIVE_ENV_RE = re.compile(
    r"^(?:AWS_(?:SECRET_ACCESS_KEY|ACCESS_KEY_ID|SESSION_TOKEN)|GITHUB_TOKEN|GH_TOKEN|NPM_TOKEN|"
    r"NODE_AUTH_TOKEN|PYPI_TOKEN|TWINE_PASSWORD|SSH_AUTH_SOCK|DOCKER_PASSWORD|SLACK_TOKEN|"
    r"AZURE_CLIENT_SECRET|GOOGLE_APPLICATION_CREDENTIALS|KUBECONFIG|OPENAI_API_KEY|ANTHROPIC_API_KEY|"
    r"HF_TOKEN|GITLAB_TOKEN)$")
PACKAGED_DATA_SOURCES = frozenset({
    "pkgutil.get_data", "importlib.resources.read_text", "importlib.resources.read_binary",
    "pkg_resources.resource_string",
})
_B64_DECODERS = {
    "base64.b64decode": base64.b64decode, "base64.urlsafe_b64decode": base64.urlsafe_b64decode,
    "base64.b32decode": base64.b32decode, "base64.b16decode": base64.b16decode,
    "base64.b85decode": base64.b85decode, "base64.a85decode": base64.a85decode,
}
MAX_FOLDED = 200_000

# Cheap prefilter for runtime-only files: if none of these tokens appears, no rule below can
# fire, so we skip the (expensive) AST pass. Install/import-phase files are always analysed in
# full. The token list is the union of everything the rules key on; keep it in sync when adding
# rules (a test asserts every rule's trigger is covered).
_TRIGGERS = re.compile(
    r"exec|eval|compile|system|popen|subprocess|spawn|socket|request|urllib|http|ftp|smtp|base64|b64|"
    r"marshal|pickle|zlib|gzip|bz2|lzma|decompress|fromhex|unhexlify|getattr|__import__|import_module|"
    r"environ|getenv|expanduser|\.ssh|\.aws|\.npmrc|\.pypirc|credential|builtins|globals|ctypes|pty|"
    r"cmdclass|recv|chr\(|hostname|getuser|getlogin|getfqdn|uname|platform|pkgutil|get_data|\.bashrc|crontab")

_FALLBACK_EXEC = re.compile(r"\b(?:exec|eval)\s*\(.{0,200}(?:b64decode|decompress|unhexlify|fromhex)", re.S)


class _Scope:
    __slots__ = ("name", "is_module", "flags")

    def __init__(self, name: str, is_module: bool) -> None:
        self.name = name
        self.is_module = is_module
        self.flags: dict[str, tuple[int, str]] = {}

    def mark(self, flag: str, line: int, evidence: str = "") -> None:
        self.flags.setdefault(flag, (line, evidence))


class _PyAnalyzer(ast.NodeVisitor):
    def __init__(self, ctx: ScanContext, path: str, text: str, tree: ast.AST, phase: str,
                 via_decoding: bool, depth: int) -> None:
        self.ctx = ctx
        self.path = path
        self.lines = text.splitlines()
        self.tree = tree
        self.file_phase = phase
        self.via_decoding = via_decoding
        self.depth = depth
        self.parents: dict[ast.AST, ast.AST] = {}
        imports, assigns, calls = self._index(tree)          # ONE walk over the tree
        self.aliases = self._build_aliases(imports)
        self.env: dict[str, str | bytes] = {}            # v2: names bound once to a foldable constant
        self.callable_alias: dict[str, str] = {}         # v2: x = getattr(__import__("os"), "system")
        if ctx.v2:
            self._build_env(assigns)
            self._build_callable_aliases(assigns)
        self.tainted: set[str] = set()
        self._propagate_taint(assigns, calls)
        self.scopes: list[_Scope] = [_Scope("<module>", True)]
        self.file_flags: dict[str, tuple[int, str]] = {}
        self.scope_combos: set[str] = set()      # combos already reported at scope level
        self.import_called = self._functions_called_at_module_level(tree)

    @staticmethod
    def _functions_called_at_module_level(tree: ast.AST) -> set[str]:
        """Names of locally defined functions that run when the module is imported.

        Only module-level statements execute on import; a function body runs only if something
        calls it. We approximate "something" with a direct call at module level, skipping
        ``if __name__ == "__main__"`` blocks (those do not run on import).
        """
        defined = {n.name for n in getattr(tree, "body", []) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))}
        called: set[str] = set()
        stack = list(getattr(tree, "body", []))
        while stack:
            n = stack.pop()
            if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
                continue
            if isinstance(n, ast.If) and isinstance(n.test, ast.Compare) and \
                    isinstance(n.test.left, ast.Name) and n.test.left.id == "__name__":
                continue
            if isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id in defined:
                called.add(n.func.id)
            stack.extend(ast.iter_child_nodes(n))
        return called

    def _is_entry_file(self) -> bool:
        return self.ctx.real_path(self.path) in self.ctx.install_entry

    def _v4_import_entry(self) -> bool:
        """v4: the package's own __init__/__main__ runs on import, so its cross-function combos count like setup.py's."""
        return (self.ctx.v4 and self.file_phase == "import"
                and self.ctx.real_path(self.path) in self.ctx.import_files
                and self.ctx.real_path(self.path).rsplit("/", 1)[-1] in ("__init__.py", "__main__.py"))

    def _install_here(self) -> bool:
        """Is the code at the current position install-time? (v3: scope-aware; v1/v2: whole-file)"""
        return self.phase() == "install" if self.ctx.v3 else self.file_phase == "install"

    def _scope_phase(self, sc: "_Scope") -> str:
        if self.file_phase == "install":
            # v3: only the entrypoint files themselves (setup.py, .pth, ...) run top to bottom at
            # install. A module merely *imported* by them runs its module-level code, not every
            # function body, so treating all of it as install-time over-approximated (207 of mypy's
            # 1,873 files landed in the install closure).
            if self.ctx.v3 and not self._is_entry_file():
                return "install" if (sc.is_module or sc.name in self.import_called) else "runtime"
            return "install"
        if self.file_phase == "import":
            return "import" if (sc.is_module or sc.name in self.import_called) else "runtime"
        return "runtime"

    # ---------------------------------------------------------------- helpers
    def _index(self, tree: ast.AST):
        """Single traversal: parent links for the node types we query, plus the node lists the
        later passes need. (An earlier version re-walked the whole tree 5-6 times per file and
        made real packages take minutes; see the performance note in the README.)"""
        imports: list[ast.AST] = []
        assigns: list[ast.AST] = []
        calls: list[ast.Call] = []
        stack = [tree]
        while stack:
            n = stack.pop()
            for c in ast.iter_child_nodes(n):
                if isinstance(c, (ast.Attribute, ast.Name, ast.Constant)):
                    self.parents[c] = n
                stack.append(c)
            if isinstance(n, ast.Call):
                calls.append(n)
            elif isinstance(n, (ast.Import, ast.ImportFrom)):
                imports.append(n)
            elif isinstance(n, (ast.Assign, ast.AnnAssign, ast.AugAssign, ast.With, ast.AsyncWith)):
                assigns.append(n)
        return imports, assigns, calls

    @staticmethod
    def _build_aliases(imports: list[ast.AST]) -> dict[str, str]:
        aliases: dict[str, str] = {}
        for n in imports:
            if isinstance(n, ast.Import):
                for a in n.names:
                    aliases[a.asname or a.name.split(".")[0]] = a.name if a.asname else a.name.split(".")[0]
            elif isinstance(n, ast.ImportFrom) and n.module and n.level == 0:
                for a in n.names:
                    aliases[a.asname or a.name] = f"{n.module}.{a.name}"
        return aliases

    def qualname(self, node: ast.AST, plain: bool = False) -> str | None:
        """Dotted name of a call target. ``plain=True`` gives the v1 behaviour (imports only)."""
        if isinstance(node, ast.Name):
            if not plain and node.id in self.callable_alias:
                return self.callable_alias[node.id]
            return self.aliases.get(node.id, node.id)
        if isinstance(node, ast.Attribute):
            base = self.qualname(node.value, plain)
            return f"{base}.{node.attr}" if base else None
        if not plain and self.ctx.v2 and isinstance(node, ast.Call):
            return self._resolve_callable(node)
        return None

    # ------------------------------------------------- v2: folding and dynamic resolution
    def fold(self, node: ast.AST, _d: int = 0):
        """Constant str/bytes value of ``node`` if statically knowable.

        v1: plain literals only. v2: also concatenation, f-strings of constants, ``chr`` /
        ``"".join`` / ``bytes([...])`` constructions, reversal, base64/hex/zlib/rot13 decodes,
        ``os.path.join`` and names bound exactly once to a foldable value.
        """
        if isinstance(node, ast.Constant):
            return node.value if isinstance(node.value, (str, bytes)) else None
        if not self.ctx.v2 or _d > 40:
            return None
        try:
            out = self._fold_v2(node, _d + 1)
        except (ValueError, TypeError, binascii.Error, UnicodeError, RecursionError):
            return None
        return out if not isinstance(out, (str, bytes)) or len(out) <= MAX_FOLDED else None

    def _fold_v2(self, node: ast.AST, d: int):
        f = lambda n: self.fold(n, d)  # noqa: E731
        if isinstance(node, ast.JoinedStr):
            parts: list[str] = []
            for v in node.values:
                if isinstance(v, ast.Constant) and isinstance(v.value, str):
                    parts.append(v.value)
                elif isinstance(v, ast.FormattedValue) and v.conversion == -1 and v.format_spec is None:
                    fv = f(v.value)
                    if not isinstance(fv, str):
                        return None
                    parts.append(fv)
                else:
                    return None
            return "".join(parts)
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            l, r = f(node.left), f(node.right)
            return l + r if l is not None and r is not None and type(l) is type(r) else None
        if isinstance(node, ast.Name):
            return self.env.get(node.id)
        if isinstance(node, ast.Subscript) and isinstance(node.slice, ast.Slice):
            sl = node.slice
            if (sl.lower is None and sl.upper is None and isinstance(sl.step, ast.UnaryOp)
                    and isinstance(sl.step.op, ast.USub) and isinstance(sl.step.operand, ast.Constant)
                    and sl.step.operand.value == 1):
                v = f(node.value)
                return v[::-1] if isinstance(v, (str, bytes)) else None
            return None
        if isinstance(node, ast.Call):
            return self._fold_call(node, d)
        return None

    @staticmethod
    def _const_ints(node: ast.AST) -> list[int] | None:
        if isinstance(node, (ast.List, ast.Tuple)) and all(
                isinstance(e, ast.Constant) and isinstance(e.value, int) and not isinstance(e.value, bool)
                for e in node.elts):
            return [e.value for e in node.elts]
        return None

    def _str_parts(self, node: ast.AST, d: int) -> list[str] | None:
        """Elements of the iterable handed to ``sep.join(...)``, if all statically known."""
        if isinstance(node, (ast.List, ast.Tuple)):
            parts = [self.fold(e, d) for e in node.elts]
            return parts if all(isinstance(p, str) for p in parts) else None
        if isinstance(node, ast.Call):
            q = self.qualname(node.func, plain=True) or ""
            if q == "map" and len(node.args) == 2 and isinstance(node.args[0], ast.Name) and node.args[0].id == "chr":
                ints = self._const_ints(node.args[1])
                return [chr(i) for i in ints if 0 <= i < 0x110000] if ints is not None else None
            if q == "reversed" and len(node.args) == 1:
                v = self.fold(node.args[0], d)
                return list(reversed(v)) if isinstance(v, str) else None
        if isinstance(node, (ast.GeneratorExp, ast.ListComp)) and len(node.generators) == 1:
            g = node.generators[0]
            if g.ifs or not isinstance(g.target, ast.Name) or not isinstance(g.iter, (ast.List, ast.Tuple)):
                return None
            out: list[str] = []
            for el in g.iter.elts:
                if (isinstance(node.elt, ast.Call) and (self.qualname(node.elt.func, plain=True) or "") == "chr"
                        and len(node.elt.args) == 1 and isinstance(node.elt.args[0], ast.Name)
                        and node.elt.args[0].id == g.target.id and isinstance(el, ast.Constant)
                        and isinstance(el.value, int) and 0 <= el.value < 0x110000):
                    out.append(chr(el.value))
                elif isinstance(node.elt, ast.Name) and node.elt.id == g.target.id:
                    v = self.fold(el, d)
                    if not isinstance(v, str):
                        return None
                    out.append(v)
                else:
                    return None
            return out
        return None

    def _fold_call(self, node: ast.Call, d: int):
        q = self.qualname(node.func, plain=True) or ""
        args = node.args
        f = lambda n: self.fold(n, d)  # noqa: E731
        if q == "chr" and len(args) == 1 and isinstance(args[0], ast.Constant) and isinstance(args[0].value, int):
            return chr(args[0].value) if 0 <= args[0].value < 0x110000 else None
        if q in ("bytes", "bytearray") and len(args) == 1:
            ints = self._const_ints(args[0])
            return bytes(ints) if ints is not None and all(0 <= i < 256 for i in ints) else None
        if q == "os.path.join" and args:
            parts = [f(a) for a in args]
            return "/".join(parts) if all(isinstance(p, str) for p in parts) else None
        if q in ("os.path.expanduser", "os.path.normpath") and len(args) == 1:
            v = f(args[0])
            return v if isinstance(v, str) else None
        if q in _B64_DECODERS and args:
            v = f(args[0])
            v = v.encode() if isinstance(v, str) else v
            return _B64_DECODERS[q](v) if isinstance(v, bytes) else None
        if q in ("bytes.fromhex", "bytearray.fromhex") and args:
            v = f(args[0])
            return bytes.fromhex(v) if isinstance(v, str) else None
        if q in ("binascii.unhexlify", "binascii.a2b_hex") and args:
            v = f(args[0])
            return binascii.unhexlify(v) if isinstance(v, (str, bytes)) else None
        if q == "zlib.decompress" and args:
            v = f(args[0])
            return _decompress(v) if isinstance(v, bytes) else None
        if q == "codecs.decode" and len(args) >= 2:
            v, enc = f(args[0]), f(args[1])
            if isinstance(v, str) and isinstance(enc, str) and enc.lower().replace("_", "").replace("-", "") == "rot13":
                return codecs.decode(v, "rot13")
            return None
        if isinstance(node.func, ast.Attribute):
            attr, recv = node.func.attr, node.func.value
            if attr == "decode":
                v = f(recv)
                return v.decode("utf-8", "replace") if isinstance(v, bytes) else None
            if attr == "encode":
                v = f(recv)
                return v.encode() if isinstance(v, str) else None
            if attr == "join" and len(args) == 1:
                sep = f(recv)
                parts = self._str_parts(args[0], d) if isinstance(sep, str) else None
                return sep.join(parts) if parts is not None else None
        return None

    def _build_env(self, assigns: list[ast.AST]) -> None:
        counts: Counter[str] = Counter()
        singles: list[ast.Assign] = []
        for a in assigns:
            if isinstance(a, ast.Assign) and len(a.targets) == 1 and isinstance(a.targets[0], ast.Name):
                counts[a.targets[0].id] += 1
                singles.append(a)
            elif isinstance(a, (ast.AugAssign, ast.AnnAssign)) and isinstance(a.target, ast.Name):
                counts[a.target.id] += 2          # re-bound: not a stable constant
        for _ in range(3):
            for a in singles:
                name = a.targets[0].id            # type: ignore[union-attr]
                if counts[name] == 1 and name not in self.env:
                    v = self.fold(a.value)
                    if v is not None:
                        self.env[name] = v

    def _build_callable_aliases(self, assigns: list[ast.AST]) -> None:
        # Source order, several passes, and no "first answer wins": an alias defined in terms of
        # another alias (``_f = getattr(_m, "system")`` after ``_m = __import__("os")``) must be
        # re-resolved once its base is known.
        ordered = sorted((a for a in assigns if isinstance(a, ast.Assign) and len(a.targets) == 1
                          and isinstance(a.targets[0], ast.Name)), key=lambda a: (a.lineno, a.col_offset))
        for _ in range(3):
            for a in ordered:
                name = a.targets[0].id            # type: ignore[union-attr]
                q = None
                if isinstance(a.value, ast.Call):
                    q = self._resolve_callable(a.value)
                elif isinstance(a.value, (ast.Name, ast.Attribute)):
                    q = self.qualname(a.value)
                    q = q if q and "." in q else None
                if q:
                    self.callable_alias[name] = q

    def _resolve_callable(self, node: ast.AST) -> str | None:
        """``__import__("o"+"s")`` -> "os";  ``getattr(<module>, "sys"+"tem")`` -> "os.system"."""
        if not isinstance(node, ast.Call) or not node.args:
            return None
        q = self.qualname(node.func, plain=True) or ""
        if q in ("__import__", "importlib.import_module"):
            v = self.fold(node.args[0])
            return v if isinstance(v, str) and v else None
        if q == "getattr" and len(node.args) >= 2:
            base = self.qualname(node.args[0])
            attr = self.fold(node.args[1])
            if base and isinstance(attr, str) and attr.isidentifier():
                return f"{base}.{attr}"
        return None

    def src(self, node: ast.AST) -> str:
        ln = getattr(node, "lineno", 0)
        return self.lines[ln - 1] if 0 < ln <= len(self.lines) else ""

    @property
    def scope(self) -> _Scope:
        return self.scopes[-1]

    def phase(self) -> str:
        return self._scope_phase(self.scope)

    def emit(self, rule_id: str, title: str, severity: S, node: ast.AST | int, tactic: str,
             evidence: str | None = None, confidence: float = 1.0) -> None:
        line = node if isinstance(node, int) else getattr(node, "lineno", 0)
        ev = evidence if evidence is not None else (self.lines[line - 1] if 0 < line <= len(self.lines) else "")
        self.ctx.add(rule_id, title, severity, self.path, line=line, phase=self.phase(),
                     tactic=tactic, evidence=ev, confidence=confidence, via_decoding=self.via_decoding)

    # ------------------------------------------------------------------ taint
    def _tainted_expr(self, expr: ast.AST) -> bool:
        for n in ast.walk(expr):
            if isinstance(n, ast.Name) and n.id in self.tainted:
                return True
            if self.ctx.v3 and isinstance(n, ast.Attribute) and isinstance(n.value, ast.Name) \
                    and f"{n.value.id}.{n.attr}" in self.tainted:
                return True
            if isinstance(n, ast.Call):
                q = self.qualname(n.func)
                if q in DECODE_SOURCES or q in FETCH_FUNCS:
                    return True
                if isinstance(n.func, ast.Attribute) and n.func.attr in ("recv", "recvfrom"):
                    return True
        return False

    def _is_taint_source(self, call: ast.Call) -> bool:
        q = self.qualname(call.func)
        if q in DECODE_SOURCES or q in FETCH_FUNCS:
            return True
        return isinstance(call.func, ast.Attribute) and call.func.attr in ("recv", "recvfrom")

    def _taint_keys(self, target: ast.AST) -> list[str]:
        """The keys an assignment to ``target`` taints.

        v1/v2: every Name anywhere inside the target, so ``self.x = tainted`` tainted ``self`` and
        the taint cascaded to ~270 names in mypy's build.py (a verified false-positive root cause).
        v3: plain names (including tuple unpacking) and one-level attribute paths such as
        ``self.payload`` only. The base object of an attribute target is NOT tainted, so attribute-held
        payloads (``self.p = b64decode(..); exec(self.p)``) are still tracked without poisoning ``self``.
        """
        if not self.ctx.v3:
            return [nm.id for nm in ast.walk(target) if isinstance(nm, ast.Name)]
        if isinstance(target, ast.Name):
            return [target.id]
        if isinstance(target, ast.Attribute) and isinstance(target.value, ast.Name):
            return [f"{target.value.id}.{target.attr}"]
        if isinstance(target, (ast.Tuple, ast.List)):
            return [k for e in target.elts for k in self._taint_keys(e)]
        if isinstance(target, ast.Starred):
            return self._taint_keys(target.value)
        return []

    def _propagate_taint(self, assigns: list[ast.AST], calls: list[ast.Call]) -> None:
        # Most files contain no decode/fetch call at all; then nothing can be tainted.
        if not any(self._is_taint_source(c) for c in calls):
            return
        for _ in range(10):  # fixed point over the assignment nodes only, bounded
            changed = False
            for n in assigns:
                targets: list[ast.AST] = []
                value = None
                if isinstance(n, ast.Assign):
                    targets, value = list(n.targets), n.value
                elif isinstance(n, (ast.AnnAssign, ast.AugAssign)) and n.value is not None:
                    targets, value = [n.target], n.value
                elif isinstance(n, (ast.With, ast.AsyncWith)):
                    for item in n.items:
                        if item.optional_vars is not None and self._tainted_expr(item.context_expr):
                            for key in self._taint_keys(item.optional_vars):
                                if key not in self.tainted:
                                    self.tainted.add(key)
                                    changed = True
                if value is not None and self._tainted_expr(value):
                    for t in targets:
                        for key in self._taint_keys(t):
                            if key not in self.tainted:
                                self.tainted.add(key)
                                changed = True
            if not changed:
                break

    # ----------------------------------------------------------------- scopes
    def _enter(self, name: str, is_module: bool) -> None:
        self.scopes.append(_Scope(name, is_module))

    def _leave(self) -> None:
        sc = self.scopes.pop()
        self._emit_scope(sc)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._enter(node.name, False)
        self.generic_visit(node)
        self._leave()

    visit_AsyncFunctionDef = visit_FunctionDef  # type: ignore[assignment]

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        self._enter(node.name, True)   # class bodies execute at import time
        self.generic_visit(node)
        self._leave()

    def _emit_scope(self, sc: _Scope) -> None:
        ph = self._scope_phase(sc)
        conf = 1.0 if ph in ("install", "import") else 0.8
        sens = [f for f in ("cred", "env_bulk") if f in sc.flags]
        if sens and "egress" in sc.flags:
            line = min(sc.flags[f][0] for f in sens + ["egress"])
            self.scope_combos.add("exfil")
            self.ctx.add("PY-EXFIL", "Reads credentials/environment and sends data out in the same scope",
                         S.HIGH, self.path, line=line, phase=ph, tactic="T1041",
                         evidence=f"{'+'.join(sens)} + {sc.flags['egress'][1]}", confidence=conf,
                         via_decoding=self.via_decoding)
        # At install time any download-then-execute is suspicious. Elsewhere we require actual data
        # flow (the executed value derives from the fetch), because plenty of legitimate code
        # downloads a file in one function and spawns an unrelated process in the same function.
        needed = {"shell", "exec_dyn", "exec_decoded"} if ph == "install" else {"exec_decoded"}
        if "fetch" in sc.flags and (needed & set(sc.flags)):
            line = sc.flags["fetch"][0]
            self.scope_combos.add("fetch_run")
            self.ctx.add("PY-FETCH-AND-RUN", "Fetches remote content and executes in the same scope",
                         S.HIGH, self.path, line=line, phase=ph, tactic="T1105",
                         evidence=sc.flags["fetch"][1], confidence=conf, via_decoding=self.via_decoding)
        if "recon" in sc.flags and "egress" in sc.flags and ph in ("install", "import"):
            self.scope_combos.add("beacon")
            self.ctx.add("PY-BEACON", "Collects host identity and sends it out at install/import time",
                         S.MEDIUM, self.path, line=sc.flags["recon"][0], phase=ph, tactic="T1082",
                         evidence=f"{sc.flags['recon'][1]} + {sc.flags['egress'][1]}",
                         via_decoding=self.via_decoding)
        if "persist" in sc.flags and "write" in sc.flags:
            self.ctx.add("PY-PERSISTENCE", "Writes to a persistence location", S.MEDIUM, self.path,
                         line=sc.flags["persist"][0], phase=ph, tactic="T1546",
                         evidence=sc.flags["persist"][1], via_decoding=self.via_decoding)
        for k, v in sc.flags.items():
            self.file_flags.setdefault(k, v)

    # ------------------------------------------------------------------ nodes
    def visit_Constant(self, node: ast.Constant) -> None:
        if isinstance(node.value, str) and len(node.value) < 300:
            parent = self.parents.get(node)
            is_docstring = isinstance(parent, ast.Expr)
            if not is_docstring:
                if SENSITIVE_PATH_RE.search(node.value):
                    self.scope.mark("cred", node.lineno, node.value)
                    if self._install_here():
                        self.emit("PY-CRED-PATH", "References credential/secret file paths at install time",
                                  S.MEDIUM, node, "T1552.001", node.value)
                if PERSIST_RE.search(node.value):
                    self.scope.mark("persist", node.lineno, node.value)
                if self.ctx.v4:
                    if IP_LOOKUP_RE.search(node.value):
                        self.scope.mark("recon", node.lineno, "ip-lookup service")
                    if STEALER_PATH_RE.search(node.value):
                        self.scope.mark("cred", node.lineno, node.value)
                    if TOKEN_REGEX_RE.search(node.value):
                        self.emit("PY-TOKEN-STEALER", "Contains a Discord-token-matching regular expression",
                                  S.HIGH, node, "T1528", node.value[:60])
                if self.ctx.v2 and SENSITIVE_ENV_RE.match(node.value):
                    # Stealers that read only specific secret variables (rather than dumping the whole
                    # environment) were the first hole the adaptive round found.
                    self.scope.mark("cred", node.lineno, node.value)
                    if self._install_here():
                        self.emit("PY-SECRET-ENV-KEY", "References secret-bearing environment variables at install time",
                                  S.MEDIUM, node, "T1552", node.value)
        self.generic_visit(node)

    def visit_Attribute(self, node: ast.Attribute) -> None:
        if self.qualname(node) == "os.environ":
            self._check_environ(node)
        self.generic_visit(node)

    def visit_Name(self, node: ast.Name) -> None:
        if isinstance(node.ctx, ast.Load) and self.aliases.get(node.id) == "os.environ":
            self._check_environ(node)

    def _check_environ(self, node: ast.AST) -> None:
        p = self.parents.get(node)
        keyed = False
        if isinstance(p, ast.Subscript) and p.value is node:
            keyed = True
        elif isinstance(p, ast.Attribute) and p.value is node and p.attr in (
                "get", "setdefault", "pop", "__contains__", "getlist"):
            keyed = True
        elif isinstance(p, ast.Compare):
            keyed = True
        if not keyed:
            self.scope.mark("env_bulk", getattr(node, "lineno", 0), "os.environ")

    def visit_Call(self, node: ast.Call) -> None:
        qn = self.qualname(node.func) or ""
        line = node.lineno
        sc = self.scope
        if qn in FETCH_FUNCS:
            sc.mark("fetch", line, qn)
            sc.mark("egress", line, qn)
        elif qn.startswith(EGRESS_PREFIXES):
            sc.mark("egress", line, qn)
        if qn in RECON_FUNCS or (self.ctx.v4 and qn in RECON_V4):
            sc.mark("recon", line, qn)
        if self.ctx.v2:
            self._v2_call_checks(node, qn)
        if qn in CODE_EXEC_SINKS and node.args:
            self._check_exec(node)
        elif qn in SHELL_SINKS or (self.ctx.v4 and qn in SHELL_SINKS_V4):
            self._check_shell(node, qn)
        if qn == "open" or qn.endswith((".write_text", ".write_bytes")):
            if self._opens_for_write(node, qn):
                sc.mark("write", line, qn)
        elif isinstance(node.func, ast.Attribute) and node.func.attr in ("write", "writelines"):
            sc.mark("write", line, "write")
        self.generic_visit(node)

    def _v2_call_checks(self, node: ast.Call, qn: str) -> None:
        plain = self.qualname(node.func, plain=True) or ""
        hidden_sink = qn and qn != plain and (
            qn in SHELL_SINKS or qn in CODE_EXEC_SINKS or qn in FETCH_FUNCS or qn.startswith(EGRESS_PREFIXES))
        if hidden_sink:
            self.emit("PY-OBFUSCATED-CALL", f"Call to {qn} hidden behind dynamic import / getattr / aliasing",
                      S.MEDIUM, node, "T1027")
        if plain in ("__import__", "importlib.import_module") and node.args \
                and not isinstance(self.fold(node.args[0]), str):
            self.emit("PY-DYN-IMPORT", "Import of a non-constant module name", S.LOW, node, "T1027")
        if qn == "os.path.join":
            path = self.fold(node)               # os.path.join(expanduser("~"), ".aws", "credentials")
            if isinstance(path, str) and SENSITIVE_PATH_RE.search(path):
                self.scope.mark("cred", node.lineno, path)
                if self._install_here():
                    self.emit("PY-CRED-PATH", "References credential/secret file paths at install time",
                              S.MEDIUM, node, "T1552.001", path)

    def _packaged_data_ref(self, arg: ast.AST) -> tuple[str, bool] | None:
        """(file name, is_python) if ``arg`` reads a packaged data file with a constant name."""
        for n in ast.walk(arg):
            if isinstance(n, ast.Call):
                q = self.qualname(n.func) or ""
                if q in PACKAGED_DATA_SOURCES:
                    names = [v for v in (self.fold(a) for a in n.args) if isinstance(v, str)]
                    return (names[-1] if names else "", False)
                if q == "open" and n.args:
                    v = self.fold(n.args[0])
                    if isinstance(v, str):
                        return v, v.endswith(".py")
        return None

    @staticmethod
    def _opens_for_write(node: ast.Call, qn: str) -> bool:
        if qn != "open":
            return True
        mode = None
        if len(node.args) > 1 and isinstance(node.args[1], ast.Constant):
            mode = node.args[1].value
        for kw in node.keywords:
            if kw.arg == "mode" and isinstance(kw.value, ast.Constant):
                mode = kw.value.value
        return isinstance(mode, str) and any(c in mode for c in "wax+")

    # ------------------------------------------------------------------ sinks
    def _check_exec(self, node: ast.Call) -> None:
        from .dispatch import analyze_source

        arg = node.args[0]
        sc = self.scope
        folded = self.fold(arg)
        if isinstance(folded, (str, bytes)):
            text = folded.decode("utf-8", "replace") if isinstance(folded, bytes) else folded
            if text.strip() and self.depth < MAX_DEPTH:
                analyze_source(self.ctx, f"{self.ctx.real_path(self.path)}::literal", text, self.phase(),
                               lang="python", via_decoding=self.via_decoding, depth=self.depth + 1)
            return
        if self._tainted_expr(arg):
            sc.mark("exec_decoded", node.lineno, self.src(node))
            self.emit("PY-EXEC-DECODED", "Executes decoded or downloaded content", S.HIGH, node, "T1059.006")
        elif self._is_local_py_exec(arg):
            return      # exec(open("pkg/version.py").read()): the standard way setup.py reads a version
        elif self.ctx.v2 and (ref := self._packaged_data_ref(arg)) is not None:
            name, is_py = ref
            if is_py:
                return
            self.emit("PY-EXEC-DATA-FILE", "Executes the contents of a packaged non-Python data file",
                      S.HIGH, node, "T1059.006")
            if name:                                # the data file is then analysed as code (scanner.py)
                self.ctx.data_exec_targets.append((self.ctx.real_path(self.path), name, self.phase()))
        else:
            sc.mark("exec_dyn", node.lineno, self.src(node))
            # Interpreter-like libraries (IPython, Babel, template engines) exec/eval by design, so
            # on its own this only matters at install time, where nothing legitimate needs it.
            sev = S.MEDIUM if self._install_here() else S.LOW
            self.emit("PY-EXEC-DYNAMIC", "exec/eval/compile of a non-constant value", sev, node, "T1059.006")

    def _is_local_py_exec(self, arg: ast.AST) -> bool:
        """True for ``exec(open(<path ending .py>).read())`` and ``Path("x.py").read_text()`` idioms.

        The file being executed is itself Python source inside the package, so it is analysed as
        code in its own right; the exec call adds nothing. (An attacker using a non-.py name for
        the target, e.g. ``exec(open("payload.dat").read())``, does NOT match this and is still
        reported.)
        """
        for n in ast.walk(arg):
            if isinstance(n, ast.Call):
                q = self.qualname(n.func) or ""
                is_reader = q == "open" or (isinstance(n.func, ast.Attribute) and n.func.attr == "read_text")
                if is_reader:
                    pieces = list(n.args)
                    if isinstance(n.func, ast.Attribute) and n.func.attr == "read_text":
                        pieces.append(n.func.value)
                    for p in pieces:
                        for c in ast.walk(p):
                            if isinstance(c, ast.Constant) and isinstance(c.value, str) and c.value.endswith(".py"):
                                return True
        return False

    def _command_text(self, node: ast.Call) -> str | None:
        arg = node.args[0] if node.args else next(
            (k.value for k in node.keywords if k.arg in ("args", "cmd", "command")), None)
        if arg is None:
            return None
        v = self.fold(arg)
        if isinstance(v, str):
            return v
        if isinstance(arg, (ast.List, ast.Tuple)):
            parts = [self.fold(e) for e in arg.elts]
            if parts and all(isinstance(p, str) for p in parts):
                return " ".join(parts)
        return None

    def _check_shell(self, node: ast.Call, qn: str) -> None:
        sc = self.scope
        sc.mark("shell", node.lineno, qn)
        if self._install_here():
            self.emit("PY-SHELL-EXEC", "Runs a shell command during installation", S.LOW, node, "T1059.004")
        arg = node.args[0] if node.args else None
        if arg is not None and self._tainted_expr(arg):
            sc.mark("exec_decoded", node.lineno, qn)
            self.emit("PY-EXEC-DECODED", "Runs a decoded or downloaded command", S.HIGH, node, "T1059.004")
            return
        cmd = self._command_text(node)
        if cmd:
            analyze_shell(self.ctx, self.path, cmd, phase=self.phase(), via_decoding=self.via_decoding,
                          line_offset=node.lineno - 1)

    # ----------------------------------------------------------------- finish
    def finish(self) -> None:
        self._emit_scope(self.scopes.pop())   # module scope
        # setup.py-style entrypoint files: everything in them is install-time (v3: entrypoints only)
        install_like = self.file_phase == "install" and (not self.ctx.v3 or self._is_entry_file())
        # v4: a package's own __init__/__main__ also runs on import, but only the HOST-BEACON combination (identity
        # collection + network egress) is applied across functions there. Extending the credential and fetch-and-run
        # combos to it flagged a security-scanner library that merely lists sensitive paths in one place and has a
        # network helper elsewhere (a constant is not a read), so those stay confined to install-time files.
        if install_like or self._v4_import_entry():
            ff = self.file_flags
            sens = [f for f in ("cred", "env_bulk") if f in ff]
            if install_like and sens and "egress" in ff and "exfil" not in self.scope_combos:
                self.ctx.add("PY-EXFIL-FILE", "Credential/environment access and network egress in one "
                             "install/import-time file", S.HIGH, self.path,
                             line=min(ff[f][0] for f in sens + ["egress"]), phase=self.file_phase,
                             tactic="T1041", evidence=f"{'+'.join(sens)} + {ff['egress'][1]}",
                             via_decoding=self.via_decoding)
            if "recon" in ff and "egress" in ff and "beacon" not in self.scope_combos:
                self.ctx.add("PY-BEACON-FILE", "Host identity collection and network egress in one "
                             "install/import-time file", S.MEDIUM, self.path, line=ff["recon"][0],
                             phase=self.file_phase, tactic="T1082", evidence=ff["recon"][1],
                             via_decoding=self.via_decoding)
            if install_like and "fetch" in ff and ({"shell", "exec_dyn", "exec_decoded"} & set(ff)) \
                    and "fetch_run" not in self.scope_combos:
                self.ctx.add("PY-FETCH-AND-RUN-FILE", "Fetches remote content and executes it, in one "
                             "install/import-time file", S.HIGH, self.path, line=ff["fetch"][0],
                             phase=self.file_phase, tactic="T1105", evidence=ff["fetch"][1],
                             via_decoding=self.via_decoding)


def analyze_python(ctx: ScanContext, path: str, text: str, phase: str, *, via_decoding: bool = False,
                   depth: int = 0) -> None:
    if phase == "runtime" and not _TRIGGERS.search(text):
        return
    if phase != "install" and len(text) > MAX_AST_BYTES:
        # Multi-hundred-KB Python files outside the install path are almost always generated
        # data tables. Skipped for cost; noted so the gap is visible, never silent.
        ctx.notes.append(f"{path}: large non-install Python file ({len(text)//1024} KB) not AST-analysed")
        return
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")        # hostile/old code is full of invalid escapes
            tree = ast.parse(text)
    except (SyntaxError, ValueError, RecursionError, MemoryError):
        sev = S.LOW if phase in ("install", "import") else S.INFO
        if sev > S.INFO:
            ctx.add("PY-UNPARSEABLE", "Python source does not parse (obfuscation or Python 2?)", sev,
                    path, phase=phase, tactic="T1027", via_decoding=via_decoding)
        m = _FALLBACK_EXEC.search(text)
        if m:
            ctx.add("PY-EXEC-DECODED", "Executes decoded content (regex fallback; file did not parse)",
                    S.HIGH, path, line=text.count("\n", 0, m.start()) + 1, phase=phase, tactic="T1059.006",
                    evidence=short(m.group()), confidence=0.8, via_decoding=via_decoding)
        return
    try:
        a = _PyAnalyzer(ctx, path, text, tree, phase, via_decoding, depth)
        a.visit(tree)
        a.finish()
    except RecursionError:
        ctx.notes.append(f"{path}: AST too deeply nested to analyse fully")
