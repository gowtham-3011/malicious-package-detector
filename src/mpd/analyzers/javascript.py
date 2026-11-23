"""Pattern analysis for JavaScript (npm packages).

There is no JS parser in the standard library, so this works on the source text after
blanking out comments. It is weaker than the Python AST analyzer and says so in the README:
no scopes, no real data flow. Combinations are therefore evaluated per *file*, and the
severities are tuned a notch lower to compensate.
"""

from __future__ import annotations

import re

from ..models import Severity as S
from .base import ScanContext
from .python_ast import PERSIST_RE, SENSITIVE_PATH_RE
from .shell import analyze_shell

_BLOCK_COMMENT = re.compile(r"/\*.*?\*/", re.S)
_LINE_COMMENT = re.compile(r"(?m)^[ \t]*//.*$")

_STR = r"""(?:'[^'\n]*'|"[^"\n]*"|`[^`]*`)"""
_DECODE_EXPR = (r"(?:atob\s*\(|Buffer\.from\s*\([^;]*?['\"](?:base64|hex)['\"]|"
                r"String\.fromCharCode\s*\(|unescape\s*\()")

RE_DECODED_ASSIGN = re.compile(
    r"\b(?:const|let|var)\s+(\w+)\s*=\s*" + _DECODE_EXPR)
RE_EVAL_DIRECT_DECODED = re.compile(
    r"\b(?:eval|new\s+Function|Function|vm\.runIn\w+)\s*\(\s*(?:[^;]{0,120}?)" + _DECODE_EXPR)
RE_EVAL_DYNAMIC = re.compile(r"\b(?:eval|new\s+Function)\s*\(\s*(?![\"'`])")
RE_CHILD_PROCESS = re.compile(
    r"require\(\s*['\"](?:node:)?child_process['\"]\s*\)|from\s+['\"](?:node:)?child_process['\"]")
RE_EXEC_CALL = re.compile(r"\b(?:exec|execSync|spawn|spawnSync|execFile|execFileSync)\s*\(")
RE_EXEC_LITERAL = re.compile(r"\b(?:exec|execSync)\s*\(\s*(" + _STR + r")")
RE_EXEC_NONLITERAL = re.compile(
    r"\b(?:exec|execSync|spawn|spawnSync|execFile|execFileSync)\s*\(\s*(?:(?![\"'`])|`[^`]*\$\{)")
RE_EGRESS = re.compile(
    r"\bhttps?\.(?:request|get)\s*\(|\bfetch\s*\(|\baxios(?:\.\w+)?\s*\(|\bXMLHttpRequest\b|"
    r"\bgot(?:\.\w+)?\s*\(|\bnet\.(?:connect|createConnection)\b|\bdns\.(?:lookup|resolve\w*)\s*\(|"
    r"\bnew\s+WebSocket\s*\(|require\(\s*['\"](?:request|node-fetch|axios|got|superagent)['\"]\s*\)")
RE_FETCH = re.compile(r"\bhttps?\.get\s*\(|\bfetch\s*\(|\baxios\.get\s*\(")
RE_ENV_BULK = re.compile(
    # Only explicit serialisation/enumeration of the whole environment counts. Destructuring or
    # passing process.env to a child process is everywhere in legitimate code.
    r"JSON\.stringify\(\s*(?:\{\s*\.\.\.\s*)?process\.env|Object\.(?:keys|entries|values)\(\s*process\.env")
RE_RECON = re.compile(r"\bos\.(?:userInfo|hostname|networkInterfaces|homedir)\s*\(")
RE_OBFUSCATOR = re.compile(r"\b_0x[0-9a-f]{4,6}\b")
RE_HEX_ESCAPES = re.compile(r"\\x[0-9a-fA-F]{2}")
RE_FS_WRITE = re.compile(r"\bfs\.(?:appendFile|writeFile)(?:Sync)?\s*\(")
RE_STRINGS = re.compile(_STR)


def _blank_comments(text: str) -> str:
    def blank(m: re.Match[str]) -> str:
        return re.sub(r"[^\n]", " ", m.group())
    return _LINE_COMMENT.sub(blank, _BLOCK_COMMENT.sub(blank, text))


def _line(text: str, pos: int) -> int:
    return text.count("\n", 0, pos) + 1


_CONCAT = re.compile(r"""(['"])([^'"\\\n]*)\1\s*\+\s*\1([^'"\\\n]*)\1""")
_BRACKET_PROP = re.compile(r"""\[\s*['"]([A-Za-z_$][\w$]*)['"]\s*\]""")
RE_SENSITIVE_ENV = re.compile(
    r"process\.env(?:\.|\[\s*['\"])(?:AWS_SECRET_ACCESS_KEY|AWS_ACCESS_KEY_ID|AWS_SESSION_TOKEN|GITHUB_TOKEN|"
    r"GH_TOKEN|NPM_TOKEN|NODE_AUTH_TOKEN|PYPI_TOKEN|SSH_AUTH_SOCK|DOCKER_PASSWORD|SLACK_TOKEN|"
    r"AZURE_CLIENT_SECRET|GOOGLE_APPLICATION_CREDENTIALS|KUBECONFIG|OPENAI_API_KEY|ANTHROPIC_API_KEY|"
    r"HF_TOKEN|GITLAB_TOKEN)\b")


# --- rule set v4: forms of require() that hide network and process calls from the literal patterns ---------
_REQ_MODS = r"(?:node:)?(?:https?|net|dns|child_process|tls|dgram)"
RE_ALIAS_REQ = re.compile(r"\b(?:const|let|var)\s+(\w+)\s*=\s*require\(\s*['\"](" + _REQ_MODS + r")['\"]\s*\)")
RE_IMPORT_ALIAS = re.compile(r"\bimport\s+(?:\*\s+as\s+)?(\w+)\s+from\s+['\"](" + _REQ_MODS + r")['\"]")
RE_DESTRUCTURED = re.compile(r"\b(?:const|let|var)\s*\{([^}]*)\}\s*=\s*require\(\s*['\"](" + _REQ_MODS + r")['\"]\s*\)")
RE_INLINE_REQ_CALL = re.compile(r"require\(\s*['\"](?:node:)?(?:https?|net|dns|tls|dgram)['\"]\s*\)\s*\.\s*\w+\s*\(")
RE_EGRESS_METHODS = r"(?:request|get|post|put|connect|createConnection|lookup|resolve\w*|Socket|send)"
RE_RECON_V4 = re.compile(r"process\.cwd\(\)|__dirname|\bos\w*\.(?:platform|arch|release|cpus|tmpdir)\s*\(")
RE_STEALER_PATH = re.compile(
    r"(?i)local storage[/\\]leveldb|login data|google[/\\]chrome[/\\]user data|[/\\]discord(?:canary|ptb)?[/\\]|"
    r"mozilla[/\\]firefox[/\\]profiles|telegram desktop[/\\]tdata|exodus[/\\]exodus\.wallet|electrum[/\\]wallets|"
    r"bravesoftware[/\\]brave-browser|microsoft[/\\]edge[/\\]user data")
RE_TOKEN_REGEX = re.compile(r"\{24\}\\?\.[^\n]{0,20}\{6\}|mfa\\?\.\[")


def _v4_alias_egress(src: str) -> tuple[bool, str]:
    """Network/process calls through an alias, destructured name, or inline require()."""
    m = RE_INLINE_REQ_CALL.search(src)
    if m:
        return True, m.group()
    names: set[str] = set()
    for rx in (RE_ALIAS_REQ, RE_IMPORT_ALIAS):
        for a in rx.finditer(src):
            if not a.group(2).endswith("child_process"):
                names.add(a.group(1))
    if names:
        m = re.search(r"\b(?:" + "|".join(map(re.escape, names)) + r")\.\s*" + RE_EGRESS_METHODS + r"\s*\(", src)
        if m:
            return True, m.group()
    for d in RE_DESTRUCTURED.finditer(src):
        if d.group(2).endswith("child_process"):
            continue
        for fn in (x.strip().split(":")[-1].strip() for x in d.group(1).split(",")):
            if fn and re.fullmatch(RE_EGRESS_METHODS, fn) and re.search(r"(?<![.\w])" + re.escape(fn) + r"\s*\(", src):
                return True, fn + "("
    return False, ""


def _fold_js(src: str) -> str:
    """v2: undo the cheapest string-splitting tricks so the literal-matching rules can see through
    them. ``require('child' + '_process')`` -> ``require('child_process')`` and
    ``cp['ex' + 'ecSync'](...)`` -> ``cp.execSync(...)``. Newlines are never touched, so line numbers
    are preserved."""
    for _ in range(12):
        new = _CONCAT.sub(lambda m: f"{m.group(1)}{m.group(2)}{m.group(3)}{m.group(1)}", src)
        if new == src:
            break
        src = new
    return _BRACKET_PROP.sub(r".\1", src)


def analyze_js(ctx: ScanContext, path: str, text: str, phase: str, *, via_decoding: bool = False,
               depth: int = 0) -> None:
    src = _blank_comments(text)
    if ctx.v2:
        src = _fold_js(src)
    add = lambda rule, title, sev, pos, tactic, ev, conf=1.0: ctx.add(  # noqa: E731
        rule, title, sev, path, line=_line(src, pos), phase=phase, tactic=tactic, evidence=ev,
        confidence=conf, via_decoding=via_decoding)
    conf = 1.0 if phase in ("install", "import") else 0.8
    flags: dict[str, tuple[int, str]] = {}

    # --- decoded -> eval: the classic dropper -------------------------------------------
    decoded_names = {m.group(1) for m in RE_DECODED_ASSIGN.finditer(src)}
    m = RE_EVAL_DIRECT_DECODED.search(src)
    if not m and decoded_names:
        names = "|".join(map(re.escape, decoded_names))
        m = re.search(r"\b(?:eval|new\s+Function|Function|vm\.runIn\w+)\s*\(\s*(?:" + names + r")\b", src)
    if m:
        flags["exec_decoded"] = (m.start(), m.group())
        add("JS-EXEC-DECODED", "Executes decoded content", S.HIGH, m.start(), "T1059.007", m.group())
    else:
        m = RE_EVAL_DYNAMIC.search(src)
        if m:
            flags["exec_dyn"] = (m.start(), m.group())
            add("JS-EXEC-DYNAMIC", "eval/new Function of a non-constant value",
                S.MEDIUM if phase in ("install", "import") else S.LOW, m.start(), "T1059.007", m.group())

    # --- child_process ------------------------------------------------------------------
    uses_cp = RE_CHILD_PROCESS.search(src)
    ex = RE_EXEC_CALL.search(src) if uses_cp else None
    if uses_cp and ex:
        if phase == "install":
            add("JS-CHILD-PROCESS", "Spawns processes during installation", S.LOW, ex.start(),
                "T1059.004", ex.group())
        for lit in RE_EXEC_LITERAL.finditer(src):
            analyze_shell(ctx, path, lit.group(1)[1:-1], phase=phase, via_decoding=via_decoding,
                          line_offset=_line(src, lit.start()) - 1)
        # Running a literal binary (spawn('git', ...)) is not "running what was fetched".
        # Only a command that is computed at runtime makes fetch-then-run plausible.
        dyn = RE_EXEC_NONLITERAL.search(src)
        if dyn:
            flags["shell"] = (dyn.start(), dyn.group())

    # --- network / secrets ----------------------------------------------------------------
    m = RE_EGRESS.search(src)
    if m:
        flags["egress"] = (m.start(), m.group())
    m = RE_FETCH.search(src)
    if m:
        flags["fetch"] = (m.start(), m.group())
    for s in RE_STRINGS.finditer(src):
        body = s.group()[1:-1]
        if len(body) < 300 and SENSITIVE_PATH_RE.search(body):
            flags.setdefault("cred", (s.start(), body))
        if len(body) < 300 and PERSIST_RE.search(body):
            flags.setdefault("persist", (s.start(), body))
    m = RE_ENV_BULK.search(src)
    if m:
        flags["env_bulk"] = (m.start(), m.group())
    if ctx.v2:
        m = RE_SENSITIVE_ENV.search(src)
        if m:
            flags.setdefault("cred", (m.start(), m.group()))
            if phase == "install":
                add("JS-SECRET-ENV-KEY", "References secret-bearing environment variables at install time",
                    S.MEDIUM, m.start(), "T1552", m.group())
    m = RE_RECON.search(src)
    if m:
        flags["recon"] = (m.start(), m.group())
    m = RE_FS_WRITE.search(src)
    if m:
        flags["write"] = (m.start(), m.group())

    if ctx.v4:
        if "egress" not in flags:
            hit, ev = _v4_alias_egress(src)
            if hit:
                flags["egress"] = (src.find(ev) if ev in src else 0, ev)
        m = RE_RECON_V4.search(src)
        if m and "recon" not in flags:
            flags["recon"] = (m.start(), m.group())
        m = RE_STEALER_PATH.search(src)
        if m:
            flags.setdefault("cred", (m.start(), m.group()))
        m = RE_TOKEN_REGEX.search(src)
        if m:
            add("JS-TOKEN-STEALER", "Contains a Discord-token-matching regular expression", S.HIGH, m.start(),
                "T1528", m.group()[:60])
    sens = [f for f in ("cred", "env_bulk") if f in flags]
    if sens and "egress" in flags:
        pos = min(flags[f][0] for f in sens + ["egress"])
        add("JS-EXFIL", "Reads credentials/environment and sends data out", S.HIGH, pos, "T1041",
            f"{'+'.join(sens)} + {flags['egress'][1]}", conf)
    if "recon" in flags and "egress" in flags and phase in ("install", "import"):
        add("JS-BEACON", "Collects host identity and sends it out at install/import time", S.MEDIUM,
            flags["recon"][0], "T1082", f"{flags['recon'][1]} + {flags['egress'][1]}")
    run_signal = "exec_decoded" in flags or (phase in ("install", "import") and {"shell", "exec_dyn"} & set(flags))
    if "fetch" in flags and run_signal:
        add("JS-FETCH-AND-RUN", "Fetches remote content and executes it", S.HIGH, flags["fetch"][0],
            "T1105", flags["fetch"][1], conf)
    if "persist" in flags and "write" in flags:
        add("JS-PERSISTENCE", "Writes to a persistence location", S.MEDIUM, flags["persist"][0],
            "T1546", flags["persist"][1])
    if "cred" in flags and phase == "install":
        add("JS-CRED-PATH", "References credential/secret file paths at install time", S.MEDIUM,
            flags["cred"][0], "T1552.001", flags["cred"][1])

    # --- obfuscation ----------------------------------------------------------------------
    # `_0x1a2b`-style identifiers are specific to javascript-obfuscator. Hex escapes alone are not:
    # minified bundles carry thousands of them in Unicode tables, so they only earn a LOW signal.
    n_obf = len(RE_OBFUSCATOR.findall(src))
    if n_obf >= 8:
        add("JS-OBFUSCATED", "Machine-obfuscated JavaScript (javascript-obfuscator style)", S.MEDIUM,
            0, "T1027", f"{n_obf} _0x identifiers")
    elif len(RE_HEX_ESCAPES.findall(src)) >= 200:
        add("JS-HEX-ESCAPES", "Heavy use of hex-escaped string literals", S.LOW, 0, "T1027")
