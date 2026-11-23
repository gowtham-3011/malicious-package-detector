"""Route a piece of source text to the right analyzers."""

from __future__ import annotations

from .base import MAX_DEPTH, ScanContext, guess_language
from .blobs import scan_blobs
from .infra import scan_infra
from .javascript import analyze_js
from .python_ast import analyze_python
from .shell import analyze_shell

MAX_TEXT_BLOB_SCAN = 300_000
PY_EXT = (".py", ".pyw")
JS_EXT = (".js", ".cjs", ".mjs", ".jsx", ".ts")
SH_EXT = (".sh", ".bash", ".ps1", ".bat", ".cmd")
BINARY_EXT = (".png", ".jpg", ".jpeg", ".gif", ".ico", ".svg", ".woff", ".woff2", ".ttf", ".eot",
              ".pdf", ".zip", ".gz", ".whl", ".so", ".pyd", ".dll", ".dylib", ".node", ".exe", ".pyc")


def is_binary(path: str, data: bytes) -> bool:
    return path.lower().endswith(BINARY_EXT) or b"\x00" in data[:2048]


def language_for(path: str, text: str) -> str:
    low = path.lower()
    if low.endswith(PY_EXT):
        return "python"
    if low.endswith(JS_EXT):
        return "js"
    if low.endswith(SH_EXT):
        return "shell"
    head = text[:120]
    if head.startswith("#!"):
        first = head.splitlines()[0]
        if "python" in first:
            return "python"
        if "node" in first:
            return "js"
        return "shell"
    return "text"


def analyze_source(ctx: ScanContext, path: str, text: str, phase: str, *, lang: str | None = None,
                   via_decoding: bool = False, depth: int = 0) -> None:
    if depth > MAX_DEPTH:
        return
    lang = lang or (guess_language(text) if via_decoding else language_for(path, text))
    if lang == "python" and ctx.enabled("python"):
        analyze_python(ctx, path, text, phase, via_decoding=via_decoding, depth=depth)
    elif lang == "js" and ctx.enabled("js"):
        analyze_js(ctx, path, text, phase, via_decoding=via_decoding, depth=depth)
    elif lang == "shell":
        analyze_shell(ctx, path, text, phase=phase, via_decoding=via_decoding)
    # Huge non-code files (generated tables, vendored data) are not where droppers hide and cost
    # a lot to regex-scan. Executable-looking languages are always scanned in full.
    if lang == "text" and not via_decoding and len(text) > MAX_TEXT_BLOB_SCAN and phase == "runtime":
        return
    if ctx.enabled("blobs"):
        scan_blobs(ctx, path, text, phase, depth)
    if ctx.enabled("infra"):
        scan_infra(ctx, path, text, via_decoding)
