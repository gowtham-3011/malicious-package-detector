"""Find encoded blobs, peel their layers, and re-analyse what comes out.

This is the "reverse-engineer the obfuscation" step. A decoded payload is not just
reported: it is fed back through the full analyzer stack (as Python, JavaScript or shell,
whichever it is), so a dropper hidden under two layers of encoding is judged by what it
*does*, not by how it looks. The SHA-256 of every decoded payload is recorded as an IoC,
because the same payload re-used across packages is how campaigns get linked.
"""

from __future__ import annotations

from ..deobfuscate import (
    MARSHAL_MAGIC, Layer, decode_blob, find_blobs, is_executable, looks_like_code, sha256,
)
from ..models import Severity as S
from .base import MAX_DEPTH, ScanContext


def handle_payload(ctx: ScanContext, path: str, payload: bytes, layers: list[Layer], *,
                   line: int, phase: str, depth: int) -> None:
    """Report a decoded payload and recursively analyse it."""
    from .dispatch import analyze_source  # local import: dispatch imports this module

    real = ctx.real_path(path)
    ctx.add_ioc("payload_sha256", sha256(payload), real, via_decoding=True)
    chain = "→".join(layer.kind for layer in layers)
    if payload.startswith(MARSHAL_MAGIC):
        ctx.add("OBF-MARSHAL-PAYLOAD", "Encoded Python bytecode payload", S.HIGH, real, line=line,
                phase=phase, tactic="T1027", evidence=chain)
        return
    if is_executable(payload):
        ctx.add("OBF-EMBEDDED-EXECUTABLE", "Encoded executable payload", S.HIGH, real, line=line,
                phase=phase, tactic="T1027", evidence=chain)
        return
    decoded = payload.decode("utf-8", errors="replace")
    vpath = f"{real}::decoded{depth + 1}"
    before = len(ctx.findings)
    analyze_source(ctx, vpath, decoded, phase, via_decoding=True, depth=depth + 1)
    inner = [f for f in ctx.findings[before:] if f.via_decoding]
    if any(f.severity >= S.MEDIUM for f in inner):
        severity, kind = S.HIGH, "malicious-looking code"
    elif looks_like_code(payload):
        severity, kind = S.MEDIUM, "code"
    else:
        severity, kind = S.LOW, "text"
    ctx.add("OBF-ENCODED-PAYLOAD", f"Encoded payload ({chain}) decodes to {kind}", severity, real,
            line=line, phase=phase, tactic="T1027", evidence=decoded[:120])


def scan_blobs(ctx: ScanContext, path: str, text: str, phase: str, depth: int) -> None:
    if depth >= MAX_DEPTH:
        return
    real = ctx.real_path(path)
    for offset, blob in find_blobs(text):
        layers, payload = decode_blob(blob)
        if payload is None:
            continue
        line = text.count("\n", 0, offset) + 1
        handle_payload(ctx, path if "::" in path else real, payload, layers,
                       line=line, phase=phase, depth=depth)
