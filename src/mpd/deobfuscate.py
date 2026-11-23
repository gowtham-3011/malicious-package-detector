"""Layered decoding of encoded blobs found in package source.

Attackers hide payloads behind base64 / hex / zlib / gzip / bzip2 chains so that string
matching on the source sees only noise. We peel those layers (bounded in depth and in
output size) and hand the result back for re-analysis, exactly as an analyst would by
hand. A blob only counts as a payload if the end of the chain is text, a marshalled code
object, or an executable - random base64 (hashes, keys, images) decodes to noise and is
ignored, which is what keeps false positives down.

Decompression is capped: a 10 KB gzip that inflates to 10 GB is a bomb, not a payload.
"""

from __future__ import annotations

import base64
import bz2
import hashlib
import math
import re
import zlib
from collections import Counter
from dataclasses import dataclass

MAX_DECODED = 5_000_000
MAX_LAYERS = 5

MARSHAL_MAGIC = b"\xe3\x00\x00\x00"
EXE_MAGICS = (b"MZ", b"\x7fELF", b"\xcf\xfa\xed\xfe", b"\xca\xfe\xba\xbe")

BLOB_RE = re.compile(r"[A-Za-z0-9+/_-]{40,}={0,2}")
HEX_RE = re.compile(r"(?<![0-9a-fA-F])(?:[0-9a-fA-F]{2}){24,}(?![0-9a-fA-F])")

_PRINTABLE = frozenset(range(32, 127)) | {9, 10, 13}
# A bare URL is not code (GitHub's camo proxy hex-encodes image URLs, source maps are base64 JSON,
# and so on), so "https://" is deliberately NOT a code hint.
_CODE_HINTS = re.compile(
    rb"(?i)(import\s+\w+|def\s+\w+\(|exec\(|eval\(|require\(|function\s*\(|=>|"
    rb"curl\s|wget\s|#!/|powershell|subprocess|os\.system|child_process|socket|/bin/(?:ba)?sh|chmod\s)"
)


@dataclass(frozen=True)
class Layer:
    kind: str       # base64 | hex | decompress
    data: bytes


def shannon_entropy(data: str | bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    n = len(data)
    return -sum(c / n * math.log2(c / n) for c in counts.values())


def is_texty(b: bytes, min_len: int = 8) -> bool:
    if len(b) < min_len:
        return False
    sample = b[:4096]
    good = sum(1 for x in sample if x in _PRINTABLE)
    return good / len(sample) > 0.92


def looks_like_code(b: bytes) -> bool:
    return is_texty(b) and _CODE_HINTS.search(b[:20000]) is not None


def is_executable(b: bytes) -> bool:
    return b.startswith(EXE_MAGICS)


def sha256(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def _decompress(b: bytes) -> bytes | None:
    """Decompress gzip/zlib/bzip2 with a hard output cap; None if not compressed or a bomb."""
    try:
        if b[:2] == b"\x1f\x8b":
            d = zlib.decompressobj(16 + zlib.MAX_WBITS)
        elif len(b) > 2 and b[0] == 0x78 and b[1] in (0x01, 0x5E, 0x9C, 0xDA):
            d = zlib.decompressobj()
        elif b[:3] == b"BZh":
            bd = bz2.BZ2Decompressor()
            out = bd.decompress(b, MAX_DECODED)
            return out if bd.eof else None
        else:
            return None
        out = d.decompress(b, MAX_DECODED)
        return None if d.unconsumed_tail else out
    except (zlib.error, OSError, ValueError, EOFError):
        return None


def _decode_text_layer(t: str) -> tuple[str, bytes] | None:
    t = t.strip()
    if len(t) >= 48 and len(t) % 2 == 0 and re.fullmatch(r"[0-9a-fA-F]+", t):
        return "hex", bytes.fromhex(t)
    if len(t) >= 24 and re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", t):
        try:
            return "base64", base64.b64decode(t + "=" * (-len(t) % 4), validate=True)
        except ValueError:
            return None
    if len(t) >= 24 and re.fullmatch(r"[A-Za-z0-9_-]+={0,2}", t):
        try:
            return "base64", base64.urlsafe_b64decode(t + "=" * (-len(t) % 4))
        except ValueError:
            return None
    return None


def decode_blob(blob: str) -> tuple[list[Layer], bytes | None]:
    """Peel encoding layers off ``blob``.

    Returns (layers, payload). ``payload`` is None unless the chain ends in something
    that is plausibly a payload (text, marshalled code, or an executable).
    """
    layers: list[Layer] = []
    cur = blob.encode("ascii", errors="ignore")
    for _ in range(MAX_LAYERS):
        dec = _decompress(cur)
        if dec is not None:
            layers.append(Layer("decompress", dec))
            cur = dec
            continue
        try:
            text = cur.decode("ascii")
        except UnicodeDecodeError:
            break
        res = _decode_text_layer(text)
        if res is None or len(res[1]) > MAX_DECODED:
            break
        layers.append(Layer(res[0], res[1]))
        cur = res[1]
    if not layers:
        return [], None
    final = layers[-1].data
    if is_texty(final) or final.startswith(MARSHAL_MAGIC) or is_executable(final):
        return layers, final
    return layers, None


def find_blobs(text: str, limit: int = 50) -> list[tuple[int, str]]:
    """Candidate encoded strings in ``text`` as (offset, blob), longest first, capped."""
    found: list[tuple[int, str]] = []
    for rx in (BLOB_RE, HEX_RE):
        for m in rx.finditer(text):
            found.append((m.start(), m.group()))
    found.sort(key=lambda t: -len(t[1]))
    return found[:limit]
