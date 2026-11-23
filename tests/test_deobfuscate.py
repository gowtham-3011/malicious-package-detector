from __future__ import annotations

import base64
import zlib

from mpd.deobfuscate import MARSHAL_MAGIC, decode_blob, find_blobs, shannon_entropy


def b64(b: bytes) -> str:
    return base64.b64encode(b).decode()


def test_base64_of_code_is_a_payload():
    code = b"import os\nos.system('echo hi')\n"
    layers, payload = decode_blob(b64(code) * 1)
    assert payload == code and [l.kind for l in layers] == ["base64"]


def test_layered_base64_zlib_base64():
    code = b"import subprocess\nsubprocess.run(['id'])\n" * 3
    blob = b64(zlib.compress(b64(code).encode()))
    layers, payload = decode_blob(blob)
    assert payload == code
    assert [l.kind for l in layers] == ["base64", "decompress", "base64"]


def test_hex_payload():
    code = b"exec('print(1)')  # padding padding padding"
    _, payload = decode_blob(code.hex())
    assert payload == code


def test_random_base64_is_not_a_payload():
    # hashes, keys and images decode to noise; reporting them would drown the signal
    _, payload = decode_blob(b64(bytes(range(256)) * 2))
    assert payload is None


def test_png_like_binary_is_not_a_text_payload():
    _, payload = decode_blob(b64(b"\x89PNG\r\n\x1a\n" + bytes(range(200))))
    assert payload is None


def test_marshal_header_counts_as_payload():
    _, payload = decode_blob(b64(MARSHAL_MAGIC + bytes(60)))
    assert payload is not None and payload.startswith(MARSHAL_MAGIC)


def test_decompression_bomb_is_refused_not_inflated():
    bomb = b64(zlib.compress(b"A" * 60_000_000))        # ~60 KB of base64, 60 MB when inflated
    layers, payload = decode_blob(bomb)
    assert payload is None


def test_find_blobs_is_bounded_and_longest_first():
    text = " ".join(b64(bytes([i]) * 60) for i in range(200))
    found = find_blobs(text, limit=50)
    assert len(found) == 50
    assert len(found[0][1]) >= len(found[-1][1])


def test_entropy_orders_random_above_text():
    assert shannon_entropy("aaaaaaaa") < shannon_entropy("hello world") < shannon_entropy(bytes(range(256)))
