"""Optional YARA layer. Degrades gracefully when ``yara-python`` is not installed."""

from __future__ import annotations

from functools import lru_cache
from importlib import resources

from ..models import Severity as S
from .base import ScanContext
from .dispatch import is_binary

try:  # optional dependency
    import yara  # type: ignore
except ImportError:  # pragma: no cover - exercised only when yara is absent
    yara = None

_SEV = {"info": S.INFO, "low": S.LOW, "medium": S.MEDIUM, "high": S.HIGH, "critical": S.CRITICAL}


@lru_cache(maxsize=1)
def _rules():
    if yara is None:
        return None
    src = resources.files("mpd").joinpath("rules").joinpath("supply_chain.yar").read_text(encoding="utf-8")
    return yara.compile(source=src)


def available() -> bool:
    return yara is not None


def _applies(tags: list[str], path: str) -> bool:
    low = path.lower()
    if not tags:
        return True
    if "python" in tags:
        return low.endswith((".py", ".pyw"))
    if "js" in tags:
        return low.endswith((".js", ".cjs", ".mjs")) or low.endswith("package.json")
    if "pth" in tags:
        return low.endswith(".pth")
    return True


def run(ctx: ScanContext) -> None:
    if not ctx.enabled("yara"):
        return
    rules = _rules()
    if rules is None:
        ctx.notes.append("yara-python not installed: YARA layer skipped")
        return
    for path, data in ctx.pkg.files.items():
        if is_binary(path, data):
            continue
        try:
            matches = rules.match(data=data)
        except yara.Error:  # pragma: no cover
            continue
        for m in matches:
            if not _applies(list(m.tags), path):
                continue
            meta = m.meta
            ctx.add(f"YARA-{m.rule}", str(meta.get("title", m.rule)),
                    _SEV.get(str(meta.get("severity", "medium")), S.MEDIUM), path,
                    tactic=str(meta.get("tactic", "")), confidence=0.8,
                    evidence=f"rule {m.rule}")
