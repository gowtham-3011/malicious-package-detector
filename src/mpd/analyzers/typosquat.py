"""Typosquatting and name-impersonation signals (metadata only; no code is read).

A bundled list of well-known package names (``data/popular_*.txt``, ~120 each) is
illustrative, not authoritative: a production system would use live download rankings.
A name that is *not* on the list but is one edit, one homoglyph, one delimiter, or one
"-security"-style suffix away from a name that *is* gets flagged.

This is deliberately a weak signal. Plenty of legitimate packages have names near popular
ones (``pyyaml`` / ``yaml``), so on its own it earns LOW/MEDIUM; it matters when combined
with a behavioural finding.
"""

from __future__ import annotations

import re
from functools import lru_cache
from importlib import resources

from ..models import Severity as S
from .base import ScanContext

COMBO_SUFFIXES = {"security", "secure", "utils", "util", "helper", "helpers", "official", "v2", "v3",
                  "js", "py", "cli", "api", "sdk", "lib", "tools", "core", "client", "dev", "fix", "patch"}
_HOMOGLYPHS = str.maketrans({"0": "o", "1": "l", "3": "e", "5": "s", "$": "s", "@": "a"})


@lru_cache(maxsize=4)
def popular_names(ecosystem: str) -> frozenset[str]:
    text = resources.files("mpd").joinpath("data").joinpath(f"popular_{ecosystem}.txt").read_text(encoding="utf-8")
    return frozenset(normalize(line, ecosystem) for line in text.splitlines() if line.strip())


def normalize(name: str, ecosystem: str) -> str:
    n = name.strip().lower()
    if ecosystem == "pypi":
        n = re.sub(r"[-_.]+", "-", n)          # PEP 503 normalisation
    return n


def damerau_levenshtein(a: str, b: str, limit: int = 3) -> int:
    """Optimal-string-alignment distance (insert/delete/substitute/transpose), early exit at limit."""
    if abs(len(a) - len(b)) > limit:
        return limit + 1
    prev2: list[int] | None = None
    prev = list(range(len(b) + 1))
    for i in range(1, len(a) + 1):
        cur = [i] + [0] * len(b)
        for j in range(1, len(b) + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            cur[j] = min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost)
            if prev2 is not None and i > 1 and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]:
                cur[j] = min(cur[j], prev2[j - 2] + 1)
        if min(cur) > limit:
            return limit + 1
        prev2, prev = prev, cur
    return prev[-1]


def classify(name: str, ecosystem: str) -> tuple[str, str, S] | None:
    """(kind, target popular name, severity) if ``name`` impersonates a popular package."""
    if ecosystem == "npm" and name.startswith("@"):
        return None                                     # scoped names are namespaced; skip
    n = normalize(name, ecosystem)
    popular = popular_names(ecosystem)
    if not n or n in popular:
        return None
    folded = n.translate(_HOMOGLYPHS).replace("rn", "m").replace("vv", "w")
    for p in sorted(popular):
        if folded == p and n != p:
            return "homoglyph", p, S.MEDIUM
        if n.replace("-", "").replace(".", "") == p.replace("-", "").replace(".", ""):
            return "delimiter", p, S.MEDIUM
        if len(p) >= 4 and (n.startswith(p + "-") or n.startswith(p + ".")):
            if n[len(p) + 1:] in COMBO_SUFFIXES:
                return "combosquat", p, S.LOW
        if len(p) >= 4 and n.endswith("-" + p) and n[: -len(p) - 1] in COMBO_SUFFIXES:
            return "combosquat", p, S.LOW
        if abs(len(p) - len(n)) <= 1 and len(p) >= 5:
            d = damerau_levenshtein(n, p, 1)
            if d == 1:
                return "edit-distance-1", p, S.MEDIUM if len(p) >= 6 else S.LOW
    return None


def run(ctx: ScanContext) -> None:
    if not ctx.enabled("typosquat") or not ctx.pkg.name:
        return
    hit = classify(ctx.pkg.name, ctx.pkg.ecosystem)
    if hit:
        kind, target, severity = hit
        ctx.add("PKG-TYPOSQUAT", f"Name resembles popular package '{target}' ({kind})", severity,
                "<metadata>", phase="install", tactic="T1036", evidence=f"{ctx.pkg.name} ~ {target}")
