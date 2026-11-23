"""Turn a bag of findings into one score and a verdict.

Model: a noisy-OR. Each finding carries a probability-like weight
(severity x phase x confidence). The package score is ``1 - prod(1 - w)``, so independent
weak signals accumulate toward certainty but no number of them can exceed 1, and one
strong signal is not diluted by a pile of benign ones.

Two guards against the failure mode that wrecks naive scanners on real code:
  * Repeats of the same rule across a package count with strongly diminishing weight
    (a big legitimate library has ``eval`` in thirty files; that is not thirty pieces of
    evidence).
  * INFO findings carry zero weight; they exist to explain, not to accuse.
"""

from __future__ import annotations

from collections import defaultdict

from .models import Finding

DEFAULT_THRESHOLDS = {"suspicious": 0.35, "malicious": 0.60}
_REPEAT_DISCOUNTS = (1.0, 0.25)      # first occurrence full weight, second 25%, the rest ignored


def effective_weights(findings: list[Finding]) -> list[float]:
    by_rule: dict[str, list[float]] = defaultdict(list)
    for f in findings:
        by_rule[f.rule_id].append(f.weight)
    out: list[float] = []
    for weights in by_rule.values():
        weights.sort(reverse=True)
        out.extend(w * d for w, d in zip(weights, _REPEAT_DISCOUNTS))
    return out


def score_findings(findings: list[Finding]) -> float:
    p_clean = 1.0
    for w in effective_weights(findings):
        p_clean *= 1.0 - min(max(w, 0.0), 0.99)
    return 1.0 - p_clean


def verdict_for(score: float, thresholds: dict[str, float] | None = None) -> str:
    t = thresholds or DEFAULT_THRESHOLDS
    if score >= t["malicious"]:
        return "malicious"
    if score >= t["suspicious"]:
        return "suspicious"
    return "benign"
