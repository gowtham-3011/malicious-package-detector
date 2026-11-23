"""Honest-reporting metrics: proportions with Wilson intervals, ROC AUC, threshold-at-FPR.

Why Wilson intervals: detection and false-positive rates are proportions, often measured on small n
or near 0/1, where the normal approximation breaks (it can give negative lower bounds). The Wilson
score interval stays inside [0, 1] and behaves at the extremes. (Same approach as the prompt-injection
firewall project in this portfolio.)
"""

from __future__ import annotations

import math
from dataclasses import dataclass


@dataclass(frozen=True)
class Proportion:
    successes: int
    total: int
    low: float
    high: float

    @property
    def rate(self) -> float:
        return self.successes / self.total if self.total else 0.0

    def __str__(self) -> str:
        return f"{self.rate:.3f} [{self.low:.3f}, {self.high:.3f}] (n={self.total})"

    def to_dict(self) -> dict:
        return {"k": self.successes, "n": self.total, "rate": round(self.rate, 4),
                "ci95": [round(self.low, 4), round(self.high, 4)]}


def wilson_interval(successes: int, total: int, z: float = 1.96) -> Proportion:
    if total == 0:
        return Proportion(0, 0, 0.0, 0.0)
    p = successes / total
    denom = 1 + z * z / total
    center = (p + z * z / (2 * total)) / denom
    margin = (z * math.sqrt(p * (1 - p) / total + z * z / (4 * total * total))) / denom
    return Proportion(successes, total, max(0.0, center - margin), min(1.0, center + margin))


def auc(pos: list[float], neg: list[float]) -> float:
    """ROC AUC as P(score(pos) > score(neg)) with ties counted half (Mann-Whitney U)."""
    if not pos or not neg:
        return float("nan")
    wins = 0.0
    for p in pos:
        for n in neg:
            wins += 1.0 if p > n else 0.5 if p == n else 0.0
    return wins / (len(pos) * len(neg))


def threshold_at_fpr(neg_scores: list[float], target_fpr: float) -> float:
    """Lowest threshold t such that the fraction of negatives with score >= t is <= target_fpr.

    Chosen on DEVELOPMENT negatives so the false-positive budget is advertised honestly and then
    verified on negatives the threshold never saw.
    """
    if not neg_scores:
        return 1.0
    ordered = sorted(neg_scores, reverse=True)
    allowed = int(math.floor(target_fpr * len(ordered)))
    if allowed <= 0:
        return ordered[0] + 1e-9
    return ordered[allowed - 1] + 1e-9 if ordered[allowed - 1] == ordered[allowed] else ordered[allowed - 1]


def rate_at(scores: list[float], threshold: float) -> Proportion:
    return wilson_interval(sum(s >= threshold for s in scores), len(scores))
