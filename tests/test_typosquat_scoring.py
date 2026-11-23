from __future__ import annotations

import pytest

from mpd.analyzers.typosquat import classify, damerau_levenshtein
from mpd.models import Finding, Severity
from mpd.scoring import DEFAULT_THRESHOLDS, score_findings, verdict_for


@pytest.mark.parametrize("name,eco,kind", [
    ("reqeusts", "pypi", "edit-distance-1"),
    ("colourama", "pypi", "edit-distance-1"),
    ("urllib4", "pypi", "edit-distance-1"),
    ("req-uests", "pypi", "delimiter"),
    ("l0dash", "npm", "homoglyph"),
    ("express-security", "npm", "combosquat"),
])
def test_typosquat_detection(name, eco, kind):
    hit = classify(name, eco)
    assert hit is not None, name
    assert hit[0] == kind


@pytest.mark.parametrize("name,eco", [
    ("requests", "pypi"), ("Requests", "pypi"), ("python_dateutil", "pypi"),   # PEP 503 normalisation
    ("lodash", "npm"), ("@types/react", "npm"), ("totally-unrelated-name", "pypi"),
])
def test_legitimate_or_distant_names_not_flagged(name, eco):
    assert classify(name, eco) is None


def test_damerau_handles_transposition_and_early_exit():
    assert damerau_levenshtein("requests", "reqeusts") == 1
    assert damerau_levenshtein("abc", "xyzxyzxyz", limit=2) > 2


def _f(rule, sev, phase="install", conf=1.0):
    return Finding(rule, rule, sev, "f", phase=phase, confidence=conf)


def test_noisy_or_accumulates_but_never_exceeds_one():
    one = score_findings([_f("A", Severity.MEDIUM)])
    two = score_findings([_f("A", Severity.MEDIUM), _f("B", Severity.MEDIUM)])
    many = score_findings([_f(f"R{i}", Severity.CRITICAL) for i in range(5)])
    assert 0 < one < two < many < 1.0


def test_info_findings_carry_no_weight():
    assert score_findings([_f("A", Severity.INFO)] * 10) == 0.0


def test_repeats_of_one_rule_have_diminishing_weight():
    one = score_findings([_f("A", Severity.MEDIUM)])
    fifty = score_findings([_f("A", Severity.MEDIUM)] * 50)
    assert fifty < 1 - (1 - one) * (1 - 0.3 * 0.3 + 0.0001)      # second occurrence at 25%, the rest ignored


def test_phase_and_confidence_scale_weight():
    install = _f("A", Severity.HIGH, "install").weight
    runtime = _f("A", Severity.HIGH, "runtime").weight
    assert install > runtime > _f("A", Severity.HIGH, "runtime", 0.5).weight


def test_verdict_thresholds():
    t = DEFAULT_THRESHOLDS
    assert verdict_for(0.0) == "benign"
    assert verdict_for(t["suspicious"]) == "suspicious"
    assert verdict_for(t["malicious"]) == "malicious"
