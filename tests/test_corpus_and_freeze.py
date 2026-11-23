"""Contracts on the synthetic corpus: it is inert, it parses, v1 is frozen, and the detectors meet the
detection targets the README reports. If a rule change breaks one of these, the README is wrong."""

from __future__ import annotations

import ast
import json
import re
import warnings
from collections import defaultdict
from pathlib import Path

import pytest

from corpus import generate
from mpd.scanner import scan_package

ROOT = Path(__file__).resolve().parent.parent
SAMPLES = generate()


@pytest.fixture(scope="module")
def results():
    return {v: [(s, scan_package(s.view(), rules_version=v)) for s in SAMPLES] for v in (1, 2, 3, 4)}


def test_corpus_is_deterministic_and_sized():
    again = generate()
    assert [s.name for s in SAMPLES] == [s.name for s in again]
    by_split = defaultdict(int)
    for s in SAMPLES:
        by_split[s.split] += 1
    assert by_split == {"dev": 48, "heldout": 20, "adaptive": 27, "benign": 50}


def test_every_python_file_in_the_corpus_parses():
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        for s in SAMPLES:
            for path, content in s.files.items():
                if path.endswith(".py") and isinstance(content, str):
                    ast.parse(content)


def test_corpus_is_inert_every_host_is_reserved_or_a_fake_webhook(results):
    """No sample may reference infrastructure that could resolve and receive anything."""
    allowed_real_names = {"discord.com", "api.telegram.org"}       # only ever with zeroed/FAKE ids
    for s, r in results[2]:
        for ioc in r.iocs:
            if ioc.kind == "domain":
                assert ioc.value.endswith(".example") or ioc.value in allowed_real_names, (s.name, ioc.value)
            if ioc.kind == "webhook":
                assert re.search(r"webhooks/0{15,}\d+/FAKE|telegram\.org/bot0", ioc.value), (s.name, ioc.value)


def test_no_sample_contains_realistic_secrets():
    pattern = re.compile(r"AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{36}|xox[bp]-[0-9A-Za-z-]{10,}|-----BEGIN [A-Z ]*PRIVATE KEY")
    for s in SAMPLES:
        for content in s.files.values():
            if isinstance(content, str):
                assert not pattern.search(content), s.name


@pytest.mark.parametrize("version", [1, 2, 3, 4])
def test_earlier_rule_sets_are_frozen(results, version):
    """Each before/after comparison is only valid if the 'before' rule set never changes after its freeze."""
    frozen = json.loads((ROOT / "results" / f"v{version}_frozen_scores.json").read_text())
    for s, r in results[version]:
        key = f"{s.split}/{s.family}/{s.name}"
        assert round(r.score, 4) == frozen[key], (version, key)


def test_v3_matches_v2_on_the_synthetic_corpus(results):
    """The v3 false-positive fixes must not cost any synthetic detection."""
    v2 = {s.name: r.verdict for s, r in results[2]}
    for s, r in results[3]:
        if s.label == 1:
            assert (r.verdict != "benign") >= (v2[s.name] != "benign"), s.name


def test_dev_and_heldout_malicious_all_flagged_by_both_rule_sets(results):
    for v in (1, 2):
        missed = [s.family for s, r in results[v] if s.label == 1 and s.split in ("dev", "heldout") and r.verdict == "benign"]
        assert not missed, (v, missed)


def test_adaptive_round_improves_detection_and_leaves_a_documented_gap(results):
    def flagged(v):
        rows = [(s, r) for s, r in results[v] if s.split == "adaptive"]
        return sum(r.verdict != "benign" for _, r in rows), len(rows)

    f1, n = flagged(1)
    f2, _ = flagged(2)
    assert f1 <= 4 and f2 >= 24 and n == 27
    still_missed = {s.family for s, r in results[2] if s.split == "adaptive" and r.verdict == "benign"}
    assert still_missed == {"a2_split_across_files"}       # cross-file data flow: out of scope, documented


def test_easy_benign_packages_are_never_flagged(results):
    for v in (1, 2):
        wrongly = [s.family for s, r in results[v] if s.split == "benign" and not s.hard and r.verdict != "benign"]
        assert not wrongly, wrongly


def test_known_hard_negative_failure_is_real_and_documented(results):
    flagged = {s.family for s, r in results[2] if s.split == "benign" and r.verdict != "benign"}
    assert flagged == {"vendored_build"}       # download-then-make in setup.py: genuinely ambiguous


def test_v2_does_not_regress_dev_or_heldout_scores(results):
    v1 = {s.name: r.score for s, r in results[1]}
    for s, r in results[2]:
        if s.split in ("dev", "heldout"):
            assert r.score >= v1[s.name] - 0.1, (s.name, v1[s.name], r.score)


def test_v4_matches_v3_on_the_synthetic_corpus(results):
    """v4's real-malware gains must not cost synthetic detection or add a synthetic false positive."""
    v3 = {s.name: r.verdict for s, r in results[3]}
    for s, r in results[4]:
        if s.label == 1:
            assert (r.verdict != "benign") >= (v3[s.name] != "benign"), s.name
        else:
            assert (r.verdict != "benign") <= (v3[s.name] != "benign"), s.name
