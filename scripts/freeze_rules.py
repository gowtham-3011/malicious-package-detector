"""Snapshot a rule set's scores on the synthetic corpus so it can never change silently.

    python scripts/freeze_rules.py --rules 2     # writes results/v2_frozen_scores.json

tests/test_corpus_and_freeze.py fails if a frozen rule set's scores ever drift: the before/after
comparisons in the README are only valid if the "before" is immutable."""
import argparse, json, sys
from pathlib import Path
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from corpus import generate
from mpd.scanner import scan_package

ap = argparse.ArgumentParser(); ap.add_argument("--rules", type=int, required=True); a = ap.parse_args()
scores = {f"{s.split}/{s.family}/{s.name}": round(scan_package(s.view(), rules_version=a.rules).score, 4) for s in generate()}
out = ROOT / "results" / f"v{a.rules}_frozen_scores.json"
out.write_text(json.dumps(scores, indent=1, sort_keys=True))
print(f"froze {len(scores)} scores for rule set v{a.rules} -> {out}")
