"""Snapshot rule-set v1's scores on the synthetic corpus. After this is committed, v1 must not change:
tests/test_v1_frozen.py fails if it does, because the before/after adaptive comparison depends on it."""
import json, sys
from pathlib import Path
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from corpus import generate
from mpd.scanner import scan_package
scores = {}
for s in generate():
    r = scan_package(s.view(), rules_version=1)
    scores[f"{s.split}/{s.family}/{s.name}"] = round(r.score, 4)
out = ROOT / "results" / "v1_frozen_scores.json"
out.write_text(json.dumps(scores, indent=1, sort_keys=True))
print(f"froze {len(scores)} scores -> {out}")
