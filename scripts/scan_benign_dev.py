"""Development check of false positives for one rule set on the benign sets already seen (A, B, C).

    python -I scripts/scan_benign_dev.py --rules 4

NOT a final measurement: those sets were all inspected while earlier rule sets were built. The fresh set D is
deliberately excluded and is only scanned in the final evaluation, after the rule set is frozen.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from mpd.batch import scan_many  # noqa: E402

SETS = {"A": "benign_real", "B": "benign_real_B", "C": "benign_real_C"}


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--rules", type=int, required=True)
    a = ap.parse_args()
    base = json.loads((ROOT / "results" / "eval_results.json").read_text())["real"]
    for label, d in SETS.items():
        manifest = json.loads((ROOT / "data" / d / "manifest.json").read_text())
        jobs = [(ROOT / "data" / d / m["file"], m["ecosystem"]) for m in manifest]
        out = scan_many(jobs, rules_version=a.rules)
        rows = [(m["name"], r.score, r.verdict, [f.rule_id for f in r.findings if f.severity >= 2][:3])
                for m, (_, r, _, _) in zip(manifest, out) if r is not None]
        flagged = sorted([x for x in rows if x[1] >= 0.35], key=lambda x: -x[1])
        before = {x["name"] for x in base[f"{label}_v3"]["flagged"]}
        now = {x[0] for x in flagged}
        print(f"set {label}: v{a.rules} flags {len(flagged)}/{len(rows)} (blocked {sum(x[2] == 'malicious' for x in rows)}) | "
              f"v3 flagged {len(before)} | NEWLY flagged: {sorted(now - before)} | no longer: {sorted(before - now)}", flush=True)
        for name, score, verdict, rules in flagged:
            if name not in before:
                print(f"     new: {name:28} {score:.2f} {verdict:10} {rules}", flush=True)


if __name__ == "__main__":
    main()
