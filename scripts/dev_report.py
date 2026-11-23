"""Developer helper: scan the synthetic corpus and print verdicts per family.

Usage: python scripts/dev_report.py [--rules 1|2] [--split dev|heldout|adaptive|benign] [--verbose]
"""

from __future__ import annotations

import argparse
import sys
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from corpus import generate  # noqa: E402
from mpd.scanner import scan_package  # noqa: E402


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--rules", type=int, default=2)
    ap.add_argument("--split", default=None)
    ap.add_argument("--family", default=None)
    ap.add_argument("--verbose", action="store_true")
    a = ap.parse_args()
    rows = defaultdict(list)
    for s in generate():
        if a.split and s.split != a.split:
            continue
        if a.family and s.family != a.family:
            continue
        r = scan_package(s.view(), rules_version=a.rules)
        rows[(s.split, s.family, s.label)].append((s, r))
    for (split, family, label), items in rows.items():
        verdicts = [r.verdict[0].upper() for _, r in items]
        scores = [r.score for _, r in items]
        print(f"{split:9} {family:34} label={label} verdicts={''.join(verdicts)} "
              f"score min/avg/max = {min(scores):.2f}/{sum(scores)/len(scores):.2f}/{max(scores):.2f}")
        if a.verbose:
            s, r = items[0]
            for f in r.findings[:10]:
                print(f"      {f.rule_id:34} {f.severity.name:8} {f.phase:8} w={f.weight:.2f} {f.file}:{f.line}")


if __name__ == "__main__":
    main()
