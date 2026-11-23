"""Scan the real benign corpus in parallel; print verdict mix and what triggered flags.
Run isolated:  python -I scripts/scan_real.py [--rules 1|2]"""
import argparse, json, sys, time
from collections import Counter
from pathlib import Path
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from mpd.batch import scan_many


def main():
    ap = argparse.ArgumentParser(); ap.add_argument("--rules", type=int, default=2); a = ap.parse_args()
    manifest = json.loads((ROOT / "data/benign_real/manifest.json").read_text())
    jobs = [(ROOT / "data/benign_real" / m["file"], m["ecosystem"]) for m in manifest]
    t0 = time.time()
    out = scan_many(jobs, rules_version=a.rules)
    wall = time.time() - t0
    verdicts = Counter(); rows = []
    for m, (path, r, err, secs) in zip(manifest, out):
        if r is None:
            print("ERR", m["file"], err); continue
        verdicts[(m["ecosystem"], r.verdict)] += 1
        rows.append((r.score, m["ecosystem"], m["name"], secs, r))
    print(f"scanned {len(rows)} packages in {wall:.1f}s wall-clock "
          f"(sum of per-package time {sum(x[3] for x in rows):.0f}s, slowest {max(x[3] for x in rows):.1f}s)")
    print(dict(sorted(verdicts.items())))
    for score, eco, name, secs, r in sorted(rows, key=lambda x: -x[0])[:16]:
        top = ", ".join(f"{f.rule_id}[{f.phase[0]}]" for f in r.findings[:5])
        print(f"  {score:.2f} {r.verdict:10} {eco:5} {name:28} {secs:5.1f}s {top}")

if __name__ == "__main__":
    main()
