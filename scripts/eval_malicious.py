"""Evaluate the detector on REAL malicious packages from the DataDog dataset (read-only, in memory).

    python -I scripts/eval_malicious.py [--set M1]            # always run untrusted data with -I

Protocol, fixed before the first run so that nothing here can be tuned on the data:
  * operating points are the defaults (flag >= 0.35, block >= 0.60) and the threshold calibrated on the REAL
    BENIGN set A at a 1% false-positive budget (read from results/eval_results.json);
  * rule sets v1, v2, v3 are all reported, none modified after seeing this sample;
  * samples the loader cannot read are reported as "not analysable", never silently dropped;
  * ``malicious_intent`` and ``compromised_lib`` are separate groups (the latter are legitimate libraries with
    injected code, which a static scanner can only catch if the injection is conspicuous).

Nothing is extracted or executed. Output contains rule ids, counts and package names only; no payload content.
"""

from __future__ import annotations

import argparse
import json
import statistics
import sys
import time
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from evaluation.metrics import wilson_interval  # noqa: E402
from mpd.batch import scan_many  # noqa: E402
from mpd.scoring import DEFAULT_THRESHOLDS  # noqa: E402

BASE = ROOT / "data" / "malicious_real"
FLAG, BLOCK = DEFAULT_THRESHOLDS["suspicious"], DEFAULT_THRESHOLDS["malicious"]
PASSWORD = "infected"          # the dataset's documented handling password; not a secret


def prop(k: int, n: int) -> dict:
    return wilson_interval(k, n).to_dict()


def fmt(p: dict) -> str:
    return f"{p['rate']*100:.1f}% ({p['k']}/{p['n']}) [{p['ci95'][0]*100:.1f}-{p['ci95'][1]*100:.1f}]"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--set", default="M1")
    ap.add_argument("--rules", type=int, nargs="+", default=[1, 2, 3, 4], help="rule sets to evaluate")
    ap.add_argument("--tag", default="", help="suffix for the results file, so earlier results are never overwritten")
    a = ap.parse_args()
    root = BASE / a.set
    index = json.loads((root / "index.json").read_text())
    calibrated = json.loads((ROOT / "results" / "eval_results.json").read_text())
    thresholds = {f"v{r}": calibrated.get(f"calibrated_v{r}", calibrated["calibrated_v3"])["threshold_chosen_on_A_at_1pct_fpr"]
                  for r in a.rules}   # a rule set without its own calibration borrows v3's until one exists

    items = list(index.items())
    jobs = [(BASE / meta["file"], meta["group"].split("/")[0]) for _, meta in items]
    out = {"set": a.set, "protocol": {"flag": FLAG, "block": BLOCK, "calibrated_on_A_at_1pct_fpr": thresholds},
           "groups": {}, "samples": {}}
    per_rules = {}
    for rules in a.rules:
        t0 = time.time()
        res = scan_many(jobs, rules_version=rules, zip_password=PASSWORD)
        per_rules[rules] = (res, time.time() - t0)
        print(f"v{rules}: scanned {len(res)} in {time.time() - t0:.0f}s", flush=True)

    for (sha, meta), idx in zip(items, range(len(items))):
        rec = {"group": meta["group"], "package": meta["package"], "version": meta["version"], "bytes": meta["bytes"]}
        for rules in a.rules:
            _, r, err, secs = per_rules[rules][0][idx]
            if r is None:
                rec[f"v{rules}"] = {"analysable": False, "error": err[:120]}
            else:
                rec[f"v{rules}"] = {"analysable": r.n_files > 0, "score": round(r.score, 3), "verdict": r.verdict,
                                    "n_files": r.n_files, "rules": [f.rule_id for f in r.findings if f.severity >= 2][:6],
                                    "notes": [n[:90] for n in r.notes][:3], "secs": round(secs, 2)}
        out["samples"][sha] = rec

    for group in sorted({m["group"] for _, m in items}):
        recs = [r for r in out["samples"].values() if r["group"] == group]
        g = {"n": len(recs)}
        for v in [f"v{r}" for r in a.rules]:
            ok = [r[v] for r in recs if r[v].get("analysable")]
            g[v] = {
                "analysable": prop(len(ok), len(recs)),
                "flagged_of_analysable": prop(sum(x["score"] >= FLAG for x in ok), len(ok)),
                "blocked_of_analysable": prop(sum(x["score"] >= BLOCK for x in ok), len(ok)),
                "flagged_of_all": prop(sum(x["score"] >= FLAG for x in ok), len(recs)),
                f"detected_at_calibrated_{thresholds[v]}": prop(sum(x["score"] >= thresholds[v] for x in ok), len(ok)),
                "median_score": round(statistics.median([x["score"] for x in ok]), 3) if ok else None,
                "top_rules_among_flagged": Counter(rid for x in ok if x["score"] >= FLAG for rid in x["rules"]).most_common(8),
                "not_analysable_reasons": Counter((r[v].get("error") or (r[v].get("notes") or ["empty"])[0])[:60]
                                                  for r in recs if not r[v].get("analysable")).most_common(4),
            }
        out["groups"][group] = g
    (ROOT / "results").mkdir(exist_ok=True)
    (ROOT / "results" / f"malicious_eval_{a.set}{a.tag}.json").write_text(json.dumps(out, indent=1))

    print(f"\n=== REAL malicious packages, sample {a.set} (flag>={FLAG}, block>={BLOCK}) ===")
    for group, g in out["groups"].items():
        print(f"\n{group}  n={g['n']}")
        for v in [f"v{r}" for r in a.rules]:
            x = g[v]
            print(f"  {v}: analysable {fmt(x['analysable'])}")
            print(f"      flagged (of analysable) {fmt(x['flagged_of_analysable'])} | blocked {fmt(x['blocked_of_analysable'])}"
                  f" | flagged of ALL {fmt(x['flagged_of_all'])}")
            key = [k for k in x if k.startswith("detected_at_calibrated")][0]
            print(f"      at {key.split('_')[-1]} (1% FPR on real benign A): {fmt(x[key])} | median score {x['median_score']}")
        last = f"v{a.rules[-1]}"
        print(f"  {last} top rules among flagged:", g[last]["top_rules_among_flagged"])
        print(f"  {last} not analysable:", g[last]["not_analysable_reasons"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
