"""End-to-end evaluation. Run isolated (real packages are untrusted files):

    python -I evaluation/run_eval.py            # full run, ~5 minutes on a 16-core machine
    python -I evaluation/run_eval.py --quick    # synthetic corpus only

Writes results/eval_results.json and results/eval_report.md.

What is measured, and what is deliberately NOT claimed:
  * Detection on SYNTHETIC malicious families (dev / held-out / adaptive). These are inert samples
    written by the same author as the rules; the report says so.
  * False positives on REAL benign packages. Set A (the development sample) was inspected while the
    rules were built; set B was fetched afterwards, never scanned before this run, and no rule was
    changed after seeing it. Set B is the number to trust.
  * NO claim is made about real malware: none was used. See the README for how to run the scanner
    against a malicious-package dataset in an isolated environment.
"""

from __future__ import annotations

import argparse
import json
import statistics
import sys
import time
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from corpus import generate  # noqa: E402
from evaluation.metrics import auc, rate_at, threshold_at_fpr, wilson_interval  # noqa: E402
from mpd.batch import scan_many  # noqa: E402
from mpd.scanner import ALL_GROUPS, scan_package  # noqa: E402
from mpd.scoring import DEFAULT_THRESHOLDS  # noqa: E402

FLAG = DEFAULT_THRESHOLDS["suspicious"]
BLOCK = DEFAULT_THRESHOLDS["malicious"]


def _prop(scores: list[float], t: float) -> dict:
    return rate_at(scores, t).to_dict()


def synthetic(rules: int, disabled: frozenset[str] = frozenset()):
    rows = []
    for s in generate():
        r = scan_package(s.view(), rules_version=rules, disabled=disabled)
        rows.append((s, r))
    return rows


def summarise_synthetic(rows) -> dict:
    out: dict = {"families": {}, "splits": {}}
    by_family = defaultdict(list)
    by_split = defaultdict(list)
    for s, r in rows:
        by_family[(s.split, s.family)].append(r.score)
        by_split[s.split].append(r.score)
    for (split, fam), scores in by_family.items():
        out["families"][f"{split}/{fam}"] = {"flag": _prop(scores, FLAG), "block": _prop(scores, BLOCK),
                                             "mean_score": round(statistics.mean(scores), 3)}
    for split, scores in by_split.items():
        out["splits"][split] = {"flag": _prop(scores, FLAG), "block": _prop(scores, BLOCK)}
    hard = [r.score for s, r in rows if s.split == "benign" and s.hard]
    out["benign_hard_negatives"] = {"flag": _prop(hard, FLAG), "block": _prop(hard, BLOCK)}
    out["flagged_benign"] = sorted({f"{s.family}" for s, r in rows if s.split == "benign" and r.score >= FLAG})
    return out


def real_set(name: str, rules: int):
    base = ROOT / "data" / name
    manifest = json.loads((base / "manifest.json").read_text())
    jobs = [(base / m["file"], m["ecosystem"]) for m in manifest]
    t0 = time.time()
    results = scan_many(jobs, rules_version=rules)
    wall = time.time() - t0
    rows = []
    for m, (path, r, err, secs) in zip(manifest, results):
        if r is not None:
            rows.append({"name": m["name"], "ecosystem": m["ecosystem"], "score": r.score, "verdict": r.verdict,
                         "secs": secs, "top": [f.rule_id for f in r.findings[:4]], "files": r.n_files})
        else:
            rows.append({"name": m["name"], "ecosystem": m["ecosystem"], "score": None, "verdict": "error",
                         "secs": secs, "top": [err], "files": 0})
    return rows, wall


def summarise_real(rows, wall) -> dict:
    ok = [r for r in rows if r["score"] is not None]
    scores = [r["score"] for r in ok]
    secs = sorted(r["secs"] for r in ok)
    flagged = sorted((r for r in ok if r["score"] >= FLAG), key=lambda r: -r["score"])
    return {
        "n": len(ok), "errors": len(rows) - len(ok),
        "flag": _prop(scores, FLAG), "block": _prop(scores, BLOCK),
        "by_ecosystem_flag": {eco: _prop([r["score"] for r in ok if r["ecosystem"] == eco], FLAG)
                              for eco in ("pypi", "npm")},
        "latency_seconds": {"median": round(statistics.median(secs), 2), "p95": round(secs[int(0.95 * (len(secs) - 1))], 2),
                            "max": round(secs[-1], 2), "wall_clock_total": round(wall, 1)},
        "flagged": [{"name": r["name"], "eco": r["ecosystem"], "score": round(r["score"], 2), "verdict": r["verdict"],
                     "top": r["top"]} for r in flagged],
    }


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--quick", action="store_true", help="synthetic corpus only (seconds)")
    ap.add_argument("--out", default=str(ROOT / "results"))
    a = ap.parse_args()
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    result: dict = {"thresholds": {"flag": FLAG, "block": BLOCK}, "synthetic": {}, "real": {}, "ablation": {}}

    # --- synthetic corpus, both rule sets -----------------------------------------------------
    syn_rows = {}
    for rules in (1, 2, 3, 4):
        syn_rows[rules] = synthetic(rules)
        result["synthetic"][f"v{rules}"] = summarise_synthetic(syn_rows[rules])

    # --- ablation: switch one analyzer group off at a time (rule set v2, synthetic corpus) ------
    base2 = result["synthetic"]["v2"]
    mal = lambda d: sum(v["flag"]["k"] for k, v in d["splits"].items() if k != "benign")  # noqa: E731
    n_mal = sum(v["flag"]["n"] for k, v in base2["splits"].items() if k != "benign")
    result["ablation"]["baseline"] = {"malicious_flagged": mal(base2), "of": n_mal}
    for g in sorted(ALL_GROUPS):
        summ = summarise_synthetic(synthetic(2, frozenset({g})))
        result["ablation"][g] = {"malicious_flagged": mal(summ), "of": n_mal,
                                 "delta": mal(summ) - mal(base2),
                                 "hard_negative_flagged": summ["benign_hard_negatives"]["flag"]["k"]}

    # --- real benign packages -------------------------------------------------------------------
    if not a.quick:
        real_rows = {}
        label = {"benign_real": "A", "benign_real_B": "B", "benign_real_C": "C", "benign_real_D": "D"}
        for setname in label:
            if not (ROOT / "data" / setname / "manifest.json").exists():
                continue
            for rules in (1, 2, 3, 4):
                rows, wall = real_set(setname, rules)
                real_rows[(setname, rules)] = rows
                result["real"][f"{label[setname]}_v{rules}"] = summarise_real(rows, wall)

        # Threshold calibration: pick the flag threshold on set A at a 1% FPR budget, verify on set B.
        for rules in (1, 2, 3, 4):
            if ("benign_real", rules) in real_rows and ("benign_real_B", rules) in real_rows:
                a_neg = [r["score"] for r in real_rows[("benign_real", rules)] if r["score"] is not None]
                b_neg = [r["score"] for r in real_rows[("benign_real_B", rules)] if r["score"] is not None]
                t = threshold_at_fpr(a_neg, 0.01)
                pos = [r.score for s, r in syn_rows[rules] if s.label == 1]
                extra = {}
                if ("benign_real_C", rules) in real_rows:
                    c_neg = [r["score"] for r in real_rows[("benign_real_C", rules)] if r["score"] is not None]
                    extra["fpr_on_C_fresh"] = _prop(c_neg, t)
                if ("benign_real_D", rules) in real_rows:
                    d_neg = [r["score"] for r in real_rows[("benign_real_D", rules)] if r["score"] is not None]
                    extra["fpr_on_D_fresh"] = _prop(d_neg, t)
                result[f"calibrated_v{rules}"] = {
                    **extra,
                    "threshold_chosen_on_A_at_1pct_fpr": round(t, 3),
                    "fpr_on_A": _prop(a_neg, t), "fpr_on_B_untouched": _prop(b_neg, t),
                    "synthetic_malicious_detected": _prop(pos, t),
                    "auc_synthetic_malicious_vs_real_B": round(auc(pos, b_neg), 4),
                }

    (out / "eval_results.json").write_text(json.dumps(result, indent=2, default=str))
    (out / "eval_report.md").write_text(render_markdown(result))
    print(render_markdown(result))


def _fmt(p: dict) -> str:
    return f"{p['rate']:.0%} ({p['k']}/{p['n']}) [{p['ci95'][0]:.0%}-{p['ci95'][1]:.0%}]"


def render_markdown(res: dict) -> str:
    L: list[str] = ["# Evaluation report", "",
                    f"Operating points: **flag** (verdict suspicious or malicious) at score >= {res['thresholds']['flag']}, "
                    f"**block** (verdict malicious) at score >= {res['thresholds']['block']}. "
                    "Intervals are 95% Wilson.", ""]
    for v in ("v1", "v2", "v3", "v4"):
        syn = res["synthetic"][v]
        L += [f"## Synthetic corpus, rule set {v}", "", "| split | flagged | blocked |", "|---|---|---|"]
        for split in ("dev", "heldout", "adaptive"):
            s = syn["splits"][split]
            L.append(f"| {split} | {_fmt(s['flag'])} | {_fmt(s['block'])} |")
        h = syn["benign_hard_negatives"]
        L.append(f"| benign hard negatives (false positives) | {_fmt(h['flag'])} | {_fmt(h['block'])} |")
        L += ["", "| family | flagged | blocked |", "|---|---|---|"]
        for fam, d in syn["families"].items():
            L.append(f"| {fam} | {_fmt(d['flag'])} | {_fmt(d['block'])} |")
        if syn["flagged_benign"]:
            L += ["", "Benign synthetic families that were flagged: " + ", ".join(syn["flagged_benign"]), ""]
        L.append("")
    if res.get("real"):
        L += ["## Real benign packages (false positives)", "",
              "A = development sample (inspected while building rules). B = test sample for v1/v2 (and "
              "NOT clean for v3: the v3 fixes were designed after seeing B's failures). C = clean for v3 but used "
              "to diagnose v4. D = fetched before v4 was frozen and never scanned until the final run: the clean test for v4.", "",
              "| set / rules | n | flagged | blocked | median s | p95 s |", "|---|---|---|---|---|---|"]
        for k, v in res["real"].items():
            lat = v["latency_seconds"]
            L.append(f"| {k} | {v['n']} | {_fmt(v['flag'])} | {_fmt(v['block'])} | {lat['median']} | {lat['p95']} |")
        for k, v in res["real"].items():
            if v["flagged"]:
                L += ["", f"Flagged in {k}:", ""]
                for f in v["flagged"]:
                    L.append(f"- {f['name']} ({f['eco']}) {f['score']} {f['verdict']}: {', '.join(f['top'][:3])}")
        L.append("")
    for k in ("calibrated_v1", "calibrated_v2", "calibrated_v3", "calibrated_v4"):
        if k in res:
            c = res[k]
            L += [f"## Threshold calibrated on set A at 1% FPR ({k[-2:]})", "",
                  f"threshold = {c['threshold_chosen_on_A_at_1pct_fpr']}",
                  f"- FPR on A: {_fmt(c['fpr_on_A'])}",
                  f"- FPR on B: {_fmt(c['fpr_on_B_untouched'])}",
                  *([f"- FPR on C: {_fmt(c['fpr_on_C_fresh'])}"] if "fpr_on_C_fresh" in c else []),
                  *([f"- FPR on D (fresh, never seen before the final run): {_fmt(c['fpr_on_D_fresh'])}"] if "fpr_on_D_fresh" in c else []),
                  f"- synthetic malicious detected: {_fmt(c['synthetic_malicious_detected'])}",
                  f"- AUC, synthetic malicious vs real B benign: {c['auc_synthetic_malicious_vs_real_B']}", ""]
    ab = res["ablation"]
    L += ["## Ablation (rule set v2, synthetic corpus)", "",
          f"Baseline flags {ab['baseline']['malicious_flagged']}/{ab['baseline']['of']} malicious samples.", "",
          "| analyzer group switched off | malicious flagged | change | hard negatives flagged |", "|---|---|---|---|"]
    for g, d in ab.items():
        if g != "baseline":
            L.append(f"| {g} | {d['malicious_flagged']}/{d['of']} | {d['delta']:+d} | {d['hard_negative_flagged']} |")
    return "\n".join(L) + "\n"


if __name__ == "__main__":
    main()
