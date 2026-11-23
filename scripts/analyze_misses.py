"""Aggregate STRUCTURAL statistics for the real malicious packages the detector missed.

    python -I scripts/analyze_misses.py

Diagnosis only: it prints counts (lifecycle scripts present, first token of install commands, file counts), never
package content. It reads results/malicious_eval_M1.json and re-opens the sample zips in memory. Nothing is executed.
This is for understanding failure modes and writing them up; any detector change made in response must be measured
on the reserved, never-fetched M2 sample, not on M1.
"""

from __future__ import annotations

import concurrent.futures as cf
import json
import re
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
BASE = ROOT / "data" / "malicious_real"
LIFECYCLE = ("preinstall", "install", "postinstall", "prepare", "prepublish")
FLAG = 0.35


def features(job):
    from mpd.loader import load_package
    group, file = job
    eco = group.split("/")[0]
    try:
        pkg = load_package(BASE / file, eco, zip_password="infected")
    except Exception as exc:  # noqa: BLE001
        return group, {"unreadable": type(exc).__name__}
    f: dict = {"n_files": len(pkg.files)}
    names = list(pkg.files)
    if eco == "npm":
        pj = pkg.metadata.get("package_json") or {}
        scripts = pj.get("scripts") if isinstance(pj.get("scripts"), dict) else {}
        lc = [k for k in LIFECYCLE if isinstance(scripts.get(k), str)]
        f["lifecycle"] = lc
        f["cmd_first"] = [scripts[k].split()[0].lower() if scripts[k].split() else "" for k in lc]
        f["cmd_subst"] = any(re.search(r"\$\(|`|%\w+%|\$\w+|\bhostname\b|\bwhoami\b", scripts[k]) for k in lc)
        f["cmd_net"] = any(re.search(r"\b(curl|wget|nslookup|dig|ping|powershell|Invoke-WebRequest|iwr)\b", scripts[k], re.I) for k in lc)
        f["n_js"] = sum(n.endswith((".js", ".cjs", ".mjs")) for n in names)
        f["has_pkgjson"] = "package.json" in pkg.files
        f["version"] = str(pj.get("version", ""))
    else:
        f["has_setup_py"] = "setup.py" in pkg.files
        f["has_pth"] = any(n.endswith(".pth") for n in names)
        f["n_py"] = sum(n.endswith(".py") for n in names)
        f["setup_cmdclass"] = "setup.py" in pkg.files and b"cmdclass" in pkg.files["setup.py"]
        f["has_pyproject"] = "pyproject.toml" in pkg.files
        f["has_pkginfo"] = "PKG-INFO" in pkg.files or any(n.endswith("METADATA") for n in names)
    return group, f


def main() -> int:
    which = sys.argv[1] if len(sys.argv) > 1 else "M1"
    res = json.loads((ROOT / "results" / f"malicious_eval_{which}.json").read_text())
    index = json.loads((BASE / which / "index.json").read_text())
    jobs = []
    for sha, rec in res["samples"].items():
        v3 = rec["v3"]
        if v3.get("analysable") and v3["score"] < FLAG:
            jobs.append((rec["group"], index[sha]["file"]))
    print(f"analysing {len(jobs)} missed (analysable, score < {FLAG}) samples structurally\n", flush=True)
    by_group: dict[str, list[dict]] = {}
    with cf.ProcessPoolExecutor(max_workers=12) as ex:
        for group, f in ex.map(features, jobs, chunksize=4):
            by_group.setdefault(group, []).append(f)

    for group, fs in sorted(by_group.items()):
        n = len(fs)
        print(f"== {group}: {n} missed")
        sizes = sorted(f.get("n_files", 0) for f in fs)
        print(f"   files per package: median {sizes[n//2]}, <=3 files: {sum(s <= 3 for s in sizes)}, "
              f">20 files: {sum(s > 20 for s in sizes)}")
        if group.startswith("npm"):
            print(f"   has a lifecycle script: {sum(bool(f['lifecycle']) for f in fs)}/{n}  "
                  f"| by name: {Counter(k for f in fs for k in f['lifecycle']).most_common()}")
            print(f"   install-command first token: {Counter(t for f in fs for t in f['cmd_first']).most_common(8)}")
            print(f"   command uses substitution/host identity: {sum(f['cmd_subst'] for f in fs)}/{n} | "
                  f"mentions a network tool: {sum(f['cmd_net'] for f in fs)}/{n}")
            print(f"   no lifecycle script AND <=3 files (likely stub/probe package): "
                  f"{sum((not f['lifecycle']) and f['n_files'] <= 3 for f in fs)}/{n}")
            print(f"   version 99.x / 999.x style (dependency-confusion shape): "
                  f"{sum(bool(re.match(r'(9\\d|\\d{3,})\\.', f['version'])) for f in fs)}/{n}")
        else:
            print(f"   setup.py present: {sum(f['has_setup_py'] for f in fs)}/{n} | with cmdclass: {sum(f['setup_cmdclass'] for f in fs)}"
                  f" | .pth: {sum(f['has_pth'] for f in fs)} | pyproject only (no setup.py): "
                  f"{sum((not f['has_setup_py']) and f['has_pyproject'] for f in fs)}")
            print(f"   python files: median {sorted(f['n_py'] for f in fs)[n//2]}, 0 py files: {sum(f['n_py'] == 0 for f in fs)}")
        print()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
