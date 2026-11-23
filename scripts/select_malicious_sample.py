"""Draw a reproducible random sample of the DataDog malicious-packages dataset from a treeless clone.

    python scripts/select_malicious_sample.py            # writes data/malicious_real/sample_manifest.json

Only DIRECTORY LISTINGS are read (``git ls-tree --name-only``); no sample content is touched. The result is
a seeded shuffle split into two disjoint sets per (ecosystem, category):

    M1  the evaluation sample  -> fetched and scanned
    M2  a RESERVE sample       -> deliberately NOT fetched; used only if the detector is changed in response to
                                  what M1 shows, so that the change can be measured on packages it never saw

``malicious_intent`` packages exist to deliver malware. ``compromised_lib`` are legitimate libraries that were
hijacked for specific versions, which a static scanner can only catch if the injected code is obvious; they are
reported as a separate group.
"""

from __future__ import annotations

import argparse
import json
import random
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
REPO = ROOT / "data" / "malicious_real" / "_repo"
OUT = ROOT / "data" / "malicious_real" / "sample_manifest.json"
SEED = 20261121
PLAN = {                       # (ecosystem, category) -> (M1 size, M2 size)
    ("pypi", "malicious_intent"): (300, 300),
    ("npm", "malicious_intent"): (300, 300),
    ("pypi", "compromised_lib"): (29, 0),          # all that exist
    ("npm", "compromised_lib"): (40, 40),
}
SAFE_PATH = re.compile(r"^[A-Za-z0-9._/+@-]+$")   # git sparse-checkout treats other characters as patterns
RESERVED = {"con", "prn", "aux", "nul", *(f"com{i}" for i in range(1, 10)), *(f"lpt{i}" for i in range(1, 10))}
MAX_REL_PATH = 120                                  # the checkout lives deep in a path; Windows caps ~260


def windows_safe(path: str) -> bool:
    """Names Windows cannot create (trailing dot, reserved device names) would abort the whole checkout."""
    if len(path) > MAX_REL_PATH:
        return False
    for part in path.split("/"):
        if part.endswith(".") or part.split(".")[0].lower() in RESERVED:
            return False
    return True


def list_zips(eco: str, cat: str) -> tuple[list[str], int]:
    out = subprocess.run(["git", "ls-tree", "-r", "-z", "--name-only", "HEAD", f"samples/{eco}/{cat}"],
                         cwd=REPO, capture_output=True, check=True).stdout
    paths = [p.decode("utf-8", "replace") for p in out.split(b"\0") if p]
    zips = [p for p in paths if p.endswith(".zip")]
    safe = sorted(p for p in zips if SAFE_PATH.match(p) and " " not in p and windows_safe(p))
    return safe, len(zips) - len(safe)


PLAN_FRESH = {                 # a fresh evaluation sample drawn from what earlier samples left unused
    ("pypi", "malicious_intent"): 300,
    ("npm", "malicious_intent"): 300,
    ("npm", "compromised_lib"): 40,
}


def main_fresh(name: str, seed: int) -> int:
    """Draw sample ``name`` EXCLUDING every package already drawn (M1 and the M2 reserve)."""
    used: set[str] = set()
    for g in json.loads(OUT.read_text())["groups"].values():
        used.update(g["M1"])
        used.update(g["M2_reserve"])
    for other in OUT.parent.glob("sample_manifest_M*.json"):
        for g in json.loads(other.read_text())["groups"].values():
            for lst in g.values():
                if isinstance(lst, list):
                    used.update(lst)
    rng = random.Random(seed)
    manifest: dict = {"seed": seed, "dataset": "DataDog/malicious-software-packages-dataset", "groups": {}}
    for (eco, cat), n in PLAN_FRESH.items():
        zips, excluded = list_zips(eco, cat)
        zips = [z for z in zips if z not in used]
        rng.shuffle(zips)
        manifest["groups"][f"{eco}/{cat}"] = {"available_after_filter_and_exclusion": len(zips),
                                              "excluded_unsafe_paths": excluded, name: zips[:n]}
        print(f"{eco}/{cat}: {len(zips)} unused -> {name}={len(zips[:n])}")
    (OUT.parent / f"sample_manifest_{name}.json").write_text(json.dumps(manifest, indent=1))
    return 0


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--fresh", metavar="NAME", help="draw a fresh sample (e.g. M3) excluding earlier samples")
    ap.add_argument("--seed", type=int, default=SEED + 1)
    args = ap.parse_args()
    if not REPO.exists():
        print("run the treeless clone first (see the README, 'Evaluating against real malware')", file=sys.stderr)
        return 1
    if args.fresh:
        return main_fresh(args.fresh, args.seed)
    rng = random.Random(SEED)
    manifest: dict = {"seed": SEED, "dataset": "DataDog/malicious-software-packages-dataset", "groups": {}}
    for (eco, cat), (n1, n2) in PLAN.items():
        zips, excluded = list_zips(eco, cat)
        rng.shuffle(zips)
        m1, m2 = zips[:n1], zips[n1:n1 + n2]
        manifest["groups"][f"{eco}/{cat}"] = {"available_after_filter": len(zips), "excluded_unsafe_paths": excluded,
                                              "M1": m1, "M2_reserve": m2}
        print(f"{eco}/{cat}: {len(zips)} usable ({excluded} excluded as Windows-unsafe/odd names) "
              f"-> M1={len(m1)}, reserve M2={len(m2)}")
    OUT.write_text(json.dumps(manifest, indent=1))
    paths = [p for g in manifest["groups"].values() for p in g["M1"]]
    (OUT.parent / "sparse_M1.txt").write_text("\n".join("/" + p for p in paths) + "\n")
    print(f"wrote {OUT.name} and sparse_M1.txt ({len(paths)} paths to fetch)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
