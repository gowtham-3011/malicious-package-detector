"""Copy the chosen sample zips out of git's object store into data/malicious_real/M1/, WITHOUT a checkout.

    python scripts/materialize_malicious_sample.py [--set M1]

Why not ``git checkout``: it builds an index and a worktree from the repository's own path names, and some of
those names are invalid on Windows (trailing dots), which aborts the checkout. Relaxing git's path validation
to get past that is the wrong trade when handling malware, so this reads each blob with ``git cat-file`` and
writes it under a filename *this script* chooses (the blob's hash). No repository-controlled path is ever
written to disk, and nothing is extracted or executed: the output files are still the encrypted zips.

Output layout:   data/malicious_real/<set>/<ecosystem>/<category>/<blob-sha>.zip   plus  index.json
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BASE = ROOT / "data" / "malicious_real"
REPO = BASE / "_repo"


def tree_index(group: str) -> dict[str, str]:
    """path -> blob sha for a whole category. Listing only: no blob contents are needed for this."""
    eco, cat = group.split("/")
    out = subprocess.run(["git", "ls-tree", "-r", "-z", "HEAD", f"samples/{eco}/{cat}"],
                         cwd=REPO, capture_output=True, check=True).stdout
    idx = {}
    for rec in out.split(b"\0"):
        if not rec:
            continue
        meta, _, path = rec.partition(b"\t")
        mode, kind, sha = meta.decode().split()
        if kind == "blob":
            idx[path.decode("utf-8", "replace")] = sha
    return idx


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--set", default="M1", help="M1, M2_reserve, or a fresh sample name such as M3")
    a = ap.parse_args()
    fresh = a.set not in ("M1", "M2_reserve")
    manifest = json.loads((BASE / (f"sample_manifest_{a.set}.json" if fresh else "sample_manifest.json")).read_text())
    out_root = BASE / ("M2" if a.set == "M2_reserve" else a.set)
    index: dict[str, dict] = {}
    todo: list[tuple[str, str, str, str]] = []       # (group, path, sha, dest)
    for group, g in manifest["groups"].items():
        paths = g[a.set]
        if not paths:
            continue
        idx = tree_index(group)
        for p in paths:
            sha = idx.get(p)
            if sha is None:
                print("not in tree, skipped:", p, file=sys.stderr)
                continue
            dest = out_root / group / f"{sha}.zip"
            todo.append((group, p, sha, str(dest)))
    print(f"{len(todo)} files to materialise into {out_root}", flush=True)

    def start() -> subprocess.Popen:
        return subprocess.Popen(["git", "cat-file", "--batch"], cwd=REPO, stdin=subprocess.PIPE,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    proc = start()
    done = skipped = 0
    for group, path, sha, dest in todo:
        d = Path(dest)
        parts = path.split("/")                       # samples/<eco>/<cat>/<name>/<version>/<file>.zip
        meta = {"group": group, "package": parts[3], "version": parts[4] if len(parts) > 5 else "",
                "source_path": path, "file": str(d.relative_to(BASE)).replace("\\", "/")}
        if d.exists() and d.stat().st_size > 0:       # resumable: already copied by an earlier run
            index[sha] = {**meta, "bytes": d.stat().st_size}
            done += 1
            continue
        data = None
        for attempt in range(4):
            try:
                proc.stdin.write(sha.encode() + b"\n")
                proc.stdin.flush()
                header = proc.stdout.readline().decode().split()
                if len(header) == 3 and header[1] == "blob":
                    data = proc.stdout.read(int(header[2]))
                    proc.stdout.read(1)               # trailing newline after each object
                    break
            except (OSError, ValueError):
                pass
            # the helper died or the lazy fetch failed: start a fresh one and retry this object
            try:
                proc.kill()
            except OSError:
                pass
            proc = start()
        if data is None:
            print("giving up on", sha, file=sys.stderr)
            skipped += 1
            continue
        d.parent.mkdir(parents=True, exist_ok=True)
        d.write_bytes(data)
        index[sha] = {**meta, "bytes": len(data)}
        done += 1
        if done % 50 == 0:
            print(f"  {done}/{len(todo)}", flush=True)
    try:
        proc.stdin.close()
    except OSError:
        pass
    proc.wait()
    (out_root / "index.json").write_text(json.dumps(index, indent=1))
    print(f"skipped {skipped} unfetchable files")
    print(f"materialised {done} files ({sum(v['bytes'] for v in index.values()) / 1e6:.1f} MB) -> {out_root}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
