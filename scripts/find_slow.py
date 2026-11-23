"""Find packages whose scan exceeds a hard timeout, each in its own subprocess. Run: python scripts/find_slow.py"""
import concurrent.futures as cf, json, subprocess, sys, time
from pathlib import Path
ROOT = Path(__file__).resolve().parent.parent
PY = sys.executable
CODE = ("import sys; sys.path.insert(0, %r)\nfrom mpd.scanner import scan_path\n"
        "scan_path(sys.argv[1], sys.argv[2], rules_version=1, max_seconds=1000)") % str(ROOT)
def run(m):
    t = time.time()
    try:
        subprocess.run([PY, "-I", "-c", CODE, str(ROOT / "data/benign_real" / m["file"]), m["ecosystem"]],
                       timeout=45, capture_output=True)
        return m["file"], time.time() - t, "ok"
    except subprocess.TimeoutExpired:
        return m["file"], 45.0, "TIMEOUT"
manifest = json.loads((ROOT / "data/benign_real/manifest.json").read_text())
t0 = time.time()
with cf.ThreadPoolExecutor(12) as ex:
    res = list(ex.map(run, manifest))
print(f"total wall {time.time()-t0:.0f}s")
for f, s, st in sorted(res, key=lambda x: -x[1])[:15]:
    print(f"  {st:8} {s:5.1f}s {f}")
