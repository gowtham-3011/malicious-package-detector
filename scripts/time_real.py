"""Print per-package scan time so slow packages are visible. Run isolated: python -I scripts/time_real.py"""
import json, sys, time
from pathlib import Path
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from mpd.scanner import scan_path
t_all = time.time()
for m in json.loads((ROOT / "data/benign_real/manifest.json").read_text()):
    t = time.time()
    print(f"START {m['file']}", flush=True)
    scan_path(ROOT / "data/benign_real" / m["file"], m["ecosystem"], rules_version=1)
    dt = time.time() - t
    if dt > 1.0:
        print(f"  SLOW {dt:6.1f}s {m['file']}", flush=True)
print(f"DONE in {time.time()-t_all:.1f}s", flush=True)
