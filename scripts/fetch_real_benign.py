"""Download REAL benign packages for false-positive measurement.

Safety: files are downloaded as opaque bytes, digest-verified against the registry, and written to
``data/benign_real/`` - a directory that holds nothing but these archives. They are never extracted,
installed, imported or executed; the scanner reads them in memory.

Usage:  python scripts/fetch_real_benign.py [--pypi 150] [--npm 150]
"""

from __future__ import annotations

import argparse
import concurrent.futures as cf
import hashlib
import json
import sys
import time
import urllib.parse
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "data" / "benign_real"
UA = {"User-Agent": "package-malware-research-fetch/0.1"}
MAX_BYTES = 15_000_000
TOP_PYPI_URLS = (
    "https://hugovk.github.io/top-pypi-packages/top-pypi-packages-30-days.min.json",
    "https://hugovk.github.io/top-pypi-packages/top-pypi-packages.min.json",
)
NPM_KEYWORDS = ["cli", "utility", "parser", "http", "testing", "logger", "stream", "framework",
                "build", "cache", "validation", "template", "date", "crypto", "markdown"]


def get(url: str, *, binary: bool = False, timeout: int = 30):
    req = urllib.request.Request(url, headers=UA)
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        data = resp.read(MAX_BYTES + 1)
    if len(data) > MAX_BYTES:
        raise ValueError("too large")
    return data if binary else json.loads(data)


def pypi_candidates(n: int, offset: int = 0) -> list[str]:
    for url in TOP_PYPI_URLS:
        try:
            rows = get(url)["rows"]
            names = [r["project"] for r in rows[:900]]
            step = max(1, 900 // n)
            return names[offset % step:: step][:n * 2]      # spread across popularity ranks
        except Exception as exc:  # noqa: BLE001
            print(f"  could not read {url}: {exc}", file=sys.stderr)
    print("  falling back to the bundled popular-package list", file=sys.stderr)
    return [l.strip() for l in (ROOT / "src/mpd/data/popular_pypi.txt").read_text().splitlines() if l.strip()]


def fetch_pypi(name: str) -> dict | None:
    try:
        meta = get(f"https://pypi.org/pypi/{urllib.parse.quote(name)}/json")
        sdist = next((u for u in meta["urls"] if u["packagetype"] == "sdist"), None)
        if not sdist or sdist.get("size", 0) > MAX_BYTES:
            return None
        data = get(sdist["url"], binary=True)
        if hashlib.sha256(data).hexdigest() != sdist["digests"]["sha256"]:
            return None
        fname = sdist["filename"]
        (OUT / "pypi").mkdir(parents=True, exist_ok=True)
        (OUT / "pypi" / fname).write_bytes(data)
        return {"ecosystem": "pypi", "name": name, "version": meta["info"]["version"], "file": f"pypi/{fname}",
                "sha256": sdist["digests"]["sha256"]}
    except Exception:  # noqa: BLE001
        return None


def npm_candidates(n: int, keywords: list[str] | None = None) -> list[str]:
    seen: list[str] = []
    for kw in keywords or NPM_KEYWORDS:
        try:
            res = get(f"https://registry.npmjs.org/-/v1/search?text=keywords:{kw}&size=40&popularity=1.0")
            for o in res.get("objects", []):
                nm = o["package"]["name"]
                if nm not in seen and not nm.startswith("@"):
                    seen.append(nm)
        except Exception:  # noqa: BLE001
            continue
    return seen[: n * 2]


def fetch_npm(name: str) -> dict | None:
    try:
        meta = get(f"https://registry.npmjs.org/{urllib.parse.quote(name)}/latest")
        tar = meta["dist"]["tarball"]
        data = get(tar, binary=True)
        if hashlib.sha1(data).hexdigest() != meta["dist"].get("shasum"):
            return None
        fname = f"{name}-{meta['version']}.tgz"
        (OUT / "npm").mkdir(parents=True, exist_ok=True)
        (OUT / "npm" / fname).write_bytes(data)
        return {"ecosystem": "npm", "name": name, "version": meta["version"], "file": f"npm/{fname}",
                "sha256": hashlib.sha256(data).hexdigest()}
    except Exception:  # noqa: BLE001
        return None


NPM_KEYWORDS_B = ["compiler", "plugin", "async", "event", "file", "string", "array", "promise",
                  "config", "server", "database", "image", "network", "terminal", "package"]
NPM_KEYWORDS_D = ["graphql", "oauth", "pdf", "excel", "chart", "animation", "calendar", "tooltip", "state-management",
                  "form", "uuid", "cookie", "compression", "semver", "csv"]
NPM_KEYWORDS_C = ["typescript", "linter", "formatter", "router", "orm", "queue", "bundler", "scheduler",
                  "websocket", "i18n", "sdk", "middleware", "serializer", "diff", "observable"]


def main() -> None:
    global OUT
    ap = argparse.ArgumentParser()
    ap.add_argument("--pypi", type=int, default=150)
    ap.add_argument("--npm", type=int, default=150)
    ap.add_argument("--set", choices=["A", "B", "C", "D"], default="A",
                    help="A = development sample; B = disjoint test sample (used for v1/v2); "
                         "C = a second, fresh test sample for the v3 fixes. Each is disjoint from the others")
    a = ap.parse_args()
    OUT = ROOT / "data" / {"A": "benign_real", "B": "benign_real_B", "C": "benign_real_C", "D": "benign_real_D"}[a.set]
    OUT.mkdir(parents=True, exist_ok=True)
    manifest: list[dict] = []
    t0 = time.time()
    taken: set[str] = set()
    for earlier in ("benign_real", "benign_real_B", "benign_real_C", "benign_real_D"):
        mf = ROOT / "data" / earlier / "manifest.json"
        if earlier != OUT.name and mf.exists():
            taken |= {m["name"] for m in json.loads(mf.read_text())}
    pypi_offset = {"A": 0, "B": 3, "C": 1, "D": 4}[a.set]
    npm_kw = {"A": None, "B": NPM_KEYWORDS_B, "C": NPM_KEYWORDS_C, "D": NPM_KEYWORDS_D}[a.set]
    pypi_c = [n for n in pypi_candidates(a.pypi, offset=pypi_offset) if n not in taken]
    npm_c = [n for n in npm_candidates(a.npm, npm_kw) if n not in taken]
    for label, cands, fn, want in (("pypi", pypi_c, fetch_pypi, a.pypi),
                                   ("npm", npm_c, fetch_npm, a.npm)):
        print(f"{label}: {len(cands)} candidates, want {want}")
        got = 0
        with cf.ThreadPoolExecutor(max_workers=6) as ex:
            for res in ex.map(fn, cands):
                if res and got < want:
                    manifest.append(res)
                    got += 1
        print(f"  downloaded {got} ({time.time() - t0:.0f}s elapsed)")
    (OUT / "manifest.json").write_text(json.dumps(manifest, indent=2))
    print(f"wrote {len(manifest)} entries to {OUT / 'manifest.json'}")


if __name__ == "__main__":
    main()
