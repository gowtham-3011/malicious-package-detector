"""Command line interface.

    mpd scan <path> [--json | --md]            scan one package (directory, .tgz, .tar.gz, .whl, .zip)
    mpd scan-dir <dir>                         scan every package found under a directory, in parallel
    mpd campaigns <dir> --db campaigns.json    scan a directory and update the campaign database
    mpd demo <outdir>                          write the INERT synthetic corpus to disk to experiment with

Exit status of `scan` is CI-friendly: 0 benign, 1 suspicious, 2 malicious, 3 could not analyse.
Nothing here ever executes package code.
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from . import __version__
from .batch import scan_many
from .campaigns import render_markdown as campaign_md, update_db
from .loader import LoadError
from .report import to_json, to_markdown
from .scanner import scan_path

ARCHIVE_SUFFIXES = (".tgz", ".tar.gz", ".whl", ".zip", ".tar.bz2", ".tar.xz")


def _find_packages(root: Path) -> list[Path]:
    """Archives anywhere under ``root``, plus any directory that itself looks like a package
    (it holds package.json / setup.py / PKG-INFO / pyproject.toml, or a *.dist-info folder)."""
    found: list[Path] = []
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        if set(filenames) & {"package.json", "setup.py", "PKG-INFO", "pyproject.toml"} or \
                any(d.endswith(".dist-info") for d in dirnames):
            found.append(Path(dirpath))
            dirnames[:] = []                       # never descend into a package
            continue
        found.extend(Path(dirpath) / f for f in filenames if f.lower().endswith(ARCHIVE_SUFFIXES))
    return sorted(found)


def _cmd_scan(a: argparse.Namespace) -> int:
    try:
        r = scan_path(a.path, a.ecosystem, rules_version=a.rules)
    except LoadError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 3
    print(to_json(r) if a.json else to_markdown(r))
    return {"benign": 0, "suspicious": 1, "malicious": 2}[r.verdict]


def _cmd_scan_dir(a: argparse.Namespace) -> int:
    pkgs = _find_packages(Path(a.dir))
    if not pkgs:
        print("no packages found", file=sys.stderr)
        return 3
    out = scan_many([(p, a.ecosystem) for p in pkgs], rules_version=a.rules)
    worst = 0
    print(f"{'verdict':10} {'score':>5}  package")
    for p, r, err, secs in sorted(out, key=lambda x: -(x[1].score if x[1] else -1)):
        if r is None:
            print(f"{'error':10} {'':>5}  {p}  ({err})")
            continue
        print(f"{r.verdict:10} {r.score:5.2f}  {r.ecosystem}:{r.name}@{r.version}  ({secs:.1f}s)")
        worst = max(worst, {"benign": 0, "suspicious": 1, "malicious": 2}[r.verdict])
    return worst


def _cmd_campaigns(a: argparse.Namespace) -> int:
    pkgs = _find_packages(Path(a.dir))
    results = [r for _, r, _, _ in scan_many([(p, a.ecosystem) for p in pkgs], rules_version=a.rules) if r]
    db = update_db(a.db, results)
    shown = [c for c in db.values() if len(c.packages) >= a.min_packages]
    print(f"scanned {len(results)} packages; {len(db)} campaign record(s) in {a.db}, "
          f"{len(shown)} linking >= {a.min_packages} packages\n")
    for c in sorted(shown, key=lambda c: -len(c.packages)):
        print(campaign_md(c))
    return 0


def _cmd_demo(a: argparse.Namespace) -> int:
    root = Path(__file__).resolve().parents[2]
    sys.path.insert(0, str(root))
    try:
        from corpus import generate
    except ImportError:
        print("the synthetic corpus lives in the repository's corpus/ folder; run from a source checkout", file=sys.stderr)
        return 3
    out = Path(a.outdir)
    n = 0
    for s in generate():
        if s.label != 1 and not a.include_benign:
            continue
        d = out / s.ecosystem / f"{s.split}__{s.family}__{s.name}"
        for rel, content in s.files.items():
            p = d / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_bytes(content.encode() if isinstance(content, str) else content)
        n += 1
    print(f"wrote {n} inert synthetic packages under {out}. (Security tools may flag them; they cannot run.)")
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="mpd", description="Static detector for malicious PyPI/npm packages.")
    ap.add_argument("--version", action="version", version=f"mpd {__version__}")
    sub = ap.add_subparsers(dest="cmd", required=True)

    def common(p: argparse.ArgumentParser) -> None:
        p.add_argument("--ecosystem", choices=["pypi", "npm"], default=None)
        p.add_argument("--rules", type=int, choices=[1, 2, 3, 4], default=4, help="rule set version (default 4)")

    p = sub.add_parser("scan", help="scan one package")
    p.add_argument("path")
    p.add_argument("--json", action="store_true", help="machine-readable output")
    common(p)
    p.set_defaults(fn=_cmd_scan)

    p = sub.add_parser("scan-dir", help="scan every package under a directory")
    p.add_argument("dir")
    common(p)
    p.set_defaults(fn=_cmd_scan_dir)

    p = sub.add_parser("campaigns", help="scan a directory and update the campaign database")
    p.add_argument("dir")
    p.add_argument("--db", default="campaigns.json")
    p.add_argument("--min-packages", type=int, default=2)
    common(p)
    p.set_defaults(fn=_cmd_campaigns)

    p = sub.add_parser("demo", help="write the inert synthetic corpus to disk")
    p.add_argument("outdir")
    p.add_argument("--include-benign", action="store_true")
    p.set_defaults(fn=_cmd_demo)

    a = ap.parse_args(argv)
    return a.fn(a)


if __name__ == "__main__":
    raise SystemExit(main())
