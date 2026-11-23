"""Orchestrates one package scan. Pure analysis: no package code is ever run."""

from __future__ import annotations

import os
import posixpath
import time
from datetime import datetime, timezone

from .analyzers import install_hooks, metadata, typosquat, yara_scan
from .analyzers.base import ScanContext, guess_language
from .analyzers.dispatch import analyze_source, is_binary
from .loader import load_package
from .models import PackageView, ScanResult, Severity
from .scoring import DEFAULT_THRESHOLDS, score_findings, verdict_for

ALL_GROUPS = frozenset({"hooks", "python", "js", "shell", "blobs", "infra", "typosquat", "metadata", "yara"})


MAX_SECONDS = 60.0     # wall-clock budget per package: a crafted package must not hang the analyst

# Directories that hold tests, docs and samples. Nothing in them runs when a victim installs or
# imports the package, and in an sdist they are often most of the code, so unless something on an
# install/import path pulls a file in (the reachability pass), it is not worth the analysis time.
# Trade-off, stated in the README: a payload parked there and never imported is not examined.
_NONCODE_DIRS = {"test", "tests", "testing", "docs", "doc", "example", "examples", "benchmark",
                 "benchmarks", "samples", "demo", "demos", ".github"}


def _is_noncode_path(path: str) -> bool:
    parts = path.split("/")
    base = parts[-1]
    return (any(p.lower() in _NONCODE_DIRS for p in parts[:-1])
            or base.startswith("test_") or base.endswith("_test.py") or base == "conftest.py")


def scan_package(pkg: PackageView, *, rules_version: int = 4, disabled: frozenset[str] = frozenset(),
                 thresholds: dict[str, float] | None = None, max_seconds: float = MAX_SECONDS) -> ScanResult:
    ctx = ScanContext(pkg=pkg, rules_version=rules_version, disabled=frozenset(disabled))
    ctx.notes.extend(pkg.notes)
    deadline = time.monotonic() + max_seconds

    install_hooks.run(ctx)
    # Install/import-time files first: if the budget runs out, the code that matters most is done.
    def _priority(p: str) -> tuple[int, str]:
        return (0 if p in ctx.install_files else 1 if p in ctx.import_files else 2, p)

    skipped_noncode = 0
    for path in sorted(pkg.files, key=_priority):
        if time.monotonic() > deadline:
            ctx.notes.append(f"time budget ({max_seconds:.0f}s) exceeded; remaining files not analysed")
            break
        if _priority(path)[0] == 2 and _is_noncode_path(path):
            skipped_noncode += 1
            continue
        data = pkg.files[path]
        if is_binary(path, data):
            continue
        if path.endswith(".pth"):                 # analysed line-by-line in install_hooks
            continue
        text = data.decode("utf-8", errors="replace")
        try:
            analyze_source(ctx, path, text, ctx.phase_of(path))
        except Exception as exc:  # noqa: BLE001 - a hostile file must never abort the whole scan
            # An analyzer crash on a file is itself worth a look: crafted input that breaks a
            # scanner is an evasion technique. Record it and keep going.
            ctx.notes.append(f"analyzer error on {path}: {exc.__class__.__name__}")
            ctx.add("SCAN-ANALYZER-ERROR", "Analysis of this file failed (malformed or adversarial input?)",
                    Severity.LOW, path, phase=ctx.phase_of(path), tactic="T1027",
                    evidence=exc.__class__.__name__)
    if ctx.v2:
        # v2: a data file that some code exec()s IS code. Analyse it as such, with the phase of the
        # file that executes it.
        for parent, name, ph in ctx.data_exec_targets:
            for cand in (posixpath.normpath(posixpath.join(posixpath.dirname(parent), name)),
                         posixpath.normpath(name)):
                if cand in pkg.files and not is_binary(cand, pkg.files[cand]):
                    text = pkg.files[cand].decode("utf-8", errors="replace")
                    try:
                        analyze_source(ctx, cand, text, ph, lang=guess_language(text))
                    except Exception as exc:  # noqa: BLE001
                        ctx.notes.append(f"analyzer error on {cand}: {exc.__class__.__name__}")
                    break
    if skipped_noncode:
        ctx.notes.append(f"skipped {skipped_noncode} test/doc/example file(s) not reachable from install/import")
    for stage in (typosquat.run, metadata.run, yara_scan.run):
        try:
            stage(ctx)
        except Exception as exc:  # noqa: BLE001
            ctx.notes.append(f"{stage.__module__.rsplit('.', 1)[-1]} error: {exc.__class__.__name__}")

    findings = sorted(ctx.findings, key=lambda f: (-f.weight, f.file, f.line))
    score = score_findings(findings)
    return ScanResult(
        ecosystem=pkg.ecosystem, name=pkg.name, version=pkg.version, source=pkg.source,
        findings=findings, iocs=ctx.iocs, score=score,
        verdict=verdict_for(score, thresholds or DEFAULT_THRESHOLDS),
        notes=list(dict.fromkeys(ctx.notes)),
        scanned_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
        n_files=len(pkg.files),
    )


def scan_path(path: str | os.PathLike, ecosystem: str | None = None, *, zip_password: str | bytes | None = None,
              **kwargs) -> ScanResult:
    return scan_package(load_package(path, ecosystem, zip_password), **kwargs)
