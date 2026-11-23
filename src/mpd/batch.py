"""Scan many packages in parallel (one process per core).

Parsing is CPU-bound pure Python, so threads would not help; processes do. Each worker loads
and scans one package at a time and returns the (picklable) ScanResult, or an error string, so
one hostile package that crashes or times out a worker cannot take the batch down.
"""

from __future__ import annotations

import concurrent.futures as cf
import os
import time
from typing import Iterable

from .models import ScanResult


def _scan_one(job: tuple[str, str | None, dict]) -> tuple[str, ScanResult | None, str, float]:
    from .scanner import scan_path   # imported in the worker

    path, ecosystem, kwargs = job
    t0 = time.monotonic()
    try:
        return path, scan_path(path, ecosystem, **kwargs), "", time.monotonic() - t0
    except Exception as exc:  # noqa: BLE001
        return path, None, f"{exc.__class__.__name__}: {exc}", time.monotonic() - t0


def scan_many(jobs: Iterable[tuple[str, str | None]], *, workers: int | None = None,
              **scan_kwargs) -> list[tuple[str, ScanResult | None, str, float]]:
    """Scan ``(path, ecosystem)`` pairs. Returns ``(path, result_or_None, error, seconds)`` in input order."""
    work = [(str(p), e, scan_kwargs) for p, e in jobs]
    workers = workers or max(1, (os.cpu_count() or 2) - 1)
    if workers == 1 or len(work) <= 1:
        return [_scan_one(j) for j in work]
    with cf.ProcessPoolExecutor(max_workers=workers) as ex:
        return list(ex.map(_scan_one, work, chunksize=1))
