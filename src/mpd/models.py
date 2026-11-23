"""Shared data model: findings, IoCs, the in-memory package view and scan results."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum
from typing import Any


class Severity(IntEnum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


# Probability-like weight of one finding of each severity, before phase scaling.
SEVERITY_WEIGHT = {
    Severity.INFO: 0.0,
    Severity.LOW: 0.10,
    Severity.MEDIUM: 0.30,
    Severity.HIGH: 0.60,
    Severity.CRITICAL: 0.85,
}

# WHEN the code runs matters more than WHAT it does. Code that runs the instant a
# victim installs a package gets no chance to be reviewed; code in a rarely-called
# function does. This is the single most important idea in the scoring model.
PHASE_FACTOR = {"install": 1.00, "import": 0.80, "runtime": 0.55}


@dataclass(frozen=True)
class Finding:
    rule_id: str
    title: str
    severity: Severity
    file: str
    line: int = 0
    phase: str = "runtime"          # install | import | runtime
    tactic: str = ""                # MITRE ATT&CK technique id, e.g. T1059
    evidence: str = ""
    confidence: float = 1.0
    via_decoding: bool = False      # found inside a decoded (de-obfuscated) layer

    @property
    def weight(self) -> float:
        return SEVERITY_WEIGHT[self.severity] * PHASE_FACTOR.get(self.phase, 0.55) * self.confidence

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id, "title": self.title, "severity": self.severity.name,
            "file": self.file, "line": self.line, "phase": self.phase, "tactic": self.tactic,
            "evidence": self.evidence, "confidence": self.confidence,
            "via_decoding": self.via_decoding, "weight": round(self.weight, 4),
        }


@dataclass(frozen=True)
class IoC:
    kind: str       # url | domain | ip | email | webhook | payload_sha256
    value: str
    file: str = ""
    via_decoding: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {"kind": self.kind, "value": self.value, "file": self.file,
                "via_decoding": self.via_decoding}


@dataclass
class PackageView:
    """An in-memory, read-only view of a package. Never touches disk after loading."""
    ecosystem: str                  # "pypi" | "npm"
    name: str
    version: str
    files: dict[str, bytes]
    source: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)

    def text(self, path: str) -> str:
        return self.files[path].decode("utf-8", errors="replace")


@dataclass
class ScanResult:
    ecosystem: str
    name: str
    version: str
    source: str
    findings: list[Finding]
    iocs: list[IoC]
    score: float
    verdict: str                    # benign | suspicious | malicious
    notes: list[str] = field(default_factory=list)
    scanned_at: str = ""
    n_files: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "ecosystem": self.ecosystem, "name": self.name, "version": self.version,
            "source": self.source, "score": round(self.score, 4), "verdict": self.verdict,
            "scanned_at": self.scanned_at, "n_files": self.n_files, "notes": self.notes,
            "findings": [f.to_dict() for f in self.findings],
            "iocs": [i.to_dict() for i in self.iocs],
        }
