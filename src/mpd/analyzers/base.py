"""ScanContext: the mutable state shared by every analyzer during one package scan."""

from __future__ import annotations

import ast
import re
import warnings
from dataclasses import dataclass, field

from ..models import Finding, IoC, PackageView, Severity

MAX_DEPTH = 4            # how many nested decode layers we will chase
MAX_EVIDENCE = 160


def short(text: str, limit: int = MAX_EVIDENCE) -> str:
    text = re.sub(r"\s+", " ", text).strip()
    return text if len(text) <= limit else text[: limit - 1] + "…"


@dataclass
class ScanContext:
    pkg: PackageView
    rules_version: int = 4                      # 1 = original, 2 = adaptive round, 3 = FP root-cause fixes, 4 = real-malware gaps
    disabled: frozenset[str] = frozenset()      # analyzer groups switched off (used for ablations)
    install_files: set[str] = field(default_factory=set)
    install_entry: set[str] = field(default_factory=set)   # files that THEMSELVES run at install (setup.py, .pth, ...)
    import_files: set[str] = field(default_factory=set)
    findings: list[Finding] = field(default_factory=list)
    iocs: list[IoC] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    data_exec_targets: list[tuple[str, str, str]] = field(default_factory=list)   # (parent file, name, phase)
    _seen: set = field(default_factory=set)
    _ioc_seen: set = field(default_factory=set)

    @property
    def v2(self) -> bool:
        return self.rules_version >= 2

    @property
    def v3(self) -> bool:
        return self.rules_version >= 3

    @property
    def v4(self) -> bool:
        return self.rules_version >= 4

    def enabled(self, group: str) -> bool:
        return group not in self.disabled

    @staticmethod
    def real_path(path: str) -> str:
        """Strip the virtual ``::decoded`` suffix used for de-obfuscated layers."""
        return path.split("::", 1)[0]

    def phase_of(self, path: str) -> str:
        real = self.real_path(path)
        if real in self.install_files:
            return "install"
        if real in self.import_files:
            return "import"
        return "runtime"

    def add(self, rule_id: str, title: str, severity: Severity, file: str, *, line: int = 0,
            phase: str | None = None, tactic: str = "", evidence: str = "",
            confidence: float = 1.0, via_decoding: bool = False) -> None:
        key = (rule_id, file, line, via_decoding)
        if key in self._seen:
            return
        self._seen.add(key)
        self.findings.append(Finding(
            rule_id=rule_id, title=title, severity=severity, file=file, line=line,
            phase=phase or self.phase_of(file), tactic=tactic, evidence=short(evidence),
            confidence=confidence, via_decoding=via_decoding))

    def add_ioc(self, kind: str, value: str, file: str, via_decoding: bool = False) -> None:
        key = (kind, value)
        if key in self._ioc_seen:
            return
        self._ioc_seen.add(key)
        self.iocs.append(IoC(kind=kind, value=value, file=file, via_decoding=via_decoding))


_JS_HINT = re.compile(r"\brequire\(|\bmodule\.exports\b|\bprocess\.(?:env|argv)\b|=>|\bfunction\s*\w*\(|\bconst\s+\w+\s*=")
_SH_HINT = re.compile(r"(?m)^#!/|\b(?:curl|wget|chmod|sudo|bash|powershell)\b|\|\s*(?:sh|bash)\b")


def guess_language(text: str) -> str:
    """Best-effort language guess for a decoded payload that has no filename."""
    head = text[:20000]
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            ast.parse(head)
        # Plain prose parses as nothing useful; require at least one statement-ish token.
        if re.search(r"\b(?:import|def|class|exec|eval|print|open|with|for|if)\b|=", head):
            return "python"
    except (SyntaxError, ValueError, RecursionError, MemoryError):
        pass
    if _JS_HINT.search(head):
        return "js"
    if _SH_HINT.search(head):
        return "shell"
    return "text"
