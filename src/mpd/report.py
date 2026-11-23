"""Render a scan result as an analyst-facing internal assessment (Markdown) or machine JSON.

The JSON form is the feed for detection pipelines; the Markdown form is what a researcher hands to a
teammate or pastes into a ticket. IoCs are defanged in the Markdown so it is safe to paste anywhere.
"""

from __future__ import annotations

import json
from collections import Counter

from .analyzers.infra import defang
from .models import ScanResult

ATTACK_NAMES = {
    "T1059": "Command and Scripting Interpreter", "T1059.004": "Unix Shell", "T1059.006": "Python",
    "T1059.007": "JavaScript", "T1027": "Obfuscated Files or Information", "T1105": "Ingress Tool Transfer",
    "T1041": "Exfiltration Over C2 Channel", "T1567": "Exfiltration Over Web Service",
    "T1552": "Unsecured Credentials", "T1552.001": "Credentials In Files", "T1082": "System Information Discovery",
    "T1546": "Event Triggered Execution (persistence)", "T1036": "Masquerading",
    "T1195.001": "Supply Chain: Compromise Software Dependencies", "T1195.002": "Supply Chain: Compromise Software Supply Chain",
}

ACTION = {
    "malicious": "Block the package, preserve the sample, and report it to the registry. Check dependents "
                 "and any machine or CI job that installed it for exposed credentials; rotate what it could reach.",
    "suspicious": "Send to manual triage. Reproduce in an isolated sandbox with network capture before "
                  "deciding. Do not install on a machine holding real credentials.",
    "benign": "No action. (A benign verdict from a static scanner is not proof of safety.)",
}


def to_json(result: ScanResult, indent: int = 2) -> str:
    return json.dumps(result.to_dict(), indent=indent)


def to_markdown(result: ScanResult, max_findings: int = 25) -> str:
    r = result
    L = [f"# Assessment: {r.ecosystem}:{r.name}@{r.version}", "",
         f"**Verdict: {r.verdict.upper()}**  (score {r.score:.2f}; {r.n_files} files analysed; scanned {r.scanned_at})", "",
         f"Recommended action: {ACTION[r.verdict]}", ""]
    if r.findings:
        phases = Counter(f.phase for f in r.findings if f.severity >= 2)
        L += ["## What it does", "",
              "Findings of MEDIUM severity or higher by when the code runs: "
              + ", ".join(f"{n} at {p}" for p, n in sorted(phases.items())) + ".", ""]
        tactics = Counter(f.tactic for f in r.findings if f.severity >= 2 and f.tactic)
        if tactics:
            L += ["Techniques observed:", ""]
            for t, n in tactics.most_common():
                L.append(f"- {t} {ATTACK_NAMES.get(t, '')} (x{n})")
            L.append("")
        L += ["## Evidence", "", "| severity | rule | runs at | location | evidence |", "|---|---|---|---|---|"]
        for f in r.findings[:max_findings]:
            ev = f.evidence.replace("|", "\\|")
            note = " (found inside a decoded layer)" if f.via_decoding else ""
            L.append(f"| {f.severity.name} | {f.rule_id} | {f.phase} | {f.file}:{f.line} | `{ev}`{note} |")
        if len(r.findings) > max_findings:
            L.append(f"\n_{len(r.findings) - max_findings} further lower-weight findings omitted._")
        L.append("")
    if r.iocs:
        L += ["## Indicators of compromise (defanged)", ""]
        for i in r.iocs:
            value = i.value if i.kind == "payload_sha256" else defang(i.value)
            tag = " (decoded layer)" if i.via_decoding else ""
            L.append(f"- {i.kind}: `{value}` in {i.file}{tag}")
        L.append("")
    if r.notes:
        L += ["## Analysis notes", ""] + [f"- {n}" for n in r.notes] + [""]
    L += ["_Static analysis only: no package code was executed. Treat a clean result as 'nothing found', not 'safe'._", ""]
    return "\n".join(L)
