"""Threat-campaign records: link flagged packages that share attacker infrastructure.

A single malicious package is an incident; the same C2 domain, webhook or decoded payload showing up
in five packages across two ecosystems is a *campaign*, and the campaign is what a threat team tracks
over time. This module clusters flagged scan results by shared indicators of compromise and keeps a
JSON database that grows as new scans arrive, recording when each package and each indicator was
first and last seen and which techniques (ATT&CK ids / rule ids) the campaign uses.

Linking is deliberately conservative:
  * only network/payload indicators link packages (domains, IPs, webhooks, decoded-payload hashes);
  * an indicator that appears in a large share of everything scanned is common infrastructure, not a
    campaign signal, and is ignored (``max_prevalence``);
  * only packages already judged suspicious or malicious participate.
"""

from __future__ import annotations

import hashlib
import json
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from .analyzers.infra import defang
from .models import IoC, ScanResult

LINK_KINDS = ("domain", "ip", "webhook", "payload_sha256")
FLAGGED = ("suspicious", "malicious")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _pkg_key(r: ScanResult) -> str:
    return f"{r.ecosystem}:{r.name}@{r.version}"


def linking_iocs(r: ScanResult) -> set[tuple[str, str]]:
    return {(i.kind, i.value) for i in r.iocs if i.kind in LINK_KINDS}


def common_indicators(results: list[ScanResult], max_prevalence: float = 0.2, min_corpus: int = 10) -> set[tuple[str, str]]:
    """Indicators seen in so many of the scanned packages that they cannot identify a campaign."""
    if len(results) < min_corpus:
        return set()
    seen: Counter[tuple[str, str]] = Counter()
    for r in results:
        for ioc in linking_iocs(r):
            seen[ioc] += 1
    limit = max_prevalence * len(results)
    return {ioc for ioc, n in seen.items() if n > limit}


@dataclass
class Campaign:
    id: str
    first_seen: str
    last_seen: str
    packages: dict[str, dict] = field(default_factory=dict)
    iocs: dict[str, dict] = field(default_factory=dict)       # "kind|value" -> {first_seen,last_seen,count}
    ttps: dict[str, int] = field(default_factory=dict)         # ATT&CK id or rule id -> occurrences

    @property
    def ecosystems(self) -> list[str]:
        return sorted({p["ecosystem"] for p in self.packages.values()})

    def to_dict(self) -> dict:
        return {"id": self.id, "first_seen": self.first_seen, "last_seen": self.last_seen,
                "ecosystems": self.ecosystems, "packages": self.packages, "iocs": self.iocs, "ttps": self.ttps}


def _campaign_id(ioc_keys: list[str]) -> str:
    return "C-" + hashlib.sha256("\n".join(sorted(ioc_keys)).encode()).hexdigest()[:10]


def cluster(results: list[ScanResult], max_prevalence: float = 0.2) -> list[list[ScanResult]]:
    """Group flagged results that share at least one non-common linking indicator (union-find)."""
    common = common_indicators(results, max_prevalence)
    flagged = [r for r in results if r.verdict in FLAGGED and (linking_iocs(r) - common)]
    parent = list(range(len(flagged)))

    def find(x: int) -> int:
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    by_ioc: dict[tuple[str, str], list[int]] = defaultdict(list)
    for i, r in enumerate(flagged):
        for ioc in linking_iocs(r) - common:
            by_ioc[ioc].append(i)
    for members in by_ioc.values():
        for j in members[1:]:
            parent[find(j)] = find(members[0])
    groups: dict[int, list[ScanResult]] = defaultdict(list)
    for i, r in enumerate(flagged):
        groups[find(i)].append(r)
    return list(groups.values())


def _absorb(c: Campaign, r: ScanResult, common: set[tuple[str, str]], now: str) -> None:
    key = _pkg_key(r)
    c.packages.setdefault(key, {"ecosystem": r.ecosystem, "name": r.name, "version": r.version,
                                "first_seen": now})
    c.packages[key].update({"verdict": r.verdict, "score": round(r.score, 3), "last_seen": now})
    for kind, value in linking_iocs(r) - common:
        ik = f"{kind}|{value}"
        entry = c.iocs.setdefault(ik, {"first_seen": now, "count": 0})
        entry["last_seen"] = now
        entry["count"] += 1
    for f in r.findings:
        if f.severity >= 2:                          # MEDIUM and above
            label = f.tactic or f.rule_id
            c.ttps[label] = c.ttps.get(label, 0) + 1
    c.last_seen = now


def update_db(db_path: str | Path, results: list[ScanResult], max_prevalence: float = 0.2) -> dict[str, Campaign]:
    """Fold a batch of scan results into the campaign database and return all campaigns."""
    path = Path(db_path)
    db: dict[str, Campaign] = {}
    if path.exists():
        raw = json.loads(path.read_text())
        for cid, d in raw.get("campaigns", {}).items():
            db[cid] = Campaign(id=cid, first_seen=d["first_seen"], last_seen=d["last_seen"],
                               packages=d["packages"], iocs=d["iocs"], ttps=d["ttps"])
    now = _now()
    common = common_indicators(results, max_prevalence)
    for group in cluster(results, max_prevalence):
        group_iocs = {f"{k}|{v}" for r in group for k, v in linking_iocs(r) - common}
        overlapping = [c for c in db.values() if group_iocs & set(c.iocs)]
        if overlapping:
            overlapping.sort(key=lambda c: c.first_seen)
            target = overlapping[0]
            for other in overlapping[1:]:                      # a new package bridged two campaigns: merge
                target.packages.update(other.packages)
                for k, v in other.iocs.items():
                    target.iocs.setdefault(k, v)
                for t, n in other.ttps.items():
                    target.ttps[t] = target.ttps.get(t, 0) + n
                target.first_seen = min(target.first_seen, other.first_seen)
                db.pop(other.id, None)
        else:
            target = Campaign(id=_campaign_id(sorted(group_iocs)), first_seen=now, last_seen=now)
            db[target.id] = target
        for r in group:
            _absorb(target, r, common, now)
    path.write_text(json.dumps({"updated": now, "campaigns": {k: c.to_dict() for k, c in db.items()}}, indent=2))
    return db


def render_markdown(c: Campaign) -> str:
    lines = [f"## Campaign {c.id}", "",
             f"- first seen {c.first_seen}, last seen {c.last_seen}",
             f"- ecosystems: {', '.join(c.ecosystems)}; {len(c.packages)} package(s)", "", "**Packages**", ""]
    for p in sorted(c.packages.values(), key=lambda p: (p["ecosystem"], p["name"])):
        lines.append(f"- `{p['ecosystem']}:{p['name']}@{p['version']}` {p['verdict']} (score {p['score']})")
    lines += ["", "**Shared infrastructure (defanged)**", ""]
    for key, v in sorted(c.iocs.items(), key=lambda kv: -kv[1]["count"]):
        kind, value = key.split("|", 1)
        lines.append(f"- {kind}: `{defang(value) if kind != 'payload_sha256' else value}` (seen in {v['count']} package(s))")
    lines += ["", "**Techniques (MITRE ATT&CK ids / rule ids)**", ""]
    for t, n in sorted(c.ttps.items(), key=lambda kv: -kv[1]):
        lines.append(f"- {t} x{n}")
    return "\n".join(lines) + "\n"
