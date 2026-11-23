"""Sample container, builders and the top-level ``generate()``."""

from __future__ import annotations

import base64
import json
import random
import zlib
from dataclasses import dataclass

ADJ = ["swift", "quiet", "bright", "lazy", "sturdy", "tiny", "plain", "clever", "gentle", "rapid",
       "silver", "amber", "north", "delta", "lunar", "solid", "crisp", "mellow", "nimble", "vivid"]
NOUN = ["parser", "cache", "router", "logger", "scheduler", "mapper", "queue", "format", "stream",
        "config", "tracker", "loader", "wrapper", "helper", "toolkit", "client", "engine", "bridge",
        "adapter", "builder"]
WORDS = ["telemetry", "sync", "collect", "update", "cdn", "metrics", "relay", "edge", "stats", "ingest"]

# Attacker infrastructure is reused across packages, which is exactly what makes campaigns
# linkable. 70% of samples draw from this small pool; the rest get a one-off host.
C2_POOL = ["metrics-relay.example", "update-sync.example", "edge-collect.example"]
WEBHOOK_POOL = ["000000000000000001/FAKE-TOKEN-AAAA", "000000000000000002/FAKE-TOKEN-BBBB"]


def c2(rng: random.Random) -> str:
    if rng.random() < 0.7:
        return rng.choice(C2_POOL)
    return f"{rng.choice(WORDS)}-{rng.choice(WORDS)}-{rng.randrange(100, 999)}.example"


def new_name(rng: random.Random, used: set[str]) -> str:
    while True:
        name = f"{rng.choice(ADJ)}-{rng.choice(NOUN)}"
        if rng.random() < 0.5:
            name += f"-{rng.randrange(2, 99)}"
        if name not in used:
            used.add(name)
            return name


def fill(template: str, **kw: str) -> str:
    """Substitute @@KEY@@ tokens (safe for brace-heavy JavaScript templates)."""
    for k, v in kw.items():
        template = template.replace(f"@@{k}@@", v)
    return template


def b64(text: str) -> str:
    return base64.b64encode(text.encode()).decode()


def b64z(text: str) -> str:
    return base64.b64encode(zlib.compress(text.encode())).decode()


@dataclass
class Sample:
    name: str
    ecosystem: str
    version: str
    files: dict
    label: int                 # 1 = malicious, 0 = benign
    family: str
    split: str                 # dev | heldout | adaptive | benign
    hard: bool = False         # benign hard negative

    def view(self):
        from mpd.loader import package_from_files
        raw = {p: (d.encode() if isinstance(d, str) else d) for p, d in self.files.items()}
        return package_from_files(raw, self.ecosystem, source=f"synthetic:{self.family}/{self.name}")


# ----------------------------------------------------------------------------- builders
def pypi_files(name: str, version: str, files: dict, *, wheel: bool = False) -> dict:
    meta = (f"Metadata-Version: 2.1\nName: {name}\nVersion: {version}\nSummary: A small helpful library\n"
            f"Home-page: https://github.com/example-org/{name}\nAuthor: Example Author\n")
    out = {}
    if wheel:
        out[f"{name.replace('-', '_')}-{version}.dist-info/METADATA"] = meta
    else:
        out["PKG-INFO"] = meta
    out.update(files)
    return out


def npm_files(name: str, version: str, files: dict, *, scripts: dict | None = None, main: str = "index.js",
              bin_: dict | None = None, extra: dict | None = None) -> dict:
    pj = {"name": name, "version": version, "description": "A small helpful library", "main": main,
          "license": "MIT",
          "repository": {"type": "git", "url": f"https://github.com/example-org/{name}.git"}}
    if scripts:
        pj["scripts"] = scripts
    if bin_:
        pj["bin"] = bin_
    if extra:
        pj.update(extra)
    out = {"package.json": json.dumps(pj, indent=2)}
    out.update(files)
    return out


def generate(seed: int = 1234) -> list[Sample]:
    from .benign import BENIGN_BUILDERS
    from .malicious import ADAPTIVE, DEV, HELDOUT

    rng = random.Random(seed)
    used: set[str] = set()
    samples: list[Sample] = []
    for split, table in (("dev", DEV), ("heldout", HELDOUT), ("adaptive", ADAPTIVE)):
        for family, fn, n in table:
            for i in range(n):
                name, eco, version, files = fn(rng, i, used)
                samples.append(Sample(name, eco, version, files, 1, family, split))
    for family, fn, hard, n in BENIGN_BUILDERS:
        for i in range(n):
            name, eco, version, files = fn(rng, i, used)
            samples.append(Sample(name, eco, version, files, 0, family, "benign", hard=hard))
    return samples
