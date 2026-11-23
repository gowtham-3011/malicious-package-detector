# Malicious Package Detector

A **static, never-executing** detector for malicious PyPI and npm packages, with a threat-campaign
tracker and an evaluation lab that reports what it gets wrong as prominently as what it gets right.

It answers one question before a package ever runs on a developer laptop, a CI job, or an AI coding
agent's sandbox: *should this be blocked, sent to a human, or left alone?*

```
$ mpd scan suspicious-1.0.0.tar.gz
Verdict: MALICIOUS  (score 0.85)
| HIGH   | PY-EXFIL                       | install | setup.py:10 | env_bulk + urllib.request.urlopen |
| MEDIUM | PYPI-CMDCLASS-INSTALL-OVERRIDE | install | setup.py:16 | cmdclass keys: ['install']        |
IoCs (defanged): hxxps://edge-collect[.]example/collect
```

---

## Headline results (read the caveats; they are the point)

| | result |
|---|---|
| **Detection of REAL malware, final run** (DataDog dataset, fresh sample M3, 640 packages, rule set v4) | **PyPI 68.3% flagged** (203/297, 95% CI 62.8-73.4%), 50.8% auto-blocked; **npm 56.7%** (170/300, CI 51.0-62.2%), 24.7% auto-blocked. At the stricter threshold calibrated for a 1% false-positive rate: **59.9% / 37.3%** |
| **False positives on real benign packages** | **fresh set D: 4.2% flagged** (11/260, CI 2.4-7.4%), 1.2% auto-blocked (3/260). Pooled over four benign sets (1,067 packages): **2.2% flagged, 0.6% auto-blocked**. The rate varies 0.8-4.2% by sample (build tooling such as `setuptools` and `hatchling` looks like install-time code) |
| What v4 added over v3 | npm detection **46.7% to 56.7%** on the same 300 packages: **30 more caught, 0 lost** (paired p = 2e-9), mostly from one rule (install-script beacons carrying host identity). PyPI +2 packages (67.7% to 68.3%). No new false positives |
| *Synthetic* families, rules written against them | 100% flagged (48/48). **Does not transfer to real malware** |
| *Synthetic* held-out families | 100% flagged (20/20), but only 75% reach the auto-block tier |
| *Synthetic* adaptive evasions written after reading the rules | 11% (3/27) before the improvement round, 89% (24/27) after. **Rule sets v1, v2 and v3 are statistically tied on real malware**, so this gain did not transfer |
| Throughput | 260–287 real packages (~165 MB) in **61–92 s** on 16 cores; median 0.2–0.6 s per package |
| Tests | 126 passed, 1 skipped (symlink privileges on Windows); safety properties are tested, not asserted |

**What these numbers are, and are not.** The real-malware figures are the ones to quote. They come from
random samples of a public malicious-package dataset, scanned with operating points fixed in advance, and
the final figures are on a sample that no development step ever touched. They are *moderate*: about two in
three PyPI and over half of npm malicious packages are flagged, at a 2-4% flag rate on real benign packages. The
synthetic figures (100%, 89%) were measured on inert samples written by the same person who wrote the rules;
**they overstated real performance and should not be quoted as detection rates.** The sharpest evidence: the
adaptive-evasion improvements moved synthetic detection from 11% to 89% and moved real-malware detection by
nothing measurable, whereas v4, built from a structural diagnosis of real misses, moved npm detection by 10
points. See [docs/findings.md](docs/findings.md) for every miss and every false positive and why.

---

## Safety

Nothing in the tool executes, imports, installs or extracts package code. Archives are read as bytes,
member by member, into memory. Each property below has a test:

- never executes package code (a `setup.py` that would write a marker file does not);
- never opens a network connection (socket calls are patched to raise during a corpus-wide scan);
- never writes to disk while scanning an archive;
- path-traversal names, symlinks and oversized members are skipped; decompression bombs are refused;
- malformed input (NUL bytes, invalid UTF-8, deep nesting, malformed URLs) is contained: a crash on one
  file becomes a recorded finding and the scan continues, because *crafting input that crashes a
  scanner is itself an evasion technique*;
- a per-package wall-clock budget bounds CPU.

The synthetic malicious corpus is **inert by construction** (reserved `.example` hosts, zeroed/`FAKE`
webhook IDs, secrets referenced by name only, built in memory); a test asserts every host and webhook
in it meets that rule. See [docs/threat_model.md](docs/threat_model.md).

---

## Quickstart

```bash
python -m venv .venv && source .venv/bin/activate      # .venv\Scripts\activate on Windows
pip install -e ".[dev,yara]"                           # the scanner itself is pure standard library

mpd scan path/to/package.tgz            # (rule set 4 by default; --rules 1|2|3 for the earlier ones) directory, .tgz, .tar.gz, .whl or .zip; exit 0/1/2 = benign/suspicious/malicious
mpd scan path/to/package.tgz --json     # for pipelines
mpd scan-dir ./downloads                # every package under a directory, in parallel
mpd campaigns ./downloads --db campaigns.json    # scan + update the threat-campaign database
mpd demo ./demo                         # write the inert synthetic corpus to disk to experiment with

pytest                                  # 105 tests, ~6 s
python -I evaluation/run_eval.py        # full evaluation, ~5 min on 16 cores (needs the real-package sets, below)
```

Reproducing the real-package numbers (downloads ~300 MB into `data/`, digest-verified, never extracted):

```bash
python scripts/fetch_real_benign.py --set A     # development sample
python scripts/fetch_real_benign.py --set B     # disjoint test sample
python scripts/fetch_real_benign.py --set C     # a third sample
python scripts/fetch_real_benign.py --set D     # a fourth, fetched before v4 was frozen (the clean test for v4)
python -I evaluation/run_eval.py                # always run untrusted data with -I
```

To evaluate against **real malware** (see "Evaluation against real malware" below), prefer an isolated VM or
container with no credentials. The samples are never extracted or executed, but Defender or another scanner
may flag the files:

```bash
git clone --filter=blob:none --no-checkout --depth 1 \
    https://github.com/DataDog/malicious-software-packages-dataset.git data/malicious_real/_repo   # ~5 MB, listings only
python scripts/select_malicious_sample.py              # seeded random sample M1 + a RESERVED, unfetched sample M2
python scripts/materialize_malicious_sample.py --set M1   # reads blobs with `git cat-file`; no checkout
python -I scripts/eval_malicious.py --set M1           # always -I for untrusted data
```

---

## How it works

```
 archive / dir ──► loader (in-memory, capped, traversal-safe)
                       │
        ┌──────────────┴───────────────┐
        ▼                              ▼
  install_hooks + reachability    typosquat · metadata (version shape, registry-bypass deps)
  WHEN does each file run?
  install | import | runtime
        │
        ▼  per file, by language
  python_ast  (taint-lite, folding, behaviour combos per scope)
  javascript  (pattern analysis)          shell  (commands, lifecycle scripts, decoded payloads)
  blobs ◄── deobfuscate: base64/hex/zlib/gzip/bz2 layers, bounded ──► re-analysed as code
  infra  (IoCs, webhook/OAST/tunnel/dropsite infrastructure)        yara (optional second opinion)
        │
        ▼
  scoring: noisy-OR of (severity × phase × confidence), repeats discounted
        │
        ▼
  verdict ─► report (analyst Markdown / JSON) ─► campaigns (cluster by shared IoCs over time)
```

**Phase is the central idea.** The same `requests.post` is routine in a library and alarming in a
`postinstall` script, because install-time code runs before anyone has reviewed it, with the
installer's privileges, often in CI with secrets in the environment. So every finding is weighted by
*when it runs* (install 1.0, import 0.8, runtime 0.55). Disabling the install/import analysis drops
detection from 92 to 47 of 95 synthetic samples, the largest effect of any component.

**Reachability.** Phase propagates through the package's own import graph, so a payload hidden in
`pkg/_helper.py` imported by `__init__.py` inherits import-time status. Inside a file, only
module-level code and functions called at module level inherit it.

**Behaviour combinations, per scope.** One signal is weak; two together are strong. Reading
`~/.aws/credentials` is normal for a cloud SDK and sending HTTP is normal for a client; doing *both
in one function* is a stealer.

**De-obfuscation.** Encoded blobs are peeled (bounded depth and output size) and the result is
analysed *as code*, so a dropper under two layers of encoding is judged by what it does. Random
base64 (hashes, images) decodes to noise and is ignored. Every decoded payload's SHA-256 becomes an
IoC, because the same payload re-used across packages is how campaigns link.

**Campaign tracking.** Flagged packages sharing attacker infrastructure (domains, IPs, webhooks,
decoded-payload hashes) are clustered into campaign records stored in JSON with first/last-seen times
per package and per indicator and the ATT&CK techniques observed. Indicators common to a large share
of everything scanned are ignored, and new packages merge into existing campaigns across runs.

---

## Method: how the evaluation avoids fooling itself

1. **Three malicious tiers.** *Dev* families were used to build the rules (iterate freely).
   *Held-out* families were written separately and not used to motivate any rule change.
   *Adaptive* evasions were written **after reading the v1 rules**, each targeting a named assumption.
2. **A frozen v1.** Before the improvement round I snapshotted v1's scores; a test fails if v1 ever
   changes, so the before/after comparison is real. Every v2 rule is gated behind `rules_version >= 2`.
3. **One improvement round**, then stop. Further tuning against the same adaptive set would turn a
   test set into a training set.
4. **Real benign packages, two disjoint samples.** Set A was inspected while building rules, so it is
   optimistic. Set B was fetched *after* the rules were written, never scanned before the final run,
   and no rule was changed after seeing it.
5. **Hard negatives.** 38 of the 50 synthetic benign packages are legitimate code that looks
   suspicious (native-build `setup.py`, security-tool fixtures, GitHub API clients, plugin loaders).
6. **Intervals everywhere** (95% Wilson), because several cells have n < 30.

### Adaptive round, per family

| adaptive evasion (targets this assumption) | v1 flagged | v2 flagged |
|---|---|---|
| `getattr(__import__("o"+"s"), "sys"+"tem")` (sinks are called by name) | 0/3 | 3/3 |
| command built with `chr()` / `"".join` (commands are visible constants) | 0/3 | 3/3 |
| `exec(pkgutil.get_data(...))` of a `.dat` file (code lives in `.py` files) | 0/3 | 3/3 |
| `require('child' + '_process')` (module name appears literally) | 0/3 | 3/3 |
| reads only `NPM_TOKEN`/`GITHUB_TOKEN` (Python) (stealers dump the whole env) | 0/3 | 3/3 |
| same, JavaScript | 0/3 | 3/3 |
| `os.path.join(expanduser("~"), ".aws", "credentials")` (paths are one string) | 0/3 | 3/3 flagged, 0/3 blocked |
| payload only runs when a function is later called (payloads run at install/import) | 3/3 | 3/3 (0/3 blocked) |
| fetch in one file, `exec` in another (fetch and exec share a scope) | 0/3 | **0/3, not fixed** |

v2 closes eight of nine holes with constant folding, dynamic-import resolution, secret-variable names
and data-file exec detection. **The ninth, cross-file data flow, is deliberately left open** and is
the first item under limitations. The fixes were written with these exact samples in hand, so 89% is
"these specific holes are closed", **not** "evasion is solved".

**The improvement cost something.** On the untouched real set B, v1 flagged 2/260 and v2 flagged
4/260. The two new false positives are a GitHub API client reading `GITHUB_TOKEN` (the predicted
cost of the new secret-variable rule) and the Kubernetes client (its existing taint false positive
scored 0.33, just under the flag line, and v2's new low-severity dynamic-import rule tipped it over).
The intervals overlap, so this is a direction, not a measurement; but a detector that reports only
the 11% to 89% half of this story would be misleading.

---

### Round 3: fixing the false positives, and what a fresh sample showed

Set B exposed two real bugs: taint cascading through `self` after an attribute assignment, and every
function in a module imported by `setup.py` being treated as install-time. **v3 fixes both** (scoped taint
that no longer poisons the base object of an attribute target while still tracking `self.payload`;
install-time status limited to entrypoint files, module-level code and functions called at module level).
v2 was frozen first (a test enforces it) and every v3 change is gated behind `rules_version >= 3`. On
`mypy` and `kubernetes` the fixes work as designed (malicious 0.71 to benign 0.12; suspicious to benign).

**But B is no longer a clean test for v3**, because v3 was designed after seeing B's failures. So I fetched
a fresh set C (260 packages, disjoint from A and B, never scanned) and measured once:

| real sample | v1 flagged / blocked | v2 | v3 |
|---|---|---|---|
| A: development (optimistic) | 5/287 / 0 | 6/287 / 0 | 5/287 / 0 |
| B: clean for v1 and v2 only | 2/260 / 1 | 4/260 / 1 | 2/260 / 0 |
| **C: fresh, the clean test for v3** | 5/260 / 3 | 6/260 / 3 | **6/260 / 3** |

**The honest reading: v3 did not lower the false-positive rate on fresh packages** (6/260 under both v2 and
v3, and 3 packages reach the auto-block tier under all three rule sets). It fixed the failures it was
designed from; set C fails for *different* reasons:

- `dprint`, `bun`, `prisma` (all three **blocked**): legitimate npm packages whose install script downloads the
  platform's native binary. The JS fetch-and-run rule cannot tell this very common pattern from a dropper (the
  same ambiguity as my synthetic `vendored_build`, now confirmed at scale on real packages).
- `sympy`: `eval(...)` of a debug-flag string read from the environment; `llvmlite`: a legitimate custom
  `install` command; `jupyter-builder`: an npm-registry helper that reads credentials and calls the registry.

This is the whack-a-mole effect: *a fix for the last sample's failures is not evidence that the rate has
fallen*, and it is why the fresh sample was worth fetching. I stopped here rather than tune against C (which
would just spend it). The next honest step is to handle the npm binary-downloader class and measure on a
new set D. Calibrating the flag threshold on set A at a 1% false-positive budget, v3 detects 91.6% of the
synthetic malicious samples (v2 81.0%, v1 69.5%) with a 1.5% false-positive rate on set C (4/260); the
synthetic figure is subject to every caveat above.

## Evaluation against real malware

**Dataset.** [DataDog/malicious-software-packages-dataset](https://github.com/DataDog/malicious-software-packages-dataset)
(Apache-2.0, about 100 GB). Samples are zips, many encrypted with the standard handling password `infected`, split
into `malicious_intent` (packages built to deliver malware) and `compromised_lib` (legitimate libraries with
hijacked versions, which a static scanner can only catch when the injection is conspicuous).

**Handling.** A treeless partial clone (5 MB of directory listings; the repository itself is far too large to
clone), a seeded random sample, and each chosen blob copied out of git's object store with `git cat-file` under a
filename the script picks (its hash). I first tried a normal checkout; Windows rejects some package names (trailing
dots), and the workaround was to relax git's NTFS path validation, **which I did not do**: reading blobs directly
needs no relaxed protection and never writes a repository-controlled path. Samples are read in memory under
`python -I`; nothing is extracted or executed. Output contains rule ids, counts and package names only.

**Protocol, fixed before the first run.** Operating points are the defaults (flag 0.35, block 0.60) and the
threshold calibrated on the benign set A at a 1% false-positive budget. Two **disjoint** samples: **M1** (669
packages) and **M2** (640), where M2 was deliberately *not fetched* until a fix had been made, so the fix could
be judged on packages it was never derived from. The sampling frame excludes names Windows cannot create
(PyPI 44 of 2,503; npm 1,728 of 25,267; npm compromised 164 of 1,448), a small selection effect.

### First contact: 19% and 11%, and a bug

On M1 the detector flagged only **19.5% of PyPI and 10.7% of npm** malicious-intent packages, far below the
synthetic numbers. The structural diagnosis was striking: *none* of the missed npm packages had a lifecycle
script and almost none of the missed PyPI packages had a `setup.py`, which almost never happens in real
malicious packages. The cause was in my loader: it strips one wrapper directory, but in these zips the
`package.json` / `setup.py` sits **2 to 9 directories deep, never at the root**, so the install-hook analysis (the
tool's most valuable component) was silently switched off. The loader now finds the shallowest directory that
contains a marker file (never inside `node_modules` or `site-packages`), re-roots there, and keeps files outside
it under `_outside_root/` so nothing is hidden. Ordinary registry layouts are untouched (tests cover both).

### After the fix, on the clean sample M2 (rule set v3)

| group | n | flagged (>= 0.35) | auto-blocked (>= 0.60) | detected at the 1%-FPR threshold (0.468) |
|---|---|---|---|---|
| PyPI `malicious_intent` | 297 analysable of 300 | **65.0%** (193) [59.4-70.2] | 46.1% (137) | 57.6% (171) [51.9-63.1] |
| npm `malicious_intent` | 300 | **40.0%** (120) [34.6-45.6] | 20.3% (61) | 28.0% (84) [23.2-33.3] |
| npm `compromised_lib` | 40 | 25.0% (10) [14.2-40.2] | 12.5% (5) | 17.5% (7) [8.8-31.9] |

(PyPI `compromised_lib` has only 29 samples, all used in M1, so it is not in M2.) The change from 19% to 65% is
far outside the confidence intervals, but it is **not a paired comparison**: M1 and M2 are different packages.

**Rule sets v1, v2 and v3 are statistically tied on real malware** (PyPI 66.7% / 66.7% / 65.0% flagged; npm 40.0%
for all three). Everything the adaptive and false-positive rounds added made no measurable difference to real
detection. The synthetic adaptive set measured the author's imagination, not attackers.

### What the remaining misses look like (structural diagnosis of M2; no payload content)

- **npm, 180 of 300 missed:** 73 have a lifecycle script (mostly `node file.js`, plus `curl`/`wget` commands; 21 use
  command substitution or host identity, i.e. beacons), and 36 are stub packages with no script and at most three
  files, which leave nothing for static analysis to find.
- **PyPI, 104 of 300 missed:** 47 have a small `setup.py` (10 override a command class) whose behaviour my rules do
  not cover; the median miss has two Python files.
- **compromised npm libraries, 30 of 40 missed:** 22 have a lifecycle script, almost all launching a Node file.

### Caveats

- The dataset's "malicious" label does not guarantee the payload is present or visible: many npm samples are
  probes or placeholders. 65% and 40% are therefore lower bounds on what a stronger scanner could do, but they are
  also what *this* scanner does.
- The loader fix was derived from M1's directory structure (layout-generic, no rule changed). **No rule was changed
  after seeing M2**, but M2 is now spent: any further detector change needs a fresh sample from the remaining
  frame (about 1,859 unused PyPI and 22,900 unused npm packages).
- Eight M1 zips contain a nested archive that the loader does not descend into; 3 of 300 PyPI zips yielded no
  readable files. A single dataset, one labelling scheme.
- Detection is measured at about a 2% flag rate on real benign packages; the calibrated column is the fairer
  comparison between rule sets.

## Final run: rule set v4 on fresh data

**What v4 adds.** Built from a structural diagnosis of what the detector still missed on the (by then spent) samples
M1 and M2. Each rule is gated behind `rules_version >= 4`, so v1-v3 stay byte-for-byte reproducible (tests enforce it).
- **Install-script beacons** (`SH-BEACON`): a network tool in an install-time command that also carries host identity
  (`curl http://x/$(whoami)`, `nslookup $(hostname).x`), plus process-substitution downloads (`bash <(curl ...)`).
- **Hidden network and process calls in JavaScript**: aliased, inline and destructured `require('https')` forms that
  my literal patterns never saw, so they never reached the egress and beacon rules.
- Windows dropper sinks (`os.startfile`), an import-time host-beacon check across a package's `__init__`, IP-lookup
  services as reconnaissance, path-shaped stealer indicators (`...\Local Storage\leveldb`) and Discord-token regexes.

**Two mistakes caught on the way, now pinned by tests.** The first version of v4 doubled the false positives on the
benign sets (13 to 25 of 807): bare words like `leveldb` and `local storage` are ordinary library vocabulary, and an
import-time file-level credential combo flagged a security-scanner library that merely *lists* sensitive paths. Both
were fixed on the development data before any fresh data was touched.

**Protocol, fixed before the final run.** v4 was frozen (a test enforces it) *before* the fresh samples were scanned:
a new malicious sample **M3** (640 packages, disjoint from M1 and M2) and a new benign set **D** (260 packages, disjoint
from A, B and C) were drawn and fetched while v4 was being built, without looking at them. The decision rule was written
down in advance: v4 becomes the default only if it beats v3 on M3 by at least 3 points *and* does not raise the
false-positive rate on D by more than 1 point. **Both conditions were met**, so v4 is the default.

### Real malware, fresh sample M3 (flagged at >= 0.35; blocked at >= 0.60)

| group | n | v1 | v2 | v3 | **v4** | v4 blocked | v4 at the 1%-FPR threshold |
|---|---|---|---|---|---|---|---|
| PyPI `malicious_intent` | 297 of 300 | 68.0% | 67.7% | 67.7% | **68.3%** (203) [62.8-73.4] | 50.8% (151) | 59.9% (178) [54.3-65.3] |
| npm `malicious_intent` | 300 | 46.7% | 46.7% | 46.7% | **56.7%** (170) [51.0-62.2] | 24.7% (74) | 37.3% (112) [32.0-42.9] |
| npm `compromised_lib` | 40 | 22.5% | 22.5% | 22.5% | 25.0% (10) [14.2-40.2] | 15.0% (6) | 17.5% (7) |

- **The gain is paired and exact:** on the same 300 npm packages v4 flags 30 that v3 does not and loses none (exact
  McNemar p = 1.9e-9). 23 of the 30 contain an `SH-BEACON` finding. On PyPI it flags 2 more and loses none (p = 0.5).
- **Combined `malicious_intent` (PyPI + npm, 597 packages): 57.1% to 62.5%** (+5.4 points; the bar was 3).
- **v1, v2 and v3 are identical on npm (46.7%) and within 0.3 points on PyPI.** The adaptive and false-positive
  rounds added nothing measurable on real malware; the diagnosis-driven round added 10 points on npm.
- The M3 baseline is higher than M2's (npm v3: 46.7% vs 40.0%) because they are different random packages, so
  compare rule sets *within* a sample, not across samples.

### Real benign packages, all four sets (flagged / auto-blocked, v4; identical to v3)

| set | n | flagged | blocked | notes |
|---|---|---|---|---|
| A (development) | 287 | 1.7% (5) | 0 | optimistic: tuned against |
| B | 260 | 0.8% (2) | 0 | |
| C | 260 | 2.3% (6) | 3 | `dprint`, `bun`, `prisma`: binary downloaders |
| **D (fresh)** | 260 | **4.2% (11)** [2.4-7.4] | **3** | `reportlab`, `mcp-remote`, `pydeck` blocked |
| pooled | 1,067 | **2.2% (24)** | **0.6% (6)** | |

**v4 adds no false positives:** it flags the same 11 packages as v3 on D. **But D is the honest number**, and it is
higher than the earlier sets. It is not tuning leakage: v1, which was never changed after its first run, also flags
4.2% of D. D simply contains more build tooling, which resembles install-time code by nature: `setuptools`,
`hatchling`, `poetry-core`, `pydeck`, `omegaconf` (custom install command), `uv`, plus `gcsfs`, `xgboost`, `debugpy`,
`reportlab` and the npm helper `mcp-remote`. Quote the **2-4% range**, not the best single sample.

### What is still true

- PyPI is stuck near 68% flagged: v4 barely helped there, and the remaining misses are mostly small `setup.py`
  packages and stubs with no distinguishing API (API presence barely separated missed from flagged packages).
- Half of the npm misses still have no install-time script at all, or are stubs with nothing to analyse statically.
- The sample frame excludes ~7% of npm names that Windows cannot create; M3 is not a sample of the whole dataset.

## What running it on real code taught me about my own tool

The synthetic corpus passed long before the tool was usable. Real packages found, in order:

- **A ReDoS in my own regexes.** An infrastructure pattern began with an unbounded `[\w.-]+`;
  on a long run of word characters (minified JS, base64) it backtracked quadratically, and 5 of 287
  packages hung for over 45 s. Re-anchored on the literal domain suffix.
- **Quadratic AST work.** Five or six whole-tree walks per file plus a taint fixed-point over the whole
  tree. Replaced with a single indexing pass; plus a keyword prefilter, a test/doc-directory skip
  (with reachability to bring files back in), and a wall-clock budget.
- **A loader that silently disabled the best analysis.** Real malicious zips nest the package 2-9 directories deep;
  my loader assumed one wrapper directory, so install-hook analysis never ran on them. Synthetic samples (built in
  memory with root-level files) could never have shown this. Found only because the first real-malware run looked
  implausible (no missed package had an install script), and fixed with root discovery.
- **A crash on `http://[`.** `urlsplit` raises on malformed IPv6 URLs. A package could include one to
  kill the scan. Fixed, and a per-file guard now turns any analyzer exception into a finding.
- **Precision bugs found only by real data:** `cookies` as a "credential path" fired on every HTTP
  library; destructuring `process.env` looked like an environment dump; GitHub's image proxy
  hex-encodes URLs, which looked like encoded payloads; `exec(open("version.py").read())` is the
  standard way a `setup.py` reads its version.

Scanning all 287 development packages went from "did not finish in 10 minutes" to **68 seconds**.

---

## Limitations (stated plainly)

1. **Real-malware detection is moderate, and the synthetic numbers overstated it.** On a fresh sample the final rule
   set flags 68% of PyPI and 57% of npm malicious packages (60% and 37% at the stricter 1%-FPR threshold), and the
   synthetic results did not transfer. Remaining gaps: small `setup.py`-only packages, stubs with nothing to analyse,
   npm packages with no install-time script, and launchers (`node file.js`) whose target is not flagged.
2. **Auto-block is not trustworthy.** Across four benign sets, 6 of 1,067 real packages (0.6%) reach the *malicious*
   tier: `dprint`, `bun`, `prisma` (native-binary downloaders), and, on the fresh set, `reportlab`, `mcp-remote` and
   `pydeck`. The overall flag rate is 2.2% (0.8-4.2% by sample). Use the *suspicious* tier as a triage queue and **do not
   wire *malicious* to automatic blocking** without an allowlist for install-time downloads and known build backends.
   Fixing one sample's false positives did not lower the rate on the next, so expect new classes on every new sample.
3. **Cross-file data flow is not tracked** (`a2_split_across_files` still evades).
4. **JavaScript analysis is regex-based**, with no parser, scopes or data flow. Aliasing
   (`const h = require('https'); h.request(...)`) and inline `require('https').request(...)` are not
   recognised as network egress.
5. **No dynamic analysis, no registry context, no binary analysis.** Dependency-confusion detection
   sees only an implausible version number. Typosquat detection uses a ~120-name illustrative list.
6. **Known ambiguous patterns stay flagged**, e.g. a `setup.py` that downloads a tarball and runs
   `make`, which is behaviourally indistinguishable from a dropper without reputation data.
7. **Test and doc directories are skipped** unless reachable from install/import code; a payload parked
   there and never imported is not examined.
8. **Small samples.** 260 real packages and 95 synthetic malicious ones; several intervals are wide.

---

## Layout

```
src/mpd/            loader · deobfuscate · scanner · scoring · campaigns · report · cli · batch
  analyzers/        install_hooks · reachability · python_ast · javascript · shell · blobs · infra ·
                    typosquat · metadata · yara_scan · dispatch
  rules/            YARA rules      data/   illustrative popular-package lists
corpus/             the inert synthetic corpus (dev / held-out / adaptive / benign)
evaluation/         Wilson-interval metrics and the evaluation runner
scripts/            fetch real benign packages, freeze v1, timing/profiling helpers
tests/              105 tests: loader safety, deobfuscation, analyzers, scoring, campaigns, CLI, contracts
docs/               threat_model.md · findings.md
results/            eval_report.md · eval_results.json · v1_frozen_scores.json
```

## Future work

- Handle the npm install-time binary-downloader class (host allowlist, or require the executed file to derive from the download), then measure on a new set D.
- Cross-module data flow; a real JavaScript parser (tree-sitter) instead of regexes.
- PyPI is the weaker side (about 68%). Diagnose the small `setup.py` misses on a spent sample, resolve `node file.js`
  launcher targets, and measure on a new sample M4 from the unused frame (about 1,560 PyPI and 22,600 npm packages).
- Allowlist known build backends and install-time binary downloaders to cut the 2-4% false-positive rate.
- Descend into nested archives; add a registry-metadata feature for stub packages.
- Registry-context features (first-publish time, maintainer history) behind an optional offline file.
- Dynamic analysis in a network-isolated sandbox to resolve the *suspicious* tier.
- An LLM-assisted triage step *after* the deterministic verdict, never instead of it.
