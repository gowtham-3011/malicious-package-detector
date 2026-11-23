# Findings

Everything below is generated from, or checked against, `results/eval_results.json` and
`results/eval_report.md`. Numbers are 95% Wilson intervals where given. "Flagged" means verdict
*suspicious* or *malicious* (score >= 0.35); "blocked" means *malicious* (score >= 0.60).

## 1. Synthetic corpus (inert samples written by the rule author)

| split | n | v1 flagged | v1 blocked | v2 flagged | v2 blocked |
|---|---|---|---|---|---|
| dev (rules built against these) | 48 | 48 (100%) | 41 (85%) | 48 (100%) | 41 (85%) |
| held-out (not used to motivate any rule) | 20 | 20 (100%) | 15 (75%) | 20 (100%) | 15 (75%) |
| adaptive (written after reading v1) | 27 | 3 (11%) | 0 (0%) | 24 (89%) | 18 (67%) |
| benign hard negatives, false positives | 38 | 2 (5%) | 2 (5%) | 2 (5%) | 2 (5%) |

Per-family detail is in `results/eval_report.md`. Things worth noticing:

- **Flagged is easy, blocked is hard.** Every dev and held-out family is flagged, but two families never
  reach the block tier: `d8_dependency_confusion` (0/6) and `h3_npm_persistence` (0/5). Both have
  weak, low-severity evidence by design (an absurd version number plus a beacon; a write to `.bashrc`
  of a string that is only a *string*, never analysed as a command). That is the right outcome for
  weak evidence, and it shows why the two tiers exist.
- **The adaptive round closed eight of nine holes** and left `a2_split_across_files` open on purpose
  (fetch in one module, `exec` in another; needs cross-module data flow).
- **`a9_path_join_credentials` is flagged but not blocked** after v2 (3/3 vs 0/3): the path is now
  resolved, but the credential read and the network call are in a function that is called at import
  time, giving a score of 0.48.
- **The only synthetic false positive is a known-ambiguous one**: `vendored_build`, a `setup.py` that
  downloads a tarball and runs `tar` and `make`. At install time that is behaviourally identical to a
  dropper without reputation data. It is asserted in a test so it cannot quietly disappear from the
  README.

## 2. Real packages (false positives)

| sample | rules | n | flagged | blocked |
|---|---|---|---|---|
| A, development (optimistic: inspected while building) | v1 | 287 | 5 (1.7%) | 0 |
| A | v2 | 287 | 6 (2.1%) | 0 |
| **B, untouched test sample** | v1 | 260 | **2 (0.8%)** | 1 (0.4%) |
| **B** | v2 | 260 | **4 (1.5%)** | 1 (0.4%) |

### Every flagged package in B, and why

| package | verdict | cause | kind |
|---|---|---|---|
| `mypy` | **malicious** 0.71 | taint over-approximation (below) made `subprocess.Popen(command, ...)` look like "runs decoded content"; the file is also treated as install-time via `setup.py`'s import closure | **bug** |
| `kubernetes` | suspicious 0.38 | same taint bug on `subprocess.Popen([self._cmd] + self._args)` (the exec-credential-plugin code path) | **bug** |
| `pycryptodomex` | suspicious 0.57 | name is one edit from `pycryptodome` (a legitimate sibling package by the same maintainers) plus `eval(line.split("=")[1])` in `setup.py` to parse a version | design limit: typosquat check has no reputation data; version-parse idiom not covered |
| `ghapi` | suspicious 0.47 | a GitHub API client that reads `GITHUB_TOKEN` and posts, which the v2 secret-variable rule treats as credential-plus-egress | **cost of v2** |

`ghapi` and `kubernetes` are the two packages v2 added over v1. `ghapi` is exactly the trade-off the
v2 secret-variable rule predicts (the synthetic `gh_client` hard negative was written to probe it, and
at runtime phase it stays benign; this one's call sits in a build script). `kubernetes` is different:
its taint false positive alone scores 0.33 under v1, just under the 0.35 flag threshold, and v2's new
low-severity dynamic-import rule (two LOW findings) added just enough to cross it. A borderline
false positive being tipped over by an unrelated weak rule is itself a finding about how thin the
margin is at this threshold.

### Root cause of the two bugs (verified, not guessed)

1. **Taint over-approximation.** `_propagate_taint` keys taint by bare variable name for the whole
   file; for an assignment target it walks every `Name` node inside the target, so `self.x = tainted`
   taints `self`; and taint flows through any call expression. In `mypy/build.py` this yields ~270
   tainted names including `self`, `name`, `path`, `data`. In `kubernetes/config/kube_config.py`,
   `self._cmd = cmd` taints `self`, after which `Popen([self._cmd] + self._args)` is "tainted".
   *Fix:* scope taint per function, do not taint the base name of an attribute/subscript target, and
   stop propagation through calls that are not decoders.
2. **Install-closure over-approximation.** Everything transitively imported by `setup.py` is marked
   install-time for all scopes, but importing a module only runs its module-level code. In mypy this
   puts 207 of 1,873 files in the install closure. *Fix:* inside closure files other than `setup.py`
   itself, treat only module scope and functions called at module level as install-time (the machinery
   already exists for import-phase files).

Neither fix was made: set B was scanned once with frozen rules, and tuning against it would make the
reported rate meaningless. A fresh sample (set C) is the honest way to measure the fix.

### The calibrated operating point

Choosing the flag threshold on set A at a 1% false-positive budget and applying it to B:

| rules | threshold | FPR on A | **FPR on B (unseen)** | synthetic malicious detected | AUC, synthetic malicious vs real B |
|---|---|---|---|---|---|
| v1 | 0.468 | 2/287 | 2/260 (0.8%) | 66/95 (69%) | 0.921 |
| v2 | 0.533 | 2/287 | 2/260 (0.8%) | 77/95 (81%) | 0.990 |

At the same measured false-positive rate on unseen real packages, v2 detects 81% of synthetic
malicious samples against v1's 69%. **Caveat on the AUC:** it compares *synthetic* positives written by
the rule author with *real* negatives, which flatters the detector; it measures separability of those
two populations, not performance on real attacks.

### Round 3 (rule set v3) and the fresh sample C

v3 fixes the two verified root causes above (scoped taint; entrypoint-only install status), gated behind
`rules_version >= 3` with v2 frozen first. Because B was used to find those bugs it is no longer clean for v3,
so a fresh set C (260 packages, disjoint from A and B, never scanned) was fetched and measured once.

| sample | v1 flagged / blocked | v2 | v3 |
|---|---|---|---|
| A (development) | 5/287 / 0 | 6/287 / 0 | 5/287 / 0 |
| B | 2/260 / 1 | 4/260 / 1 | 2/260 / 0 |
| **C (fresh)** | 5/260 / 3 | 6/260 / 3 | **6/260 / 3** |

**v3 did not reduce false positives on fresh packages.** Every package flagged in C, with the cause:

| package | verdict (v3) | cause | kind |
|---|---|---|---|
| `dprint` (npm) | **malicious** 0.68 | `install_api.cjs` downloads the platform binary via `https.get` and then runs a computed command | legitimate pattern; the rule cannot distinguish it from a dropper |
| `bun` (npm) | **malicious** 0.68 | `install.js` fetches the platform binary | same |
| `prisma` (npm) | **malicious** 0.60 | bundled CLI `dist/prisma.js`: `fetch(` plus a non-literal process call, and `os.homedir()` + `fetch(` read as a beacon | same, plus large minified bundle |
| `sympy` (PyPI) | suspicious 0.49 | `return eval(debug_str)` in a function called at import (reads the `SYMPY_DEBUG` flag) | legitimate idiom |
| `llvmlite` (PyPI) | suspicious 0.37 | `setup.py` overrides the `install` command | legitimate custom install |
| `jupyter-builder` (PyPI) | suspicious 0.35 | a function reading credentials and calling `urllib.request.Request` (npm-registry helper) | legitimate credential use |

Reading it: the failures found on B (Python taint cascade, install-closure over-approximation) are gone,
but C fails on classes that did not occur in B. The dominant new class is the **npm binary-downloader
postinstall**: three of the six, and all three auto-blocked. This is the same ambiguity as the synthetic
`vendored_build` hard negative, and it argues against ever auto-blocking on a fetch-and-run signal
without a host allowlist. Calibrated at a 1% false-positive budget on set A (v3 threshold 0.468), v3
detects 87/95 (91.6%) of the synthetic malicious samples with 4/260 (1.5%) false positives on C.

I stopped at this point rather than tune against C. The conclusion to carry forward is methodological:
**fixing the failures of the sample you looked at does not demonstrate a lower rate**; only a fresh sample
does, and here it shows no change (6/260 for both v2 and v3).

## 3. Ablation: what each component is worth (v2, synthetic corpus, 95 malicious)

| group switched off | malicious flagged | change |
|---|---|---|
| (baseline) | 92/95 | |
| hooks (phase + reachability) | 47/95 | **-45** |
| python (AST analysis) | 55/95 | -37 |
| js | 76/95 | -16 |
| shell | 80/95 | -12 |
| metadata | 89/95 | -3 |
| blobs, infra, typosquat, yara | 92/95 | 0 |

Reading this honestly:

- **The install/import phase model is the single most valuable component** (-45), more than the Python
  analyzer itself. Without it the tool is a bag of regexes that cannot tell a library from a dropper.
- **Four components add nothing to the *flagged count* here**: blobs, infra, typosquat and YARA. For
  YARA that is by design (it overlaps the native analyzers; it exists as the portable form an analyst
  can hand to another team) and the ablation confirms its marginal contribution is nil on this corpus.
  For the others, the flagged count is a coarse measure: they change *scores* and supply IoCs and
  evidence (the payload hashes and C2 domains that campaign linking depends on), which this ablation
  does not capture. A finer-grained ablation (score deltas, campaign-linking recall) is future work.
- The synthetic corpus cannot show the value of typosquat detection, because every typosquat sample
  also contains behaviour that flags it on its own.

## 4. Performance and robustness: what real packages exposed

| problem | how it showed | fix |
|---|---|---|
| ReDoS in an infrastructure regex (leading unbounded `[\w.-]+`) | 5 of 287 packages exceeded 45 s | re-anchored on the literal suffix; rule documented in the source |
| 5-6 whole-AST walks per file + whole-tree taint fixed-point | `filelock` took 6 s, `openai` 50 s | single indexing pass, keyword prefilter, test/doc skip, large-file skip |
| reachability walked entire expression trees of generated data modules | `phonenumbers` stalled | walk statements only (imports are statements) |
| `urlsplit("http://[")` raises | uncaught crash on a real malformed URL; a trivial way to kill a scan | handled at source; per-file guard turns any analyzer exception into a recorded finding |
| a sequential scan of 287 packages | did not finish in 10 minutes | parallel batch scanner; final: 65-71 s wall-clock on 16 cores |

Per-package latency on real packages: median 0.12-0.19 s, p95 4.3-5.2 s. The maximum (~62 s, `mlflow`,
which ships large minified JavaScript bundles) slightly exceeds the 60 s budget because the budget is
checked between files, not inside one.

## 7. Evaluation against real malware

Dataset: DataDog/malicious-software-packages-dataset. Operating points fixed in advance (flag 0.35, block 0.60, and
the threshold calibrated on benign set A at 1% FPR: 0.468 for v1 and v3, 0.533 for v2). Two disjoint random
samples: M1 (669) and a reserve M2 (640) that was not fetched until a fix had been made. Handling and protocol:
README, "Evaluation against real malware".

### 7.1 First contact (M1, before the loader fix)

| group | v3 flagged | v3 blocked |
|---|---|---|
| PyPI malicious-intent (297 analysable) | 19.5% (58) | 4.7% |
| npm malicious-intent (300) | 10.7% (32) | 1.0% |
| PyPI compromised (28) | 46.4% (13) | 28.6% |
| npm compromised (40) | 12.5% (5) | 5.0% |

Implausibly low, and the structure explained why: 0 of 268 missed npm packages had a lifecycle script and 1 of 239
missed PyPI packages had a `setup.py`. In every sample the marker file is 2-9 directories deep (npm: depth 2 in 3,
4 in 243, 7 in 31, 8 in 20, 9 in 3; PyPI: depth 1 in 1, 2 in 173, 4 in 75, 7 in 6; no package had it at the root),
so the install-hook analysis never ran. **A loader bug, not a detection failure.**

### 7.2 After the fix, clean sample M2

| group | n | v1 flagged | v2 flagged | v3 flagged | v3 blocked | v3 at 1%-FPR threshold |
|---|---|---|---|---|---|---|
| PyPI malicious-intent | 297 | 66.7% | 66.7% | **65.0%** [59.4-70.2] | 46.1% | 57.6% |
| npm malicious-intent | 300 | 40.0% | 40.0% | **40.0%** [34.6-45.6] | 20.3% | 28.0% |
| npm compromised | 40 | 25.0% | 25.0% | 25.0% [14.2-40.2] | 12.5% | 17.5% |

Not a paired comparison with 7.1 (different packages), but the jump is far outside the intervals.

**The three rule sets are tied.** v2's constant folding, dynamic-import resolution and secret-variable rules, and v3's
false-positive fixes, did not change real detection. At the calibrated threshold v2 is *worse* (PyPI 50.8% vs 59.6% for
v1) because its higher threshold (0.533) is set by a benign false positive. The 11% to 89% synthetic adaptive gain
did not transfer.

### 7.3 What is still missed (M2; structure only)

| group | missed | structural facts |
|---|---|---|
| npm malicious-intent | 180 / 300 | 73 have a lifecycle script (preinstall 39, postinstall 28, prepare 9); first command token: `node` 37, `curl` 11, `wget` 6, `npm` 6; 21 use command substitution or a network tool; 36 are stubs (no script, <= 3 files); 71 have <= 3 files |
| PyPI malicious-intent | 104 / 300 | 47 have `setup.py` (10 override a command class); 7 pyproject-only; median 2 Python files; 3 unreadable |
| npm compromised | 30 / 40 | 22 have a lifecycle script (13 postinstall, 9 preinstall), 21 of them `node <file>` |

Reading it: the remaining misses are (a) beacon-style install commands that are not piped into a shell, which the
shell rules do not recognise; (b) launchers (`node file.js`) whose target file is not flagged; (c) small `setup.py`
packages; (d) stub packages with essentially nothing to analyse statically.

### 7.4 Caveats

- "Malicious" in the dataset does not guarantee a visible payload; many npm samples are probes or placeholders.
- The loader fix was derived from M1's layout (layout-generic; no rule changed). M2 is now spent for any further
  change: use a fresh sample from the unused frame (about 1,859 PyPI and 22,900 npm packages).
- Not covered: nested archives (8 of 669 M1 zips), 3 of 300 PyPI zips with no readable files, ~7% of the npm
  frame excluded as Windows-unsafe names, one dataset and one labelling scheme.
- False-positive context: at the default thresholds roughly 2% of real benign packages are flagged.

## 8. Final run: rule set v4, fresh samples M3 and D

Frozen before the fresh data was scanned; decision rule fixed in advance (README, "Final run"). v4 was developed from
a structural diagnosis of misses on M1 and M2 (aggregate feature rates only; no payload content), and its first version
was caught doubling false positives on the already-seen benign sets and fixed before M3 and D were touched.

### 8.1 Real malware, M3 (640 packages, never used before)

| group | n | v1 | v2 | v3 | v4 | v4 blocked | v4 at 1%-FPR threshold (0.468) |
|---|---|---|---|---|---|---|---|
| PyPI malicious-intent | 297 | 68.0% | 67.7% | 67.7% | 68.3% | 50.8% | 59.9% |
| npm malicious-intent | 300 | 46.7% | 46.7% | 46.7% | 56.7% | 24.7% | 37.3% |
| npm compromised | 40 | 22.5% | 22.5% | 22.5% | 25.0% | 15.0% | 17.5% |

Paired v4 vs v3 (same packages, flagged at >= 0.35): npm +30 / -0 (exact McNemar p = 1.9e-9); PyPI +2 / -0 (p = 0.5);
npm compromised +1 / -0. Combined malicious-intent 57.1% to 62.5%. Of the 30 newly caught npm packages, 23 carry an
`SH-BEACON` finding (an install-time network call with host identity), 8 an OAST-infrastructure finding, 6 a drop-site
finding, 5 a `JS-BEACON` finding (some overlap).

### 8.2 Real benign packages, all four sets (v4 = v3 on every set)

| set | n | flagged | blocked |
|---|---|---|---|
| A | 287 | 5 (1.7%) | 0 |
| B | 260 | 2 (0.8%) | 0 |
| C | 260 | 6 (2.3%) | 3 |
| **D (fresh)** | 260 | **11 (4.2%)** [2.4-7.4] | **3** |
| pooled | 1,067 | 24 (2.2%) | 6 (0.6%) |

Set D, flagged by v4 (identical to v3): `reportlab` 0.85 (blocked; fetch-and-run and beacon combos in an install-time
file), `mcp-remote` 0.67 (blocked; JS fetch-and-run and beacon), `pydeck` 0.60 (blocked; dynamic exec and a custom
install command), `poetry-core`, `omegaconf`, `setuptools`, `hatchling`, `gcsfs`, `xgboost`, `debugpy`, `uv`. Most are
Python build backends and packagers, which legitimately execute code at install time.

**Why D is higher than A, B and C, and why that is not tuning leakage.** v1 (never modified after its first run) flags
11/260 (4.2%) of D as well, against 5/287, 2/260 and 5/260 on A, B and C. The packages differ, not the rules. The honest
reading is that the false-positive rate on real benign packages is **2-4%** and sample-dependent.

### 8.3 Calibrated at a 1% false-positive budget on set A (threshold 0.468 for v3 and v4)

| rules | FPR on A | B | C | D | synthetic malicious detected |
|---|---|---|---|---|---|
| v3 | 0.7% | 0.4% | 1.5% | 1.9% | 91.6% (87/95) |
| v4 | 0.7% | 0.4% | 1.5% | 1.9% | 91.6% (87/95) |

### 8.4 What this establishes, and what it does not

Establishes: a diagnosis-driven change (v4) improved npm detection by 10 points on fresh real malware at no
false-positive cost on fresh benign packages, and the earlier synthetic-driven rounds (v2, v3) did not. Does not
establish: PyPI improvement (+0.6 points, not significant); a lower false-positive rate (the best fresh estimate is 4.2%);
or that any of this generalises beyond one dataset, one labelling scheme, and a Windows-safe subset of its names.

## 5. What this evidence supports, and what it does not

**Supported:** the phase-aware, behaviour-combination design separates install-time attack shapes
from ordinary library code on real packages at roughly a 1-2% flag rate; adaptive evasions that target
specific literal-matching assumptions can be closed by constant folding and dynamic-resolution
analysis; and the tool is safe to run against hostile input (tested).

**Not supported:** that the synthetic detection rates describe real attacks (they do not; see section 7); that 89% adaptive
detection generalises beyond the nine families it was built against (it did not move real detection); that the *malicious* tier is safe
to act on automatically (6 of 1,067 real benign packages reached it, 0.6%); anything about packages outside the two
ecosystems or the 1,067 real benign packages and 1,949 real malicious packages sampled.
