# Threat model

## What is being defended

A developer, a CI job, or an AI coding agent runs `pip install` / `npm install` on a package from a
public registry. The package is attacker-controlled. The goal of this tool is to decide, **before any
of the package's code has run**, whether it should be blocked or sent to a human.

## The attacker

Publishes a package to PyPI or npm. Common routes, all of which the tool models:

| Route | What the attacker relies on | Where the tool looks |
|---|---|---|
| Typosquatting / combosquatting | a mistyped or plausible name | `analyzers/typosquat.py` |
| Dependency confusion | an inflated version beating a private package | `analyzers/metadata.py` |
| Malicious install script | code runs at install, before review, often in CI with secrets | `analyzers/install_hooks.py` |
| `.pth` / `sitecustomize` | executes on every interpreter start | `analyzers/install_hooks.py` |
| Obfuscated dropper | string matching sees only noise | `deobfuscate.py`, `analyzers/blobs.py` |
| Credential / environment theft | secrets sit in env vars and dotfiles | `python_ast.py`, `javascript.py` |
| Exfiltration to chat webhooks, tunnels, OAST | cheap, anonymous infrastructure | `analyzers/infra.py` |
| Persistence | shell rc files, cron, startup folders | `shell.py`, `python_ast.py` |

The attacker is **adaptive**: they can read this tool's source and write code to evade it. That is
why the evaluation includes an adaptive set, and why the README reports what still gets through.

## Trust boundaries and what the tool guarantees

1. **Package bytes are untrusted input to the analyst's machine.** The tool never executes, imports,
   installs or extracts to disk any package content. Archives are read member-by-member into memory;
   traversal names, symlinks and oversized members are skipped; per-file, per-archive and file-count
   caps bound memory; a wall-clock budget bounds CPU. Each of these has a test.
2. **The analyzers themselves are attack surface.** Crafted input that crashes or stalls a scanner is an
   evasion technique. Malformed URLs, NUL bytes, deep nesting, decompression bombs and a ReDoS found in
   an earlier version of this tool's own regexes are all covered by tests; a crash on one file is
   contained, recorded as a finding, and the scan continues.
3. **Output is safe to paste.** IoCs are defanged (`hxxp://c2[.]example`) in reports.

## Explicitly out of scope

- **Dynamic analysis.** No sandbox, no execution, no network capture. A package whose behaviour depends
  on runtime state, time, or a second-stage download that is not in the archive cannot be fully judged
  statically. The report says so.
- **Native binaries** (`.so`, `.node`, `.exe`) are not disassembled.
- **Registry context** (publish time, maintainer history, download counts) is not available offline.
  Dependency-confusion detection therefore sees only the *shape* (version number) of the attack.
- **Cross-file data flow.** The scanner follows the package's import graph for phase, not data between
  modules. A fetch in one file and an `exec` in another is a known miss (`a2_split_across_files`).
- **Compliance claims.** This is a research prototype, not a certified control.

## Ethics and handling

- The synthetic malicious corpus is **inert by construction**: reserved `.example` hosts only, zeroed
  or `FAKE` webhook identifiers, secrets referenced by name and never present, built in memory and
  never executed. A test asserts every host and webhook in the corpus meets this rule.
- The synthetic corpus contains no real malware. **Real malware was later evaluated** from a public dataset
  (DataDog/malicious-software-packages-dataset) with these precautions: the samples stay as opaque zips and are
  read in memory, never extracted, imported or executed; every run uses `python -I`; blobs are copied out of git's
  object store under hash-derived filenames, so no repository-controlled path is written and git's path validation
  is left on; the data directory is gitignored; and reports contain rule ids, counts and package names, never
  payload content. An isolated VM or container with no credentials is still the better place to do this, and was
  not used here: the machine that ran it holds credentials, which is acceptable only because nothing is executed.
- Real **benign** packages are downloaded as opaque archives into a dedicated directory, verified
  against the registry's digests, and read in memory by the scanner (run with `python -I`).
