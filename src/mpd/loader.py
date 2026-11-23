"""Load a package from a directory or archive into an in-memory PackageView.

Safety properties (each has a test):
  * Nothing is ever extracted to disk, imported, or executed. Archive members are read
    as bytes, so path-traversal ("zip slip") names cannot write anywhere.
  * Symlinks and special files are skipped, never followed.
  * Per-file, per-archive and file-count caps bound memory and CPU, so a decompression
    bomb or a million-file archive degrades to a note instead of hanging the analyst.
"""

from __future__ import annotations

import json
import os
import re
import tarfile
import zipfile
from email.parser import Parser
from pathlib import Path, PurePosixPath

from .models import PackageView

MAX_FILES = 5000
MAX_FILE_BYTES = 2_000_000
MAX_TOTAL_BYTES = 80_000_000
MAX_ARCHIVE_UNCOMPRESSED = 600_000_000   # stop walking a tar that claims more than this
SKIP_DIRS = {".git", ".hg", ".svn", "node_modules", "__pycache__"}


class LoadError(Exception):
    pass


def _safe_name(raw: str) -> str | None:
    """Normalise an archive member name; None if it is absolute or traverses upward."""
    name = raw.replace("\\", "/")
    if name.startswith("/") or re.match(r"^[A-Za-z]:", name):
        return None
    parts = [p for p in PurePosixPath(name).parts if p not in ("", ".")]
    if not parts or any(p == ".." for p in parts):
        return None
    return "/".join(parts)


class _Budget:
    def __init__(self, notes: list[str]) -> None:
        self.files = 0
        self.total = 0
        self.notes = notes
        self.exhausted = False

    def admit(self, name: str, size: int) -> bool:
        if self.exhausted:
            return False
        if self.files >= MAX_FILES:
            self.notes.append(f"file-count cap ({MAX_FILES}) reached; remaining files not analysed")
            self.exhausted = True
            return False
        if size > MAX_FILE_BYTES:
            self.notes.append(f"skipped oversized file {name} ({size} bytes)")
            return False
        if self.total + size > MAX_TOTAL_BYTES:
            self.notes.append("total-size cap reached; remaining files not analysed")
            self.exhausted = True
            return False
        self.files += 1
        self.total += size
        return True


def _read_dir(root: Path, notes: list[str]) -> dict[str, bytes]:
    files: dict[str, bytes] = {}
    budget = _Budget(notes)
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames[:] = sorted(d for d in dirnames
                             if d not in SKIP_DIRS and not os.path.islink(os.path.join(dirpath, d)))
        for fn in sorted(filenames):
            full = os.path.join(dirpath, fn)
            if os.path.islink(full) or not os.path.isfile(full):
                continue
            rel = os.path.relpath(full, root).replace(os.sep, "/")
            try:
                size = os.path.getsize(full)
                if not budget.admit(rel, size):
                    if budget.exhausted:
                        return files
                    continue
                with open(full, "rb") as fh:
                    files[rel] = fh.read(MAX_FILE_BYTES)
            except OSError as exc:
                notes.append(f"unreadable {rel}: {exc.__class__.__name__}")
    return files


def _read_tar(path: Path, notes: list[str]) -> dict[str, bytes]:
    files: dict[str, bytes] = {}
    budget = _Budget(notes)
    claimed = 0
    try:
        tf = tarfile.open(path, "r:*")
    except (tarfile.TarError, OSError, EOFError) as exc:
        raise LoadError(f"cannot open tar archive: {exc}") from exc
    with tf:
        try:
            for member in tf:
                claimed += max(member.size, 0)
                if claimed > MAX_ARCHIVE_UNCOMPRESSED:
                    notes.append("archive claims an implausible uncompressed size; stopped reading")
                    break
                if not member.isfile():
                    if member.issym() or member.islnk():
                        notes.append(f"skipped link member {member.name}")
                    continue
                name = _safe_name(member.name)
                if name is None:
                    notes.append(f"skipped unsafe member name {member.name!r}")
                    continue
                if not budget.admit(name, member.size):
                    if budget.exhausted:
                        break
                    continue
                fh = tf.extractfile(member)
                if fh is not None:
                    files[name] = fh.read(MAX_FILE_BYTES)
        except (tarfile.TarError, OSError, EOFError) as exc:
            notes.append(f"archive truncated or corrupt: {exc.__class__.__name__}")
    return files


def _read_zip(path: Path, notes: list[str], pwd: bytes | None = None) -> dict[str, bytes]:
    files: dict[str, bytes] = {}
    budget = _Budget(notes)
    try:
        zf = zipfile.ZipFile(path)
    except (zipfile.BadZipFile, OSError) as exc:
        raise LoadError(f"cannot open zip archive: {exc}") from exc
    with zf:
        for info in zf.infolist():
            if info.is_dir():
                continue
            name = _safe_name(info.filename)
            if name is None:
                notes.append(f"skipped unsafe member name {info.filename!r}")
                continue
            if not budget.admit(name, info.file_size):
                if budget.exhausted:
                    break
                continue
            try:
                with zf.open(info, pwd=pwd) as fh:
                    files[name] = fh.read(MAX_FILE_BYTES)
            except (zipfile.BadZipFile, RuntimeError, OSError, NotImplementedError) as exc:
                # RuntimeError = password required/wrong; NotImplementedError = AES-encrypted member
                notes.append(f"unreadable member {name}: {exc.__class__.__name__}")
    return files


def _strip_common_prefix(files: dict[str, bytes]) -> dict[str, bytes]:
    """sdists and npm tarballs wrap everything in one top directory; remove it."""
    if not files or not all("/" in p for p in files):
        return files
    tops = {p.split("/", 1)[0] for p in files}
    if len(tops) != 1:
        return files
    prefix = next(iter(tops)) + "/"
    return {p[len(prefix):]: d for p, d in files.items()}



_ROOT_MARKERS = {"npm": ("package.json",), "pypi": ("setup.py", "PKG-INFO", "pyproject.toml", "setup.cfg")}
_VENDORED = ("node_modules/", "site-packages/", "/node_modules/", "/site-packages/", "__pycache__/")
MAX_ROOT_DEPTH = 10


def _has_marker_at_root(files: dict[str, bytes], eco: str | None) -> bool:
    ecos = (eco,) if eco else tuple(_ROOT_MARKERS)
    if any(m in files for e in ecos for m in _ROOT_MARKERS[e]):
        return True
    return eco in (None, "pypi") and any(n.count("/") == 1 and n.split("/")[0].endswith(".dist-info") for n in files)


def _locate_package_root(files: dict[str, bytes], eco: str | None, notes: list[str]) -> dict[str, bytes]:
    """Re-root archives that nest the package under extra directories.

    Registry tarballs wrap the package in exactly one directory, which ``_strip_common_prefix`` removes. Datasets
    and some build outputs store the package at an arbitrary depth (the original filesystem path). Everything
    downstream keys on root-level names (``package.json``, ``setup.py``), so a package nested even one level too
    deep silently loses its install-hook analysis. This finds the SHALLOWEST directory that directly contains a
    marker file and makes it the root. Vendored trees (node_modules, site-packages) are never chosen. Files outside
    the chosen root are kept (prefixed ``_outside_root/``) so nothing is hidden from the scan.
    A package that already has a marker at its root is returned unchanged.
    """
    if _has_marker_at_root(files, eco):
        return files
    ecos = (eco,) if eco else tuple(_ROOT_MARKERS)
    candidates: dict[str, int] = {}
    for name in files:
        if any(v in name for v in _VENDORED):
            continue
        base = name.rsplit("/", 1)[-1]
        if any(base in _ROOT_MARKERS[e] for e in ecos):
            d = name.rsplit("/", 1)[0] if "/" in name else ""
            if d.count("/") < MAX_ROOT_DEPTH:
                candidates[d] = candidates.get(d, 0) + 1
    if not candidates:
        return files
    root = min(candidates, key=lambda d: (d.count("/"), -sum(1 for n in files if n.startswith(d + "/")), d))
    if root == "":
        return files
    prefix = root + "/"
    out: dict[str, bytes] = {}
    outside = 0
    for name, data in files.items():
        if name.startswith(prefix):
            out[name[len(prefix):]] = data
        else:
            out["_outside_root/" + name] = data
            outside += 1
    notes.append(f"package root found {root.count('/') + 1} level(s) deep; re-rooted ({outside} file(s) outside it kept as _outside_root/)")
    return out


def _detect_ecosystem(files: dict[str, bytes], path: Path) -> str:
    if "package.json" in files:
        return "npm"
    if path.suffix == ".whl":
        return "pypi"
    names = set(files)
    if names & {"setup.py", "pyproject.toml", "PKG-INFO", "setup.cfg"}:
        return "pypi"
    if any(n.endswith(".dist-info/METADATA") for n in names):
        return "pypi"
    if any(n.endswith(".py") for n in names):
        return "pypi"
    if any(n.endswith((".js", ".cjs", ".mjs")) for n in names):
        return "npm"
    raise LoadError("cannot determine ecosystem; pass --ecosystem pypi|npm")


_ARCHIVE_SUFFIXES = (".tar.gz", ".tgz", ".tar.bz2", ".tar.xz", ".tar", ".whl", ".zip")


def _name_version_from_filename(path: Path) -> tuple[str, str]:
    base = path.name
    for suf in _ARCHIVE_SUFFIXES:
        if base.lower().endswith(suf):
            base = base[: -len(suf)]
            break
    m = re.match(r"^(?P<name>.+?)-(?P<ver>\d[^-]*)", base)
    if m:
        return m.group("name"), m.group("ver")
    return base, ""


def _identify(eco: str, files: dict[str, bytes], path: Path, notes: list[str]):
    name = version = ""
    meta: dict = {}
    if eco == "npm":
        raw = files.get("package.json")
        if raw is not None:
            try:
                pj = json.loads(raw.decode("utf-8", errors="replace"))
                if isinstance(pj, dict):
                    meta["package_json"] = pj
                    name = str(pj.get("name") or "")
                    version = str(pj.get("version") or "")
                else:
                    notes.append("package.json is not a JSON object")
            except ValueError:
                notes.append("package.json is not valid JSON")
    else:
        header_file = "PKG-INFO" if "PKG-INFO" in files else next(
            (n for n in files if n.endswith(".dist-info/METADATA")), None)
        if header_file:
            msg = Parser().parsestr(files[header_file].decode("utf-8", errors="replace"), headersonly=True)
            name = msg.get("Name", "") or ""
            version = msg.get("Version", "") or ""
            meta["headers"] = {k: msg.get(k, "") for k in
                               ("Name", "Version", "Summary", "Home-page", "Author", "Author-email")}
            meta["project_urls"] = msg.get_all("Project-URL") or []
        elif "setup.py" in files:
            text = files["setup.py"].decode("utf-8", errors="replace")
            # Regex only. We must never execute setup.py to learn the name.
            mn = re.search(r"""\bname\s*=\s*['"]([^'"]+)['"]""", text)
            mv = re.search(r"""\bversion\s*=\s*['"]([^'"]+)['"]""", text)
            name = mn.group(1) if mn else ""
            version = mv.group(1) if mv else ""
    if not name or not version:
        fname, fver = _name_version_from_filename(path)
        if path.is_dir():
            fname, fver = path.name, ""
        name = name or fname
        version = version or fver
    return name, version, meta


def package_from_files(files: dict[str, bytes], ecosystem: str, source: str = "<memory>") -> PackageView:
    """Build a PackageView from in-memory files (used by the synthetic corpus and tests)."""
    notes: list[str] = []
    name, version, meta = _identify(ecosystem, files, Path(source), notes)
    return PackageView(ecosystem=ecosystem, name=name, version=version, files=files,
                       source=source, metadata=meta, notes=notes)


def load_package(path: str | os.PathLike, ecosystem: str | None = None,
                 zip_password: str | bytes | None = None) -> PackageView:
    p = Path(path)
    notes: list[str] = []
    if p.is_dir():
        files = _read_dir(p, notes)
    elif p.is_file():
        suffix = p.suffix.lower()
        if suffix in (".zip", ".whl"):
            pwd = zip_password.encode() if isinstance(zip_password, str) else zip_password
            files = _read_zip(p, notes, pwd)
        else:
            files = _read_tar(p, notes)
        files = _strip_common_prefix(files)
    else:
        raise LoadError(f"no such file or directory: {p}")
    if not files:
        raise LoadError(f"no readable files found in {p}")
    files = _locate_package_root(files, ecosystem, notes)
    eco = ecosystem or _detect_ecosystem(files, p)
    if eco not in ("pypi", "npm"):
        raise LoadError(f"unsupported ecosystem {eco!r}")
    name, version, meta = _identify(eco, files, p, notes)
    return PackageView(ecosystem=eco, name=name, version=version, files=files,
                       source=str(p), metadata=meta, notes=notes)
