"""File Manager, confined to a temp folder by AURORA_FILE_ROOT (see conftest)."""
import sys

import pytest

from backend import files

pytestmark = pytest.mark.skipif(not sys.platform.startswith("linux"), reason="Linux paths (the panel runs on a Pi)")


def test_write_read_list(files_root):
    files.write_text(str(files_root / "a.txt"), "hello")
    assert files.read_text("a.txt")["content"] == "hello"  # relative paths start at the root
    names = [e["name"] for e in files.list_dir("")["entries"]]
    assert names == ["a.txt"]


def test_mkdir_upload_zip_unzip(files_root):
    files.make_dir("", "sub")
    files.save_upload("sub", "b.txt", b"data")
    files.zip_entries("sub", ["b.txt"], "b.zip")
    files.delete(str(files_root / "sub" / "b.txt"), permanent=True)
    files.unzip(str(files_root / "sub" / "b.zip"))  # extracts into a folder named after the zip
    assert (files_root / "sub" / "b" / "b.txt").read_bytes() == b"data"


def test_zip_slip_refused(files_root):
    import zipfile
    with zipfile.ZipFile(files_root / "evil.zip", "w") as z:
        z.writestr("../escaped.txt", "x")
    with pytest.raises(files.FileError):
        files.unzip("evil.zip")
    assert not (files_root.parent / "escaped.txt").exists()


def test_trash_and_restore(files_root):
    (files_root / "c.txt").write_text("x")
    tid = files.delete(str(files_root / "c.txt"))["id"]
    assert not (files_root / "c.txt").exists()
    assert any(i["id"] == tid for i in files.list_trash()["items"])
    files.restore_trash(tid)
    assert (files_root / "c.txt").read_text() == "x"


@pytest.mark.parametrize("path", ["../outside", "/etc/passwd", "sub/../../x"])
def test_cannot_escape_root(files_root, path):
    with pytest.raises(files.FileError):
        files.read_text(path)


def test_symlink_escape_blocked(files_root, tmp_path):
    outside = tmp_path / "secret.txt"
    outside.write_text("s")
    try:
        (files_root / "link").symlink_to(outside)
    except OSError:
        pytest.skip("symlinks not allowed here")
    with pytest.raises(files.FileError):
        files.read_text("link")


def test_root_cannot_be_deleted(files_root):
    with pytest.raises(files.FileError):
        files.delete(str(files_root))


def test_transfer_copy_then_move(files_root):
    files.make_dir("", "src")
    files.make_dir("", "dst")
    files.save_upload("src", "f.txt", b"hi")
    r = files.transfer("src", ["f.txt"], "dst", "copy")
    assert r["copied"] == ["f.txt"] and r["clashed"] == []
    assert (files_root / "src" / "f.txt").read_bytes() == b"hi"   # original stays
    assert (files_root / "dst" / "f.txt").read_bytes() == b"hi"   # copy made
    r2 = files.transfer("src", ["f.txt"], "dst", "move")          # dst already has it
    assert r2["clashed"] == ["f.txt"] and r2["moved"] == []
    assert (files_root / "src" / "f.txt").exists()                # untouched without overwrite
    r3 = files.transfer("src", ["f.txt"], "dst", "move", overwrite=True)
    assert r3["moved"] == ["f.txt"]
    assert not (files_root / "src" / "f.txt").exists()            # moved out


def test_transfer_folder_into_itself_refused(files_root):
    files.make_dir("", "d")
    files.make_dir("d", "inner")
    with pytest.raises(files.FileError):
        files.transfer("", ["d"], "d/inner", "move")


def test_transfer_dest_must_be_folder(files_root):
    files.save_upload("", "x.txt", b"z")
    with pytest.raises(files.FileError):
        files.transfer("", ["x.txt"], "x.txt", "move")


def test_protected_folders():
    from pathlib import Path
    for p in ("/", "/etc", "/home", "/usr", "/var", "/var/www", "/var/lib", "/usr/bin", "/etc/apache2"):
        if p == "/etc/apache2" and not Path(p).is_dir():
            continue
        assert files._protected(Path(p)), p
    assert not files._protected(Path("/opt/some/app/file.txt"))
