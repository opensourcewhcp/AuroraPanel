"""File Manager: the sandbox rules, the recycle bin, zip/unzip and move/copy, on any OS.

Every test confines the manager to a fresh temp folder through AURORA_FILE_ROOT, the way the
panel does it on a Pi, so nothing here touches a real folder."""
from __future__ import annotations

import json
import os
import shutil
import sys
import types
import zipfile
from pathlib import Path

import pytest

from backend import authz, files


@pytest.fixture
def root(tmp_path, monkeypatch):
    r = tmp_path / "root"
    r.mkdir()
    monkeypatch.setenv("AURORA_FILE_ROOT", str(r))
    monkeypatch.setattr(files, "FILE_ROOT", files.FILE_ROOT)   # restored afterwards
    monkeypatch.setattr(files, "TRASH_DIR", files.TRASH_DIR)
    files._refresh_root()
    return r.resolve()


def _abs(p: Path) -> str:
    return str(p)


# ------------------------------------------------------------------ the sandbox
def test_relative_paths_start_at_the_root_and_absolute_ones_are_kept(root):
    (root / "a.txt").write_text("x")
    assert files.read_text("a.txt")["path"] == files._rel(root / "a.txt")
    assert files.read_text(_abs(root / "a.txt"))["content"] == "x"
    assert files._resolve("") == root
    assert files._resolve("\\a.txt") == root / "a.txt"   # a leading backslash is not a drive escape


def test_dotdot_and_outside_absolute_paths_are_refused(root, tmp_path):
    outside = tmp_path / "secret.txt"
    outside.write_text("s")
    for bad in ("../secret.txt", "sub/../../secret.txt", _abs(outside), _abs(tmp_path)):
        with pytest.raises(files.FileError, match="limited to"):
            files.read_text(bad)
    with pytest.raises(files.FileError):
        files.list_dir(_abs(tmp_path))


def test_symlink_pointing_outside_is_refused(root, tmp_path):
    outside = tmp_path / "outside.txt"
    outside.write_text("s")
    try:
        (root / "link").symlink_to(outside)
    except OSError:
        pytest.skip("symlinks need extra rights here")
    with pytest.raises(files.FileError):
        files.read_text("link")
    with pytest.raises(files.FileError):
        files.write_text("link", "overwrite")


def test_site_manager_is_confined_to_its_own_site_folder(root, tmp_path):
    site = root / "shop"
    site.mkdir()
    (site / "index.php").write_text("<?php")
    other = root / "other"
    other.mkdir()
    token = authz.CURRENT.set({"role": "site", "sites": ["shop"],
                               "_scope": {"sites": ["shop"], "roots": [site.resolve()], "domains": ["shop.example"]}})
    try:
        assert files.read_text("index.php")["content"] == "<?php"       # relative paths start at their site
        assert files.allowed_roots() == [site.resolve()]
        assert files.list_dir("")["parent"] is None                       # no climbing above the site
        with pytest.raises(files.FileError, match="part of your websites"):
            files.list_dir(_abs(other))
        with pytest.raises(files.FileError):
            files.list_dir(_abs(root))
    finally:
        authz.CURRENT.reset(token)


def test_without_a_file_root_the_whole_machine_is_browsable(root, monkeypatch, tmp_path):
    monkeypatch.delenv("AURORA_FILE_ROOT")
    monkeypatch.setattr(files, "_roots_cache", (0.0, []))
    monkeypatch.setattr(files, "_default_user_home", lambda: tmp_path)
    assert files._allowed(tmp_path.parent.parent) is True
    roots = files.allowed_roots()
    assert tmp_path.resolve() in roots and len(roots) == len(set(roots))
    assert files.allowed_roots() is roots                                   # cached for ten seconds


def test_file_root_prefers_env_then_web_root_then_home(monkeypatch, tmp_path):
    monkeypatch.setenv("AURORA_FILE_ROOT", str(tmp_path))
    assert files.file_root() == tmp_path.resolve()
    monkeypatch.delenv("AURORA_FILE_ROOT")
    web = tmp_path / "www"
    web.mkdir()
    monkeypatch.setattr(files.sysapps, "web_root", lambda: str(web))
    assert files.file_root() == web.resolve()
    monkeypatch.setattr(files.sysapps, "web_root", lambda: None)
    monkeypatch.setattr(files, "_default_user_home", lambda: tmp_path / "home")
    assert files.file_root() == (tmp_path / "home").resolve()


def test_default_user_comes_from_sudo_user_then_the_first_home_account(monkeypatch, tmp_path):
    home = tmp_path / "home" / "pi"
    home.mkdir(parents=True)
    users = {"pi": types.SimpleNamespace(pw_name="pi", pw_uid=1000, pw_dir="/home/pi"),
             "root": types.SimpleNamespace(pw_name="root", pw_uid=0, pw_dir="/root")}
    everyone = [users["root"], types.SimpleNamespace(pw_name="svc", pw_uid=999, pw_dir="/home/svc"),
                types.SimpleNamespace(pw_name="bob", pw_uid=1001, pw_dir="/home/bob"),
                types.SimpleNamespace(pw_name="nobody", pw_uid=65534, pw_dir="/nonexistent")]

    def getpwnam(n):
        if n in users:
            return users[n]
        raise KeyError(n)
    monkeypatch.setitem(sys.modules, "pwd", types.SimpleNamespace(getpwnam=getpwnam, getpwall=lambda: everyone))
    monkeypatch.setenv("SUDO_USER", "pi")
    assert files.default_user().pw_name == "pi"
    monkeypatch.setenv("SUDO_USER", "root")                      # root is never the default user
    monkeypatch.setenv("AURORA_USER", "ghost")                   # unknown names are skipped
    real_is_dir = Path.is_dir
    monkeypatch.setattr(Path, "is_dir", lambda self: str(self) == "/home/bob" or real_is_dir(self))  # bob's home "exists"
    picked = files.default_user()
    assert picked is not None and picked.pw_name == "bob"        # uid >= 1000 with a /home folder that exists
    assert files._default_user_home() == Path("/home/bob")


def test_default_user_is_none_without_pwd(monkeypatch):
    monkeypatch.setitem(sys.modules, "pwd", None)
    assert files.default_user() is None


def test_protected_folders_include_the_root_system_dirs_and_home_folders(root, monkeypatch):
    monkeypatch.setitem(sys.modules, "pwd", types.SimpleNamespace(
        getpwall=lambda: [types.SimpleNamespace(pw_dir="/home/pi"), types.SimpleNamespace(pw_dir="/nonexistent")]))
    monkeypatch.setattr(files, "_site_roots", lambda: [root / "site"])
    assert files._protected(root)
    assert files._protected(Path("/home/pi"))
    assert files._protected(root / "site")
    assert files._protected(Path("/var/www")) and files._protected(Path("/usr/share"))
    assert not files._protected(root / "free")


def test_site_roots_survive_a_broken_sites_module(monkeypatch, tmp_path):
    from backend import sites
    good = tmp_path / "docroot"
    good.mkdir()
    monkeypatch.setattr(sites, "list_sites", lambda: {"sites": [{"docroot": str(good)}, {"docroot": str(tmp_path / "gone")}, {}]})
    assert files._site_roots() == [good.resolve()]
    monkeypatch.setattr(sites, "list_sites", lambda: 1 / 0)
    assert files._site_roots() == []


def test_trash_lives_outside_a_web_root():
    assert files._trash_dir(Path("/var/www/html")) == Path("/var/lib/aurora/file-trash")
    assert files._trash_dir(Path("/usr/share/caddy")) == Path("/var/lib/aurora/file-trash")
    assert files._trash_dir(Path("/home/pi")) == Path("/home/pi") / ".aurora-trash"


# ------------------------------------------------------------------ listing, reading, writing
def test_listing_sorts_folders_first_marks_hidden_and_hides_the_bin(root):
    (root / "zeta.txt").write_text("z")
    (root / ".hidden").write_text("h")
    (root / "alpha").mkdir()
    files.TRASH_DIR.mkdir()
    out = files.list_dir("")
    names = [e["name"] for e in out["entries"]]
    assert names == ["alpha", ".hidden", "zeta.txt"]
    assert out["entries"][1]["is_hidden"] and not out["entries"][0]["is_hidden"]
    assert out["entries"][0]["is_dir"] and out["entries"][2]["size"] == 1
    assert out["cwd"] == files._rel(root) and out["root"] == files._rel(root) and out["roots"] == [files._rel(root)]
    assert out["parent"] is None                                          # the root has no parent inside the sandbox
    assert files.list_dir("alpha")["parent"] == files._rel(root)


def test_listing_errors(root):
    (root / "f").write_text("")
    with pytest.raises(files.FileError, match="No such directory"):
        files.list_dir("missing")
    with pytest.raises(files.FileError, match="Not a directory"):
        files.list_dir("f")


def test_read_refuses_folders_big_files_and_binary(root, monkeypatch):
    (root / "d").mkdir()
    with pytest.raises(files.FileError, match="Not a file"):
        files.read_text("d")
    (root / "big.txt").write_text("x" * 10)
    monkeypatch.setattr(files, "MAX_EDIT_BYTES", 5)
    with pytest.raises(files.FileError, match="too large"):
        files.read_text("big.txt")
    monkeypatch.setattr(files, "MAX_EDIT_BYTES", 1000)
    (root / "bin.dat").write_bytes(b"\xff\xfe\x00binary")
    with pytest.raises(files.FileError, match="not UTF-8"):
        files.read_text("bin.dat")


def test_write_keeps_a_shadow_copy_and_hands_new_files_to_the_site(root, monkeypatch):
    from backend import isolate, shadow
    shadowed, owned = [], []
    monkeypatch.setattr(shadow, "before_change", lambda p: shadowed.append(Path(p)))
    monkeypatch.setattr(isolate, "owner_of", lambda p: ("site_shop", "site_shop"))
    monkeypatch.setattr(shutil, "chown", lambda p, u, g: owned.append((Path(p), u, g)))
    r = files.write_text("new.txt", "hello")
    assert r == {"path": files._rel(root / "new.txt"), "size": 5}
    assert owned == [(root / "new.txt", "site_shop", "site_shop")] and shadowed == []
    files.write_text("new.txt", "changed")
    assert shadowed == [root / "new.txt"] and len(owned) == 1               # an edit is shadowed, not re-owned
    (root / "d").mkdir()
    with pytest.raises(files.FileError, match="directory"):
        files.write_text("d", "x")


def test_shadow_and_ownership_failures_never_break_a_write(root, monkeypatch):
    from backend import isolate, shadow
    monkeypatch.setattr(shadow, "before_change", lambda p: 1 / 0)
    monkeypatch.setattr(isolate, "owner_of", lambda p: 1 / 0)
    (root / "a.txt").write_text("old")
    assert files.write_text("a.txt", "new")["size"] == 3
    assert files.write_text("b.txt", "fresh")["size"] == 5


# ------------------------------------------------------------------ delete and the recycle bin
def test_permanent_delete_removes_files_and_folders(root):
    d = root / "d"
    d.mkdir()
    (d / "inner.txt").write_text("x")
    (root / "f.txt").write_text("y")
    assert files.delete("d", permanent=True) == {"deleted": files._rel(d), "permanent": True}
    assert files.delete("f.txt", permanent=True)["permanent"] is True
    assert not d.exists() and not (root / "f.txt").exists()


def test_delete_refusals(root):
    with pytest.raises(files.FileError, match="No such path"):
        files.delete("missing.txt")
    files.TRASH_DIR.mkdir()
    with pytest.raises(files.FileError, match="recycle bin"):
        files.delete(_abs(files.TRASH_DIR))
    with pytest.raises(files.FileError, match="Refusing to delete"):
        files.delete("")


def test_soft_delete_writes_metadata_and_the_bin_lists_it(root):
    d = root / "folder"
    d.mkdir()
    (d / "a.txt").write_bytes(b"12345")
    (d / "b.txt").write_bytes(b"678")
    r = files.delete("folder")
    tid = r["id"]
    assert files._valid_tid(tid) and r["trashed"] == files._rel(d)
    meta = json.loads((files.TRASH_DIR / f"{tid}.json").read_text())
    assert meta["name"] == "folder" and meta["is_dir"] is True and meta["original_parent"] == files._rel(root)
    (files.TRASH_DIR / "broken.json").write_text("{not json")        # a damaged entry is skipped, not fatal
    items = files.list_trash()["items"]
    assert [i["id"] for i in items] == [tid]
    assert items[0]["size"] == 8 and items[0]["exists"] is True


def test_restore_refuses_bad_ids_missing_items_and_clashes(root):
    with pytest.raises(files.FileError, match="Invalid id"):
        files.restore_trash("../x")
    with pytest.raises(files.FileError, match="not found"):
        files.restore_trash("1-abcdef")
    (root / "c.txt").write_text("v1")
    tid = files.delete("c.txt")["id"]
    (root / "c.txt").write_text("v2")
    with pytest.raises(files.FileError, match="already exists"):
        files.restore_trash(tid)
    assert files.restore_trash(tid, overwrite=True) == {"restored": files._rel(root / "c.txt")}
    assert (root / "c.txt").read_text() == "v1"
    assert not (files.TRASH_DIR / f"{tid}.json").exists()


def test_restore_overwrites_a_folder_and_recreates_a_missing_parent(root):
    d = root / "p" / "q"
    d.mkdir(parents=True)
    (d / "x").write_text("keep")
    tid = files.delete("p/q")["id"]
    shutil.rmtree(root / "p")
    files.restore_trash(tid)
    assert (d / "x").read_text() == "keep"
    tid2 = files.delete("p/q")["id"]
    d.mkdir(parents=True)
    (d / "other").write_text("new")
    files.restore_trash(tid2, overwrite=True)
    assert (d / "x").exists() and not (d / "other").exists()


def test_delete_one_trash_item_and_empty_the_bin(root):
    (root / "a").mkdir()
    (root / "b.txt").write_text("b")
    ta = files.delete("a")["id"]
    tb = files.delete("b.txt")["id"]
    with pytest.raises(files.FileError):
        files.delete_trash("bad")
    assert files.delete_trash(ta) == {"ok": True}
    assert files.delete_trash(ta) == {"ok": True}                          # already gone: still fine
    assert [i["id"] for i in files.list_trash()["items"]] == [tb]
    assert files.empty_trash() == {"emptied": 1}
    assert files.list_trash() == {"items": []}
    assert files.empty_trash() == {"emptied": 0}


def test_dir_size_skips_unreadable_entries(root, monkeypatch):
    d = root / "d"
    d.mkdir()
    (d / "a").write_bytes(b"1234")
    (d / "b").write_bytes(b"56")
    assert files._dir_size(d) == 6
    real = os.lstat
    monkeypatch.setattr(os, "lstat", lambda p: (_ for _ in ()).throw(OSError()) if str(p).endswith("b") else real(p))
    assert files._dir_size(d) == 4


# ------------------------------------------------------------------ zip and unzip
def test_zip_a_folder_and_a_file_then_unzip_into_a_folder(root):
    d = root / "site"
    d.mkdir()
    (d / "sub").mkdir()
    (d / "sub" / "deep.txt").write_text("deep")
    (root / "note.txt").write_text("note")
    r = files.zip_entries("", ["site", "note.txt"], "backup")             # .zip is added
    assert r == {"archive": files._rel(root / "backup.zip"), "count": 2}
    with zipfile.ZipFile(root / "backup.zip") as z:
        assert sorted(z.namelist()) == ["note.txt", "site/sub/deep.txt"]
    with pytest.raises(files.FileError, match="already exists"):
        files.zip_entries("", ["note.txt"], "backup.zip")
    assert files.zip_entries("", ["note.txt"], "backup.zip", overwrite=True)["count"] == 1
    out = files.unzip("backup.zip")
    assert out == {"extracted_to": files._rel(root / "backup"), "count": 1}
    assert (root / "backup" / "note.txt").read_text() == "note"
    with pytest.raises(files.FileError, match="already exists"):
        files.unzip("backup.zip")
    assert files.unzip("backup.zip", overwrite=True)["count"] == 1


def test_zip_refusals(root):
    (root / "f").write_text("")
    with pytest.raises(files.FileError, match="Not a directory"):
        files.zip_entries("f", ["x"], "a.zip")
    with pytest.raises(files.FileError, match="Nothing selected"):
        files.zip_entries("", [], "a.zip")
    with pytest.raises(files.FileError, match="Invalid archive name"):
        files.zip_entries("", ["f"], "../a.zip")
    with pytest.raises(files.FileError, match="Not found"):
        files.zip_entries("", ["missing"], "a.zip")
    assert not (root / "a.zip").exists()


def test_unzip_refuses_non_zip_and_zip_slip(root):
    (root / "plain.txt").write_text("x")
    with pytest.raises(files.FileError, match="Not a .zip"):
        files.unzip("plain.txt")
    with zipfile.ZipFile(root / "evil.zip", "w") as z:
        z.writestr("ok.txt", "fine")
        z.writestr("../../escaped.txt", "x")
    with pytest.raises(files.FileError, match="Unsafe path"):
        files.unzip("evil.zip")
    assert not (root.parent / "escaped.txt").exists() and not (root / "evil" / "ok.txt").exists()


# ------------------------------------------------------------------ folders, moves, uploads
def test_make_dir_validates_the_name_and_parent(root):
    assert files.make_dir("", "new") == {"created": files._rel(root / "new")}
    for bad in ("", "a/b", "a\\b", ".", ".."):
        with pytest.raises(files.FileError, match="Invalid folder name"):
            files.make_dir("", bad)
    (root / "f").write_text("")
    with pytest.raises(files.FileError, match="Parent is not a directory"):
        files.make_dir("f", "x")
    with pytest.raises(FileExistsError):
        files.make_dir("", "new")


def test_transfer_copies_folders_skips_missing_and_refuses_bad_modes(root):
    src = root / "src"
    src.mkdir()
    (src / "d").mkdir()
    (src / "d" / "in.txt").write_text("in")
    dst = root / "dst"
    dst.mkdir()
    with pytest.raises(files.FileError, match="Unknown operation"):
        files.transfer("src", ["d"], "dst", "rename")
    r = files.transfer("src", ["d", "nope", ".", ""], "dst", "copy")
    assert r["copied"] == ["d"] and r["skipped"] == ["nope"] and r["dest"] == files._rel(dst)
    assert (dst / "d" / "in.txt").read_text() == "in" and (src / "d" / "in.txt").exists()
    same = files.transfer("src", ["d"], "src", "move")                   # onto itself: nothing to do
    assert same["moved"] == [] and same["skipped"] == ["d"]


def test_transfer_overwrite_replaces_and_shadows_the_old_copy(root, monkeypatch):
    from backend import shadow
    shadowed = []
    monkeypatch.setattr(shadow, "before_change", lambda p: shadowed.append(Path(p).name))
    (root / "src").mkdir()
    (root / "dst").mkdir()
    (root / "src" / "f.txt").write_text("new")
    (root / "dst" / "f.txt").write_text("old")
    (root / "src" / "d").mkdir()
    (root / "dst" / "d").mkdir()
    (root / "dst" / "d" / "stale").write_text("")
    r = files.transfer("src", ["f.txt", "d"], "dst", "move", overwrite=True)
    assert r["moved"] == ["f.txt", "d"]
    assert (root / "dst" / "f.txt").read_text() == "new" and not (root / "dst" / "d" / "stale").exists()
    assert shadowed == ["f.txt", "f.txt", "d", "d"]                       # the target and the source, each


def test_transfer_never_moves_a_protected_folder(root, monkeypatch):
    (root / "keep").mkdir()
    (root / "dst").mkdir()
    monkeypatch.setattr(files, "_protected", lambda p: p.name == "keep")
    with pytest.raises(files.FileError, match="Refusing to move keep"):
        files.transfer("", ["keep"], "dst", "move")
    assert files.transfer("", ["keep"], "dst", "copy")["copied"] == ["keep"]


def test_transfer_refuses_a_non_folder_destination_and_self_nesting(root):
    (root / "a").mkdir()
    (root / "a" / "b").mkdir()
    (root / "file").write_text("")
    with pytest.raises(files.FileError, match="not a folder"):
        files.transfer("", ["a"], "file", "copy")
    with pytest.raises(files.FileError, match="into itself"):
        files.transfer("", ["a"], "a/b", "copy")
    assert files._within(root / "a" / "b", root / "a") and not files._within(root / "file", root / "a")


def test_upload_validates_names_and_overwrites_with_a_shadow(root, monkeypatch):
    from backend import shadow
    shadowed = []
    monkeypatch.setattr(shadow, "before_change", lambda p: shadowed.append(Path(p).name))
    assert files.save_upload("", "../../evil.txt", b"abc") == {"uploaded": files._rel(root / "evil.txt"), "size": 3}
    assert (root / "evil.txt").read_bytes() == b"abc" and not (root.parent / "evil.txt").exists()
    files.save_upload("", "evil.txt", b"x")
    assert shadowed == ["evil.txt"]
    for bad in ("", ".", "..", "dir/"):
        with pytest.raises(files.FileError, match="Invalid filename"):
            files.save_upload("", bad, b"")
    with pytest.raises(files.FileError, match="not a directory"):
        files.save_upload("evil.txt", "x", b"")


def test_download_resolves_only_files(root):
    (root / "d").mkdir()
    (root / "f.txt").write_text("")
    assert files.resolve_for_download("f.txt") == root / "f.txt"
    with pytest.raises(files.FileError, match="Not a file"):
        files.resolve_for_download("d")
    with pytest.raises(files.FileError):
        files.resolve_for_download("../f.txt")
