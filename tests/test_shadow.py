"""Shadow Copies: snapshots, versions, limits, restore, deletion — against a temporary store and site."""
import os
import time

import pytest

from backend import shadow


@pytest.fixture
def site(tmp_path, monkeypatch):
    root = tmp_path / "site"
    (root / "css").mkdir(parents=True)
    (root / "index.html").write_text("v1", encoding="utf-8")
    (root / "css" / "a.css").write_text("a{}", encoding="utf-8")
    (root / "cache").mkdir()
    (root / "cache" / "x.tmp").write_text("junk", encoding="utf-8")
    store_root = tmp_path / "store"
    monkeypatch.setattr(shadow, "ROOT", store_root)
    monkeypatch.setattr(shadow, "CONF", store_root / "config.json")
    monkeypatch.setattr(shadow, "targets", lambda: [{"id": "folder:t", "kind": "folder", "name": "/t", "path": str(root), "enabled_site": True}])
    shadow._roots_cache = (0.0, [])
    monkeypatch.setattr(shadow, "_target", lambda sid: {"id": "folder:t", "kind": "folder", "name": "/t", "path": str(root)})
    return root


def _enable(monkeypatch):
    d = shadow._load(); d["sites"]["folder:t"] = {"enabled": True}; shadow._save(d)


def test_snapshot_copies_once_and_again_on_change(site, monkeypatch):
    _enable(monkeypatch)
    r = shadow.snapshot("folder:t")
    assert r["changes"] == 2  # index.html + css/a.css; the cache folder isn't even walked
    assert not any(x["path"].startswith("cache/") for x in shadow.files("folder:t")["files"])
    assert shadow.snapshot("folder:t")["changes"] == 0  # nothing changed
    time.sleep(0.01)
    (site / "index.html").write_text("v2", encoding="utf-8")
    os.utime(site / "index.html", (time.time() + 5, time.time() + 5))
    assert shadow.snapshot("folder:t")["changes"] == 1
    f = shadow.files("folder:t")
    idx = next(x for x in f["files"] if x["path"] == "index.html")
    assert len(idx["versions"]) == 2 and idx["status"] == "current"


def test_restore_brings_back_old_and_deleted(site, monkeypatch):
    _enable(monkeypatch)
    shadow.snapshot("folder:t")
    first = shadow.files("folder:t")["files"]
    v = next(x for x in first if x["path"] == "index.html")["versions"][0]["ts"]
    (site / "index.html").write_text("broken", encoding="utf-8")
    shadow.restore("folder:t", "index.html", v)
    assert (site / "index.html").read_text(encoding="utf-8") == "v1"
    # the restore kept "broken" as a version, so it can be undone too
    assert len(next(x for x in shadow.files("folder:t")["files"] if x["path"] == "index.html")["versions"]) == 2
    (site / "css" / "a.css").unlink()
    gone = next(x for x in shadow.files("folder:t")["files"] if x["path"] == "css/a.css")
    assert gone["status"] == "deleted"
    shadow.restore("folder:t", "css/a.css", gone["versions"][0]["ts"])
    assert (site / "css" / "a.css").read_text(encoding="utf-8") == "a{}"


def test_before_change_saves_the_old_content(site, monkeypatch):
    _enable(monkeypatch)
    shadow.before_change(site / "index.html")  # first sight: copied
    (site / "index.html").write_text("edited", encoding="utf-8")
    os.utime(site / "index.html", (time.time() + 5, time.time() + 5))
    shadow.before_change(site / "index.html")  # changed: copied again
    vs = next(x for x in shadow.files("folder:t")["files"] if x["path"] == "index.html")["versions"]
    assert len(vs) == 2
    assert shadow.version_path("folder:t", "index.html", vs[0]["ts"]).read_text(encoding="utf-8") == "edited"
    assert shadow.version_path("folder:t", "index.html", vs[1]["ts"]).read_text(encoding="utf-8") == "v1"


def test_limits_prune_oldest_but_keep_newest(site, monkeypatch):
    _enable(monkeypatch)
    store = shadow._store("folder:t")
    vd = shadow._ver_dir(store, "index.html"); vd.mkdir(parents=True)
    now = int(time.time())
    for i in range(6):
        (vd / str(now - 86400 * 40 + i)).write_bytes(b"x" * 100)  # 6 old versions (40 days ago)
    (vd / str(now)).write_bytes(b"y" * 100)
    shadow.set_settings("folder:t", keep_days=30, max_versions=3)
    left = shadow._versions(vd)
    assert len(left) == 1 and left[0][0] == now  # old ones pruned, newest kept
    with pytest.raises(shadow.ShadowError):
        shadow.set_settings("folder:t", max_mb=1)


def test_drop_and_forget(site, monkeypatch):
    _enable(monkeypatch)
    shadow.snapshot("folder:t")
    shadow.forget("folder:t", "index.html")
    assert not any(x["path"] == "index.html" for x in shadow.files("folder:t")["files"])
    shadow.drop("folder:t")
    assert not shadow._store("folder:t").exists() and "folder:t" not in shadow._load()["sites"]


def test_wanted_skips_junk():
    assert shadow._wanted(("css", "a.css"), "a.css", 10, 1000)
    assert not shadow._wanted(("node_modules", "x.js"), "x.js", 10, 1000)
    assert not shadow._wanted(("a.log",), "a.log", 10, 1000)
    assert not shadow._wanted((".DS_Store",), ".DS_Store", 10, 1000)
    assert shadow._wanted((".htaccess",), ".htaccess", 10, 1000)
    assert not shadow._wanted(("big.zip",), "big.zip", 5000, 1000)
