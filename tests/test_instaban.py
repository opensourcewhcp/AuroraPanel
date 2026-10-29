"""InstaBan: patterns, matching, log scanning with bans, import/export; and the Activity Log clean-up."""
from __future__ import annotations

import json
import os
import time
from pathlib import Path

import pytest

from backend import audit, guard, instaban


@pytest.fixture
def ib(tmp_path, monkeypatch):
    monkeypatch.setattr(instaban, "STATE", tmp_path / "instaban.json")
    logs = tmp_path / "apache2"
    logs.mkdir()
    monkeypatch.setattr(instaban, "LOG_DIR", logs)
    bans: list[tuple] = []
    monkeypatch.setattr(guard, "ban", lambda ip, reason="", duration=None, client_ip=None, source="": bans.append((ip, reason, duration, source)) or {"ok": True})
    monkeypatch.setattr(guard, "is_trusted", lambda ip: ip.startswith("10.0.0."))
    monkeypatch.setattr(guard, "trusted_cidrs", lambda: ["10.0.0.0/8"])
    return {"logs": logs, "bans": bans}


LINE = '{ip} - - [28/Oct/2026:19:40:00 -0700] "GET {target} HTTP/1.1" 404 196 "-" "Mozilla/5.0 (scanner)"'
VLINE = 'www.example.com:443 {ip} - - [28/Oct/2026:19:40:00 -0700] "GET {target} HTTP/1.1" 403 0 "-" "curl/8"'


def test_default_list_is_seeded_and_patterns_are_validated(ib):
    s = instaban.load()
    assert any(p["pattern"] == "/.git/" for p in s["patterns"]) and all(p["kind"] == "contains" for p in s["patterns"])
    for bad, kind in (("", "contains"), ("/", "contains"), ("/index.php", "contains"), ("abc", "contains"), ("(", "regex"), ("x", "nope")):
        with pytest.raises(instaban.InstaBanError):
            instaban.add_pattern(bad, kind)
    e = instaban.add_pattern("/Backup.ZIP", "contains", "old archives")
    assert e["pattern"] == "/backup.zip" and e["note"] == "old archives"
    with pytest.raises(instaban.InstaBanError):
        instaban.add_pattern("/backup.zip")   # twice
    instaban.delete_pattern(e["id"])
    with pytest.raises(instaban.InstaBanError):
        instaban.delete_pattern(e["id"])


def test_matching_decodes_the_url_and_knows_the_three_kinds():
    comp = instaban._compiled([{"id": "a", "pattern": "/.git/", "kind": "contains"}, {"id": "b", "pattern": "/admin/", "kind": "starts"},
                               {"id": "c", "pattern": r"\.php\?.*=\.\./", "kind": "regex"}])
    assert instaban.match("/repo/.GIT/config", comp)["id"] == "a"
    assert instaban.match("/repo/%2e%2e/%2Egit/config", comp)["id"] == "a"      # URL-decoded twice
    assert instaban.match("/admin/login", comp)["id"] == "b" and instaban.match("/site/admin/", comp) is None
    assert instaban.match("/index.php?page=../../etc/passwd", comp)["id"] == "c"
    assert instaban.match("/blog/hello-world", comp) is None
    rec = instaban.parse_line(VLINE.format(ip="203.0.113.9", target="/.env"))
    assert rec == {"ip": "203.0.113.9", "host": "www.example.com", "method": "GET", "target": "/.env", "status": 403, "ua": "curl/8"}
    assert instaban.parse_line("garbage") is None


def test_scan_bans_the_first_hit_and_keeps_the_evidence(ib):
    instaban.set_settings(enabled=True, ttl="6h")
    log = ib["logs"] / "access.log"
    log.write_text("", encoding="utf-8")
    instaban.scan()   # nothing yet; the file end is remembered
    log.write_text("\n".join([
        LINE.format(ip="203.0.113.9", target="/.git/config"),
        LINE.format(ip="203.0.113.9", target="/.env"),            # same address: one ban
        LINE.format(ip="10.0.0.5", target="/etc/passwd"),         # trusted: evidence, no ban
        LINE.format(ip="198.51.100.4", target="/index.php?p=%2e%2e/%2e%2e/etc/passwd"),
        LINE.format(ip="198.51.100.7", target="/blog/"),          # harmless
    ]) + "\n", encoding="utf-8")
    r = instaban.scan()
    assert r["hits"] == 4 and r["bans"] == 2
    assert [b[0] for b in ib["bans"]] == ["203.0.113.9", "198.51.100.4"]
    assert ib["bans"][0][2] == 6 * 3600 and ib["bans"][0][3] == "InstaBan" and ib["bans"][0][1].startswith("InstaBan: /.git/")
    ov = instaban.overview()
    assert ov["hits_24h"] == 4 and ov["stats"]["bans"] == 2 and ov["enabled"] and ov["ttl_seconds"] == 6 * 3600
    trusted = next(h for h in ov["hits"] if h["ip"] == "10.0.0.5")
    assert trusted["banned"] is False and "trusted" in trusted["error"]
    assert ov["patterns"][0]["hits"] >= 1   # sorted by hits
    assert instaban.scan()["hits"] == 0     # nothing new since
    instaban.clear_hits()
    assert instaban.overview()["hits"] == []


def test_scan_is_quiet_when_off_and_old_lines_are_never_scanned(ib):
    (ib["logs"] / "access.log").write_text(LINE.format(ip="203.0.113.9", target="/.git/config") + "\n", encoding="utf-8")
    assert instaban.scan() == {"scanned": 0, "hits": 0, "bans": 0}
    instaban.set_settings(enabled=True)     # switching on marks the log ends: the old line doesn't count
    assert instaban.scan()["hits"] == 0 and ib["bans"] == []


def test_import_and_export_round_trip(ib):
    r = instaban.import_patterns("# comment\n/backup.zip  # old archives\nregex:/wp-content/uploads/.*\\.php$\nstarts:/cgi-bin/evil\n/\n/.git/\n", "contains")
    assert r["added"] == 3 and len(r["skipped"]) == 1 and "short" in r["skipped"][0].lower()
    text = instaban.export_text()
    assert "/backup.zip  # old archives" in text and "regex:/wp-content/uploads/.*\\.php$" in text and "starts:/cgi-bin/evil" in text
    with pytest.raises(instaban.InstaBanError):
        instaban.set_settings(ttl="2 weeks")


def test_instaban_routes(admin, tmp_path, monkeypatch):
    monkeypatch.setattr(instaban, "STATE", tmp_path / "instaban.json")
    monkeypatch.setattr(instaban, "LOG_DIR", tmp_path / "nologs")
    monkeypatch.setattr(guard, "trusted_cidrs", lambda: [])
    assert admin.get("/api/instaban").json()["pattern_count"] > 10
    r = admin.post("/api/instaban/patterns/add", json={"pattern": "/.svn/wc.db", "kind": "contains", "note": "svn db"})
    assert r.status_code == 200 and r.json()["pattern"] == "/.svn/wc.db"
    assert admin.post("/api/instaban/patterns/add", json={"pattern": "/", "kind": "contains"}).status_code == 400
    assert admin.post("/api/instaban/settings", json={"enabled": True, "ttl": "7d", "report": False}).json()["ttl"] == "7d"
    assert "InstaBan patterns" in admin.get("/api/instaban/export").text
    assert admin.post("/api/instaban/scan").status_code == 200


# ----------------------------------------------------------------------------- Activity Log clean-up
def test_audit_purge_keeps_a_copy_in_the_recycle_bin(tmp_path, monkeypatch):
    from backend import backups, files
    log = tmp_path / "audit.jsonl"
    monkeypatch.setattr(audit, "LOG", log)
    monkeypatch.setattr(files, "TRASH_DIR", tmp_path / "trash")
    monkeypatch.setattr(files, "_refresh_root", lambda: None)
    monkeypatch.setattr(backups, "BACKUP_DIR", tmp_path / "backups")
    now = time.time()
    rows = [{"ts": now, "user": "tester", "ip": "testclient", "action": "login", "ok": True, "status": 200},
            {"ts": now, "user": "a51", "ip": "192.168.0.2", "action": "files · delete", "ok": False, "status": 400},
            {"ts": now - 40 * 86400, "user": "a51", "ip": "192.168.0.2", "action": "login", "ok": True, "status": 200},
            {"ts": now, "user": "a51", "ip": "192.168.0.2", "action": "login", "ok": True, "status": 200}]
    log.write_text("".join(json.dumps(r) + "\n" for r in rows), encoding="utf-8")
    r = audit.purge("tests")
    assert r["removed"] == 1 and r["kept"] == 3 and r["archive"]["lines"] == 1
    meta = json.loads((tmp_path / "trash" / (r["archive"]["id"] + ".json")).read_text(encoding="utf-8"))
    assert meta["name"].startswith("activity-log-") and meta["original"].startswith(str(tmp_path / "backups"))
    assert "testclient" in (tmp_path / "trash" / r["archive"]["id"]).read_text(encoding="utf-8")
    assert audit.purge("failed", keep_copy=False) == {"removed": 1, "kept": 2, "archive": None}
    assert audit.purge("older", days=30)["removed"] == 1
    assert audit.purge("all")["removed"] == 1 and log.read_text(encoding="utf-8") == ""
    with pytest.raises(ValueError):
        audit.purge("weird")


def test_audit_purge_route(admin):
    r = admin.post("/api/audit/purge", json={"mode": "tests", "keep_copy": False})
    assert r.status_code == 200 and set(r.json()) == {"removed", "kept", "archive"}
    assert admin.post("/api/audit/purge", json={"mode": "weird"}).status_code == 400
