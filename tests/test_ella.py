"""WAF Ella, the parts that don't need a real server: parsing, masking, the audit chain, Safety Lock and the
ban state machine. The real thing runs in tests/integration/ella_stage1.py on a test server."""
import json
import os
import sqlite3
import time

import pytest

from backend.ella import adapter as A, blocks, cli, collector, leaks, service
from backend.ella.blocks import Engine
from backend.ella.db import Store
from backend.ella.registry import Registry, parse_banned

AUDIT_LINE = json.dumps({
    "transaction": {"time": "04/Nov/2026:18:58:38.217220 --0500", "transaction_id": "abc", "remote_address": "203.0.113.5"},
    "request": {"request_line": "GET /a/b?password=hunter2&q=1 HTTP/1.1",
                "headers": {"Host": "Shop.Example:443", "User-Agent": "evil/1.0", "Authorization": "Bearer SECRET", "Cookie": "sid=SECRET", "Referer": "https://x.example/p?token=SECRET"}},
    "response": {"status": 403},
    "audit_data": {"messages": [
        'Warning. Pattern match "x" at ARGS:q. [file "f"] [line "1"] [id "941100"] [msg "XSS"] [data "Matched Data: <script> found within ARGS:q: eyJhbGciOiJIUzI1.eyJzdWIiOiIxMjM0.abc"] [severity "CRITICAL"]',
        'Warning. Pattern match "y" at ARGS:password. [file "f"] [id "942100"] [msg "SQLi"] [data "hunter2"] [severity "ERROR"]',
        'Access denied with code 403 (phase 2). Operator GE matched 5 at TX:blocking_inbound_anomaly_score. [id "949110"] [msg "Inbound Anomaly Score Exceeded (Total Score: 10)"] [severity "CRITICAL"]']},
}).encode()


class FakeAdapter:
    def __init__(self):
        self.sets = {4: {}, 6: {}}
        self.fail = set()
        self.calls = []
        self.guard_sets = {"ban4": {}, "ban6": {}, "f2b4": {}, "f2b6": {}}
        self.jails = {}
        self.f2b_up, self.f2b_missing, self.ufw = True, False, ""

    def call(self, op, args=None, operation_id=""):
        args = args or {}
        self.calls.append(op)
        if op in self.fail:
            return {"ok": False, "error": f"{op} is down", "elements": []}
        if op == "nft_ensure":
            return {"ok": True}
        if op == "nft_add":
            n = A.net(args["target"])
            self.sets[n.version][str(n)] = args.get("ttl")
            return {"ok": True}
        if op == "nft_del":
            n = A.net(args["target"])
            self.sets[n.version].pop(str(n), None)
            return {"ok": True}
        if op == "nft_list":
            return {"ok": True, "elements": [{"element": k, "expires": v} for k, v in self.sets[args["family"]].items()], "error": ""}
        if op == "guard_list":
            return {"ok": True, "elements": [{"element": k, "expires": v} for k, v in self.guard_sets.get(args["name"], {}).items()], "error": ""}
        if op == "guard_del":
            self.guard_sets.get(args["name"], {}).pop(str(A.net(args["target"])), None)
            return {"ok": True, "error": ""}
        if op == "f2b_banned":
            return {"ok": self.f2b_up, "jails": self.jails if self.f2b_up else {}, "error": "" if self.f2b_up else "not running"}
        if op == "f2b_unban":
            self.jails[args["jail"]] = [i for i in self.jails.get(args["jail"], []) if i != args["ip"]]
            return {"ok": True, "error": ""}
        if op == "f2b_ban":
            self.jails.setdefault(args["jail"], []).append(args["ip"])
            return {"ok": True, "error": ""}
        if op == "f2b_status":
            return {"ok": self.f2b_up, "jails": list(self.jails), "missing": self.f2b_missing, "error": ""}
        if op == "f2b_jail":
            return {"ok": True, "banned": self.jails[args["jail"]], "failed_now": 0, "failed_total": 0, "banned_total": 1, "bantime": 3600, "findtime": 600, "maxretry": 5, "journal": "x", "logpath": [], "actions": ["aurora-guard"]}
        if op == "ufw_status":
            return {"ok": True, "installed": bool(self.ufw), "active": bool(self.ufw), "output": self.ufw}
        return {"ok": True, "available": True}


@pytest.fixture
def engine(tmp_path, monkeypatch):
    monkeypatch.setattr(blocks, "_panel_server_nets", lambda: [])
    monkeypatch.setattr(blocks, "_guard_protected", lambda ip: [])
    return Engine(Store(tmp_path), FakeAdapter())


def test_audit_record_is_normalized_with_evidence_and_no_secrets():
    e = collector.PARSERS["modsec_audit"].parse(AUDIT_LINE, {"path": "/l", "inode": 1, "offset": 0})
    assert e["client_ip"] == e["peer_ip"] == "203.0.113.5" and e["client_ip_source"] == "peer"
    assert e["domain"] == "shop.example" and e["url"] == "/a/b" and json.loads(e["query_keys"]) == ["password", "q"]
    assert e["status"] == 403 and e["action"] == "blocked" and e["anomaly_score"] == 10 and e["rule_id"] == "941100"
    by_rule = {r["rule_id"]: r for r in e["evidence"]}
    assert set(by_rule) == {"941100", "942100"}  # the score summary isn't an attack of its own
    assert by_rule["941100"]["matched_var_name"] == "ARGS:q" and "[jwt]" in by_rule["941100"]["matched_data"]
    assert by_rule["942100"]["matched_var_name"] == "ARGS:password" and by_rule["942100"]["matched_data"] == "[masked]"
    text = json.dumps(e)
    for secret in ("hunter2", "SECRET", "eyJhbGci"):
        assert secret not in text
    assert "authorization" not in json.loads(e["headers"]) and "cookie" not in json.loads(e["headers"])


V3_LINE = json.dumps({"transaction": {
    "client_ip": "203.0.113.5", "time_stamp": "Wed Nov  4 23:11:22 2026", "unique_id": "abc",
    "producer": {"secrules_engine": "Enabled"},
    "request": {"method": "GET", "uri": "/a/b?password=hunter2&q=1", "headers": {"Host": "Shop.Example:443", "User-Agent": "evil/1.0", "Authorization": "Bearer SECRET", "Cookie": "sid=SECRET"}},
    "response": {"http_code": 403},
    "messages": [
        {"message": "XSS", "details": {"ruleId": "941100", "severity": "2", "data": "Matched Data: <script> found within ARGS:q: eyJhbGciOiJIUzI1.eyJzdWIiOiIxMjM0.abc", "match": "Matched \"Operator `Rx' with parameter `x' against variable `ARGS:q' (Value: `hunter2')"}},
        {"message": "SQLi", "details": {"ruleId": "942100", "severity": "3", "data": "hunter2", "match": "Matched \"Operator `DetectSQLi' with parameter `' against variable `ARGS:password' (Value: `hunter2')"}},
        {"message": "Inbound Anomaly Score Exceeded (Total Score: 10)", "details": {"ruleId": "949110", "severity": "2", "data": ""}}]}}).encode()


def test_modsecurity_3_record_is_normalized_with_no_secrets():
    e = collector.PARSERS["modsec3_audit"].parse(V3_LINE, {"path": "/l", "inode": 1, "offset": 0})
    assert (e["client_ip"], e["domain"], e["url"], e["status"], e["action"], e["anomaly_score"], e["rule_id"]) == ("203.0.113.5", "shop.example", "/a/b", 403, "blocked", 10, "941100")
    by = {r["rule_id"]: r for r in e["evidence"]}
    assert set(by) == {"941100", "942100"} and by["941100"]["matched_var_name"] == "ARGS:q" and by["941100"]["operator"] == "Rx" and "[jwt]" in by["941100"]["matched_data"]
    assert by["942100"]["matched_data"] == "[masked]" and by["942100"]["severity"] == "ERROR"
    text = json.dumps(e)
    for secret in ("hunter2", "SECRET", "eyJhbGci"):
        assert secret not in text


def test_modsecurity_3_finds_the_variable_in_libinjection_matches():
    d = json.loads(V3_LINE)
    d["transaction"]["messages"] = [{"message": "XSS", "details": {"ruleId": "941100", "severity": "2", "match": "detected XSS using libinjection.", "data": "Matched Data: XSS data found within ARGS:q: <script>"}}]
    e = collector.PARSERS["modsec3_audit"].parse(json.dumps(d).encode(), {"path": "/l", "inode": 1, "offset": 0})
    assert e["evidence"][0]["matched_var_name"] == "ARGS:q"


def test_modsecurity_3_detection_only_and_junk():
    d = json.loads(V3_LINE)
    d["transaction"]["producer"]["secrules_engine"] = "DetectionOnly"
    d["transaction"]["response"]["http_code"] = 200
    assert collector.PARSERS["modsec3_audit"].parse(json.dumps(d).encode(), {"path": "/l", "inode": 1, "offset": 0})["action"] == "detected"
    assert collector.PARSERS["modsec3_audit"].parse(b"not json", {"path": "/l", "inode": 1, "offset": 0}) is None
    d["transaction"]["messages"] = []
    assert collector.PARSERS["modsec3_audit"].parse(json.dumps(d).encode(), {"path": "/l", "inode": 1, "offset": 0}) == {"skip": True}


def test_missing_fields_are_named_and_null():
    line = json.dumps({"transaction": {"time": "04/Nov/2026:18:58:38 --0500", "remote_address": "203.0.113.5"}, "request": {"request_line": "GET / HTTP/1.1", "headers": {}},
                       "audit_data": {"messages": ['Warning. x at ARGS:q. [file "f"] [id "941100"] [severity "ERROR"]']}}).encode()
    e = collector.PARSERS["modsec_audit"].parse(line, {"path": "/l", "inode": 1, "offset": 0})
    assert e["domain"] is None and e["status"] is None
    assert {"domain", "status", "user_agent"} <= set(json.loads(e["missing_fields"]))


@pytest.mark.parametrize("line", [b"not json", b'{"transaction": 5}', b"{}"])
def test_unreadable_audit_lines_are_not_events(line):
    assert collector.PARSERS["modsec_audit"].parse(line, {"path": "/l", "inode": 1, "offset": 0}) is None


def test_access_line_keeps_parameter_names_only():
    line = b'198.51.100.7 - - [04/Nov/2026:18:58:38 -0500] "POST /login?token=abc&x=1 HTTP/1.1" 500 12 "https://r.example/p?secret=1" "ua"'
    e = collector.PARSERS["apache_access"].parse(line, {"path": "/l", "inode": 1, "offset": 0})
    assert (e["method"], e["url"], e["status"], e["response_size"]) == ("POST", "/login", 500, 12)
    assert json.loads(e["query_keys"]) == ["token", "x"] and "abc" not in json.dumps(e) and "secret=1" not in json.dumps(e)


def _collector(tmp_path):
    logs = tmp_path / "logs"
    logs.mkdir()
    store = Store(tmp_path / "db")
    return store, collector.Collector(store, str(logs), "srv"), logs / "access.log"


def _line(n):
    return f'198.51.100.7 - - [04/Nov/2026:18:58:38 -0500] "GET /p{n} HTTP/1.1" 200 1 "-" "ua"\n'


def _count(store):
    return sum(sqlite3.connect(p).execute("SELECT count(*) FROM events").fetchone()[0] for p in store.months())


def test_secrets_in_a_url_path_are_masked():
    path, _ = collector.split_url("/reset/eyJhbGciOiJIUzI1.eyJzdWIiOiIxMjM0.abc/" + "ab12" * 10 + "?x=1")
    assert "eyJhbGci" not in path and "ab12ab12" not in path and "[jwt]" in path and "[hex]" in path


def test_secrets_check_finds_what_slipped_through_without_repeating_it(tmp_path):
    store = Store(tmp_path)
    base = {"ts_event": 1000.0, "ts_received": 1.0, "source": "s", "missing_fields": "[]", "historical": 0}
    jwt = "eyJhbGciOiJIUzI1.eyJzdWIiOiIxMjM0.abcdef"
    store.add_events([{**base, "hash": "a", "url": "/fine", "user_agent": "ok"},
                      {**base, "hash": "b", "url": "/x?password=hunter2", "user_agent": "Bearer abcdef123456"},
                      {**base, "hash": "c", "url": "/masked?password=[masked]", "headers": '{"a": "Bearer [masked]"}', "evidence": [{"rule_id": "1", "matched_data": jwt}]}])
    assert leaks.due(store)
    r = leaks.scan(store)
    assert r["scanned"] == 3 and r["counts"] == {"secret_value": 1, "bearer": 1, "jwt": 1} and not leaks.due(store)
    text = json.dumps(leaks.report(store))
    assert "hunter2" not in text and jwt not in text and "abcdef123456" not in text
    assert leaks.scan(store)["scanned"] == 0 and leaks.report(store)["total"] == 3  # only new events; old findings stay


def test_restore_puts_active_bans_back_and_skips_expired(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("AURORA_ELLA_DIR", str(tmp_path))
    monkeypatch.setattr(blocks, "_panel_server_nets", lambda: [])
    monkeypatch.setattr(blocks, "_guard_protected", lambda ip: [])
    store = Store(tmp_path)
    engine = Engine(store, FakeAdapter())
    keep = engine.ban("203.0.113.1", 600, "", "admin")
    engine.ban("203.0.113.2", None, "", "admin")
    gone = engine.ban("203.0.113.3", 600, "", "admin")
    store.run(lambda c: c.execute("UPDATE blocks SET expires_at = 5 WHERE id = ?", (gone["block_id"],)))
    fresh = FakeAdapter()
    assert cli.cmd_restore(None, fresh) == 0
    assert set(fresh.sets[4]) == {"203.0.113.1/32", "203.0.113.2/32"} and 590 < fresh.sets[4]["203.0.113.1/32"] <= 600
    assert fresh.sets[4]["203.0.113.2/32"] is None and "restored 2, failed 0, already expired 1" in capsys.readouterr().out
    assert keep["state"] == "applied"


def test_restore_without_a_database_still_brings_the_table_up(tmp_path, monkeypatch):
    monkeypatch.setenv("AURORA_ELLA_DIR", str(tmp_path / "nothing"))
    fresh = FakeAdapter()
    assert cli.cmd_restore(None, fresh) == 0 and "nft_ensure" in fresh.calls


def test_rollback_keeps_the_panels_waf_setting_in_step(tmp_path, monkeypatch):
    pre, state = tmp_path / "pre.conf", tmp_path / "waf.json"
    pre.write_text("SecRuleEngine On\n")
    state.write_text(json.dumps({"mode": "detect", "paranoia": 2}))
    monkeypatch.setattr(cli, "WAF_PRE", str(pre))
    monkeypatch.setattr(cli, "WAF_STATE", state)
    cli._sync_waf_mode()
    assert json.loads(state.read_text()) == {"mode": "block", "paranoia": 2}


def test_a_new_log_starts_at_its_end_and_partial_lines_wait(tmp_path):
    store, c, log = _collector(tmp_path)
    log.write_text(_line(0))
    c.tick()
    assert not store.months()  # history isn't imported on its own
    with log.open("a", newline="") as f:
        f.write(_line(1) + '198.51.100.7 - - [half')
    c.tick()
    assert _count(store) == 1
    with log.open("a", newline="") as f:
        f.write(' a line\n' + _line(2))
    c.tick()
    assert _count(store) == 2
    row = store.read(lambda x: x.execute("SELECT unparsed, samples FROM sources").fetchone())
    assert row["unparsed"] == 1 and "half" in row["samples"]


@pytest.mark.skipif(os.name == "nt", reason="renaming an open-for-append log and inodes behave differently on Windows")
def test_rotation_by_rename_loses_and_repeats_nothing(tmp_path):
    store, c, log = _collector(tmp_path)
    log.write_text("")
    c.tick()
    log.write_text(_line(1))
    c.tick()
    with log.open("a") as f:
        f.write(_line(2))
    log.rename(str(log) + "-20261104")
    log.write_text(_line(3))
    c.tick()
    with open(str(log) + "-20261104", "a") as f:  # a child still writing to the old file during the graceful reload
        f.write(_line(4))
    c.tick()
    urls = {r[0] for p in store.months() for r in sqlite3.connect(p).execute("SELECT url FROM events")}
    assert urls == {"/p1", "/p2", "/p3", "/p4"} and _count(store) == 4


@pytest.mark.skipif(os.name == "nt", reason="an open file can't be deleted on Windows")
def test_a_rotated_file_that_was_deleted_is_still_read_to_its_end(tmp_path):
    store, c, log = _collector(tmp_path)
    log.write_text("")
    c.tick()
    log.write_text(_line(1))
    c.tick()
    writer = log.open("a")  # Apache's own open file, as it is until the reload reaches it
    log.rename(str(log) + ".gone")
    os.unlink(str(log) + ".gone")
    writer.write(_line(2))
    writer.flush()
    log.write_text(_line(3))
    c.tick()
    writer.write(_line(4))
    writer.close()
    c.tick()
    urls = {r[0] for p in store.months() for r in sqlite3.connect(p).execute("SELECT url FROM events")}
    assert urls == {"/p1", "/p2", "/p3", "/p4"} and _count(store) == 4


def test_truncation_restarts_from_zero(tmp_path):
    store, c, log = _collector(tmp_path)
    log.write_text("")
    c.tick()
    log.write_text(_line(1) + _line(2))
    c.tick()
    log.write_text(_line(3))
    c.tick()
    assert _count(store) == 3


def test_a_new_file_in_the_old_ones_place_is_read_from_its_start(tmp_path):
    """A filesystem can give a new file the inode of a deleted one, and it may have grown past the old position already."""
    store, c, log = _collector(tmp_path)
    log.write_text("")
    c.tick()
    log.write_text(_line(1) + _line(2))
    c.tick()
    store.run(lambda x: x.execute("UPDATE sources SET inode = ?", (os.stat(log).st_ino,)))
    log.write_text(_line(3) + _line(4) + _line(5) + _line(6))  # same inode here, different start, bigger than before
    c.tick()
    urls = {r[0] for p in store.months() for r in sqlite3.connect(p).execute("SELECT url FROM events")}
    assert urls == {f"/p{i}" for i in range(1, 7)}


def test_a_growing_file_is_not_mistaken_for_a_new_one(tmp_path):
    store, c, log = _collector(tmp_path)
    log.write_text("")
    c.tick()
    with log.open("a", newline="") as f:
        f.write(_line(1))
    c.tick()
    for n in range(2, 12):
        with log.open("a", newline="") as f:
            f.write(_line(n))
        c.tick()
    assert _count(store) == 11


def test_reading_again_after_a_crash_adds_nothing(tmp_path):
    store, c, log = _collector(tmp_path)
    log.write_text("")
    c.tick()
    log.write_text(_line(1) + _line(2))
    c.tick()
    store.run(lambda x: x.execute("UPDATE sources SET offset = 0"))  # as if the position hadn't been saved
    c.tick()
    assert _count(store) == 2


def test_search_is_limited_to_the_callers_domains_in_the_query(tmp_path):
    store = Store(tmp_path)
    base = {"ts_received": 1.0, "source": "s", "missing_fields": "[]", "historical": 0}
    store.add_events([{**base, "hash": "a", "ts_event": 1000.0, "domain": "mine.example"}, {**base, "hash": "b", "ts_event": 1001.0, "domain": "theirs.example"}])
    assert [e["domain"] for e in store.search_events(allowed_domains=["mine.example"])["events"]] == ["mine.example"]
    assert store.search_events(allowed_domains=[])["events"] == []


def test_cursor_pages_without_repeats(tmp_path):
    store = Store(tmp_path)
    store.add_events([{"hash": str(i), "ts_event": 1000.0 + i, "ts_received": 1.0, "source": "s", "missing_fields": "[]", "historical": 0} for i in range(5)])
    a = store.search_events(limit=2)
    b = store.search_events(limit=2, cursor=tuple(a["next_cursor"]))
    assert [e["ts_event"] for e in a["events"] + b["events"]] == [1004.0, 1003.0, 1002.0, 1001.0]


def test_audit_chain_detects_tampering_and_refuses_changes(tmp_path):
    store = Store(tmp_path)
    store.audit("a", "x", "t", {"k": 1})
    store.audit("b", "y", "t")
    assert store.audit_verify() == {"ok": True, "records": 2, "broken_at": None}
    for sql in ("UPDATE audit SET actor = 'z'", "DELETE FROM audit"):
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            store.run(lambda c, sql=sql: c.execute(sql))
    db = sqlite3.connect(store.dir / "ella.db")
    db.execute("DROP TRIGGER audit_no_update")  # someone with the file in their hands
    db.execute("UPDATE audit SET actor = 'z' WHERE seq = 1")
    db.commit()
    db.close()
    assert store.audit_verify()["broken_at"] == 1


@pytest.mark.parametrize("op,args", [("nft_add", {"target": "1.2.3.4; reboot"}), ("nft_add", {"target": "1.2.3.4", "ttl": -1}), ("nft_add", {"target": "1.2.3.4", "ttl": "9"}),
                                     ("nft_list", {"family": 5}), ("guard_list", {"name": "x y"}), ("service_active", {"unit": "sshd;id"}), ("rm_rf", {}), ("../x", {})])
def test_the_adapter_refuses_bad_arguments_before_running_anything(op, args, monkeypatch):
    monkeypatch.setattr(A.subprocess, "run", lambda *a, **k: pytest.fail("ran a command"))
    with pytest.raises(A.AdapterError):
        A.EllaSystemAdapter().call(op, args)


def test_the_adapter_only_runs_allowlisted_programs_without_a_shell(monkeypatch):
    seen = {}

    def fake(argv, **kw):
        seen.update(argv=argv, **kw)
        return A.subprocess.CompletedProcess(argv, 0, "", "")
    monkeypatch.setattr(A.subprocess, "run", fake)
    monkeypatch.setattr(A.shutil, "which", lambda name, path=None: f"/usr/sbin/{name}")
    assert A.EllaSystemAdapter().call("nft_add", {"target": "2001:db8::1", "ttl": 60})["ok"]
    assert seen["shell"] is False and seen["timeout"] and seen["argv"][-2:] == ["ella6", "{ 2001:db8::1 timeout 60s }"]
    with pytest.raises(A.AdapterError):
        A.EllaSystemAdapter()._exec("x", "", ["bash", "-c", "id"])


def test_ban_is_applied_only_after_reading_it_back(engine):
    op = engine.ban("203.0.113.9", 600, "scan", "admin")
    assert op["state"] == "applied"
    b = engine.get_block(op["block_id"])
    assert b["actual_state"] == "present" and b["last_verified_at"] and engine.adapter.sets[4]["203.0.113.9/32"] == 599 or engine.adapter.sets[4]["203.0.113.9/32"] == 600
    assert engine.adapter.calls.index("nft_list") > engine.adapter.calls.index("nft_add")
    assert "conntrack_kill" in engine.adapter.calls and "ss_kill" in engine.adapter.calls


def test_a_write_that_cannot_be_read_back_is_not_applied(engine):
    engine.adapter.call = lambda op, args=None, operation_id="", real=engine.adapter.call: ({"ok": True, "elements": [], "error": ""} if op == "nft_list" else real(op, args, operation_id))
    op = engine.ban("203.0.113.9", None, "", "admin")
    assert op["state"] == "pending" and "isn't in the ban set" in op["error"]


def test_failures_retry_with_backoff_then_fail_with_the_reason(engine, monkeypatch):
    engine.adapter.fail.add("nft_add")
    op = engine.ban("203.0.113.9", None, "", "admin")
    assert op["state"] == "pending" and op["attempts"] == 1 and 1 < op["next_retry_at"] - time.time() <= 2
    gaps = []
    for _ in range(3):
        o = engine.get_operation(op["id"])
        gaps.append(round(o["next_retry_at"] - time.time()))
        engine.store.run(lambda c: c.execute("UPDATE operations SET next_retry_at = 1 WHERE id = ?", (op["id"],)))
        engine.tick()
    o = engine.get_operation(op["id"])
    assert gaps == [2, 8, 30] and o["state"] == "failed" and "nft_add is down" in o["error"] and o["attempts"] == 4
    assert engine.get_block(op["block_id"])["desired_state"] == "failed"
    assert engine.store.audit_entries(1)[0]["action"] == "ban.failed"


def test_a_retry_that_works_gets_applied(engine):
    engine.adapter.fail.add("nft_add")
    op = engine.ban("203.0.113.9", None, "", "admin")
    engine.adapter.fail.clear()
    engine.store.run(lambda c: c.execute("UPDATE operations SET next_retry_at = 1 WHERE id = ?", (op["id"],)))
    engine.tick()
    assert engine.get_operation(op["id"])["state"] == "applied"


@pytest.mark.parametrize("target", ["127.0.0.1", "127.5.0.0/16", "::1", "0.0.0.0/8"])
def test_safety_lock_never_bans_loopback_even_forced(engine, target):
    with pytest.raises((blocks.SafetyLocked, blocks.BlockError)):
        engine.ban(target, None, "", "admin", force=True)
    assert not engine.adapter.sets[4] and not engine.adapter.sets[6]


def test_safety_lock_protects_the_operator_and_settings_until_forced(engine):
    engine.store.set_setting("management_cidrs", ["192.0.2.0/24"])
    engine.store.set_setting("trusted_proxies", ["198.51.100.0/24"])
    for target, ip in (("203.0.113.9", "203.0.113.9"), ("203.0.113.0/24", "203.0.113.9"), ("192.0.2.7", None), ("198.51.100.7", None)):
        with pytest.raises(blocks.SafetyLocked) as e:
            engine.ban(target, None, "", "admin", ip)
        assert e.value.forceable
    assert engine.store.audit_entries(1)[0]["action"] == "ban.refused" and not engine.adapter.sets[4]
    op = engine.ban("192.0.2.7", None, "I know", "admin", force=True)
    assert op["state"] == "applied" and engine.get_block(op["block_id"])["forced"] == 1
    assert "ban.force" in [e["action"] for e in engine.store.audit_entries(5)]


def test_idempotency_key_and_merging(engine):
    a = engine.ban("203.0.113.9", None, "", "admin", idempotency_key="k1")
    assert engine.ban("203.0.113.9", None, "", "admin", idempotency_key="k1")["replayed"]
    assert engine.ban("203.0.113.9", 60, "again", "other")["merged"] and engine.ban("203.0.113.9", 60, "", "x")["id"] == a["id"]
    assert len(engine.list_blocks()) == 1


def test_domain_scope_cannot_become_a_server_ban(engine):
    with pytest.raises(blocks.BlockError, match="WAF rule"):
        engine.ban("203.0.113.9", None, "", "admin", scope="domain")


def test_unban_lifts_only_ellas_entry_and_is_audited(engine):
    op = engine.ban("203.0.113.9", None, "", "admin")
    u = engine.unban(op["block_id"], "admin", "false alarm")
    assert u["state"] == "applied" and not engine.adapter.sets[4]
    assert engine.get_block(op["block_id"])["desired_state"] == "removed"
    assert engine.store.audit_entries(1)[0]["action"] == "unban.applied" and engine.store.audit_verify()["ok"]
    with pytest.raises(blocks.BlockError, match="already"):
        engine.unban(op["block_id"], "admin")


def test_expiry_needs_the_set_to_agree(engine):
    op = engine.ban("203.0.113.9", 1, "", "admin")
    engine.store.run(lambda c: c.execute("UPDATE blocks SET expires_at = 5"))
    assert engine.tick()["expired"] == 0  # still in the set: not expired yet
    engine.adapter.sets[4].clear()
    assert engine.tick()["expired"] == 1
    assert engine.get_operation(op["id"])["state"] == "expired" and engine.get_block(op["block_id"])["desired_state"] == "expired"


def test_a_ban_lost_from_the_set_is_restored_and_strangers_are_reported(engine):
    engine.ban("203.0.113.9", None, "", "admin")
    engine.adapter.sets[4].clear()  # a reboot
    engine.adapter.sets[4]["198.51.100.1/32"] = None  # someone with nft
    r = engine.tick()
    assert r["restored"] == 1 and "203.0.113.9/32" in engine.adapter.sets[4] and r["external"] == ["198.51.100.1/32"]


def test_cli_unban_journal_stops_the_ban_coming_back(engine):
    op = engine.ban("203.0.113.9", None, "", "admin")
    engine.adapter.sets[4].clear()
    engine.journal.write_text(json.dumps({"ts": time.time(), "action": "unban", "target": "203.0.113.9/32", "user": "root"}) + "\n")
    engine.tick()
    assert not engine.adapter.sets[4] and engine.get_block(op["block_id"])["desired_state"] == "removed"
    assert any(e["action"] == "cli.unban" and e["actor"] == "cli:root" for e in engine.store.audit_entries(5))


@pytest.fixture
def api(admin, tmp_path, monkeypatch):
    monkeypatch.setattr(blocks, "_panel_server_nets", lambda: [])
    monkeypatch.setattr(blocks, "_guard_protected", lambda ip: [])
    store = Store(tmp_path / "ella")
    engine = Engine(store, FakeAdapter())
    service.configure(store=store, engine=engine, registry=Registry(engine, FakeGuard(engine.adapter), FakeFirewall(), None))
    yield admin
    service.configure()


def test_api_ban_unban_audit_and_scope(api):
    r = api.post("/api/ella/blocks", json={"target": "203.0.113.9", "ttl": 60, "reason": "x"}, headers={"Idempotency-Key": "abc"})
    assert r.status_code == 200 and r.json()["state"] == "applied"
    block = r.json()["block_id"]
    assert api.get(f"/api/ella/operations/{r.json()['id']}").json()["state"] == "applied"
    assert [b["target"] for b in api.get("/api/ella/blocks").json()["blocks"]] == ["203.0.113.9/32"]
    assert api.post(f"/api/ella/blocks/{block}/unban", json={"reason": "y"}).json()["state"] == "applied"
    a = api.get("/api/ella/audit").json()
    assert a["chain"]["ok"] and {"ban.applied", "unban.applied"} <= {e["action"] for e in a["entries"]}
    assert api.post("/api/ella/blocks", json={"target": "203.0.113.9", "scope": "domain"}).status_code == 400


def test_api_safety_lock_answers_409(api):
    r = api.post("/api/ella/blocks", json={"target": "127.0.0.1"})
    assert r.status_code == 409 and r.json()["detail"]["forceable"] is False


class FakeGuard:
    def __init__(self, adapter):
        self.adapter, self.bans = adapter, []

    def _state(self):
        return {"bans": self.bans}

    def ban(self, target, reason="", duration=None, client_ip=None, source=""):
        n = str(A.net(target))
        self.bans.append({"cidr": n, "reason": reason, "source": source})
        self.adapter.guard_sets["ban4"][n] = None

    def unban(self, target, include_fail2ban=True):
        assert include_fail2ban is False or target  # the registry must lift only this list's own entry
        n = str(A.net(target))
        self.last_include_fail2ban = include_fail2ban
        self.bans[:] = [b for b in self.bans if b["cidr"] != n]
        self.adapter.guard_sets["ban4"].pop(n, None)


class FakeFirewall:
    @staticmethod
    def _firewalld():
        return False


@pytest.fixture
def reg(engine):
    r = Registry(engine, FakeGuard(engine.adapter), FakeFirewall(), None)
    return r


def _sources(reg, target="203.0.113.9/32"):
    return {b["source"]: b for b in reg.engine.list_blocks() if b["target"] == target}


def test_three_sources_on_one_address_are_lifted_one_at_a_time(reg):
    a = reg.adapter
    reg.engine.ban("203.0.113.9", None, "", "admin")
    reg.guard.ban("203.0.113.9", "manual")
    a.jails["sshd"] = ["203.0.113.9"]
    a.guard_sets["f2b4"]["203.0.113.9/32"] = 300
    reg.sync()
    m = _sources(reg)
    assert set(m) == {"ella", "guard", "fail2ban:sshd"} and all(b["actual_state"] == "present" for b in m.values())
    assert m["fail2ban:sshd"]["expires_at"] and m["guard"]["owner"] == "IP Blocker"
    assert reg.unban(m["guard"]["id"], "admin")["state"] == "applied"
    assert reg.guard.last_include_fail2ban is False
    reg.sync()
    assert set(_sources(reg)) == {"ella", "fail2ban:sshd"} and a.sets[4]
    assert reg.unban(m["fail2ban:sshd"]["id"], "admin")["state"] == "applied"
    reg.sync()
    assert set(_sources(reg)) == {"ella"} and a.sets[4] and a.jails["sshd"] == []


def test_ufw_is_shown_but_never_changed(reg):
    reg.adapter.ufw = "Status: active\n[ 1] Anywhere                   DENY IN     203.0.113.9\n[ 2] 22/tcp                     ALLOW IN    Anywhere\n"
    reg.sync()
    m = _sources(reg)
    assert set(m) == {"ufw"} and m["ufw"]["backend"] == "ufw"
    with pytest.raises(blocks.BlockError, match="read-only"):
        reg.unban(m["ufw"]["id"], "admin")


def test_no_ufw_is_no_problem(reg):
    assert reg.sync()["added"] == 0


def test_an_entry_ending_outside_ella_is_recorded(reg):
    reg.guard.ban("203.0.113.9", "x")
    reg.sync()
    reg.guard.unban("203.0.113.9")
    assert reg.sync()["ended"] == 1 and not _sources(reg)
    assert reg.store.audit_entries(1)[0]["action"] == "block.ended"


def test_fail2ban_being_down_does_not_look_like_its_bans_ended(reg):
    reg.adapter.jails["sshd"] = ["203.0.113.9"]
    reg.sync()
    reg.adapter.f2b_up = False
    assert reg.sync()["ended"] == 0 and "fail2ban:sshd" in _sources(reg)


def test_drift_is_found_and_resolved(reg):
    a = reg.adapter
    a.sets[4]["203.0.113.1/32"] = None
    a.guard_sets["ban4"]["203.0.113.2/32"] = None
    a.guard_sets["f2b4"]["203.0.113.3/32"] = 60
    reg.guard.bans.append({"cidr": "203.0.113.4/32", "reason": "x"})
    kinds = {(d["backend"], d["target"], d["kind"]) for d in reg.drift()}
    assert kinds == {("ella", "203.0.113.1/32", "external"), ("guard", "203.0.113.2/32", "external"), ("fail2ban", "203.0.113.3/32", "external"), ("guard", "203.0.113.4/32", "missing")}
    reg.sync()
    assert reg.store.setting("drift") and any(e["action"] == "drift.found" for e in reg.store.audit_entries(10))
    reg.resolve("ella", "203.0.113.1", "accept", "admin")
    assert "ella" in _sources(reg, "203.0.113.1/32") and "203.0.113.1/32" in a.sets[4]
    reg.resolve("guard", "203.0.113.2", "remove", "admin")
    reg.resolve("fail2ban", "203.0.113.3", "remove", "admin")
    assert not a.guard_sets["ban4"].get("203.0.113.2/32") and not a.guard_sets["f2b4"]
    reg.resolve("guard", "203.0.113.4", "restore", "admin")
    assert "203.0.113.4/32" in a.guard_sets["ban4"]
    assert not reg.drift()
    with pytest.raises(blocks.BlockError, match="isn't there"):
        reg.resolve("guard", "203.0.113.2", "remove", "admin")


def test_fail2ban_states(reg):
    a = reg.adapter
    assert reg.fail2ban_overview()["state"] == "unconfigured"
    a.jails["sshd"] = []
    o = reg.fail2ban_overview()
    assert o["state"] == "ok" and o["jails"][0]["uses_panel_sets"] and o["jails"][0]["bantime"] == 3600
    with pytest.raises(blocks.BlockError, match="already has jails"):
        reg.fail2ban_init("admin")
    a.f2b_up = False
    assert reg.fail2ban_overview()["state"] == "stopped"
    a.f2b_missing = True
    assert reg.fail2ban_overview()["state"] == "not_installed"


def test_fail2ban_ban_goes_through_the_safety_lock(reg):
    reg.adapter.jails["sshd"] = []
    with pytest.raises(blocks.SafetyLocked):
        reg.fail2ban_ban("sshd", "203.0.113.9", "admin", "203.0.113.9")
    assert reg.adapter.jails["sshd"] == []
    reg.fail2ban_ban("sshd", "203.0.113.9", "admin", None)
    assert reg.adapter.jails["sshd"] == ["203.0.113.9"]


@pytest.mark.parametrize("text,want", [
    ("[{'sshd': ['1.2.3.4']}, {'recidive': []}]", {"sshd": ["1.2.3.4"], "recidive": []}),
    ("__import__('os').system('id')", {}), ("", {}), ("[{'bad jail;': ['1.2.3.4']}]", {}),
])
def test_fail2ban_output_is_read_as_data(text, want):
    assert parse_banned(text) == want


CTX = {"path": "/l", "inode": 1, "offset": 0}


def test_apache_error_line():
    e = collector.PARSERS["apache_error"].parse(b"[Wed Nov 04 22:15:31.403603 2026] [core:error] [pid 49:tid 49] [client 203.0.113.9:4242] AH00126: Invalid URI token=abc123def", CTX)
    assert e["client_ip"] == "203.0.113.9" and e["severity"] == "ERROR" and "token=[masked]" in e["evidence"][0]["msg"]
    e = collector.PARSERS["apache_error"].parse(b"[Wed Nov 04 22:15:31.403603 2026] [mpm_event:notice] [pid 4995:tid 4995] AH00492: caught SIGWINCH", CTX)
    assert e["client_ip"] is None and "client_ip" in json.loads(e["missing_fields"]) and e["severity"] == "NOTICE"


def test_apache_startup_notes_are_not_unreadable():
    assert collector.PARSERS["apache_error"].parse(b"AH00558: httpd: Could not reliably determine the server's fully qualified domain name", CTX) == {"skip": True}
    assert collector.PARSERS["apache_error"].parse(b"something else entirely", CTX) is None


def test_every_operation_the_code_calls_exists_in_the_real_adapter():
    """Fakes accept any name, so a typo or a name the check refuses would only show on a real server."""
    import re as _re
    from pathlib import Path as _P
    called = set()
    for f in _P(A.__file__).parent.glob("*.py"):
        called |= set(_re.findall(r"""adapter\.call\(\s*["']([a-z0-9_]+)["']""", f.read_text(encoding="utf-8")))
        called |= set(_re.findall(r"""\ba\.call\(\s*["']([a-z0-9_]+)["']""", f.read_text(encoding="utf-8")))
    assert {"f2b_banned", "f2b_status", "f2b_jail", "f2b_ban", "f2b_unban", "guard_del", "journal_read", "ufw_status", "nft_add"} <= called
    real = A.EllaSystemAdapter()
    for op in sorted(called):
        assert A.re.fullmatch(r"[a-z0-9_]+", op) and hasattr(real, f"op_{op}"), op
    with pytest.raises(TypeError):  # gets past the name check, and only then complains about its arguments
        real.call("f2b_jail", {})


def test_nginx_error_line():
    e = collector.PARSERS["nginx_error"].parse(b'2026/11/04 22:15:31 [error] 12#12: *1 open() "/x" failed, client: 203.0.113.9, server: a.example, request: "GET /x HTTP/1.1", host: "a.example"', CTX)
    assert e["client_ip"] == "203.0.113.9" and e["domain"] == "a.example" and e["severity"] == "ERROR"


@pytest.mark.parametrize("line,action,jail,ip", [
    (b"2026-11-04 22:05:00,469 fail2ban.actions        [29066]: NOTICE  [aurora-panel] Ban 203.0.113.9", "ban", "aurora-panel", "203.0.113.9"),
    (b"2026-11-04 22:05:00,469 fail2ban.actions        [29066]: NOTICE  [sshd] Unban 203.0.113.9", "unban", "sshd", "203.0.113.9"),
    (b"2026-11-04 22:04:12,047 fail2ban.filter         [29066]: INFO    [sshd] Found 203.0.113.9 - 2026-11-04 22:04:11", "detected", "sshd", "203.0.113.9"),
])
def test_fail2ban_log_lines(line, action, jail, ip):
    e = collector.PARSERS["fail2ban_log"].parse(line, CTX)
    assert (e["action"], e["rule_id"], e["client_ip"]) == (action, jail, ip)


def test_fail2ban_chatter_is_skipped_and_errors_kept():
    assert collector.PARSERS["fail2ban_log"].parse(b"2026-11-04 22:10:23,418 fail2ban.jail [893]: INFO    Jail 'sshd' started", CTX) == {"skip": True}
    assert collector.PARSERS["fail2ban_log"].parse(b"2026-11-04 22:10:23,418 fail2ban.x [893]: ERROR   oops", CTX)["action"] == "error"


def test_panel_audit_line():
    line = json.dumps({"ts": 1793848653.2, "user": "admin", "ip": "192.0.2.1", "action": "login failed", "ok": False, "status": 401, "method": "POST", "path": "/api/login"}).encode()
    e = collector.PARSERS["panel_audit"].parse(line, CTX)
    assert (e["action"], e["account"], e["client_ip"], e["url"], e["status"]) == ("login_failed", "admin", "192.0.2.1", "/api/login", 401)


def test_journal_parsers():
    assert collector._journal_sshd("Failed password for invalid user bob from 203.0.113.9 port 22 ssh2")[:3] == ("203.0.113.9", "bob", "login_failed")
    assert collector._journal_sshd("Invalid user  from 2001:db8::1 port 22")[0] == "2001:db8::1"
    assert collector._journal_sshd("Accepted password for admin from 192.0.2.1 port 1 ssh2")[2] == "login"
    assert collector._journal_sshd("Server listening on 0.0.0.0 port 22") is None
    assert collector._journal_postfix("warning: unknown[203.0.113.9]: SASL LOGIN authentication failed: x")[2] == "login_failed"
    assert collector._journal_dovecot("imap-login: Login aborted: (auth failed, 1 attempts in 2 secs): user=<a@b.c>, rip=203.0.113.9, lip=1.1.1.1")[:3] == ("203.0.113.9", "a@b.c", "login_failed")
    f = collector._journal_firewall("aurora-block: IN=eth0 SRC=203.0.113.9 DST=1.1.1.1 PROTO=TCP SPT=1 DPT=22")
    assert f[0] == "203.0.113.9" and f[2] == "dropped" and f[4] == ("tcp", "dpt:22")


class FakeJournal(FakeAdapter):
    def __init__(self):
        super().__init__()
        self.records = {}

    def call(self, op, args=None, operation_id=""):
        if op == "journal_read":
            recs = self.records.get(args["journal"], [])
            c = args.get("cursor")
            if not c:
                return {"ok": True, "records": recs[-1:], "error": ""}
            at = next((i for i, r in enumerate(recs) if r["cursor"] == c), -1)
            return {"ok": True, "records": recs[at + 1:], "error": ""}
        return super().call(op, args, operation_id)


def _ssh(n, ip="203.0.113.9"):
    return {"cursor": f"c{n}", "ts": 1793848000.0 + n, "message": f"Failed password for u{n} from {ip} port 22 ssh2", "priority": "6"}


def test_journal_source_starts_at_the_end_and_keeps_its_place(tmp_path):
    store, a = Store(tmp_path), FakeJournal()
    c = collector.Collector(store, adapter=a, log_dir=str(tmp_path / "none"), system=False)
    a.records["sshd"] = [_ssh(0)]
    c._tick_journal("sshd", None)
    assert not store.months()
    row = lambda: dict(store.read(lambda x: x.execute("SELECT * FROM sources WHERE path='journal:sshd'").fetchone()))  # noqa: E731
    a.records["sshd"] += [_ssh(1), _ssh(2)]
    assert c._tick_journal("sshd", row()) == 2
    assert c._tick_journal("sshd", row()) == 0
    store.run(lambda x: x.execute("UPDATE sources SET cursor='c0' WHERE path='journal:sshd'"))  # as if the position wasn't saved
    assert c._tick_journal("sshd", row()) == 0 and _count(store) == 2


def test_a_stack_trace_is_one_event(tmp_path):
    store, c, log = _collector(tmp_path)
    err = log.with_name("error.log")
    err.write_text("")
    c.tick()
    head = b"[Wed Nov 04 22:15:31.403603 2026] [php:error] [pid 49] [client 203.0.113.9:1] Fatal\n"
    err.write_bytes(head + b"Stack trace:\n#0 /a.php(1): x()\n#1 {main}\n  thrown in /a.php\n" + head)
    c.tick()
    assert _count(store) == 2
    r = store.read(lambda x: x.execute("SELECT unparsed FROM sources WHERE path=?", (str(err),)).fetchone())
    assert r["unparsed"] == 0
    tags = [json.loads(x[0]) for p in store.months() for x in sqlite3.connect(p).execute("SELECT tags FROM events ORDER BY id")]
    assert "multiline" in tags[0] and "multiline" not in tags[1]


def test_history_import_is_marked_and_not_repeated(tmp_path):
    store, c, log = _collector(tmp_path)
    log.write_text(_line(1) + _line(2) + "junk\n")
    r = c.import_file(str(log), "apache_access")
    assert r == {"lines": 3, "unparsed": 1, "stored": 2} and c.import_file(str(log), "apache_access")["stored"] == 0
    assert {x[0] for p in store.months() for x in sqlite3.connect(p).execute("SELECT historical FROM events")} == {1}


def test_custom_source_regex_and_json(tmp_path):
    store, c, log = _collector(tmp_path)
    other, j = tmp_path / "app.log", tmp_path / "app.json"
    other.write_text("")
    j.write_text("")
    store.set_setting("custom_sources", [
        {"path": str(other), "format": "regex", "pattern": r"^(?P<client_ip>\S+) (?P<url>\S+) (?P<status>\d+)$", "fields": None},
        {"path": str(j), "format": "json", "pattern": None, "fields": {"client_ip": "ip", "url": "path", "ts": "time"}}])
    c.tick()
    other.write_text("203.0.113.9 /x?token=abc 500\nnot this format\n")
    j.write_text(json.dumps({"ip": "203.0.113.8", "path": "/y", "time": 1793848000}) + "\n[1]\n")
    c.tick()
    got = {r[0]: r[1:] for p in store.months() for r in sqlite3.connect(p).execute("SELECT client_ip, url, status FROM events WHERE source='custom'")}
    assert got == {"203.0.113.9": ("/x", 500), "203.0.113.8": ("/y", None)}
    assert store.read(lambda x: x.execute("SELECT sum(unparsed) FROM sources WHERE kind='custom'").fetchone()[0]) == 2


@pytest.mark.parametrize("spec", [
    {"path": "relative.log", "format": "regex", "pattern": "(?P<url>x)"}, {"path": "/proc/self/environ", "format": "regex", "pattern": "(?P<url>x)"}, {"path": "/a/../etc/shadow", "format": "regex", "pattern": "(?P<url>x)"},
    {"path": "/var/log/a", "format": "regex", "pattern": r"(?P<url>(a+)+)"}, {"path": "/var/log/a", "format": "regex", "pattern": r"(?P<nope>x)"}, {"path": "/var/log/a", "format": "regex", "pattern": ""},
    {"path": "/var/log/a", "format": "json", "fields": {"nope": "x"}}, {"path": "/var/log/a", "format": "xml"},
])
def test_custom_source_validation(spec):
    with pytest.raises(ValueError):
        collector.check_custom(spec)


def test_api_blocks_list_covers_every_source_and_drift(api):
    reg_ = service.parts()["registry"]
    reg_.guard.ban("203.0.113.9", "x")
    assert api.post("/api/ella/drift/check", json={}).json()["added"] == 1
    assert {b["source"] for b in api.get("/api/ella/blocks").json()["blocks"]} == {"guard"}
    assert api.get("/api/ella/drift").json()["drift"] == []
    block = api.get("/api/ella/blocks").json()["blocks"][0]["id"]
    assert api.post(f"/api/ella/blocks/{block}/unban", json={}).json()["state"] == "applied"
    assert api.post("/api/ella/drift/resolve", json={"backend": "guard", "target": "203.0.113.9", "action": "remove"}).status_code == 400


def test_api_lists_sources_that_are_not_on_this_server(api):
    paths = {s["path"]: s for s in api.get("/api/ella/sources").json()["sources"]}
    assert paths["/var/log/nginx/access.log"]["status"] in ("not_found", "ok") and paths["/var/log/nginx/access.log"]["format"] == "combined"


def test_api_fail2ban_and_import_limits(api):
    assert api.get("/api/ella/fail2ban").json()["state"] == "unconfigured"
    assert api.post("/api/ella/sources/import", json={"path": "/etc/shadow", "kind": "apache_access"}).status_code == 400
    assert api.post("/api/ella/sources/custom", json={"path": "/var/log/a", "format": "regex", "pattern": "(?P<url>(a+)+)"}).status_code == 400


def test_api_needs_a_login(client):
    assert client.get("/api/ella/events").status_code == 401
    assert client.post("/api/ella/blocks", json={"target": "203.0.113.9"}).status_code == 401
