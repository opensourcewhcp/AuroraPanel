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
    service.configure(store=store, engine=Engine(store, FakeAdapter()))
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


def test_api_needs_a_login(client):
    assert client.get("/api/ella/events").status_code == 401
    assert client.post("/api/ella/blocks", json={"target": "203.0.113.9"}).status_code == 401
