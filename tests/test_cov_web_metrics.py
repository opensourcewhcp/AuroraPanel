"""Metrics: site discovery from Apache confs, log reading, visitors, errors and the collector.

Everything runs against log files written under tmp_path; journalctl is a stub."""
from __future__ import annotations

import gzip
import json
import subprocess
import time
from datetime import datetime
from types import SimpleNamespace

import pytest

from backend import metrics

MONTHS = ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec")
CHROME = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0 Safari/537.36"
IPHONE = "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 Version/18.0 Mobile/15E148 Safari/604.1"
GOOGLEBOT = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"


def clf(ts, ip="203.0.113.5", url="/", status=200, size=1234, ref="-", ua=CHROME, method="GET", user="-", vhost=""):
    """One Apache combined (or vhost_combined) log line at epoch `ts`, in UTC."""
    g = time.gmtime(ts)
    t = f"{g.tm_mday:02d}/{MONTHS[g.tm_mon - 1]}/{g.tm_year}:{g.tm_hour:02d}:{g.tm_min:02d}:{g.tm_sec:02d} +0000"
    head = f"{vhost} " if vhost else ""
    return f'{head}{ip} - {user} [{t}] "{method} {url} HTTP/1.1" {status} {size} "{ref}" "{ua}"'


def vhost_conf(name, port=80, aliases=(), log=True, err=True):
    lines = [f"<VirtualHost *:{port}>", f"    ServerName {name}"]
    if aliases:
        lines.append("    ServerAlias " + " ".join(aliases))
    if err:
        lines.append(f"    ErrorLog ${{APACHE_LOG_DIR}}/{name}-error.log")
    if log:
        lines.append(f"    CustomLog ${{APACHE_LOG_DIR}}/{name}-access.log combined")
    lines.append("</VirtualHost>")
    return "\n".join(lines) + "\n"


@pytest.fixture
def web(tmp_path, monkeypatch):
    """A fake Apache layout (sites-enabled, logs, collector state) entirely under tmp_path."""
    log_dir = tmp_path / "log"
    log_dir.mkdir()
    sites_dir = tmp_path / "sites-enabled"
    sites_dir.mkdir()
    state = tmp_path / "state"
    monkeypatch.setattr(metrics, "LOG_DIR", log_dir)
    monkeypatch.setattr(metrics, "SITES_DIR", sites_dir)
    monkeypatch.setattr(metrics, "STATE_DIR", state)
    monkeypatch.setattr(metrics, "BW_FILE", state / "bandwidth.json")
    monkeypatch.setattr(metrics, "RES_FILE", state / "resources.json")
    monkeypatch.setattr(metrics, "LOGROTATE", tmp_path / "logrotate-apache2")
    monkeypatch.setattr(metrics, "VSFTPD_LOG", tmp_path / "vsftpd.log")
    monkeypatch.setattr(metrics, "_bw", None)
    monkeypatch.setattr(metrics, "_res", None)
    monkeypatch.setattr(metrics, "_last_collect", 0.0)
    monkeypatch.setattr(metrics, "_prev_res", {})
    from backend import authz
    monkeypatch.setattr(authz, "scope", lambda: None)
    return SimpleNamespace(log=log_dir, sites=sites_dir, state=state, tmp=tmp_path)


def no_journal(monkeypatch, stdout=""):
    """journalctl never runs: subprocess.run records its argv and answers with `stdout`."""
    calls = []

    def fake_run(argv, **kw):
        calls.append(list(argv))
        return subprocess.CompletedProcess(argv, 0, stdout, "")
    monkeypatch.setattr(metrics.subprocess, "run", fake_run)
    return calls


# --------------------------------------------------------------------------- #
# Parsing details the existing tests leave out
# --------------------------------------------------------------------------- #
def test_clf_time_handles_negative_offsets_and_garbage():
    assert metrics._clf_time("24/Oct/2026:09:35:38 -0500") == metrics._clf_time("24/Oct/2026:14:35:38 +0000")
    assert metrics._clf_time("not a date") == 0.0
    assert metrics._clf_time("24/Xyz/2026:09:35:38 +0000") == 0.0


def test_request_without_method_keeps_the_raw_text_as_url():
    e = metrics.parse_access('1.2.3.4 - - [24/Oct/2026:09:35:38 +0000] "quit" 400 0 "-" "-"')
    assert e["method"] == "" and e["url"] == "quit" and e["proto"] == ""
    short = metrics.parse_access('1.2.3.4 - - [24/Oct/2026:09:35:38 +0000] "GET / HTTP/1.0" 200 5')
    assert short["ref"] == "" and short["ua"] == ""


def test_bot_names_come_from_the_product_token():
    assert metrics._bot_name("") == "(empty user agent)"
    assert metrics._bot_name(GOOGLEBOT) == "Googlebot"
    assert metrics._bot_name("Mozilla/5.0 (compatible; MyThing/1.0)") == "MyThing"
    assert metrics._bot_name("Mozilla/5.0 zgrab/0.x") == "zgrab"
    assert metrics._bot_name("curl/8.21.0") == "curl"
    assert metrics._bot_name("ZGRAB something") == "ZGRAB"
    assert metrics.classify_ua("Mozilla/5.0 (X11; Linux x86_64) Gecko/20100101 Firefox/130.0")["os"] == "Linux"
    assert metrics.classify_ua("Mozilla/5.0 (iPad; CPU OS 17_0 like Mac OS X) Version/17.0 Safari/604.1")["device"] == "tablet"
    assert metrics.classify_ua("Mozilla/5.0 (Windows NT 6.1; Trident/7.0; rv:11.0) like Gecko")["browser"] == "Internet Explorer"
    assert metrics.classify_ua("Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0) Edg/120.0")["browser"] == "Edge"
    assert metrics.classify_ua("Opera/9.80 (X11; CrOS)")["browser"] == "Opera"
    assert metrics.classify_ua("SamsungBrowser/20 Android")["browser"] == "Samsung Internet"


def test_error_categories_for_proxy_ssl_timeout_server_and_fpm():
    cat = metrics._err_category
    assert cat("proxy_http", "error", "AH01114: HTTP: failed to make connection to backend") == "proxy"
    assert cat("ssl", "error", "something") == "ssl"
    assert cat("core", "error", "SSL handshake failed") == "ssl"
    assert cat("core", "error", "Timeout waiting for output from CGI script") == "timeout"
    assert cat("core", "error", "request body limit exceeded") == "timeout"
    assert cat("mpm_event", "notice", "AH00489: Apache configured") == "server"
    assert cat("proxy_fcgi", "error", "something went wrong") == "php_fatal"
    assert cat("php", "notice", "PHP something") == "php_warn"
    assert cat("core", "error", "Invalid command 'Foo' in .htaccess") == "htaccess"
    assert cat("core", "error", "AH01630: client denied by server configuration") == "permission"
    assert cat("core", "error", "no idea") == "other"
    assert metrics._err_time("Fri Oct 24 09:35:38.123456 2026") > 0
    assert metrics._err_time("Fri Oct 24 09:35:38 2026") > 0
    assert metrics._err_time("nope") == 0.0


# --------------------------------------------------------------------------- #
# Sites and their logs
# --------------------------------------------------------------------------- #
def test_sites_are_read_from_the_enabled_confs(web):
    (web.sites / "example.com.conf").write_text(vhost_conf("example.com", aliases=("www.example.com",)) + vhost_conf("example.com", 443))
    (web.sites / "nolog.conf").write_text(vhost_conf("nolog.test", log=False, err=False))
    (web.sites / "ignored.txt").write_text(vhost_conf("ignored.test"))
    (web.log / "example.com-access.log").write_text("x\n")
    (web.log / "example.com-access.log.1").write_text("yy\n")
    out = metrics.sites()
    assert [s["id"] for s in out] == ["example.com", "other_vhosts_access", "access"]
    ex = out[0]
    assert ex["kind"] == "site" and ex["label"] == "example.com" and ex["names"] == ["example.com", "www.example.com"]
    assert ex["ssl"] is True and ex["http"] is True and ex["exists"] is True and ex["size"] == 5
    assert ex["error_logs"] == [str(web.log / "example.com-error.log")] and ex["vhost_fmt"] is False
    shared = out[1]
    assert shared["kind"] == "shared" and shared["vhost_fmt"] is True and shared["names"] == ["nolog.test"]
    assert shared["error_logs"] == [str(web.log / "error.log")] and shared["exists"] is False and shared["updated"] == 0
    default = out[2]
    assert default["kind"] == "default" and default["http"] is True and default["ssl"] is False
    assert metrics.site("example.com")["id"] == "example.com"
    with pytest.raises(metrics.MetricsError, match="Unknown site"):
        metrics.site("nope")


def test_website_manager_sees_only_their_own_sites(web, monkeypatch):
    (web.sites / "a.conf").write_text(vhost_conf("a.test"))
    (web.sites / "b.conf").write_text(vhost_conf("b.test"))
    from backend import authz
    monkeypatch.setattr(authz, "scope", lambda: {"domains": ["b.test"]})
    assert [s["id"] for s in metrics.sites()] == ["b.test"]


def test_rotated_lists_the_log_and_its_numbered_rotations(web):
    p = web.log / "a-access.log"
    p.write_text("1\n")
    (web.log / "a-access.log.1").write_text("22\n")
    with gzip.open(web.log / "a-access.log.2.gz", "wb") as f:
        f.write(b"333\n")
    (web.log / "a-access.log.bak").write_text("no\n")
    (web.log / "a-access.log.3").mkdir()
    files = metrics.rotated(p)
    assert [(f["n"], f["gz"]) for f in files] == [(0, False), (1, False), (2, True)]
    assert files[0]["size"] == 2 and files[0]["path"] == str(p)
    assert metrics.rotated(web.log / "missing.log") == []


def test_read_lines_tails_big_files_and_unpacks_gzip(web):
    p = web.tmp / "big.log"
    p.write_bytes(b"line1\nline2\nline3\n")
    assert metrics._read_lines(str(p)) == ["line1", "line2", "line3"]
    # Only the tail is read, and the first (partial) line is dropped.
    assert metrics._read_lines(str(p), max_bytes=8) == ["line3"]
    gz = web.tmp / "old.log.gz"
    with gzip.open(gz, "wb") as f:
        f.write(b"a\nb\n")
    assert metrics._read_lines(str(gz)) == ["a", "b"]
    assert metrics._read_lines(str(web.tmp / "nope.log")) == []


def test_entries_filter_by_time_and_vhost_name(web):
    now = time.time()
    (web.sites / "x.conf").write_text(vhost_conf("x.test", log=False))
    log = web.log / "other_vhosts_access.log"
    log.write_text("\n".join([clf(now - 7200, vhost="x.test:80", url="/old"), clf(now - 60, vhost="x.test:80", url="/new"),
                             clf(now - 30, vhost="y.test:80", url="/other"), "garbage"]) + "\n")
    s = metrics.site("other_vhosts_access")
    urls = [e["url"] for _, e in metrics._entries(s)]
    assert urls == ["/old", "/new", "/other"]
    assert [e["url"] for _, e in metrics._entries(s, since=now - 600)] == ["/new", "/other"]
    assert [e["url"] for _, e in metrics._entries(s, names=["x.test"])] == ["/old", "/new"]
    (web.log / "other_vhosts_access.log.1").write_text(clf(now - 86400 * 3, vhost="x.test:80", url="/ancient") + "\n")
    import os
    os.utime(web.log / "other_vhosts_access.log.1", (now - 86400 * 3, now - 86400 * 3))
    # A rotation older than `since` stops the scan before it is read.
    assert [e["url"] for _, e in metrics._entries(s, since=now - 600)] == ["/new", "/other"]


# --------------------------------------------------------------------------- #
# Visitors
# --------------------------------------------------------------------------- #
def test_visitors_are_newest_first_with_ban_state_and_own_addresses(web, monkeypatch):
    now = time.time()
    (web.sites / "ex.conf").write_text(vhost_conf("example.com"))
    log = web.log / "example.com-access.log"
    log.write_text("\n".join([clf(now - 300, ip="1.2.3.4", url="/a", ua=GOOGLEBOT), clf(now - 200, ip="5.6.7.8", url="/b.css"),
                             clf(now - 100, ip="5.6.7.8", url="/missing", status=404, size=0)]) + "\n")
    (web.log / "example.com-access.log.1").write_text(clf(now - 9000, ip="9.9.9.9", url="/rotated") + "\n")
    from backend import guard, dnszones
    asked = []
    monkeypatch.setattr(guard, "status_of", lambda ips: asked.append(sorted(ips)) or {"1.2.3.4": "banned", "5.6.7.8": ""})
    monkeypatch.setattr(dnszones, "_my_ips", lambda: {"192.168.0.100"})
    v = metrics.visitors("example.com")
    assert [r["url"] for r in v["rows"]] == ["/missing", "/b.css", "/a", "/rotated"]
    assert v["total"] == 4 and v["unique_ips"] == 3 and v["bots"] == 1 and v["errors"] == 1
    assert v["bytes"] == 1234 * 3 and v["period"] == [v["rows"][-1]["ts"], v["rows"][0]["ts"]]
    assert v["ip_status"] == {"1.2.3.4": "banned"} and asked == [["1.2.3.4", "5.6.7.8", "9.9.9.9"]]
    assert v["own"] == ["192.168.0.100", "example.com"]
    assert v["rows"][0]["page"] is False and v["rows"][2]["browser"] == "Googlebot"
    # A limit keeps the newest rows; hours drops the rotation.
    assert [r["url"] for r in metrics.visitors("example.com", limit=2)["rows"]] == ["/missing", "/b.css"]
    assert [r["url"] for r in metrics.visitors("example.com", hours=1)["rows"]] == ["/missing", "/b.css", "/a"]
    # Lookups that fail are tolerated.
    monkeypatch.setattr(guard, "status_of", lambda ips: 1 / 0)
    monkeypatch.setattr(dnszones, "_my_ips", lambda: 1 / 0)
    v = metrics.visitors("example.com")
    assert v["ip_status"] == {} and v["own"] == ["example.com"]


# --------------------------------------------------------------------------- #
# Errors
# --------------------------------------------------------------------------- #
def err_line(mod, level, rest, ago=60, pid="1234:tid 5"):
    t = datetime.fromtimestamp(time.time() - ago).strftime("%a %b %d %H:%M:%S.%f %Y")
    return f"[{t}] [{mod}:{level}] [pid {pid}] {rest}"


def test_apache_error_log_is_parsed_into_categories(web):
    log = web.log / "error.log"
    log.write_text("\n".join([
        err_line("core", "error", "[client 203.0.113.5:51234] AH10244: invalid URI path (//../.env), referer: http://x.test/"),
        err_line("php", "error", "[client 203.0.113.6:1] script '/var/www/html/info.php' not found or unable to stat"),
        err_line("security2", "error", "[client 1.2.3.4:1] ModSecurity: Warning [id \"920350\"] host header is an IP"),
        err_line("mpm_event", "notice", "AH00489: Apache/2.4.62 configured -- resuming normal operations", ago=10 * 3600),
        "not an error line",
    ]) + "\n")
    items = metrics._apache_errors([str(log)], time.time() - 3600)
    assert [i["cat"] for i in items] == ["security", "missing"]
    first = items[0]
    assert first["client"] == "203.0.113.5" and first["code"] == "AH10244" and first["referer"] == "http://x.test/"
    assert first["msg"].startswith("AH10244") and first["file"] == "error.log" and first["mod"] == "core" and first["level"] == "error"
    assert items[1]["client"] == "203.0.113.6" and items[1]["referer"] == ""
    # A wider window takes the server notice too; the WAF bookkeeping line never counts.
    assert [i["cat"] for i in metrics._apache_errors([str(log)], time.time() - 86400)] == ["security", "missing", "server"]


def test_journal_errors_use_units_per_category_and_decode_bytes(web, monkeypatch):
    now = int(time.time())
    lines = [
        json.dumps({"MESSAGE": "warning: SASL login failed from 203.0.113.9", "PRIORITY": "4", "_SYSTEMD_UNIT": "postfix@-.service",
                    "__REALTIME_TIMESTAMP": str(now * 1000000)}),
        json.dumps({"MESSAGE": list(b"bytes msg"), "PRIORITY": 3, "SYSLOG_IDENTIFIER": "kernel", "__REALTIME_TIMESTAMP": str(now * 1000000)}),
        json.dumps({"MESSAGE": "", "PRIORITY": 3}),
        "not json",
    ]
    calls = no_journal(monkeypatch, "\n".join(lines) + "\n")
    out = metrics._journal_errors("mail", now - 100)
    assert calls[0][:6] == ["journalctl", "-o", "json", "--no-pager", "-p", "warning"]
    assert calls[0][calls[0].index("-u") + 1] == "postfix@-.service" and f"@{now - 100}" in calls[0]
    assert len(out) == 2
    assert out[0]["mod"] == "postfix@-" and out[0]["level"] == "warn" and out[0]["client"] == "203.0.113.9" and out[0]["cat"] == "mail"
    assert out[1]["msg"] == "bytes msg" and out[1]["level"] == "error" and out[1]["mod"] == "kernel"
    metrics._journal_errors("system", now - 100, "err")
    assert "-k" in calls[1] and "-u" not in calls[1]

    def boom(argv, **kw):
        raise OSError("no journalctl")
    monkeypatch.setattr(metrics.subprocess, "run", boom)
    assert metrics._journal_errors("dns", now) == []


def test_errors_groups_repeats_and_counts_per_hour(web, monkeypatch):
    (web.sites / "ex.conf").write_text(vhost_conf("example.com"))
    log = web.log / "example.com-error.log"
    log.write_text("\n".join([
        err_line("core", "error", "[client 203.0.113.5:1] File does not exist: /var/www/example.com/a.php", ago=30),
        err_line("core", "error", "[client 203.0.113.5:2] File does not exist: /var/www/example.com/b.php", ago=20),
        err_line("core", "error", "[client 203.0.113.7:2] File does not exist: /var/www/example.com/c.php", ago=10),
        err_line("php", "warn", "PHP Warning:  foo() is deprecated", ago=5),
    ]) + "\n")
    now = int(time.time())
    journal = json.dumps({"MESSAGE": "mariadbd: Aborted connection", "PRIORITY": 4, "_SYSTEMD_UNIT": "mariadb.service",
                          "__REALTIME_TIMESTAMP": str(now * 1000000)})
    calls = no_journal(monkeypatch, journal + "\n")
    r = metrics.errors(hours=2)
    assert r["total"] == 5 and r["counts"] == {"missing": 3, "php_warn": 1, "database": 1}
    assert r["levels"] == {"error": 3, "warn": 2}
    g = next(g for g in r["groups"] if g["cat"] == "missing")
    assert g["count"] == 3 and g["clients"] == [("203.0.113.5", 2), ("203.0.113.7", 1)] and "/…" in g["pattern"]
    assert g["first"] <= g["last"] and r["items"][0]["ts"] >= r["items"][-1]["ts"]
    assert sum(n for _, n in r["hourly"]) == 5 and all(sum(c.values()) for _, c in r["hourly_cats"])
    assert r["categories"]["missing"]["label"] == "Missing files"
    assert len([c for c in calls if "journalctl" in c]) == 6   # one journal query per category
    # Only the web source, only one site, only a time window.
    r = metrics.errors(sid="example.com", sources="web", start=now - 15, end=now - 2)
    assert r["total"] == 2 and r["counts"] == {"missing": 1, "php_warn": 1}


def test_website_manager_errors_are_limited_to_their_sites(web, monkeypatch):
    from backend import authz
    monkeypatch.setattr(authz, "scope", lambda: {"domains": ["example.com"]})
    calls = no_journal(monkeypatch)
    with pytest.raises(metrics.MetricsError, match="No websites"):
        metrics.errors()
    (web.sites / "ex.conf").write_text(vhost_conf("example.com"))
    (web.log / "example.com-error.log").write_text(err_line("core", "error", "[client 1.1.1.1:1] File does not exist: /x") + "\n")
    r = metrics.errors(sources="web,mail,system")
    assert r["total"] == 1 and calls == []   # the journal is never asked for


# --------------------------------------------------------------------------- #
# Collector: bandwidth bins, log tailing, journal and FTP bytes
# --------------------------------------------------------------------------- #
def test_add_puts_bytes_into_the_right_bins(web):
    bw = metrics._bw_state()
    now = 1_800_000_000.0
    metrics._add(bw, now - 100, "http", 500, now)
    metrics._add(bw, now - 100, "http", 250, now)
    metrics._add(bw, now - 10 * 86400, "imap", 10, now)     # hourly + daily only
    metrics._add(bw, now - 100 * 86400, "smtp", 7, now)     # daily only
    metrics._add(bw, now - 500 * 86400, "ftp", 9, now)      # too old
    metrics._add(bw, now, "pop3", 0, now)                   # nothing to add
    assert list(bw["m5"].values()) == [{"http": 750}]
    assert sorted(v for v in bw["h"].values()) == [{"http": 750}, {"imap": 10}] or len(bw["h"]) == 2
    assert sum(v.get("smtp", 0) for v in bw["d"].values()) == 7 and not any("ftp" in v for v in bw["d"].values())


def test_ingest_http_counts_hits_pages_bots_errors_and_visitors(web):
    bw = metrics._bw_state()
    now = time.time()
    site = {"id": "other_vhosts_access", "kind": "shared"}
    uas = {}
    for line in (clf(now - 10, ip="1.1.1.1", url="/", vhost="a.test:80"), clf(now - 9, ip="1.1.1.1", url="/x.css", vhost="a.test:80"),
                 clf(now - 8, ip="2.2.2.2", url="/", vhost="a.test:80", ua=GOOGLEBOT),
                 clf(now - 7, ip="3.3.3.3", url="/missing", status=404, vhost="a.test:80")):
        metrics._ingest_http(bw, site, metrics.parse_access(line, vhost_fmt=True), now, uas)
    d = bw["site_d"][metrics._day(now)]["vh:a.test"]
    assert d == {"bytes": 1234 * 4, "hits": 4, "pages": 1, "visitors": 2, "bots": 1, "errors": 1}
    assert set(bw["site_ips"][metrics._day(now)]["vh:a.test"]) == {"1.1.1.1", "3.3.3.3"}
    metrics._ingest_http(bw, {"id": "ex", "kind": "site"}, metrics.parse_access(clf(now - 5, vhost="")), now, uas)
    assert bw["site_d"][metrics._day(now)]["ex"]["hits"] == 1


def test_tail_file_reads_only_new_lines_and_follows_rotation(web):
    bw = metrics._bw_state()
    p = web.log / "a-access.log"
    (web.log / "a-access.log.2").write_text("old2\n")
    (web.log / "a-access.log.1").write_text("old1\n")
    p.write_bytes(b"one\ntwo\nhalf")
    # First run: rotations first (oldest first), then the live file minus the half-written line.
    assert metrics._tail_file(bw, p, True) == ["old2", "old1", "one", "two"]
    rec = bw["files"][str(p)]
    assert rec["off"] == 8
    with open(p, "ab") as f:
        f.write(b"-done\nthree\n")
    assert metrics._tail_file(bw, p, True) == ["half-done", "three"]
    assert metrics._tail_file(bw, p, True) == []
    # Rotation: the live file moves to .1 and a new one appears; the rest of .1 is finished first.
    with open(p, "ab") as f:
        f.write(b"four\n")
    (web.log / "a-access.log.1").unlink()
    p.rename(web.log / "a-access.log.1")
    p.write_bytes(b"five\n")
    assert metrics._tail_file(bw, p, True) == ["four", "five"]
    assert bw["files"][str(p)]["ino"] == p.stat().st_ino
    # A truncated file starts over.
    p.write_bytes(b"x\n")
    assert metrics._tail_file(bw, p, True) == ["x"]
    assert metrics._tail_file(bw, web.log / "missing.log", True) == []
    # A file that appears later (no backfill) is read whole.
    q = web.log / "b.log"
    q.write_bytes(b"b1\n")
    assert metrics._tail_file(bw, q, False) == ["b1"]


def test_journal_bytes_counts_imap_pop3_and_smtp_and_keeps_the_cursor(web, monkeypatch):
    bw = metrics._bw_state()
    now = time.time()
    us = str(int(now * 1000000))
    lines = [
        json.dumps({"MESSAGE": "imap(bob)<1><abc>: Logged out in=120 out=4500", "__REALTIME_TIMESTAMP": us, "__CURSOR": "c1"}),
        json.dumps({"MESSAGE": "pop3(bob)<2><x>: Disconnected: Logged out top=0/0, retr=2/8000, del=0/2, size=16000", "__REALTIME_TIMESTAMP": us, "__CURSOR": "c2"}),
        json.dumps({"MESSAGE": "ABC123: from=<a@b.c>, size=3000, nrcpt=2 (queue active)", "__REALTIME_TIMESTAMP": us, "__CURSOR": "c3"}),
        json.dumps({"MESSAGE": ["no"], "__CURSOR": "c4"}),
        "garbage",
    ]
    calls = no_journal(monkeypatch, "\n".join(lines) + "\n")
    metrics._journal_bytes(bw, now)
    assert "--since" in calls[0] and "--after-cursor" not in calls[0]
    day = bw["d"][metrics._day(now)]
    assert day == {"imap": 4620, "pop3": 8000, "smtp": 6000}
    assert bw["journal"]["cursor"] == "c4"
    metrics._journal_bytes(bw, now)
    assert calls[1][-2:] == ["--after-cursor", "c4"]

    def boom(argv, **kw):
        raise subprocess.TimeoutExpired(argv, 1)
    monkeypatch.setattr(metrics.subprocess, "run", boom)
    metrics._journal_bytes(bw, now)   # tolerated
    assert bw["journal"]["cursor"] == "c4"


def test_ftp_bytes_from_vsftpd_log(web):
    bw = metrics._bw_state()
    now = time.time()
    g = time.localtime(now - 60)
    stamp = f"{('Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun')[g.tm_wday]} {MONTHS[g.tm_mon - 1]} {g.tm_mday:2d} {g.tm_hour:02d}:{g.tm_min:02d}:{g.tm_sec:02d} {g.tm_year}"
    metrics.VSFTPD_LOG.write_text(
        f'{stamp} [pid 2] [bob] OK UPLOAD: Client "203.0.113.5", "/home/bob/a.txt", 12345 bytes, 1.00Kbyte/sec\n'
        f'{stamp} [pid 2] [bob] OK DOWNLOAD: Client "203.0.113.5", "/home/bob/b.txt", 100 bytes, 1.00Kbyte/sec\n'
        f'{stamp} [pid 2] [bob] FAIL LOGIN: Client "203.0.113.5"\n'
        f'Xxx Zzz 99 00:00:00 2026 [pid 2] [bob] OK UPLOAD: Client "1.1.1.1", "/x", 5 bytes, 1.00Kbyte/sec\n')
    metrics._ftp_bytes(bw, now, True)
    assert bw["d"][metrics._day(now - 60)]["ftp"] == 12445
    metrics.VSFTPD_LOG.unlink()
    metrics._ftp_bytes(bw, now, True)   # no log: nothing happens
    assert bw["d"][metrics._day(now - 60)]["ftp"] == 12445


def test_prune_drops_old_bins_and_yesterdays_ip_sets(web):
    bw = metrics._bw_state()
    now = time.time()
    bw["m5"] = {str(int(now - 3 * 86400)): {"http": 1}, str(int(now)): {"http": 2}}
    bw["h"] = {str(int(now - 40 * 86400)): {"http": 1}, str(int(now)): {"http": 2}}
    bw["d"] = {"2000-01-01": {"http": 1}, metrics._day(now): {"http": 2}}
    bw["site_d"] = {"2000-01-01": {}, metrics._day(now): {}}
    bw["site_ips"] = {"2000-01-01": {}, metrics._day(now - 86400): {}, metrics._day(now): {}}
    metrics._prune(bw, now)
    assert list(bw["m5"]) == [str(int(now))] and list(bw["h"]) == [str(int(now))]
    assert list(bw["d"]) == [metrics._day(now)] and list(bw["site_d"]) == [metrics._day(now)]
    assert set(bw["site_ips"]) == {metrics._day(now - 86400), metrics._day(now)}


def test_collect_bandwidth_writes_state_to_disk(web, monkeypatch):
    now = time.time()
    (web.sites / "ex.conf").write_text(vhost_conf("example.com"))
    (web.log / "example.com-access.log").write_text(clf(now - 30, size=1000) + "\n" + clf(now - 20, size=500, ua=GOOGLEBOT) + "\n")
    no_journal(monkeypatch)
    metrics.collect_bandwidth()
    saved = json.loads(metrics.BW_FILE.read_text())
    assert saved["initialized"] is True and saved["updated"] >= now
    d = saved["site_d"][metrics._day(now)]["example.com"]
    assert d["hits"] == 2 and d["bots"] == 1 and d["bytes"] == 1500 and d["visitors"] == 1
    assert sum(v["http"] for v in saved["m5"].values()) == 1500
    # Loading the saved state back fills in every key the collector expects.
    monkeypatch.setattr(metrics, "_bw", None)
    assert metrics._bw_state()["site_d"] == saved["site_d"]
    metrics.BW_FILE.write_text("[]")
    monkeypatch.setattr(metrics, "_bw", None)
    assert metrics._bw_state()["files"] == {}


# --------------------------------------------------------------------------- #
# Resources
# --------------------------------------------------------------------------- #
class FakePsutil:
    """Just enough of psutil for the sampler and the Resource Usage page."""
    def __init__(self):
        self.temps = {"cpu_thermal": [SimpleNamespace(current=51.26)]}
        self.io = SimpleNamespace(read_bytes=1000, write_bytes=2000, read_count=10, write_count=5)

    def virtual_memory(self):
        return SimpleNamespace(used=512 * 1048576, percent=25.04, total=2048 * 1048576)

    def swap_memory(self):
        return SimpleNamespace(used=10 * 1048576, total=100 * 1048576)

    def disk_io_counters(self):
        return self.io

    def sensors_temperatures(self):
        return self.temps

    def cpu_percent(self, interval=None):
        return 12.34

    def pids(self):
        return [1, 2, 3]

    def cpu_count(self):
        return 4

    def boot_time(self):
        return 1700000000.0

    def process_iter(self, attrs):
        return [SimpleNamespace(info={"pid": 1, "name": "apache2", "username": "www-data", "memory_info": SimpleNamespace(rss=100), "cpu_percent": 1.5}),
                SimpleNamespace(info={"pid": 2, "name": "apache2", "username": "www-data", "memory_info": SimpleNamespace(rss=50), "cpu_percent": 0}),
                SimpleNamespace(info={"pid": 3, "name": "weird", "username": None, "memory_info": None, "cpu_percent": None})]


def proc_net_dev(tmp_path, monkeypatch, text):
    """Route Path('/proc/net/dev') (and '/proc') inside metrics to files under tmp_path."""
    real = metrics.Path
    f = tmp_path / "net-dev"
    f.write_text(text)

    def fake(p=".", *rest):
        if p == "/proc/net/dev":
            return f
        if p == "/proc":
            return tmp_path
        return real(p, *rest)
    monkeypatch.setattr(metrics, "Path", fake)


def test_net_totals_skip_loopback_and_container_interfaces(web, monkeypatch):
    proc_net_dev(web.tmp, monkeypatch,
                 "Inter-|   Receive                                                |  Transmit\n"
                 " face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed\n"
                 "    lo: 999 1 0 0 0 0 0 0 999 1 0 0 0 0 0 0\n"
                 "  eth0: 1000 1 0 0 0 0 0 0 2000 1 0 0 0 0 0 0\n"
                 " veth1: 5 1 0 0 0 0 0 0 5 1 0 0 0 0 0 0\n"
                 " wlan0: 10 1 0 0 0 0 0 0 20 1 0 0 0 0 0 0\n")
    assert metrics._net_totals() == (1010, 2020)
    proc_net_dev(web.tmp, monkeypatch, "broken")
    assert metrics._net_totals() == (0, 0)


def test_sample_resources_reports_rates_after_the_second_sample(web, monkeypatch):
    ps = FakePsutil()
    monkeypatch.setitem(__import__("sys").modules, "psutil", ps)
    proc_net_dev(web.tmp, monkeypatch, "h\nh\n  eth0: 1000 1 0 0 0 0 0 0 2000 1 0 0 0 0 0 0\n")
    monkeypatch.setattr(metrics.os, "getloadavg", lambda: (0.75, 0, 0), raising=False)
    s = metrics._sample_resources()
    assert s["cpu"] == 12.3 and s["mem"] == 512 and s["mem_pct"] == 25.0 and s["swap"] == 10 and s["load"] == 0.75
    assert s["procs"] == 3 and s["temp"] == 51.3 and "io_r" not in s
    ps.io = SimpleNamespace(read_bytes=1000 + 600, write_bytes=2000, read_count=10, write_count=25)
    proc_net_dev(web.tmp, monkeypatch, "h\nh\n  eth0: 1300 1 0 0 0 0 0 0 2000 1 0 0 0 0 0 0\n")
    monkeypatch.setattr(metrics.time, "time", lambda: metrics._prev_res["t"] + 2)
    s = metrics._sample_resources()
    assert s["io_r"] == 300 and s["io_w"] == 0 and s["iops"] == 10 and s["net_rx"] == 150 and s["net_tx"] == 0
    bw = metrics._bw_state()
    assert sum(v.get("net_rx", 0) for v in bw["m5"].values()) == 300
    # No sensors and no psutil at all are both fine.
    ps.temps = {}
    assert metrics._sample_resources()["temp"] is None
    monkeypatch.setitem(__import__("sys").modules, "psutil", None)
    assert metrics._sample_resources() is None


def test_roll_averages_samples_into_bins_and_keeps_the_max(web):
    pts = []
    now = 1_800_000_000.0
    metrics._roll(pts, 60, 600, {"cpu": 10.0, "temp": None}, now)
    metrics._roll(pts, 60, 600, {"cpu": 30.0, "mem": 5}, now + 1)
    assert len(pts) == 1 and pts[0][1]["cpu"] == 20.0 and pts[0][1]["cpu_max"] == 30.0 and pts[0][2] == 2
    assert pts[0][1]["mem"] == 5 and "temp" not in pts[0][1]
    metrics._roll(pts, 60, 600, {"cpu": 1.0}, now + 60)
    assert len(pts) == 2
    metrics._roll(pts, 60, 600, {"cpu": 1.0}, now + 1000)   # the first bins fall out of the window
    assert [p[0] for p in pts] == [int((now + 1000) // 60) * 60]


def test_collect_resources_fills_the_three_series(web, monkeypatch):
    monkeypatch.setattr(metrics, "_sample_resources", lambda: {"cpu": 5.0, "mem": 1})
    metrics.collect_resources()
    r = metrics._res_state()
    assert len(r["m1"]) == 1 and len(r["m10"]) == 1 and len(r["h"]) == 1 and r["m1"][0][1]["cpu"] == 5.0
    monkeypatch.setattr(metrics, "_sample_resources", lambda: None)
    metrics.collect_resources()
    assert len(r["m1"]) == 1


def test_faults_scan_keeps_oom_and_power_events(web, monkeypatch):
    calls = no_journal(monkeypatch, "1761300000.123 kernel: Out of memory: Killed process 123 (php)\n"
                                    "1761300001.000 kernel: Under-voltage detected!\nbad line\n")
    metrics._faults_scan()
    r = metrics._res_state()
    assert [f["kind"] for f in r["faults"]] == ["oom", "power"] and r["faults"][0]["ts"] == 1761300000.123
    assert r["faults"][0]["msg"].startswith("kernel: Out of memory") and r["faults_scanned"] > 0
    assert calls[0][0] == "journalctl" and "-k" in calls[0]


def test_resources_picks_points_per_span_and_groups_processes(web, monkeypatch):
    now = time.time()
    r = metrics._res_state()
    r["m1"] = [[int(now - 7200), {"cpu": 1}, 1], [int(now - 60), {"cpu": 2}, 1]]
    r["m10"] = [[int(now - 2 * 86400), {"cpu": 3}, 1], [int(now - 600), {"cpu": 4}, 1]]
    r["h"] = [[int(now - 3600), {"cpu": 5}, 1]]
    r["faults"] = [{"ts": now - 40 * 86400, "kind": "oom", "msg": "old"}, {"ts": now - 10, "kind": "oom", "msg": "new"}]
    monkeypatch.setitem(__import__("sys").modules, "psutil", FakePsutil())
    out = metrics.resources("hour")
    assert out["points"] == [[int(now - 60), {"cpu": 2}]] and [f["msg"] for f in out["faults"]] == ["new"]
    assert out["info"] == {"cpus": 4, "mem_total": 2048, "swap_total": 100, "boot": 1700000000.0}
    assert out["apps"][0] == {"name": "Apache", "rss": 150, "cpu": 1.5, "n": 2} and out["apps"][1]["name"] == "weird"
    assert len(metrics.resources("day")["points"]) == 1            # few m1 points: the 10-minute series of the last day
    assert len(metrics.resources("week")["points"]) == 2
    assert len(metrics.resources("month")["points"]) == 2
    assert metrics.resources("year")["points"] == [[int(now - 3600), {"cpu": 5}]]
    monkeypatch.setitem(__import__("sys").modules, "psutil", None)
    out = metrics.resources("hour")
    assert out["info"] == {} and out["apps"] == []
    assert metrics._app_name("mariadbd") == "MariaDB" and metrics._app_name("") == "?" and metrics._app_name("foo") == "foo"


def test_bandwidth_report_has_series_per_period_and_monthly_site_totals(web, monkeypatch):
    now = time.time()
    (web.sites / "ex.conf").write_text(vhost_conf("example.com"))
    monkeypatch.setattr(metrics, "_last_collect", now)   # no collection pass during the call
    bw = metrics._bw_state()
    bw["m5"] = {str(int(now - 100)): {"http": 1}, str(int(now - 3 * 86400)): {"http": 9}}
    bw["h"] = {str(int(now - 100)): {"http": 2}, str(int(now - 10 * 86400)): {"http": 3}}
    bw["d"] = {"2026-01-01": {"http": 5, "imap": 1}, "2026-01-02": {"http": 6}}
    bw["site_d"] = {"2026-01-01": {"example.com": {"bytes": 10, "hits": 2, "pages": 1, "visitors": 1}, "vh:other.test": {"bytes": 1, "hits": 1}},
                    "2026-01-02": {"example.com": {"bytes": 10, "hits": 2, "pages": 1, "visitors": 1}}}
    bw["updated"] = now
    r = metrics.bandwidth()
    assert r["series"]["day"] == [(int(now - 100), {"http": 1})]
    assert len(r["series"]["week"]) == 1 and len(r["series"]["month"]) == 2
    assert r["series"]["year"] == [("2026-01-01", {"http": 5, "imap": 1}), ("2026-01-02", {"http": 6})]
    assert r["months"]["2026-01"]["example.com"] == {"bytes": 20, "hits": 4, "pages": 2, "visitors": 2}
    assert r["month_totals"] == {"2026-01": {"http": 11, "imap": 1}}
    assert r["labels"] == {"example.com": "example.com", "vh:other.test": "other.test"}
    assert r["updated"] == now and r["protos"][0] == "http"


def test_fresh_collects_at_most_once_a_minute(web, monkeypatch):
    runs = []
    monkeypatch.setattr(metrics, "collect_bandwidth", lambda: runs.append(1))
    metrics._fresh()
    metrics._fresh()
    assert runs == [1]
    monkeypatch.setattr(metrics, "_last_collect", 0.0)
    monkeypatch.setattr(metrics, "collect_bandwidth", lambda: 1 / 0)
    metrics._fresh()   # a failing pass is carried on from


def test_collector_thread_runs_the_loop_until_sleep_stops_it(web, monkeypatch):
    monkeypatch.setattr(metrics.os, "name", "nt")
    monkeypatch.setattr(metrics.start, "_started", False, raising=False)
    metrics.start()
    assert not getattr(metrics.start, "_started", False)   # not a posix box: nothing started
    monkeypatch.setattr(metrics.os, "name", "posix")
    proc_net_dev(web.tmp, monkeypatch, "")
    done = []
    monkeypatch.setattr(metrics, "collect_resources", lambda: done.append("res"))
    monkeypatch.setattr(metrics, "collect_bandwidth", lambda: done.append("bw"))
    monkeypatch.setattr(metrics, "_faults_scan", lambda: done.append("faults"))
    monkeypatch.setitem(__import__("sys").modules, "psutil", None)

    class Stop(BaseException):
        pass

    def sleep(n):
        if len(done) > 3:
            raise Stop
    monkeypatch.setattr(metrics.time, "sleep", sleep)

    class SyncThread:
        def __init__(self, target, name, daemon):
            self.target = target

        def start(self):
            self.target()
    monkeypatch.setattr(metrics.threading, "Thread", SyncThread)
    with pytest.raises(Stop):
        metrics.start()
    assert done == ["res", "bw", "faults", "res"] and metrics.RES_FILE.exists()
    metrics.start()   # already started: a no-op
    assert done == ["res", "bw", "faults", "res"]


# --------------------------------------------------------------------------- #
# Raw access: files, download, retention
# --------------------------------------------------------------------------- #
def test_raw_lists_files_per_site_and_disk_use(web):
    (web.sites / "ex.conf").write_text(vhost_conf("example.com"))
    (web.log / "example.com-access.log").write_text("12345\n")
    (web.log / "example.com-error.log").write_text("1\n")
    (web.log / "error.log").write_text("22\n")
    metrics.LOGROTATE.write_text("/var/log/apache2/*.log {\n\tweekly\n\trotate 4\n\tcompress\n}\n")
    r = metrics.raw()
    ex = next(s for s in r["sites"] if s["id"] == "example.com")
    assert [f["name"] for f in ex["files"]] == ["example.com-access.log"] and [f["name"] for f in ex["error_files"]] == ["example.com-error.log"]
    assert next(s for s in r["sites"] if s["id"] == "access")["error_files"] == []
    assert r["disk"] == 6 + 2 + 3
    assert r["retention"] == {"supported": True, "rotate": 4, "frequency": "weekly", "days": 28, "compress": True}


def test_log_file_accepts_only_log_names_inside_the_log_folder(web):
    (web.log / "example.com-access.log.2.gz").write_bytes(b"")
    assert metrics.log_file("example.com-access.log.2.gz") == web.log / "example.com-access.log.2.gz"
    for bad in ("", "../x.log", "x.txt", "nope.log", "a/b.log"):
        with pytest.raises(metrics.MetricsError, match="Unknown log file"):
            metrics.log_file(bad)


def test_retention_is_rewritten_in_logrotate(web):
    assert metrics.retention() == {"supported": False}
    metrics.LOGROTATE.write_text("/var/log/apache2/*.log {\n\tmonthly\n\tmissingok\n}\n")
    assert metrics.retention() == {"supported": True, "rotate": 14, "frequency": "monthly", "days": 420, "compress": False}
    r = metrics.set_retention(30)
    text = metrics.LOGROTATE.read_text()
    assert "\tdaily\n" in text and "\trotate 30\n" in text and "monthly" not in text
    assert r["days"] == 30 and r["frequency"] == "daily"
    metrics.set_retention(7)
    assert metrics.LOGROTATE.read_text().count("rotate") == 1 and metrics.retention()["rotate"] == 7
    with pytest.raises(metrics.MetricsError, match="Choose"):
        metrics.set_retention(5)


# --------------------------------------------------------------------------- #
# Analytics
# --------------------------------------------------------------------------- #
def test_analytics_report_from_a_log_with_sessions_and_referrers(web, monkeypatch):
    now = time.time()
    (web.sites / "ex.conf").write_text(vhost_conf("example.com", aliases=("www.example.com",)))
    t0 = now - 7200
    lines = [
        clf(t0, ip="1.1.1.1", url="/", ref="https://www.google.com/search?q=raspberry+panel"),
        clf(t0 + 10, ip="1.1.1.1", url="/style.css", size=10),
        clf(t0 + 20, ip="1.1.1.1", url="/about", ref="https://example.com/"),
        clf(t0 + 4000, ip="1.1.1.1", url="/again", ref="https://m.facebook.com/x?y=1"),   # a new visit after 30 min
        clf(t0 + 30, ip="2.2.2.2", url="/", ua=IPHONE, ref="https://news.example.org/post?id=1", user="alice"),
        clf(t0 + 40, ip="2.2.2.2", url="/gone", status=404, size=0, ref="https://example.com/old"),
        clf(t0 + 50, ip="3.3.3.3", url="/", ua=GOOGLEBOT, size=77),
        clf(t0 + 60, ip="4.4.4.4", url="/", ref="not a url://"),
    ]
    (web.log / "example.com-access.log").write_text("\n".join(lines) + "\n")
    bw = metrics._bw_state()
    bw["site_d"] = {"2026-01-05": {"example.com": {"hits": 10, "pages": 4, "bytes": 100, "visitors": 3, "bots": 2}},
                    "2026-02-01": {"example.com": {"hits": 1, "pages": 1, "bytes": 1, "visitors": 1}}}
    r = metrics.analytics("example.com", days=7)
    s = r["summary"]
    assert s == {"visitors": 3, "visits": 4, "pages": 5, "hits": 7, "bytes": 1234 * 5 + 10, "bot_hits": 1, "bot_bytes": 77,
                 "avg_duration": 5, "pages_per_visit": 1.25}
    assert r["first"] == pytest.approx(t0) and r["last"] == pytest.approx(t0 + 4000)
    assert r["engines"] == [{"key": "Google", "n": 1}] and r["phrases"] == [{"key": "raspberry panel", "n": 1}]
    assert r["social"] == [{"key": "Facebook", "n": 1}]
    assert {x["key"] for x in r["referrers"]} == {"https://m.facebook.com/x", "https://news.example.org/post"}
    assert r["e404"] == [{"url": "/gone", "n": 1, "ref": "https://example.com/old"}]
    assert r["users"] == [{"key": "alice", "n": 1}]
    assert r["robots"] == [{"name": "Googlebot", "hits": 1, "bytes": 77, "last": pytest.approx(t0 + 50)}]
    assert {f["ext"]: f["hits"] for f in r["filetypes"]} == {"(page)": 6, "css": 1}
    assert r["status"][0] == {"code": 200, "n": 7} and {"code": 404, "n": 1} in r["status"]
    assert {b["key"] for b in r["browsers"]} == {"Chrome", "Safari"} and {d["key"] for d in r["devices"]} == {"desktop", "phone"}
    assert sum(b["visits"] for b in r["durations"]) == 4 and r["durations"][0]["visits"] == 4
    assert {e["url"]: e["n"] for e in r["entry"]} == {"/": 3, "/again": 1}
    assert {e["url"]: e["n"] for e in r["exit"]} == {"/about": 1, "/again": 1, "/": 2}
    assert r["hosts"][0]["ip"] == "1.1.1.1" and r["hosts"][0]["pages"] == 3
    assert sum(d["hits"] for d in r["by_day"]) == 7 and sum(h["pages"] for h in r["by_hour"]) == 5 and sum(w["hits"] for w in r["by_wday"]) == 7
    assert r["history"] == [{"month": "2026-01", "hits": 8, "pages": 4, "bytes": 100, "visitors": 3, "days": 1},
                            {"month": "2026-02", "hits": 1, "pages": 1, "bytes": 1, "visitors": 1, "days": 1}]
    # A single rotated file can be analysed on its own; another site's file is refused.
    (web.log / "example.com-access.log.1").write_text(clf(now - 86400 * 20, ip="9.9.9.9") + "\n")
    r1 = metrics.analytics("example.com", days=1, file="example.com-access.log.1")
    assert r1["summary"]["hits"] == 1 and r1["hosts"][0]["ip"] == "9.9.9.9"
    (web.log / "other-access.log").write_text("")
    with pytest.raises(metrics.MetricsError, match="belong"):
        metrics.analytics("example.com", file="other-access.log")


def test_analytics_on_a_shared_log_counts_the_named_vhost_history(web):
    now = time.time()
    (web.sites / "x.conf").write_text(vhost_conf("x.test", log=False))
    (web.log / "other_vhosts_access.log").write_text(clf(now - 10, vhost="x.test:80") + "\n")
    bw = metrics._bw_state()
    bw["site_d"] = {metrics._day(now): {"vh:x.test": {"hits": 3, "pages": 2, "bytes": 5, "visitors": 1}}}
    r = metrics.analytics("other_vhosts_access", name="x.test")
    assert r["summary"]["hits"] == 1 and r["history"][0]["hits"] == 3


# --------------------------------------------------------------------------- #
# One IP
# --------------------------------------------------------------------------- #
def test_ip_info_combines_logs_bans_waf_and_abuse(web, monkeypatch):
    now = time.time()
    (web.sites / "ex.conf").write_text(vhost_conf("example.com"))
    (web.log / "example.com-access.log").write_text("\n".join([clf(now - 100, ip="203.0.113.5", url="/a"), clf(now - 50, ip="203.0.113.5", url="/b.css", size=10),
                                                               clf(now - 10, ip="8.8.8.8", url="/")]) + "\n")
    from backend import abuse, guard, waf, servers
    monkeypatch.setattr(metrics, "_ptr", lambda ip: "host.example.net")
    monkeypatch.setattr(abuse, "lookup", lambda ip: {"isp": "Example ISP"})
    monkeypatch.setattr(abuse, "evidence", lambda ip, days: [{"kind": "ssh"}, {"kind": "attack"}])
    monkeypatch.setattr(abuse, "reported", lambda: {"203.0.113.5": {"at": 1}})
    monkeypatch.setattr(guard, "status_of", lambda ips: {ips[0]: "banned"})
    monkeypatch.setattr(guard, "listing", lambda: {"enabled": True, "bans": [{"cidr": "203.0.113.0/24", "reason": "scan", "expires": None, "created": 1, "source": "manual"}],
                                                   "fail2ban": [{"ip": "203.0.113.5", "jails": ["sshd"], "expires_in": 60}],
                                                   "trusted": [{"cidr": "10.0.0.0/8", "note": "lan"}]})
    monkeypatch.setattr(waf, "events", lambda hours, limit, ip: [{"blocked": True, "rules": ["r"]}, {"blocked": False, "rules": ["r"]}])
    monkeypatch.setattr(waf, "_primary", lambda rules: {"category": "sqli"})
    monkeypatch.setattr(servers, "count", lambda: 2)
    out = metrics.ip_info(" 203.0.113.5 ", days=1)
    assert out["ip"] == "203.0.113.5" and out["ptr"] == "host.example.net" and out["private"] is False
    assert out["owner"] == {"isp": "Example ISP"}
    assert out["state"]["kind"] == "fail2ban" and out["state"]["cidr"] == "203.0.113.0/24" and out["state"]["enabled"] is True
    w = out["web"]
    assert w["hits"] == 2 and w["pages"] == 1 and w["bytes"] == 1244 and w["sites"] == [("example.com", 2)]
    assert [r["url"] for r in w["recent"]] == ["/b.css", "/a"] and w["agents"][0]["browser"] == "Chrome" and w["status"] == [(200, 2)]
    assert out["waf"] == {"events": 2, "blocked": 1, "types": [("sqli", 2)]}
    assert out["logins_failed"] == 1 and out["reported"] == {"at": 1} and out["servers"] == 2
    # A private address is never looked up; failures of the helpers are reported, not raised.
    monkeypatch.setattr(guard, "listing", lambda: 1 / 0)
    monkeypatch.setattr(waf, "events", lambda **kw: 1 / 0)
    monkeypatch.setattr(abuse, "evidence", lambda ip, days: 1 / 0)
    monkeypatch.setattr(servers, "count", lambda: 1 / 0)
    priv = metrics.ip_info("10.1.2.3")
    assert priv["private"] is True and priv["owner"] == {} and "error" in priv["state"]
    assert priv["waf"]["events"] == 0 and priv["logins_failed"] == 0 and priv["servers"] == 0
    monkeypatch.setattr(abuse, "lookup", lambda ip: 1 / 0)
    assert "error" in metrics.ip_info("203.0.113.9")["owner"]
    with pytest.raises(metrics.MetricsError, match="IP address"):
        metrics.ip_info("not-an-ip")


def test_ptr_uses_reverse_dns_with_a_timeout(monkeypatch):
    import socket
    monkeypatch.setattr(socket, "gethostbyaddr", lambda ip: ("name.example.net", [], [ip]))
    assert metrics._ptr("203.0.113.5") == "name.example.net"

    def fail(ip):
        raise socket.herror("no PTR")
    monkeypatch.setattr(socket, "gethostbyaddr", fail)
    assert metrics._ptr("203.0.113.5") == ""


def test_state_files_are_written_atomically(web):
    metrics._save_json(metrics.RES_FILE, {"a": 1})
    assert json.loads(metrics.RES_FILE.read_text()) == {"a": 1}
    assert [p.name for p in metrics.STATE_DIR.iterdir()] == ["resources.json"]
    assert metrics._load_json(metrics.STATE_DIR / "missing.json", {"d": 1}) == {"d": 1}
    r = metrics._res_state()
    assert r == {"m1": [], "m10": [], "h": [], "faults": []}
