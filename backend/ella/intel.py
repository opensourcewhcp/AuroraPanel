"""Stage 7: reputation lists, real bot checks, country lookup. All of it is added information with a source and a date.

A list hit tags and scores. It bans only if the operator turned that on for that list, and the Safety Lock still applies.
"""
from __future__ import annotations

import csv
import gzip
import ipaddress
import re
import socket
import time
import urllib.request
from pathlib import Path

FEEDS = {
    "spamhaus-drop": ("Spamhaus DROP", "https://www.spamhaus.org/drop/drop.txt"),
    "firehol-level1": ("FireHOL level 1", "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset"),
    "tor-exits": ("Tor exit nodes", "https://check.torproject.org/torbulkexitlist"),
}
TTL = 86400
MAX_ENTRIES = 200_000
BOTS = {
    "Googlebot": (r"googlebot", (".googlebot.com", ".google.com", ".googleusercontent.com")),
    "Bingbot": (r"bingbot", (".search.msn.com",)),
    "YandexBot": (r"yandex(bot|images|mobilebot)", (".yandex.ru", ".yandex.net", ".yandex.com")),
    "Applebot": (r"applebot", (".applebot.apple.com",)),
}
_LINE = re.compile(r"^\s*([0-9a-fA-F:.]+(?:/\d{1,3})?)")


def parse_list(text: str) -> list:
    out = []
    for line in text.splitlines():
        if line.lstrip().startswith((";", "#")):
            continue
        m = _LINE.match(line)
        if not m:
            continue
        try:
            n = ipaddress.ip_network(m.group(1), strict=False)
        except ValueError:
            continue
        if not (n.is_private or n.is_loopback or n.is_link_local or n.is_multicast or n.is_unspecified or n.is_reserved):  # never block your own LAN because a list says so
            out.append(n)
    return out[:MAX_ENTRIES]


def _b(ip) -> bytes:
    return ip.packed


def claimed_bot(user_agent: str | None) -> str | None:
    ua = (user_agent or "").lower()
    for name, (rx, _) in BOTS.items():
        if re.search(rx, ua):
            return name
    return None


def verify_bot(ip: str, name: str, resolver=None) -> bool | None:
    """Reverse DNS, then forward DNS back to the same address. None means DNS didn't answer, which proves nothing."""
    res = resolver or _Resolver()
    try:
        host = res.reverse(ip)
    except socket.herror:
        return False
    except OSError:
        return None
    if not host.lower().rstrip(".").endswith(BOTS[name][1]):
        return False
    try:
        return ip in res.forward(host)
    except OSError:
        return None


class _Resolver:
    def reverse(self, ip: str) -> str:
        return socket.gethostbyaddr(ip)[0]

    def forward(self, host: str) -> list[str]:
        return [i[4][0] for i in socket.getaddrinfo(host, None)]


class Intel:
    def __init__(self, store, fetch=None, geo_dir: str | Path | None = None):
        self.store = store
        self.fetch = fetch or _fetch
        self.geo_dir = Path(geo_dir) if geo_dir else store.dir / "geo"
        self._geo: list | None = None
        self._geo_source: dict = {}
        self._bot_cache: dict = {}

    # ---- lists
    def lists(self) -> list[dict]:
        rows = {r["name"]: dict(r) for r in self.store.read(lambda c: c.execute("SELECT * FROM ti_lists").fetchall())}
        out = []
        for key, (title, url) in FEEDS.items():
            out.append({"name": key, "title": title, "url": url, "enabled": 0, "auto_ban": 0, "count": 0, "fetched_at": None, "expires_at": None, "last_error": "", **rows.pop(key, {})})
        out += [{"title": v["name"], **v} for v in rows.values()]
        return out

    def configure(self, name: str, enabled: bool, auto_ban: bool, actor: str) -> dict:
        if name not in FEEDS and not self.store.read(lambda c: c.execute("SELECT 1 FROM ti_lists WHERE name=?", (name,)).fetchone()):
            raise ValueError("Unknown list")

        def save(c):
            c.execute("INSERT INTO ti_lists(name, url, enabled, auto_ban) VALUES (?,?,?,?) ON CONFLICT(name) DO UPDATE SET enabled=excluded.enabled, auto_ban=excluded.auto_ban", (name, FEEDS.get(name, ("", ""))[1], int(enabled), int(auto_ban)))
            self.store.audit_in(c, actor, "ti.configured", name, {"enabled": bool(enabled), "auto_ban": bool(auto_ban)})
        self.store.run(save)
        if enabled:
            self.refresh(name)
        return next(x for x in self.lists() if x["name"] == name)

    def add_own(self, name: str, text: str, actor: str) -> dict:
        if not re.fullmatch(r"[a-z0-9-]{2,40}", name or "") or name in FEEDS:
            raise ValueError("A list name uses lowercase letters, digits and dashes")
        nets = parse_list(text)
        if not nets:
            raise ValueError("No public addresses found in that text")
        self._store_entries(name, nets, None, True)
        self.store.audit(actor, "ti.own_list", name, {"count": len(nets)})
        return next(x for x in self.lists() if x["name"] == name)

    def _store_entries(self, name: str, nets: list, url, enabled: bool) -> None:
        now = time.time()

        def save(c):
            c.execute("INSERT INTO ti_lists(name, url, enabled) VALUES (?,?,?) ON CONFLICT(name) DO NOTHING", (name, url, int(enabled)))
            c.execute("DELETE FROM ti_entries WHERE list = ?", (name,))
            c.executemany("INSERT INTO ti_entries(list, family, start, stop) VALUES (?,?,?,?)", ((name, n.version, _b(n.network_address), _b(n.broadcast_address)) for n in nets))
            c.execute("UPDATE ti_lists SET count=?, fetched_at=?, expires_at=?, last_error='' WHERE name=?", (len(nets), now, now + 3 * TTL if url else None, name))
        self.store.run(save)

    def refresh(self, name: str) -> None:
        url = FEEDS[name][1] if name in FEEDS else None
        if not url:
            return
        try:
            nets = parse_list(self.fetch(url))
            if not nets:
                raise ValueError("the download had no addresses in it")
            self._store_entries(name, nets, url, True)
        except (OSError, ValueError) as exc:
            self.store.run(lambda c: c.execute("UPDATE ti_lists SET last_error=? WHERE name=?", (str(exc)[:200], name)))

    def tick(self) -> None:
        now = time.time()
        for x in self.lists():
            if x["enabled"] and x["name"] in FEEDS and now - (x["fetched_at"] or 0) > TTL:
                self.refresh(x["name"])

    def lookup(self, ip: str) -> list[dict]:
        """Which lists have this address, with source and age. An expired list is left out rather than trusted."""
        try:
            a = ipaddress.ip_address(ip)
        except ValueError:
            return []
        now = time.time()
        rows = self.store.read(lambda c: c.execute(
            "SELECT DISTINCT l.name, l.url, l.fetched_at, l.expires_at, l.auto_ban FROM ti_entries e JOIN ti_lists l ON l.name = e.list WHERE e.family = ? AND e.start <= ? AND e.stop >= ? AND l.enabled = 1",
            (a.version, _b(a), _b(a))).fetchall())
        return [dict(r) for r in rows if not r["expires_at"] or r["expires_at"] > now]

    # ---- countries: a CSV from DB-IP Lite or similar (start,end,country), which the operator puts in the geo folder
    def geo_status(self) -> dict:
        self._load_geo()
        return self._geo_source

    def _load_geo(self) -> None:
        files = sorted(self.geo_dir.glob("*.csv*")) if self.geo_dir.exists() else []
        if not files:
            self._geo, self._geo_source = [], {"available": False, "why": f"No database. Put a start,end,country CSV (such as DB-IP Lite) in {self.geo_dir}."}
            return
        src = files[-1]
        stamp = src.stat().st_mtime
        if self._geo is not None and self._geo_source.get("mtime") == stamp:
            return
        rows = []
        opener = gzip.open if src.suffix == ".gz" else open
        with opener(src, "rt", encoding="utf-8", errors="replace") as f:
            for rec in csv.reader(f):
                if len(rec) >= 3:
                    try:
                        s, e = ipaddress.ip_address(rec[0].strip()), ipaddress.ip_address(rec[1].strip())
                    except ValueError:
                        continue
                    rows.append((s.version, _b(s), _b(e), rec[2].strip()[:2].upper()))
        rows.sort()
        self._geo, self._geo_source = rows, {"available": True, "source": src.name, "date": stamp, "mtime": stamp, "ranges": len(rows)}

    def country(self, ip: str) -> dict | None:
        self._load_geo()
        if not self._geo:
            return None
        try:
            a = ipaddress.ip_address(ip)
        except ValueError:
            return None
        import bisect
        i = bisect.bisect_right(self._geo, (a.version, _b(a), b"\xff" * 17, "ZZ")) - 1
        if i >= 0:
            v, s, e, cc = self._geo[i]
            if v == a.version and s <= _b(a) <= e:
                return {"country": cc, "source": self._geo_source["source"], "date": self._geo_source["date"], "note": "Country data is often wrong for mobile and VPN addresses."}
        return None

    # ---- bots
    def bot_check(self, ip: str, user_agent: str | None, resolver=None) -> dict | None:
        """{"bot", "verified"} when the User-Agent claims to be a search engine, cached for an hour."""
        name = claimed_bot(user_agent)
        if not name:
            return None
        key = (ip, name)
        hit = self._bot_cache.get(key)
        if hit and hit[0] > time.time():
            return {"bot": name, "verified": hit[1]}
        ok = verify_bot(ip, name, resolver)
        if len(self._bot_cache) > 5000:
            self._bot_cache.clear()
        self._bot_cache[key] = (time.time() + 3600, ok)
        return {"bot": name, "verified": ok}


def _fetch(url: str) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": "AuroraPanel"})
    with urllib.request.urlopen(req, timeout=30) as r:  # noqa: S310  fixed https addresses from FEEDS
        return r.read(30_000_000).decode("utf-8", "replace")
