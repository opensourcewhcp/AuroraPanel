"""Stage 5: one panel holds the policy, others pull it.

Managed servers call in, so they can sit behind NAT and no inbound port is needed. Every request and every policy is signed
with HMAC-SHA256 under a secret made when the server joined. A request carries a timestamp and a nonce, so an old one
can't be replayed. A policy carries a version that only goes up, so an old one can't be fed back. If the control panel is
gone, a managed server keeps enforcing the last valid policy, and queues what it wants to report in a bounded file.
"""
from __future__ import annotations

import hashlib
import hmac
import http.client
import json
import os
import re
import secrets
import ssl
import time
import uuid
from pathlib import Path
from urllib.parse import urlsplit

from . import housekeeping

PROTOCOL = 1
SKEW = 60  # seconds a signed request stays good, both ways
SPOOL_MAX_BYTES = 20_000_000
OFFLINE_AFTER = 180


class FleetError(RuntimeError):
    pass


def canonical(doc: dict) -> bytes:
    return json.dumps(doc, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def sign_doc(secret: str, doc: dict) -> str:
    return hmac.new(secret.encode(), canonical(doc), hashlib.sha256).hexdigest()


def request_sig(secret: str, method: str, path: str, ts: int, nonce: str, body: bytes) -> str:
    msg = b"\n".join([method.encode(), path.encode(), str(ts).encode(), nonce.encode(), hashlib.sha256(body).hexdigest().encode()])
    return hmac.new(secret.encode(), msg, hashlib.sha256).hexdigest()


def verify_policy(secret: str, envelope: dict, have_version: int) -> dict:
    """The policy inside, if it's signed correctly and newer than what's here. Otherwise it's refused."""
    doc, sig = envelope.get("policy"), envelope.get("signature")
    if not isinstance(doc, dict) or not isinstance(sig, str) or not hmac.compare_digest(sign_doc(secret, doc), sig):
        raise FleetError("The policy's signature doesn't match, so it wasn't used")
    if not isinstance(doc.get("version"), int) or doc["version"] <= have_version:
        raise FleetError(f"This policy is version {doc.get('version')} and {have_version} is already here, so it wasn't used")
    if doc.get("protocol") != PROTOCOL:
        raise FleetError("This policy uses a protocol version this server doesn't know")
    return doc


class ControlPlane:
    def __init__(self, store, book, engine=None):
        self.store, self.book, self.engine = store, book, engine

    def agents(self) -> list[dict]:
        now = time.time()
        rows = [dict(r) for r in self.store.read(lambda c: c.execute("SELECT * FROM agents ORDER BY created_at").fetchall())]
        for r in rows:
            r.pop("secret", None)
            r["status"] = json.loads(r["status"] or "{}")
            r["online"] = bool(r["last_seen"] and now - r["last_seen"] < OFFLINE_AFTER and not r["revoked"])
        return rows

    def enroll(self, name: str, actor: str) -> dict:
        name = re.sub(r"[^A-Za-z0-9 ._-]", "", str(name or ""))[:60]
        if not name:
            raise FleetError("Give the server a name")
        aid, secret = uuid.uuid4().hex, secrets.token_urlsafe(32)

        def add(c):
            c.execute("INSERT INTO agents(id, name, secret, created_at) VALUES (?,?,?,?)", (aid, name, secret, time.time()))
            self.store.audit_in(c, actor, "fleet.enrolled", aid, {"name": name})
        self.store.run(add)
        return {"agent_id": aid, "secret": secret, "name": name, "note": "Shown once. Enter it on the other server's WAF Ella page."}

    def rotate(self, aid: str, actor: str) -> dict:
        secret = secrets.token_urlsafe(32)

        def save(c):
            n = c.execute("UPDATE agents SET secret=? WHERE id=? AND revoked=0", (secret, aid)).rowcount
            if not n:
                raise FleetError("No such server")
            self.store.audit_in(c, actor, "fleet.rotated", aid, {})
        self.store.run(save)
        return {"agent_id": aid, "secret": secret}

    def revoke(self, aid: str, actor: str) -> dict:
        def save(c):
            c.execute("UPDATE agents SET revoked=1 WHERE id=?", (aid,))
            self.store.audit_in(c, actor, "fleet.revoked", aid, {})
        self.store.run(save)
        return {"ok": True}

    def _agent(self, aid: str) -> dict:
        r = self.store.read(lambda c: c.execute("SELECT * FROM agents WHERE id=?", (aid,)).fetchone())
        if not r or r["revoked"]:
            raise PermissionError("Unknown or revoked server")
        return dict(r)

    def authenticate(self, method: str, path: str, aid: str, ts, nonce: str, sig: str, body: bytes, now: float | None = None) -> dict:
        """Signature, time window, then the nonce, which works only once. The order means junk can't fill the nonce table."""
        now = now or time.time()
        agent = self._agent(aid)
        try:
            ts = int(ts)
        except (TypeError, ValueError) as exc:
            raise PermissionError("Bad timestamp") from exc
        if abs(now - ts) > SKEW:
            raise PermissionError(f"The clocks differ by more than {SKEW} seconds")
        if not re.fullmatch(r"[A-Za-z0-9_-]{16,64}", nonce or "") or not hmac.compare_digest(request_sig(agent["secret"], method, path, ts, nonce, body), sig or ""):
            raise PermissionError("Bad signature")

        def use(c):
            c.execute("DELETE FROM nonces WHERE ts < ?", (now - 2 * SKEW,))
            if c.execute("SELECT 1 FROM nonces WHERE nonce = ?", (nonce,)).fetchone():
                raise PermissionError("This request has already been used")
            c.execute("INSERT INTO nonces(nonce, ts) VALUES (?, ?)", (nonce, now))
        self.store.run(use)
        return agent

    def _policy_doc(self) -> dict:
        ver = self.store.setting("fleet_version") or 0
        config = housekeeping.export_config(self.book, self.store)
        config.pop("exported", None)
        digest = hashlib.sha256(canonical(config)).hexdigest()
        bans = self.store.setting("fleet_bans") or []
        bans = [b for b in bans if not b.get("until") or b["until"] > time.time()]
        changed = digest != self.store.setting("fleet_digest") or bans != (self.store.setting("fleet_bans_seen") or [])
        if changed or not ver:
            ver += 1
            self.store.set_setting("fleet_version", ver)
            self.store.set_setting("fleet_digest", digest)
            self.store.set_setting("fleet_bans", bans)
            self.store.set_setting("fleet_bans_seen", bans)
        return {"protocol": PROTOCOL, "version": ver, "issued": int(time.time()), "config": config, "bans": bans}

    def checkin(self, agent: dict, report: dict, now: float | None = None) -> dict:
        """A managed server's heartbeat: its state goes in, a new policy comes back if there is one, signed with its secret."""
        now = now or time.time()
        doc = self._policy_doc()
        status = {k: report.get(k) for k in ("transport", "enforcing_version", "error", "web", "skew", "panel", "queue") if k in report}
        events = report.get("events") or []
        added = 0
        if events:
            added = self.store.add_events([e for e in events if isinstance(e, dict) and _fleet_event_ok(e)][:2000])

        def save(c):
            c.execute("UPDATE agents SET last_seen=?, policy_version=?, status=? WHERE id=?", (now, int(report.get("enforcing_version") or 0), json.dumps(status)[:4000], agent["id"]))
        self.store.run(save)
        out = {"protocol": PROTOCOL, "server_time": now, "events_stored": added, "events_seen": len(events)}
        if int(report.get("have_version") or 0) < doc["version"]:
            out["envelope"] = {"policy": doc, "signature": sign_doc(agent["secret"], doc)}
        return out

    def ban_everywhere(self, target: str, ttl: int | None, reason: str, actor: str) -> dict:
        """Goes out with the next policy. Each server still applies its own Safety Lock."""
        from .adapter import net
        n = str(net(target))
        bans = [b for b in (self.store.setting("fleet_bans") or []) if b["target"] != n]
        bans.append({"target": n, "until": time.time() + ttl if ttl else None, "reason": str(reason or "")[:200], "id": uuid.uuid4().hex})
        self.store.set_setting("fleet_bans", bans)
        self.store.audit(actor, "fleet.ban_everywhere", n, {"ttl": ttl, "reason": reason})
        result = {"queued": True, "servers": len([a for a in self.agents() if not a["revoked"]])}
        if self.engine:
            try:
                result["here"] = self.engine.ban(n, ttl, reason, actor)["state"]
            except RuntimeError as exc:
                result["here"] = f"refused: {exc}"
        return result

    def lift_everywhere(self, target: str, actor: str) -> dict:
        from .adapter import net
        n = str(net(target))
        self.store.set_setting("fleet_bans", [b for b in (self.store.setting("fleet_bans") or []) if b["target"] != n])
        self.store.audit(actor, "fleet.lift_everywhere", n, {})
        return {"ok": True}


def _fleet_event_ok(e: dict) -> bool:
    return isinstance(e.get("hash"), str) and re.fullmatch(r"[0-9a-f]{64}", e["hash"]) is not None and isinstance(e.get("ts_event"), (int, float)) and isinstance(e.get("source"), str)


class Spool:
    """A bounded queue on disk. When it's full the oldest records go first, and the count of what was lost is kept."""

    def __init__(self, path: Path | str, max_bytes: int = SPOOL_MAX_BYTES):
        self.path, self.max_bytes = Path(path), max_bytes

    def put(self, events: list[dict]) -> None:
        if not events:
            return
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("a", encoding="utf-8") as f:
            for e in events:
                f.write(json.dumps(e) + "\n")
        if self.path.stat().st_size > self.max_bytes:
            data = self.path.read_bytes()
            keep = data[len(data) - self.max_bytes // 2:]
            keep = keep[keep.find(b"\n") + 1:]
            lost = data[:len(data) - len(keep)].count(b"\n")
            tmp = self.path.with_suffix(".tmp")
            tmp.write_bytes(keep)
            os.replace(tmp, self.path)
            counter = self.path.with_suffix(".lost")
            counter.write_text(str(self.lost() + lost), encoding="utf-8")

    def lost(self) -> int:
        try:
            return int(self.path.with_suffix(".lost").read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return 0

    def peek(self, n: int = 1000) -> tuple[list[dict], int]:
        """(records, bytes they take). Taken off only after the other side confirms them, so a failure repeats, and the hash drops repeats."""
        if not self.path.exists():
            return [], 0
        out, size = [], 0
        with self.path.open("rb") as f:
            for line in f:
                if len(out) >= n:
                    break
                size += len(line)
                try:
                    out.append(json.loads(line))
                except ValueError:
                    continue
        return out, size

    def drop(self, size: int) -> None:
        if not size or not self.path.exists():
            return
        data = self.path.read_bytes()[size:]
        tmp = self.path.with_suffix(".tmp")
        tmp.write_bytes(data)
        os.replace(tmp, self.path)

    def depth(self) -> int:
        return self.path.stat().st_size if self.path.exists() else 0


FORWARD_SEVERITY = ("CRITICAL", "ERROR", "WARNING")
FORWARD_FIELDS = ("hash", "ts_event", "ts_received", "server", "account", "domain", "source", "peer_ip", "client_ip", "client_ip_source", "method", "url", "query_keys", "status", "response_size", "user_agent", "headers", "rule_id", "severity", "confidence", "anomaly_score", "action", "tags", "raw_ref", "historical", "missing_fields")


class Member:
    """This panel as a managed server."""

    def __init__(self, store, book, engine, transport=None, sender=None):
        self.store, self.book, self.engine = store, book, engine
        self.transport = transport
        self.sender = sender or _send
        self.spool = Spool(store.dir / "fleet-spool.jsonl")

    def config(self) -> dict | None:
        return self.store.setting("fleet_member")

    def status(self) -> dict:
        cfg = self.config()
        if not cfg:
            return {"joined": False}
        return {"joined": True, "url": cfg["url"], "agent_id": cfg["agent_id"], "version": cfg.get("version", 0), "last_ok": cfg.get("last_ok"), "last_error": cfg.get("last_error", ""), "queue_bytes": self.spool.depth(), "lost_events": self.spool.lost(), "skew": cfg.get("skew")}

    def join(self, url: str, agent_id: str, secret: str, actor: str, pin: str | None = None) -> dict:
        u = urlsplit(str(url or "").strip())
        if u.scheme not in ("https", "http") or not u.hostname:
            raise FleetError("Give the control panel's address, like https://panel.example.com:8088")
        if not re.fullmatch(r"[0-9a-f]{32}", agent_id or "") or len(secret or "") < 20:
            raise FleetError("The server ID or secret doesn't look right")
        cfg = {"url": url.rstrip("/"), "agent_id": agent_id, "secret": secret, "pin": (pin or "").lower().replace(":", "") or None, "version": 0, "position": time.time()}
        self.store.set_setting("fleet_member", cfg)
        self.store.audit(actor, "fleet.joined", url, {"agent_id": agent_id})
        return self.tick()

    def leave(self, actor: str) -> dict:
        self.store.set_setting("fleet_member", None)
        self.store.audit(actor, "fleet.left", "", {})
        return {"ok": True}

    def _collect(self, cfg: dict) -> None:
        since = float(cfg.get("position") or time.time())
        rows = list(self.store.scan_events(since + 0.000001, "historical = 0 AND severity IN ('CRITICAL','ERROR','WARNING')", limit=2000))
        if rows:
            self.spool.put([{k: e.get(k) for k in FORWARD_FIELDS} for e in reversed(rows)])
            cfg["position"] = rows[0]["ts_event"]

    def tick(self) -> dict:
        cfg = self.config()
        if not cfg:
            return {"joined": False}
        self._collect(cfg)
        events, size = self.spool.peek()
        report = {"have_version": cfg.get("version", 0), "enforcing_version": cfg.get("version", 0), "transport": getattr(self.transport, "last_transport", "in-process"), "queue": self.spool.depth(), "events": events, "lost": self.spool.lost()}
        try:
            answer = self.sender(cfg, "/api/ella/fleet/checkin", report)
        except (OSError, http.client.HTTPException, FleetError, ValueError) as exc:
            cfg["last_error"] = str(exc)[:300]
            self.store.set_setting("fleet_member", cfg)
            return {"ok": False, "error": cfg["last_error"], "enforcing": cfg.get("version", 0)}  # keeps enforcing what it has
        self.spool.drop(size)
        cfg.update(last_ok=time.time(), last_error="", skew=round(time.time() - answer.get("server_time", time.time()), 1))
        result = {"ok": True, "applied": None}
        env = answer.get("envelope")
        if env:
            try:
                doc = verify_policy(cfg["secret"], env, cfg.get("version", 0))
                self._apply(doc)
                cfg["version"] = doc["version"]
                result["applied"] = doc["version"]
            except (FleetError, ValueError) as exc:  # includes a web server refusing the rules
                cfg["last_error"] = str(exc)[:300]
                result = {"ok": False, "error": cfg["last_error"]}
        self.store.set_setting("fleet_member", cfg)
        return result

    def _apply(self, doc: dict) -> None:
        housekeeping.import_config(self.book, self.store, doc["config"], "control-panel")
        from .blocks import BlockError
        wanted = {b["target"]: b for b in doc.get("bans") or []}
        held = self.store.setting("fleet_held") or {}
        for t, b in wanted.items():
            if t in held:
                continue
            ttl = int(b["until"] - time.time()) if b.get("until") else None
            if ttl is not None and ttl <= 0:
                continue
            try:
                self.engine.ban(t, ttl, f"From the control panel: {b.get('reason', '')}"[:300], "control-panel")
                held[t] = b.get("id")
            except BlockError as exc:  # this server's Safety Lock has the last word over its own addresses
                self.store.audit("control-panel", "ban.refused_locally", t, {"why": str(exc)[:200]})
        for t in [x for x in held if x not in wanted]:
            for row in self.engine.list_blocks():
                if row["source"] == "ella" and row["target"] == t and row["owner"] == "control-panel":
                    self.engine.unban(row["id"], "control-panel", "Lifted by the control panel")
            held.pop(t)
        self.store.set_setting("fleet_held", held)


def _send(cfg: dict, path: str, report: dict, timeout: int = 15) -> dict:
    u = urlsplit(cfg["url"])
    body = json.dumps(report).encode()
    ts, nonce = int(time.time()), secrets.token_urlsafe(24)
    headers = {"Content-Type": "application/json", "X-Ella-Agent": cfg["agent_id"], "X-Ella-Time": str(ts), "X-Ella-Nonce": nonce, "X-Ella-Signature": request_sig(cfg["secret"], "POST", path, ts, nonce, body)}
    if u.scheme == "https":
        ctx = ssl.create_default_context()
        if cfg.get("pin"):  # a self-signed panel: the certificate's fingerprint is what identifies it, as under Servers
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        c = http.client.HTTPSConnection(u.hostname, u.port or 443, timeout=timeout, context=ctx)
    else:
        c = http.client.HTTPConnection(u.hostname, u.port or 80, timeout=timeout)
    try:
        c.connect()
        if u.scheme == "https" and cfg.get("pin"):
            got = hashlib.sha256(c.sock.getpeercert(binary_form=True)).hexdigest()
            if not hmac.compare_digest(got, cfg["pin"]):
                raise FleetError("The control panel's certificate doesn't match the fingerprint on record")
        c.request("POST", path, body=body, headers=headers)
        r = c.getresponse()
        data = r.read(50_000_000)
    finally:
        c.close()
    if r.status != 200:
        raise FleetError(f"The control panel answered {r.status}: {data[:200].decode('utf-8', 'replace')}")
    return json.loads(data)
