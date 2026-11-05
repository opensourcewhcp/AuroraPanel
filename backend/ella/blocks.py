"""Enforcer: network bans with a state machine, Safety Lock and reconciliation.

An operation goes requested -> pending -> applied | failed. "applied" is only ever set after the address has been
written to the nft set and read back from it; nothing moves a state on a timer. Ella's bans live in their own
table, so lifting one can't touch a ban from fail2ban or the IP Blocker on the same address.
"""
from __future__ import annotations

import ipaddress
import json
import math
import os
import socket
import time
import uuid
from pathlib import Path
from urllib.parse import urlsplit

from .adapter import AdapterError, AgentUnavailable, net

RETRY_DELAYS = (2, 8, 30)  # seconds before attempts 2, 3 and 4; after that the operation has failed
MIN_PREFIX = {4: 8, 6: 32}  # wider than this is never a single ban
LOOPBACK = (ipaddress.ip_network("127.0.0.0/8"), ipaddress.ip_network("::1/128"), ipaddress.ip_network("0.0.0.0/8"))


class BlockError(RuntimeError):
    pass


class SafetyLocked(BlockError):
    """Refused by the Safety Lock. reasons says what the target would have covered."""

    def __init__(self, reasons: list[str], forceable: bool):
        super().__init__("; ".join(reasons))
        self.reasons, self.forceable = reasons, forceable


def _overlap(a, b) -> bool:
    return a.version == b.version and (a.subnet_of(b) or b.subnet_of(a))


def _panel_server_nets() -> list:
    """Addresses of the other panels added under Servers."""
    out = []
    try:
        from .. import servers
        for s in servers._load().get("servers", []):
            host = urlsplit(s.get("url", "")).hostname
            if not host:
                continue
            try:
                out.append(ipaddress.ip_network(host))
            except ValueError:
                try:
                    socket.setdefaulttimeout(2)
                    out += [ipaddress.ip_network(i[4][0]) for i in socket.getaddrinfo(host, None)]
                except OSError:
                    pass
                finally:
                    socket.setdefaulttimeout(None)
    except Exception:  # noqa: BLE001  the lock must still answer when that module can't
        pass
    return out


def _guard_protected(client_ip: str | None) -> list[tuple]:
    """What the panel's own guard already refuses to ban (this server's addresses, the LAN gateway)."""
    try:
        from .. import guard
        return list(guard._protected_nets(client_ip))
    except Exception:  # noqa: BLE001
        return []


class Engine:
    def __init__(self, store, adapter, journal: Path | str | None = None):
        self.store, self.adapter = store, adapter
        self.journal = Path(journal) if journal else store.dir / "cli-journal.jsonl"

    # ------------------------------------------------------------- Safety Lock
    def safety_reasons(self, target, operator_ip: str | None) -> tuple[list[str], bool]:
        """(why it's locked, can a force flag override it). Loopback can't be overridden at all."""
        n = target
        for lo in LOOPBACK:
            if _overlap(n, lo):
                return [f"{n} includes {lo}, this machine's own range, which is never banned"], False
        reasons = []
        checks: list[tuple] = []
        if operator_ip:
            try:
                checks.append((ipaddress.ip_network(operator_ip), "your own address"))
            except ValueError:
                pass
        for key, label in (("management_cidrs", "a management range"), ("trusted_proxies", "a trusted proxy or CDN range")):
            for c in self.store.setting(key) or []:
                try:
                    checks.append((ipaddress.ip_network(c, strict=False), f"{label} ({c})"))
                except ValueError:
                    pass
        checks += [(p, "a panel server from Servers") for p in _panel_server_nets()]
        checks += _guard_protected(None)
        for p, why in checks:
            if _overlap(n, p) and why not in reasons:
                reasons.append(why)
        return [f"{n} includes {r}" for r in reasons], True

    # ------------------------------------------------------------- reading
    def get_block(self, block_id: str) -> dict | None:
        r = self.store.read(lambda c: c.execute("SELECT * FROM blocks WHERE id = ?", (block_id,)).fetchone())
        return dict(r) if r else None

    def get_operation(self, op_id: str) -> dict | None:
        r = self.store.read(lambda c: c.execute("SELECT * FROM operations WHERE id = ?", (op_id,)).fetchone())
        if not r:
            return None
        return {**dict(r), "capabilities": json.loads(r["capabilities"])}

    def list_blocks(self, active_only: bool = True, limit: int = 500) -> list[dict]:
        sql = "SELECT b.*, o.state AS op_state, o.error AS op_error, o.attempts AS op_attempts FROM blocks b LEFT JOIN operations o ON o.id = b.operation_id "
        sql += ("WHERE b.desired_state = 'active' " if active_only else "") + "ORDER BY b.created_at DESC LIMIT ?"
        return [dict(r) for r in self.store.read(lambda c: c.execute(sql, (max(1, min(limit, 5000)),)).fetchall())]

    def _set_elements(self) -> dict | None:
        """Everything in Ella's sets, or None when they can't be read."""
        out = {}
        for family in (4, 6):
            r = self.adapter.call("nft_list", {"family": family})
            if not r["ok"]:
                return None
            for e in r["elements"]:
                out[str(net(e["element"]))] = e
        return out

    # ------------------------------------------------------------- ban
    def ban(self, target: str, ttl: int | None, reason: str, actor: str, operator_ip: str | None = None, force: bool = False,
            idempotency_key: str | None = None, scope: str = "server") -> dict:
        if scope != "server":
            raise BlockError("A network ban applies to the whole server. A domain or path can only be blocked by a WAF rule, which firewall bans can't express.")
        try:
            n = net(target)
        except AdapterError as exc:
            raise BlockError(str(exc)) from exc
        if n.prefixlen < MIN_PREFIX[n.version]:
            raise BlockError(f"{n} is too wide for a ban (narrowest allowed prefix: /{MIN_PREFIX[n.version]})")
        if ttl is not None and (not isinstance(ttl, int) or not 1 <= ttl <= 10 * 365 * 86400):
            raise BlockError("TTL must be between 1 second and 10 years")
        if idempotency_key:
            row = self.store.read(lambda c: c.execute("SELECT id FROM operations WHERE idempotency_key = ?", (idempotency_key,)).fetchone())
            if row:
                return {**self.get_operation(row["id"]), "replayed": True}
        reasons, forceable = self.safety_reasons(n, operator_ip)
        if reasons and not (force and forceable):
            self.store.audit(actor, "ban.refused", str(n), {"reasons": reasons, "operator_ip": operator_ip})
            raise SafetyLocked(reasons, forceable)
        block_id, op_id, now, cidr = uuid.uuid4().hex, uuid.uuid4().hex, time.time(), str(n)
        expires = now + ttl if ttl else None

        def create(c):
            old = c.execute("SELECT id, operation_id FROM blocks WHERE source = 'ella' AND target = ? AND desired_state = 'active'", (cidr,)).fetchone()
            if old:
                return old
            c.execute("INSERT INTO blocks(id, source, owner, scope, backend, target, reason, ttl, created_at, expires_at, desired_state, actual_state, operation_id, forced) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                      (block_id, "ella", actor, scope, "nft-set", cidr, (reason or "")[:500], ttl, now, expires, "active", "absent", op_id, int(bool(force and reasons))))
            c.execute("INSERT INTO operations(id, block_id, kind, idempotency_key, state, actor, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?)",
                      (op_id, block_id, "ban", idempotency_key, "requested", actor, now, now))
            self.store.audit_in(c, actor, "ban.force" if force and reasons else "ban.requested", cidr,
                                {"reason": reason, "ttl": ttl, "scope": scope, "operator_ip": operator_ip, "overrode": reasons}, op_id)
            return None
        existing = self.store.run(create)
        if existing:  # same target, same source: merge rather than hold two records for one set element
            return {**self.get_operation(existing["operation_id"]), "merged": True}
        self._attempt(op_id)
        return self.get_operation(op_id)

    # ------------------------------------------------------------- unban
    def unban(self, block_id: str, actor: str, reason: str = "") -> dict:
        b = self.get_block(block_id)
        if not b or b["source"] != "ella":
            raise BlockError("No such WAF Ella ban. Bans from other sources are lifted where they were made.")
        if b["desired_state"] != "active":
            raise BlockError(f"This ban is already {b['desired_state']}")
        op_id, now = uuid.uuid4().hex, time.time()

        def create(c):
            c.execute("INSERT INTO operations(id, block_id, kind, state, actor, created_at, updated_at) VALUES (?,?,?,?,?,?,?)", (op_id, block_id, "unban", "requested", actor, now, now))
            c.execute("UPDATE blocks SET desired_state = 'removed', operation_id = ? WHERE id = ?", (op_id, block_id))
            self.store.audit_in(c, actor, "unban.requested", b["target"], {"reason": reason, "block": block_id}, op_id)
        self.store.run(create)
        self._attempt(op_id)
        return self.get_operation(op_id)

    # ------------------------------------------------------------- applying
    def _attempt(self, op_id: str) -> None:
        op = self.get_operation(op_id)
        b = self.get_block(op["block_id"])
        attempt = op["attempts"] + 1
        self.store.run(lambda c: c.execute("UPDATE operations SET state='pending', attempts=?, next_retry_at=NULL, updated_at=? WHERE id=?", (attempt, time.time(), op_id)))
        try:
            caps = self._apply_ban(b, op_id) if op["kind"] == "ban" else self._apply_unban(b, op_id)
        except (BlockError, AgentUnavailable) as exc:
            self._failed_attempt(op, b, attempt, str(exc))
            return
        now = time.time()
        present = op["kind"] == "ban"

        def done(c):
            c.execute("UPDATE operations SET state='applied', error='', applied_at=?, updated_at=?, capabilities=? WHERE id=?", (now, now, json.dumps(caps), op_id))
            c.execute("UPDATE blocks SET actual_state=?, last_verified_at=? WHERE id=?", ("present" if present else "absent", now, b["id"]))
            self.store.audit_in(c, op["actor"], f"{op['kind']}.applied", b["target"], {"secs": round(now - op["created_at"], 3), "capabilities": caps}, op_id)
        self.store.run(done)
        if caps:
            self.store.set_setting("capabilities", {**(self.store.setting("capabilities") or {}), **caps})

    def _failed_attempt(self, op: dict, b: dict, attempt: int, error: str) -> None:
        now = time.time()
        if attempt <= len(RETRY_DELAYS):
            retry = now + RETRY_DELAYS[attempt - 1]
            self.store.run(lambda c: c.execute("UPDATE operations SET state='pending', next_retry_at=?, error=?, updated_at=? WHERE id=?", (retry, error[:500], now, op["id"])))
            return

        def fail(c):
            c.execute("UPDATE operations SET state='failed', next_retry_at=NULL, error=?, updated_at=? WHERE id=?", (error[:500], now, op["id"]))
            if op["kind"] == "ban":  # the ban never took effect, so it doesn't stay "active"
                c.execute("UPDATE blocks SET desired_state='failed' WHERE id=?", (b["id"],))
            else:  # the address is still banned: say so, and let the operator try again
                c.execute("UPDATE blocks SET desired_state='active', actual_state='present' WHERE id=?", (b["id"],))
            self.store.audit_in(c, op["actor"], f"{op['kind']}.failed", b["target"], {"error": error[:500], "attempts": attempt}, op["id"])
        self.store.run(fail)

    def _in_set(self, target: str, op_id: str) -> bool:
        n = net(target)
        r = self.adapter.call("nft_list", {"family": n.version}, op_id)
        if not r["ok"]:
            raise BlockError(f"Could not read the ban set back: {r['error']}")
        return any(str(net(e["element"])) == str(n) for e in r["elements"])

    def _apply_ban(self, b: dict, op_id: str) -> dict:
        ready = self.adapter.call("nft_ensure", {}, op_id)
        if not ready["ok"]:
            raise BlockError(f"nftables is unavailable: {ready.get('error')}")
        ttl = None
        if b["expires_at"]:
            left = b["expires_at"] - time.time()
            if left <= 0:
                raise BlockError("The ban's time ran out before it could be applied")
            ttl = math.ceil(left)
        r = self.adapter.call("nft_add", {"target": b["target"], "ttl": ttl}, op_id)
        if not r["ok"]:
            raise BlockError(f"nft refused the ban: {r['error']}")
        if not self._in_set(b["target"], op_id):
            raise BlockError("The address isn't in the ban set after writing it")
        ct = self.adapter.call("conntrack_kill", {"target": b["target"]}, op_id)
        ss = self.adapter.call("ss_kill", {"target": b["target"]}, op_id)
        return {"conntrack": bool(ct.get("available")), "ss_kill": bool(ss.get("available"))}

    def _apply_unban(self, b: dict, op_id: str) -> dict:
        r = self.adapter.call("nft_del", {"target": b["target"]}, op_id)
        if not r["ok"]:
            raise BlockError(f"nft refused to remove the ban: {r['error']}")
        if self._in_set(b["target"], op_id):
            raise BlockError("The address is still in the ban set after removing it")
        return {}

    # ------------------------------------------------------------- the background pass
    def tick(self) -> dict:
        self.replay_journal()
        now = time.time()
        due = self.store.read(lambda c: c.execute("SELECT id FROM operations WHERE state = 'pending' AND next_retry_at IS NOT NULL AND next_retry_at <= ?", (now,)).fetchall())
        for r in due:
            self._attempt(r["id"])
        return {"retried": len(due), **self.reconcile()}

    def reconcile(self) -> dict:
        """Compare the records with the sets: mark what expired, put back what vanished (a reboot empties nft)."""
        elements = self._set_elements()
        rows = [dict(r) for r in self.store.read(lambda c: c.execute("SELECT * FROM blocks WHERE source = 'ella' AND desired_state = 'active' AND actual_state = 'present'").fetchall())]
        if elements is None:
            if rows:  # the table itself may be what's gone, as after a reboot
                self.adapter.call("nft_ensure")
                elements = self._set_elements()
            if elements is None:
                return {"expired": 0, "restored": 0, "external": [], "unreadable": True}
        now, expired, restored = time.time(), 0, 0
        known = {r["target"] for r in rows}
        for b in rows:
            there = b["target"] in elements
            if b["expires_at"] and b["expires_at"] <= now and not there:
                def finish(c, b=b):
                    c.execute("UPDATE blocks SET desired_state='expired', actual_state='absent', last_verified_at=? WHERE id=?", (now, b["id"]))
                    c.execute("UPDATE operations SET state='expired', updated_at=? WHERE id=?", (now, b["operation_id"]))
                    self.store.audit_in(c, "system", "ban.expired", b["target"], {"block": b["id"]}, b["operation_id"] or "")
                self.store.run(finish)
                expired += 1
            elif there:
                self.store.run(lambda c, b=b: c.execute("UPDATE blocks SET last_verified_at=? WHERE id=?", (now, b["id"])))
            elif not b["expires_at"] or b["expires_at"] > now + 1:
                ttl = math.ceil(b["expires_at"] - now) if b["expires_at"] else None
                self.adapter.call("nft_ensure")
                ok = self.adapter.call("nft_add", {"target": b["target"], "ttl": ttl})["ok"]
                self.store.audit("system", "ban.restored" if ok else "ban.restore_failed", b["target"], {"block": b["id"], "ttl": ttl}, b["operation_id"] or "")
                restored += int(ok)
        external = sorted(t for t in elements if t not in known and not self._pending(t))
        return {"expired": expired, "restored": restored, "external": external, "unreadable": False}

    def _pending(self, target: str) -> bool:
        r = self.store.read(lambda c: c.execute("SELECT 1 FROM blocks WHERE source='ella' AND target=? AND desired_state='active' LIMIT 1", (target,)).fetchone())
        return bool(r)

    # ------------------------------------------------------------- ella-cli leaves notes here when the panel is down
    def replay_journal(self) -> int:
        if not self.journal.exists():
            return 0
        work = self.journal.with_suffix(".replaying")
        try:
            if not work.exists():
                os.replace(self.journal, work)
            lines = work.read_text(encoding="utf-8").splitlines()
        except OSError:
            return 0
        for line in lines:
            try:
                e = json.loads(line)
            except ValueError:
                continue
            target = str(e.get("target", ""))

            def apply(c, e=e, target=target):
                if e.get("action") == "unban":
                    c.execute("UPDATE blocks SET desired_state='removed', actual_state='absent', last_verified_at=? WHERE source='ella' AND target=? AND desired_state='active'", (e.get("ts"), target))
                self.store.audit_in(c, f"cli:{e.get('user', '?')}", f"cli.{e.get('action', '?')}", target, {k: v for k, v in e.items() if k not in ("action", "target", "user")})
            self.store.run(apply)
        work.unlink(missing_ok=True)
        return len(lines)
