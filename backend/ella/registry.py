"""One list of every ban on the server, whoever made it, compared with what the firewall really holds.

WAF Ella's own bans are records it controls. Fail2ban's, the IP Blocker's (guard), ufw's and firewalld's are mirrored
here from their real state, each under its own source, so one address can have several independent entries. Lifting
one lifts only that one. ufw and firewalld are read-only here.
"""
from __future__ import annotations

import ast
import ipaddress
import json
import re
import time
import uuid

from .adapter import AdapterError, net
from .blocks import BlockError, Engine, SafetyLocked

READ_ONLY = {"ufw", "firewalld"}
JAIL = re.compile(r"^[A-Za-z0-9._-]{1,64}$")


def _norm(target: str) -> str | None:
    try:
        return str(net(target))
    except AdapterError:
        return None


def _is_ip(text: str) -> bool:
    try:
        ipaddress.ip_network(text, strict=False)
        return True
    except ValueError:
        return False


class Registry:
    def __init__(self, engine: Engine, guard_module=None, firewall_module=None, fail2ban_module=None):
        self.engine, self.store, self.adapter = engine, engine.store, engine.adapter
        self._guard, self._firewall, self._fail2ban = guard_module, firewall_module, fail2ban_module

    # Imported late: they pull in much of the panel, and ella-cli must not depend on them.
    @property
    def guard(self):
        if self._guard is None:
            from .. import guard
            self._guard = guard
        return self._guard

    @property
    def firewall(self):
        if self._firewall is None:
            from .. import firewall
            self._firewall = firewall
        return self._firewall

    @property
    def fail2ban(self):
        if self._fail2ban is None:
            from .. import fail2ban
            self._fail2ban = fail2ban
        return self._fail2ban

    # ------------------------------------------------------------- what is really there
    def _guard_sets(self) -> dict:
        """set name -> {cidr: element}, or None for a set that can't be read (no guard table yet)."""
        out = {}
        for name in ("ban4", "ban6", "f2b4", "f2b6"):
            r = self.adapter.call("guard_list", {"name": name})
            out[name] = {str(net(e["element"])): e for e in r["elements"]} if r["ok"] else None
        return out

    def _jails(self) -> dict | None:
        """jail -> [addresses], or None when fail2ban isn't answering."""
        r = self.adapter.call("f2b_banned")
        if not r["ok"]:
            return None
        return r["jails"]

    def _ufw_rules(self) -> list[dict]:
        r = self.adapter.call("ufw_status")
        out = []
        if r.get("installed") and r.get("active"):
            for line in r["output"].splitlines():
                m = re.match(r"^\[\s*\d+\]\s+.*?\b(DENY|REJECT)\s+IN\s+(\S+)", line.strip())
                if m and _is_ip(m.group(2)):
                    out.append({"source": "ufw", "target": _norm(m.group(2)), "backend": "ufw", "owner": "ufw", "reason": re.sub(r"\s+", " ", line.strip())[:200]})
        return out

    def _firewalld_rules(self) -> list[dict]:
        out = []
        try:
            if not self.firewall._firewalld():
                return out
            for r in self.firewall.status().get("rules", []):
                m = re.match(r"^Anywhere DENY IN (\S+)$", r["rule"])
                if m and _is_ip(m.group(1)):
                    out.append({"source": "firewalld", "target": _norm(m.group(1)), "backend": "firewalld", "owner": "firewalld", "reason": r["rule"]})
        except Exception:  # noqa: BLE001  one backend failing must not stop the others being listed
            pass
        return out

    def actual(self) -> dict:
        """Everything outside Ella's own records, plus what each backend says, and which backends could be read."""
        sets, jails = self._guard_sets(), self._jails()
        rows: list[dict] = []
        now = time.time()
        state = self._guard_state()
        for b in state:
            cidr = _norm(b.get("cidr", ""))
            if cidr:
                family = "6" if ":" in cidr else "4"
                live = (sets.get(f"ban{family}") or {}).get(cidr)
                rows.append({"source": "guard", "target": cidr, "backend": "nft-set", "owner": b.get("source") or "IP Blocker", "reason": b.get("reason", ""),
                             "expires_at": b.get("expires"), "present": live is not None})
        for jail, ips in (jails or {}).items():
            for ip in ips:
                cidr = _norm(ip)
                if not cidr:
                    continue
                family = "6" if ":" in cidr else "4"
                live = (sets.get(f"f2b{family}") or {}).get(cidr)
                expires = now + live["expires"] if live and live.get("expires") else None
                # A jail on fail2ban's own action has no entry in these sets, and that isn't a drift.
                rows.append({"source": f"fail2ban:{jail}", "target": cidr, "backend": "f2b-jail", "owner": jail, "reason": f"fail2ban jail {jail}", "expires_at": expires,
                             "present": live is not None})
        rows += [{**r, "expires_at": None, "present": True} for r in self._ufw_rules() + self._firewalld_rules()]
        return {"rows": rows, "sets": sets, "jails": jails, "state": state}

    def _guard_state(self) -> list[dict]:
        try:
            return list(self.guard._state().get("bans", []))
        except Exception:  # noqa: BLE001
            return []

    # ------------------------------------------------------------- mirroring into the blocks table
    def sync(self) -> dict:
        got = self.actual()
        seen = {(r["source"], r["target"]) for r in got["rows"]}
        now = time.time()
        readable = {"guard": True, "ufw": True, "firewalld": True, "fail2ban": got["jails"] is not None}

        def write(c):
            added = ended = 0
            for r in got["rows"]:
                old = c.execute("SELECT id FROM blocks WHERE source=? AND target=? AND desired_state='active'", (r["source"], r["target"])).fetchone()
                actual = "present" if r["present"] else "missing"
                if old:
                    c.execute("UPDATE blocks SET actual_state=?, last_verified_at=?, expires_at=?, reason=? WHERE id=?", (actual, now, r.get("expires_at"), r["reason"][:500], old["id"]))
                else:
                    c.execute("INSERT INTO blocks(id, source, owner, scope, backend, target, reason, created_at, expires_at, desired_state, actual_state, last_verified_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                              (uuid.uuid4().hex, r["source"], r["owner"][:64], "server", r["backend"], r["target"], r["reason"][:500], now, r.get("expires_at"), "active", actual, now))
                    self.store.audit_in(c, "system", "block.seen", r["target"], {"source": r["source"], "reason": r["reason"][:200]})
                    added += 1
            for row in c.execute("SELECT id, source, target FROM blocks WHERE source != 'ella' AND desired_state='active'").fetchall():
                family = row["source"].split(":")[0]
                if (row["source"], row["target"]) not in seen and readable.get(family, True):
                    c.execute("UPDATE blocks SET desired_state='ended', actual_state='absent', last_verified_at=? WHERE id=?", (now, row["id"]))
                    self.store.audit_in(c, "system", "block.ended", row["target"], {"source": row["source"]})
                    ended += 1
            return added, ended
        added, ended = self.store.run(write)
        drift = self.drift(got)
        known = {(d["backend"], d["target"], d["kind"]) for d in (self.store.setting("drift") or [])}
        for d in drift:
            if (d["backend"], d["target"], d["kind"]) not in known:
                self.store.audit("system", "drift.found", d["target"], d)
        self.store.set_setting("drift", drift)
        self.store.set_setting("drift_checked", now)
        return {"added": added, "ended": ended, "drift": len(drift)}

    # ------------------------------------------------------------- drift
    def drift(self, got: dict | None = None) -> list[dict]:
        """external: in a set with no record behind it. missing: a record says yes, the firewall says no."""
        got = got or self.actual()
        out = []
        ella = self.engine._set_elements()
        if ella is not None:
            records = {r["target"] for r in self.engine.list_blocks() if r["source"] == "ella"}
            out += [{"backend": "ella", "target": t, "kind": "external", "detail": "In WAF Ella's ban set, with no record behind it", "actions": ["accept", "remove"]} for t in sorted(set(ella) - records)]
        sets = got["sets"]
        guard_live = {**(sets.get("ban4") or {}), **(sets.get("ban6") or {})}
        guard_known = {_norm(b.get("cidr", "")) for b in got["state"]}
        now = time.time()
        if sets.get("ban4") is not None:
            out += [{"backend": "guard", "target": t, "kind": "external", "detail": "In the IP Blocker's set, but not on its list", "actions": ["accept", "remove"]} for t in sorted(set(guard_live) - guard_known)]
            for b in got["state"]:
                cidr = _norm(b.get("cidr", ""))
                if cidr and cidr not in guard_live and (not b.get("expires") or b["expires"] > now + 2):
                    out.append({"backend": "guard", "target": cidr, "kind": "missing", "detail": "On the IP Blocker's list, but not in the firewall", "actions": ["restore", "remove"]})
        if sets.get("f2b4") is not None and got["jails"] is not None:
            f2b_live = {**(sets.get("f2b4") or {}), **(sets.get("f2b6") or {})}
            banned = {_norm(ip) for ips in got["jails"].values() for ip in ips}
            out += [{"backend": "fail2ban", "target": t, "kind": "external", "detail": "In fail2ban's set, but no jail lists it", "actions": ["remove"]} for t in sorted(set(f2b_live) - banned)]
        return out

    def resolve(self, backend: str, target: str, action: str, actor: str, operator_ip: str | None = None) -> dict:
        cidr = _norm(target)
        if not cidr:
            raise BlockError("Not an IP address or range")
        match = next((d for d in self.drift() if d["backend"] == backend and d["target"] == cidr and action in d["actions"]), None)
        if not match:
            raise BlockError("That difference isn't there any more, or this action doesn't apply to it")
        if backend == "ella" and action == "accept":
            now = time.time()

            def adopt(c):
                c.execute("INSERT INTO blocks(id, source, owner, scope, backend, target, reason, created_at, desired_state, actual_state, last_verified_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                          (uuid.uuid4().hex, "ella", actor, "server", "nft-set", cidr, "Added outside WAF Ella, then accepted", now, "active", "present", now))
                self.store.audit_in(c, actor, "drift.accepted", cidr, {"backend": backend})
            self.store.run(adopt)
        elif backend == "ella" and action == "remove":
            r = self.adapter.call("nft_del", {"target": cidr})
            if not r["ok"]:
                raise BlockError(r["error"])
            self.store.audit(actor, "drift.removed", cidr, {"backend": backend})
        elif backend == "guard" and action in ("accept", "restore"):
            self.guard.ban(cidr, "Accepted from outside the panel" if action == "accept" else "Restored by WAF Ella", None, operator_ip, "WAF Ella")
            self.store.audit(actor, f"drift.{action}ed" if action == "restore" else "drift.accepted", cidr, {"backend": backend})
        elif backend == "guard" and action == "remove":
            if match["kind"] == "external":
                r = self.adapter.call("guard_del", {"name": f"ban{net(cidr).version}", "target": cidr})
                if not r["ok"]:
                    raise BlockError(r["error"])
            else:
                self.guard.unban(cidr, include_fail2ban=False)
            self.store.audit(actor, "drift.removed", cidr, {"backend": backend})
        elif backend == "fail2ban" and action == "remove":
            r = self.adapter.call("guard_del", {"name": f"f2b{net(cidr).version}", "target": cidr})
            if not r["ok"]:
                raise BlockError(r["error"])
            self.store.audit(actor, "drift.removed", cidr, {"backend": backend})
        else:
            raise BlockError("That action isn't available here")
        return self.sync()

    # ------------------------------------------------------------- lifting one entry
    def unban(self, block_id: str, actor: str, reason: str = "") -> dict:
        b = self.engine.get_block(block_id)
        if not b:
            raise BlockError("No such ban")
        if b["desired_state"] != "active":
            raise BlockError(f"This ban is already {b['desired_state']}")
        source = b["source"]
        if source == "ella":
            return self.engine.unban(block_id, actor, reason)
        if source.split(":")[0] in READ_ONLY:
            raise BlockError(f"{source} is shown here read-only. Change it with its own tool.")
        target = b["target"]
        n = net(target)
        if source == "guard":
            self.guard.unban(target, include_fail2ban=False)
            gone = target not in {str(net(e["element"])) for e in self.adapter.call("guard_list", {"name": f"ban{n.version}"})["elements"]}
        elif source.startswith("fail2ban:"):
            jail = source.split(":", 1)[1]
            r = self.adapter.call("f2b_unban", {"jail": jail, "ip": str(n.network_address)})
            if not r["ok"]:
                raise BlockError(f"fail2ban refused: {r['error']}")
            after = self._jails() or {}
            gone = str(n.network_address) not in after.get(jail, [])
        else:
            raise BlockError(f"Unknown source: {source}")
        if not gone:
            raise BlockError("It's still there after trying to lift it")
        now = time.time()

        def done(c):
            c.execute("UPDATE blocks SET desired_state='removed', actual_state='absent', last_verified_at=? WHERE id=?", (now, block_id))
            self.store.audit_in(c, actor, "unban.applied", target, {"source": source, "reason": reason})
        self.store.run(done)
        return {"state": "applied", "source": source, "target": target}

    # ------------------------------------------------------------- fail2ban page
    def fail2ban_overview(self) -> dict:
        st = self.adapter.call("f2b_status")
        if st.get("missing"):
            return {"state": "not_installed", "jails": []}
        if not st["ok"]:
            return {"state": "stopped", "error": st["error"], "jails": []}
        jails = []
        for name in st["jails"]:
            j = self.adapter.call("f2b_jail", {"jail": name})
            actions = j.get("actions") or []
            jails.append({"name": name, **{k: j.get(k) for k in ("banned", "failed_now", "failed_total", "banned_total", "bantime", "findtime", "maxretry", "journal", "logpath", "actions")},
                          "uses_panel_sets": "aurora-guard" in actions})
        return {"state": "ok" if jails else "unconfigured", "jails": jails}

    def fail2ban_init(self, actor: str) -> dict:
        """The panel's default profile, for a server with no jails. Never touches a server that has some."""
        before = self.fail2ban_overview()
        if before["state"] == "not_installed":
            raise BlockError("fail2ban isn't installed")
        if before["jails"]:
            raise BlockError("This server already has jails, so its setup was left alone")
        self.fail2ban.enable_service(True)
        self.fail2ban.save(None, None)
        self.store.audit(actor, "fail2ban.initialized", "fail2ban", {})
        return self.fail2ban_overview()

    def fail2ban_ban(self, jail: str, ip: str, actor: str, operator_ip: str | None, force: bool = False) -> dict:
        n = net(ip)
        reasons, forceable = self.engine.safety_reasons(n, operator_ip)
        if reasons and not (force and forceable):
            self.store.audit(actor, "ban.refused", str(n), {"reasons": reasons, "jail": jail})
            raise SafetyLocked(reasons, forceable)
        r = self.adapter.call("f2b_ban", {"jail": jail, "ip": str(n.network_address)})
        if not r["ok"]:
            raise BlockError(f"fail2ban refused: {r['error']}")
        self.store.audit(actor, "ban.force" if reasons else "ban.applied", str(n), {"source": f"fail2ban:{jail}"})
        self.sync()
        return {"state": "applied", "jail": jail, "target": str(n)}


def parse_banned(text: str) -> dict:
    """`fail2ban-client banned` prints a Python list of one-key dicts: read it as data, never run it."""
    out: dict = {}
    try:
        for item in ast.literal_eval((text or "").strip() or "[]"):
            for jail, ips in item.items():
                if JAIL.match(str(jail)):
                    out[str(jail)] = [str(i) for i in ips]
    except (ValueError, SyntaxError, AttributeError):
        return {}
    return out


__all__ = ["Registry", "parse_banned", "json"]
