"""ella-cli: emergency access on the server itself. Needs neither the panel nor the database.

  ella-cli status
  ella-cli unban <ip>
  ella-cli bypass --minutes N [--cidr X ...]   (default: the management ranges)
  ella-cli waf detect-only
  ella-cli rollback
  ella-cli restore      (run at boot: put recorded bans back into nftables)

Changes go straight to nftables or Apache. A note goes in a journal first, which the panel replays when it next
runs, so it can't put a lifted ban back and the audit chain still gets the record.
"""
from __future__ import annotations

import argparse
import getpass
import json
import os
import re
import sqlite3
import sys
import time
from pathlib import Path

from .adapter import AdapterError, EllaSystemAdapter, net
from .configs import ConfigError, ConfigManager, health

WAF_PRE = "/etc/modsecurity/zz-aurora-waf.conf"
WAF_STATE = Path("/var/lib/aurora/waf.json")


def ella_dir() -> Path:
    return Path(os.environ.get("AURORA_ELLA_DIR", "/var/lib/aurora/ella"))


def _adapter() -> EllaSystemAdapter:
    return EllaSystemAdapter(ella_dir() / "adapter.log")


def _journal(action: str, target: str, **extra) -> None:
    ella_dir().mkdir(parents=True, exist_ok=True)
    with (ella_dir() / "cli-journal.jsonl").open("a", encoding="utf-8") as f:
        f.write(json.dumps({"ts": time.time(), "action": action, "target": target, "user": getpass.getuser(), **extra}) + "\n")


def _management_cidrs() -> list[str]:
    """From the database when it opens. Without it the operator names the ranges with --cidr."""
    try:
        c = sqlite3.connect(f"file:{ella_dir() / 'ella.db'}?mode=ro", uri=True, timeout=2)
        row = c.execute("SELECT value FROM settings WHERE key = 'management_cidrs'").fetchone()
        c.close()
        return json.loads(row[0]) if row else []
    except (sqlite3.Error, ValueError):
        return []


def cmd_status(_args, a: EllaSystemAdapter) -> int:
    for family in (4, 6):
        r = a.call("nft_list", {"family": family})
        print(f"ella{family}: " + (f"{len(r['elements'])} banned" if r["ok"] else f"unreadable ({r['error'].strip()[:120]})"))
        for e in r["elements"][:50]:
            print(f"  {e['element']}" + (f"  expires in {e['expires']}s" if e["expires"] else ""))
    for name in ("f2b4", "f2b6", "ban4", "ban6"):
        r = a.call("guard_list", {"name": name})
        print(f"guard {name}: " + (f"{len(r['elements'])}" if r["ok"] else "not available"))
    st = a.call("service_active")
    alive, detail = health()
    print(f"{st['unit']}: {'active' if st['active'] else 'NOT active'}, local answer: {detail if alive else 'FAILED ' + detail}")
    pre = Path(WAF_PRE)
    if pre.exists():
        m = re.search(r"(?m)^SecRuleEngine\s+(\S+)", pre.read_text(errors="replace"))
        print(f"WAF engine: {m.group(1) if m else 'unknown'}")
    print(f"database: {'readable' if _management_cidrs() is not None and (ella_dir() / 'ella.db').exists() else 'not available'}")
    return 0


def cmd_unban(args, a: EllaSystemAdapter) -> int:
    try:
        n = net(args.ip)
    except AdapterError as exc:
        print(exc, file=sys.stderr)
        return 2
    _journal("unban", str(n))  # first, so the panel can't restore it in the moment between
    r = a.call("nft_del", {"target": str(n)})
    if not r["ok"]:
        print(f"Failed: {r['error']}", file=sys.stderr)
        return 1
    print(f"{n}: not in Ella's ban set any more" + (" (it wasn't there)" if r.get("absent_before") else ""))
    print("Bans from fail2ban and the IP Blocker on this address, if any, are separate and still stand.")
    return 0


def cmd_bypass(args, a: EllaSystemAdapter) -> int:
    cidrs = args.cidr or _management_cidrs()
    if not cidrs:
        print("No management ranges are set (or the database can't be read). Name one with --cidr.", file=sys.stderr)
        return 2
    code = 0
    for c in cidrs:
        try:
            r = a.call("bypass", {"target": c, "minutes": args.minutes})
        except AdapterError as exc:
            print(exc, file=sys.stderr)
            code = 2
            continue
        print(f"{c}: {'past every ban' if r['ok'] else 'FAILED ' + r['error']} for {args.minutes} min" + ("" if r["guard"] else " (Ella's bans only, guard table not found)"))
        code = code or (0 if r["ok"] else 1)
        _journal("bypass", str(c), minutes=args.minutes)
    return code


def _managers(a: EllaSystemAdapter) -> ConfigManager:
    return ConfigManager(a, ella_dir() / "snapshots", audit=lambda actor, action, target, detail=None: _journal(action, target, **(detail or {})))


def cmd_waf(args, a: EllaSystemAdapter) -> int:
    pre = Path(WAF_PRE)
    if args.mode != "detect-only" or not pre.exists():
        print("Only `waf detect-only` is available, and it needs the WAF to be installed.", file=sys.stderr)
        return 2
    text = re.sub(r"(?m)^SecRuleEngine\s+\S+", "SecRuleEngine DetectionOnly", pre.read_text(encoding="utf-8"))
    try:
        _managers(a).apply(WAF_PRE, text, f"cli:{getpass.getuser()}", watch_seconds=None)
    except ConfigError as exc:
        print(exc, file=sys.stderr)
        return 1
    try:  # the panel rewrites this file from its state, so the state has to agree
        state = json.loads(WAF_STATE.read_text(encoding="utf-8"))
        state["mode"] = "detect"
        WAF_STATE.write_text(json.dumps(state), encoding="utf-8")
    except (OSError, ValueError) as exc:
        print(f"Note: the panel's WAF setting wasn't updated ({exc}), it may switch back on its next save", file=sys.stderr)
    print("WAF is in detection-only mode: it logs attacks and blocks nothing.")
    return 0


ENGINE_TO_MODE = {"On": "block", "DetectionOnly": "detect", "Off": "off"}


def _sync_waf_mode() -> None:
    """The panel rewrites the WAF file from its own state, so after a rollback the state has to say the same."""
    m = re.search(r"(?m)^SecRuleEngine\s+(\S+)", Path(WAF_PRE).read_text(encoding="utf-8"))
    mode = ENGINE_TO_MODE.get(m.group(1)) if m else None
    if not mode:
        return
    try:
        state = json.loads(WAF_STATE.read_text(encoding="utf-8"))
        state["mode"] = mode
        WAF_STATE.write_text(json.dumps(state), encoding="utf-8")
    except (OSError, ValueError) as exc:
        print(f"Note: the panel's WAF setting wasn't updated ({exc})", file=sys.stderr)


def cmd_restore(_args, a: EllaSystemAdapter) -> int:
    """Firewall tables don't survive a reboot. Runs before the network is up, so bans hold from the first packet."""
    ready = a.call("nft_ensure")
    if not ready["ok"]:
        print(f"nftables unavailable: {ready.get('error')}", file=sys.stderr)
        return 1
    try:
        c = sqlite3.connect(f"file:{ella_dir() / 'ella.db'}?mode=ro", uri=True, timeout=5)
        rows = c.execute("SELECT target, expires_at FROM blocks WHERE source = 'ella' AND desired_state = 'active' AND actual_state = 'present'").fetchall()
        c.close()
    except sqlite3.Error as exc:
        print(f"No bans restored, the database can't be read: {exc}. The table is up, empty.", file=sys.stderr)
        return 0  # no bans is better than a failed boot unit; the panel tries again when it starts
    now, restored, failed, expired = time.time(), 0, 0, 0
    for target, expires_at in rows:
        if expires_at and expires_at <= now:
            expired += 1  # the panel's worker records it
            continue
        ttl = max(1, int(expires_at - now)) if expires_at else None
        if a.call("nft_add", {"target": target, "ttl": ttl})["ok"]:
            restored += 1
        else:
            failed += 1
    print(f"restored {restored}, failed {failed}, already expired {expired}")
    return 1 if failed else 0


def cmd_rollback(args, a: EllaSystemAdapter) -> int:
    m = _managers(a)
    d = ella_dir() / "snapshots"
    newest = sorted(d.glob("*/*.json"), key=lambda p: p.name, reverse=True) if d.exists() else []
    for f in newest:
        try:
            path = json.loads(f.read_text(encoding="utf-8"))["path"]
            r = m.rollback(path, f"cli:{getpass.getuser()}")
            if path == WAF_PRE:
                _sync_waf_mode()
            print(f"{path}: back to the version from {time.ctime(r['from'])}")
            return 0
        except (ConfigError, ValueError, KeyError, OSError) as exc:
            print(f"{f.parent.name}: {exc}", file=sys.stderr)
    print("Nothing to roll back to.", file=sys.stderr)
    return 1


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="ella-cli", description="WAF Ella emergency access. Works without the panel and the database.")
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("status").set_defaults(fn=cmd_status)
    u = sub.add_parser("unban")
    u.add_argument("ip")
    u.set_defaults(fn=cmd_unban)
    b = sub.add_parser("bypass")
    b.add_argument("--minutes", type=int, required=True)
    b.add_argument("--cidr", action="append")
    b.set_defaults(fn=cmd_bypass)
    w = sub.add_parser("waf")
    w.add_argument("mode", choices=["detect-only"])
    w.set_defaults(fn=cmd_waf)
    sub.add_parser("rollback").set_defaults(fn=cmd_rollback)
    sub.add_parser("restore").set_defaults(fn=cmd_restore)
    args = p.parse_args(argv)
    return args.fn(args, _adapter())


if __name__ == "__main__":
    sys.exit(main())
