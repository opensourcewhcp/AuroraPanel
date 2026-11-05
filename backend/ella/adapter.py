"""EllaSystemAdapter: the only door from WAF Ella to system commands.

Every operation has a fixed name, takes and returns JSON-compatible data only, validates its arguments and
runs one allowlisted program with shell=False, a timeout and capped output. That shape lets the adapter
move behind a Unix socket later without changing its callers. Standard library only: ella-cli needs it
when the panel and its virtualenv are down.
"""
from __future__ import annotations

import ipaddress
import json
import os
import re
import shutil
import subprocess
import time
from pathlib import Path

BASE_PATH = "/usr/sbin:/usr/bin:/sbin:/bin"  # never the Fedora compatibility folder
PROGRAMS = {"nft", "conntrack", "ss", "systemctl", "httpd", "apache2ctl", "systemd-run"}
UNITS = {"httpd", "apache2", "nginx", "fail2ban", "aurorapanel"}
GUARD_SETS = {"ban4", "ban6", "f2b4", "f2b6", "trust4", "trust6"}
TABLE = ("inet", "aurora_ella")
MAX_OUTPUT = 1_000_000
MAX_TTL = 10 * 365 * 86400
LOG_MAX = 5_000_000

TABLE_TEXT = """table inet aurora_ella {
  set ella4 { type ipv4_addr; flags interval, timeout; }
  set ella6 { type ipv6_addr; flags interval, timeout; }
  set bypass4 { type ipv4_addr; flags interval, timeout; }
  set bypass6 { type ipv6_addr; flags interval, timeout; }
  chain ella_input {
    type filter hook input priority -25; policy accept;
    iifname "lo" return
    ip saddr @bypass4 return
    ip6 saddr @bypass6 return
    ip saddr @ella4 drop
    ip6 saddr @ella6 drop
  }
  chain ella_forward {
    type filter hook forward priority -25; policy accept;
    ip saddr @bypass4 return
    ip6 saddr @bypass6 return
    ip saddr @ella4 drop
    ip6 saddr @ella6 drop
  }
}
"""


class AdapterError(ValueError):
    """The arguments were refused before anything ran."""


def net(value) -> ipaddress.IPv4Network | ipaddress.IPv6Network:
    try:
        return ipaddress.ip_network(str(value).strip(), strict=False)
    except ValueError as exc:
        raise AdapterError(f"Not an IP address or CIDR range: {value!r}") from exc


def _elem(n) -> str:
    return str(n.network_address) if n.num_addresses == 1 else str(n)


def _ttl(value) -> int | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= MAX_TTL:
        raise AdapterError(f"Bad TTL: {value!r}")
    return value


class EllaSystemAdapter:
    def __init__(self, log_path: Path | str | None = None):
        self.log_path = Path(log_path) if log_path else None

    # ------------------------------------------------------------- the one entry point
    def call(self, op: str, args: dict | None = None, operation_id: str = "") -> dict:
        fn = getattr(self, f"op_{op}", None) if re.fullmatch(r"[a-z_]+", op or "") else None
        if fn is None:
            raise AdapterError(f"Unknown operation: {op!r}")
        return fn(operation_id=operation_id, **(args or {}))

    # ------------------------------------------------------------- running one program
    def _exec(self, op: str, operation_id: str, argv: list[str], stdin: str | None = None, timeout: int = 30) -> dict:
        if argv[0] not in PROGRAMS:
            raise AdapterError(f"Program not allowed: {argv[0]}")
        exe = shutil.which(argv[0], path=BASE_PATH)
        t0 = time.time()
        if not exe:
            res = {"ok": False, "rc": 127, "stdout": "", "stderr": f"{argv[0]} is not installed", "missing": True}
        else:
            try:
                p = subprocess.run([exe, *argv[1:]], input=stdin, capture_output=True, text=True, shell=False, timeout=timeout,
                                   env={"PATH": BASE_PATH, "LC_ALL": "C"})
                res = {"ok": p.returncode == 0, "rc": p.returncode, "stdout": p.stdout[:MAX_OUTPUT], "stderr": p.stderr[-4000:]}
            except subprocess.TimeoutExpired:
                res = {"ok": False, "rc": 124, "stdout": "", "stderr": f"{argv[0]} timed out after {timeout}s"}
            except OSError as exc:
                res = {"ok": False, "rc": 126, "stdout": "", "stderr": str(exc)}
        self._log(op, operation_id, argv, res, time.time() - t0)
        return res

    def _log(self, op: str, operation_id: str, argv: list[str], res: dict, secs: float) -> None:
        if not self.log_path:
            return
        try:
            self.log_path.parent.mkdir(parents=True, exist_ok=True)
            if self.log_path.exists() and self.log_path.stat().st_size > LOG_MAX:
                os.replace(self.log_path, self.log_path.with_suffix(".log.1"))
            with self.log_path.open("a", encoding="utf-8") as f:
                f.write(json.dumps({"ts": round(time.time(), 3), "op": op, "operation_id": operation_id, "argv": argv, "rc": res["rc"],
                                    "secs": round(secs, 3), "stderr": res["stderr"][-300:]}) + "\n")
        except OSError:
            pass

    # ------------------------------------------------------------- nftables
    def op_nft_ensure(self, operation_id: str = "") -> dict:
        have = self._exec("nft_ensure", operation_id, ["nft", "list", "table", *TABLE])
        if have["ok"]:
            return {"ok": True, "created": False}
        if have.get("missing"):
            return {"ok": False, "error": have["stderr"]}
        made = self._exec("nft_ensure", operation_id, ["nft", "-f", "-"], stdin=TABLE_TEXT)
        return {"ok": made["ok"], "created": made["ok"], "error": made["stderr"][-400:]}

    def _set(self, n, kind: str = "ella") -> str:
        return f"{kind}{n.version}"

    def op_nft_add(self, target: str, ttl: int | None = None, operation_id: str = "") -> dict:
        n, ttl = net(target), _ttl(ttl)
        spec = _elem(n) + (f" timeout {ttl}s" if ttl else "")
        r = self._exec("nft_add", operation_id, ["nft", "add", "element", *TABLE, self._set(n), "{ " + spec + " }"])
        return {"ok": r["ok"], "error": r["stderr"][-400:]}

    def op_nft_del(self, target: str, operation_id: str = "") -> dict:
        n = net(target)
        r = self._exec("nft_del", operation_id, ["nft", "delete", "element", *TABLE, self._set(n), "{ " + _elem(n) + " }"])
        gone = not r["ok"] and re.search(r"No such file or directory|does not exist", r["stderr"]) is not None
        return {"ok": r["ok"] or gone, "absent_before": gone, "error": "" if r["ok"] or gone else r["stderr"][-400:]}

    def _list(self, op: str, operation_id: str, table: tuple[str, str], name: str) -> dict:
        r = self._exec(op, operation_id, ["nft", "-j", "list", "set", *table, name])
        if not r["ok"]:
            return {"ok": False, "elements": [], "error": r["stderr"][-400:]}
        out = []
        try:
            for item in json.loads(r["stdout"]).get("nftables", []):
                for e in (item.get("set") or {}).get("elem", []):
                    val, expires = e, None
                    if isinstance(e, dict) and "elem" in e:
                        val, expires = e["elem"].get("val"), e["elem"].get("expires")
                    if isinstance(val, dict) and "prefix" in val:
                        val = f"{val['prefix']['addr']}/{val['prefix']['len']}"
                    if isinstance(val, dict) and "range" in val:
                        val = "-".join(str(x) for x in val["range"])
                    out.append({"element": str(val), "expires": expires})
        except (ValueError, AttributeError, TypeError) as exc:
            return {"ok": False, "elements": [], "error": f"Unreadable nft output: {exc}"}
        return {"ok": True, "elements": out, "error": ""}

    def op_nft_list(self, family: int, operation_id: str = "") -> dict:
        if family not in (4, 6):
            raise AdapterError("family must be 4 or 6")
        return self._list("nft_list", operation_id, TABLE, f"ella{family}")

    def op_guard_list(self, name: str, operation_id: str = "") -> dict:
        """Read-only look at the panel's existing guard table (fail2ban's and manual bans)."""
        if name not in GUARD_SETS:
            raise AdapterError(f"Unknown guard set: {name!r}")
        return self._list("guard_list", operation_id, ("inet", "aurora_guard"), name)

    def op_bypass(self, target: str, minutes: int, operation_id: str = "") -> dict:
        """Let a range past every ban for a while: Ella's own set expires by itself; guard's trust set has no
        timeouts, so a one-shot systemd timer takes the entry out again, panel or no panel."""
        n = net(target)
        if isinstance(minutes, bool) or not isinstance(minutes, int) or not 1 <= minutes <= 1440:
            raise AdapterError("minutes must be between 1 and 1440")
        el = _elem(n)
        self.op_nft_ensure(operation_id)
        r = self._exec("bypass", operation_id, ["nft", "add", "element", *TABLE, self._set(n, "bypass"), "{ " + el + f" timeout {minutes}m" + " }"])
        guard = self._exec("bypass", operation_id, ["nft", "add", "element", "inet", "aurora_guard", f"trust{n.version}", "{ " + el + " }"])
        timer = None
        if guard["ok"]:
            nft = shutil.which("nft", path=BASE_PATH) or "/usr/sbin/nft"
            timer = self._exec("bypass", operation_id, ["systemd-run", "--quiet", "--collect", f"--on-active={minutes}m", nft, "delete", "element",
                                                        "inet", "aurora_guard", f"trust{n.version}", "{ " + el + " }"])
        return {"ok": r["ok"], "guard": guard["ok"], "guard_timer": bool(timer and timer["ok"]), "error": r["stderr"][-400:]}

    # ------------------------------------------------------------- cutting live connections
    def op_conntrack_kill(self, target: str, operation_id: str = "") -> dict:
        ip = str(net(target))
        results = [self._exec("conntrack_kill", operation_id, ["conntrack", "-D", flag, ip]) for flag in ("-s", "-d")]
        if any(r.get("missing") for r in results):
            return {"available": False, "ok": True, "note": "conntrack is not installed"}
        return {"available": True, "ok": True}  # "0 flow entries" exits non-zero and isn't a failure

    def op_ss_kill(self, target: str, operation_id: str = "") -> dict:
        ip = str(net(target))
        r = self._exec("ss_kill", operation_id, ["ss", "-K", "dst", ip])
        unsupported = "Operation not supported" in r["stderr"] or "not supported" in r["stderr"].lower()
        if r.get("missing"):
            return {"available": False, "ok": True, "note": "ss is not installed"}
        return {"available": not unsupported, "ok": True, "note": "kernel lacks CONFIG_INET_DIAG_DESTROY" if unsupported else ""}

    # ------------------------------------------------------------- Apache
    @staticmethod
    def _apache() -> tuple[list[str], str]:
        if shutil.which("httpd", path=BASE_PATH):
            return ["httpd", "-t"], "httpd"
        return ["apache2ctl", "-t"], "apache2"

    def op_apache_test(self, operation_id: str = "") -> dict:
        r = self._exec("apache_test", operation_id, self._apache()[0], timeout=60)
        return {"ok": r["ok"], "output": (r["stderr"] or r["stdout"])[-1500:]}

    def op_apache_reload(self, operation_id: str = "") -> dict:
        r = self._exec("apache_reload", operation_id, ["systemctl", "reload", self._apache()[1]], timeout=90)
        return {"ok": r["ok"], "error": r["stderr"][-400:]}

    def op_service_active(self, unit: str = "", operation_id: str = "") -> dict:
        unit = unit or self._apache()[1]
        if unit not in UNITS:
            raise AdapterError(f"Unknown unit: {unit!r}")
        r = self._exec("service_active", operation_id, ["systemctl", "is-active", unit], timeout=15)
        return {"ok": True, "active": r["stdout"].strip() == "active", "unit": unit}
