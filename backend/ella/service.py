"""Wires WAF Ella together inside the panel and runs its background worker."""
from __future__ import annotations

import os
import platform
import shutil
import threading
import time

from .. import problems
from . import housekeeping, leaks, rulebook, supply
from .adapter import BASE_PATH, EllaSystemAdapter
from .agentd import SOCKET, SocketAdapter
from .blocks import Engine
from .collector import Collector
from .correlate import Correlator
from .fleet import ControlPlane, Member
from .intel import Intel
from .notify import Alerts
from .proxies import Proxies
from .registry import Registry
from .configs import ConfigManager
from .db import Store, ella_dir
from .tester import Tester

COLLECT_SECONDS = 0.4  # how often logs are read; the batch of each pass is one transaction
ENFORCE_SECONDS = 5
REGISTRY_SECONDS = 30  # how often every ban list is compared with the firewall
SOC_SECONDS = 30  # correlation, alerts, export, a managed server's check-in
DAILY_SECONDS = 3600  # retention, list downloads and the like check hourly whether they're due
_lock = threading.Lock()
_parts: dict = {}


def parts() -> dict:
    with _lock:
        if not _parts:
            store = Store(ella_dir())
            inside = EllaSystemAdapter(store.dir / "adapter.log")
            adapter = SocketAdapter(SOCKET, fallback=inside, fail_mode=lambda: store.setting("fail_mode") or "open") if platform.system() == "Linux" else inside
            engine = Engine(store, adapter)
            alerts = Alerts(store)

            def critical(title, detail):
                problems.record(title, RuntimeError(detail), hint="See WAF Ella's audit log.")
                alerts.raise_alert("watchdog", f"watchdog:{title}", "CRITICAL", title, detail)
            configs = ConfigManager(adapter, store.dir / "snapshots", audit=store.audit, on_critical=critical)
            book = rulebook.RuleBook(store, configs)
            intel = Intel(store)
            _parts.update(store=store, adapter=adapter, engine=engine, registry=Registry(engine), collector=Collector(store, adapter=adapter, system=True), configs=configs, book=book, alerts=alerts, intel=intel,
                          tester=Tester(configs, rulebook._waf_servers), proxies=Proxies(store, configs, rulebook._waf_servers), correlator=Correlator(store, engine, alerts, intel), retention=housekeeping.Retention(store),
                          exporter=housekeeping.Exporter(store), control=ControlPlane(store, book, engine), member=Member(store, book, engine, adapter))
        return _parts


def configure(**overrides) -> None:
    """Tests put their own store or adapter here."""
    with _lock:
        _parts.clear()
        _parts.update(overrides)


def _guarded(name: str, hint: str, fn) -> None:
    try:
        fn()
    except Exception as exc:  # noqa: BLE001  the worker must outlive any one bad pass
        problems.record(name, exc, hint=hint)


def soc_pass(p: dict) -> None:
    """Everything that looks at what's been collected, or passes it on. One failing never stops the others."""
    _guarded("WAF Ella rules", "Rules with an end date and Under Attack may not switch off on time.", p["book"].tick)
    _guarded("WAF Ella correlation", "Credential stuffing and breach alerts aren't being raised.", p["correlator"].tick)
    _guarded("WAF Ella drift alert", "Differences from the firewall aren't being alerted on.", lambda: _drift_alert(p))
    _guarded("WAF Ella silent sources", "A log that stops being written won't raise an alert.", lambda: _silent_sources(p))
    _guarded("WAF Ella alerts", "Alerts aren't being sent. See Alerts in WAF Ella.", p["alerts"].tick)
    _guarded("WAF Ella export", "Events aren't reaching your SIEM.", p["exporter"].tick)
    _guarded("WAF Ella control panel", "This server isn't checking in, and keeps its last policy.", p["member"].tick)


def daily_pass(p: dict) -> None:
    _guarded("WAF Ella retention", "Old events aren't being removed.", p["retention"].tick)
    _guarded("WAF Ella audit anchor", "Today's audit anchor wasn't written.", p["retention"].anchor)
    _guarded("WAF Ella reputation lists", "Reputation lists may be out of date.", p["intel"].tick)
    _guarded("WAF Ella Cloudflare ranges", "Cloudflare's address list may be out of date.", p["proxies"].tick)
    _guarded("WAF Ella rule set check", "The Core Rule Set's files weren't checked.", lambda: _crs_check(p))
    _guarded("WAF Ella disk", "Disk space isn't being watched.", lambda: _disk(p))


def _drift_alert(p: dict) -> None:
    for d in p["store"].setting("drift") or []:
        p["alerts"].raise_alert("drift", f"drift:{d['backend']}:{d['target']}", "WARNING", f"{d['target']} differs from the firewall ({d['backend']})", d.get("detail", ""))
    failed = p["store"].read(lambda c: c.execute("SELECT o.id, b.target, o.error FROM operations o JOIN blocks b ON b.id = o.block_id WHERE o.state = 'failed' AND o.updated_at > ?", (time.time() - 3600,)).fetchall())
    for f in failed:
        p["alerts"].raise_alert("ban_failed", f"banfail:{f['id']}", "ERROR", f"A ban on {f['target']} couldn't be applied", f["error"])


def _silent_sources(p: dict) -> None:
    now = time.time()
    limit = p["store"].setting("silent_after") or 0  # off unless set: a quiet log on a quiet site is normal
    if not limit:
        return
    for s in p["store"].read(lambda c: c.execute("SELECT path, last_event_ts FROM sources WHERE last_event_ts IS NOT NULL").fetchall()):
        if now - s["last_event_ts"] > limit:
            p["alerts"].raise_alert("source_silent", f"silent:{s['path']}", "WARNING", f"{s['path']} has had nothing new for a while", "Check that this service is still logging.")


def _crs_check(p: dict) -> None:
    got = supply.check_crs(p["store"])
    if got.get("changed"):
        p["alerts"].raise_alert("crs_changed", "crs:changed", "ERROR", "Core Rule Set files changed outside a package update", ", ".join(got["changed"][:5]))


def _disk(p: dict) -> None:
    use = p["retention"].usage()
    if use["free_mb"] < 500:
        p["alerts"].raise_alert("disk_low", "disk:low", "ERROR", f"Only {use['free_mb']} MB left where WAF Ella keeps events", "")
    leak = leaks.report(p["store"])
    if leak.get("total"):
        p["alerts"].raise_alert("secret_leak", "secrets", "ERROR", f"{leak['total']} possible secrets in stored events", "See Sources in WAF Ella. The values aren't shown.")


def _loop() -> None:
    p = parts()
    next_enforce = next_registry = next_soc = next_daily = 0.0
    while True:
        try:
            p["collector"].tick()
        except Exception as exc:  # noqa: BLE001  the worker must outlive any one bad pass
            problems.record("WAF Ella collector", exc, hint="Security events may be delayed. See Sources in WAF Ella.")
        if time.time() >= next_enforce:
            next_enforce = time.time() + ENFORCE_SECONDS
            try:
                p["engine"].tick()
            except Exception as exc:  # noqa: BLE001
                problems.record("WAF Ella enforcer", exc, hint="Bans may not be checked or retried until this clears.")
            try:
                if leaks.due(p["store"]):
                    found = leaks.scan(p["store"])
                    if found["total"]:
                        problems.record("WAF Ella stored secrets", RuntimeError(f"{found['total']} possible secrets in stored events"), hint="See Sources in WAF Ella for where. The values aren't shown.")
            except Exception as exc:  # noqa: BLE001
                problems.record("WAF Ella leak check", exc, hint="Stored events weren't checked for secrets today.")
        if time.time() >= next_registry:
            next_registry = time.time() + REGISTRY_SECONDS
            try:
                p["registry"].sync()
            except Exception as exc:  # noqa: BLE001
                problems.record("WAF Ella ban list", exc, hint="The combined ban list and its checks aren't being updated.")
        if time.time() >= next_soc:
            next_soc = time.time() + SOC_SECONDS
            soc_pass(p)
        if time.time() >= next_daily:
            next_daily = time.time() + DAILY_SECONDS
            daily_pass(p)
        time.sleep(COLLECT_SECONDS)


def start() -> bool:
    """Runs where it can do its job: Linux, as root, with nftables."""
    if platform.system() != "Linux" or os.geteuid() != 0 or not shutil.which("nft", path=BASE_PATH):
        return False
    threading.Thread(target=_loop, name="ella-worker", daemon=True).start()
    return True
