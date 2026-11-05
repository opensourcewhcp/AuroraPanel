"""Wires WAF Ella together inside the panel and runs its background worker."""
from __future__ import annotations

import os
import platform
import shutil
import threading
import time

from .. import problems
from . import leaks
from .adapter import BASE_PATH, EllaSystemAdapter
from .blocks import Engine
from .collector import Collector
from .configs import ConfigManager
from .db import Store, ella_dir

COLLECT_SECONDS = 0.4  # how often logs are read; the batch of each pass is one transaction
ENFORCE_SECONDS = 5
_lock = threading.Lock()
_parts: dict = {}


def parts() -> dict:
    with _lock:
        if not _parts:
            store = Store(ella_dir())
            adapter = EllaSystemAdapter(store.dir / "adapter.log")
            _parts.update(store=store, adapter=adapter, engine=Engine(store, adapter), collector=Collector(store),
                          configs=ConfigManager(adapter, store.dir / "snapshots", audit=store.audit,
                                                on_critical=lambda title, detail: problems.record(title, RuntimeError(detail), hint="See WAF Ella's audit log.")))
        return _parts


def configure(**overrides) -> None:
    """Tests put their own store or adapter here."""
    with _lock:
        _parts.clear()
        _parts.update(overrides)


def _loop() -> None:
    p = parts()
    next_enforce = 0.0
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
        time.sleep(COLLECT_SECONDS)


def start() -> bool:
    """Runs where it can do its job: Linux, as root, with nftables."""
    if platform.system() != "Linux" or os.geteuid() != 0 or not shutil.which("nft", path=BASE_PATH):
        return False
    threading.Thread(target=_loop, name="ella-worker", daemon=True).start()
    return True
