"""Problems: what went wrong in the background, kept where the owner can see it.

The panel keeps running when a tool is missing or a command fails, which is right for a
box that must stay reachable. The cost used to be silence: a failed WAF rewrite looked
exactly like a successful one. Two levels fix that:

  record(where, exc)   something the owner should act on. Shown on the dashboard until
                       dismissed, and written to the journal as a warning.
  quiet(exc)           an exception the code deliberately carries on from. Counted and
                       kept (newest first) for the Problems list and the journal at info
                       level, never raised, never shown as an alarm.

Both de-duplicate: the same message from the same place is one entry with a count, so a
loop that fails every second cannot flood anything. Everything lives in memory and starts
empty at each boot, which is the right lifetime: a problem that does not come back after a
restart is not a problem."""
from __future__ import annotations

import logging
import sys
import threading
import time

LOG = logging.getLogger("aurora")
if not LOG.handlers:   # uvicorn configures its own loggers only; ours goes to the journal as well
    _h = logging.StreamHandler(sys.stderr)
    _h.setFormatter(logging.Formatter("aurora: %(message)s"))
    LOG.addHandler(_h)
    LOG.setLevel(logging.INFO)
    LOG.propagate = False

MAX_PROBLEMS = 200
MAX_QUIET = 500
_LOCK = threading.Lock()
_problems: dict[str, dict] = {}   # key -> entry (dashboard-worthy)
_quiet: dict[str, dict] = {}      # key -> entry (carried on from)
_seq = 0


def _where(depth: int) -> str:
    """module.function:line of the caller, for a message that says where without a traceback."""
    try:
        f = sys._getframe(depth)
        mod = str(f.f_globals.get("__name__", "?")).rsplit(".", 1)[-1]
        return f"{mod}.{f.f_code.co_name}:{f.f_lineno}"
    except Exception:
        return "?"


def _text(message) -> str:
    if isinstance(message, BaseException):
        s = f"{type(message).__name__}: {message}" if str(message) else type(message).__name__
    else:
        s = str(message)
    return " ".join(s.split())[:400]


def _put(store: dict, cap: int, where: str, message: str, hint: str) -> dict:
    global _seq
    now = int(time.time())
    key = where + "\n" + message
    with _LOCK:
        e = store.get(key)
        if e:
            e["count"] += 1
            e["last"] = now
            if hint:
                e["hint"] = hint
            return dict(e)
        _seq += 1
        e = {"id": f"p{_seq}", "ts": now, "last": now, "count": 1, "where": where, "message": message, "hint": hint}
        store[key] = e
        while len(store) > cap:   # oldest out
            store.pop(next(iter(store)))
        return dict(e)


def record(where: str, message, hint: str = "") -> dict:
    """Something the owner should see: shown on the dashboard until dismissed."""
    e = _put(_problems, MAX_PROBLEMS, str(where)[:80], _text(message), str(hint or "")[:300])
    if e["count"] == 1:
        LOG.warning("%s: %s", e["where"], e["message"])
    return e


def quiet(exc: BaseException, where: str | None = None) -> None:
    """A caught exception the code carries on from. Never raises, never alarms; just not silent."""
    try:
        e = _put(_quiet, MAX_QUIET, where or _where(2), _text(exc), "")
        if e["count"] == 1 or e["count"] % 100 == 0:
            LOG.info("carried on after %s in %s (x%d)", e["message"], e["where"], e["count"])
    except Exception:
        pass


def listing() -> dict:
    with _LOCK:
        probs = sorted(_problems.values(), key=lambda e: e["last"], reverse=True)
        quiets = sorted(_quiet.values(), key=lambda e: e["last"], reverse=True)[:100]
    return {"problems": [dict(e) for e in probs], "quiet": [dict(e) for e in quiets]}


def dismiss(problem_id: str | None = None) -> dict:
    """Take a problem off the dashboard (all of them without an id). It comes back if it happens again."""
    with _LOCK:
        if problem_id:
            for k, e in list(_problems.items()):
                if e["id"] == problem_id:
                    del _problems[k]
        else:
            _problems.clear()
        left = len(_problems)
    return {"ok": True, "left": left}


def clear() -> None:
    """Tests only."""
    with _LOCK:
        _problems.clear()
        _quiet.clear()


def background(name: str, fn, hint: str = "") -> threading.Thread:
    """Run fn on a daemon thread; if it raises, the owner sees it on the dashboard instead of nowhere."""
    def run():
        try:
            fn()
        except Exception as exc:
            record(name, exc, hint)
    t = threading.Thread(target=run, name=name, daemon=True)
    t.start()
    return t
