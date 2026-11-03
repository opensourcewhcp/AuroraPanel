"""Shared stand-ins for the network and VPN coverage tests (tests/test_cov_net_*.py).

Nothing here talks to the system: subprocess.run is replaced by a recorder that answers
from rules, shutil.which answers from a fixed set of tool names, absolute system paths are
redirected into a temp folder, and background jobs run on the spot so their output and
their result can be checked directly.
"""
from __future__ import annotations

import os
import subprocess
from pathlib import Path
from types import SimpleNamespace


def _tok_match(tok: str, word: str) -> bool:
    return tok == word or tok.endswith("/" + word)


def _contains(argv: list[str], words: tuple) -> bool:
    n = len(words)
    if n == 0:
        return True
    for i in range(len(argv) - n + 1):
        if all(_tok_match(argv[i + j], words[j]) for j in range(n)):
            return True
    return False


class FakeRun:
    """A subprocess.run replacement: records every argv, answers from rules.

    fake.on("wg", "genkey", out="KEY") answers any argv containing those tokens in a row
    (the directory part of a tool path is ignored). Later rules win. A rule may raise
    (exc=) or run a side effect (side=callable(argv, kwargs)) to mimic what the tool does
    to the file system."""

    def __init__(self):
        self.calls: list[list[str]] = []
        self.kwargs: list[dict] = []
        self.rules: list[tuple] = []

    def on(self, *words, rc=0, out="", err="", side=None, exc=None):
        self.rules.append((words, rc, out, err, side, exc))
        return self

    def __call__(self, argv, *args, **kw):
        argv = [str(a) for a in argv]
        self.calls.append(argv)
        self.kwargs.append(kw)
        for words, rc, out, err, side, exc in reversed(self.rules):
            if _contains(argv, words):
                if exc is not None:
                    raise exc
                if side is not None:
                    side(argv, kw)
                return subprocess.CompletedProcess(argv, rc, out, err)
        return subprocess.CompletedProcess(argv, 0, "", "")

    def find(self, *words) -> list[list[str]]:
        return [c for c in self.calls if _contains(c, words)]

    def called(self, *words) -> bool:
        return bool(self.find(*words))

    def input_for(self, *words):
        for c, kw in zip(self.calls, self.kwargs):
            if _contains(c, words):
                return kw.get("input")
        return None


def fake_which(*names: str):
    """A shutil.which replacement that knows only the given tools."""
    def which(name, mode=os.F_OK | os.X_OK, path=None):
        return f"/usr/bin/{name}" if name in names else None
    return which


def redirect_paths(monkeypatch, module, root: Path, prefixes=("/etc", "/var", "/proc", "/run", "/sys", "/usr")):
    """Make module.Path(...) land system paths under root (a temp folder).

    Module constants built at import time are untouched: tests set those to the matching
    place under root themselves."""
    real = Path

    def redirected(*parts):
        p = real(*parts)
        s = p.as_posix()
        for pre in prefixes:
            if s == pre or s.startswith(pre + "/"):
                return root / s.lstrip("/")
        return p
    monkeypatch.setattr(module, "Path", redirected)
    return redirected


class Log:
    """What jobs hand to a job function: log("line") and log.progress()."""

    def __init__(self):
        self.lines: list[str] = []

    def __call__(self, line: str) -> None:
        self.lines.append(line)

    def progress(self, pct=None, stage=None) -> None:
        pass


def run_jobs_inline(monkeypatch, jobs_module):
    """Replace jobs.launch_fn so the function runs now, on this thread.

    Returns a record filled in by the call: title, log lines, result (or the
    exception re-raised to the caller)."""
    rec = SimpleNamespace(title=None, lines=[], result=None, meta=None)

    def launch_fn(title, fn, meta=None):
        log = Log()
        rec.title, rec.lines, rec.meta = title, log.lines, meta
        rec.result = fn(log)
        return SimpleNamespace(id="inline", title=title, lines=log.lines, status="done", meta=meta)
    monkeypatch.setattr(jobs_module, "launch_fn", launch_fn)
    return rec


def capture_launch(monkeypatch, jobs_module):
    """Replace jobs.launch (apt and other commands) with a recorder; nothing runs."""
    rec = SimpleNamespace(calls=[])

    def launch(title, argv, env=None, meta=None):
        rec.calls.append({"title": title, "argv": list(argv), "env": env, "meta": meta})
        return SimpleNamespace(id="launched", title=title, status="running", meta=meta or {})
    monkeypatch.setattr(jobs_module, "launch", launch)
    return rec
