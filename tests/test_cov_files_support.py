"""Shared stubs for the test_cov_files_* modules (no tests in here).

The modules under test shell out to apt, systemctl, certbot, useradd and friends and read
hard-coded system paths. These helpers record the commands instead of running them and
bend the hard-coded paths into a temp folder, so the tests run on Windows and on a CI
container without root.
"""
from __future__ import annotations

import subprocess
from pathlib import Path


class Recorder:
    """A subprocess.run stand-in: remembers every argv and answers from a table of replies.

    replies: list of (needle, CompletedProcess-like dict); the first needle found in
    " ".join(argv) wins. Everything else succeeds with empty output."""

    def __init__(self, replies=None):
        self.calls: list[list[str]] = []
        self.inputs: list = []
        self.replies = list(replies or [])

    def __call__(self, argv, *a, **kw):
        argv = [str(x) for x in argv]
        self.calls.append(argv)
        self.inputs.append(kw.get("input"))
        joined = " ".join(argv)
        for needle, reply in self.replies:
            if needle in joined:
                if callable(reply):
                    reply = reply(argv)
                return subprocess.CompletedProcess(argv, reply.get("rc", 0), reply.get("out", ""), reply.get("err", ""))
        return subprocess.CompletedProcess(argv, 0, "", "")

    def ran(self, *words: str) -> list[list[str]]:
        """Every recorded command whose joined text contains all the words."""
        return [c for c in self.calls if all(w in " ".join(c) for w in words)]


def redirect_paths(monkeypatch, module, tmp_path: Path, prefixes: list[str]):
    """Replace module.Path with a factory that re-roots the given absolute prefixes under tmp_path.

    Path("/etc/shells") becomes tmp_path/"etc/shells" while every other path is untouched.
    Returns a function mapping a system path to its temp twin."""
    real = Path

    def twin(raw: str) -> Path:
        raw = raw.replace("\\", "/")
        for pre in prefixes:
            if raw == pre or raw.startswith(pre + "/"):
                return real(tmp_path, *[p for p in raw.split("/") if p])
        return real(raw)

    def factory(*args):
        if not args:
            return real()
        raw = "/".join(str(a) for a in args).replace("\\", "/")
        for pre in prefixes:
            if raw == pre or raw.startswith(pre + "/"):
                return twin(raw)
        return real(*args)

    monkeypatch.setattr(module, "Path", factory)
    return twin


def fake_glob(monkeypatch, module, table: dict[str, list[str]]):
    """module.glob.glob answers from the table for known patterns; other patterns use the real glob."""
    import glob as real_glob
    import types

    def g(pattern, *a, **kw):
        key = str(pattern).replace("\\", "/")
        if key in table:
            return list(table[key])
        return real_glob.glob(pattern, *a, **kw)

    monkeypatch.setattr(module, "glob", types.SimpleNamespace(glob=g))
    return g
