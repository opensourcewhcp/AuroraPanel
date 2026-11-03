"""A tiny in-memory background job runner for long-running commands
(apt updates, backups, restores). Each job streams stdout+stderr into a buffer
that the frontend polls.

Jobs are ephemeral (lost on restart) which is fine for interactive use.
"""
from __future__ import annotations

import subprocess
import threading
import time
import uuid
from collections import deque
from typing import Sequence

_jobs: dict[str, "Job"] = {}
_lock = threading.Lock()
_MAX_JOBS = 50


class Job:
    def __init__(self, title: str, argv: Sequence[str], meta: dict | None = None):
        self.id = uuid.uuid4().hex[:12]
        self.title = title
        self.argv = list(argv)
        self.lines: deque[str] = deque(maxlen=20000)
        self.status = "running"  # running | done | failed
        self.returncode: int | None = None
        self.started = time.time()
        self.finished: float | None = None
        self.meta = meta or {}
        self.progress: float | None = None  # 0-100 when the job can tell, else None
        self.stage = ""
        self._thread: threading.Thread | None = None

    def to_dict(self, tail: int | None = None) -> dict:
        lines = list(self.lines)
        if tail is not None:
            lines = lines[-tail:]
        return {
            "id": self.id,
            "title": self.title,
            "status": self.status,
            "returncode": self.returncode,
            "started": self.started,
            "finished": self.finished,
            "output": "\n".join(lines),
            "line_count": len(self.lines),
            "meta": self.meta,
            "progress": self.progress,
            "stage": self.stage,
        }

    def _run(self, env: dict | None):
        try:
            argv = _with_apt_progress(self.argv)
            proc = subprocess.Popen(
                argv,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
                env=env,
            )
            assert proc.stdout is not None
            for line in proc.stdout:
                line = line.rstrip("\n")
                if not apt_status(self, line):
                    self.lines.append(line)
            proc.wait()
            self.returncode = proc.returncode
            ok_codes = self.meta.get("ok_returncodes", [0])
            self.status = "done" if proc.returncode in ok_codes else "failed"
            if self.status == "done" and self.progress is not None:
                self.progress = 100.0
        except (OSError, subprocess.SubprocessError) as exc:
            self.lines.append(f"[runner error] {exc}")
            self.status = "failed"
            self.returncode = -1
        finally:
            self.finished = time.time()

    def start(self, env: dict | None = None):
        self._thread = threading.Thread(target=self._run, args=(env,), daemon=True)
        self._thread.start()


# apt-get reports machine-readable progress on a file descriptor of our choice
# ("dlstatus:pkg:pct:text" while downloading, "pmstatus:pkg:pct:text" while installing),
# which drives the job's progress bar. Downloads fill the first DL_SHARE percent.
DL_SHARE = 40
_APT_OPTS = ["-o", "APT::Status-Fd=1", "-o", "Dpkg::Use-Pty=0"]
_LOCK_OPT = ["-o", "DPkg::Lock::Timeout=600"]


def _with_apt_progress(argv: Sequence[str]) -> list[str]:
    """apt-get commands get progress reporting, and wait for a running apt (a fresh
    Ubuntu server runs unattended-upgrades right after boot) instead of failing on its lock."""
    argv = list(argv)
    if argv and argv[0].rsplit("/", 1)[-1] == "apt-get":
        extra = list(_APT_OPTS)
        if not any("Lock::Timeout" in a for a in argv):
            extra += _LOCK_OPT
        argv[1:1] = extra
    return argv


def apt_status(job: "Job", line: str, span: tuple[float, float] = (0.0, 100.0)) -> bool:
    """Turn an apt status line into job progress/stage; True when the line was one."""
    kind, _, rest = line.partition(":")
    if kind not in ("dlstatus", "pmstatus") or rest.count(":") < 2:
        return False
    pkg, pct, text = rest.split(":", 2)
    try:
        p = float(pct)
    except ValueError:
        return True
    p = p * DL_SHARE / 100 if kind == "dlstatus" else DL_SHARE + p * (100 - DL_SHARE) / 100
    lo, hi = span
    job.progress = round(max(job.progress or 0.0, lo + (hi - lo) * p / 100), 1)
    job.stage = text.strip() or pkg
    return True


def launch(title: str, argv: Sequence[str], env: dict | None = None, meta: dict | None = None) -> Job:
    job = Job(title, argv, meta=meta)
    with _lock:
        # Evict oldest finished jobs if we hit the cap.
        if len(_jobs) >= _MAX_JOBS:
            for jid in list(_jobs):
                if _jobs[jid].status != "running":
                    del _jobs[jid]
                    break
        _jobs[job.id] = job
    job.start(env=env)
    return job


class _Log:
    """What FnJob passes to fn: log(line) adds an output line, log.progress(pct, stage) moves the bar."""

    def __init__(self, job: "Job"):
        self.job = job

    def __call__(self, line: str) -> None:
        self.job.lines.append(line)

    def progress(self, pct: float | None, stage: str | None = None) -> None:
        self.job.progress = None if pct is None else round(max(0.0, min(100.0, pct)), 1)
        if stage is not None:
            self.job.stage = stage

    def apt(self, args: Sequence[str], span: tuple[float, float] = (0.0, 100.0), timeout: int = 1800, env: dict | None = None) -> int:
        """Run apt-get (args after "apt-get"), streaming its output into the log and its
        progress into the span [lo, hi] of this job's bar. Returns the exit code."""
        argv = _with_apt_progress(["apt-get", "-y", *args])
        env = {"DEBIAN_FRONTEND": "noninteractive", "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
               "LANG": "C.UTF-8", **(env or {})}
        proc = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1, env=env)
        assert proc.stdout is not None
        t0 = time.time()
        for line in proc.stdout:
            line = line.rstrip("\n")
            if not apt_status(self.job, line, span):
                self.job.lines.append(line)
            if time.time() - t0 > timeout:
                proc.kill()
                self.job.lines.append("✖ apt-get took too long and was stopped")
                break
        return proc.wait()


class FnJob(Job):
    """A job that runs a Python function; fn(log) writes progress via log(str) and log.progress()."""

    def __init__(self, title: str, fn, meta: dict | None = None):
        super().__init__(title, [], meta=meta)
        self.fn = fn
        self.result = None

    def _run(self, env):
        try:
            self.result = self.fn(_Log(self))
            self.returncode, self.status = 0, "done"
            if self.progress is not None:
                self.progress = 100.0
        except Exception as exc:  # surfaced to the UI as the job's last line
            self.lines.append(f"✖ {exc}")
            self.returncode, self.status = 1, "failed"
        finally:
            self.finished = time.time()

    def to_dict(self, tail: int | None = None) -> dict:
        d = super().to_dict(tail)
        d["result"] = self.result
        return d


def launch_fn(title: str, fn, meta: dict | None = None) -> Job:
    job = FnJob(title, fn, meta=meta)
    with _lock:
        if len(_jobs) >= _MAX_JOBS:
            for jid in list(_jobs):
                if _jobs[jid].status != "running":
                    del _jobs[jid]
                    break
        _jobs[job.id] = job
    job.start()
    return job


def get(job_id: str) -> Job | None:
    return _jobs.get(job_id)


def find(**meta) -> list[Job]:
    """Jobs whose meta contains all the given key/values, newest first."""
    with _lock:
        found = [j for j in _jobs.values() if all(j.meta.get(k) == v for k, v in meta.items())]
    return sorted(found, key=lambda j: j.started, reverse=True)


def listing() -> list[dict]:
    with _lock:
        jobs = sorted(_jobs.values(), key=lambda j: j.started, reverse=True)
    return [j.to_dict(tail=1) for j in jobs]
