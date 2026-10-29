"""Git Version Control (cPanel parity).

Repositories the panel manages are listed in /var/lib/aurora/git.json. Git
always runs as the repository's owner (runuser), never as root, so files keep
normal ownership. Private repositories: the panel can make a per-repo SSH
deploy key (read-only on GitHub/GitLab) instead of storing passwords.
Deploy = pull + optionally copy the files (without .git) to a folder, e.g.
the web root, and/or run a command as the owner."""
from __future__ import annotations

import json
import re
import shutil
import subprocess
import time
from pathlib import Path

from . import jobs

STATE = Path("/var/lib/aurora/git.json")
_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")
_URL = re.compile(r"^(https?://[^\s'\"`;|&$<>\\]+|ssh://[^\s'\"`;|&$<>\\]+|[A-Za-z0-9_.-]+@[A-Za-z0-9_.-]+:[^\s'\"`;|&$<>\\]+)$")
_BRANCH = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,99}$")
_ALLOWED = ("/var/www/", "/srv/", "/home/")


class GitError(RuntimeError):
    pass


def _load() -> dict:
    try:
        return json.loads(STATE.read_text())
    except (OSError, ValueError):
        return {}


def _save(d: dict):
    STATE.parent.mkdir(parents=True, exist_ok=True)
    STATE.write_text(json.dumps(d, indent=2))


def _owner_ok(owner: str):
    import pwd
    try:
        pw = pwd.getpwnam(owner)
    except KeyError:
        raise GitError("No such Linux user")
    if pw.pw_uid == 0:
        raise GitError("Repositories can't be owned by root — pick a normal user (e.g. the Pi's login)")
    return pw


def _path_ok(path: str) -> Path:
    p = Path((path or "").strip())
    if not p.is_absolute() or ".." in p.parts:
        raise GitError("Path must be absolute, e.g. /home/pi/repositories/site")
    if not str(p).startswith(_ALLOWED) or str(p).rstrip("/") in ("/home", "/srv", "/var/www"):
        raise GitError("Keep repositories inside /home/<user>, /srv or /var/www")
    return p


def _key_path(owner_home: str, name: str) -> Path:
    return Path(owner_home) / ".ssh" / f"aurora_git_{name}"


def _env(repo: dict) -> dict:
    env = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "HOME": repo["home"], "GIT_TERMINAL_PROMPT": "0"}
    if repo.get("key"):
        env["GIT_SSH_COMMAND"] = f"ssh -i {repo['key']} -o IdentitiesOnly=yes -o StrictHostKeyChecking=accept-new"
    return env


def _as(owner: str, argv: list[str], env: dict, timeout: int = 60, cwd: str | None = None) -> subprocess.CompletedProcess:
    envargs = [f"{k}={v}" for k, v in env.items()]
    return subprocess.run(["runuser", "-u", owner, "--", "env", *envargs, *argv], capture_output=True, text=True,
                          timeout=timeout, cwd=cwd)


def _git(repo: dict, *args: str, timeout: int = 60) -> str:
    r = _as(repo["owner"], ["git", "-C", repo["path"], *args], _env(repo), timeout)
    if r.returncode != 0:
        raise GitError((r.stderr or r.stdout).strip()[-500:] or "git failed")
    return r.stdout


def _mask(url: str) -> str:
    return re.sub(r"//[^/@]+@", "//***@", url or "")


def make_key(name: str, owner: str) -> dict:
    """Create (or show) an SSH deploy key for a repository that isn't cloned yet."""
    if not _NAME.match(name or ""):
        raise GitError("Name: letters, digits, . _ - (max 64)")
    pw = _owner_ok(owner)
    key = _key_path(pw.pw_dir, name)
    if not key.exists():
        key.parent.mkdir(mode=0o700, exist_ok=True)
        shutil.chown(key.parent, pw.pw_uid, pw.pw_gid)
        r = _as(owner, ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", f"aurora-{name}@{_hostname()}", "-f", str(key)],
                {"PATH": "/usr/bin:/bin", "HOME": pw.pw_dir})
        if r.returncode != 0:
            raise GitError(r.stderr.strip() or "ssh-keygen failed")
    return {"public_key": Path(str(key) + ".pub").read_text().strip(), "key": str(key)}


def _hostname() -> str:
    import socket
    return socket.gethostname()


def create(name: str, path: str, owner: str, clone_url: str | None = None, branch: str | None = None,
           use_key: bool = False) -> jobs.Job:
    if not shutil.which("git"):
        raise GitError("git is not installed (apt install git)")
    if not _NAME.match(name or ""):
        raise GitError("Name: letters, digits, . _ - (max 64)")
    repos = _load()
    if name in repos:
        raise GitError("A repository with that name already exists")
    pw = _owner_ok(owner)
    p = _path_ok(path)
    if p.exists() and any(p.iterdir()):
        raise GitError("That folder already exists and isn't empty")
    url = (clone_url or "").strip()
    if url and not _URL.match(url):
        raise GitError("Clone URL must look like https://github.com/me/site.git or git@github.com:me/site.git")
    if branch and not _BRANCH.match(branch):
        raise GitError("Invalid branch name")
    repo = {"path": str(p), "owner": owner, "home": pw.pw_dir, "created": int(time.time()), "deploy_path": "", "deploy_cmd": ""}
    if use_key:
        repo["key"] = make_key(name, owner)["key"]

    def fn(log):
        parent = p.parent
        if not parent.exists():
            parent.mkdir(parents=True)
            shutil.chown(parent, pw.pw_uid, pw.pw_gid)
        if url:
            log(f"• Cloning {_mask(url)} into {p} as {owner}…")
            argv = ["git", "clone", "--progress"] + (["--branch", branch] if branch else []) + [url, str(p)]
            r = _as(owner, argv, _env(repo), timeout=1800)
            if r.returncode != 0 and branch and "Remote branch" in (r.stderr or "") and "not found" in (r.stderr or ""):
                log(f"• The remote has no branch called {branch}; cloning its default branch instead…")
                shutil.rmtree(p, ignore_errors=True)
                r = _as(owner, ["git", "clone", "--progress", url, str(p)], _env(repo), timeout=1800)
            for line in (r.stderr or "").splitlines()[-15:]:
                log("  " + line)
            if r.returncode != 0:
                raise GitError("Clone failed" + (" — for a private repo, add the deploy key on the Git host first" if use_key or "@" in url else ""))
        else:
            log(f"• Creating an empty repository in {p}…")
            p.mkdir(parents=True, exist_ok=True)
            shutil.chown(p, pw.pw_uid, pw.pw_gid)
            r = _as(owner, ["git", "init", "-b", branch or "main", str(p)], _env(repo))
            if r.returncode != 0:
                raise GitError(r.stderr.strip())
        repos2 = _load()
        repos2[name] = repo
        _save(repos2)
        log("✔ Repository ready")
        return {"name": name}
    return jobs.launch_fn(f"git: {name}", fn)


def listing() -> dict:
    out = []
    for name, r in sorted(_load().items()):
        item = {"name": name, "path": r["path"], "owner": r["owner"], "deploy_path": r.get("deploy_path", ""),
                "has_key": bool(r.get("key")), "exists": Path(r["path"], ".git").exists()}
        if item["exists"]:
            try:
                item["branch"] = _git(r, "rev-parse", "--abbrev-ref", "HEAD").strip()
                last = _git(r, "log", "-1", "--format=%h%x1f%s%x1f%an%x1f%ct").strip().split("\x1f")
                item["last"] = {"hash": last[0], "subject": last[1], "author": last[2], "time": int(last[3])} if len(last) == 4 else None
                item["remote"] = _mask(_git(r, "remote", "get-url", "origin").strip()) if "origin" in _git(r, "remote").split() else None
                item["dirty"] = len([l for l in _git(r, "status", "--porcelain").splitlines() if l.strip()])
            except GitError as exc:
                item["error"] = str(exc)[:200]
        out.append(item)
    return {"git": bool(shutil.which("git")), "repos": out}


def _repo(name: str) -> dict:
    r = _load().get(name)
    if not r:
        raise GitError("No such repository")
    return r


def details(name: str) -> dict:
    r = _repo(name)
    log = []
    for line in _git(r, "log", "-30", "--format=%h%x1f%s%x1f%an%x1f%ct").splitlines():
        f = line.split("\x1f")
        if len(f) == 4:
            log.append({"hash": f[0], "subject": f[1], "author": f[2], "time": int(f[3])})
    branches = [b.strip() for b in _git(r, "branch", "-a", "--format=%(refname:short)").splitlines()
                if b.strip() and b.strip() != "origin" and not b.strip().endswith("/HEAD")]
    status = [l for l in _git(r, "status", "--porcelain").splitlines() if l.strip()][:200]
    pub = None
    if r.get("key") and Path(r["key"] + ".pub").exists():
        pub = Path(r["key"] + ".pub").read_text().strip()
    return {"name": name, "log": log, "branches": branches, "status": status, "public_key": pub,
            "deploy_path": r.get("deploy_path", ""), "deploy_cmd": r.get("deploy_cmd", "")}


def pull(name: str) -> jobs.Job:
    r = _repo(name)

    def fn(log):
        log(f"• git pull --ff-only in {r['path']}")
        out = _git(r, "pull", "--ff-only", timeout=900)
        for line in out.splitlines()[-20:]:
            log("  " + line)
        log("✔ Up to date")
        return {"ok": True}
    return jobs.launch_fn(f"git pull: {name}", fn)


def checkout(name: str, branch: str) -> dict:
    r = _repo(name)
    if not _BRANCH.match(branch or ""):
        raise GitError("Invalid branch name")
    local = branch.split("/", 1)[1] if branch.startswith("origin/") else branch
    try:
        _git(r, "checkout", local)
    except GitError:
        _git(r, "checkout", "-b", local, "--track", f"origin/{local}")
    return {"ok": True, "branch": local}


def set_deploy(name: str, deploy_path: str, deploy_cmd: str) -> dict:
    repos = _load()
    r = repos.get(name)
    if not r:
        raise GitError("No such repository")
    dp = (deploy_path or "").strip()
    if dp:
        dp = str(_path_ok(dp))
        if Path(dp).resolve() == Path(r["path"]).resolve():
            raise GitError("Deploy folder must differ from the repository folder")
    cmd = (deploy_cmd or "").strip()
    if len(cmd) > 500 or "\n" in cmd:
        raise GitError("Deploy command: one line, max 500 characters")
    r["deploy_path"], r["deploy_cmd"] = dp, cmd
    _save(repos)
    return {"ok": True}


def deploy(name: str) -> jobs.Job:
    r = _repo(name)

    def fn(log):
        if Path(r["path"], ".git").exists() and "origin" in _git(r, "remote").split():
            log("• Pulling the latest commits…")
            for line in _git(r, "pull", "--ff-only", timeout=900).splitlines()[-10:]:
                log("  " + line)
        if r.get("deploy_path"):
            dest = r["deploy_path"]
            log(f"• Copying files to {dest} (without .git)…")
            if not Path(dest).exists():
                # Create it as the repo owner so the copy (which runs as the owner) can write there.
                import pwd
                pw = pwd.getpwnam(r["owner"])
                Path(dest).mkdir(parents=True)
                shutil.chown(dest, pw.pw_uid, pw.pw_gid)
            if shutil.which("rsync"):
                res = _as(r["owner"], ["rsync", "-a", "--exclude", ".git", f"{r['path']}/", f"{dest}/"], {"PATH": "/usr/bin:/bin"}, 900)
            else:
                res = _as(r["owner"], ["cp", "-a", f"{r['path']}/.", dest], {"PATH": "/usr/bin:/bin"}, 900)
                subprocess.run(["rm", "-rf", f"{dest}/.git"], capture_output=True)
            if res.returncode != 0:
                raise GitError("Copy failed: " + (res.stderr or "").strip()[-300:] + " (does the owner have write access to the deploy folder?)")
        if r.get("deploy_cmd"):
            log(f"• Running: {r['deploy_cmd']}")
            res = _as(r["owner"], ["bash", "-lc", r["deploy_cmd"]], _env(r), 1800, cwd=r["path"])
            for line in (res.stdout + res.stderr).splitlines()[-25:]:
                log("  " + line)
            if res.returncode != 0:
                raise GitError(f"Deploy command failed (exit {res.returncode})")
        log("✔ Deployed")
        return {"ok": True}
    return jobs.launch_fn(f"deploy: {name}", fn)


def remove(name: str, delete_files: bool = False) -> dict:
    repos = _load()
    r = repos.pop(name, None)
    if not r:
        raise GitError("No such repository")
    if delete_files and Path(r["path"]).exists():
        shutil.rmtree(r["path"])
    if r.get("key"):
        for suf in ("", ".pub"):
            Path(r["key"] + suf).unlink(missing_ok=True)
    _save(repos)
    return {"ok": True}
