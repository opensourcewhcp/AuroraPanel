"""Package management: apt on Debian / Raspberry Pi OS, dnf on Fedora.

Read operations run synchronously; mutating/long ones (update, upgrade,
install, remove) run as background jobs so the HTTP request returns immediately.
"""
from __future__ import annotations

import platform
import re
import shutil
import subprocess

from . import distro, jobs

IS_LINUX = platform.system() == "Linux"
# Non-interactive apt.
_APT_ENV = {"DEBIAN_FRONTEND": "noninteractive", "PATH": distro.PATH}
_DNF_ENV = {"PATH": distro.PATH, "LC_ALL": "C"}

# Package names: letters, digits, + - . : (arch suffix). No spaces / shell metachars.
_PKG_RE = re.compile(r"^[a-z0-9][a-z0-9+._:-]*$", re.IGNORECASE)


class PackageError(RuntimeError):
    pass


def _dnf() -> bool:
    return IS_LINUX and distro.is_dnf()


def _require_apt():
    if not IS_LINUX or not (shutil.which("apt-get") or distro.pkg_manager()):
        raise PackageError("No supported package manager (apt or dnf) on this host")


def _validate(pkg: str) -> str:
    if not _PKG_RE.match(pkg or ""):
        raise PackageError(f"Invalid package name: {pkg!r}")
    return pkg


def _rpm_installed(limit: int) -> list[dict]:
    out = subprocess.run(["rpm", "-qa", "--qf", "%{NAME}\t%{VERSION}-%{RELEASE}\t%{SIZE}\t%{SUMMARY}\n"],
                         capture_output=True, text=True, timeout=30, env=_DNF_ENV)
    pkgs = {}
    for line in out.stdout.splitlines():
        parts = line.split("\t")
        if len(parts) < 2 or parts[0] == "gpg-pubkey":
            continue
        size = int(parts[2]) // 1024 if len(parts) > 2 and parts[2].isdigit() else 0
        pkgs[parts[0]] = {"name": parts[0], "version": parts[1], "size_kb": size, "summary": parts[3] if len(parts) > 3 else ""}
    return [pkgs[n] for n in sorted(pkgs)][:limit]


def parse_check_upgrade(text: str) -> list[tuple[str, str, str, str]]:
    """`dnf check-upgrade` lines to (name, arch, version, repo). Headings and notices have another shape."""
    rows = []
    for line in text.splitlines():
        m = re.match(r"^([A-Za-z0-9][\w+.-]*)\.(\w+)\s+(\S+)\s+(\S+)\s*$", line)
        if m:
            rows.append(m.groups())
    return rows


def installed(limit: int = 500) -> list[dict]:
    if _dnf():
        return _rpm_installed(limit)
    if not IS_LINUX or not shutil.which("dpkg-query"):
        return []
    out = subprocess.run(
        ["dpkg-query", "-W", "-f=${Package}\t${Version}\t${Installed-Size}\t${binary:Summary}\n"],
        capture_output=True, text=True, timeout=30,
    )
    pkgs = []
    for line in out.stdout.splitlines():
        parts = line.split("\t")
        if len(parts) < 2:
            continue
        name, version = parts[0], parts[1]
        size_kb = int(parts[2]) if len(parts) > 2 and parts[2].isdigit() else 0
        summary = parts[3] if len(parts) > 3 else ""
        pkgs.append({"name": name, "version": version, "size_kb": size_kb, "summary": summary})
    pkgs.sort(key=lambda p: p["name"])
    return pkgs[:limit]


def upgradable() -> list[dict]:
    _require_apt()
    if _dnf():
        out = subprocess.run(["dnf", "-q", "check-upgrade"], capture_output=True, text=True, timeout=180, env=_DNF_ENV)
        rows = parse_check_upgrade(out.stdout)
        current = dict(l.split("\t", 1) for l in subprocess.run(
            ["rpm", "-qa", "--qf", "%{NAME}\t%{VERSION}-%{RELEASE}\n"], capture_output=True, text=True, timeout=30, env=_DNF_ENV,
        ).stdout.splitlines() if "\t" in l)
        return [{"name": n, "new_version": v, "arch": a, "current": current.get(n, "")} for n, a, v, _ in rows]
    out = subprocess.run(
        ["apt", "list", "--upgradable"],
        capture_output=True, text=True, timeout=30, env=_APT_ENV,
    )
    items = []
    for line in out.stdout.splitlines():
        # format: name/suite version arch [upgradable from: oldver]
        m = re.match(r"^([^/]+)/\S+\s+(\S+)\s+(\S+)\s+\[upgradable from:\s+([^\]]+)\]", line)
        if m:
            items.append({"name": m.group(1), "new_version": m.group(2), "arch": m.group(3), "current": m.group(4)})
    return items


def search(term: str, limit: int = 60) -> list[dict]:
    _require_apt()
    if not term or len(term) > 100 or any(c in term for c in "\n\r`$;|&"):
        raise PackageError("Invalid search term")
    if _dnf():
        out = subprocess.run(["dnf", "-q", "search", "--", term], capture_output=True, text=True, timeout=120, env=_DNF_ENV)
        results = []
        for line in out.stdout.splitlines():
            # " name.arch<TAB>summary"; the "Matched fields:" headings have no tab.
            if "\t" not in line:
                continue
            name, _, summary = line.strip().partition("\t")
            name = name.rpartition(".")[0] or name
            if term.lower() in name.lower() and all(r["name"] != name for r in results):
                results.append({"name": name, "summary": summary.strip()})
        return results[:limit]
    out = subprocess.run(
        ["apt-cache", "search", "--names-only", term],
        capture_output=True, text=True, timeout=20, env=_APT_ENV,
    )
    results = []
    for line in out.stdout.splitlines()[:limit]:
        if " - " in line:
            name, _, summary = line.partition(" - ")
            results.append({"name": name.strip(), "summary": summary.strip()})
    return results


# ---- mutating operations (background jobs) ----
def job_update() -> jobs.Job:
    _require_apt()
    if _dnf():
        return jobs.launch("dnf makecache", ["dnf", "-y", "makecache", "--refresh"], env=_DNF_ENV)
    return jobs.launch("apt update", ["apt-get", "update"], env=_APT_ENV)


def job_upgrade() -> jobs.Job:
    _require_apt()
    if _dnf():
        return jobs.launch("dnf upgrade", ["dnf", "-y", "upgrade"], env=_DNF_ENV)
    return jobs.launch("apt upgrade", ["apt-get", "-y", "upgrade"], env=_APT_ENV)


def job_install(pkgs: list[str]) -> jobs.Job:
    _require_apt()
    valid = [_validate(p) for p in pkgs]
    if not valid:
        raise PackageError("No packages specified")
    if _dnf():
        return jobs.launch(f"install {' '.join(valid)}", ["dnf", "-y", "install", *valid], env=_DNF_ENV)
    return jobs.launch(f"install {' '.join(valid)}", ["apt-get", "-y", "install", *valid], env=_APT_ENV)


def job_remove(pkgs: list[str]) -> jobs.Job:
    _require_apt()
    valid = [_validate(p) for p in pkgs]
    if not valid:
        raise PackageError("No packages specified")
    if _dnf():
        return jobs.launch(f"remove {' '.join(valid)}", ["dnf", "-y", "remove", *valid], env=_DNF_ENV)
    return jobs.launch(f"remove {' '.join(valid)}", ["apt-get", "-y", "remove", *valid], env=_APT_ENV)
