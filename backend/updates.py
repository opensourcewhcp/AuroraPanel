"""System updates — what's waiting, security first, one click to install, and automatic security updates.

refresh() runs `apt-get update` (daily from the task runner, or on demand) and caches the list of
upgradable packages, marking the ones from a -security pocket. Automatic updates are Debian's own
unattended-upgrades, configured here (security only, or everything; optional restart at a set time).
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import time
from pathlib import Path

from . import jobs

CACHE = Path("/var/lib/aurora/updates.json")
AUTO_CONF = Path("/etc/apt/apt.conf.d/20auto-upgrades")
UU_CONF = Path("/etc/apt/apt.conf.d/52aurora-unattended")
PATH = "/usr/sbin:/usr/bin:/sbin:/bin"
ENV = {"DEBIAN_FRONTEND": "noninteractive", "PATH": PATH, "LC_ALL": "C"}


class UpdateError(RuntimeError):
    pass


def _run(argv, timeout=600) -> subprocess.CompletedProcess:
    try:
        return subprocess.run(argv, capture_output=True, text=True, timeout=timeout, env={**os.environ, **ENV})
    except (OSError, subprocess.TimeoutExpired) as e:
        return subprocess.CompletedProcess(argv, 1, "", str(e))


def _parse_upgradable() -> list[dict]:
    """`apt list --upgradable` → [{name, from, to, origin, security}]."""
    out = _run(["apt", "list", "--upgradable"], 120).stdout
    pkgs = []
    for line in out.splitlines():
        m = re.match(r"^([^/\s]+)/(\S+)\s+(\S+)\s+(\S+)\s+\[upgradable from: ([^\]]+)\]", line)
        if m:
            name, origin, new, arch, old = m.groups()
            pkgs.append({"name": name, "origin": origin, "to": new, "from": old, "arch": arch,
                         "security": "-security" in origin or "security" in origin.split(",")[0]})
    return sorted(pkgs, key=lambda p: (not p["security"], p["name"]))


def refresh(update_lists: bool = True) -> dict:
    if not shutil.which("apt-get", path=PATH):
        return {"supported": False}
    err = ""
    if update_lists:
        r = _run(["apt-get", "-o", "DPkg::Lock::Timeout=120", "-q", "update"], 900)
        if r.returncode != 0:
            err = (r.stderr or r.stdout).strip()[-400:]
            if "Could not get lock" in err:
                err = ""  # another apt run (e.g. the nightly one) is refreshing the same lists right now
    pkgs = _parse_upgradable()
    data = {"checked": int(time.time()), "packages": pkgs, "total": len(pkgs), "security": sum(p["security"] for p in pkgs),
            "error": err}
    CACHE.parent.mkdir(parents=True, exist_ok=True)
    CACHE.write_text(json.dumps(data))
    return data


def cached() -> dict:
    try:
        return json.loads(CACHE.read_text())
    except (OSError, ValueError):
        return {"checked": 0, "packages": [], "total": 0, "security": 0}


def reboot_info() -> dict:
    need = Path("/var/run/reboot-required").exists()
    pkgs = []
    if need:
        try:
            pkgs = sorted(set(Path("/var/run/reboot-required.pkgs").read_text().split()))
        except OSError:
            pass
    running = os.uname().release
    try:
        import psutil
        boot = psutil.boot_time()
    except Exception:
        boot = 0
    return {"required": need, "packages": pkgs, "kernel": running, "boot": boot}


def auto_status() -> dict:
    installed = shutil.which("unattended-upgrade", path=PATH) is not None
    on = False
    try:
        on = bool(re.search(r'Unattended-Upgrade\s+"1"', AUTO_CONF.read_text()))
    except OSError:
        pass
    mode, reboot, reboot_time = "security", False, "04:00"
    try:
        t = UU_CONF.read_text()
        mode = "all" if "AURORA-MODE all" in t else "security"
        reboot = 'Automatic-Reboot "true"' in t
        m = re.search(r'Automatic-Reboot-Time "(\d\d:\d\d)"', t)
        reboot_time = m.group(1) if m else "04:00"
    except OSError:
        pass
    last = ""
    try:
        log = Path("/var/log/unattended-upgrades/unattended-upgrades.log").read_text(errors="replace").splitlines()
        last = next((l for l in reversed(log) if "Packages that will be upgraded" in l or "No packages found" in l or "All upgrades installed" in l), "")
    except OSError:
        pass
    return {"installed": installed, "enabled": installed and on, "mode": mode, "reboot": reboot, "reboot_time": reboot_time, "last": last[:200]}


def status() -> dict:
    c = cached()
    return {"supported": shutil.which("apt-get", path=PATH) is not None, **c, "reboot": reboot_info(), "auto": auto_status(),
            "running": next((j.id for j in jobs.find(updates="install") if j.status == "running"), None)}


def set_auto(enabled: bool, mode: str = "security", reboot: bool = False, reboot_time: str = "04:00") -> jobs.Job | dict:
    if mode not in ("security", "all"):
        raise UpdateError("Choose security or all")
    if not re.match(r"^([01]\d|2[0-3]):[0-5]\d$", reboot_time):
        raise UpdateError("Time must look like 04:00")

    def write():
        AUTO_CONF.write_text('// Written by AuroraPanel (System → Updates)\n'
                             f'APT::Periodic::Update-Package-Lists "{1 if enabled else 0}";\n'
                             f'APT::Periodic::Unattended-Upgrade "{1 if enabled else 0}";\n'
                             'APT::Periodic::AutocleanInterval "7";\n', encoding="utf-8")
        origins = ['"origin=Debian,codename=${distro_codename}-security,label=Debian-Security";',
                   '"origin=Debian,codename=${distro_codename},label=Debian-Security";',
                   '"origin=Ubuntu,archive=${distro_codename}-security";',
                   '"origin=Raspbian,codename=${distro_codename},label=Raspbian";' if mode == "all" else "",
                   '"origin=Raspberry Pi Foundation,codename=${distro_codename},label=Raspberry Pi Foundation";' if mode == "all" else ""]
        if mode == "all":
            origins += ['"origin=Debian,codename=${distro_codename},label=Debian";', '"origin=Debian,codename=${distro_codename}-updates";',
                        '"origin=Ubuntu,archive=${distro_codename}";', '"origin=Ubuntu,archive=${distro_codename}-updates";']
        UU_CONF.write_text(f'// Written by AuroraPanel (System → Updates). AURORA-MODE {mode}\n'
                           'Unattended-Upgrade::Origins-Pattern {\n' + "".join(f"        {o}\n" for o in origins if o) + '};\n'
                           'Unattended-Upgrade::Remove-Unused-Kernel-Packages "true";\n'
                           'Unattended-Upgrade::Remove-Unused-Dependencies "true";\n'
                           f'Unattended-Upgrade::Automatic-Reboot "{"true" if reboot else "false"}";\n'
                           f'Unattended-Upgrade::Automatic-Reboot-Time "{reboot_time}";\n'
                           'Dpkg::Options { "--force-confdef"; "--force-confold"; };\n', encoding="utf-8")

    if enabled and not shutil.which("unattended-upgrade", path=PATH):
        def fn(log):
            log.progress(2, "Installing unattended-upgrades")
            rc = log.apt(["install", "unattended-upgrades"], (5, 90))
            if rc != 0:
                raise UpdateError("apt-get install unattended-upgrades failed")
            write()
            log.progress(100, "Automatic updates on")
            log("✓ Automatic updates are on")
            return {"ok": True}
        return jobs.launch_fn("turn on automatic updates", fn, meta={"updates": "auto"})
    write()
    return {"ok": True, **auto_status()}


def install(names: list[str] | None = None) -> jobs.Job:
    """Upgrade everything (or only the named packages) with a progress bar."""
    for j in jobs.find(updates="install"):
        if j.status == "running":
            return j
    pkgs = [n for n in (names or []) if re.fullmatch(r"[a-z0-9][a-z0-9+.-]{0,100}", n)]

    def fn(log):
        log.progress(1, "Checking what's new")
        log.apt(["update"], (1, 10))
        if pkgs:
            log(f"• Upgrading {len(pkgs)} package(s): {' '.join(pkgs[:20])}{' …' if len(pkgs) > 20 else ''}")
            rc = log.apt(["install", "--only-upgrade", "-o", "Dpkg::Options::=--force-confdef", "-o", "Dpkg::Options::=--force-confold", *pkgs], (10, 95), timeout=7200)
        else:
            log("• Upgrading every package that has a new version")
            rc = log.apt(["-o", "Dpkg::Options::=--force-confdef", "-o", "Dpkg::Options::=--force-confold", "full-upgrade"], (10, 95), timeout=7200)
        if rc != 0:
            raise UpdateError(f"apt-get failed (exit {rc}) — see the log")
        log.progress(96, "Cleaning up")
        _run(["apt-get", "-y", "autoremove", "--purge"], 600)
        data = refresh(update_lists=False)
        r = reboot_info()
        log.progress(100, "Up to date" if not data["total"] else f"{data['total']} left")
        log("✓ Updates installed" + (" — restart to finish (new kernel or system libraries)" if r["required"] else ""))
        return {"ok": True, "left": data["total"], "reboot": r["required"]}

    return jobs.launch_fn("install updates", fn, meta={"updates": "install"})


def reboot(delay_min: int = 1) -> dict:
    delay_min = max(1, min(60, int(delay_min)))
    r = _run(["shutdown", "-r", f"+{delay_min}", "Restart requested from AuroraPanel"], 30)
    if r.returncode != 0:
        raise UpdateError(r.stderr.strip() or "shutdown failed")
    return {"ok": True, "in_minutes": delay_min}


def cancel_reboot() -> dict:
    _run(["shutdown", "-c"], 30)
    return {"ok": True}
