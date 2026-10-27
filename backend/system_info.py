"""System metrics via psutil, plus Raspberry-Pi-specific extras.

Everything degrades gracefully so the panel still runs on a dev machine
(Windows/macOS) where some Linux-only files/commands are absent.
"""
from __future__ import annotations

import platform
import shutil
import socket
import subprocess
import time
from pathlib import Path

import psutil

_BOOT_TIME = psutil.boot_time()


def _cpu_temperature() -> float | None:
    """CPU temperature in Celsius. Tries psutil, then the Pi thermal zone."""
    try:
        temps = psutil.sensors_temperatures()  # not available on Windows
        for key in ("cpu_thermal", "coretemp", "cpu-thermal"):
            if key in temps and temps[key]:
                return round(temps[key][0].current, 1)
        # Fall back to the first sensor we can find.
        for entries in temps.values():
            if entries:
                return round(entries[0].current, 1)
    except (AttributeError, NotImplementedError):
        pass
    # Raspberry Pi thermal zone.
    zone = Path("/sys/class/thermal/thermal_zone0/temp")
    if zone.exists():
        try:
            return round(int(zone.read_text().strip()) / 1000.0, 1)
        except (ValueError, OSError):
            return None
    return None


def is_pi() -> bool:
    return "raspberry pi" in (_pi_model() or "").lower()


def _pi_model() -> str | None:
    model_file = Path("/proc/device-tree/model")
    if model_file.exists():
        try:
            return model_file.read_text().replace("\x00", "").strip()
        except OSError:
            return None
    return None


def _throttled() -> str | None:
    """`vcgencmd get_throttled` — undervoltage/throttle bit flags (Pi only)."""
    if not shutil.which("vcgencmd"):
        return None
    try:
        out = subprocess.run(
            ["vcgencmd", "get_throttled"], capture_output=True, text=True, timeout=3
        )
        return out.stdout.strip().split("=", 1)[-1] or None
    except (subprocess.SubprocessError, OSError):
        return None


def overview() -> dict:
    vm = psutil.virtual_memory()
    swap = psutil.swap_memory()
    uptime = int(time.time() - _BOOT_TIME)

    try:
        load1, load5, load15 = psutil.getloadavg()
    except (AttributeError, OSError):
        load1 = load5 = load15 = None

    return {
        "hostname": socket.gethostname(),
        "pi_model": _pi_model(),
        "platform": platform.platform(),
        "arch": platform.machine(),
        "python": platform.python_version(),
        "uptime_seconds": uptime,
        "boot_time": _BOOT_TIME,
        "cpu": {
            "percent": psutil.cpu_percent(interval=0.3),
            "per_core": psutil.cpu_percent(interval=0.0, percpu=True),
            "cores_logical": psutil.cpu_count(logical=True),
            "cores_physical": psutil.cpu_count(logical=False),
            "temperature_c": _cpu_temperature(),
            "load_avg": [load1, load5, load15],
            "freq_mhz": round(psutil.cpu_freq().current, 0) if psutil.cpu_freq() else None,
        },
        "memory": {
            "total": vm.total,
            "used": vm.used,
            "available": vm.available,
            "percent": vm.percent,
        },
        "swap": {"total": swap.total, "used": swap.used, "percent": swap.percent},
        "throttled": _throttled(),
    }


def disks() -> list[dict]:
    result = []
    for part in psutil.disk_partitions(all=False):
        try:
            usage = psutil.disk_usage(part.mountpoint)
        except (PermissionError, OSError):
            continue
        result.append(
            {
                "device": part.device,
                "mountpoint": part.mountpoint,
                "fstype": part.fstype,
                "total": usage.total,
                "used": usage.used,
                "free": usage.free,
                "percent": usage.percent,
            }
        )
    return result


def networks() -> dict:
    addrs = psutil.net_if_addrs()
    stats = psutil.net_if_stats()
    io = psutil.net_io_counters(pernic=True)
    interfaces = []
    for name, addr_list in addrs.items():
        ipv4 = next(
            (a.address for a in addr_list if a.family == socket.AF_INET), None
        )
        ipv6 = next(
            (a.address for a in addr_list if a.family == socket.AF_INET6), None
        )
        mac = next(
            (a.address for a in addr_list if a.family == psutil.AF_LINK), None
        )
        st = stats.get(name)
        counters = io.get(name)
        interfaces.append(
            {
                "name": name,
                "ipv4": ipv4,
                "ipv6": ipv6,
                "mac": mac,
                "is_up": st.isup if st else None,
                "speed_mbps": st.speed if st else None,
                "bytes_sent": counters.bytes_sent if counters else 0,
                "bytes_recv": counters.bytes_recv if counters else 0,
            }
        )
    return {"interfaces": interfaces}


# psutil states → the group the page sorts them into
PROC_GROUP = {"running": "busy", "sleeping": "sleeping", "idle": "idle", "disk-sleep": "attention", "stopped": "attention",
              "zombie": "attention", "tracing-stop": "attention", "dead": "attention", "wake-kill": "attention", "waking": "sleeping", "parked": "idle"}


def processes_full(limit: int = 500, sort_by: str = "cpu") -> tuple[list[dict], dict]:
    """Every process with what the page needs to group and sort it, plus counts per group (over all of them)."""
    procs = []
    counts = {"busy": 0, "sleeping": 0, "idle": 0, "attention": 0, "kernel": 0, "total": 0}
    for p in psutil.process_iter(["pid", "ppid", "name", "username", "cpu_percent", "memory_percent", "status", "cmdline", "memory_info", "num_threads", "create_time"]):
        try:
            info = p.info
            cmd = " ".join(info.get("cmdline") or [])
            kernel = not cmd and (info["pid"] == 2 or info.get("ppid") == 2)
            status = info.get("status") or "?"
            group = PROC_GROUP.get(status, "sleeping")
            mem = info.get("memory_info")
            procs.append({
                "pid": info["pid"], "ppid": info.get("ppid"), "name": info["name"] or "?", "username": info.get("username") or "?",
                "cpu_percent": round(info.get("cpu_percent") or 0.0, 1), "memory_percent": round(info.get("memory_percent") or 0.0, 1),
                "status": status, "group": group, "kernel": kernel, "cmd": cmd[:200], "rss": getattr(mem, "rss", 0) if mem else 0,
                "threads": info.get("num_threads") or 0, "started": info.get("create_time") or 0,
            })
            counts["total"] += 1
            counts[group] += 1
            if kernel:
                counts["kernel"] += 1
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue
    key = "memory_percent" if sort_by == "memory" else "cpu_percent"
    procs.sort(key=lambda x: (x[key], x["rss"]), reverse=True)
    return procs[:limit], counts


def processes(limit: int = 40, sort_by: str = "cpu") -> list[dict]:
    return processes_full(limit, sort_by)[0]


def kill_process(pid: int) -> None:
    p = psutil.Process(pid)  # raises NoSuchProcess if gone
    p.terminate()
    try:
        p.wait(timeout=3)
    except psutil.TimeoutExpired:
        p.kill()
