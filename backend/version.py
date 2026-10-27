"""AuroraPanel version + a manual update check against aurora51.com.

The check only runs when the admin clicks "Check for updates" — the panel
never contacts anything on its own. It reads https://aurora51.com/version.json:
    {"version": "1.0.0-beta", "label": "Beta v1.0.0", "released": "2026-09-27",
     "download": "https://aurora51.com/aurorapanel.zip", "notes": ["…", "…"]}
"""
from __future__ import annotations

import json
import re
import urllib.error
import urllib.request

VERSION = "1.1.12"
LABEL = "v1.1.11"
RELEASED = "2026-10-26"
VERSION_URL = "https://aurora51.com/version.json"
CHANGELOG_URL = "https://aurora51.com/changelog.json"
SITE = "https://aurora51.com"
_SEMVER = re.compile(r"^(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?$")


class UpdateError(RuntimeError):
    pass


def _key(v: str):
    """Sortable key: 1.0.0-beta < 1.0.0-rc.1 < 1.0.0 < 1.0.1."""
    m = _SEMVER.match((v or "").strip())
    if not m:
        raise UpdateError(f"Unrecognised version: {v!r}")
    pre = m.group(4)
    pre_key = (1,) if pre is None else (0, *[(0, int(p)) if p.isdigit() else (1, p) for p in pre.split(".")])
    return (int(m.group(1)), int(m.group(2)), int(m.group(3)), pre_key)


def _install_dir() -> str:
    from pathlib import Path
    return str(Path(__file__).resolve().parent.parent)


def update_command(url: str = "") -> str:
    """Download + unpack over this install + re-run the installer (keeps the admin account and settings)."""
    from pathlib import Path
    url = url or f"{SITE}/aurorapanel.zip"
    d = Path(_install_dir())
    if d.name == "AuroraPanel":
        return (f"cd {d.parent} && wget -O aurorapanel.zip '{url}' && unzip -o aurorapanel.zip "
                f"&& cd AuroraPanel && sudo bash install.sh --yes")
    return (f"cd /tmp && wget -O aurorapanel.zip '{url}' && unzip -o aurorapanel.zip "
            f"&& cp -r AuroraPanel/. {d}/ && cd {d} && sudo bash install.sh --yes")


def _download_url(data: dict, latest: str) -> str:
    """The release zip on the official site, with the version in the query string: the
    site sits behind Cloudflare, which caches /aurorapanel.zip for hours, so a plain URL
    can hand out the previous release (the checksum check then refuses it)."""
    from urllib.parse import quote
    url = str(data.get("download") or "")
    if not url.startswith(SITE + "/") or any(c in url for c in "'\"\\ "):
        url = f"{SITE}/aurorapanel.zip"  # only ever point at the official site
    if "?" not in url and latest:
        url += "?v=" + quote(latest, safe="")
    return url


def info() -> dict:
    return {"version": VERSION, "label": LABEL, "released": RELEASED, "site": SITE,
            "install_dir": _install_dir(), "update_command": update_command()}


def _latest() -> dict:
    req = urllib.request.Request(VERSION_URL, headers={"User-Agent": f"AuroraPanel/{VERSION}", "Cache-Control": "no-cache"})
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            data = json.loads(r.read(64 * 1024).decode("utf-8"))
    except (urllib.error.URLError, OSError, ValueError) as exc:
        raise UpdateError(f"Couldn't reach aurora51.com ({getattr(exc, 'reason', exc)}). Is the Pi online?")
    if not isinstance(data, dict):
        raise UpdateError("aurora51.com sent an unexpected answer")
    return data


def changelog() -> dict:
    """Every release's notes from aurora51.com/changelog.json (only fetched when the admin asks)."""
    req = urllib.request.Request(CHANGELOG_URL, headers={"User-Agent": f"AuroraPanel/{VERSION}", "Cache-Control": "no-cache"})
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            data = json.loads(r.read(512 * 1024).decode("utf-8"))
    except (urllib.error.URLError, OSError, ValueError) as exc:
        raise UpdateError(f"Couldn't load the change log from aurora51.com ({getattr(exc, 'reason', exc)})")
    releases = []
    for rel in (data.get("releases") if isinstance(data, dict) else None) or []:
        if not isinstance(rel, dict):
            continue
        v = str(rel.get("version", ""))
        try:
            k = _key(v)
        except UpdateError:
            continue
        notes = rel.get("notes") if isinstance(rel.get("notes"), list) else []
        releases.append({"version": v, "label": str(rel.get("label") or v)[:40], "released": str(rel.get("released") or "")[:20],
                         "notes": [str(n)[:800] for n in notes if isinstance(n, (str, int, float))][:40],
                         "newer": k > _key(VERSION), "current": v == VERSION, "_k": k})
    releases.sort(key=lambda r: r.pop("_k"), reverse=True)
    return {"version": VERSION, "label": LABEL, "releases": releases[:100]}


def _can_auto(data: dict) -> bool:
    import platform
    import shutil
    return (platform.system() == "Linux" and bool(shutil.which("systemd-run"))
            and bool(_SHA256.match(str(data.get("sha256") or ""))))


def check() -> dict:
    data = _latest()
    latest = str(data.get("version", ""))
    newer = _key(latest) > _key(VERSION)
    download = _download_url(data, latest)
    notes = data.get("notes") or []
    notes = [str(n)[:800] for n in notes if isinstance(n, (str, int, float))][:30] if isinstance(notes, list) else []
    return {**info(), "latest": latest,
            "update_command": update_command(download), "latest_label": str(data.get("label") or latest)[:40],
            "latest_released": str(data.get("released") or "")[:20], "update_available": newer,
            "download": download, "notes": notes, "auto_update": newer and _can_auto(data)}


# ------------------------------------------------------------- one-click update
# The panel can't update itself in-process: install.sh restarts the service, and
# systemd kills the whole service cgroup on restart. So the panel downloads and
# verifies the release, then hands off to a transient unit (aurorapanel-update)
# that copies the files, re-runs install.sh, and rolls back if the panel doesn't
# come back up.
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
UPDATE_DIR = "/var/lib/aurora/updates"
UPDATE_UNIT = "aurorapanel-update"
_MAX_ZIP = 50 * 1024 * 1024

_RUNNER = r"""#!/bin/bash
# Written by AuroraPanel (backend/version.py) — runs as the transient unit aurorapanel-update.
set -uo pipefail
SRC=$1 DEST=$2 OLD=$3 NEW=$4
DIR=$(dirname "$0"); BK="$DIR/backup-$OLD.tgz"
exec >>"$DIR/update.log" 2>&1
echo "== $(date -Is) updating AuroraPanel $OLD -> $NEW in $DEST"
echo "• Backing up the current install to $BK"
tar -czf "$BK" -C "$DEST" --exclude=./.venv --exclude=__pycache__ . || { echo "✖ backup failed — nothing changed"; exit 1; }
# Keep the install folder's owner (e.g. a51) so a later manual unzip can still overwrite.
chown -R --reference="$DEST" "$SRC"
echo "• Copying the new files"
if cp -a "$SRC/." "$DEST/" && bash "$DEST/install.sh" --yes; then
  rm -rf "$SRC"; echo "✔ updated to $NEW"; exit 0
fi
echo "✖ update failed — restoring $OLD"
tar -xzf "$BK" -C "$DEST" && bash "$DEST/install.sh" --yes && echo "↩ rolled back to $OLD"
exit 1
"""


def _unit_active() -> bool:
    import subprocess
    r = subprocess.run(["systemctl", "is-active", UPDATE_UNIT], capture_output=True, text=True, timeout=10)
    return r.stdout.strip() in ("active", "activating")


def apply_update() -> dict:
    """Download + verify the latest release and start the background updater."""
    import hashlib
    import os
    import shutil
    import subprocess
    import zipfile
    from pathlib import Path

    data = _latest()
    latest = str(data.get("version", ""))
    if not _key(latest) > _key(VERSION):
        raise UpdateError(f"Already up to date ({LABEL})")
    if not _can_auto(data):
        raise UpdateError("This release can't be installed automatically — use the update command instead.")
    if _unit_active():
        raise UpdateError("An update is already running")
    download = _download_url(data, latest)

    udir = Path(UPDATE_DIR)
    udir.mkdir(parents=True, exist_ok=True)
    os.chmod(udir, 0o700)  # backups include aurora_config.json
    zpath = udir / f"aurorapanel-{latest}.zip"
    h = hashlib.sha256()
    req = urllib.request.Request(download, headers={"User-Agent": f"AuroraPanel/{VERSION}", "Cache-Control": "no-cache"})
    try:
        with urllib.request.urlopen(req, timeout=60) as r, open(zpath, "wb") as fh:
            total = 0
            while chunk := r.read(1 << 16):
                total += len(chunk)
                if total > _MAX_ZIP:
                    raise UpdateError("Download is unexpectedly large — stopped")
                h.update(chunk)
                fh.write(chunk)
    except (urllib.error.URLError, OSError) as exc:
        raise UpdateError(f"Download failed ({getattr(exc, 'reason', exc)})")
    if h.hexdigest() != str(data["sha256"]):
        zpath.unlink(missing_ok=True)
        raise UpdateError("Downloaded file doesn't match the published checksum — not installing it")

    staging = udir / f"staging-{latest}"
    shutil.rmtree(staging, ignore_errors=True)
    try:
        with zipfile.ZipFile(zpath) as z:
            names = z.namelist()
            if not names or any(n.startswith("/") or ".." in Path(n).parts or not n.startswith("AuroraPanel/") for n in names):
                raise UpdateError("Unexpected layout in the release zip — not installing it")
            for need in ("AuroraPanel/install.sh", "AuroraPanel/backend/app.py", "AuroraPanel/backend/version.py"):
                if need not in names:
                    raise UpdateError(f"Release zip is missing {need}")
            m = re.search(r'^VERSION = "([^"]+)"', z.read("AuroraPanel/backend/version.py").decode("utf-8", "replace"), re.M)
            if not m or m.group(1) != latest:
                raise UpdateError("Release zip version doesn't match version.json — not installing it")
            z.extractall(staging)
    except zipfile.BadZipFile:
        raise UpdateError("The downloaded file isn't a valid zip")

    runner = udir / "run-update.sh"
    runner.write_text(_RUNNER)
    argv = ["systemd-run", "--quiet", "--collect", f"--unit={UPDATE_UNIT}"]
    if os.environ.get("AURORA_USER"):  # install.sh keeps AURORA_USER from $SUDO_USER
        argv.append(f"--setenv=SUDO_USER={os.environ['AURORA_USER']}")
    argv += ["/bin/bash", str(runner), str(staging / "AuroraPanel"), _install_dir(), VERSION, latest]
    r = subprocess.run(argv, capture_output=True, text=True, timeout=30)
    if r.returncode != 0:
        raise UpdateError(r.stderr.strip() or "Couldn't start the updater")
    return {"ok": True, "from": VERSION, "to": latest}


def update_status() -> dict:
    from pathlib import Path
    log = Path(UPDATE_DIR) / "update.log"
    try:
        lines = log.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        lines = []
    # Only the latest run (each starts with "== <date> updating").
    start = max((i for i, l in enumerate(lines) if l.startswith("== ")), default=0)
    return {"running": _unit_active(), "version": VERSION, "log": lines[start:][-80:]}
