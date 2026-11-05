"""Which Linux family the panel is running on.

Debian, Ubuntu and Raspberry Pi OS use apt. Fedora uses dnf. apt is checked first, so a
Debian machine that happens to have dnf installed keeps behaving as it always did.
"""
from __future__ import annotations

import os
import shutil

BASE_PATH = "/usr/sbin:/usr/bin:/sbin:/bin"
# On Fedora the installer puts Debian-named commands here (backend/fedora_compat.py): apt-get, a2ensite,
# dpkg-query and so on, answered by dnf, rpm and httpd. Only the panel has this folder on its PATH.
COMPAT_DIR = "/usr/local/lib/aurora/compat"
PATH = f"{COMPAT_DIR}:{BASE_PATH}" if os.path.isdir(COMPAT_DIR) else BASE_PATH


def pkg_manager() -> str | None:
    """"apt", "dnf", or None when the system has neither."""
    if shutil.which("apt-get", path=BASE_PATH):
        return "apt"
    if shutil.which("dnf", path=BASE_PATH):
        return "dnf"
    return None


def is_dnf() -> bool:
    return pkg_manager() == "dnf"
