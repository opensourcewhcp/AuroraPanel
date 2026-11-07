"""Which Linux family the panel is running on.

Debian, Ubuntu and Raspberry Pi OS use apt. Fedora and the Red Hat family use dnf. apt is checked
first, so a Debian machine that happens to have dnf installed keeps behaving as it always did.
"""
from __future__ import annotations

import os
import shutil

from .fedora_compat import el_major, os_release

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


def has_dnf5() -> bool:
    """Fedora has dnf 5. The Red Hat family has dnf 4, whose commands and output differ in places."""
    return shutil.which("dnf5", path=BASE_PATH) is not None


def name() -> str:
    """This system's own name for itself, for messages."""
    return os_release().get("NAME") or "This system"


def system_python() -> str:
    """A system Python new enough for tools that need 3.10. RHEL 9's python3 stays at 3.9 and 3.12 sits beside it."""
    return "/usr/bin/python3.12" if el_major() == 9 and os.path.exists("/usr/bin/python3.12") else "/usr/bin/python3"
