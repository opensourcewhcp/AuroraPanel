"""The panel's own Python: pinned, verified, and never at the cost of a working panel."""
import re
from pathlib import Path

SCRIPT = (Path(__file__).resolve().parent.parent / "install.sh").read_text(encoding="utf-8")


def test_every_architecture_is_pinned_to_a_checksum():
    rows = dict(re.findall(r"^  (\w+)\) PY_TRIPLE=\S+; PY_SHA=([0-9a-f]{64}) ;;$", SCRIPT, re.M))
    assert set(rows) == {"x86_64", "aarch64"} and len(set(rows.values())) == 2


def test_32_bit_systems_stay_on_the_systems_python():
    assert "armv7" not in SCRIPT and 'if [ -n "$PY_TRIPLE" ] && ! py_ok "$PY_HOME/bin/python3"; then' in SCRIPT


def test_a_python_this_system_cannot_run_is_not_kept():
    # A 64-bit kernel under a 32-bit system says aarch64, and that download won't start.
    fetch = SCRIPT[SCRIPT.index("py_fetch() {"):SCRIPT.index('if [ -n "$PY_TRIPLE" ]')]
    assert fetch.index('py_ok "$tmp/python/bin/python3"') < fetch.index('mv "$tmp/python"')


def test_a_venv_on_a_removed_python_is_replaced():
    assert '[ -d .venv ] && [ "$(.venv/bin/python -c' in SCRIPT


def test_nothing_between_moving_the_venv_and_restoring_it_can_stop_the_script():
    part = SCRIPT[SCRIPT.index("mv .venv .venv.old"):SCRIPT.index("# Older copies of the panel's Python")]
    assert "die " not in part
    assert 'install --quiet --upgrade pip || warn' in part
    assert part.count('|| warn "Could not install the build tools"') == 2


def test_a_python_beside_the_systems_gets_its_own_headers():
    assert 'case "$PY" in python3.*) PY_DEV="$PY" ;; esac' in SCRIPT
    assert '"${PY_DEV}-dev"' in SCRIPT and '"${PY_DEV}-devel"' in SCRIPT


def test_the_download_is_checked_before_it_is_used():
    fetch = SCRIPT[SCRIPT.index("py_fetch() {"):SCRIPT.index('if [ -n "$PY_TRIPLE" ]')]
    assert fetch.index("sha256sum -c") < fetch.index("tar xzf") < fetch.index('mv "$tmp/python"')
    assert "https://github.com/astral-sh/python-build-standalone/" in fetch


def test_a_failed_download_falls_back_instead_of_stopping():
    assert 'py_fetch || warn' in SCRIPT


def test_a_failed_rebuild_restores_the_old_environment():
    assert "mv .venv .venv.old" in SCRIPT and "mv .venv.old .venv" in SCRIPT
    assert 'pip install --quiet -r requirements.txt || venv_fail' in SCRIPT


def test_minimum_is_a_python_still_getting_security_fixes():
    assert "sys.version_info < (3, 11)" in SCRIPT and "(3, 10)" not in SCRIPT
