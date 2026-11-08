"""Regression tests for the security fixes: path/zip-slip guards, option injection, ReDoS bound,
vhost directive injection, and the zone-file allowlist. Symlink-dependent behaviour (root following a
planted link) is exercised on Linux only; the cross-platform cases run everywhere.
"""
from __future__ import annotations

import os
import zipfile
from pathlib import Path

import pytest

from backend import domains, netdiag

_can_symlink = hasattr(os, "symlink") and os.name == "posix"
skip_symlink = pytest.mark.skipif(not _can_symlink, reason="needs POSIX symlinks")


# --------------------------------------------------------------------------- netdiag option injection
def test_netdiag_rejects_a_leading_dash():
    for bad in ("-v", "-f/etc/passwd", "--help"):
        with pytest.raises(netdiag.NetDiagError):
            netdiag._valid_host(bad)
    assert netdiag._valid_host("example.com") == "example.com"


# --------------------------------------------------------------------------- unzip zip-slip
def test_unzip_refuses_a_zip_slip_member(files_root):
    from backend import files
    z = files_root / "eggs.zip"
    with zipfile.ZipFile(z, "w") as zf:
        zf.writestr("../escaped.txt", "nope")
    with pytest.raises(files.FileError, match="Unsafe path"):
        files.unzip("eggs.zip", overwrite=True)


def test_unzip_extracts_a_normal_archive(files_root):
    from backend import files
    z = files_root / "good.zip"
    with zipfile.ZipFile(z, "w") as zf:
        zf.writestr("inside/hello.txt", "hi")
    r = files.unzip("good.zip", overwrite=True)
    assert (files_root / "good" / "inside" / "hello.txt").read_text() == "hi"
    assert r["count"] == 1


# --------------------------------------------------------------------------- zone-file allowlist
def test_zone_content_only_serves_listed_zone_files(monkeypatch, tmp_path):
    monkeypatch.setattr(domains, "BIND_DIR", tmp_path)
    (tmp_path / "db.example.com").write_text("; a real zone\n")
    (tmp_path / "rndc.key").write_text('key "rndc-key" { secret "TOPSECRET"; };\n')
    monkeypatch.setattr(domains, "zones", lambda: {"zones": [{"name": "db.example.com", "path": str(tmp_path / "db.example.com")}]})
    assert "real zone" in domains.zone_content("db.example.com")["content"]
    with pytest.raises(domains.DomainError, match="not found"):
        domains.zone_content("rndc.key")          # a secret that is not a listed zone file
    with pytest.raises(domains.DomainError):
        domains.zone_content("../etc/passwd")      # traversal still blocked


# --------------------------------------------------------------------------- vhost directive injection
@skip_symlink  # POSIX absolute-path semantics; verified on the Linux host
def test_create_vhost_rejects_a_docroot_that_would_inject_directives(monkeypatch):
    import shutil as _sh
    monkeypatch.setattr(domains, "IS_LINUX", True)
    monkeypatch.setattr(_sh, "which", lambda *a, **k: "/usr/sbin/a2ensite")
    # validation happens before any file is touched, so no apache install is needed
    with pytest.raises(domains.DomainError, match="aren't allowed"):
        domains.create_vhost("example.com", docroot="/var/www/x\n    Include /etc/evil")
    with pytest.raises(domains.DomainError, match="dedicated folder"):
        domains.create_vhost("example.com", docroot="/")


# --------------------------------------------------------------------------- ssh key ReDoS bound
def test_add_key_bounds_length_and_rejects_newlines(monkeypatch):
    from backend import sshaccess
    monkeypatch.setattr(sshaccess, "IS_LINUX", True)  # get past the platform gate to reach the guard
    with pytest.raises(sshaccess.SSHError):
        sshaccess.add_key("someone", "ssh-rsa " + "A" * 20000)
    with pytest.raises(sshaccess.SSHError):
        sshaccess.add_key("someone", "ssh-rsa AAAA\nssh-rsa BBBB")


# --------------------------------------------------------------------------- symlink escapes (Linux only)
@skip_symlink
def test_unzip_refuses_a_symlinked_extraction_folder(files_root, tmp_path):
    from backend import files
    outside = tmp_path / "outside"
    outside.mkdir()
    z = files_root / "evil.zip"
    with zipfile.ZipFile(z, "w") as zf:
        zf.writestr("pwned.txt", "escaped")
    os.symlink(outside, files_root / "evil")   # evil/ -> outside the file root
    with pytest.raises(files.FileError):
        files.unzip("evil.zip", overwrite=True)
    assert not (outside / "pwned.txt").exists()  # nothing written through the link


@skip_symlink
def test_zip_skips_symlinked_files(files_root, tmp_path):
    from backend import files
    secret = tmp_path / "secret.txt"
    secret.write_text("root only")
    folder = files_root / "site"
    folder.mkdir()
    (folder / "ok.txt").write_text("fine")
    os.symlink(secret, folder / "leak.txt")     # a link pointing outside the area
    files.zip_entries("", ["site"], "out.zip", overwrite=True)
    with zipfile.ZipFile(files_root / "out.zip") as zf:
        names = zf.namelist()
    assert any(n.endswith("ok.txt") for n in names)
    assert not any(n.endswith("leak.txt") for n in names)  # the link's target was not copied
