"""The Red Hat family: telling it from Fedora, the packages that differ, vendor repositories and dnf 4's output."""
import hashlib
import io
import tarfile

import pytest

from backend import distro, fedora_compat as fc, updates

ALMA = 'NAME="AlmaLinux"\nID="almalinux"\nID_LIKE="rhel centos fedora"\nVERSION_ID="{}"\n'
OS_RELEASES = [
    (ALMA.format("9.8"), 9),
    (ALMA.format("10.2"), 10),
    ('ID="rocky"\nID_LIKE="rhel centos fedora"\nVERSION_ID="9.6"\n', 9),
    ('ID="rhel"\nID_LIKE="fedora"\nVERSION_ID="10.1"\n', 10),
    ('ID="centos"\nID_LIKE="rhel fedora"\nVERSION_ID="10"\n', 10),
    ('ID=fedora\nVERSION_ID=45\n', None),
    ('ID=amzn\nID_LIKE="fedora"\nVERSION_ID="2023"\n', None),
    ('ID=debian\nVERSION_ID="13"\n', None),
]


def _system(monkeypatch, text, arch="x86_64"):
    monkeypatch.setattr(fc.Path, "read_text", lambda self, *a, **k: text if str(self).replace("\\", "/") == "/etc/os-release" else "")
    monkeypatch.setattr(fc.os, "uname", lambda: type("U", (), {"machine": arch})(), raising=False)


@pytest.mark.parametrize("text,major", OS_RELEASES)
def test_el_major(monkeypatch, text, major):
    _system(monkeypatch, text)
    assert fc.el_major() == major


@pytest.mark.parametrize("major,deb,rpms", [
    (9, "docker.io", ["docker-ce", "docker-ce-cli", "containerd.io"]),
    (10, "docker-compose-v2", ["docker-compose-plugin"]),
    (9, "redis-server", ["valkey"]),
    (9, "dovecot-sieve", ["dovecot-sieve"]),
    (9, "modsecurity-crs", ["mod_security_crs"]),
    (10, "modsecurity-crs", []),
    (9, "postfix", ["postfix"]),
    (10, "postfix", ["postfix", "postfix-lmdb"]),
    (10, "apache2", ["httpd", "mod_ssl"]),
])
def test_packages_that_differ(monkeypatch, major, deb, rpms):
    _system(monkeypatch, ALMA.format(major))
    assert fc.rpms_for(deb) == rpms


def test_fedora_packages_are_unchanged(monkeypatch):
    _system(monkeypatch, "ID=fedora\nVERSION_ID=45\n")
    assert fc.rpms_for("docker.io") == ["moby-engine"]
    assert fc.rpms_for("redis-server") == ["valkey", "valkey-compat-redis"]
    assert fc.rpms_for("dovecot-sieve") == ["dovecot-pigeonhole"]
    assert fc.rpms_for("modsecurity-crs") == ["mod_security_crs"]
    assert fc.external_repo("docker-ce") is None


def test_dovecot_repository_is_x86_64_only(monkeypatch):
    _system(monkeypatch, ALMA.format("9.8"), arch="aarch64")
    assert fc.external_repo("dovecot") is None
    assert fc.rpms_for("dovecot-sieve") == ["dovecot-pigeonhole"]  # the system's 2.3, which the mail page refuses with a reason
    assert fc.external_repo("docker-ce")["baseurl"].endswith("/linux/centos/9/aarch64/stable")


def test_docker_uses_the_rhel_path_only_on_rhel(monkeypatch):
    _system(monkeypatch, 'ID="rhel"\nID_LIKE="fedora"\nVERSION_ID="9.6"\n')
    assert "/linux/rhel/9/" in fc.external_repo("docker-ce")["baseurl"]
    _system(monkeypatch, ALMA.format("10.2"))
    assert "/linux/centos/10/" in fc.external_repo("docker-ce")["baseurl"]


def test_vendor_repositories_verify_signatures_and_are_https(monkeypatch):
    _system(monkeypatch, ALMA.format("10.2"))
    for rpm in ("docker-ce", "dovecot"):
        repo = fc.external_repo(rpm)
        assert repo["baseurl"].startswith("https://") and repo["gpgkey"].startswith("https://")


def _crs_tar(extra=b""):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for name, data in (("coreruleset-1/crs-setup.conf.example", b"setup"), ("coreruleset-1/rules/REQUEST-901.conf", b"rule"),
                           ("coreruleset-1/rules/words.data", b"data"), ("coreruleset-1/LICENSE", b"text"), ("coreruleset-1/rules/../../evil", b"bad")):
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    return buf.getvalue() + extra


class _Resp(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def _crs_setup(monkeypatch, tmp_path, data):
    root = tmp_path / "modsecurity.d"
    real_path = fc.Path
    monkeypatch.setattr(fc, "Path", lambda p, *a: root if str(p) == "/etc/httpd/modsecurity.d" else real_path(p, *a))
    monkeypatch.setattr(fc, "CRS_MARKER", root / ".aurora-crs-version")
    monkeypatch.setattr(fc, "selinux_on", lambda: False)
    monkeypatch.setattr(fc.urllib.request, "urlopen", lambda url, timeout=0: _Resp(data))
    return root


def test_rule_set_is_laid_out_like_the_package(monkeypatch, tmp_path):
    data = _crs_tar()
    root = _crs_setup(monkeypatch, tmp_path, data)
    monkeypatch.setattr(fc, "CRS_SHA256", hashlib.sha256(data).hexdigest())
    fc.install_crs()
    assert (root / "crs-setup.conf").read_text() == "setup"
    assert sorted(p.name for p in (root / "activated_rules").iterdir()) == ["REQUEST-901.conf", "words.data"]
    assert (root / ".aurora-crs-version").read_text().strip() == fc.CRS_VERSION
    assert not (tmp_path / "evil").exists()


def test_rule_set_with_the_wrong_checksum_is_refused(monkeypatch, tmp_path):
    root = _crs_setup(monkeypatch, tmp_path, _crs_tar())
    monkeypatch.setattr(fc, "CRS_SHA256", "0" * 64)
    with pytest.raises(OSError, match="checksum"):
        fc.install_crs()
    assert not (root / "activated_rules").exists()


def test_install_adds_the_vendor_repository_first(monkeypatch):
    _system(monkeypatch, ALMA.format("9.8"))
    order = []
    monkeypatch.setattr(fc, "add_repos", lambda rpms: order.append(("repos", rpms)))
    monkeypatch.setattr(fc, "dnf", lambda *a: order.append(("dnf", a)) or 1)
    monkeypatch.setattr(fc, "status_line", lambda *a: None)
    assert fc.apt_get(["-y", "install", "docker-compose-v2"]) == 1
    assert order == [("repos", ["docker-compose-plugin"]), ("dnf", ("-y", "install", "docker-compose-plugin"))]


def test_policy_offers_dovecot_24_before_its_repository_is_added(monkeypatch, capsys):
    _system(monkeypatch, ALMA.format("9.8"))
    monkeypatch.setattr(fc, "run", lambda *a, **k: type("R", (), {"stdout": "dovecot 2.3.16-1\n", "returncode": 0})())
    monkeypatch.setattr(fc, "rpm_versions", lambda names: {})
    fc.apt_cache(["policy", "dovecot-core"])
    assert "Candidate: 2.4" in capsys.readouterr().out


def test_search_reads_both_dnf_versions(monkeypatch, capsys):
    out = ("=== Name Exactly Matched: valkey ===\nvalkey.x86_64 : A key-value database\n"
           "Matched fields: name\n valkey-devel.x86_64\tDevelopment files\n")
    monkeypatch.setattr(fc, "run", lambda *a, **k: type("R", (), {"stdout": out})())
    fc.apt_cache(["search", "valkey"])
    assert capsys.readouterr().out.splitlines() == ["valkey - A key-value database", "valkey-devel - Development files"]


def test_advisories_in_both_dnf_versions():
    dnf4 = "ALSA-2026:92907 Moderate/Sec. curl-minimal-7.76.1-40.el9_8.9.x86_64\nALSA-2026:1 bugfix glibc-2.34-1.el9.x86_64\n"
    dnf5 = "Name Type Severity Package Issued\nFEDORA-2026-1 security Moderate krb5-libs-1.22.2-11.fc45.x86_64 2026-10-31 18:23:01\n"
    assert updates.parse_advisories(dnf4) == {"curl-minimal"}
    assert updates.parse_advisories(dnf5) == {"krb5-libs"}


@pytest.mark.parametrize("has5,timer,pkg,word", [
    (True, "dnf5-automatic.timer", "dnf5-plugin-automatic", "advisory"),
    (False, "dnf-automatic.timer", "dnf-automatic", "updateinfo"),
])
def test_dnf_version_picks_the_commands(monkeypatch, has5, timer, pkg, word):
    monkeypatch.setattr(distro, "has_dnf5", lambda: has5)
    calls = []
    monkeypatch.setattr(updates, "_run", lambda argv, t=0: calls.append(argv) or type("R", (), {"stdout": ""})())
    updates._dnf_security_packages()
    assert (updates._auto_timer(), updates._auto_pkg(), calls[0][2]) == (timer, pkg, word)


@pytest.mark.parametrize("major,exists,want", [(9, True, "/usr/bin/python3.12"), (9, False, "/usr/bin/python3"), (10, True, "/usr/bin/python3"), (None, True, "/usr/bin/python3")])
def test_system_python(monkeypatch, major, exists, want):
    monkeypatch.setattr(distro, "el_major", lambda: major)
    monkeypatch.setattr(distro.os.path, "exists", lambda p: exists)
    assert distro.system_python() == want


def test_gcloud_gets_python_3_12_on_el9_and_names_it_at_install_time(monkeypatch, tmp_path):
    from pathlib import Path as P
    from types import SimpleNamespace
    from backend import requires
    calls = []
    monkeypatch.setattr(requires.distro, "is_dnf", lambda: True)
    monkeypatch.setattr(requires.distro, "el_major", lambda: 9)
    monkeypatch.setattr(requires, "Path", lambda p: tmp_path / P(p).name)
    monkeypatch.setattr(requires.os.path, "exists", lambda p: bool(calls))
    monkeypatch.setattr(requires, "_run", lambda a, t=0, **k: calls.append(a) or SimpleNamespace(returncode=0, stdout="", stderr=""))
    requires._gcloud_repo()
    assert calls == [["dnf", "install", "-y", "-q", "python3.12"]]
    assert requires.COMPONENTS["gcloud"]["env"]() == {"CLOUDSDK_PYTHON": "/usr/bin/python3.12"}
