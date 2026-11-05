"""Fedora support: dnf output parsing, firewalld rules in the wording the panel reads, and the
distro switch that keeps Debian machines on apt and ufw."""
import subprocess

import pytest

from backend import distro, firewall, packages, updates

CHECK_UPGRADE = """Upgrades
PackageKit.x86_64                     1.4.0-2.fc45               updates
krb5-libs.x86_64                      1.22.2-11.fc45             updates
alsa-sof-firmware.noarch              2026.09.2-1.fc45           updates
Obsoleting packages
"""
ADVISORY = """Name                   Type     Severity                                        Package              Issued
FEDORA-2026-01926f9706 security Moderate                krb5-libs-1.22.2-11.fc45.x86_64 2026-10-31 18:23:01
"""
RPM = "PackageKit\t1.3.0-1.fc45\nkrb5-libs\t1.22.2-10.fc45\n"


def _which(monkeypatch, *present):
    monkeypatch.setattr(distro.shutil, "which", lambda name, **k: f"/usr/bin/{name}" if name in present else None)


@pytest.mark.parametrize("present,want", [(("apt-get", "dnf"), "apt"), (("dnf",), "dnf"), (("apt-get",), "apt"), ((), None)])
def test_apt_wins_so_debian_machines_never_change(monkeypatch, present, want):
    _which(monkeypatch, *present)
    assert distro.pkg_manager() == want


def test_check_upgrade_keeps_packages_and_skips_headings():
    assert packages.parse_check_upgrade(CHECK_UPGRADE) == [
        ("PackageKit", "x86_64", "1.4.0-2.fc45", "updates"),
        ("krb5-libs", "x86_64", "1.22.2-11.fc45", "updates"),
        ("alsa-sof-firmware", "noarch", "2026.09.2-1.fc45", "updates"),
    ]


def test_updates_put_security_advisories_first(monkeypatch):
    def run(argv, timeout=600):
        out = {"check-upgrade": CHECK_UPGRADE, "advisory": ADVISORY}.get(argv[2], RPM if argv[0] == "rpm" else "")
        return subprocess.CompletedProcess(argv, 100, out, "")
    monkeypatch.setattr(updates, "_run", run)
    pk = updates._dnf_upgradable()
    assert pk[0]["name"] == "krb5-libs" and pk[0]["security"] is True
    assert pk[0]["from"] == "1.22.2-10.fc45" and pk[0]["to"] == "1.22.2-11.fc45"
    assert [p["security"] for p in pk[1:]] == [False, False]


def test_automatic_updates_config_round_trips(tmp_path, monkeypatch):
    conf = tmp_path / "automatic.conf"
    monkeypatch.setattr(updates, "DNF_AUTO_CONF", conf)
    _which(monkeypatch, "dnf")
    calls = []

    def run(argv, timeout=600):
        calls.append(argv)
        return subprocess.CompletedProcess(argv, 0, "enabled\n", "")
    monkeypatch.setattr(updates, "_run", run)
    conf.write_text("")
    got = updates.set_auto(True, "all", True, "03:30")
    assert ["systemctl", "enable", "--now", "dnf5-automatic.timer"] in calls
    assert (got["enabled"], got["mode"], got["reboot"], got["reboot_time"]) == (True, "all", True, "03:30")
    assert "upgrade_type = default" in conf.read_text()


class _Fwd:
    """A firewalld stand-in that records changes."""

    def __init__(self, monkeypatch, services="ssh cockpit", ports="8088/tcp", rich=""):
        self.calls, self.services, self.ports, self.rich = [], services, ports, rich
        _which(monkeypatch, "firewall-cmd")
        monkeypatch.setattr(firewall, "IS_LINUX", True)
        monkeypatch.setattr(firewall.subprocess, "run", self.run)

    def run(self, argv, **kw):
        self.calls.append(argv)
        out = ""
        if "--list-services" in argv:
            out = self.services
        elif "--list-ports" in argv:
            out = self.ports
        elif "--list-rich-rules" in argv:
            out = self.rich
        elif "--get-ports" in argv:
            out = {"--service=ssh": "22/tcp", "--service=cockpit": "9090/tcp"}.get(argv[-2], "")
        return subprocess.CompletedProcess(argv, 0, out, "")


def test_status_uses_the_wording_the_security_pages_parse(monkeypatch):
    _Fwd(monkeypatch, rich='rule family="ipv4" source address="203.0.113.9" drop')
    st = firewall.status()
    assert st["backend"] == "firewalld" and st["active"] is True
    assert [r["rule"] for r in st["rules"]] == [
        "22/tcp ALLOW IN Anywhere (ssh)", "9090/tcp ALLOW IN Anywhere (cockpit)",
        "8088/tcp ALLOW IN Anywhere", "Anywhere DENY IN 203.0.113.9"]


def test_ufw_stays_in_charge_when_both_are_installed(monkeypatch):
    _which(monkeypatch, "ufw", "firewall-cmd")
    monkeypatch.setattr(firewall, "IS_LINUX", True)
    assert firewall._firewalld() is False


@pytest.mark.parametrize("action,want", [
    ("allow", "--add-port=80/tcp"),
    ("deny", '--add-rich-rule=rule port port="80" protocol="tcp" drop'),
    ("reject", '--add-rich-rule=rule port port="80" protocol="tcp" reject'),
    ("limit", '--add-rich-rule=rule port port="80" protocol="tcp" accept limit value="6/m"'),
])
def test_add_rule_maps_each_action_and_reloads(monkeypatch, action, want):
    fw = _Fwd(monkeypatch)
    firewall.add_rule(action, "80", "tcp")
    assert any(want in c for c in fw.calls)
    assert ["firewall-cmd", "--reload"] in fw.calls


def test_deleting_the_ssh_rule_is_refused_while_active(monkeypatch):
    fw = _Fwd(monkeypatch)
    with pytest.raises(firewall.FirewallError, match="lock you out"):
        firewall.delete_rule(1)
    assert not any("--remove-service=ssh" in c for c in fw.calls)


def test_deleting_an_ordinary_rule_removes_it(monkeypatch):
    fw = _Fwd(monkeypatch, ports="8088/tcp 8443/tcp")
    firewall.delete_rule(4)
    assert any("--remove-port=8443/tcp" in c for c in fw.calls)


def test_spamassassin_settings_follow_the_panel(monkeypatch):
    from backend import mail
    s = mail._default_state() if hasattr(mail, "_default_state") else None
    s = s or {"spam": {}}
    s["spam"].update(threshold=6, allow=["friend@example.com", "good.example"], block=["bad.example", "x y\nrequired_score 99"])
    text = mail.render_spamassassin(s)
    assert "required_score 6\n" in text and "add_header all Level _STARS(*)_" in text
    assert "welcomelist_from friend@example.com\n" in text and "welcomelist_from *@good.example\n" in text
    assert "blocklist_from *@bad.example\n" in text
    assert "99" not in text  # a line break in a list entry can't add a setting


def test_opendkim_signs_what_the_submission_ports_send():
    from backend import mail
    conf = mail.render_opendkim_conf()
    assert "MTA ORIGINATING" in conf and "Mode sv" in conf and f"inet:{mail.OPENDKIM_PORT}@127.0.0.1" in conf


def test_postfix_runs_unchrooted_with_both_milters_on_fedora(monkeypatch):
    from backend import mail
    monkeypatch.setattr(mail.distro, "is_dnf", lambda: True)
    entries = [e for _, e, _ in mail.postfix_services() if e.startswith("submission")]
    assert entries and all(" - n - - smtpd" in e for e in entries)
    settings = mail.postfix_settings("h.example", "/c", "/k")
    assert settings["smtpd_milters"].startswith(f"inet:127.0.0.1:{mail.OPENDKIM_PORT},unix:")
    assert "unix:" not in settings["non_smtpd_milters"]


@pytest.mark.parametrize("page,dry,sub,kept", [
    ("<p>New site created by AuroraPanel.</p>", False, "", False),
    ("<p>New site created by AuroraPanel.</p>", True, "", True),
    ("<p>New site created by AuroraPanel.</p>", False, "blog", True),
    ("<p>My own page</p>", False, "", True),
])
def test_installing_into_a_site_removes_only_the_starter_page(tmp_path, monkeypatch, page, dry, sub, kept):
    from backend import apps
    (tmp_path / "index.html").write_text(page)
    monkeypatch.setattr(apps.sites, "get_site", lambda name: {"system": False, "has_http": True,
                                                              "settings": {"docroot": str(tmp_path), "ssl": "none", "server_name": name}})
    monkeypatch.setattr(apps, "_host", lambda o: "h")
    dest, url, created = apps._resolve_target({"mode": "existing", "site": "a.example", "subfolder": sub}, lambda *_: None, dry=dry)
    assert (tmp_path / "index.html").exists() is kept
    assert created is False and url.startswith("http://a.example")
