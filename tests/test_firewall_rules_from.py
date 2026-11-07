"""Rules that let only certain addresses reach a port."""
from types import SimpleNamespace

import pytest

from backend import firewall


@pytest.fixture
def cmds(monkeypatch):
    seen = []
    monkeypatch.setattr(firewall, "_ufw", lambda: "ufw")
    monkeypatch.setattr(firewall, "_fwd_running", lambda: True)
    monkeypatch.setattr(firewall.subprocess, "run", lambda a, **k: seen.append(a) or SimpleNamespace(returncode=0, stdout="", stderr=""))
    return seen


def test_ufw_rules(monkeypatch, cmds):
    monkeypatch.setattr(firewall, "_firewalld", lambda: False)
    firewall.allow_from("5432", "tcp", ["192.168.0.0/24"], "note")
    firewall.remove_from("5432", "tcp", ["192.168.0.0/24"])
    assert cmds == [["ufw", "allow", "from", "192.168.0.0/24", "to", "any", "port", "5432", "proto", "tcp", "comment", "note"],
                    ["ufw", "--force", "delete", "allow", "from", "192.168.0.0/24", "to", "any", "port", "5432", "proto", "tcp"]]


def test_a_ufw_refusal_is_reported(monkeypatch):
    monkeypatch.setattr(firewall, "_firewalld", lambda: False)
    monkeypatch.setattr(firewall, "_ufw", lambda: "ufw")
    monkeypatch.setattr(firewall.subprocess, "run", lambda a, **k: SimpleNamespace(returncode=1, stdout="", stderr="bad address"))
    with pytest.raises(firewall.FirewallError, match="bad address"):
        firewall.allow_from("5432", "tcp", ["::/0"])


def test_firewalld_rules_name_the_address_family(monkeypatch, cmds):
    monkeypatch.setattr(firewall, "_firewalld", lambda: True)
    firewall.allow_from("5432", "tcp", ["10.0.0.0/8", "::/0"])
    firewall.remove_from("5432", "tcp", ["10.0.0.0/8"])
    joined = [" ".join(c) for c in cmds]
    assert any('add-rich-rule=rule family="ipv4" source address="10.0.0.0/8" port port="5432" protocol="tcp" accept' in c for c in joined)
    assert any('add-rich-rule=rule family="ipv6" source address="::/0"' in c for c in joined)
    assert any('remove-rich-rule=rule family="ipv4" source address="10.0.0.0/8"' in c for c in joined)
    assert joined.count("firewall-cmd --reload") == 2


def test_an_empty_list_changes_nothing(monkeypatch, cmds):
    monkeypatch.setattr(firewall, "_firewalld", lambda: True)
    firewall.allow_from("5432", "tcp", [])
    firewall.remove_from("5432", "tcp", [])
    assert cmds == []
