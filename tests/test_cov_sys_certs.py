"""SSL certificates: inspection, listing, names on a certificate and self-signed generation.
openssl is replaced by a recorder that answers from a table and writes the files a real one would."""
from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from backend import sslcerts


class _Calls(list):
    """The recorded openssl calls; carries the canned answers too (a plain list can't take attributes)."""

X509_OUT = "subject=CN = pi.lan\nissuer=CN = pi.lan\nnotAfter=Jan  1 00:00:00 2030 GMT\nnotBefore=Jan  1 00:00:00 2025 GMT\n"
X509_LE = "subject=CN = www.example.com\nissuer=C = US, O = Let's Encrypt, CN = R11\nnotAfter=Mar  1 00:00:00 2027 GMT\nnotBefore=Dec  1 00:00:00 2026 GMT\n"
SAN_OUT = "X509v3 Subject Alternative Name: \n    DNS:pi.lan, DNS:pi.local, IP Address:192.168.0.100, IP Address:FD00:0:0:0:0:0:0:1\n"
PEM = "-----BEGIN CERTIFICATE-----\nMIIBfake\n-----END CERTIFICATE-----\n"


@pytest.fixture
def openssl(monkeypatch):
    """openssl present; `calls` records every argv, `answers` maps a subcommand to (rc, stdout, stderr)."""
    calls = _Calls()
    answers = {"x509": (0, X509_OUT, ""), "san": (0, SAN_OUT, ""), "req": (0, "", "")}

    def run(argv, **kw):
        calls.append(argv)
        sub = argv[1]
        if sub == "x509" and "-ext" in argv:
            rc, out, err = answers["san"]
        elif sub == "req":
            rc, out, err = answers["req"]
            if rc == 0:   # a real openssl writes both files
                Path(argv[argv.index("-keyout") + 1]).write_text("KEY")
                Path(argv[argv.index("-out") + 1]).write_text(PEM)
        else:
            rc, out, err = answers[sub]
        return subprocess.CompletedProcess(argv, rc, out, err)
    monkeypatch.setattr(sslcerts.shutil, "which", lambda name, *a, **k: "/usr/bin/openssl" if name == "openssl" else None)
    monkeypatch.setattr(sslcerts.subprocess, "run", run)
    calls.answers = answers
    return calls


def test_without_openssl_inspection_is_quietly_empty(monkeypatch, tmp_path):
    monkeypatch.setattr(sslcerts.shutil, "which", lambda *a, **k: None)
    with pytest.raises(sslcerts.SSLCertError, match="not installed"):
        sslcerts._openssl()
    assert sslcerts._inspect(tmp_path / "x.pem") is None
    assert sslcerts.subject_alt_names(tmp_path / "x.pem") == []
    with pytest.raises(sslcerts.SSLCertError, match="not installed"):
        sslcerts.generate_self_signed("pi.lan")


def test_inspect_parses_openssl_output(openssl, tmp_path):
    info = sslcerts._inspect(tmp_path / "pi.crt")
    assert info == {"path": str(tmp_path / "pi.crt"), "name": "pi.crt", "subject": "CN = pi.lan", "issuer": "CN = pi.lan",
                    "expires": "Jan  1 00:00:00 2030 GMT", "starts": "Jan  1 00:00:00 2025 GMT", "self_signed": True}
    assert openssl[-1][1:6] == ["x509", "-in", str(tmp_path / "pi.crt"), "-noout", "-subject"]
    openssl.answers["x509"] = (0, X509_LE, "")
    assert sslcerts._inspect(tmp_path / "le.pem")["self_signed"] is False
    openssl.answers["x509"] = (1, "", "unable to load certificate")
    assert sslcerts._inspect(tmp_path / "junk.pem") is None
    openssl.answers["x509"] = (0, X509_OUT, "")
    openssl.answers["san"] = (0, "No extensions in certificate\n", "")
    assert sslcerts.subject_alt_names(tmp_path / "pi.crt") == []


def test_listing_scans_the_known_folders_once_each(openssl, tmp_path, monkeypatch):
    le = tmp_path / "letsencrypt" / "live" / "www.example.com"
    le.mkdir(parents=True)
    (le / "fullchain.pem").write_text(PEM)
    (le / "privkey.pem").write_text("KEY")   # not a top-level *.pem: not listed
    own = tmp_path / "aurora-certs"
    own.mkdir()
    (own / "pi.crt").write_text(PEM)
    (own / "pi.key").write_text("KEY")
    (own / "old.pem").write_text(PEM)
    monkeypatch.setattr(sslcerts, "CERT_DIR", own)
    monkeypatch.setattr(sslcerts, "_SCAN_DIRS", [str(tmp_path / "letsencrypt" / "live"), str(tmp_path / "missing"), str(own), str(own)])
    lst = sslcerts.list_certs()
    assert lst["cert_dir"] == str(own)
    assert sorted(c["name"] for c in lst["certs"]) == ["fullchain.pem", "old.pem", "pi.crt"]
    assert sum(1 for c in openssl if c[1] == "x509") == 3   # the duplicate folder is inspected once


def test_self_signed_generation_checks_its_inputs_and_calls_openssl(openssl, tmp_path, monkeypatch):
    monkeypatch.setattr(sslcerts, "CERT_DIR", tmp_path / "certs")
    for bad in ("", "pi lan", "a" * 254, "pi;rm"):
        with pytest.raises(sslcerts.SSLCertError, match="Invalid common name"):
            sslcerts.generate_self_signed(bad)
    with pytest.raises(sslcerts.SSLCertError, match="Days"):
        sslcerts.generate_self_signed("pi.lan", 0)
    with pytest.raises(sslcerts.SSLCertError, match="Days"):
        sslcerts.generate_self_signed("pi.lan", 3651)
    r = sslcerts.generate_self_signed("*.example.com", 30)
    assert r == {"ok": True, "cert": str(tmp_path / "certs" / "wildcard.example.com.crt"), "key": str(tmp_path / "certs" / "wildcard.example.com.key")}
    argv = openssl[-1]
    assert argv[1:4] == ["req", "-x509", "-nodes"] and argv[argv.index("-days") + 1] == "30" and argv[argv.index("-subj") + 1] == "/CN=*.example.com"
    assert "basicConstraints=critical,CA:FALSE" in argv and Path(r["key"]).read_text() == "KEY"
    openssl.answers["req"] = (1, "", "problems making Certificate Request")
    with pytest.raises(sslcerts.SSLCertError, match="problems making"):
        sslcerts.generate_self_signed("pi.lan")


def test_names_that_may_go_on_a_certificate():
    for ok in ("pi.lan", "192.168.0.100", "[fd00::1]", "a-b.example.com.", "localhost"):
        assert sslcerts.valid_cert_name(ok), ok
    for bad in ("", "-bad.example", "a..b", "a_b.example", "x" * 254, "pi lan"):
        assert not sslcerts.valid_cert_name(bad), bad
    assert sslcerts.san_token(" 192.168.0.100 ") == "IP:192.168.0.100"
    assert sslcerts.san_token("[fd00::1]") == "IP:fd00::1"
    assert sslcerts.san_token("pi.lan") == "DNS:pi.lan"
    with pytest.raises(sslcerts.SSLCertError, match="Can't put"):
        sslcerts.san_token("a b")


def test_san_entries_and_whether_a_certificate_covers_a_host(openssl, tmp_path):
    crt = tmp_path / "pi.crt"
    crt.write_text(PEM)
    assert sslcerts.subject_alt_names(crt) == ["DNS:pi.lan", "DNS:pi.local", "IP:192.168.0.100", "IP:FD00:0:0:0:0:0:0:1"]
    assert openssl[-1][-2:] == ["-ext", "subjectAltName"]
    assert sslcerts.covers_host(crt, "PI.local.") and sslcerts.covers_host(crt, "[192.168.0.100]")
    assert not sslcerts.covers_host(crt, "other.lan") and not sslcerts.covers_host(tmp_path / "missing.crt", "pi.lan")
    openssl.answers["san"] = (0, "", "")   # no SAN: the CN decides
    assert sslcerts.covers_host(crt, "pi.lan") and not sslcerts.covers_host(crt, "pi.local")


def test_describe_reads_names_and_the_pem_body(openssl, tmp_path):
    crt = tmp_path / "pi.crt"
    crt.write_text("junk before\n" + PEM + "trailing key material\n")
    d = sslcerts.describe_cert(crt)
    assert d["san"] == ["DNS:pi.lan", "DNS:pi.local", "IP:192.168.0.100", "IP:FD00:0:0:0:0:0:0:1"]
    assert d["names"] == ["pi.lan", "pi.local", "192.168.0.100", "FD00:0:0:0:0:0:0:1"] and d["pem"] == PEM
    openssl.answers["san"] = (0, "", "")
    crt.write_text("not pem at all")
    d = sslcerts.describe_cert(crt)
    assert d["names"] == ["pi.lan"] and d["pem"] is None   # CN only, and an unreadable body is None
    with pytest.raises(sslcerts.SSLCertError, match="not a PEM"):
        sslcerts.read_pem(crt)
    openssl.answers["x509"] = (1, "", "bad")
    assert sslcerts.describe_cert(crt) is None


def test_write_self_signed_puts_every_name_in_the_san_and_cleans_up_on_failure(openssl, tmp_path):
    crt, key = tmp_path / "ssl" / "panel.crt", tmp_path / "ssl" / "panel.key"
    with pytest.raises(sslcerts.SSLCertError, match="No names"):
        sslcerts.write_self_signed(crt, key, ["", "  "])
    with pytest.raises(sslcerts.SSLCertError, match="Can't put"):
        sslcerts.write_self_signed(crt, key, ["pi.lan", "bad name"])
    with pytest.raises(sslcerts.SSLCertError, match="Days"):
        sslcerts.write_self_signed(crt, key, ["pi.lan"], days=0)
    sslcerts.write_self_signed(crt, key, ["pi.lan", "pi.lan", "[192.168.0.100]", "pi.local."], days=400)
    argv = openssl[-1]
    assert argv[argv.index("-subj") + 1] == "/CN=pi.lan" and argv[argv.index("-days") + 1] == "400"
    assert "subjectAltName=DNS:pi.lan,IP:192.168.0.100,DNS:pi.local" in argv
    assert crt.read_text() == PEM and key.read_text() == "KEY"
    assert not list(tmp_path.joinpath("ssl").glob("*.tmp"))
    long_name = "x" * 40 + "." + "y" * 30 + ".example.com"   # valid labels (63 max each), over 64 in all
    sslcerts.write_self_signed(crt, key, [long_name, "short.lan"])
    assert openssl[-1][openssl[-1].index("-subj") + 1] == "/CN=short.lan"   # a CN must fit in 64 characters
    openssl.answers["req"] = (1, "", "openssl exploded")
    with pytest.raises(sslcerts.SSLCertError, match="openssl exploded"):
        sslcerts.write_self_signed(crt, key, ["pi.lan"])
    assert crt.read_text() == PEM and not list(tmp_path.joinpath("ssl").glob("*.tmp"))   # the old pair is untouched
