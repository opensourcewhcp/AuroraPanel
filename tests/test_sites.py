"""Apache site settings: validation and the config the panel writes (no Apache needed)."""
import re

import sys

import pytest

from backend import sites

pytestmark = pytest.mark.skipif(not sys.platform.startswith("linux"), reason="Linux paths (the panel runs on a Pi)")


def clean(**kw):
    return sites._clean({"server_name": "example.com", **kw})


def test_defaults():
    s = clean()
    assert s["docroot"] == "/var/www/example.com"
    assert s["ssl"] == "none" and s["aliases"] == []


@pytest.mark.parametrize("name", ["", "not a domain", "exa mple.com", "-bad.com", "a" * 300 + ".com"])
def test_bad_names(name):
    with pytest.raises(sites.SiteError):
        sites._clean({"server_name": name})


def test_ip_site_rules():
    assert sites._clean({"server_name": "192.168.0.100"})["server_name"] == "192.168.0.100"
    with pytest.raises(sites.SiteError):
        sites._clean({"server_name": "192.168.0.100", "www": "force_www"})
    with pytest.raises(sites.SiteError):
        sites._clean({"server_name": "192.168.0.100", "ssl": "letsencrypt"})


@pytest.mark.parametrize("root", ["relative/path", "/var/www/../etc", '/var/www/x"y', "/var/www/<x>"])
def test_bad_docroot(root):
    with pytest.raises(sites.SiteError):
        clean(docroot=root)


def test_force_https_needs_cert():
    with pytest.raises(sites.SiteError):
        clean(force_https=True)


def test_www_alias_added():
    assert clean(www="force_www")["aliases"] == ["www.example.com"]


def test_custom_cannot_break_out_of_vhost():
    with pytest.raises(sites.SiteError):
        clean(custom="</VirtualHost>\n<VirtualHost *:80>")


def test_render_plain_and_https():
    text = sites.render(clean())
    assert "<VirtualHost *:80>" in text and "ServerName example.com" in text and ":443" not in text
    s = clean(ssl="selfsigned", force_https=True, hsts=True)
    text = sites.render(s)
    assert "<VirtualHost *:443>" in text and "SSLEngine on" in text
    assert "RewriteRule ^ https://" in text and "Strict-Transport-Security" in text
    # The settings line round-trips, so the panel can read its own file back.
    mark = next(l for l in text.splitlines() if l.startswith(sites.MARK))
    assert '"server_name":"example.com"' in mark


def test_folder_site_names():
    ok = sites._FOLDER_NAME.match
    assert ok("mysite") and ok("my-site_2") and ok("site.v2")
    assert not ok("../x") and not ok("My Site") and not ok("")
    assert "phpmyadmin" in sites._RESERVED


def test_custom_block_markers_roundtrip():
    block = f"\n    {sites._CX_BEGIN}\n    Header set X-A 1\n    {sites._CX_END}"
    text = "<VirtualHost *:80>\n    ServerName x.test" + block + "\n</VirtualHost>\n"
    assert sites._CX_BLOCK.search(text)
    assert not re.search("X-A", sites._CX_BLOCK.sub("", text))


def test_builtin_ssl_choice_is_remembered(tmp_path):
    """A Custom certificate can be the panel's own self-signed files; the picked option must stick."""
    own = sites.SSL_DIR / "192.168.0.100.crt"
    body = (f"<VirtualHost *:443>\n    ServerName 192.168.0.100\n    SSLEngine on\n"
            f"    SSLCertificateFile {own}\n    SSLCertificateKeyFile {own.with_suffix('.key')}\n</VirtualHost>\n")
    conf = tmp_path / "default-ssl.conf"
    conf.write_text(body)
    assert sites._settings_from_conf(conf)["ssl"] == "selfsigned"  # guessed from the path
    conf.write_text("# aurora-ssl-mode: custom\n" + body)
    assert sites._settings_from_conf(conf)["ssl"] == "custom"


def test_lets_encrypt_email_must_be_reachable():
    # Let's Encrypt rejects addresses on a domain that exists only on the local network.
    from backend.sites import le_email_problem
    assert le_email_problem("") == ""  # optional: certbot registers without an email
    assert le_email_problem("me@gmail.com") == ""
    for bad in ("alert@ns0.local", "a@pi.home.arpa", "x@192.168.0.100", "a@router.lan", "a@box"):
        assert le_email_problem(bad), bad
