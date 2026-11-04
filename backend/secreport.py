"""Security Report — scan what this server owns, score it, and say how to fix each finding.

Targets are only things that live here: the panel under every name it is opened as, every website
on this server (by name and by bare IP), and the mail server. Nothing else is ever scanned.

Every probe connects to this machine itself (127.0.0.1) with the target's name as SNI / Host, so the
result reflects this server's own configuration — not a CDN or proxy in front of it — and works even
for names that don't resolve from the inside (double NAT, hosts-file names, .test sites).

Checks per HTTPS target: certificate (trusted, matches the name, expiry), legacy TLS 1.0/1.1, weak
TLS 1.2 cipher suites, the response headers scanners look at (Server version, X-Frame-Options,
Content-Security-Policy, X-Content-Type-Options, Referrer-Policy, HSTS, X-Powered-By, cookie flags),
and whether plain HTTP redirects to HTTPS. Plus the server's own posture: 2FA, Panel HTTPS, firewall,
Fail2ban, WAF.

Score: 100 minus a deduction per finding (critical 25, high 15, medium 8, low 3), per target and
overall; grades A+ … F. The last report is kept in /var/lib/aurora/secreport.json.
"""
from __future__ import annotations

import html
import ipaddress
import json
import re
import socket
import ssl
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from pathlib import Path
from . import dmarc, jobs, problems, secnet

STATE = Path("/var/lib/aurora/secreport.json")
SITES_ENABLED = Path("/etc/apache2/sites-enabled")
TIMEOUT = 4.0
STRONG = ("ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:"
          "ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:"
          "DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384:DHE-RSA-CHACHA20-POLY1305")
# What scanners call weak: suites without an AEAD cipher (CBC with SHA-1/SHA-2, RC4, 3DES, NULL) or without forward
# secrecy (static RSA key exchange). Offer only those; if the server agrees to one, it accepts weak ciphers.
WEAK_OFFER = "ALL:-AESGCM:-CHACHA20:-AESCCM:-ARIAGCM:kRSA:@SECLEVEL=0"
DEDUCT = {"critical": 25, "high": 15, "medium": 8, "low": 3, "info": 0}
SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


class SecReportError(RuntimeError):
    pass


# ---------------------------------------------------------------- what we own
def _is_ip(s: str) -> bool:
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False


def targets() -> list[dict]:
    """Everything on this server worth checking — never anything else."""
    out: list[dict] = []
    seen: set[str] = set()

    def add(t: dict):
        if t["id"] not in seen:
            seen.add(t["id"]); out.append(t)

    try:
        from . import panelhttps
        st = panelhttps.status("https")
        scheme = "https" if st["enabled"] else "http"
        for n in panelhttps._known_names():
            if n in ("localhost", "127.0.0.1"):
                continue
            add({"id": f"panel:{n}", "kind": "panel", "name": n, "port": st["port"], "scheme": scheme,
                 "label": f"Panel · {n}:{st['port']}", "deep": (st["port"], "") if scheme == "https" and not any(x["kind"] == "panel" for x in out) else None})
    except Exception as quiet_exc:
        problems.quiet(quiet_exc)
    sites = []
    try:
        from . import sites as S
        sites = [s for s in S.list_sites()["sites"] if s.get("enabled")]
    except Exception:
        sites = []
    for s in sites:
        names = [s["server_name"]] + list(s.get("aliases") or [])
        for n in names:
            n = (n or "").lower().strip()
            if not n or n.startswith("*."):
                continue
            add({"id": f"site:{n}", "kind": "site", "name": n, "site": s["server_name"], "system": bool(s.get("system")), "ssl": s.get("ssl", "none"), "force_https": bool(s.get("force_https")),
                 "has_http": bool(s.get("has_http", True)), "conf": s.get("conf"), "label": f"Website · {n}",
                 "deep": (443, "") if n == s["server_name"].lower() and s.get("ssl", "none") != "none" else None})
    if sites:
        try:
            from . import panelhttps
            for ip in [x for x in panelhttps._known_names() if _is_ip(x) and x != "127.0.0.1"]:
                add({"id": f"ip:{ip}", "kind": "ip", "name": ip, "label": f"Web server by address · {ip}"})
        except Exception as quiet_exc:
            problems.quiet(quiet_exc)
    try:
        from . import mail
        ms = mail.load()
        if ms.get("domains") or ms.get("accounts"):
            h = mail.hostname(ms)
            add({"id": f"mail:{h}", "kind": "mail", "name": h, "label": f"Mail server · {h}", "deep": (25, "smtp")})
    except Exception as quiet_exc:
        problems.quiet(quiet_exc)
    add({"id": "network", "kind": "network", "name": socket.gethostname(), "label": "Network services · open ports, SSH, FTP, DNS"})
    for d in mail_domains():
        add({"id": f"dmarc:{d}", "kind": "dmarc", "name": d, "sends": True, "label": f"Email authentication · {d}"})
    for s in sites:
        # DMARC protects the From: domain; a site's subdomain is covered by its organizational domain's record
        d = dmarc.org_domain((s.get("server_name") or "").lower())
        if dmarc.is_public(d) and not s.get("system"):
            add({"id": f"dmarc:{d}", "kind": "dmarc", "name": d, "sends": False, "label": f"Email authentication · {d}"})
    add({"id": "server", "kind": "server", "name": socket.gethostname(), "label": "This server's protections"})
    return out


def mail_domains() -> list[str]:
    try:
        from . import mail
        return sorted(d for d in (mail.load().get("domains") or {}) if dmarc.is_public(d))
    except Exception as quiet_exc:
        problems.quiet(quiet_exc)
        return []


# ---------------------------------------------------------------- probes (all against 127.0.0.1)
def _ctx(verify: bool = False, min_v=None, max_v=None, ciphers: str | None = None) -> ssl.SSLContext:
    ctx = ssl.create_default_context() if verify else ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    if not verify:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    if min_v is not None:
        ctx.minimum_version = min_v
    if max_v is not None:
        ctx.maximum_version = max_v
    if ciphers:
        ctx.set_ciphers(ciphers)
    return ctx


def _handshake(port: int, sni: str, ctx: ssl.SSLContext) -> dict:
    """{'ok', 'version', 'cipher', 'der', 'error', 'verify_code'}"""
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=TIMEOUT) as raw:
            with ctx.wrap_socket(raw, server_hostname=sni if (sni and not _is_ip(sni)) else None) as s:
                return {"ok": True, "version": s.version(), "cipher": (s.cipher() or ("",))[0], "der": s.getpeercert(True)}
    except ssl.SSLCertVerificationError as e:
        return {"ok": False, "error": str(e), "verify_code": getattr(e, "verify_code", None), "verify_message": getattr(e, "verify_message", "")}
    except (OSError, ssl.SSLError, ValueError) as e:
        return {"ok": False, "error": str(e)}


def _cert_details(der: bytes) -> dict:
    """subject, issuer, names, expires (days) — via openssl, which every Pi has."""
    info = {"subject": "", "issuer": "", "names": [], "days": None, "self_signed": None}
    try:
        r = subprocess.run(["openssl", "x509", "-inform", "DER", "-noout", "-subject", "-issuer", "-enddate", "-ext", "subjectAltName"],
                           input=der, capture_output=True, timeout=10)
        for line in r.stdout.decode(errors="replace").splitlines():
            line = line.strip()
            if line.startswith("subject="):
                info["subject"] = line[8:].strip()
            elif line.startswith("issuer="):
                info["issuer"] = line[7:].strip()
            elif line.startswith("notAfter="):
                try:
                    exp = datetime.strptime(line[9:].strip(), "%b %d %H:%M:%S %Y %Z")
                    info["days"] = int((exp - datetime.utcnow()).total_seconds() // 86400)
                except ValueError:
                    pass
            elif "DNS:" in line or "IP Address:" in line:
                info["names"] = [n.split(":", 1)[1].strip() for n in line.split(",") if ":" in n]
        info["self_signed"] = bool(info["subject"]) and info["subject"] == info["issuer"]
    except (OSError, subprocess.TimeoutExpired):
        pass
    return info


def _http(port: int, host: str, tls: bool, path: str = "/") -> dict | None:
    """One GET; returns {'status', 'headers': {lower: value}, 'cookies': [..], 'body': str, 'length': int}
    or None if nothing answered. The body is read up to 64 KB."""
    req = (f"GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: AuroraPanel-SecurityReport\r\n"
           f"Accept: text/html,*/*\r\nConnection: close\r\n\r\n").encode()
    buf = b""
    try:
        raw = socket.create_connection(("127.0.0.1", port), timeout=TIMEOUT)
        s = _ctx().wrap_socket(raw, server_hostname=host if not _is_ip(host) else None) if tls else raw
        with s:
            s.sendall(req)
            while len(buf) < 65536:
                chunk = s.recv(16384)
                if not chunk:
                    break
                buf += chunk
    except (OSError, ssl.SSLError, ValueError):
        if not buf:
            return None
    head_b, _, raw_body = buf.partition(b"\r\n\r\n")
    head = head_b.decode("latin-1")
    lines = head.split("\r\n")
    m = re.match(r"HTTP/\d\.\d (\d{3})", lines[0] if lines else "")
    if not m:
        return None
    headers: dict[str, str] = {}
    cookies: list[str] = []
    for ln in lines[1:]:
        if ":" not in ln:
            continue
        k, v = ln.split(":", 1)
        k, v = k.strip().lower(), v.strip()
        if k == "set-cookie":
            cookies.append(v)
        else:
            headers[k] = v
    if headers.get("transfer-encoding", "").lower() == "chunked":
        raw_body = _dechunk(raw_body)
    return {"status": int(m.group(1)), "headers": headers, "cookies": cookies, "body": raw_body.decode("utf-8", "replace"), "length": len(raw_body)}


def _dechunk(b: bytes) -> bytes:
    out = b""
    while b:
        size, _, rest = b.partition(b"\r\n")
        try:
            n = int(size.split(b";")[0].strip() or b"0", 16)
        except ValueError:
            return out + b
        if n == 0:
            break
        out += rest[:n]
        b = rest[n + 2:]
    return out


# ---------------------------------------------------------------- findings
def _f(sev: str, title: str, detail: str, fix: str = "", view: str = "", action: str = "", fid: str = "", cat: str = "") -> dict:
    out = {"severity": sev, "title": title, "detail": detail, "fix": fix, "view": view, "action": action, "id": fid or re.sub(r"\W+", "-", title.lower()).strip("-")}
    if cat:
        out["cat"] = cat
    return out


def _tls_findings(port: int, name: str, kind: str, fix_view: str, fix_action: str) -> tuple[list[dict], dict]:
    """Certificate + protocol + cipher findings for one TLS endpoint. Returns (findings, facts)."""
    out: list[dict] = []
    facts: dict = {}
    base = _handshake(port, name, _ctx())
    if not base["ok"]:
        return [_f("info", "No TLS on this port", f"Nothing answered TLS on port {port} ({base.get('error', '')[:80]}).", fid="no-tls")], {"reachable": False}
    facts.update({"reachable": True, "version": base["version"], "cipher": base["cipher"]})
    cert = _cert_details(base["der"])
    facts["cert"] = cert
    # trusted + matching?
    ver = _handshake(port, name, _ctx(verify=True)) if not _is_ip(name) else {"ok": False, "verify_code": None}
    from . import panelhttps
    matches = panelhttps.covers(cert["names"], name) if cert["names"] else False
    facts["matches"] = matches
    facts["trusted"] = bool(ver.get("ok"))
    if not matches:
        if kind == "ip":
            out.append(_f("info", "Certificate is not for this IP address",
                          f"Opening https://{name}/ shows the certificate of “{(cert['names'] or [cert['subject']])[0]}”. Normal for a server that hosts named websites: "
                          "visitors use the site name, scanners pointed at the bare address report a host-name mismatch.", "Use the website's name, not the address.", fid="cert-ip"))
        else:
            out.append(_f("high", "Certificate does not match the host name",
                          f"The certificate is valid for {', '.join(cert['names'][:6]) or cert['subject'] or 'unknown names'}, not for {name}. Browsers and scanners report a host-name mismatch.",
                          "Panel HTTPS → New certificate (it includes every name this server is opened as)." if kind == "panel" else
                          "Domains → the site → SSL: issue a certificate for this name (Let's Encrypt) or regenerate the self-signed one.",
                          fix_view, fix_action if kind == "panel" else "", fid="cert-mismatch"))
    if cert["self_signed"]:
        by_ip = kind == "ip" or _is_ip(name)
        who = "mail apps" if kind == "mail" else "browsers"
        if kind == "panel":
            out.append(_f("low", "Self-signed certificate", f"Encrypted, but {who} warn about it and nothing vouches for the name.",
                          "Fine for a panel used on your own network. For a public site or mail, get a Let's Encrypt certificate (AutoSSL).", fix_view, fid="self-signed"))
        elif by_ip:
            out.append(_f("low", "Self-signed certificate", f"Encrypted, but {who} warn about it. No public authority issues certificates for a bare IP address, so by address this is as good as it gets.",
                          "Give the server a name — a domain, or a free Dynamic DNS one — add it as a website, and AutoSSL gets it a trusted certificate.", "autossl", fid="self-signed"))
        else:
            out.append(_f("medium", "Self-signed certificate", f"Encrypted, but {who} warn about it and nothing vouches for the name.",
                          "Get a free Let's Encrypt certificate (AutoSSL). The name must point at this server and port 80 must be reachable from the internet.", "autossl", fid="self-signed"))
    elif not ver.get("ok") and not _is_ip(name) and matches:
        out.append(_f("medium", "Certificate is not trusted", f"Verification failed: {ver.get('verify_message') or ver.get('error', '')[:120]}.",
                      "Check the chain (fullchain.pem) and the issuer.", fix_view, fid="untrusted"))
    if cert["days"] is not None:
        if cert["days"] < 0:
            out.append(_f("critical", "Certificate has expired", f"Expired {-cert['days']} days ago.", "Renew it now (AutoSSL / Domains → SSL).", "autossl", fid="expired"))
        elif cert["days"] < 14:
            out.append(_f("high", "Certificate expires soon", f"{cert['days']} days left.", "Renew it (AutoSSL renews Let's Encrypt certificates automatically).", "autossl", fid="expiring"))
    # legacy protocols
    legacy = []
    for label, v in (("TLS 1.0", ssl.TLSVersion.TLSv1), ("TLS 1.1", ssl.TLSVersion.TLSv1_1)):
        try:
            r = _handshake(port, name, _ctx(min_v=v, max_v=v, ciphers="ALL:@SECLEVEL=0"))
        except ssl.SSLError:
            r = {"ok": False}
        if r.get("ok"):
            legacy.append(label)
    facts["legacy"] = legacy
    if legacy:
        out.append(_f("high", f"Obsolete {' and '.join(legacy)} accepted", "These versions have known weaknesses and every current browser dropped them.",
                      "Allow only TLS 1.2 and 1.3.", fix_view, fix_action, fid="legacy-tls"))
    # weak TLS 1.2 ciphers
    try:
        w = _handshake(port, name, _ctx(max_v=ssl.TLSVersion.TLSv1_2, ciphers=WEAK_OFFER))
    except ssl.SSLError:
        w = {"ok": False}
    facts["weak_cipher"] = w.get("cipher") if w.get("ok") else None
    if w.get("ok"):
        c = w["cipher"]
        bad = re.search(r"RC4|DES|NULL|EXPORT|MD5|anon", c, re.I)
        if kind == "mail":
            out.append(_f("high" if bad else "info", "Weak cipher suites supported in TLS 1.2",
                          f"The server agreed to {c}. Mail servers keep broader cipher support on purpose, so other mail servers can still deliver to you; "
                          "AuroraPanel leaves this alone. TLS 1.0/1.1 are already off.", fid="weak-ciphers"))
        else:
            out.append(_f("high" if bad else "medium", "Weak cipher suites supported in TLS 1.2",
                          f"The server agreed to {c}. Suites with CBC, SHA-1, RC4, 3DES or without forward secrecy are flagged by every scanner.",
                          "Allow only modern suites (Mozilla's intermediate list).", fix_view, fix_action, fid="weak-ciphers"))
    for x in out:
        x.setdefault("cat", "tls")
    return out, facts


def _vhost_tls_override(conf: str) -> str:
    """Name of the site conf that sets its own SSLCipherSuite / SSLProtocol (which beats the server-wide setting), or ''."""
    for c in ([conf] if conf else []) + ["default-ssl.conf", "000-default.conf"]:
        p = SITES_ENABLED / c
        try:
            if p.is_file() and re.search(r"(?im)^\s*SSL(CipherSuite|Protocol)\s", p.read_text(errors="replace")):
                return c
        except OSError:
            continue
    return ""


def _header_findings(resp: dict, kind: str, fix_view: str, fix_action: str, https: bool) -> list[dict]:
    h, out = resp["headers"], []
    srv = h.get("server", "")
    if re.search(r"\d", srv):
        out.append(_f("medium", "Server header exposes the version", f"“Server: {srv}” tells attackers exactly what to look up exploits for.",
                      "Hide it (Apache: ServerTokens Prod).", fix_view, fix_action, fid="server-header"))
    if h.get("x-powered-by"):
        out.append(_f("low", "X-Powered-By exposes the stack", f"“X-Powered-By: {h['x-powered-by']}”.", "PHP Settings → expose_php off (or remove the header).", "phpsettings", fid="x-powered-by"))
    xfo = h.get("x-frame-options", "").upper()
    csp = h.get("content-security-policy", "")
    if "frame-ancestors" not in csp and xfo not in ("DENY", "SAMEORIGIN"):
        out.append(_f("medium", "X-Frame-Options is not deny or sameorigin", "Other sites can show this page in a frame (clickjacking).",
                      "Send X-Frame-Options: SAMEORIGIN.", fix_view, fix_action, fid="x-frame-options"))
    if not csp:
        out.append(_f("medium", "CSP is not implemented", "No Content-Security-Policy header: more exposure to cross-site scripting and clickjacking.",
                      "At least frame-ancestors 'self'; a full policy is best set by the application.", fix_view, fix_action, fid="csp"))
    else:
        weak = csp_weaknesses(csp)
        if weak:
            out.append(_f("medium", "Content-Security-Policy is incomplete", "Scanners (OWASP ZAP) report: " + "; ".join(weak) + ".",
                          "A full policy depends on what the site loads, so it belongs in the application or the site's Advanced directives "
                          "(e.g. default-src 'self'; form-action 'self'; object-src 'none'). If the site needs inline scripts, Accept this finding.",
                          fix_view, fid="csp-weak"))
    if h.get("x-content-type-options", "").lower() != "nosniff":
        out.append(_f("medium", "X-Content-Type-Options is not nosniff", "Browsers may guess a different content type than declared (MIME confusion).",
                      "Send X-Content-Type-Options: nosniff.", fix_view, fix_action, fid="nosniff"))
    if not h.get("referrer-policy"):
        out.append(_f("low", "Referrer-Policy missing", "Full URLs of this site are sent to other sites as the referrer.",
                      "Send Referrer-Policy: strict-origin-when-cross-origin.", fix_view, fix_action, fid="referrer-policy"))
    if https and kind == "site" and not h.get("strict-transport-security"):
        out.append(_f("low", "HSTS not set", "Without Strict-Transport-Security a first visit over http:// can be intercepted.",
                      "Domains → the site → HSTS (only once HTTPS is known to work).", "vhosts", fid="hsts"))
    for c in resp["cookies"]:
        name = c.split("=", 1)[0].strip()
        flags = c.lower()
        missing = [f for f, ok in (("Secure", "secure" in flags or not https), ("HttpOnly", "httponly" in flags), ("SameSite", "samesite=" in flags)) if not ok]
        if missing:
            out.append(_f("low", f"Cookie “{name}” without {' / '.join(missing)}",
                          "Cookies without these flags can leak over http://, be read by scripts, or be sent along with requests other sites trigger (CSRF).",
                          "Set the flags in the application (Secure; HttpOnly; SameSite=Lax).", fid=f"cookie-{name}"))
            break
    body = resp.get("body") or ""
    if "text/html" in h.get("content-type", "text/html") and _forms_without_token(body):
        out.append(_f("low", "Form without an anti-CSRF token", "A POST form on this page has no hidden token field, so another site could submit it "
                      "on a signed-in visitor's behalf (ZAP: “Absence of Anti-CSRF Tokens”). Public forms like comments are often fine.",
                      "Use the application's CSRF protection; WordPress and most frameworks add a nonce field to their own forms.", fid="csrf"))
    for x in out:
        x.setdefault("cat", "web")
    return out


CSP_NO_FALLBACK = ("form-action", "frame-ancestors")
CSP_FETCH = ("script-src", "style-src", "img-src", "connect-src", "frame-src", "font-src", "media-src", "object-src", "manifest-src", "worker-src")


def csp_weaknesses(csp: str) -> list[str]:
    """What ZAP's CSP rules flag in a policy, one phrase each."""
    d: dict[str, str] = {}
    for part in csp.split(";"):
        bits = part.strip().split(None, 1)
        if bits:
            d.setdefault(bits[0].lower(), bits[1].lower() if len(bits) > 1 else "")
    out = []
    nofb = [x for x in CSP_NO_FALLBACK if x not in d]
    if nofb:
        out.append(f"{', '.join(nofb)} not defined (no fallback to default-src)")
    default = d.get("default-src")
    loose = [x for x in CSP_FETCH if (d.get(x, default) is None) or re.search(r"(^|\s)(\*|https?:|data:)(\s|$)", d.get(x, default) or "")]
    if loose:
        out.append(f"wildcard or undefined: {', '.join(loose)}")
    for x in ("script-src", "style-src"):
        if "'unsafe-inline'" in (d.get(x, default) or ""):
            out.append(f"{x} allows 'unsafe-inline'")
    if "'unsafe-eval'" in (d.get("script-src", default) or ""):
        out.append("script-src allows 'unsafe-eval'")
    return out


_FORM = re.compile(r"<form\b([^>]*)>(.*?)</form>", re.I | re.S)
_TOKEN = re.compile(r"<input[^>]+type\s*=\s*[\"']?hidden[^>]*name\s*=\s*[\"']?[^\"'>]*(csrf|xsrf|token|nonce|authenticity)", re.I)


def _forms_without_token(body: str) -> bool:
    for attrs, inner in _FORM.findall(body or ""):
        if re.search(r"method\s*=\s*[\"']?post", attrs, re.I) and not _TOKEN.search(inner):
            return True
    return False


_BANNER = re.compile(r"\b(Apache|nginx|LiteSpeed|Microsoft-IIS|lighttpd|OpenResty|Caddy)/\d[\w.]*", re.I)


def _extra_web_findings(port: int, name: str, tls: bool, fix_view: str, fix_action: str) -> list[dict]:
    """Version banner on an error page (ZAP: “In Page Banner Information Leak”)."""
    r = _http(port, name, tls, "/aurora-security-report-check-404")
    if r and _BANNER.search(r.get("body") or ""):
        return [_f("low", "Error pages show the server version", f"An error page says “{_BANNER.search(r['body']).group(0)}” in its text.",
                   "One click: Harden web server (ServerSignature Off).", fix_view, fix_action, fid="banner", cat="web")]
    return []


def _big_redirect(resp: dict) -> dict | None:
    """ZAP's “Big Redirect Detected”: a redirect whose body is larger than the Location URL plus 300 bytes."""
    loc = resp["headers"].get("location", "")
    if resp["status"] in (301, 302, 303, 307, 308) and loc and resp.get("length", 0) > len(loc) + 300:
        return _f("low", "Redirect carries a page of content", f"The redirect to {loc} also sends {resp['length']} bytes of content. "
                  "Redirects should be almost empty; extra content can leak what the target page shows.",
                  "One click: Harden web server (no signature on server pages). If the application sends it, fix it there.",
                  "vhosts", "apache_harden", fid="big-redirect", cat="web")
    return None


def _scan_target(t: dict, deep: bool = False) -> dict:
    kind, name = t["kind"], t["name"]
    findings: list[dict] = []
    facts: dict = {}
    findings += _scan_kind(t, kind, name, facts)
    if deep and t.get("deep"):
        port, starttls = t["deep"]
        findings += secnet.testssl(name, port, starttls)
        facts["testssl"] = True
    cat = {"network": "network", "server": "server", "dmarc": "email"}.get(kind, "web")
    for x in findings:
        x.setdefault("cat", cat)
    # de-duplicate (http and https runs can repeat a header finding)
    seen, uniq = set(), []
    for x in findings:
        if x["id"] not in seen:
            seen.add(x["id"]); uniq.append(x)
    uniq.sort(key=lambda x: SEV_ORDER.get(x["severity"], 9))
    score = max(0, 100 - sum(DEDUCT.get(x["severity"], 0) for x in uniq))
    return {**{k: v for k, v in t.items()}, "findings": uniq, "facts": facts, "score": score, "grade": grade(score)}


def _scan_kind(t: dict, kind: str, name: str, facts: dict) -> list[dict]:
    findings: list[dict] = []
    if kind == "panel":
        port = t["port"]
        if t["scheme"] != "https":
            findings.append(_f("critical", "Panel without HTTPS", "Your password and login cookie travel in clear text.", "Turn on Panel HTTPS.", "panelhttps", fid="panel-http"))
            r = _http(port, name, False)
            if r:
                findings += _header_findings(r, kind, "panelhttps", "", False)
        else:
            f, fa = _tls_findings(port, name, kind, "panelhttps", "panel_regen")
            facts.update(fa)
            findings += f
            r = _http(port, name, True)
            if r:
                findings += _header_findings(r, kind, "panelhttps", "panel_harden", True)
                findings += _extra_web_findings(port, name, True, "panelhttps", "panel_harden")
    elif kind in ("site", "ip"):
        has_tls = _handshake(443, name, _ctx())["ok"]
        if has_tls:
            f, fa = _tls_findings(443, name, kind, "vhosts", "apache_harden")
            facts.update(fa)
            over = _vhost_tls_override(t.get("conf", "") if kind == "site" else "")
            site_key = t.get("site") or name
            for x in f:
                if x["id"] in ("weak-ciphers", "legacy-tls") and over:
                    x["detail"] += f" This site's own configuration ({over}) sets SSLCipherSuite / SSLProtocol itself, which overrides the server-wide “Modern TLS only” setting."
                    x["fix"] = f"One click: switch those lines off in {over} (backed up) so the server-wide modern TLS applies here too."
                    x["action"] = f"vhost_tls:{over}"
                if x["id"] == "self-signed" and kind == "site" and not _is_ip(name) and not t.get("system"):
                    x["action"] = f"autossl_run:{site_key}"
            findings += f
            r = _http(443, name, True)
            if r:
                hf = _header_findings(r, kind, "vhosts", "apache_harden", True)
                # HSTS is only honoured over a trusted certificate: with a self-signed one browsers drop the header,
                # and setting it would lock visitors out of a site whose certificate they can't bypass. Not a finding then.
                untrusted = (facts.get("cert") or {}).get("self_signed") or not facts.get("trusted")
                for x in list(hf):
                    if x["id"] == "hsts":
                        if untrusted or kind == "ip" or t.get("system"):
                            hf.remove(x)
                        else:
                            x["action"] = f"hsts:{site_key}"
                findings += hf
                findings += _extra_web_findings(443, name, True, "vhosts", "apache_harden")
        plain = _http(80, name, False)
        if plain:
            loc = plain["headers"].get("location", "")
            big = _big_redirect(plain)
            if big:
                findings.append(big)
            if has_tls and not (plain["status"] in (301, 302, 307, 308) and loc.lower().startswith("https://")):
                if kind == "site":
                    findings.append(_f("medium", "HTTP is not redirected to HTTPS", f"http://{name}/ answers {plain['status']} instead of sending visitors to https://.",
                                       "One click: Force HTTPS (a 301 to https:// on every http:// visit).", "vhosts", f"force_https:{t.get('site') or name}", fid="no-redirect"))
                findings += _header_findings(plain, kind, "vhosts", "apache_harden", False)
            elif not has_tls and kind == "site":
                findings.append(_f("high", "No HTTPS", "The site is served over plain HTTP only.", "Domains → the site → SSL: Let's Encrypt (AutoSSL) or a self-signed certificate.", "vhosts", fid="no-https"))
                findings += _header_findings(plain, kind, "vhosts", "apache_harden", False)
        elif not has_tls:
            findings.append(_f("info", "Nothing answered", "Neither port 80 nor 443 answered for this name on this server.", fid="silent"))
    elif kind == "mail":
        for port, label in ((465, "SMTP submission (465)"), (993, "IMAP (993)")):
            f, fa = _tls_findings(port, name, kind, "email", "")
            for x in f:
                x["title"] = f"{label}: {x['title']}"
                x["id"] = f"{port}-{x['id']}"
                if x["id"].endswith("self-signed") and not _is_ip(name):
                    x["action"] = f"autossl_run:{name}"  # AutoSSL covers the mail name too (and switches Postfix/Dovecot to it)
            findings += f
            facts[str(port)] = fa
        findings += secnet.mail_anon_findings()
    elif kind == "network":
        f, fa = secnet.scan()
        findings += f
        facts.update(fa)
    elif kind == "dmarc":
        findings += _dmarc_findings(t, facts)
    elif kind == "server":
        findings += _posture()
    return findings


def _dmarc_findings(t: dict, facts: dict) -> list[dict]:
    d = t["name"]
    live = dmarc.live_records(d)
    sends = t.get("sends", False)
    a = dmarc.assess(d, dmarc.parse(live["record"]), live["spf"], live["dkim"], sends, live["parent"])
    facts.update({"record": live["record"] or live["parent"], "inherited": bool(live["parent"] and not live["record"]), "spf": live["spf"],
                  "dkim": live["dkim"], "level": a["level"], "dmarc_grade": a["grade"]})
    here = live.get("here", False)
    out = []
    for x in a["findings"]:
        wiz = x["id"].startswith("dmarc")
        if wiz:
            action = f"dmarc_step:{d}" if here and x["id"] != "dmarc-inherited" else f"dmarc_wizard:{d}"
        elif here and sends and x["id"].startswith(("spf", "dkim")):
            action = f"mail_dns:{x['id'].split('-')[0]}:{d}"
        else:
            action = ""
        fix = x["fix"] + (" One click publishes it in this server's DNS zone." if action and not action.startswith("dmarc_wizard") else "")
        out.append(_f(x["severity"], x["title"], x["detail"], fix, "dmarc" if wiz else "deliverability", action, fid=x["id"], cat="email"))
    if live.get("propagating"):
        out.append(_f("info", "DNS caches still hold the old record",
                      f"This server already answers with the new record; resolvers that looked it up earlier keep the old answer until it expires (up to an hour).",
                      "Nothing to do, it clears by itself.", "dmarc", fid="dmarc-propagating", cat="email"))
    return out


def _posture() -> list[dict]:
    out = []
    def chk(fn):
        try:
            return fn()
        except Exception as quiet_exc:
            problems.quiet(quiet_exc)
            return None
    from . import twofa
    if not chk(twofa.is_enabled):
        out.append(_f("medium", "Two-factor sign-in is off", "A leaked or guessed password is enough to get in.", "Security → Enable 2FA.", "security", fid="2fa"))
    from . import panelhttps
    ph = chk(lambda: panelhttps.status("https"))
    if ph and not ph["enabled"]:
        out.append(_f("critical", "Panel HTTPS is off", "Your password and cookie travel in clear text.", "Security → Panel HTTPS → Turn on.", "panelhttps", fid="panel-https"))
    elif ph and not ph.get("hardened"):
        out.append(_f("low", "Panel TLS not hardened yet", "The panel still accepts older cipher suites and sends a Server header.",
                      "Panel HTTPS → Harden (strong ciphers only, no Server header).", "panelhttps", "panel_harden", fid="panel-ciphers"))
    from . import firewall
    fw = chk(firewall.status)
    if fw and fw.get("available") and not fw.get("active"):
        out.append(_f("medium", "Firewall (ufw) is inactive", "Every listening port is reachable.", "One click: enable ufw — SSH and the panel port are allowed first, so nothing locks you out.", "firewall", "ufw_enable", fid="ufw"))
    from . import fail2ban
    f2 = chk(fail2ban.status)
    if f2 is not None and not (f2.get("installed") and f2.get("active")):
        out.append(_f("medium", "Fail2ban is not running", "Password guessing on SSH, mail and the panel goes unpunished.", "Security → Fail2ban.", "leech", fid="fail2ban"))
    from . import waf
    w = chk(waf.status)
    if w is not None and w.get("installed") and w.get("mode", "off") == "off":
        out.append(_f("medium", "WAF is off", "ModSecurity is installed but not protecting your sites.", "Security → WAF Firewall → Blocking.", "modsec", fid="waf-off"))
    # October 2026: the private keys of eight eMudhra (emSign) intermediate CAs were recoverable from their certificates.
    # Browsers and Debian's ca-certificates distrust "emSign ECC Root CA - G3"; a trust store that still has it lets a
    # forged certificate pass for curl, Python, apt and mail on this server (OpenSSL doesn't check revocation lists).
    if emsign_trusted():
        out.append(_f("high", "Compromised certificate authority still trusted", "emSign ECC Root CA - G3 (eMudhra) is in this server's trust store although its "
                      "intermediate CA keys were recovered by researchers in October 2026.", "One click: distrust it (what the browsers and Debian's update do).",
                      "sysapps", "ca_distrust", fid="emsign-g3"))
    try:
        from . import appconfig
        ah = appconfig.apache_hardening()
        if ah.get("available") and ah["ok"] < ah["total"]:
            miss = ", ".join(i["label"] for i in ah["items"] if not i["ok"])
            out.append(_f("medium", "Web server not fully hardened", f"Missing: {miss}.", "One click: Harden web server.", "sysapps", "apache_harden", fid="apache-harden"))
    except Exception as quiet_exc:
        problems.quiet(quiet_exc)
    return out


CA_CONF = Path("/etc/ca-certificates.conf")
EMSIGN_G3 = "mozilla/emSign_ECC_Root_CA_-_G3.crt"


def emsign_trusted() -> bool:
    try:
        conf = CA_CONF.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return False
    return any(line.strip() == EMSIGN_G3 for line in conf.splitlines())


def distrust_emsign() -> dict:
    """Comment the root out the Debian way ("!" prefix) and rebuild /etc/ssl/certs."""
    if not emsign_trusted():
        return {"changed": False}
    conf = CA_CONF.read_text(encoding="utf-8", errors="replace")
    conf = "\n".join(("!" + EMSIGN_G3) if line.strip() == EMSIGN_G3 else line for line in conf.splitlines()) + "\n"
    CA_CONF.write_text(conf, encoding="utf-8")
    r = subprocess.run(["update-ca-certificates"], capture_output=True, text=True, timeout=120)
    if r.returncode != 0:
        raise SecReportError((r.stderr or r.stdout).strip()[-300:] or "update-ca-certificates failed")
    return {"changed": True}


def fix(action: str) -> dict:
    """The one-click fixes offered next to findings. `kind[:argument]` — see the frontend's FIX_LABEL."""
    kind, _, arg = action.partition(":")
    try:
        if kind == "apache_harden":
            from . import appconfig
            appconfig.apache_harden()
            msg = "Web server hardened: version hidden, security headers on every site, modern TLS only"
        elif kind == "panel_harden":
            from . import panelhttps
            panelhttps.harden()
            msg = "Panel restarting with strong ciphers and the http → https redirect"
        elif kind == "ufw_enable":
            from . import firewall
            r = firewall.set_enabled(True)
            msg = ("Firewall on. Kept open because they were already serving: " + ", ".join(r.get("preallowed") or [])
                   + ". Everything else is blocked now — trim the list under Security → Firewall.")
        elif kind == "vhost_tls":
            from . import appconfig
            r = appconfig.strip_vhost_tls(arg)
            msg = (f"{arg}: {r['changed']} cipher/protocol line{'s' if r['changed'] != 1 else ''} switched off — the server-wide modern TLS applies now"
                   if r["changed"] else f"{arg} has no cipher lines of its own — the server-wide modern TLS applies")
        elif kind == "autossl_run":
            from . import autossl
            autossl.start(True, arg)
            msg = f"Requesting a Let's Encrypt certificate for {arg} — it takes 1–4 minutes; the result shows under Security → AutoSSL. Run the report again afterwards."
        elif kind == "hsts":
            from . import sites
            sites.quick_toggle(arg, "hsts", True)
            msg = f"HSTS on for {arg}"
        elif kind == "force_https":
            from . import sites
            sites.quick_toggle(arg, "force_https", True)
            msg = f"Force HTTPS on for {arg}"
        elif kind == "ca_distrust":
            r = distrust_emsign()
            msg = "emSign ECC Root CA - G3 is no longer trusted on this server" if r["changed"] else "It was already distrusted"
        elif kind == "dmarc_step":
            msg = dmarc.step(arg)["message"]
        elif kind == "mail_dns":
            what, _, dom = arg.partition(":")
            from . import mail
            mail.install_record(dom, what)
            msg = f"{what.upper()} record for {dom} published in this server's DNS zone"
        elif kind in secnet.FIXES:
            msg = secnet.FIXES[kind]()["message"]
        elif kind == "port_lan":
            msg = secnet.port_lan_fix(arg)["message"]
        else:
            raise SecReportError("Unknown fix")
    except (SecReportError, secnet.SecNetError) as e:
        raise SecReportError(str(e))
    except Exception as e:
        raise SecReportError(str(e) or e.__class__.__name__)
    return {"ok": True, "message": msg}


def grade(score: int) -> str:
    return "A+" if score >= 97 else "A" if score >= 90 else "B" if score >= 80 else "C" if score >= 65 else "D" if score >= 50 else "F"


# ---------------------------------------------------------------- run / store
ACCEPTED = Path("/var/lib/aurora/secreport-accepted.json")
HISTORY = Path("/var/lib/aurora/secreport-history.json")
HISTORY_MAX = 60
# What each one-click fix does, shown in the "Apply fixes" list after a report. caution: shown in the
# list and the fix starts unticked, because it changes how people or programs connect.
FIX_INFO = {
    "apache_harden": {"label": "Harden web server", "what": "Hide the Apache version, add the security headers to every site, allow only modern TLS."},
    "panel_harden": {"label": "Harden panel TLS", "what": "Strong ciphers only and no Server header for this panel. The panel restarts, the page reloads by itself.", "last": True},
    "ufw_enable": {"label": "Enable firewall", "what": "Turn ufw on. Every port that serves something now stays open, so nothing stops working."},
    "vhost_tls": {"label": "Use server-wide TLS", "what": "Switch off a site's own cipher and protocol lines (backed up) so the modern server-wide TLS applies."},
    "autossl_run": {"label": "Get Let's Encrypt certificate", "what": "Request a free trusted certificate. The name must point at this server and port 80 must be reachable from the internet."},
    "hsts": {"label": "Turn on HSTS", "what": "Tell browsers to only ever use HTTPS for this site."},
    "force_https": {"label": "Force HTTPS", "what": "Send every http:// visit to https:// (301)."},
    "ca_distrust": {"label": "Distrust it", "what": "Remove the compromised emSign root from this server's trust store."},
    "ssh_crypto": {"label": "Strong SSH algorithms only", "what": "Offer only strong SSH ciphers, MACs and key exchanges. Tested with sshd -t; open sessions stay connected.",
                   "caution": "Very old SSH clients (before 2015) may no longer connect."},
    "timestamps_off": {"label": "Hide timestamps", "what": "Switch TCP timestamps off and drop ICMP timestamp requests in the firewall."},
    "mail_anon_off": {"label": "No anonymous TLS for mail", "what": "Exclude anonymous and weak cipher suites in Postfix, then reload it."},
    "ftp_tls": {"label": "Require FTPS", "what": "FTP logins and transfers must use TLS.",
                "caution": "FTP clients must connect with “explicit FTP over TLS” afterwards."},
    "port_lan": {"label": "Local network only", "what": "Allow this port only from your local network (10.x, 172.16-31.x, 192.168.x) and block it from the internet.",
                 "caution": "Anyone using it from outside your network (or over a VPN with another range) loses access."},
    "dmarc_step": {"label": "Tighten DMARC", "what": "Publish the next DMARC step in this server's DNS zone: monitoring becomes quarantine, quarantine becomes reject, with reports switched on.",
                   "caution": "Mail that fails SPF and DKIM goes to spam (quarantine) or is refused (reject). Senders outside this server must be in SPF first.", "last": True},
    "mail_dns": {"label": "Publish mail record", "what": "Write the SPF or DKIM record this server's mail needs into its DNS zone (replacing an old one)."},
    "dmarc_wizard": {"label": "Set up DMARC", "what": "Open the DMARC wizard for this domain.", "interactive": True},
    "panel_regen": {"label": "New panel certificate", "what": "Open Panel HTTPS to make a certificate that covers every name.", "interactive": True},
}


def _load_json(p: Path, default):
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return default


def _save_json(p: Path, data) -> None:
    try:
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(data), encoding="utf-8")
    except OSError as quiet_exc:
        problems.quiet(quiet_exc)


def finalize(rep: dict, accepted: dict | None = None) -> dict:
    """Mark accepted findings, then (re)compute every score, the counts and the fix plan from what is left."""
    accepted = _load_json(ACCEPTED, {}) if accepted is None else accepted
    counts = {k: 0 for k in SEV_ORDER}
    counts["accepted"] = 0
    cats: dict[str, int] = {}
    for t in rep["targets"]:
        for f in t["findings"]:
            f["key"] = f"{t['id']}|{f['id']}"
            f["accepted"] = accepted.get(f["key"])
            if f["accepted"]:
                counts["accepted"] += 1
                continue
            counts[f["severity"]] = counts.get(f["severity"], 0) + 1
            if f["severity"] != "info":
                cats[f.get("cat", "web")] = cats.get(f.get("cat", "web"), 0) + 1
        live = [f for f in t["findings"] if not f.get("accepted")]
        t["score"] = max(0, 100 - sum(DEDUCT.get(f["severity"], 0) for f in live))
        t["grade"] = grade(t["score"])
    results = rep["targets"]
    # overall = the average of what's exposed; the server's own posture pulls it down at half weight
    exposed = [r for r in results if r["kind"] != "server"]
    srv = next((r for r in results if r["kind"] == "server"), None)
    overall = round(sum(r["score"] for r in exposed) / len(exposed)) if exposed else (srv["score"] if srv else 100)
    if srv and exposed:
        overall = max(0, overall - (100 - srv["score"]) // 2)
    weakest = min(results, key=lambda r: r["score"]) if results else None
    plan: dict[str, dict] = {}
    for t in results:
        for f in t["findings"]:
            a = f.get("action")
            if not a or f.get("accepted"):
                continue
            info = FIX_INFO.get(a.split(":", 1)[0], {"label": "Fix", "what": ""})
            p = plan.setdefault(a, {"action": a, "label": info["label"], "what": info["what"], "caution": info.get("caution", ""),
                                    "interactive": bool(info.get("interactive")), "last": bool(info.get("last")),
                                    "arg": a.split(":", 1)[1] if ":" in a else "", "resolves": [], "worst": "info"})
            if f["title"] not in p["resolves"]:
                p["resolves"].append(f["title"])
            if SEV_ORDER.get(f["severity"], 9) < SEV_ORDER.get(p["worst"], 9):
                p["worst"] = f["severity"]
    rep.update({"score": overall, "grade": grade(overall), "counts": counts, "cats": cats, "weakest": weakest["id"] if weakest else None,
                "fixes": sorted(plan), "fix_plan": sorted(plan.values(), key=lambda p: (p["interactive"], p["last"], SEV_ORDER.get(p["worst"], 9), p["label"]))})
    return rep


def _history(rep: dict, prev: dict | None) -> None:
    """first_seen per finding, findings resolved since the last report, and the score trend."""
    h = _load_json(HISTORY, {"runs": [], "first_seen": {}})
    seen = h.setdefault("first_seen", {})
    scanned = {t["id"] for t in rep["targets"]}
    now_keys = set()
    for t in rep["targets"]:
        for f in t["findings"]:
            k = f"{t['id']}|{f['id']}"
            now_keys.add(k)
            f["first_seen"] = seen.setdefault(k, rep["ts"])
            f["new"] = bool(prev) and f["first_seen"] == rep["ts"]
    for k in [k for k in seen if k.split("|", 1)[0] in scanned and k not in now_keys]:
        del seen[k]
    resolved = []
    for t in (prev or {}).get("targets", []):
        if t["id"] not in scanned:
            continue
        for f in t["findings"]:
            if f"{t['id']}|{f['id']}" not in now_keys and f["severity"] != "info":
                resolved.append({"target": t["label"], "title": f["title"], "severity": f["severity"]})
    rep["resolved"] = resolved
    h["runs"] = (h.get("runs", []) + [{"ts": rep["ts"], "score": rep["score"], "grade": rep["grade"], "counts": rep["counts"]}])[-HISTORY_MAX:]
    _save_json(HISTORY, h)


def history() -> list[dict]:
    return _load_json(HISTORY, {}).get("runs", [])


def run(ids: list[str] | None = None, deep: bool = False, log=None) -> dict:
    all_t = targets()
    chosen = [t for t in all_t if not ids or t["id"] in ids]
    if not chosen:
        raise SecReportError("Nothing to check, pick at least one target")
    t0 = time.time()
    total, done = len(chosen), 0
    results: list[dict] = []

    def one(t):
        return _scan_target(t, deep)
    with ThreadPoolExecutor(max_workers=6) as ex:
        for r in ex.map(one, chosen):
            results.append(r)
            done += 1
            if log is not None:
                log.progress(5 + 90 * done / total, f"Checked {r['label']}")
                log(f"{r['label']}: {len(r['findings'])} finding{'s' if len(r['findings']) != 1 else ''}")
    prev = last()
    rep = {"ts": int(time.time()), "took": round(time.time() - t0, 1), "hostname": socket.gethostname(), "deep": bool(deep),
           "targets": results, "tools": secnet.tools()}
    finalize(rep)
    _history(rep, prev)
    _save_json(STATE, rep)
    return rep


def start(ids: list[str] | None = None, deep: bool = False) -> dict:
    """Run the report as a background job; the page follows its progress. One at a time."""
    running = [j for j in jobs.find(kind="secreport") if j.status == "running"]
    if running:
        return {"job": running[0].id, "already": True}

    def fn(log):
        log.progress(2, "Collecting what lives on this server")
        return run(ids, deep, log)
    job = jobs.launch_fn("Security report", fn, meta={"kind": "secreport"})
    return {"job": job.id}


def accept(key: str, on: bool, note: str = "") -> dict:
    """Mark a finding as accepted (reviewed: a false positive, or on purpose). It stays visible but no longer counts."""
    if not re.match(r"^[\w:.\-|/@]{3,300}$", key or ""):
        raise SecReportError("Bad finding key")
    acc = _load_json(ACCEPTED, {})
    if on:
        acc[key] = {"note": (note or "").strip()[:300], "ts": int(time.time())}
    else:
        acc.pop(key, None)
    _save_json(ACCEPTED, acc)
    rep = last()
    if rep:
        finalize(rep, acc)
        _save_json(STATE, rep)
    return {"ok": True, "report": rep}


def last() -> dict | None:
    return _load_json(STATE, None)


def overview() -> dict:
    running = [j for j in jobs.find(kind="secreport") if j.status == "running"]
    return {"targets": targets(), "last": last(), "tools": secnet.tools(), "history": history()[-30:],
            "running": running[0].id if running else None, "fix_info": FIX_INFO}



# ---------------------------------------------------------------- standalone HTML report
_COL = {"critical": "#ff6b6b", "high": "#ff8a5b", "medium": "#ffb347", "low": "#8ab4ff", "info": "#9aa3ad", "accepted": "#a78bfa", "fixed": "#3fd08f"}


def report_html(rep: dict) -> str:
    """The report as one self-contained page: the score, what to do first (every distinct finding once,
    worst first, with the fix), then the targets, with the ones that look the same folded into one card."""
    e = html.escape
    when = datetime.fromtimestamp(rep["ts"]).strftime("%b %d, %Y %H:%M")
    order = ("critical", "high", "medium", "low", "info")
    col = lambda score: "#3fd08f" if score >= 90 else "#ffb347" if score >= 65 else "#ff6b6b"  # noqa: E731
    circ = 2 * 3.14159 * 52
    dash = circ * max(0, min(100, rep["score"])) / 100
    targets = rep["targets"]

    def sev(s):
        return f'<span class="sev" style="--c:{_COL.get(s, "#999")}">{e(s)}</span>'

    # What to do first: each distinct finding once, with the targets it was seen on.
    todo = {}
    accepted = []
    for t in targets:
        for f in t["findings"]:
            if f.get("accepted"):
                accepted.append((t, f))
                continue
            k = (f["severity"], f["title"])
            todo.setdefault(k, {"f": f, "on": []})["on"].append(t["label"])
    todo_items = sorted(todo.values(), key=lambda x: (order.index(x["f"]["severity"]) if x["f"]["severity"] in order else 9, x["f"]["title"]))
    todo_html = "".join(
        f'<li>{sev(x["f"]["severity"])}<div><b>{e(x["f"]["title"])}</b>'
        f'<p>{e(x["f"]["detail"])}</p>'
        + (f'<p class="fix"><span>Fix</span>{e(x["f"]["fix"])}</p>' if x["f"].get("fix") else "")
        + f'<p class="on">{"Seen on " + e(", ".join(x["on"][:6])) + (f" and {len(x['on']) - 6} more" if len(x["on"]) > 6 else "") if len(x["on"]) > 1 else "Seen on " + e(x["on"][0])}</p></div></li>'
        for x in todo_items) or '<li class="ok">Nothing to do. Every check passed.</li>'

    # Targets: the ones with the same kind, score and findings fold into one card.
    groups = []
    for t in targets:
        sig = (t["kind"], t["score"], tuple((f["severity"], f["title"]) for f in t["findings"]))
        g = next((g for g in groups if g["sig"] == sig), None)
        if not g:
            g = {"sig": sig, "items": []}
            groups.append(g)
        g["items"].append(t)
    cards = []
    for g in groups:
        t = g["items"][0]
        rows = "".join(
            f'<li{" class=acc" if f.get("accepted") else ""}>{sev("accepted" if f.get("accepted") else f["severity"])}<div><b>{e(f["title"])}</b><p>{e(f["detail"])}</p>'
            + (f'<p class="fix"><span>Fix</span>{e(f["fix"])}</p>' if f.get("fix") and not f.get("accepted") else "")
            + (f'<p class="on">Accepted{": " + e(f["accepted"].get("note", "")) if f["accepted"].get("note") else ""}</p>' if f.get("accepted") else "")
            + (f'<p class="on">First seen {datetime.fromtimestamp(f["first_seen"]).strftime("%b %d, %Y")}</p>' if f.get("first_seen") and not f.get("accepted") else "")
            + "</div></li>"
            for f in t["findings"]) or '<li class="ok">No findings. Nicely done.</li>'
        facts = t.get("facts") or {}
        if facts.get("ports"):
            rows += ('<li class="ports"><table><tr><th>Port</th><th>Service</th><th>Announces</th><th>Firewall</th></tr>' + "".join(
                f'<tr><td>{p["port"]}/{p["proto"]}</td><td>{e(p.get("service") or p.get("process") or "")}</td><td>{e(p.get("product") or "")}</td>'
                f'<td>{e({"open": "open to all", "lan": "limited", "blocked": "blocked", "none": "no firewall"}.get(p.get("firewall"), ""))}</td></tr>'
                for p in facts["ports"]) + "</table></li>")
        if facts.get("record"):
            rows += f'<li class="ports"><p class="on">DMARC record: <code>{e(facts["record"])}</code></p></li>'
        meta = []
        if facts.get("version"):
            meta.append(f'{facts["version"]} · {facts.get("cipher", "")}'.strip(" ·"))
        c = facts.get("cert") or {}
        if c.get("days") is not None:
            meta.append(f'certificate expires in {c["days"]} days')
        names = [x["label"] for x in g["items"]]
        if len(names) == 1:
            head = f'<h2>{e(names[0])}</h2>'
        else:
            kind = e(t["kind"]).capitalize()
            head = (f'<h2>{kind} · {len(names)} addresses, same result</h2>'
                    f'<div class="chips">{"".join(f"<span>{e(n)}</span>" for n in names)}</div>')
        n = len(t["findings"])
        summary = "no findings" if not n else f"{n} finding{'s' if n > 1 else ''}"
        cards.append(f'''<details class="t"{" open" if n else ""}><summary><div><span class="kind">{e(t["kind"])}</span>{head}
          {("<small>" + e(" · ".join(meta)) + "</small>") if meta else ""}</div>
          <div class="right"><span class="n">{summary}</span><div class="g" style="--c:{col(t["score"])}"><b>{t["score"]}</b><span>{e(t["grade"])}</span></div></div></summary><ul>{rows}</ul></details>''')
    counts = "".join(f'<div class="cnt" style="--c:{_COL[k]}"><b>{rep["counts"].get(k, 0)}</b><span>{k}</span></div>' for k in (*order, "accepted"))
    resolved = rep.get("resolved") or []
    resolved_html = ("<h3>Fixed since the last report <i>" + str(len(resolved)) + "</i></h3><div class=\"todo\"><ul>" + "".join(
        f'<li>{sev("fixed")}<div><b>{e(x["title"])}</b><p>{e(x["target"])}</p></div></li>' for x in resolved) + "</ul></div>") if resolved else ""
    accepted_html = ("<h3>Accepted <i>" + str(len(accepted)) + " reviewed and left as they are, not counted in the score</i></h3><div class=\"todo\"><ul>" + "".join(
        f'<li>{sev("accepted")}<div><b>{e(f["title"])}</b><p>{e(t["label"])}{" · " + e(f["accepted"].get("note", "")) if f["accepted"].get("note") else ""}</p></div></li>'
        for t, f in accepted) + "</ul></div>") if accepted else ""
    n_t, n_g = len(targets), len(groups)
    return f'''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Security Report · {e(rep["hostname"])}</title>
<style>
:root{{--bg:#0e0c0b;--card:#17141299;--stroke:#ffffff1f;--text:#f4efeb;--dim:#b8aea6;--accent:#ff7a1a;--w:#ffffff0d}}
@media (prefers-color-scheme:light){{:root{{--bg:#f7f3ef;--card:#ffffffcc;--stroke:#00000014;--text:#1b1715;--dim:#6b625c;--w:#00000008}}}}
*{{box-sizing:border-box}}body{{margin:0;background:var(--bg);color:var(--text);font:15px/1.5 system-ui,-apple-system,Segoe UI,Roboto,sans-serif}}
.wrap{{max-width:980px;margin:0 auto;padding:32px 16px 60px}}
.hero{{display:flex;gap:28px;align-items:center;flex-wrap:wrap;background:var(--card);border:1px solid var(--stroke);border-radius:22px;padding:26px 28px;backdrop-filter:blur(8px)}}
.ring{{position:relative;width:132px;height:132px;flex:none}}.ring svg{{display:block;transform:rotate(-90deg)}}
.ring b{{position:absolute;inset:0;display:flex;flex-direction:column;align-items:center;justify-content:center;font-size:40px;line-height:1;letter-spacing:-.03em}}
.ring b small{{margin-top:6px;font-size:11px;font-weight:700;color:var(--dim);letter-spacing:.1em;text-transform:uppercase}}
.hero > div:last-child{{flex:1;min-width:260px}}
h1{{margin:0 0 4px;font-size:26px;letter-spacing:-.02em}}.sub{{color:var(--dim);margin:0 0 14px}}
.counts{{display:flex;gap:10px;flex-wrap:wrap}}.cnt{{border:1px solid var(--stroke);border-left:4px solid var(--c);border-radius:12px;padding:6px 12px;min-width:84px;background:var(--w)}}
.cnt b{{display:block;font-size:20px;line-height:1.2}}.cnt span{{font-size:11px;text-transform:uppercase;letter-spacing:.08em;color:var(--dim)}}
h3{{margin:28px 0 10px;font-size:13px;letter-spacing:.1em;text-transform:uppercase;color:var(--dim);display:flex;align-items:center;gap:10px}}h3 i{{font-style:normal;color:var(--text);font-size:15px;letter-spacing:0;text-transform:none;font-weight:600}}
.todo{{background:var(--card);border:1px solid var(--stroke);border-radius:18px;padding:6px 22px}}
.t{{background:var(--card);border:1px solid var(--stroke);border-radius:18px;padding:0 22px;margin-top:12px}}
summary{{list-style:none;cursor:pointer;display:flex;justify-content:space-between;gap:16px;align-items:center;padding:16px 0}}summary::-webkit-details-marker{{display:none}}
summary > div:first-child{{min-width:0}}.t h2{{margin:0;font-size:17px;letter-spacing:-.01em}}.kind{{font-size:11px;text-transform:uppercase;letter-spacing:.1em;color:var(--accent)}}
.t small{{color:var(--dim);display:block;margin-top:2px;font-size:12.5px}}.right{{display:flex;align-items:center;gap:14px;flex:none}}.n{{font-size:12.5px;color:var(--dim)}}
.g{{text-align:center;border:2px solid var(--c);color:var(--c);border-radius:14px;padding:4px 12px;min-width:64px}}.g b{{display:block;font-size:20px;line-height:1.1}}.g span{{font-size:12px}}
.chips{{display:flex;flex-wrap:wrap;gap:6px;margin-top:8px}}.chips span{{font-size:12px;border:1px solid var(--stroke);background:var(--w);border-radius:999px;padding:2px 10px;color:var(--dim);font-family:ui-monospace,Consolas,monospace}}
ul{{list-style:none;margin:0;padding:0 0 8px}}li{{display:flex;gap:12px;padding:12px 0;border-top:1px solid var(--stroke)}}li p{{margin:2px 0 0;color:var(--dim);font-size:13.5px}}
li .fix{{color:var(--text);margin-top:6px;display:flex;gap:8px;align-items:baseline}}li .fix span{{flex:none;font-size:10.5px;font-weight:800;letter-spacing:.1em;text-transform:uppercase;color:var(--accent);border:1px solid var(--accent);border-radius:999px;padding:0 7px}}
li .on{{font-size:12px;margin-top:6px}}li.ok{{color:#3fd08f}}li.acc{{opacity:.7}}li.ports{{display:block}}code{{font-family:ui-monospace,Consolas,monospace;font-size:12px;overflow-wrap:anywhere}}table{{width:100%;border-collapse:collapse;font-size:13px}}th,td{{text-align:left;padding:6px 8px;border-bottom:1px solid var(--stroke)}}th{{color:var(--dim);font-weight:600;font-size:11.5px;text-transform:uppercase;letter-spacing:.06em}}
.sev{{flex:none;align-self:flex-start;margin-top:3px;font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.06em;color:var(--c);border:1px solid var(--c);border-radius:999px;padding:1px 8px;min-width:68px;text-align:center}}
footer{{margin-top:28px;color:var(--dim);font-size:12.5px;text-align:center;line-height:1.6}}
@media (max-width:640px){{summary{{flex-direction:column;align-items:flex-start}}.right{{width:100%;justify-content:space-between}}}}
@media print{{body{{background:#fff;color:#111}}.hero,.t,.todo{{break-inside:avoid;background:#fff;border-color:#ddd}}.t{{padding-top:0}}}}
</style></head><body><div class="wrap">
<div class="hero"><div class="ring"><svg width="132" height="132" viewBox="0 0 132 132"><circle cx="66" cy="66" r="52" fill="none" stroke="var(--stroke)" stroke-width="12"/>
<circle cx="66" cy="66" r="52" fill="none" stroke="{col(rep["score"])}" stroke-width="12" stroke-linecap="round" stroke-dasharray="{dash:.1f} {circ:.1f}"/></svg><b>{e(rep["grade"])}<small>{rep["score"]} / 100</small></b></div>
<div><h1>Security Report · {e(rep["hostname"])}</h1><p class="sub">{when} · {n_t} target{"s" if n_t != 1 else ""} checked in {rep["took"]} s · everything on this server, nothing else</p><div class="counts">{counts}</div></div></div>
<h3>What to do first <i>{len(todo_items)} distinct finding{"s" if len(todo_items) != 1 else ""}</i></h3>
<div class="todo"><ul>{todo_html}</ul></div>
{resolved_html}{accepted_html}
<h3>Every target <i>{n_t} checked{f", shown as {n_g} cards" if n_g != n_t else ""}</i></h3>
{"".join(cards)}
<footer>Made by AuroraPanel on {e(rep["hostname"])}.<br>Scores: 100 minus 25 per critical, 15 per high, 8 per medium and 3 per low finding; accepted findings don't count. Targets with the same result share one card.<br>Covers web application headers, cookies and forms, TLS certificates, protocols and ciphers, open ports and network services, SSH, FTP, DNS, mail TLS, DMARC / SPF / DKIM and the server's own protections.</footer>
</div></body></html>'''
