"""Track DNS / network diagnostics: dig, host, reverse lookup, traceroute."""
from __future__ import annotations

import re
import shutil
import subprocess
from concurrent.futures import ThreadPoolExecutor

_HOST_RE = re.compile(r"^[A-Za-z0-9._-]{1,253}$")
_IP_RE = re.compile(r"^[0-9a-fA-F:.]{2,45}$")


class NetDiagError(RuntimeError):
    pass


def _valid_host(host: str) -> str:
    host = (host or "").strip()
    if not (_HOST_RE.match(host) or _IP_RE.match(host)):
        raise NetDiagError("Invalid hostname or IP")
    return host


def _run(argv: list[str], timeout: int = 20) -> str:
    try:
        out = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
    except FileNotFoundError:
        raise NetDiagError(f"{argv[0]} is not installed")
    except (subprocess.SubprocessError, OSError) as exc:
        raise NetDiagError(str(exc)) from exc
    return (out.stdout + (("\n" + out.stderr) if out.stderr else "")).strip()


TYPES = ("A", "AAAA", "CNAME", "MX", "TXT", "NS", "SOA", "CAA", "SRV", "PTR")
DEFAULT_TYPES = ("A", "AAAA", "CNAME", "MX", "TXT", "NS")
# Public resolvers for "has my change spread yet?" — plus this Pi's own resolver.
RESOLVERS = (("This Pi", None), ("Cloudflare", "1.1.1.1"), ("Google", "8.8.8.8"), ("Quad9", "9.9.9.9"), ("OpenDNS", "208.67.222.222"))
RESOLVER_BY_KEY = {"system": None, "cloudflare": "1.1.1.1", "google": "8.8.8.8", "quad9": "9.9.9.9", "opendns": "208.67.222.222"}


def _need_dig():
    if not shutil.which("dig"):
        raise NetDiagError("dig is not installed (apt install dnsutils)")


def _dig(host: str, rtype: str, server: str | None = None, timeout: int = 10) -> list[str]:
    argv = ["dig", "+short", "+time=3", "+tries=1"] + ([f"@{server}"] if server else []) + [host, rtype]
    return [ln for ln in _run(argv, timeout=timeout).splitlines() if ln.strip() and not ln.startswith(";")]


def _server(key: str) -> str | None:
    key = (key or "").strip()
    if not key or key in RESOLVER_BY_KEY:
        return RESOLVER_BY_KEY.get(key)
    return _valid_host(key)  # a resolver address typed by hand


def dns_records(host: str, types: list[str] | None = None, server: str = "") -> dict:
    """The chosen record types of a name, from the chosen resolver (default: this Pi's)."""
    host = _valid_host(host)
    _need_dig()
    srv = _server(server)
    want = [t for t in (types or DEFAULT_TYPES) if t in TYPES] or list(DEFAULT_TYPES)
    with ThreadPoolExecutor(max_workers=min(6, len(want))) as ex:
        answers = list(ex.map(lambda t: _dig(host, t, srv), want))
    return {"host": host, "server": srv or "this Pi", "records": dict(zip(want, answers))}


def propagation(host: str, rtype: str = "A") -> dict:
    """The same question to several resolvers at once: while they disagree, a change is still spreading."""
    host = _valid_host(host)
    rtype = rtype if rtype in TYPES else "A"
    _need_dig()
    with ThreadPoolExecutor(max_workers=len(RESOLVERS)) as ex:
        rows = list(ex.map(lambda r: {"name": r[0], "ip": r[1], "answers": _dig(host, rtype, r[1])}, RESOLVERS))
    distinct = {tuple(sorted(r["answers"])) for r in rows}
    return {"host": host, "type": rtype, "resolvers": rows, "agree": len(distinct) <= 1}


DKIM_SELECTORS = ("default", "mail", "dkim", "selector1", "selector2", "google", "k1", "s1")


def mail_check(domain: str) -> dict:
    """The records a mail domain needs: MX, SPF, DMARC and a DKIM key under the usual selectors."""
    domain = _valid_host(domain)
    _need_dig()
    jobs = {"mx": (domain, "MX"), "txt": (domain, "TXT"), "dmarc": (f"_dmarc.{domain}", "TXT")}
    jobs.update({f"dkim:{s}": (f"{s}._domainkey.{domain}", "TXT") for s in DKIM_SELECTORS})
    with ThreadPoolExecutor(max_workers=6) as ex:
        got = dict(zip(jobs, ex.map(lambda nt: _dig(nt[0], nt[1]), jobs.values())))
    spf = [t for t in got["txt"] if "v=spf1" in t.lower()]
    dmarc = [t for t in got["dmarc"] if "v=dmarc1" in t.lower()]
    dkim = {s: got[f"dkim:{s}"] for s in DKIM_SELECTORS if got[f"dkim:{s}"]}
    return {"domain": domain, "mx": got["mx"], "spf": spf, "dmarc": dmarc, "dkim": dkim,
            "ok": {"mx": bool(got["mx"]), "spf": bool(spf), "dmarc": bool(dmarc), "dkim": bool(dkim)}}


def ns_check(domain: str) -> dict:
    """Ask each authoritative name server for the zone's SOA serial: do they all carry the same version?"""
    domain = _valid_host(domain)
    _need_dig()
    ns = sorted(n.rstrip(".") for n in _dig(domain, "NS"))

    def one(n: str) -> dict:
        ip = (_dig(n, "A") or [""])[0]
        soa = _dig(domain, "SOA", ip or n) if (ip or n) else []
        serial = soa[0].split()[2] if soa and len(soa[0].split()) > 2 else ""
        return {"ns": n, "ip": ip, "serial": serial, "ok": bool(soa)}

    with ThreadPoolExecutor(max_workers=6) as ex:
        servers = list(ex.map(one, ns)) if ns else []
    serials = {s["serial"] for s in servers if s["ok"]}
    return {"domain": domain, "ns": ns, "servers": servers, "agree": len(serials) <= 1}


_WHOIS_KEYS = (("Registrar", r"^\s*Registrar:\s*(.+)"), ("Created", r"^\s*Creat(?:ion|ed)(?: Date)?:\s*(.+)"),
               ("Expires", r"^\s*(?:Registry Expiry Date|Expir(?:y|ation) Date|paid-till):\s*(.+)"), ("Updated", r"^\s*Updated Date:\s*(.+)"),
               ("Status", r"^\s*(?:Domain )?Status:\s*(\S+)"), ("Name servers", r"^\s*(?:Name Server|nserver):\s*(\S+)"),
               ("Network", r"^\s*(?:NetName|netname):\s*(.+)"), ("Range", r"^\s*(?:CIDR|inetnum):\s*(.+)"), ("Range", r"^\s*NetRange:\s*(.+)"),
               ("Owner", r"^\s*(?:OrgName|org-name|descr|Registrant Organization):\s*(.+)"), ("Country", r"^\s*(?:Country|country|Registrant Country):\s*(\S+)"))


def whois_summary(text: str) -> dict:
    """The handful of lines people actually want out of a WHOIS record."""
    out: dict[str, str] = {}
    for label, rx in _WHOIS_KEYS:  # a label may have fallbacks: first pattern that hits wins
        if label in out:
            continue
        vals = []
        for m in re.finditer(rx, text, re.I | re.M):
            v = m.group(1).strip()
            if v and v.lower() not in {x.lower() for x in vals}:  # registries repeat name servers in two cases
                vals.append(v)
        if vals:
            out[label] = ", ".join(vals[:4] if label in ("Name servers", "Status") else vals[:1])
    return out


def whois(host: str) -> dict:
    host = _valid_host(host)
    if not shutil.which("whois"):
        raise NetDiagError("whois is not installed (apt install whois)")
    text = _run(["whois", host], timeout=25)
    body = "\n".join(ln for ln in text.splitlines() if not ln.lstrip().startswith(("%", "#", ">>>", "NOTICE", "TERMS")))
    return {"host": host, "summary": whois_summary(body), "text": body.strip()[:8000]}


def reverse_lookup(ip: str) -> dict:
    ip = _valid_host(ip)
    if shutil.which("dig"):
        out = _run(["dig", "+short", "-x", ip], timeout=12)
    elif shutil.which("host"):
        out = _run(["host", ip], timeout=12)
    else:
        raise NetDiagError("dig/host not installed")
    return {"ip": ip, "result": out or "(no PTR record)"}


def ping(host: str, count: int = 4) -> dict:
    host = _valid_host(host)
    count = max(1, min(int(count), 10))
    if not shutil.which("ping"):
        raise NetDiagError("ping is not installed")
    out = _run(["ping", "-c", str(count), "-w", str(count + 5), host], timeout=count + 10)
    # Parse summary: "min/avg/max/mdev = 1.2/3.4/5.6/0.7 ms" and loss %.
    avg = None
    m = re.search(r"=\s*[\d.]+/([\d.]+)/", out)
    if m:
        avg = float(m.group(1))
    loss = None
    ml = re.search(r"([\d.]+)% packet loss", out)
    if ml:
        loss = float(ml.group(1))
    return {"host": host, "output": out, "avg_ms": avg, "loss_pct": loss}


def traceroute(host: str) -> dict:
    host = _valid_host(host)
    if shutil.which("traceroute"):
        out = _run(["traceroute", "-w", "2", "-q", "1", "-m", "20", host], timeout=60)
    elif shutil.which("tracepath"):
        out = _run(["tracepath", host], timeout=60)
    else:
        raise NetDiagError("Neither traceroute nor tracepath is installed (apt install traceroute)")
    return {"host": host, "output": out}
