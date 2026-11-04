"""DMARC: read, explain, build and publish a domain's DMARC policy.

DMARC is one TXT record at _dmarc.<domain>. It tells receiving mail servers what to do with a message
that claims to be From: someone@<domain> but fails both SPF and DKIM (or passes them only for a
different domain): deliver it anyway (p=none), send it to spam (p=quarantine) or refuse it (p=reject).
It also asks them to mail daily aggregate reports (rua) about everything they saw using the domain.

This module parses a record into settings, builds a record from settings, grades a domain's setup
(DMARC + SPF + DKIM), turns the answers of the setup wizard into recommended settings, and writes the
record into this server's DNS zone for the domain when the zone lives here. When DNS is hosted
elsewhere the record is returned so it can be added at the DNS provider.
"""
from __future__ import annotations

import re

from . import problems

POLICIES = ("none", "quarantine", "reject")
ALIGN = ("r", "s")
FO_VALUES = ("0", "1", "d", "s")
MAX_ADDRS = 5
DEFAULT_RI = 86400
_EMAIL = re.compile(r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,63}$")
_DOMAIN = re.compile(r"^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")
# Names a public DNS will never answer for: nothing to publish, nothing to check.
_LOCAL_TLDS = ("local", "lan", "home", "internal", "intranet", "localdomain", "localhost", "test", "example", "invalid", "arpa")


class DmarcError(RuntimeError):
    pass


DEFAULTS = {"p": "none", "sp": "", "pct": 100, "rua": [], "ruf": [], "adkim": "r", "aspf": "r", "fo": "0", "ri": DEFAULT_RI}


# ---------------------------------------------------------------- names
def clean_domain(d: str) -> str:
    d = (d or "").strip().lower().rstrip(".")
    if d.startswith("www."):
        d = d[4:]
    if not _DOMAIN.match(d):
        raise DmarcError("Enter a domain name like example.com")
    return d


def is_public(d: str) -> bool:
    """A name the internet's DNS can answer for (not an address, not .local / .test …)."""
    d = (d or "").lower().rstrip(".")
    return bool(_DOMAIN.match(d)) and d.rsplit(".", 1)[-1] not in _LOCAL_TLDS


def org_domain(d: str) -> str:
    """The registrable parent receivers fall back to (best effort: the last two labels, three for
    the common two-part suffixes like co.uk)."""
    parts = d.lower().rstrip(".").split(".")
    if len(parts) >= 3 and parts[-2] in ("co", "com", "net", "org", "gov", "ac", "edu") and len(parts[-1]) == 2:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


# ---------------------------------------------------------------- parse / build
def parse(text: str) -> dict:
    """Tag → value for a DMARC record, {} if the text isn't one (it must start with v=DMARC1)."""
    tags: dict[str, str] = {}
    for part in (text or "").split(";"):
        if "=" not in part:
            continue
        k, v = part.split("=", 1)
        tags[k.strip().lower()] = v.strip()
    if tags.get("v", "").upper() != "DMARC1":
        return {}
    return tags


def _mailtos(v: str) -> list[str]:
    out = []
    for a in (v or "").split(","):
        a = a.strip()
        if a.lower().startswith("mailto:"):
            a = a[7:]
        a = a.split("!", 1)[0].strip()  # "!10m" is a size limit
        if a:
            out.append(a)
    return out


def settings_from(tags: dict) -> dict:
    """What the editor shows for a parsed record; unknown or broken values fall back to the defaults."""
    if not tags:
        return {**DEFAULTS, "enabled": False}
    p = tags.get("p", "").lower()
    sp = tags.get("sp", "").lower()
    try:
        pct = max(0, min(100, int(tags.get("pct", "100"))))
    except ValueError:
        pct = 100
    try:
        ri = int(tags.get("ri", str(DEFAULT_RI)))
    except ValueError:
        ri = DEFAULT_RI
    return {"enabled": True, "p": p if p in POLICIES else "none", "sp": sp if sp in POLICIES else "", "pct": pct,
            "rua": _mailtos(tags.get("rua", "")), "ruf": _mailtos(tags.get("ruf", "")),
            "adkim": "s" if tags.get("adkim", "r").lower() == "s" else "r", "aspf": "s" if tags.get("aspf", "r").lower() == "s" else "r",
            "fo": tags.get("fo", "0") or "0", "ri": ri}


def validate(s: dict) -> dict:
    """Checked, normalised settings. Raises DmarcError with a sentence the user can act on."""
    s = {**DEFAULTS, **(s or {})}
    p = str(s["p"]).lower()
    if p not in POLICIES:
        raise DmarcError("Policy must be none, quarantine or reject")
    sp = str(s.get("sp") or "").lower()
    if sp and sp not in POLICIES:
        raise DmarcError("Subdomain policy must be none, quarantine or reject (or the same as the domain)")
    try:
        pct = int(s["pct"])
    except (TypeError, ValueError):
        raise DmarcError("Percentage must be a number from 1 to 100")
    if not 1 <= pct <= 100:
        raise DmarcError("Percentage must be a number from 1 to 100")
    out = {"p": p, "sp": sp, "pct": pct}
    for k, what in (("rua", "report"), ("ruf", "failure report")):
        raw = s.get(k) or []
        if isinstance(raw, str):
            raw = [x for x in re.split(r"[,\s;]+", raw) if x]
        addrs = []
        for a in raw:
            a = str(a).strip()
            if a.lower().startswith("mailto:"):
                a = a[7:]
            if not _EMAIL.match(a):
                raise DmarcError(f"“{a}” isn't a valid {what} address")
            if a.lower() not in [x.lower() for x in addrs]:
                addrs.append(a)
        if len(addrs) > MAX_ADDRS:
            raise DmarcError(f"At most {MAX_ADDRS} {what} addresses")
        out[k] = addrs
    for k in ("adkim", "aspf"):
        v = str(s.get(k) or "r").lower()
        if v not in ALIGN:
            raise DmarcError("Alignment must be relaxed (r) or strict (s)")
        out[k] = v
    fo = [x.strip() for x in str(s.get("fo") or "0").split(":") if x.strip()]
    if not fo or any(x not in FO_VALUES for x in fo):
        raise DmarcError("Failure reporting options are 0, 1, d and s")
    out["fo"] = ":".join(dict.fromkeys(fo))
    try:
        ri = int(s.get("ri") or DEFAULT_RI)
    except (TypeError, ValueError):
        raise DmarcError("Report interval must be a number of seconds")
    if not 3600 <= ri <= 604800:
        raise DmarcError("Report interval must be between 1 hour and 7 days")
    out["ri"] = ri
    return out


def build(s: dict) -> str:
    """The TXT value for validated settings, tags in the conventional order, defaults left out."""
    s = validate(s)
    parts = ["v=DMARC1", f"p={s['p']}"]
    if s["sp"]:
        parts.append(f"sp={s['sp']}")
    if s["pct"] != 100:
        parts.append(f"pct={s['pct']}")
    if s["rua"]:
        parts.append("rua=" + ",".join(f"mailto:{a}" for a in s["rua"]))
    if s["ruf"]:
        parts.append("ruf=" + ",".join(f"mailto:{a}" for a in s["ruf"]))
        if s["fo"] != "0":
            parts.append(f"fo={s['fo']}")
    parts.append(f"adkim={s['adkim']}")
    parts.append(f"aspf={s['aspf']}")
    if s["ri"] != DEFAULT_RI:
        parts.append(f"ri={s['ri']}")
    return "; ".join(parts)


def explain(s: dict, domain: str = "") -> list[dict]:
    """One plain sentence per tag of the record that build(s) makes, for the wizard's review step."""
    s = validate(s)
    what = {"none": "deliver it normally (monitoring only, no protection yet)",
            "quarantine": "put it in the spam or junk folder", "reject": "refuse it, it never reaches the inbox"}
    out = [{"tag": "v=DMARC1", "text": "Marks this TXT record as a DMARC policy."},
           {"tag": f"p={s['p']}", "text": f"Mail that fails DMARC for this domain: {what[s['p']]}."}]
    if s["sp"]:
        out.append({"tag": f"sp={s['sp']}", "text": f"Subdomains (anything.{domain or 'domain'}): {what[s['sp']]}."})
    else:
        out.append({"tag": "(no sp)", "text": "Subdomains follow the same policy as the domain."})
    if s["pct"] != 100:
        out.append({"tag": f"pct={s['pct']}", "text": f"Apply the policy to {s['pct']}% of failing mail; the rest is treated one step softer. Raise it to 100 once nothing legitimate is caught."})
    if s["rua"]:
        out.append({"tag": "rua=…", "text": f"Daily aggregate reports go to {', '.join(s['rua'])}: who sent mail using your domain and whether it passed."})
    else:
        out.append({"tag": "(no rua)", "text": "No reports: receivers enforce the policy but you won't see who sends as you."})
    if s["ruf"]:
        out.append({"tag": "ruf=…", "text": f"Per-message failure reports go to {', '.join(s['ruf'])} (few providers send them, and they can contain message details)."})
    out.append({"tag": f"adkim={s['adkim']}", "text": "DKIM must be signed by exactly this domain." if s["adkim"] == "s" else "DKIM signed by this domain or any of its subdomains counts."})
    out.append({"tag": f"aspf={s['aspf']}", "text": "SPF must pass for exactly this domain." if s["aspf"] == "s" else "SPF passing for this domain or any of its subdomains counts."})
    return out


# ---------------------------------------------------------------- the wizard
WIZARD = [
    {"id": "sends", "q": "Does this domain send email?",
     "help": "Think of everything that sends mail as you@domain: this server, Google Workspace or Microsoft 365, a newsletter or shop system, your printer.",
     "options": [["here", "Yes, from this server only"], ["elsewhere", "Yes, through another service"], ["both", "Yes, this server and other services"],
                 ["none", "No, it never sends email"]]},
    {"id": "stage", "q": "How sure are you that all your legitimate mail passes SPF or DKIM?",
     "help": "Start by monitoring. Reports show every server sending as you; move up once only yours appear and they pass.",
     "options": [["new", "Not sure yet, just starting"], ["monitored", "I watched reports for a few weeks, they look clean"],
                 ["confident", "Fully confident, block every forgery"]], "skip_if": {"sends": "none"}},
    {"id": "reports", "q": "Where should receivers send the daily DMARC reports?",
     "help": "Reports are XML attachments, a few per day. A separate mailbox like dmarc@ keeps them out of your way. Leave empty for no reports.",
     "input": "email"},
    {"id": "subdomains", "q": "Do subdomains (shop.domain, mail.domain …) send email of their own?",
     "options": [["same", "Some might, give them the same policy"], ["reject", "No, refuse mail from any subdomain"]]},
    {"id": "alignment", "q": "How strict should the domain match be?",
     "help": "Relaxed lets mail signed for a subdomain count for the domain. It's what almost everyone uses.",
     "options": [["relaxed", "Relaxed (recommended)"], ["strict", "Strict, the exact domain only"]]},
]


def recommend(domain: str, answers: dict) -> dict:
    """Settings for the wizard's answers, with the reasons shown on its last step."""
    domain = clean_domain(domain)
    a = answers or {}
    sends = a.get("sends", "here")
    stage = a.get("stage", "new")
    why = []
    if sends == "none":
        p, why_p = "reject", "A domain that never sends mail can safely refuse everything sent in its name, the strongest protection against spoofing."
    elif stage == "confident":
        p, why_p = "reject", "You're sure your own mail passes, so forgeries are refused outright."
    elif stage == "monitored":
        p, why_p = "quarantine", "Reports look clean, so failing mail goes to spam. Move to reject after a few more clean weeks."
    else:
        p, why_p = "none", "Monitoring first: nothing is blocked yet, but reports show who sends as you. Plan to move on within a few weeks."
    why.append(why_p)
    rep = (a.get("reports") or "").strip()
    rua = [rep] if rep else []
    if rua:
        why.append(f"Reports go to {rep}." + ("" if rep.lower().endswith("@" + domain) else " That address is on another domain, which must allow it (see the note below)."))
    elif p == "none":
        why.append("Without reports p=none tells you nothing, consider adding an address.")
    sp = "reject" if a.get("subdomains") == "reject" or sends == "none" else ""
    if sp:
        why.append("Subdomains can't be used to send forged mail.")
    strict = a.get("alignment") == "strict"
    s = validate({"p": p, "sp": sp if sp != p else "", "pct": 100, "rua": rua, "adkim": "s" if strict else "r", "aspf": "s" if strict else "r"})
    if sends in ("elsewhere", "both"):
        why.append("Other services that send as you must be in your SPF record and sign with DKIM for your domain, or their mail fails once you leave p=none.")
    return {"settings": s, "record": build(s), "why": why, "explain": explain(s, domain), "external": external_auth(domain, rua)}


def external_auth(domain: str, addrs: list[str]) -> list[dict]:
    """Report addresses on another domain need that domain's permission: a TXT record
    <domain>._report._dmarc.<their domain> = "v=DMARC1". Returns the records to ask for."""
    out = []
    for a in addrs or []:
        rd = a.rsplit("@", 1)[-1].lower()
        if org_domain(rd) == org_domain(domain):  # RFC 7489 §7.1: same organizational domain needs no permission
            continue
        out.append({"address": a, "name": f"{domain}._report._dmarc.{rd}", "value": "v=DMARC1"})
    return out


# ---------------------------------------------------------------- grading
def assess(domain: str, tags: dict, spf: str, dkim: bool, sends_here: bool, inherited: str = "") -> dict:
    """level: missing | monitor | partial | enforced, plus notes (tone good/warn/bad) and findings
    (severity, id, title, detail, fix) the Security Report shows."""
    notes, findings = [], []

    def add(sev, fid, title, detail, fix, tone):
        notes.append({"tone": tone, "text": f"{title}. {detail}"})
        findings.append({"severity": sev, "id": fid, "title": title, "detail": detail, "fix": fix})

    if not tags:
        level = "missing"
        if inherited:
            add("low", "dmarc-inherited", "No DMARC record of its own",
                f"Receivers use the parent domain's policy ({inherited}). Fine unless this name needs a different one.",
                "Optional: give it its own record with the DMARC wizard.", "warn")
            level = "inherited"
        else:
            add("high" if sends_here else "medium", "dmarc-missing", "No DMARC policy",
                f"Anyone can send mail that claims to be from @{domain} and receivers have no instruction to stop it. "
                "Gmail and Yahoo also require DMARC from bulk senders.", "Run the DMARC wizard (Domains → this domain → Email authentication).", "bad")
    else:
        s = settings_from(tags)
        if s["p"] == "none":
            level = "monitor"
            add("low", "dmarc-none", "DMARC only monitors (p=none)",
                "Forged mail is still delivered. p=none is the right start, but it gives no protection.",
                "When reports show only your own servers, move to quarantine, then reject.", "warn")
        elif s["pct"] < 100 or s["p"] == "quarantine":
            level = "partial"
            if s["pct"] < 100:
                add("low", "dmarc-pct", f"DMARC applies to {s['pct']}% of failing mail",
                    "The rest is handled one step softer.", "Raise pct to 100 once nothing legitimate is caught.", "warn")
            else:
                notes.append({"tone": "good", "text": "Failing mail goes to spam (p=quarantine)."})
        else:
            level = "enforced"
            notes.append({"tone": "good", "text": "Forged mail is refused (p=reject)."})
        if not s["rua"]:
            add("low", "dmarc-no-rua", "No DMARC reports requested",
                "Without rua you can't see who sends mail using your domain, or notice when your own mail starts failing.",
                "Add a report address in the DMARC settings.", "warn")
        if s["sp"] == "none" and s["p"] != "none":
            add("low", "dmarc-sp-none", "Subdomains are not protected (sp=none)",
                "Mail forged from any subdomain is still delivered.", "Set the subdomain policy to the same as the domain.", "warn")
    spf = spf or ""
    if not spf:
        add("medium", "spf-missing", "No SPF record",
            "Receivers can't tell which servers may send for this domain, and DMARC can only pass through DKIM.",
            "Add one: v=spf1 mx a ~all for mail sent from this server" + (", or v=spf1 -all if the domain never sends mail." if not sends_here else "."), "bad")
    elif re.search(r"(^|\s)[+]?all\b", spf):
        add("high", "spf-all", "SPF allows every server (+all)", "“+all” authorises the whole internet to send as this domain.",
            "End the record with ~all or -all instead.", "bad")
    elif spf.rstrip().endswith("?all"):
        add("low", "spf-neutral", "SPF ends with ?all (neutral)", "Mail from unlisted servers is neither passed nor failed.", "End the record with ~all or -all.", "warn")
    else:
        notes.append({"tone": "good", "text": "SPF record published."})
    if sends_here and not dkim:
        add("medium", "dkim-missing", "No DKIM key published",
            "Mail from this server isn't signed with a key receivers can check, so DMARC relies on SPF alone, which breaks on forwarding.",
            "Email → Deliverability → publish the DKIM record.", "bad")
    elif dkim:
        notes.append({"tone": "good", "text": "DKIM key published."})
    grade = {"enforced": "A", "partial": "B", "monitor": "C", "inherited": "C", "missing": "F"}[level]
    if grade in ("A", "B") and any(f["severity"] in ("medium", "high") for f in findings):
        grade = chr(ord(grade) + 1)
    return {"level": level, "grade": grade, "notes": notes, "findings": findings}


# ---------------------------------------------------------------- DNS
def _resolver():
    import dns.resolver
    r = dns.resolver.Resolver()
    r.lifetime = 5
    return r


def _txt(name: str) -> list[str]:
    try:
        return ["".join(p.decode(errors="replace") for p in rr.strings) for rr in _resolver().resolve(name, "TXT")]
    except Exception as quiet_exc:
        problems.quiet(quiet_exc)
        return []


def lookup(domain: str) -> dict:
    """The live records: DMARC (own, or the parent's that receivers fall back to), SPF, DKIM."""
    own = next((t for t in _txt(f"_dmarc.{domain}") if t.lower().replace(" ", "").startswith("v=dmarc1")), "")
    parent = ""
    org = org_domain(domain)
    if not own and org != domain:
        parent = next((t for t in _txt(f"_dmarc.{org}") if t.lower().replace(" ", "").startswith("v=dmarc1")), "")
    spf = next((t for t in _txt(domain) if t.lower().startswith("v=spf1")), "")
    dkim = False
    try:
        from . import mail
        sel = mail.SELECTOR
    except Exception:  # pragma: no cover - mail always imports; guard for trimmed installs
        sel = "aurora"
    for s in dict.fromkeys([sel, "default", "google", "selector1", "selector2", "k1", "mail", "dkim"]):
        if any("p=" in t for t in _txt(f"{s}._domainkey.{domain}")):
            dkim = True
            break
    return {"record": own, "parent": parent, "org": org, "spf": spf, "dkim": dkim}


def _sends_here(domain: str) -> bool:
    try:
        from . import mail
        return domain in (mail.load().get("domains") or {})
    except Exception as quiet_exc:
        problems.quiet(quiet_exc)
        return False


def _zone_for(domain: str) -> str:
    """The zone on this server that holds _dmarc.<domain>: the domain's own, or a parent's."""
    try:
        from . import dnszones
    except Exception:  # pragma: no cover
        return ""
    labels = domain.split(".")
    for i in range(len(labels) - 1):
        cand = ".".join(labels[i:])
        try:
            if dnszones._path(cand).exists():
                return cand
        except Exception as quiet_exc:
            problems.quiet(quiet_exc)
    return ""


def _zone_record(zone: str, domain: str) -> tuple[str, list[int]]:
    """(the DMARC text in this server's zone, indexes of every DMARC TXT at _dmarc.<domain>)."""
    from . import dnszones
    name = f"_dmarc.{domain}."
    text, idx = "", []
    for i, r in enumerate(dnszones.get_zone(zone).get("records", [])):
        if r.get("type") == "TXT" and r.get("name", "").lower() == name and parse(str(r.get("text", ""))):
            idx.append(i)
            text = text or str(r.get("text", ""))
    return text, idx


def status(domain: str) -> dict:
    domain = clean_domain(domain)
    if not is_public(domain):
        return {"domain": domain, "public": False, "settings": {**DEFAULTS, "enabled": False}, "wizard": WIZARD,
                "note": "This name only exists on your network, so no mail server on the internet will look up its DMARC record."}
    live = lookup(domain)
    zone = _zone_for(domain)
    zone_text = ""
    if zone:
        try:
            zone_text, _ = _zone_record(zone, domain)
        except Exception as quiet_exc:
            problems.quiet(quiet_exc)
    sends = _sends_here(domain)
    current = zone_text or live["record"]
    tags = parse(current)
    a = assess(domain, parse(live["record"]), live["spf"], live["dkim"], sends, live["parent"])
    return {"domain": domain, "public": True, "record": live["record"], "parent_record": live["parent"], "org": live["org"],
            "zone": zone, "zone_record": zone_text, "pending": bool(zone_text) and zone_text != live["record"],
            "spf": live["spf"], "dkim": live["dkim"], "sends_here": sends, "settings": settings_from(tags),
            "assess": a, "wizard": WIZARD, "default_reports": f"dmarc@{domain}" if sends else f"postmaster@{domain}",
            "external": external_auth(domain, settings_from(tags)["rua"])}


def save(domain: str, settings: dict) -> dict:
    """Publish the record in this server's zone (replacing any DMARC TXT there). Without a zone here
    nothing is written and the record is returned for the DNS provider."""
    domain = clean_domain(domain)
    value = build(settings)
    name = f"_dmarc.{domain}"
    zone = _zone_for(domain)
    if not zone:
        return {"published": False, "name": name, "value": value, "external": external_auth(domain, validate(settings)["rua"]),
                "message": f"DNS for {domain} isn't served by this server. Add this TXT record at your DNS provider."}
    from . import dnszones
    _, idx = _zone_record(zone, domain)
    for i in reversed(idx):
        dnszones.delete_record(zone, i)
    dnszones.add_record(zone, {"name": name + ".", "type": "TXT", "text": value, "ttl": 3600})
    return {"published": True, "zone": zone, "name": name, "value": value, "external": external_auth(domain, validate(settings)["rua"]),
            "message": f"Published in the {zone} zone. Receivers see it within the record's TTL (about an hour)."}


def remove(domain: str) -> dict:
    domain = clean_domain(domain)
    zone = _zone_for(domain)
    if not zone:
        raise DmarcError(f"DNS for {domain} isn't served by this server. Remove the _dmarc record at your DNS provider.")
    from . import dnszones
    _, idx = _zone_record(zone, domain)
    for i in reversed(idx):
        dnszones.delete_record(zone, i)
    return {"removed": len(idx)}
