"""The WAF for Nginx: ModSecurity 3 (libmodsecurity with its Nginx connector) and the OWASP Core Rule Set.

It follows the WAF Firewall page's paranoia level, anomaly threshold, app exclusions, trusted addresses, sites with the
WAF off and rules switched off; only its on/detect/off mode is its own, since Apache and Nginx can be in different states.
Every change goes through `nginx -t` and comes back out if Nginx refuses it.

Anything else that speaks HTTP (Caddy, Lighttpd, a Docker app) is protected by putting it behind a reverse proxy site on
Nginx, with the app listening on 127.0.0.1 so the WAF can't be walked around.
"""
from __future__ import annotations

import glob
import json
import re
import subprocess
from pathlib import Path

from . import distro, jobs, nginxsites, waf

STATE = Path("/var/lib/aurora/nginx-waf.json")
DIR = Path("/etc/nginx/aurora-waf")
MAIN = DIR / "main.conf"
PRE = DIR / "pre.conf"
POST = DIR / "post.conf"
HOOK = nginxsites.CONF_DIR / "aurora-waf.conf"
AUDIT = nginxsites.LOG_DIR / "modsec_audit.log"
MODES = ("block", "detect", "off")
MODULE_GLOBS = ("/usr/lib64/nginx/modules/ngx_http_modsecurity_module.so", "/usr/lib/nginx/modules/ngx_http_modsecurity_module.so", "/usr/share/nginx/modules/*modsecurity*.conf")
PACKAGES = ["libnginx-mod-http-modsecurity", "modsecurity-crs"]
# (setup file, folder of rule files): Fedora's package, then Debian's.
CRS_LAYOUTS = (("/etc/httpd/modsecurity.d/crs-setup.conf", "/etc/httpd/modsecurity.d/activated_rules"), ("/etc/modsecurity/crs/crs-setup.conf", "/usr/share/modsecurity-crs/rules"))
HEADER = "# Written by AuroraPanel (Nginx Websites). Edit there: changes here are overwritten.\n"
BASE = f"""SecRequestBodyAccess On
SecRequestBodyLimit 13107200
SecRequestBodyNoFilesLimit 131072
SecRequestBodyLimitAction Reject
SecResponseBodyAccess Off
SecArgumentSeparator &
SecCookieFormat 0
SecAuditEngine RelevantOnly
SecAuditLogParts ABFHZ
SecAuditLogType Serial
SecAuditLogFormat JSON
SecAuditLog {AUDIT.as_posix()}
"""


class NginxWafError(RuntimeError):
    pass


def module_installed() -> bool:
    return any(glob.glob(p) for p in MODULE_GLOBS)


def find_crs() -> tuple[str, list[str]] | None:
    """The rule set's setup file and its rule files in load order, or None when it isn't installed."""
    for setup, folder in CRS_LAYOUTS:
        rules = sorted(glob.glob(f"{folder}/*.conf"))
        if Path(setup).exists() and rules:
            return setup, rules
    return None


def mode() -> str:
    try:
        m = json.loads(STATE.read_text(encoding="utf-8")).get("mode")
    except (OSError, ValueError):
        return "off"
    return m if m in MODES else "off"


def render_post(s: dict) -> str:
    """Rules switched off on the WAF Firewall page. ModSecurity 3 has no <IfModule>, so this isn't Apache's file."""
    ids = sorted(s.get("disabled_rules", {}), key=int)
    return HEADER + "".join(f"SecRuleRemoveById {int(i)}\n" for i in ids)


def render_main(setup: str, rules: list[str]) -> str:
    lines = [HEADER.rstrip(), BASE.rstrip(), f"Include {PRE.as_posix()}", f"Include {setup}", *[f"Include {r}" for r in rules], f"Include {POST.as_posix()}"]
    return "\n".join(lines) + "\n"


def _files(m: str) -> dict:
    """Every file for this mode. Off still leaves the rules out of Nginx altogether, so it costs nothing."""
    if m == "off":
        return {HOOK: None}
    crs = find_crs()
    if not module_installed() or not crs:
        raise NginxWafError("The WAF for Nginx isn't installed yet")
    s = waf.load()
    return {PRE: waf.render_pre({**s, "mode": m}), POST: render_post(s), MAIN: render_main(*crs),
            HOOK: f"{HEADER}modsecurity on;\nmodsecurity_rules_file {MAIN.as_posix()};\n"}


def set_mode(m: str) -> dict:
    if m not in MODES:
        raise NginxWafError("Mode must be block, detect or off")
    try:
        files = _files(m)
        DIR.mkdir(parents=True, exist_ok=True)
        off_list = Path("/etc/modsecurity/aurora-sites-off.txt")  # the WAF Firewall page's list of sites with it off
        if m != "off" and waf.load().get("sites_off") and not off_list.exists():
            off_list.parent.mkdir(parents=True, exist_ok=True)
            off_list.write_text("\n".join(waf.load()["sites_off"]) + "\n", encoding="utf-8")
        nginxsites._apply(files)
    except nginxsites.NginxError as exc:
        raise NginxWafError(str(exc)) from exc
    STATE.parent.mkdir(parents=True, exist_ok=True)
    STATE.write_text(json.dumps({"mode": m}), encoding="utf-8")
    return status()


def refresh() -> None:
    """The WAF Firewall page changed something: pass it on, if this WAF is on."""
    m = mode()
    if m != "off" and HOOK.exists():
        try:
            nginxsites._apply(_files(m))
        except (nginxsites.NginxError, NginxWafError):
            raise
    return None


def status() -> dict:
    crs = find_crs()
    m = mode()
    on = HOOK.exists()
    return {"module": module_installed(), "rules": bool(crs), "rule_files": len(crs[1]) if crs else 0, "installed": module_installed() and bool(crs),
            "mode": m if on else "off", "protecting": on and m == "block" and nginxsites._active("nginx"), "audit_log": AUDIT.as_posix()}


def install(then_mode: str = "block") -> jobs.Job:
    if then_mode not in MODES:
        raise NginxWafError("Mode must be block, detect or off")
    if distro.is_dnf():
        policy = subprocess.run(["apt-cache", "policy", PACKAGES[0]], capture_output=True, text=True, timeout=120, env={"PATH": distro.PATH}).stdout
        if "Candidate: (none)" in policy:
            raise NginxWafError(f"{distro.name()}'s package repositories don't have ModSecurity for Nginx. Apache has a WAF here.")

    def fn(log):
        log.progress(5, "Installing ModSecurity for Nginx and the Core Rule Set")
        rc = log.apt(["install", *PACKAGES], (5, 85))
        if rc != 0:
            raise NginxWafError(f"The install failed (exit {rc})")
        log.progress(90, "Switching the WAF on")
        status_now = set_mode(then_mode)
        log(f"• WAF for Nginx is in {status_now['mode']} mode, with {status_now['rule_files']} rule files")
        log.progress(100, "WAF ready")
        return {"ok": True}
    return jobs.launch_fn("install WAF for Nginx", fn, meta={"area": "nginx-waf"})


def is_local_only(url: str) -> bool:
    """Is this reverse proxy target on this machine? If it also listens publicly, visitors could go around the WAF."""
    return bool(re.match(r"^https?://(127\.\d+\.\d+\.\d+|localhost|\[::1\])(:\d+)?(/|$)", url or ""))
