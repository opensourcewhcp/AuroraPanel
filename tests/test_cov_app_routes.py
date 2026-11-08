"""Every plain pass-through route in backend/app.py, driven by one table.

Each entry names the route, the backend function it must call, the exact arguments the route
has to hand over, and the error class whose message must come back as the HTTP detail. The
backend is stubbed, so this runs the same on the Windows dev box and on Linux CI without root.
"""
from __future__ import annotations

import importlib
import types

import pytest

# The exception each module raises, caught by the route and turned into a 400 (or the status given).
ERR = {
    "netmgr": "NetError", "apps": "AppError", "services": "ServiceError", "files": "FileError",
    "packages": "PackageError", "cron": "CronError", "users": "UserError", "sshtwofa": "SshTwofaError",
    "firewall": "FirewallError", "diskusage": "DiskUsageError", "backups": "BackupError",
    "panelhttps": "PanelHttpsError", "appconfig": "AppConfigError", "shadow": "ShadowError",
    "secreport": "SecReportError", "apache": "ApacheError", "netdiag": "NetDiagError",
    "antivirus": "AntivirusError", "sshaccess": "SSHError", "ipblocker": "IPBlockError",
    "sslcerts": "SSLCertError", "apitokens": "APITokenError", "modsecurity": "ModSecError",
    "waf": "WafError", "fail2ban": "Fail2banError", "perms": "PermError", "sites": "SiteError",
    "proxysites": "ProxyError", "dnszones": "ZoneError", "domains": "DomainError",
    "databases": "DatabaseError", "appmanager": "AppError", "phpmgr": "PHPError",
    "phpsettings": "PHPSettingsError", "mail": "MailError", "abuse": "AbuseError",
    "requires": "RequiresError", "sysapps": "SysAppError", "vpncommon": "VPNError",
    "wireguard": ("vpncommon", "VPNError"), "openvpn": ("vpncommon", "VPNError"),
    "ipsec": ("vpncommon", "VPNError"), "netmon": ("vpncommon", "VPNError"), "ddns": "DDNSError",
    "portcheck": "PortError", "instaban": "InstaBanError", "guard": "GuardError", "images": "ImageError",
    "webaccess": "WebAccessError", "gitvc": "GitError", "ftp": "FTPError", "version": "UpdateError",
    "alerts": "AlertError", "slackbot": "SlackError", "schedules": "ScheduleError", "updates": "UpdateError",
    "wptoolkit": "WPError", "migrate": "MigrateError", "servers": "ServerError", "dockerapps": "DockerError",
    "isolate": "IsolateError", "autossl": "AutoSSLError", "metrics": "MetricsError", "ddnshosts": "DdnsError",
    "panelusers": "PanelUserError", "dmarc": "DmarcError",
}


def R(method, url, mod, fn, args=(), kwargs=None, body=None, params=None, err=True, status=400, wrap=None, extra=()):
    """One route: what it calls, with what, and how its answer and its error come back.

    wrap: None = the stub's dict is the whole answer; "job" = the stub returns a job and the answer is
    {"job": id}; "merge" = the stub's dict is part of the answer; any other string = the answer's key
    that holds the stub's dict. extra = other (module, function, value) stubs the route needs."""
    return {"method": method, "url": url, "mod": mod, "fn": fn, "args": tuple(args), "kwargs": kwargs or {},
            "body": body, "params": params, "err": err, "status": status, "wrap": wrap, "extra": extra}


HOST, PORT, IP = "testserver", 80, "testclient"

ROUTES = [
    # ---- network manager
    R("GET", "/api/net/overview", "netmgr", "overview", (HOST,)),
    R("POST", "/api/net/ipv4", "netmgr", "set_ipv4", ("u1", "manual", "10.0.0.5/24", "10.0.0.1", ["1.1.1.1"], HOST, PORT),
      body={"uuid": "u1", "method": "manual", "address": "10.0.0.5/24", "gateway": "10.0.0.1", "dns": ["1.1.1.1"]}),
    R("GET", "/api/net/wifi", "netmgr", "wifi_scan", (False,), params={"rescan": "false"}),
    R("POST", "/api/net/wifi/connect", "netmgr", "wifi_connect", ("Net", "pw", "wlan0", True, HOST, PORT),
      body={"ssid": "Net", "password": "pw", "device": "wlan0", "hidden": True}),
    R("POST", "/api/net/wifi/forget", "netmgr", "wifi_forget", ("Net",), body={"name": "Net"}),
    R("POST", "/api/net/wifi/radio", "netmgr", "wifi_radio", (True, HOST), body={"on": True}),
    R("GET", "/api/net/hotspot", "netmgr", "hotspot_status", err=None),
    R("POST", "/api/net/hotspot/start", "netmgr", "hotspot_start", ("Spot", "pw12345678", "wlan0", "a", HOST),
      body={"ssid": "Spot", "password": "pw12345678", "device": "wlan0", "band": "a"}),
    R("POST", "/api/net/hotspot/stop", "netmgr", "hotspot_stop"),
    R("POST", "/api/net/hostname", "netmgr", "set_hostname", ("pi5",), body={"name": "pi5"}),
    R("GET", "/api/net/neighbours", "netmgr", "neighbours", err=None),
    R("GET", "/api/net/ports", "netmgr", "ports", err=None),
    R("GET", "/api/net/pending", "netmgr", "pending_status", err=None, wrap="pending"),
    R("POST", "/api/net/confirm", "netmgr", "confirm", ("p1",), body={"id": "p1"}),
    R("POST", "/api/net/revert", "netmgr", "revert_now", ("p1",), body={"id": "p1"}),
    # ---- applications (installer)
    R("GET", "/api/apps2/status", "apps", "status", err=None),
    R("POST", "/api/apps2/wordpress", "apps", "install_wordpress", ({"site": "a.com"},), body={"options": {"site": "a.com"}}, wrap="job"),
    R("POST", "/api/apps2/remove", "apps", "uninstall", ("/var/www/a", False, True), body={"path": "/var/www/a", "drop_db": False, "remove_site": True}),
    R("GET", "/api/apps2/catalog", "apps", "catalog", err=None),
    R("GET", "/api/apps2/latest", "apps", "latest", ("nextcloud",), params={"app_id": "nextcloud"}),
    R("POST", "/api/apps2/preview", "apps", "preview", ({"x": 1, "app": "wp"},), body={"app": "wp", "options": {"x": 1}}),
    R("POST", "/api/apps2/install", "apps", "install", ("wp", {"x": 1}), body={"app": "wp", "options": {"x": 1}}, wrap="job"),
    R("GET", "/api/apps2/password", "apps", "suggest_password", err=None),
    # ---- services
    R("GET", "/api/services", "services", "list_services", err=True, status=500, wrap="services"),
    R("POST", "/api/services/control", "services", "control_service", ("nginx", "restart"), body={"unit": "nginx", "action": "restart"}),
    R("GET", "/api/services/status", "services", "service_status", ("nginx",), params={"unit": "nginx"}),
    # ---- file manager
    R("GET", "/api/files/list", "files", "list_dir", ("www",), params={"path": "www"}),
    R("GET", "/api/files/read", "files", "read_text", ("a.txt",), params={"path": "a.txt"}),
    R("POST", "/api/files/write", "files", "write_text", ("a.txt", "hi"), body={"path": "a.txt", "content": "hi"}),
    R("POST", "/api/files/move", "files", "transfer", ("src", ["a"], "dst", "move", True), body={"path": "src", "names": ["a"], "dest": "dst", "overwrite": True}),
    R("POST", "/api/files/copy", "files", "transfer", ("src", ["a"], "dst", "copy", False), body={"path": "src", "names": ["a"], "dest": "dst"}),
    R("POST", "/api/files/delete", "files", "delete", ("a.txt", True), body={"path": "a.txt", "permanent": True}),
    R("POST", "/api/files/zip", "files", "zip_entries", ("d", ["a", "b"], "x.zip", True), body={"path": "d", "names": ["a", "b"], "archive_name": "x.zip", "overwrite": True}),
    R("POST", "/api/files/unzip", "files", "unzip", ("x.zip", True), body={"path": "x.zip", "overwrite": True}),
    R("GET", "/api/files/trash", "files", "list_trash", err=None),
    R("POST", "/api/files/trash/restore", "files", "restore_trash", ("t1", True), body={"id": "t1", "overwrite": True}),
    R("POST", "/api/files/trash/delete", "files", "delete_trash", ("t1",), body={"id": "t1"}),
    R("POST", "/api/files/trash/empty", "files", "empty_trash", err=None),
    R("POST", "/api/files/mkdir", "files", "make_dir", ("d", "new"), body={"path": "d", "name": "new"}),
    # ---- jobs, packages
    R("GET", "/api/jobs", "jobs", "listing", err=None, wrap="jobs"),
    R("GET", "/api/packages/installed", "packages", "installed", err=None, wrap="packages"),
    R("GET", "/api/packages/upgradable", "packages", "upgradable", wrap="packages"),
    R("GET", "/api/packages/search", "packages", "search", ("vim",), params={"q": "vim"}, wrap="results"),
    R("POST", "/api/packages/update", "packages", "job_update", wrap="job"),
    R("POST", "/api/packages/upgrade", "packages", "job_upgrade", wrap="job"),
    R("POST", "/api/packages/install", "packages", "job_install", (["vim"],), body={"packages": ["vim"]}, wrap="job"),
    R("POST", "/api/packages/remove", "packages", "job_remove", (["vim"],), body={"packages": ["vim"]}, wrap="job"),
    # ---- cron
    R("GET", "/api/cron", "cron", "list_jobs", wrap="merge"),
    R("POST", "/api/cron/add", "cron", "add_job", ("* * * * *", "ls", "L"), body={"schedule": "* * * * *", "command": "ls", "label": "L"}),
    R("POST", "/api/cron/update", "cron", "update_job", ("raw", "0 * * * *", "ls", None, True), body={"raw": "raw", "schedule": "0 * * * *", "command": "ls", "paused": True}),
    R("POST", "/api/cron/pause", "cron", "set_paused", ("raw", True), body={"raw": "raw", "paused": True}),
    R("POST", "/api/cron/run", "cron", "run_now", ("raw",), body={"raw": "raw"}),
    R("POST", "/api/cron/delete", "cron", "delete_job", ("raw",), body={"raw": "raw"}),
    # ---- linux users
    R("GET", "/api/users", "users", "list_users", kwargs={"include_system": True}, params={"include_system": "true"}, err=None, wrap="users"),
    R("POST", "/api/users/add", "users", "add_user", ("bob", False, "/bin/sh"), body={"name": "bob", "create_home": False, "shell": "/bin/sh"}),
    R("POST", "/api/users/delete", "users", "delete_user", ("bob", True, True), body={"name": "bob", "remove_home": True, "backup": True}),
    R("POST", "/api/users/lock", "users", "set_lock", ("bob", True), body={"name": "bob", "locked": True}),
    R("POST", "/api/users/password", "users", "set_password", ("bob", "secret12"), body={"name": "bob", "password": "secret12"}),
    R("POST", "/api/users/2fa/enroll", "sshtwofa", "enroll", ("bob",), body={"name": "bob"}),
    R("POST", "/api/users/2fa/confirm", "sshtwofa", "confirm", ("bob", "123456"), body={"name": "bob", "code": "123456"}),
    R("POST", "/api/users/2fa/disable", "sshtwofa", "disable", ("bob",), body={"name": "bob"}),
    # ---- firewall, disk usage
    R("GET", "/api/firewall", "firewall", "status", err=None),
    R("POST", "/api/firewall/toggle", "firewall", "set_enabled", (True,), body={"enabled": True}),
    R("POST", "/api/firewall/rule", "firewall", "add_rule", ("allow", "22", "udp"), body={"action": "allow", "port": "22", "proto": "udp"}),
    R("POST", "/api/firewall/delete", "firewall", "delete_rule", (3,), body={"num": 3}),
    R("GET", "/api/diskusage", "diskusage", "children_sizes", ("/var",), params={"path": "/var"}),
    # ---- backups
    R("GET", "/api/backups", "backups", "list_backups", err=None),
    R("POST", "/api/backups/create", "backups", "create_backup", ("/srv", "L"), body={"source": "/srv", "label": "L"}, wrap="job"),
    R("POST", "/api/backups/restore", "backups", "restore_backup", ("b.tgz", "/tmp"), body={"name": "b.tgz", "dest": "/tmp"}, wrap="job"),
    R("POST", "/api/backups/database", "backups", "backup_database", ("mysql", "shop", "L"), body={"engine": "mysql", "db": "shop", "label": "L"}, wrap="job"),
    R("POST", "/api/backups/restore-db", "backups", "restore_database", ("d.sql", "shop", "mysql", False), body={"name": "d.sql", "target": "shop", "engine": "mysql", "wipe": False}, wrap="job"),
    R("GET", "/api/backups/jobs", "backups", "backup_jobs", err=None),
    R("POST", "/api/backups/delete", "backups", "delete_backup", ("b.tgz",), body={"name": "b.tgz"}),
    # ---- 2fa, panel https, apache hardening
    R("GET", "/api/2fa/status", "twofa", "status", err=None),
    R("POST", "/api/2fa/enroll", "twofa", "begin_enroll", ("tester",), err=None),
    R("GET", "/api/panel/https", "panelhttps", "status", ("http", HOST), err=None),
    R("POST", "/api/panel/https/enable", "panelhttps", "enable", ("le", True, "pi.example"), body={"source": "le", "regenerate": True, "host": "pi.example"}),
    R("POST", "/api/panel/https/confirm", "panelhttps", "confirm", ("http",)),
    R("POST", "/api/panel/https/disable", "panelhttps", "disable", err=None),
    R("POST", "/api/panel/https/harden", "panelhttps", "harden"),
    R("POST", "/api/panel/https/redirect", "panelhttps", "harden"),
    R("GET", "/api/apache/hardening", "appconfig", "apache_hardening", err=None),
    R("POST", "/api/apache/harden", "appconfig", "apache_harden"),
    # ---- shadow copies
    R("GET", "/api/shadow", "shadow", "overview", err=None),
    R("GET", "/api/shadow/files", "shadow", "files", ("s1", "x", "changed"), params={"id": "s1", "q": "x", "only": "changed"}),
    R("POST", "/api/shadow/enable", "shadow", "set_enabled", ("s1", True), body={"id": "s1", "on": True}),
    R("POST", "/api/shadow/settings", "shadow", "set_settings", ("s1", 7, 5, 100, 10), body={"id": "s1", "keep_days": 7, "max_versions": 5, "max_mb": 100, "max_file_mb": 10}),
    R("POST", "/api/shadow/snapshot", "shadow", "snapshot", ("s1",), body={"id": "s1"}),
    R("POST", "/api/shadow/snapshot", "shadow", "snapshot_all", body={"id": "*"}, err=None, wrap="sites"),
    R("POST", "/api/shadow/restore", "shadow", "restore", ("s1", "a/b", 0), body={"id": "s1", "path": "a/b"}),
    R("POST", "/api/shadow/forget", "shadow", "forget", ("s1", "a/b", 5), body={"id": "s1", "path": "a/b", "ts": 5}),
    # ---- security report
    R("GET", "/api/secreport", "secreport", "overview", err=None),
    R("POST", "/api/secreport/run", "secreport", "start", (None, False), body={"targets": []}),
    R("POST", "/api/secreport/run", "secreport", "start", (["a.com"], True), body={"targets": ["a.com"], "deep": True}),
    R("POST", "/api/secreport/accept", "secreport", "accept", ("site:a|csp", True, "lan"), body={"key": "site:a|csp", "note": "lan"}),
    R("GET", "/api/dmarc", "dmarc", "status", ("x.com",), params={"domain": "x.com"}),
    R("POST", "/api/dmarc/recommend", "dmarc", "recommend", ("x.com", {"sends": "none"}), body={"domain": "x.com", "answers": {"sends": "none"}}),
    R("POST", "/api/dmarc/save", "dmarc", "save", ("x.com", {"p": "reject"}), body={"domain": "x.com", "settings": {"p": "reject"}}),
    R("POST", "/api/dmarc/remove", "dmarc", "remove", ("x.com",), body={"domain": "x.com"}),
    R("POST", "/api/secreport/fix", "secreport", "fix", ("headers",), body={"action": "headers"}),
    # ---- apache .htaccess
    R("GET", "/api/apache/htaccess", "apache", "raw", ("d",), params={"dir": "d"}),
    R("GET", "/api/apache/indexes", "apache", "get_indexes", ("d",), params={"dir": "d"}, wrap="merge"),
    R("POST", "/api/apache/indexes", "apache", "set_indexes", ("d", True, "index.php"), body={"dir": "d", "listing": True, "directory_index": "index.php"}),
    R("GET", "/api/apache/mime", "apache", "list_mime", ("d",), params={"dir": "d"}, wrap="merge", extra=(("apache", "system_mime", {}),)),
    R("POST", "/api/apache/mime", "apache", "add_mime", ("d", "text/x", "x"), body={"dir": "d", "mime": "text/x", "extensions": "x"}),
    R("GET", "/api/apache/errors", "apache", "list_errors", ("d",), params={"dir": "d"}),
    R("POST", "/api/apache/errors", "apache", "set_error", ("d", "404", "/404.html", "404.html"), body={"dir": "d", "code": "404", "document": "/404.html", "create": "404.html"}),
    R("GET", "/api/apache/handlers", "apache", "list_handlers", ("d",), params={"dir": "d"}),
    R("POST", "/api/apache/handlers", "apache", "add_handler", ("d", "cgi-script", "cgi"), body={"dir": "d", "handler": "cgi-script", "extensions": "cgi"}),
    R("GET", "/api/apache/options", "apache", "list_options", ("d",), params={"dir": "d"}),
    R("POST", "/api/apache/options", "apache", "set_option", ("d", "Indexes", False), body={"dir": "d", "name": "Indexes", "on": False}),
    R("POST", "/api/apache/remove", "apache", "remove_directive", ("d", "AddType x"), body={"dir": "d", "raw": "AddType x"}),
    R("GET", "/api/apache/hotlink", "apache", "get_hotlink", ("d",), params={"dir": "d"}, wrap="merge"),
    R("POST", "/api/apache/hotlink", "apache", "set_hotlink", ("d", True, "a.com", "jpg"), body={"dir": "d", "enabled": True, "allowed_hosts": "a.com", "extensions": "jpg"}),
    R("GET", "/api/apache/redirects", "apache", "list_redirects", ("d",), params={"dir": "d"}),
    R("POST", "/api/apache/redirects", "apache", "add_redirect", ("d", "301", "/old", "/new"), body={"dir": "d", "code": "301", "source": "/old", "target": "/new"}),
    # ---- dns tools
    R("GET", "/api/dns/records", "netdiag", "dns_records", ("a.com", ["A", "MX"], "8.8.8.8"), params={"host": "a.com", "types": "a,mx", "server": "8.8.8.8"}),
    R("GET", "/api/dns/propagation", "netdiag", "propagation", ("a.com", "AAAA"), params={"host": "a.com", "type": "aaaa"}),
    R("GET", "/api/dns/mailcheck", "netdiag", "mail_check", ("a.com",), params={"domain": "a.com"}),
    R("GET", "/api/dns/nscheck", "netdiag", "ns_check", ("a.com",), params={"domain": "a.com"}),
    R("GET", "/api/dns/whois", "netdiag", "whois", ("a.com",), params={"host": "a.com"}),
    R("GET", "/api/dns/reverse", "netdiag", "reverse_lookup", ("1.1.1.1",), params={"ip": "1.1.1.1"}),
    R("GET", "/api/dns/traceroute", "netdiag", "traceroute", ("a.com",), params={"host": "a.com"}),
    R("GET", "/api/net/ping", "netdiag", "ping", ("a.com", 2), params={"host": "a.com", "count": 2}),
    # ---- antivirus, ssh, ip blocker, certificates, tokens
    R("GET", "/api/antivirus/status", "antivirus", "status", err=None),
    R("POST", "/api/antivirus/scan", "antivirus", "scan", ("/srv", False), body={"path": "/srv", "recursive": False}, wrap="job"),
    R("POST", "/api/antivirus/update", "antivirus", "update_db", wrap="job"),
    R("GET", "/api/ssh/status", "sshaccess", "status", err=None),
    R("POST", "/api/ssh/restart", "sshaccess", "restart"),
    R("GET", "/api/ssh/keys", "sshaccess", "list_keys", ("bob",), params={"target": "bob"}),
    R("POST", "/api/ssh/keys/add", "sshaccess", "add_key", ("bob", "ssh-ed25519 AAA"), body={"user": "bob", "public_key": "ssh-ed25519 AAA"}),
    R("POST", "/api/ssh/keys/remove", "sshaccess", "remove_key", ("bob", "ssh-ed25519 AAA"), body={"user": "bob", "raw": "ssh-ed25519 AAA"}),
    R("GET", "/api/ipblocker", "ipblocker", "list_blocked", err=None),
    R("POST", "/api/ipblocker/block", "ipblocker", "block", ("1.2.3.4", IP), body={"ip": "1.2.3.4"}),
    R("POST", "/api/ipblocker/unblock", "ipblocker", "unblock", (2,), body={"num": 2}),
    R("GET", "/api/ssl/certs", "sslcerts", "list_certs"),
    R("POST", "/api/ssl/selfsigned", "sslcerts", "generate_self_signed", ("pi.local", 30), body={"common_name": "pi.local", "days": 30}),
    R("GET", "/api/tokens", "apitokens", "listing", err=None),
    R("POST", "/api/tokens/create", "apitokens", "create", ("ci", "read", "", None), body={"name": "ci"}),
    R("POST", "/api/tokens/revoke", "apitokens", "revoke", ("t1",), body={"id": "t1"}),
    # ---- modsecurity, waf, fail2ban, perms
    R("GET", "/api/modsecurity", "modsecurity", "status", err=None),
    R("POST", "/api/modsecurity/toggle", "modsecurity", "set_enabled", (False,), body={"enabled": False}),
    R("POST", "/api/modsecurity/install", "modsecurity", "install", err=None, wrap="job"),
    R("GET", "/api/waf", "waf", "status", err=None),
    R("POST", "/api/waf", "waf", "update", ({"mode": "on", "paranoia": 2},), body={"mode": "on", "paranoia": 2}),
    R("POST", "/api/waf/allow-rule", "waf", "allow_rule", ("941100", "xss"), body={"id": "941100", "msg": "xss"}),
    R("POST", "/api/waf/restore-rule", "waf", "restore_rule", ("941100",), body={"id": "941100"}),
    R("POST", "/api/waf/test", "waf", "test"),
    R("GET", "/api/fail2ban", "fail2ban", "status", err=None),
    R("POST", "/api/fail2ban/unban", "fail2ban", "unban", ("sshd", "1.2.3.4"), body={"jail": "sshd", "ip": "1.2.3.4"}),
    R("POST", "/api/fail2ban/install", "fail2ban", "install", err=None, wrap="job"),
    R("POST", "/api/fail2ban/service", "fail2ban", "enable_service", (True,), body={"on": True}),
    R("POST", "/api/fail2ban/ban", "fail2ban", "ban", ("sshd", "1.2.3.4", IP), body={"jail": "sshd", "ip": "1.2.3.4"}),
    R("GET", "/api/fail2ban/logs", "fail2ban", "logs", (50,), params={"lines": 50}, err=None, wrap="text"),
    R("GET", "/api/fail2ban/logs", "fail2ban", "logs", (20,), params={"lines": 1}, err=None, wrap="text"),
    R("GET", "/api/fail2ban/events", "fail2ban", "events", (100,), params={"limit": 100}, err=None),
    R("POST", "/api/fail2ban/events/delete", "fail2ban", "dismiss", (["k1"],), body={"keys": ["k1"]}),
    R("POST", "/api/fixperms", "perms", "fix_home", ("bob",), body={"name": "bob"}),
    # ---- websites
    R("GET", "/api/sites", "sites", "list_sites", err=None),
    R("GET", "/api/sites/get", "sites", "get_site", ("a.com",), params={"name": "a.com"}),
    R("POST", "/api/sites/create", "sites", "create_site", ({"server_name": "a.com"},), body={"settings": {"server_name": "a.com"}}),
    R("POST", "/api/sites/save", "sites", "save_site", ("a.com", {"server_name": "b.com"}), body={"original": "a.com", "settings": {"server_name": "b.com"}}),
    R("POST", "/api/sites/toggle", "sites", "quick_toggle", ("a.com", "ssl", True), body={"server_name": "a.com", "key": "ssl", "value": True}),
    R("POST", "/api/sites/system-ssl", "sites", "set_system_ssl", ("000-default", "self", "c", "k", "ch"), body={"conf": "000-default", "ssl": "self", "cert": "c", "key": "k", "chain": "ch"}),
    R("POST", "/api/sites/system-adopt", "sites", "adopt_system_conf", ("x.conf",), body={"conf": "x.conf"}),
    R("POST", "/api/sites/folders/indexes", "sites", "set_folder_site_indexes", ("blog", True), body={"name": "blog", "on": True}),
    R("POST", "/api/sites/conf", "sites", "save_conf_text", ("a.com", "<VirtualHost>"), body={"name": "a.com", "text": "<VirtualHost>"}),
    R("GET", "/api/proxy", "proxysites", "list_proxies", err=None),
    R("POST", "/api/proxy/create", "proxysites", "create_proxy", ("p.a.com", "http://127.0.0.1:81", False, ["q.a.com"]), body={"domain": "p.a.com", "target": "http://127.0.0.1:81", "websockets": False, "aliases": ["q.a.com"]}),
    R("POST", "/api/proxy/delete", "proxysites", "delete_proxy", ("p.a.com",), body={"name": "p.a.com"}),
    R("POST", "/api/sites/system-custom", "sites", "set_system_custom", ("000-default", "# x"), body={"conf": "000-default", "custom": "# x"}),
    R("POST", "/api/sites/remove", "sites", "remove_site", ("a.com", True, True), body={"server_name": "a.com", "delete_files": True, "backup": True}),
    R("GET", "/api/sites/folders", "sites", "list_folder_sites", err=None),
    R("POST", "/api/sites/folders/create", "sites", "create_folder_site", ("blog", "/srv/blog"), body={"name": "blog", "path": "/srv/blog"}),
    R("POST", "/api/sites/folders/remove", "sites", "remove_folder_site", ("blog", True, True), body={"name": "blog", "delete_files": True, "backup": True}),
    R("POST", "/api/sites/certbot/install", "sites", "certbot_install", err=None, wrap="job"),
    R("POST", "/api/sites/letsencrypt", "sites", "issue_letsencrypt", ("a.com", "me@a.com", False, True), body={"server_name": "a.com", "email": "me@a.com", "include_aliases": False, "force": True}, wrap="job"),
    R("POST", "/api/sites/selfsigned/regenerate", "sites", "regenerate_selfsigned", ("a.com",), body={"name": "a.com"}),
    # ---- zone editor, domains
    R("GET", "/api/dns/zone", "dnszones", "get_zone", ("a.com",), params={"domain": "a.com"}),
    R("POST", "/api/dns/zone/create", "dnszones", "create_zone", ("a.com", "1.2.3.4", "mail"), body={"domain": "a.com", "ip": "1.2.3.4", "mode": "mail"}),
    R("POST", "/api/dns/zone/delete", "dnszones", "delete_zone", ("a.com",), body={"domain": "a.com"}),
    R("POST", "/api/dns/record/add", "dnszones", "add_record", ("a.com", {"type": "A"}), body={"domain": "a.com", "record": {"type": "A"}}),
    R("POST", "/api/dns/record/update", "dnszones", "update_record", ("a.com", 2, {"type": "A"}, {"h": 1}), body={"domain": "a.com", "index": 2, "record": {"type": "A"}, "fingerprint": {"h": 1}}),
    R("POST", "/api/dns/record/delete", "dnszones", "delete_record", ("a.com", 2, None), body={"domain": "a.com", "index": 2}),
    R("GET", "/api/dns/secondaries", "dnszones", "secondary_settings", err=None),
    R("POST", "/api/dns/secondaries", "dnszones", "set_secondaries", (False, ["ns2.x"]), body={"auto": False, "extra": ["ns2.x"]}),
    R("GET", "/api/domains/vhosts", "domains", "list_vhosts"),
    R("POST", "/api/domains/vhosts/create", "domains", "create_vhost", ("a.com", "/srv/a", 8080), body={"server_name": "a.com", "docroot": "/srv/a", "port": 8080}),
    R("POST", "/api/domains/vhosts/remove", "domains", "remove_vhost", ("a.com",), body={"server_name": "a.com"}),
    R("GET", "/api/domains/info", "domains", "domain_info", ("a.com",), params={"name": "a.com"}),
    R("GET", "/api/domains/dyndns", "domains", "dyndns_status", err=None),
    R("POST", "/api/domains/dyndns/run", "domains", "dyndns_run"),
    R("POST", "/api/domains/dyndns/install", "domains", "dyndns_install", err=None, wrap="job"),
    R("GET", "/api/domains/zones", "domains", "zones", err=None),
    R("GET", "/api/domains/zone", "domains", "zone_content", ("a.com",), params={"name": "a.com"}),
    R("POST", "/api/domains/bind/install", "domains", "bind_install", err=None, wrap="job"),
    # ---- databases
    R("GET", "/api/db/overview", "databases", "overview", err=None),
    R("POST", "/api/db/mysql/create", "databases", "mysql_create_db", ("shop",), body={"name": "shop"}),
    R("POST", "/api/db/mysql/drop", "databases", "mysql_drop_db", ("shop",), body={"name": "shop"}),
    R("POST", "/api/db/mysql/wizard", "databases", "mysql_wizard", ("shop", "bob", "pw", "%"), body={"db": "shop", "user": "bob", "password": "pw", "host": "%"}),
    R("POST", "/api/db/mysql/user/create", "databases", "mysql_create_user", ("bob", "localhost", "pw", "shop", True), body={"user": "bob", "password": "pw", "db": "shop", "admin": True}),
    R("POST", "/api/db/mysql/user/password", "databases", "mysql_set_password", ("bob", "localhost", "pw"), body={"user": "bob", "password": "pw"}),
    R("POST", "/api/db/mysql/user/admin", "databases", "mysql_set_admin", ("bob", "localhost", True), body={"user": "bob", "admin": True}),
    R("POST", "/api/db/mysql/user/drop", "databases", "mysql_drop_user", ("bob", "localhost"), body={"user": "bob"}),
    R("POST", "/api/db/mysql/grant", "databases", "mysql_grant", ("shop", "bob", "localhost", False), body={"db": "shop", "user": "bob", "on": False}),
    R("POST", "/api/db/phpmyadmin/install", "databases", "phpmyadmin_install", wrap="job"),
    R("POST", "/api/db/pg/role/create", "databases", "pg_create_role", ("bob", "pw", True, True, False, False), body={"name": "bob", "password": "pw", "createdb": True}),
    R("POST", "/api/db/pg/role/update", "databases", "pg_update_role", ("bob", False, False, False, True, 5), body={"name": "bob", "login": False, "superuser": True, "conn_limit": 5}),
    R("POST", "/api/db/pg/role/password", "databases", "pg_set_password", ("bob", "pw"), body={"name": "bob", "password": "pw"}),
    R("POST", "/api/db/pg/role/drop", "databases", "pg_drop_role", ("bob",), body={"name": "bob"}),
    R("POST", "/api/db/pg/grant", "databases", "pg_grant", ("shop", "bob", False), body={"db": "shop", "role": "bob", "grant": False}),
    R("POST", "/api/db/pg/owner", "databases", "pg_set_owner", ("shop", "bob"), body={"db": "shop", "role": "bob"}),
    R("POST", "/api/db/phppgadmin/lan", "databases", "phppgadmin_set_lan", (True,), body={"on": True}),
    R("POST", "/api/db/phppgadmin/install", "databases", "phppgadmin_install", wrap="job"),
    R("POST", "/api/db/pg/repair", "databases", "pg_repair"),
    R("POST", "/api/db/pg/create", "databases", "pg_create_db_owned", ("shop", "bob"), body={"name": "shop", "owner": "bob"}),
    R("POST", "/api/db/pg/drop", "databases", "pg_drop_db_force", ("shop",), body={"name": "shop"}),
    R("POST", "/api/db/pg/wizard", "databases", "pg_wizard", ("shop", "bob", "pw"), body={"db": "shop", "role": "bob", "password": "pw"}),
    R("POST", "/api/db/install", "databases", "install_pkg", ("mariadb",), body={"pkg": "mariadb"}, wrap="job"),
    # ---- application manager, php
    R("GET", "/api/apps", "appmanager", "list_apps", err=None),
    R("POST", "/api/apps/create", "appmanager", "create_app", ("bot", "/srv/bot", "python3 bot.py", False), body={"name": "bot", "workdir": "/srv/bot", "command": "python3 bot.py", "autostart": False}),
    R("POST", "/api/apps/control", "appmanager", "control_app", ("bot", "stop"), body={"name": "bot", "action": "stop"}),
    R("POST", "/api/apps/remove", "appmanager", "remove_app", ("bot",), body={"name": "bot"}),
    R("GET", "/api/apps/logs", "appmanager", "logs", ("bot",), params={"name": "bot"}),
    R("GET", "/api/php", "phpmgr", "status", err=None),
    R("POST", "/api/php/set", "phpmgr", "set_cli_version", ("8.2",), body={"version": "8.2"}),
    R("GET", "/api/php/settings/overview", "phpsettings", "overview"),
    R("GET", "/api/php/settings", "phpsettings", "get", ("8.2", "fpm"), params={"version": "8.2", "sapi": "fpm"}),
    R("POST", "/api/php/settings", "phpsettings", "save", ("8.2", ["fpm"], {"memory_limit": "256M"}, ["x"]), body={"version": "8.2", "sapis": ["fpm"], "changes": {"memory_limit": "256M"}, "reset": ["x"]}),
    R("GET", "/api/php/extensions", "phpsettings", "extensions", ("8.2",), params={"version": "8.2"}),
    R("POST", "/api/php/extensions/toggle", "phpsettings", "set_extension", ("8.2", "gd", "", False), body={"version": "8.2", "module": "gd", "on": False}),
    R("POST", "/api/php/extensions/install", "phpsettings", "install_extension", ("8.2", "gd"), body={"version": "8.2", "module": "gd"}, wrap="job"),
    R("POST", "/api/php/apache-version", "phpsettings", "set_apache_version", ("8.2",), body={"version": "8.2"}),
    # ---- email
    R("POST", "/api/mail/remote/add", "mail", "remote_add", ({"id": None, "preset": "gmail", "label": None, "email": "a@gmail.com", "username": None, "password": None,
                                                              "imap_host": None, "imap_port": None, "imap_enc": None, "smtp_host": None, "smtp_port": None, "smtp_enc": None},),
      body={"preset": "gmail", "email": "a@gmail.com"}),
    R("POST", "/api/mail/remote/remove", "mail", "remote_remove", ("",), body={}),
    R("POST", "/api/mail/remote/remove", "mail", "remote_remove", ("r1",), body={"id": "r1"}),
    R("POST", "/api/mail/inbox/clear", "mail", "inbox_clear", ("tester", ["m1"]), body={"ids": ["m1"]}, err=None, wrap="cleared"),
    R("POST", "/api/mail/domains/add", "mail", "add_domain", ("a.com",), body={"domain": "a.com"}),
    R("POST", "/api/mail/domains/remove", "mail", "remove_domain", ("a.com",), body={"domain": "a.com"}),
    R("POST", "/api/mail/domains/routing", "mail", "set_routing", ("a.com", "local"), body={"domain": "a.com"}),
    R("POST", "/api/mail/domains/routing", "mail", "set_routing", ("a.com", "remote"), body={"domain": "a.com", "routing": "remote"}),
    R("POST", "/api/mail/domains/catchall", "mail", "set_catchall", ("a.com", "fail", "", ""), body={"domain": "a.com"}),
    R("POST", "/api/mail/domains/catchall", "mail", "set_catchall", ("a.com", "forward", "x@a.com", "m"), body={"domain": "a.com", "mode": "forward", "target": "x@a.com", "message": "m"}),
    R("GET", "/api/mail/accounts", "mail", "list_accounts", err=None),
    R("POST", "/api/mail/accounts/create", "mail", "create_account", ("bob@a.com", "", 1024, ""), body={"address": "bob@a.com"}),
    R("POST", "/api/mail/accounts/create", "mail", "create_account", ("bob@a.com", "pw", 0, "Bob"), body={"address": "bob@a.com", "password": "pw", "quota_mb": 0, "name": "Bob"}),
    R("POST", "/api/mail/accounts/update", "mail", "update_account", ("bob@a.com", None, 5, {"on": True}, None), body={"address": "bob@a.com", "quota_mb": 5, "suspend": {"on": True}}),
    R("POST", "/api/mail/accounts/delete", "mail", "delete_account", ("bob@a.com", True), body={"address": "bob@a.com", "delete_mail": True}),
    R("GET", "/api/mail/accounts/device", "mail", "device_settings", ("bob@a.com",), params={"address": "bob@a.com"}),
    R("GET", "/api/mail/password", "mail", "gen_password", err=None, wrap="password"),
    R("GET", "/api/mail/forwarders", "mail", "list_forwarders", err=None),
    R("POST", "/api/mail/forwarders/add", "mail", "add_forwarder", ("a@a.com", "forward", "b@b.com", ""), body={"source": "a@a.com", "dest": "b@b.com"}),
    R("POST", "/api/mail/forwarders/delete", "mail", "delete_forwarder", ("a@a.com", None), body={"source": "a@a.com"}),
    R("POST", "/api/mail/forwarders/delete", "mail", "delete_forwarder", ("a@a.com", "b@b.com"), body={"source": "a@a.com", "dest": "b@b.com"}),
    R("POST", "/api/mail/forwarders/domain", "mail", "delete_domain_forwarder", ("a.com",), body={"source": "a.com", "kind": "delete"}),
    R("POST", "/api/mail/forwarders/domain", "mail", "add_domain_forwarder", ("a.com", "b.com"), body={"source": "a.com", "dest": "b.com"}),
    R("GET", "/api/mail/trace", "mail", "trace", ("bob@a.com",), params={"address": "bob@a.com"}),
    R("GET", "/api/mail/autoresponders", "mail", "list_autoresponders", err=None),
    R("POST", "/api/mail/autoresponders/save", "mail", "set_autoresponder", ("bob@a.com", {"subject": "Away"}), body={"owner": "bob@a.com", "data": {"subject": "Away"}}),
    R("POST", "/api/mail/autoresponders/delete", "mail", "delete_autoresponder", ("bob@a.com",), body={"owner": "bob@a.com"}),
    R("GET", "/api/mail/filters", "mail", "get_filters", ("global",)),
    R("GET", "/api/mail/filters", "mail", "get_filters", ("bob@a.com",), params={"owner": "bob@a.com"}),
    R("POST", "/api/mail/filters", "mail", "save_filters", ("bob@a.com", [{"r": 1}]), body={"owner": "bob@a.com", "filters": [{"r": 1}]}),
    R("GET", "/api/mail/spam", "mail", "get_spam", ("global",)),
    R("POST", "/api/mail/spam", "mail", "set_spam", ("global", {"score": 5}), body={"owner": "global", "data": {"score": 5}}),
    R("GET", "/api/mail/lists", "mail", "list_lists", err=None),
    R("POST", "/api/mail/lists/save", "mail", "save_list", ("all@a.com", {"members": []}, True), body={"address": "all@a.com", "data": {"members": []}, "create": True}),
    R("POST", "/api/mail/lists/delete", "mail", "delete_list", ("all@a.com",), body={"address": "all@a.com"}),
    R("GET", "/api/mail/track", "mail", "track", ("bob", "sent", 24), params={"q": "bob", "status": "sent", "hours": 24}),
    R("GET", "/api/mail/queue", "mail", "queue", err=None),
    R("POST", "/api/mail/queue", "mail", "queue_action", ("flush", ["q1"]), body={"action": "flush", "ids": ["q1"]}),
    R("GET", "/api/mail/deliverability", "mail", "deliverability_all"),
    R("GET", "/api/mail/deliverability", "mail", "deliverability", ("a.com",), params={"domain": "a.com"}),
    R("POST", "/api/mail/deliverability/install", "mail", "install_record", ("a.com", "dkim"), body={"domain": "a.com", "mode": "dkim"}),
    R("GET", "/api/mail/disk", "mail", "disk_overview", err=None),
    R("GET", "/api/mail/disk", "mail", "disk_usage", ("bob@a.com",), params={"address": "bob@a.com"}),
    R("POST", "/api/mail/disk/expunge", "mail", "expunge", ("bob@a.com", "Trash", 30), body={"address": "bob@a.com", "mailbox": "Trash", "older_days": 30}),
    R("POST", "/api/mail/import", "mail", "import_csv", ("accounts", "a,b", False, "a.com", 512), body={"kind": "accounts", "text": "a,b", "dry_run": False, "default_domain": "a.com", "quota_mb": 512}),
    R("GET", "/api/mail/tls", "mail", "get_tls", err=None),
    R("POST", "/api/mail/tls", "mail", "set_tls", ("self",), body={}),
    R("POST", "/api/mail/tls", "mail", "set_tls", ("le",), body={"value": "le"}),
    R("POST", "/api/mail/tls/issue", "mail", "issue_cert", wrap="job"),
    R("POST", "/api/mail/hostname", "mail", "set_hostname", ("mail.a.com",), body={"value": "mail.a.com"}),
    R("GET", "/api/mail/dav", "mail", "list_collections", err=None),
    R("POST", "/api/mail/dav/create", "mail", "create_collection", ("bob@a.com", "addressbook", "Work", "#fff", "d"), body={"owner": "bob@a.com", "kind": "addressbook", "name": "Work", "color": "#fff", "description": "d"}),
    R("POST", "/api/mail/dav/update", "mail", "update_collection", ("bob@a.com", "c1", "Work", "", ""), body={"owner": "bob@a.com", "id": "c1", "name": "Work"}),
    R("POST", "/api/mail/dav/delete", "mail", "delete_collection", ("bob@a.com", "c1"), body={"owner": "bob@a.com", "id": "c1"}),
    R("POST", "/api/mail/dav/share", "mail", "share_collection", ("bob@a.com", "c1", "ann@a.com", True), body={"owner": "bob@a.com", "id": "c1", "with_": "ann@a.com", "write": True}),
    R("POST", "/api/mail/dav/unshare", "mail", "unshare_collection", ("bob@a.com", "c1", "ann@a.com"), body={"owner": "bob@a.com", "id": "c1", "with_": "ann@a.com"}),
    R("POST", "/api/mail/local", "mail", "enable_local", (False,), body={"enabled": False}),
    R("POST", "/api/mail/track/settings", "mail", "set_track_settings", (14, True), body={"days": 14, "clear": True}),
    R("GET", "/api/abuse/preview", "abuse", "preview", ("1.2.3.4",), params={"ip": "1.2.3.4"}),
    R("GET", "/api/abuse/reported", "abuse", "reported", err=None),
    R("POST", "/api/abuse/report", "abuse", "report", ("1.2.3.4", "me@a.com", "abuse@isp", "n", True), body={"ip": "1.2.3.4", "sender": "me@a.com", "to": "abuse@isp", "note": "n", "force": True}),
    R("POST", "/api/mail/test", "mail", "send_test", ("x@b.com", "me@a.com"), body={"to": "x@b.com", "sender": "me@a.com"}),
    # ---- requirements, system applications
    R("GET", "/api/requires", "requires", "status", (["php", "mariadb"],), params={"ids": "php,mariadb"}, err=None),
    R("POST", "/api/requires/install", "requires", "install", ("php",), body={"id": "php"}, wrap="job"),
    R("GET", "/api/sysapps", "sysapps", "status", err=None),
    R("POST", "/api/sysapps/install", "sysapps", "install", ("nginx", True), body={"id": "nginx", "switch": True}, wrap="job"),
    R("POST", "/api/sysapps/uninstall", "sysapps", "uninstall", ("nginx",), body={"id": "nginx"}, wrap="job"),
    R("POST", "/api/sysapps/control", "sysapps", "control", ("nginx", "restart", False), body={"id": "nginx", "action": "restart"}),
    # ---- vpn, ddns, port check, network monitor
    R("POST", "/api/vpn/settings", "vpncommon", "save_settings", ("vpn.a.com", "1.1.1.1"), body={"endpoint": "vpn.a.com", "dns": "1.1.1.1"}),
    R("GET", "/api/vpn/wireguard", "wireguard", "status"),
    R("GET", "/api/vpn/openvpn", "openvpn", "status"),
    R("GET", "/api/vpn/ipsec", "ipsec", "status"),
    R("POST", "/api/vpn/wireguard/install", "wireguard", "install", wrap="job"),
    R("POST", "/api/vpn/wireguard/setup", "wireguard", "setup", (51820, "10.8.0.0/24"), body={}),
    R("POST", "/api/vpn/wireguard/setup", "wireguard", "setup", (5555, "10.1.0.0/24"), body={"port": 5555, "subnet": "10.1.0.0/24"}),
    R("POST", "/api/vpn/openvpn/setup", "openvpn", "setup", (1194, "udp", "10.9.0.0/24", True), body={}, wrap="job"),
    R("POST", "/api/vpn/openvpn/setup", "openvpn", "setup", (443, "tcp", "10.2.0.0/24", False), body={"port": 443, "proto": "tcp", "subnet": "10.2.0.0/24", "redirect": False}, wrap="job"),
    R("POST", "/api/vpn/ipsec/setup", "ipsec", "setup", ("10.10.0.0/24",), body={}, wrap="job"),
    R("POST", "/api/vpn/openvpn/control", "openvpn", "control", ("stop",), body={"action": "stop"}),
    R("POST", "/api/vpn/wireguard/selftest", "wireguard", "selftest", wrap="job"),
    R("POST", "/api/vpn/wireguard/clients", "wireguard", "add_peer", ("phone", "full"), body={"name": "phone"}),
    R("POST", "/api/vpn/wireguard/clients", "wireguard", "add_peer", ("phone", "split"), body={"name": "phone", "tunnel": "split"}),
    R("POST", "/api/vpn/openvpn/clients", "openvpn", "add_user", ("phone", "cert+password", None), body={"name": "phone"}),
    R("POST", "/api/vpn/openvpn/clients", "openvpn", "add_user", ("phone", "cert", "pw"), body={"name": "phone", "mode": "cert", "password": "pw"}),
    R("POST", "/api/vpn/ipsec/clients", "ipsec", "add_user", ("phone", "pw"), body={"name": "phone", "password": "pw"}),
    R("POST", "/api/vpn/wireguard/clients/remove", "wireguard", "remove_peer", ("phone",), body={"name": "phone"}),
    R("POST", "/api/vpn/openvpn/clients/remove", "openvpn", "revoke_client", ("phone",), body={"name": "phone"}),
    R("POST", "/api/vpn/ipsec/clients/remove", "ipsec", "remove_user", ("phone",), body={"name": "phone"}),
    R("POST", "/api/vpn/openvpn/users/password", "openvpn", "set_password", ("phone", "pw"), body={"name": "phone", "password": "pw"}),
    R("POST", "/api/vpn/openvpn/users/mode", "openvpn", "set_mode", ("phone", "cert", None), body={"name": "phone", "mode": "cert"}),
    R("POST", "/api/vpn/openvpn/users/toggle", "openvpn", "set_disabled", ("phone", True), body={"name": "phone", "disabled": True}),
    R("POST", "/api/vpn/wireguard/clients/toggle", "wireguard", "set_peer_disabled", ("phone", False), body={"name": "phone"}),
    R("GET", "/api/vpn/wireguard/clients/phone/config", "wireguard", "client_config", ("phone",)),
    R("GET", "/api/vpn/openvpn/clients/phone/config", "openvpn", "client_config", ("phone",)),
    R("GET", "/api/vpn/ipsec/clients/phone/config", "ipsec", "client_profiles", ("phone",)),
    R("GET", "/api/ddns", "ddns", "status"),
    R("POST", "/api/ddns", "ddns", "configure", ("duckdns", {"token": "t"}, False), body={"provider": "duckdns", "fields": {"token": "t"}, "enabled": False}),
    R("POST", "/api/ddns/update", "ddns", "update", kwargs={"force": True}),
    R("POST", "/api/ddns/disable", "ddns", "disable"),
    R("POST", "/api/ddns/stop-ddclient", "ddns", "stop_ddclient"),
    R("POST", "/api/portcheck", "portcheck", "check", (8080, "udp"), body={"port": 8080, "proto": "udp"}),
    R("POST", "/api/portcheck/upnp/open", "portcheck", "upnp_open", (8080, "tcp"), body={"port": 8080}),
    R("POST", "/api/portcheck/upnp/close", "portcheck", "upnp_close", (8080, "tcp"), body={"port": 8080}),
    R("POST", "/api/portcheck/upnp/install", "portcheck", "install_upnp", wrap="job"),
    R("GET", "/api/netmon", "netmon", "summary", (6, "lan"), params={"hours": 6, "scope": "lan"}),
    R("POST", "/api/netmon/logging", "netmon", "set_logging", (True,), body={"on": True}),
    # ---- instaban, guard
    R("GET", "/api/instaban", "instaban", "overview"),
    R("POST", "/api/instaban/settings", "instaban", "set_settings", (True, "1d", False), body={"enabled": True, "ttl": "1d", "report": False}),
    R("POST", "/api/instaban/behavior", "instaban", "set_behavior", ({"scanner": True},), body={"scanner": True}),
    R("POST", "/api/instaban/patterns/add", "instaban", "add_pattern", ("/wp-login", "contains", "n"), body={"pattern": "/wp-login", "note": "n"}),
    R("POST", "/api/instaban/patterns/import", "instaban", "import_patterns", ("a\nb", "regex"), body={"text": "a\nb", "kind": "regex"}),
    R("POST", "/api/instaban/patterns/delete", "instaban", "delete_pattern", ("p1",), body={"id": "p1"}),
    R("POST", "/api/instaban/hits/clear", "instaban", "clear_hits"),
    R("POST", "/api/instaban/scan", "instaban", "scan"),
    R("GET", "/api/guard", "guard", "listing"),
    R("POST", "/api/guard/ban", "guard", "ban", ("1.2.3.4", "bad", 60, IP, "manual"), body={"target": "1.2.3.4", "reason": "bad", "duration": 60, "source": "manual"}),
    R("POST", "/api/guard/ban", "guard", "ban", ("1.2.3.4", "", None, IP, ""), body={"target": "1.2.3.4"}),
    R("POST", "/api/guard/unban", "guard", "unban", ("1.2.3.4",), body={"target": "1.2.3.4"}),
    R("POST", "/api/guard/trust", "guard", "trust", ("1.2.3.4", "office"), body={"target": "1.2.3.4", "reason": "office"}),
    R("POST", "/api/guard/untrust", "guard", "untrust", ("1.2.3.4",), body={"target": "1.2.3.4"}),
    # ---- images, web disk, directory privacy, git, backup wizard, inodes
    R("POST", "/api/images/scale", "images", "scale", ("p.jpg", 100, None, None, True, False, 70), body={"path": "p.jpg", "width": 100, "keep_original": False, "quality": 70}),
    R("POST", "/api/images/thumbnails", "images", "thumbnails", ("d", 50, 200, True), body={"path": "d", "percent": 50, "max_px": 200, "recursive": True}, wrap="job"),
    R("POST", "/api/images/convert", "images", "convert", ("p.png", "webp", 85, True), body={"path": "p.png", "to": "webp", "delete_original": True}, wrap="job"),
    R("GET", "/api/webdisk", "webaccess", "webdisk_list", err=None),
    R("POST", "/api/webdisk", "webaccess", "webdisk_create", ("bob", "pw", "/srv", True), body={"name": "bob", "password": "pw", "path": "/srv", "readonly": True}),
    R("POST", "/api/webdisk/update", "webaccess", "webdisk_update", ("bob", None, False, True, None), body={"name": "bob", "readonly": False, "disabled": True}),
    R("POST", "/api/webdisk/delete", "webaccess", "webdisk_delete", ("bob",), body={"name": "bob"}),
    R("GET", "/api/webdisk/certificate", "webaccess", "webdisk_certificate", ("pi.local",), params={"host": "pi.local"}),
    R("POST", "/api/webdisk/certificate", "webaccess", "webdisk_certificate_ensure", ("pi.local",), body={"host": "pi.local"}),
    R("GET", "/api/dirprivacy", "webaccess", "privacy_list", err=None),
    R("POST", "/api/dirprivacy/protect", "webaccess", "privacy_protect", ("/srv/x", "Staff", "bob", "pw"), body={"path": "/srv/x", "label": "Staff", "name": "bob", "password": "pw"}),
    R("POST", "/api/dirprivacy/user", "webaccess", "privacy_user", ("/srv/x", "bob", None, True), body={"path": "/srv/x", "name": "bob", "remove": True}),
    R("POST", "/api/dirprivacy/toggle", "webaccess", "privacy_toggle", ("/srv/x", True), body={"path": "/srv/x", "enabled": True}),
    R("POST", "/api/dirprivacy/remove", "webaccess", "privacy_remove", ("/srv/x",), body={"path": "/srv/x"}),
    R("GET", "/api/git", "gitvc", "listing"),
    R("GET", "/api/git/site", "gitvc", "details", ("site",)),
    R("POST", "/api/git/key", "gitvc", "make_key", ("site", "bob"), body={"name": "site", "owner": "bob"}),
    R("POST", "/api/git/create", "gitvc", "create", ("site", "/srv/site", "", "git@x:y.git", "main", True), body={"name": "site", "path": "/srv/site", "clone_url": "git@x:y.git", "branch": "main", "use_key": True}, wrap="job"),
    R("POST", "/api/git/pull", "gitvc", "pull", ("site",), body={"name": "site"}, wrap="job"),
    R("POST", "/api/git/checkout", "gitvc", "checkout", ("site", "dev"), body={"name": "site", "branch": "dev"}),
    R("POST", "/api/git/deploy-settings", "gitvc", "set_deploy", ("site", "/var/www", "make"), body={"name": "site", "deploy_path": "/var/www", "deploy_cmd": "make"}),
    R("POST", "/api/git/deploy", "gitvc", "deploy", ("site",), body={"name": "site"}, wrap="job"),
    R("POST", "/api/git/remove", "gitvc", "remove", ("site", True), body={"name": "site", "delete_files": True}),
    R("GET", "/api/backups/wizard", "backups", "wizard_options"),
    R("POST", "/api/backups/wizard", "backups", "wizard_create", ("full", ["/srv"], ["shop"], [], "L"), body={"kind": "full", "paths": ["/srv"], "mysql": ["shop"], "label": "L"}, wrap="job"),
    R("GET", "/api/backups/manifest", "backups", "manifest", ("b.tgz",), params={"name": "b.tgz"}),
    R("POST", "/api/backups/wizard/restore", "backups", "wizard_restore", ("b.tgz", ["/srv"], [], ["db"], "/", {"a": "b"}, False), body={"name": "b.tgz", "paths": ["/srv"], "pgsql": ["db"], "rename": {"a": "b"}, "wipe": False}, wrap="job"),
    R("GET", "/api/inodes", "diskusage", "inodes", ("/home",), params={"path": "/home"}),
    # ---- per-app configuration, ftp
    R("GET", "/api/sysapps/apache/config", "appconfig", "info", ("apache",)),
    R("GET", "/api/sysapps/apache/settings", "appconfig", "settings", ("apache",)),
    R("POST", "/api/sysapps/apache/settings", "appconfig", "save", ("apache", {"Timeout": "30"}), body={"changes": {"Timeout": "30"}}),
    R("GET", "/api/sysapps/apache/modules", "appconfig", "modules", ("apache",), wrap="modules"),
    R("POST", "/api/sysapps/apache/modules", "appconfig", "set_module", ("apache", "rewrite", True), body={"name": "rewrite", "on": True}),
    R("GET", "/api/sysapps/apache/file", "appconfig", "read_file", ("apache", "apache2.conf"), params={"path": "apache2.conf"}),
    R("POST", "/api/sysapps/apache/file", "appconfig", "write_file", ("apache", "apache2.conf", "x"), body={"path": "apache2.conf", "content": "x"}),
    R("GET", "/api/sysapps/apache/logs", "appconfig", "logs", ("apache", "error", 50), params={"source": "error", "lines": 50}),
    R("POST", "/api/ftp/accounts", "ftp", "create", ("bob", "pw", "/srv", "full", True), body={"name": "bob", "password": "pw", "folder": "/srv"}),
    R("POST", "/api/ftp/accounts/password", "ftp", "set_password", ("bob", "pw"), body={"name": "bob", "password": "pw"}),
    R("POST", "/api/ftp/accounts/modify", "ftp", "modify", ("bob", "/srv", "ro", False), body={"name": "bob", "folder": "/srv", "access": "ro", "create_folder": False}),
    R("POST", "/api/ftp/accounts/toggle", "ftp", "set_enabled", ("bob", True), body={"name": "bob", "enabled": True}),
    R("POST", "/api/ftp/accounts/delete", "ftp", "delete", ("bob",), body={"name": "bob"}),
    # ---- about and updates
    R("GET", "/api/about", "version", "info", err=None),
    R("POST", "/api/about/check", "version", "check", status=502),
    R("POST", "/api/about/changelog", "version", "changelog", status=502),
    R("POST", "/api/about/update", "version", "apply_update"),
    R("GET", "/api/about/update", "version", "update_status", err=None),
    R("POST", "/api/about/rollback", "version", "apply_rollback", ("1.0.0",), body={"version": "1.0.0"}),
    # ---- alerts, slack, schedules, system updates
    R("POST", "/api/alerts", "alerts", "update", ({"cpu": 90},), body={"cpu": 90}),
    R("POST", "/api/alerts/test", "alerts", "test"),
    R("GET", "/api/slack", "slackbot", "public", err=None),
    R("POST", "/api/slack/test", "slackbot", "test"),
    R("GET", "/api/schedules", "schedules", "listing", err=None),
    R("POST", "/api/schedules/plans", "schedules", "save_plan", ({"name": "nightly"},), body={"name": "nightly"}),
    R("DELETE", "/api/schedules/plans/p1", "schedules", "delete_plan", ("p1",)),
    R("POST", "/api/schedules/plans/p1/run", "schedules", "start", ("p1",)),
    R("GET", "/api/schedules/plans/p1/log", "schedules", "run_log", ("p1", "run1"), params={"name": "run1"}),
    R("GET", "/api/schedules/plans/p1/snapshots", "schedules", "snapshots", ("p1",)),
    R("POST", "/api/schedules/plans/p1/fetch", "schedules", "fetch", ("p1", "/tmp", "snap"), body={"dest": "/tmp", "name": "snap"}),
    R("GET", "/api/schedules/plans/p1/passphrase", "schedules", "passphrase", ("p1",), wrap="passphrase"),
    R("POST", "/api/schedules/destinations", "schedules", "save_destination", ({"kind": "sftp"},), body={"kind": "sftp"}),
    R("DELETE", "/api/schedules/destinations/d1", "schedules", "delete_destination", ("d1",)),
    R("POST", "/api/schedules/destinations/d1/test", "schedules", "test_destination", ("d1",)),
    R("GET", "/api/updates", "updates", "status", err=None),
    R("POST", "/api/updates/install", "updates", "install", (["vim"],), body={"packages": ["vim"]}, wrap="job"),
    R("POST", "/api/updates/auto", "updates", "set_auto", (True, "all", True, "03:30"), body={"enabled": True, "mode": "all", "reboot": True, "reboot_time": "03:30"}),
    R("POST", "/api/updates/reboot", "updates", "reboot", (5,), body={"minutes": 5}),
    R("POST", "/api/updates/reboot", "updates", "cancel_reboot", body={"cancel": True}),
    # ---- wordpress toolkit, migration, servers
    R("GET", "/api/wptoolkit/site", "wptoolkit", "details", ("/srv/wp",), params={"path": "/srv/wp"}),
    R("POST", "/api/wptoolkit/update", "wptoolkit", "update", ("/srv/wp", "plugins", ["akismet"]), body={"path": "/srv/wp", "what": "plugins", "names": ["akismet"]}),
    R("POST", "/api/wptoolkit/scan", "wptoolkit", "scan", ("/srv/wp",), body={"path": "/srv/wp"}, wrap="job"),
    R("POST", "/api/wptoolkit/harden", "wptoolkit", "harden", ("/srv/wp",), body={"path": "/srv/wp"}),
    R("POST", "/api/wptoolkit/autoupdates", "wptoolkit", "auto_updates", ("/srv/wp", False), body={"path": "/srv/wp", "on": False}),
    R("POST", "/api/wptoolkit/maintenance", "wptoolkit", "maintenance", ("/srv/wp", True), body={"path": "/srv/wp"}),
    R("POST", "/api/wptoolkit/staging", "wptoolkit", "make_staging", ("/srv/wp",), body={"path": "/srv/wp", "on": True}, wrap="job"),
    R("POST", "/api/wptoolkit/staging", "wptoolkit", "delete_staging", ("/srv/wp",), body={"path": "/srv/wp", "on": False}),
    R("GET", "/api/migrate/analyze", "migrate", "analyze", ("b.tar.gz",), params={"path": "b.tar.gz"}),
    R("POST", "/api/migrate/fetch", "migrate", "fetch", ("https://x/b.tar.gz",), body={"url": "https://x/b.tar.gz"}, wrap="job"),
    R("POST", "/api/migrate/run", "migrate", "run", ("b.tar.gz", {"path": "b.tar.gz", "sites": ["a.com"], "databases": [], "mail": False, "zones": True}),
      body={"path": "b.tar.gz", "sites": ["a.com"], "mail": False, "zones": True}, wrap="job"),
    R("GET", "/api/fleet/self", "servers", "self_summary", err=None, wrap="merge"),
    R("GET", "/api/servers", "servers", "overview", err=None),
    R("POST", "/api/servers", "servers", "add", ("ns3", "https://ns3:8088", "tok"), body={"name": "ns3", "url": "https://ns3:8088", "token": "tok"}),
    R("DELETE", "/api/servers/s1", "servers", "remove", ("s1",)),
    R("POST", "/api/servers/s1/repin", "servers", "repin", ("s1",)),
    # ---- docker
    R("POST", "/api/docker/install", "dockerapps", "install", ("gitea", "git", "lan", "", {"data": "/srv"}), body={"app": "gitea", "name": "git", "access": "lan", "folders": {"data": "/srv"}}, wrap="job"),
    R("POST", "/api/docker/prune", "dockerapps", "prune"),
    R("POST", "/api/docker/apps/git/update", "dockerapps", "update", ("git",), wrap="job"),
    R("POST", "/api/docker/apps/git/stop", "dockerapps", "control", ("git", "stop")),
    R("GET", "/api/docker/apps/git/logs", "dockerapps", "logs", ("git", 50), params={"lines": 50}),
    R("GET", "/api/docker/apps/git/secret", "dockerapps", "secret", ("git", "DB_PASS"), params={"key": "DB_PASS"}),
    R("DELETE", "/api/docker/apps/git", "dockerapps", "remove", ("git", True), params={"data": "true"}),
    R("GET", "/api/docker/catalog", "dockerapps", "catalog", err=None),
    R("POST", "/api/docker/memcgroup", "dockerapps", "enable_mem_cgroup"),
    R("GET", "/api/docker/containers", "dockerapps", "containers", err=None),
    R("GET", "/api/docker/containers/c1", "dockerapps", "inspect", ("c1",)),
    R("POST", "/api/docker/containers/c1/action/restart", "dockerapps", "container_action", ("c1", "restart")),
    R("GET", "/api/docker/containers/c1/logs", "dockerapps", "container_logs", ("c1", 400)),
    R("GET", "/api/docker/containers/c1/top", "dockerapps", "container_top", ("c1",)),
    R("POST", "/api/docker/containers/c1/exec", "dockerapps", "exec_cmd", ("c1", "ls", "www-data", "/srv"), body={"cmd": "ls", "user": "www-data", "workdir": "/srv"}),
    R("DELETE", "/api/docker/containers/c1", "dockerapps", "container_remove", ("c1", False)),
    R("GET", "/api/docker/images", "dockerapps", "images", err=None),
    R("POST", "/api/docker/images/pull", "dockerapps", "image_pull", ("nginx:1.27",), body={"image": "nginx:1.27"}, wrap="job"),
    R("GET", "/api/docker/images/library/nginx:1.27", "dockerapps", "image_inspect", ("library/nginx:1.27",)),
    R("DELETE", "/api/docker/images/library/nginx:1.27", "dockerapps", "image_remove", ("library/nginx:1.27",)),
    # ---- isolation, autossl, metrics, dynamic dns hosts
    R("GET", "/api/isolation", "isolate", "status", err=None),
    R("POST", "/api/isolation/enable", "isolate", "enable_all_job", body={}, wrap="job"),
    R("POST", "/api/isolation/enable", "isolate", "enable_job", ("a.com",), body={"site": "a.com"}, wrap="job"),
    R("POST", "/api/isolation/disable", "isolate", "disable", ("a.com",), body={"site": "a.com"}),
    R("POST", "/api/isolation/fix", "isolate", "fix_permissions", ("a.com",), body={"site": "a.com"}),
    R("GET", "/api/autossl", "autossl", "status", err=None),
    R("POST", "/api/autossl", "autossl", "settings", (True, "me@a.com", True, ["x.com"]), body={"enabled": True, "email": "me@a.com", "agreed": True, "exclude": ["x.com"]}),
    R("POST", "/api/autossl/run", "autossl", "start", (True, "a.com"), body={"only": "a.com"}),
    R("POST", "/api/autossl/wildcard", "autossl", "issue_wildcard", ("a.com",), body={"domain": "a.com"}),
    R("GET", "/api/metrics/sites", "metrics", "sites", err=None, wrap="sites"),
    R("GET", "/api/metrics/visitors", "metrics", "visitors", ("a.com", 10, 2, "bob"), params={"site": "a.com", "limit": 10, "hours": 2, "name": "bob"}),
    R("GET", "/api/metrics/errors", "metrics", "errors", ("a.com", 24, "web", 1.5, 2.5), params={"site": "a.com", "sources": "web", "start": 1.5, "end": 2.5}),
    R("GET", "/api/metrics/bandwidth", "metrics", "bandwidth", err=None),
    R("GET", "/api/metrics/resources", "metrics", "resources", ("week",), params={"span": "week"}, err=None),
    R("GET", "/api/metrics/analytics", "metrics", "analytics", ("a.com", 7, "f", "n"), params={"site": "a.com", "days": 7, "file": "f", "name": "n"}),
    R("GET", "/api/metrics/ip", "metrics", "ip_info", ("1.2.3.4", 90), params={"ip": "1.2.3.4", "days": 500}),
    R("GET", "/api/metrics/raw", "metrics", "raw", err=None),
    R("POST", "/api/metrics/retention", "metrics", "set_retention", (30,), body={"days": 30}),
    R("POST", "/api/ddns-hosts", "ddnshosts", "create", ("a.com", "home", "1.2.3.4", "d"), body={"domain": "a.com", "prefix": "home", "ip": "1.2.3.4", "description": "d"}),
    R("GET", "/api/ddns-hosts/h1/key", "ddnshosts", "reveal", ("h1",)),
    R("POST", "/api/ddns-hosts/h1/regenerate", "ddnshosts", "regenerate", ("h1",)),
    R("DELETE", "/api/ddns-hosts/h1", "ddnshosts", "delete", ("h1",)),
    # ---- panel users (the owner is signed in as "tester")
    R("POST", "/api/panel-users", "panelusers", "create", ("ann", "", "viewer", None), body={"username": "ann"}),
    R("POST", "/api/panel-users/update", "panelusers", "update", ("ann", "site", ["a.com"], "pw1234567890", True), body={"username": "ann", "role": "site", "sites": ["a.com"], "password": "pw1234567890", "disabled": True}),
    R("POST", "/api/panel-users/delete", "panelusers", "delete", ("ann",), body={"username": "ann"}),
    R("POST", "/api/me/password", "panelusers", "change_own_password", ("tester", "old", "new"), body={"current": "old", "new": "new"}),
]


class Recorder:
    def __init__(self, ret):
        self.ret, self.calls = ret, []

    def __call__(self, *a, **k):
        self.calls.append((a, k))
        return self.ret


def _mod(name):
    return importlib.import_module("backend." + name)


def _ids(rows):
    return [f"{r['method']} {r['url']} -> {r['mod']}.{r['fn']}" for r in rows]


def _stub_extras(monkeypatch, r):
    for emod, efn, eret in r["extra"]:
        monkeypatch.setattr(_mod(emod), efn, lambda *a, _r=eret, **k: _r)


@pytest.mark.parametrize("r", ROUTES, ids=_ids(ROUTES))
def test_route_hands_the_call_to_the_backend_and_returns_its_answer(admin, monkeypatch, r):
    _stub_extras(monkeypatch, r)
    ret = types.SimpleNamespace(id="job-1") if r["wrap"] == "job" else {"stub": r["fn"], "n": 1}
    rec = Recorder(ret)
    monkeypatch.setattr(_mod(r["mod"]), r["fn"], rec)
    resp = admin.request(r["method"], r["url"], json=r["body"], params=r["params"])
    assert resp.status_code == 200, resp.text
    data = resp.json()
    if r["wrap"] == "job":
        assert data == {"job": "job-1"}
    elif r["wrap"] is None:
        assert data == ret
    elif r["wrap"] == "merge":
        assert all(data[k] == v for k, v in ret.items()), data
    else:
        assert data[r["wrap"]] == ret
    assert rec.calls == [(r["args"], r["kwargs"])], rec.calls


ERRORS = [r for r in ROUTES if r["err"]]


@pytest.mark.parametrize("r", ERRORS, ids=_ids(ERRORS))
def test_route_turns_the_backend_error_into_the_http_status_with_its_message(admin, monkeypatch, r):
    _stub_extras(monkeypatch, r)
    err = ERR[r["mod"]] if r["err"] is True else r["err"]
    emod, ecls = (r["mod"], err) if isinstance(err, str) else err
    cls = getattr(_mod(emod), ecls)

    def boom(*a, **k):
        raise cls("it went wrong")

    monkeypatch.setattr(_mod(r["mod"]), r["fn"], boom)
    resp = admin.request(r["method"], r["url"], json=r["body"], params=r["params"])
    assert resp.status_code == r["status"], resp.text
    assert resp.json() == {"detail": "it went wrong"}


def test_every_table_entry_names_a_real_backend_function():
    for r in ROUTES:
        assert callable(getattr(_mod(r["mod"]), r["fn"])), (r["mod"], r["fn"])


def test_dmarc_preview_route(admin):
    r = admin.post("/api/dmarc/preview", json={"domain": "www.x.com", "settings": {"p": "quarantine", "rua": ["d@reports.net"]}})
    assert r.status_code == 200
    d = r.json()
    assert d["record"] == "v=DMARC1; p=quarantine; rua=mailto:d@reports.net; adkim=r; aspf=r"
    assert d["external"][0]["name"] == "x.com._report._dmarc.reports.net" and d["explain"][0]["tag"] == "v=DMARC1"
    bad = admin.post("/api/dmarc/preview", json={"domain": "x.com", "settings": {"p": "maybe"}})
    assert bad.status_code == 400 and "Policy" in bad.json()["detail"]
