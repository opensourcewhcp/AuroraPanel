#!/usr/bin/python3
"""Debian compatibility commands for Fedora and the Red Hat family.

RHEL, AlmaLinux, Rocky Linux and CentOS Stream are answered the same way, with EL_PACKAGES where their
packages differ and EPEL plus the vendors' own repositories for what they don't carry.

The panel's web features are written against Debian's layout: apt-get and dpkg-query, a2ensite and
friends, /etc/apache2, /etc/php/<ver>, the apache2 and cron service names, the www-data user. This
one file is installed under many names in /usr/local/lib/aurora/compat, a folder only the panel has
on its PATH, and answers those commands with Fedora's real tools. `setup` builds the matching
folders and links for whatever software is installed, and is safe to run again at any time.

It uses the system Python and the standard library only.
"""
import glob
import hashlib
import io
import os
import re
import shutil
import subprocess
import sys
import tarfile
import urllib.request
from pathlib import Path

COMPAT_DIR = Path("/usr/local/lib/aurora/compat")
SELF_PATH = COMPAT_DIR / "aurora-compat"
STATE = Path("/var/lib/aurora/compat")
REAL_PATH = "/usr/sbin:/usr/bin:/sbin:/bin"
ENV = {**os.environ, "PATH": REAL_PATH, "LC_ALL": "C"}

COMMANDS = ["apt-get", "apt-cache", "dpkg-query", "dpkg", "debconf-set-selections", "a2ensite", "a2dissite", "a2enconf",
            "a2disconf", "a2enmod", "a2dismod", "apache2ctl", "systemctl", "journalctl", "pg_lsclusters", "phpenmod", "phpdismod", "usermod", "gpasswd"]

# Debian package -> the Fedora packages that provide the same thing. An empty list means Fedora
# ships it inside another package. Anything not listed has the same name on both.
PACKAGES = {
    "apache2": ["httpd", "mod_ssl"], "apache2-utils": ["httpd-tools"],
    "libapache2-mod-php": ["php", "php-fpm"], "php-mysql": ["php-mysqlnd"], "php-mysqli": ["php-mysqlnd"], "php-curl": ["php-common"],
    "php-zip": ["php-pecl-zip"], "php-imagick": ["php-pecl-imagick"], "php-redis": ["php-pecl-redis6"],
    "php-apcu": ["php-pecl-apcu"], "php-opcache": [], "php-json": [], "php-readline": ["php-cli"],
    "mariadb-client": ["mariadb"], "default-mysql-server": ["mariadb-server"], "mysql-server": ["mariadb-server"],
    "postgresql": ["postgresql-server", "postgresql-contrib"],
    "bind9": ["bind"], "bind9-utils": ["bind-utils"], "dnsutils": ["bind-utils"],
    "cron": ["cronie"], "libnginx-mod-http-modsecurity": ["nginx-mod-modsecurity"], "libapache2-mod-security2": ["mod_security"], "modsecurity-crs": ["mod_security_crs"],
    "testssl.sh": ["testssl"], "ufw": ["firewalld"],
    "dovecot-core": ["dovecot"], "dovecot-imapd": [], "dovecot-pop3d": [], "dovecot-lmtpd": [],
    "dovecot-sieve": ["dovecot-pigeonhole"], "dovecot-managesieved": ["dovecot-pigeonhole"],
    "redis-server": ["valkey", "valkey-compat-redis"],
    "radicale": ["radicale3"], "roundcube": ["roundcubemail"], "roundcube-sqlite3": ["php-pdo"], "roundcube-plugins": [],
    "docker.io": ["moby-engine"], "docker-cli": [], "docker-compose-v2": ["docker-compose"],
    "awscli": ["awscli2"], "phpmyadmin": ["phpMyAdmin"], "iproute2": ["iproute"], "iputils-ping": ["iputils"],
    "libpam-google-authenticator": ["google-authenticator"],
    "charon-systemd": ["strongswan"], "strongswan-swanctl": ["strongswan"], "strongswan-pki": ["strongswan"],
    "libcharon-extra-plugins": [], "libcharon-extauth-plugins": [], "libstrongswan-extra-plugins": [], "libstrongswan-standard-plugins": [], "build-essential": ["gcc", "make"], "python3-dev": ["python3-devel"], "libffi-dev": ["libffi-devel"],
}

# Two names share one account here, but a process only gets the group memberships of the name it starts
# under: httpd starts as apache and named as named, so that is who must join a group.
ACCOUNTS = {"www-data": "apache", "bind": "named"}
# Debian starts a service as soon as its package is installed and the panel counts on that. Fedora doesn't.
START_AFTER_INSTALL = {"apache2": "httpd", "nginx": "nginx", "lighttpd": "lighttpd", "caddy": "caddy", "mariadb-server": "mariadb",
                       "postgresql": "postgresql", "redis-server": "valkey", "memcached": "memcached", "vsftpd": "vsftpd"}
UNITS = {"apache2": "httpd", "cron": "crond", "bind9": "named", "redis-server": "valkey", "redis": "valkey", "ssh": "sshd",
         "mysql": "mariadb", "clamav-daemon": "clamd@scan", "certbot": "certbot-renew"}


def run(*argv, **kw):
    kw.setdefault("env", ENV)
    return subprocess.run(argv, capture_output=True, text=True, **kw)


EL_IDS = {"rhel", "centos", "almalinux", "rocky", "ol"}
# Where the Red Hat family differs from Fedora. Dovecot's own packages are split up the way Debian's are.
EL_PACKAGES = {
    "docker.io": ["docker-ce", "docker-ce-cli", "containerd.io"], "docker-cli": [], "docker-compose-v2": ["docker-compose-plugin"],
    "redis-server": ["valkey"],
}
EL_DOVECOT = {"dovecot-core": ["dovecot"], "dovecot-imapd": ["dovecot-imapd"], "dovecot-pop3d": ["dovecot-pop3d"], "dovecot-lmtpd": ["dovecot-lmtpd"],
              "dovecot-sieve": ["dovecot-sieve"], "dovecot-managesieved": ["dovecot-managesieved"]}
DOCKER_RPMS = {"docker-ce", "docker-ce-cli", "containerd.io", "docker-compose-plugin"}
# EL 10 has no rule set package, so the release itself is installed. Pinned: a new version needs a new checksum.
CRS_VERSION = "4.30.0"
CRS_SHA256 = "3d678a41fd5aade34760127fef5dd64fd7a77848913fc0f70dde0cf467c94427"
CRS_URL = f"https://github.com/coreruleset/coreruleset/releases/download/v{CRS_VERSION}/coreruleset-{CRS_VERSION}-minimal.tar.gz"
CRS_MARKER = Path("/etc/httpd/modsecurity.d/.aurora-crs-version")


def os_release():
    try:
        text = Path("/etc/os-release").read_text()
    except OSError:
        return {}
    return {k: v.strip().strip('"') for k, _, v in (line.partition("=") for line in text.splitlines()) if k}


def el_major():
    """9 or 10 on RHEL and its rebuilds. None on Fedora, which has newer software and dnf 5."""
    info = os_release()
    if info.get("ID") == "fedora":
        return None
    if info.get("ID") in EL_IDS or "rhel" in info.get("ID_LIKE", "").split():
        m = re.match(r"\d+", info.get("VERSION_ID", ""))
        return int(m.group()) if m else None
    return None


def external_repo(rpm):
    """The vendor repository that carries this rpm on the Red Hat family, or None."""
    major = el_major()
    if not major or not rpm:
        return None
    arch = os.uname().machine
    if rpm in DOCKER_RPMS and arch in ("x86_64", "aarch64"):
        vendor_os = "rhel" if os_release().get("ID") == "rhel" else "centos"
        return {"id": "docker-ce", "name": "Docker CE", "version": "latest", "baseurl": f"https://download.docker.com/linux/{vendor_os}/{major}/{arch}/stable",
                "gpgkey": f"https://download.docker.com/linux/{vendor_os}/gpg"}
    # The panel writes Dovecot 2.4 settings and the family ships 2.3. Dovecot publishes x86_64 packages only.
    if rpm.startswith("dovecot") and arch == "x86_64":
        return {"id": "dovecot-2.4", "name": "Dovecot 2.4", "version": "2.4", "baseurl": f"https://repo.dovecot.org/ce-2.4-latest/rhel/{major}/RPMS/{arch}",
                "gpgkey": "https://repo.dovecot.org/DOVECOT-REPO-GPG-2.4"}
    return None


def add_repos(rpms):
    """Add the vendor repositories these rpms come from. Only asked for when someone installs them."""
    for rpm in rpms:
        repo = external_repo(rpm)
        path = Path(f"/etc/yum.repos.d/aurora-{repo['id']}.repo") if repo else None
        if path and not path.exists():
            path.write_text(f"[aurora-{repo['id']}]\nname={repo['name']}\nbaseurl={repo['baseurl']}\nenabled=1\ngpgcheck=1\ngpgkey={repo['gpgkey']}\n")


def setup_el_repos():
    """EPEL carries much of what the panel installs, and it needs CRB. Failing here isn't fatal: the panel
    still runs, and what is missing says so when someone tries to install it."""
    major = el_major()
    if not major:
        return
    distro_id, arch = os_release().get("ID"), os.uname().machine
    if distro_id == "rhel":
        epel, crb = f"https://dl.fedoraproject.org/pub/epel/epel-release-latest-{major}.noarch.rpm", None
        r = run("subscription-manager", "repos", "--enable", f"codeready-builder-for-rhel-{major}-{arch}-rpms")
        if r.returncode != 0:
            print(f"! Could not enable CodeReady Builder: {r.stderr.strip()}", file=sys.stderr)
    elif distro_id == "ol":
        epel, crb = f"oracle-epel-release-el{major}", f"ol{major}_codeready_builder"
    else:
        epel, crb = "epel-release", "crb"
    r = run("dnf", "-y", "install", "dnf-plugins-core", epel)
    if r.returncode != 0:
        print(f"! Could not add EPEL: {r.stderr.strip()[-400:]}", file=sys.stderr)
    if crb:
        r = run("dnf", "config-manager", "--set-enabled", crb)
        if r.returncode != 0:
            print(f"! Could not enable {crb}: {r.stderr.strip()}", file=sys.stderr)


def crs_is_bundled():
    return (el_major() or 0) >= 10


def install_crs():
    """Lay the rule set out the way mod_security_crs does on EL 9 and Fedora, so everything else reads it alike."""
    with urllib.request.urlopen(CRS_URL, timeout=120) as resp:
        data = resp.read()
    got = hashlib.sha256(data).hexdigest()
    if got != CRS_SHA256:
        raise OSError(f"the rule set download has the wrong checksum: {got}")
    root = Path("/etc/httpd/modsecurity.d")
    active = root / "activated_rules"
    active.mkdir(parents=True, exist_ok=True)
    with tarfile.open(fileobj=io.BytesIO(data)) as tar:
        for member in tar.getmembers():
            parts = member.name.split("/")
            if not member.isfile() or ".." in parts:
                continue
            content = tar.extractfile(member).read()
            if parts[1:] == ["crs-setup.conf.example"]:
                write_new(root / "crs-setup.conf", content.decode())
            elif len(parts) == 3 and parts[1] == "rules":
                (active / parts[2]).write_bytes(content)
    CRS_MARKER.write_text(CRS_VERSION + "\n")
    if selinux_on():
        run("restorecon", "-R", str(root))


def rpms_for(pkg):
    m = re.fullmatch(r"php\d+\.\d+-(.+)", pkg)
    if m:
        pkg = f"php-{m.group(1)}"
    if el_major():
        if pkg == "modsecurity-crs" and crs_is_bundled():
            return []
        if pkg == "postfix" and el_major() >= 10:  # its only keyed map type comes as a separate package
            return ["postfix", "postfix-lmdb"]
        if pkg in EL_PACKAGES:
            return EL_PACKAGES[pkg]
        if pkg in EL_DOVECOT and external_repo("dovecot"):
            return EL_DOVECOT[pkg]
    return PACKAGES.get(pkg, [pkg])


def rpm_versions(names):
    """rpm name -> version-release for the ones that are installed."""
    if not names:
        return {}
    out = run("rpm", "-q", "--qf", "%{NAME}\t%{VERSION}-%{RELEASE}\n", *sorted(set(names))).stdout
    return dict(line.split("\t", 1) for line in out.splitlines() if line.count("\t") == 1)


# ---------------------------------------------------------------- apt-get
def status_line(kind, pct, text):
    print(f"{kind}:dnf:{pct}:{text}", flush=True)


def apt_get(args):
    words, flags, skip = [], [], False
    for a in args:
        if skip:
            skip = False
        elif a == "-o":
            skip = True
        elif a.startswith("-"):
            flags.append(a)
        else:
            words.append(a)
    if not words:
        return 0
    action, names = words[0], words[1:]
    if action == "update":
        return dnf("makecache", "--refresh")
    if action in ("upgrade", "full-upgrade", "dist-upgrade"):
        return dnf("-y", "upgrade", *names)
    if action == "autoremove":
        return dnf("-y", "autoremove")
    if action in ("clean", "autoclean"):
        return dnf("clean", "packages")
    if action == "install" or action == "reinstall":
        rpms = sorted({r for n in names for r in rpms_for(n)})
        bundled_crs = "modsecurity-crs" in names and crs_is_bundled()
        if not rpms and not bundled_crs:
            return 0
        status_line("pmstatus", 10, "Downloading and installing " + " ".join(rpms[:4]))
        try:
            add_repos(rpms)
        except OSError as e:
            print(f"Could not add a package repository: {e}", file=sys.stderr)
            return 100
        rc = dnf("-y", "install", *rpms) if rpms else 0
        if rc == 0 and bundled_crs:
            try:
                install_crs()
            except OSError as e:  # URLError is an OSError
                print(f"Could not install the OWASP Core Rule Set: {e}", file=sys.stderr)
                return 100
        if rc == 0:
            status_line("pmstatus", 90, "Setting up")
            setup()
            for n in names:
                if n in START_AFTER_INSTALL:
                    run("systemctl", "enable", "--now", START_AFTER_INSTALL[n])
        return rc
    if action in ("remove", "purge"):
        rpms = sorted({r for n in names for r in rpms_for(n)})
        return dnf("-y", "remove", *rpms) if rpms else 0
    print(f"apt-get {action} isn't available on this system", file=sys.stderr)
    return 100


def dnf(*args):
    return subprocess.call(["dnf", *args], env=ENV)


# ---------------------------------------------------------------- apt-cache
def apt_cache(args):
    if not args:
        return 1
    if args[0] == "policy":
        names = args[1:]
        rpm_of = {n: (rpms_for(n) or [None])[0] for n in names}
        wanted = sorted({r for r in rpm_of.values() if r})
        cand = {}
        if wanted:
            out = run("dnf", "-q", "-C", "repoquery", "--latest-limit=1", "--qf", "%{name} %{version}-%{release}\n", *wanted).stdout
            cand = dict(line.split(" ", 1) for line in out.splitlines() if line.count(" ") == 1)
        have = rpm_versions(wanted)
        for n in names:
            r = rpm_of[n]
            # No rpm of its own means it comes inside another package, so it is always available. A vendor's
            # repository is only added on install, so its version is known without being asked.
            repo = external_repo(r)
            best = have.get(r) or (repo and repo["version"]) or cand.get(r) or ("included" if r is None else "(none)")
            print(f"{n}:\n  Installed: {have.get(r, '(none)')}\n  Candidate: {best}")
        return 0
    if args[0] == "search":
        term = args[-1]
        out = run("dnf", "-q", "search", "--", term).stdout
        for line in out.splitlines():
            # dnf 5 prints " name.arch<TAB>summary" and dnf 4 "name.arch : summary". Headings match neither.
            m = re.match(r"\s*(\S+?)\.\w+(?:\t| : )(.*)", line)
            if m:
                print(f"{m.group(1)} - {m.group(2).strip()}")
        return 0
    return 1


# ---------------------------------------------------------------- dpkg
def dpkg_query(args):
    fmt, names = "${Package}\t${db:Status-Abbrev}\t${Version}\n", []
    for a in args:
        if a.startswith(("-f=", "--showformat=")):
            fmt = a.split("=", 1)[1]
        elif not a.startswith("-"):
            names.append(a)
    fmt = fmt.replace("\\t", "\t").replace("\\n", "\n")
    rows = []
    for n in names:
        if n == "modsecurity-crs" and crs_is_bundled():
            if CRS_MARKER.exists():
                rows.append((n, CRS_MARKER.read_text().strip()))
            continue
        if n == "postgresql-[0-9]*":
            ver = rpm_versions(["postgresql-server"]).get("postgresql-server")
            if ver:
                rows.append((f"postgresql-{ver.split('.')[0]}", ver))
            continue
        rpms = rpms_for(n)
        if not rpms:  # part of another Fedora package: installed together with its family
            family = n.split("-")[0]
            rpms = rpms_for(family + "-core") or rpms_for(family)
            rpms = [r for r in rpms if r]
        got = rpm_versions(rpms)
        if rpms and all(r in got for r in rpms):
            rows.append((n, got[rpms[0]]))
    for pkg, ver in rows:
        sys.stdout.write(fmt.replace("${Package}", pkg).replace("${db:Status-Abbrev}", "ii ").replace("${Status}", "install ok installed")
                         .replace("${Version}", ver).replace("${binary:Summary}", "").replace("${Installed-Size}", "0"))
    return 0 if rows or not names else 1


def dpkg(args):
    if "--print-architecture" in args:
        print({"x86_64": "amd64", "aarch64": "arm64", "armv7l": "armhf"}.get(os.uname().machine, os.uname().machine))
    return 0  # --configure -a and friends: rpm has no half-configured state to repair


# ---------------------------------------------------------------- Apache
AP = Path("/etc/apache2")
HTTPD_MODS = Path("/etc/httpd/conf.modules.d")


def a2_link(kind, name, enable):
    name = re.sub(r"\.conf$", "", name)
    avail, on = AP / f"{kind}-available" / f"{name}.conf", AP / f"{kind}-enabled" / f"{name}.conf"
    if not enable:
        on.unlink(missing_ok=True)
        return 0
    if not avail.exists():
        print(f"ERROR: {kind.rstrip('s')} {name} does not exist!", file=sys.stderr)
        return 1
    if not on.is_symlink():
        on.parent.mkdir(parents=True, exist_ok=True)
        on.symlink_to(f"../{kind}-available/{name}.conf")
    return 0


def stock_module(name, enable):
    """Fedora loads modules from conf.modules.d: switch the matching line on or off. True if there is one."""
    line = re.compile(rf"^(\s*#\s*)?(LoadModule\s+{re.escape(name)}_module\s)", re.M)
    found = False
    for f in sorted(HTTPD_MODS.glob("*.conf")):
        text = f.read_text(errors="replace")
        if line.search(text):
            found = True
            new = line.sub(r"\2" if enable else r"#\2", text)
            if new != text:
                f.write_text(new)
    return found


def a2_mod(name, enable):
    name = re.sub(r"\.load$", "", name)
    load = AP / "mods-enabled" / f"{name}.load"
    if re.fullmatch(r"php\d*(\.\d+)?", name) or name.startswith("mpm_"):
        # PHP runs through php-fpm on Fedora, and the MPM is chosen in 00-mpm.conf.
        if enable:
            load.write_text(f"# {name}: provided by Fedora's own configuration\n")
        else:
            load.unlink(missing_ok=True)
        return 0
    if stock_module(name, enable):
        if enable:
            load.write_text(f"# {name}: loaded from {HTTPD_MODS}\n")
        else:
            load.unlink(missing_ok=True)
        return 0
    if not enable:
        load.unlink(missing_ok=True)
        return 0
    if not Path(f"/usr/lib64/httpd/modules/mod_{name}.so").exists():
        print(f"ERROR: Module {name} does not exist!", file=sys.stderr)
        return 1
    load.write_text(f"LoadModule {name}_module modules/mod_{name}.so\n")
    return 0


def a2(cmd, args):
    names = [a for a in args if not a.startswith("-")]
    enable = cmd.startswith("a2en")
    kind = {"site": "sites", "conf": "conf"}.get(cmd[4:] if enable else cmd[5:])
    (AP / "mods-enabled").mkdir(parents=True, exist_ok=True)
    rc = 0
    for n in names:
        rc = (a2_mod(n, enable) if cmd.endswith("mod") else a2_link(kind, n, enable)) or rc
    return rc


# ---------------------------------------------------------------- services
def unit_name(arg):
    base, dot, suffix = arg.partition(".")
    if re.fullmatch(r"php\d+\.\d+-fpm", arg.removesuffix(".service")):
        return "php-fpm.service" if arg.endswith(".service") else "php-fpm"
    if re.fullmatch(r"postgresql@.+", arg):
        return "postgresql"
    if arg in UNITS:
        return UNITS[arg]
    if base in UNITS and suffix in ("service", "timer"):
        return f"{UNITS[base]}.{suffix}"
    return arg


def pg_lsclusters():
    ver = rpm_versions(["postgresql-server"]).get("postgresql-server")
    if not ver:
        return 0
    state = "online" if run("systemctl", "is-active", "postgresql").stdout.strip() == "active" else "down"
    print(f"{ver.split('.')[0]} main 5432 {state} postgres /var/lib/pgsql/data /var/lib/pgsql/data/log/postgresql.log")
    return 0


# ---------------------------------------------------------------- setup
def link(path, target):
    p = Path(path)
    if p.is_symlink() and os.readlink(p) == str(target):
        return
    if p.is_symlink():
        p.unlink()
    elif p.exists():
        return  # something real lives there: never replace it
    p.parent.mkdir(parents=True, exist_ok=True)
    p.symlink_to(target)


def write_new(path, text, mode=None):
    p = Path(path)
    if not p.exists():
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)
        if mode:
            p.chmod(mode)


def alias_user(alias, real):
    """Another name for an existing account (www-data = apache): the same user and group numbers."""
    import grp
    import pwd
    try:
        pw = pwd.getpwnam(real)
    except KeyError:
        return
    try:
        grp.getgrnam(alias)
    except KeyError:
        run("groupadd", "-o", "-g", str(pw.pw_gid), alias)
    try:
        pwd.getpwnam(alias)
    except KeyError:
        run("useradd", "-o", "-u", str(pw.pw_uid), "-g", str(pw.pw_gid), "-M", "-d", pw.pw_dir, "-s", "/sbin/nologin", alias)


def selinux_on():
    return bool(shutil.which("selinuxenabled", path=REAL_PATH)) and run("selinuxenabled").returncode == 0


def once(key, fn):
    """semanage and setsebool are slow, so each group of changes runs one time only."""
    STATE.mkdir(parents=True, exist_ok=True)
    mark = STATE / key
    if not mark.exists():
        fn()
        mark.touch()


def label(*rules):
    """rules: ("equal", new_path, like_path) or ("type", selinux_type, path)."""
    if not selinux_on():
        return
    for rule in rules:
        if rule[0] == "equal":
            run("semanage", "fcontext", "-a", "-e", rule[2], rule[1])
            run("restorecon", "-R", rule[1])
        else:
            pattern = f"{rule[2]}(/.*)?"
            if run("semanage", "fcontext", "-a", "-t", rule[1], pattern).returncode != 0:
                run("semanage", "fcontext", "-m", "-t", rule[1], pattern)
            run("restorecon", "-R", rule[2])


def booleans(*names):
    if selinux_on():
        run("setsebool", "-P", *[f"{n}=on" for n in names])


# Two files because order matters: modules load first, while the panel's settings and sites come after
# everything in conf.d (WAF exceptions, for one, only work once the rules they switch off exist).
APACHE_FIRST = """# Written by AuroraPanel.
Define APACHE_LOG_DIR /var/log/httpd
IncludeOptional /etc/apache2/mods-enabled/*.load
"""
APACHE_LAST = """# Written by AuroraPanel: the panel keeps its settings and sites in these folders.
IncludeOptional /etc/apache2/conf-enabled/*.conf
IncludeOptional /etc/apache2/sites-enabled/*.conf
"""
DEFAULT_SITE = """<VirtualHost *:80>
    DocumentRoot /var/www/html
    ErrorLog ${APACHE_LOG_DIR}/error.log
    CustomLog ${APACHE_LOG_DIR}/access.log combined
</VirtualHost>
"""


def setup_apache():
    if not Path("/etc/httpd/conf/httpd.conf").exists():
        return
    alias_user("www-data", "apache")
    for d in ("sites-available", "sites-enabled", "conf-available", "conf-enabled", "mods-available", "mods-enabled", "ssl"):
        (AP / d).mkdir(parents=True, exist_ok=True)
    link(AP / "apache2.conf", "/etc/httpd/conf/httpd.conf")
    link("/var/log/apache2", "/var/log/httpd")
    Path("/var/lib/apache2").mkdir(parents=True, exist_ok=True)
    Path("/var/www/html").mkdir(parents=True, exist_ok=True)
    Path("/etc/httpd/conf.d/00-aurora-compat.conf").write_text(APACHE_FIRST)
    Path("/etc/httpd/conf.d/zz-aurora-compat.conf").write_text(APACHE_LAST)
    write_new(AP / "sites-available/000-default.conf", DEFAULT_SITE)
    link(AP / "sites-enabled/000-default.conf", "../sites-available/000-default.conf")
    once("apache-selinux", lambda: (
        label(("equal", "/etc/apache2", "/etc/httpd"), ("equal", "/var/log/apache2", "/var/log/httpd"),
              ("type", "httpd_var_lib_t", "/var/lib/apache2"), ("type", "httpd_sys_rw_content_t", "/var/www")),
        booleans("httpd_can_network_connect", "httpd_can_network_connect_db", "httpd_can_sendmail")))
    if selinux_on():
        run("restorecon", "-R", "/etc/apache2")


def setup_php():
    if not shutil.which("php", path=REAL_PATH):
        return
    ver = run("php", "-r", "echo PHP_MAJOR_VERSION.'.'.PHP_MINOR_VERSION;").stdout.strip()
    if not re.fullmatch(r"\d+\.\d+", ver):
        return
    base = Path("/etc/php") / ver
    for sapi in ("cli", "apache2", "fpm"):
        link(base / sapi / "php.ini", "/etc/php.ini")
        link(base / sapi / "conf.d", "/etc/php.d")
    link(base / "mods-available", "/etc/php.d")
    link(base / "fpm/pool.d", "/etc/php-fpm.d")
    link(f"/usr/bin/php{ver}", "/usr/bin/php")
    if shutil.which("php-fpm", path=REAL_PATH):
        link(COMPAT_DIR / f"php-fpm{ver}", "/usr/sbin/php-fpm")
        write_new("/etc/tmpfiles.d/aurora-php.conf", "d /run/php 0755 root root -\n")
        Path("/run/php").mkdir(exist_ok=True)
        once("php-selinux", lambda: label(("equal", "/run/php", "/run/php-fpm")))
        run("systemctl", "enable", "--now", "php-fpm")
    if AP.is_dir():
        load = AP / "mods-enabled" / f"php{ver}.load"
        if not any((AP / "mods-enabled").glob("php*.load")):
            load.write_text(f"# php{ver}: runs through php-fpm on Fedora\n")


def setup_mariadb():
    if Path("/etc/my.cnf.d").is_dir():
        link("/etc/mysql/mariadb.conf.d", "/etc/my.cnf.d")


def setup_postgres():
    ver = rpm_versions(["postgresql-server"]).get("postgresql-server")
    if not ver:
        return
    major = ver.split(".")[0]
    data = Path("/var/lib/pgsql/data")
    if not (data / "PG_VERSION").exists():
        run("postgresql-setup", "--initdb")
    conf = data / "postgresql.conf"
    if conf.exists():
        (data / "conf.d").mkdir(exist_ok=True)
        shutil.chown(data / "conf.d", "postgres", "postgres")
        text = conf.read_text()
        if not re.search(r"(?m)^include_dir\s*=?\s*'conf\.d'", text):
            conf.write_text(text.rstrip("\n") + "\n\ninclude_dir 'conf.d'\n")
    link(f"/etc/postgresql/{major}/main", data)
    link(f"/usr/lib/postgresql/{major}/bin", "/usr/bin")


NAMED_CONF = """// Written by AuroraPanel. The panel keeps BIND's settings in /etc/bind.
include "/etc/bind/named.conf.options";
include "/etc/bind/named.conf.local";
"""


def setup_bind():
    if not Path("/usr/sbin/named").exists():
        return
    alias_user("bind", "named")
    for d in ("/etc/bind", "/var/lib/bind", "/var/cache/bind"):
        Path(d).mkdir(parents=True, exist_ok=True)
    for d in ("/var/lib/bind", "/var/cache/bind"):
        shutil.chown(d, "named", "named")
    write_new("/etc/bind/named.conf.options", 'options {\n\tdirectory "/var/cache/bind";\n};\n')
    write_new("/etc/bind/named.conf.local", "// Zones added by AuroraPanel\n")
    current = Path("/etc/named.conf")
    if not current.exists() or "AuroraPanel" not in current.read_text(errors="replace"):
        if current.exists() and not Path("/etc/named.conf.fedora").exists():
            shutil.copy2(current, "/etc/named.conf.fedora")
        current.write_text(NAMED_CONF)
        shutil.chown(current, "root", "named")
    once("bind-selinux", lambda: label(("type", "named_conf_t", "/etc/bind"), ("type", "named_cache_t", "/var/lib/bind"),
                                       ("type", "named_cache_t", "/var/cache/bind")))
    if selinux_on():
        run("restorecon", "/etc/named.conf")


WAF_DEFAULTS = """# Written by AuroraPanel. The engine itself is configured in /etc/httpd/conf.d/mod_security.conf.
SecAuditEngine RelevantOnly
SecAuditLogParts ABFHZ
SecResponseBodyAccess Off
"""


def setup_waf():
    """Fedora's mod_security reads modsecurity.d/*.conf before the rule set: the panel's files join in there."""
    rules = Path("/etc/httpd/modsecurity.d")
    if not rules.is_dir():
        return
    Path("/etc/modsecurity").mkdir(exist_ok=True)
    write_new("/etc/modsecurity/modsecurity.conf-recommended", WAF_DEFAULTS)
    write_new("/etc/modsecurity/modsecurity.conf", WAF_DEFAULTS)
    write_new("/etc/modsecurity/zz-aurora-waf.conf", "# Filled in by AuroraPanel\n")
    write_new(AP / "mods-available/security2.load", "# security2: loaded from /etc/httpd/conf.modules.d\n")
    write_new("/usr/share/modsecurity-crs/owasp-crs.load", "# The rule set is loaded from /etc/httpd/modsecurity.d\n")
    link(rules / "00-aurora-main.conf", "/etc/modsecurity/modsecurity.conf")
    link(rules / "zz-aurora-waf.conf", "/etc/modsecurity/zz-aurora-waf.conf")
    once("waf-selinux", lambda: label(("equal", "/etc/modsecurity", "/etc/httpd/modsecurity.d")))
    if selinux_on():
        run("restorecon", "-R", "/etc/modsecurity", str(rules))


PMA_ACCESS = """# Written by AuroraPanel. Fedora's phpMyAdmin.conf only answers this machine; open it like Debian's does.
<Directory /usr/share/phpMyAdmin/>
    Require all granted
</Directory>
"""


def setup_phpmyadmin():
    if not Path("/etc/httpd/conf.d/phpMyAdmin.conf").exists() or not AP.is_dir():
        return
    link("/usr/share/phpmyadmin", "/usr/share/phpMyAdmin")
    link("/etc/phpmyadmin", "/etc/phpMyAdmin")
    write_new(AP / "conf-available/phpmyadmin.conf", PMA_ACCESS)
    link(AP / "conf-enabled/phpmyadmin.conf", "../conf-available/phpmyadmin.conf")
    if selinux_on():
        run("restorecon", "-R", str(AP))


def setup_strongswan():
    if not Path("/etc/strongswan/swanctl").is_dir():
        return
    link("/etc/swanctl", "/etc/strongswan/swanctl")
    # Fedora renames strongSwan's `pki` tool so it can't clash with other software.
    tool = next((f for f in run("rpm", "-ql", "strongswan").stdout.split() if re.search(r"/(strongswan-)?pki$", f) and os.path.isfile(f)), "")
    if tool:
        link(COMPAT_DIR / "pki", tool)


RC_DB = "/var/lib/roundcubemail/sqlite.db"


def setup_roundcube():
    """The panel's webmail settings and paths, with the sqlite database Debian's package would have made."""
    if not Path("/etc/roundcubemail").is_dir():
        return
    link("/etc/roundcube", "/etc/roundcubemail")
    link("/usr/share/roundcube", "/usr/share/roundcubemail")
    link("/var/lib/roundcube", "/usr/share/roundcubemail")
    write_new("/etc/roundcubemail/config.inc.php", "<?php\n$config = [];\n")  # Fedora ships none; the panel fills it in
    write_new("/etc/roundcubemail/debian-db-roundcube.php", f"<?php\n$config['db_dsnw'] = 'sqlite:///{RC_DB}?mode=0640';\n")
    if not Path(RC_DB).exists():
        Path(RC_DB).parent.mkdir(parents=True, exist_ok=True)
        script = (f'$d = new PDO("sqlite:{RC_DB}"); '
                  '$d->exec(file_get_contents("/usr/share/roundcubemail/SQL/sqlite.initial.sql"));')
        run("php", "-r", script)
        if Path(RC_DB).exists():
            shutil.chown(RC_DB, "apache", "apache")
            shutil.chown(Path(RC_DB).parent, "apache", "apache")
    if selinux_on():
        run("restorecon", "-R", "/var/lib/roundcubemail")


def setup_mail():
    """SELinux labels for the folders the panel's mail setup uses and Fedora's policy doesn't know."""
    if not Path("/etc/postfix/main.cf").exists():
        return
    # The Red Hat family lists port 465 under older names, and Postfix can't start on a name it can't look up.
    services = Path("/etc/services")
    if el_major() and services.exists() and not re.search(r"(?m)^submissions\s", services.read_text()):
        with services.open("a") as fh:
            fh.write("submissions     465/tcp                         # Added by AuroraPanel for Postfix\n")
    once("mail-selinux", lambda: label(("type", "mail_spool_t", "/var/vmail"), ("type", "cert_t", "/etc/aurora-mail/tls")))


def setup_openvpn():
    """easy-rsa sits one folder deeper on Fedora, and OpenVPN's login check is a script SELinux must allow it to run."""
    real = Path("/usr/share/easy-rsa/3")
    if not (real / "easyrsa").exists():
        return
    for name in ("easyrsa", "openssl-easyrsa.cnf", "x509-types"):
        link(real.parent / name, f"3/{name}")
    once("openvpn-selinux", lambda: booleans("openvpn_run_unconfined"))


def setup_vsftpd():
    if Path("/etc/vsftpd/vsftpd.conf").exists():
        link("/etc/vsftpd.conf", "/etc/vsftpd/vsftpd.conf")
        once("ftp-selinux", lambda: booleans("ftpd_full_access"))


def setup_panel_state():
    """Services such as nft read the rule files the panel keeps in /var/lib/aurora. SELinux lets them read
    etc_t, and ordinary file permissions still protect anything private in there."""
    Path("/var/lib/aurora").mkdir(parents=True, exist_ok=True)
    once("state-selinux", lambda: label(("type", "etc_t", "/var/lib/aurora")))


def setup():
    for step in (setup_panel_state, setup_apache, setup_php, setup_waf, setup_phpmyadmin, setup_mariadb, setup_postgres, setup_bind, setup_strongswan, setup_openvpn, setup_roundcube, setup_mail, setup_vsftpd):
        try:
            step()
        except OSError as e:
            print(f"! {step.__name__}: {e}", file=sys.stderr)


def install(source):
    """Put this file in place under every command name."""
    COMPAT_DIR.mkdir(parents=True, exist_ok=True)
    if Path(source).resolve() != SELF_PATH:
        shutil.copyfile(source, SELF_PATH)
    SELF_PATH.chmod(0o755)
    for c in COMMANDS:
        link(COMPAT_DIR / c, SELF_PATH.name)
    if selinux_on():
        run("restorecon", "-R", str(COMPAT_DIR))
    setup_el_repos()
    setup()
    return 0


def main():
    cmd, args = Path(sys.argv[0]).name, sys.argv[1:]
    if cmd in ("aurora-compat", "fedora_compat.py"):
        if args[:1] == ["install"]:
            return install(sys.argv[0])
        if args[:1] == ["setup"]:
            setup()
            return 0
        print(__doc__)
        return 2
    if cmd == "apt-get":
        return apt_get(args)
    if cmd == "apt-cache":
        return apt_cache(args)
    if cmd == "dpkg-query":
        return dpkg_query(args)
    if cmd == "dpkg":
        return dpkg(args)
    if cmd in ("debconf-set-selections", "phpenmod", "phpdismod"):
        return 0  # Fedora asks no install questions, and PHP loads every installed extension
    if cmd.startswith(("a2en", "a2dis")):
        return a2(cmd, args)
    if cmd == "apache2ctl":
        return subprocess.call(["apachectl", *args], env=ENV)
    if cmd in ("systemctl", "journalctl"):
        mapped = [unit_name(a) if not a.startswith("-") else a for a in args]
        return subprocess.call([f"/usr/bin/{cmd}", *mapped], env=ENV)
    if cmd in ("usermod", "gpasswd"):
        return subprocess.call([f"/usr/sbin/{cmd}", *[ACCOUNTS.get(a, a) for a in args]], env=ENV)
    if cmd == "pg_lsclusters":
        return pg_lsclusters()
    print(f"{cmd}: not available on this system", file=sys.stderr)
    return 127


if __name__ == "__main__":
    sys.exit(main())
