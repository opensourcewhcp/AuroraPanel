#!/usr/bin/env bash
# AuroraPanel installer — Raspberry Pi OS / Debian / Ubuntu.
#
#   sudo bash install.sh                 # interactive: asks which port
#   sudo bash install.sh --port 9000     # non-interactive
#   sudo bash install.sh --no-https      # new install on plain HTTP (HTTPS is the default)
#   sudo bash install.sh --uninstall     # remove AuroraPanel completely (asks first)
#   sudo bash install.sh --reset-password  # lost the admin password: print a new one
#
# Installs in place (the folder this script lives in): creates .venv, installs
# Python deps, and registers a systemd service "aurorapanel" that starts on
# boot. Re-run it any time to change the port or repair the install — your
# admin account (aurora_config.json) and custom AURORA_* settings are kept.
set -euo pipefail

SERVICE=aurorapanel
UNIT="/etc/systemd/system/${SERVICE}.service"
DEFAULT_PORT=8088
APP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

ORIG_ARGS=("$@")
PORT=""
ASSUME_YES=0
NO_HTTPS=0
UNINSTALL=0
RESET_PW=0

c_ok=$'\e[32m'; c_warn=$'\e[33m'; c_err=$'\e[31m'; c_hi=$'\e[1;38;5;208m'; c_off=$'\e[0m'
[ -t 1 ] || { c_ok=; c_warn=; c_err=; c_hi=; c_off=; }
say()  { echo "${c_hi}==>${c_off} $*"; }
ok()   { echo "${c_ok}  ✓${c_off} $*"; }
warn() { echo "${c_warn}  !${c_off} $*"; }
die()  { echo "${c_err}  ✗ $*${c_off}" >&2; exit 1; }

usage() {
  sed -n '2,12p' "$0" | sed 's/^# \{0,1\}//'
  exit 0
}

while [ $# -gt 0 ]; do
  case "$1" in
    -p|--port)   PORT="${2:-}"; shift 2 ;;
    --port=*)    PORT="${1#*=}"; shift ;;
    -y|--yes)    ASSUME_YES=1; shift ;;
    --no-https)  NO_HTTPS=1; shift ;;
    --uninstall) UNINSTALL=1; shift ;;
    --reset-password) RESET_PW=1; shift ;;
    -h|--help)   usage ;;
    *) die "Unknown option: $1 (try --help)" ;;
  esac
done

# --- root -------------------------------------------------------------------
if [ "$(id -u)" -ne 0 ]; then
  command -v sudo >/dev/null || die "Run this as root."
  exec sudo bash "$0" "${ORIG_ARGS[@]}"
fi

# The regular user who ran sudo (File Manager defaults to their home).
PANEL_USER="${SUDO_USER:-}"
[ "$PANEL_USER" = "root" ] && PANEL_USER=""

# --- uninstall --------------------------------------------------------------
if [ $UNINSTALL = 1 ]; then
  # Started from the panel's own Terminal, this shell lives in the service's cgroup:
  # stopping the service kills this script halfway (unit file left behind). Hand the
  # job to a transient unit outside the panel and let it finish there.
  if [ -z "${AURORA_DETACHED:-}" ] && grep -q "/${SERVICE}\.service" /proc/self/cgroup 2>/dev/null; then
    warn "Running inside AuroraPanel's Terminal — the panel and this terminal will close."
    systemd-run --quiet --collect --unit="${SERVICE}-uninstall" --setenv=AURORA_DETACHED=1 \
      /bin/bash "${APP_DIR}/$(basename "${BASH_SOURCE[0]}")" --uninstall \
      || die "Could not start the uninstall in the background."
    ok "Uninstall continues in the background. Check it with: journalctl -u ${SERVICE}-uninstall"
    exit 0
  fi
  OLD_PORT=""
  [ -f "$UNIT" ] && OLD_PORT="$(sed -n 's/^Environment=PORT=\([0-9]*\).*/\1/p' "$UNIT" | head -n1)"
  BACKUPS="$(sed -n 's/^Environment=AURORA_BACKUP_DIR=//p' "$UNIT" 2>/dev/null | head -n1 || true)"
  BACKUPS="${BACKUPS:-/root/aurora-backups}"

  if [ $ASSUME_YES = 0 ]; then
    echo
    echo "${c_hi}  Uninstall AuroraPanel completely${c_off}"
    echo
    echo "  This removes:"
    echo "    - the panel service, its HTTPS certificate and its ufw rule"
    echo "    - its helpers: IP bans/trusted list, Network Monitor, VPN NAT, Dynamic DNS"
    echo "    - its fail2ban jails, filters and ban action"
    echo "    - its Apache/MariaDB settings, Web Disk and Directory Privacy"
    echo "    - everything in /var/lib/aurora (VPN client lists, file recycle bin, site backups)"
    echo "    - the program files in ${APP_DIR} (and your panel login)"
    echo
    echo "  Kept: your websites, databases, VPN servers, FTP and Linux users, installed"
    echo "  software, and backups in ${BACKUPS}."
    if [ -s /etc/apache2/conf-available/zz-aurora-privacy.conf ]; then
      echo
      warn "Folders protected with Directory Privacy will no longer ask for a password."
    fi
    if grep -qs '^Alias ' /etc/apache2/conf-available/zz-aurora-folders.conf; then
      warn "Folder sites linked in from outside the default web folder will stop answering (their files are kept)."
    fi
    echo
    [ -t 0 ] || die "Re-run with --yes to uninstall without a prompt."
    read -r -p "  Type 'yes' to uninstall: " ANSWER
    [ "$ANSWER" = "yes" ] || die "Cancelled — nothing was removed."
  fi

  # Started from the panel's own Terminal, this shell lives in the service's cgroup:
  # stopping the service kills this script halfway. Hand the job to a transient unit
  # outside the panel and let it finish there.
  if [ -z "${AURORA_DETACHED:-}" ] && grep -q "/${SERVICE}\.service" /proc/self/cgroup 2>/dev/null; then
    warn "Running inside AuroraPanel's Terminal — the panel and this terminal will close."
    systemd-run --quiet --collect --unit="${SERVICE}-uninstall" --setenv=AURORA_DETACHED=1 \
      /bin/bash "${APP_DIR}/$(basename "${BASH_SOURCE[0]}")" --uninstall --yes \
      || die "Could not start the uninstall in the background."
    ok "Uninstall continues in the background. Check it with: journalctl -u ${SERVICE}-uninstall"
    exit 0
  fi

  say "Removing the ${SERVICE} service"
  systemctl stop "${SERVICE}-https-revert.timer" "${SERVICE}-https-revert.service" 2>/dev/null || true
  for u in $(systemctl list-units --all --plain --no-legend "${SERVICE}-restart-*" 2>/dev/null | awk '{print $1}'); do
    systemctl stop "$u" 2>/dev/null || true
  done
  systemctl disable --now "$SERVICE" 2>/dev/null || true
  rm -rf "$UNIT" "/etc/systemd/system/${SERVICE}.service.d" "/etc/letsencrypt/renewal-hooks/deploy/${SERVICE}-restart"
  if [ -n "$OLD_PORT" ] && command -v ufw >/dev/null && ufw status 2>/dev/null | grep -qE "^${OLD_PORT}/tcp"; then
    ufw delete allow "${OLD_PORT}/tcp" >/dev/null && ok "Removed the ufw rule for ${OLD_PORT}/tcp"
  fi
  ok "Service removed"

  say "Removing helpers"
  HELPERS=(aurora-ddns.timer aurora-ddns.service aurora-guard.service aurora-netmon.service aurora-vpn-nat.service)
  for u in "${HELPERS[@]}"; do
    systemctl disable --now "$u" 2>/dev/null || true
    rm -f "/etc/systemd/system/$u"
  done
  if command -v nft >/dev/null; then
    for t in "inet aurora_guard" "inet aurora_mon" "ip aurora_vpn"; do
      # shellcheck disable=SC2086
      nft delete table $t 2>/dev/null || true
    done
  fi
  rm -f /usr/local/sbin/aurora-guard-ban /etc/sysctl.d/99-aurora-vpn.conf
  systemctl daemon-reload
  systemctl reset-failed "$SERVICE" "${HELPERS[@]}" 2>/dev/null || true
  ok "Bans, Network Monitor, VPN NAT and Dynamic DNS removed"

  if [ -e /etc/fail2ban/jail.d/zz-aurora.local ] || [ -e /etc/fail2ban/action.d/aurora-guard.conf ]; then
    rm -f /etc/fail2ban/jail.d/zz-aurora.local /etc/fail2ban/action.d/aurora-guard.conf /etc/fail2ban/filter.d/aurora-*.conf
    systemctl try-restart fail2ban 2>/dev/null || true
    ok "fail2ban is back to its own defaults"
  fi

  if [ -d /etc/apache2 ]; then
    APACHE_CHANGED=0
    for c in zz-aurora-tuning zz-aurora-privacy zz-aurora-webdisk zz-aurora-phppgadmin zz-aurora-folders; do
      if [ -e "/etc/apache2/conf-available/$c.conf" ] || [ -L "/etc/apache2/conf-enabled/$c.conf" ]; then
        rm -f "/etc/apache2/conf-enabled/$c.conf" "/etc/apache2/conf-available/$c.conf"
        APACHE_CHANGED=1
      fi
    done
    if [ -e /etc/apache2/sites-available/zz-aurora-webdisk-ssl.conf ] || [ -L /etc/apache2/sites-enabled/zz-aurora-webdisk-ssl.conf ]; then
      rm -f /etc/apache2/sites-enabled/zz-aurora-webdisk-ssl.conf /etc/apache2/sites-available/zz-aurora-webdisk-ssl.conf
      APACHE_CHANGED=1
    fi
    rm -rf /etc/apache2/aurora-privacy /etc/apache2/aurora-webdisk.htpasswd /etc/apache2/ssl/aurora /var/lib/apache2/aurora-davlock
    if [ $APACHE_CHANGED = 1 ] && systemctl is-active --quiet apache2; then
      if apache2ctl -t >/dev/null 2>&1; then
        systemctl reload apache2 && ok "Apache settings removed (Apache reloaded)"
      else
        warn "Apache's config doesn't pass 'apache2ctl -t' — fix it, then reload Apache"
      fi
    fi
  fi
  if [ -e /etc/mysql/mariadb.conf.d/99-aurora.cnf ]; then
    rm -f /etc/mysql/mariadb.conf.d/99-aurora.cnf
    ok "MariaDB settings removed (they stop applying at MariaDB's next restart)"
  fi

  rm -rf /var/lib/aurora
  ok "Removed /var/lib/aurora"

  # Only the files AuroraPanel ships (and what it made there) — never anything else
  # that happens to share the folder.
  say "Removing the program files"
  for f in backend frontend docs deploy .venv install.sh run.sh run.bat requirements.txt README.md LICENSE \
           .gitattributes .gitignore .git aurora_config.json aurora_config.tmp aurora_config.json.tmp \
           aurora_initial_password aurora_initial_password.tmp \
           tests requirements-dev.txt pytest.ini .coveragerc .github htmlcov .coverage .pytest_cache; do
    rm -rf "${APP_DIR:?}/$f"
  done
  if rmdir "$APP_DIR" 2>/dev/null; then
    ok "Removed ${APP_DIR}"
  else
    ok "Program files removed; other files you put in ${APP_DIR} were left there"
  fi
  echo
  echo "${c_hi}  AuroraPanel has been uninstalled.${c_off}"
  [ -d "$BACKUPS" ] && echo "  Your backups are still in ${BACKUPS}."
  exit 0
fi

echo
echo "${c_hi}  AuroraPanel installer${c_off}"
echo "  Installing from: ${APP_DIR}"
echo

[ -f "$APP_DIR/backend/app.py" ] || die "backend/app.py not found — run this from the AuroraPanel folder."
command -v systemctl >/dev/null || die "systemd is required."

# The admin account's first password: random, printed here, saved root-only in
# aurora_initial_password until it's changed at the first sign-in (the panel asks).
show_initial_password() {
  local f="$APP_DIR/aurora_initial_password"
  [ -f "$f" ] || return 0
  echo "  ${c_hi}Sign in with:${c_off}"
  sed 's/^/    /' "$f"
  echo "  You'll be asked to choose your own password straight away."
  echo "  (Saved until then in ${f}, readable by root only.)"
}

# --- lost password ----------------------------------------------------------
if [ $RESET_PW = 1 ]; then
  [ -x "$APP_DIR/.venv/bin/python" ] || die "AuroraPanel isn't installed here yet — run: sudo bash install.sh"
  ( cd "$APP_DIR" && .venv/bin/python -c 'from backend import config; config.issue_temporary_password()' ) \
    || die "Could not set a new password."
  ok "New password set. Everyone signed in to the panel was signed out."
  echo
  show_initial_password
  echo
  exit 0
fi

# --- port -------------------------------------------------------------------
# Default to the currently-installed port on a re-run.
CURRENT_PORT=""
FRESH=1
if [ -f "$UNIT" ]; then
  FRESH=0
  CURRENT_PORT="$(sed -n 's/^Environment=PORT=\([0-9]*\).*/\1/p' "$UNIT" | head -n1)"
fi
SUGGESTED="${CURRENT_PORT:-$DEFAULT_PORT}"

port_in_use() {
  # Our own service holding its current port doesn't count.
  [ "$1" = "$CURRENT_PORT" ] && systemctl is-active --quiet "$SERVICE" && return 1
  ss -Hltn "sport = :$1" 2>/dev/null | grep -q .
}

valid_port() {
  [[ "$1" =~ ^[0-9]+$ ]] && [ "$1" -ge 1 ] && [ "$1" -le 65535 ]
}

check_port() {
  valid_port "$1" || { warn "\"$1\" is not a valid port (1-65535)."; return 1; }
  if port_in_use "$1"; then
    local who
    who="$(ss -Hltnp "sport = :$1" 2>/dev/null | grep -o 'users:(("[^"]*' | head -n1 | cut -d'"' -f2)"
    warn "Port $1 is already in use${who:+ by $who}."
    return 1
  fi
  case "$1" in
    22)     warn "Port 22 is SSH."; return 1 ;;
    80|443) warn "Port $1 is normally used by the web server (Apache) — pick another." ; return 1 ;;
  esac
  return 0
}

if [ -n "$PORT" ]; then
  check_port "$PORT" || die "Choose a different port with --port."
elif [ $ASSUME_YES = 1 ] || [ ! -t 0 ]; then
  PORT="$SUGGESTED"
  check_port "$PORT" || die "Port $PORT is unavailable. Re-run with --port <number>."
else
  while :; do
    read -r -p "  Which port should AuroraPanel listen on? [${SUGGESTED}]: " PORT
    PORT="${PORT:-$SUGGESTED}"
    check_port "$PORT" && break
  done
fi
ok "Using port ${PORT}"

# --- system packages --------------------------------------------------------
say "Checking system packages"
NEED=()
command -v python3 >/dev/null || NEED+=(python3)
python3 -c 'import venv, ensurepip' 2>/dev/null || NEED+=(python3-venv)
command -v ss >/dev/null || NEED+=(iproute2)
command -v curl >/dev/null || NEED+=(curl)
command -v openssl >/dev/null || NEED+=(openssl)
if [ ${#NEED[@]} -gt 0 ]; then
  command -v apt-get >/dev/null || die "Missing: ${NEED[*]} — install them and re-run."
  say "Installing: ${NEED[*]}"
  DEBIAN_FRONTEND=noninteractive apt-get update -qq
  DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "${NEED[@]}" >/dev/null
fi
PYV="$(python3 -c 'import sys; print("%d.%d" % sys.version_info[:2])')"
python3 -c 'import sys; sys.exit(sys.version_info < (3, 10))' || die "Python 3.10+ required (found $PYV)."
ok "Python $PYV"

# --- virtualenv + deps ------------------------------------------------------
say "Setting up Python environment"
cd "$APP_DIR"
if [ ! -x .venv/bin/python ]; then
  python3 -m venv .venv || die "Could not create .venv (is python3-venv installed?)."
fi
.venv/bin/python -m pip install --quiet --upgrade pip
if ! .venv/bin/python -m pip install --quiet -r requirements.txt; then
  # No prebuilt wheel for this Pi (e.g. 32-bit / older OS) — build from source.
  command -v apt-get >/dev/null || die "pip install failed."
  warn "Prebuilt packages unavailable — installing build tools and retrying (this can take a while on older Pis)"
  DEBIAN_FRONTEND=noninteractive apt-get install -y -qq build-essential python3-dev libffi-dev >/dev/null
  .venv/bin/python -m pip install --quiet -r requirements.txt || die "pip install failed — see errors above."
fi
ok "Dependencies installed"

# --- leftovers from earlier installs ----------------------------------------
# A Panel HTTPS drop-in whose certificate is gone or broken would stop the panel
# from starting at all: fall back to plain HTTP instead.
DROPIN="/etc/systemd/system/${SERVICE}.service.d/aurora-https.conf"
if [ -f "$DROPIN" ]; then
  CRT="$(sed -n 's/^Environment=UVICORN_SSL_CERTFILE=//p' "$DROPIN" | head -n1)"
  KEY="$(sed -n 's/^Environment=UVICORN_SSL_KEYFILE=//p' "$DROPIN" | head -n1)"
  if ! .venv/bin/python -c 'import ssl,sys; ssl.create_default_context(ssl.Purpose.CLIENT_AUTH).load_cert_chain(sys.argv[1], sys.argv[2])' \
       "$CRT" "$KEY" 2>/dev/null; then
    rm -f "$DROPIN"
    rmdir "$(dirname "$DROPIN")" 2>/dev/null || true
    warn "Panel HTTPS was on but its certificate is missing or broken — switched back to HTTP (turn it on again under Security → Panel HTTPS)"
  elif ! grep -q '^Environment=UVICORN_SSL_CIPHERS=' "$DROPIN"; then
    # 1.1.9+: strong TLS 1.2 ciphers only and no "server:" header (what a regenerated drop-in gets)
    CIPHERS="$(.venv/bin/python -c 'from backend import panelhttps; print(panelhttps.CIPHERS)' 2>/dev/null || true)"
    if [ -n "$CIPHERS" ]; then
      printf 'Environment=UVICORN_SSL_CIPHERS=%s\nEnvironment=UVICORN_SERVER_HEADER=false\n' "$CIPHERS" >> "$DROPIN"
    fi
  fi
fi
# Dynamic DNS runs this folder's Python; point it here if the panel was installed elsewhere before.
DDNS_UNIT=/etc/systemd/system/aurora-ddns.service
if [ -f "$DDNS_UNIT" ] && ! grep -qxF "WorkingDirectory=${APP_DIR}" "$DDNS_UNIT"; then
  sed -i -e "s|^WorkingDirectory=.*|WorkingDirectory=${APP_DIR}|" \
         -e "s|^ExecStart=[^ ]*|ExecStart=${APP_DIR}/.venv/bin/python|" "$DDNS_UNIT"
  ok "Dynamic DNS now runs from ${APP_DIR}"
fi
systemctl reset-failed "$SERVICE" 2>/dev/null || true

# --- panel HTTPS --------------------------------------------------------------
# New installs start on HTTPS with a self-signed certificate (turn it off under
# Security → Panel HTTPS). Updates and re-runs keep whatever was chosen before.
if [ $FRESH = 1 ] && [ $NO_HTTPS = 0 ] && [ ! -f "$DROPIN" ]; then
  if .venv/bin/python -c 'from backend import panelhttps; panelhttps.install_default()'; then
    ok "Panel HTTPS is on (self-signed certificate)"
  else
    warn "Couldn't create the panel's certificate — it runs on plain HTTP for now (Security → Panel HTTPS)"
  fi
fi

# --- systemd unit -----------------------------------------------------------
say "Writing ${UNIT}"
# Keep any custom AURORA_* settings from a previous install.
EXTRA_ENV=""
if [ -f "$UNIT" ]; then
  EXTRA_ENV="$(grep -E '^Environment=AURORA_' "$UNIT" | grep -v '^Environment=AURORA_USER=' || true)"
fi

cat > "$UNIT" <<EOF
# Generated by AuroraPanel install.sh — re-run the installer to change the port.
[Unit]
Description=AuroraPanel - Raspberry Pi control panel
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
WorkingDirectory=${APP_DIR}
Environment=HOST=0.0.0.0
Environment=PORT=${PORT}
${PANEL_USER:+Environment=AURORA_USER=${PANEL_USER}}
${EXTRA_ENV}
ExecStart=${APP_DIR}/.venv/bin/python -m backend.serve backend.app:app --host 0.0.0.0 --port ${PORT}
Restart=on-failure
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF
# Drop the blank lines left by empty optional entries.
sed -i '/^$/N;/^\n$/D' "$UNIT"

# Before the panel starts: a fresh panel never waits unclaimed for whoever finds it first.
.venv/bin/python -c 'from backend import config; config.lock_down(); config.ensure_initial_credentials()' \
  || die "Could not create the admin account."

systemctl daemon-reload
systemctl enable "$SERVICE" >/dev/null 2>&1
systemctl restart "$SERVICE"
ok "Service enabled (starts on boot)"

# --- firewall ---------------------------------------------------------------
if command -v ufw >/dev/null && ufw status 2>/dev/null | grep -q "Status: active"; then
  ufw allow "${PORT}/tcp" >/dev/null
  ok "ufw is active — allowed ${PORT}/tcp"
  if [ -n "$CURRENT_PORT" ] && [ "$CURRENT_PORT" != "$PORT" ]; then
    warn "The old panel port ${CURRENT_PORT}/tcp is still allowed in ufw (remove it with: sudo ufw delete allow ${CURRENT_PORT}/tcp)"
  fi
fi

# --- health check -----------------------------------------------------------
say "Waiting for AuroraPanel to start"
# Panel HTTPS (Security page) is a drop-in that this unit rewrite leaves in place,
# so the panel may answer on either scheme.
SCHEME=http
UP=0
for _ in $(seq 1 30); do
  if curl -fsk -o /dev/null --max-time 3 "https://127.0.0.1:${PORT}/"; then SCHEME=https; UP=1; break; fi
  if curl -fs -o /dev/null --max-time 3 "http://127.0.0.1:${PORT}/"; then UP=1; break; fi
  sleep 1
done
if [ $UP = 0 ]; then
  warn "The panel did not answer on port ${PORT}. Recent logs:"
  journalctl -u "$SERVICE" -n 25 --no-pager || true
  die "Install finished but the service isn't responding."
fi
ok "Panel is up"

IPS="$(hostname -I 2>/dev/null | tr ' ' '\n' | grep -E '^[0-9]+\.' || true)"
echo
echo "${c_hi}  AuroraPanel is installed!${c_off}"
echo
echo "  Open it from a browser on your network:"
for ip in $IPS; do echo "    ${SCHEME}://${ip}:${PORT}"; done
systemctl is-active --quiet avahi-daemon 2>/dev/null && echo "    ${SCHEME}://$(hostname).local:${PORT}"
echo
if [ -f "$APP_DIR/aurora_initial_password" ]; then
  show_initial_password
  echo
fi
if [ "$SCHEME" = https ] && [ $FRESH = 1 ]; then
  echo "  The panel uses HTTPS with a self-signed certificate: your browser warns once"
  echo "  (\"Not private\") — choose Advanced → Proceed. The connection is encrypted."
  echo "  Turn HTTPS off or use a Let's Encrypt certificate: Security → Panel HTTPS."
fi
echo "  Change the port later:  sudo bash ${APP_DIR}/install.sh"
echo "  Logs:                   sudo journalctl -u ${SERVICE} -f"
echo "  Uninstall completely:   sudo bash ${APP_DIR}/install.sh --uninstall"
echo
