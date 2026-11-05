#!/usr/bin/env bash
# AuroraPanel — Linux / Raspberry Pi launcher
set -e
cd "$(dirname "$0")"

# Installed as a service, the panel runs as root and its settings are root's alone. Say so, rather than crash halfway.
if [ -f aurora_config.json ] && [ ! -r aurora_config.json ]; then
  echo "AuroraPanel is installed as a service here, and its settings can only be read by root." >&2
  if command -v systemctl >/dev/null 2>&1 && systemctl is-active --quiet aurorapanel; then
    echo "It's already running, so there's nothing to start. Open port ${PORT:-8088} in a browser." >&2
    echo "Restart it with:  sudo systemctl restart aurorapanel" >&2
  else
    echo "Start it with:  sudo systemctl start aurorapanel" >&2
  fi
  exit 1
fi

if [ ! -d ".venv" ]; then
  echo "Creating virtual environment..."
  python3 -m venv .venv
fi
# shellcheck disable=SC1091
source .venv/bin/activate
pip install --quiet --upgrade pip
pip install --quiet -r requirements.txt

HOST="${HOST:-0.0.0.0}"
PORT="${PORT:-8088}"
echo
echo "AuroraPanel running at http://${HOST}:${PORT}"
echo
exec python -m uvicorn backend.app:app --host "$HOST" --port "$PORT"
