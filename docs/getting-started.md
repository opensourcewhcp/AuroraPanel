# Getting started

## Install

On a Raspberry Pi (Raspberry Pi OS Bookworm or newer) or an Ubuntu/Debian server with systemd and
Python 3.10+:

```bash
git clone https://github.com/aurora51dotcom/AuroraPanel ~/AuroraPanel
cd ~/AuroraPanel
sudo bash install.sh
```

The installer asks for a port (default `8088`), sets up the `aurorapanel` service and prints the
address to open, e.g. `https://192.168.1.20:8088`, with the first sign-in: user `admin` and a random
password. Sign in with them and the panel asks you to choose your own password before anything else
opens. There is no "create your account" page, so nobody who finds a freshly installed server
(on a VPS: anyone on the internet) can claim it before you.

Until you change it, the password is kept in `aurora_initial_password` in the AuroraPanel folder,
readable by root only (`sudo cat aurora_initial_password`). Lost your password later?
`sudo bash install.sh --reset-password` prints a new one-time password (the username stays).

The owner account is always an administrator, and two-factor login (TOTP) is available for it.
More people can be added later with their own roles (see [Users and roles](users-and-roles.md)).

Nothing else needs to be installed first: pages that need Apache, PHP, MariaDB, the mail server,
Docker and so on offer to install them, with a progress bar.

## HTTPS

New installs use a self-signed certificate, so the browser warns once ("Not private" → Advanced →
Proceed). Under **Security → Panel HTTPS** you can switch to a Let's Encrypt certificate for a host
name that points at the server, which removes the warning.

## Install it as an app

With a trusted certificate (Let's Encrypt, or `http://localhost`), browsers offer to install the
panel as an app: Chrome/Edge show an install icon in the address bar, Safari on iPhone uses
**Share → Add to Home Screen**. The app opens in its own window with the AuroraPanel icon.

Only the panel's own scripts, styles, icons and fonts are kept on the device so it starts fast.
Nothing the server tells the panel (`/api/…`) is ever stored, and every start checks the server
first, so updates appear straight away. With a self-signed certificate browsers don't allow this;
the panel then works exactly as a normal web page.

## Background tasks

Alerts, scheduled backups, AutoSSL renewals and the update check run from a systemd timer
(`aurora-tasks.timer`, once a minute), not from the panel process — they keep working while the
panel restarts. `systemctl list-timers aurora-tasks.timer` shows it.

## Updating

**Preferences → About & Updates → Check for updates** (it only contacts aurora51.com when you click),
or download the zip, unzip it over the install and run `sudo bash install.sh` again — your
accounts and settings are kept.
