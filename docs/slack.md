# Slack: alerts you can answer

With the Slack app connected, AuroraPanel posts to a Slack channel. It works on a Raspberry Pi at home
too: the panel opens the connection to Slack itself (Slack's Socket Mode), so no public address, open
port or certificate is needed.

## What it sends

- **Every alert** (disk, services, certificates, backups, updates, attack waves…), with:
  - **Snooze 24 h**;
  - **Restart** for a stopped service;
  - for attack alerts, **Ban** / **Trust** for each address.
- **A message for each new attacker** (at most once a day per address):
  - when the WAF blocks it several times in 10 minutes;
  - when it fails to sign in to the panel several times in 15 minutes;
  - when fail2ban bans it.

  The message shows what it tried, with **Ban**, **Trust** and **Allow this WAF rule** (for a false alarm).

Every button flips: Ban ⇄ Unban, Trust ⇄ Untrust, Allow rule ⇄ Undo. So a click can always be reversed,
and the message keeps a line for each action: who, what and when. Everything is also in the Activity Log
as `slack:<name>`.

## /aurora

- `/aurora status`: load, memory, disk, problems.
- `/aurora alerts`: what's wrong right now.
- `/aurora ip 1.2.3.4`: what an address did here, with buttons.
- `/aurora ban 1.2.3.4`, `unban`, `trust`, `untrust`.

## Setting it up (about 2 minutes)

1. **System → Alerts → Slack → Copy the app manifest.**
2. At api.slack.com/apps: **Create New App → From a manifest**, pick your workspace, paste, then
   **Create** and **Install to Workspace**.
3. Copy two tokens into the panel:
   - **Bot token:** *OAuth & Permissions → Bot User OAuth Token* (`xoxb-…`).
   - **App-level token:** *Basic Information → App-Level Tokens → Generate*, with the
     `connections:write` scope (`xapp-…`).
4. Enter the channel (e.g. `#alerts`; for a private channel, invite the bot first), switch it on and
   **Save**.
5. **Send a test message.** In Slack, press **Allow me to use the buttons**. Only allowed members can
   press buttons or use `/aurora`. Add more people by member ID (Slack profile → ⋮ → Copy member ID).

Several servers in one workspace: create one app per server. Each server's manifest names its app after
the server.
