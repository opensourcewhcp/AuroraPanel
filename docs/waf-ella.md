# WAF Ella

A security center over the panel's WAF, bans and logs. It is being built in stages and runs alongside WAF Firewall,
Fail2ban and IP Blocker, which keep working as before. This page describes stage 1.

## What stage 1 does

A real ModSecurity event or Apache log line is read, normalized and stored; it appears under Security > WAF Ella; an
operator bans the address; the ban is written to nftables, read back, and only then marked `applied`; live connections
are cut; the ban expires or is lifted; every step is in a tamper-evident audit log.

## Layout

| File | Purpose |
|---|---|
| `backend/ella/adapter.py` | `EllaSystemAdapter`: the only path to system commands. Allowlist, validated arguments, `shell=False`, timeouts, JSON in and out |
| `backend/ella/db.py` | SQLite storage, schema (DDL) and audit hash chain |
| `backend/ella/collector.py` | Log sources, normalization, masking, rotation handling |
| `backend/ella/blocks.py` | Ban state machine, Safety Lock, retries, reconciliation |
| `backend/ella/configs.py` | Safe Apache config changes, snapshots, Watchdog |
| `backend/ella/cli.py` | `ella-cli`, emergency access without the panel or database |
| `backend/ella/service.py` | Background worker inside the panel |
| `backend/ella/routes.py` | `/api/ella/*` |
| `frontend/js/ella.js` | The page |
| `tests/integration/ella_stage1.py` | End-to-end test on a real server |

## Storage

`/var/lib/aurora/ella/`: `ella.db` holds state; `events-YYYYMM.db` holds one month of events, so retention is deleting a
file. WAL mode, one writing connection per process on a worker thread.

Nothing is stored for: request bodies, `Authorization`, `Cookie`, query string values. A matched secret field keeps its
name only. JWTs, bearer tokens and long hex strings are masked in matched data.

## Network bans

Ella's bans live in their own table, `inet aurora_ella` (sets `ella4`, `ella6`, hook priority -25). Guard's table and
fail2ban's `f2b4`/`f2b6` sets are never written by a ban or unban, so lifting one source's ban leaves the others.
A domain or path can't be banned at the firewall, which doesn't see the Host header. That needs a WAF rule (stage 3).

HTTP/3 (QUIC): `ss -K` can't close UDP sessions. New datagrams are still dropped by the nft rule.

Bans come back after a reboot through `aurora-ella.service` (`ella-cli restore`), before the network is up. If the
database can't be read then, the table comes up empty and the panel restores the bans when it starts.

## Other web servers

Nginx has its own WAF (`backend/nginxwaf.py`): ModSecurity 3 and the Core Rule Set. Events reach WAF Ella from
`/var/log/nginx/modsec_audit.log`. It follows the WAF Firewall page's settings except for its own on/detect/off mode.

With it on, SELinux logs an `execmem` refusal for nginx: its regex engine asks for executable memory, most likely for
PCRE's JIT, and rules still work. `httpd_execmem` would allow it for every web process, so it stays off. The rules add about
141 MB across Nginx's processes on a 4-core test VM, which matters on small boards.

Caddy, Lighttpd and other HTTP servers: listen on 127.0.0.1 and add a reverse proxy site on Nginx. A server that also
listens on a public address can be reached around the WAF. The Coraza plugin for Caddy isn't used: Fedora and Debian have no
package for it, so it would mean building Caddy with Go or running an unsigned download in place of the packaged binary.

## Secrets check

Once a day the worker looks through newly stored events for anything masking missed (JWTs, bearer tokens, long hex
strings, `password=` style values). The result is on the Sources tab and on the dashboard's Problems notice. It names
the file, event and column, never the value. Long hex strings can be false alarms, such as a hash in a URL.

## Safety Lock

Refused without the force flag: the operator's own address, `management_cidrs`, `trusted_proxies`, panels under Servers,
this server's addresses and the LAN gateway. Refused even with it: `127.0.0.0/8`, `::1`, `0.0.0.0/8`. Set the ranges in
the `settings` table (no page for this yet).

## Emergency access

    sudo ella-cli status
    sudo ella-cli unban 203.0.113.9
    sudo ella-cli bypass --minutes 15 --cidr 192.0.2.0/24
    sudo ella-cli waf detect-only
    sudo ella-cli rollback
    sudo ella-cli restore

Works with the panel and database down. Changes are journaled and replayed into the audit log when the panel next runs.

## Testing

    python -m pytest tests/test_ella.py
    sudo PYTHONPATH=. .venv/bin/python tests/integration/ella_stage1.py

The integration test needs Apache with the WAF, fail2ban, nftables and a running panel. It changes that server's
firewall and Apache config while it runs, and initializes the fail2ban profile if there are no jails, so use a test
machine. Its attacker is a network namespace, so it can't ban the address you connect from.

## Undoing stage 1

Stage 1 changes no existing rule, ban or setting, so there is no data to migrate back.

    sudo nft delete table inet aurora_ella
    sudo systemctl disable aurora-ella.service
    sudo rm -f /etc/systemd/system/aurora-ella.service /etc/apache2/conf-enabled/zz-ella.conf /etc/apache2/conf-available/zz-ella.conf /usr/local/sbin/ella-cli
    sudo rm -rf /var/lib/aurora/ella
    sudo systemctl reload httpd   # apache2 on Debian

Then restore the previous panel version. `install.sh --uninstall` removes the table and `ella-cli`.
