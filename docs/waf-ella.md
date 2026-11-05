# WAF Ella

A security center over the panel's WAF, bans and logs, under Security > WAF Ella. It runs alongside WAF Firewall, Fail2ban
and IP Blocker, which keep working as before. Its pages are Overview, Live Events, Investigate, Blocks, WAF Rules, Fail2Ban,
Sources, Incidents & Audit, and Settings. Every button is an API call under `/api/ella`, so an API token can do the same.

## Layout

| File | Purpose |
|---|---|
| `backend/ella/adapter.py` | `EllaSystemAdapter`: the only path to system commands. Allowlist, validated arguments, `shell=False`, timeouts, JSON in and out |
| `backend/ella/agentd.py` | The adapter behind a Unix socket as its own service, and `SocketAdapter`, which calls it |
| `backend/ella/db.py` | SQLite storage, schema and audit hash chain |
| `backend/ella/collector.py` | Log sources, normalization, masking, rotation, client address, possible-breach tagging |
| `backend/ella/blocks.py`, `registry.py` | Ban state machine, Safety Lock, one list of all bans, drift |
| `backend/ella/configs.py` | Safe config changes on Apache and Nginx: snapshot, check, reload, Watchdog |
| `backend/ella/rulebook.py` | Rules, exceptions, honeypots, CMS profiles, virtual patches, Under Attack, settings per domain |
| `backend/ella/tester.py` | Rule Tester |
| `backend/ella/proxies.py` | Trusted proxies, real client address, Cloudflare, what each web server can do |
| `backend/ella/fleet.py` | One panel managing others: signed check-ins and policies |
| `backend/ella/correlate.py` | Credential stuffing, slow guessing, rates, suggested exceptions |
| `backend/ella/intel.py` | Reputation lists, search engine checks, country lookup |
| `backend/ella/notify.py` | Alerts and their channels |
| `backend/ella/housekeeping.py` | Retention, SIEM export, YAML config, digests, Prometheus metrics |
| `backend/ella/supply.py` | Rule set file hashes, SBOM |
| `backend/ella/query.py` | The Live Events search language |
| `backend/ella/cli.py` | `ella-cli`, emergency access without the panel or database |
| `frontend/js/ella.js`, `ella_soc.js` | The pages |

## Rules

A rule is a tree of AND, OR and NOT conditions on the client address, host, path, method, User-Agent, any header, or any
parameter. ModSecurity has no OR across a chain, so a tree becomes one chain per way it can match, 16 at most. Rules are
written to `/etc/nginx/aurora-waf/ella.conf` and `/etc/modsecurity/zz-ella-rules.conf`, loaded after the panel's settings and
before the Core Rule Set. Each web server checks the file before reloading, a refusal puts the old file back, and the Watchdog
then watches the server.

- A rule starts off, and can't go to block without a detect period first.
- Every change is a version. Preview runs a rule over stored events, and says which conditions it can't check, because
  parameter values and bodies are never stored.
- Patterns with a repeat inside a repeat, backreferences or lookaround are refused, since their run time can't be limited.
- Imported rules take only `SecRule` and `SecAction`, IDs 1150000 to 1169999, and nothing that runs programs or reads files.

ID ranges: 1100000 own rules, 1150000 patches, 1170000 settings per domain, 1175000 Under Attack, 1180000 exceptions, 1190000
honeypots, 1191000 CMS profiles.

An exception from the False Positive Wizard covers one rule, one variable, one path, one site, using
`ctl:ruleRemoveTargetById`. It says so when it has to be wider than that.

Rates, countries and multi-source patterns aren't rule conditions: they are read from logs, so they act on the next request.

## Who the client is

`X-Forwarded-For`, `CF-Connecting-IP` and `X-Real-IP` are believed only from ranges under Settings > Proxies and CDN. Those
ranges also configure Nginx's real-IP module and Apache's `mod_remoteip`, so rules and logs see the visitor. In a forwarded
chain, the rightmost address that isn't a trusted proxy counts: anything to its left was sent by the client. Trusted ranges
can't be banned at the firewall. Behind Cloudflare, ban at Cloudflare with an API token.

## Possible Breach

An event is tagged `possible-breach` when its anomaly score reached the blocking level and it still got a 2xx or 5xx, or a
response rule fired on an answer that went out. Response rules need "Also check responses for leaks", which is off by default
because it costs CPU on every page. It's a suspicion, and says so.

## The agent service

`aurora-ella-agent.service` runs the adapter behind `/run/aurora-ella/agent.sock`. Only root may connect (socket mode and
`SO_PEERCRED`). It has `ProtectSystem=strict`, `NoNewPrivileges`, a reduced capability set, `MemoryMax=200M`, `CPUQuota=50%`.
It stays root rather than its own user, because `fail2ban-client` and `systemctl reload` need that.

If it stops, the panel either carries on inside itself (open, the default) or refuses firewall changes and shows why (closed).
Bans already in the firewall stay either way. Set this on the Sources page.

## Managing other servers

Managed servers call in, so they need no open port. Requests are signed with HMAC-SHA256 under a per-server secret, with a
timestamp (60 seconds either way) and a single-use nonce. A policy is signed too, and its version only goes up. Without the
control panel a server keeps its last valid policy, and queues events in a 20 MB file that drops the oldest first and counts
what it lost. Each server's own Safety Lock has the last word on bans sent from the center.

## Storage

`/var/lib/aurora/ella/`: `ella.db` holds state; `events-YYYYMM.db` holds one month of events, so retention is deleting a file.
Addresses are cut to /24 or /48 after 90 days by default. Nothing is stored for request bodies, `Authorization`, `Cookie`, or
query string values. A matched secret field keeps its name only. JWTs, bearer tokens and long hex strings are masked.
Once a day the chain's newest hash goes to `audit-anchors.log`.

## Network bans

Ella's bans live in their own table, `inet aurora_ella`, so lifting one source's ban leaves the others. A domain or path can't
be banned at the firewall, which doesn't see the Host header: use a rule. `ss -K` can't close HTTP/3 (QUIC) sessions, though new
datagrams are still dropped.

## Roles

`admin` has everything. `viewer` reads. `soc_operator` works in WAF Ella and nothing else in the panel, without fleet, config
import, proxies, channels or exports. `site` sees events and exceptions for its own domains only, enforced in the query.

## What was measured

Fedora 45 VM, one CPU, 8 GB, Apache with ModSecurity 2 at paranoia 1, 2026-11-05, `tests/integration/ella_load.py 300000`.

| Measure | Target | Result | |
|---|---|---|---|
| Added latency, p99 | 5 ms | 9 ms (8 to 17) | missed |
| Throughput with the WAF | 70 % | 25 % (6185 to 1567 requests/s) | missed |
| Writing events | 2 000/s | 18 216/s | met |
| Reading a log through to stored | 2 000/s | 21 782/s | met |
| Storage per event | 1 KB | 734 bytes, without evidence rows | met |
| Search | 2 s over 10 million | 5 ms over 300 000. 10 million wasn't built | not shown at that size |
| Ban to confirmed, p95 | 3 s | 90 ms | met |
| Comparing 10 000 set entries | 1 s | 15 ms | met |
| Agent memory | 200 MB | 16 MB | met |

The throughput test serves a tiny static page on one CPU, the case where the rule set is most of the work. A page that takes
PHP tens of milliseconds pays the same 3 to 4 ms. The "without" side is a host with rules switched off by policy.

Memory for Nginx's WAF, measured as PSS: 5 MB without it, 37 MB with it. Nearly all of that is the compiled rule set, shared
between workers.

## Not built

- Tarpit and inline rate limits. Nothing packaged does these on Apache without tying up workers. A rate here is read from logs.
- JA3/JA4 and HTTP/2 fingerprints: the packaged servers don't expose them, so there's no such field.
- A custom block page with an incident ID. A CAPTCHA or Turnstile challenge. A 444 answer.
- Agent self-update from signed releases. Agents update with the panel.
- Settings at server and account level: settings are global or per domain.
- ASN lookup, and AbuseIPDB. Digests are on the API, not emailed.
- An eBPF/XDP interface. mTLS: panels use signed requests over HTTPS with a pinned certificate.
- A policy for duplicate parameters beyond what the rule set does.

## Emergency access

    sudo ella-cli status
    sudo ella-cli unban 203.0.113.9
    sudo ella-cli bypass --minutes 15 --cidr 192.0.2.0/24
    sudo ella-cli waf detect-only
    sudo ella-cli rollback
    sudo ella-cli restore

Works with the panel and database down. Changes are journaled and replayed into the audit log when the panel next runs.

## Testing

    python -m pytest tests/test_ella.py tests/test_ella_soc.py
    sudo PYTHONPATH=. .venv/bin/python tests/integration/ella_stage1.py
    sudo PYTHONPATH=. .venv/bin/python tests/integration/ella_stage2.py
    sudo PYTHONPATH=. .venv/bin/python tests/integration/ella_soc.py apache   # or nginx
    sudo PYTHONPATH=. .venv/bin/python tests/integration/ella_load.py 300000

They change that server's firewall and web server config while they run, so use a test machine, and don't use its panel at the
same time.

## Undoing it

Nothing here changes an existing rule, ban or setting, so there's no data to migrate back.

    sudo systemctl disable --now aurora-ella-agent.service aurora-ella.service
    sudo nft delete table inet aurora_ella
    sudo rm -f /etc/systemd/system/aurora-ella*.service /usr/local/sbin/ella-cli
    sudo rm -f /etc/modsecurity/zz-ella-rules.conf /etc/nginx/aurora-waf/ella.conf /etc/nginx/conf.d/aurora-ella-*.conf /etc/apache2/conf-*/zz-ella-*.conf
    sudo rm -rf /var/lib/aurora/ella

Then restore the previous panel version, and reload the web server. `install.sh --uninstall` removes the service, table, rule
files and `ella-cli`, and keeps the data folder.
