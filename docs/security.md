# Security

## InstaWAFF

**Security → InstaWAFF** is the web application firewall and the ban list on one page. ModSecurity with
the OWASP Core Rule Set inspects every request; the ban list names paths, payloads, scanner user agents
and addresses that no real visitor uses.

- **Blocking**, **Detect only** (log, don't block) or **Off**, and a switch for the ban list.
- In Blocking mode a request for something on the ban list is refused before the file is served, and
  the address is banned at the firewall right after. Detect only logs it and lets it through.
- **Overview** shows the numbers: attacks, refused, logged, bans, hits and reports, a chart over time,
  what was tried, who is attacking and which sites they went for. Three panels split it by what caught
  the address: **Application firewall**, **Knocks** (port scans) and **Other** (guessing paths, hammering).
- **Attacks** and **Bans** list every event. Search by address or any text (a path, a site, a rule, a
  user agent), show 100, 300, 500, 1000, 5000 or any number per page, and from each row **Investigate**
  the address (the IP card), **Ban** or **Unban** it, or **Report** it to its abuse desk.
- **Detection** holds the ban list (add, import, export, delete), the ban length, automatic reports and
  the thresholds for knocks and other behaviour.
- **Exceptions**: addresses that are always let through (this server's own address is remembered and
  always among them, as are the addresses trusted under IP Blocker & Trust), apps the rules know
  (WordPress, Nextcloud, Drupal, DokuWiki, phpMyAdmin, phpBB, XenForo, webmail), a switch per website,
  and the rules you switched off as false alarms.
- **Rule level** sets how strict the rules are (paranoia) and the score at which a request is blocked.

## IP Blocker, Trust and the IP card

Clicking any IP address in the panel (visitors, errors, Network Monitor, WAF) opens the **IP card**:
who owns the address, its reverse DNS, what it did here (web requests, WAF hits, failed logins), and
buttons to **Ban**, **Unban**, **Trust**, **Untrust** and **Report**.

Bans are server-wide firewall (nftables) rules, so a banned IP can't reach any service. Every ban
records where it was made (IP card, Network Monitor, WAF, IP Blocker, another server) and shows it
in the IP Blocker. With [several servers](servers.md) a ban can be applied everywhere.

**Trusted** means trusted everywhere: a trusted address can't be banned, fail2ban ignores it, InstaBan
skips it and the WAF lets its requests through. Trust your own devices (or your LAN range) first, so a
site opened by IP address or a mistyped password never locks you out.

## Reporting abuse

**Report** prepares an abuse report for the network that owns the IP (its abuse contact from the
registry), with the evidence from this server's logs — failed logins and web attacks with times.
You see a preview, can change the recipient and add a note, and nothing is sent until you click
Send. An IP that was already reported is marked as such.

## The panel's own login

- A new install has no open "create account" page: the installer sets a random password that must be
  replaced at the first sign-in.
- `aurora_config.json` (session key, 2FA secret, API token and user hashes) is readable by root only.
- Ten failed logins from one address wait 15 minutes; fail2ban can ban at the firewall too.

## fail2ban, SSH keys, two-factor login, API tokens

See the matching pages under Security; each explains its settings.

## Security Report

Security → Security Report checks everything an outside vulnerability scanner checks, from the inside and only for what lives on this server. Run report starts it in the background; a bar shows each target as it finishes (about 20 seconds, a few minutes with the deep TLS scan).

What it covers:

- Web application: security headers, an incomplete Content-Security-Policy (no form-action, wildcard or undefined sources, unsafe-inline), cookies without Secure, HttpOnly or SameSite, POST forms without an anti-CSRF token, version banners on error pages, redirects that carry a page of content.
- SSL / TLS: certificate trust, name and expiry, TLS 1.0/1.1, weak cipher suites, anonymous cipher suites on the mail ports (STARTTLS included).
- Network: every open TCP and UDP port and whether the firewall lets the world reach it, services that belong on your own network only (databases, Samba, rpcbind, NFS, printing), FTP logins in clear text, weak SSH algorithms, TCP and ICMP timestamps, an open DNS resolver.
- Email authentication: DMARC, SPF and DKIM for every mail domain, and for the main domain of every website.
- Server protections: 2FA, Panel HTTPS, firewall, Fail2ban, WAF, the trusted certificate authorities.

Three optional tools make it match a full outside scan: Nmap (the version every port announces), testssl.sh (every protocol, cipher and known TLS attack) and ssh-audit (every SSH algorithm rated). The report offers to install whichever is missing; without them it runs its built-in checks.

After a report, Apply fixes lists every one-click fix with what it changes and which findings it resolves. Fixes that change how people or programs connect (FTPS, local-network-only ports, SSH algorithms) start unticked. The report runs again afterwards to confirm. A finding that is fine as it is (a false positive, or on purpose) can be Accepted with a note: it stays listed but no longer counts in the score. Each finding shows when it was first seen, and the report lists what was fixed since the last run.

## DMARC

DMARC tells receiving mail servers what to do with mail that claims to be from your domain but fails SPF and DKIM: deliver it (p=none, monitoring only), send it to spam (p=quarantine) or refuse it (p=reject). Domains → Manage → Email authentication shows the domain's status, SPF and DKIM, and the current record.

The wizard asks whether the domain sends email, how sure you are that your own mail passes, where daily reports should go, and how subdomains and alignment should be treated, then shows the record with every tag explained. Saving publishes it in this server's DNS zone when the domain's DNS is served here; otherwise it shows the record to add at your DNS provider. The policy, subdomain policy, percentage, report addresses and alignment can also be set directly under the wizard. How DMARC works explains the whole flow.

Start with p=none and a report address, move to quarantine when the reports show only your own servers, then to reject. A domain that never sends mail can go straight to p=reject.
