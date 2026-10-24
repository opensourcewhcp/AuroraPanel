# Hosting accounts, plans and resellers

**Hosting** works like WHM: you sell or give space on your server to other people, each in their own
separate account.

## Plans

**Hosting → Plans** sets what an account may use (0 = unlimited):

| Limit | What it does |
|---|---|
| Disk space | Files, mail and databases together. Going over raises an alert. |
| Bandwidth per month | Web traffic of the account's sites. Going over raises an alert. |
| Websites | How many domains the account can have. |
| Databases | How many `user_…` databases it can create. |
| Email accounts | How many mailboxes on its domains. |
| PHP workers | How many PHP requests its sites run at once, so one busy site can't slow the server. |
| PHP memory | Memory per PHP request. |

Three plans come ready (Starter, Business, Unlimited). Editing a plan applies to every account on it:
PHP limits at once, disk and bandwidth at the next hourly check.

## Accounts

**Hosting → Accounts → Create an account** asks for a user name, the main domain, a password and a plan.
The account gets:

- its own Linux user and home, `/home/<user>`, closed to every other account;
- its website in `/home/<user>/public_html` (more domains in `/home/<user>/<domain>`);
- PHP that runs as the account itself, within the plan's limits and only inside its home;
- its own panel login (the user name and password you set). It sees only its websites, files,
  mailboxes, visitors and its own databases (`<user>_name`), plus a page with its plan and usage.

**Suspend** takes its websites offline and stops its panel login and its mailboxes' sign-in. Nothing
is deleted. **Unsuspend** restores exactly what was on before. **Terminate** deletes everything, after you
type the account's name. You can keep its files if you want.

## Resellers

Add a panel user with the **Reseller** role (**System → Panel Users**). Then choose under **Hosting → Resellers**:

- which plans they may sell;
- how many accounts they may have.

A reseller sees only their own accounts and can create, suspend and terminate them, but can't change plans.

## Notes

- Needs Apache and PHP (PHP-FPM); the Accounts page offers to install them.
- Disk and bandwidth are measured every hour. Going over a limit raises an alert; nothing is blocked
  automatically, so suspend the account if you need to.
