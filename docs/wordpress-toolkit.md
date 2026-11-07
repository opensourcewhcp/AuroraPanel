# WordPress Toolkit

**Applications → WordPress Toolkit** finds every WordPress installed through the App Installer and
manages it with [WP-CLI](https://wp-cli.org) (downloaded and checksum-verified on first use). Commands
run as the user that owns the site's files, with the same PHP version as the web server.

| Action | What it does |
| ------ | ------------ |
| **Update everything** | WordPress core, its database, plugins, themes and translations. Single plugins can be updated from the list. |
| **Check for hacked files** | Compares WordPress and plugin files with the official checksums from wordpress.org, looks for PHP files inside `uploads/` (a classic backdoor), and runs ClamAV when installed. |
| **Harden** | Turns off the theme/plugin file editor in wp-admin, blocks `xmlrpc.php` (a password-guessing target) on every web server, makes `wp-config.php` readable only by the site, and turns debug output off. On Apache it also blocks `readme.html` and `license.txt`. Nginx and Caddy don't read `.htaccess`, so there those two files are removed; a WordPress update brings them back, so Harden again after one. |
| **Auto-updates** | WordPress, plugins and themes update themselves. |
| **Maintenance mode** | Shows visitors a "briefly unavailable" page while you work. |
| **Staging copy** | A copy at `<site>/aurora-staging/` with its own copy of the database, hidden from search engines. It has the live site's admin accounts, so it's locked: pages, logins and the API answer 403 until it's opened with the link in the toolkit, which holds a private key and leaves a cookie in that browser. Images and other static files aren't covered by the lock. **Delete staging** removes the files, database, database user and key. A copy made by an older version shows **Lock staging copy**; press it. |

If a site can't reach its database (wrong `DB_*` settings in `wp-config.php` or a missing database),
the toolkit says so and doesn't attempt updates.

The toolkit is for admins. Viewer and website manager accounts can't open it. Anything that touches a site's files runs as the
site's user, so a hacked site can't use the panel to reach the rest of the server.
