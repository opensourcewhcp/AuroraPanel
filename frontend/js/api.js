/* Thin fetch wrapper around the AuroraPanel API. */
const API = (() => {
  async function request(method, path, body, isForm) {
    const opts = { method, credentials: "same-origin", headers: {} };
    if (body !== undefined) {
      if (isForm) {
        opts.body = body; // FormData, let the browser set the boundary.
      } else {
        opts.headers["Content-Type"] = "application/json";
        opts.body = JSON.stringify(body);
      }
    }
    const res = await fetch(path, opts);
    // The panel was updated while this tab was open: its scripts are now out of date.
    const build = res.headers.get("X-Aurora-Build");
    const mine = document.querySelector('meta[name="aurora-build"]');
    if (build && mine && build !== mine.content && !request.stale) {
      request.stale = true;
      window.dispatchEvent(new CustomEvent("aurora-updated"));
    }
    if (res.status === 401) {
      // Keep the server's reason: the login page needs "otp_required" (show the 2FA code field),
      // "Invalid credentials" and "Invalid 2FA code"; everywhere else 401 just means "signed out".
      let detail = "";
      try { if ((res.headers.get("content-type") || "").includes("application/json")) detail = (await res.json()).detail || ""; } catch (e) {}
      const err = new Error(typeof detail === "string" && detail ? detail : "Not authenticated");
      err.status = 401;
      throw err;
    }
    let data = null;
    const ct = res.headers.get("content-type") || "";
    if (ct.includes("application/json")) data = await res.json();
    // Still on the installer's password (e.g. reset from another tab): back to the change form.
    if (res.status === 403 && data && data.detail === "password_change_required" && !request.pwReload) {
      request.pwReload = true;
      location.reload();
    }
    if (!res.ok) {
      const err = new Error((data && data.detail) || res.statusText || "Request failed");
      err.status = res.status;
      throw err;
    }
    return data;
  }

  return {
    get: (p) => request("GET", p),
    post: (p, b) => request("POST", p, b),
    postForm: (p, form) => request("POST", p, form, true),

    // convenience endpoints
    status: () => request("GET", "/api/status"),
    login: (username, password) => request("POST", "/api/login", { username, password }),
    logout: () => request("POST", "/api/logout"),
    me: () => request("GET", "/api/me"),

    overview: () => request("GET", "/api/system/overview"),
    disks: () => request("GET", "/api/system/disks"),
    network: () => request("GET", "/api/system/network"),
    processes: (sort) => request("GET", `/api/system/processes?sort_by=${sort || "cpu"}&limit=1500`),
    killProcess: (pid) => request("POST", `/api/system/processes/${pid}/kill`),

    services: () => request("GET", "/api/services"),
    serviceControl: (unit, action) => request("POST", "/api/services/control", { unit, action }),
    serviceStatus: (unit) => request("GET", `/api/services/status?unit=${encodeURIComponent(unit)}`),

    filesList: (path) => request("GET", `/api/files/list?path=${encodeURIComponent(path)}`),
    filesRead: (path) => request("GET", `/api/files/read?path=${encodeURIComponent(path)}`),
    filesWrite: (path, content) => request("POST", "/api/files/write", { path, content }),
    filesDelete: (path, permanent) => request("POST", "/api/files/delete", { path, permanent: !!permanent }),
    filesMkdir: (path, name) => request("POST", "/api/files/mkdir", { path, name }),
    downloadUrl: (path) => `/api/files/download?path=${encodeURIComponent(path)}`,
    filesZip: (path, names, archive_name, overwrite) => request("POST", "/api/files/zip", { path, names, archive_name, overwrite: !!overwrite }),
    filesUnzip: (path, overwrite) => request("POST", "/api/files/unzip", { path, overwrite: !!overwrite }),
    trashList: () => request("GET", "/api/files/trash"),
    trashRestore: (id, overwrite) => request("POST", "/api/files/trash/restore", { id, overwrite: !!overwrite }),
    trashDelete: (id) => request("POST", "/api/files/trash/delete", { id }),
    trashEmpty: () => request("POST", "/api/files/trash/empty"),

    // jobs
    job: (id) => request("GET", `/api/jobs/${id}`),

    // packages
    pkgInstalled: () => request("GET", "/api/packages/installed"),
    pkgUpgradable: () => request("GET", "/api/packages/upgradable"),
    pkgSearch: (q) => request("GET", `/api/packages/search?q=${encodeURIComponent(q)}`),
    pkgUpdate: () => request("POST", "/api/packages/update"),
    pkgUpgrade: () => request("POST", "/api/packages/upgrade"),
    pkgInstall: (packages) => request("POST", "/api/packages/install", { packages }),
    pkgRemove: (packages) => request("POST", "/api/packages/remove", { packages }),

    // cron
    cronList: () => request("GET", "/api/cron"),
    cronAdd: (schedule, command, label) => request("POST", "/api/cron/add", { schedule, command, label }),
    cronUpdate: (b) => request("POST", "/api/cron/update", b),
    cronPause: (raw, paused) => request("POST", "/api/cron/pause", { raw, paused }),
    cronRun: (raw) => request("POST", "/api/cron/run", { raw }),
    cronDelete: (raw) => request("POST", "/api/cron/delete", { raw }),

    // users
    usersList: (sys) => request("GET", `/api/users?include_system=${sys ? "true" : "false"}`),
    userAdd: (b) => request("POST", "/api/users/add", b),
    userDelete: (name, remove_home) => request("POST", "/api/users/delete", { name, remove_home }),
    userLock: (name, locked) => request("POST", "/api/users/lock", { name, locked }),
    userPassword: (name, password) => request("POST", "/api/users/password", { name, password }),

    // firewall
    firewall: () => request("GET", "/api/firewall"),
    firewallToggle: (enabled) => request("POST", "/api/firewall/toggle", { enabled }),
    firewallRule: (action, port, proto) => request("POST", "/api/firewall/rule", { action, port, proto }),
    firewallDelete: (num) => request("POST", "/api/firewall/delete", { num }),

    // disk usage
    diskUsage: (path) => request("GET", `/api/diskusage?path=${encodeURIComponent(path)}`),

    // backups
    backups: () => request("GET", "/api/backups"),
    backupCreate: (source, label) => request("POST", "/api/backups/create", { source, label }),
    backupRestore: (name, dest) => request("POST", "/api/backups/restore", { name, dest }),
    backupDelete: (name) => request("POST", "/api/backups/delete", { name }),
    backupDatabase: (engine, db, label) => request("POST", "/api/backups/database", { engine, db, label }),
    backupRestoreDb: (body) => request("POST", "/api/backups/restore-db", body),
    backupJobs: () => request("GET", "/api/backups/jobs"),
    // XHR rather than fetch: fetch can't report upload progress.
    backupUpload: (file, onProgress) => new Promise((resolve, reject) => {
      const xhr = new XMLHttpRequest();
      const form = new FormData();
      form.append("file", file);
      xhr.open("POST", "/api/backups/upload");
      xhr.withCredentials = true;
      xhr.upload.onprogress = (e) => onProgress && onProgress(e.loaded, e.lengthComputable ? e.total : file.size);
      xhr.onload = () => {
        let data = null;
        try { data = JSON.parse(xhr.responseText); } catch (e) {}
        if (xhr.status === 401) { const err = new Error("Not authenticated"); err.status = 401; reject(err); return; }
        if (xhr.status >= 200 && xhr.status < 300) resolve(data);
        else reject(new Error((data && data.detail) || xhr.statusText || "Upload failed"));
      };
      xhr.onerror = () => reject(new Error("Upload failed, connection lost"));
      xhr.send(form);
    }),
    backupDownloadUrl: (name) => `/api/backups/download?name=${encodeURIComponent(name)}`,
    backupWizard: () => request("GET", "/api/backups/wizard"),
    backupWizardCreate: (body) => request("POST", "/api/backups/wizard", body),
    backupManifest: (name) => request("GET", `/api/backups/manifest?name=${encodeURIComponent(name)}`),
    backupWizardRestore: (body) => request("POST", "/api/backups/wizard/restore", body),
    // Files tools
    imageInfo: (path) => request("GET", `/api/images/info?path=${encodeURIComponent(path || "")}`),
    imageScale: (body) => request("POST", "/api/images/scale", body),
    imageThumbs: (body) => request("POST", "/api/images/thumbnails", body),
    imageConvert: (body) => request("POST", "/api/images/convert", body),
    webdisk: () => request("GET", "/api/webdisk"),
    webdiskCreate: (body) => request("POST", "/api/webdisk", body),
    webdiskUpdate: (body) => request("POST", "/api/webdisk/update", body),
    webdiskDelete: (name) => request("POST", "/api/webdisk/delete", { name }),
    webdiskCert: (host) => request("GET", `/api/webdisk/certificate?host=${encodeURIComponent(host || "")}`),
    webdiskCertCreate: (host) => request("POST", "/api/webdisk/certificate", { host: host || "" }),
    dirPrivacy: () => request("GET", "/api/dirprivacy"),
    dirPrivacyProtect: (body) => request("POST", "/api/dirprivacy/protect", body),
    dirPrivacyUser: (body) => request("POST", "/api/dirprivacy/user", body),
    dirPrivacyToggle: (path, enabled) => request("POST", "/api/dirprivacy/toggle", { path, enabled }),
    dirPrivacyRemove: (path) => request("POST", "/api/dirprivacy/remove", { path }),
    git: () => request("GET", "/api/git"),
    gitDetails: (name) => request("GET", `/api/git/${encodeURIComponent(name)}`),
    gitKey: (name, owner) => request("POST", "/api/git/key", { name, owner }),
    gitCreate: (body) => request("POST", "/api/git/create", body),
    gitPull: (name) => request("POST", "/api/git/pull", { name }),
    gitCheckout: (name, branch) => request("POST", "/api/git/checkout", { name, branch }),
    gitDeploySettings: (name, deploy_path, deploy_cmd) => request("POST", "/api/git/deploy-settings", { name, deploy_path, deploy_cmd }),
    gitDeploy: (name) => request("POST", "/api/git/deploy", { name }),
    gitRemove: (name, delete_files) => request("POST", "/api/git/remove", { name, delete_files }),
    inodes: (path) => request("GET", `/api/inodes?path=${encodeURIComponent(path || "/")}`),

    // 2fa
    twofaStatus: () => request("GET", "/api/2fa/status"),
    twofaEnroll: () => request("POST", "/api/2fa/enroll"),
    twofaEnable: (code) => request("POST", "/api/2fa/enable", { code }),
    twofaDisable: (code) => request("POST", "/api/2fa/disable", { code }),
    panelHttps: () => request("GET", "/api/panel/https"),
    panelHttpsEnable: (source, regenerate, host) => request("POST", "/api/panel/https/enable", { source, regenerate, host: host || location.hostname }),
    panelHttpsHarden: () => request("POST", "/api/panel/https/harden"),
    panelHttpsRedirect: () => request("POST", "/api/panel/https/redirect"),
    apacheHardening: () => request("GET", "/api/apache/hardening"),
    apacheHarden: () => request("POST", "/api/apache/harden"),
    shadow: () => request("GET", "/api/shadow"),
    shadowFiles: (id, q, only) => request("GET", `/api/shadow/files?id=${encodeURIComponent(id)}&q=${encodeURIComponent(q || "")}&only=${encodeURIComponent(only || "")}`),
    shadowEnable: (id, on) => request("POST", "/api/shadow/enable", { id, on }),
    shadowSettings: (id, s) => request("POST", "/api/shadow/settings", { id, ...s }),
    shadowSnapshot: (id) => request("POST", "/api/shadow/snapshot", { id }),
    shadowRestore: (id, path, ts) => request("POST", "/api/shadow/restore", { id, path, ts }),
    shadowForget: (id, path, ts) => request("POST", "/api/shadow/forget", { id, path: path || "", ts: ts == null ? null : ts }),
    shadowDownloadUrl: (id, path, ts) => `/api/shadow/download?id=${encodeURIComponent(id)}&path=${encodeURIComponent(path)}&ts=${ts}`,
    secreport: () => request("GET", "/api/secreport"),
    secreportFix: (action) => request("POST", "/api/secreport/fix", { action }),
    secreportRun: (targets) => request("POST", "/api/secreport/run", { targets }),
    panelHttpsConfirm: () => request("POST", "/api/panel/https/confirm"),
    panelHttpsDisable: () => request("POST", "/api/panel/https/disable"),

    // ssh access
    sshStatus: () => request("GET", "/api/ssh/status"),
    sshRestart: () => request("POST", "/api/ssh/restart"),
    sshKeys: (target) => request("GET", `/api/ssh/keys?target=${encodeURIComponent(target)}`),
    sshKeyAdd: (u, public_key) => request("POST", "/api/ssh/keys/add", { user: u, public_key }),
    sshKeyRemove: (u, raw) => request("POST", "/api/ssh/keys/remove", { user: u, raw }),

    // ip blocker
    ipblocker: () => request("GET", "/api/ipblocker"),
    ipBlock: (ip) => request("POST", "/api/ipblocker/block", { ip }),
    ipUnblock: (num) => request("POST", "/api/ipblocker/unblock", { num }),

    // ssl
    sslCerts: () => request("GET", "/api/ssl/certs"),
    sslSelfSigned: (common_name, days) => request("POST", "/api/ssl/selfsigned", { common_name, days }),

    // api tokens
    tokens: () => request("GET", "/api/tokens"),
    tokenCreate: (name) => request("POST", "/api/tokens/create", { name }),
    tokenRevoke: (id) => request("POST", "/api/tokens/revoke", { id }),

    // hotlink + redirects
    hotlink: (dir) => request("GET", `/api/apache/hotlink?dir=${encodeURIComponent(dir)}`),
    hotlinkSet: (b) => request("POST", "/api/apache/hotlink", b),
    redirects: (dir) => request("GET", `/api/apache/redirects?dir=${encodeURIComponent(dir)}`),
    redirectAdd: (b) => request("POST", "/api/apache/redirects", b),

    // modsecurity
    modsec: () => request("GET", "/api/modsecurity"),
    modsecToggle: (enabled) => request("POST", "/api/modsecurity/toggle", { enabled }),
    modsecInstall: () => request("POST", "/api/modsecurity/install"),

    // fail2ban (leech)
    fail2ban: () => request("GET", "/api/fail2ban"),
    fail2banUnban: (jail, ip) => request("POST", "/api/fail2ban/unban", { jail, ip }),
    fail2banInstall: () => request("POST", "/api/fail2ban/install"),
    fail2banSave: (global, jails) => request("POST", "/api/fail2ban/save", { global, jails }),
    fail2banService: (on) => request("POST", "/api/fail2ban/service", { on }),
    fail2banBan: (jail, ip) => request("POST", "/api/fail2ban/ban", { jail, ip }),
    fail2banLogs: () => request("GET", "/api/fail2ban/logs"),
    fail2banEvents: () => request("GET", "/api/fail2ban/events"),
    // bans & trusted addresses
    guard: () => request("GET", "/api/guard"),
    guardBan: (target, reason, duration, source) => request("POST", "/api/guard/ban", { target, reason, duration, source }),
    guardUnban: (target) => request("POST", "/api/guard/unban", { target }),
    guardTrust: (target, reason) => request("POST", "/api/guard/trust", { target, reason }),
    guardUntrust: (target) => request("POST", "/api/guard/untrust", { target }),

    // fix perms
    fixPerms: (name) => request("POST", "/api/fixperms", { name }),

    // domains
    vhosts: () => request("GET", "/api/domains/vhosts"),
    dyndns: () => request("GET", "/api/domains/dyndns"),
    dyndnsRun: () => request("POST", "/api/domains/dyndns/run"),
    dyndnsInstall: () => request("POST", "/api/domains/dyndns/install"),

    // System application configuration + FTP accounts
    appConfig: (id) => request("GET", `/api/sysapps/${id}/config`),
    appSettings: (id) => request("GET", `/api/sysapps/${id}/settings`),
    appSettingsSave: (id, changes) => request("POST", `/api/sysapps/${id}/settings`, { changes }),
    appModules: (id) => request("GET", `/api/sysapps/${id}/modules`),
    appModule: (id, name, on) => request("POST", `/api/sysapps/${id}/modules`, { name, on }),
    appFile: (id, path) => request("GET", `/api/sysapps/${id}/file?path=${encodeURIComponent(path)}`),
    appFileSave: (id, path, content) => request("POST", `/api/sysapps/${id}/file`, { path, content }),
    appCfgLogs: (id, source, lines) => request("GET", `/api/sysapps/${id}/logs?lines=${encodeURIComponent(lines || 200)}${source ? "&source=" + encodeURIComponent(source) : ""}`),
    ftpAccounts: () => request("GET", "/api/ftp/accounts"),
    ftpCreate: (body) => request("POST", "/api/ftp/accounts", body),
    ftpPassword: (name, password) => request("POST", "/api/ftp/accounts/password", { name, password }),
    ftpModify: (body) => request("POST", "/api/ftp/accounts/modify", body),
    ftpToggle: (name, enabled) => request("POST", "/api/ftp/accounts/toggle", { name, enabled }),
    ftpDelete: (name) => request("POST", "/api/ftp/accounts/delete", { name }),

    // About & updates
    about: () => request("GET", "/api/about"),
    aboutCheck: () => request("POST", "/api/about/check"),
    aboutChangelog: () => request("POST", "/api/about/changelog"),
    aboutUpdate: () => request("POST", "/api/about/update"),
    aboutUpdateStatus: () => request("GET", "/api/about/update"),

    // PHP settings
    phpOverview: () => request("GET", "/api/php/settings/overview"),
    phpSettings: (version, sapi) => request("GET", `/api/php/settings?version=${encodeURIComponent(version)}&sapi=${encodeURIComponent(sapi)}`),
    phpSettingsSave: (version, sapis, changes, reset) => request("POST", "/api/php/settings", { version, sapis, changes, reset }),
    phpExtensions: (version) => request("GET", `/api/php/extensions?version=${encodeURIComponent(version)}`),
    phpExtToggle: (version, module, sapi, on) => request("POST", "/api/php/extensions/toggle", { version, module, sapi, on }),
    phpExtInstall: (version, module) => request("POST", "/api/php/extensions/install", { version, module }),
    phpApacheVersion: (version) => request("POST", "/api/php/apache-version", { version }),

    // Network: VPN servers, Dynamic DNS, Port Checker, Monitor
    vpnOverview: () => request("GET", "/api/vpn/overview"),
    vpnSettings: (body) => request("POST", "/api/vpn/settings", body),
    vpn: (kind) => request("GET", `/api/vpn/${kind}`),
    vpnInstall: (kind) => request("POST", `/api/vpn/${kind}/install`),
    vpnSetup: (kind, body) => request("POST", `/api/vpn/${kind}/setup`, body),
    vpnControl: (kind, action) => request("POST", `/api/vpn/${kind}/control`, { action }),
    vpnSelftest: (kind) => request("POST", `/api/vpn/${kind}/selftest`),
    vpnClientAdd: (kind, body) => request("POST", `/api/vpn/${kind}/clients`, body),
    vpnClientRemove: (kind, name) => request("POST", `/api/vpn/${kind}/clients/remove`, { name }),
    vpnClientConfig: (kind, name) => request("GET", `/api/vpn/${kind}/clients/${encodeURIComponent(name)}/config`),
    wgToggle: (name, disabled) => request("POST", "/api/vpn/wireguard/clients/toggle", { name, disabled }),
    ovpnUserAdd: (name, mode, password) => request("POST", "/api/vpn/openvpn/clients", { name, mode, password }),
    ovpnUserPassword: (name, password) => request("POST", "/api/vpn/openvpn/users/password", { name, password }),
    ovpnUserMode: (name, mode, password) => request("POST", "/api/vpn/openvpn/users/mode", { name, mode, password }),
    ovpnUserToggle: (name, disabled) => request("POST", "/api/vpn/openvpn/users/toggle", { name, disabled }),
    ddns: () => request("GET", "/api/ddns"),
    ddnsSave: (provider, fields, enabled) => request("POST", "/api/ddns", { provider, fields, enabled }),
    ddnsUpdate: () => request("POST", "/api/ddns/update"),
    ddnsDisable: () => request("POST", "/api/ddns/disable"),
    ddnsStopDdclient: () => request("POST", "/api/ddns/stop-ddclient"),
    portCheck: (port, proto) => request("POST", "/api/portcheck", { port, proto }),
    upnpOpen: (port, proto) => request("POST", "/api/portcheck/upnp/open", { port, proto }),
    upnpClose: (port, proto) => request("POST", "/api/portcheck/upnp/close", { port, proto }),
    upnpInstall: () => request("POST", "/api/portcheck/upnp/install"),
    netmon: (hours, scope) => request("GET", `/api/netmon?hours=${encodeURIComponent(hours)}&scope=${encodeURIComponent(scope)}`),
    netmonLogging: (on) => request("POST", "/api/netmon/logging", { on }),
    zones: () => request("GET", "/api/domains/zones"),
    zone: (name) => request("GET", `/api/domains/zone?name=${encodeURIComponent(name)}`),
    bindInstall: () => request("POST", "/api/domains/bind/install"),

    // domains (extended)
    vhostCreate: (b) => request("POST", "/api/domains/vhosts/create", b),
    vhostRemove: (server_name) => request("POST", "/api/domains/vhosts/remove", { server_name }),
    netOverview: () => request("GET", "/api/net/overview"),
    netIPv4: (b) => request("POST", "/api/net/ipv4", b),
    netWifi: (rescan) => request("GET", `/api/net/wifi?rescan=${rescan ? "true" : "false"}`),
    netWifiConnect: (b) => request("POST", "/api/net/wifi/connect", b),
    netWifiForget: (name) => request("POST", "/api/net/wifi/forget", { name }),
    netWifiRadio: (on) => request("POST", "/api/net/wifi/radio", { on }),
    netHotspot: () => request("GET", "/api/net/hotspot"),
    netHotspotStart: (b) => request("POST", "/api/net/hotspot/start", b),
    netHotspotStop: () => request("POST", "/api/net/hotspot/stop"),
    netHostname: (name) => request("POST", "/api/net/hostname", { name }),
    netNeighbours: () => request("GET", "/api/net/neighbours"),
    netPorts: () => request("GET", "/api/net/ports"),
    netPending: () => request("GET", "/api/net/pending"),
    netConfirm: (id) => request("POST", "/api/net/confirm", { id }),
    netRevert: (id) => request("POST", "/api/net/revert", { id }),
    appsStatus: () => request("GET", "/api/apps2/status"),
    wpInstall: (options) => request("POST", "/api/apps2/wordpress", { options }),
    appRemove2: (path, drop_db, remove_site) => request("POST", "/api/apps2/remove", { path, drop_db, remove_site }),
    appPassword: () => request("GET", "/api/apps2/password"),
    appCatalog: () => request("GET", "/api/apps2/catalog"),
    appLatest: (id) => request("GET", `/api/apps2/latest?app_id=${encodeURIComponent(id)}`),
    appPreview: (app, options) => request("POST", "/api/apps2/preview", { app, options }),
    appInstall: (app, options) => request("POST", "/api/apps2/install", { app, options }),
    sites: () => request("GET", "/api/sites"),
    siteGet: (name) => request("GET", `/api/sites/get?name=${encodeURIComponent(name)}`),
    siteCreate: (settings) => request("POST", "/api/sites/create", { settings }),
    siteSave: (original, settings) => request("POST", "/api/sites/save", { original, settings }),
    siteToggle: (server_name, key, value) => request("POST", "/api/sites/toggle", { server_name, key, value }),
    folderSiteIndexes: (name, on) => request("POST", "/api/sites/folders/indexes", { name, on }),
    siteConfSave: (name, text) => request("POST", "/api/sites/conf", { name, text }),
    siteSystemCustom:(conf, custom) => request("POST", "/api/sites/system-custom", { conf, custom: custom || "" }),
    siteSystemAdopt:(conf) => request("POST", "/api/sites/system-adopt", { conf }),
    siteSystemSsl:(conf, ssl, cert, key, chain) => request("POST", "/api/sites/system-ssl", { conf, ssl, cert: cert || "", key: key || "", chain: chain || "" }),
    siteRemove: (server_name) => request("POST", "/api/sites/remove", { server_name }),
    folderSites: () => request("GET", "/api/sites/folders"),
    folderSiteCreate: (name, path) => request("POST", "/api/sites/folders/create", { name, path }),
    folderSiteRemove: (name, delete_files, backup) => request("POST", "/api/sites/folders/remove", { name, delete_files: !!delete_files, backup: !!backup }),
    certbotInstall: () => request("POST", "/api/sites/certbot/install"),
    siteLE: (server_name, email, include_aliases, force) => request("POST", "/api/sites/letsencrypt", { server_name, email, include_aliases, force: !!force }),
    siteRegenCert: (name) => request("POST", "/api/sites/selfsigned/regenerate", { name }),
    dnsZones: () => request("GET", "/api/dns/zones"),
    dnsZone: (domain) => request("GET", `/api/dns/zone?domain=${encodeURIComponent(domain)}`),
    dnsZoneCreate: (domain, ip, mode) => request("POST", "/api/dns/zone/create", { domain, ip, mode }),
    dnsZoneDelete: (domain) => request("POST", "/api/dns/zone/delete", { domain }),
    dnsRecordAdd: (domain, record) => request("POST", "/api/dns/record/add", { domain, record }),
    dnsRecordUpdate: (domain, index, record, fingerprint) => request("POST", "/api/dns/record/update", { domain, index, record, fingerprint }),
    dnsRecordDelete: (domain, index, fingerprint) => request("POST", "/api/dns/record/delete", { domain, index, fingerprint }),
    domainInfo: (name) => request("GET", `/api/domains/info?name=${encodeURIComponent(name)}`),

    // software: app manager
    apps: () => request("GET", "/api/apps"),
    appCreate: (b) => request("POST", "/api/apps/create", b),
    appControl: (name, action) => request("POST", "/api/apps/control", { name, action }),
    appRemove: (name) => request("POST", "/api/apps/remove", { name }),
    appLogs: (name) => request("GET", `/api/apps/logs?name=${encodeURIComponent(name)}`),
    // software: php
    php: () => request("GET", "/api/php"),
    phpSet: (version) => request("POST", "/api/php/set", { version }),
    // software: system applications
    sysapps: () => request("GET", "/api/sysapps"),
    sysappInstall: (id, sw) => request("POST", "/api/sysapps/install", { id, switch: !!sw }),
    requires: (ids) => request("GET", `/api/requires?ids=${encodeURIComponent(ids.join(","))}`),
    requireInstall: (id) => request("POST", "/api/requires/install", { id }),
    dnsSecondaries: () => request("GET", "/api/dns/secondaries"),
    dnsSecondariesSet: (auto, extra) => request("POST", "/api/dns/secondaries", { auto, extra }),
    // Email
    mailStatus: () => request("GET", "/api/mail/status"),
    mailDomains: () => request("GET", "/api/mail/domains"),
    mailDomainAdd: (domain) => request("POST", "/api/mail/domains/add", { domain }),
    mailDomainRemove: (domain) => request("POST", "/api/mail/domains/remove", { domain }),
    mailRouting: (domain, routing) => request("POST", "/api/mail/domains/routing", { domain, routing }),
    mailRoutingGet: (domain) => request("GET", `/api/mail/domains/routing?domain=${encodeURIComponent(domain)}`),
    mailCatchall: (b) => request("POST", "/api/mail/domains/catchall", b),
    mailAccounts: () => request("GET", "/api/mail/accounts"),
    mailAccountCreate: (b) => request("POST", "/api/mail/accounts/create", b),
    mailAccountUpdate: (b) => request("POST", "/api/mail/accounts/update", b),
    mailAccountDelete: (address, delete_mail) => request("POST", "/api/mail/accounts/delete", { address, delete_mail: !!delete_mail }),
    mailDevice: (address) => request("GET", `/api/mail/accounts/device?address=${encodeURIComponent(address)}`),
    mailPassword: () => request("GET", "/api/mail/password"),
    mailForwarders: () => request("GET", "/api/mail/forwarders"),
    mailForwarderAdd: (b) => request("POST", "/api/mail/forwarders/add", b),
    mailForwarderDelete: (source, dest) => request("POST", "/api/mail/forwarders/delete", { source, dest: dest || "" }),
    mailDomainForwarder: (source, dest, kind) => request("POST", "/api/mail/forwarders/domain", { source, dest, kind: kind || "add" }),
    mailTrace: (address) => request("GET", `/api/mail/trace?address=${encodeURIComponent(address)}`),
    mailAutoresponders: () => request("GET", "/api/mail/autoresponders"),
    mailAutoresponderSave: (owner, data) => request("POST", "/api/mail/autoresponders/save", { owner, data }),
    mailAutoresponderDelete: (owner) => request("POST", "/api/mail/autoresponders/delete", { owner }),
    mailFilters: (owner) => request("GET", `/api/mail/filters?owner=${encodeURIComponent(owner)}`),
    mailFiltersSave: (owner, filters) => request("POST", "/api/mail/filters", { owner, filters }),
    mailSpam: (owner) => request("GET", `/api/mail/spam?owner=${encodeURIComponent(owner)}`),
    mailSpamSave: (owner, data) => request("POST", "/api/mail/spam", { owner, data }),
    mailLists: () => request("GET", "/api/mail/lists"),
    mailListSave: (address, data, create) => request("POST", "/api/mail/lists/save", { address, data, create: !!create }),
    mailListDelete: (address) => request("POST", "/api/mail/lists/delete", { address }),
    mailTrack: (q, status, hours) => request("GET", `/api/mail/track?q=${encodeURIComponent(q || "")}&status=${encodeURIComponent(status || "")}&hours=${hours || 168}`),
    mailQueueGet: () => request("GET", "/api/mail/queue"),
    mailQueue: (action, ids) => request("POST", "/api/mail/queue", { action, ids: ids || [] }),
    mailDeliverability: (domain) => request("GET", `/api/mail/deliverability?domain=${encodeURIComponent(domain || "")}`),
    mailDeliverabilityInstall: (domain, kind) => request("POST", "/api/mail/deliverability/install", { domain, mode: kind }),
    mailDisk: (address) => request("GET", `/api/mail/disk?address=${encodeURIComponent(address || "")}`),
    mailExpunge: (b) => request("POST", "/api/mail/disk/expunge", b),
    mailImport: (b) => request("POST", "/api/mail/import", b),
    mailTLS: () => request("GET", "/api/mail/tls"),
    mailTLSSet: (value) => request("POST", "/api/mail/tls", { value }),
    mailTLSIssue: () => request("POST", "/api/mail/tls/issue"),
    mailHostname: (value) => request("POST", "/api/mail/hostname", { value }),
    mailTrackSettings: (b) => request("POST", "/api/mail/track/settings", b),
    abusePreview: (ip) => request("GET", `/api/abuse/preview?ip=${encodeURIComponent(ip)}`),
    abuseReported: () => request("GET", "/api/abuse/reported"),
    abuseReport: (b) => request("POST", "/api/abuse/report", b),
    mailLocal: (enabled) => request("POST", "/api/mail/local", { enabled }),
    mailTest: (to, sender) => request("POST", "/api/mail/test", { to, sender: sender || "" }),
    mailDav: () => request("GET", "/api/mail/dav"),
    mailDavCreate: (b) => request("POST", "/api/mail/dav/create", b),
    mailDavUpdate: (b) => request("POST", "/api/mail/dav/update", b),
    mailDavDelete: (b) => request("POST", "/api/mail/dav/delete", b),
    mailDavShare: (b) => request("POST", "/api/mail/dav/share", b),
    mailDavUnshare: (b) => request("POST", "/api/mail/dav/unshare", b),
    sysappUninstall: (id) => request("POST", "/api/sysapps/uninstall", { id }),
    sysappControl: (id, action, sw) => request("POST", "/api/sysapps/control", { id, action, switch: !!sw }),
    // preferences
    prefs: () => request("GET", "/api/account/prefs"),
    prefsSet: (b) => request("POST", "/api/account/prefs", b),
    passwordChange: (current, new_password) => request("POST", "/api/account/password", { current, new_password }),
    renameUser: (username) => request("POST", "/api/account/rename", { username }),

    // databases
    dbOverview: () => request("GET", "/api/db/overview"),
    mysql: () => request("GET", "/api/db/mysql"),
    mysqlCreate: (name) => request("POST", "/api/db/mysql/create", { name }),
    mysqlDrop: (name) => request("POST", "/api/db/mysql/drop", { name }),
    mysqlWizard: (b) => request("POST", "/api/db/mysql/wizard", b),
    mysqlUserCreate: (b) => request("POST", "/api/db/mysql/user/create", b),
    mysqlUserPassword: (user, host, password) => request("POST", "/api/db/mysql/user/password", { user, host, password }),
    mysqlUserAdmin: (user, host, admin) => request("POST", "/api/db/mysql/user/admin", { user, host, admin }),
    mysqlUserDrop: (user, host) => request("POST", "/api/db/mysql/user/drop", { user, host }),
    mysqlGrant: (db, user, host, on) => request("POST", "/api/db/mysql/grant", { db, user, host, on }),
    phpmyadminInstall: () => request("POST", "/api/db/phpmyadmin/install"),
    pg: () => request("GET", "/api/db/pg"),
    pgCreate: (name, owner) => request("POST", "/api/db/pg/create", { name, owner: owner || "" }),
    pgRoleCreate: (b) => request("POST", "/api/db/pg/role/create", b),
    pgRoleUpdate: (b) => request("POST", "/api/db/pg/role/update", b),
    pgRolePassword: (name, password) => request("POST", "/api/db/pg/role/password", { name, password }),
    pgRoleDrop: (name) => request("POST", "/api/db/pg/role/drop", { name }),
    pgGrant: (db, role, grant) => request("POST", "/api/db/pg/grant", { db, role, grant: !!grant }),
    pgOwner: (db, role) => request("POST", "/api/db/pg/owner", { db, role }),
    phppgadminLan: (on) => request("POST", "/api/db/phppgadmin/lan", { on: !!on }),
    phppgadminInstall: () => request("POST", "/api/db/phppgadmin/install"),
    pgDrop: (name) => request("POST", "/api/db/pg/drop", { name }),
    pgRepair: () => request("POST", "/api/db/pg/repair"),
    pgWizard: (b) => request("POST", "/api/db/pg/wizard", b),
    dbInstall: (pkg) => request("POST", "/api/db/install", { pkg }),

    // login with optional OTP
    loginOtp: (username, password, otp) => request("POST", "/api/login", { username, password, otp }),

    // apache .htaccess (Advanced)
    apacheRaw: (dir) => request("GET", `/api/apache/htaccess?dir=${encodeURIComponent(dir)}`),
    apacheIndexes: (dir) => request("GET", `/api/apache/indexes?dir=${encodeURIComponent(dir)}`),
    apacheSetIndexes: (b) => request("POST", "/api/apache/indexes", b),
    apacheMime: (dir) => request("GET", `/api/apache/mime?dir=${encodeURIComponent(dir)}`),
    apacheAddMime: (b) => request("POST", "/api/apache/mime", b),
    apacheErrors: (dir) => request("GET", `/api/apache/errors?dir=${encodeURIComponent(dir)}`),
    apacheSetError: (b) => request("POST", "/api/apache/errors", b),
    apacheHandlers: (dir) => request("GET", `/api/apache/handlers?dir=${encodeURIComponent(dir)}`),
    apacheAddHandler: (b) => request("POST", "/api/apache/handlers", b),
    apacheOptions: (dir) => request("GET", `/api/apache/options?dir=${encodeURIComponent(dir)}`),
    apacheSetOption: (dir, name, on) => request("POST", "/api/apache/options", { dir, name, on }),
    apacheRemove: (dir, raw) => request("POST", "/api/apache/remove", { dir, raw }),

    // track dns (Advanced)
    dnsRecords: (host, types, server) => request("GET", `/api/dns/records?host=${encodeURIComponent(host)}&types=${encodeURIComponent((types || []).join(","))}&server=${encodeURIComponent(server || "")}`),
    dnsPropagation: (host, type) => request("GET", `/api/dns/propagation?host=${encodeURIComponent(host)}&type=${encodeURIComponent(type || "A")}`),
    dnsMailCheck: (domain) => request("GET", `/api/dns/mailcheck?domain=${encodeURIComponent(domain)}`),
    dnsNsCheck: (domain) => request("GET", `/api/dns/nscheck?domain=${encodeURIComponent(domain)}`),
    dnsWhois: (host) => request("GET", `/api/dns/whois?host=${encodeURIComponent(host)}`),
    dnsReverse: (ip) => request("GET", `/api/dns/reverse?ip=${encodeURIComponent(ip)}`),
    dnsTrace: (host) => request("GET", `/api/dns/traceroute?host=${encodeURIComponent(host)}`),
    ping: (host) => request("GET", `/api/net/ping?host=${encodeURIComponent(host)}&count=4`),

    // virus scanner (Advanced)
    avStatus: () => request("GET", "/api/antivirus/status"),
    avScan: (path, recursive) => request("POST", "/api/antivirus/scan", { path, recursive }),
    avUpdate: () => request("POST", "/api/antivirus/update"),
    // WAF firewall
    waf: () => request("GET", "/api/waf"),
    wafSave: (data) => request("POST", "/api/waf", data),
    wafEvents: (hours, ip) => request("GET", `/api/waf/events?hours=${hours || 24}${ip ? "&ip=" + encodeURIComponent(ip) : ""}`),
    wafAllow: (id, msg) => request("POST", "/api/waf/allow-rule", { id, msg }),
    wafRestore: (id) => request("POST", "/api/waf/restore-rule", { id }),
    wafTest: () => request("POST", "/api/waf/test"),
    // Dynamic DNS hosts (Domains)
    ddnsHosts: () => request("GET", "/api/ddns-hosts"),
    ddnsHostCreate: (data) => request("POST", "/api/ddns-hosts", data),
    ddnsHostEdit: (id, data) => request("POST", `/api/ddns-hosts/${encodeURIComponent(id)}`, data),
    ddnsHostKey: (id) => request("GET", `/api/ddns-hosts/${encodeURIComponent(id)}/key`),
    ddnsHostRegen: (id) => request("POST", `/api/ddns-hosts/${encodeURIComponent(id)}/regenerate`),
    ddnsHostDelete: (id) => request("DELETE", `/api/ddns-hosts/${encodeURIComponent(id)}`),
    // Metrics
    metSites: () => request("GET", "/api/metrics/sites"),
    metVisitors: (site, limit, hours, name) => request("GET", `/api/metrics/visitors?site=${encodeURIComponent(site)}&limit=${limit || 1000}&hours=${hours || 0}${name ? "&name=" + encodeURIComponent(name) : ""}`),
    metErrors: (site, hours, sources, start, end) => request("GET", `/api/metrics/errors?site=${encodeURIComponent(site || "")}&hours=${hours || 24}${sources ? "&sources=" + encodeURIComponent(sources) : ""}${start ? `&start=${start}&end=${end}` : ""}`),
    metBandwidth: () => request("GET", "/api/metrics/bandwidth"),
    metResources: (span) => request("GET", `/api/metrics/resources?span=${encodeURIComponent(span || "day")}`),
    metAnalytics: (site, days, file, name) => request("GET", `/api/metrics/analytics?site=${encodeURIComponent(site)}&days=${days || 30}${file ? "&file=" + encodeURIComponent(file) : ""}${name ? "&name=" + encodeURIComponent(name) : ""}`),
    metRaw: () => request("GET", "/api/metrics/raw"),
    audit: (days, q, user, failed) => request("GET", `/api/audit?days=${days || 7}&q=${encodeURIComponent(q || "")}&user=${encodeURIComponent(user || "")}&failed=${failed ? "true" : "false"}`),
    alerts: () => request("GET", "/api/alerts"),
    alertsSave: (data) => request("POST", "/api/alerts", data),
    alertsTest: () => request("POST", "/api/alerts/test"),
    slack: () => request("GET", "/api/slack"),
    slackSave: (body) => request("POST", "/api/slack", body),
    slackTest: () => request("POST", "/api/slack/test"),
    alertsCheck: () => request("POST", "/api/alerts/check"),
    schedules: () => request("GET", "/api/schedules"),
    schedPlanSave: (data) => request("POST", "/api/schedules/plans", data),
    schedPlanDelete: (id) => request("DELETE", `/api/schedules/plans/${encodeURIComponent(id)}`),
    schedRun: (id) => request("POST", `/api/schedules/plans/${encodeURIComponent(id)}/run`),
    schedLog: (id, name) => request("GET", `/api/schedules/plans/${encodeURIComponent(id)}/log?name=${encodeURIComponent(name || "")}`),
    schedSnaps: (id) => request("GET", `/api/schedules/plans/${encodeURIComponent(id)}/snapshots`),
    schedFetch: (id, dest, name) => request("POST", `/api/schedules/plans/${encodeURIComponent(id)}/fetch`, { dest, name }),
    schedPass: (id) => request("GET", `/api/schedules/plans/${encodeURIComponent(id)}/passphrase`),
    schedDestSave: (data) => request("POST", "/api/schedules/destinations", data),
    schedDestDelete: (id) => request("DELETE", `/api/schedules/destinations/${encodeURIComponent(id)}`),
    schedDestTest: (id) => request("POST", `/api/schedules/destinations/${encodeURIComponent(id)}/test`),
    updates: () => request("GET", "/api/updates"),
    updatesRefresh: () => request("POST", "/api/updates/refresh"),
    updatesInstall: (packages) => request("POST", "/api/updates/install", { packages }),
    updatesAuto: (enabled, mode, reboot, reboot_time) => request("POST", "/api/updates/auto", { enabled, mode, reboot, reboot_time }),
    reboot: (minutes, cancel) => request("POST", "/api/updates/reboot", { minutes: minutes || 1, cancel: !!cancel }),
    isolation: () => request("GET", "/api/isolation"),
    docker: () => request("GET", "/api/docker"),
    servers: () => request("GET", "/api/servers"),
    mySites: () => request("GET", "/api/mysites"),
    wpt: () => request("GET", "/api/wptoolkit"),
    wptSite: (path) => request("GET", `/api/wptoolkit/site?path=${encodeURIComponent(path)}`),
    wptAct: (action, data) => request("POST", { update: "/api/wptoolkit/update", scan: "/api/wptoolkit/scan", harden: "/api/wptoolkit/harden",
      autoupdates: "/api/wptoolkit/autoupdates", maintenance: "/api/wptoolkit/maintenance", staging: "/api/wptoolkit/staging" }[action], data),
    migrate: () => request("GET", "/api/migrate"),
    migrateAnalyze: (path) => request("GET", `/api/migrate/analyze?path=${encodeURIComponent(path)}`),
    migrateFetch: (url) => request("POST", "/api/migrate/fetch", { url }),
    migrateRun: (data) => request("POST", "/api/migrate/run", data),
    myPassword: (current, next) => request("POST", "/api/me/password", { current, new: next }),
    panelUsers: () => request("GET", "/api/panel-users"),
    panelUserCreate: (data) => request("POST", "/api/panel-users", data),
    panelUserUpdate: (data) => request("POST", "/api/panel-users/update", data),
    panelUserDelete: (username) => request("POST", "/api/panel-users/delete", { username }),
    serverAdd: (data) => request("POST", "/api/servers", data),
    serverRemove: (id) => request("DELETE", `/api/servers/${encodeURIComponent(id)}`),
    serverRepin: (id) => request("POST", `/api/servers/${encodeURIComponent(id)}/repin`),
    serversBan: (data) => request("POST", "/api/servers/ban", data),
    dockerInstall: (data) => request("POST", "/api/docker/install", data),
    dockerCtl: (name, action) => request("POST", `/api/docker/apps/${encodeURIComponent(name)}/${action}`),
    dockerLogs: (name) => request("GET", `/api/docker/apps/${encodeURIComponent(name)}/logs?lines=400`),
    dockerSecret: (name, key) => request("GET", `/api/docker/apps/${encodeURIComponent(name)}/secret?key=${encodeURIComponent(key)}`),
    dockerRemove: (name, data) => request("DELETE", `/api/docker/apps/${encodeURIComponent(name)}?data=${data ? "true" : "false"}`),
    dockerPrune: () => request("POST", "/api/docker/prune"),
    dockerCatalog: () => request("GET", "/api/docker/catalog"),
    dockerMemCgroup: () => request("POST", "/api/docker/memcgroup"),
    dockerOverview: () => request("GET", "/api/docker/overview"),
    dockerContainers: () => request("GET", "/api/docker/containers"),
    dockerInspect: (ref) => request("GET", `/api/docker/containers/${encodeURIComponent(ref)}`),
    dockerAction: (ref, action) => request("POST", `/api/docker/containers/${encodeURIComponent(ref)}/action/${action}`),
    dockerCLogs: (ref, lines) => request("GET", `/api/docker/containers/${encodeURIComponent(ref)}/logs?lines=${lines || 400}`),
    dockerTop: (ref) => request("GET", `/api/docker/containers/${encodeURIComponent(ref)}/top`),
    dockerExec: (ref, data) => request("POST", `/api/docker/containers/${encodeURIComponent(ref)}/exec`, data),
    dockerSettings: (ref, data) => request("PUT", `/api/docker/containers/${encodeURIComponent(ref)}/settings`, data),
    dockerCRemove: (ref, data) => request("DELETE", `/api/docker/containers/${encodeURIComponent(ref)}?data=${data ? "true" : "false"}`),
    dockerCustom: (data) => request("POST", "/api/docker/custom", data),
    dockerImages: () => request("GET", "/api/docker/images"),
    dockerPull: (image) => request("POST", "/api/docker/images/pull", { image }),
    dockerImageRemove: (ref) => request("DELETE", `/api/docker/images/${encodeURIComponent(ref)}`),
    dockerImageInspect: (ref) => request("GET", `/api/docker/images/${encodeURIComponent(ref)}`),
    isolationOn: (site) => request("POST", "/api/isolation/enable", { site: site || "" }),
    isolationOff: (site) => request("POST", "/api/isolation/disable", { site }),
    isolationFix: (site) => request("POST", "/api/isolation/fix", { site }),
    autossl: () => request("GET", "/api/autossl"),
    autosslSave: (data) => request("POST", "/api/autossl", data),
    autosslRun: (only) => request("POST", "/api/autossl/run", { only: only || "" }),
    autosslWildcard: (domain) => request("POST", "/api/autossl/wildcard", { domain }),
    metIp: (ip, days) => request("GET", `/api/metrics/ip?ip=${encodeURIComponent(ip)}&days=${days || 7}`),
    metRetention: (days) => request("POST", "/api/metrics/retention", { days }),
  };
})();
