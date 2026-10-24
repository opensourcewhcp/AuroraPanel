/* AuroraPanel — running the server: Activity Log, Alerts, Scheduled Backups, Updates, AutoSSL.
   Loaded before app.js; app.js calls window.AuroraOps(ui) once with its helpers (and extras.js's). */
window.AuroraOps = (ui) => {
  "use strict";
  const { el, icon, btn, pill, field, sw, toast, API, navigate, state, openModal, closeModal, copyText, fmtBytes, ago, downloadText,
    pageHead, empty, call, armed, seg, tile, card, t2s, num, dur, LS, requireCard, jobPanel } = ui;
  const modalWide = () => { const m = document.querySelector("#modal .modal"); if (m) m.classList.add("em-modal"); };
  const timeIn = (ts) => { const s = ts - Date.now() / 1000; return s <= 0 ? "now" : s < 3600 ? `in ${Math.round(s / 60)} min` : s < 86400 ? `in ${Math.round(s / 3600)} h` : `in ${Math.round(s / 86400)} days`; };
  async function waitJob(jobId, onTick) {
    for (;;) {
      let j;
      try { j = await API.job(jobId); } catch (e) { return null; }
      if (onTick) onTick(j);
      if (j.status !== "running") return j;
      await new Promise((r) => setTimeout(r, 1500));
    }
  }
  function progressBox() {
    const bar = el("div", { class: "ax-bar" }, el("span"));
    const stage = el("div", { class: "ax-stage" });
    const box = el("div", { class: "ax-progress op-prog", hidden: "" }, [stage, bar]);
    return { node: box, set(j) { box.hidden = false; const pct = j.status === "done" ? 100 : (j.progress || 2); bar.firstChild.style.width = `${Math.max(2, pct)}%`;
      stage.textContent = j.stage || j.title || ""; box.classList.toggle("ok", j.status === "done"); box.classList.toggle("bad", j.status === "failed"); } };
  }

  // ======================================================================
  //  Security → Activity Log
  // ======================================================================
  async function viewActivity(root) {
    let days = LS.get("act.days", 7), q = "", who = "", failed = false, d;
    const search = el("input", { type: "search", class: "em-search", placeholder: "Search actions, IPs, names…" });
    let qt;
    search.addEventListener("input", () => { clearTimeout(qt); qt = setTimeout(() => { q = search.value.trim(); load(); }, 250); });
    const userSel = el("select", { class: "em-select mx-narrow", onchange: () => { who = userSel.value; load(); } });
    const failSw = sw(false, (v) => { failed = v; load(); });
    const list = el("div", {}, el("div", { class: "loading", text: "Loading…" }));
    root.append(pageHead("Activity Log", "Every change made in this panel — who did it, from which address, and whether it worked — plus logins and what the background tasks did on their own. Passwords and keys are never recorded.",
      [btn("Export CSV", () => {
        if (!d) return;
        const esc = (v) => { let s = String(v ?? ""); if (/^[=+\-@\t\r]/.test(s)) s = "'" + s; return `"${s.replace(/"/g, '""')}"`; };
        downloadText(`activity-${new Date().toISOString().slice(0, 10)}.csv`, ["time,user,ip,action,result,status",
          ...d.entries.map((e) => [new Date(e.ts * 1000).toISOString(), e.user, e.ip, e.action, e.ok ? "ok" : "failed", e.status].map(esc).join(","))].join("\n"), "text/csv");
      }, "btn-ghost")]),
      el("div", { class: "card em-pad0" }, [el("div", { class: "mx-toolbar" }, [search, userSel, el("label", { class: "mx-live" }, [failSw, el("span", { text: "Failures only" })]), el("span", { class: "grow" }),
        seg([[1, "24 h"], [7, "7 days"], [30, "30 days"], [90, "90 days"]], days, (v) => { days = v; LS.set("act.days", v); load(); })]), list]));
    async function load() {
      try { d = await API.audit(days, q, who, failed); } catch (e) { list.innerHTML = ""; list.append(el("p", { class: "empty", text: e.message })); return; }
      if (userSel.options.length !== d.users.length + 1) {
        userSel.innerHTML = "";
        userSel.append(el("option", { value: "", text: "Everyone" }), ...d.users.map((u) => el("option", { value: u, text: u })));
        userSel.value = who;
      }
      list.innerHTML = "";
      if (!d.entries.length) { list.append(empty("listing", "Nothing recorded", q || failed ? "Nothing matches the filter." : "Changes made from now on appear here.")); return; }
      let lastDay = "";
      const rows = [];
      for (const e of d.entries.slice(0, 1500)) {
        const day = new Date(e.ts * 1000).toLocaleDateString([], { weekday: "long", month: "long", day: "numeric" });
        if (day !== lastDay) { rows.push(el("div", { class: "op-day", text: day })); lastDay = day; }
        const sys = e.user === "system";
        rows.push(el("button", { type: "button", class: `op-act ${e.ok ? "" : "bad"}`, onclick: () => detail(e) }, [
          el("span", { class: "op-act-t", text: new Date(e.ts * 1000).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" }) }),
          el("span", { class: `op-who ${sys ? "sys" : ""}`, text: sys ? "⚙ system" : e.user }),
          el("span", { class: "op-act-a mx-ell", title: e.action, text: e.action }),
          el("span", { class: "op-act-ip mx-ell", text: e.ip || "" }),
          pill(e.ok ? "ok" : `failed ${e.status || ""}`, e.ok ? "good" : "bad"),
        ]));
      }
      list.append(el("div", { class: "op-acts" }, rows));
      if (d.total > 1500) list.append(el("p", { class: "muted mx-p", style: "padding:0 16px 14px", text: `Showing 1,500 of ${num(d.total)} — narrow the search or export.` }));
    }
    function detail(e) {
      openModal("Activity", el("div", {}, [
        el("div", { class: "mx-kv" }, [el("span", { text: "When" }), el("span", { text: new Date(e.ts * 1000).toLocaleString() })]),
        el("div", { class: "mx-kv" }, [el("span", { text: "Who" }), el("span", { text: e.user })]),
        el("div", { class: "mx-kv" }, [el("span", { text: "From" }), e.ip ? btn(e.ip, () => { closeModal(); ui.ipCard && ui.ipCard(e.ip); }, "btn-ghost") : el("span", { text: "—" })]),
        el("div", { class: "mx-kv" }, [el("span", { text: "Action" }), el("span", { text: e.action })]),
        el("div", { class: "mx-kv" }, [el("span", { text: "Result" }), pill(e.ok ? `ok (${e.status})` : `failed (${e.status})`, e.ok ? "good" : "bad")]),
        e.path ? el("div", { class: "mx-kv" }, [el("span", { text: "Request" }), el("code", { text: `${e.method} ${e.path}` })]) : null,
        e.detail ? el("pre", { class: "mx-pre", text: JSON.stringify(e.detail, null, 2) }) : null,
      ]), []);
    }
    load();
  }

  // ======================================================================
  //  System → Alerts
  // ======================================================================
  const LVL = { critical: ["Critical", "bad"], warning: ["Warning", "warn"], info: ["Info", "dim"] };
  async function viewAlerts(root) {
    root.append(pageHead("Alerts", "Get told when something needs you: a disk filling up, a service down, a certificate about to expire, an attack wave, a failed backup, waiting security updates, a hot or under-powered Pi. Checked every minute — even when the panel itself is down."));
    const body = el("div", {}, el("div", { class: "loading", text: "Loading…" }));
    root.append(body);
    let d;
    const slackCard = el("div", {});
    async function load() {
      try { d = await API.alerts(); } catch (e) { body.innerHTML = ""; body.append(el("p", { class: "empty", text: e.message })); return; }
      draw();
      loadSlack();
    }
    // Slack app: alerts and attack reports with Ban / Trust / Allow buttons, and /aurora.
    async function loadSlack() {
      let sl;
      try { sl = await API.slack(); } catch (e) { slackCard.innerHTML = ""; return; }
      drawSlack(sl);
    }
    function drawSlack(sl) {
      slackCard.innerHTML = "";
      const on = sw(sl.enabled, () => {});
      const bot = el("input", { type: "password", autocomplete: "off", placeholder: sl.bot_token_set ? "(saved — leave empty to keep)" : "xoxb-…" });
      const app = el("input", { type: "password", autocomplete: "off", placeholder: sl.app_token_set ? "(saved — leave empty to keep)" : "xapp-…" });
      const chan = el("input", { type: "text", value: sl.channel || "", placeholder: "#alerts" });
      const allowed = el("input", { type: "text", value: (sl.allowed || []).join(", "), placeholder: "U0123ABCD, U0456EFGH" });
      const sec = sw(sl.security, () => {}), f2b = sw(sl.fail2ban, () => {});
      const wafMin = el("input", { type: "number", min: 1, max: 1000, value: sl.waf_min, class: "op-num" });
      const loginMin = el("input", { type: "number", min: 1, max: 1000, value: sl.login_min, class: "op-num" });
      const sk = sl.socket || {};
      const status = !sl.enabled ? pill("off", "dim")
        : sk.connected ? pill(`connected${sl.team ? " · " + sl.team : ""}`, "good")
        : pill(sk.error ? "not connected" : "connecting…", sk.error ? "bad" : "warn");
      const step = (n, title, kids) => el("div", { class: "sl-step" }, [el("span", { class: "sl-step-n", text: n }), el("div", { class: "grow" }, [el("b", { text: title }), ...kids])]);
      const save = () => call(() => API.slackSave({ enabled: on.querySelector("input").checked, bot_token: bot.value.trim(), app_token: app.value.trim(),
        channel: chan.value.trim(), allowed: allowed.value, security: sec.querySelector("input").checked, fail2ban: f2b.querySelector("input").checked,
        waf_min: +wafMin.value, login_min: +loginMin.value }), "Slack saved", (r) => { drawSlack(r); setTimeout(loadSlack, 3000); });
      slackCard.append(card("Slack — alerts you can answer", [
        el("div", { class: "op-ch-h" }, [el("span", { class: "em-rcard-ico" }, icon("send", 18)), el("div", { class: "grow" }, [
          el("b", { text: "Every alert, plus a message for each attacker with Ban, Trust and Allow-rule buttons" }),
          el("p", { class: "muted", text: "Every button flips (Ban ⇄ Unban, Trust ⇄ Untrust), so a click can always be undone, and the message records who did what. /aurora status · alerts · ban · unban · trust · ip in any channel. Works behind a home router: no public address or open port needed." })]),
          status, on]),
        sk.error && sl.enabled ? el("p", { class: "form-error", text: sk.error }) : null,
        el("div", { class: "sl-steps" }, [
          step("1", "Create the Slack app (2 minutes)", [el("p", { class: "muted", text: "Open Slack's app page → Create New App → From a manifest → pick your workspace → paste → Create, then Install to Workspace." }),
            el("div", { class: "toolbar" }, [btn("Copy the app manifest", async () => toast(await copyText(sl.manifest) ? "Manifest copied — paste it in Slack" : "Copy failed", "good"), "btn-primary"),
              el("a", { class: "btn btn-ghost", href: "https://api.slack.com/apps?new_app=1", target: "_blank", rel: "noopener noreferrer", text: "Open api.slack.com/apps ↗" })])]),
          step("2", "Paste the two tokens", [el("p", { class: "muted", text: "Bot token: OAuth & Permissions → Bot User OAuth Token (xoxb-…). App token: Basic Information → App-Level Tokens → Generate, with the connections:write scope (xapp-…)." }),
            el("div", { class: "op-ch-f" }, [field("Bot token", bot), field("App-level token", app)])]),
          step("3", "Where to post, and who may press the buttons", [
            el("div", { class: "op-ch-f" }, [field("Channel", chan), field("Allowed Slack members (member IDs)", allowed)]),
            el("p", { class: "muted mx-small", text: "Private channel? Invite the bot there first (/invite @aurora-…). Leave the members empty: the test message has an “Allow me” button for the first person. Member ID: your Slack profile → ⋮ → Copy member ID." })]),
          step("4", "Attack reports", [el("div", { class: "op-rules" }, [
            el("label", { class: "op-rule" }, [sec, el("div", {}, [el("b", { text: "Report attackers" }), el("p", { class: "muted", text: "One message per new address, at most once a day; private addresses are skipped." })])]),
            el("div", { class: "op-rule" }, [el("b", { text: "WAF blocks in 10 min" }), el("span", { class: "op-numw" }, [wafMin, el("span", { class: "muted", text: "or more" })])]),
            el("div", { class: "op-rule" }, [el("b", { text: "Failed panel logins in 15 min" }), el("span", { class: "op-numw" }, [loginMin, el("span", { class: "muted", text: "or more" })])]),
            el("label", { class: "op-rule" }, [f2b, el("div", {}, [el("b", { text: "fail2ban bans" }), el("p", { class: "muted", text: "With Unban — handy if it was you." })])]),
          ])]),
        ]),
        el("div", { class: "toolbar" }, [btn("Save", save, "btn-primary"), sl.bot_token_set ? btn("Send a test message", () => call(() => API.slackTest(), "Test message sent — press its buttons in Slack"), "btn-ghost") : null]),
      ]));
    }
    function draw() {
      body.innerHTML = "";
      const ch = d.channels, anyOn = Object.values(ch).some((c) => c.enabled);
      const t = d.tasks || {};
      body.append(el("div", { class: `card mx-hero ${!anyOn ? "warn" : d.active.some((a) => a.level === "critical") ? "bad" : "good"}` }, [
        el("div", { class: "mx-hero-ico" }, icon("warning", 28)),
        el("div", { class: "mx-hero-txt" }, [
          el("h3", { text: !anyOn ? "Alerts are off — nothing will reach you" : d.active.length ? `${d.active.length} problem${d.active.length > 1 ? "s" : ""} right now` : "All good — nothing needs you" }),
          el("p", { class: "muted", text: `${t.timer === "active" ? "Checking every minute" : "The background checker isn't running"}${t.last_run ? ` · last check ${ago(t.last_run)}` : ""}.${anyOn ? "" : " Turn on email, Telegram or a webhook below."}` }),
        ]),
        el("div", { class: "mx-hero-act" }, [btn("Check now", async () => { const r = await call(() => API.alertsCheck(), "Checked"); if (r) { d = { ...d, ...r }; draw(); } }, "btn-ghost"),
          anyOn ? btn("Send a test alert", () => call(() => API.alertsTest(), "").then((r) => r && toast(r.sent.length ? `Sent by ${r.sent.join(", ")}${r.errors.length ? ` — failed: ${r.errors.join("; ")}` : ""}` : `Failed: ${r.errors.join("; ")}`, r.sent.length ? "good" : "bad")), "btn-primary") : null]),
      ]));
      if (d.active.length) body.append(card("Happening now", [el("div", { class: "op-alerts" }, d.active.map((a) => el("div", { class: `op-alert ${LVL[a.level]?.[1] || ""}` }, [
        pill(LVL[a.level]?.[0] || a.level, LVL[a.level]?.[1]), el("div", { class: "grow" }, [el("b", { text: a.title }), el("p", { class: "muted", text: a.text })]),
        el("span", { class: "muted mx-small", text: `since ${ago(a.since)}` })])))]));
      // channels
      const em = ch.email, tg = ch.telegram, wh = ch.webhook;
      const emOn = sw(em.enabled, () => {}), tgOn = sw(tg.enabled, () => {}), whOn = sw(wh.enabled, () => {});
      const emTo = el("input", { type: "email", value: em.to || "", placeholder: "you@example.com" });
      const emFrom = el("select", { class: "em-select" }, [el("option", { value: "", text: "AuroraPanel (aurora@this server)" }), ...d.mail_accounts.map((a) => el("option", { value: a, text: a }))]);
      emFrom.value = em.from || "";
      const tgTok = el("input", { type: "password", placeholder: tg.token_set ? "(saved — leave empty to keep)" : "123456789:AAE…", autocomplete: "off" });
      const tgChat = el("input", { type: "text", value: tg.chat_id || "", placeholder: "123456789" });
      const whKind = el("select", { class: "em-select" }, [["generic", "JSON (any service)"], ["discord", "Discord"], ["slack", "Slack"], ["ntfy", "ntfy (phone push)"]].map(([v, l]) => el("option", { value: v, text: l })));
      whKind.value = wh.kind || "generic";
      const whUrl = el("input", { type: "url", placeholder: wh.url_hint ? `${wh.url_hint} (saved — leave empty to keep)` : "https://…" });
      const chBox = (ico, title, sub, onSw, fields, hint) => el("div", { class: "op-ch" }, [el("div", { class: "op-ch-h" }, [el("span", { class: "em-rcard-ico" }, icon(ico, 18)), el("div", { class: "grow" }, [el("b", { text: title }), el("p", { class: "muted", text: sub })]), onSw]),
        el("div", { class: "op-ch-f" }, fields), hint ? el("p", { class: "muted mx-small", text: hint }) : null]);
      const saveCh = btn("Save channels", () => call(() => API.alertsSave({ channels: {
        email: { enabled: emOn.querySelector("input").checked, to: emTo.value.trim(), from: emFrom.value },
        telegram: { enabled: tgOn.querySelector("input").checked, token: tgTok.value.trim(), chat_id: tgChat.value.trim() },
        webhook: { enabled: whOn.querySelector("input").checked, url: whUrl.value.trim(), kind: whKind.value } } }), "Channels saved", (r) => { d = { ...d, ...r }; draw(); }), "btn-primary");
      body.append(card("Where alerts go", [el("div", { class: "op-chs" }, [
        chBox("mail", "Email", d.sendmail ? "Sent by this server's mail system." : "Needs the mail server (Email section) — or use Telegram/webhook.", emOn,
          [field("Send to", emTo), field("Send from", emFrom)]),
        chBox("send", "Telegram", "Instant on your phone. Free.", tgOn, [field("Bot token", tgTok), field("Chat ID", tgChat)],
          "Create a bot with @BotFather and copy its token; send your bot any message, then get your chat ID from @userinfobot."),
        chBox("link", "Webhook", "Discord, Slack, ntfy push, or any URL.", whOn, [field("Type", whKind), field("URL", whUrl)],
          "ntfy: install the ntfy app, subscribe to a hard-to-guess topic and use https://ntfy.sh/<topic>."),
      ]), el("div", { class: "toolbar" }, [saveCh])]));
      body.append(slackCard);
      // rules
      const r = d.rules;
      const n = (k, min, max, suffix) => { const i = el("input", { type: "number", min, max, value: r[k], class: "op-num" }); i.dataset.k = k; return el("span", { class: "op-numw" }, [i, el("span", { class: "muted", text: suffix })]); };
      const t2 = (k, label, hint) => { const s = sw(r[k], () => {}); s.querySelector("input").dataset.k = k; return el("label", { class: "op-rule" }, [s, el("div", {}, [el("b", { text: label }), el("p", { class: "muted", text: hint })])]); };
      const rules = el("div", { class: "op-rules" }, [
        el("div", { class: "op-rule" }, [el("b", { text: "Disk fuller than" }), n("disk_pct", 50, 99, "%")]),
        el("div", { class: "op-rule" }, [el("b", { text: "Memory above" }), n("mem_pct", 50, 100, "%")]),
        el("div", { class: "op-rule" }, [el("b", { text: "CPU hotter than" }), n("temp_c", 50, 100, "°C")]),
        el("div", { class: "op-rule" }, [el("b", { text: "Certificate expires within" }), n("cert_days", 1, 60, "days")]),
        el("div", { class: "op-rule" }, [el("b", { text: "WAF blocks in 10 minutes" }), n("waf_burst", 5, 10000, "or more")]),
        el("div", { class: "op-rule" }, [el("b", { text: "Failed panel logins in 15 min" }), n("login_fails", 3, 1000, "or more")]),
        t2("services", "A service stops", "Web, mail, database, DNS, VPN, fail2ban, Docker…"),
        t2("backups", "A backup fails", "Or hasn't succeeded for twice its schedule."),
        t2("updates", "Security updates are waiting", "Checked every 6 hours."),
        t2("reboot", "A restart is needed", "After kernel or system library updates."),
        t2("power", "Raspberry Pi power problems", "Under-voltage or throttling."),
      ]);
      const minLvl = el("select", { class: "em-select mx-narrow" }, [["info", "Everything"], ["warning", "Warnings and critical"], ["critical", "Critical only"]].map(([v, l]) => el("option", { value: v, text: l })));
      minLvl.value = d.min_level;
      const remind = el("select", { class: "em-select mx-narrow" }, [[0, "Never"], [1, "Every hour"], [6, "Every 6 hours"], [24, "Every day"], [72, "Every 3 days"]].map(([v, l]) => el("option", { value: v, text: l })));
      remind.value = String(d.remind_hours);
      const quiet = sw(d.quiet, () => {});
      body.append(card("When to alert", [rules, el("div", { class: "op-rules2" }, [field("Send", minLvl), field("Remind me while it lasts", remind),
        el("label", { class: "op-rule" }, [quiet, el("div", {}, [el("b", { text: "Pause all alerts" }), el("p", { class: "muted", text: "Problems are still recorded below." })])])]),
        el("div", { class: "toolbar" }, [btn("Save", () => {
          const rr = {};
          rules.querySelectorAll("[data-k]").forEach((i) => { rr[i.dataset.k] = i.type === "checkbox" ? i.checked : +i.value; });
          call(() => API.alertsSave({ rules: rr, min_level: minLvl.value, remind_hours: +remind.value, quiet: quiet.querySelector("input").checked }), "Saved", (x) => { d = { ...d, ...x }; draw(); });
        }, "btn-primary")])]));
      body.append(card("History", [d.history.length ? el("div", { class: "mx-list" }, d.history.slice(0, 60).map((h) => el("div", { class: "mx-list-row" }, [
        pill(h.event === "resolved" ? "resolved" : LVL[h.level]?.[0] || h.level, h.event === "resolved" ? "good" : LVL[h.level]?.[1]),
        el("span", { class: "grow mx-ell", text: h.title }), el("span", { class: "muted", text: t2s(h.ts) })]))) : el("p", { class: "muted", text: "Nothing has happened yet." })]));
    }
    load();
  }

  // ======================================================================
  //  Files → Scheduled Backups
  // ======================================================================
  const DEST_T = { local: ["Folder on this machine", "disk", "A USB drive or second disk, e.g. /mnt/usb/backups"], s3: ["S3 storage", "t_cloud", "Amazon S3, Cloudflare R2, Wasabi, DigitalOcean Spaces, MinIO…"],
    b2: ["Backblaze B2", "t_cloud", "Cheap, reliable cloud storage"], sftp: ["SFTP server", "t_transfer", "Another server or NAS you can SSH into"],
    webdav: ["WebDAV / Nextcloud", "t_cloud", "Nextcloud, ownCloud, Synology, any WebDAV"], rclone: ["Other (rclone)", "link", "Google Drive, OneDrive, Dropbox… paste an rclone remote"] };
  const FREQ = { hourly: "Every hour", daily: "Every day", weekly: "Every week", monthly: "Every month" };
  const WD = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"];
  const WHAT = [["sites", "Websites", "Every site's files"], ["databases", "Databases", "All MariaDB and PostgreSQL databases"], ["mail", "Email", "Mailboxes, DKIM keys, calendars"],
    ["panel", "Server settings", "Panel, Apache, mail, DNS, certificates, VPN, firewall"], ["home", "Home folder", "Your user's home directory"]];
  function schedText(p) {
    return p.freq === "hourly" ? `Every hour at :${p.time.slice(3)}` : p.freq === "weekly" ? `Every ${WD[p.weekday]} at ${p.time}`
      : p.freq === "monthly" ? `On day ${p.monthday} of every month at ${p.time}` : `Every day at ${p.time}`;
  }
  async function viewSchedBackups(root) {
    root.append(pageHead("Scheduled Backups", "Automatic backups that leave this machine — to cloud storage, another server or a USB disk — so a dead SD card, a hacked site or a deleted file is never the end. Encrypted before they leave, old copies cleaned up for you.",
      [btn("Backups (manual)", () => navigate("backups"), "btn-ghost")]));
    const body = el("div", {}, el("div", { class: "loading", text: "Loading…" }));
    root.append(body);
    let d, poll = null;
    state.cleanups.push(() => clearInterval(poll));
    async function load() {
      try { d = await API.schedules(); } catch (e) { body.innerHTML = ""; body.append(el("p", { class: "empty", text: e.message })); return; }
      draw();
      clearInterval(poll);
      if (d.plans.some((p) => p.running)) poll = setInterval(load, 4000);
    }
    function draw() {
      body.innerHTML = "";
      // plans
      if (!d.plans.length) {
        body.append(el("div", { class: "card op-start" }, [el("div", { class: "op-start-ico" }, icon("backup", 34)), el("h3", { text: "No automatic backups yet" }),
          el("p", { class: "muted", text: "Two steps: tell AuroraPanel where to keep the copies, then what to back up and how often. A good start: everything, every night, kept for two weeks, encrypted, in cloud storage." }),
          el("div", { class: "toolbar" }, [btn(d.destinations.length ? "Create a backup plan" : "1. Add where to store backups", () => d.destinations.length ? planEditor() : destEditor(), "btn-primary"),
            d.destinations.length ? null : btn("Keep copies on this machine only", () => planEditor({ keep_local: 3 }), "btn-ghost")])]));
      } else {
        body.append(el("div", { class: "op-plans" }, d.plans.map(planCard)), el("div", { class: "toolbar" }, [btn("New backup plan", () => planEditor(), "btn-primary")]));
      }
      // destinations
      body.append(card("Where backups are stored", [
        d.destinations.length ? el("div", { class: "op-dests" }, d.destinations.map((x) => el("div", { class: "op-dest" }, [
          el("span", { class: "em-rcard-ico" }, icon(DEST_T[x.type][1], 18)),
          el("div", { class: "grow" }, [el("b", { text: x.name }), el("p", { class: "muted mx-ell", text: x.type === "local" ? x.path : [DEST_T[x.type][0], x.provider, x.bucket || x.host || x.url, x.prefix].filter(Boolean).join(" · ") })]),
          btn("Test", async (e) => { e.target.disabled = true; const r = await call(() => API.schedDestTest(x.id)); e.target.disabled = false; if (r) toast(`${x.name}: ${r.message} (${r.ms} ms)`, "good"); }, "btn-ghost"),
          btn("Edit", () => destEditor(x), "btn-ghost"),
          armed("Remove", "Click again", () => call(() => API.schedDestDelete(x.id), "Removed", load), "btn-ghost")]))) : el("p", { class: "muted", text: "Nowhere yet." }),
        el("div", { class: "toolbar" }, [btn("Add a destination", () => destEditor(), d.destinations.length ? "btn-ghost" : "btn-primary")]),
        d.ssh_key ? el("div", { class: "op-key" }, [el("p", { class: "muted mx-small", text: "SFTP destinations log in with this key — add it to ~/.ssh/authorized_keys on the other server:" }),
          el("div", { class: "em-copy" }, [el("code", { class: "em-mono", text: d.ssh_key }), el("button", { type: "button", class: "bk-mini", text: "Copy", onclick: async () => toast(await copyText(d.ssh_key) ? "Key copied" : "Copy failed", "good") })])]) : null,
      ]));
    }
    function planCard(p) {
      const last = p.last || {};
      const dests = p.dests.map((id) => (d.destinations.find((x) => x.id === id) || {}).name).filter(Boolean);
      const what = WHAT.filter(([k]) => p.what[k]).map(([, l]) => l).concat(p.what.paths.length ? [`${p.what.paths.length} folder(s)`] : []);
      const stateP = p.running ? pill("running…", "warn") : !p.enabled ? pill("paused") : !last.ts ? pill("not run yet") : last.ok ? pill("last run ok", "good") : pill("last run failed", "bad");
      const logBox = el("pre", { class: "mx-pre op-log", hidden: "" });
      if (p.running) API.schedLog(p.id).then((l) => { logBox.hidden = false; logBox.textContent = l.text || "Starting…"; logBox.scrollTop = 1e9; }).catch(() => {});
      return el("div", { class: `card op-plan ${last.ok === false ? "bad" : ""}` }, [
        el("div", { class: "op-plan-h" }, [el("span", { class: "op-plan-ico" }, icon("backup", 20)), el("div", { class: "grow" }, [el("h3", { text: p.name }), el("p", { class: "muted", text: `${schedText(p)} · keeps ${p.keep} cop${p.keep === 1 ? "y" : "ies"}${p.encrypt ? " · 🔒 encrypted" : ""}` })]), stateP]),
        el("div", { class: "op-plan-facts" }, [
          el("div", {}, [el("span", { class: "muted", text: "Backs up" }), el("b", { text: what.join(", ") })]),
          el("div", {}, [el("span", { class: "muted", text: "Sends to" }), el("b", { text: [...dests, p.keep_local ? `this machine (${p.keep_local})` : null].filter(Boolean).join(", ") })]),
          el("div", {}, [el("span", { class: "muted", text: "Last run" }), el("b", { text: last.ts ? `${ago(last.ts)}${last.size ? ` · ${fmtBytes(last.size)}` : ""}${last.secs != null ? ` · ${dur(last.secs)}` : ""}` : "—" })]),
          el("div", {}, [el("span", { class: "muted", text: "Next run" }), el("b", { text: p.enabled && p.next ? `${t2s(p.next)} (${timeIn(p.next)})` : "paused" })]),
        ]),
        last.ok === false ? el("div", { class: "mx-note" }, [icon("warning", 16), el("span", { text: last.error || "Failed — see the log." })]) : null,
        logBox,
        el("div", { class: "toolbar" }, [
          btn(p.running ? "Running…" : "Back up now", async (e) => { e.target.disabled = true; if (await call(() => API.schedRun(p.id), "Backup started")) setTimeout(load, 1500); }, "btn-primary"),
          btn("Copies & restore", () => snapshotsModal(p), "btn-ghost"),
          btn("Log", async () => { const l = await call(() => API.schedLog(p.id)); if (l) openModal(`Last run of ${p.name}`, el("pre", { class: "mx-pre", style: "max-height:60vh", text: l.text || "No runs yet." }), []); }, "btn-ghost"),
          btn("Edit", () => planEditor(p), "btn-ghost"),
          p.encrypt ? btn("Show passphrase", async () => { const r = await call(() => API.schedPass(p.id)); if (r) openModal("Encryption passphrase", el("div", {}, [
            el("p", { class: "muted", text: "Without this passphrase the off-site copies can't be opened. Keep it somewhere safe outside this server (a password manager)." }),
            el("div", { class: "em-copy" }, [el("code", { class: "em-mono", text: r.passphrase }), el("button", { type: "button", class: "bk-mini", text: "Copy", onclick: async () => toast(await copyText(r.passphrase) ? "Copied" : "Copy failed", "good") })]),
            el("p", { class: "muted mx-small", text: "To open a copy by hand: openssl enc -d -aes-256-cbc -pbkdf2 -iter 200000 -in FILE.tar.gz.enc -out FILE.tar.gz" })]), []); }, "btn-ghost") : null,
          armed("Delete plan", "Click again", () => call(() => API.schedPlanDelete(p.id), "Plan deleted", load), "btn-ghost"),
        ]),
      ]);
    }
    async function snapshotsModal(p) {
      const box = el("div", {}, el("div", { class: "loading", text: "Listing copies…" }));
      openModal(`Copies of “${p.name}”`, box, []); modalWide();
      let r;
      try { r = await API.schedSnaps(p.id); } catch (e) { box.innerHTML = ""; box.append(el("p", { class: "empty", text: e.message })); return; }
      box.innerHTML = "";
      Object.entries(r.errors).forEach(([id, msg]) => box.append(el("div", { class: "mx-note" }, [icon("warning", 16), el("span", { text: `${(d.destinations.find((x) => x.id === id) || {}).name || id}: ${msg}` })])));
      if (!r.snapshots.length) { box.append(empty("backup", "No copies yet", "Run the plan once (“Back up now”).")); return; }
      box.append(el("p", { class: "muted", text: "Restore brings a copy back to this machine (decrypting it) and opens it in Backups, where you choose exactly which files and databases to put back." }),
        el("div", { class: "table-wrap" }, el("table", { class: "mx-table" }, [el("thead", {}, el("tr", {}, ["Copy", "Where", "Size", "Made", ""].map((h) => el("th", { text: h })))),
          el("tbody", {}, r.snapshots.map((s) => el("tr", {}, [el("td", { class: "mx-ell", text: s.name }), el("td", { text: s.where }), el("td", { class: "num", text: fmtBytes(s.size) }),
            el("td", { text: s.time ? ago(s.time) : "—" }),
            el("td", { class: "mx-actions" }, btn("Restore…", async (e) => { e.target.disabled = true; e.target.textContent = "Fetching…";
              const x = await call(() => API.schedFetch(p.id, s.dest, s.name), "Copy fetched — choose what to restore");
              if (x) { closeModal(); state.backupFocus = x.name; navigate("backupwiz"); } else { e.target.disabled = false; e.target.textContent = "Restore…"; } }, "btn-primary"))])))])));
    }
    function planEditor(p = {}) {
      const isNew = !p.id;
      const w = p.what || { sites: true, databases: true, mail: true, panel: true, home: false, paths: [] };
      const name = el("input", { type: "text", value: p.name || "Full server backup", maxlength: 60 });
      const checks = WHAT.map(([k, l, h]) => { const c = el("input", { type: "checkbox" }); c.checked = !!w[k]; c.dataset.k = k;
        return el("label", { class: "op-what" }, [c, el("div", {}, [el("b", { text: l }), el("span", { class: "muted", text: h })])]); });
      const paths = el("textarea", { rows: 2, placeholder: "Extra folders, one per line (optional)", class: "mx-mono" }); paths.value = (w.paths || []).join("\n");
      let freq = p.freq || "daily";
      const time = el("input", { type: "time", value: p.time || "03:30" });
      const wday = el("select", { class: "em-select" }, WD.map((x, i) => el("option", { value: i, text: x }))); wday.value = String(p.weekday || 0);
      const mday = el("input", { type: "number", min: 1, max: 28, value: p.monthday || 1 });
      const extra = el("div", { class: "op-when-x" });
      const drawWhen = () => { extra.innerHTML = ""; if (freq === "weekly") extra.append(field("Day", wday)); if (freq === "monthly") extra.append(field("Day of month", mday)); };
      const keep = el("input", { type: "number", min: 1, max: 365, value: p.keep || 14 });
      const keepLocal = el("input", { type: "number", min: 0, max: 30, value: p.keep_local ?? 1 });
      const dests = d.destinations.map((x) => { const c = el("input", { type: "checkbox" }); c.checked = isNew ? true : (p.dests || []).includes(x.id); c.value = x.id;
        return el("label", { class: "dm-check" }, [c, el("span", { text: `${x.name} (${DEST_T[x.type][0]})` })]); });
      const enc = el("input", { type: "checkbox" }); enc.checked = isNew ? true : !!p.encrypt;
      const pass = el("input", { type: "text", placeholder: p.encrypt ? "(unchanged — leave empty)" : "Leave empty to generate a strong one", autocomplete: "off" });
      const enabled = el("input", { type: "checkbox" }); enabled.checked = p.enabled !== false;
      drawWhen();
      openModal(isNew ? "New backup plan" : `Edit “${p.name}”`, el("div", { class: "em-form" }, [
        field("Name", name),
        el("div", { class: "mx-sub" }, "What"), el("div", { class: "op-whats" }, checks), paths,
        el("div", { class: "mx-sub" }, "When"),
        el("div", { class: "op-when" }, [seg(Object.entries(FREQ), freq, (v) => { freq = v; drawWhen(); }), field(freq === "hourly" ? "Minute (hh:MM)" : "Time", time), extra]),
        el("div", { class: "mx-sub" }, "Where & how long"),
        dests.length ? el("div", { class: "op-destpick" }, dests) : el("p", { class: "muted", text: "No destinations yet — copies stay on this machine only (add one later for real safety)." }),
        el("div", { class: "mx-grid2" }, [field("Copies to keep at each destination", keep, "Older ones are deleted after each run."), field("Copies also kept on this machine", keepLocal, "0 = none (saves disk space).")]),
        el("label", { class: "dm-check" }, [enc, el("span", { text: "Encrypt with AES-256 before sending (recommended)" })]), field("Passphrase", pass, "Saved on this server so backups run unattended — but keep a copy elsewhere: without it, the off-site copies can't be opened."),
        el("label", { class: "dm-check" }, [enabled, el("span", { text: "Plan is active" })]),
      ]), [el("button", { class: "btn btn-primary", text: isNew ? "Create plan" : "Save", onclick: () => call(() => API.schedPlanSave({
        id: p.id, name: name.value.trim(), freq, time: time.value, weekday: +wday.value, monthday: +mday.value, keep: +keep.value, keep_local: +keepLocal.value,
        dests: dests.map((l) => l.querySelector("input")).filter((c) => c.checked).map((c) => c.value), encrypt: enc.checked, passphrase: pass.value, enabled: enabled.checked,
        what: { ...Object.fromEntries(checks.map((l) => [l.querySelector("input").dataset.k, l.querySelector("input").checked])), paths: paths.value.split("\n").map((x) => x.trim()).filter(Boolean) },
      }), isNew ? "Plan created — it runs on schedule; “Back up now” tests it right away" : "Saved", () => { closeModal(); load(); }) })]);
      modalWide();
    }
    function destEditor(x = null) {
      let type = x ? x.type : "s3";
      const box = el("div", {});
      const pick = el("div", { class: "op-dtypes" });
      const drawPick = () => { pick.innerHTML = ""; Object.entries(DEST_T).forEach(([k, [l, ico, h]]) => pick.append(el("button", { type: "button", class: `op-dtype ${k === type ? "on" : ""}`, disabled: x && k !== type ? "" : null,
        onclick: () => { type = k; drawPick(); drawForm(); } }, [el("span", { class: "em-rcard-ico" }, icon(ico, 18)), el("b", { text: l }), el("span", { class: "muted", text: h })]))); };
      const f = {};
      const inp = (k, ph, typeAttr = "text", val = "") => (f[k] = el("input", { type: typeAttr, placeholder: ph, value: val, autocomplete: "off" }));
      function drawForm() {
        box.innerHTML = "";
        Object.keys(f).forEach((k) => delete f[k]);
        const v = (k) => (x && x[k]) || "";
        box.append(field("Name", inp("name", DEST_T[type][0], "text", x ? x.name : "")));
        if (type !== "local" && !d.rclone) {
          box.append(requireCard ? el("div", { id: "op-rq" }) : el("p", { class: "empty", text: "Install rclone first." }));
          if (requireCard) { const host = box.querySelector("#op-rq"); API.requires(["rclone"]).then((st) => host.append(requireCard([st.components.rclone], "Off-site backups", false, () => load().then(() => destEditor(x))))).catch(() => {}); }
          return;
        }
        if (type === "local") box.append(field("Folder", inp("path", "/mnt/usb/aurora-backups", "text", v("path")), "Best on a different disk than the system (a USB drive). It's created if missing."));
        if (type === "s3") {
          const prov = el("select", { class: "em-select" }, Object.entries(d.s3_providers).map(([k, l]) => el("option", { value: k, text: l }))); prov.value = v("provider") || "Cloudflare"; f.provider = prov;
          box.append(field("Provider", prov), el("div", { class: "mx-grid2" }, [field("Access key ID", inp("access_key", x ? "(saved — leave empty to keep)" : "")), field("Secret access key", inp("secret_key", x ? "(saved)" : "", "password"))]),
            el("div", { class: "mx-grid2" }, [field("Bucket", inp("bucket", "my-backups", "text", v("bucket"))), field("Folder in the bucket (optional)", inp("prefix", "aurora", "text", v("prefix")))]),
            el("div", { class: "mx-grid2" }, [field("Endpoint", inp("endpoint", "R2: https://<account>.r2.cloudflarestorage.com", "text", v("endpoint")), "Leave empty for Amazon S3."), field("Region", inp("region", "auto / us-east-1", "text", v("region")))]));
        }
        if (type === "b2") box.append(el("div", { class: "mx-grid2" }, [field("Application key ID", inp("access_key", x ? "(saved — leave empty to keep)" : "")), field("Application key", inp("secret_key", x ? "(saved)" : "", "password"))]),
          el("div", { class: "mx-grid2" }, [field("Bucket", inp("bucket", "my-backups", "text", v("bucket"))), field("Folder (optional)", inp("prefix", "aurora", "text", v("prefix")))]));
        if (type === "sftp") box.append(el("div", { class: "mx-grid2" }, [field("Host", inp("host", "backup.example.com", "text", v("host"))), field("Port", inp("port", "22", "number", v("port") || "22"))]),
          el("div", { class: "mx-grid2" }, [field("User", inp("user", "backup", "text", v("user"))), field("Folder", inp("path", "backups/aurora", "text", v("prefix")))]),
          field("Password (optional)", inp("password", "Leave empty to use the key shown on the Scheduled Backups page", "password")));
        if (type === "webdav") {
          const vendor = el("select", { class: "em-select" }, [["nextcloud", "Nextcloud"], ["owncloud", "ownCloud"], ["other", "Other WebDAV"]].map(([a, b]) => el("option", { value: a, text: b }))); vendor.value = v("vendor") || "nextcloud"; f.vendor = vendor;
          box.append(field("Server", vendor), field("WebDAV URL", inp("url", "https://cloud.example.com/remote.php/dav/files/USER/", "url", v("url"))),
            el("div", { class: "mx-grid2" }, [field("User", inp("user", "", "text", v("user"))), field("App password", inp("password", x ? "(saved — leave empty to keep)" : "", "password"))]), field("Folder", inp("path", "Backups/aurora", "text", v("prefix"))));
        }
        if (type === "rclone") {
          f.conf = el("textarea", { rows: 6, class: "mx-mono", placeholder: "type = drive\nscope = drive.file\ntoken = {\"access_token\":…}" });
          box.append(el("p", { class: "muted", text: "For Google Drive, OneDrive, Dropbox and others: run “rclone config” on your computer, then paste the lines under your remote's [name] here (from rclone.conf)." }),
            field("rclone remote", f.conf), field("Folder (optional)", inp("path", "aurora-backups", "text", v("prefix"))));
        }
      }
      drawPick(); drawForm();
      openModal(x ? `Edit ${x.name}` : "Where should backups go?", el("div", { class: "em-form" }, [pick, box]), [el("button", { class: "btn btn-primary", text: x ? "Save" : "Add & test", onclick: async (e) => {
        const data = { id: x?.id, type };
        Object.entries(f).forEach(([k, i]) => { data[k] = i.value.trim(); });
        e.target.disabled = true;
        const r = await call(() => API.schedDestSave(data));
        if (!r) { e.target.disabled = false; return; }
        const t = await call(() => API.schedDestTest(r.id));
        e.target.disabled = false;
        if (t) { toast(`${r.name}: ${t.message}`, "good"); closeModal(); load(); }
      } })]);
      modalWide();
    }
    load();
  }

  // ======================================================================
  //  System → Updates
  // ======================================================================
  async function viewUpdates(root) {
    root.append(pageHead("Updates", "Security fixes and new versions for everything installed on this server. Install them with one click, or let the server install security updates by itself every night."));
    const body = el("div", {}, el("div", { class: "loading", text: "Loading…" }));
    const prog = progressBox();
    const log = el("pre", { class: "log op-log", hidden: "" });
    root.append(prog.node, log, body);
    let d, sel = new Set();
    async function load() {
      try { d = await API.updates(); } catch (e) { body.innerHTML = ""; body.append(el("p", { class: "empty", text: e.message })); return; }
      if (d.running) watch(d.running);
      draw();
    }
    async function watch(id) {
      log.hidden = false;
      const j = await waitJob(id, (j) => { prog.set(j); log.textContent = j.output || ""; log.scrollTop = 1e9; });
      if (j) { toast(j.status === "done" ? "Updates installed" : "Updating failed — see the log", j.status === "done" ? "good" : "bad"); load(); }
    }
    function draw() {
      body.innerHTML = "";
      if (!d.supported) { body.append(el("p", { class: "empty", text: "This system has no apt." })); return; }
      const rb = d.reboot;
      body.append(el("div", { class: `card mx-hero ${d.security ? "bad" : d.total ? "warn" : "good"}` }, [
        el("div", { class: "mx-hero-ico" }, icon(d.total ? "packages" : "check", 28)),
        el("div", { class: "mx-hero-txt" }, [el("h3", { text: d.total ? `${d.total} update${d.total > 1 ? "s" : ""} available${d.security ? ` — ${d.security} for security` : ""}` : "Everything is up to date" }),
          el("p", { class: "muted", text: `Checked ${d.checked ? ago(d.checked) : "never"}${d.auto.enabled ? ` · automatic ${d.auto.mode === "all" ? "updates" : "security updates"} on` : " · automatic updates off"}.${d.error ? " Last check had a problem: " + d.error : ""}` })]),
        el("div", { class: "mx-hero-act" }, [btn("Check now", async (e) => { e.target.disabled = true; e.target.textContent = "Checking…"; await call(() => API.updatesRefresh()); load(); }, "btn-ghost"),
          d.total ? btn(`Install all ${d.total}`, () => call(() => API.updatesInstall([]), "Updating…", (r) => watch(r.job)), "btn-primary") : null]),
      ]));
      if (rb.required) body.append(el("div", { class: "card op-reboot" }, [icon("refresh", 20), el("div", { class: "grow" }, [el("b", { text: "Restart needed to finish updating" }),
        el("p", { class: "muted", text: `${rb.packages.length ? rb.packages.slice(0, 6).join(", ") + (rb.packages.length > 6 ? "…" : "") : "System packages"} were updated. Websites and mail are offline for about a minute while it restarts.` })]),
        armed("Restart in 1 minute", "Click again to restart", () => call(() => API.reboot(1), "Restarting in 1 minute — the panel comes back by itself"), "btn-primary"),
        btn("Cancel a planned restart", () => call(() => API.reboot(0, true), "Cancelled"), "btn-ghost")]));
      // automatic updates
      const a = d.auto;
      let mode = a.mode;
      const on = sw(a.enabled, () => {});
      const rbOn = sw(a.reboot, () => {});
      const rbTime = el("input", { type: "time", value: a.reboot_time || "04:00" });
      body.append(card("Automatic updates", [
        el("label", { class: "op-rule" }, [on, el("div", {}, [el("b", { text: "Install updates automatically every night" }), el("p", { class: "muted", text: a.installed ? `Uses Debian's unattended-upgrades.${a.last ? " Last: " + a.last.replace(/^\S+ \S+ INFO /, "") : ""}` : "Installs Debian's unattended-upgrades the first time." })])]),
        el("div", { class: "op-auto" }, [seg([["security", "Security fixes only (safest)"], ["all", "All updates"]], mode, (v) => { mode = v; }),
          el("label", { class: "op-rule" }, [rbOn, el("div", {}, [el("b", { text: "Restart by itself when an update needs it" }), el("p", { class: "muted", text: "Only when needed, at the time below." })])]), field("Restart time", rbTime)]),
        el("div", { class: "toolbar" }, [btn("Save", () => call(() => API.updatesAuto(on.querySelector("input").checked, mode, rbOn.querySelector("input").checked, rbTime.value), "Saved",
          (r) => { if (r && r.job) watch(r.job); else load(); }), "btn-primary")])]));
      // list
      if (d.packages.length) {
        const selBtn = btn("Install selected", () => call(() => API.updatesInstall([...sel]), "Updating…", (r) => watch(r.job)), "btn-ghost");
        const upd = () => { selBtn.disabled = !sel.size; selBtn.textContent = sel.size ? `Install ${sel.size} selected` : "Install selected"; };
        upd();
        body.append(card(`Waiting updates (${d.packages.length})`, [el("div", { class: "table-wrap mx-table-wrap" }, el("table", { class: "mx-table" }, [
          el("thead", {}, el("tr", {}, ["", "Package", "Now", "New", "From"].map((h) => el("th", { text: h })))),
          el("tbody", {}, d.packages.map((p) => { const c = el("input", { type: "checkbox", onchange: () => { c.checked ? sel.add(p.name) : sel.delete(p.name); upd(); } }); c.checked = sel.has(p.name);
            return el("tr", {}, [el("td", {}, c), el("td", {}, [el("b", { text: p.name }), p.security ? el("span", { class: "pill bad", style: "margin-left:8px", text: "security" }) : null]),
              el("td", { class: "muted mx-mono", text: p.from }), el("td", { class: "mx-mono", text: p.to }), el("td", { class: "muted", text: p.origin.split(",")[0] })]); })),
        ]))], "", [selBtn]));
      }
    }
    load();
  }

  // ======================================================================
  //  Security → AutoSSL
  // ======================================================================
  const AS = { ok: ["Covered", "good"], renew: ["Renewing soon", "warn"], missing: ["Will get one", "warn"], elsewhere: ["Points elsewhere", "dim"], nodns: ["No DNS record", "dim"], excluded: ["Excluded", "dim"] };
  async function viewAutoSSL(root) {
    root.append(pageHead("AutoSSL", "A free, trusted HTTPS certificate for every website and the mail server — requested, installed and renewed by itself. Names that don't point to this server are skipped until their DNS does.",
      [btn("SSL/TLS Certificates", () => navigate("ssl"), "btn-ghost")]));
    const body = el("div", {}, el("div", { class: "loading", text: "Checking every name…" }));
    root.append(body);
    let d, poll = null;
    state.cleanups.push(() => clearInterval(poll));
    async function load() {
      try { d = await API.autossl(); } catch (e) { body.innerHTML = ""; body.append(el("p", { class: "empty", text: e.message })); return; }
      draw();
      clearInterval(poll);
      if (d.running) poll = setInterval(load, 5000);
    }
    function draw() {
      body.innerHTML = "";
      const todo = d.plan.reduce((a, i) => a + i.names.filter((r) => r.state === "missing" || r.state === "renew").length, 0);
      const okN = d.plan.reduce((a, i) => a + i.names.filter((r) => r.state === "ok").length, 0);
      if (!d.certbot) { body.append(el("div", { class: "card" }, empty("lock", "Certbot isn't installed", "AutoSSL uses Certbot (Let's Encrypt's official client).", btn("Install it on the SSL/TLS page", () => navigate("ssl"), "btn-primary")))); return; }
      const email = el("input", { type: "email", value: d.email || "", placeholder: "you@example.com" });
      const agree = el("input", { type: "checkbox" }); agree.checked = d.agreed;
      body.append(el("div", { class: `card mx-hero ${d.enabled ? (todo ? "warn" : "good") : "bad"}` }, [
        el("div", { class: "mx-hero-ico" }, icon("lock", 28)),
        el("div", { class: "mx-hero-txt" }, [el("h3", { text: d.enabled ? (todo ? `${todo} name${todo > 1 ? "s" : ""} waiting for a certificate` : `All ${okN} names are covered`) : "AutoSSL is off" }),
          el("p", { class: "muted", text: d.running ? "Requesting certificates right now…" : d.enabled ? `Runs every night${d.last_run ? ` · last run ${ago(d.last_run)}` : ""}.` : "Turn it on to get certificates for every site automatically." })]),
        el("div", { class: "mx-hero-act" }, [d.enabled ? btn(d.running ? "Running…" : "Run now", (e) => { e.target.disabled = true; call(() => API.autosslRun(""), "AutoSSL started", () => setTimeout(load, 2000)); }, "btn-primary") : null,
          d.enabled ? btn("Turn off", () => call(() => API.autosslSave({ enabled: false }), "AutoSSL off", (r) => { d = r; draw(); }), "btn-ghost") : null]),
      ]));
      if (!d.enabled) body.append(card("Turn on AutoSSL", [
        field("Email for expiry notices", email, "Let's Encrypt writes here only if a certificate is about to expire and renewal keeps failing."),
        el("label", { class: "dm-check" }, [agree, el("span", {}, ["I agree to the ", el("a", { href: "https://letsencrypt.org/repository/", target: "_blank", rel: "noopener noreferrer", text: "Let's Encrypt Subscriber Agreement" })])]),
        el("div", { class: "toolbar" }, [btn("Turn on AutoSSL", () => call(() => API.autosslSave({ email: email.value.trim(), agreed: agree.checked, enabled: true }), "AutoSSL on — click Run now to start", (r) => { d = r; draw(); }), "btn-primary")])]));
      // per site
      body.append(card("Your sites", [d.plan.length ? el("div", { class: "op-sites" }, d.plan.map((it) => {
        const res = d.results[it.site];
        return el("div", { class: "op-site" }, [
          el("div", { class: "op-site-h" }, [icon(it.mail ? "mail" : "globe", 16), el("b", { text: it.site }), it.mail ? pill("mail server") : null, el("span", { class: "grow" }),
            d.enabled && it.names.some((r) => r.state === "missing" || r.state === "renew") ? btn("Get it now", () => call(() => API.autosslRun(it.site), "Requesting…", () => setTimeout(load, 2000)), "btn-ghost") : null]),
          it.note ? el("p", { class: "muted mx-small", text: it.note }) : null,
          el("div", { class: "op-names" }, it.names.map((r) => el("div", { class: "op-name" }, [el("code", { text: r.name }), pill(AS[r.state][0] + (r.state === "ok" || r.state === "renew" ? ` · ${r.days} days` : ""), AS[r.state][1]),
            el("span", { class: "muted mx-small mx-ell", text: r.state === "elsewhere" ? `→ ${r.addrs.join(", ")}` : r.state === "nodns" ? "add an A record in the Zone Editor" : r.cert ? `certificate “${r.cert}”` : "" })]))),
          res && res.ok === false ? el("div", { class: "mx-note" }, [icon("warning", 16), el("span", { text: `${t2s(res.ts)}: ${res.error}` })]) : res && res.ok ? el("p", { class: "muted mx-small", text: `✓ ${t2s(res.ts)}${res.note ? " — " + res.note : ""}` }) : null,
        ]);
      })) : el("p", { class: "muted", text: "No websites yet." })]));
      // wildcards
      if (d.zones.length) body.append(card("Wildcard certificates", [el("p", { class: "muted", text: "One certificate for every subdomain (*.example.com) — handy for Dynamic DNS names and Docker apps. Needs this server to answer DNS for the domain: the panel adds the proof record itself." }),
        el("div", { class: "mx-list" }, d.zones.map((z) => { const r = d.results[`*.${z}`]; const have = d.certs.find((c) => c.names.includes(`*.${z}`));
          return el("div", { class: "mx-list-row" }, [el("code", { text: `*.${z}` }), have ? pill(`valid · ${Math.round((have.expires - Date.now() / 1000) / 86400)} days`, "good") : r && r.ok === false ? pill("failed", "bad") : pill("none"),
            el("span", { class: "grow muted mx-small mx-ell", text: r && r.ok === false ? r.error : have ? "Renewed automatically by Certbot" : "" }),
            d.agreed ? btn(have ? "Renew" : "Get wildcard", () => call(() => API.autosslWildcard(z), "Requesting — this takes 1–4 minutes (waiting for DNS)", () => setTimeout(load, 60000)), "btn-ghost") : null]); }))]));
    }
    load();
  }

  // ======================================================================
  //  Security → Site Isolation
  // ======================================================================
  async function viewIsolation(root) {
    root.append(pageHead("Site Isolation", "Give every website its own locked room: its PHP runs as its own user and can only open its own files. A hacked plugin on one site can then no longer read the others' files or database passwords. Uses almost no memory — a site's PHP only runs while it's being visited."));
    const prog = progressBox();
    const log = el("pre", { class: "log op-log", hidden: "" });
    const body = el("div", {}, el("div", { class: "loading", text: "Loading…" }));
    root.append(prog.node, log, body);
    let d;
    async function load() {
      try { d = await API.isolation(); } catch (e) { body.innerHTML = ""; body.append(el("p", { class: "empty", text: e.message })); return; }
      draw();
    }
    async function watch(id, label) {
      log.hidden = false;
      const j = await waitJob(id, (j) => { prog.set(j); log.textContent = j.output || ""; log.scrollTop = 1e9; });
      if (j) toast(j.status === "done" ? label : "Something went wrong — see the log", j.status === "done" ? "good" : "bad");
      load();
    }
    function draw() {
      body.innerHTML = "";
      const on = d.sites.filter((s) => s.on).length;
      body.append(el("div", { class: `card mx-hero ${!d.sites.length ? "" : on === d.sites.length ? "good" : on ? "warn" : "bad"}` }, [
        el("div", { class: "mx-hero-ico" }, icon("shield", 28)),
        el("div", { class: "mx-hero-txt" }, [el("h3", { text: !d.sites.length ? "No websites yet" : on === d.sites.length ? `All ${on} sites are isolated` : `${on} of ${d.sites.length} sites isolated` }),
          el("p", { class: "muted", text: `PHP ${d.php || "?"} · ${d.fpm ? "PHP-FPM ready" : "PHP-FPM is installed the first time you isolate a site"}. The panel's own tools (phpMyAdmin, webmail) keep working as before.` })]),
        el("div", { class: "mx-hero-act" }, [d.sites.length && on < d.sites.length ? btn("Isolate all sites", () => call(() => API.isolationOn(""), "Isolating…", (r) => watch(r.job, "Every site is isolated")), "btn-primary") : null]),
      ]));
      if (!d.sites.length) return;
      body.append(card("Your sites", [el("div", { class: "op-isos" }, d.sites.map((s) => el("div", { class: `op-iso ${s.on ? "on" : ""}` }, [
        el("span", { class: "em-rcard-ico" }, icon(s.on ? "lock" : "globe", 18)),
        el("div", { class: "grow" }, [el("b", { text: s.site }), el("p", { class: "muted mx-small mx-ell", text: s.on ? `PHP runs as ${s.user} · folder ${s.docroot} closed to other sites${s.ram ? ` · ${fmtBytes(s.ram)} in use now` : " · idle"}` : `Shares PHP with every other site (www-data) · ${s.docroot}` })]),
        s.on ? pill(s.socket_ok ? "isolated" : "isolated · pool not running", s.socket_ok ? "good" : "warn") : pill("shared"),
        s.on ? btn("Fix permissions", () => call(() => API.isolationFix(s.site), "Ownership re-applied — PHP can write its files again"), "btn-ghost") : null,
        s.on ? armed("Turn off", "Click again", () => call(() => API.isolationOff(s.site), `${s.site} shares PHP again`, load), "btn-ghost")
          : btn("Isolate", () => call(() => API.isolationOn(s.site), "Isolating…", (r) => watch(r.job, `${s.site} is isolated`)), "btn-primary"),
      ])))]),
      el("p", { class: "muted mx-small mx-p", text: "Uploaded a site as root (File Manager, a restore)? “Fix permissions” gives the files back to the site so it can update itself. Some old plugins that run shell commands (exec, system) won't work while isolated — that's exactly what attackers use." }));
    }
    load();
  }

  // ======================================================================
  //  Applications → Docker Apps
  // ======================================================================
  const APP_HUE = (s) => { let h = 0; for (const c of String(s)) h = (h * 31 + c.charCodeAt(0)) % 360; return h; };
  async function viewDockerApps(root) {
    root.append(pageHead("Docker Apps", "Self-hosted apps in one click — smart home, media server, password manager, ad blocking, monitoring. Each runs in its own container, kept apart from the rest of the server, and is reached at its own web address with HTTPS."));
    const prog = progressBox();
    const log = el("pre", { class: "log op-log", hidden: "" });
    const body = el("div", {}, el("div", { class: "loading", text: "Loading…" }));
    root.append(prog.node, log, body);
    let d, cat = "All";
    async function load() {
      try { d = await API.docker(); } catch (e) { body.innerHTML = ""; body.append(el("p", { class: "empty", text: e.message })); return; }
      draw();
    }
    async function watch(id, label) {
      log.hidden = false; prog.node.scrollIntoView({ block: "nearest" });
      const j = await waitJob(id, (j) => { prog.set(j); log.textContent = j.output || ""; log.scrollTop = 1e9; });
      if (j) toast(j.status === "done" ? label : "Something went wrong — see the log", j.status === "done" ? "good" : "bad");
      load();
    }
    const host = (u) => u.replace("{host}", location.hostname);
    function appCard(a) {
      const up = a.state === "running";
      const url = a.url ? host(a.url) : "";
      return el("div", { class: "op-dapp" }, [
        el("div", { class: "op-dapp-h" }, [el("span", { class: "op-dapp-ico", style: `--h:${APP_HUE(a.app)}`, text: a.title[0] }),
          el("div", { class: "grow" }, [el("b", { text: a.title }), el("p", { class: "muted mx-small", text: `${a.name}${a.cpu ? ` · CPU ${a.cpu}` : ""}${a.mem && !a.mem.startsWith("0B") ? ` · ${a.mem.split("/")[0].trim()}` : ""}` })]),
          pill(up ? "running" : a.state, up ? "good" : a.state === "missing" ? "bad" : "dim")]),
        url ? el("a", { class: "op-dapp-url", href: url, target: "_blank", rel: "noopener", text: url.replace(/\/$/, "") + " ↗" }) : el("p", { class: "muted mx-small", text: "No web page (service only)" }),
        a.note ? el("p", { class: "muted mx-small", text: a.note }) : null,
        el("div", { class: "op-dapp-act" }, [
          up ? btn("Stop", () => call(() => API.dockerCtl(a.name, "stop"), `${a.title} stopped`, load), "btn-ghost") : btn("Start", () => call(() => API.dockerCtl(a.name, "start"), `${a.title} started`, load), "btn-primary"),
          btn("Restart", () => call(() => API.dockerCtl(a.name, "restart"), "Restarted", load), "btn-ghost"),
          btn("Update", () => call(() => API.dockerCtl(a.name, "update"), "Updating…", (r) => watch(r.job, `${a.title} is up to date`)), "btn-ghost"),
          btn("Logs", async () => {
            const r = await call(() => API.dockerLogs(a.name));
            if (!r) return;
            openModal(`${a.title} — logs`, el("pre", { class: "mx-pre", style: "max-height:65vh", text: r.text || "(empty)" }), []); modalWide();
            const pre = document.querySelector("#modal pre"); if (pre) pre.scrollTop = 1e9;
          }, "btn-ghost"),
          a.secrets.length ? btn("Passwords", async () => {
            const rows = [];
            for (const k of a.secrets) {
              const r = await call(() => API.dockerSecret(a.name, k));
              if (r) rows.push(el("div", { class: "em-copy" }, [el("span", { class: "em-copy-k", text: k }), el("code", { class: "em-mono", text: r.value }),
                el("button", { type: "button", class: "bk-mini", text: "Copy", onclick: async () => toast(await copyText(r.value) ? "Copied" : "Copy failed", "good") })]));
            }
            openModal(`${a.title} — generated passwords`, el("div", { class: "em-form" }, rows), []); modalWide();
          }, "btn-ghost") : null,
          btn("Remove…", () => removeApp(a), "btn-ghost"),
        ]),
      ]);
    }
    function draw() {
      body.innerHTML = "";
      if (!d.running) body.append(el("div", { class: "mx-note" }, [icon("warning", 16), el("span", { text: "Docker is installed but not running — System Applications → Docker → Start." })]));
      if (d.apps.length) {
        body.append(card(`Your apps (${d.apps.length})`, [el("div", { class: "op-dapps" }, d.apps.map(appCard))], "",
          [d.disk && d.disk.Images ? el("span", { class: "muted mx-small", text: `Images use ${d.disk.Images.size}` }) : null,
            btn("Clean up", () => call(() => API.dockerPrune(), "").then((r) => r && toast(`Freed ${r.reclaimed}`, "good")), "btn-ghost")]));
      }
      const cats = ["All", ...new Set(d.catalog.map((x) => x.cat))];
      const grid = el("div", { class: "op-cat" });
      const drawGrid = () => {
        grid.innerHTML = "";
        d.catalog.filter((x) => cat === "All" || x.cat === cat).forEach((x) => grid.append(el("div", { class: "op-capp" }, [
          el("div", { class: "op-dapp-h" }, [el("span", { class: "op-dapp-ico", style: `--h:${APP_HUE(x.id)}`, text: x.name[0] }),
            el("div", { class: "grow" }, [el("b", { text: x.name }), el("p", { class: "muted mx-small", text: `${x.cat} · ${x.ram}` })])]),
          el("p", { class: "op-capp-d", text: x.desc }),
          el("div", { class: "op-dapp-act" }, [btn("Install", () => installDlg(x), "btn-primary"),
            x.home ? el("a", { class: "btn btn-sm btn-ghost", href: x.home, target: "_blank", rel: "noopener noreferrer", text: "Website ↗" }) : null]),
        ])));
      };
      body.append(card("App catalog", [el("div", { class: "op-catbar" }, seg(cats.map((c) => [c, c]), cat, (v) => { cat = v; drawGrid(); })), grid],
        "", [el("span", { class: "muted mx-small", text: `${d.arch} · images match this processor` })]));
      drawGrid();
    }
    function removeApp(a) {
      const del = el("input", { type: "checkbox" });
      openModal(`Remove ${a.title}?`, el("div", { class: "em-form" }, [el("p", { text: `The container stops and is removed${a.domain ? `, and the web address ${a.domain} is taken down` : ""}.` }),
        el("label", { class: "dm-check" }, [del, el("span", { text: "Also delete its data (settings, databases, uploads) — can't be undone" })])]),
        [armed("Remove", "Click again to remove", () => call(() => API.dockerRemove(a.name, del.checked), `${a.title} removed`, () => { closeModal(); load(); }), "btn-danger")]);
    }
    function installDlg(x) {
      let access = (x.host_network || x.no_web) ? (d.lan_ip ? "lan" : "public") : "proxy";
      const name = el("input", { type: "text", value: x.id, maxlength: 31 });
      const domain = el("input", { type: "text", placeholder: `${x.id}.example.com` });
      const domWrap = el("div", {}, field("Web address", domain, "A name whose DNS points to this server (e.g. a subdomain in the Zone Editor). AutoSSL then gives it HTTPS."));
      const opts = [];
      if (!x.host_network && !x.no_web) opts.push({ value: "proxy", label: "At a web address (recommended)", icon: "globe", desc: "https://app.yourdomain — HTTPS, protected by the WAF and your ban list. The app itself is never exposed directly." });
      if (d.lan_ip) opts.push({ value: "lan", label: "On my local network only", icon: "wifi", desc: `http://${d.lan_ip}:<port> — reachable from devices at home, not from the internet.` });
      opts.push({ value: "public", label: "On a public port", icon: "warning", desc: "Anyone on the internet can reach it directly — Docker skips the firewall for these ports. Only for apps with their own strong login.", tone: "warn" });
      const rc = el("div", { class: "em-rcards" });
      opts.forEach((o) => {
        const r = el("input", { type: "radio", name: "acc", value: o.value });
        r.checked = o.value === access;
        r.onchange = () => { access = o.value; domWrap.hidden = access !== "proxy"; };
        rc.append(el("label", { class: `em-rcard ${o.tone || ""}` }, [r, el("span", { class: "em-rcard-ico" }, icon(o.icon, 18)),
          el("div", {}, [el("div", { class: "em-rcard-t" }, el("b", { text: o.label })), el("p", { class: "muted", text: o.desc })])]));
      });
      domWrap.hidden = access !== "proxy";
      const folders = {};
      const fold = x.folders.map((f) => {
        folders[f] = el("input", { type: "text", placeholder: `/srv/${f} (empty = a folder inside the app)` });
        return field(`Your ${f} folder`, folders[f], f === "media" || f === "music" ? "Where your files already are — the app reads them from here." : "");
      });
      openModal(`Install ${x.name}`, el("div", { class: "em-form" }, [
        el("p", { class: "muted", text: x.desc }),
        x.note ? el("div", { class: "mx-note" }, [icon("info", 16), el("span", { text: x.note })]) : null,
        x.host_network ? el("div", { class: "mx-note mx-note-dim" }, [icon("info", 16), el("span", { text: `${x.name} needs the host network (to find devices at home), so it's reached at http://<this server>:${x.ports[0].port}.` })]) : null,
        field("Name", name, "Lowercase letters, digits and dashes — install the same app twice with different names."),
        el("div", { class: "mx-sub" }, "How to reach it"), rc, domWrap, ...fold,
      ]), [el("button", { class: "btn btn-primary", text: "Install", onclick: () => call(() => API.dockerInstall({ app: x.id, name: name.value.trim(), access, domain: domain.value.trim(),
        folders: Object.fromEntries(Object.entries(folders).map(([k, i]) => [k, i.value.trim()]).filter(([, v]) => v)) }), "Installing…", (r) => { closeModal(); watch(r.job, `${x.name} is running`); }) })]);
      modalWide();
    }
    load();
  }

  // ======================================================================
  //  System → Servers (every AuroraPanel on one page)
  // ======================================================================
  const meter = (label, pct, sub) => el("div", { class: "op-meter" }, [el("div", { class: "op-meter-l" }, [el("span", { text: label }), el("b", { text: pct == null ? "—" : `${Math.round(pct)}%` })]),
    el("div", { class: `op-meter-bar ${pct >= 90 ? "bad" : pct >= 75 ? "warn" : ""}` }, el("span", { style: `width:${Math.max(2, Math.min(100, pct || 0))}%` })), sub ? el("small", { class: "muted", text: sub }) : null]);
  const upt = (s) => !s ? "—" : s < 3600 ? `${Math.round(s / 60)} min` : s < 86400 ? `${Math.round(s / 3600)} h` : `${Math.round(s / 86400)} days`;
  async function viewServers(root) {
    root.append(pageHead("Servers", "All your AuroraPanel servers on one page — Raspberry Pis at home, VPSs in the cloud. See which one needs attention, and act on all of them at once.",
      [btn("Add a server", () => addDlg(), "btn-primary")]));
    const body = el("div", {}, el("div", { class: "loading", text: "Asking every server…" }));
    root.append(body);
    let d;
    async function load() {
      try { d = await API.servers(); } catch (e) { body.innerHTML = ""; body.append(el("p", { class: "empty", text: e.message })); return; }
      draw();
    }
    function draw() {
      body.innerHTML = "";
      const bad = d.servers.filter((s) => !s.ok || (s.alerts || []).some((a) => a.level === "critical") || (s.failed_units || []).length).length;
      body.append(el("div", { class: "mx-tiles" }, [
        tile("Servers", String(d.servers.length), d.servers.length > 1 ? `${d.servers.filter((s) => s.ok).length} reachable` : "add your others", "server"),
        tile("Need attention", String(bad), bad ? "critical alerts, failed services or unreachable" : "everything is healthy", "warning", bad ? "warnt" : ""),
        tile("Security updates", String(d.servers.reduce((a, s) => a + ((s.updates || {}).security || 0), 0)), "waiting across all servers", "t_update"),
        tile("Banned addresses", String(d.servers.reduce((a, s) => a + (s.bans || 0), 0)), "manual + fail2ban, all servers", "ban"),
      ]));
      body.append(el("div", { class: "op-srvs" }, d.servers.map((s) => el("div", { class: `card op-srv ${s.ok ? "" : "bad"}` }, [
        el("div", { class: "op-srv-h" }, [el("span", { class: `op-dot ${s.ok ? ((s.alerts || []).some((a) => a.level === "critical") || (s.failed_units || []).length ? "warn" : "good") : "bad"}` }),
          el("div", { class: "grow" }, [el("b", { text: s.name + (s.local ? "" : "") }), el("p", { class: "muted mx-small mx-ell", text: [s.hostname, s.model || (s.pi ? "Raspberry Pi" : ""), s.version ? `v${s.version}` : ""].filter(Boolean).join(" · ") })]),
          s.local ? pill("this one", "good") : null]),
        s.ok ? el("div", { class: "op-srv-m" }, [meter("CPU", s.cpu, `${s.cpus || "?"} cores · load ${s.load != null ? s.load.toFixed(2) : "—"}${s.temp ? ` · ${s.temp}°C` : ""}`),
          meter("Memory", s.mem_pct, s.mem_total ? fmtBytes(s.mem_total) : ""), meter("Disk", s.disk_pct, s.disk_total ? fmtBytes(s.disk_total) : "")])
          : el("div", { class: "mx-note" }, [icon("warning", 16), el("span", { text: s.error || "Unreachable" })]),
        s.ok ? el("div", { class: "op-srv-f" }, [
          el("span", { text: `Up ${upt(s.uptime)}` }),
          (s.updates || {}).total ? pill(`${s.updates.total} updates${s.updates.security ? ` · ${s.updates.security} security` : ""}`, s.updates.security ? "bad" : "warn") : pill("up to date", "good"),
          (s.updates || {}).reboot ? pill("restart needed", "warn") : null,
          (s.failed_units || []).length ? pill(`${s.failed_units.length} failed service${s.failed_units.length > 1 ? "s" : ""}`, "bad") : null,
          s.bans ? el("span", { class: "muted", text: `${s.bans} banned` }) : null]) : null,
        (s.alerts || []).length ? el("div", { class: "op-srv-al" }, s.alerts.slice(0, 3).map((a) => el("div", {}, [pill(a.level, a.level === "critical" ? "bad" : a.level === "warning" ? "warn" : "dim"), el("span", { class: "mx-ell", text: a.title })]))) : null,
        el("div", { class: "toolbar" }, [
          s.local ? null : el("a", { class: "btn btn-sm btn-ghost", href: s.url, target: "_blank", rel: "noopener", text: "Open its panel ↗" }),
          !s.local && s.error && /certificate changed/.test(s.error) ? armed("Trust its new certificate", "Click again", () => call(() => API.serverRepin(s.id), "Certificate accepted", load), "btn-ghost") : null,
          s.local ? null : armed("Remove", "Click again", () => call(() => API.serverRemove(s.id), "Removed", load), "btn-ghost"),
        ]),
      ]))));
      // ban everywhere
      const ip = el("input", { type: "text", placeholder: "203.0.113.7 or 203.0.113.0/24" });
      const reason = el("input", { type: "text", placeholder: "e.g. SSH brute force" });
      const durSel = el("select", { class: "em-select mx-narrow" }, [[3600, "1 hour"], [86400, "24 hours"], [604800, "7 days"], [2592000, "30 days"], [0, "Forever"]].map(([v, l]) => el("option", { value: v, text: l })));
      durSel.value = "86400";
      const out = el("div", {});
      const res = (r) => { out.innerHTML = ""; out.append(el("div", { class: "mx-list" }, [el("div", { class: "mx-list-row" }, [el("b", { class: "grow", text: "This server" }), pill(r.local.ok ? "done" : r.local.error, r.local.ok ? "good" : "warn")]),
        ...Object.entries(r.servers).map(([n, x]) => el("div", { class: "mx-list-row" }, [el("b", { class: "grow", text: n }), pill(x.ok ? "done" : x.error, x.ok ? "good" : "bad")]))])); };
      body.append(card("Ban or unban everywhere", [el("p", { class: "muted", text: d.servers.length > 1
        ? `One click blocks an address on this server and on ${d.servers.length - 1} other${d.servers.length === 2 ? "" : "s"} — websites, mail, SSH, VPN, panels.`
        : "Blocks an address on this server — websites, mail, SSH, VPN, the panel. Add your other servers above and it reaches them too." }),
        el("div", { class: "op-banrow" }, [field("Address or range", ip), field("Reason", reason), field("For", durSel)]),
        el("div", { class: "toolbar" }, [btn("Ban everywhere", () => call(() => API.serversBan({ ip: ip.value.trim(), reason: reason.value.trim(), duration: +durSel.value || null }), "", res), "btn-danger"),
          btn("Unban everywhere", () => call(() => API.serversBan({ ip: ip.value.trim(), unban: true }), "", res), "btn-ghost")]), out]));
    }
    function addDlg() {
      const name = el("input", { type: "text", placeholder: "Home Pi" });
      const url = el("input", { type: "text", placeholder: "https://192.168.0.100:8088" });
      const token = el("input", { type: "password", placeholder: "aur_…", autocomplete: "off" });
      openModal("Add a server", el("div", { class: "em-form" }, [
        el("ol", { class: "op-steps" }, [el("li", { text: "On the other server's panel: Security → Manage API Tokens → create a token (name it after this server)." }),
          el("li", { text: "Copy it and paste it below with that panel's address (the one you open it with)." })]),
        field("Name", name), field("Panel address", url, "https:// with any certificate — it's remembered (pinned) on first contact. http:// only on your own network."), field("API token", token),
      ]), [el("button", { class: "btn btn-primary", text: "Add", onclick: () => call(() => API.serverAdd({ name: name.value.trim(), url: url.value.trim(), token: token.value.trim() }), "Server added", () => { closeModal(); load(); }) })]);
    }
    load();
    const t = setInterval(load, 60000); state.cleanups.push(() => clearInterval(t));
  }

  // ======================================================================
  //  Applications → WordPress Toolkit
  // ======================================================================
  async function viewWPToolkit(root) {
    root.append(pageHead("WordPress Toolkit", "Every WordPress on this server in one place: update WordPress, plugins and themes, check for hacked files, lock it down, and try changes on a private staging copy first.",
      [btn("Install WordPress", () => navigate("wordpress"), "btn-ghost")]));
    const prog = progressBox();
    const log = el("pre", { class: "log op-log", hidden: "" });
    const body = el("div", {}, el("div", { class: "loading", text: "Finding WordPress sites…" }));
    root.append(prog.node, log, body);
    let list;
    async function watch(id, label, after) {
      log.hidden = false; prog.node.scrollIntoView({ block: "nearest" });
      const j = await waitJob(id, (j) => { prog.set(j); log.textContent = j.output || ""; log.scrollTop = 1e9; });
      if (j) toast(j.status === "done" ? label : "Something went wrong — see the log", j.status === "done" ? "good" : "bad");
      if (after) after();
    }
    async function load() {
      try { list = await API.wpt(); } catch (e) { body.innerHTML = ""; body.append(el("p", { class: "empty", text: e.message })); return; }
      body.innerHTML = "";
      if (!list.sites.length) { body.append(el("div", { class: "card" }, empty("wordpress", "No WordPress here yet", "Install one with the App Installer — it shows up here by itself.", btn("Install WordPress", () => navigate("wordpress"), "btn-primary")))); return; }
      list.sites.forEach((s) => body.append(siteCard(s)));
    }
    function siteCard(s) {
      const box = el("div", { class: "card op-wp" }, el("div", { class: "loading", text: `Checking ${s.url || s.path}…` }));
      const fill = async () => {
        let d;
        try { d = await API.wptSite(s.path); } catch (e) { box.innerHTML = ""; box.append(el("p", { class: "empty", text: e.message })); return; }
        box.innerHTML = "";
        const pu = d.plugins.filter((p) => p.update === "available"), tu = d.themes.filter((t) => t.update === "available"), cu = d.core_updates.length;
        const todo = pu.length + tu.length + (cu ? 1 : 0);
        const hard = Object.values(d.hardening).filter(Boolean).length;
        const autoOn = d.plugins.length && d.plugins.every((p) => p.auto_update === "on");
        box.append(
          el("div", { class: "op-plan-h" }, [el("span", { class: "op-plan-ico" }, icon("wordpress", 20)), el("div", { class: "grow" }, [el("h3", { text: d.url.replace(/^https?:\/\//, "") }),
            el("p", { class: "muted mx-small", text: `WordPress ${d.version} · ${d.plugins.length} plugins · ${d.themes.length} themes · ${d.path}` })]),
            d.db_error ? pill("database error", "bad") : todo ? pill(`${todo} update${todo > 1 ? "s" : ""}`, "warn") : pill("up to date", "good"), d.maintenance ? pill("maintenance mode", "warn") : null]),
          d.db_error ? el("p", { class: "bk-warnline", text: d.db_error + " — check DB_NAME / DB_USER / DB_PASSWORD in wp-config.php, or restore the database from a backup." }) : null,
          el("div", { class: "op-plan-facts" }, [
            el("div", {}, [el("span", { class: "muted", text: "WordPress" }), el("b", { text: cu ? `${d.version} → ${d.core_updates[0].version}` : `${d.version} (latest)` })]),
            el("div", {}, [el("span", { class: "muted", text: "Plugins" }), el("b", { text: pu.length ? `${pu.length} to update` : "all current" })]),
            el("div", {}, [el("span", { class: "muted", text: "Security" }), el("b", { text: `${hard} of 4 protections on` })]),
            el("div", {}, [el("span", { class: "muted", text: "Staging copy" }), d.staging ? el("a", { href: d.staging.url, target: "_blank", rel: "noopener", text: "open ↗" }) : el("b", { text: "none" })]),
          ]),
          el("div", { class: "toolbar" }, [
            todo && !d.db_error ? btn("Update everything", () => call(() => API.wptAct("update", { path: d.path, what: "all" }), "Updating…", (r) => watch(r.job, "Updated", fill)), "btn-primary") : null,
            btn("Check for hacked files", () => call(() => API.wptAct("scan", { path: d.path }), "Scanning…", (r) => watch(r.job, "Scan finished")), "btn-ghost"),
            hard < 4 ? btn("Harden", () => call(() => API.wptAct("harden", { path: d.path }), "", (r) => { toast(r.done.join(" · "), "good"); fill(); }), "btn-ghost") : null,
            btn(autoOn ? "Turn off auto-updates" : "Turn on auto-updates", () => call(() => API.wptAct("autoupdates", { path: d.path, on: !autoOn }), autoOn ? "Auto-updates off" : "WordPress, plugins and themes now update themselves", fill), "btn-ghost"),
            btn(d.maintenance ? "End maintenance" : "Maintenance mode", () => call(() => API.wptAct("maintenance", { path: d.path, on: !d.maintenance }), "", fill), "btn-ghost"),
            d.staging ? armed("Delete staging", "Click again", () => call(() => API.wptAct("staging", { path: d.path, on: false }), "Staging copy deleted", fill), "btn-ghost")
              : btn("Make a staging copy", () => call(() => API.wptAct("staging", { path: d.path, on: true }), "Copying…", (r) => watch(r.job, "Staging copy ready", fill)), "btn-ghost"),
            d.url ? el("a", { class: "btn btn-sm btn-ghost", href: d.url.replace(/\/$/, "") + "/wp-admin/", target: "_blank", rel: "noopener", text: "wp-admin ↗" }) : null,
          ]),
          pu.length || tu.length ? el("details", { class: "op-wp-list" }, [el("summary", { text: `What will be updated (${pu.length + tu.length})` }),
            el("div", { class: "mx-list" }, [...pu.map((p) => el("div", { class: "mx-list-row" }, [pill("plugin"), el("b", { class: "grow", text: p.title || p.name }), el("span", { class: "muted", text: `${p.version} → ${p.update_version}` }),
              btn("Update", () => call(() => API.wptAct("update", { path: d.path, what: "plugins", names: [p.name] }), "Updating…", (r) => watch(r.job, `${p.title || p.name} updated`, fill)), "btn-ghost")])),
              ...tu.map((t) => el("div", { class: "mx-list-row" }, [pill("theme"), el("b", { class: "grow", text: t.title || t.name }), el("span", { class: "muted", text: `${t.version} → ${t.update_version}` })]))])]) : null,
        );
      };
      fill();
      return box;
    }
    load();
  }

  // ======================================================================
  //  Files → Move from cPanel
  // ======================================================================
  async function viewMigrate(root) {
    root.append(pageHead("Move from cPanel", "Bring a whole cPanel account over: websites, databases, mailboxes with their mail and passwords, forwarders and DNS zones. Nothing that already exists here is overwritten."));
    const prog = progressBox();
    const log = el("pre", { class: "log op-log", hidden: "" });
    const body = el("div", {}, el("div", { class: "loading", text: "Looking for cPanel backups…" }));
    root.append(prog.node, log, body);
    let d;
    async function watch(id, label, after) {
      log.hidden = false; prog.node.scrollIntoView({ block: "nearest" });
      const j = await waitJob(id, (j) => { prog.set(j); log.textContent = j.output || ""; log.scrollTop = 1e9; });
      if (j) toast(j.status === "done" ? label : "Something went wrong — see the log", j.status === "done" ? "good" : "bad");
      if (after) after();
    }
    async function load() {
      try { d = await API.migrate(); } catch (e) { body.innerHTML = ""; body.append(el("p", { class: "empty", text: e.message })); return; }
      body.innerHTML = "";
      const url = el("input", { type: "url", placeholder: "https://old-host.example.com/…/backup-…tar.gz" });
      body.append(card("1. Get the backup here", [
        el("ol", { class: "op-steps" }, [el("li", { text: "In the old cPanel: Files → Backup → “Download a Full Account Backup” (or ask your host)." }),
          el("li", {}, ["Upload the .tar.gz to ", el("code", { text: d.folder }), " with the File Manager or SFTP — or paste a download link:"])]),
        el("div", { class: "op-banrow", style: "grid-template-columns:1fr auto" }, [field("Download link", url), btn("Download", () => call(() => API.migrateFetch(url.value.trim()), "Downloading…", (r) => watch(r.job, "Downloaded", load)), "btn-primary")]),
      ]));
      body.append(card("2. Pick the backup", [d.backups.length ? el("div", { class: "mx-list" }, d.backups.map((b) => el("div", { class: "mx-list-row" }, [icon("backup", 16), el("b", { class: "grow mx-ell", text: b.name }),
        el("span", { class: "muted", text: `${fmtBytes(b.size)} · ${ago(b.mtime)}` }), btn("Look inside", () => inspect(b.path), "btn-primary")]))) : el("p", { class: "muted", text: "No cPanel backups found yet (files named cpmove-… or backup-…_user.tar.gz)." })]));
    }
    async function inspect(path) {
      const box = el("div", {}, el("div", { class: "loading", text: "Reading the backup (big ones take a minute)…" }));
      openModal("What's in this backup", box, []); modalWide();
      let a;
      try { a = await API.migrateAnalyze(path); } catch (e) { box.innerHTML = ""; box.append(el("p", { class: "empty", text: e.message })); return; }
      box.innerHTML = "";
      const chk = (label, sub, val = true) => { const c = el("input", { type: "checkbox" }); c.checked = val; c.dataset.v = label; return el("label", { class: "op-what" }, [c, el("div", {}, [el("b", { text: label }), sub ? el("span", { class: "muted", text: sub }) : null])]); };
      const siteC = a.sites.map((s) => chk(s.domain, `${s.kind} · ${s.docroot_rel}${s.aliases.length ? ` · also ${s.aliases.join(", ")}` : ""}`));
      const dbC = a.databases.map((x) => chk(x.name, fmtBytes(x.size)));
      const mailC = chk(`${a.mailboxes.length} mailboxes`, `${a.mailboxes.map((m) => m.address).slice(0, 4).join(", ")}${a.mailboxes.length > 4 ? "…" : ""}${a.forwarders ? ` · ${a.forwarders} forwarders` : ""}`, a.mailboxes.length > 0);
      const zoneC = chk(`${a.zones.length} DNS zones`, "Only if this server will answer DNS for these domains", false);
      box.append(el("p", { class: "muted", text: `cPanel account “${a.user}” · main domain ${a.main_domain || "?"}` }),
        el("div", { class: "mx-sub" }, "Websites"), el("div", { class: "op-whats" }, siteC.length ? siteC : [el("p", { class: "muted", text: "None" })]),
        el("div", { class: "mx-sub" }, "Databases (users keep their passwords)"), el("div", { class: "op-whats" }, dbC.length ? dbC : [el("p", { class: "muted", text: "None" })]),
        el("div", { class: "mx-sub" }, "Email & DNS"), el("div", { class: "op-whats" }, [mailC, ...(a.zones.length ? [zoneC] : [])]));
      const go = el("button", { class: "btn btn-primary", text: "Import", onclick: () => {
        const v = (arr) => arr.filter((l) => l.querySelector("input").checked).map((l) => l.querySelector("input").dataset.v);
        closeModal();
        call(() => API.migrateRun({ path, sites: v(siteC), databases: v(dbC), mail: mailC.querySelector("input").checked, zones: zoneC.querySelector("input").checked }), "Importing…",
          (r) => watch(r.job, "Import finished"));
      } });
      document.querySelector("#modal .modal-foot").prepend(go);
    }
    load();
  }

  // ======================================================================
  //  A website manager's home: My Websites
  // ======================================================================
  async function viewMySites(root) {
    root.append(pageHead("My Websites", "The websites you manage on this server — their files, email accounts and visitors."));
    const body = el("div", {}, el("div", { class: "loading", text: "Loading…" }));
    root.append(body);
    let d;
    try { d = await API.mySites(); } catch (e) { body.innerHTML = ""; body.append(el("p", { class: "empty", text: e.message })); return; }
    body.innerHTML = "";
    if (state.account) hostingMeCards(body);
    if (!d.sites.length) { body.append(el("div", { class: "card" }, empty("globe", "No websites assigned yet", "Ask the server's administrator to give you access to your websites."))); }
    body.append(el("div", { class: "op-dapps" }, d.sites.map((s) => el("div", { class: "op-dapp" }, [
      el("div", { class: "op-dapp-h" }, [el("span", { class: "op-dapp-ico", style: `--h:${APP_HUE(s.name)}`, text: s.name[0].toUpperCase() }),
        el("div", { class: "grow" }, [el("b", { text: s.name }), el("p", { class: "muted mx-small mx-ell", text: s.docroot })]), pill(s.ssl === "none" ? "http" : "https", s.ssl === "none" ? "dim" : "good")]),
      el("a", { class: "op-dapp-url", href: `${s.ssl === "none" ? "http" : "https"}://${s.name}/`, target: "_blank", rel: "noopener", text: `${s.name} ↗` }),
      el("div", { class: "op-dapp-act" }, [btn("Files", () => navigate("files", { arg: s.docroot }), "btn-primary"), btn("Email accounts", () => navigate("mailaccounts"), "btn-ghost"),
        btn("Visitors", () => navigate("visitors"), "btn-ghost"), btn("Analytics", () => navigate("analytics"), "btn-ghost"), btn("Errors", () => navigate("errors"), "btn-ghost"),
        d.webmail ? el("a", { class: "btn btn-sm btn-ghost", href: d.webmail.startsWith("/") ? `https://${location.hostname}${d.webmail}` : d.webmail, target: "_blank", rel: "noopener", text: "Webmail ↗" }) : null]),
    ]))));
    const cur = el("input", { type: "password", autocomplete: "current-password" });
    const nw = el("input", { type: "password", autocomplete: "new-password" });
    body.append(card("Change my password", [el("div", { class: "mx-grid2" }, [field("Current password", cur), field("New password (10+ characters)", nw)]),
      el("div", { class: "toolbar" }, [btn("Change password", () => call(() => API.myPassword(cur.value, nw.value), "Password changed", () => { cur.value = nw.value = ""; }), "btn-primary")])]));
  }

  // ======================================================================
  //  Preferences → Panel Users
  // ======================================================================
  const ROLE_TXT = { admin: ["Administrator", "Everything, like you."], viewer: ["Viewer", "Sees every page, changes nothing, can't open files or secrets."],
    site: ["Website manager", "Only their own websites: files, email accounts, visitors. Nothing else on the server."],
    reseller: ["Reseller", "Creates and manages their own hosting accounts with the plans you allow (Hosting → Resellers)."] };
  async function viewPanelUsers(root) {
    root.append(pageHead("Panel Users", "Let other people into the panel with just the power they need — a colleague who only watches, or a client who manages their own website and mailboxes.",
      [btn("Add a user", () => editor(), "btn-primary")]));
    const body = el("div", {}, el("div", { class: "loading", text: "Loading…" }));
    root.append(body);
    let d;
    async function load() {
      try { d = await API.panelUsers(); } catch (e) { body.innerHTML = ""; body.append(el("p", { class: "empty", text: e.message })); return; }
      body.innerHTML = "";
      body.append(card(`Users (${d.users.length})`, [el("div", { class: "op-isos" }, d.users.map((u) => el("div", { class: `op-iso ${u.disabled ? "" : "on"}` }, [
        el("span", { class: "op-dapp-ico", style: `--h:${APP_HUE(u.username)}`, text: u.username[0].toUpperCase() }),
        el("div", { class: "grow" }, [el("b", { text: u.username }), el("p", { class: "muted mx-small mx-ell", text: u.owner ? "Owner — set up this panel" :
          `${ROLE_TXT[u.role][0]}${u.sites && u.sites.length ? ` · ${u.sites.join(", ")}` : ""}${u.last_login ? ` · last sign-in ${ago(u.last_login)}` : " · never signed in"}` })]),
        pill(u.disabled ? "disabled" : ROLE_TXT[u.role][0], u.disabled ? "dim" : u.role === "admin" ? "warn" : u.role === "site" ? "good" : "dim"),
        u.owner ? null : u.account ? btn("Hosting account", () => navigate("hostaccounts"), "btn-ghost") : btn("Edit", () => editor(u), "btn-ghost"),
        u.owner || u.account ? null : armed("Delete", "Click again", () => call(() => API.panelUserDelete(u.username), "User deleted — signed out at once", load), "btn-ghost"),
      ])))]),
      card("What each role can do", [el("div", { class: "mx-list" }, Object.entries(ROLE_TXT).map(([k, [l, h]]) => el("div", { class: "mx-list-row" }, [pill(l, k === "admin" ? "warn" : k === "site" ? "good" : "dim"), el("span", { class: "grow", text: h })])))]));
    }
    function editor(u = null) {
      let role = u ? u.role : "site";
      const name = el("input", { type: "text", value: u ? u.username : "", disabled: u ? "" : null, autocomplete: "off" });
      const pw = el("input", { type: "text", placeholder: u ? "(unchanged — leave empty)" : "at least 10 characters", autocomplete: "off" });
      const gen = btn("Generate", () => { const a = new Uint32Array(16); crypto.getRandomValues(a); pw.value = Array.from(a, (n) => "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789"[n % 57]).join(""); }, "btn-ghost");
      const siteBox = el("div", { class: "op-destpick" }, d.sites.map((s) => { const c = el("input", { type: "checkbox", value: s }); c.checked = !!(u && u.sites && u.sites.includes(s)); return el("label", { class: "dm-check" }, [c, el("span", { text: s })]); }));
      const siteWrap = el("div", {}, [el("div", { class: "mx-sub" }, "Websites they manage"), d.sites.length ? siteBox : el("p", { class: "muted", text: "No websites yet — create one under Domains first." })]);
      siteWrap.hidden = role !== "site";
      const rc = el("div", { class: "em-rcards" });
      Object.entries(ROLE_TXT).forEach(([k, [l, h]]) => { const r = el("input", { type: "radio", name: "role", value: k }); r.checked = k === role; r.onchange = () => { role = k; siteWrap.hidden = role !== "site"; };
        rc.append(el("label", { class: "em-rcard" }, [r, el("span", { class: "em-rcard-ico" }, icon(k === "admin" ? "key" : k === "site" ? "globe" : k === "reseller" ? "users" : "search", 18)), el("div", {}, [el("div", { class: "em-rcard-t" }, el("b", { text: l })), el("p", { class: "muted", text: h })])])); });
      const dis = el("input", { type: "checkbox" }); dis.checked = !!(u && u.disabled);
      openModal(u ? `Edit ${u.username}` : "Add a user", el("div", { class: "em-form" }, [
        el("div", { class: "mx-grid2" }, [field("User name", name), field("Password", el("div", { class: "op-pwrow" }, [pw, gen]), "Share it with them privately; they can change it on their home page.")]),
        el("div", { class: "mx-sub" }, "Role"), rc, siteWrap,
        u ? el("label", { class: "dm-check" }, [dis, el("span", { text: "Disabled (can't sign in)" })]) : null,
      ]), [el("button", { class: "btn btn-primary", text: u ? "Save" : "Add user", onclick: () => {
        const sites = [...siteBox.querySelectorAll("input:checked")].map((c) => c.value);
        call(() => u ? API.panelUserUpdate({ username: u.username, role, sites, password: pw.value || null, disabled: dis.checked })
          : API.panelUserCreate({ username: name.value.trim(), password: pw.value, role, sites }), u ? "Saved" : "User added", () => { closeModal(); load(); });
      } })]);
      modalWide();
    }
    load();
  }

  // ======================================================================
  //  Hosting (WHM-style): accounts, plans, resellers
  // ======================================================================
  const genPw = () => { const a = new Uint32Array(16); crypto.getRandomValues(a); return Array.from(a, (n) => "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789"[n % 57]).join(""); };
  const mbFmt = (mb) => (mb >= 1024 ? `${+(mb / 1024).toFixed(1)} GB` : `${mb} MB`);
  // One usage bar: used of limit (limit 0 = unlimited).
  function useBar(label, used, limit, fmt) {
    const pct = limit ? Math.min(100, (used / limit) * 100) : 0;
    return el("div", { class: "hs-use" }, [
      el("div", { class: "hs-use-t" }, [el("span", { class: "muted", text: label }), el("b", { text: `${fmt(used)}${limit ? ` / ${fmt(limit)}` : " · unlimited"}` })]),
      el("div", { class: `em-use-bar ${pct >= 100 ? "bad" : pct >= 85 ? "warn" : ""}` }, el("span", { style: `width:${limit ? Math.max(pct, used ? 1 : 0) : 0}%` })),
    ]);
  }
  function usageBars(u, lim) {
    u = u || {}; lim = lim || {};
    return el("div", { class: "hs-uses" }, [
      useBar("Disk", u.disk_bytes || 0, (lim.disk_mb || 0) * 1048576, fmtBytes),
      useBar("Bandwidth this month", u.bandwidth_bytes || 0, (lim.bandwidth_gb || 0) * 1e9, fmtBytes),
      useBar("Email accounts", u.mailboxes || 0, lim.mailboxes || 0, num),
    ]);
  }
  const limitTxt = (lim, labels) => labels.map(([k, l, unit]) => `${l}: ${lim[k] ? `${k === "disk_mb" ? mbFmt(lim[k]) : lim[k]}${unit && k !== "disk_mb" ? " " + unit : ""}` : "unlimited"}`).join(" · ");

  async function viewHostAccounts(root) {
    const isReseller = state.role === "reseller";
    root.append(pageHead(isReseller ? "My Hosting Accounts" : "Hosting Accounts",
      "Each account is a separate Linux user with its own home folder, website(s), panel login, mailboxes and databases — its PHP runs as that user, within its plan's limits. Like cPanel accounts in WHM.",
      [btn("Create an account", () => create(), "btn-primary")]));
    const body = el("div", {}, el("div", { class: "loading", text: "Loading…" }));
    root.append(body);
    let d;
    async function load() {
      try { d = await API.hosting(); } catch (e) { body.innerHTML = ""; body.append(el("p", { class: "empty", text: e.message })); return; }
      draw();
    }
    function draw() {
      body.innerHTML = "";
      if (d.ready && !(d.ready.apache && d.ready.php)) body.append(el("div", { class: "card mx-hero warn" }, [el("div", { class: "mx-hero-ico" }, icon("warning", 26)),
        el("div", { class: "mx-hero-txt" }, [el("h3", { text: "Hosting needs Apache and PHP" }), el("p", { class: "muted", text: "Install them under Software (Apache, PHP-FPM) — every account's website runs on them." })]),
        el("div", { class: "mx-hero-act" }, [btn("Software", () => navigate("software"), "btn-primary")])]));
      if (d.reseller) body.append(el("p", { class: "muted mx-p", text: `${d.reseller.used} of ${d.reseller.max_accounts || "unlimited"} accounts used.` }));
      if (!d.accounts.length) { body.append(el("div", { class: "card" }, empty("users", "No hosting accounts yet", "Create one: it gets its own Linux user, website, panel login, mail and databases."))); return; }
      body.append(el("div", { class: "hs-accts" }, d.accounts.map((a) => el("div", { class: `card hs-acct ${a.suspended ? "susp" : ""}` }, [
        el("div", { class: "hs-acct-h" }, [
          el("span", { class: "op-dapp-ico", style: `--h:${APP_HUE(a.user)}`, text: a.user[0].toUpperCase() }),
          el("div", { class: "grow" }, [el("b", { text: a.user }), el("p", { class: "muted mx-small mx-ell", text: `${a.sites.join(", ")}${a.email ? " · " + a.email : ""}${a.owner ? " · reseller " + a.owner : ""}` })]),
          pill(a.plan, "dim"), a.suspended ? pill("suspended", "bad") : pill("active", "good"),
        ]),
        a.suspended && a.suspend_reason ? el("p", { class: "form-error", text: a.suspend_reason }) : null,
        usageBars(a.usage, a.limits),
        el("p", { class: "muted mx-small", text: a.usage && a.usage.measured ? `Measured ${ago(a.usage.measured)} (every hour)` : "Usage is measured every hour." }),
        el("div", { class: "toolbar" }, [
          el("a", { class: "btn btn-sm btn-ghost", href: `http://${a.domain}/`, target: "_blank", rel: "noopener", text: `${a.domain} ↗` }),
          btn("Add a website", () => addDomain(a), "btn-ghost"),
          btn("Plan", () => changePlan(a), "btn-ghost"),
          btn("Password", () => setPw(a), "btn-ghost"),
          a.suspended ? btn("Unsuspend", () => call(() => API.hostingSuspend(a.user, false), `${a.user} is active again`, load), "btn-primary")
            : btn("Suspend", () => suspendDlg(a), "btn-ghost"),
          btn("Terminate", () => terminateDlg(a), "btn-ghost"),
        ]),
      ]))));
      if (!isReseller) body.append(el("div", { class: "toolbar" }, [btn("Measure usage now", () => call(() => API.hostingMeasure(), "Measured", load), "btn-ghost")]));
    }
    function create() {
      if (!d) return;
      const plans = Object.keys(d.plans);
      if (!plans.length) return toast(isReseller ? "The administrator hasn't given you any plans yet" : "Create a plan first (Hosting → Plans)", "bad");
      const user = el("input", { type: "text", placeholder: "alice", autocomplete: "off", maxlength: 16 });
      const dom = el("input", { type: "text", placeholder: "alice-shop.com", autocomplete: "off" });
      const pw = el("input", { type: "text", autocomplete: "off", placeholder: "at least 10 characters" });
      const mail = el("input", { type: "email", placeholder: "Optional", autocomplete: "off" });
      const plan = el("select", { class: "em-select" }, plans.map((p) => el("option", { value: p, text: p })));
      const planInfo = el("p", { class: "muted mx-small" });
      const showPlan = () => { planInfo.textContent = limitTxt(d.plans[plan.value] || {}, d.limits); };
      plan.onchange = showPlan; showPlan();
      user.oninput = () => { user.value = user.value.toLowerCase().replace(/[^a-z0-9]/g, ""); };
      const log = el("div", {});
      openModal("Create a hosting account", el("div", { class: "em-form" }, [
        el("div", { class: "mx-grid2" }, [field("User name", user, "Lowercase letters and digits — it becomes the Linux user and the panel login."), field("Main domain", dom, "Its website: /home/<user>/public_html")]),
        el("div", { class: "mx-grid2" }, [field("Panel password", el("div", { class: "op-pwrow" }, [pw, btn("Generate", () => { pw.value = genPw(); }, "btn-ghost")]), "Give it to the customer privately."), field("Contact email", mail)]),
        field("Plan", plan), planInfo, log,
      ]), [el("button", { class: "btn btn-primary", text: "Create", onclick: async (ev) => {
        const b = ev.currentTarget;
        b.disabled = true; b.textContent = "Creating…";
        let r;
        try {
          r = await API.hostingCreate({ user: user.value.trim(), domain: dom.value.trim(), plan: plan.value, password: pw.value, email: mail.value.trim() });
        } catch (e) { toast(e.message, "bad"); b.disabled = false; b.textContent = "Create"; return; }
        // Follow the job: its log here, then close and show the new account (or keep the log if it failed).
        const out = el("pre", { class: "log", text: "Starting…" });
        log.replaceChildren(out);
        const name = user.value.trim();
        const t = setInterval(async () => {
          let j;
          try { j = await API.job(r.job); } catch (e) { return; }
          out.textContent = j.output || "Working…"; out.scrollTop = out.scrollHeight;
          if (j.status === "running") return;
          clearInterval(t);
          if (j.status === "done") { toast(`Account ${name} is ready`, "good"); closeModal(); load(); }
          else { toast(`Creating ${name} failed — see the log`, "bad"); b.textContent = "Failed"; load(); }
        }, 1200);
      } })]);
    }
    function addDomain(a) {
      const dom = el("input", { type: "text", placeholder: "another-site.com" });
      openModal(`Add a website to ${a.user}`, el("div", { class: "em-form" }, [field("Domain", dom, `Its files: /home/${a.user}/<domain>. Counts toward the plan's websites (${a.limits.sites || "unlimited"}).`)]),
        [el("button", { class: "btn btn-primary", text: "Add", onclick: () => call(() => API.hostingDomain(a.user, dom.value.trim()), "Website added", () => { closeModal(); load(); }) })]);
    }
    function changePlan(a) {
      const plan = el("select", { class: "em-select" }, Object.keys(d.plans).map((p) => el("option", { value: p, text: p })));
      plan.value = a.plan;
      const info = el("p", { class: "muted mx-small" });
      const show = () => { info.textContent = limitTxt(d.plans[plan.value] || {}, d.limits); };
      plan.onchange = show; show();
      openModal(`Plan for ${a.user}`, el("div", { class: "em-form" }, [field("Plan", plan), info]),
        [el("button", { class: "btn btn-primary", text: "Change plan", onclick: () => call(() => API.hostingPlan(a.user, plan.value), "Plan changed — PHP limits applied", () => { closeModal(); load(); }) })]);
    }
    function setPw(a) {
      const pw = el("input", { type: "text", autocomplete: "off" });
      openModal(`New panel password for ${a.user}`, el("div", { class: "em-form" }, [field("Password", el("div", { class: "op-pwrow" }, [pw, btn("Generate", () => { pw.value = genPw(); }, "btn-ghost")]), "They're signed out everywhere.")]),
        [el("button", { class: "btn btn-primary", text: "Set password", onclick: () => call(() => API.hostingPassword(a.user, pw.value), "Password set", () => closeModal()) })]);
    }
    function suspendDlg(a) {
      const why = el("input", { type: "text", placeholder: "e.g. unpaid invoice" });
      openModal(`Suspend ${a.user}`, el("div", { class: "em-form" }, [el("p", { class: "muted", text: "Its websites go offline, its panel login and its mailboxes' sign-in stop. Nothing is deleted; Unsuspend restores everything exactly." }), field("Reason (shown to admins)", why)]),
        [el("button", { class: "btn btn-primary", text: "Suspend", onclick: () => call(() => API.hostingSuspend(a.user, true, why.value), `${a.user} suspended`, () => { closeModal(); load(); }) })]);
    }
    function terminateDlg(a) {
      const keep = el("input", { type: "checkbox" });
      const conf = el("input", { type: "text", placeholder: a.user, autocomplete: "off" });
      openModal(`Terminate ${a.user}`, el("div", { class: "em-form" }, [
        el("p", { class: "form-error", text: `Deletes the websites (${a.sites.join(", ")}), the Linux user, the panel login, every mailbox with its mail and every ${a.user}_ database. This can't be undone.` }),
        el("label", { class: "dm-check" }, [keep, el("span", { text: `Keep the files in /home/${a.user}` })]),
        field(`Type ${a.user} to confirm`, conf),
      ]), [el("button", { class: "btn btn-primary", text: "Terminate", onclick: () => {
        if (conf.value.trim() !== a.user) return toast(`Type ${a.user} to confirm`, "bad");
        call(() => API.hostingTerminate(a.user, keep.checked), `${a.user} terminated`, () => { closeModal(); load(); });
      } })]);
    }
    load();
  }

  async function viewHostPlans(root) {
    root.append(pageHead("Hosting Plans", "What an account may use — like WHM packages. Changing a plan applies to every account on it at once (PHP limits right away, disk and bandwidth at the next hourly check). 0 means unlimited.",
      [btn("New plan", () => edit(), "btn-primary")]));
    const body = el("div", {}, el("div", { class: "loading", text: "Loading…" }));
    root.append(body);
    let d;
    async function load() {
      try { d = await API.hosting(); } catch (e) { body.innerHTML = ""; body.append(el("p", { class: "empty", text: e.message })); return; }
      body.innerHTML = "";
      const used = (p) => d.accounts.filter((a) => a.plan === p).length;
      body.append(el("div", { class: "hs-plans" }, Object.entries(d.plans).map(([name, lim]) => el("div", { class: "card hs-plan" }, [
        el("div", { class: "hs-acct-h" }, [el("div", { class: "grow" }, [el("b", { text: name }), el("p", { class: "muted mx-small", text: `${used(name)} account${used(name) === 1 ? "" : "s"}` })])]),
        el("div", { class: "hs-limits" }, d.limits.map(([k, l, unit]) => el("div", {}, [el("span", { class: "muted", text: l }),
          el("b", { text: lim[k] ? (k === "disk_mb" || k === "php_memory_mb" ? mbFmt(lim[k]) : k === "bandwidth_gb" ? `${lim[k]} GB` : String(lim[k])) : "unlimited" })]))),
        el("div", { class: "toolbar" }, [btn("Edit", () => edit(name, lim), "btn-ghost"), used(name) ? null : armed("Delete", "Click again", () => call(() => API.hostingPlanDelete(name), "Plan deleted", load), "btn-ghost")]),
      ]))));
    }
    function edit(name = "", lim = {}) {
      const nm = el("input", { type: "text", value: name, maxlength: 40 });
      const inputs = {};
      const rows = d.limits.map(([k, l, unit]) => { inputs[k] = el("input", { type: "number", min: 0, value: lim[k] ?? 0, class: "op-num" });
        return el("div", { class: "op-rule" }, [el("b", { text: l }), el("span", { class: "op-numw" }, [inputs[k], el("span", { class: "muted", text: unit || "" })])]); });
      openModal(name ? `Edit ${name}` : "New plan", el("div", { class: "em-form" }, [field("Name", nm), el("div", { class: "op-rules" }, rows),
        el("p", { class: "muted mx-small", text: "PHP workers: how many requests an account's sites run at once (others wait) — keeps one busy site from slowing the server." })]),
        [el("button", { class: "btn btn-primary", text: "Save plan", onclick: () => {
          const limits = {}; Object.entries(inputs).forEach(([k, i]) => { limits[k] = +i.value || 0; });
          call(() => API.hostingPlanSave({ name: nm.value.trim(), original: name, limits }), "Plan saved", () => { closeModal(); load(); });
        } })]);
      modalWide();
    }
    load();
  }

  async function viewHostResellers(root) {
    root.append(pageHead("Resellers", "People who sell hosting from this server: they create and manage their own accounts with the plans you allow, up to the number you set. Make someone a reseller under Panel Users (role: Reseller).",
      [btn("Panel Users", () => navigate("panelusers"), "btn-ghost")]));
    const body = el("div", {}, el("div", { class: "loading", text: "Loading…" }));
    root.append(body);
    let d;
    async function load() {
      try { d = await API.hosting(); } catch (e) { body.innerHTML = ""; body.append(el("p", { class: "empty", text: e.message })); return; }
      body.innerHTML = "";
      if (!d.resellers.length) { body.append(el("div", { class: "card" }, empty("users", "No resellers yet", "Add a panel user with the Reseller role, then choose their plans here."))); return; }
      body.append(el("div", { class: "hs-plans" }, d.resellers.map((r) => {
        const max = el("input", { type: "number", min: 0, value: r.max_accounts || 0, class: "op-num" });
        const box = el("div", { class: "op-destpick" }, Object.keys(d.plans).map((p) => { const c = el("input", { type: "checkbox", value: p }); c.checked = (r.plans || []).includes(p); return el("label", { class: "dm-check" }, [c, el("span", { text: p })]); }));
        return el("div", { class: "card hs-plan" }, [
          el("div", { class: "hs-acct-h" }, [el("span", { class: "op-dapp-ico", style: `--h:${APP_HUE(r.username)}`, text: r.username[0].toUpperCase() }),
            el("div", { class: "grow" }, [el("b", { text: r.username }), el("p", { class: "muted mx-small", text: `${r.accounts} account${r.accounts === 1 ? "" : "s"}` })])]),
          el("div", { class: "mx-sub" }, "Plans they may sell"), box,
          el("div", { class: "op-rule" }, [el("b", { text: "Most accounts" }), el("span", { class: "op-numw" }, [max, el("span", { class: "muted", text: "0 = unlimited" })])]),
          el("div", { class: "toolbar" }, [btn("Save", () => call(() => API.hostingReseller({ username: r.username, plans: [...box.querySelectorAll("input:checked")].map((c) => c.value), max_accounts: +max.value || 0 }), "Saved", load), "btn-primary")]),
        ]);
      })));
    }
    load();
  }

  // A hosting account's own page (shown on My Websites): plan, usage, and its databases.
  async function hostingMeCards(body) {
    let me, db;
    try { [me, db] = await Promise.all([API.hostingMe(), API.hostingMyDb()]); } catch (e) { return; }
    body.prepend(card(`My plan: ${me.plan}`, [usageBars(me.usage, me.limits),
      el("p", { class: "muted mx-small", text: `${limitTxt(me.limits, me.labels)} · Your files: ${me.home}` })]));
    const dbCard = el("div", {});
    const draw = () => {
      dbCard.innerHTML = "";
      const name = el("input", { type: "text", placeholder: "shop", autocomplete: "off" });
      const pw = el("input", { type: "text", autocomplete: "off", placeholder: "at least 8 characters" });
      dbCard.append(card(`My databases (${db.databases.length}${db.limit ? ` of ${db.limit}` : ""})`, [
        !db.available ? el("p", { class: "muted", text: "MySQL/MariaDB isn't installed on this server." }) : el("div", { class: "mx-list" }, db.databases.length ? db.databases.map((x) => el("div", { class: "mx-list-row" }, [
          icon("database", 16), el("b", { class: "grow", text: x.name }), el("span", { class: "muted", text: `${x.size} · ${x.tables} tables · user ${x.name}@localhost` }),
          armed("Delete", "Click again — deletes all its data", () => call(() => API.hostingMyDbDrop(x.name), "Database deleted", reload), "btn-ghost")])) : [el("p", { class: "muted", text: "No databases yet." })]),
        db.available ? el("div", { class: "mx-grid2" }, [field(`New database (${db.prefix}<name>)`, name), field("Its user's password", el("div", { class: "op-pwrow" }, [pw, btn("Generate", () => { pw.value = genPw(); }, "btn-ghost")]))]) : null,
        db.available ? el("div", { class: "toolbar" }, [btn("Create database and user", () => call(() => API.hostingMyDbCreate(name.value.trim(), pw.value), "Created — the user has the same name as the database", reload), "btn-primary")]) : null,
      ]));
    };
    const reload = async () => { try { db = await API.hostingMyDb(); draw(); } catch (e) {} };
    draw();
    body.children[0].after(dbCard);
  }

  // ======================================================================
  //  Security → Global Security (one place for every security tool)
  // ======================================================================
  async function viewGlobalSecurity(root) {
    root.append(pageHead("Global Security", "Every security tool in one place, with its current state. Click a card to open it."));
    const body = el("div", {});
    root.append(body);
    const S = {};
    // Each status call runs on its own and updates its card when it lands (some, like listing every
    // certificate, are slow) — the page and the cards are usable straight away.
    const withTimeout = (p, ms) => Promise.race([p, new Promise((r) => setTimeout(() => r(undefined), ms))]);
    const grab = (k, fn) => withTimeout(fn().catch(() => undefined), 9000).then((d) => { if (d !== undefined) S[k] = d; });
    const on = (t) => ({ text: t || "on", tone: "good" });
    const off = (t) => ({ text: t || "off", tone: "dim" });
    const warn = (t) => ({ text: t, tone: "warn" });
    const num0 = (n) => (n || 0);
    // key view, icon, title, description, status() -> {text,tone} | null, and whether it's a core hardening item
    const TOOLS = [
      { view: "modsec", icon: "shield", title: "WAF Firewall", desc: "Blocks SQL injection, XSS and other web attacks (ModSecurity + OWASP CRS).", core: true,
        status: () => !S.waf ? null : (S.waf.installed ? (S.waf.module_on && S.waf.enabled !== false ? on(S.waf.mode === "detect" ? "detect only" : "blocking") : off("installed, off")) : off("not installed")) },
      { view: "leech", icon: "trap", title: "Fail2ban", desc: "Bans IPs that repeatedly fail to log in (SSH, panel, mail, FTP…).", core: true,
        status: () => !S.f2b ? null : (S.f2b.installed ? (S.f2b.active ? on(`active · ${num0(S.f2b.jails && S.f2b.jails.length)} jails`) : warn("installed, stopped")) : off("not installed")) },
      { view: "ipblocker", icon: "ban", title: "IP Blocker & Trust", desc: "Ban or trust any address at the firewall; see where each ban came from.",
        status: () => !S.guard ? null : on(`${num0(S.guard.bans && S.guard.bans.length)} banned · ${num0(S.guard.trusted && S.guard.trusted.length)} trusted`) },
      { view: "netmon", icon: "network", title: "Network Monitor", desc: "Who tried to reach this server — connection attempts, logins and VPN handshakes.",
        status: () => null },
      { view: "security", icon: "key", title: "Two-Factor Auth", desc: "A one-time code from your phone on top of your password, for the owner login.", core: true,
        status: () => !S.twofa ? null : (S.twofa.enabled ? on() : warn("off — recommended")) },
      { view: "panelhttps", icon: "lock", title: "Panel HTTPS", desc: "Encrypt the connection to this panel; switch to a trusted certificate.", core: true,
        status: () => !S.https ? null : (S.https.source && S.https.source !== "none" ? on(S.https.source === "self" ? "self-signed" : "trusted") : off()) },
      { view: "autossl", icon: "autossl", title: "AutoSSL", desc: "Free Let's Encrypt certificates for every site and the mail host, renewed automatically.",
        status: () => !S.autossl ? null : (S.autossl.enabled ? on() : off()) },
      { view: "ssl", icon: "lock", title: "SSL/TLS Certificates", desc: "Every certificate on the server: issue, renew, upload or inspect.",
        status: () => !S.ssl ? null : on(`${num0(S.ssl.certs && S.ssl.certs.length)} certs`) },
      { view: "isolation", icon: "t_isolate", title: "Site Isolation", desc: "Run each website as its own user so one hacked site can't reach the others.",
        status: () => { if (!S.iso || !S.iso.sites) return null; const sites = Object.values(S.iso.sites); const n = sites.filter((x) => x.on).length; return n ? on(`${n} isolated`) : off("none isolated"); } },
      { view: "ssh", icon: "key", title: "SSH Access", desc: "SSH keys, and whether password login is allowed.", status: () => null },
      { view: "tokens", icon: "token", title: "API Tokens", desc: "Tokens that let scripts or other servers use this panel's API.",
        status: () => !S.tokens ? null : on(`${num0(S.tokens.tokens ? S.tokens.tokens.length : (Array.isArray(S.tokens) ? S.tokens.length : 0))} tokens`) },
      { view: "hotlink", icon: "link", title: "Hotlink Protection", desc: "Stop other sites from embedding your images and files.", status: () => null },
      { view: "virus", icon: "virus", title: "Antivirus", desc: "Scan files for malware with ClamAV.",
        status: () => !S.av ? null : (S.av.available ? on("ready") : off("not installed")) },
      { view: "activity", icon: "t_activity", title: "Activity Log", desc: "Who changed what in this panel, from where — plus every login.", status: () => null },
      { view: "fixperms", icon: "home", title: "Fix Permissions", desc: "Reset a website's file ownership and permissions to safe values.", status: () => null },
      { view: "firewall", icon: "firewall", title: "Firewall (ufw)", desc: "Which ports are open to the internet.", core: true,
        status: () => !S.fw ? null : (!S.fw.available ? off("not installed") : (S.fw.active ? on("active") : warn("inactive"))) },
      { view: "alerts", icon: "t_bell", title: "Alerts & Slack", desc: "Be told about attacks, failures and problems — by email, Telegram, webhook or Slack.",
        status: () => (S.slack && S.slack.enabled) ? on("Slack on") : null },
    ];
    // Render the grid at once; each card carries a status slot that fills in when its call lands.
    const hero = el("div", { class: "card mx-hero" }, el("div", { class: "loading", text: "Checking your defences…" }));
    body.append(hero);
    const slots = new Map();
    body.append(el("div", { class: "gs-grid" }, TOOLS.map((t) => {
      const slot = el("span", { class: "gs-status" });
      slots.set(t, slot);
      return el("button", { type: "button", class: "card gs-card", onclick: () => navigate(t.view) }, [
        el("div", { class: "gs-head" }, [el("span", { class: "gs-ico" }, icon(t.icon, 20)), el("b", { class: "grow", text: t.title }), slot]),
        el("p", { class: "muted gs-desc", text: t.desc }),
        el("span", { class: "gs-open", text: "Open →" }),
      ]);
    })));
    const paint = () => {
      TOOLS.forEach((t) => {
        const s = t.status && t.status();
        const slot = slots.get(t);
        slot.innerHTML = "";
        if (s) slot.append(pill(s.text, s.tone));
        else if (t.core) slot.append(pill("check", "warn"));
      });
      const core = TOOLS.filter((t) => t.core).map((t) => t.status && t.status());
      const done = core.every((s) => s !== null && s !== undefined);
      const onCount = core.filter((s) => s && s.tone === "good").length;
      hero.className = `card mx-hero ${!done ? "" : onCount === core.length ? "good" : onCount >= core.length - 1 ? "" : "warn"}`;
      hero.innerHTML = "";
      hero.append(el("div", { class: "mx-hero-ico" }, icon("shield", 28)),
        el("div", { class: "mx-hero-txt" }, [
          el("h3", { text: `${onCount} of ${core.length} core protections on` }),
          el("p", { class: "muted", text: onCount === core.length ? "WAF, Fail2ban, two-factor login, Panel HTTPS and the firewall are all on. Nicely hardened." : "Turn on the ones marked below to harden this server: two-factor login, the WAF, Fail2ban, Panel HTTPS and the firewall." }),
        ]));
    };
    // Fire all status calls; repaint as each resolves.
    [["guard", API.guard], ["twofa", API.twofaStatus], ["waf", API.waf], ["f2b", API.fail2ban], ["fw", API.firewall],
     ["autossl", API.autossl], ["iso", API.isolation], ["av", API.avStatus], ["https", API.panelHttps],
     ["tokens", API.tokens], ["ssl", API.sslCerts], ["slack", () => API.slack()]].forEach(([k, fn]) => grab(k, fn).then(paint));
    paint();
  }

  return { activity: viewActivity, alerts: viewAlerts, schedbackups: viewSchedBackups, updates: viewUpdates, autossl: viewAutoSSL, isolation: viewIsolation,
    dockerapps: viewDockerApps, servers: viewServers, mysites: viewMySites, panelusers: viewPanelUsers, wptoolkit: viewWPToolkit, migrate: viewMigrate,
    hostaccounts: viewHostAccounts, hostplans: viewHostPlans, hostresellers: viewHostResellers, globalsec: viewGlobalSecurity };
};
