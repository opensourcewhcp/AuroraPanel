/* AuroraPanel, running the server: Activity Log, Alerts, Scheduled Backups, Updates, AutoSSL.
   Loaded before app.js; app.js calls window.AuroraOps(ui) once with its helpers (and extras.js's). */
window.AuroraOps = (ui) => {
  "use strict";
  const { el, icon, btn, pill, field, sw, toast, popNotice, API, navigate, state, openModal, closeModal, copyText, fmtBytes, ago, downloadText,
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
    root.append(pageHead("Activity Log", "Every change made in this panel, who did it, from which address, and whether it worked, plus logins and what the background tasks did on their own. Passwords and keys are never recorded.",
      [btn("Export CSV", () => {
        if (!d) return;
        const esc = (v) => { let s = String(v ?? ""); if (/^[=+\-@\t\r]/.test(s)) s = "'" + s; return `"${s.replace(/"/g, '""')}"`; };
        downloadText(`activity-${new Date().toISOString().slice(0, 10)}.csv`, ["time,user,ip,action,result,status",
          ...d.entries.map((e) => [new Date(e.ts * 1000).toISOString(), e.user, e.ip, e.action, e.ok ? "ok" : "failed", e.status].map(esc).join(","))].join("\n"), "text/csv");
      }, "btn-ghost"), btn("Clean up", () => cleanUp(), "btn-ghost")]),
      el("div", { class: "card em-pad0" }, [el("div", { class: "mx-toolbar" }, [search, userSel, el("label", { class: "mx-live" }, [failSw, el("span", { text: "Failures only" })]), el("span", { class: "grow" }),
        seg([[1, "24 h"], [7, "7 days"], [30, "30 days"], [90, "90 days"]], days, (v) => { days = v; LS.set("act.days", v); load(); })]), list]));
    // Take entries out of the log; a copy goes to the Recycle Bin (restores into the backup folder) unless unticked.
    function cleanUp() {
      const modes = [["tests", "Entries from the test suite", "Requests the panel's own test run made (user tester, address testclient)."],
        ["failed", "Failed attempts only", "Every entry that ended in an error, including failed logins."],
        ["older", "Older than 30 days", "Anything recorded more than 30 days ago."],
        ["all", "Everything", "The whole log, all days."]];
      let mode = "tests";
      const radios = modes.map(([v, t, dsc]) => { const r = el("input", { type: "radio", name: "act-purge", value: v, onchange: () => { mode = v; } }); if (v === mode) r.checked = true;
        return el("label", { class: "dm-check act-purge-opt" }, [r, el("span", {}, [el("b", { text: t }), el("small", { class: "muted", text: dsc })])]); });
      const keep = el("input", { type: "checkbox" }); keep.checked = true;
      const go = el("button", { class: "btn btn-danger", text: "Remove", onclick: async () => {
        go.disabled = true;
        try {
          const r = await API.auditPurge(mode, 30, keep.checked);
          closeModal();
          popNotice({ title: `${r.removed} entr${r.removed === 1 ? "y" : "ies"} removed`, text: r.archive ? `A copy, ${r.archive.name}, is in the File Manager's Recycle Bin; restoring it puts it in the backup folder.` : (r.removed ? "No copy was kept." : "Nothing matched."), kind: "good", icon: "check", ms: 9000 });
          load();
        } catch (e) { toast(e.message, "bad"); go.disabled = false; }
      } });
      openModal("Clean up the Activity Log", el("div", { class: "dm-form" }, [
        el("p", { class: "muted", text: "Pick what to take out of the log." }), ...radios,
        el("label", { class: "dm-check", style: "margin-top:10px" }, [keep, el("span", { text: " Keep a copy in the Recycle Bin (activity-log-<date>.jsonl); restoring it lands in the panel's backup folder" })]),
      ]), [go]);
    }
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
      if (d.total > 1500) list.append(el("p", { class: "muted mx-p", style: "padding:0 16px 14px", text: `Showing 1,500 of ${num(d.total)}, narrow the search or export.` }));
    }
    function detail(e) {
      openModal("Activity", el("div", {}, [
        el("div", { class: "mx-kv" }, [el("span", { text: "When" }), el("span", { text: new Date(e.ts * 1000).toLocaleString() })]),
        el("div", { class: "mx-kv" }, [el("span", { text: "Who" }), el("span", { text: e.user })]),
        el("div", { class: "mx-kv" }, [el("span", { text: "From" }), e.ip ? btn(e.ip, () => { closeModal(); ui.ipCard && ui.ipCard(e.ip); }, "btn-ghost") : el("span", { text: ", " })]),
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
    root.append(pageHead("Alerts", "Get told when something needs you: a disk filling up, a service down, a certificate about to expire, an attack wave, a failed backup, waiting security updates, a hot or under-powered Pi. Checked every minute, even when the panel itself is down."));
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
      const bot = el("input", { type: "password", autocomplete: "off", placeholder: sl.bot_token_set ? "(saved, leave empty to keep)" : "xoxb-…" });
      const app = el("input", { type: "password", autocomplete: "off", placeholder: sl.app_token_set ? "(saved, leave empty to keep)" : "xapp-…" });
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
      slackCard.append(card("Slack, alerts you can answer", [
        el("div", { class: "op-ch-h" }, [el("span", { class: "em-rcard-ico" }, icon("send", 18)), el("div", { class: "grow" }, [
          el("b", { text: "Every alert, plus a message for each attacker with Ban, Trust and Allow-rule buttons" }),
          el("p", { class: "muted", text: "Every button flips (Ban ⇄ Unban, Trust ⇄ Untrust), so a click can always be undone, and the message records who did what. /aurora status · alerts · ban · unban · trust · ip in any channel. Works behind a home router: no public address or open port needed." })]),
          status, on]),
        sk.error && sl.enabled ? el("p", { class: "form-error", text: sk.error }) : null,
        el("div", { class: "sl-steps" }, [
          step("1", "Create the Slack app (2 minutes)", [el("p", { class: "muted", text: "Open Slack's app page → Create New App → From a manifest → pick your workspace → paste → Create, then Install to Workspace." }),
            el("div", { class: "toolbar" }, [btn("Copy the app manifest", async () => toast(await copyText(sl.manifest) ? "Manifest copied, paste it in Slack" : "Copy failed", "good"), "btn-primary"),
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
            el("label", { class: "op-rule" }, [f2b, el("div", {}, [el("b", { text: "fail2ban bans" }), el("p", { class: "muted", text: "With Unban, handy if it was you." })])]),
          ])]),
        ]),
        el("div", { class: "toolbar" }, [btn("Save", save, "btn-primary"), sl.bot_token_set ? btn("Send a test message", () => call(() => API.slackTest(), "Test message sent, press its buttons in Slack"), "btn-ghost") : null]),
      ]));
    }
    function draw() {
      body.innerHTML = "";
      const ch = d.channels, anyOn = Object.values(ch).some((c) => c.enabled);
      const t = d.tasks || {};
      body.append(el("div", { class: `card mx-hero ${!anyOn ? "warn" : d.active.some((a) => a.level === "critical") ? "bad" : "good"}` }, [
        el("div", { class: "mx-hero-ico" }, icon("warning", 28)),
        el("div", { class: "mx-hero-txt" }, [
          el("h3", { text: !anyOn ? "Alerts are off, nothing will reach you" : d.active.length ? `${d.active.length} problem${d.active.length > 1 ? "s" : ""} right now` : "All good, nothing needs you" }),
          el("p", { class: "muted", text: `${t.timer === "active" ? "Checking every minute" : "The background checker isn't running"}${t.last_run ? ` · last check ${ago(t.last_run)}` : ""}.${anyOn ? "" : " Turn on email, Telegram or a webhook below."}` }),
        ]),
        el("div", { class: "mx-hero-act" }, [btn("Check now", async () => { const r = await call(() => API.alertsCheck(), "Checked"); if (r) { d = { ...d, ...r }; draw(); } }, "btn-ghost"),
          anyOn ? btn("Send a test alert", () => call(() => API.alertsTest(), "").then((r) => r && toast(r.sent.length ? `Sent by ${r.sent.join(", ")}${r.errors.length ? `, failed: ${r.errors.join("; ")}` : ""}` : `Failed: ${r.errors.join("; ")}`, r.sent.length ? "good" : "bad")), "btn-primary") : null]),
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
      const tgTok = el("input", { type: "password", placeholder: tg.token_set ? "(saved, leave empty to keep)" : "123456789:AAE…", autocomplete: "off" });
      const tgChat = el("input", { type: "text", value: tg.chat_id || "", placeholder: "123456789" });
      const whKind = el("select", { class: "em-select" }, [["generic", "JSON (any service)"], ["discord", "Discord"], ["slack", "Slack"], ["ntfy", "ntfy (phone push)"]].map(([v, l]) => el("option", { value: v, text: l })));
      whKind.value = wh.kind || "generic";
      const whUrl = el("input", { type: "url", placeholder: wh.url_hint ? `${wh.url_hint} (saved, leave empty to keep)` : "https://…" });
      const chBox = (ico, title, sub, onSw, fields, hint) => el("div", { class: "op-ch" }, [el("div", { class: "op-ch-h" }, [el("span", { class: "em-rcard-ico" }, icon(ico, 18)), el("div", { class: "grow" }, [el("b", { text: title }), el("p", { class: "muted", text: sub })]), onSw]),
        el("div", { class: "op-ch-f" }, fields), hint ? el("p", { class: "muted mx-small", text: hint }) : null]);
      const saveCh = btn("Save channels", () => call(() => API.alertsSave({ channels: {
        email: { enabled: emOn.querySelector("input").checked, to: emTo.value.trim(), from: emFrom.value },
        telegram: { enabled: tgOn.querySelector("input").checked, token: tgTok.value.trim(), chat_id: tgChat.value.trim() },
        webhook: { enabled: whOn.querySelector("input").checked, url: whUrl.value.trim(), kind: whKind.value } } }), "Channels saved", (r) => { d = { ...d, ...r }; draw(); }), "btn-primary");
      body.append(card("Where alerts go", [el("div", { class: "op-chs" }, [
        chBox("mail", "Email", d.sendmail ? "Sent by this server's mail system." : "Needs the mail server (Email section), or use Telegram/webhook.", emOn,
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
    root.append(pageHead("Scheduled Backups", "Automatic backups that leave this machine, to cloud storage, another server or a USB disk, so a dead SD card, a hacked site or a deleted file is never the end. Encrypted before they leave, old copies cleaned up for you.",
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
        d.ssh_key ? el("div", { class: "op-key" }, [el("p", { class: "muted mx-small", text: "SFTP destinations log in with this key, add it to ~/.ssh/authorized_keys on the other server:" }),
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
          el("div", {}, [el("span", { class: "muted", text: "Last run" }), el("b", { text: last.ts ? `${ago(last.ts)}${last.size ? ` · ${fmtBytes(last.size)}` : ""}${last.secs != null ? ` · ${dur(last.secs)}` : ""}` : ", " })]),
          el("div", {}, [el("span", { class: "muted", text: "Next run" }), el("b", { text: p.enabled && p.next ? `${t2s(p.next)} (${timeIn(p.next)})` : "paused" })]),
        ]),
        last.ok === false ? el("div", { class: "mx-note" }, [icon("warning", 16), el("span", { text: last.error || "Failed, see the log." })]) : null,
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
            el("td", { text: s.time ? ago(s.time) : ", " }),
            el("td", { class: "mx-actions" }, btn("Restore…", async (e) => { e.target.disabled = true; e.target.textContent = "Fetching…";
              const x = await call(() => API.schedFetch(p.id, s.dest, s.name), "Copy fetched, choose what to restore");
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
      const pass = el("input", { type: "text", placeholder: p.encrypt ? "(unchanged, leave empty)" : "Leave empty to generate a strong one", autocomplete: "off" });
      const enabled = el("input", { type: "checkbox" }); enabled.checked = p.enabled !== false;
      drawWhen();
      openModal(isNew ? "New backup plan" : `Edit “${p.name}”`, el("div", { class: "em-form" }, [
        field("Name", name),
        el("div", { class: "mx-sub" }, "What"), el("div", { class: "op-whats" }, checks), paths,
        el("div", { class: "mx-sub" }, "When"),
        el("div", { class: "op-when" }, [seg(Object.entries(FREQ), freq, (v) => { freq = v; drawWhen(); }), field(freq === "hourly" ? "Minute (hh:MM)" : "Time", time), extra]),
        el("div", { class: "mx-sub" }, "Where & how long"),
        dests.length ? el("div", { class: "op-destpick" }, dests) : el("p", { class: "muted", text: "No destinations yet, copies stay on this machine only (add one later for real safety)." }),
        el("div", { class: "mx-grid2" }, [field("Copies to keep at each destination", keep, "Older ones are deleted after each run."), field("Copies also kept on this machine", keepLocal, "0 = none (saves disk space).")]),
        el("label", { class: "dm-check" }, [enc, el("span", { text: "Encrypt with AES-256 before sending (recommended)" })]), field("Passphrase", pass, "Saved on this server so backups run unattended, but keep a copy elsewhere: without it, the off-site copies can't be opened."),
        el("label", { class: "dm-check" }, [enabled, el("span", { text: "Plan is active" })]),
      ]), [el("button", { class: "btn btn-primary", text: isNew ? "Create plan" : "Save", onclick: () => call(() => API.schedPlanSave({
        id: p.id, name: name.value.trim(), freq, time: time.value, weekday: +wday.value, monthday: +mday.value, keep: +keep.value, keep_local: +keepLocal.value,
        dests: dests.map((l) => l.querySelector("input")).filter((c) => c.checked).map((c) => c.value), encrypt: enc.checked, passphrase: pass.value, enabled: enabled.checked,
        what: { ...Object.fromEntries(checks.map((l) => [l.querySelector("input").dataset.k, l.querySelector("input").checked])), paths: paths.value.split("\n").map((x) => x.trim()).filter(Boolean) },
      }), isNew ? "Plan created, it runs on schedule; “Back up now” tests it right away" : "Saved", () => { closeModal(); load(); }) })]);
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
          box.append(field("Provider", prov), el("div", { class: "mx-grid2" }, [field("Access key ID", inp("access_key", x ? "(saved, leave empty to keep)" : "")), field("Secret access key", inp("secret_key", x ? "(saved)" : "", "password"))]),
            el("div", { class: "mx-grid2" }, [field("Bucket", inp("bucket", "my-backups", "text", v("bucket"))), field("Folder in the bucket (optional)", inp("prefix", "aurora", "text", v("prefix")))]),
            el("div", { class: "mx-grid2" }, [field("Endpoint", inp("endpoint", "R2: https://<account>.r2.cloudflarestorage.com", "text", v("endpoint")), "Leave empty for Amazon S3."), field("Region", inp("region", "auto / us-east-1", "text", v("region")))]));
        }
        if (type === "b2") box.append(el("div", { class: "mx-grid2" }, [field("Application key ID", inp("access_key", x ? "(saved, leave empty to keep)" : "")), field("Application key", inp("secret_key", x ? "(saved)" : "", "password"))]),
          el("div", { class: "mx-grid2" }, [field("Bucket", inp("bucket", "my-backups", "text", v("bucket"))), field("Folder (optional)", inp("prefix", "aurora", "text", v("prefix")))]));
        if (type === "sftp") box.append(el("div", { class: "mx-grid2" }, [field("Host", inp("host", "backup.example.com", "text", v("host"))), field("Port", inp("port", "22", "number", v("port") || "22"))]),
          el("div", { class: "mx-grid2" }, [field("User", inp("user", "backup", "text", v("user"))), field("Folder", inp("path", "backups/aurora", "text", v("prefix")))]),
          field("Password (optional)", inp("password", "Leave empty to use the key shown on the Scheduled Backups page", "password")));
        if (type === "webdav") {
          const vendor = el("select", { class: "em-select" }, [["nextcloud", "Nextcloud"], ["owncloud", "ownCloud"], ["other", "Other WebDAV"]].map(([a, b]) => el("option", { value: a, text: b }))); vendor.value = v("vendor") || "nextcloud"; f.vendor = vendor;
          box.append(field("Server", vendor), field("WebDAV URL", inp("url", "https://cloud.example.com/remote.php/dav/files/USER/", "url", v("url"))),
            el("div", { class: "mx-grid2" }, [field("User", inp("user", "", "text", v("user"))), field("App password", inp("password", x ? "(saved, leave empty to keep)" : "", "password"))]), field("Folder", inp("path", "Backups/aurora", "text", v("prefix"))));
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
      if (j) { toast(j.status === "done" ? "Updates installed" : "Updating failed, see the log", j.status === "done" ? "good" : "bad"); load(); }
    }
    function draw() {
      body.innerHTML = "";
      if (!d.supported) { body.append(el("p", { class: "empty", text: "This system has no apt." })); return; }
      const rb = d.reboot;
      body.append(el("div", { class: `card mx-hero ${d.security ? "bad" : d.total ? "warn" : "good"}` }, [
        el("div", { class: "mx-hero-ico" }, icon(d.total ? "packages" : "check", 28)),
        el("div", { class: "mx-hero-txt" }, [el("h3", { text: d.total ? `${d.total} update${d.total > 1 ? "s" : ""} available${d.security ? `, ${d.security} for security` : ""}` : "Everything is up to date" }),
          el("p", { class: "muted", text: `Checked ${d.checked ? ago(d.checked) : "never"}${d.auto.enabled ? ` · automatic ${d.auto.mode === "all" ? "updates" : "security updates"} on` : " · automatic updates off"}.${d.error ? " Last check had a problem: " + d.error : ""}` })]),
        el("div", { class: "mx-hero-act" }, [btn("Check now", async (e) => { e.target.disabled = true; e.target.textContent = "Checking…"; await call(() => API.updatesRefresh()); load(); }, "btn-ghost"),
          d.total ? btn(`Install all ${d.total}`, () => call(() => API.updatesInstall([]), "Updating…", (r) => watch(r.job)), "btn-primary") : null]),
      ]));
      if (rb.required) body.append(el("div", { class: "card op-reboot" }, [icon("refresh", 20), el("div", { class: "grow" }, [el("b", { text: "Restart needed to finish updating" }),
        el("p", { class: "muted", text: `${rb.packages.length ? rb.packages.slice(0, 6).join(", ") + (rb.packages.length > 6 ? "…" : "") : "System packages"} were updated. Websites and mail are offline for about a minute while it restarts.` })]),
        armed("Restart in 1 minute", "Click again to restart", () => call(() => API.reboot(1), "Restarting in 1 minute, the panel comes back by itself"), "btn-primary"),
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
    root.append(pageHead("AutoSSL", "A free, trusted HTTPS certificate for every website and the mail server, requested, installed and renewed by itself. Names that don't point to this server are skipped until their DNS does.",
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
      const p80 = d.port80;
      if (d.enabled && p80 && p80.verdict === "closed") body.append(el("div", { class: "card", style: "border-color:rgba(255,179,71,.35)" }, [
        el("h3", { text: "Port 80 is closed from the internet" }),
        el("p", { class: "muted", text: `Let's Encrypt proves you own a name by fetching http://<name>/.well-known/… from the internet, so TCP port 80 must reach this Pi${p80.lan_ip ? ` (${p80.lan_ip})` : ""}. Checked from outside ${ago(p80.ts)}: closed${p80.public_ip ? ` at ${p80.public_ip}` : ""}. Nothing was requested, a failed try only counts against Let's Encrypt's limits.` }),
        p80.steps && p80.steps.length ? el("ol", { style: "margin:0 0 12px 18px;padding:0;display:grid;gap:6px;font-size:13px" }, p80.steps.map((t) => el("li", { text: t }))) : null,
        el("div", { class: "toolbar", style: "margin:0" }, [
          btn("Check port 80 again", (e) => { e.target.disabled = true; call(() => API.portCheck(80, "tcp"), null, (r) => { toast(r.verdict === "open" ? "Port 80 is open from the internet, click Run now" : r.verdict === "closed" ? "Still closed from the internet" : "Couldn't verify from outside, try Run now", r.verdict === "open" ? "good" : "bad"); e.target.disabled = false; if (r.verdict === "open") { d.port80 = { ...p80, verdict: "open", ts: Date.now() / 1000 }; draw(); } }).then((ok) => { if (!ok) e.target.disabled = false; }); }, "btn-primary"),
          p80.upnp ? btn("Open it with UPnP", () => call(() => API.upnpOpen(80, "tcp"), "Asked the router to forward port 80, check again in a few seconds"), "btn-ghost") : null,
          p80.router_url ? el("a", { class: "btn btn-ghost", href: p80.router_url, target: "_blank", rel: "noopener", text: "Open the router" }) : null,
          btn("Port check tool", () => navigate("portcheck"), "btn-ghost"),
        ].filter(Boolean)),
      ]));
      if (!d.enabled) body.append(card("Turn on AutoSSL", [
        field("Email for expiry notices", email, "Let's Encrypt writes here only if a certificate is about to expire and renewal keeps failing."),
        el("label", { class: "dm-check" }, [agree, el("span", {}, ["I agree to the ", el("a", { href: "https://letsencrypt.org/repository/", target: "_blank", rel: "noopener noreferrer", text: "Let's Encrypt Subscriber Agreement" })])]),
        el("div", { class: "toolbar" }, [btn("Turn on AutoSSL", () => call(() => API.autosslSave({ email: email.value.trim(), agreed: agree.checked, enabled: true }), "AutoSSL on, click Run now to start", (r) => { d = r; draw(); }), "btn-primary")])]));
      // per site
      body.append(card("Your sites", [d.plan.length ? el("div", { class: "op-sites" }, d.plan.map((it) => {
        const res = d.results[it.site];
        return el("div", { class: "op-site" }, [
          el("div", { class: "op-site-h" }, [icon(it.mail ? "mail" : "globe", 16), el("b", { text: it.site }), it.mail ? pill("mail server") : null, el("span", { class: "grow" }),
            d.enabled && it.names.some((r) => r.state === "missing" || r.state === "renew") ? btn("Get it now", () => call(() => API.autosslRun(it.site), "Requesting…", () => setTimeout(load, 2000)), "btn-ghost") : null]),
          it.note ? el("p", { class: "muted mx-small", text: it.note }) : null,
          el("div", { class: "op-names" }, it.names.map((r) => el("div", { class: "op-name" }, [el("code", { text: r.name }), pill(AS[r.state][0] + (r.state === "ok" || r.state === "renew" ? ` · ${r.days} days` : ""), AS[r.state][1]),
            el("span", { class: "muted mx-small mx-ell", text: r.state === "elsewhere" ? `→ ${r.addrs.join(", ")}` : r.state === "nodns" ? "add an A record in the Zone Editor" : r.cert ? `certificate “${r.cert}”` : "" })]))),
          res && res.ok === false ? el("div", { class: "mx-note" }, [icon("warning", 16), el("span", { text: `${t2s(res.ts)}: ${res.error}` })]) : res && res.ok ? el("p", { class: "muted mx-small", text: `✓ ${t2s(res.ts)}${res.note ? ", " + res.note : ""}` }) : null,
        ]);
      })) : el("p", { class: "muted", text: "No websites yet." })]));
      // wildcards
      if (d.zones.length) body.append(card("Wildcard certificates", [el("p", { class: "muted", text: "One certificate for every subdomain (*.example.com), handy for Dynamic DNS names and Docker apps. Needs this server to answer DNS for the domain: the panel adds the proof record itself." }),
        el("div", { class: "mx-list" }, d.zones.map((z) => { const r = d.results[`*.${z}`]; const have = d.certs.find((c) => c.names.includes(`*.${z}`));
          return el("div", { class: "mx-list-row" }, [el("code", { text: `*.${z}` }), have ? pill(`valid · ${Math.round((have.expires - Date.now() / 1000) / 86400)} days`, "good") : r && r.ok === false ? pill("failed", "bad") : pill("none"),
            el("span", { class: "grow muted mx-small mx-ell", text: r && r.ok === false ? r.error : have ? "Renewed automatically by Certbot" : "" }),
            d.agreed ? btn(have ? "Renew" : "Get wildcard", () => call(() => API.autosslWildcard(z), "Requesting, this takes 1–4 minutes (waiting for DNS)", () => setTimeout(load, 60000)), "btn-ghost") : null]); }))]));
    }
    load();
  }

  // ======================================================================
  //  Security → Site Isolation
  // ======================================================================
  async function viewIsolation(root) {
    root.append(pageHead("Site Isolation", "Give every website its own locked room: its PHP runs as its own user and can only open its own files. A hacked plugin on one site can then no longer read the others' files or database passwords. Uses almost no memory, a site's PHP only runs while it's being visited."));
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
      if (j) toast(j.status === "done" ? label : "Something went wrong, see the log", j.status === "done" ? "good" : "bad");
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
        s.on ? btn("Fix permissions", () => call(() => API.isolationFix(s.site), "Ownership re-applied, PHP can write its files again"), "btn-ghost") : null,
        s.on ? armed("Turn off", "Click again", () => call(() => API.isolationOff(s.site), `${s.site} shares PHP again`, load), "btn-ghost")
          : btn("Isolate", () => call(() => API.isolationOn(s.site), "Isolating…", (r) => watch(r.job, `${s.site} is isolated`)), "btn-primary"),
      ])))]),
      el("p", { class: "muted mx-small mx-p", text: "Uploaded a site as root (File Manager, a restore)? “Fix permissions” gives the files back to the site so it can update itself. Some old plugins that run shell commands (exec, system) won't work while isolated, that's exactly what attackers use." }));
    }
    load();
  }

  // ======================================================================
  //  Applications → Docker (every container: the catalog apps, custom ones, and any made elsewhere)
  // ======================================================================
  const APP_HUE = (s) => { let h = 0; for (const c of String(s)) h = (h * 31 + c.charCodeAt(0)) % 360; return h; };
  // Original artwork: a cargo boat carrying containers (no third-party logo).
  const DK_ART = `<svg viewBox="0 0 260 150" xmlns="http://www.w3.org/2000/svg" aria-hidden="true">
    <defs><linearGradient id="dkh" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="#2aa7e8"/><stop offset="1" stop-color="#0e5c95"/></linearGradient>
    <linearGradient id="dkw1" x1="0" y1="0" x2="1" y2="0"><stop offset="0" stop-color="#7fd0ff"/><stop offset="1" stop-color="#3fb3f0"/></linearGradient></defs>
    <g stroke="#0a3a5c" stroke-width="2.2" stroke-linejoin="round">
      <g><rect x="80" y="34" width="34" height="20" rx="2" fill="#ff8a3d"/><path d="M89 34v20M97 34v20M105 34v20" stroke-opacity=".45"/></g>
      <g><rect x="62" y="56" width="34" height="20" rx="2" fill="#4fc3f7"/><path d="M71 56v20M79 56v20M87 56v20" stroke-opacity=".45"/></g>
      <g><rect x="98" y="56" width="34" height="20" rx="2" fill="#ffd166"/><path d="M107 56v20M115 56v20M123 56v20" stroke-opacity=".45"/></g>
      <g><rect x="134" y="56" width="34" height="20" rx="2" fill="#8be28f"/><path d="M143 56v20M151 56v20M159 56v20" stroke-opacity=".45"/></g>
      <g><rect x="44" y="78" width="34" height="20" rx="2" fill="#ffd166"/><path d="M53 78v20M61 78v20M69 78v20" stroke-opacity=".45"/></g>
      <g><rect x="80" y="78" width="34" height="20" rx="2" fill="#8be28f"/><path d="M89 78v20M97 78v20M105 78v20" stroke-opacity=".45"/></g>
      <g><rect x="116" y="78" width="34" height="20" rx="2" fill="#ff8a3d"/><path d="M125 78v20M133 78v20M141 78v20" stroke-opacity=".45"/></g>
      <g><rect x="152" y="78" width="34" height="20" rx="2" fill="#4fc3f7"/><path d="M161 78v20M169 78v20M177 78v20" stroke-opacity=".45"/></g>
      <rect x="192" y="66" width="26" height="32" rx="3" fill="#e9f6ff"/><rect x="198" y="72" width="14" height="8" rx="1.5" fill="#2aa7e8"/><path d="M205 56v10" stroke-width="3"/>
      <path d="M26 98h206l-12 24a10 10 0 0 1-9 6H54a10 10 0 0 1-9-6z" fill="url(#dkh)"/>
      <path d="M38 110h184" stroke="#e9f6ff" stroke-opacity=".55" stroke-width="3"/>
    </g>
    <path d="M22 44c4-4 8-4 12 0M40 36c4-4 8-4 12 0" fill="none" stroke="#e9f6ff" stroke-width="2" stroke-linecap="round" opacity=".8"/>
    <path d="M0 126c20-10 40-10 60 0s40 10 60 0 40-10 60 0 40 10 60 0 20-6 20-6v30H0z" fill="url(#dkw1)" opacity=".9"/>
    <path d="M0 136c20-8 40-8 60 0s40 8 60 0 40-8 60 0 40 8 60 0 20-5 20-5v19H0z" fill="#1d8fd1"/>
  </svg>`;
  const DK_WAVES = `<svg viewBox="0 0 1200 60" preserveAspectRatio="none" xmlns="http://www.w3.org/2000/svg" aria-hidden="true">
    <path d="M0 30c60-20 120-20 180 0s120 20 180 0 120-20 180 0 120 20 180 0 120-20 180 0 120 20 180 0 120-20 120-20v50H0z" fill="#3fb3f0" opacity=".35"/>
    <path d="M0 42c60-16 120-16 180 0s120 16 180 0 120-16 180 0 120 16 180 0 120-16 180 0 120 16 180 0 120-16 120-16v34H0z" fill="#1d8fd1" opacity=".55"/>
  </svg>`;
  const DK_TONE = { running: "good", paused: "warn", restarting: "warn", exited: "dim", created: "dim", dead: "bad", missing: "bad" };
  // ---- Docker action queue: Stop/Start/Restart clicks line up and run one after another; a panel at the
  //      right shows what is in the queue, what is being done now and what just finished. ----
  const DK_VERB = { stop: ["Stopping", "Stopped"], start: ["Starting", "Started"], restart: ["Restarting", "Restarted"], pause: ["Pausing", "Paused"], unpause: ["Resuming", "Resumed"], kill: ["Killing", "Killed"] };
  const dkQueue = {
    items: [], busy: false, panel: null,
    add(job) {
      if (this.items.some((j) => j.key === job.key && j.state !== "done" && j.state !== "failed")) { this.render(); return; }
      this.items.push({ ...job, state: "queued" });
      if (this.panel) this.panel.hidden = false;
      this.render(); this.pump();
    },
    async pump() {
      if (this.busy) return;
      const job = this.items.find((j) => j.state === "queued");
      if (!job) return;
      this.busy = true; job.state = "working"; this.render();
      try { await job.run(); job.state = "done"; } catch (e) { job.state = "failed"; job.error = e.message || "Failed"; }
      this.busy = false; this.render();
      try { job.after && job.after(); } catch (e) {}
      setTimeout(() => { this.items = this.items.filter((j) => j !== job); this.render(); }, job.state === "done" ? 3000 : 9000);
      this.pump();
    },
    render() {
      if (!this.items.length) { if (this.panel) { const p = this.panel; this.panel = null; p.classList.add("out"); setTimeout(() => p.remove(), 320); } return; }
      if (!this.panel) { this.panel = el("div", { class: "pop-notice dk-queue", role: "status", "aria-live": "polite" }); document.body.append(this.panel); }
      const queued = this.items.filter((j) => j.state === "queued").length, working = this.items.some((j) => j.state === "working");
      this.panel.innerHTML = "";
      this.panel.append(
        el("div", { class: "pop-body" }, [
          el("div", { class: "pop-title" }, [el("b", { text: working || queued ? "Working on your containers" : "Done" }), queued ? pill(`${queued} in queue`, "warn") : null]),
          el("div", { class: "dk-q-list" }, this.items.map((j) => {
            const [doing, done] = DK_VERB[j.action] || [j.action, j.action];
            const txt = j.state === "queued" ? `In queue to ${j.action}` : j.state === "working" ? `${doing}…` : j.state === "failed" ? j.error : done;
            return el("div", { class: `dk-q ${j.state}` }, [
              el("span", { class: "dk-q-dot" }, j.state === "working" ? el("span", { class: "dk-q-spin" }) : icon(j.state === "done" ? "check" : j.state === "failed" ? "error" : "clock", 12)),
              el("b", { text: j.name }), el("span", { class: "muted", text: txt })]);
          })),
        ]),
        el("button", { type: "button", class: "pop-close", "aria-label": "Close", text: "✕", onclick: () => {
          this.items = this.items.filter((j) => j.state === "queued" || j.state === "working");
          if (this.items.length) this.panel.hidden = true; else this.render();
        } }));
    },
  };
  const dkIB = (ico, label, onclick, cls, disabled) => el("button", { type: "button", class: `dk-ib ${cls || ""}`, title: label, "aria-label": label, onclick, disabled: disabled ? "" : null }, icon(ico, 15));
  const dkPort = (p) => el("span", { class: `dk-port ${p.bind === "127.0.0.1" ? "lo" : ""}`, title: p.bind === "127.0.0.1" ? "Only reachable from this server (behind the web address)" : p.bind ? `Listens on ${p.bind}` : "Listens on every address",
    text: `${p.host}→${p.container}/${p.proto}` });
  const dkRows = (kind) => { const box = el("div", { class: "dk-rows" }); box.dataset.kind = kind; return box; };
  const dkMem = (s) => { const m = /^([\d.]+)\s*([KMG]i?B)/.exec(s || ""); return m && !/^0B/.test(s) ? `${m[1]} ${m[2].replace("iB", "B")}` : ""; };

  async function viewDockerApps(root) {
    const hero = el("div", { class: "dk-hero" });
    const prog = progressBox();
    const log = el("pre", { class: "log op-log", hidden: "" });
    const body = el("div", {}, el("div", { class: "loading", text: "Loading…" }));
    root.append(hero, prog.node, log, body);
    let cat = "All", filt = LS.get("dk.filt", "all"), catalogData = null, ov = null, cs = [], imgs = [];
    const hostOf = (u) => u.replace("{host}", location.hostname);
    const connHost = (bind) => (!bind || bind === "0.0.0.0" || bind === "::") ? location.hostname : bind;
    // For a service with no web page (a broker, a database…), show where to point clients instead of a dead blank.
    const connAddrs = (c) => {
      if (c.url) return [];
      const seen = new Set(), out = [];
      (c.ports || []).forEach((p) => {
        if (p.bind === "127.0.0.1" || !p.host) return;  // loopback = behind the web address, not for clients
        const a = `${connHost(p.bind)}:${p.host}`;
        if (!seen.has(a)) { seen.add(a); out.push({ addr: a, proto: p.proto }); }
      });
      return out;
    };

    function drawHero() {
      hero.innerHTML = "";
      const running = ov ? ov.containers_running || 0 : 0;
      hero.append(
        el("div", { class: "dk-hero-art", html: DK_ART, raw: true }),
        el("div", { class: "dk-hero-txt" }, [
          el("h2", { text: "Docker" }),
          el("p", { text: "Every container on this server in one place, the one-click apps from the catalog, your own custom containers, and anything started outside the panel. Start, pause, open a root shell, change ports and settings, or remove them." }),
          el("div", { class: "dk-hero-act" }, [
            btn("＋ Custom container", () => customDlg(), "btn-primary"),
            btn("Pull an image", () => pullDlg(), ""),
            btn("Clean up", () => call(() => API.dockerPrune(), "").then((r) => { if (r) { toast(`Freed ${r.reclaimed}`, "good"); load(true); } }), ""),
          ]),
        ]),
        el("div", { class: "dk-hero-stat" }, [
          ov && ov.running ? pill(`${running} running · Docker ${ov.version}`, "good") : ov && ov.installed ? pill("Docker is not running", "bad") : pill("Docker is not installed", "dim"),
          el("span", { class: "dk-hero-sub", text: ov && ov.installed ? `${ov.arch} · ${ov.root || "/var/lib/docker"}` : "System Applications → Docker → Install" }),
        ]),
        el("div", { class: "dk-waves", html: DK_WAVES, raw: true }),
      );
    }
    async function load(quiet) {
      try {
        const [o, c, i, k] = await Promise.all([API.dockerOverview(), API.dockerContainers(), API.dockerImages(), catalogData ? Promise.resolve(catalogData) : API.dockerCatalog()]);
        ov = o; cs = c.containers; imgs = i.images; catalogData = k;
      } catch (e) { if (!quiet) { body.innerHTML = ""; body.append(el("p", { class: "empty", text: e.message })); } return; }
      drawHero(); draw();
    }
    async function watch(id, label) {
      log.hidden = false; prog.node.scrollIntoView({ block: "nearest" });
      const j = await waitJob(id, (j) => { prog.set(j); log.textContent = j.output || ""; log.scrollTop = 1e9; });
      if (j) toast(j.status === "done" ? label : "Something went wrong, see the log", j.status === "done" ? "good" : "bad");
      load(true);
    }
    const act = (c, action) => dkQueue.add({ key: `${c.name}:${action}`, name: c.title || c.name, action, run: () => API.dockerAction(c.name, action), after: () => load(true) });

    function row(c) {
      const tone = DK_TONE[c.state] || "dim";
      const url = c.url ? hostOf(c.url) : "";
      const running = c.state === "running", paused = c.state === "paused";
      const memPct = parseFloat(c.mem_pct) || 0, cpu = parseFloat(c.cpu) || 0;
      return el("div", { class: `dk-row ${c.state}` }, [
        el("span", { class: "dk-ico", style: `--h:${APP_HUE(c.app || c.image)}`, text: (c.title || c.name)[0].toUpperCase() }),
        el("div", { class: "dk-name" }, [
          el("div", { class: "dk-name-t" }, [el("b", { text: c.title || c.name }),
            c.origin === "app" ? pill("catalog app", "dim") : c.origin === "custom" ? pill("custom", "dim") : c.origin === "compose" ? pill(`compose · ${c.project}`, "dim") : pill("made outside the panel", "dim")]),
          el("p", { class: "muted mx-small mx-ell", title: c.image, text: `${c.name} · ${c.image}` }),
          url ? el("a", { class: "dk-url", href: url, target: "_blank", rel: "noopener", text: url.replace(/\/$/, "") + " ↗" }) : null,
          ...(url ? [] : connAddrs(c).map((e) => el("button", { type: "button", class: "dk-conn", title: "Copy this address", onclick: async () => toast((await copyText(e.addr)) ? "Address copied" : "Copy failed", "good") },
            [icon("copy", 12), el("span", {}, [el("b", { text: e.addr }), el("span", { class: "muted", text: ` · connect your ${e.proto === "udp" ? "UDP" : ""} clients here` })])]))),
          c.tls_port ? el("p", { class: "muted mx-small", text: `HTTPS front on port ${c.tls_port} (self-signed certificate) → the app` }) : null,
        ]),
        el("div", { class: "dk-state" }, [pill(c.state || "?", tone), el("span", { class: "muted mx-small", text: c.status })]),
        el("div", { class: "dk-ports" }, c.ports.length ? c.ports.map(dkPort) : [el("span", { class: "muted mx-small", text: c.state === "running" && !c.ports.length ? "no published ports" : "" })]),
        el("div", { class: "dk-res" }, running ? [
          el("div", { class: "dk-res-l" }, [el("span", { text: "CPU" }), el("b", { text: c.cpu || "n/a" })]), el("div", { class: "dk-bar" }, el("span", { style: `width:${Math.min(100, cpu)}%` })),
          el("div", { class: "dk-res-l", title: dkMem(c.mem) ? "" : "RAM figures need memory accounting (see the note above)" }, [el("span", { text: "RAM" }), el("b", { text: dkMem(c.mem) || "n/a" })]), el("div", { class: "dk-bar" }, el("span", { style: `width:${Math.min(100, memPct)}%` })),
        ] : [el("span", { class: "muted mx-small", text: paused ? "paused, frozen in memory" : "not running" })]),
        el("div", { class: "dk-acts" }, [
          running ? dkIB("square", "Stop", () => act(c, "stop"), "bad") : paused ? dkIB("play", "Resume", () => act(c, "unpause"), "good") : dkIB("play", "Start", () => act(c, "start"), "good"),
          dkIB("refresh", "Restart", () => act(c, "restart"), "", !running && !paused),
          dkIB("pause", "Pause", () => act(c, "pause"), "", !running),
          dkIB("listing", "Logs", () => detailDlg(c, "logs")),
          ov && ov.admin ? dkIB("terminal", "Shell (root)", () => shellDlg(c), "", !running) : null,
          dkIB("gear", "Settings & details", () => detailDlg(c, "overview")),
        ]),
      ]);
    }
    function draw() {
      body.innerHTML = "";
      if (ov && ov.installed && !ov.running) body.append(el("div", { class: "mx-note" }, [icon("warning", 16), el("span", { text: "Docker is installed but not running, System Applications → Docker → Start." })]));
      const mc = ov && ov.mem_cgroup;
      if (mc && !mc.active) body.append(el("div", { class: "mx-note mx-note-dim" }, [icon("info", 16), el("span", { class: "grow", text: mc.pending
        ? "Memory accounting for containers is switched on, RAM figures and RAM limits start working after the next reboot."
        : "This system boots without memory accounting for containers (the Raspberry Pi default), so RAM figures show, and RAM limits don't apply. One click adds cgroup_enable=memory to the boot line; it takes effect after a reboot." }),
        mc.can_enable ? btn("Turn on", () => call(() => API.dockerMemCgroup(), "Done, reboot when convenient", () => load(true)), "btn-primary") : null]));
      if (ov && ov.installed) {
        const dImg = ov.disk && ov.disk.Images, dVol = ov.disk && ov.disk["Local Volumes"];
        body.append(el("div", { class: "mx-tiles mx-tiles-6" }, [
          tile("Running", String(ov.containers_running || 0), `of ${ov.containers || 0} containers`, "play", ov.containers_running ? "accent" : "", () => setFilt("running")),
          tile("Paused", String(ov.containers_paused || 0), "frozen in memory", "pause", "", () => setFilt("paused")),
          tile("Stopped", String(ov.containers_stopped || 0), "not running", "square", ov.containers_stopped ? "warnt" : "", () => setFilt("stopped")),
          tile("Images", String(ov.images || 0), dImg ? `${dImg.size} · ${dImg.reclaimable} unused` : "", "t_layers"),
          tile("Volumes", String(ov.volumes || 0), dVol ? `${dVol.size} on disk` : "", "disk"),
          tile("Docker", (ov.version || "n/a").split("+")[0], ov.arch, "t_ship"),
        ]));
      }
      const shown = cs.filter((c) => filt === "all" || (filt === "running" ? c.state === "running" : filt === "paused" ? c.state === "paused" : filt === "stopped" ? !["running", "paused"].includes(c.state)
        : filt === "panel" ? c.managed : !c.managed));
      const segBar = seg([["all", `All (${cs.length})`], ["running", "Running"], ["paused", "Paused"], ["stopped", "Stopped"], ["panel", "Panel's"], ["other", "Other"]], filt, (v) => setFilt(v));
      const containersCard = card("Containers", [
        cs.length ? (shown.length ? el("div", { class: "dk-list" }, shown.map(row)) : empty("t_ship", "Nothing here", "No container matches this filter."))
          : empty("t_ship", "No containers yet", ov && ov.installed ? "Install an app from the catalog below, or create a custom container from any image." : "Install Docker first (System Applications)."),
      ], "", [segBar, btn("↻", () => load(true), "btn-ghost")]);
      body.append(containersCard);
      // Apps on the panel's list whose container no longer exists (removed outside the panel, or a re-create that failed).
      if (ov && ov.installed) API.docker().then((dk) => {
        const gone = (dk && dk.apps ? dk.apps : []).filter((a) => a.state === "missing");
        if (!gone.length || !containersCard.isConnected) return;
        containersCard.after(card("Installed by the panel, container gone", [
          el("p", { class: "muted mx-small", style: "margin:0 0 8px", text: "These apps are on the panel's list but their container no longer exists. Re-create brings the app back with its data folder; Forget drops it from the list and keeps the data folder." }),
          el("div", { class: "dk-gone-list" }, gone.map((a) => el("div", { class: "dk-gone" }, [
            el("div", {}, [el("b", { text: a.title || a.name }), el("span", { class: "muted mx-small", text: ` · ${a.image || a.app || ""}` })]),
            el("div", { class: "dk-td-btns" }, [
              btn("Re-create", () => call(() => API.dockerCtl(a.name, "start"), `${a.title || a.name} is back`, () => load(true)), "btn-primary"),
              armed("Forget", "Sure?", () => call(() => API.dockerRemove(a.name, false), `${a.title || a.name} forgotten`, () => load(true)), "btn-ghost"),
            ]),
          ]))),
        ]));
      }).catch(() => {});
      if (imgs.length) body.append(card(`Images (${imgs.length})`, [el("div", { class: "table-wrap" }, el("table", { class: "dk-table" }, [
        el("thead", {}, el("tr", {}, ["Image", "Size", "Downloaded", "Used by", ""].map((h) => el("th", { text: h })))),
        el("tbody", {}, imgs.map((i) => el("tr", {}, [
          el("td", {}, [el("b", { text: i.repo }), el("span", { class: "muted", text: `:${i.tag}` })]), el("td", { text: i.size }), el("td", { class: "muted", text: i.created }),
          el("td", {}, i.used_by.length ? i.used_by.map((n) => pill(n, "dim")) : el("span", { class: "muted", text: "nothing, safe to remove" })),
          el("td", { class: "dk-td-act" }, el("div", { class: "dk-td-btns" }, [
            btn("Run", () => runImage(i), "btn-primary"), btn("Details", () => imageDlg(i), "btn-ghost"),
            btn("Update", () => call(() => API.dockerPull(i.ref), "Downloading…", (r) => watch(r.job, `${i.ref} is up to date${i.used_by.length ? ", re-create its container (Settings → Save) to use it" : ""}`)), "btn-ghost"),
            i.used_by.length ? null : armed("Remove", "Sure?", () => call(() => API.dockerImageRemove(i.id), `${i.repo} removed`, () => load(true)), "btn-ghost"),
          ].filter(Boolean))),
        ]))),
      ]))], "", [el("span", { class: "muted mx-small", text: ov && ov.disk && ov.disk.Images ? `${ov.disk.Images.reclaimable} reclaimable` : "" }), btn("Pull an image", () => pullDlg(), "btn-ghost")]));
      if (catalogData) {
        const cats = ["All", ...new Set(catalogData.catalog.map((x) => x.cat))];
        const grid = el("div", { class: "op-cat" });
        const drawGrid = () => {
          grid.innerHTML = "";
          catalogData.catalog.filter((x) => cat === "All" || x.cat === cat).forEach((x) => grid.append(el("div", { class: "op-capp" }, [
            el("div", { class: "op-dapp-h" }, [el("span", { class: "op-dapp-ico", style: `--h:${APP_HUE(x.id)}`, text: x.name[0] }),
              el("div", { class: "grow" }, [el("b", { text: x.name }), el("p", { class: "muted mx-small", text: `${x.cat} · ${x.ram}` })])]),
            el("p", { class: "op-capp-d", text: x.desc }),
            el("div", { class: "op-dapp-act" }, [btn("Install", () => installDlg(x), "btn-primary"),
              x.home ? el("a", { class: "btn btn-sm btn-ghost", href: x.home, target: "_blank", rel: "noopener noreferrer", text: "Website ↗" }) : null]),
          ])));
        };
        body.append(card("App catalog", [el("div", { class: "op-catbar" }, seg(cats.map((c) => [c, c]), cat, (v) => { cat = v; drawGrid(); })), grid],
          "", [el("span", { class: "muted mx-small", text: `${catalogData.arch} · images match this processor` })]));
        drawGrid();
      }
    }
    function setFilt(v) { filt = v; LS.set("dk.filt", v); draw(); }

    // ---- details + settings ------------------------------------------------------------------
    async function detailDlg(c, tab) {
      const info = await call(() => API.dockerInspect(c.name));
      if (!info) return;
      const tabs = [["overview", "Overview"], ["settings", "Settings"], ["logs", "Logs"], ["top", "Processes"], ...(ov && ov.admin ? [["exec", "Run a command"]] : [])];
      const pane = el("div", { class: "dk-pane" });
      const foot = el("div", { class: "dk-foot" });
      const segBar = seg(tabs, tab || "overview", (v) => show(v));
      const stateTone = DK_TONE[info.state] || "dim";
      openModal(`${c.title || c.name}`, el("div", { class: "em-form" }, [
        el("div", { class: "dk-dhead" }, [el("span", { class: "dk-ico", style: `--h:${APP_HUE(c.app || c.image)}`, text: (c.title || c.name)[0].toUpperCase() }),
          el("div", { class: "grow" }, [el("b", { text: info.name }), el("p", { class: "muted mx-small mx-ell", text: `${info.image} · ${info.id}` })]), pill(info.state, stateTone)]),
        segBar, pane]), [foot]);
      modalWide();
      function kv(pairs) { return el("div", { class: "net-kv" }, pairs.filter(Boolean).map(([k, v]) => el("div", {}, [el("span", { class: "net-k", text: k }), typeof v === "object" && v ? v : el("span", { class: "net-v", text: v == null || v === "" ? "n/a" : String(v) })]))); }
      async function show(v) {
        pane.innerHTML = ""; foot.innerHTML = "";
        if (v === "overview") {
          pane.append(kv([
            ["Status", `${info.status || info.state}${info.health ? ` · health ${info.health}` : ""}${info.exit_code ? ` · last exit code ${info.exit_code}` : ""}`],
            info.error ? ["Last error", info.error] : null,
            ["Image", `${info.image} (${info.image_id})`],
            ["Created", info.created ? new Date(info.created).toLocaleString() : "n/a"],
            info.started && info.running ? ["Started", new Date(info.started).toLocaleString()] : null,
            ["Restart policy", info.restart],
            ["Network", `${info.network_mode}${Object.entries(info.networks).map(([n, x]) => ` · ${n}${x.ip ? ` ${x.ip}` : ""}`).join("")}`],
            ["Ports", info.ports.length ? el("div", { class: "dk-ports" }, info.ports.map((p) => p.host ? dkPort(p) : el("span", { class: "dk-port lo", text: `${p.container}/${p.proto} (not published)` }))) : "none"],
            ["Command", `${info.entrypoint ? info.entrypoint + " " : ""}${info.cmd}`.trim() || "n/a"],
            info.user ? ["Runs as", info.user] : null,
            ["Limits", `${info.memory ? fmtBytes(info.memory) + " RAM" : "no RAM limit"} · ${info.cpus ? info.cpus + " CPUs" : "all CPUs"}`],
            ["Privileged", info.privileged ? "yes, full access to the host's devices" : "no"],
            ["Storage", info.mounts.length ? el("div", { class: "dk-mounts" }, info.mounts.map((m) => el("div", { class: "dk-mount" }, [el("code", { text: m.source }), el("span", { class: "muted", text: " → " }), el("code", { text: m.dest }), m.rw ? null : pill("read-only", "dim")]))) : "none (everything inside is lost when the container is removed)"],
            ["Environment", info.env.length ? el("details", { class: "dk-env" }, [el("summary", { text: `${info.env.length} variables` }), el("div", { class: "dk-envlist" }, info.env.map((e) => el("div", {}, [el("code", { text: e.key }), el("span", { text: "=" }), el("code", { class: e.secret ? "muted" : "", text: e.value })])))]) : "none"],
            info.managed ? ["Panel", info.custom ? "custom container, its compose file lives in /opt/aurora-apps/" + info.name : `catalog app (${info.app}), compose file in /opt/aurora-apps/${info.name}`] : ["Panel", "not created by the panel, changes re-create it from the same image, volumes and networks"],
          ]));
          if (c.secrets && c.secrets.length) foot.append(btn("Generated passwords", async () => {
            const rows = [];
            for (const k of c.secrets) {
              const r = await call(() => API.dockerSecret(c.name, k));
              if (r) rows.push(el("div", { class: "em-copy" }, [el("span", { class: "em-copy-k", text: k }), el("code", { class: "em-mono", text: r.value }),
                el("button", { type: "button", class: "bk-mini", text: "Copy", onclick: async () => toast(await copyText(r.value) ? "Copied" : "Copy failed", "good") })]));
            }
            openModal(`${c.title}, generated passwords`, el("div", { class: "em-form" }, rows), []); modalWide();
          }, "btn-ghost"));
          if (info.managed && !info.custom) foot.append(btn("Update to the latest version", () => call(() => API.dockerCtl(c.name, "update"), "Updating…", (r) => { closeModal(); watch(r.job, `${c.title} is up to date`); }), "btn-ghost"));
          foot.append(btn("Remove…", () => removeDlg(c), "btn-danger"));
        } else if (v === "settings") settingsPane(c, info, pane, foot);
        else if (v === "logs") {
          const pre = el("pre", { class: "mx-pre dk-log", text: "Loading…" });
          const lines = el("select", { class: "em-select mx-narrow" }, [200, 400, 1000, 3000].map((n) => el("option", { value: n, text: `last ${n} lines` })));
          lines.value = "400";
          const refresh = async () => { const r = await call(() => API.dockerCLogs(c.name, lines.value)); if (r) { pre.textContent = r.text || "(empty)"; pre.scrollTop = 1e9; } };
          lines.onchange = refresh;
          pane.append(el("div", { class: "mx-toolbar mx-toolbar-top" }, [lines, el("span", { class: "grow" }), btn("Refresh", refresh, "btn-ghost"), btn("Download", () => downloadText(`${c.name}.log`, pre.textContent, "text/plain"), "btn-ghost")]), pre);
          refresh();
        } else if (v === "top") {
          const pre = el("pre", { class: "mx-pre dk-log", text: "Loading…" });
          pane.append(pre);
          const r = await call(() => API.dockerTop(c.name));
          pre.textContent = r ? r.text : "Not running";
        } else if (v === "exec") {
          const cmd = el("input", { type: "text", placeholder: "e.g.  ls -la /config   or   cat /etc/os-release", class: "em-mono" });
          const user = el("input", { type: "text", placeholder: "root", style: "max-width:140px" });
          const out = el("pre", { class: "mx-pre dk-log", text: "" });
          const run = async () => {
            out.textContent = "Running…";
            const r = await call(() => API.dockerExec(c.name, { cmd: cmd.value, user: user.value.trim() }));
            out.textContent = r ? `${r.output || "(no output)"}\n\n[exit code ${r.code}]` : "Failed";
          };
          cmd.onkeydown = (e) => { if (e.key === "Enter") run(); };
          pane.append(el("p", { class: "muted mx-small", text: "Runs one command inside the container through docker exec and shows what it printed. For an interactive session use Shell (the terminal icon)." }),
            el("div", { class: "dk-execbar" }, [field("Command", cmd), field("As user", user, "empty = root")]), el("div", {}, btn("Run", run, "btn-primary")), out);
          setTimeout(() => cmd.focus(), 50);
        }
      }
      show(tab || "overview");
    }

    function portsEditor(list, opts) {
      const box = el("div", { class: "dk-edit" });
      const rows = [];
      const head = el("div", { class: "dk-edit-r dk-edit-h" }, [el("span", { text: "In the container" }), el("span", { text: "Proto" }), el("span", { text: "On this server" }),
        opts.bind ? el("span", { text: "Listen on" }) : el("span", { text: "Role" }), el("span")]);
      const add = (p) => {
        const cport = el("input", { type: "number", min: 1, max: 65535, value: p.container || "", placeholder: "8080", disabled: opts.fixed ? "" : null });
        const proto = el("select", {}, [["tcp", "tcp"], ["udp", "udp"]].map(([v, t]) => el("option", { value: v, text: t })));
        proto.value = p.proto || "tcp"; if (opts.fixed) proto.disabled = true;
        const hport = el("input", { type: "number", min: 0, max: 65535, value: p.host || "", placeholder: opts.auto ? "auto" : "e.g. 10080" });
        let extra;
        if (opts.bind) { extra = el("select", {}, [["", "Every address (public)"], ["127.0.0.1", "This server only"], ...(ov && ov.lan_ip ? [[ov.lan_ip, `Local network (${ov.lan_ip})`]] : [])].map(([v, t]) => el("option", { value: v, text: t }))); extra.value = p.bind || ""; }
        else { extra = el("select", {}, [["tcp", "Other"], ["web", "Web page"], ["dns", "DNS"]].map(([v, t]) => el("option", { value: v, text: t }))); extra.value = p.kind || "tcp"; if (opts.fixed) extra.disabled = true; }
        const r = { cport, proto, hport, extra };
        const node = el("div", { class: "dk-edit-r" }, [cport, proto, hport, extra, opts.fixed ? el("span") : el("button", { type: "button", class: "bk-mini", text: "✕", title: "Remove", onclick: () => { rows.splice(rows.indexOf(r), 1); node.remove(); } })]);
        rows.push(r); box.insertBefore(node, addBtn);
      };
      const addBtn = opts.fixed ? el("span") : el("button", { type: "button", class: "btn btn-sm btn-ghost", text: "＋ Add a port", onclick: () => add({}) });
      box.append(head, addBtn);
      list.forEach(add);
      box.value = () => rows.map((r) => ({ container: Number(r.cport.value), proto: r.proto.value, host: Number(r.hport.value || 0), ...(opts.bind ? { bind: r.extra.value } : { kind: r.extra.value }) })).filter((p) => p.container);
      return box;
    }
    function kvEditor(list, placeholderK, placeholderV) {
      const box = el("div", { class: "dk-edit" });
      const rows = [];
      const add = (e) => {
        const k = el("input", { type: "text", value: e.key || "", placeholder: placeholderK, class: "em-mono" });
        const v = el("input", { type: e.secret ? "password" : "text", value: e.value || "", placeholder: e.secret ? "unchanged" : placeholderV, class: "em-mono" });
        const r = { k, v };
        const node = el("div", { class: "dk-edit-r dk-edit-kv" }, [k, v, el("button", { type: "button", class: "bk-mini", text: "✕", title: "Remove", onclick: () => { rows.splice(rows.indexOf(r), 1); node.remove(); } })]);
        rows.push(r); box.insertBefore(node, addBtn);
      };
      const addBtn = el("button", { type: "button", class: "btn btn-sm btn-ghost", text: "＋ Add", onclick: () => add({}) });
      box.append(addBtn);
      list.forEach(add);
      box.value = () => rows.map((r) => ({ key: r.k.value.trim(), value: r.v.value })).filter((e) => e.key);
      return box;
    }
    const restartSel = (cur) => { const s = el("select", {}, [["unless-stopped", "Always, unless I stop it (recommended)"], ["always", "Always, even after I stop it"], ["on-failure", "Only after a crash"], ["no", "Never"]].map(([v, t]) => el("option", { value: v, text: t }))); s.value = cur || "unless-stopped"; return s; };

    function settingsPane(c, info, pane, foot) {
      const managed = info.managed, hostNet = info.network_mode === "host";
      const kinds = info.port_kinds || {};
      const ports = hostNet ? null : portsEditor(info.ports.filter((p) => p.host || managed).map((p) => ({ ...p, kind: kinds[`${p.container}/${p.proto}`] || p.kind })), { bind: !managed, fixed: managed && !info.custom, auto: false });
      const env = kvEditor(info.env, "NAME", "value");
      const pagePath = el("input", { type: "text", value: info.path || "", placeholder: "/, or e.g. /admin", class: "em-mono", style: "max-width:320px" });
      const keepAlive = sw(!!info.tty, () => {});
      const restart = restartSel(info.restart);
      const mem = el("input", { type: "text", value: info.memory ? fmtBytes(info.memory).replace(/\s/g, "").toLowerCase().replace("ib", "") : "", placeholder: "none, e.g. 512m or 2g", style: "max-width:200px" });
      const cpus = el("input", { type: "text", value: info.cpus || "", placeholder: "all, e.g. 1 or 0.5", style: "max-width:200px" });
      let access = info.access || "public";
      const domain = el("input", { type: "text", value: info.domain || "", placeholder: `${c.name}.example.com` });
      const domWrap = el("div", {}, field("Web address", domain, "A name whose DNS points to this server. AutoSSL gives it HTTPS; the WAF and ban list protect it."));
      const hasWeb = managed && Object.values(kinds).includes("web");
      const accessBox = el("div", { class: "em-rcards" });
      if (managed && !hostNet) {
        const opts = [];
        if (hasWeb) opts.push({ value: "proxy", label: "At a web address (recommended)", icon: "globe", desc: "https://app.yourdomain, the web port listens on this server only; everything else on the local network." });
        if (ov.lan_ip) opts.push({ value: "lan", label: "On my local network only", icon: "wifi", desc: `Ports listen on ${ov.lan_ip}, reachable at home, not from the internet.` });
        opts.push({ value: "public", label: "On public ports", icon: "warning", desc: "Ports listen on every address, Docker skips the firewall for them, so the internet can reach the container directly.", tone: "warn" });
        opts.forEach((o) => {
          const r = el("input", { type: "radio", name: "dkacc", value: o.value }); r.checked = o.value === access;
          r.onchange = () => { access = o.value; domWrap.hidden = access !== "proxy"; };
          accessBox.append(el("label", { class: `em-rcard ${o.tone || ""}` }, [r, el("span", { class: "em-rcard-ico" }, icon(o.icon, 18)), el("div", {}, [el("div", { class: "em-rcard-t" }, el("b", { text: o.label })), el("p", { class: "muted", text: o.desc })])]));
        });
        domWrap.hidden = access !== "proxy";
      }
      pane.append(...[
        managed ? null : el("div", { class: "mx-note mx-note-dim" }, [icon("info", 16), el("span", { text: "This container wasn't made by the panel. Docker can't change a container in place, so saving re-creates it from the same image, volumes and networks with the new settings, the old one is kept until the new one runs." })]),
        hostNet ? el("div", { class: "mx-note mx-note-dim" }, [icon("info", 16), el("span", { text: "Uses the host network: it has every port of this server directly, so there's nothing to publish." })])
          : el("div", {}, [el("div", { class: "mx-sub" }, "Ports"), el("p", { class: "muted mx-small", text: managed && !info.custom ? "The container side is fixed by the app; change the port on this server if it clashes with something else." : "Which port inside the container is reachable on which port of this server." }), ports,
              info.custom && hasWeb ? field("Page path", pagePath, "Where the app's page is when it isn't the site root (Pi-hole: /admin). The Open button uses it.") : null].filter(Boolean)),
        managed && !hostNet ? el("div", {}, [el("div", { class: "mx-sub" }, "How to reach it"), accessBox, domWrap]) : null,
        el("div", {}, [el("div", { class: "mx-sub" }, "Environment variables"), el("p", { class: "muted mx-small", text: "The app's own settings (see its documentation). Generated passwords stay as they are unless you type a new one." }), env]),
        el("div", {}, [el("div", { class: "mx-sub" }, "Behaviour"), el("div", { class: "dk-grid2" }, [field("Restart", restart), field("RAM limit", mem, "Protects the rest of the server if the app misbehaves."), field("CPUs", cpus)])]),
        info.custom ? el("label", { class: "mx-live" }, [keepAlive, el("span", { text: "Keep it running, attach a terminal so an image that only starts a shell (kali, ubuntu, alpine) doesn't exit at once." })]) : null,
      ].filter(Boolean));
      foot.append(btn("Save & re-create", () => {
        const data = { ports: ports ? ports.value() : null, env: env.value(), restart: restart.value, mem_limit: mem.value.trim(), cpus: cpus.value.trim(), access: managed ? access : "", domain: domain.value.trim(),
          ...(info.custom ? { path: pagePath.value.trim(), keep_alive: swOn(keepAlive) } : {}) };
        call(() => API.dockerSettings(c.name, data), "Applying…", (r) => { closeModal(); watch(r.job, `${c.title || c.name} re-created with the new settings`); });
      }, "btn-primary"));
    }
    function removeDlg(c) {
      const del = el("input", { type: "checkbox" });
      openModal(`Remove ${c.title || c.name}?`, el("div", { class: "em-form" }, [el("p", { text: `The container stops and is removed${c.managed ? ", and its web address (if any) is taken down" : ""}.` }),
        el("label", { class: "dm-check" }, [del, el("span", { text: c.managed ? "Also delete its data folder (settings, databases, uploads), can't be undone" : "Also delete its anonymous volumes, can't be undone" })])]),
        [armed("Remove", "Click again to remove", () => call(() => API.dockerCRemove(c.name, del.checked), `${c.title || c.name} removed`, () => { closeModal(); load(true); }), "btn-danger")]);
    }

    // ---- shell inside a container (xterm over the panel's WebSocket terminal) -----------------
    function shellDlg(c) {
      const user = el("input", { type: "text", placeholder: "root", style: "max-width:120px" });
      const host = el("div", { class: "dk-term" });
      let term = null, ws = null, fit = null;
      const start = () => {
        if (ws) { try { ws.close(); } catch (e) {} }
        if (term) { try { term.dispose(); } catch (e) {} }
        host.innerHTML = "";
        if (typeof Terminal === "undefined") { host.innerHTML = '<p class="empty">Terminal library failed to load.</p>'; return; }
        term = new Terminal({ cursorBlink: true, fontSize: 13, fontFamily: '"Cascadia Code","Consolas",monospace', theme: { background: "#000000", foreground: "#e6edf3" } });
        try { fit = new FitAddon.FitAddon(); term.loadAddon(fit); } catch (e) { fit = null; }
        term.open(host);
        const proto = location.protocol === "https:" ? "wss" : "ws";
        ws = new WebSocket(`${proto}://${location.host}/api/docker/containers/${encodeURIComponent(c.name)}/shell?user=${encodeURIComponent(user.value.trim())}`);
        const sendResize = () => { if (ws.readyState === 1) ws.send(JSON.stringify({ type: "resize", cols: term.cols, rows: term.rows })); };
        ws.onopen = () => { term.focus(); if (fit) { try { fit.fit(); } catch (e) {} } sendResize(); };
        ws.onmessage = (ev) => { try { const m = JSON.parse(ev.data); if (m.type === "output") term.write(m.data); else if (m.type === "exit") term.write("\r\n\x1b[90m[session ended]\x1b[0m\r\n"); } catch (e) {} };
        ws.onclose = (ev) => { try { term.write(ev.code === 1008 ? "\r\n\x1b[91m[refused, administrators only]\x1b[0m\r\n" : "\r\n\x1b[90m[disconnected]\x1b[0m\r\n"); } catch (e) {} };
        term.onData((d) => { if (ws.readyState === 1) ws.send(JSON.stringify({ type: "input", data: d })); });
        setTimeout(() => { if (fit) { try { fit.fit(); } catch (e) {} } sendResize(); }, 80);
      };
      openModal(`Shell, ${c.name}`, el("div", { class: "em-form" }, [
        el("div", { class: "mx-toolbar mx-toolbar-top" }, [el("span", { class: "muted mx-small", text: "A shell inside the container (docker exec), as root unless you pick another user. Type exit or close this window to end it." }),
          el("span", { class: "grow" }), field("User", user), btn("Reconnect", start, "btn-ghost")]), host]), []);
      modalWide();
      start();
      const t = setInterval(() => { if (!host.isConnected) { clearInterval(t); try { ws && ws.close(); } catch (e) {} try { term && term.dispose(); } catch (e) {} } }, 800);
      state.cleanups.push(() => { clearInterval(t); try { ws && ws.close(); } catch (e) {} });
    }

    // ---- images: what's inside, and run one ---------------------------------------------------
    const swOn = (s) => { const i = s.querySelector && s.querySelector("input"); return !!(i ? i.checked : s.checked); };
    const slugName = (repo) => {
      let s = (repo || "").split("/").pop().split(":")[0].toLowerCase().replace(/[^a-z0-9-]+/g, "-").replace(/^-+|-+$/g, "").slice(0, 28) || "app";
      if (!/^[a-z]/.test(s)) s = "app-" + s;
      const taken = new Set(cs.map((c) => c.name));
      let n = s, k = 2;
      while (taken.has(n)) n = `${s}-${k++}`;
      return n;
    };
    const prefillFrom = (i, info) => ({
      image: i.ref, name: slugName(i.repo), cmd: [...(info.entrypoint || []), ...(info.cmd || [])].join(" "),
      ports: info.ports.map((p) => ({ container: p.port, proto: p.proto, host: "", kind: p.kind })),
      volumes: info.volumes.map((v) => ({ host: "", container: v })), keep_alive: info.shell, shell: info.shell,
    });
    async function runImage(i) {
      const info = await call(() => API.dockerImageInspect(i.ref));
      if (info) customDlg(prefillFrom(i, info));
    }
    async function imageDlg(i) {
      const info = await call(() => API.dockerImageInspect(i.ref));
      if (!info) return;
      const kv = (pairs) => el("div", { class: "net-kv" }, pairs.filter(Boolean).map(([k, v]) => el("div", {}, [el("span", { class: "net-k", text: k }), typeof v === "object" && v ? v : el("span", { class: "net-v", text: v == null || v === "" ? "n/a" : String(v) })])));
      const mono = (t) => el("code", { class: "dk-mono", text: t });
      const defaults = [...(info.entrypoint || []), ...(info.cmd || [])].join(" ");
      const tbl = (heads, rows) => el("div", { class: "table-wrap" }, el("table", { class: "dk-table dk-table-sm" }, [el("thead", {}, el("tr", {}, heads.map((h) => el("th", { text: h })))), el("tbody", {}, rows)]));
      const labels = Object.entries(info.labels || {});
      openModal(`${i.repo}:${i.tag}`, el("div", { class: "em-form" }, [
        kv([["Tags", (info.tags || []).join(", ")], ["ID", `${info.id}${info.digests.length ? ` · digest ${info.digests[0]}…` : ""}`], ["Built", info.created], ["Size", fmtBytes(info.size)], ["Platform", `${info.os}/${info.arch}`],
          ["Starts with", defaults ? mono(defaults) : "n/a"], ["Working dir", info.workdir], ["Runs as", info.user || "root"], ["Used by", info.used_by.length ? el("span", {}, info.used_by.map((n) => pill(n, "dim"))) : "no container"]]),
        info.shell ? el("div", { class: "mx-note mx-note-dim" }, [icon("info", 16), el("span", { text: "This image starts a shell, not a service: without a terminal it exits at once. “Run” keeps it alive so you can open a shell inside it from the container list." })]) : null,
        el("div", { class: "mx-sub" }, "Ports it listens on"),
        info.ports.length ? el("div", { class: "dk-chips" }, info.ports.map((p) => pill(`${p.port}/${p.proto}${p.kind === "web" ? " · web page" : ""}`, p.kind === "web" ? "good" : "dim"))) : el("p", { class: "muted mx-small", text: "None declared, a command-line tool or a shell image, or the documentation names the port." }),
        el("div", { class: "mx-sub" }, "Folders it keeps data in"),
        info.volumes.length ? el("div", { class: "dk-chips" }, info.volumes.map((v) => pill(v, "dim"))) : el("p", { class: "muted mx-small", text: "None declared." }),
        el("div", { class: "mx-sub" }, `Environment defaults (${info.env.length})`),
        info.env.length ? tbl(["Variable", "Default"], info.env.map((e) => el("tr", {}, [el("td", {}, mono(e.key)), el("td", {}, mono(e.value))]))) : el("p", { class: "muted mx-small", text: "None." }),
        el("details", { class: "dk-adv" }, [el("summary", { text: `Layers (${info.history.length})` }),
          tbl(["Step", "Size"], info.history.map((h) => el("tr", {}, [el("td", {}, mono(h.by || "n/a")), el("td", { class: "muted", text: h.size })])))]),
        labels.length ? el("details", { class: "dk-adv" }, [el("summary", { text: `Labels (${labels.length})` }),
          tbl(["Label", "Value"], labels.map(([k, v]) => el("tr", {}, [el("td", {}, mono(k)), el("td", {}, mono(v))])))]) : null,
      ].filter(Boolean)), [
        btn("Run as a container", () => { closeModal(); customDlg(prefillFrom(i, info)); }, "btn-primary"),
        btn("Update", () => call(() => API.dockerPull(i.ref), "Downloading…", (r) => { closeModal(); watch(r.job, `${i.ref} is up to date`); }), "btn-ghost"),
        info.used_by.length ? null : armed("Remove", "Sure?", () => call(() => API.dockerImageRemove(info.id), `${i.repo} removed`, () => { closeModal(); load(true); }), "btn-ghost"),
      ].filter(Boolean));
      modalWide();
    }

    // ---- custom container --------------------------------------------------------------------
    function customDlg(pre) {
      pre = pre || {};
      const name = el("input", { type: "text", placeholder: "my-app", maxlength: 31, value: pre.name || "" });
      const title = el("input", { type: "text", placeholder: "Shown in the list (optional)" });
      const image = el("input", { type: "text", placeholder: "nginx:latest · ghcr.io/owner/app:1.2 · lscr.io/linuxserver/…", class: "em-mono", value: pre.image || "" });
      const ports = portsEditor(pre.ports && pre.ports.length ? pre.ports : [{ container: "", proto: "tcp", host: "", kind: "web" }], { auto: true });
      const pagePath = el("input", { type: "text", placeholder: "/, or e.g. /admin for Pi-hole", class: "em-mono", style: "max-width:320px" });
      const vols = el("div", { class: "dk-edit" });
      const vrows = [];
      const addVol = (v) => {
        const h = el("input", { type: "text", value: v.host || "", placeholder: "empty = a folder the panel keeps; or /srv/media; or a volume name" });
        const cpath = el("input", { type: "text", value: v.container || "", placeholder: "/data" });
        const r = { h, cpath };
        const node = el("div", { class: "dk-edit-r dk-edit-kv" }, [h, cpath, el("button", { type: "button", class: "bk-mini", text: "✕", onclick: () => { vrows.splice(vrows.indexOf(r), 1); node.remove(); } })]);
        vrows.push(r); vols.insertBefore(node, addV);
      };
      const addV = el("button", { type: "button", class: "btn btn-sm btn-ghost", text: "＋ Add storage", onclick: () => addVol({}) });
      vols.append(el("div", { class: "dk-edit-r dk-edit-kv dk-edit-h" }, [el("span", { text: "On this server" }), el("span", { text: "In the container" }), el("span")]), addV);
      (pre.volumes && pre.volumes.length ? pre.volumes : [{}]).forEach(addVol);
      const env = kvEditor([], "NAME", "value");
      const command = el("input", { type: "text", placeholder: pre.cmd ? `leave empty for the image's default: ${pre.cmd}` : "leave empty for the image's default", class: "em-mono" });
      const keepAlive = sw(!!pre.keep_alive, () => {});
      const devices = el("input", { type: "text", placeholder: "/dev/ttyUSB0, /dev/video0", class: "em-mono" });
      const restart = restartSel("unless-stopped");
      const mem = el("input", { type: "text", placeholder: "none, e.g. 512m" });
      const cpus = el("input", { type: "text", placeholder: "all, e.g. 1" });
      const uid = el("input", { type: "text", placeholder: "e.g. 1000, if the image runs as a user, its data folder is given to that user", style: "max-width:320px" });
      const hostNet = sw(false, (v) => { portsWrap.hidden = v; });
      const priv = sw(false, () => {});
      const httpsOnly = sw(false, () => {});
      let access = ov && ov.lan_ip ? "lan" : "public";
      const domain = el("input", { type: "text", placeholder: "app.example.com" });
      const domWrap = el("div", {}, field("Web address", domain, "A name whose DNS points to this server. Mark the container's web port as “Web page” above."));
      const rc = el("div", { class: "em-rcards" });
      const opts = [];
      if (ov && ov.lan_ip) opts.push({ value: "lan", label: "On my local network only", icon: "wifi", desc: `http://${ov.lan_ip}:<port>, reachable at home, not from the internet.` });
      opts.push({ value: "proxy", label: "At a web address", icon: "globe", desc: "https://app.yourdomain, HTTPS from AutoSSL, protected by the WAF and your ban list." });
      opts.push({ value: "public", label: "On public ports", icon: "warning", desc: "Anyone on the internet can reach it directly, Docker skips the firewall for published ports.", tone: "warn" });
      opts.forEach((o) => {
        const r = el("input", { type: "radio", name: "dkcacc", value: o.value }); r.checked = o.value === access;
        r.onchange = () => { access = o.value; domWrap.hidden = access !== "proxy"; };
        rc.append(el("label", { class: `em-rcard ${o.tone || ""}` }, [r, el("span", { class: "em-rcard-ico" }, icon(o.icon, 18)), el("div", {}, [el("div", { class: "em-rcard-t" }, el("b", { text: o.label })), el("p", { class: "muted", text: o.desc })])]));
      });
      domWrap.hidden = access !== "proxy";
      const portsWrap = el("div", {}, [el("div", { class: "mx-sub" }, "Ports"), el("p", { class: "muted mx-small", text: "The port the app listens on inside the container (its documentation says). Leave the server side empty to pick a free one." }), ports,
        field("Page path", pagePath, "Where the app's own page is when it isn't the site root. Left empty, the panel looks at the usual places when / answers 404."),
        el("div", { class: "mx-sub" }, "How to reach it"), rc, domWrap]);
      openModal(pre.image ? `Run ${pre.image}` : "Custom container", el("div", { class: "em-form" }, [
        el("p", { class: "muted", text: pre.image ? "Ports and folders below come from the image itself; adjust them if its documentation says otherwise." : "Run any image from Docker Hub, GitHub (ghcr.io) or another registry. The panel keeps it like a catalog app: a compose file and data folder in /opt/aurora-apps, auto-restart, capped logs." }),
        pre.shell ? el("div", { class: "mx-note mx-note-dim" }, [icon("info", 16), el("span", { text: "This image starts a shell rather than a service, so “Keep it running” is on: the container stays up and you can open a shell inside it from the list." })]) : null,
        el("div", { class: "dk-grid2" }, [field("Name", name, "Lowercase letters, digits and dashes."), field("Title", title)]),
        field("Image", image, `Must have a build for this processor (${ov ? ov.arch : "arm64"}).`),
        portsWrap,
        el("div", { class: "mx-sub" }, "Storage"), el("p", { class: "muted mx-small", text: "Folders inside the container that must survive updates (config, databases, uploads)." }), vols,
        el("div", { class: "mx-sub" }, "Environment variables"), env,
        el("details", { class: "dk-adv" }, [el("summary", { text: "Advanced" }), el("div", { class: "em-form" }, [
          el("div", { class: "dk-grid2" }, [field("Restart", restart), field("Runs as user ID", uid)]),
          el("div", { class: "dk-grid2" }, [field("RAM limit", mem), field("CPUs", cpus)]),
          field("Command", command), field("Devices", devices, "Hardware passed to the container, comma-separated (USB sticks, cameras)."),
          el("label", { class: "mx-live" }, [hostNet, el("span", { text: "Host network, the container shares this server's network (needed by apps that discover devices at home). No port mapping then." })]),
          el("label", { class: "mx-live" }, [keepAlive, el("span", { text: "Keep it running, attach a terminal so an image that only starts a shell (kali, ubuntu, alpine) doesn't exit at once." })]),
          el("label", { class: "mx-live" }, [priv, el("span", { text: "Privileged, full access to the host's devices. Only if the app's documentation says so." })]),
          el("label", { class: "mx-live" }, [httpsOnly, el("span", { text: "Needs HTTPS, the app refuses plain http (password managers, apps with camera or microphone access). On the local network the panel then serves it over HTTPS with a self-signed certificate." })]),
        ])]),
      ].filter(Boolean)), [el("button", { class: "btn btn-primary", text: "Create & start", onclick: () => {
        const data = { name: name.value.trim(), title: title.value.trim(), image: image.value.trim(), access, domain: domain.value.trim(), restart: restart.value,
          ports: ports.value(), volumes: vrows.map((r) => ({ host: r.h.value.trim(), container: r.cpath.value.trim() })).filter((v) => v.container), env: env.value(),
          devices: devices.value.split(",").map((s) => s.trim()).filter(Boolean), command: command.value.trim(), mem_limit: mem.value.trim(), cpus: cpus.value.trim(),
          host_network: swOn(hostNet), privileged: swOn(priv), https_only: swOn(httpsOnly), uid: uid.value.trim(), path: pagePath.value.trim(), keep_alive: swOn(keepAlive) };
        call(() => API.dockerCustom(data), "Creating…", (r) => { closeModal(); watch(r.job, `${data.title || data.name} is running`); });
      } })]);
      modalWide();
      setTimeout(() => name.focus(), 50);
    }
    function pullDlg() {
      const image = el("input", { type: "text", placeholder: "nginx:latest", class: "em-mono" });
      openModal("Pull an image", el("div", { class: "em-form" }, [el("p", { class: "muted", text: "Download an image now (for example before creating a custom container, or to update one you run yourself)." }), field("Image", image)]),
        [btn("Pull", () => call(() => API.dockerPull(image.value.trim()), "Downloading…", (r) => { closeModal(); watch(r.job, "Image downloaded"); }), "btn-primary")]);
      setTimeout(() => image.focus(), 50);
    }

    // ---- catalog install (unchanged behaviour) -------------------------------------------------
    function installDlg(x) {
      const d = catalogData;
      let access = (x.host_network || x.no_web) ? (d.lan_ip ? "lan" : "public") : "proxy";
      const name = el("input", { type: "text", value: x.id, maxlength: 31 });
      const domain = el("input", { type: "text", placeholder: `${x.id}.example.com` });
      const domWrap = el("div", {}, field("Web address", domain, "A name whose DNS points to this server (e.g. a subdomain in the Zone Editor). AutoSSL then gives it HTTPS."));
      const opts = [];
      if (!x.host_network && !x.no_web) opts.push({ value: "proxy", label: "At a web address (recommended)", icon: "globe", desc: "https://app.yourdomain, HTTPS, protected by the WAF and your ban list. The app itself is never exposed directly." });
      if (d.lan_ip) opts.push({ value: "lan", label: "On my local network only", icon: "wifi", desc: x.https_only ? `https://${d.lan_ip}:<port>, the panel adds HTTPS itself (self-signed certificate, your browser asks once to trust it). Reachable at home, not from the internet.` : `http://${d.lan_ip}:<port>, reachable from devices at home, not from the internet.` });
      opts.push({ value: "public", label: "On a public port", icon: "warning", desc: "Anyone on the internet can reach it directly, Docker skips the firewall for these ports. Only for apps with their own strong login.", tone: "warn" });
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
        return field(`Your ${f} folder`, folders[f], f === "media" || f === "music" ? "Where your files already are, the app reads them from here." : "");
      });
      openModal(`Install ${x.name}`, el("div", { class: "em-form" }, [
        el("p", { class: "muted", text: x.desc }),
        x.note ? el("div", { class: "mx-note" }, [icon("info", 16), el("span", { text: x.note })]) : null,
        x.host_network ? el("div", { class: "mx-note mx-note-dim" }, [icon("info", 16), el("span", { text: `${x.name} needs the host network (to find devices at home), so it's reached at http://<this server>:${x.ports[0].port}.` })]) : null,
        field("Name", name, "Lowercase letters, digits and dashes, install the same app twice with different names."),
        el("div", { class: "mx-sub" }, "How to reach it"), rc, domWrap, ...fold,
      ]), [el("button", { class: "btn btn-primary", text: "Install", onclick: () => call(() => API.dockerInstall({ app: x.id, name: name.value.trim(), access, domain: domain.value.trim(),
        folders: Object.fromEntries(Object.entries(folders).map(([k, i]) => [k, i.value.trim()]).filter(([, v]) => v)) }), "Installing…", (r) => { closeModal(); watch(r.job, `${x.name} is running`); }) })]);
      modalWide();
    }

    drawHero();
    load();
    const tick = setInterval(() => { if (!document.querySelector("#modal")) load(true); }, 12000);
    state.cleanups.push(() => clearInterval(tick));
  }

  // ======================================================================
  //  System → Servers (every AuroraPanel on one page)
  // ======================================================================
  const meter = (label, pct, sub) => el("div", { class: "op-meter" }, [el("div", { class: "op-meter-l" }, [el("span", { text: label }), el("b", { text: pct == null ? "n/a" : `${Math.round(pct)}%` })]),
    el("div", { class: `op-meter-bar ${pct >= 90 ? "bad" : pct >= 75 ? "warn" : ""}` }, el("span", { style: `width:${Math.max(2, Math.min(100, pct || 0))}%` })), sub ? el("small", { class: "muted", text: sub }) : null]);
  const upt = (s) => !s ? "n/a" : s < 3600 ? `${Math.round(s / 60)} min` : s < 86400 ? `${Math.round(s / 3600)} h` : `${Math.round(s / 86400)} days`;
  async function viewServers(root) {
    root.append(pageHead("Servers", "All your AuroraPanel servers on one page, Raspberry Pis at home, VPSs in the cloud. See which one needs attention, and act on all of them at once.",
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
        s.ok ? el("div", { class: "op-srv-m" }, [meter("CPU", s.cpu, `${s.cpus || "?"} cores · load ${s.load != null ? s.load.toFixed(2) : "n/a"}${s.temp ? ` · ${s.temp}°C` : ""}`),
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
        ? `One click blocks an address on this server and on ${d.servers.length - 1} other${d.servers.length === 2 ? "" : "s"}, websites, mail, SSH, VPN, panels.`
        : "Blocks an address on this server, websites, mail, SSH, VPN, the panel. Add your other servers above and it reaches them too." }),
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
        field("Name", name), field("Panel address", url, "https:// with any certificate, it's remembered (pinned) on first contact. http:// only on your own network."), field("API token", token),
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
      if (j) toast(j.status === "done" ? label : "Something went wrong, see the log", j.status === "done" ? "good" : "bad");
      if (after) after();
    }
    async function load() {
      try { list = await API.wpt(); } catch (e) { body.innerHTML = ""; body.append(el("p", { class: "empty", text: e.message })); return; }
      body.innerHTML = "";
      if (!list.sites.length) { body.append(el("div", { class: "card" }, empty("wordpress", "No WordPress here yet", "Install one with the App Installer, it shows up here by itself.", btn("Install WordPress", () => navigate("wordpress"), "btn-primary")))); return; }
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
        box.append(...[
          el("div", { class: "op-plan-h" }, [el("span", { class: "op-plan-ico" }, icon("wordpress", 20)), el("div", { class: "grow" }, [el("h3", { text: d.url.replace(/^https?:\/\//, "") }),
            el("p", { class: "muted mx-small", text: `WordPress ${d.version} · ${d.plugins.length} plugins · ${d.themes.length} themes · ${d.path}` })]),
            d.db_error ? pill("database error", "bad") : todo ? pill(`${todo} update${todo > 1 ? "s" : ""}`, "warn") : pill("up to date", "good"), d.maintenance ? pill("maintenance mode", "warn") : null]),
          d.db_error ? el("p", { class: "bk-warnline", text: d.db_error + ", check DB_NAME / DB_USER / DB_PASSWORD in wp-config.php, or restore the database from a backup." }) : null,
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
        ].filter(Boolean));
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
      if (j) toast(j.status === "done" ? label : "Something went wrong, see the log", j.status === "done" ? "good" : "bad");
      if (after) after();
    }
    async function load() {
      try { d = await API.migrate(); } catch (e) { body.innerHTML = ""; body.append(el("p", { class: "empty", text: e.message })); return; }
      body.innerHTML = "";
      const url = el("input", { type: "url", placeholder: "https://old-host.example.com/…/backup-…tar.gz" });
      body.append(card("1. Get the backup here", [
        el("ol", { class: "op-steps" }, [el("li", { text: "In the old cPanel: Files → Backup → “Download a Full Account Backup” (or ask your host)." }),
          el("li", {}, ["Upload the .tar.gz to ", el("code", { text: d.folder }), " with the File Manager or SFTP, or paste a download link:"])]),
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
    root.append(pageHead("My Websites", "The websites you manage on this server, their files, email accounts and visitors."));
    const body = el("div", {}, el("div", { class: "loading", text: "Loading…" }));
    root.append(body);
    let d;
    try { d = await API.mySites(); } catch (e) { body.innerHTML = ""; body.append(el("p", { class: "empty", text: e.message })); return; }
    body.innerHTML = "";
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
    site: ["Website manager", "Only their own websites: files, email accounts, visitors. Nothing else on the server."] };
  async function viewPanelUsers(root) {
    root.append(pageHead("Panel Users", "Let other people into the panel with just the power they need, a colleague who only watches, or a client who manages their own website and mailboxes.",
      [btn("Add a user", () => editor(), "btn-primary")]));
    const body = el("div", {}, el("div", { class: "loading", text: "Loading…" }));
    root.append(body);
    let d;
    async function load() {
      try { d = await API.panelUsers(); } catch (e) { body.innerHTML = ""; body.append(el("p", { class: "empty", text: e.message })); return; }
      body.innerHTML = "";
      body.append(card(`Users (${d.users.length})`, [el("div", { class: "op-isos" }, d.users.map((u) => el("div", { class: `op-iso ${u.disabled ? "" : "on"}` }, [
        el("span", { class: "op-dapp-ico", style: `--h:${APP_HUE(u.username)}`, text: u.username[0].toUpperCase() }),
        el("div", { class: "grow" }, [el("b", { text: u.username }), el("p", { class: "muted mx-small mx-ell", text: u.owner ? "Owner, set up this panel" :
          `${ROLE_TXT[u.role][0]}${u.sites && u.sites.length ? ` · ${u.sites.join(", ")}` : ""}${u.last_login ? ` · last sign-in ${ago(u.last_login)}` : " · never signed in"}` })]),
        pill(u.disabled ? "disabled" : ROLE_TXT[u.role][0], u.disabled ? "dim" : u.role === "admin" ? "warn" : u.role === "site" ? "good" : "dim"),
        u.owner ? null : btn("Edit", () => editor(u), "btn-ghost"),
        u.owner ? null : armed("Delete", "Click again", () => call(() => API.panelUserDelete(u.username), "User deleted, signed out at once", load), "btn-ghost"),
      ])))]),
      card("What each role can do", [el("div", { class: "mx-list" }, Object.entries(ROLE_TXT).map(([k, [l, h]]) => el("div", { class: "mx-list-row" }, [pill(l, k === "admin" ? "warn" : k === "site" ? "good" : "dim"), el("span", { class: "grow", text: h })])))]));
    }
    function editor(u = null) {
      let role = u ? u.role : "site";
      const name = el("input", { type: "text", value: u ? u.username : "", disabled: u ? "" : null, autocomplete: "off" });
      const pw = el("input", { type: "text", placeholder: u ? "(unchanged, leave empty)" : "at least 10 characters", autocomplete: "off" });
      const gen = btn("Generate", () => { const a = new Uint32Array(16); crypto.getRandomValues(a); pw.value = Array.from(a, (n) => "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789"[n % 57]).join(""); }, "btn-ghost");
      const siteBox = el("div", { class: "op-destpick" }, d.sites.map((s) => { const c = el("input", { type: "checkbox", value: s }); c.checked = !!(u && u.sites && u.sites.includes(s)); return el("label", { class: "dm-check" }, [c, el("span", { text: s })]); }));
      const siteWrap = el("div", {}, [el("div", { class: "mx-sub" }, "Websites they manage"), d.sites.length ? siteBox : el("p", { class: "muted", text: "No websites yet, create one under Domains first." })]);
      siteWrap.hidden = role !== "site";
      const rc = el("div", { class: "em-rcards" });
      Object.entries(ROLE_TXT).forEach(([k, [l, h]]) => { const r = el("input", { type: "radio", name: "role", value: k }); r.checked = k === role; r.onchange = () => { role = k; siteWrap.hidden = role !== "site"; };
        rc.append(el("label", { class: "em-rcard" }, [r, el("span", { class: "em-rcard-ico" }, icon(k === "admin" ? "key" : k === "site" ? "globe" : "search", 18)), el("div", {}, [el("div", { class: "em-rcard-t" }, el("b", { text: l })), el("p", { class: "muted", text: h })])])); });
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
  //  Security → Global Security (one place for every security tool)
  // ======================================================================
  async function viewGlobalSecurity(root) {
    root.append(pageHead("Global Security", "Every security tool in one place, with its current state. Click a card to open it."));
    const body = el("div", {});
    root.append(body);
    const S = {};
    // Each status call runs on its own and updates its card when it lands (some, like listing every
    // certificate, are slow), the page and the cards are usable straight away.
    const withTimeout = (p, ms) => Promise.race([p, new Promise((r) => setTimeout(() => r(undefined), ms))]);
    const grab = (k, fn) => withTimeout(fn().catch(() => undefined), 9000).then((d) => { if (d !== undefined) S[k] = d; });
    const on = (t) => ({ text: t || "on", tone: "good" });
    const off = (t) => ({ text: t || "off", tone: "dim" });
    const warn = (t) => ({ text: t, tone: "warn" });
    const num0 = (n) => (n || 0);
    // key view, icon, title, description, status() -> {text,tone} | null, and whether it's a core hardening item
    const TOOLS = [
      { view: "secreport", icon: "listing", title: "Security Report", desc: "Scan everything you own on this server, panel, websites, mail, score it like an outside scanner would, and get a fix list.",
        status: () => !S.rep ? null : (S.rep.last ? { text: `${S.rep.last.grade} · ${S.rep.last.score}/100 · ${ago(S.rep.last.ts)}`, tone: S.rep.last.score >= 90 ? "good" : S.rep.last.score >= 65 ? "warn" : "bad" } : warn("not run yet")) },
      { view: "modsec", icon: "shield", title: "WAF Firewall", desc: "Blocks SQL injection, XSS and other web attacks (ModSecurity + OWASP CRS).", core: true,
        status: () => !S.waf ? null : (S.waf.installed ? (S.waf.module_on && S.waf.enabled !== false ? on(S.waf.mode === "detect" ? "detect only" : "blocking") : off("installed, off")) : off("not installed")) },
      { view: "instaban", icon: "trap", title: "InstaBan", desc: "Bans an address the moment it asks for a payload or path only attackers use, and keeps the evidence.",
        status: () => !S.ib ? null : (S.ib.enabled ? on(`on · ${S.ib.stats.bans || 0} ban${S.ib.stats.bans === 1 ? "" : "s"}`) : off("off")) },
      { view: "leech", icon: "trap", title: "Fail2ban", desc: "Bans IPs that repeatedly fail to log in (SSH, panel, mail, FTP…).", core: true,
        status: () => !S.f2b ? null : (S.f2b.installed ? (S.f2b.active ? on(`active · ${num0((S.f2b.jails || []).filter((j) => j.live).length + (S.f2b.other_jails || []).length)} jails`) : warn("installed, stopped")) : off("not installed")) },
      { view: "ipblocker", icon: "ban", title: "IP Blocker & Trust", desc: "Ban or trust any address at the firewall; see where each ban came from.",
        status: () => !S.guard ? null : on(`${num0(S.guard.bans && S.guard.bans.length)} banned · ${num0(S.guard.trusted && S.guard.trusted.length)} trusted`) },
      { view: "netmon", icon: "network", title: "Network Monitor", desc: "Who tried to reach this server, connection attempts, logins and VPN handshakes.",
        status: () => null },
      { view: "security", icon: "key", title: "Two-Factor Auth", desc: "A one-time code from your phone on top of your password, for the owner login.", core: true,
        status: () => !S.twofa ? null : (S.twofa.enabled ? on() : warn("off, recommended")) },
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
      { view: "activity", icon: "t_activity", title: "Activity Log", desc: "Who changed what in this panel, from where, plus every login.", status: () => null },
      { view: "fixperms", icon: "home", title: "Fix Permissions", desc: "Reset a website's file ownership and permissions to safe values.", status: () => null },
      { view: "firewall", icon: "firewall", title: "Firewall (ufw)", desc: "Which ports are open to the internet.", core: true,
        status: () => !S.fw ? null : (!S.fw.available ? off("not installed") : (S.fw.active ? on("active") : warn("inactive"))) },
      { view: "alerts", icon: "t_bell", title: "Alerts & Slack", desc: "Be told about attacks, failures and problems, by email, Telegram, webhook or Slack.",
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
      const ah = S.apache;
      const heroAct = el("div", { class: "mx-hero-act" }, [
        btn("Run security report", () => navigate("secreport"), "btn-primary"),
        ah && ah.available && ah.ok < ah.total ? btn(`Harden web server (${ah.total - ah.ok} to fix)`, () => runFix("apache_harden", paint), "btn-ghost") : null,
      ].filter(Boolean));
      hero.append(el("div", { class: "mx-hero-ico" }, icon("shield", 28)),
        el("div", { class: "mx-hero-txt" }, [
          el("h3", { text: `${onCount} of ${core.length} core protections on` }),
          el("p", { class: "muted", text: onCount === core.length ? "WAF, Fail2ban, two-factor login, Panel HTTPS and the firewall are all on. Nicely hardened." : "Turn on the ones marked below to harden this server: two-factor login, the WAF, Fail2ban, Panel HTTPS and the firewall." }),
        ]), heroAct);
    };
    // Fire all status calls; repaint as each resolves.
    [["guard", API.guard], ["twofa", API.twofaStatus], ["waf", API.waf], ["f2b", API.fail2ban], ["fw", API.firewall],
     ["autossl", API.autossl], ["iso", API.isolation], ["av", API.avStatus], ["https", API.panelHttps],
     ["tokens", API.tokens], ["ssl", API.sslCerts], ["slack", () => API.slack()], ["rep", API.secreport], ["apache", API.apacheHardening], ["ib", API.instaban]].forEach(([k, fn]) => grab(k, fn).then(paint));
    paint();
  }

  // One-click fixes the report (and Global Security) can offer.
  async function runFix(action, after) {
    if (action === "panel_regen") return navigate("panelhttps");
    if (action === "panel_harden") {
      if (await call(() => API.panelHttpsHarden(), "Panel restarting with strong ciphers, reloading in a moment")) setTimeout(() => location.reload(), 4000);
      return;
    }
    const r = await call(() => API.secreportFix(action), null, (r) => toast(r.message || "Done", "good"));
    if (r && after) after(r);
  }
  // action → button label; per-target actions look like "kind:argument"
  const FIX_LABEL = { ca_distrust: "Distrust it", apache_harden: "Harden web server", panel_harden: "Harden panel TLS", panel_regen: "New panel certificate", ufw_enable: "Enable firewall",
    vhost_tls: "Use server-wide TLS", autossl_run: "Get Let's Encrypt certificate", hsts: "Turn on HSTS", force_https: "Force HTTPS" };
  const fixLabel = (a) => FIX_LABEL[a] || FIX_LABEL[(a || "").split(":")[0]] || "Fix";
  const fixIsGlobal = (a) => !/^(autossl_run|hsts|force_https):/.test(a);

  // ======================================================================
  //  Files → Shadow Copies (version history of a site's files)
  // ======================================================================
  const shWhen = (ts) => new Date(ts * 1000).toLocaleString([], { month: "short", day: "numeric", hour: "numeric", minute: "2-digit" });
  const shDay = (ts) => new Date(ts * 1000).toLocaleDateString([], { weekday: "short", month: "short", day: "numeric", year: "numeric" });
  const SH_STATUS = { current: ["current", "good", "The newest copy equals the file as it is now"], modified: ["changed since", "warn", "The file changed after its last copy, the next snapshot (every 10 min) saves it"], deleted: ["deleted", "bad", "The file is gone from the site, restore any version to bring it back"] };
  const extIcon = (p) => { const e = (p.split(".").pop() || "").toLowerCase(); return /^(png|jpe?g|gif|webp|svg|ico|avif)$/.test(e) ? "image" : /^(html?|php|css|js|mjs|json|xml|md|txt|yml|yaml|ini|conf|env|htaccess)$/.test(e) ? "t_code" : /^(zip|gz|tar|tgz|7z|rar)$/.test(e) ? "packages" : "listing"; };

  async function viewShadow(root) {
    const snapAll = btn("Snapshot all now", () => call(() => API.shadowSnapshot("*"), "Snapshots taken", load), "btn-ghost");
    const head = pageHead("Shadow Copies", "A version history for a website's files: everything you upload, edit or delete can be brought back, any earlier version, or a file that is gone. Copies are taken every 10 minutes and the moment before the File Manager overwrites or deletes something, and they live outside the site where the web server can't reach them.", [snapAll]);
    head.classList.add("sh-head"); root.append(head);
    const body = el("div", {}, el("div", { class: "loading", text: "Loading…" }));
    root.append(body);
    const jp = jobPanel(root);
    let d, sel = state.viewArg && typeof state.viewArg === "string" ? state.viewArg : "", q = "", only = "", open = new Set();
    const site = () => (d.sites || []).find((s) => s.id === sel);
    const pct = (s) => Math.min(100, Math.round((s.usage.bytes / (s.max_mb * 1048576)) * 100));

    async function load() {
      try { d = await API.shadow(); } catch (e) { body.innerHTML = ""; body.append(el("p", { class: "empty", text: e.message })); return; }
      if (sel && !site()) sel = "";
      draw();
    }
    const watch = (jobId, label) => { jp.run(jobId, label); const t = setInterval(async () => { try { const j = await API.job(jobId); if (j.status !== "running") { clearInterval(t); load(); } } catch (e) { clearInterval(t); } }, 1500); };
    async function toggle(s, on, inp) {
      try {
        const r = await API.shadowEnable(s.id, on);
        toast(on ? `Shadow copies on for ${s.name}` : `Shadow copies off for ${s.name}, the copies stay until you delete them`, "good");
        if (r.job) watch(r.job, `First snapshot · ${s.name}`); else load();
      } catch (e) { if (inp) inp.checked = !on; toast(e.message, "bad"); }
    }

    function hero() {
      const on = d.sites.filter((s) => s.enabled);
      const versions = d.sites.reduce((n, s) => n + s.usage.versions, 0), bytes = d.sites.reduce((n, s) => n + s.usage.bytes, 0);
      return el("div", { class: `card mx-hero sh-hero ${on.length ? "good" : ""}` }, [
        el("div", { class: "mx-hero-ico" }, icon("shadow", 28)),
        el("div", { class: "mx-hero-txt" }, [
          el("h3", { text: on.length ? `${on.length} of ${d.sites.length} site${d.sites.length === 1 ? "" : "s"} protected` : "No site is protected yet" }),
          el("p", { class: "muted", text: on.length ? `${num(versions)} versions of ${num(d.sites.reduce((n, s) => n + s.usage.files, 0))} files · ${fmtBytes(bytes)} in ${d.store}${d.free != null ? ` · ${fmtBytes(d.free)} free on the disk` : ""}` : "Turn it on per site below. Each site gets its own limits, so you decide how much space it may take." }),
        ]),
        el("div", { class: "mx-note sh-warn" }, [icon("warning", 16), el("span", { text: "Uses extra space: every version is a full copy. The caps below (versions per file, days, total MB) keep it bounded; big files over the per-file limit are skipped. The first snapshot copies the whole site once." })]),
      ]);
    }

    function siteCard(s) {
      const sw0 = sw(s.enabled, (v, inp) => toggle(s, v, inp), { title: s.enabled ? "Turn off (copies are kept)" : "Turn on, takes a first snapshot" });
      const u = s.usage;
      return el("div", { class: `card sh-site ${s.enabled ? "on" : ""} ${s.id === sel ? "sel" : ""}` }, [
        el("div", { class: "sh-site-h" }, [
          el("span", { class: "sh-site-ico" }, icon(s.kind === "folder" ? "folder" : "globe", 18)),
          el("div", { class: "grow" }, [el("b", { text: s.name }), el("p", { class: "muted mx-small mx-ell", text: s.path, title: s.path })]),
          sw0,
        ]),
        el("div", { class: "sh-stats" }, [
          el("div", {}, [el("b", { text: num(u.versions) }), el("span", { text: "versions" })]),
          el("div", {}, [el("b", { text: num(u.files) }), el("span", { text: "files" })]),
          el("div", {}, [el("b", { text: fmtBytes(u.bytes) }), el("span", { text: `of ${s.max_mb} MB` })]),
          el("div", {}, [el("b", { text: s.last_run ? ago(s.last_run) : ", " }), el("span", { text: "last snapshot" })]),
        ]),
        s.enabled ? el("div", { class: `em-use-bar ${pct(s) >= 90 ? "bad" : pct(s) >= 70 ? "warn" : ""}` }, el("span", { style: `width:${Math.max(pct(s), u.bytes ? 1 : 0)}%` })) : null,
        el("div", { class: "toolbar" }, [
          btn(s.enabled || u.versions ? "Open history" : "Set up", () => { sel = s.id; draw(); }, "btn-primary"),
          s.enabled ? btn("Snapshot now", () => call(() => API.shadowSnapshot(s.id), null, (r) => { toast(`${r.changes} file${r.changes === 1 ? "" : "s"} copied`, "good"); load(); }), "btn-ghost") : null,
        ].filter(Boolean)),
      ]);
    }

    function settingsCard(s) {
      const inp = (v, min, max, unit) => el("input", { type: "number", value: v, min, max, class: "mx-narrow" });
      const kd = inp(s.keep_days, 1, 3650), mv = inp(s.max_versions, 1, 500), mm = inp(s.max_mb, 10, 1000000), mf = inp(s.max_file_mb, 1, 10000);
      return card("Limits for this site", [
        el("p", { class: "muted", text: "Oldest versions go first when a limit is hit; the newest copy of every file is always kept. Lowering a limit prunes right away." }),
        el("div", { class: "sh-settings" }, [field("Versions per file", mv), field("Keep for (days)", kd), field("Total space (MB)", mm), field("Skip files over (MB)", mf)]),
        el("div", { class: "toolbar" }, [
          btn("Save limits", () => call(() => API.shadowSettings(s.id, { keep_days: +kd.value, max_versions: +mv.value, max_mb: +mm.value, max_file_mb: +mf.value }), "Limits saved", (r) => { if (r.freed) toast(`${fmtBytes(r.freed)} pruned`, "good"); load(); }), "btn-primary"),
          armed("Delete all copies", "Click again, every version of this site goes", () => call(() => API.shadowForget(s.id), "All shadow copies of this site deleted", load), "btn-ghost"),
        ]),
      ]);
    }

    async function fileList(s, box) {
      box.innerHTML = ""; box.append(el("div", { class: "loading", text: "Reading the history…" }));
      let r;
      try { r = await API.shadowFiles(s.id, q, only); } catch (e) { box.innerHTML = ""; box.append(el("p", { class: "empty", text: e.message })); return; }
      box.innerHTML = "";
      const search = el("input", { type: "search", placeholder: "Find a file…", value: q, class: "sh-search" });
      let t; search.oninput = () => { clearTimeout(t); t = setTimeout(() => { q = search.value.trim(); fileList(s, box); }, 250); };
      const chips = el("div", { class: "cw-seg cw-seg-sm" }, [["", `All · ${num(r.total)}`], ["modified", `Changed since · ${num(r.counts.modified)}`], ["deleted", `Deleted · ${num(r.counts.deleted)}`], ["current", `Up to date · ${num(r.counts.current)}`]].map(([k, l]) =>
        el("button", { type: "button", class: k === only ? "active" : "", text: l, onclick: () => { only = k; fileList(s, box); } })));
      box.append(el("div", { class: "sh-tools" }, [search, chips]));
      if (!r.files.length) { box.append(empty("shadow", q || only ? "Nothing matches" : "No copies yet", q || only ? "Try another filter." : s.enabled ? "The first snapshot is on its way, or the folder is empty." : "Turn Shadow on for this site to start keeping versions.")); return; }
      box.append(el("div", { class: "sh-list" }, r.files.map((f) => {
        const [lbl, tone, hint] = SH_STATUS[f.status];
        const isOpen = open.has(f.path);
        const row = el("div", { class: `sh-row ${isOpen ? "open" : ""} st-${f.status}` });
        const head = el("button", { type: "button", class: "sh-row-h", onclick: () => { if (open.has(f.path)) open.delete(f.path); else open.add(f.path); fileList(s, box); } }, [
          el("span", { class: "sh-dotst", title: hint }), icon(extIcon(f.path), 16),
          el("span", { class: "sh-path grow", title: f.path }, [el("span", { class: "muted", text: f.path.includes("/") ? f.path.slice(0, f.path.lastIndexOf("/") + 1) : "" }), el("b", { text: f.path.split("/").pop() })]),
          pill(lbl, tone),
          el("span", { class: "muted sh-meta", text: `${f.versions.length} version${f.versions.length === 1 ? "" : "s"} · ${ago(f.versions[0].ts)}` }),
          el("span", { class: "sh-chev" }, icon("chevron", 14)),
        ]);
        row.append(head);
        if (isOpen) {
          const tl = el("div", { class: "sh-timeline" });
          if (f.current) tl.append(el("div", { class: "sh-v now" }, [el("span", { class: "sh-v-dot" }), el("div", { class: "grow" }, [el("b", { text: "Now on the site" }), el("p", { class: "muted", text: `${fmtBytes(f.current.size)} · changed ${shWhen(f.current.mtime)}${f.status === "modified" ? " · not copied yet" : ""}` })]),
            el("div", { class: "sh-v-act" }, [btn("Open in File Manager", () => navigate("files", { arg: `${r.root}/${f.path}`.replace(/\/[^/]*$/, "") }), "btn-ghost")])]));
          else tl.append(el("div", { class: "sh-v gone" }, [el("span", { class: "sh-v-dot" }), el("div", { class: "grow" }, [el("b", { text: "Gone from the site" }), el("p", { class: "muted", text: "Restore any version below to bring it back." })])]));
          let lastDay = "";
          f.versions.forEach((v, i) => {
            const day = shDay(v.ts);
            if (day !== lastDay) { tl.append(el("div", { class: "sh-day", text: day })); lastDay = day; }
            tl.append(el("div", { class: "sh-v" }, [el("span", { class: "sh-v-dot" }), el("div", { class: "grow" }, [el("b", { text: `${shWhen(v.ts)}${i === 0 ? " · newest copy" : ""}` }), el("p", { class: "muted", text: fmtBytes(v.size) })]),
              el("div", { class: "sh-v-act" }, [
                armed(f.status === "deleted" ? "Bring back" : "Restore", "Click again to restore", () => call(() => API.shadowRestore(s.id, f.path, v.ts), `Restored ${f.path.split("/").pop()} from ${shWhen(v.ts)}, the previous content was kept as a version`, () => fileList(s, box)), "btn-primary"),
                el("a", { class: "btn btn-sm btn-ghost", href: API.shadowDownloadUrl(s.id, f.path, v.ts), download: f.path.split("/").pop(), text: "Download" }),
                armed("Delete", "Click again", () => call(() => API.shadowForget(s.id, f.path, v.ts), "Version deleted", () => fileList(s, box)), "btn-ghost"),
              ])]));
          });
          tl.append(el("div", { class: "toolbar" }, [armed("Forget this file's history", "Click again, all its versions go", () => call(() => API.shadowForget(s.id, f.path), "History deleted", () => fileList(s, box)), "btn-ghost")]));
          row.append(tl);
        }
        return row;
      })));
      if (r.total > r.files.length) box.append(el("p", { class: "muted mx-small", text: `Showing ${num(r.files.length)} of ${num(r.total)}, narrow it down with the search.` }));
    }

    function detail(s) {
      const sw0 = sw(s.enabled, (v, inp) => toggle(s, v, inp), { title: s.enabled ? "Turn off (copies are kept)" : "Turn on, takes a first snapshot" });
      const head = el("div", { class: "card sh-detail-h" }, [
        btn("← All sites", () => { sel = ""; draw(); }, "btn-ghost"),
        el("span", { class: "sh-site-ico big" }, icon(s.kind === "folder" ? "folder" : "globe", 22)),
        el("div", { class: "grow" }, [el("h3", { text: s.name }), el("p", { class: "muted mx-small", text: `${s.path} · ${num(s.usage.versions)} versions · ${fmtBytes(s.usage.bytes)} of ${s.max_mb} MB${s.last_run ? ` · last snapshot ${ago(s.last_run)}` : ""}` })]),
        el("label", { class: "sh-toggle" }, [el("span", { text: s.enabled ? "On" : "Off" }), sw0]),
        s.enabled ? btn("Snapshot now", () => call(() => API.shadowSnapshot(s.id), null, (r) => { toast(`${r.changes} file${r.changes === 1 ? "" : "s"} copied`, "good"); load(); }), "btn-primary") : null,
      ].filter(Boolean));
      const files = el("div", { class: "card sh-files" });
      const setBox = el("details", { class: "sh-more" }, [el("summary", {}, [icon("gear", 14), " Limits & cleanup"]), settingsCard(s)]);
      fileList(s, files);
      return el("div", { class: "sh-detail" }, [head, s.enabled ? null : el("div", { class: "mx-note sh-warn" }, [icon("warning", 16), el("span", { text: `Shadow is off for ${s.name}. Turn it on to start keeping versions, the first snapshot copies every file under the limits (currently up to ${s.max_mb} MB in total, files over ${s.max_file_mb} MB skipped).` })]), files, setBox].filter(Boolean));
    }

    function draw() {
      body.innerHTML = "";
      if (!d.sites.length) { body.append(el("div", { class: "card" }, empty("shadow", "No websites yet", "Create a website or a folder site under Domains first, Shadow keeps a history of its files."))); return; }
      const s = site();
      if (s) { body.append(detail(s)); return; }
      body.append(hero(), el("div", { class: "sh-sites" }, d.sites.map(siteCard)));
    }
    load();
  }

  // ======================================================================
  //  Security → Security Report (scores what this server owns)
  // ======================================================================
  const SEV_TONE = { critical: "bad", high: "bad", medium: "warn", low: "dim", info: "dim" };
  const KIND_TXT = { panel: "Panel", site: "Website", ip: "By address", mail: "Mail", server: "Server" };
  const scoreTone = (n) => (n >= 90 ? "good" : n >= 65 ? "warn" : "bad");
  function scoreRing(score, grade, size = 120) {
    const r = size * 0.4, c = 2 * Math.PI * r, tone = scoreTone(score);
    const ring = el("div", { class: `sr-ring ${tone}`, style: `width:${size}px;height:${size}px` });
    ring.innerHTML = `<svg width="${size}" height="${size}" viewBox="0 0 ${size} ${size}"><circle cx="${size / 2}" cy="${size / 2}" r="${r}" class="sr-track"/>` +
      `<circle cx="${size / 2}" cy="${size / 2}" r="${r}" class="sr-bar" stroke-dasharray="${(c * score / 100).toFixed(1)} ${c.toFixed(1)}"/></svg>`;
    ring.append(el("b", {}, [document.createTextNode(grade), el("small", { text: `${score} / 100` })]));
    return ring;
  }
  async function viewSecReport(root) {
    const runBtn = btn("Run report", () => run(), "btn-primary");
    root.append(pageHead("Security Report", "What an outside scanner would say about this server, checked from the inside, only for what you own here: the panel under every name it's opened as, every website (by name and by bare address), the mail server, and the server's own protections. Each finding comes with the fix.", [runBtn]));
    const body = el("div", {}, el("div", { class: "loading", text: "Loading…" }));
    root.append(body);
    let d, picks = null;
    const chosen = () => (picks ? [...picks.querySelectorAll("input:checked")].map((c) => c.value) : []);
    async function run() {
      const ids = chosen();
      if (!ids.length) return toast("Pick at least one target", "bad");
      runBtn.disabled = true; runBtn.textContent = "Checking…";
      try { d.last = await API.secreportRun(ids); draw(); const c = d.last.counts || {}; popNotice({ title: `Report done: ${d.last.grade}, ${d.last.score} / 100`, text: `${d.last.targets.length} targets checked in ${d.last.took} s. ${(c.critical || 0) + (c.high || 0) ? `${(c.critical || 0) + (c.high || 0)} serious finding${(c.critical || 0) + (c.high || 0) === 1 ? "" : "s"} to look at.` : "Nothing serious found."}`, kind: (c.critical || 0) + (c.high || 0) ? "warn" : "good", icon: "shield", ms: 9000 }); }
      catch (e) { toast(e.message, "bad"); }
      runBtn.disabled = false; runBtn.textContent = "Run report";
    }
    function picker() {
      const groups = {};
      d.targets.forEach((t) => { (groups[t.kind] = groups[t.kind] || []).push(t); });
      const wasOn = new Set(d.last ? d.last.targets.map((t) => t.id) : d.targets.map((t) => t.id));
      picks = el("div", { class: "sr-picks" }, Object.entries(groups).map(([k, ts]) => el("div", { class: "sr-pick-grp" }, [
        el("div", { class: "mx-sub" }, KIND_TXT[k] || k),
        ...ts.map((t) => { const c = el("input", { type: "checkbox", value: t.id }); c.checked = wasOn.has(t.id); return el("label", { class: "dm-check" }, [c, el("span", { text: t.label.replace(/^[^·]+· /, "") })]); }),
      ])));
      const all = (on) => picks.querySelectorAll("input").forEach((c) => { c.checked = on; });
      return card("What to check", [el("p", { class: "muted", text: "Only things that live on this server are listed, nothing else is ever scanned. Every probe connects to this machine itself with the name as SNI / Host, so proxies and CDNs in front don't colour the result." }),
        picks, el("div", { class: "toolbar" }, [btn("All", () => all(true), "btn-ghost"), btn("None", () => all(false), "btn-ghost")])]);
    }
    function findingRow(f) {
      return el("div", { class: `sr-f sev-${f.severity}` }, [
        pill(f.severity, SEV_TONE[f.severity] || "dim"),
        el("div", { class: "grow" }, [el("b", { text: f.title }), el("p", { class: "muted", text: f.detail }), f.fix ? el("p", { class: "sr-fix" }, [el("b", { text: "Fix: " }), f.fix]) : null]),
        el("div", { class: "sr-f-act" }, [
          f.action ? btn(fixLabel(f.action), () => runFix(f.action, () => run()), "btn-primary") : null,
          f.view ? btn("Open", () => navigate(f.view), "btn-ghost") : null].filter(Boolean)),
      ]);
    }
    function draw() {
      body.innerHTML = "";
      const rep = d.last;
      if (rep) {
        const c = rep.counts || {};
        body.append(el("div", { class: `card mx-hero sr-hero ${scoreTone(rep.score)}` }, [
          scoreRing(rep.score, rep.grade, 132),
          el("div", { class: "mx-hero-txt" }, [
            el("h3", { text: rep.score >= 90 ? "Looking solid" : rep.score >= 65 ? "Some things to tighten" : "Needs attention" }),
            el("p", { class: "muted", text: `${rep.targets.length} target${rep.targets.length === 1 ? "" : "s"} checked ${ago(rep.ts)} in ${rep.took} s on ${rep.hostname}.` }),
            el("div", { class: "sr-counts" }, ["critical", "high", "medium", "low", "info"].map((k) => el("div", { class: `sr-cnt sev-${k}` }, [el("b", { text: String(c[k] || 0) }), el("span", { text: k })]))),
          ]),
          el("div", { class: "mx-hero-act" }, [
            ...(rep.fixes || []).filter(fixIsGlobal).map((a) => btn(fixLabel(a), () => runFix(a, () => run()), "btn-primary")),
            btn("Download HTML report", async () => {
              // Fetched by the page and saved as a file from here: a browser refuses a plain download from a panel on a self-signed certificate.
              try { const r = await fetch("/api/secreport/html", { credentials: "same-origin" }); if (!r.ok) throw new Error("Couldn't fetch the report"); downloadText(`security-report-${d.last.hostname}-${new Date(d.last.ts * 1000).toISOString().slice(0, 10)}.html`, await r.text(), "text/html"); }
              catch (e) { toast(e.message, "bad"); }
            }, "btn-ghost btn-sm"),
          ]),
        ]));
        body.append(el("div", { class: "sr-targets" }, rep.targets.map((t) => {
          const facts = t.facts || {}, cert = facts.cert || {};
          const meta = [facts.version ? `${facts.version} · ${facts.cipher || ""}` : null, cert.days != null ? `certificate expires in ${cert.days} days` : null,
            facts.trusted === false && facts.matches ? null : null].filter(Boolean).join(" · ");
          return el("div", { class: "card sr-t" }, [
            el("div", { class: "sr-t-h" }, [
              el("div", { class: "grow" }, [el("span", { class: "sr-kind", text: KIND_TXT[t.kind] || t.kind }), el("h3", { text: t.label.replace(/^[^·]+· /, "") }), meta ? el("p", { class: "muted mx-small", text: meta }) : null]),
              el("div", { class: `sr-grade ${scoreTone(t.score)}` }, [el("b", { text: String(t.score) }), el("span", { text: t.grade })]),
            ]),
            t.findings.length ? el("div", { class: "sr-list" }, t.findings.map(findingRow)) : el("p", { class: "sr-ok" }, [icon("check", 16), " No findings, nicely done."]),
          ]);
        })));
      } else {
        body.append(el("div", { class: "card" }, empty("listing", "No report yet", "Pick what to check below and run the report. It takes a few seconds.")));
      }
      body.append(picker());
    }
    try { d = await API.secreport(); } catch (e) { body.innerHTML = ""; body.append(el("p", { class: "empty", text: e.message })); return; }
    draw();
  }

  return { activity: viewActivity, alerts: viewAlerts, schedbackups: viewSchedBackups, updates: viewUpdates, autossl: viewAutoSSL, isolation: viewIsolation,
    dockerapps: viewDockerApps, servers: viewServers, mysites: viewMySites, panelusers: viewPanelUsers, wptoolkit: viewWPToolkit, migrate: viewMigrate,
    globalsec: viewGlobalSecurity, secreport: viewSecReport, shadow: viewShadow };
};
