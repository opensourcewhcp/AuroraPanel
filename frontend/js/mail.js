/* AuroraPanel, Email section (accounts, forwarders, routing, autoresponders, filters,
   spam, lists, delivery tracking, deliverability, import, encryption, calendars, disk, queue).
   Loaded before app.js; app.js calls window.AuroraMail(ui) once with its helpers. */
window.AuroraMail = (ui) => {
  "use strict";
  const { el, icon, btn, pill, kv, field, sw, toast, popNotice, API, navigate, state, openModal, closeModal, copyText,
    fmtBytes, ago, downloadText, esc } = ui;
  const MAIL = {};  // small per-session cache (domains for pickers)
  const LS_get = (k, d) => { try { const v = localStorage.getItem("ap." + k); return v == null ? d : JSON.parse(v); } catch (e) { return d; } };
  const LS_set = (k, v) => { try { localStorage.setItem("ap." + k, JSON.stringify(v)); } catch (e) {} };
  // Webmail is served by the web server (port 443), not by the panel's own port.
  const wm = (path) => (path && path.startsWith("/") ? `https://${location.hostname}${path}` : path);

  // ------------------------------------------------------------------ shared bits
  const hue = (s) => { let h = 0; for (const c of String(s)) h = (h * 31 + c.charCodeAt(0)) % 360; return h; };
  const avatar = (addr) => el("span", { class: "em-av", style: `--h:${hue(String(addr).split("@")[1] || addr)}`, text: String(addr)[0].toUpperCase() });
  const mb = (n) => (n ? (n >= 1024 ? `${+(n / 1024).toFixed(n % 1024 ? 1 : 0)} GB` : `${n} MB`) : "Unlimited");
  function pageHead(title, desc, actions = []) {
    return el("div", { class: "em-head" }, [
      el("div", { class: "em-head-txt" }, [el("h2", { text: title }), desc ? el("p", { class: "muted", text: desc }) : null]),
      el("div", { class: "em-head-act" }, actions.filter(Boolean)),
    ]);
  }
  function usage(used, quotaMb) {
    const pct = quotaMb ? Math.min(100, used / (quotaMb * 1048576) * 100) : 0;
    return el("div", { class: "em-use" }, [
      el("div", { class: "em-use-txt" }, [el("b", { text: fmtBytes(used || 0) }), el("span", { class: "muted", text: ` / ${mb(quotaMb)}${quotaMb ? ` · ${pct < 0.1 && used ? "<0.1" : pct.toFixed(pct < 10 ? 1 : 0)}%` : ""}` })]),
      el("div", { class: `em-use-bar ${pct >= 90 ? "bad" : pct >= 75 ? "warn" : ""}` }, el("span", { style: `width:${quotaMb ? Math.max(pct, used ? 1 : 0) : 0}%` })),
    ]);
  }
  // The default domain in forms: not an IP address (left from before those were refused, mail apps reject name@1.2.3.4).
  const prefDomain = () => (MAIL.domains || []).find((d) => !/^[0-9.]+$/.test(d)) || (MAIL.domains || [])[0];
  function domainSelect(domains, value, opts = {}) {
    const s = el("select", { class: "em-select" });
    if (opts.all) s.append(el("option", { value: "", text: opts.all }));
    domains.forEach((d) => s.append(el("option", { value: d, text: d })));
    if (opts.other) s.append(el("option", { value: "__other", text: "Another domain…" }));
    if (value != null) s.value = value;
    return s;
  }
  async function domainsAll() {
    const d = await API.mailDomains();
    MAIL.domains = d.domains.map((x) => x.domain);
    MAIL.candidates = d.candidates;
    MAIL.hostname = d.hostname;
    return d;
  }
  // Domain picker that also offers the server's websites and lets you type any other domain.
  function domainPicker(value) {
    const all = [...new Set([...(MAIL.domains || []), ...(MAIL.candidates || [])])].sort();
    const sel = domainSelect(all, value || all[0] || "__other", { other: true });
    const other = el("input", { type: "text", placeholder: "example.com", class: "em-other", hidden: sel.value !== "__other" ? "" : null });
    sel.onchange = () => { other.hidden = sel.value !== "__other"; if (!other.hidden) other.focus(); wrap.dispatchEvent(new Event("change")); };
    other.oninput = () => wrap.dispatchEvent(new Event("change"));
    const wrap = el("div", { class: "em-dpick" }, [sel, other]);
    wrap.value = () => (sel.value === "__other" ? other.value.trim().toLowerCase() : sel.value);
    return wrap;
  }
  function addrInput(domainValue) {
    const user = el("input", { type: "text", placeholder: "name", autocomplete: "off", spellcheck: "false" });
    const dp = domainPicker(domainValue);
    const node = el("div", { class: "em-addr" }, [user, el("span", { class: "em-at", text: "@" }), dp]);
    return { node, user, dp, value: () => `${user.value.trim().toLowerCase()}@${dp.value()}` };
  }
  function strength(pw) {
    let s = 0;
    if (pw.length >= 8) s++; if (pw.length >= 12) s++; if (pw.length >= 16) s++;
    if (/[A-Z]/.test(pw) && /[a-z]/.test(pw)) s++; if (/\d/.test(pw)) s++; if (/[^A-Za-z0-9]/.test(pw)) s++;
    return Math.min(5, Math.max(0, s - 1));
  }
  function pwField(required = true) {
    const inp = el("input", { type: "text", autocomplete: "new-password", placeholder: required ? "8+ characters" : "leave empty to keep", spellcheck: "false", class: "em-mono" });
    const meter = el("div", { class: "em-meter" }, [0, 1, 2, 3, 4].map(() => el("i")));
    const label = el("span", { class: "em-meter-txt muted" });
    const upd = () => {
      const s = inp.value ? strength(inp.value) : -1;
      [...meter.children].forEach((b, i) => { b.className = i <= s ? `on s${s}` : ""; });
      label.textContent = s < 0 ? "" : ["Very weak", "Weak", "Fair", "Good", "Strong", "Excellent"][s];
    };
    inp.oninput = upd;
    const gen = btn("Generate", async () => {
      try { inp.value = (await API.mailPassword()).password; } catch (e) { inp.value = ui.genPassword(18); }
      upd();
    }, "btn-ghost");
    const copy = btn("Copy", async () => toast(await copyText(inp.value) ? "Password copied" : "Copy failed", "good"), "btn-ghost");
    return { node: el("div", { class: "em-pw" }, [el("div", { class: "em-pw-row" }, [inp, gen, copy]), el("div", { class: "em-pw-meter" }, [meter, label])]),
      value: () => inp.value, input: inp, gen };
  }
  function armed(label, armedLabel, action, cls) {
    let t = null;
    const b = btn(label, async () => {
      if (!b.classList.contains("armed")) {
        b.classList.add("armed"); b.textContent = armedLabel;
        t = setTimeout(() => { b.classList.remove("armed"); b.textContent = label; }, 4000);
        return;
      }
      clearTimeout(t); b.classList.remove("armed"); b.textContent = label;
      b.disabled = true;
      try { await action(b); } finally { b.disabled = false; }
    }, cls);
    return b;
  }
  const empty = (ico, title, text, action) => el("div", { class: "em-empty" }, [el("span", { class: "em-empty-ico" }, icon(ico, 26)),
    el("b", { text: title }), el("p", { class: "muted", text }), action || null]);
  const call = async (fn, ok, after) => {
    try { const r = await fn(); if (ok) toast(ok, "good"); if (after) after(r); return r || true; }
    catch (e) { toast(e.message, "bad"); return null; }
  };
  function radioCards(name, options, value, onChange) {
    const box = el("div", { class: "em-rcards" });
    options.forEach((o) => {
      const r = el("input", { type: "radio", name, value: o.value });
      r.checked = o.value === value;
      r.onchange = () => onChange && onChange(o.value);
      box.append(el("label", { class: `em-rcard ${o.tone || ""}` }, [r, o.icon ? el("span", { class: "em-rcard-ico" }, icon(o.icon, 18)) : null, el("div", {}, [
        el("div", { class: "em-rcard-t" }, [el("b", { text: o.label }), o.badge ? pill(o.badge, o.badgeKind || "good") : null].filter(Boolean)),
        o.desc ? el("p", { class: "muted", text: o.desc }) : null, o.extra || null].filter(Boolean))].filter(Boolean)));
    });
    box.value = () => (box.querySelector("input:checked") || {}).value;
    return box;
  }
  function copyRow(label, value, mono = true) {
    return el("div", { class: "em-copy" }, [el("span", { class: "em-copy-k", text: label }),
      el("code", { class: mono ? "em-mono" : "", text: value }),
      el("button", { type: "button", class: "bk-mini", text: "Copy", onclick: async () => toast(await copyText(value) ? `${label} copied` : "Copy failed", "good") })]);
  }
  const modalWide = () => { const m = document.querySelector("#modal .modal"); if (m) m.classList.add("em-modal"); };

  // ------------------------------------------------------------------ Overview
  async function viewOverview(root) {
    const body = el("div", {}, el("div", { class: "loading", text: "Loading…" }));
    root.append(body);
    let st, doms;
    try { [st, doms] = await Promise.all([API.mailStatus(), domainsAll()]); }
    catch (e) { body.innerHTML = ""; body.append(el("p", { class: "empty", text: e.message })); return; }
    body.innerHTML = "";
    const svc = (name, on) => el("span", { class: `em-svc ${on ? "on" : "off"}` }, [el("i"), name]);
    const hostIn = el("input", { type: "text", value: st.hostname, class: "em-mono", spellcheck: "false" });
    const tls = st.tls || {};
    const selfSigned = tls.cert && tls.cert.self_signed;
    body.append(el("div", { class: "em-hero" }, [
      el("div", { class: "em-hero-main" }, [
        el("span", { class: "em-hero-ico" }, icon("mail", 30)),
        el("div", {}, [
          el("h2", { text: "Your mail server" }),
          el("div", { class: "em-svcs" }, [svc("Postfix", st.services.postfix), svc("Dovecot", st.services.dovecot), svc("Rspamd", st.services.rspamd), svc("Redis", st.services["redis-server"])]),
          el("p", { class: "muted", html: `Server name <b>${esc(st.hostname)}</b> · IP <b>${esc(st.ip || "?")}</b> · ${st.queue ? `<b>${st.queue}</b> message(s) waiting in the queue` : "queue empty"}` }),
        ]),
      ]),
      el("div", { class: "em-hero-act" }, [
        st.webmail ? el("a", { class: "btn btn-primary", href: wm(st.webmail), target: "_blank", rel: "noopener" }, [icon("inbox", 15), " Open Webmail"])
          : btn("Install Webmail", () => installComponent("webmail"), "btn-primary"),
        btn("Send a test email", () => testMail(), "btn-ghost"),
      ]),
    ]));
    if (selfSigned) body.append(el("div", { class: "dm-note" }, [icon("lock", 15), el("span", { html: "Mail is encrypted with a <b>self-signed certificate</b>. Phones and mail apps will warn about it, get a free Let's Encrypt certificate under <b>Encryption</b> once your mail host name points here." }),
      btn("Encryption", () => navigate("mailtls"), "btn-ghost")]));
    const stat = (n, label, ico, view) => el("button", { type: "button", class: "em-stat", onclick: () => navigate(view) }, [el("span", { class: "em-stat-ico" }, icon(ico, 18)), el("b", { text: String(n) }), el("span", { class: "muted", text: label })]);
    body.append(el("div", { class: "em-stats" }, [stat(st.domains, "domains", "globe", "deliverability"), stat(st.accounts, "email accounts", "users", "mailaccounts"),
      stat(st.forwarders, "forwarders", "forward", "forwarders"), stat(st.lists, "mailing lists", "listing", "mailinglists")]));
    if (!st.accounts) {
      const steps = [["Create your first email account", "Pick a domain and a name, the domain is set up automatically.", "mailaccounts", st.accounts > 0],
        ["Publish the DNS records", "MX, SPF, DKIM and DMARC so mail arrives and isn't marked as spam.", "deliverability", false],
        ["Connect your phone and computer", "One-tap profile for iPhone/Mac; automatic setup for Thunderbird and Outlook.", "mailaccounts", false]];
      body.append(el("div", { class: "card em-start" }, [el("h3", { text: "Get started in three steps" }),
        el("ol", {}, steps.map(([t, d, v]) => el("li", { onclick: () => navigate(v) }, [el("b", { text: t }), el("span", { class: "muted", text: d })])))]));
    }
    // domains with deliverability
    const dl = el("div", { class: "em-domains" }, doms.domains.length ? doms.domains.map((d) => {
      const score = el("span", { class: "em-score" }, el("span", { class: "muted", text: "checking…" }));
      return el("div", { class: "em-dom" }, [avatar(d.domain), el("div", { class: "em-dom-t" }, [el("b", { text: d.domain }),
        el("span", { class: "muted", text: `${d.accounts} account${d.accounts === 1 ? "" : "s"} · routing ${d.routing}` })]), score,
        btn("DNS health", () => { state.mailDomain = d.domain; navigate("deliverability"); }, "btn-ghost"),
        d.accounts ? null : armed("Remove", "Click again to remove", () => call(() => API.mailDomainRemove(d.domain), `${d.domain} removed`, () => navigate("email", { history: "none" })), "btn-ghost")].filter(Boolean));
    }) : [empty("globe", "No mail domains yet", "Creating an email account adds its domain automatically.", btn("Create an email account", () => navigate("mailaccounts"), "btn-primary"))]);
    body.append(el("div", { class: "card" }, [el("div", { class: "em-card-h" }, [el("h3", { text: "Domains" }), btn("Add a domain", () => addDomainModal(() => navigate("email", { history: "none" })), "btn-ghost")]), dl]));
    if (doms.domains.length) API.mailDeliverability("").then((r) => {
      r.domains.forEach((x, i) => {
        const node = dl.children[i] && dl.children[i].querySelector(".em-score");
        if (!node) return;
        node.innerHTML = "";
        node.append(x.local ? pill("local network", "good") : x.error ? pill("check failed", "warn") : pill(`${x.score}/${x.total} DNS checks`, x.score === x.total ? "good" : x.score >= 3 ? "warn" : "bad"));
      });
    }).catch(() => {});
    // all tools
    const tools = [["mailaccounts", "Email Accounts", "users"], ["forwarders", "Forwarders", "forward"], ["mailrouting", "Email Routing", "route"],
      ["autoresponders", "Autoresponders", "reply"], ["defaultaddress", "Default Address", "at"], ["mailinglists", "Mailing Lists", "listing"],
      ["trackdelivery", "Track Delivery", "pin"], ["globalfilters", "Global Email Filters", "filter"], ["emailfilters", "Email Filters", "filter"],
      ["deliverability", "Email Deliverability", "send"], ["addressimporter", "Address Importer", "upload"], ["spamfilters", "Spam Filters", "spam"],
      ["mailtls", "Encryption", "lock"], ["calendars", "Calendars & Contacts", "calendar"], ["maildisk", "Email Disk Usage", "disk"], ["mailqueue", "Mail Queue", "queue"]];
    body.append(el("div", { class: "card" }, [el("h3", { text: "Email tools" }), el("div", { class: "em-tools" },
      tools.map(([v, l, ic]) => el("button", { type: "button", class: "em-tool", onclick: () => navigate(v) }, [el("span", { class: "em-tool-ico" }, icon(ic, 20)), el("span", { text: l })])))]));
    // local network mail
    const lc = st.local || {};
    body.append(el("div", { class: "card em-local" }, [el("div", { class: "em-card-h" }, [el("h3", { text: "Local mail (no internet needed)" }),
      lc.enabled ? pill(`on · @${lc.domain}`, "good") : pill("off")]),
      el("p", { class: "muted", text: `Gives this ${lc.mdns ? "device" : "server"} its own mail domain, ${lc.domain}. Apps here (WordPress, cron, scripts) can use addresses like admin@${lc.domain}, and other AuroraPanel servers on the same network can send to it, they find each other by their .local name, no DNS or internet required.` }),
      lc.enabled ? el("div", { class: "em-local-tips" }, [
        el("div", {}, [el("b", { text: "Here" }), el("span", { class: "muted", text: lc.accounts.length ? lc.accounts.join(", ") : `No accounts yet, create e.g. admin@${lc.domain} in Email Accounts.` })]),
        el("div", {}, [el("b", { text: "Other devices" }), el("span", { class: "muted", text: `Send to name@<their-hostname>.local (e.g. you@ns2.local). ${lc.mdns ? "This device answers its .local name (avahi is running)." : "This machine doesn't run avahi, so other devices can't find it by name, fine for mail on this server itself."}` })]),
      ]) : null,
      el("div", { class: "toolbar" }, lc.enabled ? [btn("Create an account here", () => { state.mailDomain = lc.domain; navigate("mailaccounts"); }, "btn-primary"),
        btn("Turn off", () => call(() => API.mailLocal(false), "Local mail turned off", () => navigate("email", { history: "none" })), "btn-ghost")]
        : [btn(`Turn on local mail as @${lc.domain || "this-device.local"}`, () => call(() => API.mailLocal(true), "Local mail is on", () => navigate("email", { history: "none" })), "btn-primary")]),
    ].filter(Boolean)));
    // server name: detected automatically unless set by hand
    const det = st.detected || {};
    const auto = st.hostname_mode !== "manual";
    hostIn.disabled = auto;
    const autoSw = sw(auto, (v) => { hostIn.disabled = v; if (v) call(() => API.mailHostname("auto"), "Server name follows DNS automatically", () => navigate("email", { history: "none" })); });
    const guardBox = el("div", {});
    body.append(guardBox);
    mailGuard(guardBox);
    body.append(el("div", { class: "card" }, [el("h3", { text: "Mail server name (HELO)" }),
      el("p", { class: "muted", text: "The name this server introduces itself with to other mail servers. Gmail and Outlook check that it points to this server and matches the IP's reverse DNS (PTR)." }),
      el("div", { class: "em-toggle" }, [autoSw, el("div", {}, [el("b", { text: "Choose automatically (recommended)" }),
        el("span", { class: "muted", text: det.hostname ? `Best name now: ${det.hostname}. ${det.reason}` : "Follows your domains' DNS and the IP's reverse DNS." })])]),
      det.ptr !== undefined ? kv([["This server's IP", det.ip || ", "], ["Its reverse DNS (PTR)", det.ptr ? det.ptr : "none"],
        ["Matches the server name", det.ptr && det.ptr === st.hostname ? pill("yes", "good") : pill("no, ask your provider", "warn")]]) : null,
      el("div", { class: "toolbar" }, [hostIn, btn("Use this name", () => { autoSw.querySelector("input").checked = false; call(() => API.mailHostname(hostIn.value.trim()), "Server name saved", () => navigate("email", { history: "none" })); }, "btn-primary")])].filter(Boolean)));
  }
  function testMail(prefill) {
    const to = el("input", { type: "email", placeholder: "you@gmail.com", value: prefill || "" });
    openModal("Send a test email", el("div", {}, [field("Send to", to, "Then watch it in Track Delivery."),]), [
      el("button", { class: "btn btn-primary", text: "Send", onclick: async () => {
        const r = await call(() => API.mailTest(to.value.trim()), "Test message sent");
        if (r) { closeModal(); navigate("trackdelivery"); }
      } })]);
  }
  function addDomainModal(done) {
    const dp = domainPicker("");
    openModal("Add a mail domain", el("div", {}, [field("Domain", dp, "Your websites are listed; choose “Another domain…” for any other."),
      el("p", { class: "muted", text: "A DKIM key is created for it right away. You'll find the DNS records to publish under Email Deliverability." })]), [
      el("button", { class: "btn btn-primary", text: "Add domain", onclick: async () => { if (await call(() => API.mailDomainAdd(dp.value()), "Domain added")) { closeModal(); done && done(); } } })]);
  }
  function installComponent(id) {
    const host = el("div");
    openModal("Install", host, []);
    API.requires([id]).then((st) => {
      const c = st.components[id];
      host.append(ui.requireCard([c], c.name, false, () => { closeModal(); navigate(state.view, { history: "none", arg: state.viewArg }); }));
    }).catch((e) => host.append(el("p", { class: "empty", text: e.message })));
  }

  // ------------------------------------------------------------------ Remote accounts (Gmail, Outlook, any IMAP)
  // The panel keeps server settings only; the password is typed in webmail, like in any mail app, and is
  // never stored on this server. "Check Email" opens webmail with the account already selected.
  async function remoteAccounts(box) {
    let d;
    const draw = async () => {
      try { d = await API.mailRemote(); } catch (e) { box.innerHTML = ""; return; }
      box.innerHTML = "";
      const list = d.accounts.length ? el("div", { class: "em-list" }, d.accounts.map((a) => el("div", { class: "em-row" }, [
        el("span", { class: "em-avatar em-remote-av", text: (a.label || a.email).charAt(0).toUpperCase() }),
        el("div", { class: "em-row-main" }, [el("b", { text: a.label }), el("div", { class: "em-row-sub" }, [el("span", { class: "muted", text: `${a.email} · ${a.imap_host} · password never stored here` })])]),
        el("div", { class: "em-row-act" }, [
          a.webmail ? el("a", { class: "btn btn-sm btn-ghost", href: `${location.protocol}//${location.hostname}${a.webmail}`, target: "_blank", rel: "noopener", title: "Open webmail on this account" }, [icon("inbox", 13), " Check Email"]) : null,
          armed("Remove", "Sure?", async () => { try { await API.mailRemoteRemove(a.id); toast("Removed", "good"); draw(); } catch (e) { toast(e.message, "bad"); } }, "btn-ghost"),
        ].filter(Boolean)),
      ]))) : el("p", { class: "muted em-remote-empty", text: "None yet. Add your Gmail, Outlook, Yahoo, iCloud or any IMAP mailbox and read it in this server's webmail next to your local mail." });
      box.append(el("div", { class: "card" }, [
        el("div", { class: "net-card-h" }, [icon("globe", 20), el("h3", { text: "Remote accounts" }), el("span", { style: "flex:1" }),
          d.webmail ? null : el("span", { class: "muted mx-small", text: "install Webmail to read them here" }),
          btn("Add remote account", () => addRemote(d), "btn-primary")]),
        el("p", { class: "muted", style: "margin:0 0 10px", text: "Mailboxes elsewhere, read through this server's webmail. Only the server settings live here; the password is typed in webmail and never kept on this server, so nothing to steal if the panel is ever compromised." }),
        list,
      ].filter(Boolean)));
    };
    function addRemote(d) {
      let preset = "gmail";
      const P = d.presets;
      const f = {};
      const inp = (k, ph, type) => (f[k] = el("input", { type: type || "text", placeholder: ph, autocomplete: type === "password" ? "new-password" : "off", spellcheck: "false" }));
      const sel = (k, opts) => (f[k] = el("select", {}, opts.map(([v, t]) => el("option", { value: v, text: t }))));
      const seg = el("div", { class: "cw-seg cw-seg-sm", style: "margin-bottom:12px" });
      const hint = el("p", { class: "mx-note mx-note-dim", hidden: true });
      const adv = el("div", { class: "em-remote-adv" });
      const apply = () => {
        seg.querySelectorAll("button").forEach((b) => b.classList.toggle("active", b.dataset.p === preset));
        const p = P[preset];
        f.imap_host.value = p.imap_host; f.imap_port.value = p.imap_port; f.imap_enc.value = p.imap_enc;
        f.smtp_host.value = p.smtp_host; f.smtp_port.value = p.smtp_port; f.smtp_enc.value = p.smtp_enc;
        hint.hidden = !p.hint; hint.innerHTML = ""; if (p.hint) hint.append(icon("info", 16), el("span", { text: p.hint }));
        adv.open = preset === "custom";
      };
      Object.keys(P).forEach((k) => seg.append(el("button", { type: "button", "data-p": k, text: P[k].name.split(" / ")[0], onclick: () => { preset = k; apply(); } })));
      const enc = [["ssl", "SSL/TLS"], ["tls", "STARTTLS"], ["none", "None"]];
      const body = el("div", { class: "dm-form" }, [
        seg,
        el("label", { class: "cw-lbl" }, ["Email address", inp("email", "you@gmail.com", "email")]),
        el("label", { class: "cw-lbl" }, ["Name shown in webmail", inp("label", "Gmail, Work, Mum's account…")]),
        hint,
        el("details", { class: "em-remote-details" }, [el("summary", { text: "Server settings" }), adv]),
        el("label", { class: "cw-lbl" }, ["Password, only to test the sign-in now (not stored)", inp("password", "optional", "password")]),
        el("p", { class: "muted mx-small", text: "If you leave the password empty the account is added untested; you type it in webmail each time it asks. Either way this server never keeps it." }),
      ]);
      adv.append(
        el("div", { class: "em-remote-grid" }, [
          el("label", { class: "cw-lbl" }, ["IMAP server", inp("imap_host", "imap.example.com")]), el("label", { class: "cw-lbl" }, ["Port", inp("imap_port", "993", "number")]), el("label", { class: "cw-lbl" }, ["Encryption", sel("imap_enc", enc)]),
          el("label", { class: "cw-lbl" }, ["SMTP server", inp("smtp_host", "smtp.example.com")]), el("label", { class: "cw-lbl" }, ["Port", inp("smtp_port", "587", "number")]), el("label", { class: "cw-lbl" }, ["Encryption", sel("smtp_enc", enc)]),
        ]),
        el("label", { class: "cw-lbl" }, ["Sign-in name, if not the address", inp("username", "same as the address")]));
      apply();
      const go = el("button", { class: "btn btn-primary", text: "Add account", onclick: async () => {
        go.disabled = true;
        const data = { preset, email: f.email.value.trim(), label: f.label.value.trim(), username: f.username.value.trim(), password: f.password.value,
          imap_host: f.imap_host.value.trim(), imap_port: +f.imap_port.value, imap_enc: f.imap_enc.value, smtp_host: f.smtp_host.value.trim(), smtp_port: +f.smtp_port.value, smtp_enc: f.smtp_enc.value };
        try { const r = await API.mailRemoteAdd(data); closeModal(); toast(`${r.label} added${data.password ? ", sign-in tested" : ""}`, "good"); draw(); }
        catch (e) { toast(e.message, "bad"); go.disabled = false; }
      } });
      openModal("Add a remote account", body, [go]);
      setTimeout(() => f.email.focus(), 50);
    }
    draw();
  }

  // ------------------------------------------------------------------ Login protection: fail2ban's mail jails, in plain words
  // Password guessing over IMAP, POP3 and SMTP is banned at the firewall; the trusted list is fail2ban's
  // ignoreip, so a trusted address is never banned. (The WAF guards HTTP; mail logins are not HTTP.)
  async function mailGuard(box) {
    let d;
    const draw = async () => {
      try { d = await API.fail2ban(); } catch (e) { box.innerHTML = ""; return; }
      box.innerHTML = "";
      const jails = (d.jails || []).filter((j) => j.id === "dovecot" || j.id === "postfix-sasl");
      const on = !!(d.installed && d.active && jails.length && jails.every((j) => j.enabled));
      const tries = jails.length ? Math.max(...jails.map((j) => j.maxretry || 5)) : 5;
      const live = jails.map((j) => j.live).filter(Boolean);
      const failed = live.reduce((a, l) => a + (l.failed_total || 0), 0), banned = live.reduce((a, l) => a + (l.banned_total || 0), 0), now = live.reduce((a, l) => a + (l.banned_now || 0), 0);
      const sel = el("select", { class: "em-select mx-narrow" }, [3, 5, 10].map((n) => el("option", { value: n, text: `${n} wrong passwords` })));
      sel.value = String([3, 5, 10].includes(tries) ? tries : 5);
      const setIt = async (enabled) => {
        try {
          const jl = {};
          jails.forEach((j) => { jl[j.id] = { enabled, maxretry: +sel.value, findtime: -2, bantime: -2 }; });
          await API.fail2banSave(null, jl);
          toast(enabled ? `Mail logins protected: banned after ${sel.value} wrong passwords` : "Mail login protection is off", "good");
          draw();
        } catch (e) { toast(e.message, "bad"); }
      };
      box.append(el("div", { class: `card em-guard-card ${on ? "good" : ""}` }, [
        el("div", { class: "em-card-h" }, [el("h3", { text: "Login protection" }), pill(!d.installed ? "fail2ban not installed" : on ? `on · ban after ${tries} wrong passwords` : "off", on ? "good" : "warn")]),
        el("p", { class: "muted", text: "Whoever guesses mailbox passwords over IMAP, POP3 or SMTP is banned at the firewall after a few wrong tries. Addresses on your trusted list (IP Blocker & Trust) are never banned, so you can't lock yourself out." }),
        d.installed ? el("div", { class: "em-guard" }, [
          el("div", { class: "em-guard-opt" }, [el("span", { class: "muted", text: "Ban after" }), sel]),
          btn(on ? "Apply" : "Turn on", () => setIt(true), on ? "btn-ghost" : "btn-primary"),
          on ? btn("Turn off", () => setIt(false), "btn-ghost") : null,
          btn("Trusted addresses", () => navigate("ipblocker"), "btn-ghost"),
          btn("All jails", () => navigate("leech"), "btn-ghost"),
        ].filter(Boolean)) : btn("Install Fail2ban", () => navigate("leech"), "btn-primary"),
        live.length ? el("div", { class: "em-guard-stats" }, [
          el("span", {}, [el("b", { text: String(failed) }), "wrong passwords seen"]),
          el("span", {}, [el("b", { text: String(banned) }), "bans so far"]),
          el("span", {}, [el("b", { text: String(now) }), "banned right now"])]) : null,
      ].filter(Boolean)));
    };
    draw();
  }


  // ------------------------------------------------------------------ Accounts
  async function viewAccounts(root) {
    const view = { q: "", domain: state.mailDomain || "", filter: "all", sel: new Set() };
    const head = pageHead("Email Accounts", "Mailboxes people sign in to with IMAP, POP3, webmail or their phone.", [
      el("a", { class: "btn btn-ghost", href: "/api/mail/export?kind=accounts", download: "" }, [icon("backup", 14), " Export CSV"]),
      el("button", { class: "btn btn-primary", onclick: () => createAccount() }, [icon("users", 15), " Create"]),
    ]);
    const search = el("input", { type: "search", placeholder: "Search accounts…", class: "em-search", oninput: (e) => { view.q = e.target.value.toLowerCase(); draw(); } });
    const chips = el("div", { class: "em-chips" });
    const filt = el("div", { class: "cw-seg cw-seg-sm" });
    const bulk = el("div", { class: "em-bulk", hidden: true });
    const list = el("div", { class: "em-list" }, el("div", { class: "loading", text: "Loading…" }));
    const summary = el("div", { class: "em-summary muted" });
    const localBox = el("div", {});
    const remoteBox = el("div", {});
    root.append(head, localBox, el("div", { class: "card em-pad0" }, [el("div", { class: "em-tools-bar" }, [search, filt, summary]), chips, bulk, list]), remoteBox);
    remoteAccounts(remoteBox);
    let data = null;
    const load = async () => {
      try { data = await API.mailAccounts(); MAIL.domains = data.domains; MAIL.candidates = data.candidates; MAIL.webmail = data.webmail; }
      catch (e) { list.innerHTML = ""; list.append(el("p", { class: "empty", text: e.message })); return; }
      drawLocal();
      draw();
    };
    // No domain yet (or only an IP, which mail apps refuse): offer you@<hostname>.local in one click.
    function drawLocal() {
      localBox.innerHTML = "";
      const ld = data.local_domain;
      if (!ld || data.domains.includes(ld)) return;
      const ips = data.ip_domains || [];
      localBox.append(el("div", { class: "card em-local-offer" }, [
        el("span", { class: "em-local-ico" }, icon("mail", 18)),
        el("div", { class: "grow" }, [
          el("b", { text: `Mail without a domain: info@${ld}` }),
          el("p", { class: "muted", text: ips.length
            ? `Webmail and mail apps refuse addresses on an IP (${ips.join(", ")}). Local mail gives this server addresses like info@${ld}, for alerts, apps and webmail, no DNS or internet needed.`
            : `Gives this server addresses like info@${ld}, for alerts, cron, apps and webmail, with no DNS or internet needed. Other AuroraPanel servers on your network can send to it too.` }),
        ]),
        btn(`Turn on @${ld}`, () => call(() => API.mailLocal(true), `Local mail is on, create info@${ld} now`, load), "btn-primary"),
      ]));
    }
    function draw() {
      const accs = data.accounts;
      chips.innerHTML = "";
      if (data.domains.length > 1) chips.append(...["", ...data.domains].map((d) => el("button", { type: "button", class: `em-chip ${view.domain === d ? "on" : ""}`,
        text: d ? `${d} (${accs.filter((a) => a.domain === d).length})` : `All domains (${accs.length})`, onclick: () => { view.domain = d; state.mailDomain = d; draw(); } })));
      const restricted = accs.filter((a) => Object.values(a.suspend || {}).some(Boolean)).length;
      const full = accs.filter((a) => a.percent != null && a.percent >= 80).length;
      filt.innerHTML = "";
      [["all", "All"], ["restricted", `Restricted${restricted ? ` (${restricted})` : ""}`], ["full", `Almost full${full ? ` (${full})` : ""}`]].forEach(([k, l]) =>
        filt.append(el("button", { type: "button", class: view.filter === k ? "active" : "", text: l, onclick: () => { view.filter = k; draw(); } })));
      let rows = accs.filter((a) => (!view.domain || a.domain === view.domain) && (!view.q || a.address.includes(view.q) || (a.name || "").toLowerCase().includes(view.q)));
      if (view.filter === "restricted") rows = rows.filter((a) => Object.values(a.suspend || {}).some(Boolean));
      if (view.filter === "full") rows = rows.filter((a) => a.percent != null && a.percent >= 80);
      const total = accs.reduce((n, a) => n + (a.used_bytes || 0), 0);
      summary.textContent = `${accs.length} account${accs.length === 1 ? "" : "s"} · ${fmtBytes(total)} stored`;
      list.innerHTML = "";
      if (!accs.length) { list.append(empty("users", "No email accounts yet", "Create one, its domain is set up for mail automatically.", btn("Create an email account", () => createAccount(), "btn-primary"))); return; }
      if (!rows.length) {
        if (view.domain && !accs.some((a) => a.domain === view.domain)) {
          const d = view.domain;
          list.append(empty("globe", `No accounts on ${d}`, "Create one, or stop handling mail for this domain (its lists, forwarders and settings are removed too).", el("div", { class: "toolbar" }, [
            btn(`Create an account on ${d}`, () => createAccount(), "btn-primary"),
            armed(`Remove ${d}`, "Click again to remove the domain", async () => {
              const r = await call(() => API.mailDomainRemove(d), `${d} removed`);
              if (r) { view.domain = ""; state.mailDomain = ""; load(); }
            }, "btn-ghost")])));
        } else list.append(el("p", { class: "empty", text: "Nothing matches." }));
        return;
      }
      rows.forEach((a) => {
        const cb = el("input", { type: "checkbox" }); cb.checked = view.sel.has(a.address);
        cb.onchange = () => { cb.checked ? view.sel.add(a.address) : view.sel.delete(a.address); drawBulk(); };
        const sp = a.suspend || {};
        const flags = [sp.login ? pill("login off", "bad") : null, sp.incoming ? pill("not receiving", "bad") : null, sp.outgoing ? pill("not sending", "bad") : null,
          a.autoresponder ? pill("auto-reply on", "warn") : null, a.forwards.length ? pill(`${a.forwards.length} alias${a.forwards.length > 1 ? "es" : ""}`) : null].filter(Boolean);
        list.append(el("div", { class: "em-row" }, [cb, avatar(a.address),
          el("div", { class: "em-row-main", onclick: () => manageAccount(a) }, [el("b", { text: a.address }), el("div", { class: "em-row-sub" }, [a.name ? el("span", { class: "muted", text: a.name }) : null,
            flags.length ? el("span", { class: "em-flags" }, flags) : el("span", { class: "em-ok" }, [icon("shield", 12), " Unrestricted"])].filter(Boolean))]),
          usage(a.used_bytes, a.quota_mb),
          el("div", { class: "em-row-act" }, [
            data.webmail ? el("a", { class: "btn btn-sm btn-ghost", href: `${wm(data.webmail)}?_user=${encodeURIComponent(a.address)}`, target: "_blank", rel: "noopener", title: "Open webmail" }, [icon("inbox", 13), " Check Email"]) : null,
            btn("Manage", () => manageAccount(a), "btn-ghost"), btn("Connect Devices", () => connectDevices(a.address), "btn-ghost")].filter(Boolean)),
        ]));
      });
      drawBulk();
    }
    function drawBulk() {
      bulk.innerHTML = "";
      bulk.hidden = !view.sel.size;
      if (!view.sel.size) return;
      bulk.append(el("b", { text: `${view.sel.size} selected` }), armed("Delete", "Click again, delete accounts", async () => {
        for (const a of [...view.sel]) await call(() => API.mailAccountDelete(a, false));
        view.sel.clear(); toast("Deleted (mail kept on disk)", "good"); load();
      }, "btn-danger"), btn("Clear", () => { view.sel.clear(); draw(); }, "btn-ghost"));
    }
    function createAccount() {
      const ad = addrInput(view.domain || (data && data.domains[0]) || "");
      const name = el("input", { type: "text", placeholder: "Optional, e.g. Sales team" });
      const pw = pwField(true);
      let quota = 1024;
      const qCustom = el("input", { type: "number", min: 1, step: 1, value: 1024, class: "em-qnum", hidden: true });
      const qChips = el("div", { class: "em-chips em-chips-tight" });
      const qOpts = [[250, "250 MB"], [1024, "1 GB"], [5120, "5 GB"], [10240, "10 GB"], [0, "Unlimited"], ["c", "Custom"]];
      const drawQ = () => { qChips.innerHTML = ""; qOpts.forEach(([v, l]) => qChips.append(el("button", { type: "button", class: `em-chip ${(v === "c" ? !qCustom.hidden : qCustom.hidden && quota === v) ? "on" : ""}`, text: l,
        onclick: () => { if (v === "c") { qCustom.hidden = false; qCustom.focus(); } else { qCustom.hidden = true; quota = v; } drawQ(); } }))); };
      drawQ();
      const again = el("input", { type: "checkbox" });
      const preview = el("div", { class: "em-preview muted" });
      const upd = () => { const v = ad.value(); preview.textContent = /^[^@]+@[^@]+\.[^@]+$/.test(v) ? `Creates ${v}` : ""; };
      ad.user.oninput = upd; ad.dp.addEventListener("change", upd);
      pw.gen.click();
      openModal("Create an email account", el("div", { class: "em-form" }, [
        field("Email address", ad.node), field("Display name", name), field("Password", pw.node, "Share it securely, it's stored only as a hash."),
        field("Storage", el("div", {}, [qChips, qCustom]), "Mail over the limit is refused until space is freed."),
        el("label", { class: "dm-check" }, [again, el("span", { text: "Create another after this one" })]), preview]), [
        el("button", { class: "btn btn-primary", text: "Create", onclick: async (e) => {
          const b = e.currentTarget; b.disabled = true;
          const q = qCustom.hidden ? quota : parseInt(qCustom.value, 10) || 0;
          const addr = ad.value(), pass = pw.value();
          const r = await call(() => API.mailAccountCreate({ address: addr, password: pass, quota_mb: q, name: name.value.trim() }));
          b.disabled = false;
          if (!r) return;
          toast(`${r.address} created`, "good");
          load();
          if (again.checked) { ad.user.value = ""; name.value = ""; pw.gen.click(); ad.user.focus(); upd(); return; }
          closeModal();
          created(r.address, pass);
        } })]);
      modalWide(); upd(); setTimeout(() => ad.user.focus(), 50);
    }
    function created(addr, pass) {
      openModal("Account ready", el("div", { class: "em-form" }, [
        el("div", { class: "em-done" }, [el("span", { class: "bk-badge good", text: "✓" }), el("b", { text: addr })]),
        copyRow("Username", addr), copyRow("Password", pass),
        el("p", { class: "muted", text: "This password isn't shown again. Next: connect devices, or publish the domain's DNS records so mail arrives." })]), [
        btn("Connect Devices", () => connectDevices(addr), "btn-primary"), btn("DNS records", () => { closeModal(); state.mailDomain = addr.split("@")[1]; navigate("deliverability"); }, "btn-ghost")]);
    }
    function manageAccount(a) {
      const tabs = el("div", { class: "cw-seg em-tabs" });
      const pane = el("div", { class: "em-pane" });
      const T = {
        Overview: () => [el("div", { class: "em-mhead" }, [avatar(a.address), el("div", {}, [el("b", { text: a.address }), el("span", { class: "muted", text: a.created ? `created ${ago(a.created)}` : "" })])]),
          usage(a.used_bytes, a.quota_mb),
          el("div", { class: "em-quick" }, [
            data.webmail ? el("a", { class: "btn btn-sm", href: `${wm(data.webmail)}?_user=${encodeURIComponent(a.address)}`, target: "_blank", rel: "noopener" }, [icon("inbox", 13), " Check Email"]) : null,
            btn("Forwarders", () => { closeModal(); navigate("forwarders"); }, "btn-ghost"), btn("Autoresponder", () => { closeModal(); state.mailOwner = a.address; navigate("autoresponders"); }, "btn-ghost"),
            btn("Filters", () => { closeModal(); state.mailOwner = a.address; navigate("emailfilters"); }, "btn-ghost"), btn("Spam settings", () => { closeModal(); state.mailOwner = a.address; navigate("spamfilters"); }, "btn-ghost"),
            btn("Disk usage", () => { closeModal(); state.mailOwner = a.address; navigate("maildisk"); }, "btn-ghost")].filter(Boolean))],
        Security: () => {
          const pw = pwField(true);
          const name = el("input", { type: "text", value: a.name || "" });
          const sp = { ...(a.suspend || {}) };
          const tg = (k, label, desc) => el("div", { class: "em-toggle" }, [sw(!sp[k], (v) => { sp[k] = !v; }), el("div", {}, [el("b", { text: label }), el("span", { class: "muted", text: desc })])]);
          return [field("New password", pw.node), el("div", { class: "toolbar" }, [btn("Change password", async () => {
              if (await call(() => API.mailAccountUpdate({ address: a.address, password: pw.value() }), "Password changed")) pw.input.value = "";
            }, "btn-primary")]),
            field("Display name", name), el("div", { class: "toolbar" }, [btn("Save name", () => call(() => API.mailAccountUpdate({ address: a.address, name: name.value }), "Saved", load), "btn-ghost")]),
            el("h4", { class: "em-sub", text: "Restrictions" }),
            tg("login", "Allow sign-in", "IMAP, POP3, webmail and sending"), tg("incoming", "Receive new mail", "Off: senders get a “not accepting mail” error"),
            tg("outgoing", "Send mail", "Off: this account can't send"),
            el("div", { class: "toolbar" }, [btn("Save restrictions", () => call(() => API.mailAccountUpdate({ address: a.address, suspend: sp }), "Restrictions saved", load), "btn-primary")])];
        },
        Storage: () => {
          const q = el("input", { type: "number", min: 0, value: a.quota_mb || 0, class: "em-qnum" });
          return [usage(a.used_bytes, a.quota_mb), field("Quota in MB (0 = unlimited)", q),
            el("div", { class: "toolbar" }, [btn("Save quota", () => call(() => API.mailAccountUpdate({ address: a.address, quota_mb: parseInt(q.value, 10) || 0 }), "Quota saved", load), "btn-primary"),
              btn("Free up space", () => { closeModal(); state.mailOwner = a.address; navigate("maildisk"); }, "btn-ghost")])];
        },
        Delete: () => {
          const keep = el("input", { type: "checkbox" }); keep.checked = true;
          return [el("p", { text: `Delete ${a.address}? Sign-in stops at once and new mail to it is refused.` }),
            el("label", { class: "dm-check" }, [keep, el("span", { text: "Keep the stored mail (moved to the panel's trash otherwise)" })]),
            el("div", { class: "toolbar" }, [armed("Delete account", "Click again to delete", async () => {
              if (await call(() => API.mailAccountDelete(a.address, !keep.checked), "Account deleted")) { closeModal(); load(); }
            }, "btn-danger")])];
        },
      };
      const show = (k) => { tabs.querySelectorAll("button").forEach((b) => b.classList.toggle("active", b.textContent === k)); pane.innerHTML = ""; pane.append(...T[k]().filter(Boolean)); };
      Object.keys(T).forEach((k) => tabs.append(el("button", { type: "button", text: k, onclick: () => show(k) })));
      openModal(a.address, el("div", { class: "em-form" }, [tabs, pane]), [btn("Connect Devices", () => connectDevices(a.address), "btn-ghost")]);
      modalWide(); show("Overview");
    }
    load();
  }

  async function connectDevices(addr) {
    let d;
    try { d = await API.mailDevice(addr); } catch (e) { toast(e.message, "bad"); return; }
    const box = (title, ico, rows, wide) => el("div", { class: `em-dev ${wide ? "em-dev-wide" : ""}` }, [el("div", { class: "em-dev-h" }, [icon(ico, 16), el("b", { text: title })]), ...rows]);
    openModal(`Connect devices - ${addr}`, el("div", { class: "em-form" }, [
      el("div", { class: "em-dev-quick" }, [
        el("a", { class: "btn btn-primary", href: `/api/mail/accounts/mobileconfig?address=${encodeURIComponent(addr)}` }, [icon("phone", 15), " iPhone / iPad / Mac profile"]),
        d.webmail ? el("a", { class: "btn btn-ghost", href: `${wm(d.webmail)}?_user=${encodeURIComponent(addr)}`, target: "_blank", rel: "noopener" }, [icon("inbox", 15), " Webmail"]) : null].filter(Boolean)),
      el("p", { class: "muted", text: "Thunderbird, Outlook (new), K-9/Thunderbird for Android and Evolution fill these in by themselves once you type the address and password. Otherwise use:" }),
      el("div", { class: "em-dev-grid" }, [
        box("Incoming (IMAP)", "inbox", [copyRow("Server", d.incoming.imap.host), copyRow("Port", "993"), copyRow("Security", "SSL/TLS", false)]),
        box("Outgoing (SMTP)", "send", [copyRow("Server", d.outgoing.host), copyRow("Port", "465"), copyRow("Security", "SSL/TLS", false),
          el("small", { class: "dm-hint", text: "Or port 587 with STARTTLS." })]),
        box("POP3 (download only)", "backup", [copyRow("Server", d.incoming.pop3.host), copyRow("Port", "995")]),
        box("Sign in", "key", [copyRow("Username", addr), el("small", { class: "dm-hint", text: "The full email address, and the account's password, for both incoming and outgoing." })]),
        d.dav && d.dav.server ? box("Calendars & contacts", "calendar", [copyRow("Server", d.dav.server), el("small", { class: "dm-hint", text: "iPhone: Settings → Calendar → Accounts → Other → CalDAV. Android: DAVx⁵." })], true) : null,
      ].filter(Boolean)),
    ]), []);
    modalWide();
  }

  // ------------------------------------------------------------------ Forwarders
  async function viewForwarders(root) {
    const head = pageHead("Forwarders", "Send a copy of incoming mail from one address to another, or forward a whole domain.", [
      el("a", { class: "btn btn-ghost", href: "/api/mail/export?kind=forwarders", download: "" }, [icon("backup", 14), " Export CSV"]),
      btn("Add Domain Forwarder", () => addDomainFwd(), "btn-ghost"),
      el("button", { class: "btn btn-primary", onclick: () => addFwd() }, [icon("forward", 15), " Add Forwarder"])]);
    const search = el("input", { type: "search", placeholder: "Search…", class: "em-search", oninput: () => draw() });
    const list = el("div", { class: "em-list" }, el("div", { class: "loading", text: "Loading…" }));
    const dlist = el("div", {});
    root.append(head, el("div", { class: "card em-pad0" }, [el("div", { class: "em-tools-bar" }, [search]), list]), dlist);
    let data;
    const load = async () => { try { data = await API.mailForwarders(); MAIL.domains = data.domains; MAIL.candidates = data.candidates; draw(); } catch (e) { list.innerHTML = ""; list.append(el("p", { class: "empty", text: e.message })); } };
    function draw() {
      const q = search.value.toLowerCase();
      list.innerHTML = "";
      const rows = data.forwarders.filter((f) => !q || f.source.includes(q) || (f.dest || []).join(" ").toLowerCase().includes(q));
      if (!data.forwarders.length) list.append(empty("forward", "No forwarders", "Forward sales@ to your own inbox, or send everything for one address elsewhere.", btn("Add Forwarder", () => addFwd(), "btn-primary")));
      rows.forEach((f) => {
        const dests = f.type === "forward" ? f.dest.map((d) => el("span", { class: "em-dest" }, [d, el("button", { type: "button", title: "Remove this destination", text: "×",
          onclick: () => call(() => API.mailForwarderDelete(f.source, d), "Removed", load) })]))
          : [pill(f.type === "fail" ? `rejects: “${f.message}”` : "discarded", f.type === "fail" ? "warn" : "dim")];
        list.append(el("div", { class: "em-row" }, [avatar(f.source), el("div", { class: "em-row-main" }, [el("b", { text: f.source })]),
          el("span", { class: "em-arrow" }, icon("forward", 16)), el("div", { class: "em-dests" }, dests),
          el("div", { class: "em-row-act" }, [btn("Trace", () => traceModal(f.source), "btn-ghost"),
            armed("Delete", "Click again", () => call(() => API.mailForwarderDelete(f.source), "Forwarder deleted", load), "btn-ghost")])]));
      });
      dlist.innerHTML = "";
      dlist.append(el("div", { class: "card" }, [el("h3", { text: "Domain forwarders" }),
        el("p", { class: "muted", text: "Everything addressed to one domain goes to the same name at another domain (anything@old.com → anything@new.com). Real mailboxes on the domain are skipped." }),
        data.domain_forwarders.length ? el("div", { class: "em-list" }, data.domain_forwarders.map((d) => el("div", { class: "em-row" }, [avatar(d.domain),
          el("div", { class: "em-row-main" }, [el("b", { text: `*@${d.domain}` })]), el("span", { class: "em-arrow" }, icon("forward", 16)), el("div", { class: "em-dests" }, [el("span", { class: "em-dest", text: `*@${d.target}` })]),
          el("div", { class: "em-row-act" }, [armed("Delete", "Click again", () => call(() => API.mailDomainForwarder(d.domain, "", "delete"), "Removed", load), "btn-ghost")])])))
          : el("p", { class: "empty", text: "None." })]));
    }
    function addFwd() {
      const ad = addrInput(prefDomain() || "");
      const dest = el("input", { type: "text", placeholder: "someone@gmail.com, other@example.com" });
      const msg = el("input", { type: "text", value: "No such person at this address" });
      const kind = radioCards("fwd-kind", [
        { value: "forward", label: "Forward to email address", desc: "One or more addresses, separated by commas.", extra: dest },
        { value: "fail", label: "Reject with a message", desc: "The sender gets this error right away (at SMTP time).", extra: msg },
        { value: "discard", label: "Discard silently", desc: "Not recommended, the sender never learns the mail was lost.", tone: "warn" }], "forward");
      openModal("Add a forwarder", el("div", { class: "em-form" }, [field("Address to forward", ad.node), field("Destination", kind)]), [
        el("button", { class: "btn btn-primary", text: "Add Forwarder", onclick: async () => {
          if (await call(() => API.mailForwarderAdd({ source: ad.value(), kind: kind.value(), dest: dest.value, message: msg.value }), "Forwarder added")) { closeModal(); load(); }
        } })]);
      modalWide(); setTimeout(() => ad.user.focus(), 50);
    }
    function addDomainFwd() {
      const from = domainSelect(MAIL.domains, prefDomain());
      const to = el("input", { type: "text", placeholder: "newdomain.com" });
      openModal("Add a domain forwarder", el("div", { class: "em-form" }, [field("Forward all mail for", from), field("To the same names at", to)]), [
        el("button", { class: "btn btn-primary", text: "Add Domain Forwarder", onclick: async () => {
          if (await call(() => API.mailDomainForwarder(from.value, to.value.trim()), "Domain forwarder added")) { closeModal(); load(); }
        } })]);
    }
    load();
  }
  async function traceModal(addr) {
    let r;
    try { r = await API.mailTrace(addr); } catch (e) { toast(e.message, "bad"); return; }
    const label = { mailbox: ["Delivered to the mailbox", "good"], remote: ["Sent on to another server", "good"], list: ["Sent to the mailing list", "good"],
      rejected: ["Rejected", "bad"], discarded: ["Discarded", "warn"], loop: ["Loop!", "bad"] };
    openModal(`Where mail to ${addr} goes`, el("div", { class: "em-trace" }, [
      el("div", { class: "em-hop start" }, [icon("mail", 14), el("b", { text: r.address })]),
      ...r.hops.map((h) => el("div", { class: "em-hop" }, [icon("forward", 14), el("span", { text: `${h.via ? `(${h.via}) ` : ""}→ ${h.to}` })])),
      ...r.ends.map((e) => el("div", { class: `em-hop end ${label[e.result] ? label[e.result][1] : ""}` }, [el("b", { text: e.address }),
        pill((label[e.result] || [e.result])[0], (label[e.result] || [0, "dim"])[1]), e.message ? el("span", { class: "muted", text: `“${e.message}”` }) : null].filter(Boolean)))]), []);
  }

  // ------------------------------------------------------------------ Routing
  async function viewRouting(root) {
    await domainsAll().catch(() => {});
    root.append(pageHead("Email Routing", "Decide whether this server receives mail for a domain, or hands it to another mail server (Google Workspace, Microsoft 365…)."));
    if (!MAIL.domains.length) { root.append(el("div", { class: "card" }, empty("route", "No mail domains yet", "Add a domain first.", btn("Add a domain", () => addDomainModal(() => navigate("mailrouting", { history: "none" })), "btn-primary")))); return; }
    const sel = domainSelect(MAIL.domains, state.mailDomain && MAIL.domains.includes(state.mailDomain) ? state.mailDomain : prefDomain());
    const body = el("div");
    root.append(el("div", { class: "card em-routing" }, [el("div", { class: "em-route-dom" }, [el("span", { class: "muted", text: "Domain" }), sel]), body]));
    const draw = async () => {
      state.mailDomain = sel.value;
      body.innerHTML = ""; body.append(el("div", { class: "loading", text: "Looking up MX records…" }));
      let r;
      try { r = await API.mailRoutingGet(sel.value); } catch (e) { body.innerHTML = ""; body.append(el("p", { class: "empty", text: e.message })); return; }
      body.innerHTML = "";
      const cur = r.routing;
      const det = { local: "this server", backup: "another server (this one is a backup)", remote: "another server" }[r.effective];
      const cards = radioCards("routing", [
        { value: "auto", label: "Automatically detect (recommended)", desc: `Follows the domain's MX records. Right now: mail is handled by ${det}.`, badge: cur === "auto" ? "current" : null, icon: "refresh" },
        { value: "local", label: "Local mail exchanger", desc: "This server receives and stores the domain's mail, even if MX records point elsewhere.", badge: cur === "local" ? "current" : null, icon: "inbox" },
        { value: "backup", label: "Backup mail exchanger", desc: "Accept and hold mail when the main server is down, then pass it on.", badge: cur === "backup" ? "current" : null, icon: "backup" },
        { value: "remote", label: "Remote mail exchanger", desc: "Another service hosts this domain's mailboxes. Mail sent from here to the domain goes out to it.", badge: cur === "remote" ? "current" : null, icon: "send" }], cur);
      const save = btn("Save routing", () => call(() => API.mailRouting(sel.value, cards.value()), "Routing saved", draw), "btn-primary");
      save.disabled = true;
      cards.addEventListener("change", () => { save.disabled = cards.value() === cur; });
      body.append(cards, el("div", { class: "em-mxbox" }, [
        el("div", { class: "em-mxbox-h" }, [el("b", { text: "MX records for " + sel.value }), el("span", { class: "muted", text: "Where the internet sends this domain's mail" })]),
        r.mx.length ? el("div", { class: "em-mx" }, r.mx.map(([p, h]) => el("div", { class: "em-mx-row" }, [el("span", { class: "em-mx-pri", title: "Priority (lower is tried first)", text: String(p) }),
          el("code", { class: "em-mono", text: h }), h === r.hostname ? pill("this server", "good") : pill("another server")])))
          : el("p", { class: "muted", text: "No MX records, mail falls back to the domain's A record. Publish one under Email Deliverability." }),
      ]), el("div", { class: "em-route-act" }, [save, btn("Zone Editor", () => navigate("zones"), "btn-ghost")]));
    };
    sel.onchange = draw; draw();
  }

  // ------------------------------------------------------------------ Default address (catch-all)
  async function viewDefault(root) {
    let d;
    try { d = await domainsAll(); } catch (e) { root.append(el("p", { class: "empty", text: e.message })); return; }
    root.append(pageHead("Default Address", "What happens to mail sent to an address that doesn't exist on your domain."));
    if (!d.domains.length) { root.append(el("div", { class: "card" }, empty("at", "No mail domains yet", "Create an email account first.", btn("Email Accounts", () => navigate("mailaccounts"), "btn-primary")))); return; }
    const sel = domainSelect(MAIL.domains, state.mailDomain && MAIL.domains.includes(state.mailDomain) ? state.mailDomain : prefDomain());
    const body = el("div");
    root.append(el("div", { class: "card" }, [field("Domain", sel), body]));
    const draw = () => {
      state.mailDomain = sel.value;
      const dom = d.domains.find((x) => x.domain === sel.value);
      const ca = dom.catchall || { mode: "fail" };
      const msg = el("input", { type: "text", value: ca.mode === "fail" ? ca.message || "No such user here" : "No such user here" });
      const to = el("input", { type: "text", placeholder: "you@example.com", value: ca.mode === "forward" ? ca.target : "" });
      body.innerHTML = "";
      const cur = { fail: `rejects with “${ca.message || "No such user here"}”`, forward: `forwards to ${ca.target}`, discard: "discards it" }[ca.mode];
      const cards = radioCards("ca", [
        { value: "fail", label: "Reject with an error message (recommended)", desc: "The sender learns at once that the address doesn't exist.", extra: msg },
        { value: "forward", label: "Forward to an email address", desc: "A catch-all: every unknown name lands here. Expect more spam.", extra: to },
        { value: "discard", label: "Discard", desc: "Silently drop it. Not recommended.", tone: "warn" }], ca.mode);
      body.append(...[el("div", { class: "dm-note warn" }, [icon("info", 15), el("span", { html: `Right now ${esc(sel.value)} <b>${esc(cur)}</b>.` })]),
        dom.forward_to ? el("div", { class: "dm-note" }, [icon("forward", 15), el("span", { text: `This domain forwards everything to ${dom.forward_to} (Forwarders), which takes precedence.` })]) : null,
        cards, el("div", { class: "toolbar" }, [btn("Change", async () => {
          if (await call(() => API.mailCatchall({ domain: sel.value, mode: cards.value(), target: to.value, message: msg.value }), "Default address saved")) { d = await domainsAll(); draw(); }
        }, "btn-primary"), btn("Test an address", () => { const a = `test-${Math.random().toString(36).slice(2, 7)}@${sel.value}`; traceModal(a); }, "btn-ghost")])].filter(Boolean));
    };
    sel.onchange = draw; draw();
  }

  // ------------------------------------------------------------------ Autoresponders
  async function viewAutoresponders(root) {
    const head = pageHead("Autoresponders", "Automatic replies, out of office, holidays, or “we got your message”.", [el("button", { class: "btn btn-primary", onclick: () => edit() }, [icon("reply", 15), " Add Autoresponder"])]);
    const list = el("div", { class: "em-list" }, el("div", { class: "loading", text: "Loading…" }));
    root.append(head, el("div", { class: "card em-pad0" }, list));
    let data;
    const load = async () => { try { data = await API.mailAutoresponders(); draw(); if (state.mailOwner && !data.autoresponders.find((x) => x.address === state.mailOwner) && data.accounts.includes(state.mailOwner)) { const o = state.mailOwner; state.mailOwner = null; edit(null, o); } } catch (e) { list.innerHTML = ""; list.append(el("p", { class: "empty", text: e.message })); } };
    const status = (a) => {
      const now = Date.now() / 1000;
      if (!a.enabled) return pill("off");
      if (a.start && a.start > now) return pill(`starts ${new Date(a.start * 1000).toLocaleString()}`, "warn");
      if (a.stop && a.stop <= now) return pill("ended", "dim");
      return pill(a.stop ? `active until ${new Date(a.stop * 1000).toLocaleString()}` : "active", "good");
    };
    function draw() {
      list.innerHTML = "";
      if (!data.autoresponders.length) { list.append(empty("reply", "No autoresponders", data.accounts.length ? "Set one up for holidays or a support address." : "Autoresponders run on an email account, create one first.", data.accounts.length ? btn("Add Autoresponder", () => edit(), "btn-primary") : btn("Email Accounts", () => navigate("mailaccounts"), "btn-primary"))); return; }
      data.autoresponders.forEach((a) => list.append(el("div", { class: "em-row" }, [avatar(a.address), el("div", { class: "em-row-main", onclick: () => edit(a) }, [el("b", { text: a.address }), el("span", { class: "muted", text: a.subject })]),
        status(a), el("div", { class: "em-row-act" }, [btn("Edit", () => edit(a), "btn-ghost"), armed("Delete", "Click again", () => call(() => API.mailAutoresponderDelete(a.address), "Autoresponder deleted", load), "btn-ghost")])])));
    }
    function edit(a, owner) {
      if (!data.accounts.length) { toast("Create an email account first", "bad"); return; }
      a = a || { address: owner || data.accounts[0], subject: "Out of office: %subject%", body: "Hello %from%,\n\nThanks for your message. I'm away until …, and will reply when I'm back.\n\nBest regards", interval_hours: 24, enabled: true, html: false };
      const acc = el("select", {}, data.accounts.map((x) => el("option", { value: x, text: x }))); acc.value = a.address; if (a.subject && data.autoresponders.find((x) => x.address === a.address)) acc.disabled = true;
      const fromName = el("input", { type: "text", value: a.from_name || "", placeholder: "Optional, e.g. Jane Doe" });
      const subject = el("input", { type: "text", value: a.subject || "" });
      const bodyT = el("textarea", { rows: 8, class: "em-text" }); bodyT.value = a.body || "";
      const html = el("input", { type: "checkbox" }); html.checked = !!a.html;
      const interval = el("input", { type: "number", min: 0, value: a.interval_hours ?? 24, class: "em-qnum" });
      const iso = (ts) => { if (!ts) return ""; const d = new Date(ts * 1000); d.setMinutes(d.getMinutes() - d.getTimezoneOffset()); return d.toISOString().slice(0, 16); };
      const start = el("input", { type: "datetime-local", value: iso(a.start) });
      const stop = el("input", { type: "datetime-local", value: iso(a.stop) });
      const enabled = el("input", { type: "checkbox" }); enabled.checked = a.enabled !== false;
      const tag = (t, d) => el("button", { type: "button", class: "em-tag", title: d, text: t, onclick: () => { const p = bodyT.selectionStart || bodyT.value.length; bodyT.value = bodyT.value.slice(0, p) + t + bodyT.value.slice(p); bodyT.focus(); upd(); } });
      const prev = el("div", { class: "em-prev" });
      const upd = () => {
        const f = (s) => s.replace(/%subject%/g, "Meeting next week").replace(/%from%/g, "Alex Smith").replace(/%email%/g, "alex@example.com");
        prev.innerHTML = "";
        prev.append(el("div", { class: "em-prev-h" }, [el("b", { text: f(subject.value) }), el("span", { class: "muted", text: `from ${fromName.value ? `${fromName.value} <${acc.value}>` : acc.value}` })]),
          html.checked ? el("div", { class: "em-prev-b", html: f(bodyT.value).replace(/<script[\s\S]*?<\/script>/gi, "") }) : el("pre", { class: "em-prev-b", text: f(bodyT.value) }));
      };
      [subject, bodyT, fromName, acc].forEach((x) => x.addEventListener("input", upd)); html.onchange = upd;
      openModal(a.subject && data.autoresponders.find((x) => x.address === a.address) ? `Autoresponder, ${a.address}` : "Add an autoresponder", el("div", { class: "em-form em-ar" }, [
        el("div", {}, [field("Email account", acc), field("From name", fromName), field("Subject", subject),
          field("Message", bodyT), el("div", { class: "em-tags" }, [el("span", { class: "muted", text: "Insert:" }), tag("%subject%", "Their subject"), tag("%from%", "Their name"), tag("%email%", "Their address")]),
          el("label", { class: "dm-check" }, [html, el("span", { text: "The message is HTML" })]),
          el("div", { class: "em-grid2" }, [field("Start", start, "Empty = right away"), field("Stop", stop, "Empty = never")]),
          field("Reply to the same sender at most every … hours", interval, "0 = every message (careful with mailing lists)."),
          el("label", { class: "dm-check" }, [enabled, el("span", { text: "Enabled" })])]),
        el("div", { class: "em-ar-prev" }, [el("span", { class: "em-sub", text: "Preview" }), prev])]), [
        el("button", { class: "btn btn-primary", text: "Save", onclick: async () => {
          const toTs = (v) => (v ? new Date(v).toISOString() : null);
          if (await call(() => API.mailAutoresponderSave(acc.value, { from_name: fromName.value, subject: subject.value, body: bodyT.value, html: html.checked,
            interval_hours: parseInt(interval.value, 10) || 0, start: toTs(start.value), stop: toTs(stop.value), enabled: enabled.checked }), "Autoresponder saved")) { closeModal(); load(); }
        } })]);
      modalWide(); upd();
    }
    load();
  }

  // ------------------------------------------------------------------ Mailing lists
  async function viewLists(root) {
    const head = pageHead("Mailing Lists", "One address that reaches a whole group, team@, members@, announcements@.", [el("button", { class: "btn btn-primary", onclick: () => edit() }, [icon("listing", 15), " Create a list"])]);
    const list = el("div", { class: "em-list" }, el("div", { class: "loading", text: "Loading…" }));
    root.append(head, el("div", { class: "card em-pad0" }, list));
    let data;
    const load = async () => { try { data = await API.mailLists(); MAIL.domains = data.domains; MAIL.candidates = data.candidates; draw(); } catch (e) { list.innerHTML = ""; list.append(el("p", { class: "empty", text: e.message })); } };
    const ACC = { public: ["Public", "Anyone can post, e.g. info@ for a small team.", "good"], members: ["Members only", "Only addresses on the list can post, discussion lists.", "warn"],
      announce: ["Announcements", "Only the owners can post; members just receive, newsletters.", "dim"] };
    function draw() {
      list.innerHTML = "";
      if (!data.lists.length) { list.append(empty("listing", "No mailing lists", "Create team@yourdomain and add the members.", btn("Create a list", () => edit(), "btn-primary"))); return; }
      data.lists.forEach((l) => list.append(el("div", { class: "em-row" }, [avatar(l.address), el("div", { class: "em-row-main", onclick: () => edit(l) }, [el("b", { text: l.address }), el("span", { class: "muted", text: l.description || "" })]),
        pill(`${l.member_count} member${l.member_count === 1 ? "" : "s"}`), pill(ACC[l.access][0], ACC[l.access][2]),
        el("div", { class: "em-row-act" }, [btn("Edit", () => edit(l), "btn-ghost"), armed("Delete", "Click again", () => call(() => API.mailListDelete(l.address), "List deleted", load), "btn-ghost")])])));
    }
    function edit(l) {
      const isNew = !l;
      l = l || { access: "members", members: [], owners: [], prefix: true, reply_to_list: true, munge_from: true, description: "" };
      const ad = addrInput(prefDomain() || "");
      const desc = el("input", { type: "text", value: l.description || "", placeholder: "e.g. Sales team" });
      const members = el("textarea", { rows: 7, class: "em-text em-mono", placeholder: "one address per line (or paste a list)" }); members.value = (l.members || []).join("\n");
      const count = el("span", { class: "muted" });
      const cnt = () => { const n = members.value.split(/[\s,;]+/).filter((x) => x.includes("@")).length; count.textContent = `${n} member${n === 1 ? "" : "s"}`; };
      members.oninput = cnt; cnt();
      const owners = el("input", { type: "text", value: (l.owners || []).join(", "), placeholder: "owner@example.com" });
      const access = radioCards("acc", Object.entries(ACC).map(([k, v]) => ({ value: k, label: v[0], desc: v[1] })), l.access);
      const opt = (k, label, desc) => { const c = el("input", { type: "checkbox" }); c.checked = l[k] !== false; opt[k] = c; return el("label", { class: "dm-check" }, [c, el("span", {}, [el("b", { text: label }), el("span", { class: "muted", text: `, ${desc}` })])]); };
      openModal(isNew ? "Create a mailing list" : `Edit ${l.address}`, el("div", { class: "em-form" }, [
        isNew ? field("List address", ad.node) : null, field("Description", desc), field("Who can post", access),
        field("Members", el("div", {}, [members, count])), field("Owners", owners, "They receive bounces and unsubscribe requests, and may post to announcement lists."),
        opt("prefix", "Subject tag", "adds [name] to subjects"), opt("reply_to_list", "Replies go to the list", "sets Reply-To"),
        opt("munge_from", "DMARC-safe sending", "shows “Name via list” so Gmail/Outlook don't reject posts from domains with strict DMARC")].filter(Boolean)), [
        el("button", { class: "btn btn-primary", text: isNew ? "Create list" : "Save", onclick: async () => {
          const payload = { description: desc.value, access: access.value(), members: members.value.split(/[\s,;]+/).filter(Boolean), owners: owners.value.split(/[\s,;]+/).filter(Boolean),
            prefix: opt.prefix.checked, reply_to_list: opt.reply_to_list.checked, munge_from: opt.munge_from.checked };
          if (await call(() => API.mailListSave(isNew ? ad.value() : l.address, payload, isNew), isNew ? "List created" : "List saved")) { closeModal(); load(); }
        } })]);
      modalWide(); if (isNew) setTimeout(() => ad.user.focus(), 50);
    }
    load();
  }

  // ------------------------------------------------------------------ Track delivery
  // Plain-English reading of one delivery event: what happened, and what (if anything) to do about it.
  const PROVIDERS = [[/google|gmail/, "Gmail"], [/outlook|hotmail|protection\.outlook|microsoft/, "Outlook / Microsoft 365"], [/yahoo|yahoodns/, "Yahoo"],
    [/icloud|apple|me\.com/, "iCloud"], [/yandex/, "Yandex"], [/mail\.ru/, "Mail.ru"], [/proton/, "Proton Mail"], [/zoho/, "Zoho"], [/gmx|web\.de/, "GMX"]];
  function trackExplain(x) {
    const r = (x.result || "").toLowerCase(), relay = (x.relay || "").toLowerCase();
    const local = /lmtp|dovecot|private\/|local|virtual|pipe/.test(relay);
    const dir = x.status === "rejected" || local ? "in" : "out";
    const host = (relay.split("[")[0] || "").replace(/\.$/, "");
    const prov = (PROVIDERS.find(([rx]) => rx.test(relay)) || [0, ""])[1];
    let what, fix = "";
    if (x.status === "sent") {
      what = local ? "Delivered to the mailbox" : `Delivered to ${prov || host || "the receiving server"}`;
      if (x.spam != null && x.spam >= 5) fix = "It got through, but our spam check scored it high, the receiver may file it as spam.";
    } else if (x.status === "deferred") {
      what = /greylist|try again later|4\.7\.1|temporar/.test(r) ? "Receiver asked us to try again later, retrying automatically"
        : /timed out|refused|unreachable|no route|lost connection/.test(r) ? "Couldn't reach the receiving server, retrying automatically"
        : /rate|too many|throttl/.test(r) ? "Receiver is limiting how fast we send, retrying automatically"
        : /tls|certificate|ssl/.test(r) ? "Secure (TLS) connection to the receiver failed, retrying"
        : /quota|full/.test(r) ? "Their mailbox is full for now, retrying" : "Temporary problem, retrying automatically";
      fix = "Nothing to do yet: the server keeps retrying for up to 5 days. Mail Queue shows what's waiting.";
    } else if (x.status === "bounced" || x.status === "expired") {
      if (/user unknown|5\.1\.1|does not exist|no such user|unknown user|recipient not found|invalid recipient|address rejected/.test(r)) { what = "That email address doesn't exist"; fix = "Check the spelling of the address."; }
      else if (/spf|dkim|dmarc|5\.7\.(1|23|25|26)|spam|blocked|blacklist|blocklist|reputation|policy/.test(r)) { what = "Refused as spam or not authenticated"; fix = "Open Deliverability: SPF, DKIM, DMARC and reverse DNS (PTR) must all be green."; }
      else if (/quota|mailbox full|5\.2\.2|over quota/.test(r)) { what = "Their mailbox is full"; fix = "Nothing you can fix, try again later or reach them another way."; }
      else if (/too large|size|5\.3\.4/.test(r)) { what = "The message was too large for the receiver"; fix = "Send the attachment as a link instead."; }
      else if (x.status === "expired") { what = "Gave up after retrying for days"; fix = "The receiving server never accepted it, check the address or their server."; }
      else { what = "The receiving server refused it permanently"; fix = "The server's answer below says why."; }
    } else if (x.status === "rejected") {
      if (/relay access denied/.test(r)) { what = "Refused: tried to use this server to relay mail to others"; fix = "Normal, that's a spammer probing. Nothing to do."; }
      else if (/user unknown|recipient address rejected|unknown in virtual|no such user|5\.1\.1/.test(r)) { what = "Refused: no such mailbox here"; fix = "If it should exist, create it in Email Accounts or add a Forwarder."; }
      else if (/blocked using|rbl|spamhaus|dnsbl/.test(r)) { what = "Refused: the sender's IP is on a spam blocklist"; fix = "Normal protection. If it's someone you know, add them to the Spam Filters allow list."; }
      else if (/spam|milter|gtube|rspamd/.test(r)) { what = "Blocked by the spam filter"; fix = "If this was real mail, add the sender to the allow list in Spam Filters."; }
      else if (/helo|hostname/.test(r)) { what = "Refused: the sender's server introduced itself badly"; fix = "Usually a spam bot. Nothing to do."; }
      else if (/sender address rejected|not owned by user|not logged in|authentication/.test(r)) { what = "Refused: this sender isn't allowed to send as that address"; fix = "Sign in with the matching account, or check the account's sending restrictions."; }
      else { what = "Refused when it arrived"; fix = "The server's answer below says why."; }
    } else what = x.result || x.status;
    return { dir, what, fix, prov };
  }

  async function viewTrack(root) {
    const v = { hours: LS_get("track.hours", 24), status: "", q: "" };
    const q = el("input", { type: "search", placeholder: "Search an address, domain or reason…", class: "em-search" });
    let qt = null;
    q.addEventListener("input", () => { clearTimeout(qt); qt = setTimeout(() => { v.q = q.value.trim().toLowerCase(); draw(); }, 120); });
    const range = el("div", { class: "cw-seg cw-seg-sm" });
    [[1, "1 hour"], [24, "24 hours"], [168, "7 days"], [720, "30 days"]].forEach(([h, l]) => range.append(el("button", { type: "button", class: v.hours === h ? "active" : "", text: l,
      onclick: (e) => { v.hours = h; LS_set("track.hours", h); range.querySelectorAll("button").forEach((b) => b.classList.toggle("active", b === e.target)); load(); } })));
    const tiles = el("div", { class: "em-trk-tiles" });
    const table = el("div", {}, el("div", { class: "loading", text: "Reading the mail log…" }));
    const keep = el("select", { class: "em-age", title: "How long Track Delivery shows history" },
      [[7, "Keep 7 days"], [30, "Keep 30 days"], [90, "Keep 90 days"], [365, "Keep a year"]].map(([d, l]) => el("option", { value: d, text: l })));
    keep.onchange = () => call(() => API.mailTrackSettings({ days: +keep.value }), "History setting saved", load);
    const clearBtn = armed("Clear history", "Click again to clear", () => call(() => API.mailTrackSettings({ clear: true }), "History cleared", load), "btn-ghost");
    root.append(pageHead("Track Delivery", "Every email this server received or sent, and what happened to it, in plain words.", [keep, clearBtn, btn("Send a test email", () => testMail(), "btn-primary")]),
      tiles, el("div", { class: "card em-pad0" }, [el("div", { class: "em-tools-bar" }, [q, el("span", { class: "grow" }), range]), table]));
    const GROUPS = [["sent", "Delivered", "good", "check", ["sent"]], ["deferred", "Retrying", "warn", "clock", ["deferred"]],
      ["bounced", "Bounced", "bad", "warning", ["bounced", "expired"]], ["rejected", "Refused", "bad", "ban", ["rejected"]]];
    const ST = { sent: ["Delivered", "good", "✓"], deferred: ["Retrying", "warn", "⏳"], bounced: ["Bounced", "bad", "!"], rejected: ["Refused", "bad", "⛔"], expired: ["Expired", "bad", "!"] };
    let data;
    async function load() {
      table.innerHTML = ""; table.append(el("div", { class: "loading", text: "Reading the mail log…" }));
      try { data = await API.mailTrack("", "", v.hours); } catch (e) { table.innerHTML = ""; table.append(el("p", { class: "empty", text: e.message })); return; }
      if (data.settings) keep.value = String(data.settings.days);
      data.events.forEach((x) => { x._e = trackExplain(x); });
      draw();
    }
    function draw() {
      if (!data) return;
      const c = data.counts || {};
      tiles.innerHTML = "";
      tiles.append(...GROUPS.map(([k, label, tone, ico, sts]) => {
        const n = sts.reduce((a, s) => a + (c[s] || 0), 0);
        return el("button", { type: "button", class: `em-trk-tile ${tone} ${v.status === k ? "on" : ""} ${n ? "" : "zero"}`, onclick: () => { v.status = v.status === k ? "" : k; draw(); } },
          [el("span", { class: "em-trk-ico" }, icon(ico, 16)), el("b", { text: String(n) }), el("span", { text: label })]);
      }));
      const grp = GROUPS.find((g) => g[0] === v.status);
      const rows = data.events.filter((x) => (!grp || grp[4].includes(x.status)) &&
        (!v.q || `${x.from} ${x.to} ${x.result} ${x._e.what} ${x.relay} ${x.client}`.toLowerCase().includes(v.q)));
      table.innerHTML = "";
      if (!data.events.length) { table.append(empty("pin", "No email in this period", "Send a test email and it shows up here within seconds.", btn("Send a test email", () => testMail(), "btn-primary"))); return; }
      if (!rows.length) { table.append(empty("search", "Nothing matches", "Clear the search or pick another tile.")); return; }
      table.append(...[el("div", { class: "em-trk-list" }, rows.slice(0, 500).map((x) => {
        const s = ST[x.status] || [x.status, "dim", "?"], e = x._e;
        return el("button", { type: "button", class: `em-trk-row ${s[1]}`, onclick: () => detail(x) }, [
          el("span", { class: `em-ev ${s[1]}`, title: s[0], text: s[2] }),
          el("span", { class: `em-trk-dir ${e.dir}`, title: e.dir === "in" ? "Received by this server" : "Sent out by this server", text: e.dir === "in" ? "↓ In" : "↑ Out" }),
          el("span", { class: "em-trk-who" }, [el("span", { class: "em-ell", text: x.from || "(no sender)" }), el("span", { class: "muted", text: " → " }), el("b", { class: "em-ell", text: x.to || ", " })]),
          el("span", { class: "em-trk-what em-ell", title: x.result || "", text: e.what }),
          x.spam != null ? el("span", { class: `em-trk-spam ${x.spam >= 5 ? "hi" : ""}`, title: "Spam score (5 or more = likely spam)", text: x.spam.toFixed(1) }) : el("span"),
          el("span", { class: "muted em-nowrap em-trk-time", text: new Date(x.time).toLocaleString([], { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" }) }),
        ]);
      })), rows.length > 500 ? el("p", { class: "muted", style: "padding:10px 16px", text: `Showing the newest 500 of ${rows.length}.` }) : null].filter(Boolean));
    }
    function detail(x) {
      const s = ST[x.status] || [x.status, "dim"], e = x._e;
      openModal("What happened to this email", el("div", {}, [
        el("div", { class: `em-trk-verdict ${s[1]}` }, [el("b", { text: e.what }), e.fix ? el("span", { text: e.fix }) : null]),
        kv([["Status", pill(s[0], s[1])], ["Direction", e.dir === "in" ? "Received by this server" : "Sent out by this server"], ["Time", new Date(x.time).toLocaleString()],
          ["From", x.from || ", "], ["To", x.to || ", "], ["Handed to", x.relay ? `${x.relay}${e.prov ? ` (${e.prov})` : ""}` : ", "], ["Took", x.delay != null ? `${x.delay}s` : ", "],
          ["Came from", x.client || ", "], ["Signed-in user", x.user || ", "], ["Spam score", x.spam != null ? `${x.spam} ${x.spam >= 5 ? "(likely spam)" : "(fine)"}` : ", "], ["Queue ID", x.id || ", "]]),
        el("h4", { class: "em-sub", text: "The receiving server's exact answer" }), el("pre", { class: "log", text: x.result || ", " })]),
        [x.to ? btn("Trace this address", () => traceModal(x.to), "btn-ghost") : null, x.status === "deferred" ? btn("Mail Queue", () => { closeModal(); navigate("mailqueue"); }, "btn-ghost") : null,
          /spf|dkim|dmarc|spam/i.test(x.result || "") ? btn("Deliverability", () => { closeModal(); navigate("deliverability"); }, "btn-ghost") : null].filter(Boolean));
    }
    load();
  }

  // ------------------------------------------------------------------ Filters
  const PARTS = [["from", "From"], ["to", "To"], ["cc", "Cc"], ["any_recipient", "Any recipient"], ["subject", "Subject"], ["body", "Body"], ["header", "Header…"], ["spam_score", "Spam score"], ["size", "Size"]];
  const OPS = [["contains", "contains"], ["not_contains", "does not contain"], ["is", "equals"], ["not_is", "does not equal"], ["begins", "begins with"], ["ends", "ends with"], ["matches", "matches (* ?)"], ["regex", "matches regex"], ["not_regex", "doesn't match regex"]];
  const ACTS = [["fileinto", "Move to folder"], ["copyinto", "Copy to folder"], ["redirect", "Redirect to email"], ["redirect_copy", "Send a copy to email"], ["markread", "Mark as read"], ["flag", "Flag it"],
    ["reject", "Reject with message"], ["discard", "Discard (delete)"], ["stop", "Stop processing rules"]];
  function filterEditor(root, owner, intro) {
    const box = el("div", {}, el("div", { class: "loading", text: "Loading…" }));
    root.append(box);
    let filters = [];
    const load = async () => { try { filters = (await API.mailFilters(owner)).filters; draw(); } catch (e) { box.innerHTML = ""; box.append(el("p", { class: "empty", text: e.message })); } };
    const save = async (msg) => { const r = await call(() => API.mailFiltersSave(owner, filters), msg); if (!r) await load(); else draw(); return r; };
    const summary = (f) => `${f.rules.map((r) => `${(PARTS.find((p) => p[0] === r.part) || [0, r.part])[1].replace("…", ` ${r.header || ""}`)} ${r.part === "spam_score" ? "≥" : r.part === "size" ? (r.op === "under" ? "<" : ">") : (OPS.find((o) => o[0] === r.op) || [0, r.op])[1]} “${r.value}”`).join(f.match === "any" ? " or " : " and ")} → ${f.actions.map((a) => `${(ACTS.find((x) => x[0] === a.type) || [0, a.type])[1]}${a.value && !["discard", "stop", "flag", "markread"].includes(a.type) ? ` ${a.value}` : ""}`).join(", ")}`;
    function draw() {
      box.innerHTML = "";
      box.append(el("div", { class: "em-card-h" }, [el("p", { class: "muted", text: intro }), el("button", { class: "btn btn-primary", onclick: () => edit() }, [icon("filter", 15), " Create a new filter"])]));
      if (!filters.length) { box.append(empty("filter", "No filters yet", "Sort newsletters into a folder, forward invoices, or drop mail from one sender.")); return; }
      box.append(el("div", { class: "em-list" }, filters.map((f, i) => el("div", { class: `em-row ${f.enabled === false ? "em-dim" : ""}` }, [
        el("div", { class: "em-order" }, [el("button", { type: "button", title: "Up", disabled: i === 0 ? "" : null, onclick: () => { [filters[i - 1], filters[i]] = [filters[i], filters[i - 1]]; save("Order saved"); } }, "▲"),
          el("button", { type: "button", title: "Down", disabled: i === filters.length - 1 ? "" : null, onclick: () => { [filters[i + 1], filters[i]] = [filters[i], filters[i + 1]]; save("Order saved"); } }, "▼")]),
        sw(f.enabled !== false, (val) => { f.enabled = val; save(val ? "Filter on" : "Filter off"); }),
        el("div", { class: "em-row-main", onclick: () => edit(f, i) }, [el("b", { text: f.name }), el("span", { class: "muted em-ell", text: summary(f) })]),
        el("div", { class: "em-row-act" }, [btn("Edit", () => edit(f, i), "btn-ghost"), armed("Delete", "Click again", () => { filters.splice(i, 1); return save("Filter deleted"); }, "btn-ghost")])]))),
        el("p", { class: "dm-hint", text: "Filters run top to bottom; “Stop processing rules” ends the run for that message." }));
    }
    function edit(f, idx) {
      f = f ? JSON.parse(JSON.stringify(f)) : { name: "", match: "all", rules: [{ part: "from", op: "contains", value: "" }], actions: [{ type: "fileinto", value: "" }], enabled: true };
      const name = el("input", { type: "text", value: f.name, placeholder: "e.g. Newsletters" });
      const match = el("div", { class: "cw-seg cw-seg-sm" });
      const drawMatch = () => { match.innerHTML = ""; [["all", "All rules match"], ["any", "Any rule matches"]].forEach(([k, l]) => match.append(el("button", { type: "button", class: f.match === k ? "active" : "", text: l, onclick: () => { f.match = k; drawMatch(); } }))); };
      drawMatch();
      const rulesBox = el("div", { class: "em-rules" }), actsBox = el("div", { class: "em-rules" });
      const drawRules = () => {
        rulesBox.innerHTML = "";
        f.rules.forEach((r, i) => {
          const part = el("select", {}, PARTS.map(([v, l]) => el("option", { value: v, text: l }))); part.value = r.part;
          const isNum = r.part === "spam_score" || r.part === "size";
          const op = el("select", {}, (r.part === "size" ? [["over", "is larger than"], ["under", "is smaller than"]] : r.part === "spam_score" ? [["over", "is at least"]] : OPS).map(([v, l]) => el("option", { value: v, text: l })));
          op.value = r.op; if (!op.value) { op.selectedIndex = 0; r.op = op.value; }
          const hdr = el("input", { type: "text", placeholder: "Header name", value: r.header || "", class: "em-hdr", hidden: r.part !== "header" ? "" : null, oninput: (e) => { r.header = e.target.value; } });
          const val = el("input", { type: "text", value: r.value, placeholder: r.part === "size" ? "e.g. 5M" : r.part === "spam_score" ? "e.g. 5" : "value", oninput: (e) => { r.value = e.target.value; } });
          part.onchange = () => { r.part = part.value; r.op = r.part === "size" || r.part === "spam_score" ? "over" : "contains"; drawRules(); };
          op.onchange = () => { r.op = op.value; };
          rulesBox.append(el("div", { class: "em-rule" }, [part, hdr, op, val, el("button", { type: "button", class: "bk-mini", text: "−", title: "Remove", disabled: f.rules.length < 2 ? "" : null, onclick: () => { f.rules.splice(i, 1); drawRules(); } })]));
        });
        rulesBox.append(el("button", { type: "button", class: "bk-mini", text: "+ Add rule", onclick: () => { f.rules.push({ part: "subject", op: "contains", value: "" }); drawRules(); } }));
      };
      const drawActs = () => {
        actsBox.innerHTML = "";
        f.actions.forEach((a, i) => {
          const t = el("select", {}, ACTS.map(([v, l]) => el("option", { value: v, text: l }))); t.value = a.type;
          const needs = ["fileinto", "copyinto", "redirect", "redirect_copy", "reject"].includes(a.type);
          const val = el("input", { type: "text", value: a.value || "", hidden: needs ? null : "", placeholder: a.type.includes("redirect") ? "someone@example.com" : a.type === "reject" ? "Message for the sender" : "Folder (e.g. Newsletters or Work/Invoices)", oninput: (e) => { a.value = e.target.value; } });
          t.onchange = () => { a.type = t.value; drawActs(); };
          actsBox.append(el("div", { class: "em-rule" }, [t, val, el("button", { type: "button", class: "bk-mini", text: "−", disabled: f.actions.length < 2 ? "" : null, onclick: () => { f.actions.splice(i, 1); drawActs(); } })]));
        });
        actsBox.append(el("button", { type: "button", class: "bk-mini", text: "+ Add action", onclick: () => { f.actions.push({ type: "stop", value: "" }); drawActs(); } }));
      };
      drawRules(); drawActs();
      openModal(idx == null ? "Create a filter" : `Edit filter, ${f.name}`, el("div", { class: "em-form" }, [field("Filter name", name), el("h4", { class: "em-sub", text: "When a message arrives" }), match, rulesBox,
        el("h4", { class: "em-sub", text: "Then" }), actsBox,
        el("p", { class: "dm-hint", text: "Tip: rule “Spam score is at least 5” catches what the spam filter marked; Size over 10M finds big attachments." })]), [
        el("button", { class: "btn btn-primary", text: "Save filter", onclick: async () => {
          f.name = name.value.trim();
          const next = filters.slice(); if (idx == null) next.push(f); else next[idx] = f;
          const old = filters; filters = next;
          if (await save("Filter saved")) closeModal(); else filters = old;
        } })]);
      modalWide(); setTimeout(() => name.focus(), 50);
    }
    load();
  }
  function viewGlobalFilters(root) {
    root.append(pageHead("Global Email Filters", "Rules for every mailbox on this server, run before each account's own filters."));
    const card = el("div", { class: "card" }); root.append(card);
    filterEditor(card, "global", "Applies to all mail delivered to any account on this server.");
  }
  async function viewEmailFilters(root) {
    root.append(pageHead("Email Filters", "Rules for one email account, sort, forward or drop its incoming mail."));
    let accs;
    try { accs = (await API.mailAccounts()).accounts.map((a) => a.address); } catch (e) { root.append(el("p", { class: "empty", text: e.message })); return; }
    if (!accs.length) { root.append(el("div", { class: "card" }, empty("filter", "No email accounts", "Filters belong to an account.", btn("Email Accounts", () => navigate("mailaccounts"), "btn-primary")))); return; }
    const cur = state.mailOwner && accs.includes(state.mailOwner) ? state.mailOwner : accs[0];
    const sel = el("select", {}, accs.map((a) => el("option", { value: a, text: a }))); sel.value = cur;
    const card = el("div", { class: "card" });
    root.append(el("div", { class: "card em-pickbar" }, [field("Account", sel)]), card);
    const draw = () => { state.mailOwner = sel.value; card.innerHTML = ""; filterEditor(card, sel.value, `Filters for ${sel.value}.`); };
    sel.onchange = draw; draw();
  }

  // ------------------------------------------------------------------ Deliverability
  async function viewDeliverability(root) {
    const body = el("div", {}, el("div", { class: "loading", text: "Checking DNS…" }));
    root.append(pageHead("Email Deliverability", "The DNS records that make mail arrive, and keep it out of spam folders at Gmail, Outlook and Yahoo."), body);
    let all;
    try { all = await API.mailDeliverability(""); } catch (e) { body.innerHTML = ""; body.append(el("p", { class: "empty", text: e.message })); return; }
    body.innerHTML = "";
    if (!all.domains.length) { body.append(el("div", { class: "card" }, empty("send", "No mail domains yet", "Create an email account first.", btn("Email Accounts", () => navigate("mailaccounts"), "btn-primary")))); return; }
    const listBox = el("div", { class: "card em-pad0" }, el("div", { class: "em-list" }, all.domains.map((d) => el("div", { class: "em-row" }, [avatar(d.domain),
      el("div", { class: "em-row-main", onclick: () => (d.local ? null : detail(d.domain)) }, [el("b", { text: d.domain }), el("span", { class: "muted", text: d.error ? d.error : d.local ? "Local network domain, no DNS records needed" : d.problems.length ? `Problems: ${d.problems.join(", ")}` : "All checks pass" })]),
      d.local ? pill("local", "good") : d.error ? pill("error", "bad") : el("span", { class: `em-ring ${d.score === d.total ? "good" : d.score >= 3 ? "warn" : "bad"}`, text: `${d.score}/${d.total}` }),
      el("div", { class: "em-row-act" }, d.local ? [] : [btn("Manage", () => detail(d.domain), "btn-ghost")])]))));
    const detBox = el("div");
    body.append(listBox, detBox);
    async function detail(domain) {
      state.mailDomain = domain;
      detBox.innerHTML = ""; detBox.append(el("div", { class: "loading", text: `Checking ${domain}…` }));
      let r;
      try { r = await API.mailDeliverability(domain); } catch (e) { detBox.innerHTML = ""; detBox.append(el("p", { class: "empty", text: e.message })); return; }
      detBox.innerHTML = "";
      const where = r.zone_here ? (r.authoritative ? "This server answers DNS for the domain: install the records with one click." : "There's a zone for it on this server, but the domain's nameservers are elsewhere, records installed here won't be seen until the nameservers point here.")
        : `DNS for ${domain} is served by ${r.nameservers.join(", ") || "unknown nameservers"}, add these records there (registrar, Cloudflare…).`;
      const CH = { mx: ["MX", "Where mail for the domain is delivered."], spf: ["SPF", "Which servers may send mail as the domain."], dkim: ["DKIM", "A signature proving the mail wasn't forged or changed."],
        dmarc: ["DMARC", "Tells receivers what to do when SPF/DKIM fail, required by Gmail and Yahoo for bulk senders."], ptr: ["Reverse DNS (PTR)", "The IP's name must match the server name."] };
      detBox.append(el("div", { class: "card" }, [el("div", { class: "em-card-h" }, [el("h3", { text: domain }), el("div", { class: "toolbar" }, [btn("Re-check", () => detail(domain), "btn-ghost"), btn("Zone Editor", () => navigate("zones"), "btn-ghost")])]),
        el("div", { class: `dm-note ${r.zone_here && r.authoritative ? "good" : ""}` }, [icon("info", 15), el("span", { text: where })]),
        el("p", { class: "muted", html: `Mail server <b>${esc(r.hostname)}</b> · IP <b>${esc(r.ip)}</b>` }),
        ...Object.entries(r.checks).map(([k, c]) => el("div", { class: `em-check ${c.ok ? "ok" : "bad"}` }, [
          el("div", { class: "em-check-h" }, [el("span", { class: `em-ev ${c.ok ? "good" : "warn"}`, text: c.ok ? "✓" : "!" }), el("b", { text: CH[k][0] }), el("span", { class: "muted", text: CH[k][1] }),
            el("span", { class: "grow" }), pill(c.ok ? "Valid" : "Problem", c.ok ? "good" : "warn")]),
          c.note ? el("p", { class: "em-check-note", text: c.note }) : null,
          c.current && k !== "ptr" ? copyRow("Current", c.current) : null,
          k === "ptr" ? kv([["IP", c.ip], ["Its name now", c.current || "none"], ["Should be", c.hostname]]) : null,
          !c.ok && c.suggest && c.suggest.value ? el("div", { class: "em-suggest" }, [el("span", { class: "em-sub", text: `Suggested ${c.suggest.type} record` }),
            copyRow("Name", c.suggest.name), copyRow("Value", c.suggest.value),
            r.zone_here ? el("div", { class: "toolbar" }, [btn("Install the suggested record", () => call(() => API.mailDeliverabilityInstall(domain, k), `${CH[k][0]} record installed`, () => detail(domain)), "btn-primary")]) : null].filter(Boolean)) : null,
        ].filter(Boolean)))]));
      detBox.scrollIntoView({ behavior: "smooth", block: "start" });
    }
    if (state.mailDomain && all.domains.find((d) => d.domain === state.mailDomain)) detail(state.mailDomain);
  }

  // ------------------------------------------------------------------ Address importer
  async function viewImporter(root) {
    await domainsAll().catch(() => {});
    root.append(pageHead("Address Importer", "Create many email accounts or forwarders at once from a CSV file or a pasted list."));
    const kind = radioCards("imp", [{ value: "accounts", label: "Email accounts", desc: "email, password (optional, generated if empty), quota in MB (optional)", icon: "users" },
      { value: "forwarders", label: "Forwarders", desc: "source address, destination address(es) separated by ; or |", icon: "forward" }], "accounts");
    const text = el("textarea", { rows: 9, class: "em-text em-mono", placeholder: "email,password,quota_mb\njane@example.com,1024\njohn@example.com,S3cure-pass!,5120" });
    const file = el("input", { type: "file", accept: ".csv,.txt,text/csv", onchange: async () => { const f = file.files[0]; if (f) text.value = await f.text(); } });
    const dom = domainSelect(MAIL.domains || [], "", { all: ", none, " });
    const quota = el("input", { type: "number", value: 1024, min: 0, class: "em-qnum" });
    const out = el("div");
    const sample = () => downloadText(kind.value() === "accounts" ? "accounts-example.csv" : "forwarders-example.csv",
      kind.value() === "accounts" ? "email,password,quota_mb\njane@example.com,1024\njohn,\n" : "source,destination\nsales@example.com,jane@example.com;john@example.com\n", "text/csv");
    root.append(el("div", { class: "card em-form" }, [field("1 · What to import", kind), field("2 · CSV file or pasted text", el("div", {}, [file, text])),
      el("div", { class: "em-grid2" }, [field("Domain for bare names", dom, "Rows like “john” become john@this-domain"), field("Default quota (MB)", quota, "For accounts without one; 0 = unlimited")]),
      el("div", { class: "toolbar" }, [btn("Preview", () => run(true), "btn-primary"), btn("Download an example file", sample, "btn-ghost")]), out]));
    let last = null;
    async function run(dry) {
      const r = await call(() => API.mailImport({ kind: kind.value(), text: text.value, dry_run: dry, default_domain: dom.value, quota_mb: parseInt(quota.value, 10) || 0 }));
      if (!r) return;
      last = r;
      out.innerHTML = "";
      const accounts = kind.value() === "accounts";
      out.append(el("div", { class: "em-imp-sum" }, [pill(`${r.valid} ready`, "good"), r.invalid ? pill(`${r.invalid} with problems`, "bad") : null, dry ? null : pill("imported", "good")].filter(Boolean)),
        el("div", { class: "table-wrap" }, el("table", { class: "em-table" }, [el("thead", {}, el("tr", {}, ["#", accounts ? "Address" : "Source", accounts ? "Password" : "Destination", accounts ? "Quota" : "", "Status"].map((h) => el("th", { text: h })))),
          el("tbody", {}, r.rows.map((x) => el("tr", {}, [el("td", { text: x.line }), el("td", { text: x.address || x.source || ", " }),
            el("td", { class: "em-mono", text: accounts ? (x.password ? (x.generated ? (dry ? "generated on import" : x.password) : "••••••••") : ", ") : x.dest || ", " }),
            el("td", { text: accounts && x.quota_mb != null ? mb(x.quota_mb) : "" }),
            el("td", {}, x.ok ? pill(dry ? "ok" : "created", "good") : el("span", { class: "em-err", text: x.error }))])))])));
      if (dry && r.valid) out.append(el("div", { class: "toolbar" }, [btn(`Import ${r.valid} ${accounts ? "account" : "forwarder"}${r.valid > 1 ? "s" : ""}`, () => run(false), "btn-primary")]));
      if (!dry && accounts) out.append(el("div", { class: "toolbar" }, [btn("Download the passwords (CSV)", () => downloadText("imported-accounts.csv",
        "email,password,quota_mb\n" + last.rows.filter((x) => x.ok).map((x) => `${x.address},${x.password},${x.quota_mb}`).join("\n") + "\n", "text/csv"), "btn-primary"),
        el("span", { class: "dm-hint", text: "Generated passwords are shown only now." })]));
    }
  }

  // ------------------------------------------------------------------ Spam
  async function viewSpam(root) {
    let accs = [];
    try { accs = (await API.mailAccounts()).accounts.map((a) => a.address); } catch (e) {}
    root.append(pageHead("Spam Filters", "Rspamd scores every incoming message. Decide what happens to the ones it marks as spam."));
    const sel = el("select", {}, [el("option", { value: "global", text: "All accounts (server default)" }), ...accs.map((a) => el("option", { value: a, text: a }))]);
    sel.value = state.mailOwner && accs.includes(state.mailOwner) ? state.mailOwner : "global";
    const body = el("div");
    root.append(el("div", { class: "card em-pickbar" }, [field("Settings for", sel)]), body);
    const LEVELS = [[3, "Strict"], [5, "Balanced"], [8, "Relaxed"], [12, "Very relaxed"]];
    const draw = async () => {
      state.mailOwner = sel.value === "global" ? null : sel.value;
      body.innerHTML = ""; body.append(el("div", { class: "loading", text: "Loading…" }));
      let d;
      try { d = await API.mailSpam(sel.value); } catch (e) { body.innerHTML = ""; body.append(el("p", { class: "empty", text: e.message })); return; }
      body.innerHTML = "";
      const g = sel.value === "global";
      const v = { ...d };
      const thr = el("input", { type: "range", min: 1, max: 15, step: 1, value: v.threshold, class: "em-range" });
      const thrTxt = el("b");
      const desc = () => { const n = +thr.value; v.threshold = n; thrTxt.textContent = `${n}, ${n <= 3 ? "strict: catches more, may catch good mail" : n <= 6 ? "balanced (recommended)" : n <= 9 ? "relaxed" : "very relaxed: only obvious spam"}`; };
      thr.oninput = desc; desc();
      const del = el("input", { type: "number", min: 2, max: 50, value: v.delete_threshold, class: "em-qnum", oninput: (e) => { v.delete_threshold = +e.target.value; } });
      const toggle = (k, title, text, extra) => el("div", { class: "em-sp" }, [sw(!!v[k], (x) => { v[k] = x; }), el("div", {}, [el("b", { text: title }), el("p", { class: "muted", text }), extra || null].filter(Boolean))]);
      const listEd = (k, ph) => { const t = el("textarea", { rows: 4, class: "em-text em-mono", placeholder: ph }); t.value = (v[k] || []).join("\n"); t.oninput = () => { v[k] = t.value.split(/[\s,;]+/).filter(Boolean); }; return t; };
      if (g && d.stats) body.append(el("div", { class: "em-stats" }, [["scanned", "scanned"], ["ham", "clean"], ["spam", "marked spam"], ["rejected", "rejected"]].map(([k, l]) =>
        el("div", { class: "em-stat" }, [el("b", { text: String(d.stats[k] || 0) }), el("span", { class: "muted", text: l })]))));
      if (!g) body.append(el("div", { class: `dm-note ${d.custom ? "" : "good"}` }, [icon("info", 15), el("span", { text: d.custom ? "This account has its own spam settings." : "This account follows the server default, saving here gives it its own settings." }),
        d.custom ? btn("Use server default", () => call(() => API.mailSpamSave(sel.value, { reset: true }), "Back to the server default", draw), "btn-ghost") : null].filter(Boolean)));
      body.append(el("div", { class: "card" }, [
        toggle("enabled", "Process new mail and act on spam", "Rspamd marks suspicious messages with a score; the rules below decide what happens."),
        el("div", { class: "em-sp-thr" }, [el("span", { class: "em-sub", text: "Spam threshold score" }), el("div", { class: "em-range-row" }, [thr, el("div", { class: "em-levels" }, LEVELS.map(([n, l]) => el("button", { type: "button", class: "em-tag", text: l, onclick: () => { thr.value = n; desc(); } })))]), thrTxt]),
        toggle("junk", "Move spam to the Junk folder (Spam Box)", "Recommended, nothing is lost; check Junk now and then."),
        toggle("autodelete", "Automatically delete obvious spam", "Permanently deletes messages scoring at or above:", el("div", { class: "toolbar" }, [del, el("span", { class: "muted", text: "Keep it well above the threshold." })])),
        g ? toggle("greylist", "Greylisting", "Ask unknown senders to retry a few minutes later, spam robots usually don't. Delays the first mail from new senders.") : null,
        el("div", { class: "em-grid2" }, [field("Always allow (whitelist)", listEd("allow", "friend@example.com\ntrusted-company.com"), "Addresses or whole domains, one per line."),
          field("Always block (blacklist)", listEd("block", "spammer@example.com\nbad-domain.biz"), "Mail from these is rejected or dropped.")]),
        el("div", { class: "toolbar" }, [btn("Save", () => call(() => API.mailSpamSave(sel.value, v), "Spam settings saved", draw), "btn-primary")]),
      ].filter(Boolean)));
    };
    sel.onchange = draw; draw();
  }

  // ------------------------------------------------------------------ Encryption (TLS)
  async function viewTLS(root) {
    const body = el("div", {}, el("div", { class: "loading", text: "Loading…" }));
    root.append(pageHead("Encryption", "TLS keeps passwords and messages private between mail apps and this server, and between mail servers."), body);
    let d;
    try { d = await API.mailTLS(); } catch (e) { body.innerHTML = ""; body.append(el("p", { class: "empty", text: e.message })); return; }
    body.innerHTML = "";
    const c = d.cert || {};
    const days = c.expires ? Math.round((new Date(c.expires) - Date.now()) / 864e5) : null;
    body.append(el("div", { class: "card" }, [el("div", { class: "em-card-h" }, [el("h3", { text: "Certificate" }), pill(d.source === "self" ? "Self-signed" : "Let's Encrypt", d.source === "self" ? "warn" : "good")]),
      kv([["Mail server name", d.hostname], ["Issued to", (c.names || []).join(", ") || c.subject], ["Issuer", c.issuer],
        ["Expires", c.expires ? `${new Date(c.expires).toLocaleDateString()}${days != null ? ` (${days} days${d.source !== "self" ? ", renews automatically" : ""})` : ""}` : ", "],
        ["Covers the server name", d.covers_host ? pill("yes", "good") : pill("no", "bad")]]),
      d.source === "self" ? el("div", { class: "dm-note" }, [icon("info", 15), el("span", { text: "Mail apps show a warning with a self-signed certificate. A free Let's Encrypt certificate fixes that, the server name must point to this server and port 80 must be reachable." })]) : null,
      el("div", { class: "toolbar" }, [
        d.certbot ? btn(d.source === d.hostname ? "Renew now" : `Get a Let's Encrypt certificate for ${d.hostname}`, async () => {
          const r = await call(() => API.mailTLSIssue()); if (!r) return;
          const jp = ui.jobPanel(body); jp.run(r.job, "Let's Encrypt");
          const t = setInterval(async () => { const j = await API.job(r.job).catch(() => null); if (j && j.status !== "running") { clearInterval(t); if (j.status === "done") { toast("Certificate installed", "good"); navigate("mailtls", { history: "none" }); } } }, 2000);
          state.cleanups.push(() => clearInterval(t));
        }, d.source === d.hostname ? "btn-ghost" : "btn-primary") : btn("Install Certbot", () => installComponent("certbot"), "btn-primary"),
        ...d.letsencrypt.filter((n) => n !== d.source).map((n) => btn(`Use ${n}`, () => call(() => API.mailTLSSet(n), "Certificate switched", () => navigate("mailtls", { history: "none" })), "btn-ghost")),
        d.source !== "self" ? btn("Back to self-signed", () => call(() => API.mailTLSSet("self"), "Switched to self-signed", () => navigate("mailtls", { history: "none" })), "btn-ghost") : null].filter(Boolean))].filter(Boolean)));
    body.append(el("div", { class: "card" }, [el("h3", { text: "Encrypted connections" }),
      el("p", { class: "muted", text: "Passwords are only accepted over encrypted connections. Mail to and from other servers uses TLS whenever they support it." }),
      el("div", { class: "table-wrap" }, el("table", { class: "em-table" }, [el("thead", {}, el("tr", {}, ["Port", "Service", "Listening"].map((h) => el("th", { text: h })))),
        el("tbody", {}, d.ports.map((p) => el("tr", {}, [el("td", { class: "em-mono", text: String(p.port) }), el("td", { text: p.label }), el("td", {}, pill(p.listening ? "yes" : "no", p.listening ? "good" : "bad"))])))])),
      el("div", { class: "toolbar" }, [btn("Check ports from outside", () => navigate("portcheck"), "btn-ghost"), btn("Firewall", () => navigate("firewall"), "btn-ghost")])]));
  }

  // ------------------------------------------------------------------ Calendars & contacts
  async function viewCalendars(root) {
    const body = el("div", {}, el("div", { class: "loading", text: "Loading…" }));
    root.append(pageHead("Calendars & Contacts", "Every email account gets a calendar and an address book that sync with phones and computers (CalDAV / CardDAV)."), body);
    const tabs = el("div", { class: "cw-seg cw-seg-sm em-tabs" });
    const pane = el("div");
    let d;
    const load = async () => { try { d = await API.mailDav(); } catch (e) { body.innerHTML = ""; body.append(el("p", { class: "empty", text: e.message })); return false; } return true; };
    if (!(await load())) return;
    body.innerHTML = ""; body.append(tabs, pane);
    const T = {
      "Connect devices": () => [el("div", { class: "card" }, [el("h3", { text: "Settings for any app" }), copyRow("Server", d.server),
        el("p", { class: "muted", text: "Sign in with the email address and its password. Apps find the calendars and address books by themselves." }),
        el("div", { class: "em-dev-grid" }, [["iPhone / iPad", "Settings → Calendar → Accounts → Add Account → Other → Add CalDAV Account (and CardDAV for contacts). Server: the address above."],
          ["Mac", "System Settings → Internet Accounts → Add Other Account → CalDAV / CardDAV account → Manual."],
          ["Android", "Install DAVx⁵ (free), add an account with “URL and user name”, paste the server address."],
          ["Thunderbird", "Calendar → New Calendar → On the network → enter the email address and the server address."],
          ["Outlook", "Use the CalDAV Synchronizer add-in, or open the calendar's URL below."]].map(([t, x]) => el("div", { class: "em-dev" }, [el("b", { text: t }), el("p", { class: "muted", text: x })])))])],
      Collections: () => {
        const own = el("select", {}, d.accounts.map((a) => el("option", { value: a, text: a })));
        const kind = el("select", {}, [el("option", { value: "calendar", text: "Calendar" }), el("option", { value: "addressbook", text: "Address book" })]);
        const name = el("input", { type: "text", placeholder: "e.g. Work" });
        const color = el("input", { type: "color", value: "#ff7a1a", class: "em-color" });
        const rows = d.collections.map((c) => el("div", { class: "em-row" }, [el("span", { class: "em-cal", style: `background:${c.color || (c.type === "calendar" ? "#ff7a1a" : "#6b8afd")}` }, icon(c.type === "calendar" ? "calendar" : "contacts", 14)),
          el("div", { class: "em-row-main" }, [el("b", { text: c.name }), el("span", { class: "muted", text: `${c.owner} · ${c.type === "calendar" ? "Calendar" : "Address book"} · ${c.items} item${c.items === 1 ? "" : "s"}` })]),
          el("div", { class: "em-row-act" }, [btn("Copy URL", async () => toast(await copyText(c.url) ? "URL copied" : "Copy failed", "good"), "btn-ghost"),
            btn("Rename", () => renameCol(c), "btn-ghost"), armed("Delete", "Click again, deletes its items", () => call(() => API.mailDavDelete({ owner: c.owner, id: c.id }), "Deleted", refresh), "btn-ghost")])]));
        return [el("div", { class: "card" }, [el("h3", { text: "Create" }), el("div", { class: "em-grid4" }, [field("Owner", own), field("Type", kind), field("Name", name), field("Colour", color)]),
          el("div", { class: "toolbar" }, [btn("Create", () => call(() => API.mailDavCreate({ owner: own.value, kind: kind.value, name: name.value, color: color.value }), "Created", refresh), "btn-primary")])]),
          el("div", { class: "card em-pad0" }, rows.length ? el("div", { class: "em-list" }, rows) : empty("calendar", "No calendars yet", "They're created with each new email account."))];
      },
      Sharing: () => {
        const cols = d.collections;
        const col = el("select", {}, cols.map((c, i) => el("option", { value: i, text: `${c.owner}, ${c.name}` })));
        const who = el("select", {}, d.accounts.map((a) => el("option", { value: a, text: a })));
        const write = el("input", { type: "checkbox" });
        const name = (s) => (cols.find((c) => c.owner === s.owner && c.id === s.collection) || { name: s.collection }).name;
        return [el("div", { class: "card" }, [el("h3", { text: "Share a calendar or address book" }),
          el("div", { class: "em-grid2" }, [field("Collection", col), field("Share with", who)]), el("label", { class: "dm-check" }, [write, el("span", { text: "Allow editing" })]),
          el("div", { class: "toolbar" }, [btn("Share", () => { const c = cols[+col.value]; if (!c) return; call(() => API.mailDavShare({ owner: c.owner, id: c.id, with_: who.value, write: write.checked }), "Shared", refresh); }, "btn-primary")]),
          el("p", { class: "dm-hint", text: "The other person adds it with the collection's URL (Collections → Copy URL), signing in with their own address and password." })]),
          el("div", { class: "card em-pad0" }, d.shares.length ? el("div", { class: "em-list" }, d.shares.map((s) => el("div", { class: "em-row" }, [avatar(s.owner),
            el("div", { class: "em-row-main" }, [el("b", { text: name(s) }), el("span", { class: "muted", text: `${s.owner} → ${s.with}` })]), pill(s.write ? "can edit" : "read only", s.write ? "warn" : "dim"),
            el("div", { class: "em-row-act" }, [armed("Stop sharing", "Click again", () => call(() => API.mailDavUnshare({ owner: s.owner, id: s.collection, with_: s.with }), "No longer shared", refresh), "btn-ghost")])])))
            : empty("users", "Nothing shared", "Share a team calendar, a meeting room or a company address book."))];
      },
    };
    let curTab = "Connect devices";
    const show = (k) => { curTab = k; tabs.querySelectorAll("button").forEach((b) => b.classList.toggle("active", b.textContent === k)); pane.innerHTML = ""; pane.append(...T[k]()); };
    Object.keys(T).forEach((k) => tabs.append(el("button", { type: "button", text: k, onclick: () => show(k) })));
    async function refresh() { if (await load()) show(curTab); }
    function renameCol(c) {
      const name = el("input", { type: "text", value: c.name });
      const color = el("input", { type: "color", value: c.color || "#ff7a1a", class: "em-color" });
      openModal(`Rename ${c.name}`, el("div", { class: "em-form" }, [field("Name", name), c.type === "calendar" ? field("Colour", color) : null].filter(Boolean)), [
        el("button", { class: "btn btn-primary", text: "Save", onclick: async () => { if (await call(() => API.mailDavUpdate({ owner: c.owner, id: c.id, name: name.value, color: color.value }), "Saved")) { closeModal(); refresh(); } } })]);
    }
    show(curTab);
  }

  // ------------------------------------------------------------------ Disk usage
  async function viewDisk(root) {
    root.append(pageHead("Email Disk Usage", "See which mailboxes take the space, and clear out old messages."));
    let ov;
    try { ov = await API.mailDisk(""); } catch (e) { root.append(el("p", { class: "empty", text: e.message })); return; }
    if (!ov.accounts.length) { root.append(el("div", { class: "card" }, empty("disk", "No email accounts", "Nothing stored yet."))); return; }
    const sel = el("select", {}, ov.accounts.map((a) => el("option", { value: a.address, text: `${a.address}, ${fmtBytes(a.used_bytes)}` })));
    sel.value = state.mailOwner && ov.accounts.find((a) => a.address === state.mailOwner) ? state.mailOwner : ov.accounts[0].address;
    const body = el("div");
    const max = Math.max(1, ...ov.accounts.map((a) => a.used_bytes));
    root.append(el("div", { class: "card" }, [el("h3", { text: "Accounts by size" }), el("div", { class: "em-bars" }, ov.accounts.slice(0, 12).map((a) => el("button", { type: "button", class: "em-hbar", onclick: () => { sel.value = a.address; draw(); } }, [
      el("span", { class: "em-ell", text: a.address }), el("i", {}, el("span", { style: `width:${Math.max(1, a.used_bytes / max * 100)}%` })), el("b", { text: fmtBytes(a.used_bytes) })])))]),
      el("div", { class: "card em-pickbar" }, [field("Account", sel)]), body);
    const draw = async () => {
      state.mailOwner = sel.value;
      body.innerHTML = ""; body.append(el("div", { class: "loading", text: "Counting…" }));
      let d;
      try { d = await API.mailDisk(sel.value); } catch (e) { body.innerHTML = ""; body.append(el("p", { class: "empty", text: e.message })); return; }
      body.innerHTML = "";
      body.append(el("div", { class: "card" }, [el("div", { class: "em-card-h em-disk-h" }, [el("h3", { text: "Mailboxes" }), usage(d.total, d.quota_mb)]), el("div", { class: "table-wrap" }, el("table", { class: "em-table" }, [el("thead", {}, el("tr", {}, ["Mailbox", "Messages", "Size", ""].map((h) => el("th", { text: h })))),
        el("tbody", {}, d.mailboxes.map((m) => {
          const age = el("select", { class: "em-age" }, [["30", "older than 30 days"], ["90", "older than 90 days"], ["365", "older than a year"], ["0", "all messages"]].map(([v, l]) => el("option", { value: v, text: l })));
          return el("tr", {}, [el("td", {}, [icon(m.mailbox === "INBOX" ? "inbox" : m.mailbox === "Junk" ? "spam" : "folder", 14), ` ${m.mailbox}`]), el("td", { text: m.messages.toLocaleString() }), el("td", { text: fmtBytes(m.size) }),
            el("td", {}, m.messages ? el("div", { class: "em-row-act" }, [age, armed("Delete", "Click again", () => call(() => API.mailExpunge({ address: sel.value, mailbox: m.mailbox, older_days: +age.value }), "Messages deleted", draw), "btn-ghost")]) : null)]);
        }))]))]));
    };
    sel.onchange = draw; draw();
  }

  // ------------------------------------------------------------------ Queue
  async function viewQueue(root) {
    const sel = new Set();
    const list = el("div", {}, el("div", { class: "loading", text: "Loading…" }));
    let count = 0;
    const retry = btn("Retry all now", () => {
      if (!count) return popNotice({ title: "The queue is empty", text: "Nothing is waiting to be delivered, so there is nothing to retry.", kind: "good", icon: "info" });
      call(() => API.mailQueue("flush"), `Retrying delivery of ${count} message${count === 1 ? "" : "s"}`, () => setTimeout(load, 2000));
    }, "btn-primary");
    const purge = armed("Delete all deferred", "Click again", () => call(() => API.mailQueue("delete_deferred"), "Deferred messages deleted", load), "btn-ghost");
    root.append(pageHead("Mail Queue", "Messages waiting to be delivered, usually because the receiving server is slow or refusing them for now.", [retry, purge]),
      el("div", { class: "card em-pad0" }, list));
    async function load() {
      let d;
      try { d = await API.mailQueueGet(); } catch (e) { list.innerHTML = ""; list.append(el("p", { class: "empty", text: e.message })); return; }
      list.innerHTML = "";
      count = d.messages.length; retry.disabled = !count; purge.disabled = !count; retry.title = purge.title = count ? "" : "Nothing is waiting";
      if (!d.messages.length) { list.append(empty("queue", "The queue is empty", "Everything has been delivered.")); return; }
      const bar = el("div", { class: "em-bulk" }, [btn("Retry selected", () => call(() => API.mailQueue("requeue", [...sel]), "Re-queued", load), "btn-ghost"),
        armed("Delete selected", "Click again", () => call(() => API.mailQueue("delete", [...sel]), "Deleted", () => { sel.clear(); load(); }), "btn-ghost")]);
      list.append(bar, el("div", { class: "table-wrap" }, el("table", { class: "em-table" }, [el("thead", {}, el("tr", {}, ["", "Queued", "From", "To", "Size", "Reason"].map((h) => el("th", { text: h })))),
        el("tbody", {}, d.messages.map((m) => { const cb = el("input", { type: "checkbox", onchange: (e) => (e.target.checked ? sel.add(m.id) : sel.delete(m.id)) });
          return el("tr", {}, [el("td", {}, cb), el("td", { class: "em-nowrap", text: ago(m.arrival) }), el("td", { class: "em-ell", text: m.sender || "<>" }),
            el("td", { class: "em-ell", text: m.recipients.map((r) => r.address).join(", ") }), el("td", { text: fmtBytes(m.size) }),
            el("td", { class: "em-ell", title: m.recipients.map((r) => r.reason).join("\n"), text: (m.recipients[0] || {}).reason || m.queue })]); }))])));
    }
    load();
    const t = setInterval(load, 15000); state.cleanups.push(() => clearInterval(t));
  }

  return {
    email: viewOverview, mailaccounts: viewAccounts, forwarders: viewForwarders, mailrouting: viewRouting, autoresponders: viewAutoresponders,
    defaultaddress: viewDefault, mailinglists: viewLists, trackdelivery: viewTrack, globalfilters: viewGlobalFilters, emailfilters: viewEmailFilters,
    deliverability: viewDeliverability, addressimporter: viewImporter, spamfilters: viewSpam, mailtls: viewTLS, calendars: viewCalendars,
    maildisk: viewDisk, mailqueue: viewQueue,
  };
};
