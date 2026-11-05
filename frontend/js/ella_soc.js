/* WAF Ella's security center pages: Overview, Investigate, WAF Rules, Incidents and Settings. Loaded before ella.js.
   Everything shown from an event came from a stranger's request or a log file: it reaches the page only as text. */
window.AuroraEllaSOC = (ui, tools) => {
  "use strict";
  const { el, btn, pill, field, toast, API, openModal, closeModal } = ui;
  const { show, when, banDialog, stamp } = tools;
  const api = API.ella;
  const FIELD_LABEL = { path: "Path", host: "Host", method: "Method", user_agent: "User-Agent", ip: "Client address", referer: "Referer", origin: "Origin", content_type: "Content-Type", size: "Body size", query: "Query string", header: "A header", arg: "A parameter", query_arg: "A URL parameter", body_arg: "A form or JSON field" };
  const OP_LABEL = { equals: "is", contains: "contains", prefix: "starts with", suffix: "ends with", regex: "matches pattern", in_list: "contains one of", cidr: "is in range", exists: "exists", missing: "is missing", gt: "is more than", ge: "is at least", lt: "is less than", le: "is at most", eq: "equals number" };
  const table = (heads, rows, empty) => rows.length ? el("div", { class: "table-wrap mx-table-wrap" }, el("table", { class: "mx-table" }, [el("thead", {}, el("tr", {}, heads.map((c) => el("th", { text: c })))), el("tbody", {}, rows)])) : el("p", { class: "empty", text: empty });
  const td = (v, max) => el("td", { text: show(v, max) });
  const warn = (text) => el("p", { class: "dm-note warn", text });
  const note = (text) => el("p", { class: "muted", text });
  const act = (label, fn, cls = "btn-ghost") => btn(label, async (ev) => {
    if (ev && ev.stopPropagation) ev.stopPropagation();
    try { await fn(); } catch (e) { toast(e.message, "bad"); }
  }, cls);
  const loading = () => el("div", { class: "loading", text: "Loading…" });
  const secs = (v) => (v === null || v === undefined ? "nothing measured yet" : `${v.toFixed(2)} s`);

  // ------------------------------------------------------------------ Overview
  async function viewOverview(body, go) {
    body.replaceChildren(loading());
    let d;
    try { d = await api("GET", "/overview"); } catch (e) {
      body.replaceChildren(warn(`Couldn't load the overview: ${e.message}. That isn't the same as nothing happening.`));
      return;
    }
    const redraw = () => viewOverview(body, go);
    body.replaceChildren();
    const ua = d.under_attack || {};
    if (ua.on) body.append(warn(`Under Attack is on until ${stamp(ua.until)}: a lower threshold, and only everyday methods are allowed.`));
    if (d.kill_switch) body.append(warn("The kill switch is on: every WAF rule only logs, and nothing is blocked."));
    if (d.breaches.length) body.append(warn(`${d.breaches.length} possible breaches recently. A suspicious request got a real answer. That's a suspicion, not proof. See the list below.`));
    const stat = (label, value, tone) => el("div", { class: "card", style: "min-width:150px;flex:1" }, [el("div", { class: "muted", text: label }), el("div", { style: `font-size:24px;font-weight:600;${tone ? "color:var(--bad,#d33)" : ""}`, text: String(value) })]);
    const totalBans = Object.values(d.blocks).reduce((a, b) => a + b, 0);
    body.append(el("div", { style: "display:flex;gap:10px;flex-wrap:wrap;margin-bottom:14px" }, [
      stat("Blocked, last 24 hours", d.digest.blocked), stat("Detected only", d.digest.detected), stat("Possible breaches", d.digest.breaches, d.digest.breaches > 0), stat("Failed logins", d.digest.login_failed), stat("Active bans", totalBans), stat("Open alerts", d.open_alerts, d.open_alerts > 0), stat("Firewall differences", d.drift, d.drift > 0),
    ]));
    const uaBtn = ua.on ? act("Turn Under Attack off", async () => { await api("POST", "/under-attack", { minutes: 0 }); toast("Under Attack is off", "good"); redraw(); }, "btn-primary") : act("Under Attack for 1 hour", async () => { await api("POST", "/under-attack", { minutes: 60 }); toast("Under Attack is on", "warn"); redraw(); }, "btn-danger");
    const kill = act(d.kill_switch ? "Turn the kill switch off (rules block again)" : "Kill switch: only log", async () => { await api("POST", "/switch/kill_switch", { value: !d.kill_switch }); toast("Done", "good"); redraw(); });
    body.append(el("div", { class: "toolbar" }, [uaBtn, kill]));
    body.append(el("h3", { text: "WAF by web server" }), table(["Server", "Engine", "Running", "Mode"], d.waf.map((s) => el("tr", {}, [td(s.name), td(s.engine === "v3" ? "ModSecurity 3" : "ModSecurity 2"), el("td", {}, pill(s.active ? "yes" : "no", s.active ? "good" : "dim")), el("td", {}, pill(show(s.mode), s.mode === "block" ? "good" : "warn"))])), "No web server here has a WAF installed. Nothing is inspecting requests."));
    const src = d.sources;
    body.append(el("h3", { text: "Health" }), el("div", { class: "muted" }, [
      el("div", { text: `Logs: ${src.total} sources, ${src.stale} not read lately, ${src.error} with errors.` }),
      el("div", { text: d.agent.ok ? `Agent service: answering. Firewall changes go through ${d.agent.transport}.` : `Agent service: not answering (${show(d.agent.error)}). Without it this server ${d.agent.fail_mode === "closed" ? "refuses firewall changes" : "makes them from inside the panel"}.` }),
      el("div", { text: `Log time to stored, 95th percentile: ${secs(d.slo.event_to_store_p95)} (target ${d.slo.targets.event_to_store_p95} s). Ban to confirmed: ${secs(d.slo.ban_applied_p95)} (target ${d.slo.targets.ban_applied_p95} s).` }),
      d.fleet.member.joined ? el("div", { text: `Managed by ${show(d.fleet.member.url)}: policy version ${d.fleet.member.version}, last contact ${stamp(d.fleet.member.last_ok)}${d.fleet.member.last_error ? `, problem: ${show(d.fleet.member.last_error)}` : ""}.` }) : "",
      d.fleet.agents.length ? el("div", { text: `Managing ${d.fleet.agents.length} servers, ${d.fleet.agents.filter((a) => a.online).length} online.` }) : "",
    ].filter(Boolean)));
    body.append(el("h3", { text: "Possible breaches" }), table(["Time", "Client", "Request", "Status", "Rule"], d.breaches.map((e) => el("tr", { style: "cursor:pointer", onclick: () => go.investigate(e.client_ip) }, [el("td", {}, when(e.ts_event)), td(e.client_ip, 64), td(`${e.domain || ""}${e.url || ""}`, 120), td(e.status, 6), td(e.rule_id, 16)])), "None recorded."));
    const top = (title, rows) => el("div", { style: "flex:1;min-width:220px" }, [el("h3", { text: title }), table(["", "Hits"], rows.map(([k, n]) => el("tr", {}, [td(k, 80), td(n)])), "None.")]);
    body.append(el("div", { style: "display:flex;gap:14px;flex-wrap:wrap" }, [top("Top rules", d.digest.top_rules), top("Top clients", d.digest.top_clients), top("Top sites", d.digest.top_domains)]));
  }

  // ------------------------------------------------------------------ Investigate
  function viewInvestigate(body, ip, go) {
    const input = el("input", { type: "text", placeholder: "IP address", value: ip || "", style: "max-width:260px" });
    const out = el("div");
    const run = async () => {
      const v = input.value.trim();
      if (!v) return;
      out.replaceChildren(loading());
      let d;
      try { d = await api("GET", `/investigate/${encodeURIComponent(v)}`); } catch (e) { out.replaceChildren(warn(e.message)); return; }
      out.replaceChildren();
      const admin = d.blocks !== undefined;
      if (admin) {
        const facts = [];
        if (d.safety.reasons.length) facts.push(warn(`Safety Lock: ${d.safety.reasons.join("; ")}`));
        if (d.bot) facts.push(d.bot.verified === true ? el("p", { text: `Confirmed ${d.bot.bot}: its reverse and forward DNS agree.` }) : d.bot.verified === false ? warn(`Claims to be ${d.bot.bot}, and its DNS says otherwise.`) : note(`Claims to be ${d.bot.bot}. DNS didn't answer, so that's unknown.`));
        facts.push(d.lists.length ? el("p", { text: `On reputation lists: ${d.lists.map((l) => `${l.name} (fetched ${stamp(l.fetched_at)})`).join(", ")}` }) : note("On none of the reputation lists that are switched on."));
        facts.push(d.country ? note(`${d.country.country}, from ${d.country.source}. ${d.country.note}`) : note(d.geo.available ? "Not in the country database." : show(d.geo.why)));
        facts.push(note("An address isn't a person, and it may be shared."));
        out.append(...facts);
        out.append(el("div", { class: "toolbar" }, [btn("Ban", () => banDialog(v, run), "btn-danger"), act("Open an incident", () => incidentDialog(`Investigate ${v}`, "client", v, go))]));
        out.append(el("h3", { text: "Bans on this address" }), table(["Source", "Backend", "State", "Expires", "Reason"], d.blocks.map((b) => el("tr", {}, [td(b.source, 40), td(b.backend), td(b.desired_state), el("td", {}, b.expires_at ? when(b.expires_at) : "no expiry"), td(b.reason, 100)])), "None, now or earlier."));
      }
      out.append(el("h3", { text: "Sites and rules" }), el("div", { class: "muted", text: `Sites: ${d.domains.map(([k, n]) => `${show(k, 60)} (${n})`).join(", ") || "none"}. Rules: ${d.rules.map(([k, n]) => `${show(k, 16)} (${n})`).join(", ") || "none"}.` }));
      out.append(el("h3", { text: "Timeline, newest first" }), table(["Time", "Source", "Action", "Request", "Status", "Rule"], d.events.map((e) => el("tr", {}, [el("td", {}, when(e.ts_event)), td(e.source, 30), td(e.action, 20), td(`${e.method || ""} ${e.domain || ""}${e.url || ""}`, 140), td(e.status, 6), td(e.rule_id, 16)])), "No stored events from this address."));
      if (admin && d.audit.length) out.append(el("h3", { text: "What operators did" }), table(["Time", "Who", "What"], d.audit.map((a) => el("tr", {}, [el("td", {}, when(a.ts)), td(a.actor, 40), td(a.action, 40)])), ""));
    };
    input.onkeydown = (e) => { if (e.key === "Enter") run(); };
    body.append(el("div", { class: "toolbar" }, [input, btn("Investigate", run, "btn-primary")]), out);
    if (ip) run();
  }

  // ------------------------------------------------------------------ False Positive Wizard
  async function wizard(e, hit, after) {
    let s;
    try { s = await api("POST", "/exceptions/suggest", { ts: e.ts_event, id: e.id, rule_id: hit.rule_id }); } catch (err) { toast(err.message, "bad"); return; }
    const path = el("input", { type: "text", value: s.path });
    const reason = el("input", { type: "text", maxlength: 200, placeholder: "Why this is a false alarm" });
    const notice = el("div");
    openModal(`Exception for rule ${show(hit.rule_id, 16)}`, el("div", {}, [
      el("p", { text: `Only on ${show(s.domain, 80)}, only under the path below${s.var ? `, and only for ${show(s.var, 80)}` : ""}. The rule keeps working everywhere else.` }),
      ...s.warnings.map(warn), field("Path", path), field("Reason", reason), el("h4", { text: "What this adds to the WAF" }), el("pre", { style: "white-space:pre-wrap;font-size:12px", text: s.preview }), notice,
    ]), [btn("Cancel", closeModal, "btn-ghost"), btn("Add the exception", async () => {
      try {
        await api("POST", "/exceptions", { rule_id: s.rule_id, var: s.var, domain: s.domain, path: path.value.trim(), reason: reason.value.trim() });
        closeModal();
        toast("Exception added, and the web server accepted it", "good");
        if (after) after();
      } catch (err) { notice.replaceChildren(warn(err.message)); }
    }, "btn-primary")]);
  }

  function incidentDialog(title, kind, ref, go) {
    const name = el("input", { type: "text", value: title || "", maxlength: 200 });
    const sev = el("select", {}, ["NOTICE", "WARNING", "ERROR", "CRITICAL"].map((v) => el("option", { value: v, text: v })));
    sev.value = "WARNING";
    openModal("Open an incident", el("div", {}, [field("Title", name), field("Severity", sev)]), [btn("Cancel", closeModal, "btn-ghost"), btn("Open it", async () => {
      try {
        const r = await api("POST", "/incidents", { title: name.value.trim(), severity: sev.value, kind, ref });
        closeModal();
        toast(`Incident ${r.id} opened`, "good");
        if (go && go.incidents) go.incidents();
      } catch (e) { toast(e.message, "bad"); }
    }, "btn-primary")]);
  }

  // ------------------------------------------------------------------ WAF Rules
  function conditionRow(onChange, fields, ops, start) {
    const f = el("select", {}, fields.map((x) => el("option", { value: x, text: FIELD_LABEL[x] || x })));
    const name = el("input", { type: "text", placeholder: "Name", style: "max-width:130px" });
    const op = el("select", {}, ops.map((x) => el("option", { value: x, text: OP_LABEL[x] || x })));
    const val = el("input", { type: "text", placeholder: "Value" });
    const neg = el("input", { type: "checkbox", title: "Not" });
    f.value = (start && start.field) || "path"; op.value = (start && start.op) || "prefix"; val.value = (start && start.value) || ""; name.value = (start && start.name) || "";
    const sync = () => { name.style.display = ["header", "arg", "query_arg", "body_arg"].includes(f.value) ? "" : "none"; val.style.display = ["exists", "missing"].includes(op.value) ? "none" : ""; };
    f.onchange = () => { sync(); onChange(); }; op.onchange = () => { sync(); onChange(); }; val.oninput = onChange; neg.onchange = onChange;
    sync();
    const row = el("div", { class: "toolbar", style: "margin-bottom:6px" }, [el("label", { style: "display:flex;gap:4px;align-items:center" }, [neg, el("span", { text: "not" })]), f, name, op, val]);
    row.read = () => {
      const c = { field: f.value, op: op.value };
      if (name.style.display !== "none") c.name = name.value.trim();
      if (val.style.display !== "none") c.value = val.value;
      return neg.checked ? { not: c } : c;
    };
    return row;
  }

  function ruleDialog(meta, after, rule) {
    const editing = !!rule;
    const r = rule || { domains: [], path: "", action: "block", status: 403, priority: 100, reason: "" };
    const name = el("input", { type: "text", value: r.name || "", maxlength: 80 });
    const domains = el("input", { type: "text", value: (r.domains || []).join(" "), placeholder: "Leave empty for every site. shop.example *.example.org" });
    const path = el("input", { type: "text", value: r.path || "", placeholder: "Leave empty for every path" });
    const join = el("select", {}, [el("option", { value: "all", text: "All of these" }), el("option", { value: "any", text: "Any of these" })]);
    const action = el("select", {}, [el("option", { value: "block", text: "Block the request" }), el("option", { value: "log", text: "Only log it" })]);
    action.value = r.action;
    const status = el("select", {}, [403, 404, 429, 503].map((s) => el("option", { value: String(s), text: `Answer ${s}` })));
    status.value = String(r.status);
    const reason = el("input", { type: "text", value: r.reason || "", maxlength: 200, placeholder: "Why (kept with the rule's history)" });
    const box = el("div"), result = el("div"), rows = [];
    const flat = r.tree ? (r.tree.all || r.tree.any || [r.tree]) : [{}];
    if (r.tree && r.tree.any) join.value = "any";
    const stale = () => result.replaceChildren();
    const add = (start) => { const row = conditionRow(stale, meta.fields, meta.operators, start && start.not ? start.not : start); rows.push(row); box.append(row); };
    flat.forEach(add);
    const tree = () => ({ [join.value]: rows.map((x) => x.read()) });
    const payload = () => ({ name: name.value.trim(), domains: domains.value.split(/[\s,]+/).filter(Boolean), path: path.value.trim(), action: action.value, status: Number(status.value), reason: reason.value.trim(), tree: tree() });
    const preview = act("Preview on stored events", async () => {
      const p = await api("POST", "/rules/preview", { tree: tree(), domains: payload().domains, path: payload().path, days: 7 });
      const compiled = await api("POST", "/rules/compile", payload());
      result.replaceChildren(el("p", { text: `In the last ${p.days} days it would have matched ${p.matched} of ${p.checked} stored requests.` }), ...(p.note ? [warn(`${p.note} Not checked: ${p.cannot_check.join(", ")}.`)] : []),
        p.domains.length ? note(`Sites: ${p.domains.map(([k, n]) => `${show(k, 60)} (${n})`).join(", ")}. Clients: ${p.clients.map(([k, n]) => `${show(k, 45)} (${n})`).join(", ")}.`) : "", el("h4", { text: "What this adds to the WAF" }), el("pre", { style: "white-space:pre-wrap;font-size:12px", text: compiled.text }));
    });
    openModal(editing ? `Edit ${show(r.name, 60)}` : "New WAF rule", el("div", {}, [
      field("Name", name), field("Only on these sites", domains), field("Only under this path", path), field("Match", join), box,
      el("div", { class: "toolbar" }, [btn("Add a condition", () => add({}), "btn-sm btn-ghost"), preview]), field("Then", action), field("Answer", status), field("Reason", reason), result,
      note("A new rule starts off. Run it in detect mode first to see what it would block."),
    ]), [btn("Cancel", closeModal, "btn-ghost"), btn(editing ? "Save" : "Create rule", async () => {
      try {
        if (editing) await api("PUT", `/rules/${r.id}`, payload()); else await api("POST", "/rules", payload());
        closeModal(); toast("Saved", "good"); after();
      } catch (e) { result.replaceChildren(warn(e.message)); }
    }, "btn-primary")]);
  }

  function patchDialog(after) {
    const cve = el("input", { type: "text", placeholder: "CVE-2026-12345" }), name = el("input", { type: "text" }), software = el("input", { type: "text" }), versions = el("input", { type: "text" }), url = el("input", { type: "text", placeholder: "https://…" });
    const raw = el("textarea", { rows: 6, placeholder: 'SecRule REQUEST_URI "@contains /vulnerable" "id:1150001,phase:1,deny,status:403,log,msg:\'Virtual patch\'"' });
    const notice = el("div");
    openModal("Import a virtual patch", el("div", {}, [field("CVE", cve), field("Name", name), field("Software", software), field("Affected versions", versions), field("Where it's described", url), field("ModSecurity rules, IDs 1150000 to 1169999", raw), notice, note("It's checked by the web server, and starts in detect mode whatever the rule says.")]),
      [btn("Cancel", closeModal, "btn-ghost"), btn("Import", async () => {
        try {
          await api("POST", "/patches", { cve_id: cve.value.trim(), name: name.value.trim(), software: software.value.trim(), versions: versions.value.trim(), source_url: url.value.trim(), raw: raw.value });
          closeModal(); toast("Imported, in detect mode", "good"); after();
        } catch (e) { notice.replaceChildren(warn(e.message)); }
      }, "btn-primary")]);
  }

  function testerPane() {
    const out = el("div");
    const method = el("select", {}, ["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "TRACE"].map((m) => el("option", { value: m, text: m })));
    const host = el("input", { type: "text", value: "localhost", placeholder: "Host" }), url = el("input", { type: "text", value: "/?q=<script>alert(1)</script>" });
    const headers = el("textarea", { rows: 2, placeholder: "One per line. User-Agent: curl/8" }), bodyText = el("textarea", { rows: 2, placeholder: "Request body" });
    const pane = el("div", {}, [el("h3", { text: "Rule Tester" }), note("Sends a made-up request to the real rules, on a listener only this machine can reach, with nothing behind it. It reaches no website and adds nothing to Live Events."),
      el("div", { class: "toolbar" }, [method, host, url]), field("Headers", headers), field("Body", bodyText)]);
    const run = act("Test this request", async () => {
      let s = await api("GET", "/tester");
      if (!s.available) { out.replaceChildren(warn(`Rule Tester isn't available here: ${s.why}`)); return; }
      if (!s.ready) s = await api("POST", "/tester/setup");
      const hd = {};
      headers.value.split("\n").forEach((l) => { const i = l.indexOf(":"); if (i > 0) hd[l.slice(0, i).trim()] = l.slice(i + 1).trim(); });
      const r = await api("POST", "/tester/run", { method: method.value, url: url.value.replace(/ /g, "%20").replace(/</g, "%3C").replace(/>/g, "%3E"), host: host.value.trim(), headers: hd, body: bodyText.value });
      out.replaceChildren(el("p", {}, [pill(r.action, r.action === "blocked" ? "bad" : "good"), el("span", { text: ` on ${r.server}: answered ${r.status}, anomaly score ${show(r.anomaly_score)}.` })]),
        table(["Rule", "Severity", "Matched in", "Message", "Matched data"], r.rules.map((x) => el("tr", {}, [td(x.rule_id, 16), td(x.severity), td(x.matched_var_name, 60), td(x.msg, 100), td(x.matched_data, 120)])), r.logged ? "A record was written, with no rule details." : "No rule matched this request."));
    }, "btn-primary");
    pane.append(el("div", { class: "toolbar" }, [run]), out);
    return pane;
  }

  async function viewRules(body) {
    body.replaceChildren(loading());
    let m, exs, learn;
    try { [m, exs, learn] = await Promise.all([api("GET", "/rules"), api("GET", "/exceptions"), api("GET", "/learning")]); } catch (e) { body.replaceChildren(warn(`Couldn't load the rules: ${e.message}`)); return; }
    const redraw = () => viewRules(body);
    body.replaceChildren();
    if (!m.servers.length) body.append(warn("Neither Apache nor Nginx has a WAF installed. Rules can be written, but there's nowhere to put them."));
    const custom = m.rules.filter((r) => r.kind === "custom"), patches = m.rules.filter((r) => r.kind === "vpatch");
    const modeBtns = (r) => el("div", { class: "toolbar" }, ["off", "detect", "block"].map((x) => btn(x, async () => { try { await api("POST", `/rules/${r.id}/mode`, { mode: x }); toast(`Now ${x}`, "good"); } catch (e) { toast(e.message, "bad"); } redraw(); }, x === r.mode ? "btn-sm btn-primary" : "btn-sm btn-ghost")));
    body.append(el("div", { class: "toolbar" }, [btn("New rule", () => ruleDialog(m, redraw), "btn-primary"), btn("Import a virtual patch", () => patchDialog(redraw), "btn-ghost")]));
    body.append(el("h3", { text: "Your rules" }), table(["Rule", "Sites", "Path", "Then", "Version", "Mode", ""], custom.map((r) => el("tr", {}, [td(r.name, 80), td(r.domains.join(" ") || "all", 80), td(r.path || "all", 60), td(r.action === "block" ? `block, ${r.status}` : "log"), td(r.version), el("td", {}, modeBtns(r)),
      el("td", {}, el("div", { class: "toolbar" }, [btn("Edit", () => ruleDialog(m, redraw, r), "btn-sm btn-ghost"), act("History", async () => {
        const v = await api("GET", `/rules/${r.id}/versions`);
        openModal(`History of ${show(r.name, 60)}`, table(["Version", "When", "Who", "Conditions"], v.versions.map((x) => el("tr", {}, [td(x.version), el("td", {}, when(x.ts)), td(x.actor, 40), td(x.snapshot.tree, 300)])), "None."), [btn("Close", closeModal, "btn-ghost")]);
      }, "btn-sm btn-ghost"), act("Delete", async () => { await api("DELETE", `/rules/${r.id}`); toast("Deleted", "good"); redraw(); }, "btn-sm btn-danger")]))])), "No rules of your own yet. The Core Rule Set is still working."));
    body.append(el("h3", { text: "Virtual patches" }), table(["CVE", "Name", "Software", "Versions", "Mode", ""], patches.map((r) => el("tr", {}, [td(r.cve_id, 24), td(r.name, 60), td(r.software, 40), td(r.versions, 40), el("td", {}, modeBtns(r)), el("td", {}, act("Delete", async () => { await api("DELETE", `/rules/${r.id}`); redraw(); }, "btn-sm btn-danger"))])), "None."));
    body.append(el("h3", { text: "Exceptions" }), table(["Rule", "Site", "Path", "Only for", "By", "Why", ""], exs.exceptions.map((x) => el("tr", {}, [td(x.rule_id, 16), td(x.domain, 80), td(x.path, 80), td(x.var || "the whole rule", 60), td(x.author, 40), td(x.reason, 100), el("td", {}, act("Remove", async () => { await api("DELETE", `/exceptions/${x.id}`); toast("Removed", "good"); redraw(); }, "btn-sm btn-ghost"))])), "None. Open an event in Live Events to make one."));
    body.append(el("h3", { text: "Suggested exceptions" }), note("From requests rules flagged but didn't block. Many different clients hitting one rule on one page usually means a false alarm. One client usually means an attack."),
      table(["Rule", "Site", "Path", "Field", "Hits", "Clients", ""], learn.suggestions.slice(0, 25).map((s) => el("tr", {}, [td(s.rule_id, 16), td(s.domain, 60), td(s.path, 80), td(s.var, 60), td(s.hits), td(s.clients), el("td", {}, act("Add", async () => { await api("POST", "/exceptions", { rule_id: s.rule_id, var: s.var, domain: s.domain, path: s.path || "/", reason: "From suggested exceptions" }); toast("Added", "good"); redraw(); }, "btn-sm btn-ghost"))])), "Nothing to suggest yet."));
    const cmsDomains = {};
    body.append(el("h3", { text: "Ready-made protection" }), table(["Protection", "Side effects", "Sites", "Mode"], m.cms.map((c) => {
      const inp = el("input", { type: "text", value: (c.domains || []).join(" "), placeholder: "all sites", style: "max-width:190px" });
      cmsDomains[c.id] = inp;
      return el("tr", {}, [td(c.title, 80), td(c.effect, 200), el("td", {}, inp), el("td", {}, el("div", { class: "toolbar" }, ["off", "detect", "block"].map((x) => btn(x, async () => {
        try { await api("POST", `/cms/${c.id}`, { mode: x, domains: inp.value.split(/[\s,]+/).filter(Boolean) }); toast(`${c.title}: ${x}`, "good"); } catch (e) { toast(e.message, "bad"); }
        redraw();
      }, x === c.mode ? "btn-sm btn-primary" : "btn-sm btn-ghost"))))]);
    }), ""));
    const hp = el("textarea", { rows: 4 });
    hp.value = (m.honeypot.paths || []).join("\n");
    const hpMode = el("select", {}, ["off", "detect", "block"].map((x) => el("option", { value: x, text: x })));
    hpMode.value = m.honeypot.mode;
    body.append(el("h3", { text: "Honeypot paths" }), note("Paths no real visitor asks for. A site where the path really exists is left out by itself."), hp, el("div", { class: "toolbar" }, [hpMode, act("Save", async () => {
      const r = await api("POST", "/honeypot", { mode: hpMode.value, paths: hp.value.split("\n").map((x) => x.trim()).filter(Boolean) });
      toast(r.excluded.length ? `Saved. Left out because the path exists: ${r.excluded.join(", ")}` : "Saved", "good");
    }, "btn-primary")]));
    const sw = m.switches;
    const resp = el("input", { type: "checkbox" }); resp.checked = !!sw.response_inspection;
    const limit = el("select", {}, [el("option", { value: "Reject", text: "Refuse it (recommended)" }), el("option", { value: "ProcessPartial", text: "Check the part that fits, and tag it" })]); limit.value = sw.body_limit_action;
    resp.onchange = async () => { try { await api("POST", "/switch/response_inspection", { value: resp.checked }); toast("Saved", "good"); } catch (e) { toast(e.message, "bad"); redraw(); } };
    limit.onchange = async () => { try { await api("POST", "/switch/body_limit_action", { value: limit.value }); toast("Saved", "good"); } catch (e) { toast(e.message, "bad"); redraw(); } };
    body.append(el("h3", { text: "How requests are read" }), el("label", { style: "display:flex;gap:8px;align-items:center" }, [resp, el("span", { text: "Also check responses for leaks. Costs CPU on every page. Bodies still aren't copied to logs." })]), field("A body over the size limit", limit));
    body.append(testerPane());
    body.append(el("h3", { text: "What each web server can do" }), table(["Server", "OS", "Connected by", "Stops requests", "Logs", "IP bans", "Rate limit", "Tarpit", "Status", "Limits"], m.matrix.map((x) => el("tr", {}, [td(x.server), td(x.os), td(x.connect), td(x.inline ? "yes" : "no"), td(x.logs ? "yes" : "no"), td(x.ip_ban ? "yes" : "no"), td(x.rate_limit ? "yes" : "no"), td(x.tarpit ? "yes" : "no"), el("td", {}, pill(x.status, x.status === "verified" ? "good" : "warn")), td(x.limits, 200)])), ""));
    body.append(el("h3", { text: "ModSecurity 2 (Apache) and 3 (Nginx) differ" }), table(["What", "Apache", "Nginx"], m.differences.map((x) => el("tr", {}, [td(x.what), td(x.v2, 200), td(x.v3, 200)])), ""));
  }

  // ------------------------------------------------------------------ Incidents and audit
  async function viewIncidents(body, go) {
    body.replaceChildren(loading());
    let inc, al, audit;
    try { [inc, al, audit] = await Promise.all([api("GET", "/incidents"), api("GET", "/alerts"), API.ellaAudit()]); } catch (e) { body.replaceChildren(warn(`Couldn't load incidents: ${e.message}`)); return; }
    const redraw = () => viewIncidents(body, go);
    body.replaceChildren(el("div", { class: "toolbar" }, [btn("Open an incident", () => incidentDialog("", null, null, { incidents: redraw }), "btn-primary")]));
    const open = async (i) => {
      const d = await api("GET", `/incidents/${i.id}`);
      const text = el("textarea", { rows: 3, placeholder: "Add a note" });
      const status = el("select", {}, ["open", "investigating", "resolved", "false_alarm"].map((x) => el("option", { value: x, text: x.replace("_", " ") })));
      status.value = d.status;
      openModal(`Incident ${d.id}: ${show(d.title, 80)}`, el("div", {}, [field("Status", status), table(["When", "Who", "Kind", "What"], d.items.map((x) => el("tr", {}, [el("td", {}, when(x.ts)), td(x.actor, 40), td(x.kind), td(x.note || x.ref, 400)])), "Nothing yet."), field("Note", text)]),
        [btn("Close", closeModal, "btn-ghost"), btn("Save", async () => {
          try {
            if (text.value.trim()) await api("POST", `/incidents/${i.id}/items`, { kind: "note", note: text.value.trim() });
            if (status.value !== d.status) await api("POST", `/incidents/${i.id}/status`, { status: status.value });
            closeModal(); redraw();
          } catch (e) { toast(e.message, "bad"); }
        }, "btn-primary")]);
    };
    body.append(el("h3", { text: "Incidents" }), table(["#", "Title", "Status", "Severity", "Owner", "Items", "Updated"], inc.incidents.map((i) => el("tr", { style: "cursor:pointer", onclick: () => open(i).catch((e) => toast(e.message, "bad")) }, [td(i.id), td(i.title, 120), td(i.status), td(i.severity), td(i.owner, 40), td(i.items), el("td", {}, when(i.updated_at))])), "None."));
    body.append(el("h3", { text: "Alerts" }), table(["Last", "Severity", "What", "Details", "Times", "Sent", ""], al.alerts.map((a) => el("tr", {}, [el("td", {}, when(a.last_ts)), el("td", {}, pill(a.severity, a.severity === "CRITICAL" ? "bad" : "warn")), td(a.title, 160), td(a.detail, 200), td(a.count), td(a.delivered ? "yes" : "no"), el("td", {}, a.acked ? "seen" : act("Mark seen", async () => { await api("POST", `/alerts/${a.id}/ack`); redraw(); }, "btn-sm btn-ghost"))])), "None."));
    const chain = audit.chain;
    body.append(el("h3", { text: "Audit log" }), chain.ok ? note(`Hash chain intact over ${chain.records} records.`) : warn(`The audit chain breaks at record ${chain.broken_at}: something edited this log.`),
      table(["When", "Who", "What", "Target", "Details"], audit.entries.slice(0, 200).map((a) => el("tr", {}, [el("td", {}, when(a.ts)), td(a.actor, 40), td(a.action, 40), td(a.target, 64), td(JSON.stringify(a.detail), 200)])), "Nothing yet."));
    void go;
  }

  // ------------------------------------------------------------------ Settings
  async function viewSettings(body) {
    body.replaceChildren(loading());
    let al, prox, cor, ret, intel, fl, exp;
    try { [al, prox, cor, ret, intel, fl, exp] = await Promise.all(["/alerts", "/proxies", "/correlator", "/retention", "/intel", "/fleet", "/exports"].map((p) => api("GET", p))); } catch (e) { body.replaceChildren(warn(`Couldn't load settings: ${e.message}`)); return; }
    const redraw = () => viewSettings(body);
    body.replaceChildren();
    // Alerts
    const kind = el("select", {}, ["email", "telegram", "slack", "discord", "webhook", "syslog"].map((k) => el("option", { value: k, text: k })));
    const a = el("input", { type: "text", placeholder: "Address, webhook URL, bot token or syslog host" }), b = el("input", { type: "text", placeholder: "Telegram chat ID, webhook secret or syslog port" });
    const sev = el("select", {}, ["NOTICE", "WARNING", "ERROR", "CRITICAL"].map((k) => el("option", { value: k, text: `${k} and above` })));
    sev.value = "WARNING";
    body.append(el("h3", { text: "Where alerts go" }), table(["Name", "Kind", "From", "Last sent", "Problem", ""], al.channels.map((c) => el("tr", {}, [td(c.name, 60), td(c.kind), td(c.min_severity), el("td", {}, when(c.last_sent)), td(c.last_error || "none", 200), el("td", {}, el("div", { class: "toolbar" }, [act("Test", async () => { const r = await api("POST", `/channels/${c.id}/test`); toast(r.ok ? "Sent" : r.error, r.ok ? "good" : "bad"); redraw(); }, "btn-sm btn-ghost"), act("Remove", async () => { await api("DELETE", `/channels/${c.id}`); redraw(); }, "btn-sm btn-danger")]))])), "None. Alerts only show on the Incidents page until you add one."),
      el("div", { class: "toolbar" }, [kind, a, b, sev, act("Add", async () => {
        const k = kind.value, x = a.value.trim(), y = b.value.trim();
        const config = k === "email" ? { to: x } : k === "telegram" ? { token: x, chat: y } : k === "syslog" ? { host: x, port: Number(y) || 514, proto: "udp" } : k === "webhook" ? { url: x, secret: y } : { url: x };
        await api("POST", "/channels", { kind: k, name: k, config, min_severity: sev.value }); toast("Added. Use Test to check it.", "good"); redraw();
      }, "btn-primary")]));
    // Correlation
    const s = cor.settings;
    const num = (key) => { const i = el("input", { type: "number", value: String(s[key]), style: "max-width:110px" }); i.dataset.key = key; return i; };
    const nums = ["ip_many_logins", "login_many_ips", "net_many_ips", "slow_fails_day", "rate_per_minute", "ban_seconds"].map(num);
    const auto = el("input", { type: "checkbox" }); auto.checked = !!s.auto_ban;
    const LAB = { ip_many_logins: "Logins tried by one address, 10 min", login_many_ips: "Addresses trying one login, 10 min", net_many_ips: "Addresses in one network failing, 10 min", slow_fails_day: "Failures by one address, 24 hours", rate_per_minute: "Requests a minute from one client (0 is off)", ban_seconds: "Automatic ban length, seconds" };
    body.append(el("h3", { text: "Automatic detection" }), note("These read logs, so they act on the next request, not the one that set them off."), ...nums.map((i) => field(LAB[i.dataset.key], i)), el("label", { style: "display:flex;gap:8px;align-items:center" }, [auto, el("span", { text: "Ban automatically. Otherwise they only raise alerts. The Safety Lock still applies." })]),
      el("div", { class: "toolbar" }, [act("Save", async () => { const d = { auto_ban: auto.checked }; nums.forEach((i) => { d[i.dataset.key] = Number(i.value); }); await api("POST", "/correlator", d); toast("Saved", "good"); }, "btn-primary")]),
      cor.now.length ? el("div", {}, cor.now.map((f) => warn(show(f.title, 200)))) : note("Nothing is tripping these right now."));
    // Proxies
    const ranges = el("textarea", { rows: 3 }); ranges.value = prox.manual.join("\n");
    const hdr = el("select", {}, ["X-Forwarded-For", "CF-Connecting-IP", "X-Real-IP"].map((h) => el("option", { value: h, text: h }))); hdr.value = prox.header;
    const cfOn = el("input", { type: "checkbox" }); cfOn.checked = prox.cloudflare.enabled;
    const zone = el("input", { type: "text", value: prox.cloudflare.zone || "", placeholder: "Zone ID, for bans at Cloudflare" });
    const token = el("input", { type: "password", placeholder: prox.cloudflare.has_token ? "Token saved. Enter a new one to replace it." : "API token, for bans at Cloudflare" });
    body.append(el("h3", { text: "Proxies and CDN" }), note("A forwarded address is only believed from these ranges. Without them, anyone could claim to be any address. They can't be banned at the firewall, since that would cut off every visitor behind them."), field("Trusted proxies", ranges), field("Header they set", hdr),
      el("div", { class: "toolbar" }, [act("Save", async () => { await api("POST", "/proxies", { ranges: ranges.value.split(/\s+/).filter(Boolean), header: hdr.value }); toast("Saved, and the web server accepted it", "good"); redraw(); }, "btn-primary")]),
      el("label", { style: "display:flex;gap:8px;align-items:center" }, [cfOn, el("span", { text: `Sites are behind Cloudflare (${prox.cloudflare.ranges} ranges, updated ${stamp(prox.cloudflare.updated)}${prox.cloudflare.error ? `, last problem: ${show(prox.cloudflare.error, 120)}` : ""})` })]), field("Zone ID", zone), field("API token", token),
      el("div", { class: "toolbar" }, [act("Save Cloudflare", async () => { const d = { enabled: cfOn.checked, zone: zone.value.trim() }; if (token.value) d.token = token.value; await api("POST", "/proxies/cloudflare", d); toast("Saved", "good"); redraw(); }, "btn-primary")]));
    // Reputation
    body.append(el("h3", { text: "Reputation lists" }), note("A hit raises an alert and shows when investigating. It bans only if you turn that on for the list."), table(["List", "On", "Ban automatically", "Entries", "Fetched", "Problem"], intel.lists.map((l) => {
      const on = el("input", { type: "checkbox" }); on.checked = !!l.enabled;
      const ban = el("input", { type: "checkbox" }); ban.checked = !!l.auto_ban;
      const save = async () => { try { await api("POST", `/intel/${encodeURIComponent(l.name)}`, { enabled: on.checked, auto_ban: ban.checked }); toast("Saved", "good"); } catch (e) { toast(e.message, "bad"); } redraw(); };
      on.onchange = save; ban.onchange = save;
      return el("tr", {}, [td(l.title, 60), el("td", {}, on), el("td", {}, ban), td(l.count), el("td", {}, when(l.fetched_at)), td(l.last_error || "none", 160)]);
    }), ""), note(intel.geo.available ? `Country data: ${show(intel.geo.source)}, dated ${stamp(intel.geo.date)}, ${intel.geo.ranges} ranges.` : show(intel.geo.why)));
    // Retention
    const keep = el("input", { type: "number", value: String(ret.settings.keep_months), style: "max-width:110px" }), pseudo = el("input", { type: "number", value: String(ret.settings.pseudonymize_days), style: "max-width:110px" }), maxMb = el("input", { type: "number", value: String(ret.settings.max_mb), style: "max-width:110px" });
    body.append(el("h3", { text: "What's kept, and for how long" }), note(`${ret.usage.total_mb} MB in ${ret.usage.files.length} monthly files, ${ret.usage.free_mb} MB free.`), field("Keep events for, months", keep), field("Cut addresses to /24 or /48 after, days", pseudo), field("Most space to use, MB", maxMb),
      el("div", { class: "toolbar" }, [act("Save", async () => { await api("POST", "/retention", { keep_months: Number(keep.value), pseudonymize_days: Number(pseudo.value), max_mb: Number(maxMb.value) }); toast("Saved", "good"); }, "btn-primary")]));
    // Config as code
    const yaml = el("textarea", { rows: 5, placeholder: "Paste an exported file here" }), yamlOut = el("div");
    body.append(el("h3", { text: "Configuration as a file" }), el("div", { class: "toolbar" }, [el("a", { class: "btn btn-ghost", href: "/api/ella/config", text: "Export YAML" }), el("a", { class: "btn btn-ghost", href: "/api/ella/sbom", target: "_blank", text: "List of components (SBOM)" }), el("a", { class: "btn btn-ghost", href: "/api/ella/metrics", target: "_blank", text: "Prometheus metrics" })]), yaml,
      el("div", { class: "toolbar" }, [act("Show what it would change", async () => { const d = await api("POST", "/config/diff", { text: yaml.value }); yamlOut.replaceChildren(el("pre", { style: "white-space:pre-wrap;font-size:12px", text: JSON.stringify(d, null, 1) })); }), act("Import it", async () => { await api("POST", "/config/import", { text: yaml.value }); toast("Imported, and the web servers accepted it", "good"); redraw(); }, "btn-danger")]), yamlOut);
    // Fleet
    const member = fl.member;
    const mUrl = el("input", { type: "text", placeholder: "https://panel.example.com:8088" }), mId = el("input", { type: "text", placeholder: "Server ID" }), mSecret = el("input", { type: "password", placeholder: "Secret" }), mPin = el("input", { type: "text", placeholder: "Certificate fingerprint, for a self-signed panel" });
    const enrollName = el("input", { type: "text", placeholder: "Name of the other server" });
    body.append(el("h3", { text: "Other servers" }), table(["Server", "Online", "Last seen", "Policy", "Firewall via", ""], fl.agents.map((x) => el("tr", {}, [td(x.name, 60), el("td", {}, pill(x.revoked ? "revoked" : x.online ? "online" : "offline", x.online ? "good" : "bad")), el("td", {}, when(x.last_seen)), td(`${x.policy_version} of ${fl.version}`), td(x.status.transport, 20), el("td", {}, x.revoked ? "" : el("div", { class: "toolbar" }, [act("New secret", async () => { const r = await api("POST", `/fleet/agents/${x.id}/rotate`); openModal("New secret", el("pre", { text: r.secret }), [btn("Close", closeModal, "btn-ghost")]); }, "btn-sm btn-ghost"), act("Remove", async () => { await api("DELETE", `/fleet/agents/${x.id}`); redraw(); }, "btn-sm btn-danger")]))])), "This panel manages no other servers."),
      el("div", { class: "toolbar" }, [enrollName, act("Add a server", async () => { const r = await api("POST", "/fleet/enroll", { name: enrollName.value.trim() }); openModal(`Join details for ${show(r.name, 60)}`, el("div", {}, [el("p", { text: "Enter these on the other server, under Settings. The secret isn't shown again." }), el("pre", { style: "white-space:pre-wrap", text: `Server ID: ${r.agent_id}\nSecret: ${r.secret}` })]), [btn("Close", () => { closeModal(); redraw(); }, "btn-ghost")]); }, "btn-primary")]));
    body.append(member.joined ? el("div", {}, [el("p", { text: `This server is managed by ${show(member.url)}: policy version ${member.version}, last contact ${stamp(member.last_ok)}, ${member.queue_bytes} bytes queued, ${member.lost_events} events lost to a full queue.${member.last_error ? ` Problem: ${show(member.last_error, 200)}` : ""}` }), act("Leave", async () => { await api("POST", "/fleet/leave"); redraw(); }, "btn-danger")])
      : el("div", {}, [el("h4", { text: "Let another panel manage this one" }), field("Its address", mUrl), field("Server ID", mId), field("Secret", mSecret), field("Fingerprint", mPin), act("Join", async () => { const r = await api("POST", "/fleet/join", { url: mUrl.value.trim(), agent_id: mId.value.trim(), secret: mSecret.value, pin: mPin.value.trim() }); toast(r.ok ? "Joined" : `Saved, but: ${r.error}`, r.ok ? "good" : "warn"); redraw(); }, "btn-primary")]));
    void exp;
  }

  return { viewOverview, viewInvestigate, viewRules, viewIncidents, viewSettings, wizard, incidentDialog };
};
