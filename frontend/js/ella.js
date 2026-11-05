/* WAF Ella, stage 1: Live Events, Blocks and Sources. Loaded before app.js.
   Everything in an event came from a stranger's request or a log file: it only ever reaches the page
   through el()'s text option (textContent), never as HTML. */
window.AuroraElla = (ui) => {
  "use strict";
  const { el, icon, btn, pill, field, toast, API, openModal, closeModal } = ui;
  const REFRESH_MS = 5000;
  const STALE_SECONDS = 30;
  const TTLS = [["15 minutes", 900], ["1 hour", 3600], ["24 hours", 86400], ["7 days", 604800], ["30 days", 2592000], ["No expiry", 0]];
  const stamp = (ts) => ts ? new Date(ts * 1000).toLocaleString() : "never";
  const utc = (ts) => ts ? new Date(ts * 1000).toISOString() : "";
  // Control characters are made visible, and very long values cut, so a log line can't disguise itself.
  const show = (v, max = 300) => {
    if (v === null || v === undefined || v === "") return "not available";
    const s = String(v).replace(/[\u0000-\u001f\u007f-\u009f​-‏‪-‮⁦-⁩]/g, (c) => `\\u${c.charCodeAt(0).toString(16).padStart(4, "0")}`);
    return s.length > max ? `${s.slice(0, max)}…` : s;
  };
  const when = (ts) => el("span", { text: stamp(ts), title: utc(ts) });
  const STATE_PILL = { applied: "good", present: "good", pending: "warn", requested: "warn", failed: "bad" };

  function banDialog(target, after) {
    const ttl = el("select", {}, TTLS.map(([label, secs]) => el("option", { value: String(secs), text: label })));
    ttl.value = "3600";
    const reason = el("input", { type: "text", maxlength: 200, placeholder: "Why (kept in the audit log)" });
    const ip = el("input", { type: "text", value: target || "", placeholder: "IP address or CIDR range" });
    const notice = el("div");
    let forceable = false;
    const force = el("input", { type: "checkbox" });
    const forceRow = el("label", { style: "display:none;gap:8px;align-items:center" }, [force, el("span", { text: "I understand. Ban it anyway (recorded separately in the audit log)." })]);
    const go = btn("Ban address", async () => {
      try {
        const op = await API.ellaBan({ target: ip.value.trim(), ttl: Number(ttl.value) || null, reason: reason.value.trim(), force: forceable && force.checked });
        closeModal();
        toast(op.state === "applied" ? "Banned: confirmed in the firewall" : op.merged ? "That address already has a WAF Ella ban" : `Not confirmed yet: ${op.error || op.state}`, op.state === "applied" ? "good" : "warn");
        after();
      } catch (e) {
        notice.replaceChildren(el("p", { class: "dm-note warn", text: e.message }));
        forceable = !!(e.detail && e.detail.forceable);
        forceRow.style.display = forceable ? "flex" : "none";
      }
    }, "btn-danger");
    openModal("Ban an address", el("div", {}, [
      el("p", { class: "muted", text: "This blocks every connection from the address to the whole server, every site and service, at the firewall. An address isn't a person, and it may be shared." }),
      field("Address", ip), field("For how long", ttl), field("Reason", reason), notice, forceRow,
    ]), [btn("Cancel", closeModal, "btn-ghost"), go]);
  }

  function eventDetail(e) {
    const line = (k, v) => el("div", { class: "muted" }, [el("b", { text: `${k}: ` }), el("span", { text: show(v, 2000) })]);
    const missing = e.missing_fields && e.missing_fields.length ? e.missing_fields.join(", ") : "none";
    return el("div", {}, [
      line("Peer address", e.peer_ip), line(`Client address (from ${show(e.client_ip_source)})`, e.client_ip), line("User-Agent", e.user_agent),
      line("Query parameter names", (e.query_keys || []).join(", ")), line("Anomaly score", e.anomaly_score), line("Fields this source didn't have", missing), line("Source record", e.raw_ref),
      ...(e.evidence || []).map((x) => el("div", { class: "card", style: "margin-top:8px" }, [
        el("b", { text: `Rule ${show(x.rule_id)} (${show(x.severity)})` }), el("div", { text: show(x.msg) }),
        line("Matched in", x.matched_var_name), line("Check", x.operator), line("Matched data", x.matched_data)])),
      el("p", { class: "muted", text: "A rule match is a suspicion, not proof that anything was broken into." }),
    ]);
  }

  function viewEvents(body, goBlocks) {
    const filters = { client_ip: "", domain: "", rule_id: "", source: "" };
    const expanded = new Set(); // what the operator has open survives the refresh every few seconds
    let paused = false, timer = null, cursor = null, shown = [];
    const table = el("div", { class: "table-wrap mx-table-wrap" });
    const status = el("span", { class: "muted" });
    const inputs = Object.keys(filters).map((k) => {
      const inp = el("input", { type: "text", placeholder: { client_ip: "Client address", domain: "Domain", rule_id: "Rule ID", source: "Source" }[k], style: "max-width:170px" });
      inp.onchange = () => { filters[k] = inp.value.trim(); cursor = null; load(); };
      return inp;
    });
    const pauseBtn = btn("Pause", () => { paused = !paused; pauseBtn.textContent = paused ? "Resume" : "Pause"; }, "btn-ghost");
    const more = btn("Older events", () => load(true), "btn-ghost");
    more.style.display = "none";

    function render() {
      const rows = [];
      shown.forEach((e) => {
        const key = `${e.source}:${e.id}`;
        const detail = el("tr", { style: expanded.has(key) ? "" : "display:none" }, el("td", { colspan: 8 }, eventDetail(e)));
        rows.push(el("tr", { style: "cursor:pointer", onclick: () => {
          const opening = detail.style.display === "none";
          detail.style.display = opening ? "" : "none";
          if (opening) expanded.add(key); else expanded.delete(key);
        } }, [
          el("td", {}, when(e.ts_event)), el("td", {}, pill(show(e.action), e.action === "blocked" ? "bad" : e.action === "detected" ? "warn" : "dim")),
          el("td", { text: show(e.client_ip, 64) }), el("td", { text: show(e.domain, 80) }), el("td", { text: `${show(e.method, 12)} ${show(e.url, 120)}` }),
          el("td", { text: show(e.status, 6) }), el("td", { text: show(e.rule_id, 16) }),
          el("td", {}, e.client_ip ? btn("Ban", (ev) => { if (ev) ev.stopPropagation(); banDialog(e.client_ip, goBlocks); }, "btn-sm btn-ghost") : ""),
        ]), detail);
      });
      table.replaceChildren(shown.length ? el("table", { class: "mx-table" }, [
        el("thead", {}, el("tr", {}, ["Time", "Action", "Client", "Domain", "Request", "Status", "Rule", ""].map((c) => el("th", { text: c })))), el("tbody", {}, rows)])
        : el("p", { class: "empty", text: "No events match. That only means none were recorded: check that the sources are healthy." }));
    }

    async function load(older) {
      try {
        const params = { limit: 100, ...filters };
        if (older && cursor) { params.cursor_ts = cursor[0]; params.cursor_id = cursor[1]; }
        const r = await API.ellaEvents(params);
        shown = older ? shown.concat(r.events) : r.events;
        cursor = r.next_cursor;
        more.style.display = cursor ? "" : "none";
        status.textContent = `Updated ${new Date().toLocaleTimeString()}, ${shown.length} shown`;
        render();
      } catch (e) {
        status.textContent = `Couldn't load events: ${e.message}. What's on screen may be out of date.`;
      }
    }
    body.append(el("div", { class: "toolbar" }, [...inputs, pauseBtn, status]), table, el("div", { class: "toolbar" }, [more]));
    load();
    timer = setInterval(() => {
      if (!table.isConnected) { clearInterval(timer); return; }
      if (!paused && !cursor && !document.hidden) load();
    }, REFRESH_MS);
  }

  function viewBlocks(body) {
    const box = el("div");
    const load = async () => {
      box.replaceChildren(el("div", { class: "loading", text: "Loading…" }));
      try {
        const { blocks } = await API.ellaBlocks();
        box.replaceChildren(blocks.length ? el("div", { class: "table-wrap mx-table-wrap" }, el("table", { class: "mx-table" }, [
          el("thead", {}, el("tr", {}, ["Address", "Scope", "Backend", "State", "Expires", "Checked", "Reason", "By", ""].map((c) => el("th", { text: c })))),
          el("tbody", {}, blocks.map((b) => el("tr", {}, [
            el("td", { text: show(b.target, 64) }), el("td", { text: show(b.scope) }), el("td", { text: show(b.backend) }),
            el("td", {}, [pill(show(b.op_state), STATE_PILL[b.op_state] || "dim"), b.op_error ? el("div", { class: "muted", text: show(b.op_error) }) : ""]),
            el("td", {}, b.expires_at ? when(b.expires_at) : el("span", { text: "no expiry" })), el("td", {}, when(b.last_verified_at)),
            el("td", { text: show(b.reason) }), el("td", { text: show(b.owner) }),
            el("td", {}, btn("Unban", async () => {
              try {
                const op = await API.ellaUnban(b.id);
                toast(op.state === "applied" ? "Unbanned: confirmed gone from WAF Ella's set. Bans from other sources stay." : `Not confirmed yet: ${op.error || op.state}`, op.state === "applied" ? "good" : "warn");
              } catch (e) { toast(e.message, "bad"); }
              load();
            }, "btn-sm btn-ghost")),
          ]))),
        ])) : el("p", { class: "empty", text: "WAF Ella has no active bans. Fail2ban and IP Blocker bans are listed on their own pages for now." }));
      } catch (e) {
        box.replaceChildren(el("p", { class: "dm-note warn", text: `Couldn't load bans: ${e.message}` }));
      }
    };
    body.append(el("div", { class: "toolbar" }, [btn("Ban an address", () => banDialog("", load), "btn-primary")]), box);
    load();
  }

  async function leakNote(body) {
    let r;
    try { r = await API.ellaLeaks(); } catch (e) {
      body.prepend(el("p", { class: "dm-note warn", text: `Couldn't read the secrets check: ${e.message}` }));
      return;
    }
    let note;
    if (!r.ts) note = el("p", { class: "dm-note warn", text: "Stored events haven't been checked for leaked secrets yet. It runs daily." });
    else if (r.total) note = el("p", { class: "dm-note warn", text: `Secrets check, ${stamp(r.ts)}: ${r.total} possible secrets in stored events (${Object.entries(r.counts).map(([k, n]) => `${k}: ${n}`).join(", ")}). First at ${show((r.findings[0] || {}).file)}, event ${show((r.findings[0] || {}).event_id)}. Values aren't shown here.` });
    else note = el("p", { class: "muted", text: `Secrets check, ${stamp(r.ts)}: nothing found in the ${r.scanned} events newly checked.` });
    body.prepend(note);
  }

  async function viewSources(body) {
    leakNote(body);
    try {
      const { sources } = await API.ellaSources();
      if (!sources.length) {
        body.append(el("p", { class: "dm-note warn", text: "No log sources yet: the collector hasn't started, or found no logs. No data here doesn't mean no attacks." }));
        return;
      }
      const now = Date.now() / 1000;
      body.append(el("div", { class: "table-wrap mx-table-wrap" }, el("table", { class: "mx-table" }, [
        el("thead", {}, el("tr", {}, ["Log", "Format", "State", "Last event", "Lines read", "Unreadable lines", "Problem"].map((c) => el("th", { text: c })))),
        el("tbody", {}, sources.map((s) => {
          const stale = !s.last_read_ts || now - s.last_read_ts > STALE_SECONDS;
          const state = stale ? "not being read" : s.status;
          return el("tr", {}, [el("td", { text: show(s.path) }), el("td", { text: show(s.kind) }), el("td", {}, pill(show(state), state === "ok" ? "good" : "bad")),
            el("td", {}, when(s.last_event_ts)), el("td", { text: String(s.lines) }), el("td", { text: String(s.unparsed) }), el("td", { text: s.last_error ? show(s.last_error) : "" })]);
        })),
      ])));
    } catch (e) {
      body.append(el("p", { class: "dm-note warn", text: `Couldn't load sources: ${e.message}` }));
    }
  }

  function viewElla(root) {
    const body = el("div");
    const tabs = [["Live Events", (b) => viewEvents(b, () => open(1))], ["Blocks", viewBlocks], ["Sources", viewSources]];
    const bar = el("div", { class: "toolbar" });
    function open(i) {
      body.replaceChildren();
      bar.replaceChildren(...tabs.map(([label], n) => btn(label, () => open(n), n === i ? "btn-primary" : "btn-ghost")));
      tabs[i][1](body);
    }
    root.append(el("div", { class: "em-head" }, [el("div", { class: "em-head-txt" }, [el("h2", {}, [icon("shield", 20), " WAF Ella"]),
      el("p", { class: "muted", text: "Security events from your logs, and bans confirmed in the firewall. It runs alongside WAF Firewall, Fail2ban and IP Blocker, which keep working as before." })])]), bar, body);
    open(0);
  }

  return { ella: viewElla };
};
