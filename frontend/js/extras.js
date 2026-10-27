/* AuroraPanel, WAF Firewall (Security), Dynamic DNS hosts (Domains) and the Metrics section
   (Visitors, Errors, Bandwidth, Raw Access, Analytics, Resource Usage).
   Loaded before app.js; app.js calls window.AuroraExtras(ui) once with its helpers. */
window.AuroraExtras = (ui) => {
  "use strict";
  const { icon, btn, pill, field, sw, toast, API, navigate, state, openModal, closeModal, copyText, fmtBytes, ago, downloadText } = ui;
  // Text from logs (URLs, user agents, referrers, error messages) is attacker-controlled: always textContent,
  // shown exactly as recorded; an "html" attribute is refused outright.
  const el = (tag, attrs = {}, kids = []) => {
    if ("html" in attrs) throw new Error("extras.js never renders HTML");
    return ui.el(tag, { raw: true, ...attrs }, kids);
  };
  // Only real web links become clickable (a referrer can be "javascript:…" or anything else a bot sends).
  const safeUrl = (u) => (/^https?:\/\/[^\s"'<>]+$/i.test(u || "") ? u : null);

  // ------------------------------------------------------------------ shared bits
  const NS = "http://www.w3.org/2000/svg";
  const S = (tag, attrs = {}, kids = []) => {
    const n = document.createElementNS(NS, tag);
    for (const [k, v] of Object.entries(attrs)) if (v != null) n.setAttribute(k, v);
    kids.forEach((k) => k && n.append(k));
    return n;
  };
  function pageHead(title, desc, actions = []) {
    return el("div", { class: "em-head" }, [
      el("div", { class: "em-head-txt" }, [el("h2", { text: title }), desc ? el("p", { class: "muted", text: desc }) : null]),
      el("div", { class: "em-head-act" }, actions.filter(Boolean)),
    ]);
  }
  const empty = (ico, title, text, action) => el("div", { class: "em-empty" }, [el("span", { class: "em-empty-ico" }, icon(ico, 26)),
    el("b", { text: title }), el("p", { class: "muted", text }), action || null]);
  const call = async (fn, ok, after) => {
    try { const r = await fn(); if (ok) toast(ok, "good"); if (after) after(r); return r || true; }
    catch (e) { toast(e.message, "bad"); return null; }
  };
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
  function seg(options, value, onChange) {
    const box = el("div", { class: "mx-seg", role: "tablist" });
    const draw = (v) => { box.innerHTML = ""; options.forEach(([k, label]) => box.append(el("button", { type: "button", class: k === v ? "on" : "", text: label, onclick: () => { draw(k); onChange(k); } }))); };
    draw(value);
    return box;
  }
  const tile = (label, value, sub, ico, kind, onclick) => el(onclick ? "button" : "div", { class: `mx-tile ${kind || ""}`, type: onclick ? "button" : null, onclick },
    [el("div", { class: "mx-tile-l" }, [ico ? icon(ico, 15) : null, el("span", { text: label })]), el("div", { class: "mx-tile-v", text: value }), sub ? el("div", { class: "mx-tile-s", text: sub }) : null]);
  const num = (n) => (n == null ? ", " : Number(n).toLocaleString());
  const t2s = (ts, opts) => (ts ? new Date(ts * 1000).toLocaleString([], opts || { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" }) : ", ");
  const dur = (s) => (s < 60 ? `${Math.round(s)}s` : s < 3600 ? `${Math.floor(s / 60)}m ${Math.round(s % 60)}s` : `${Math.floor(s / 3600)}h ${Math.round((s % 3600) / 60)}m`);
  const rate = (b) => `${fmtBytes(b)}/s`;
  const statusKind = (s) => (s >= 500 ? "bad" : s >= 400 ? "warn" : s >= 300 ? "dim" : "good");
  const LS = { get: (k, d) => { try { const v = localStorage.getItem("ap." + k); return v == null ? d : JSON.parse(v); } catch (e) { return d; } },
    set: (k, v) => { try { localStorage.setItem("ap." + k, JSON.stringify(v)); } catch (e) {} } };
  // Fill a time series so every slot in [start, start + n*step) exists (empty ones as {}).
  function fillSlots(points, start, step, n) {
    const m = new Map(points.map(([ts, v]) => [Math.round((ts - start) / step), v]));
    return Array.from({ length: n }, (_, i) => [start + i * step, m.get(i) || {}]);
  }
  const niceBytes = (v) => { if (!(v > 0)) return 1024; const u = Math.pow(1024, Math.floor(Math.log(v) / Math.log(1024))); return niceMax(v / u) * u; };
  function niceMax(v) {
    if (!(v > 0)) return 1;
    const p = Math.pow(10, Math.floor(Math.log10(v))), f = v / p;
    return (f <= 1 ? 1 : f <= 2 ? 2 : f <= 2.5 ? 2.5 : f <= 5 ? 5 : 10) * p;
  }

  // Bars or lines over time, with axis labels and a hover read-out. points: [[t, {key: value}], …]
  function chart(o) {
    const W = 1000, H = o.height || 190, pts = o.points || [], series = o.series;
    const box = el("div", { class: "mx-chart", style: `--h:${H}px` });
    if (!pts.length) { box.append(el("div", { class: "mx-chart-empty muted", text: o.emptyText || "No data yet, the collector adds a point every few minutes." })); return box; }
    const val = (p, k) => +(p[1][k] || 0);
    const tot = pts.map((p) => (o.stacked === false ? Math.max(...series.map((s) => val(p, s.key))) : series.reduce((a, s) => a + val(p, s.key), 0)));
    const top = Math.max(...tot, ...(o.lines || []).map((l) => l.value || 0));
    const max = o.max || (o.bytes ? niceBytes(top) : niceMax(top));
    const svg = S("svg", { viewBox: `0 0 ${W} ${H}`, preserveAspectRatio: "none", class: "mx-svg" });
    for (let i = 1; i <= 4; i++) svg.append(S("line", { x1: 0, x2: W, y1: H - (H * i) / 4, y2: H - (H * i) / 4, class: "mx-grid" }));
    const n = pts.length, bw = W / n;
    if ((o.type || "bars") === "bars") {
      pts.forEach((p, i) => {
        let y = H;
        series.forEach((s) => {
          const v = val(p, s.key); if (!v) return;
          const h = Math.max(1, (v / max) * H);
          y -= h;
          svg.append(S("rect", { x: i * bw + bw * 0.12, y, width: Math.max(1, bw * 0.76), height: h, fill: s.color, rx: Math.min(2, bw / 4),
            opacity: o.sel != null && o.sel !== i ? 0.3 : null }));
        });
      });
    } else {
      series.forEach((s) => {
        const xy = pts.map((p, i) => [n === 1 ? W / 2 : (i / (n - 1)) * W, H - (val(p, s.key) / max) * H]);
        const d = xy.map(([x, y], i) => `${i ? "L" : "M"}${x.toFixed(1)},${y.toFixed(1)}`).join("");
        if (s.fill !== false) svg.append(S("path", { d: `${d}L${W},${H}L0,${H}Z`, fill: s.color, opacity: 0.13 }));
        svg.append(S("path", { d, fill: "none", stroke: s.color, "stroke-width": 2, "vector-effect": "non-scaling-stroke", "stroke-linejoin": "round" }));
      });
    }
    (o.lines || []).forEach((l) => svg.append(S("line", { x1: 0, x2: W, y1: H - (l.value / max) * H, y2: H - (l.value / max) * H, stroke: l.color || "var(--bad)", "stroke-dasharray": "6 5", "vector-effect": "non-scaling-stroke" })));
    const yl = el("div", { class: "mx-yax" }, [4, 3, 2, 1, 0].map((i) => el("span", { text: o.yfmt ? o.yfmt((max * i) / 4) : num((max * i) / 4) })));
    const xl = el("div", { class: "mx-xax" });
    const ticks = Math.min(o.ticks || 6, n);
    for (let i = 0; i < ticks; i++) {
      const idx = Math.round((i * (n - 1)) / Math.max(1, ticks - 1));
      xl.append(el("span", { style: `left:${n === 1 ? 50 : (idx / (n - 1)) * 100}%`, text: o.xfmt(pts[idx][0]) }));
    }
    const guide = el("div", { class: "mx-guide", hidden: "" }), tip = el("div", { class: "mx-tip", hidden: "" });
    const plot = el("div", { class: `mx-plot ${o.onPick ? "mx-plot-pick" : ""}` }, [svg, guide, tip]);
    const slot = (e) => {
      const r = plot.getBoundingClientRect(), f = (e.clientX - r.left) / r.width;
      return Math.max(0, Math.min(n - 1, o.type === "line" ? Math.round(f * (n - 1)) : Math.floor(f * n)));
    };
    // onPick(index, point): a click on a bar, e.g. to show only what happened then.
    if (o.onPick) plot.addEventListener("click", (e) => o.onPick(slot(e), pts[slot(e)]));
    plot.addEventListener("mousemove", (e) => {
      const i = slot(e);
      const p = pts[i];
      const gx = o.type === "line" ? (n === 1 ? 50 : (i / (n - 1)) * 100) : ((i + 0.5) / n) * 100;
      guide.hidden = false; guide.style.left = `${gx}%`;
      tip.hidden = false; tip.innerHTML = "";
      // tipNonZero: many series (one per category), list only those present in this slot, biggest first.
      const shown = series.filter((s) => p[1][s.key] != null && (!o.tipNonZero || val(p, s.key)));
      if (o.tipNonZero) shown.sort((a, b) => val(p, b.key) - val(p, a.key));
      tip.append(el("b", { text: (o.tipX || o.xfmt)(p[0]) }), ...shown.map((s) =>
        el("div", {}, [el("i", { style: `background:${s.color}` }), el("span", { text: s.label }), el("em", { text: o.yfmt ? o.yfmt(val(p, s.key)) : num(val(p, s.key)) })])));
      if (o.stacked !== false && series.length > 1) tip.append(el("div", { class: "mx-tip-tot" }, [el("span", { text: "Total" }), el("em", { text: o.yfmt ? o.yfmt(tot[i]) : num(tot[i]) })]));
      if (o.onPick && o.pickHint && tot[i]) tip.append(el("div", { class: "mx-tip-hint", text: o.pickHint }));
      tip.style.left = gx > 60 ? "" : `calc(${gx}% + 12px)`; tip.style.right = gx > 60 ? `calc(${100 - gx}% + 12px)` : "";
    });
    plot.addEventListener("mouseleave", () => { guide.hidden = true; tip.hidden = true; });
    box.append(el("div", { class: "mx-chart-body" }, [yl, plot]), xl);
    if (o.legend !== false && series.length > 1) box.append(el("div", { class: "mx-legend" }, series.map((s) => el("span", {}, [el("i", { style: `background:${s.color}` }), s.label]))));
    return box;
  }
  const PALETTE = ["#ff7a1a", "#6fb6ff", "#3fd08f", "#b38cff", "#ffb347", "#ff6b9a", "#4fd1c5", "#c4a484", "#9aa5b1", "#ffd84d"];
  function donut(items, fmt) {
    if (!items.length || !items.some((x) => x.n)) return el("p", { class: "muted mx-none", text: "Nothing yet." });
    const total = items.reduce((a, x) => a + x.n, 0) || 1;
    const svg = S("svg", { viewBox: "0 0 42 42", class: "mx-donut" });
    svg.append(S("circle", { cx: 21, cy: 21, r: 15.915, fill: "none", stroke: "var(--stroke)", "stroke-width": 6 }));
    let off = 25;
    items.forEach((x, i) => {
      const pct = (x.n / total) * 100;
      svg.append(S("circle", { cx: 21, cy: 21, r: 15.915, fill: "none", stroke: x.color || PALETTE[i % PALETTE.length], "stroke-width": 6,
        "stroke-dasharray": `${pct} ${100 - pct}`, "stroke-dashoffset": off }));
      off -= pct;
    });
    return el("div", { class: "mx-donut-wrap" }, [svg, el("div", { class: "mx-donut-legend" }, items.map((x, i) =>
      el("div", {}, [el("i", { style: `background:${x.color || PALETTE[i % PALETTE.length]}` }), el("span", { class: "mx-ell", text: x.label, title: x.label }),
        el("em", { text: `${fmt ? fmt(x.n) : num(x.n)} · ${((x.n / total) * 100).toFixed(x.n / total < 0.1 ? 1 : 0)}%` })])))]);
  }
  // Ranked list with proportional bars; rows: {label, n, sub?, onclick?, extra?}
  function rank(rows, opts = {}) {
    if (!rows.length) return el("p", { class: "muted mx-none", text: opts.empty || "Nothing yet." });
    const max = Math.max(...rows.map((r) => r.n)) || 1;
    return el("div", { class: "mx-rank" }, rows.slice(0, opts.limit || 10).map((r) => el(r.onclick ? "button" : "div", { class: "mx-rank-row", type: r.onclick ? "button" : null, onclick: r.onclick, title: r.title || r.label }, [
      el("div", { class: "mx-rank-bar", style: `width:${(r.n / max) * 100}%` }),
      el("span", { class: `mx-rank-l mx-ell ${r.cls || ""}`, text: r.label }), r.extra || null,
      el("span", { class: "mx-rank-n", text: opts.fmt ? opts.fmt(r.n) : num(r.n) }),
    ])));
  }
  const card = (title, kids, cls, head) => el("div", { class: `card mx-card ${cls || ""}` }, [el("div", { class: "mx-card-h" }, [el("h3", { text: title }), el("span", { class: "grow" }), ...(head || [])]), ...kids]);
  function sortableTable(cols, rows, opts = {}) {
    let sk = opts.sort || cols[0].k, dir = opts.dir || -1;
    const wrap = el("div", { class: "table-wrap mx-table-wrap" });
    const draw = () => {
      const col = cols.find((c) => c.k === sk) || cols[0];
      const v = col.sortv || ((r) => r[col.k]);
      const rs = [...rows].sort((a, b) => { const x = v(a), y = v(b); return (x > y ? 1 : x < y ? -1 : 0) * dir; });
      wrap.innerHTML = "";
      wrap.append(el("table", { class: "mx-table" }, [el("thead", {}, el("tr", {}, cols.map((c) => el("th", { class: `${c.num ? "num" : ""} ${c.k === sk ? "sorted" : ""}`,
        onclick: () => { if (sk === c.k) dir = -dir; else { sk = c.k; dir = c.num ? -1 : 1; } draw(); } }, [c.label, c.k === sk ? el("span", { class: "mx-sort", text: dir < 0 ? " ↓" : " ↑" }) : null])))),
        el("tbody", {}, rs.slice(0, opts.limit || 500).map((r) => el("tr", {}, cols.map((c) => el("td", { class: c.num ? "num" : c.cls || "" }, c.render ? c.render(r) : String(r[c.k] ?? ""))))))]));
    };
    draw();
    return wrap;
  }
  const ipCls = (st, rep) => (st === "banned" ? "ip-banned" : st === "trusted" ? "ip-trusted" : rep ? "ip-reported" : "");
  async function banIp(ip, reason) {
    return call(() => API.guardBan(ip, reason, 24 * 3600, document.title.split(" · ")[0]), `${ip} banned for 24 hours`);
  }

  // ---------------------------------------------------------------- one IP, in the panel
  const FLAG = (cc) => (cc && /^[A-Z]{2}$/.test(cc) ? String.fromCodePoint(...[...cc].map((c) => 0x1f1a5 + c.charCodeAt(0))) : "");
  const DURATIONS = [[3600, "1 hour"], [86400, "24 hours"], [7 * 86400, "7 days"], [30 * 86400, "30 days"], [0, "Forever"]];
  async function ipCard(ip, onChange) {
    const body = el("div", { class: "mx-ipcard" }, el("div", { class: "loading", text: `Looking up ${ip}…` }));
    const foot = el("div", { class: "mx-ipfoot" });
    openModal(`IP address ${ip}`, el("div", {}, [body]), [foot]);
    const m = document.querySelector("#modal .modal"); if (m) m.classList.add("em-modal");
    let days = 7;
    async function load() {
      let d;
      try { d = await API.metIp(ip, days); } catch (e) { body.innerHTML = ""; body.append(el("p", { class: "empty", text: e.message })); return; }
      const st = d.state || {}, o = d.owner || {}, w = d.web;
      body.innerHTML = "";
      const stPill = st.status === "banned" ? pill(st.kind === "fail2ban" ? `banned by fail2ban (${(st.jails || []).join(", ") || "jail"})` : "banned", "bad")
        : st.status === "trusted" ? pill("trusted", "good") : pill("not banned");
      const banLine = st.status === "banned" ? (st.kind === "manual"
        ? `Banned ${st.created ? ago(st.created) : ""}${st.source ? ` from ${st.source}` : ""}${st.cidr && st.cidr !== ip && st.cidr !== ip + "/32" ? ` as part of ${st.cidr}` : ""}${st.reason ? `, “${st.reason}”` : ""}. ${st.expires ? `Lifts ${new Date(st.expires * 1000).toLocaleString()}.` : "Until you unban it."}`
        : `fail2ban banned it automatically${st.expires_in ? `, lifts in ${dur(st.expires_in)}` : ""}.`) + " It can't reach anything on this server: websites, mail, SSH, FTP, VPN and this panel."
        : st.status === "trusted" ? `Trusted${st.cidr && st.cidr !== ip && st.cidr !== ip + "/32" ? ` (via ${st.cidr})` : ""}${st.reason ? `, “${st.reason}”` : ""}: it is never banned.` : "";
      body.append(el("div", { class: "mx-ip-head" }, [
        el("div", { class: "mx-ip-flag", text: FLAG(o.country) || "🌐" }),
        el("div", { class: "mx-ip-id" }, [el("div", { class: "mx-ip-addr" }, [el("code", { class: ipCls(st.status, d.reported), text: ip }), stPill, d.reported ? pill("reported", "warn") : null]),
          el("div", { class: "muted", text: [o.network, o.country, d.ptr].filter(Boolean).join(" · ") || (d.private ? "A private / local network address" : "No owner information") })]),
        seg([[1, "24 h"], [7, "7 days"], [30, "30 days"]], days, (v) => { days = v; load(); }),
      ]));
      if (banLine) body.append(el("div", { class: `mx-note ${st.status === "trusted" ? "mx-note-ok" : ""}` }, [icon(st.status === "trusted" ? "check" : "ban", 16), el("span", { text: banLine })]));
      body.append(el("div", { class: "mx-tiles mx-tiles-6" }, [
        tile("Requests", num(w.hits), w.last ? `last ${ago(w.last)}` : "none in this period", "processes"),
        tile("Pages", num(w.pages), "real pages, not images/CSS", "listing"),
        tile("Data sent", fmtBytes(w.bytes), "", "network"),
        tile("WAF", num(d.waf.events), d.waf.events ? `${num(d.waf.blocked)} blocked` : "no attacks seen", "shield", d.waf.events ? "warnt" : ""),
        tile("Failed logins", num(d.logins_failed), "SSH, mail, panel, FTP", "key", d.logins_failed ? "warnt" : ""),
      ]));
      const kvRow = (k, v) => (v ? el("div", { class: "mx-kv" }, [el("span", { text: k }), typeof v === "string" ? el("span", { text: v }) : v]) : null);
      body.append(el("div", { class: "mx-grid2" }, [
        card("Who owns it", [
          o.error ? el("p", { class: "muted", text: o.error }) : null,
          kvRow("Network", o.network), kvRow("Country", o.country ? `${FLAG(o.country)} ${o.country}` : ""), kvRow("Range", o.range), kvRow("Reverse DNS", d.ptr),
          o.contacts && o.contacts.length ? kvRow(o.abuse_role ? "Abuse contact" : "Contact", el("span", {}, o.contacts.map((c) => el("code", { class: "mx-chipc", text: c })))) : null,
          d.private ? el("p", { class: "muted", text: "A private address: a device on your own network, a VPN client, or this server itself." }) : null,
          el("div", { class: "toolbar" }, [el("a", { class: "btn btn-sm btn-ghost", href: `https://rdap.org/ip/${encodeURIComponent(ip)}`, target: "_blank", rel: "noopener noreferrer", text: "Full registry record ↗" })]),
        ]),
        card("What it did", [
          w.sites.length ? el("div", { class: "mx-sub" }, "Websites") : null, w.sites.length ? rank(w.sites.map(([s, n]) => ({ label: s, n })), { limit: 5 }) : null,
          d.waf.types.length ? el("div", { class: "mx-sub" }, "Attacks the WAF saw") : null, d.waf.types.length ? rank(d.waf.types.map(([s, n]) => ({ label: s, n })), { limit: 5 }) : null,
          w.agents.length ? el("div", { class: "mx-sub" }, "Identifies as") : null,
          ...w.agents.map((a) => el("div", { class: "mx-list-row" }, [el("span", { class: a.bot ? "mx-bot" : "", text: a.bot ? `🤖 ${a.browser}` : `${a.browser} · ${a.os}` }),
            el("span", { class: "muted mx-ell grow", title: a.ua, text: a.ua || "(empty)" }), el("b", { text: num(a.n) })])),
          !w.hits && !d.waf.events ? el("p", { class: "muted", text: "No requests to your websites in this period." }) : null,
        ]),
      ]));
      if (w.recent.length) body.append(card("Latest requests", [el("div", { class: "table-wrap mx-table-wrap", style: "max-height:320px" }, el("table", { class: "mx-table" }, [
        el("thead", {}, el("tr", {}, ["Time", "Site", "Request", "Status", "Size"].map((h, i) => el("th", { class: i >= 3 ? "num" : "", text: h })))),
        el("tbody", {}, w.recent.map((r) => el("tr", {}, [el("td", { class: "mx-time", text: t2s(r.ts) }), el("td", { class: "mx-ell", text: r.site }),
          el("td", {}, [el("span", { class: "muted", text: r.method + " " }), el("span", { class: "mx-url", title: r.url, text: r.url })]),
          el("td", { class: "num" }, el("span", { class: `mx-st ${statusKind(r.status)}`, text: r.status })), el("td", { class: "num", text: fmtBytes(r.size) })])))]))]));
      // actions
      foot.innerHTML = "";
      const act = async (fn, ok) => { if (await call(fn, ok)) { await load(); if (onChange) onChange(); } };
      const allSrv = d.servers ? el("label", { class: "dm-check op-allsrv" }, [el("input", { type: "checkbox" }), el("span", { text: `also on my ${d.servers} other server${d.servers > 1 ? "s" : ""}` })]) : null;
      const everywhere = () => allSrv && allSrv.querySelector("input").checked;
      if (st.status === "banned") foot.append(btn("Unban", () => act(() => everywhere() ? API.serversBan({ ip: st.kind === "manual" && st.cidr ? st.cidr : ip, unban: true })
        : API.guardUnban(st.kind === "manual" && st.cidr ? st.cidr : ip), `${ip} unbanned`), "btn-primary"));
      else if (st.status !== "trusted") {
        const dsel = el("select", { class: "em-select mx-narrow" }, DURATIONS.map(([v, l]) => el("option", { value: v, text: l })));
        dsel.value = "86400";
        foot.append(el("div", { class: "mx-ban" }, [dsel, btn("Ban", () => act(() => everywhere() ? API.serversBan({ ip, reason: `${w.hits} requests, ${d.waf.events} WAF events, ${d.logins_failed} failed logins`, duration: +dsel.value || null })
          : API.guardBan(ip, `${w.hits} requests, ${d.waf.events} WAF events, ${d.logins_failed} failed logins`, +dsel.value || null, `IP card · ${document.title.split(" · ")[0]}`), `${ip} banned`), "btn-danger")]));
      }
      if (st.status === "trusted") foot.append(btn("Remove from trusted", () => act(() => API.guardUntrust(st.cidr || ip), `${ip} no longer trusted`), "btn-ghost"));
      else if (st.status !== "banned") foot.append(btn("Trust", () => act(() => API.guardTrust(ip, "Trusted from the IP card"), `${ip} trusted, it will never be banned`), "btn-ghost"));
      if (!d.private) foot.append(btn(d.reported ? "Reported · read / send again" : "Report abuse", () => reportIp(ip, onChange), "btn-ghost"));
      foot.append(btn("Copy IP", async () => toast(await copyText(ip) ? "Copied" : "Copy failed", "good"), "btn-ghost"));
      if (allSrv && st.status !== "trusted") foot.append(allSrv);
    }
    load();
  }
  // Send an abuse report to the network that owns ip, from this server's own mail, with the evidence attached.
  async function reportIp(ip, done) {
    let p;
    try { p = await API.abusePreview(ip); } catch (e) { toast(e.message, "bad"); return; }
    if (!p.mail_ready) { toast("Reports go out through this server's mail, set up Email first", "bad"); return; }
    if (!p.info.contacts.length) { toast(`No abuse contact is published for ${ip}`, "bad"); return; }
    const from = el("select", { class: "em-select" }, p.accounts.map((a) => el("option", { value: a, text: a })));
    if (p.from) from.value = p.from;
    // Editable: pre-filled with the parsed abuse contact, but the registry often lists a person, 
    // the real desk is usually abuse@<domain>, offered in the dropdown. The user can type any address.
    const suggestions = p.info.suggestions && p.info.suggestions.length ? p.info.suggestions : p.info.contacts;
    const toList = el("datalist", { id: "abuse-to-list" }, suggestions.map((a) => el("option", { value: a })));
    const to = el("input", { type: "email", class: "em-select", value: p.info.contacts[0] || "", list: "abuse-to-list", autocomplete: "off", spellcheck: "false" });
    const toWrap = el("div", { style: "display:contents" }, [to, toList]);
    const note = el("textarea", { rows: 2, placeholder: "Optional note added to the report" });
    const preview = el("pre", { class: "mx-pre", style: "max-height:280px", text: p.body });
    const c = p.counts || { logins: p.events, attacks: 0 };
    const send = el("button", { class: "btn btn-primary", text: p.reported ? "Send again" : "Send report", onclick: async () => {
      const dest = to.value.trim();
      if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(dest)) { to.focus(); return toast("Enter the abuse contact's email address", "bad"); }
      send.disabled = true;
      try {
        const r = await API.abuseReport({ ip, sender: from.value, to: dest, note: note.value.trim(), force: !!p.reported });
        toast(`Reported ${ip} to ${r.to.join(", ")}`, "good"); closeModal(); if (done) done();
      } catch (err) { toast(err.message, "bad"); send.disabled = false; }
    } });
    openModal(`Report ${ip}`, el("div", { class: "em-form" }, [
      el("div", { class: "mx-tiles" }, [
        tile("Failed logins", num(c.logins), "SSH, mail, panel, FTP · 7 days", "key", c.logins ? "warnt" : ""),
        tile("Web attacks", num(c.attacks), "caught by the WAF · 7 days", "shield", c.attacks ? "warnt" : ""),
        tile("Network", p.info.network || ", ", p.info.country || "", "globe"),
      ]),
      !p.events ? el("div", { class: "mx-note" }, [icon("warning", 16), el("span", { text: "No failed logins or WAF attacks from this address in the last 7 days, abuse desks usually ignore reports without evidence." })]) : null,
      p.reported ? el("div", { class: "mx-note" }, [icon("check", 16), el("span", { text: `Already reported to ${p.reported.to.join(", ")} on ${new Date(p.reported.ts * 1000).toLocaleString()} from ${p.reported.from}. Sending again repeats it.` })]) : null,
      p.accounts.length ? el("div", { class: "mx-grid2" }, [field("Send from", from, "Remembered for next time; replies come here."), field("To (abuse contact)", toWrap, "Pre-filled from the registry, edit it or pick abuse@… if the desk differs.")])
        : el("p", { class: "empty", text: "Create an email account first (Email → Email Accounts)." }),
      field("Note", note),
      el("div", { class: "mx-sub" }, "The message"), preview,
      p.info.whois_url ? el("p", { class: "muted mx-small", style: "margin:6px 0 0" },
        [el("a", { href: p.info.whois_url, target: "_blank", rel: "noopener noreferrer", text: p.info.whois_label || "Look up the registry record" }), ", check the abuse address if it looks wrong."]) : null,
    ].filter(Boolean)), p.accounts.length ? [send] : []);
    const m = document.querySelector("#modal .modal"); if (m) m.classList.add("em-modal");
  }

  // ======================================================================
  //  Security → WAF Firewall
  // ======================================================================
  const WAF_MODES = [["block", "Blocking"], ["detect", "Detect only"], ["off", "Off"]];
  const PARANOIA = {
    1: ["Standard", "Recommended. Catches the common attacks with almost no false alarms."],
    2: ["Strict", "More rules (e.g. extra SQL and XSS patterns). Occasional false alarms on complex forms."],
    3: ["Very strict", "For sites handling sensitive data. Expect to allow a few rules for your apps."],
    4: ["Paranoid", "Everything unusual is blocked. Only for locked-down APIs; many false alarms."],
  };
  function viewWaf(root) {
    const body = el("div", {}, el("div", { class: "loading", text: "Loading…" }));
    root.append(pageHead("WAF Firewall", "A web application firewall in front of every website on this server: ModSecurity with the OWASP Core Rule Set inspects each request and stops SQL injection, cross-site scripting, path traversal, remote code execution and vulnerability scanners before they reach your apps."), body);
    let d, hours = 24, evFilter = "all", evQ = "", sitesList = [];
    async function save(data, msg) { return call(() => API.wafSave(data), msg || "WAF settings applied", () => load()); }
    async function load() {
      try { d = await API.waf(); } catch (e) { body.innerHTML = ""; body.append(el("p", { class: "empty", text: e.message })); return; }
      if (!sitesList.length) { try { sitesList = (await API.metSites()).sites; } catch (e) {} }
      draw();
    }
    function draw() {
      body.innerHTML = "";
      const on = d.mode !== "off" && d.module_on;
      const modeKind = !on ? "bad" : d.mode === "block" ? "good" : "warn";
      const testOut = el("div", { class: "mx-test-out" });
      body.append(el("div", { class: `card mx-hero ${modeKind}` }, [
        el("div", { class: "mx-hero-ico" }, icon("shield", 30)),
        el("div", { class: "mx-hero-txt" }, [
          el("h3", { text: !on ? "The WAF is off, websites aren't filtered" : d.mode === "block" ? "Protecting your websites" : "Watching, not blocking" }),
          el("p", { class: "muted", text: !on ? "Turn on Blocking to stop attacks, or Detect only to see what would be blocked first."
            : d.mode === "block" ? `Attacks are refused with “403 Forbidden”. OWASP CRS ${d.crs_version || ""}, ${PARANOIA[d.paranoia][0].toLowerCase()} rules.`
            : "Attacks are logged below but still reach your sites, good for a few days after installing a new app, then switch to Blocking." }),
          testOut,
        ]),
        el("div", { class: "mx-hero-act" }, [
          seg(WAF_MODES, d.mode, (m) => save({ mode: m }, m === "block" ? "Blocking attacks" : m === "detect" ? "Detect-only mode" : "WAF off")),
          btn("Send a test attack", async (e) => {
            e.target.disabled = true;
            const r = await call(() => API.wafTest());
            e.target.disabled = false;
            if (r) { testOut.innerHTML = ""; testOut.append(pill(r.verdict, r.blocked ? "good" : r.mode === "block" ? "bad" : "warn")); loadEvents(); }
          }, "btn-ghost"),
        ]),
      ]));
      const st = d.stats;
      body.append(el("div", { class: "mx-tiles" }, [
        tile("Attacks, last 24 h", num(st.events), st.events ? `${num(st.blocked)} blocked · ${num(st.detected)} logged only` : "None, quiet day", "shield", st.events ? "accent" : ""),
        tile("Top attack type", st.types[0] ? st.types[0][0] : ", ", st.types[0] ? `${num(st.types[0][1])} requests` : "", "brick"),
        tile("Top attacker", st.ips[0] ? st.ips[0][0] : ", ", st.ips[0] ? `${num(st.ips[0][1])} requests` : "", "ban"),
        tile("Rules switched off", num(Object.keys(d.disabled_rules).length), "False alarms you allowed", "check"),
      ]));
      // ---- settings
      const lvl = el("div", { class: "mx-levels" }, [1, 2, 3, 4].map((n) => el("button", { type: "button", class: `mx-level ${d.paranoia === n ? "on" : ""}`,
        onclick: () => d.paranoia !== n && save({ paranoia: n }, `Rule level: ${PARANOIA[n][0]}`) }, [el("b", { text: `${n} · ${PARANOIA[n][0]}` }), el("span", { class: "muted", text: PARANOIA[n][1] })])));
      const thr = el("select", { class: "em-select", onchange: () => save({ threshold: +thr.value }, "Sensitivity saved") },
        [[5, "Normal, one critical match blocks (recommended)"], [10, "Relaxed, needs two critical matches"], [25, "Lenient, only obvious attacks"], [3, "Tight, even minor matches add up"]].map(([v, l]) => el("option", { value: v, text: l })));
      thr.value = String(d.threshold);
      if (thr.value !== String(d.threshold)) thr.append(el("option", { value: d.threshold, text: `Custom (${d.threshold})`, selected: "" }));
      const apps = el("div", { class: "mx-chips" }, Object.entries(d.apps_all).map(([k, v]) => {
        const onA = d.apps.includes(k);
        return el("button", { type: "button", class: `em-chip ${onA ? "on" : ""}`, text: (onA ? "✓ " : "") + v,
          onclick: () => save({ apps: onA ? d.apps.filter((x) => x !== k) : [...d.apps, k] }, `${v} exclusions ${onA ? "off" : "on"}`) });
      }));
      const trusted = el("textarea", { rows: 3, placeholder: "One IP or range per line, e.g. 203.0.113.10 or 10.0.0.0/8", class: "mx-mono" });
      trusted.value = d.trusted.join("\n");
      const names = [...new Set(sitesList.flatMap((s) => s.names))].sort();
      const offSites = el("div", { class: "mx-chips" }, names.length ? names.map((h) => {
        const off = d.sites_off.includes(h);
        return el("button", { type: "button", class: `em-chip ${off ? "warnchip" : ""}`, text: (off ? "⏸ " : "") + h, title: off ? "The WAF skips this site, click to protect it again" : "Click to switch the WAF off for this site only",
          onclick: () => save({ sites_off: off ? d.sites_off.filter((x) => x !== h) : [...d.sites_off, h] }, off ? `${h} protected again` : `WAF off for ${h}`) });
      }) : [el("span", { class: "muted", text: "No websites yet." })]);
      body.append(el("div", { class: "mx-grid2" }, [
        card("Rule level (paranoia)", [lvl, field("Sensitivity (anomaly threshold)", thr, "Every matching rule adds points; a request is blocked once it reaches this score.")]),
        card("Exceptions", [
          el("p", { class: "muted mx-p", text: "App exclusions teach the rules what normal looks like for these apps (editors, admin pages), so they don't trip the WAF." }), apps,
          el("div", { class: "mx-sep" }),
          field("Trusted addresses, never filtered", trusted, "Your office or monitoring service. Applied when you click Save."),
          el("div", { class: "toolbar" }, [btn("Save trusted addresses", () => save({ trusted: trusted.value.split(/[\s,]+/).filter(Boolean) }, "Trusted addresses saved"), "btn-primary")]),
          el("div", { class: "mx-sep" }),
          el("p", { class: "muted mx-p", text: "Switch the WAF off for one website only:" }), offSites,
        ]),
      ]));
      const dis = Object.entries(d.disabled_rules);
      if (dis.length) body.append(card("Rules you switched off", [el("div", { class: "mx-list" }, dis.map(([id, r]) => el("div", { class: "mx-list-row" }, [
        el("code", { text: id }), el("span", { class: "mx-ell grow", text: r.msg || "", title: r.msg || "" }), el("span", { class: "muted", text: r.since ? ago(r.since) : "" }),
        btn("Turn back on", () => call(() => API.wafRestore(id), `Rule ${id} active again`, load), "btn-ghost")])))]));
      evBox = el("div", {}, el("div", { class: "loading", text: "Loading events…" }));
      const search = el("input", { type: "search", class: "em-search", placeholder: "Filter by IP, site, path or rule…", value: evQ, oninput: () => { evQ = search.value.toLowerCase(); drawEvents(); } });
      body.append(card("Recent attacks", [el("div", { class: "mx-toolbar" }, [search,
        seg([["all", "All"], ["blocked", "Blocked"], ["logged", "Logged only"]], evFilter, (v) => { evFilter = v; drawEvents(); }),
        seg([[1, "1 h"], [24, "24 h"], [168, "7 days"], [720, "30 days"]], hours, (v) => { hours = v; loadEvents(); })]), evBox], "", [btn("Refresh", () => loadEvents(), "btn-ghost")]));
      loadEvents();
    }
    let evBox, events = [], ipst = {}, reportedIps = {};
    async function loadEvents() {
      try { const r = await API.wafEvents(hours); events = r.events; ipst = r.ip_status || {}; } catch (e) { evBox.innerHTML = ""; evBox.append(el("p", { class: "empty", text: e.message })); return; }
      try { reportedIps = (await API.abuseReported()) || {}; } catch (e) { reportedIps = {}; }
      drawEvents();
    }
    // Ban / Unban / Report straight from a row, with the address's state shown next to the buttons.
    function ipRowActions(e, r0) {
      const ip = e.ip, st = ipst[ip], rep = reportedIps[ip];
      return el("div", { class: "mx-ev-act" }, [
        st === "banned" ? pill("banned", "bad") : st === "trusted" ? pill("trusted", "good") : null,
        rep ? el("span", { class: "pill warn", title: `Reported to ${(rep.to || []).join(", ")} ${ago(rep.ts)}`, text: "reported" }) : null,
        btn("Lookup", () => ipCard(ip, loadEvents), "btn-ghost"),
        st === "banned" ? btn("Unban", () => call(() => API.guardUnban(ip), `${ip} unbanned`, loadEvents), "btn-ghost")
          : st === "trusted" ? null
          : armed("Ban", "Click again · 24 h", () => call(() => API.guardBan(ip, `WAF: ${r0.category}, ${r0.msg}`, 86400, "WAF Firewall"), `${ip} banned for 24 hours`, loadEvents), "btn-danger"),
        btn(rep ? "Report again" : "Report", () => reportIp(ip, loadEvents), "btn-ghost"),
      ].filter(Boolean));
    }
    function drawEvents() {
      if (!evBox) return;
      evBox.innerHTML = "";
      const rows = events.filter((e) => (evFilter === "all" || (evFilter === "blocked") === e.blocked) &&
        (!evQ || `${e.ip} ${e.host} ${e.request} ${e.rules.map((r) => r.id + " " + r.msg).join(" ")}`.toLowerCase().includes(evQ)));
      if (!rows.length) { evBox.append(empty("shield", events.length ? "No matching events" : "No attacks in this period", events.length ? "Try another filter." : "When the WAF stops or logs a request, it shows up here with the reason.")); return; }
      const codeTone = (s) => s >= 500 ? "bad" : s >= 400 ? (s === 404 ? "warn" : "bad") : s >= 300 ? "dim" : "ok";
      evBox.append(el("div", { class: "mx-events" }, rows.slice(0, 300).map((e) => {
        const r0 = e.rules[0];
        const more = el("div", { class: "mx-ev-more", hidden: "" }, [
          el("div", { class: "mx-kv" }, [el("span", { text: "Request" }), el("code", { text: e.request })]),
          (e.status != null && e.status !== "") ? el("div", { class: "mx-kv" }, [el("span", { text: "Server replied" }), el("code", { text: "HTTP " + e.status })]) : null,
          e.ua ? el("div", { class: "mx-kv" }, [el("span", { text: "User agent" }), el("code", { text: e.ua })]) : null,
          el("div", { class: "mx-ev-rules" }, e.rules.map((r) => el("div", { class: "mx-ev-rule" }, [el("code", { text: r.id }), el("span", { class: "grow", text: r.msg }),
            r.severity ? pill(r.severity.toLowerCase(), r.severity === "CRITICAL" ? "bad" : "warn") : null,
            d.disabled_rules[r.id] ? pill("switched off") : btn("Allow this rule", () => {
              if (!confirm(`Switch off rule ${r.id} (“${r.msg}”) for all sites? Do this only for false alarms caused by your own app.`)) return;
              call(() => API.wafAllow(r.id, r.msg), `Rule ${r.id} switched off`, load);
            }, "btn-ghost")]))),
        ]);
        return el("div", { class: `mx-ev${ipst[e.ip] === "banned" ? " is-banned" : ""}` }, [
          el("button", { type: "button", class: "mx-ev-main", onclick: () => { more.hidden = !more.hidden; } }, [
            pill(e.blocked ? "Blocked" : "Logged", e.blocked ? "bad" : "warn"),
            el("div", { class: "mx-ev-what" }, [el("b", { text: r0.category }), el("span", { class: "muted mx-ell", text: r0.msg })]),
            el("div", { class: "mx-ev-req mx-ell", title: e.request }, [el("span", { class: "muted", text: e.host || "" }), " ", el("code", { text: e.request.replace(/ HTTP\/[\d.]+$/, "") })]),
            (e.status != null && e.status !== "") ? el("span", { class: "mx-ev-code code-" + codeTone(e.status), title: `Server replied with HTTP ${e.status}`, text: String(e.status) }) : null,
            el("span", { class: "mx-ev-ipw" },[el("span", { class: `mx-ev-ip mx-ip ${ipCls(ipst[e.ip], reportedIps[e.ip])}`, role: "link", text: e.ip, title: "Who is this?", onclick: (ev) => { ev.stopPropagation(); ipCard(e.ip, loadEvents); } })]),
            el("span", { class: "muted mx-ev-t", text: ago(e.ts) }),
          ]),
          ipRowActions(e, r0),
          more,
        ]);
      })));
    }
    load();
  }

  // ======================================================================
  //  Domains → Dynamic DNS (hosts on this server's own DNS zones)
  // ======================================================================
  let DDNS_BASES = {};
  function ddnsUrls(h, key) {
    const base = DDNS_BASES[h.domain] || `https://${h.domain}`;
    return { url: `${base}/ddns/update?key=${key}`, panel: `${location.origin}/ddns/update?key=${key}`, nic: `${base}/nic/update?hostname=${h.host}` };
  }
  function showDdnsKey(h, key) {
    const u = ddnsUrls(h, key);
    const row = (label, value) => el("div", { class: "em-copy" }, [el("span", { class: "em-copy-k", text: label }), el("code", { class: "em-mono", text: value }),
      el("button", { type: "button", class: "bk-mini", text: "Copy", onclick: async () => toast(await copyText(value) ? `${label} copied` : "Copy failed", "good") })]);
    const tabs = el("div", { class: "mx-seg" }), pane = el("div", { class: "mx-ddns-pane" });
    const T = {
      "Update URL": () => [el("p", { class: "muted", text: "Open this URL from the network whose IP should be used, a browser, a script, or a router. The record moves to the caller's public IP. Add &ip=… to set an address yourself." }),
        row("URL", u.url), row("Via the panel", u.panel),
        u.url.startsWith("http:") ? el("p", { class: "muted mx-small", text: "No trusted HTTPS certificate covers this domain yet, so the URL uses plain HTTP. Get a free certificate in SSL/TLS to switch it to HTTPS." }) : null,
        el("p", { class: "muted mx-small", text: "Answers: “good <ip>” (changed), “nochg <ip>” (already right), “badauth” (wrong key), “abuse” (too often, wait 30 s)." })],
      "Linux (cron)": () => [el("p", { class: "muted", text: "Runs every 5 minutes on the machine at home and keeps the name pointed at it:" }),
        row("crontab -e", `*/5 * * * * curl -fsS "${u.url}" >/dev/null`), row("IPv6 too", `*/5 * * * * curl -6 -fsS "${u.url}" >/dev/null`)],
      "Router (DynDNS)": () => [el("p", { class: "muted", text: "Most routers (FRITZ!Box, OpenWrt, pfSense, OPNsense, MikroTik, Ubiquiti…) have a “Custom” or “DynDNS2” Dynamic DNS option:" }),
        row("Server / URL", `${u.nic.replace(/^https?:\/\//, "").split("/")[0]}/nic/update?hostname=<domain>&myip=<ipaddr>`), row("Hostname", h.host), row("Username", h.host), row("Password", key),
        el("p", { class: "muted mx-small", text: "If the router asks for a full update URL instead, use the one from the first tab." })],
      Windows: () => [el("p", { class: "muted", text: "Task Scheduler → Create Basic Task → every 5 minutes → Start a program:" }),
        row("Program", "powershell.exe"), row("Arguments", `-NoProfile -Command "Invoke-RestMethod '${u.url}'"`)],
    };
    const show = (k) => { tabs.querySelectorAll("button").forEach((b) => b.classList.toggle("on", b.textContent === k)); pane.innerHTML = ""; pane.append(...T[k]()); };
    Object.keys(T).forEach((k) => tabs.append(el("button", { type: "button", text: k, onclick: () => show(k) })));
    openModal(`Update ${h.host}`, el("div", { class: "em-form" }, [
      el("div", { class: "mx-note" }, [icon("key", 16), el("span", { text: "The key in this URL is the password for this name, anyone who has it can move the record. Regenerate it if it leaks." })]),
      tabs, pane]), []);
    const m = document.querySelector("#modal .modal"); if (m) m.classList.add("em-modal");
    show("Update URL");
  }
  function viewDdnsHosts(root) {
    const body = el("div", {}, el("div", { class: "loading", text: "Loading…" }));
    const createBtn = el("button", { class: "btn btn-primary", onclick: () => create() }, [icon("plus", 15), " Create"]);
    root.append(pageHead("Dynamic DNS", "Give a device on a network with a changing IP, your home, an office, a Raspberry Pi behind a router, a fixed name like home.example.com, served by this server's DNS. A secret URL moves the name whenever the IP changes.",
      [btn("Updater on this machine (DuckDNS…)", () => navigate("dyndns"), "btn-ghost"), createBtn]), body);
    let d, q = "";
    async function load() {
      try { d = await API.ddnsHosts(); } catch (e) { body.innerHTML = ""; body.append(el("p", { class: "empty", text: e.message })); return; }
      DDNS_BASES = d.bases || {};
      draw();
    }
    function draw() {
      body.innerHTML = "";
      if (!d.domains.length) {
        body.append(el("div", { class: "card" }, empty("zone", "No DNS zones on this server yet", "Dynamic DNS names live in a domain whose DNS this server answers. Create the zone first, then point the domain's nameservers here.", btn("Open Zone Editor", () => navigate("zones"), "btn-primary"))));
        createBtn.disabled = true; return;
      }
      if (!d.hosts.length) {
        body.append(el("div", { class: "card" }, empty("refresh", "No Dynamic DNS names yet", "Create one, then put its update URL in your router or a cron job at home.", btn("Create", () => create(), "btn-primary"))));
        return;
      }
      const search = el("input", { type: "search", class: "em-search", placeholder: "Search by name, IP or description…", value: q, oninput: () => { q = search.value.toLowerCase(); list(); } });
      const tbl = el("div", {});
      body.append(el("div", { class: "card em-pad0" }, [el("div", { class: "em-tools-bar" }, [search, el("span", { class: "muted", text: `${d.hosts.length} name${d.hosts.length === 1 ? "" : "s"}` })]), tbl]));
      function list() {
        const rows = d.hosts.filter((h) => !q || `${h.host} ${h.ip} ${h.ip6} ${h.description}`.toLowerCase().includes(q));
        tbl.innerHTML = "";
        tbl.append(el("div", { class: "table-wrap" }, el("table", { class: "mx-table" }, [
          el("thead", {}, el("tr", {}, ["Name", "Address", "Last update", "Description", ""].map((h) => el("th", { text: h })))),
          el("tbody", {}, rows.map((h) => el("tr", {}, [
            el("td", {}, [el("b", { text: h.host }), el("div", { class: "muted mx-small", text: `created ${ago(h.created)}` })]),
            el("td", {}, [h.ip ? el("code", { text: h.ip }) : null, h.ip6 ? el("div", {}, el("code", { class: "mx-small", text: h.ip6 })) : null, !h.ip && !h.ip6 ? el("span", { class: "muted", text: "waiting for the first update" }) : null]),
            el("td", {}, [el("div", { text: h.updated ? ago(h.updated) : "never" }), h.last_result ? el("div", { class: "muted mx-small mx-ell", title: `${h.last_result}${h.last_from ? " · from " + h.last_from : ""}`, text: `${h.last_result}${h.last_from ? " · from " + h.last_from : ""}` }) : null]),
            el("td", { class: "mx-ell", text: h.description || ", " }),
            el("td", { class: "mx-actions" }, [
              btn("Update URL", async () => { const k = await call(() => API.ddnsHostKey(h.id)); if (k) showDdnsKey(h, k.key); }, "btn-primary"),
              btn("Edit", () => edit(h), "btn-ghost"),
              armed("Delete", "Click again", () => call(() => API.ddnsHostDelete(h.id), `${h.host} deleted`, load), "btn-ghost"),
            ]),
          ])))])));
      }
      list();
    }
    function create() {
      const prefix = el("input", { type: "text", placeholder: "home", autocomplete: "off" });
      const dom = el("select", { class: "em-select" }, d.domains.map((x) => el("option", { value: x, text: "." + x })));
      const manual = el("input", { type: "text", placeholder: d.your_ip || "203.0.113.10", autocomplete: "off" });
      const ipWrap = el("div", { hidden: "" }, field("IP address", manual, "Leave empty to wait for the first update from the device."));
      const useMine = el("input", { type: "checkbox" }); useMine.checked = !!d.your_ip && !/^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|127\.)/.test(d.your_ip);
      const desc = el("input", { type: "text", placeholder: "Home router, office NAS…", maxlength: 200 });
      const preview = el("div", { class: "mx-preview" });
      const upd = () => { preview.textContent = `${(prefix.value.trim() || "home").toLowerCase()}.${dom.value}`; };
      prefix.addEventListener("input", upd); dom.addEventListener("change", upd); upd();
      const go = el("button", { class: "btn btn-primary", text: "Create", onclick: async () => {
        go.disabled = true;
        const ip = !ipWrap.hidden ? manual.value.trim() : useMine.checked ? d.your_ip : "";
        const r = await call(() => API.ddnsHostCreate({ domain: dom.value, prefix: prefix.value.trim(), ip, description: desc.value.trim() }), "Dynamic DNS name created");
        go.disabled = false;
        if (r) { closeModal(); await load(); showDdnsKey(r, r.key); }
      } });
      openModal("Create a Dynamic DNS name", el("div", { class: "em-form" }, [
        el("label", { class: "net-field" }, [el("span", { text: "Name" }), el("div", { class: "mx-prefix" }, [prefix, dom]), el("small", { class: "dm-hint", text: "A subdomain of a zone on this server, e.g. home, office or pi.lab." })]),
        preview,
        d.your_ip ? el("label", { class: "dm-check" }, [useMine, el("span", { text: `Start with the IP you're connecting from now (${d.your_ip})` })]) : null,
        el("button", { type: "button", class: "mx-link", text: "Enter an IP address manually (optional) ›", onclick: (e) => { ipWrap.hidden = !ipWrap.hidden; e.target.textContent = ipWrap.hidden ? "Enter an IP address manually (optional) ›" : "Hide manual IP ‹"; useMine.closest("label") && (useMine.closest("label").hidden = !ipWrap.hidden); } }),
        ipWrap,
        field("Description (optional)", desc, "A friendly label so you know which device this is."),
      ]), [go]);
      setTimeout(() => prefix.focus(), 50);
    }
    function edit(h) {
      const desc = el("input", { type: "text", value: h.description || "", maxlength: 200 });
      const ip = el("input", { type: "text", placeholder: h.ip || h.ip6 || "203.0.113.10" });
      openModal(`Edit ${h.host}`, el("div", { class: "em-form" }, [
        field("Description", desc),
        field("Set the IP now (optional)", ip, "Normally the device updates it by itself."),
        el("div", { class: "mx-sep" }),
        el("p", { class: "muted", text: "New key: the old update URL stops working at once, update your router or cron job afterwards." }),
        el("div", { class: "toolbar" }, [armed("Regenerate key", "Click again", async () => { const r = await call(() => API.ddnsHostRegen(h.id), "New key generated"); if (r) { closeModal(); showDdnsKey(h, r.key); } }, "btn-ghost")]),
      ]), [el("button", { class: "btn btn-primary", text: "Save", onclick: () => call(() => API.ddnsHostEdit(h.id, { description: desc.value, ip: ip.value.trim() || null }), "Saved", () => { closeModal(); load(); }) })]);
    }
    load();
  }

  // ======================================================================
  //  Metrics, site picker shared by Visitors and Analytics
  // ======================================================================
  async function sitePicker(root, view, title, desc) {
    root.append(pageHead(title, desc));
    const box = el("div", {}, el("div", { class: "loading", text: "Loading…" }));
    root.append(box);
    let sites;
    try { sites = (await API.metSites()).sites; } catch (e) { box.innerHTML = ""; box.append(el("p", { class: "empty", text: e.message })); return; }
    box.innerHTML = "";
    const real = sites.filter((s) => s.exists || s.size);
    if (!real.length) { box.append(el("div", { class: "card" }, empty("globe", "No web server logs yet", "Once Apache serves a website its visits show up here.", btn("Domains", () => navigate("vhosts"), "btn-primary")))); return; }
    box.append(el("div", { class: "mx-sites" }, real.map((s) => el("button", { type: "button", class: "mx-site", onclick: () => navigate(view, { arg: s.id }) }, [
      el("div", { class: "mx-site-h" }, [icon(s.kind === "site" ? "globe" : "server", 18), el("b", { class: "mx-ell", text: s.label }), s.ssl ? pill("HTTPS", "good") : null]),
      el("div", { class: "muted mx-small mx-ell", text: s.names.length ? s.names.join(", ") : s.kind === "default" ? "Requests by IP address or names no site claims" : "" }),
      el("div", { class: "mx-site-f" }, [el("span", { text: fmtBytes(s.size) + " of logs" }), el("span", { class: "muted", text: s.updated ? "last hit " + ago(s.updated) : "no visits yet" })]),
    ]))));
  }
  async function siteSwitcher(view, sid) {
    const sites = (await API.metSites()).sites.filter((s) => s.exists || s.size);
    const sel = el("select", { class: "em-select mx-site-sel", onchange: () => navigate(view, { arg: sel.value }) }, sites.map((s) => el("option", { value: s.id, text: s.label })));
    sel.value = sid;
    return { sel, sites };
  }

  // ======================================================================
  //  Metrics → Visitors
  // ======================================================================
  const VCOLS = [
    { k: "ip", label: "IP" }, { k: "url", label: "URL" }, { k: "ts", label: "Time", num: true }, { k: "size", label: "Size", num: true },
    { k: "status", label: "Status", num: true }, { k: "method", label: "Method" }, { k: "proto", label: "Protocol" }, { k: "ref", label: "Referring URL" },
    { k: "client", label: "Client" }, { k: "ua", label: "User agent" }, { k: "vhost", label: "Host" },
  ];
  async function viewVisitors(root) {
    const sid = state.viewArg;
    if (!sid) return sitePicker(root, "visitors", "Visitors", "Every request to your websites, newest first, who visited, what they opened, how the server answered. Pick a site:");
    let sw0;
    try { sw0 = await siteSwitcher("visitors", sid); } catch (e) { root.append(el("p", { class: "empty", text: e.message })); return; }
    const cols = new Set(LS.get("vis.cols", ["ip", "url", "ts", "size", "status", "method", "ref", "client"]));
    let d = null, q = "", stat = "all", who = "all", ipF = "", per = LS.get("vis.per", 100), page = 0, sortK = "ts", dir = -1, limit = 1000, live = false, liveT = null, reportedIps = {};
    const head = pageHead("Visitors", "", [sw0.sel, btn("Analytics", () => navigate("analytics", { arg: sid }), "btn-ghost"), btn("Errors", () => navigate("errors", { arg: sid }), "btn-ghost")]);
    const sumBox = el("div", {}), facets = el("div", {}), tblBox = el("div", {}, el("div", { class: "loading", text: "Reading the log…" }));
    const search = el("input", { type: "search", class: "em-search", placeholder: "Search IP, URL, referrer, browser…", oninput: () => { q = search.value.toLowerCase(); page = 0; drawTable(); } });
    const count = el("span", { class: "muted mx-count" });
    const colMenu = el("div", { class: "mx-menu", hidden: "" }, VCOLS.map((c) => {
      const cb = el("input", { type: "checkbox", onchange: () => { cb.checked ? cols.add(c.k) : cols.delete(c.k); LS.set("vis.cols", [...cols]); drawTable(); } }); cb.checked = cols.has(c.k);
      return el("label", { class: "dm-check" }, [cb, el("span", { text: c.label })]);
    }));
    const colBtn = el("div", { class: "mx-menu-wrap" }, [el("button", { type: "button", class: "sa-icon-btn", title: "Columns", "aria-label": "Choose columns", onclick: () => { colMenu.hidden = !colMenu.hidden; } }, icon("gear", 16)), colMenu]);
    document.addEventListener("click", (e) => { if (!colBtn.contains(e.target)) colMenu.hidden = true; });
    const liveSw = sw(false, (v) => { live = v; clearInterval(liveT); if (v) liveT = setInterval(load, 10000); });
    state.cleanups.push(() => clearInterval(liveT));
    const limSel = el("select", { class: "em-select mx-narrow", onchange: () => { limit = +limSel.value; load(); } }, [[1000, "Latest 1,000"], [5000, "Latest 5,000"], [20000, "Latest 20,000"]].map(([v, l]) => el("option", { value: v, text: l })));
    const toolbar = el("div", { class: "mx-toolbar" }, [search, count, el("span", { class: "grow" }),
      seg([["all", "Everyone"], ["humans", "People"], ["bots", "Bots"]], who, (v) => { who = v; page = 0; drawTable(); }),
      seg([["all", "All"], ["2", "2xx"], ["3", "3xx"], ["4", "4xx"], ["5", "5xx"]], stat, (v) => { stat = v; page = 0; drawTable(); }),
      limSel,
      el("label", { class: "mx-live", title: "Refresh every 10 seconds" }, [liveSw, el("span", { text: "Live" })]),
      el("button", { type: "button", class: "sa-icon-btn", title: "Refresh", "aria-label": "Refresh", onclick: () => load() }, icon("refresh", 16)), colBtn]);
    const ipBar = el("div", {});
    const pager = el("div", { class: "mx-pager" });
    root.append(head, sumBox, facets, el("div", { class: "card em-pad0 mx-vis" }, [toolbar, ipBar, tblBox, pager]));
    async function load() {
      try { d = await API.metVisitors(sid, limit); } catch (e) { tblBox.innerHTML = ""; tblBox.append(el("p", { class: "empty", text: e.message })); return; }
      try { reportedIps = (await API.abuseReported()) || {}; } catch (e) { reportedIps = {}; }
      d.rows.forEach((r) => { r.client = r.bot ? `🤖 ${r.browser}` : `${r.browser} · ${r.os}${r.device !== "desktop" ? " · " + r.device : ""}`; });
      drawSummary(); drawTable();
    }
    function drawSummary() {
      sumBox.innerHTML = "";
      head.querySelector("p") || head.querySelector(".em-head-txt").append(el("p", { class: "muted" }));
      head.querySelector(".em-head-txt p").textContent = d.period ? `Latest visitors to “${d.site.label}” · ${t2s(d.period[0])} – ${t2s(d.period[1])}` : `No visits to “${d.site.label}” yet.`;
      sumBox.append(el("div", { class: "mx-tiles" }, [
        tile("Requests", num(d.total), d.period ? `over ${dur(d.period[1] - d.period[0])}` : "", "processes"),
        tile("Data sent", fmtBytes(d.bytes), "to visitors", "network"),
        tile("Unique IPs", num(d.unique_ips), `${num(d.total - d.bots)} requests by people`, "users"),
        tile("Bots & scanners", d.total ? `${Math.round((d.bots / d.total) * 100)}%` : "0%", `${num(d.bots)} requests`, "radar", "", () => { who = "bots"; drawTable(); }),
        tile("Errors (4xx/5xx)", num(d.errors), d.total ? `${((d.errors / d.total) * 100).toFixed(1)}% of requests` : "", "warning", d.errors ? "warnt" : "", () => { stat = "4"; drawTable(); }),
      ]));
      const own = new Set([...(d.own || []), location.hostname]);
      const refHost = (u) => { try { return new URL(u).hostname.replace(/^\[|\]$/g, ""); } catch (e) { return ""; } };
      const top = (key, f = (r) => true) => { const c = new Map(); d.rows.filter(f).forEach((r) => c.set(r[key], (c.get(r[key]) || 0) + 1)); return [...c.entries()].sort((a, b) => b[1] - a[1]); };
      facets.innerHTML = "";
      facets.append(el("div", { class: "mx-grid3" }, [
        card("Top visitors", [rank(top("ip").slice(0, 8).map(([ip, n]) => ({ label: ip, n, onclick: () => setIp(ip), extra: d.ip_status[ip] ? pill(d.ip_status[ip], d.ip_status[ip] === "trusted" ? "good" : "bad") : reportedIps[ip] ? pill("reported", "warn") : null, cls: ipCls(d.ip_status[ip], reportedIps[ip]) })))]),
        card("Top pages", [rank(top("url", (r) => !r.bot && r.page).slice(0, 8).map(([u, n]) => ({ label: u, n, onclick: () => { search.value = u; q = u.toLowerCase(); drawTable(); } })))]),
        card("Top referrers", [rank(top("ref", (r) => r.ref && !r.bot && !own.has(refHost(r.ref))).slice(0, 8).map(([u, n]) => ({ label: u.replace(/^https?:\/\//, ""), n })), { empty: "No links from other websites, visitors typed the address, used a bookmark or came from your own pages." })]),
      ]));
    }
    function setIp(ip) { ipF = ip; page = 0; drawTable(); }
    function filtered() {
      return d.rows.filter((r) => (who === "all" || (who === "bots") === r.bot) && (stat === "all" || String(r.status)[0] === stat) && (!ipF || r.ip === ipF) &&
        (!q || `${r.ip} ${r.url} ${r.ref} ${r.ua} ${r.client} ${r.status} ${r.vhost}`.toLowerCase().includes(q)));
    }
    function cell(c, r) {
      switch (c) {
        case "ip": return el("span", { class: "mx-ev-ipw" }, [el("button", { type: "button", class: `mx-ip ${ipCls(d.ip_status[r.ip], reportedIps[r.ip])}`, text: r.ip, title: "Show only this visitor", onclick: () => setIp(r.ip) }),
          d.ip_status[r.ip] ? el("span", { class: `mx-ipdot ${d.ip_status[r.ip]}`, title: d.ip_status[r.ip] === "banned" ? "Banned from the whole server" : "Trusted" }) : null,
          reportedIps[r.ip] ? el("span", { class: "mx-ipdot reported", title: `Reported to ${(reportedIps[r.ip].to || []).join(", ")} ${ago(reportedIps[r.ip].ts)}` }) : null]);
        case "url": return el("span", { class: "mx-url", title: r.url, text: r.url });
        case "ts": return el("span", { class: "mx-time", text: t2s(r.ts, { month: "numeric", day: "numeric", year: "2-digit", hour: "numeric", minute: "2-digit", second: "2-digit" }) });
        case "size": return document.createTextNode(fmtBytes(r.size));
        case "status": return el("span", { class: `mx-st ${statusKind(r.status)}`, text: r.status });
        case "ref": return !r.ref ? el("span", { class: "muted", text: ", " })
          : safeUrl(r.ref) ? el("a", { href: safeUrl(r.ref), target: "_blank", rel: "noopener noreferrer nofollow", referrerpolicy: "no-referrer", class: "mx-url", title: r.ref, text: r.ref.replace(/^https?:\/\//, "") })
          : el("span", { class: "mx-url mx-bad-url", title: r.ref, text: r.ref });
        case "ua": return el("span", { class: "mx-ua", title: r.ua, text: r.ua || ", " });
        case "client": return el("span", { class: r.bot ? "mx-bot" : "", text: r.client });
        default: return document.createTextNode(r[c] || "");
      }
    }
    function drawTable() {
      if (!d) return;
      const rows = filtered();
      const col = VCOLS.find((c) => c.k === sortK);
      rows.sort((a, b) => { const x = a[sortK], y = b[sortK]; return (x > y ? 1 : x < y ? -1 : 0) * dir; });
      count.textContent = `${num(rows.length)} record${rows.length === 1 ? "" : "s"} match`;
      ipBar.innerHTML = "";
      if (ipF) {
        const st = d.ip_status[ipF];
        const run = (fn, msg) => async () => { try { await fn(); toast(msg, "good"); load(); } catch (e) { toast(e.message, "bad"); } };
        const btns = [btn("Who is this?", () => ipCard(ipF, load), "btn-primary")];
        // Context-aware: show the reverse action when already banned/trusted. Ban/Trust ask once (click again).
        if (st === "banned") btns.push(btn("Unban", run(() => API.guardUnban(ipF), `${ipF} unbanned`), "btn-ghost"));
        else btns.push(armed("Ban", "Click again · 24 h", run(() => API.guardBan(ipF, `${rows.length} requests on ${d.site.label || "this site"}`, 86400, "Visitors"), `${ipF} banned for 24 hours`), "btn-danger"));
        if (st === "trusted") btns.push(btn("Untrust", run(() => API.guardUntrust(ipF), `${ipF} no longer trusted`), "btn-ghost"));
        else btns.push(armed("Trust", "Click again to trust", run(() => API.guardTrust(ipF, "Visitors"), `${ipF} trusted`), "btn-ghost"));
        const rep = reportedIps[ipF];
        btns.push(btn(rep ? "Report again" : "Report", () => reportIp(ipF, load), "btn-ghost"));
        btns.push(btn("Show everyone", () => setIp(""), "btn-ghost"));
        ipBar.append(el("div", { class: "mx-ipbar" }, [icon("users", 16), el("span", {}, ["Only ", el("b", { class: ipCls(st, rep), text: ipF }), ` · ${num(rows.length)} requests`]), st ? pill(st, st === "trusted" ? "good" : "bad") : null,
          rep ? el("span", { class: "pill warn", title: `Reported to ${(rep.to || []).join(", ")} on ${new Date(rep.ts * 1000).toLocaleString()}`, text: `reported ${ago(rep.ts)}` }) : null,
          el("span", { class: "grow" }), ...btns]));
      }
      const shown = VCOLS.filter((c) => cols.has(c.k));
      const pages = per ? Math.max(1, Math.ceil(rows.length / per)) : 1;
      page = Math.min(page, pages - 1);
      const slice = per ? rows.slice(page * per, page * per + per) : rows;
      tblBox.innerHTML = "";
      if (!rows.length) { tblBox.append(empty("search", "No matching requests", d.rows.length ? "Clear a filter to see more." : "Nobody has visited this site yet.")); }
      else tblBox.append(el("div", { class: "table-wrap mx-table-wrap" }, el("table", { class: "mx-table mx-vtable" }, [
        el("thead", {}, el("tr", {}, shown.map((c) => el("th", { class: `${c.num ? "num" : ""} ${c.k === sortK ? "sorted" : ""} c-${c.k}`, onclick: () => { if (sortK === c.k) dir = -dir; else { sortK = c.k; dir = c.num ? -1 : 1; } drawTable(); } },
          [c.label, c.k === sortK ? el("span", { class: "mx-sort", text: dir < 0 ? " ↓" : " ↑" }) : null])))),
        el("tbody", {}, slice.map((r) => el("tr", { class: r.bot ? "is-bot" : "" }, shown.map((c) => el("td", { class: `${c.num ? "num" : ""} c-${c.k}` }, cell(c.k, r)))))),
      ])));
      pager.innerHTML = "";
      const pb = (label, p, dis) => el("button", { type: "button", class: `mx-pg ${p === page ? "on" : ""}`, text: label, disabled: dis ? "" : null, onclick: () => { page = p; drawTable(); tblBox.scrollIntoView({ block: "nearest" }); } });
      const nums = [];
      for (let i = Math.max(0, page - 2); i < Math.min(pages, page + 3); i++) nums.push(pb(String(i + 1), i));
      pager.append(el("div", { class: "mx-pg-group" }, [pb("« First", 0, page === 0), pb("‹ Prev", page - 1, page === 0), ...nums, pb("Next ›", page + 1, page >= pages - 1), pb("Last »", pages - 1, page >= pages - 1)]),
        el("span", { class: "grow" }),
        seg([[25, "25"], [100, "100"], [250, "250"], [0, "All"]], per, (v) => { per = v; LS.set("vis.per", v); page = 0; drawTable(); }),
        btn("Export CSV", () => {
          const esc = (v) => { let s = String(v ?? ""); if (/^[=+\-@\t\r]/.test(s)) s = "'" + s; return `"${s.replace(/"/g, '""')}"`; };
          const keys = ["ts", "ip", "method", "url", "proto", "status", "size", "ref", "ua", "browser", "os", "device", "bot", "vhost"];
          downloadText(`${sid}-visitors.csv`, [keys.join(","), ...rows.map((r) => keys.map((k) => esc(k === "ts" ? new Date(r.ts * 1000).toISOString() : r[k])).join(","))].join("\n"), "text/csv");
        }, "btn-ghost"));
    }
    load();
  }

  // ======================================================================
  //  Metrics → Errors
  // ======================================================================
  const CAT_ICO = { missing: "search", permission: "lock", htaccess: "gear", php_fatal: "warning", php_warn: "brick", security: "shield", proxy: "plug",
    ssl: "lock", timeout: "clock", server: "server", mail: "mail", database: "database", dns: "dns", php_fpm: "brick", panel: "dashboard", system: "processes", other: "listing" };
  const SOURCES = [["web", "Web server"], ["mail", "Mail"], ["database", "Database"], ["dns", "DNS"], ["php_fpm", "PHP-FPM"], ["panel", "Panel"], ["system", "System"]];
  async function viewErrors(root) {
    // full = the whole period (drives the timeline); d = what the cards and list show, 
    // the same, or only the hour(s) of the bar that was clicked (win).
    let sid = state.viewArg || "", hours = 24, cat = "", lvl = "", q = "", mode = "grouped", d, full, win = null;
    const srcOn = new Set(LS.get("err.src", SOURCES.map((s) => s[0])));
    let sites = [];
    try { sites = (await API.metSites()).sites.filter((s) => s.kind === "site"); } catch (e) {}
    const siteSel = el("select", { class: "em-select mx-site-sel", onchange: () => { sid = siteSel.value; load(); } }, [el("option", { value: "", text: "All websites" }), ...sites.map((s) => el("option", { value: s.id, text: s.label }))]);
    siteSel.value = sid;
    root.append(pageHead("Errors", "Problems from the web server, PHP, mail, database, DNS and the system, sorted into categories, with repeats grouped and a hint for what to do about each.", [siteSel,
      btn("Download", () => {
        if (!d) return;
        downloadText(`errors-${new Date().toISOString().slice(0, 10)}.log`, filtered().map((e) => `${new Date(e.ts * 1000).toISOString()} [${e.source}/${e.mod || "-"}:${e.level}]${e.client ? " [client " + e.client + "]" : ""} ${e.msg}`).join("\n"));
      }, "btn-ghost")]));
    const catsBox = el("div", {}), timeline = el("div", {}), listBox = el("div", {}, el("div", { class: "loading", text: "Reading the logs…" }));
    const search = el("input", { type: "search", class: "em-search", placeholder: "Search messages, files, IPs…", oninput: () => { q = search.value.toLowerCase(); drawList(); } });
    const srcChips = el("div", { class: "mx-chips" });
    const drawSrc = () => { srcChips.innerHTML = ""; SOURCES.forEach(([k, l]) => srcChips.append(el("button", { type: "button", class: `em-chip ${srcOn.has(k) ? "on" : ""}`, text: l,
      onclick: () => { srcOn.has(k) ? srcOn.delete(k) : srcOn.add(k); LS.set("err.src", [...srcOn]); drawSrc(); load(); } }))); };
    drawSrc();
    const lvlSlot = el("span", { class: "mx-seg-slot" });
    const drawLvl = () => { lvlSlot.innerHTML = ""; lvlSlot.append(seg([["", "All levels"], ["error", "Errors"], ["warn", "Warnings"]], lvl, (v) => { lvl = v; drawList(); })); };
    drawLvl();
    root.append(el("div", { class: "mx-toolbar mx-toolbar-top" }, [srcChips, el("span", { class: "grow" }),
      seg([[1, "1 h"], [24, "24 h"], [168, "7 days"], [720, "30 days"]], hours, (v) => { hours = v; win = null; load(); })]), catsBox, timeline,
      el("div", { class: "card em-pad0" }, [el("div", { class: "mx-toolbar" }, [search, el("span", { class: "grow" }), lvlSlot,
        seg([["grouped", "Grouped"], ["lines", "Every line"]], mode, (v) => { mode = v; drawList(); })]), listBox]));
    const src = () => [...srcOn].join(",");
    async function load() {
      listBox.innerHTML = ""; listBox.append(el("div", { class: "loading", text: "Reading the logs…" }));
      try {
        full = await API.metErrors(sid, hours, src());
        d = win ? await API.metErrors(sid, hours, src(), win.start, win.end) : full;
      } catch (e) { listBox.innerHTML = ""; listBox.append(el("p", { class: "empty", text: e.message })); return; }
      if (cat && !d.counts[cat]) cat = "";
      drawCats(); drawTimeline(); drawList();
    }
    // A bar of the timeline was clicked: show only that hour (or day); clicking it again shows everything.
    async function pick(start, end) {
      win = !start || (win && win.start === start) ? null : { start, end };
      drawTimeline();
      listBox.innerHTML = ""; listBox.append(el("div", { class: "loading", text: "Reading the logs…" }));
      try { d = win ? await API.metErrors(sid, hours, src(), win.start, win.end) : full; } catch (e) { listBox.innerHTML = ""; listBox.append(el("p", { class: "empty", text: e.message })); return; }
      if (cat && !d.counts[cat]) cat = "";
      drawCats(); drawList();
    }
    function drawCats() {
      catsBox.innerHTML = "";
      if (win) {
        const f = (t) => new Date(t * 1000).toLocaleString([], { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" });
        const to = new Date(win.end * 1000).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
        catsBox.append(el("div", { class: "mx-ipbar" }, [icon("clock", 16),
          el("span", {}, ["Only ", el("b", { text: `${f(win.start)} – ${win.end - win.start > 86400 ? f(win.end) : to}` }), ` · ${num(d.total)} message${d.total === 1 ? "" : "s"}`]),
          el("span", { class: "grow" }),
          btn(`Show the whole ${hours === 1 ? "hour" : hours === 24 ? "24 hours" : hours === 168 ? "7 days" : "30 days"}`, () => pick(0), "btn-ghost")]));
      }
      const cats = Object.entries(d.counts).sort((a, b) => b[1] - a[1]);
      if (!cats.length) return;
      catsBox.append(el("div", { class: "mx-cats" }, [
        el("button", { type: "button", class: `mx-cat ${!cat ? "on" : ""}`, onclick: () => { cat = ""; drawCats(); drawList(); } }, [el("span", { class: "mx-cat-ico" }, icon("listing", 16)), el("span", { class: "mx-cat-l", text: "All categories" }), el("b", { text: num(d.total) })]),
        ...cats.map(([k, n]) => el("button", { type: "button", class: `mx-cat c-${k} ${cat === k ? "on" : ""}`, title: d.categories[k].hint, onclick: () => { cat = cat === k ? "" : k; drawCats(); drawList(); } },
          [el("span", { class: "mx-cat-ico" }, icon(CAT_ICO[k] || "listing", 16)), el("span", { class: "mx-cat-l", text: d.categories[k].label }), el("b", { text: num(n) })])),
      ]));
    }
    function drawTimeline() {
      timeline.innerHTML = "";
      if (!full.total) return;
      const step = 3600;
      const now = Math.floor(Date.now() / 1000 / step) * step, start = now - hours * 3600 + step;
      const map = new Map(full.hourly_cats || []);
      const pts = [];
      for (let t = start; t <= now; t += step) pts.push([t, map.get(t) || {}]);
      // Bars stacked by category (biggest first), so the chart says what went wrong, not only how much.
      const keys = Object.entries(full.counts).sort((a, b) => b[1] - a[1]).map(([k]) => k);
      const series = keys.map((k, i) => ({ key: k, label: full.categories[k].label, color: PALETTE[i % PALETTE.length] }));
      const agg = hours > 168 ? 24 : hours > 24 ? 6 : 1;
      const pts2 = [];
      for (let i = 0; i < pts.length; i += agg) {
        const sum = {};
        pts.slice(i, i + agg).forEach((p) => Object.entries(p[1]).forEach(([k, v]) => { sum[k] = (sum[k] || 0) + v; }));
        pts2.push([pts[i][0], sum]);
      }
      const sel = win ? pts2.findIndex((p) => p[0] === win.start) : -1;
      timeline.append(card("When they happened", [chart({ points: pts2, series, height: 110, tipNonZero: true, sel: sel >= 0 ? sel : null,
        pickHint: "Click to see only these", onPick: (i, p) => Object.keys(p[1]).length && pick(p[0], p[0] + agg * step),
        xfmt: (t) => new Date(t * 1000).toLocaleString([], hours > 24 ? { month: "short", day: "numeric" } : { hour: "2-digit", minute: "2-digit" }),
        tipX: (t) => {
          const f = (x, o) => new Date(x * 1000).toLocaleString([], o);
          return `${f(t, { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" })} – ${f(t + agg * step, agg >= 24 ? { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" } : { hour: "2-digit", minute: "2-digit" })}`;
        } })], "", [el("span", { class: "muted mx-small", text: "click a bar to see only those" })]));
    }
    const lvlOk = (l) => !lvl || (lvl === "error" ? /^(error|crit|alert|emerg)/.test(l) : /^warn/.test(l));
    // Everything picked is only hidden by the Errors/Warnings switch: say so, with the way out.
    function hiddenByLevel() {
      if (!lvl) return null;
      const n = d.items.filter((e) => (!cat || e.cat === cat) && (!q || `${e.msg} ${e.mod} ${e.client} ${e.code} ${e.file}`.toLowerCase().includes(q))).length;
      if (!n) return null;
      return el("div", { class: "mx-lvl-hidden" }, [
        el("p", { class: "muted", text: `No ${lvl === "error" ? "errors" : "warnings"} here, ${num(n)} message${n === 1 ? " is" : "s are"} ${lvl === "error" ? "warnings or notices" : "errors or notices"}.` }),
        btn("Show all levels", () => { lvl = ""; drawLvl(); drawList(); }, "btn-primary")]);
    }
    function filtered() {
      return d.items.filter((e) => (!cat || e.cat === cat) && lvlOk(e.level) && (!q || `${e.msg} ${e.mod} ${e.client} ${e.code} ${e.file}`.toLowerCase().includes(q)));
    }
    function drawList() {
      if (!d) return;
      listBox.innerHTML = "";
      if (cat) listBox.append(el("div", { class: "mx-hint" }, [icon(CAT_ICO[cat] || "listing", 18), el("div", {}, [el("b", { text: d.categories[cat].label }), el("p", { class: "muted", text: d.categories[cat].hint })]),
        cat === "security" ? btn("WAF Firewall", () => navigate("modsec"), "btn-ghost") : cat === "permission" ? btn("Fix permissions", () => navigate("fixperms"), "btn-ghost") : cat === "mail" ? btn("Email", () => navigate("email"), "btn-ghost") : null]));
      if (!d.total) { listBox.append(empty("check", "No errors in this period", "Nothing went wrong, or the selected sources are quiet.")); return; }
      if (mode === "grouped") {
        const gs = d.groups.filter((g) => (!cat || g.cat === cat) && lvlOk(g.level) && (!q || `${g.pattern} ${g.example.msg} ${g.mod} ${g.clients.map((c) => c[0]).join(" ")}`.toLowerCase().includes(q)));
        if (!gs.length) { listBox.append(hiddenByLevel() || empty("search", "Nothing matches", "Try another filter.")); return; }
        listBox.append(el("div", { class: "mx-errs" }, gs.slice(0, 300).map((g) => {
          const more = el("div", { class: "mx-err-more", hidden: "" }, [
            el("pre", { class: "mx-pre", text: g.example.msg }),
            g.example.referer ? el("div", { class: "mx-kv" }, [el("span", { text: "Referer" }), el("code", { text: g.example.referer })]) : null,
            g.clients.length ? el("div", { class: "mx-err-clients" }, [el("span", { class: "muted", text: "From: " }), ...g.clients.map(([ip, n]) => el("span", { class: "mx-client" }, [el("code", { text: ip }), el("span", { class: "muted", text: `×${n}` }),
              btn("Who? · Ban", () => ipCard(ip), "btn-ghost")]))]) : null,
            el("div", { class: "muted mx-small", text: `First ${t2s(g.first)} · last ${t2s(g.last)} · ${g.mod || g.example.source}${g.example.code ? " · " + g.example.code : ""} · ${g.example.file}` }),
          ]);
          return el("div", { class: `mx-err lv-${g.level.slice(0, 4)}` }, [
            el("button", { type: "button", class: "mx-err-main", onclick: () => { more.hidden = !more.hidden; } }, [
              el("span", { class: `mx-err-n ${g.count > 9 ? "hot" : ""}`, text: `×${num(g.count)}` }),
              el("div", { class: "mx-err-txt" }, [el("span", { class: "mx-err-cat", text: `${d.categories[g.cat].label}${g.mod ? " · " + g.mod : ""}` }), el("span", { class: "mx-err-msg", text: g.example.msg })]),
              pill(g.level, /^(error|crit|alert|emerg)/.test(g.level) ? "bad" : /^warn/.test(g.level) ? "warn" : "dim"),
              el("span", { class: "muted mx-ev-t", text: ago(g.last) }),
            ]), more]);
        })));
      } else {
        const rows = filtered();
        if (!rows.length) { listBox.append(hiddenByLevel() || empty("search", "Nothing matches", "Try another filter.")); return; }
        listBox.append(el("div", { class: "mx-lines" }, rows.slice(0, 1500).map((e) => el("div", { class: `mx-line lv-${e.level.slice(0, 4)}` }, [
          el("span", { class: "mx-line-t", text: t2s(e.ts, { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit", second: "2-digit" }) }),
          el("span", { class: "mx-line-src", text: `${e.mod || e.source}:${e.level}` }),
          el("span", { class: "mx-line-msg", text: `${e.client ? "[" + e.client + "] " : ""}${e.msg}` })]))));
        if (rows.length > 1500) listBox.append(el("p", { class: "muted mx-p", text: `Showing the newest 1,500 of ${num(rows.length)}, use Download for all of them.` }));
      }
    }
    load();
  }

  // ======================================================================
  //  Metrics → Bandwidth
  // ======================================================================
  const PROTO = [{ key: "http", label: "HTTP (websites)", color: "#ff7a1a" }, { key: "imap", label: "IMAP", color: "#6fb6ff" }, { key: "pop3", label: "POP3", color: "#b38cff" },
    { key: "smtp", label: "SMTP", color: "#3fd08f" }, { key: "ftp", label: "FTP", color: "#ffb347" }];
  const NET = [{ key: "net_rx", label: "Download (in)", color: "#6fb6ff" }, { key: "net_tx", label: "Upload (out)", color: "#ff7a1a" }];
  async function viewBandwidth(root) {
    let d, view = LS.get("bw.view", "services"), month = null;
    root.append(pageHead("Bandwidth", "How much data your websites, mail and FTP send and receive, and all traffic through the network card, over the last day, week, month and year. History is kept even after logs are rotated.",
      [seg([["services", "By service"], ["network", "All network traffic"]], view, (v) => { view = v; LS.set("bw.view", v); draw(); })]));
    const body = el("div", {}, el("div", { class: "loading", text: "Loading…" }));
    root.append(body);
    try { d = await API.metBandwidth(); } catch (e) { body.innerHTML = ""; body.append(el("p", { class: "empty", text: e.message })); return; }
    const months = Object.keys(d.month_totals).sort().reverse();
    month = months[0] || null;
    function draw() {
      body.innerHTML = "";
      const ser = view === "network" ? NET : PROTO;
      const sum = (pts, keys) => pts.reduce((a, p) => a + keys.reduce((b, s) => b + (p[1][s.key] || 0), 0), 0);
      const now = Date.now() / 1000;
      const day = fillSlots(d.series.day, Math.floor(now / 300) * 300 - 287 * 300, 300, 288);
      const week = fillSlots(d.series.week, Math.floor(now / 3600) * 3600 - 167 * 3600, 3600, 168);
      const today = new Date(); today.setHours(0, 0, 0, 0);
      const yStart = new Date(today); yStart.setDate(yStart.getDate() - 364);
      const ymap = new Map(d.series.year);
      const year = Array.from({ length: 365 }, (_, i) => { const dt = new Date(yStart); dt.setDate(dt.getDate() + i);
        const k = `${dt.getFullYear()}-${String(dt.getMonth() + 1).padStart(2, "0")}-${String(dt.getDate()).padStart(2, "0")}`; return [dt.getTime() / 1000, ymap.get(k) || {}]; });
      const thisM = months[0] ? d.month_totals[months[0]] : {}, lastM = months[1] ? d.month_totals[months[1]] : {};
      const mt = (m) => ser.reduce((a, s) => a + ((m || {})[s.key] || 0), 0);
      const peak = day.reduce((a, p) => Math.max(a, ser.reduce((b, s) => b + (p[1][s.key] || 0), 0)), 0);
      body.append(el("div", { class: "mx-tiles" }, [
        tile("Last 24 hours", fmtBytes(sum(day, ser)), view === "network" ? "in + out, every interface" : "websites, mail and FTP", "network", "accent"),
        tile("Last 7 days", fmtBytes(sum(week, ser)), "", "calendar"),
        tile("This month", fmtBytes(mt(thisM)), months[1] ? `last month: ${fmtBytes(mt(lastM))}` : "", "chart"),
        tile("Busiest 5 minutes", rate(peak / 300), "average rate in the peak slot today", "radar"),
      ]));
      const hm = { hour: "2-digit", minute: "2-digit" };
      body.append(
        card("Past 24 hours", [chart({ points: day.map(([ts, v]) => [ts, Object.fromEntries(Object.entries(v).map(([k, x]) => [k, x / 5]))]), series: ser, xfmt: (t) => new Date(t * 1000).toLocaleTimeString([], hm), tipX: (t) => `${new Date(t * 1000).toLocaleTimeString([], hm)} – ${new Date((t + 300) * 1000).toLocaleTimeString([], hm)}`, yfmt: (v) => `${fmtBytes(v)}/min`, ticks: 8, bytes: true })], "", [el("span", { class: "muted mx-small", text: "5-minute slots" })]),
        card("Past week", [chart({ points: week, series: ser, xfmt: (t) => new Date(t * 1000).toLocaleDateString([], { weekday: "short", day: "numeric" }), tipX: (t) => new Date(t * 1000).toLocaleString([], { weekday: "short", month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" }), yfmt: (v) => fmtBytes(v) + "/h", ticks: 7, bytes: true })], "", [el("span", { class: "muted mx-small", text: "hourly" })]),
        card("Past year", [chart({ points: year, series: ser, xfmt: (t) => new Date(t * 1000).toLocaleDateString([], { month: "short", year: "2-digit" }), tipX: (t) => new Date(t * 1000).toLocaleDateString([], { weekday: "short", month: "short", day: "numeric", year: "numeric" }), yfmt: (v) => fmtBytes(v) + "/day", ticks: 12, bytes: true })], "", [el("span", { class: "muted mx-small", text: "daily" })]),
      );
      if (view === "services" && months.length) {
        const msel = el("select", { class: "em-select mx-narrow", onchange: () => { month = msel.value; drawMonth(); } }, months.map((m) => el("option", { value: m, text: new Date(m + "-01T00:00:00").toLocaleDateString([], { month: "long", year: "numeric" }) })));
        msel.value = month;
        const mbox = el("div", {});
        body.append(card("By website and service", [mbox], "", [msel]));
        const drawMonth = () => {
          mbox.innerHTML = "";
          const items = [];
          // A site whose HTTPS side writes to Apache's shared log shows up twice, add them together.
          const by = new Map();
          Object.entries(d.months[month] || {}).forEach(([k, v]) => {
            const label = `HTTP · ${d.labels[k] || k}`, x = by.get(label) || { label, n: 0, hits: 0, visitors: 0 };
            x.n += v.bytes; x.hits += v.hits; x.visitors += v.visitors; by.set(label, x);
          });
          items.push(...by.values());
          const t = d.month_totals[month] || {};
          PROTO.slice(1).forEach((p) => { if (t[p.key]) items.push({ label: p.label, n: t[p.key] }); });
          items.sort((a, b) => b.n - a.n);
          if (!items.length) { mbox.append(el("p", { class: "muted", text: "No traffic recorded for this month." })); return; }
          mbox.append(el("div", { class: "mx-bw-month" }, [
            sortableTable([{ k: "label", label: "Website / service" }, { k: "hits", label: "Requests", num: true, render: (r) => r.hits != null ? num(r.hits) : ", " },
              { k: "visitors", label: "Visitors", num: true, render: (r) => r.visitors != null ? num(r.visitors) : ", " }, { k: "n", label: "Data", num: true, render: (r) => fmtBytes(r.n) }], items, { sort: "n" }),
            donut(items.slice(0, 9).concat(items.length > 9 ? [{ label: "Everything else", n: items.slice(9).reduce((a, x) => a + x.n, 0) }] : []), fmtBytes),
          ]));
        };
        drawMonth();
      }
      body.append(el("p", { class: "muted mx-small mx-p", text: `Times are in your browser's time zone. Updated ${d.updated ? ago(d.updated) : "just now"}; the collector reads new log lines every 5 minutes.` }));
    }
    draw();
  }

  // ======================================================================
  //  Metrics → Raw Access
  // ======================================================================
  async function viewRawAccess(root) {
    root.append(pageHead("Raw Access", "The web server's own log files, download them as they are (or gzipped), open them in Analytics, and choose how long the server keeps them."));
    const body = el("div", {}, el("div", { class: "loading", text: "Loading…" }));
    root.append(body);
    async function load() {
      let d;
      try { d = await API.metRaw(); } catch (e) { body.innerHTML = ""; body.append(el("p", { class: "empty", text: e.message })); return; }
      body.innerHTML = "";
      const r = d.retention;
      if (r.supported) {
        const sel = el("select", { class: "em-select mx-narrow" }, [7, 14, 30, 60, 90, 180, 365].map((n) => el("option", { value: n, text: n === 365 ? "1 year" : `${n} days` })));
        sel.value = String(r.days);
        if (sel.value !== String(r.days)) sel.append(el("option", { value: r.days, text: `${r.days} days (current)`, selected: "" }));
        body.append(card("Keep logs for", [
          el("div", { class: "mx-ret" }, [sel, btn("Save", () => call(() => API.metRetention(+sel.value), "Retention saved", load), "btn-primary"),
            el("span", { class: "muted", text: `Rotated every day${r.compress ? " and gzipped" : ""}. All web logs use ${fmtBytes(d.disk)} now.` })]),
          el("p", { class: "muted mx-small mx-p", text: "Bandwidth and the monthly Analytics history are stored separately and survive rotation; Visitors and Errors read the logs themselves, so they reach back as far as you keep them." }),
        ]));
      }
      d.sites.filter((s) => s.files.length).forEach((s) => {
        const rows = s.files.concat(s.error_files.map((f) => ({ ...f, err: true })));
        body.append(card(s.label, [
          s.names.length ? el("p", { class: "muted mx-small mx-p", text: s.names.join(" · ") }) : null,
          el("div", { class: "table-wrap" }, el("table", { class: "mx-table mx-files" }, [el("thead", {}, el("tr", {}, ["File", "Covers up to", "Size", ""].map((h, i) => el("th", { class: i === 2 ? "num" : "", text: h })))),
            el("tbody", {}, rows.map((f) => el("tr", {}, [
              el("td", {}, [icon(f.err ? "warning" : "listing", 14), " ", el("code", { text: f.name }), f.n === 0 ? pill(f.err ? "error log" : "current", f.err ? "warn" : "good") : f.err ? pill("error log", "warn") : null]),
              el("td", { text: t2s(f.mtime, { weekday: "short", month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" }) }),
              el("td", { class: "num", text: fmtBytes(f.size) }),
              el("td", { class: "mx-actions" }, [
                el("a", { class: "btn btn-sm btn-ghost", href: `/api/metrics/download?file=${encodeURIComponent(f.name)}`, download: f.name, text: "Download" }),
                f.gz ? null : el("a", { class: "btn btn-sm btn-ghost", href: `/api/metrics/download?file=${encodeURIComponent(f.name)}&gz=1`, download: f.name + ".gz", text: ".gz" }),
                f.err ? btn("View", () => navigate("errors", { arg: s.id }), "btn-ghost") : btn("Analyze", () => { state.anaFile = f.name; navigate("analytics", { arg: s.id }); }, "btn-primary"),
              ]),
            ])))])),
        ], "", [btn("Visitors", () => navigate("visitors", { arg: s.id }), "btn-ghost")]));
      });
    }
    load();
  }

  // ======================================================================
  //  Metrics → Analytics (AWStats-style, from the logs)
  // ======================================================================
  async function viewAnalytics(root) {
    const sid = state.viewArg;
    if (!sid) return sitePicker(root, "analytics", "Analytics", "Visitors, visits, pages, traffic sources, browsers and more, worked out from the web server's logs, no tracking script needed. Pick a site:");
    let days = LS.get("ana.days", 30), file = state.anaFile || "";
    state.anaFile = "";
    let sw0;
    try { sw0 = await siteSwitcher("analytics", sid); } catch (e) { root.append(el("p", { class: "empty", text: e.message })); return; }
    const sub = el("p", { class: "muted" });
    const periodSeg = seg([[7, "7 days"], [30, "30 days"], [90, "90 days"], [365, "Year"]], days, (v) => { days = v; file = ""; LS.set("ana.days", v); load(); });
    root.append(el("div", { class: "em-head" }, [el("div", { class: "em-head-txt" }, [el("h2", { text: "Analytics" }), sub]),
      el("div", { class: "em-head-act" }, [sw0.sel, periodSeg, btn("Visitors", () => navigate("visitors", { arg: sid }), "btn-ghost")])]));
    const body = el("div", {}, el("div", { class: "loading", text: "Crunching the logs…" }));
    root.append(body);
    async function load() {
      body.innerHTML = ""; body.append(el("div", { class: "loading", text: "Crunching the logs…" }));
      let a;
      try { a = await API.metAnalytics(sid, days, file); } catch (e) { body.innerHTML = ""; body.append(el("p", { class: "empty", text: e.message })); return; }
      draw(a);
    }
    function draw(a) {
      body.innerHTML = "";
      const s = a.summary;
      sub.textContent = file ? `From the log file ${file}` + (a.first ? ` · ${t2s(a.first)} – ${t2s(a.last)}` : "")
        : a.first ? `${a.site.label} · ${t2s(a.first, { month: "short", day: "numeric", year: "numeric" })} – ${t2s(a.last, { month: "short", day: "numeric", year: "numeric" })}` : `${a.site.label} · no visits in this period`;
      if (file) body.append(el("div", { class: "mx-ipbar" }, [icon("listing", 16), el("span", {}, ["Analyzing one file: ", el("code", { text: file })]), el("span", { class: "grow" }), btn("Back to the whole period", () => { file = ""; load(); }, "btn-ghost")]));
      body.append(el("div", { class: "mx-tiles mx-tiles-6" }, [
        tile("Unique visitors", num(s.visitors), "different IPs (people only)", "users", "accent"),
        tile("Visits", num(s.visits), s.visitors ? `${(s.visits / s.visitors).toFixed(1)} per visitor` : "", "login"),
        tile("Pages", num(s.pages), `${s.pages_per_visit} per visit`, "listing"),
        tile("Hits", num(s.hits), "every file: pages, images, CSS…", "processes"),
        tile("Bandwidth", fmtBytes(s.bytes), s.visits ? `${fmtBytes(s.bytes / s.visits)} per visit` : "", "network"),
        tile("Avg. visit", s.avg_duration ? dur(s.avg_duration) : ", ", "time between first and last page", "clock"),
      ]));
      body.append(el("div", { class: "mx-note mx-note-dim" }, [icon("radar", 16), el("span", { text: `Not counted above: ${num(s.bot_hits)} requests (${fmtBytes(s.bot_bytes)}) by bots, crawlers and scanners, see “Robots & tools” below.` })]));
      if (!s.hits && !s.bot_hits) { body.append(el("div", { class: "card" }, empty("chart", "No visits in this period", "Choose a longer period, or check back once people have visited the site."))); return; }
      const dayMetric = LS.get("ana.metric", "visitors");
      const dayBox = el("div", {});
      const metrics = [["visitors", "Visitors", "#ff7a1a"], ["visits", "Visits", "#ffb347"], ["pages", "Pages", "#6fb6ff"], ["hits", "Hits", "#4fd1c5"], ["bytes", "Bandwidth", "#3fd08f"]];
      // Every day of the period, so quiet days show as gaps instead of disappearing.
      const dmap = new Map(a.by_day.map((x) => [x.day, x]));
      const first = file && a.by_day.length ? new Date(a.by_day[0].day + "T00:00:00") : (() => { const x = new Date(); x.setHours(0, 0, 0, 0); x.setDate(x.getDate() - (days - 1)); return x; })();
      const nDays = file && a.by_day.length ? Math.round((new Date(a.by_day[a.by_day.length - 1].day + "T00:00:00") - first) / 864e5) + 1 : days;
      const dayPts = Array.from({ length: nDays }, (_, i) => { const dt = new Date(first); dt.setDate(dt.getDate() + i);
        const k = `${dt.getFullYear()}-${String(dt.getMonth() + 1).padStart(2, "0")}-${String(dt.getDate()).padStart(2, "0")}`; return [dt.getTime() / 1000, dmap.get(k) || {}]; });
      const drawDays = (m) => {
        dayBox.innerHTML = "";
        const mm = metrics.find((x) => x[0] === m);
        dayBox.append(chart({ points: dayPts.map(([ts, x]) => [ts, { [m]: x[m] || 0 }]), series: [{ key: m, label: mm[1], color: mm[2] }], legend: false,
          yfmt: m === "bytes" ? fmtBytes : (v) => num(Math.round(v)), xfmt: (t) => new Date(t * 1000).toLocaleDateString([], { month: "short", day: "numeric" }),
          tipX: (t) => new Date(t * 1000).toLocaleDateString([], { weekday: "short", month: "short", day: "numeric" }), type: dayPts.length > 120 ? "line" : "bars", ticks: 8 }));
      };
      body.append(card("Day by day", [dayBox], "", [seg(metrics.map((x) => [x[0], x[1]]), dayMetric, (v) => { LS.set("ana.metric", v); drawDays(v); })]));
      drawDays(dayMetric);
      if (a.history.length) {
        body.append(card("Monthly history", [sortableTable([{ k: "month", label: "Month", render: (r) => new Date(r.month + "-01T00:00:00").toLocaleDateString([], { month: "long", year: "numeric" }) },
          { k: "visitors", label: "Visitors / day*", num: true, render: (r) => num(r.visitors) }, { k: "pages", label: "Pages", num: true, render: (r) => num(r.pages) },
          { k: "hits", label: "Hits", num: true, render: (r) => num(r.hits) }, { k: "bytes", label: "Bandwidth", num: true, render: (r) => fmtBytes(r.bytes) }], a.history, { sort: "month", dir: -1 }),
          el("p", { class: "muted mx-small mx-p", text: "* sum of each day's unique visitors. Kept by the panel, so months stay after the logs are rotated." })]));
      }
      const hourPts = a.by_hour.map((h, i) => [i, { pages: h.pages, hits: h.hits - h.pages }]);
      const wd = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"];
      body.append(el("div", { class: "mx-grid2" }, [
        card("Hours of the day (server time)", [chart({ points: hourPts, series: [{ key: "pages", label: "Pages", color: "#6fb6ff" }, { key: "hits", label: "Other files", color: "rgba(111,182,255,.35)" }], height: 150, xfmt: (h) => `${h}:00`, tipX: (h) => `${h}:00 – ${h}:59`, ticks: 7 })]),
        card("Days of the week (server time)", [chart({ points: a.by_wday.map((h, i) => [i, { pages: h.pages, hits: h.hits - h.pages }]), series: [{ key: "pages", label: "Pages", color: "#ff7a1a" }, { key: "hits", label: "Other files", color: "rgba(255,122,26,.35)" }], height: 150, xfmt: (i) => wd[i], ticks: 7 })]),
      ]));
      body.append(el("div", { class: "mx-grid3" }, [
        card("Devices", [donut(a.devices.map((x) => ({ label: x.key[0].toUpperCase() + x.key.slice(1), n: x.n })))]),
        card("Browsers", [donut(a.browsers.slice(0, 7).map((x) => ({ label: x.key, n: x.n })))]),
        card("Operating systems", [donut(a.os.slice(0, 7).map((x) => ({ label: x.key, n: x.n })))]),
      ]));
      body.append(el("div", { class: "mx-grid2" }, [
        card("Most viewed pages", [rank(a.pages_top.map((p) => ({ label: p.url, n: p.hits })), { limit: 15 })]),
        card("Where visitors came from", [
          el("div", { class: "mx-sub" }, "Search engines"), rank(a.engines.map((x) => ({ label: x.key, n: x.n })), { empty: "No search engine visits yet." }),
          a.phrases.length ? el("div", { class: "mx-sub" }, "Search phrases") : null, a.phrases.length ? rank(a.phrases.map((x) => ({ label: x.key, n: x.n }))) : null,
          a.social.length ? el("div", { class: "mx-sub" }, "Social networks") : null, a.social.length ? rank(a.social.map((x) => ({ label: x.key, n: x.n }))) : null,
          el("div", { class: "mx-sub" }, "Other websites"), rank(a.referrers.map((x) => ({ label: x.key.replace(/^https?:\/\//, ""), n: x.n })), { empty: "No links from other sites yet." }),
        ]),
      ]));
      body.append(el("div", { class: "mx-grid3" }, [
        card("Entry pages", [rank(a.entry.map((p) => ({ label: p.url, n: p.n })))]),
        card("Exit pages", [rank(a.exit.map((p) => ({ label: p.url, n: p.n })))]),
        card("Visit duration", [rank(a.durations.filter((x) => x.visits).map((x) => ({ label: x.label, n: x.visits })), { limit: 7 })]),
      ]));
      body.append(card("Visitors (hosts)", [sortableTable([{ k: "ip", label: "IP address", render: (r) => el("button", { type: "button", class: "mx-ip", text: r.ip, title: "Who is this?", onclick: () => ipCard(r.ip) }) },
        { k: "pages", label: "Pages", num: true, render: (r) => num(r.pages) }, { k: "hits", label: "Hits", num: true, render: (r) => num(r.hits) },
        { k: "bytes", label: "Bandwidth", num: true, render: (r) => fmtBytes(r.bytes) }, { k: "last", label: "Last visit", num: true, render: (r) => ago(r.last) },
        { k: "_", label: "", render: (r) => btn("Who?", () => ipCard(r.ip), "btn-ghost") }], a.hosts, { sort: "pages", limit: 50 })]));
      body.append(el("div", { class: "mx-grid2" }, [
        card("Robots & tools", [sortableTable([{ k: "name", label: "Name" }, { k: "hits", label: "Hits", num: true, render: (r) => num(r.hits) },
          { k: "bytes", label: "Bandwidth", num: true, render: (r) => fmtBytes(r.bytes) }, { k: "last", label: "Last visit", num: true, render: (r) => ago(r.last) }], a.robots, { sort: "hits", limit: 30 })]),
        card("File types", [sortableTable([{ k: "ext", label: "Type", render: (r) => r.ext === "(page)" ? "Pages (no extension)" : "." + r.ext }, { k: "hits", label: "Hits", num: true, render: (r) => num(r.hits) },
          { k: "bytes", label: "Bandwidth", num: true, render: (r) => fmtBytes(r.bytes) }], a.filetypes, { sort: "hits" })]),
      ]));
      body.append(el("div", { class: "mx-grid2" }, [
        card("HTTP status codes", [rank(a.status.map((x) => ({ label: `${x.code} ${STATUS[x.code] || ""}`, n: x.n, extra: el("span", { class: `mx-st ${statusKind(x.code)}`, text: "" }) })), { limit: 12 })]),
        card("Not found (404)", [a.e404.length ? sortableTable([{ k: "url", label: "Missing URL", render: (r) => el("span", { class: "mx-url", title: r.url, text: r.url }) },
          { k: "n", label: "Hits", num: true }, { k: "ref", label: "Linked from", render: (r) => r.ref ? el("span", { class: "mx-url", title: r.ref, text: r.ref.replace(/^https?:\/\//, "") }) : el("span", { class: "muted", text: ", " }) }], a.e404, { sort: "n" })
          : el("p", { class: "muted mx-none", text: "No broken links, nice." })]),
      ]));
      if (a.users.length) body.append(card("Signed-in users (HTTP auth)", [rank(a.users.map((x) => ({ label: x.key, n: x.n })))]));
    }
    load();
  }
  const STATUS = { 200: "OK", 201: "Created", 204: "No content", 206: "Partial", 301: "Moved permanently", 302: "Found (redirect)", 304: "Not modified", 307: "Temporary redirect", 308: "Permanent redirect",
    400: "Bad request", 401: "Login required", 403: "Forbidden", 404: "Not found", 405: "Method not allowed", 408: "Timeout", 413: "Too large", 429: "Too many requests",
    444: "No response", 499: "Client closed", 500: "Server error", 502: "Bad gateway", 503: "Unavailable", 504: "Gateway timeout" };

  // ======================================================================
  //  Metrics → Resource Usage
  // ======================================================================
  async function viewResources(root) {
    let span = LS.get("res.span", "day");
    root.append(pageHead("Resource Usage", "CPU, memory, disk and network over time, sampled every minute by the panel, kept for a year, plus which software uses the most and any times the server ran out of memory or power.",
      [seg([["hour", "Hour"], ["day", "Day"], ["week", "Week"], ["month", "Month"], ["year", "Year"]], span, (v) => { span = v; LS.set("res.span", v); load(); })]));
    const body = el("div", {}, el("div", { class: "loading", text: "Loading…" }));
    root.append(body);
    async function load() {
      let d;
      try { d = await API.metResources(span); } catch (e) { body.innerHTML = ""; body.append(el("p", { class: "empty", text: e.message })); return; }
      body.innerHTML = "";
      const P = d.points, info = d.info || {};
      const last = P.length ? P[P.length - 1][1] : {};
      const xf = span === "hour" || span === "day" ? (t) => new Date(t * 1000).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })
        : span === "year" ? (t) => new Date(t * 1000).toLocaleDateString([], { month: "short" }) : (t) => new Date(t * 1000).toLocaleDateString([], { month: "short", day: "numeric" });
      const tx = (t) => new Date(t * 1000).toLocaleString([], { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" });
      const peak = (k) => P.reduce((a, p) => Math.max(a, p[1][k + "_max"] ?? p[1][k] ?? 0), 0);
      const oom = d.faults.filter((f) => f.kind === "oom").length, pwr = d.faults.filter((f) => f.kind === "power").length;
      body.append(el("div", { class: "mx-tiles" }, [
        tile("CPU now", last.cpu != null ? `${Math.round(last.cpu)}%` : ", ", `peak ${Math.round(peak("cpu"))}% · ${info.cpus || "?"} cores`, "processes", last.cpu > 85 ? "warnt" : ""),
        tile("Memory", last.mem != null ? `${fmtBytes(last.mem * 1048576)}` : ", ", info.mem_total ? `of ${fmtBytes(info.mem_total * 1048576)} · peak ${Math.round(peak("mem_pct"))}%` : "", "server", last.mem_pct > 90 ? "warnt" : ""),
        tile("Load", last.load != null ? String(last.load) : ", ", info.cpus ? `${info.cpus} = all cores busy` : "", "dashboard"),
        tile("Faults (31 days)", String(oom + pwr), oom || pwr ? `${oom} out-of-memory · ${pwr} power` : "No crashes or throttling", "warning", oom + pwr ? "warnt" : ""),
      ]));
      if (!P.length) { body.append(el("div", { class: "card" }, empty("chart", "Collecting…", "The first points appear within a minute; history grows from now on."))); return; }
      const want = { hour: 3600, day: 86400, week: 7 * 86400, month: 30 * 86400, year: 365 * 86400 }[span];
      if (P[0][0] > Date.now() / 1000 - want * 0.9) body.append(el("div", { class: "mx-note mx-note-dim" }, [icon("clock", 16),
        el("span", { text: `History starts ${t2s(P[0][0])}, the panel began recording then. The charts fill the whole ${span} as time goes on.` })]));
      const c = (title, series, yfmt, extra = {}) => card(title, [chart({ points: P, series, type: "line", stacked: false, height: 150, xfmt: xf, tipX: tx, yfmt, ticks: 5, ...extra })], "mx-res");
      const charts = [
        c("CPU", [{ key: "cpu", label: "Average", color: "#ff7a1a" }, { key: "cpu_max", label: "Peak", color: "rgba(255,122,26,.45)", fill: false }], (v) => `${Math.round(v)}%`, { max: 100 }),
        c("Physical memory", [{ key: "mem", label: "Used", color: "#6fb6ff" }], (v) => fmtBytes(v * 1048576), { lines: info.mem_total ? [{ value: info.mem_total, color: "var(--bad)" }] : [], max: info.mem_total ? niceMax(info.mem_total) : undefined }),
        c("Disk I/O", [{ key: "io_r", label: "Read", color: "#3fd08f" }, { key: "io_w", label: "Write", color: "#ffb347" }], (v) => rate(v)),
        c("IOPS", [{ key: "iops", label: "Operations/s", color: "#b38cff" }], (v) => `${Math.round(v)}/s`),
        c("Network", [{ key: "net_rx", label: "In", color: "#6fb6ff" }, { key: "net_tx", label: "Out", color: "#ff7a1a" }], (v) => rate(v)),
        c("Load average", [{ key: "load", label: "1-minute load", color: "#4fd1c5" }], (v) => v.toFixed(1), { lines: info.cpus ? [{ value: info.cpus, color: "var(--warn)" }] : [] }),
        c("Processes", [{ key: "procs", label: "Processes", color: "#c4a484" }], (v) => num(Math.round(v))),
        c("Swap", [{ key: "swap", label: "Used", color: "#ff6b9a" }], (v) => fmtBytes(v * 1048576), info.swap_total ? { lines: [{ value: info.swap_total }], max: niceMax(info.swap_total) } : {}),
      ];
      if (P.some((p) => p[1].temp != null)) charts.push(c("Temperature", [{ key: "temp", label: "CPU °C", color: "#ff6b6b" }], (v) => `${Math.round(v)}°C`, { lines: [{ value: 80, color: "var(--bad)" }] }));
      body.append(el("div", { class: "mx-res-grid" }, charts));
      body.append(el("div", { class: "mx-grid2" }, [
        card("What uses the memory now", [rank(d.apps.map((a) => ({ label: `${a.name}${a.n > 1 ? ` (${a.n})` : ""}`, n: a.rss })), { fmt: fmtBytes, limit: 12 }),
          el("div", { class: "toolbar" }, [btn("Processes", () => navigate("processes"), "btn-ghost"), btn("System Applications", () => navigate("sysapps"), "btn-ghost")])]),
        card("Faults", [d.faults.length ? el("div", { class: "mx-list" }, d.faults.slice(-30).reverse().map((f) => el("div", { class: "mx-list-row" }, [pill(f.kind === "oom" ? "out of memory" : "power", "bad"),
          el("span", { class: "mx-ell grow", title: f.msg, text: f.msg }), el("span", { class: "muted", text: ago(f.ts) })])))
          : el("p", { class: "muted mx-none", text: "No out-of-memory kills, under-voltage or throttling in the last 31 days." }),
          el("p", { class: "muted mx-small mx-p", text: "Out-of-memory: the kernel stopped a program because RAM and swap were full. Power: a Raspberry Pi's supply dropped too low or it slowed down because it was too hot." })]),
      ]));
    }
    load();
    const t = setInterval(() => { if (span === "hour") load(); }, 60000);
    state.cleanups.push(() => clearInterval(t));
  }

  return {
    modsec: viewWaf, ddnshosts: viewDdnsHosts, visitors: viewVisitors, errors: viewErrors, bandwidth: viewBandwidth,
    rawaccess: viewRawAccess, analytics: viewAnalytics, resources: viewResources,
    _ui: { el, pageHead, empty, call, armed, seg, tile, card, chart, rank, donut, sortableTable, ipCard, reportIp, t2s, num, dur, LS, niceMax },
  };
};
