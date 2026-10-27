/* AuroraPanel single-page app. */
(() => {
  "use strict";

  const $ = (sel, root = document) => root.querySelector(sel);
  // The interface was written for a Raspberry Pi; on any other machine "Pi" reads "server".
  let IS_PI = true;
  const host = (s) => (IS_PI || typeof s !== "string" ? s
    : s.replace(/(?<!Raspberry )\bPi's\b/g, "server's").replace(/(?<!Raspberry |\w\.)\bPi\b(?![-.]\w)/g, "server"));
  const el = (tag, attrs = {}, children = []) => {
    const node = document.createElement(tag);
    // raw: data shown exactly as it is (log lines, URLs, user agents), never reworded, never parsed as HTML.
    const h = attrs.raw ? (s) => s : host;
    for (const [k, v] of Object.entries(attrs)) {
      if (k === "raw") continue;
      if (k === "class") node.className = v;
      else if (k === "html") node.innerHTML = h(v);
      else if (k === "text") node.textContent = h(v);
      else if ((k === "placeholder" || k === "title") && typeof v === "string") node.setAttribute(k, h(v));
      else if (k.startsWith("on")) { if (typeof v === "function") node.addEventListener(k.slice(2), v); }  // never inline handlers
      else if (v !== null && v !== undefined) node.setAttribute(k, v);
    }
    for (const c of [].concat(children)) {
      if (c == null) continue;
      node.appendChild(typeof c === "string" ? document.createTextNode(h(c)) : c);
    }
    return node;
  };

  // -------- formatting helpers --------
  const fmtBytes = (n) => {
    if (n == null) return ", ";
    const u = ["B", "KB", "MB", "GB", "TB", "PB"];
    let i = 0, v = n;
    while (v >= 1024 && i < u.length - 1) { v /= 1024; i++; }
    return `${v.toFixed(v < 10 && i > 0 ? 1 : 0)} ${u[i]}`;
  };
  const fmtUptime = (s) => {
    const d = Math.floor(s / 86400), h = Math.floor((s % 86400) / 3600), m = Math.floor((s % 3600) / 60);
    return [d && `${d}d`, (d || h) && `${h}h`, `${m}m`].filter(Boolean).join(" ");
  };
  const meterClass = (p) => (p >= 90 ? "bad" : p >= 75 ? "warn" : "");
  const esc = (s) => String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

  let toastTimer = null;
  function toast(msg, kind = "good") {
    const t = $("#toast");
    t.textContent = host(msg);
    t.className = `toast ${kind}`;
    t.hidden = false;
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => { t.hidden = true; }, 3200);
  }

  window.addEventListener("aurora-updated", () => {
    if (document.querySelector(".update-banner")) return;
    document.body.append(el("div", { class: "update-banner", role: "status" }, [
      el("span", { text: "AuroraPanel was updated, reload to use the new version." }),
      el("button", { class: "btn btn-sm btn-primary", text: "Reload", onclick: () => location.reload() }),
    ]));
  });

  // ======================================================================
  //  SVG line icons (Lucide-style)
  // ======================================================================
  const ICONS = {
    t_wptool: '<circle cx="10" cy="10" r="7.5"/><path d="M4.6 7.2 7.5 15l2-5.2 2.1 5.2 2.8-7.8M6 7.2h3M11 7.2h3"/><path d="M19.7 14.6a2.6 2.6 0 0 0-3.5 3.3l-2.6 2.6 1.1 1.1 2.6-2.6a2.6 2.6 0 0 0 3.3-3.5l-1.5 1.5-1-1z"/>',
    t_migrate: '<rect x="2" y="4" width="8" height="16" rx="2"/><rect x="14" y="4" width="8" height="16" rx="2"/><path d="M10 12h4"/><polyline points="12 10 14 12 12 14"/><path d="M5 8h2M17 8h2"/>',
    t_servers: '<rect x="2.5" y="3" width="12" height="7" rx="1.8"/><rect x="9.5" y="14" width="12" height="7" rx="1.8"/><path d="M5.5 6.5h.01M12.5 17.5h.01M8.5 10v2.5h7V14"/>',
    t_docker: '<path d="M3 16l1.6 3.2A1.5 1.5 0 0 0 6 20h12a1.5 1.5 0 0 0 1.4-.8L21 16"/><path d="M4 16h16"/><rect x="7" y="11" width="3.5" height="3.5" rx=".6"/><rect x="10.5" y="11" width="3.5" height="3.5" rx=".6"/><rect x="14" y="11" width="3.5" height="3.5" rx=".6"/><rect x="8.75" y="7.5" width="3.5" height="3.5" rx=".6"/><rect x="12.25" y="7.5" width="3.5" height="3.5" rx=".6"/><path d="M2 21.5c1.7-1.2 3.3-1.2 5 0s3.3 1.2 5 0 3.3-1.2 5 0 3.3 1.2 5 0"/>',
    t_ship: '<path d="M3 16l1.6 3.2A1.5 1.5 0 0 0 6 20h12a1.5 1.5 0 0 0 1.4-.8L21 16"/><path d="M4 16h16"/><rect x="7" y="11" width="3.5" height="3.5" rx=".6"/><rect x="10.5" y="11" width="3.5" height="3.5" rx=".6"/><rect x="14" y="11" width="3.5" height="3.5" rx=".6"/><rect x="8.75" y="7.5" width="3.5" height="3.5" rx=".6"/><rect x="12.25" y="7.5" width="3.5" height="3.5" rx=".6"/><path d="M2 21.5c1.7-1.2 3.3-1.2 5 0s3.3 1.2 5 0 3.3-1.2 5 0 3.3 1.2 5 0"/>',
    play: '<polygon points="7 4 20 12 7 20 7 4"/>',
    pause: '<rect x="6" y="4" width="4" height="16" rx="1"/><rect x="14" y="4" width="4" height="16" rx="1"/>',
    square: '<rect x="5" y="5" width="14" height="14" rx="2"/>',
    trash: '<polyline points="3 6 5 6 21 6"/><path d="M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6"/><path d="M10 11v6M14 11v6"/><path d="M9 6V4h6v2"/>',
    t_isolate: '<rect x="3" y="3" width="8" height="8" rx="2"/><rect x="13" y="3" width="8" height="8" rx="2"/><rect x="3" y="13" width="8" height="8" rx="2"/><rect x="13.5" y="16" width="7" height="5" rx="1"/><path d="M15 16v-1.3a2 2 0 0 1 4 0V16"/>',
    t_activity: '<path d="M3 5h11M3 12h7M3 19h9"/><circle cx="17.5" cy="15.5" r="4.5"/><path d="M17.5 13.3v2.4l1.6 1"/>',
    t_bell: '<path d="M6 16V11a6 6 0 0 1 12 0v5l1.5 2h-15z"/><path d="M10 20.5a2 2 0 0 0 4 0"/><path d="M12 3v2"/>',
    t_cloudup: '<path d="M7 18.5a4.6 4.6 0 0 1-.7-9.1A6.2 6.2 0 0 1 18.2 8.3 4.1 4.1 0 0 1 18 16.5"/><path d="M12 20.5v-9"/><polyline points="9 14.5 12 11.5 15 14.5"/>',
    t_update: '<path d="M20.5 12a8.5 8.5 0 1 1-2.5-6"/><polyline points="21 3.5 21 8.5 16 8.5"/><path d="M12 8v5l3 2"/>',
    t_autossl: '<path d="M12 2.5 4 5.5v6c0 5 3.4 8.7 8 10 4.6-1.3 8-5 8-10v-6z"/><rect x="8.8" y="11" width="6.4" height="5" rx="1"/><path d="M10 11V9.8a2 2 0 0 1 4 0V11"/>',
    t_dbweb: '<ellipse cx="9" cy="5.5" rx="6" ry="2.5"/><path d="M3 5.5v10c0 1.4 2.7 2.5 6 2.5"/><path d="M15 5.5V10"/><path d="M3 10.5c0 1.4 2.7 2.5 6 2.5"/><path d="m14 13 7.5 2.8-3.2 1.2-1.2 3.3z"/>',
    t_dbnew: '<ellipse cx="10" cy="5.5" rx="6.5" ry="2.5"/><path d="M3.5 5.5v11c0 1.4 2.9 2.5 6.5 2.5"/><path d="M16.5 5.5v5"/><path d="M3.5 11c0 1.4 2.9 2.5 6.5 2.5"/><path d="M18.5 14v7M15 17.5h7"/>',
    t_table: '<rect x="3" y="4" width="18" height="16" rx="2.5"/><path d="M3 9.5h18M3 14.8h18M9.5 9.5V20"/>',
    t_tablenew: '<rect x="2.5" y="3.5" width="14" height="14" rx="2.2"/><path d="M2.5 8.5h14M2.5 13h14M7.5 8.5v9"/><path d="M19.5 15v7M16 18.5h7"/>',
    t_tableweb: '<rect x="2.5" y="3.5" width="16" height="13" rx="2.2"/><path d="M2.5 8.5h16M8 8.5v8"/><path d="m13.5 13 8 3-3.4 1.3-1.3 3.4z"/>',
    t_ddns: '<path d="M12 21.5s-6.5-5.6-6.5-11a6.5 6.5 0 0 1 13 0c0 5.4-6.5 11-6.5 11z"/><path d="M9.3 10.6a2.8 2.8 0 0 1 5-1.7"/><polyline points="14.6 6.9 14.6 9 12.5 9"/><path d="M14.7 11a2.8 2.8 0 0 1-5 1.7"/><polyline points="9.4 14.7 9.4 12.6 11.5 12.6"/>',
    t_mailuser: '<rect x="2" y="4.5" width="14.5" height="11" rx="2"/><path d="m2.5 6.5 6.75 5 6.75-5"/><circle cx="18.5" cy="15" r="2.6"/><path d="M14 21.5a4.5 4.5 0 0 1 9 0"/>',
    t_megaphone: '<path d="M3 10v4.5h3.2L13 19.5v-15L6.2 10z"/><path d="M17 9.2a4 4 0 0 1 0 6.1"/><path d="M19.6 6.6a7.6 7.6 0 0 1 0 11.3"/>',
    t_mailtrack: '<rect x="2" y="4" width="14.5" height="10.5" rx="2"/><path d="m2.5 6 6.75 4.8L16 6"/><circle cx="17.5" cy="17.5" r="3.2"/><path d="m22 22-2.2-2.2"/>',
    t_filterglobal: '<path d="M2 4h14l-5.5 6.4v5.3l-3 1.6v-6.9z"/><circle cx="18" cy="17" r="4.5"/><path d="M13.5 17h9M18 12.5a6.8 6.8 0 0 1 0 9"/>',
    t_contactin: '<rect x="2.5" y="3.5" width="13" height="17" rx="2.2"/><circle cx="9" cy="10" r="2.6"/><path d="M5.3 16.5a3.8 3.8 0 0 1 7.4 0"/><path d="M22 12h-5.5"/><polyline points="19 9 16 12 19 15"/>',
    t_mailspam: '<rect x="2.5" y="5" width="15" height="11.5" rx="2"/><path d="m3 7 7 5 7-5"/><circle cx="18" cy="17.5" r="4"/><path d="m15.2 20.3 5.6-5.6"/>',
    t_maillock: '<rect x="2" y="4.5" width="15" height="11" rx="2"/><path d="m2.5 6.5 7 5 7-5"/><rect x="14.5" y="15" width="7.5" height="6" rx="1.3"/><path d="M16.2 15v-1.4a2 2 0 0 1 4 0V15"/>',
    t_pie: '<path d="M20.5 13.5A8.6 8.6 0 1 1 10.5 3.6v9.9z"/><path d="M14 2.6a8.6 8.6 0 0 1 7.4 7.4H14z"/>',
    t_vpnglobe: '<circle cx="10" cy="10" r="7.5"/><path d="M2.5 10h15M10 2.5a11 11 0 0 1 0 15M10 2.5a11 11 0 0 0 0 15"/><rect x="14.5" y="15" width="7.5" height="6" rx="1.3"/><path d="M16.2 15v-1.4a2 2 0 0 1 4 0V15"/>',
    t_bolt: '<circle cx="12" cy="12" r="9.5"/><path d="M13.2 5.8 8.4 13.2h3.8l-1.4 5 4.8-7.4h-3.8z"/>',
    t_keyhole: '<circle cx="12" cy="12" r="9.5"/><circle cx="12" cy="9.8" r="2.6"/><path d="M10.9 12.2 9.9 17h4.2l-1-4.8"/>',
    t_laptoplock: '<rect x="4" y="4" width="16" height="11" rx="1.6"/><path d="M2 19h20"/><rect x="9.6" y="8.6" width="4.8" height="3.8" rx=".7"/><path d="M10.6 8.6v-.9a1.4 1.4 0 0 1 2.8 0v.9"/>',
    t_router: '<rect x="2" y="13" width="20" height="7.5" rx="2.2"/><path d="M6 16.8h.01M9.5 16.8h.01"/><path d="M15 16.8h3"/><path d="M14 9.5a4 4 0 0 1 6 0"/><path d="M11.5 6.8a7.6 7.6 0 0 1 11 0"/>',
    t_browserlock: '<rect x="2" y="3" width="20" height="18" rx="2.5"/><path d="M2 8h20M5.5 5.5h.01M8.5 5.5h.01"/><rect x="9" y="13" width="6" height="5" rx="1"/><path d="M10.3 13v-1.2a1.7 1.7 0 0 1 3.4 0V13"/>',
    t_cert: '<rect x="2.5" y="3" width="19" height="13" rx="2.2"/><path d="M6.5 7.5h11M6.5 11h6"/><circle cx="16.5" cy="15.5" r="3"/><path d="m15 18.2-1 3.8 2.5-1.3L19 22l-1-3.8"/>',
    t_apikey: '<path d="M8 4H6.5A2.5 2.5 0 0 0 4 6.5V10l-2 2 2 2v3.5A2.5 2.5 0 0 0 6.5 20H8"/><path d="M16 4h1.5A2.5 2.5 0 0 1 20 6.5V10l2 2-2 2v3.5a2.5 2.5 0 0 1-2.5 2.5H16"/><circle cx="12" cy="9.5" r="2.2"/><path d="M12 11.7V17M12 14.8h1.8"/>',
    t_linkoff: '<path d="M9 15l2-2M13 11l2-2"/><path d="M11 6.2l.6-.6a4.2 4.2 0 0 1 6 6l-.6.6"/><path d="M13 17.8l-.6.6a4.2 4.2 0 0 1-6-6l.6-.6"/><path d="M3 3l18 18"/>',
    t_waf: '<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="M4.4 9h15.2M4.9 13.4h14.2M9 5.5V9M15 5.5V9M12 9v4.4M8.6 13.4v4.2M15.4 13.4v4.2"/>',
    t_phonecheck: '<rect x="6" y="2" width="12" height="20" rx="2.6"/><path d="M10.5 18.5h3"/><path d="m9.2 10.2 2 2 3.8-3.9"/>',
    t_folderwrench: '<path d="M3 7a2 2 0 0 1 2-2h4l2 2h8a2 2 0 0 1 2 2v2.5"/><path d="M3 7v10a2 2 0 0 0 2 2h7"/><path d="M20 14.6a2.6 2.6 0 0 0-3.5 3.3l-2.8 2.8 1.2 1.2 2.8-2.8a2.6 2.6 0 0 0 3.3-3.5l-1.5 1.5-1-1z"/>',
    t_folderlock: '<path d="M3 7a2 2 0 0 1 2-2h4l2 2h8a2 2 0 0 1 2 2v2.5"/><path d="M3 7v10a2 2 0 0 0 2 2h8.5"/><rect x="14.5" y="15" width="7.5" height="6" rx="1.3"/><path d="M16.2 15v-1.4a2 2 0 0 1 4 0V15"/>',
    t_cloud: '<path d="M7 18.5a4.6 4.6 0 0 1-.7-9.1A6.2 6.2 0 0 1 18.2 8.3 4.1 4.1 0 0 1 18 16.5"/><path d="M12 11.5v9"/><polyline points="9 17.5 12 20.5 15 17.5"/>',
    t_transfer: '<path d="M7.5 3v15"/><polyline points="4 14.5 7.5 18 11 14.5"/><path d="M16.5 21V6"/><polyline points="13 9.5 16.5 6 20 9.5"/>',
    t_restore: '<path d="M3.5 12a8.5 8.5 0 1 0 2.6-6.1"/><polyline points="3 3.5 3 8.5 8 8.5"/><path d="M12 7.5V12l3.2 2"/>',
    t_grid: '<rect x="3" y="3" width="5" height="5" rx="1.2"/><rect x="9.5" y="3" width="5" height="5" rx="1.2"/><rect x="16" y="3" width="5" height="5" rx="1.2"/><rect x="3" y="9.5" width="5" height="5" rx="1.2"/><rect x="9.5" y="9.5" width="5" height="5" rx="1.2"/><rect x="3" y="16" width="5" height="5" rx="1.2"/>',
    t_cpu: '<rect x="6" y="6" width="12" height="12" rx="2.2"/><rect x="9.5" y="9.5" width="5" height="5" rx=".9"/><path d="M9 2.5V6M15 2.5V6M9 18v3.5M15 18v3.5M2.5 9H6M2.5 15H6M18 9h3.5M18 15h3.5"/>',
    t_firewall: '<rect x="3" y="12.5" width="18" height="8.5" rx="1.3"/><path d="M3 16.8h18M8 12.5v4.3M16 12.5v4.3M12 16.8V21"/><path d="M12 10c-2 0-3.2-1.4-3.2-3.1 0-2.2 2.1-3.1 2.1-5.4 1.7 1.1 4.3 3.1 4.3 5.7 0 1.6-1.2 2.8-3.2 2.8z"/>',
    t_rack: '<rect x="3" y="3" width="18" height="7.5" rx="2"/><rect x="3" y="13.5" width="18" height="7.5" rx="2"/><path d="M7 6.8h.01M7 17.3h.01M11 6.8h6M11 17.3h6"/>',
    t_layers: '<path d="m12 2.5 10 5-10 5-10-5z"/><path d="m2 12.3 10 5 10-5"/><path d="m2 17 10 5 10-5"/>',
    t_hex: '<path d="M12 2 21 7v10l-9 5-9-5V7z"/><path d="M12 7.2l4.4 2.5v4.9L12 17.1l-4.4-2.5V9.7z"/>',
    t_python: '<path d="M12 3H9.2a3 3 0 0 0-3 3v3H12"/><path d="M6.2 9H5a3 3 0 0 0-3 3v1a3 3 0 0 0 3 3h2"/><path d="M12 21h2.8a3 3 0 0 0 3-3v-3H12"/><path d="M17.8 15H19a3 3 0 0 0 3-3v-1a3 3 0 0 0-3-3h-2"/><path d="M7 16v-2a2 2 0 0 1 2-2h6a2 2 0 0 0 2-2V8"/><path d="M9.6 5.8h.01M14.4 18.2h.01"/>',
    t_gem: '<path d="M6 3.5h12l4 5.7-10 11.8L2 9.2z"/><path d="M2 9.2h20M12 21 8.2 9.2 12 3.5l3.8 5.7z"/>',
    t_code: '<ellipse cx="12" cy="12" rx="10" ry="7.2"/><path d="m8.3 9.6-2.4 2.4 2.4 2.4M15.7 9.6l2.4 2.4-2.4 2.4M13.1 8.8l-2.2 6.4"/>',
    t_password: '<rect x="2" y="6.5" width="20" height="11" rx="3"/><path d="M6.5 12h.01M10 12h.01M13.5 12h.01"/><path d="M17.5 9.5v5"/>',
    shadow: '<path d="M3.5 12a8.5 8.5 0 1 0 2.6-6.1"/><path d="M3.5 4.5v4h4"/><path d="M12 8v4.3l2.8 1.7"/><path d="M12 20.5a8.5 8.5 0 0 0 0-17" opacity=".35" stroke-dasharray="2 2.5"/>',
    t_account: '<circle cx="12" cy="12" r="9.5"/><circle cx="12" cy="10" r="3.2"/><path d="M6.3 18.6a6.6 6.6 0 0 1 11.4 0"/>',
    t_contact: '<rect x="2" y="4" width="20" height="16" rx="2.5"/><circle cx="8" cy="11" r="2.6"/><path d="M4.4 17a3.6 3.6 0 0 1 7.2 0"/><path d="M14.5 9h5M14.5 13h5"/>',
    t_lang: '<path d="M3 5h10M8 3v2M5.5 5c.6 3.2 2.7 6 6.5 8"/><path d="M10.6 5c-.6 3.2-2.8 6-7.1 8"/><path d="m12 21.5 4.5-10 4.5 10M13.5 18.2h6"/>',
    t_usergear: '<circle cx="9" cy="8" r="4"/><path d="M2 21a7 7 0 0 1 10.6-6"/><circle cx="18" cy="17" r="2.3"/><path d="M18 12.8v1.6M18 19.6v1.6M13.8 17h1.6M20.6 17h1.6M15 14l1.1 1.1M19.9 18.9 21 20M15 20l1.1-1.1M19.9 15.1 21 14"/>',
    metrics: '<path d="M3 21h18"/><rect x="4.5" y="15" width="3" height="6" rx="1"/><rect x="10.5" y="12" width="3" height="9" rx="1"/><rect x="16.5" y="13.5" width="3" height="7.5" rx="1"/><polyline points="4 10 9 6 13 8.5 20 3"/><polyline points="16 3 20 3 20 7"/>',
    chart: '<path d="M3 3v18h18"/><polyline points="7 15 11 10 14 13 20 6"/>',
    check: '<polyline points="20 6 9 17 4 12"/>',
    clock: '<circle cx="12" cy="12" r="9"/><polyline points="12 7 12 12 15 14"/>',
    login: '<path d="M15 3h4a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2h-4"/><polyline points="10 17 15 12 10 7"/><line x1="15" y1="12" x2="3" y2="12"/>',
    plus: '<line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/>',
    server: '<rect x="3" y="4" width="18" height="7" rx="2"/><rect x="3" y="13" width="18" height="7" rx="2"/><line x1="7" y1="7.5" x2="7.01" y2="7.5"/><line x1="7" y1="16.5" x2="7.01" y2="16.5"/>',
    warning: '<path d="M10.3 3.9 1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/>',
    visitors: '<circle cx="9" cy="8" r="4"/><path d="M2 21v-1a6 6 0 0 1 9.5-4.9"/><polyline points="14 20 17 16 19 18 22 13"/>',
    errors: '<polygon points="7.9 2 16.1 2 22 7.9 22 16.1 16.1 22 7.9 22 2 16.1 2 7.9"/><line x1="12" y1="7" x2="12" y2="13"/><line x1="12" y1="16.5" x2="12.01" y2="16.5"/>',
    gauge: '<path d="M4.9 19a9 9 0 1 1 14.2 0"/><line x1="12" y1="15" x2="16" y2="9"/><circle cx="12" cy="15" r="1.5"/>',
    rawlog: '<path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="8" y1="13" x2="16" y2="13"/><polyline points="9 17 12 20 15 17"/>',
    dashboard: '<rect x="3" y="3" width="7" height="7" rx="1.5"/><rect x="14" y="3" width="7" height="7" rx="1.5"/><rect x="14" y="14" width="7" height="7" rx="1.5"/><rect x="3" y="14" width="7" height="7" rx="1.5"/>',
    terminal: '<polyline points="4 17 10 11 4 5"/><line x1="12" y1="19" x2="20" y2="19"/>',
    services: '<line x1="4" y1="21" x2="4" y2="14"/><line x1="4" y1="10" x2="4" y2="3"/><line x1="12" y1="21" x2="12" y2="12"/><line x1="12" y1="8" x2="12" y2="3"/><line x1="20" y1="21" x2="20" y2="16"/><line x1="20" y1="12" x2="20" y2="3"/><line x1="1" y1="14" x2="7" y2="14"/><line x1="9" y1="8" x2="15" y2="8"/><line x1="17" y1="16" x2="23" y2="16"/>',
    processes: '<polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/>',
    packages: '<path d="M21 16V8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16z"/><polyline points="3.3 7 12 12 20.7 7"/><line x1="12" y1="22" x2="12" y2="12"/>',
    network: '<polyline points="17 1 21 5 17 9"/><path d="M3 11V9a4 4 0 0 1 4-4h14"/><polyline points="7 23 3 19 7 15"/><path d="M21 13v2a4 4 0 0 1-4 4H3"/>',
    firewall: '<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>',
    shield: '<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><polyline points="9 12 11 14 15 10"/>',
    users: '<path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M23 21v-2a4 4 0 0 0-3-3.87"/><path d="M16 3.13a4 4 0 0 1 0 7.75"/>',
    database: '<ellipse cx="12" cy="5" rx="9" ry="3"/><path d="M3 5v14c0 1.66 4 3 9 3s9-1.34 9-3V5"/><path d="M3 12c0 1.66 4 3 9 3s9-1.34 9-3"/>',
    wizard: '<line x1="4" y1="20" x2="15" y2="9"/><path d="M17 3l.9 2.1L20 6l-2.1.9L17 9l-.9-2.1L14 6l2.1-.9z"/><circle cx="19" cy="15" r="1"/><circle cx="6" cy="6" r="1"/>',
    globe: '<circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/><path d="M12 2a15 15 0 0 1 0 20 15 15 0 0 1 0-20z"/>',
    redirect: '<polyline points="15 14 20 9 15 4"/><path d="M4 20v-7a4 4 0 0 1 4-4h12"/>',
    zone: '<path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="8" y1="13" x2="16" y2="13"/><line x1="8" y1="17" x2="16" y2="17"/>',
    refresh: '<polyline points="23 4 23 10 17 10"/><polyline points="1 20 1 14 7 14"/><path d="M3.5 9a9 9 0 0 1 14.9-3.4L23 10M1 14l4.6 4.4A9 9 0 0 0 20.5 15"/>',
    key: '<circle cx="7.5" cy="15.5" r="4.5"/><path d="m10.7 12.3 8-8"/><path d="m16 6 2 2"/><path d="m18.5 3.5 2 2"/>',
    ban: '<circle cx="12" cy="12" r="10"/><line x1="4.9" y1="4.9" x2="19.1" y2="19.1"/>',
    lock: '<rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/>',
    token: '<path d="M3 8a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2 2 2 0 0 0 0 4 2 2 0 0 1-2 2H5a2 2 0 0 1-2-2 2 2 0 0 0 0-4z"/><line x1="13" y1="7" x2="13" y2="17" stroke-dasharray="2 2"/>',
    link: '<path d="M10 13a5 5 0 0 0 7 0l3-3a5 5 0 0 0-7-7l-1.5 1.5"/><path d="M14 11a5 5 0 0 0-7 0l-3 3a5 5 0 0 0 7 7l1.5-1.5"/>',
    trap: '<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><line x1="12" y1="8" x2="12" y2="12.5"/><line x1="12" y1="16" x2="12.01" y2="16"/>',
    brick: '<polygon points="12 2 2 7 12 12 22 7 12 2"/><polyline points="2 17 12 22 22 17"/><polyline points="2 12 12 17 22 12"/>',
    phone: '<rect x="7" y="2" width="10" height="20" rx="2.5"/><line x1="11" y1="18" x2="13" y2="18"/>',
    home: '<path d="M3 9.5 12 3l9 6.5V20a1 1 0 0 1-1 1h-5v-6H9v6H4a1 1 0 0 1-1-1z"/>',
    virus: '<rect x="8" y="6" width="8" height="14" rx="4"/><path d="M8 12H4m16 0h-4M8 16H5m14 0h-3M8.5 8.5 6 6m9.5 2.5L18 6"/><path d="M9.5 3v2m5-2v2"/>',
    folder: '<path d="M3 7a2 2 0 0 1 2-2h4l2 2h8a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/>',
    disk: '<line x1="22" y1="12" x2="2" y2="12"/><path d="M5.5 5h13a2 2 0 0 1 1.8 1.1l1.4 3A2 2 0 0 1 22 10v8a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2v-8a2 2 0 0 1 .3-1L3.7 6A2 2 0 0 1 5.5 5z"/><line x1="6" y1="16" x2="6.01" y2="16"/><line x1="10" y1="16" x2="10.01" y2="16"/>',
    backup: '<rect x="3" y="4" width="18" height="4" rx="1"/><path d="M5 8v11a1 1 0 0 0 1 1h12a1 1 0 0 0 1-1V8"/><line x1="10" y1="12" x2="14" y2="12"/>',
    cron: '<circle cx="12" cy="12" r="9"/><polyline points="12 7 12 12 15 14"/>',
    indexes: '<line x1="8" y1="6" x2="21" y2="6"/><line x1="8" y1="12" x2="21" y2="12"/><line x1="8" y1="18" x2="21" y2="18"/><line x1="3" y1="6" x2="3.01" y2="6"/><line x1="3" y1="12" x2="3.01" y2="12"/><line x1="3" y1="18" x2="3.01" y2="18"/>',
    error: '<path d="M10.3 3.9 1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/>',
    handler: '<line x1="6" y1="3" x2="6" y2="15"/><circle cx="18" cy="6" r="3"/><circle cx="6" cy="18" r="3"/><path d="M18 9a9 9 0 0 1-9 9"/>',
    mime: '<path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><polyline points="10 12 8 14 10 16"/><polyline points="14 12 16 14 14 16"/>',
    dns: '<circle cx="12" cy="12" r="2"/><path d="M4.9 4.9a10 10 0 0 0 0 14.2m14.2 0a10 10 0 0 0 0-14.2M7.8 7.8a6 6 0 0 0 0 8.4m8.4 0a6 6 0 0 0 0-8.4"/>',
    search: '<circle cx="11" cy="11" r="7"/><line x1="21" y1="21" x2="16.65" y2="16.65"/>',
    sun: '<circle cx="12" cy="12" r="4"/><path d="M12 2v2m0 16v2M2 12h2m16 0h2M5 5l1.5 1.5M17.5 17.5 19 19M19 5l-1.5 1.5M6.5 17.5 5 19"/>',
    moon: '<path d="M21 12.8A9 9 0 1 1 11.2 3a7 7 0 0 0 9.8 9.8z"/>',
    menu: '<line x1="3" y1="6" x2="21" y2="6"/><line x1="3" y1="12" x2="21" y2="12"/><line x1="3" y1="18" x2="21" y2="18"/>',
    chevron: '<polyline points="9 6 15 12 9 18"/>',
    dot: '<circle cx="12" cy="12" r="3"/>',
    flame: '<path d="M12 22a7 7 0 0 0 7-7c0-4-3-6-4-9-1 2-2 3-3.5 3.5C11 7 11 4 9 2 8 6 5 9 5 15a7 7 0 0 0 7 7z"/>',
    gear: '<circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.7 1.7 0 0 0 .3 1.8l.1.1a2 2 0 1 1-2.8 2.8l-.1-.1a1.7 1.7 0 0 0-1.8-.3 1.7 1.7 0 0 0-1 1.5V21a2 2 0 1 1-4 0v-.1a1.7 1.7 0 0 0-1.1-1.5 1.7 1.7 0 0 0-1.8.3l-.1.1a2 2 0 1 1-2.8-2.8l.1-.1a1.7 1.7 0 0 0 .3-1.8 1.7 1.7 0 0 0-1.5-1H3a2 2 0 1 1 0-4h.1a1.7 1.7 0 0 0 1.5-1.1 1.7 1.7 0 0 0-.3-1.8l-.1-.1a2 2 0 1 1 2.8-2.8l.1.1a1.7 1.7 0 0 0 1.8.3H9a1.7 1.7 0 0 0 1-1.5V3a2 2 0 1 1 4 0v.1a1.7 1.7 0 0 0 1 1.5 1.7 1.7 0 0 0 1.8-.3l.1-.1a2 2 0 1 1 2.8 2.8l-.1.1a1.7 1.7 0 0 0-.3 1.8V9a1.7 1.7 0 0 0 1.5 1H21a2 2 0 1 1 0 4h-.1a1.7 1.7 0 0 0-1.5 1z"/>',
    bell: '<path d="M18 8a6 6 0 0 0-12 0c0 7-3 9-3 9h18s-3-2-3-9"/><path d="M13.7 21a2 2 0 0 1-3.4 0"/>',
    calendar: '<rect x="3" y="4" width="18" height="18" rx="2"/><line x1="16" y1="2" x2="16" y2="6"/><line x1="8" y1="2" x2="8" y2="6"/><line x1="3" y1="10" x2="21" y2="10"/>',
    logout: '<path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/><polyline points="16 17 21 12 16 7"/><line x1="21" y1="12" x2="9" y2="12"/>',
    apps: '<rect x="3" y="3" width="7" height="7" rx="2"/><rect x="14" y="3" width="7" height="7" rx="2"/><rect x="3" y="14" width="7" height="7" rx="2"/><path d="M17.5 14v7M14 17.5h7"/>',
    wordpress: '<circle cx="12" cy="12" r="10"/><path d="M3.5 8.5 8 20l3-8.5M9 8.5h6M12.5 8.5 16 20l3.5-11.5M7 8.5h3.5M14 8.5h3.5"/>',
    wifi: '<path d="M5 12.5a10 10 0 0 1 14 0M8.5 16a5 5 0 0 1 7 0M2 9a15 15 0 0 1 20 0"/><circle cx="12" cy="19.5" r="1"/>',
    grid: '<rect x="3" y="3" width="7" height="7" rx="1.5"/><rect x="14" y="3" width="7" height="7" rx="1.5"/><rect x="14" y="14" width="7" height="7" rx="1.5"/><rect x="3" y="14" width="7" height="7" rx="1.5"/>',
    vpn: '<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><rect x="9" y="10.5" width="6" height="5" rx="1"/><path d="M10.5 10.5V9a1.5 1.5 0 0 1 3 0v1.5"/>',
    plug: '<path d="M9 2v6M15 2v6"/><path d="M6 8h12v3a6 6 0 0 1-12 0z"/><path d="M12 17v5"/>',
    radar: '<circle cx="12" cy="12" r="9"/><circle cx="12" cy="12" r="5"/><path d="M12 12 18.5 5.5"/><circle cx="12" cy="12" r="1"/>',
    tunnel: '<path d="M3 20V11a9 9 0 0 1 18 0v9"/><path d="M8 20v-7a4 4 0 0 1 8 0v7"/><line x1="2" y1="20" x2="22" y2="20"/>',
    image: '<rect x="3" y="3" width="18" height="18" rx="2"/><circle cx="8.5" cy="8.5" r="1.5"/><polyline points="21 15 16 10 5 21"/>',
    info: '<circle cx="12" cy="12" r="10"/><line x1="12" y1="16" x2="12" y2="11"/><line x1="12" y1="8" x2="12.01" y2="8"/>',
    eye: '<path d="M2 12s3.6-7 10-7 10 7 10 7-3.6 7-10 7S2 12 2 12z"/><circle cx="12" cy="12" r="3"/>',
    eyeOff: '<path d="M10.6 5.1A9.8 9.8 0 0 1 12 5c6.4 0 10 7 10 7a17 17 0 0 1-2.6 3.5M6.6 6.6A17 17 0 0 0 2 12s3.6 7 10 7a9.7 9.7 0 0 0 5.4-1.6"/><path d="M9.9 9.9a3 3 0 0 0 4.2 4.2"/><line x1="3" y1="3" x2="21" y2="21"/>',
    wand: '<path d="m15 4 1-2 1 2 2 1-2 1-1 2-1-2-2-1z"/><path d="m18 12 .7-1.3L20 10l-1.3-.7L18 8l-.7 1.3L16 10l1.3.7z"/><line x1="3" y1="21" x2="14" y2="10"/>',
    mail: '<rect x="3" y="5" width="18" height="14" rx="2"/><path d="m3 7 9 6 9-6"/>',
    forward: '<polyline points="15 17 20 12 15 7"/><path d="M4 18v-2a4 4 0 0 1 4-4h12"/>',
    route: '<circle cx="6" cy="19" r="2"/><circle cx="18" cy="5" r="2"/><path d="M8 19h7a3.5 3.5 0 0 0 0-7H9a3.5 3.5 0 0 1 0-7h7"/>',
    reply: '<polyline points="9 17 4 12 9 7"/><path d="M20 18v-2a4 4 0 0 0-4-4H4"/>',
    at: '<circle cx="12" cy="12" r="4"/><path d="M16 8v5a3 3 0 0 0 6 0v-1a10 10 0 1 0-4 8"/>',
    listing: '<line x1="8" y1="6" x2="21" y2="6"/><line x1="8" y1="12" x2="21" y2="12"/><line x1="8" y1="18" x2="21" y2="18"/><circle cx="3.5" cy="6" r="1"/><circle cx="3.5" cy="12" r="1"/><circle cx="3.5" cy="18" r="1"/>',
    pin: '<path d="M12 21s-7-6.1-7-11.5A7 7 0 0 1 19 9.5C19 14.9 12 21 12 21z"/><circle cx="12" cy="9.5" r="2.5"/>',
    filter: '<polygon points="22 3 2 3 10 12.5 10 19 14 21 14 12.5 22 3"/>',
    inbox: '<polyline points="22 12 16 12 14 15 10 15 8 12 2 12"/><path d="M5.5 5h13l3.5 7v6a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2v-6z"/>',
    upload: '<path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="17 8 12 3 7 8"/><line x1="12" y1="3" x2="12" y2="15"/>',
    send: '<line x1="22" y1="2" x2="11" y2="13"/><polygon points="22 2 15 22 11 13 2 9 22 2"/>',
    spam: '<path d="M12 2 4 5v6c0 5 3.4 9.4 8 11 4.6-1.6 8-6 8-11V5z"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/>',
    queue: '<rect x="3" y="4" width="18" height="4" rx="1"/><rect x="3" y="10" width="18" height="4" rx="1"/><rect x="3" y="16" width="18" height="4" rx="1"/>',
    contacts: '<rect x="3" y="3" width="18" height="18" rx="2"/><circle cx="12" cy="10" r="3"/><path d="M6.5 19a5.5 5.5 0 0 1 11 0"/>',
    git: '<circle cx="6" cy="6" r="2.5"/><circle cx="6" cy="18" r="2.5"/><circle cx="18" cy="8" r="2.5"/><line x1="6" y1="8.5" x2="6" y2="15.5"/><path d="M18 10.5c0 4-6 3-11 6"/>',
  };
  // Polar-bear brand logo (filled, drawn on the aurora chip).
  function brandLogo() {
    document.querySelectorAll(".brand-mark").forEach((m) => { m.innerHTML = '<img src="/img/logo-mark-128.png" alt="AuroraPanel" width="128" height="128" draggable="false">'; });
  }
  function icon(name, size) {
    const span = document.createElement("span");
    span.className = "ic";
    span.innerHTML = `<svg width="${size || 18}" height="${size || 18}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">${ICONS[name] || ICONS.dot}</svg>`;
    return span;
  }
  // view/nav -> icon name
  const VIEW_ICONS = {
    dashboard: "dashboard", terminal: "terminal", services: "services", processes: "processes",
    packages: "packages", network: "network", firewall: "firewall", users: "users",
    mysql: "database", mysqlwiz: "wizard", pgsql: "database", pgwiz: "wizard",
    vhosts: "globe", redirects: "redirect", revproxy: "redirect", zones: "zone", dyndns: "refresh", ddnshosts: "refresh",
    activity: "t_activity", isolation: "t_isolate", dockerapps: "t_docker", servers: "t_servers", mysites: "globe", panelusers: "t_usergear", wptoolkit: "t_wptool", migrate: "t_migrate", alerts: "t_bell", schedbackups: "t_cloudup", updates: "t_update", autossl: "t_autossl",
    visitors: "visitors", errors: "errors", bandwidth: "gauge", rawaccess: "rawlog", analytics: "chart", resources: "dashboard",
    ssh: "key", ipblocker: "ban", ssl: "lock", panelhttps: "lock", tokens: "token", hotlink: "link", secreport: "listing",
    leech: "trap", modsec: "shield", security: "phone", fixperms: "home", virus: "virus", globalsec: "shield",
    files: "folder", shadow: "shadow", disk: "disk", backups: "backup", cron: "cron", indexes: "indexes",
    errorpages: "error", handlers: "handler", mime: "mime", dns: "dns",
    appmgr: "packages", sysapps: "services", phpver: "brick", password: "lock", accountprefs: "services",
    contact: "phone", language: "globe", wordpress: "wordpress", appstore: "apps", app: "apps",
    vpn: "vpn", wireguard: "tunnel", openvpn: "key", ipsec: "shield", portcheck: "plug", netmon: "radar",
    images: "image", dirprivacy: "lock", webdisk: "disk", ftpaccounts: "folder", backupwiz: "wizard", git: "git", inodes: "indexes",
    about: "info",
  };
  function decorateNav() {
    document.querySelectorAll("#nav .nav-item").forEach((btn) => {
      const ic = btn.querySelector(".nav-ico");
      const name = VIEW_ICONS[btn.dataset.view];
      if (ic && name) { ic.textContent = ""; ic.appendChild(icon(name, 16)); }
    });
    document.querySelectorAll("[data-ic]").forEach((sp) => {
      if (!sp.querySelector("svg")) { sp.textContent = ""; sp.appendChild(icon(sp.dataset.ic, 18)); }
    });
  }
  function closeDrawer() { document.body.classList.remove("nav-open"); const o = $("#nav-overlay"); if (o) o.hidden = true; }
  function setupNav() {
    const toggle = $("#nav-toggle"), overlay = $("#nav-overlay");
    if (toggle) toggle.addEventListener("click", () => { document.body.classList.add("nav-open"); if (overlay) overlay.hidden = false; });
    if (overlay) overlay.addEventListener("click", closeDrawer);
    // Collapsible sidebar categories (persisted).
    let collapsed = [];
    try { collapsed = JSON.parse(localStorage.getItem("aurora-nav-collapsed") || "[]"); } catch (e) {}
    document.querySelectorAll("#nav .nav-group").forEach((g) => {
      const name = g.dataset.group || g.textContent.trim();
      g.dataset.group = name;
      if (!g.querySelector(".nav-group-chev")) {
        g.classList.add("nav-group-btn");
        const chev = document.createElement("span"); chev.className = "nav-group-chev"; chev.appendChild(icon("chevron", 12));
        g.appendChild(chev);
      }
      const apply = (isC) => {
        g.classList.toggle("collapsed", isC);
        let s = g.nextElementSibling;
        while (s && !s.classList.contains("nav-group")) { s.hidden = isC; s = s.nextElementSibling; }
      };
      apply(collapsed.includes(name));
      g.addEventListener("click", () => {
        const nowC = !g.classList.contains("collapsed");
        apply(nowC);
        collapsed = collapsed.filter((n) => n !== name); if (nowC) collapsed.push(name);
        try { localStorage.setItem("aurora-nav-collapsed", JSON.stringify(collapsed)); } catch (e) {}
      });
    });
  }

  // ======================================================================
  //  Shell chrome: icon rail (sections) + pill tabs (tools in a section)
  // ======================================================================
  const GROUP_ICONS = {
    System: "processes", Network: "network", Applications: "apps", Databases: "database", Domains: "globe", Email: "mail", Security: "shield",
    Metrics: "metrics", Files: "folder", Advanced: "terminal", Software: "packages", Preferences: "gear",
  };
  let NAV_GROUPS = [];
  function applyRole() {
    document.body.dataset.role = state.role;
    const lbl = $("#user-label");
    if (lbl && state.role !== "admin" && !document.getElementById("role-pill")) {
      lbl.after(el("span", { id: "role-pill", class: `pill ${state.role === "viewer" ? "warn" : "dim"}`, text: state.role === "viewer" ? "read-only" : "website manager" }));
    }
    if (state.role !== "site") return;
    const nav = $("#nav");
    nav.querySelectorAll(".nav-item").forEach((n) => { if (!SITE_VIEWS.has(n.dataset.view)) n.remove(); });
    [...nav.querySelectorAll(".nav-group")].forEach((g) => { let n = g.nextElementSibling; if (!n || n.classList.contains("nav-group")) g.remove(); });
    nav.prepend(el("div", { class: "nav-group", text: "My Websites" }), el("button", { class: "nav-item", "data-view": "mysites" }, [el("span", { class: "nav-ico", text: "🌐" }), " My Websites"]));
  }
  function buildNavGroups() {
    NAV_GROUPS = [];
    let cur = null;
    document.querySelectorAll("#nav > *").forEach((n) => {
      if (n.classList.contains("nav-group")) { cur = { name: n.dataset.group || n.textContent.trim(), items: [] }; NAV_GROUPS.push(cur); }
      else if (cur && n.dataset.view && n.dataset.view !== "dashboard") {
        const label = [...n.childNodes].filter((x) => !(x.classList && x.classList.contains("nav-ico"))).map((x) => x.textContent).join("").trim();
        cur.items.push({ view: n.dataset.view, label });
      }
    });
  }
  // An app's page (#/app/<id>) belongs to the App Installer's section.
  const navView = (view) => (view === "app" ? (state.viewArg === "wordpress" ? "wordpress" : "appstore") : view);
  function groupOf(view) {
    if (view === "dashboard") return null;
    view = navView(view);
    if (state.group) { const g = NAV_GROUPS.find((x) => x.name === state.group); if (g && g.items.some((i) => i.view === view)) return g; }
    return NAV_GROUPS.find((g) => g.items.some((i) => i.view === view)) || null;
  }
  function buildRail() {
    const box = $("#rail-groups");
    box.innerHTML = "";
    $("#rail-brand").onclick = () => navigate("dashboard");
    box.append(el("button", { class: "rail-btn", "data-rail": "Home", title: "Home", onclick: () => navigate("dashboard") }, icon("home", 19)));
    NAV_GROUPS.filter((g) => g.name !== "Preferences").forEach((g) => {
      box.append(el("button", { class: "rail-btn", "data-rail": g.name, title: g.name, onclick: () => { state.group = g.name; navigate(g.items[0].view); } }, icon(GROUP_ICONS[g.name] || "dot", 19)));
    });
    const pref = NAV_GROUPS.find((g) => g.name === "Preferences");
    const sb = $("#rail-settings");
    if (sb && pref) { sb.textContent = ""; sb.appendChild(icon("gear", 19)); sb.onclick = () => { state.group = pref.name; navigate(pref.items[0].view); }; }
    dockRail();
  }

  // macOS Dock-style magnification: the icon under the pointer grows, its neighbours a little
  // less, and a name label floats beside it. Distances are measured against where the icons sat
  // before growing, so the effect doesn't chase its own movement. Desktop pointers only.
  function dockRail() {
    const rail = $(".rail");
    if (!rail || rail.dataset.dock) return;
    rail.dataset.dock = "1";
    const MAX = 0.5, RANGE = 120;  // +50% at the pointer, fading out over 120px
    const label = el("div", { class: "rail-label", hidden: "" });
    document.body.append(label);
    let base = null, frame = 0;
    const off = () => !window.matchMedia("(hover: hover) and (min-width: 761px)").matches || window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    const btns = () => [...rail.querySelectorAll(".rail-btn")];
    const reset = () => {
      base = null; label.hidden = true; rail.classList.remove("docking");
      btns().forEach((b) => { b.style.removeProperty("--dock"); });
    };
    rail.addEventListener("mousemove", (e) => {
      if (off()) return;
      if (!base) {
        base = btns().map((b) => {
          // Our label replaces the browser's slow tooltip (kept for screen readers).
          if (b.title) { b.setAttribute("aria-label", b.title); b.dataset.name = b.title; b.removeAttribute("title"); }
          const r = b.getBoundingClientRect();
          return { b, y: r.top + r.height / 2, right: r.right, half: r.width / 2, name: b.dataset.name || b.dataset.rail || "" };
        });
        rail.classList.add("docking");
      }
      const y = e.clientY;
      cancelAnimationFrame(frame);
      frame = requestAnimationFrame(() => {
        let best = null;
        base.forEach((it) => {
          const d = Math.abs(y - it.y);
          // Cosine falloff: smooth at the peak and at the edge, like the Dock.
          const s = d >= RANGE ? 0 : MAX * (0.5 + 0.5 * Math.cos((Math.PI * d) / RANGE));
          it.b.style.setProperty("--dock", s.toFixed(3));
          if (!best || d < best.d) best = { d, it, s };
        });
        if (best && best.d < 30 && best.it.name) {
          label.textContent = best.it.name;
          label.style.top = `${best.it.y}px`;
          // Clear of the grown icon: its right edge moves by the scale and the lean (see .rail-btn).
          const edge = best.it.right + best.it.half * best.s + 14 * best.s;
          label.style.left = `${Math.max(edge, rail.getBoundingClientRect().right) + 12}px`;
          label.hidden = false;
        } else label.hidden = true;
      });
    });
    rail.addEventListener("mouseleave", () => { cancelAnimationFrame(frame); reset(); });
    window.addEventListener("scroll", () => { if (base) reset(); }, { passive: true });
    window.addEventListener("resize", reset);
  }
  function renderChrome(view) {
    const g = groupOf(view);
    state.group = g ? g.name : null;
    document.querySelectorAll(".rail-btn[data-rail]").forEach((b) => b.classList.toggle("active", b.dataset.rail === (g ? g.name : "Home")));
    const settings = $("#rail-settings");
    if (settings) settings.classList.toggle("active", !!g && g.name === "Preferences");
    const tabs = $("#tabs");
    tabs.innerHTML = "";
    const pill = (label, active, onclick) => el("button", { class: `tab ${active ? "active" : ""}`, text: label, onclick });
    tabs.append(pill("Home", !g, () => navigate("dashboard")));
    if (!g) NAV_GROUPS.forEach((x) => tabs.append(pill(x.name, false, () => { state.group = x.name; navigate(x.items[0].view); })));
    else g.items.forEach((i) => tabs.append(pill(i.label, i.view === navView(view), () => navigate(i.view))));
    const act = tabs.querySelector(".tab.active");
    if (act && act.scrollIntoView) try { act.scrollIntoView({ block: "nearest", inline: "nearest" }); } catch (e) {}
    const user = $("#user-label").textContent;
    const h = new Date().getHours();
    const part = h < 5 ? "Good night" : h < 12 ? "Good morning" : h < 18 ? "Good afternoon" : h < 22 ? "Good evening" : "Good night";
    const appName = view === "app" && APPX.cat ? (APPX.cat.apps.find((x) => x.id === state.viewArg) || {}).name : null;
    $("#view-title").textContent = g ? (appName || TITLES[view] || view) : `${part}, ${user || "there"}!`;
    $("#view-crumb").textContent = g ? g.name : "";
  }
  function isoWeek(d) {
    const t = new Date(Date.UTC(d.getFullYear(), d.getMonth(), d.getDate()));
    const day = t.getUTCDay() || 7; t.setUTCDate(t.getUTCDate() + 4 - day);
    return Math.ceil(((t - Date.UTC(t.getUTCFullYear(), 0, 1)) / 86400000 + 1) / 7);
  }
  function tickClock() {
    const d = new Date();
    $("#now-date").textContent = d.toLocaleDateString([], { weekday: "short", month: "short", day: "numeric" });
    $("#now-time").textContent = d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", hour12: false });
    $("#now-week").textContent = `Week ${isoWeek(d)}`;
  }
  function setupAvatar(username) {
    $("#avatar-initial").textContent = (username || "?").charAt(0).toUpperCase();
    const btn = $("#avatar-btn"), menu = $("#avatar-menu");
    btn.addEventListener("click", (e) => { e.stopPropagation(); menu.hidden = !menu.hidden; });
    document.addEventListener("click", (e) => { if (!menu.hidden && !menu.contains(e.target)) menu.hidden = true; });
  }

  // ======================================================================
  //  Theme toggle
  // ======================================================================
  function applyTheme(theme) {
    if (theme === "light") document.documentElement.setAttribute("data-theme", "light");
    else document.documentElement.removeAttribute("data-theme");
    const btn = $("#theme-btn");
    if (btn) { btn.textContent = ""; btn.appendChild(icon(theme === "light" ? "moon" : "sun", 17)); }
  }
  function initTheme() {
    let t = "dark";
    try { t = localStorage.getItem("aurora-theme") || "dark"; } catch (e) {}
    applyTheme(t);
    const btn = $("#theme-btn");
    if (btn) btn.addEventListener("click", () => {
      const cur = document.documentElement.getAttribute("data-theme") === "light" ? "light" : "dark";
      const next = cur === "light" ? "dark" : "light";
      applyTheme(next);
      try { localStorage.setItem("aurora-theme", next); } catch (e) {}
    });
  }

  // ======================================================================
  //  Command palette (⌘K)
  // ======================================================================
  function allCommands() {
    const cmds = [];
    for (const [view, title] of Object.entries(TITLES)) {
      cmds.push({ label: title, view, icon: VIEW_ICONS[view] || "dot" });
    }
    cmds.push({ label: "phpMyAdmin", ext: "/phpmyadmin", icon: "database" });
    cmds.push({ label: "phpPgAdmin", ext: "/phppgadmin", icon: "database" });
    return cmds;
  }
  function fuzzy(q, s) {
    q = q.toLowerCase(); s = s.toLowerCase();
    if (!q) return 1;
    if (s.includes(q)) return 100 - s.indexOf(q);
    let i = 0; for (const ch of s) { if (ch === q[i]) i++; if (i === q.length) return 10; }
    return -1;
  }
  let cmdkEl = null, cmdkIdx = 0, cmdkList = [];
  function openCmdk() {
    if (cmdkEl) return;
    cmdkEl = el("div", { class: "cmdk-backdrop", onclick: (e) => { if (e.target === cmdkEl) closeCmdk(); } }, [
      el("div", { class: "cmdk" }, [
        el("div", { class: "cmdk-input-wrap" }, [icon("search", 18), el("input", { id: "cmdk-input", type: "text", placeholder: "Jump to any tool…", autocomplete: "off" })]),
        el("div", { class: "cmdk-list", id: "cmdk-results" }),
      ]),
    ]);
    document.body.appendChild(cmdkEl);
    const input = $("#cmdk-input");
    input.addEventListener("input", () => renderCmdk(input.value));
    input.addEventListener("keydown", cmdkKeys);
    renderCmdk("");
    setTimeout(() => input.focus(), 20);
  }
  function closeCmdk() { if (cmdkEl) { cmdkEl.remove(); cmdkEl = null; } }
  function renderCmdk(q) {
    const results = allCommands().map((c) => ({ c, score: fuzzy(q, c.label) }))
      .filter((r) => r.score >= 0).sort((a, b) => b.score - a.score).slice(0, 9).map((r) => r.c);
    cmdkList = results; cmdkIdx = 0;
    const box = $("#cmdk-results");
    box.innerHTML = "";
    if (!results.length) { box.append(el("div", { class: "cmdk-empty", text: "No matches" })); return; }
    results.forEach((c, i) => {
      const row = el("div", { class: `cmdk-item ${i === 0 ? "sel" : ""}`, "data-i": i,
        onmouseenter: () => { cmdkIdx = i; highlightCmdk(); },
        onclick: () => runCmdk(c) }, [
        icon(c.icon, 16), el("span", { text: c.label }), c.ext ? el("span", { class: "cmdk-tag", text: "port 80" }) : null,
      ]);
      box.append(row);
    });
  }
  function highlightCmdk() {
    document.querySelectorAll(".cmdk-item").forEach((r, i) => r.classList.toggle("sel", i === cmdkIdx));
  }
  function cmdkKeys(e) {
    if (e.key === "ArrowDown") { e.preventDefault(); cmdkIdx = Math.min(cmdkIdx + 1, cmdkList.length - 1); highlightCmdk(); }
    else if (e.key === "ArrowUp") { e.preventDefault(); cmdkIdx = Math.max(cmdkIdx - 1, 0); highlightCmdk(); }
    else if (e.key === "Enter") { e.preventDefault(); if (cmdkList[cmdkIdx]) runCmdk(cmdkList[cmdkIdx]); }
    else if (e.key === "Escape") { closeCmdk(); }
  }
  function runCmdk(c) {
    closeCmdk();
    if (c.ext) window.open(`http://${location.hostname}${c.ext}`, "_blank");
    else navigate(c.view);
  }
  document.addEventListener("keydown", (e) => {
    if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k") { e.preventDefault(); cmdkEl ? closeCmdk() : openCmdk(); }
  });

  // ======================================================================
  //  Auth flow
  // ======================================================================
  const state = { view: "dashboard", firstLogin: false, refreshHandler: null, sysUser: null, sysHome: null };
  // The Pi's regular login (whoever installed the panel), used for defaults/placeholders.
  const sysUser = () => state.sysUser || "pi";
  const sysHome = () => state.sysHome || `/home/${sysUser()}`;

  async function boot() {
    brandLogo();
    try {
      const s = await API.status();
      IS_PI = s.pi !== false;
      if (!IS_PI) document.querySelectorAll("[data-pi]").forEach((n) => { n.textContent = host(n.textContent); });
      state.firstLogin = !!s.first_login;
      // Check for a live session.
      try {
        const me = await API.me();
        return me.must_change_password ? showPasswordChange(me.username, null) : enterApp(me.username, me);
      } catch (e) {
        return showAuth();
      }
    } catch (e) {
      showAuth();
      toast("Cannot reach the server", "bad");
    }
  }

  function showAuth() {
    $("#app-shell").hidden = true;
    $("#auth-screen").hidden = false;
    $("#pw-form").hidden = true;
    $("#auth-form").hidden = false;
    $("#auth-subtitle").textContent = IS_PI ? "Sign in to your Raspberry Pi" : "Sign in to your server";
    // The installer made "admin" with a random password: say where it is.
    $("#auth-hint").hidden = !state.firstLogin;
    if (state.firstLogin && !$("#auth-username").value) $("#auth-username").value = "admin";
    $("#auth-error").hidden = true;
  }

  // Signed in with the installer's password: nothing else opens until it's replaced.
  function showPasswordChange(username, current) {
    $("#app-shell").hidden = true;
    $("#auth-screen").hidden = false;
    $("#auth-form").hidden = true;
    $("#auth-hint").hidden = true;
    $("#pw-form").hidden = false;
    $("#auth-subtitle").textContent = "Choose your own password to continue, the one from the installer works only once.";
    $("#pw-form").querySelector('input[name="username"]').value = username;
    $("#pw-current-wrap").hidden = !!current;
    $("#pw-current").required = !current;
    state.pwChange = { username, current };
    $("#pw-error").hidden = true;
    (current ? $("#pw-new") : $("#pw-current")).focus();
  }

  $("#pw-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    const errEl = $("#pw-error");
    errEl.hidden = true;
    const { username, current } = state.pwChange || {};
    const now = current || $("#pw-current").value;
    const pw = $("#pw-new").value;
    const fail = (msg) => { errEl.textContent = msg; errEl.hidden = false; };
    if (pw !== $("#pw-repeat").value) return fail("The two new passwords are different.");
    if (pw.length < 8) return fail("Use at least 8 characters.");
    if (pw === now) return fail("Choose a password different from the installer's.");
    try {
      await API.passwordChange(now, pw);
    } catch (err) {
      return fail(err.message);
    }
    for (const id of ["#pw-current", "#pw-new", "#pw-repeat"]) $(id).value = "";
    state.pwChange = null;
    state.firstLogin = false;
    enterApp(username);
    toast("Password saved", "good");
  });

  $("#pw-logout").addEventListener("click", async () => {
    try { await API.logout(); } catch (e) {}
    location.reload();
  });

  function ensureOtpField() {
    let wrap = $("#auth-otp-wrap");
    if (!wrap) {
      wrap = el("label", { id: "auth-otp-wrap", style: "display:flex;flex-direction:column;gap:6px;font-size:13px;color:var(--text-dim)" }, [
        "2FA code",
        el("input", { id: "auth-otp", type: "text", inputmode: "numeric", autocomplete: "one-time-code", placeholder: "6-digit code" }),
      ]);
      const errEl = $("#auth-error");
      errEl.parentNode.insertBefore(wrap, errEl);
    }
    wrap.hidden = false;
    $("#auth-otp").focus();
  }

  $("#auth-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    const username = $("#auth-username").value.trim();
    const password = $("#auth-password").value;
    const otpEl = $("#auth-otp");
    const otp = otpEl ? otpEl.value.trim() : null;
    const errEl = $("#auth-error");
    errEl.hidden = true;
    try {
      await API.loginOtp(username, password, otp || null);
      $("#auth-password").value = "";
      const me = await API.me();
      if (me.must_change_password) return showPasswordChange(me.username, password);
      enterApp(me.username, me);
    } catch (err) {
      if (err.message === "otp_required") {
        ensureOtpField();
        errEl.textContent = "Enter your authenticator code to continue.";
        errEl.hidden = false;
        return;
      }
      errEl.textContent = err.message;
      errEl.hidden = false;
    }
  });

  // What a limited panel user may open (the server enforces it too, this only keeps the menus honest).
  const SITE_VIEWS = new Set(["mysites", "files", "mailaccounts", "visitors", "analytics", "errors"]);
  async function enterApp(username, me) {
    $("#auth-screen").hidden = true;
    $("#app-shell").hidden = false;
    $("#user-label").textContent = username;
    if (!me) { try { me = await API.me(); } catch (e) { me = {}; } }
    state.role = me.role || "admin";
    state.sysUser = me.system_user; state.sysHome = me.home;
    state.meReady = Promise.resolve();
    applyRole();
    // Just switched the panel to HTTPS: reaching it over https:// is the proof
    // that stops the automatic revert to HTTP.
    if (location.protocol === "https:") {
      API.panelHttps().then((st) => st.pending && API.panelHttpsConfirm()
        .then(() => toast("Panel HTTPS is on, bookmark this https:// address", "good"))).catch(() => {});
    }
    initTheme();
    decorateNav();
    setupNav();
    buildNavGroups();
    buildRail();
    setupAvatar(username);
    tickClock();
    setInterval(tickClock, 15000);
    const cmdkBtn = $("#cmdk-open");
    if (cmdkBtn) cmdkBtn.addEventListener("click", openCmdk);
    // Open the page named in the URL (#/openvpn) so refresh and bookmarks land where they were.
    navigate(viewFromHash() || "dashboard", { history: "replace" });
    window.addEventListener("popstate", () => {
      // Back/Forward: close an open dialog first, then show the page from the URL.
      closeModal(); closeCmdk();
      const v = viewFromHash() || "dashboard";
      if (v !== state.view || (argFromHash() || null) !== (state.viewArg || null)) navigate(v, { history: "none" });
    });
    API.overview().then((o) => { $("#host-label").textContent = o.hostname; $("#host-badge").textContent = o.hostname; }).catch(() => {});
    API.about().then((a) => {
      const v = $("#am-version");
      if (v) { v.textContent = `AuroraPanel ${a.label}`; v.onclick = () => { $("#avatar-menu").hidden = true; navigate("about"); }; }
    }).catch(() => {});
  }

  $("#logout-btn").addEventListener("click", async () => {
    try { await API.logout(); } catch (e) {}
    location.reload();
  });

  $("#refresh-btn").addEventListener("click", () => {
    if (state.refreshHandler) state.refreshHandler();
  });

  // ======================================================================
  //  Navigation
  // ======================================================================
  const TITLES = {
    dashboard: "Dashboard", terminal: "Terminal", services: "Services", processes: "Processes",
    packages: "Packages", cron: "Cron Jobs", files: "File Manager", shadow: "Shadow Copies", disk: "Disk Usage",
    backups: "Backups", network: "Interfaces & Wi-Fi", firewall: "Firewall", users: "Users", security: "Security", panelhttps: "Panel HTTPS",
    indexes: "Indexes", mime: "MIME Types", errorpages: "Error Pages", handlers: "Apache Handlers",
    virus: "Virus Scanner", dns: "Track DNS",
    ssh: "SSH Access", ipblocker: "IP Blocker & Trust", ssl: "SSL/TLS Certificates", tokens: "Manage API Tokens",
    hotlink: "Hotlink Protection", redirects: "Redirects", modsec: "WAF Firewall", globalsec: "Global Security", secreport: "Security Report", activity: "Activity Log", isolation: "Site Isolation", dockerapps: "Docker", servers: "Servers", mysites: "My Websites", panelusers: "Panel Users", wptoolkit: "WordPress Toolkit", migrate: "Move from cPanel", alerts: "Alerts", schedbackups: "Scheduled Backups", updates: "Updates", autossl: "AutoSSL", ddnshosts: "Dynamic DNS", visitors: "Visitors", errors: "Errors", bandwidth: "Bandwidth", rawaccess: "Raw Access", analytics: "Analytics", resources: "Resource Usage", leech: "Fail2ban",
    fixperms: "Fix Home Permissions", vhosts: "Domains", revproxy: "Reverse Proxy", dyndns: "Dynamic DNS Updater", zones: "Zone Editor",
    mysql: "Manage Databases", mysqlwiz: "MariaDB Wizard", pgsql: "PostgreSQL Databases",
    pgwiz: "PostgreSQL Wizard",
    sysapps: "System Applications", appmgr: "Application Manager", phpver: "PHP Settings",
    password: "Password & Security", accountprefs: "Account Preferences",
    contact: "Contact Information", language: "Change Language", wordpress: "WordPress", appstore: "App Installer", app: "App",
    vpn: "VPN Overview", wireguard: "WireGuard", openvpn: "OpenVPN", ipsec: "IPsec / IKEv2 (strongSwan)",
    portcheck: "Port Checker", netmon: "Network Monitor",
    images: "Images", dirprivacy: "Directory Privacy", webdisk: "Web Disk", ftpaccounts: "FTP Accounts",
    backupwiz: "Backup Wizard", git: "Git Version Control", inodes: "Inodes Usage",
    about: "About & Updates",
    email: "Email", mailaccounts: "Email Accounts", forwarders: "Forwarders", mailrouting: "Email Routing", autoresponders: "Autoresponders",
    defaultaddress: "Default Address", mailinglists: "Mailing Lists", trackdelivery: "Track Delivery", globalfilters: "Global Email Filters",
    emailfilters: "Email Filters", deliverability: "Email Deliverability", addressimporter: "Address Importer", spamfilters: "Spam Filters",
    mailtls: "Encryption", calendars: "Calendars & Contacts", maildisk: "Email Disk Usage", mailqueue: "Mail Queue",
  };

  $("#nav").addEventListener("click", (e) => {
    const btn = e.target.closest(".nav-item");
    if (btn) navigate(btn.dataset.view);
  });

  // "#/wireguard" -> "wireguard"; "#/sysapps/vsftpd" -> view "sysapps", arg "vsftpd".
  // Only known pages; anything else falls back to the dashboard.
  function viewFromHash() {
    const m = /^#\/([a-z0-9_-]+)(?:\/([^?#]*))?/i.exec(location.hash || "");
    return m && (TITLES[m[1]] || m[1] === "dashboard") ? m[1] : null;
  }
  function argFromHash() {
    const m = /^#\/[a-z0-9_-]+\/([^?#]+)/i.exec(location.hash || "");
    try { return m ? decodeURIComponent(m[1]) : null; } catch (e) { return null; }
  }
  const argToUrl = (a) => encodeURIComponent(a).replace(/%3A/g, ":");
  // Sub-page inside a view (a tab, an app id): updates the URL without re-rendering.
  function setViewArg(arg, replace) {
    state.viewArg = arg || null;
    const hash = `#/${state.view}${arg ? "/" + argToUrl(arg) : ""}`;
    if (location.hash !== hash) history[replace ? "replaceState" : "pushState"]({ view: state.view, arg }, "", hash);
  }
  // opts.history: "push" (default, a user click) | "replace" (startup) | "none" (Back/Forward)
  // opts.arg: optional sub-page (#/view/arg)
  function navigate(view, opts = {}) {
    if (!TITLES[view] && view !== "dashboard") view = "dashboard";
    if (state.role === "site" && !SITE_VIEWS.has(view)) view = "mysites";
    const mode = opts.history || "push";
    state.viewArg = opts.arg !== undefined ? opts.arg : (mode === "push" ? null : argFromHash());
    const hash = `#/${view}${state.viewArg ? "/" + argToUrl(state.viewArg) : ""}`;
    if (mode === "push" && location.hash !== hash) history.pushState({ view }, "", hash);
    else if (mode === "replace" && location.hash !== hash) history.replaceState({ view }, "", hash);
    document.title = view === "dashboard" ? "AuroraPanel" : `${TITLES[view]} · AuroraPanel`;
    // Run any per-view cleanups (polling timers, sockets) before switching.
    (state.cleanups || []).forEach((fn) => { try { fn(); } catch (e) {} });
    state.cleanups = [];
    closeDrawer();
    state.view = view;
    state.refreshHandler = null;
    document.querySelectorAll(".nav-item").forEach((b) => b.classList.toggle("active", b.dataset.view === view));
    $("#view-title").textContent = TITLES[view] || view;
    renderChrome(view);
    const root = $("#view-root");
    root.innerHTML = "";
    state.navId = (state.navId || 0) + 1;
    // Scroll back to the top so a short view never looks blank.
    try { window.scrollTo(0, 0); const c = document.querySelector(".content"); if (c) c.scrollTop = 0; } catch (e) {}
    // Tear down any active terminal when leaving its view.
    if (view !== "terminal" && termCtx.dispose) { termCtx.dispose(); }
    const render = ({
      dashboard: viewDashboard,
      terminal: viewTerminal,
      services: viewServices,
      processes: viewProcesses,
      packages: viewPackages,
      cron: viewCron,
      files: viewFiles,
      disk: viewDisk,
      backups: viewBackups,
      network: viewNetwork,
      firewall: viewFirewall,
      users: viewUsers,
      security: viewSecurity,
      panelhttps: (root) => viewSecurity(root, "https"),
      indexes: viewIndexes,
      mime: viewMime,
      errorpages: viewErrorPages,
      handlers: viewHandlers,
      virus: viewVirus,
      dns: viewDns,
      ssh: viewSSH,
      ipblocker: viewIPBlocker,
      ssl: viewSSL,
      tokens: viewAPITokens,
      hotlink: viewHotlink,
      redirects: viewRedirects,
      leech: viewLeech,
      fixperms: viewFixPerms,
      vhosts: viewDomains,
      revproxy: viewRevProxy,
      dyndns: viewDynDNS,
      zones: viewZoneEditor,
      mysql: viewMySQL,
      mysqlwiz: viewMySQLWizard,
      pgsql: viewPgSQL,
      pgwiz: viewPgWizard,
      sysapps: viewSysApps,
      appmgr: viewAppManager,
      phpver: viewPHPVersion,
      password: viewPassword,
      accountprefs: viewAccountPrefs,
      contact: viewContact,
      language: viewLanguage,
      wordpress: viewWordPress,
      appstore: viewAppStore,
      app: viewAppPageRoute,
      vpn: viewVPNOverview,
      wireguard: viewWireGuard,
      openvpn: viewOpenVPN,
      ipsec: viewIPsec,
      portcheck: viewPortCheck,
      netmon: viewNetMon,
      images: viewImages,
      dirprivacy: viewDirPrivacy,
      webdisk: viewWebDisk,
      ftpaccounts: (r) => { r.append(el("p", { class: "muted", style: "margin:0 0 14px", text: "Accounts for uploading files with an FTP program (FileZilla, WinSCP, Cyberduck…). Each account is locked into its own folder." })); ftpAccountsPanel(r); },
      backupwiz: viewBackupWizard,
      git: viewGit,
      inodes: viewInodes,
      about: viewAbout,
    }[view] || mailViews()[view] || extraViews()[view] || opsViews()[view] || viewDashboard);
    if (VIEW_NEEDS[view]) requireGate(root, view, VIEW_NEEDS[view], render);
    else render(root);
  }

  // ======================================================================
  //  Requirements, a fresh Ubuntu/Debian server has no Apache, PHP, MariaDB…
  //  Pages that need them offer a one-click install (with an orange progress
  //  bar) instead of failing. "soft" ones only show a banner above the page.
  // ======================================================================
  const VIEW_NEEDS = {
    vhosts: ["apache"], revproxy: ["apache"], redirects: ["apache"], hotlink: ["apache"], indexes: ["apache"], mime: ["apache"], errorpages: ["apache"],
    handlers: ["apache"], dirprivacy: ["apache"], webdisk: ["apache"], phpver: ["web"],
    appstore: ["web", "mariadb"], app: ["web", "mariadb"], wordpress: ["web", "mariadb"],
    modsec: ["apache", "modsecurity"], dockerapps: ["docker"], autossl: { need: ["apache"], soft: ["certbot"] }, visitors: ["apache"], analytics: ["apache"], rawaccess: ["apache"], ddnshosts: { soft: ["bind9"] }, ssl: { need: ["apache"], soft: ["certbot"] },
    mysql: ["mariadb"], mysqlwiz: ["mariadb"], pgsql: ["postgresql"], pgwiz: ["postgresql"],
    ftpaccounts: ["ftp"], git: ["git"], cron: ["cron"], virus: ["clamav"], firewall: ["ufw"], leech: ["fail2ban"],
    zones: { soft: ["bind9"] },
    email: ["mail"], mailaccounts: { need: ["mail"], soft: ["webmail"] }, forwarders: ["mail"], mailrouting: ["mail"], autoresponders: ["mail"],
    defaultaddress: ["mail"], mailinglists: ["mail"], trackdelivery: ["mail"], globalfilters: ["mail"], emailfilters: ["mail"],
    deliverability: ["mail"], addressimporter: ["mail"], spamfilters: ["mail"], mailtls: ["mail"], calendars: ["dav"], maildisk: ["mail"], mailqueue: ["mail"],
  };
  const SOFT_WHY = {
    bind9: "Zones are saved and can be exported, but this server doesn't answer DNS for them yet.",
    certbot: "Needed for free Let's Encrypt certificates; uploaded and self-signed certificates work without it.",
    webmail: "Lets people read and send mail in the browser at /webmail (the “Check Email” button).",
  };

  async function requireGate(root, view, spec, render) {
    const need = Array.isArray(spec) ? spec : spec.need || [];
    const soft = Array.isArray(spec) ? [] : spec.soft || [];
    const nav = state.navId;
    const wait = el("div", { class: "loading", text: "Loading…" });
    root.append(wait);
    let st = null;
    try { st = await API.requires([...need, ...soft]); } catch (e) { if (e.status === 401) return location.reload(); }
    if (state.navId !== nav) return;  // the user already moved on
    wait.remove();
    const comps = (ids) => ids.map((id) => st && st.components[id]).filter((c) => c && !c.installed);
    const again = () => { if (state.navId === nav) navigate(view, { history: "none", arg: state.viewArg }); };
    const missing = st && st.supported ? comps(need) : [];
    if (missing.length) { root.append(requireCard(missing, TITLES[view] || "This page", false, again)); return; }
    const softMissing = st && st.supported ? comps(soft) : [];
    if (softMissing.length) root.append(requireCard(softMissing, TITLES[view] || "This page", true, again));
    render(root);
  }

  function requireCard(comps, page, soft, done) {
    const names = comps.map((c) => c.name);
    const list = names.length > 1 ? `${names.slice(0, -1).join(", ")} and ${names[names.length - 1]}` : names[0];
    const them = names.length > 1 ? "them" : "it";
    const bar = el("div", { class: "ax-bar" }, el("span"));
    const stage = el("div", { class: "ax-stage" });
    const log = el("pre", { class: "log ax-log", hidden: true });
    const logBtn = el("button", { type: "button", class: "bk-mini", text: "Show log",
      onclick: () => { log.hidden = !log.hidden; logBtn.textContent = log.hidden ? "Show log" : "Hide log"; } });
    const prog = el("div", { class: "ax-progress rq-progress", hidden: true }, [el("div", { class: "ax-prog-top" }, [stage, logBtn]), bar, log]);
    const rows = comps.map((c) => {
      const li = el("li", { class: "rq-item" }, [
        el("span", { class: "rq-ico" }, icon(c.icon, 18)),
        el("div", { class: "rq-txt" }, [el("b", { text: c.name }), el("span", { class: "muted", text: soft ? SOFT_WHY[c.id] || c.desc : c.desc })]),
        el("span", { class: "rq-size", text: c.size }), el("span", { class: "rq-mark" })]);
      return { c, li };
    });
    const go = el("button", { class: "btn btn-primary", text: `Install ${list}` });
    const card = el("div", { class: `card rq${soft ? " rq-soft" : ""}` }, [
      soft ? null : el("div", { class: "rq-head" }, [
        el("span", { class: "rq-badge" }, icon(comps[0].icon, 26)),
        el("div", {}, [
          el("h3", { text: `${page} needs ${list}` }),
          el("p", { class: "muted", text: `This server doesn't have ${them} yet. One click downloads, installs and starts ${them}, your other software and settings aren't touched.` }),
        ]),
      ]),
      el("ul", { class: "rq-list" }, rows.map((r) => r.li)),
      prog,
      el("div", { class: "toolbar rq-actions" }, [go, soft ? null : btn("System Applications", () => navigate("sysapps"), "btn-ghost")].filter(Boolean)),
    ].filter(Boolean));

    let timer = null;
    state.cleanups.push(() => { if (timer) clearTimeout(timer); });
    const t0 = Date.now();
    const watch = (r, i) => new Promise((resolve) => {
      const tick = async () => {
        let j;
        try { j = await API.job(r.job); } catch (e) { timer = setTimeout(tick, 2000); return; }
        const pct = (i + (j.status === "done" ? 1 : (j.progress || 1) / 100)) / rows.length * 100;
        bar.firstChild.style.width = `${Math.max(2, pct)}%`;
        const secs = (Date.now() - t0) / 1000;
        stage.innerHTML = "";
        stage.append(el("span", { class: "bk-spin" }), el("b", { text: j.stage || `Installing ${rows[i].c.name}…` }),
          el("span", { class: "bk-pct", text: `${Math.floor(pct)}%` }),
          el("span", { class: "muted", text: ` · ${Math.floor(secs / 60)}:${String(Math.floor(secs % 60)).padStart(2, "0")}` }));
        log.textContent = j.output || ""; log.scrollTop = log.scrollHeight;
        if (j.status === "running") { timer = setTimeout(tick, 1000); return; }
        resolve(j);
      };
      tick();
    });
    function fail(row, msg) {
      row.li.className = "rq-item bad";
      prog.classList.add("bad");
      stage.innerHTML = "";
      stage.append(el("span", { class: "bk-badge bad", text: "!" }), el("b", { text: `${row.c.name}: ${msg.replace(/^✖\s*/, "")}` }));
      log.hidden = false; logBtn.textContent = "Hide log";
      card.classList.remove("busy");
      go.disabled = false; go.textContent = "Try again";
    }
    const run = async (resume) => {
      go.disabled = true; go.textContent = "Installing…";
      prog.hidden = false; prog.classList.remove("ok", "bad");
      card.classList.add("busy");
      for (let i = 0; i < rows.length; i++) {
        const row = rows[i];
        if (row.li.classList.contains("done")) continue;
        row.li.className = "rq-item on";
        let r;
        try { r = resume && row.c.job ? { job: row.c.job } : await API.requireInstall(row.c.id); }
        catch (e) { return fail(row, e.message); }
        const j = await watch(r, i);
        if (j.status !== "done") return fail(row, (j.output || "").trim().split("\n").filter(Boolean).pop() || "Install failed");
        row.li.className = "rq-item done";
      }
      prog.classList.add("ok"); bar.firstChild.style.width = "100%";
      stage.innerHTML = "";
      stage.append(el("span", { class: "bk-badge good", text: "✓" }), el("b", { text: `${list} ${names.length > 1 ? "are" : "is"} installed` }),
        el("span", { class: "muted", text: ` · took ${Math.round((Date.now() - t0) / 1000)}s` }));
      toast(`${list} installed`, "good");
      card.classList.remove("busy");
      go.textContent = "Opening…";
      setTimeout(done, 1200);
    };
    go.onclick = () => run(false);
    // An install already running (another tab, or before a refresh): follow it.
    if (comps.some((c) => c.job)) setTimeout(() => run(true), 0);
    return card;
  }

  async function guardedLoad(fn) {
    try { await fn(); }
    catch (err) {
      if (err.status === 401) return location.reload();
      throw err;
    }
  }

  // ======================================================================
  //  Dashboard
  // ======================================================================
  const TILE_GROUPS = [
    { name: "Databases", icon: "database", tiles: [
      { label: "phpMyAdmin", icon: "database", ext: "/phpmyadmin" },
      { label: "Manage Databases", icon: "database", view: "mysql" },
      { label: "MariaDB Wizard", icon: "wizard", view: "mysqlwiz" },
      { label: "PostgreSQL Databases", icon: "database", view: "pgsql" },
      { label: "PostgreSQL Wizard", icon: "wizard", view: "pgwiz" },
      { label: "phpPgAdmin", icon: "database", ext: "/phppgadmin" },
    ]},
    { name: "Domains", icon: "globe", tiles: [
      { label: "Domains", icon: "globe", view: "vhosts" },
      { label: "Redirects", icon: "redirect", view: "redirects" },
      { label: "Reverse Proxy", icon: "redirect", view: "revproxy" },
      { label: "Zone Editor", icon: "zone", view: "zones" },
      { label: "Dynamic DNS", icon: "refresh", view: "ddnshosts" },
    ]},
    { name: "Email", icon: "mail", tiles: [
      { label: "Email Accounts", icon: "users", view: "mailaccounts" },
      { label: "Forwarders", icon: "forward", view: "forwarders" },
      { label: "Email Routing", icon: "route", view: "mailrouting" },
      { label: "Autoresponders", icon: "reply", view: "autoresponders" },
      { label: "Default Address", icon: "at", view: "defaultaddress" },
      { label: "Mailing Lists", icon: "listing", view: "mailinglists" },
      { label: "Track Delivery", icon: "pin", view: "trackdelivery" },
      { label: "Global Email Filters", icon: "filter", view: "globalfilters" },
      { label: "Email Filters", icon: "filter", view: "emailfilters" },
      { label: "Email Deliverability", icon: "send", view: "deliverability" },
      { label: "Address Importer", icon: "upload", view: "addressimporter" },
      { label: "Spam Filters", icon: "spam", view: "spamfilters" },
      { label: "Encryption", icon: "lock", view: "mailtls" },
      { label: "Calendars & Contacts", icon: "calendar", view: "calendars" },
      { label: "Email Disk Usage", icon: "disk", view: "maildisk" },
      { label: "Webmail", icon: "inbox", ext: "/webmail/" },
    ]},
    { name: "Network", icon: "network", tiles: [
      { label: "VPN Overview", icon: "vpn", view: "vpn" },
      { label: "WireGuard", icon: "tunnel", view: "wireguard" },
      { label: "OpenVPN", icon: "key", view: "openvpn" },
      { label: "IPsec / IKEv2", icon: "shield", view: "ipsec" },
      { label: "Dynamic DNS Updater", icon: "refresh", view: "dyndns" },
      { label: "Port Checker", icon: "plug", view: "portcheck" },
      { label: "Network Monitor", icon: "radar", view: "netmon" },
      { label: "IP Blocker & Trust", icon: "ban", view: "ipblocker" },
      { label: "Fail2ban", icon: "trap", view: "leech" },
      { label: "Interfaces & Wi-Fi", icon: "wifi", view: "network" },
    ]},
    { name: "Security", icon: "shield", tiles: [
      { label: "Security Report", icon: "listing", view: "secreport" },
      { label: "SSH Access", icon: "key", view: "ssh" },
      { label: "IP Blocker & Trust", icon: "ban", view: "ipblocker" },
      { label: "Panel HTTPS", icon: "lock", view: "panelhttps" },
      { label: "SSL/TLS Certificates", icon: "lock", view: "ssl" },
      { label: "AutoSSL", icon: "t_autossl", view: "autossl" },
      { label: "Manage API Tokens", icon: "token", view: "tokens" },
      { label: "Hotlink Protection", icon: "link", view: "hotlink" },
      { label: "Fail2ban", icon: "trap", view: "leech" },
      { label: "WAF Firewall", icon: "shield", view: "modsec" },
      { label: "Site Isolation", icon: "t_isolate", view: "isolation" },
      { label: "Two-Factor Authentication", icon: "phone", view: "security" },
      { label: "Activity Log", icon: "t_activity", view: "activity" },
      { label: "Fix Home Permissions", icon: "home", view: "fixperms" },
      { label: "Antivirus", icon: "virus", view: "virus" },
    ]},
    { name: "Files", icon: "folder", tiles: [
      { label: "File Manager", icon: "folder", view: "files" },
      { label: "Shadow Copies", icon: "shadow", view: "shadow" },
      { label: "Images", icon: "image", view: "images" },
      { label: "Directory Privacy", icon: "lock", view: "dirprivacy" },
      { label: "Disk Usage", icon: "disk", view: "disk" },
      { label: "Web Disk", icon: "disk", view: "webdisk" },
      { label: "FTP Accounts", icon: "folder", view: "ftpaccounts" },
      { label: "Backup", icon: "backup", view: "backups" },
      { label: "Backup Wizard", icon: "wizard", view: "backupwiz" },
      { label: "Scheduled Backups", icon: "t_cloudup", view: "schedbackups" },
      { label: "Move from cPanel", icon: "t_migrate", view: "migrate" },
      { label: "Git Version Control", icon: "git", view: "git" },
      { label: "Inodes Usage", icon: "indexes", view: "inodes" },
    ]},
    { name: "Metrics", icon: "metrics", tiles: [
      { label: "Visitors", icon: "visitors", view: "visitors" },
      { label: "Errors", icon: "errors", view: "errors" },
      { label: "Bandwidth", icon: "gauge", view: "bandwidth" },
      { label: "Raw Access", icon: "rawlog", view: "rawaccess" },
      { label: "Analytics", icon: "chart", view: "analytics" },
      { label: "Resource Usage", icon: "dashboard", view: "resources" },
      { label: "Processes", icon: "processes", view: "processes" },
    ]},
    { name: "System", icon: "services", tiles: [
      { label: "Services", icon: "services", view: "services" },
      { label: "Packages", icon: "packages", view: "packages" },
      { label: "Updates", icon: "t_update", view: "updates" },
      { label: "Servers", icon: "t_servers", view: "servers" },
      { label: "Alerts", icon: "t_bell", view: "alerts" },
      { label: "Firewall", icon: "firewall", view: "firewall" },
      { label: "Users", icon: "users", view: "users" },
    ]},
    { name: "Applications", icon: "apps", tiles: [
      { label: "App Installer", icon: "apps", view: "appstore" },
      { label: "Docker", icon: "t_docker", view: "dockerapps" },
      { label: "WordPress Toolkit", icon: "t_wptool", view: "wptoolkit" },
      { label: "WordPress", icon: "wordpress", view: "wordpress" },
      { label: "System Applications", icon: "services", view: "sysapps" },
      { label: "Application Manager", icon: "packages", view: "appmgr" },
      { label: "Setup Node.js App", icon: "terminal", view: "appmgr" },
      { label: "Setup Python App", icon: "terminal", view: "appmgr" },
      { label: "Setup Ruby App", icon: "terminal", view: "appmgr" },
      { label: "PHP Settings", icon: "brick", view: "phpver" },
    ]},
    { name: "Advanced", icon: "terminal", tiles: [
      { label: "Terminal", icon: "terminal", view: "terminal" },
      { label: "Cron Jobs", icon: "cron", view: "cron" },
      { label: "Track DNS", icon: "dns", view: "dns" },
      { label: "Indexes", icon: "indexes", view: "indexes" },
      { label: "Error Pages", icon: "error", view: "errorpages" },
      { label: "Apache Handlers", icon: "handler", view: "handlers" },
      { label: "MIME Types", icon: "mime", view: "mime" },
    ]},
    { name: "Preferences", icon: "services", tiles: [
      { label: "Password & Security", icon: "lock", view: "password" },
      { label: "Account Preferences", icon: "services", view: "accountprefs" },
      { label: "Contact Information", icon: "phone", view: "contact" },
      { label: "Change Language", icon: "globe", view: "language" },
      { label: "User Manager", icon: "users", view: "panelusers" },
    ]},
  ];

  const dashHistory = { cpu: [], mem: [], temp: [], disk: [] };
  const dashTimes = [];
  const HISTORY_MAX = 40;
  function pushHist(o, disks) {
    const rd = rootDisk(disks) || {};
    const vals = { cpu: o.cpu.percent, mem: o.memory.percent, temp: o.cpu.temperature_c || 0, disk: rd.percent || 0 };
    for (const k of Object.keys(dashHistory)) {
      dashHistory[k].push(vals[k]);
      if (dashHistory[k].length > HISTORY_MAX) dashHistory[k].shift();
    }
    dashTimes.push(Date.now());
    if (dashTimes.length > HISTORY_MAX) dashTimes.shift();
  }

  // ======================================================================
  //  Bento dashboard, device-style cards fed by live system data
  // ======================================================================
  const I = (name, size) => icon(name, size).outerHTML;
  const clamp = (v, a = 0, b = 100) => Math.max(a, Math.min(b, v));
  const hhmm = (d) => d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", hour12: false });

  function bcHead(ico, kicker, name, extra) {
    return `<div class="bc-head"><span class="bc-ico">${I(ico, 16)}</span>
      <div class="bc-titles"><div class="bc-kicker">${esc(kicker)}</div><div class="bc-name">${esc(name)}</div></div>${extra || ""}</div>`;
  }
  const rbtn = (ico, view, title, cls) => `<button class="rbtn ${cls || ""}" data-go="${view}" title="${esc(title)}">${I(ico, 14)}</button>`;
  const tuneBtn = (view, title) => rbtn("services", view, title || "Open", "rbtn-tune");

  const netState = { prev: null, prevT: 0, rx: 0, tx: 0, iface: null };

  // ---- dashboard layout: drag cards to rearrange, remembered per browser ----
  const DASH_ORDER_KEY = "aurora.dash.order";
  function getDashOrder() { try { return JSON.parse(localStorage.getItem(DASH_ORDER_KEY) || "[]"); } catch (e) { return []; } }
  function setDashOrder(ids) { try { if (ids && ids.length) localStorage.setItem(DASH_ORDER_KEY, JSON.stringify(ids)); else localStorage.removeItem(DASH_ORDER_KEY); } catch (e) {} }
  const dashIds = (grid) => [...grid.querySelectorAll(".bcard")].map((c) => c.id.replace(/^c-/, ""));
  function applyDashOrder(grid, defaults) {
    const saved = getDashOrder().filter((id) => grid.querySelector("#c-" + id));
    [...saved, ...defaults.filter((id) => !saved.includes(id))].forEach((id) => { const c = grid.querySelector("#c-" + id); if (c) grid.appendChild(c); });
  }
  // Don't start a drag from something the user is actually using (a button, link, slider…).
  const DASH_NO_DRAG = "button, a, input, select, textarea, .slider, .rbtn, [data-go], [role=button]";

  // Swap reorder, calm by design: the dragged item floats as a clone while nothing else moves, and dropping
  // it onto another item swaps the two. No live reflow (so no jitter), and with fixed-footprint slots on the
  // dashboard a swap can't open a gap. Works with a real mouse and touch; a plain click still gets through.
  function swapNodes(a, b) {
    const aParent = a.parentNode, aNext = a.nextSibling === b ? a : a.nextSibling;
    b.parentNode.insertBefore(a, b);
    aParent.insertBefore(b, aNext);
  }
  function enableReorder(container, { itemSel, handleSel, noDrag, onDrop, afterSwap }) {
    let drag = null, swallowClick = false, raf = 0, px = 0, py = 0, hover = null;
    const THRESH = 5;

    const cardUnder = () => {
      for (const n of container.children) {
        if (n === drag.el || !n.matches(itemSel)) continue;
        const r = n.getBoundingClientRect();
        if (px >= r.left && px <= r.right && py >= r.top && py <= r.bottom) return n;
      }
      return null;
    };

    function frame() {
      raf = 0;
      if (!drag || !drag.moved) return;
      drag.clone.style.transform = `translate(${px - drag.x}px, ${py - drag.y}px)`;
      const t = cardUnder();
      if (t !== hover) {
        if (hover) hover.classList.remove("swap-target");
        hover = t;
        if (hover) hover.classList.add("swap-target");
      }
    }

    container.addEventListener("pointerdown", (e) => {
      if (e.button != null && e.button !== 0) return;             // left button / primary touch only
      swallowClick = false;
      const item = e.target.closest(itemSel);
      if (!item || !container.contains(item)) return;
      if (handleSel && !e.target.closest(handleSel)) return;      // must grab the handle (e.g. the panel header)
      if (noDrag && e.target.closest(noDrag)) return;             // not from a control inside the item
      drag = { el: item, x: e.clientX, y: e.clientY, pid: e.pointerId, moved: false, clone: null };
      px = e.clientX; py = e.clientY;
    });

    container.addEventListener("pointermove", (e) => {
      if (!drag) return;
      px = e.clientX; py = e.clientY;
      if (!drag.moved) {
        if (Math.abs(e.clientX - drag.x) < THRESH && Math.abs(e.clientY - drag.y) < THRESH) return;
        drag.moved = true;
        try { drag.el.setPointerCapture(drag.pid); } catch (_) {}
        document.body.classList.add("reordering");
        const r = drag.el.getBoundingClientRect();
        // A floating clone follows the cursor; the original stays put, so nothing reflows while dragging.
        const clone = drag.el.cloneNode(true);
        clone.classList.add("drag-clone");
        clone.removeAttribute("id");
        Object.assign(clone.style, { position: "fixed", left: r.left + "px", top: r.top + "px",
          width: r.width + "px", height: r.height + "px", margin: "0", zIndex: "1000", pointerEvents: "none" });
        drag.clone = clone;
        document.body.appendChild(clone);
        drag.el.classList.add("drag-source");                     // dim the original in place
      }
      e.preventDefault();
      if (!raf) raf = requestAnimationFrame(frame);
    });

    const end = (e) => {
      if (!drag) return;
      if (e && e.clientX != null) { px = e.clientX; py = e.clientY; }   // use the actual release point
      const d = drag; drag = null;
      if (raf) { cancelAnimationFrame(raf); raf = 0; }
      document.body.classList.remove("reordering");
      if (hover) { hover.classList.remove("swap-target"); hover = null; }
      if (!d.moved) { if (d.clone) d.clone.remove(); return; }
      d.el.classList.remove("drag-source");
      if (d.clone) d.clone.remove();
      // Resolve the drop target from the final pointer position (a fast drop can beat the rAF hover update).
      let target = null;
      for (const n of container.children) {
        if (n === d.el || !n.matches(itemSel)) continue;
        const r = n.getBoundingClientRect();
        if (px >= r.left && px <= r.right && py >= r.top && py <= r.bottom) { target = n; break; }
      }
      if (target && target !== d.el) {
        swapNodes(d.el, target);                                  // exchange the two slots
        if (afterSwap) afterSwap();
        swallowClick = true;                                      // eat the click this drop would otherwise fire
        if (onDrop) onDrop();
      }
    };
    container.addEventListener("pointerup", end);
    container.addEventListener("pointercancel", end);
    container.addEventListener("click", (e) => {
      if (swallowClick) { swallowClick = false; e.stopPropagation(); e.preventDefault(); }
    }, true);
  }

  // ---- "All tools" layout: drag a category panel by its title bar to reorder, remembered per browser ----
  const TILES_ORDER_KEY = "aurora.tiles.order";
  function getTilesOrder() { try { return JSON.parse(localStorage.getItem(TILES_ORDER_KEY) || "[]"); } catch (e) { return []; } }
  function setTilesOrder(names) { try { if (names && names.length) localStorage.setItem(TILES_ORDER_KEY, JSON.stringify(names)); else localStorage.removeItem(TILES_ORDER_KEY); } catch (e) {} }
  const tilesGroupSel = (n) => `.tile-group[data-group="${(window.CSS && CSS.escape) ? CSS.escape(n) : n}"]`;
  function applyTilesOrder(root, defaults) {
    const saved = getTilesOrder().filter((n) => root.querySelector(tilesGroupSel(n)));
    [...saved, ...defaults.filter((n) => !saved.includes(n))].forEach((n) => { const g = root.querySelector(tilesGroupSel(n)); if (g) root.appendChild(g); });
  }
  const tilesOrderNow = (root) => [...root.querySelectorAll(".tile-group")].map((x) => x.dataset.group);

  function viewDashboard(root) {
    const grid = el("div", { class: "bento", id: "bento" });
    const slots = {};
    const add = (id, cls) => { const c = el("div", { class: `bcard ${cls}`, id: `c-${id}` }, el("div", { class: "bc-loading" })); slots[id] = c; grid.append(c); };
    add("cpu", "tone-ember");
    add("temp", "tone-ember-hot span-2");
    add("mem", "tone-dark span-2 split");
    add("disk", "tone-fill");
    add("svc", "tone-violet span-2");
    add("fw", "tone-green");
    add("user", "tone-slate");
    add("sys", "tone-sky span-2 row-2");
    add("cron", "tone-ember span-2 row-2");
    add("activity", "tone-dark span-2");
    add("net", "tone-ember");
    add("storage", "tone-dark span-2");
    add("term", "tone-dark tone-glow");

    const DASH_DEFAULT = Object.keys(slots);
    applyDashOrder(grid, DASH_DEFAULT);
    const tilesWrap = el("div", { id: "dash-tiles" });
    const hasCustomLayout = () => getDashOrder().length || getTilesOrder().length;
    const resetBtn = el("button", { class: "btn btn-sm btn-ghost dash-reset", title: "Put the cards and tool panels back the way they started",
      onclick: () => {
        setDashOrder(null); applyDashOrder(grid, DASH_DEFAULT);
        setTilesOrder(null); renderTiles(tilesWrap, refreshReset);
        resetBtn.hidden = true;
      } }, [icon("refresh", 13), " Reset layout"]);
    const refreshReset = () => { resetBtn.hidden = !hasCustomLayout(); };
    enableReorder(grid, { itemSel: ".bcard", noDrag: DASH_NO_DRAG, onDrop: () => { setDashOrder(dashIds(grid)); refreshReset(); } });
    refreshReset();

    grid.addEventListener("click", (e) => {
      const b = e.target.closest("[data-go]");
      if (b) navigate(b.dataset.go);
    });

    root.append(el("div", { class: "dash-tools" }, resetBtn), grid, el("h2", { class: "section-title dash-section", text: "All tools" }), tilesWrap);
    renderTiles(tilesWrap, refreshReset);
    try {
      if (!localStorage.getItem("aurora.dash.hint")) {
        toast("Tip: drag a dashboard card, or a tool panel by its title bar, to rearrange. Your layout is remembered.", "good");
        localStorage.setItem("aurora.dash.hint", "1");
      }
    } catch (e) {}

    renderUserCard(slots.user);
    renderTermCard(slots.term);

    const fast = async () => {
      const [o, dr, n] = await Promise.all([API.overview(), API.disks(), API.network().catch(() => null)]);
      const d = dr.disks || [];
      pushHist(o, d);
      if (n) trackNet(n);
      renderCpuCard(slots.cpu, o);
      renderTempCard(slots.temp, o);
      renderMemCard(slots.mem, o);
      renderDiskCard(slots.disk, d);
      renderSysCard(slots.sys, o);
      renderActivityCard(slots.activity, o);
      renderNetCard(slots.net);
      renderStorageCard(slots.storage, d);
      renderTermCard(slots.term, o);
    };
    const slow = () => {
      API.services().then((s) => renderSvcCard(slots.svc, Array.isArray(s) ? s : s.services || [])).catch(() => renderSvcCard(slots.svc, null));
      API.firewall().then((f) => renderFwCard(slots.fw, f)).catch(() => renderFwCard(slots.fw, null));
      API.cronList().then((c) => renderCronCard(slots.cron, c)).catch(() => renderCronCard(slots.cron, null));
    };
    const load = async () => { slow(); await guardedLoad(fast); };
    state.refreshHandler = load;
    load();

    const t1 = setInterval(() => { fast().catch(() => {}); }, 3000);
    const t2 = setInterval(slow, 30000);
    (state.cleanups = state.cleanups || []).push(() => { clearInterval(t1); clearInterval(t2); });
  }

  // Virtual interfaces (Docker bridges + per-container veth, loopback, VPN/tunnels) are NOT the uplink.
  // Counting them double-counts a download: bytes that arrive on wlan0 and are forwarded into a container
  // show again as "sent" on that container's veth, which used to make a download look like upload.
  const NET_VIRT = /^(lo|docker|br-|veth|virbr|vnet|tap\d|tun\d|wg\d|tailscale|zt|cni|flannel|kube|ifb|dummy|sit\d|gre)/;
  function trackNet(data) {
    const now = Date.now();
    const phys = (data.interfaces || []).filter((n) => !NET_VIRT.test(n.name));
    // The uplink the tile names: a real interface that's up with an address (fall back to any real one).
    const i = phys.find((n) => n.is_up && n.ipv4) || phys.find((n) => n.is_up) || phys[0] || null;
    netState.iface = i;
    if (!i) { netState.rx = 0; netState.tx = 0; netState.prev = null; return; }
    const cur = { name: i.name, rx: i.bytes_recv, tx: i.bytes_sent };
    if (netState.prev && netState.prev.name === cur.name && now > netState.prevT) {
      const dt = (now - netState.prevT) / 1000;
      netState.rx = Math.max(0, (cur.rx - netState.prev.rx) / dt);
      netState.tx = Math.max(0, (cur.tx - netState.prev.tx) / dt);
    } else { netState.rx = 0; netState.tx = 0; }  // first sample, or the interface changed, no rate yet
    netState.prev = cur; netState.prevT = now;
  }

  // ---- CPU (slider card) ----
  function renderCpuCard(c, o) {
    const p = clamp(o.cpu.percent);
    c.innerHTML = `${bcHead("processes", "Processor", `${o.cpu.cores_logical} cores${o.cpu.freq_mhz ? " · " + (o.cpu.freq_mhz / 1000).toFixed(1) + " GHz" : ""}`)}
      <div class="bc-body">
        <div class="bc-row"><span class="bc-lbl">CPU load</span><b>${p.toFixed(0)}%</b></div>
        <div class="slider"><span class="slider-fill" style="width:${p}%"></span><span class="slider-knob" style="left:${p}%"></span></div>
      </div>
      <div class="bc-foot">${rbtn("processes", "processes", "Processes")}${rbtn("terminal", "terminal", "Terminal")}<span class="grow"></span>${tuneBtn("processes", "Processes")}</div>`;
  }

  // ---- Temperature (HVAC card with glowing dial) ----
  function renderTempCard(c, o) {
    const t = o.cpu.temperature_c;
    const hot = t != null && t >= 75;
    const frac = t == null ? 0 : clamp((t - 25) / 60, 0, 1);
    const R = 92, C = 2 * Math.PI * R;
    const ticks = Array.from({ length: 13 }, (_, i) => {
      const a = Math.PI / 2 + (i / 12) * Math.PI; // left half, top→bottom
      const x1 = 120 + Math.cos(a) * 112, y1 = 120 - Math.sin(a) * 112, x2 = 120 + Math.cos(a) * 122, y2 = 120 - Math.sin(a) * 122;
      return `<line x1="${x1.toFixed(1)}" y1="${y1.toFixed(1)}" x2="${x2.toFixed(1)}" y2="${y2.toFixed(1)}"/>`;
    }).join("");
    const throttled = o.throttled && o.throttled !== "0x0";
    const hist = dashHistory.temp.filter((v) => v > 0);
    c.innerHTML = `
      <svg class="dial" viewBox="0 0 240 240" aria-hidden="true">
        <defs><linearGradient id="dialg" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="#ffd29a"/><stop offset="1" stop-color="#ff6a14"/></linearGradient></defs>
        <g class="dial-ticks">${ticks}</g>
        <circle cx="120" cy="120" r="${R}" class="dial-track"/>
        <circle cx="120" cy="120" r="${R}" class="dial-fill" transform="rotate(90 120 120)" style="stroke-dasharray:${C.toFixed(1)};stroke-dashoffset:${(C * (1 - frac)).toFixed(1)}"/>
        <circle cx="120" cy="120" r="70" class="dial-core"/>
      </svg>
      ${bcHead("flame", "Thermal", o.pi_model ? "SoC temperature" : "CPU temperature")}
      <div class="bc-body">
        <div class="bc-big ${hot ? "is-hot" : ""}">${t != null ? t.toFixed(1) : ", "}<small>°C</small></div>
        <div class="bc-sub">${t == null ? "No temperature sensor (normal on a virtual server)" : throttled ? "⚠ Throttled (" + esc(o.throttled) + ")" : hist.length > 1 ? `Low ${Math.min(...hist).toFixed(0)}° · High ${Math.max(...hist).toFixed(0)}°` : "No throttling"}</div>
      </div>
      <div class="bc-foot">
        <span class="chip">${I("processes", 12)} ${o.cpu.freq_mhz ? o.cpu.freq_mhz.toFixed(0) + " MHz" : ", "}</span>
        <span class="chip ${throttled ? "chip-bad" : ""}">${t == null ? "n/a" : throttled ? "throttled" : "nominal"}</span>
      </div>`;
  }

  // ---- Memory (speaker-style split card) ----
  function renderMemCard(c, o) {
    const m = o.memory, p = clamp(m.percent);
    const R = 34, C = 2 * Math.PI * R;
    c.innerHTML = `
      <div class="split-art">
        <div class="disc"><svg viewBox="0 0 84 84"><circle cx="42" cy="42" r="${R}" class="disc-track"/><circle cx="42" cy="42" r="${R}" class="disc-fill" style="stroke-dasharray:${C.toFixed(1)};stroke-dashoffset:${(C * (1 - p / 100)).toFixed(1)}"/></svg>
        <span class="disc-center">${p.toFixed(0)}<small>%</small></span></div>
      </div>
      <div class="split-main">
        <div class="bc-titles"><div class="bc-kicker">Memory</div><div class="bc-name">RAM · ${fmtBytes(m.total)}</div></div>
        <div class="split-now"><b>${fmtBytes(m.used)} in use</b><span>${fmtBytes(m.available)} available</span></div>
        <div class="line-meter"><span style="width:${p}%"></span></div>
        <div class="bc-row small"><span>Swap ${o.swap.percent.toFixed(0)}%</span><span>${fmtBytes(m.total)}</span></div>
        <div class="bc-foot">${rbtn("processes", "processes", "Processes")}<span class="grow"></span>${tuneBtn("processes", "Processes")}</div>
      </div>`;
  }

  // ---- Root disk (blinds-style fill) ----
  function renderDiskCard(c, disks) {
    const rd = rootDisk(disks) || {};
    const p = clamp(rd.percent || 0);
    c.style.setProperty("--fill", `${p}%`);
    c.innerHTML = `${bcHead("disk", "Root filesystem", rd.mountpoint || "/")}
      <div class="bc-body"><div class="bc-big accent">${rd.percent != null ? p.toFixed(0) : ", "}<small>%</small></div>
      <div class="bc-sub">Used · ${fmtBytes(rd.free)} free</div></div>
      <div class="bc-foot">${rbtn("disk", "disk", "Disk usage")}${rbtn("folder", "files", "File manager")}<span class="grow"></span>${tuneBtn("backups", "Backups")}</div>`;
  }

  // ---- Services (TV-remote style) ----
  function renderSvcCard(c, list) {
    if (!list) { c.innerHTML = `${bcHead("services", "Services", "systemd")}<div class="bc-body"><div class="bc-sub">Unavailable</div></div>`; return; }
    const running = list.filter((s) => s.sub === "running").length;
    const failed = list.filter((s) => s.active === "failed");
    const total = list.length || 1;
    const R = 50, C = 2 * Math.PI * R;
    c.innerHTML = `
      <div class="pad"><svg viewBox="0 0 120 120"><circle cx="60" cy="60" r="${R}" class="pad-track"/><circle cx="60" cy="60" r="${R}" class="pad-fill" style="stroke-dasharray:${C.toFixed(1)};stroke-dashoffset:${(C * (1 - running / total)).toFixed(1)}"/></svg>
        <button class="pad-ok" data-go="services" title="Open services">${running}</button></div>
      ${bcHead("services", "Services", "systemd units")}
      <div class="bc-body">
        <div class="svc-stats"><span><b>${running}</b> running</span><span><b>${list.length}</b> loaded</span></div>
        <div class="svc-failed">${failed.length ? failed.slice(0, 3).map((s) => `<span class="chip chip-bad">${esc(s.unit.replace(/\.service$/, ""))}</span>`).join("") + (failed.length > 3 ? `<span class="chip">+${failed.length - 3}</span>` : "") : `<span class="chip chip-good">No failed units</span>`}</div>
      </div>
      <div class="bc-foot">${rbtn("services", "services", "Services")}${rbtn("terminal", "terminal", "Terminal")}${rbtn("packages", "packages", "Packages")}${rbtn("cron", "cron", "Cron")}<span class="grow"></span>
        <button class="pill-btn" data-go="services">Manage ${I("chevron", 12)}</button></div>`;
  }

  // ---- Firewall (lock card) ----
  function renderFwCard(c, f) {
    const avail = f && f.available, active = avail && f.active;
    c.classList.toggle("is-off", !active);
    c.innerHTML = `${bcHead("lock", avail ? (active ? "Active" : "Inactive") : "Not installed", "Firewall · ufw")}
      <div class="lock-ring">${I("lock", 22)}</div>
      <button class="slide-btn" data-go="firewall"><span class="slide-knob">${I("chevron", 14)}</span>${avail ? `${f.rules.length} rule${f.rules.length === 1 ? "" : "s"} · manage` : "Set up"}</button>`;
  }

  // ---- Signed-in user ----
  function renderUserCard(c) {
    const u = $("#user-label").textContent || "admin";
    c.innerHTML = `<div class="user-ring">${I("users", 22)}</div>
      <div class="user-meta"><div class="bc-kicker">Signed in</div><div class="bc-name">${esc(u)}</div></div>
      <div class="user-actions">${rbtn("lock", "password", "Password & security")}${rbtn("phone", "security", "Two-factor")}</div>`;
  }

  // ---- System (weather-style card) ----
  function renderSysCard(c, o) {
    const raw = (o.cpu.per_core && o.cpu.per_core.length) ? o.cpu.per_core : [o.cpu.percent];
    // Many-core hosts: average into at most 8 columns so the row never overflows.
    const per = Math.ceil(raw.length / 8);
    const cores = [];
    for (let i = 0; i < raw.length; i += per) {
      const s = raw.slice(i, i + per);
      cores.push({ label: per > 1 ? `C${i}–${i + s.length - 1}` : `Core ${i}`, v: s.reduce((a, b) => a + b, 0) / s.length });
    }
    const boot = new Date(o.boot_time * 1000);
    const la = o.cpu.load_avg;
    const model = (o.pi_model || o.arch || "").replace(/Raspberry Pi/i, "Pi").replace(/ Model /i, " ").replace(/Rev [\d.]+/i, "").trim();
    c.innerHTML = `
      <svg class="waves" viewBox="0 0 400 200" preserveAspectRatio="none" aria-hidden="true">
        <path d="M0 70 C 80 40, 150 95, 240 62 S 360 40, 400 58 L400 200 L0 200 Z" class="w1"/>
        <path d="M0 105 C 90 80, 170 130, 260 100 S 360 84, 400 96 L400 200 L0 200 Z" class="w2"/>
      </svg>
      <div class="sys-top"><span class="sys-loc">${I("globe", 15)} ${esc(o.hostname)}</span><span class="sys-cond">${I("dashboard", 26)}<em>${esc(model || "Linux")}</em></span></div>
      <div class="sys-mid">
        <div><div class="sys-big">${esc(fmtUptime(o.uptime_seconds))}</div>
          <div class="sys-hl">Load ${la[0] != null ? la[0].toFixed(2) : ", "} · ${o.cpu.cores_logical} threads</div>
          <div class="sys-note">${esc(o.arch)} · Python ${esc(o.python)}</div></div>
        <div class="sys-stats">
          <div><span>Load 5m</span><b>${la[1] != null ? la[1].toFixed(2) : ", "}</b></div>
          <div><span>Load 15m</span><b>${la[2] != null ? la[2].toFixed(2) : ", "}</b></div>
          <div><span>Swap</span><b>${o.swap.percent.toFixed(0)}%</b></div>
        </div>
      </div>
      <div class="sys-sun"><span>${I("refresh", 13)} ${hhmm(boot)}</span><i></i><span>${esc(fmtUptime(o.uptime_seconds))} up</span><i></i><span>${I("cron", 13)} ${hhmm(new Date())}</span></div>
      <div class="sys-days">${cores.map(({ label, v }) => `<div class="day"><span>${label}</span><span class="day-bar"><span style="height:${clamp(v).toFixed(0)}%"></span></span><b>${v.toFixed(0)}%</b></div>`).join("")}</div>`;
  }

  // ---- Cron (calendar card) ----
  function cronLabel(s) {
    const t = s.trim();
    const at = { "@reboot": ["AT", "BOOT", ""], "@daily": ["EVERY", "DAY", ""], "@midnight": ["EVERY", "DAY", ""], "@hourly": ["EVERY", "HOUR", ""], "@weekly": ["EVERY", "WEEK", ""], "@monthly": ["EVERY", "MONTH", ""], "@yearly": ["EVERY", "YEAR", ""], "@annually": ["EVERY", "YEAR", ""] };
    if (at[t]) return at[t];
    const f = t.split(/\s+/);
    if (f.length !== 5) return ["CRON", "•", ""];
    const [mi, h, dom, mon, dow] = f;
    let m;
    if ((m = mi.match(/^\*\/(\d+)$/)) && h === "*" && dom === "*" && mon === "*" && dow === "*") return ["EVERY", m[1], "MIN"];
    if (/^\d+$/.test(mi) && (m = h.match(/^\*\/(\d+)$/))) return ["EVERY", m[1], "HRS"];
    if (/^\d+$/.test(mi) && h === "*" && dom === "*") return ["HOURLY", ":" + mi.padStart(2, "0"), ""];
    const DOW = ["SUN", "MON", "TUE", "WED", "THU", "FRI", "SAT", "SUN"];
    if (/^\d+$/.test(mi) && /^\d+$/.test(h)) {
      const time = `${h.padStart(2, "0")}:${mi.padStart(2, "0")}`;
      if (dom === "*" && mon === "*" && dow === "*") return ["DAILY", time, ""];
      if (dom === "*" && /^\d$/.test(dow)) return [DOW[+dow], time, "WEEKLY"];
      if (/^\d+$/.test(dom)) return ["DAY " + dom, time, "MONTHLY"];
    }
    return ["CRON", "•", ""];
  }
  function renderCronCard(c, data) {
    const jobs = data && data.jobs ? data.jobs : [];
    const head = bcHead("cron", "Scheduled", "Cron jobs", `<span class="grow"></span>${tuneBtn("cron", "Cron jobs")}`);
    if (!data || data.supported === false) { c.innerHTML = `${head}<div class="bc-empty">Cron isn't available on this host.</div>`; return; }
    if (!jobs.length) { c.innerHTML = `${head}<div class="bc-empty">No scheduled jobs yet.<button class="pill-btn" data-go="cron">Add a job ${I("chevron", 12)}</button></div>`; return; }
    c.innerHTML = `${head}<div class="agenda">${jobs.slice(0, 5).map((j) => {
      const [a, b, cc] = cronLabel(j.schedule);
      const name = (j.label || j.command.split(/\s+/)[0].split("/").pop() || j.command) + (j.paused ? " (paused)" : "");
      return `<div class="ag-row" data-go="cron"><div class="ag-date"><span>${esc(a)}</span><b>${esc(b)}</b><span>${esc(cc)}</span></div>
        <div class="ag-body"><div class="ag-title">${esc(name)}</div><div class="ag-meta">${I("cron", 11)} <code>${esc(j.schedule)}</code></div><div class="ag-meta dim">${esc(j.command)}</div></div></div>`;
    }).join("")}${jobs.length > 5 ? `<div class="ag-more" data-go="cron">+${jobs.length - 5} more</div>` : ""}</div>`;
  }

  // ---- Activity (energy-style chart) ----
  function renderActivityCard(c, o) {
    const data = dashHistory.cpu, n = data.length, W = 400, H = 110;
    let area = "", line = "";
    if (n >= 2) {
      const max = Math.max(20, ...data) * 1.15;
      const pts = data.map((v, i) => [(i / (n - 1)) * W, H - (v / max) * (H - 8)]);
      // smooth curve via midpoints
      let d = `M${pts[0][0].toFixed(1)},${pts[0][1].toFixed(1)}`;
      for (let i = 1; i < pts.length; i++) {
        const [x0, y0] = pts[i - 1], [x1, y1] = pts[i], mx = (x0 + x1) / 2;
        d += ` C${mx.toFixed(1)},${y0.toFixed(1)} ${mx.toFixed(1)},${y1.toFixed(1)} ${x1.toFixed(1)},${y1.toFixed(1)}`;
      }
      line = d; area = `${d} L${W},${H} L0,${H} Z`;
    }
    const span = n > 1 ? Math.round((dashTimes[n - 1] - dashTimes[0]) / 1000) : 0;
    c.innerHTML = `${bcHead("processes", "Activity", "CPU now", `<span class="grow"></span><div class="act-now"><b>${o.cpu.percent.toFixed(0)}%</b><span>Mem ${o.memory.percent.toFixed(0)}%</span></div>`)}
      <div class="act-chart">
        <svg viewBox="0 0 ${W} ${H}" preserveAspectRatio="none">
          <defs><linearGradient id="actg" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="#ff7a1a" stop-opacity=".55"/><stop offset="1" stop-color="#ff7a1a" stop-opacity="0"/></linearGradient></defs>
          <line x1="0" y1="10" x2="${W}" y2="10" class="act-dash"/>
          ${area ? `<path d="${area}" fill="url(#actg)"/><path d="${line}" class="act-line"/>` : ""}
        </svg>
        ${n < 2 ? '<div class="chart-empty">collecting…</div>' : ""}
        <div class="act-axis"><span>${span ? "−" + (span >= 60 ? Math.round(span / 60) + " min" : span + "s") : ""}</span><span>${span ? "−" + (span >= 120 ? Math.round(span / 120) + " min" : Math.round(span / 2) + "s") : ""}</span><span>now</span></div>
      </div>`;
  }

  // ---- Network (switch-style) ----
  function renderNetCard(c) {
    const i = netState.iface;
    c.innerHTML = `${bcHead("network", "Network", i ? i.name : ", ")}
      <div class="bc-body"><div class="net-rate">${I("chevron", 12)}<b>${fmtBytes(netState.rx)}/s</b><span>down</span></div>
        <div class="net-rate up">${I("chevron", 12)}<b>${fmtBytes(netState.tx)}/s</b><span>up</span></div></div>
      <div class="bc-foot"><span class="bc-sub mono">${esc((i && i.ipv4) || "no IPv4")}</span><span class="grow"></span>${tuneBtn("network", "Network")}</div>`;
  }

  // ---- Storage (vacuum-style stats) ----
  function renderStorageCard(c, disks) {
    const rd = rootDisk(disks) || {};
    const totalAll = disks.reduce((s, d) => s + d.total, 0);
    c.innerHTML = `${bcHead("backup", `Storage · ${disks.length} mount${disks.length === 1 ? "" : "s"}`, rd.device || ", ")}
      <div class="stat3">
        <div><span>${I("disk", 12)} Used</span><b>${fmtBytes(rd.used)}</b></div>
        <div><span>${I("folder", 12)} Free</span><b>${fmtBytes(rd.free)}</b></div>
        <div><span>${I("database", 12)} All disks</span><b>${fmtBytes(totalAll)}</b></div>
      </div>
      <div class="bc-foot">${rbtn("folder", "files", "File manager")}${rbtn("disk", "disk", "Disk usage")}${rbtn("backup", "backups", "Backups")}<span class="grow"></span>${tuneBtn("disk", "Disk usage")}</div>`;
  }

  // ---- Terminal shortcut ----
  function renderTermCard(c, o) {
    const u = $("#user-label").textContent || "root";
    const host = o ? o.hostname : ($("#host-label").textContent || "pi");
    c.innerHTML = `${bcHead("terminal", "Shell", "Terminal")}
      <div class="term-line" data-go="terminal"><span class="dim">${esc(u)}@${esc(host)}</span>:~$ <i class="caret"></i></div>
      <div class="bc-foot"><span class="grow"></span>${rbtn("chevron", "terminal", "Open terminal")}</div>`;
  }

  const GROUP_COLORS = {
    System: "#ff8a3d", Network: "#22c7d6", Databases: "#a78bfa", Domains: "#34d399", Email: "#f472b6", Security: "#f87171", Files: "#fbbf24", Metrics: "#60a5fa", Applications: "#818cf8", Software: "#a3e635", Advanced: "#2dd4bf", Preferences: "#cbd5e1",
  };
  // Every tool its own symbol (shared ones only where it's the same tool in two sections).
  const TILE_ICON = {
    "phpMyAdmin": "t_dbweb", "Manage Databases": "database", "MariaDB Wizard": "t_dbnew", "PostgreSQL Databases": "t_table",
    "PostgreSQL Wizard": "t_tablenew", "phpPgAdmin": "t_tableweb", "Dynamic DNS": "t_ddns", "Email Accounts": "t_mailuser",
    "Mailing Lists": "t_megaphone", "Track Delivery": "t_mailtrack", "Global Email Filters": "t_filterglobal", "Address Importer": "t_contactin",
    "Spam Filters": "t_mailspam", "Encryption": "t_maillock", "Email Disk Usage": "t_pie", "VPN Overview": "t_vpnglobe",
    "WireGuard": "t_bolt", "OpenVPN": "t_keyhole", "IPsec / IKEv2": "t_laptoplock", "Dynamic DNS Updater": "t_router",
    "Panel HTTPS": "t_browserlock", "SSL/TLS Certificates": "t_cert", "Manage API Tokens": "t_apikey", "Hotlink Protection": "t_linkoff",
    "WAF Firewall": "t_waf", "Two-Factor Authentication": "t_phonecheck", "Fix Home Permissions": "t_folderwrench", "Directory Privacy": "t_folderlock",
    "Web Disk": "t_cloud", "FTP Accounts": "t_transfer", "Backup Wizard": "t_restore", "Inodes Usage": "t_grid",
    "Resource Usage": "t_cpu", "Firewall": "t_firewall", "System Applications": "t_rack", "Application Manager": "t_layers",
    "Setup Node.js App": "t_hex", "Setup Python App": "t_python", "Setup Ruby App": "t_gem", "PHP Settings": "t_code",
    "Password & Security": "t_password", "Account Preferences": "t_account", "Contact Information": "t_contact", "Change Language": "t_lang",
    "User Manager": "t_usergear",
  };
  function renderTiles(root, onChange) {
    root.innerHTML = "";
    const names = [];
    for (const group of TILE_GROUPS) {
      names.push(group.name);
      const c = GROUP_COLORS[group.name] || "#ff8a3d";
      const grid = el("div", { class: "tile-grid" });
      for (const t of group.tiles) {
        const ico = el("span", { class: "tile-ico" }, icon(TILE_ICON[t.label] || t.icon, 21));
        const tile = el("button", { class: `tile ${t.ext ? "ext" : ""}`, style: `--tile-accent:${c}`,
          onclick: () => {
            if (t.ext) window.open(`http://${location.hostname}${t.ext}`, "_blank");
            else navigate(t.view);
          } }, [
          ico,
          el("span", { class: "tile-body" }, [el("span", { class: "tile-label", text: t.label }), t.ext ? el("span", { class: "tile-sub", text: "opens in a new tab" }) : null]),
          el("span", { class: "tile-chev", text: "›" }),
        ]);
        grid.append(tile);
      }
      const head = el("div", { class: "tile-group-head tgh", onclick: () => {
        const isC = !grid.hidden; grid.hidden = isC; head.classList.toggle("collapsed", isC); setTileCollapsed(group.name, isC);
      } }, [
        el("span", { class: "gh-ico" }, icon(group.icon, 15)),
        group.name,
        el("span", { class: "tgh-chev" }, icon("chevron", 13)),
      ]);
      if (getTileCollapsed().includes(group.name)) { grid.hidden = true; head.classList.add("collapsed"); }
      root.append(el("div", { class: "tile-group", "data-group": group.name, style: `--tile-accent:${c}` }, [head, grid]));
    }
    applyTilesOrder(root, names);
    enableReorder(root, { itemSel: ".tile-group", handleSel: ".tile-group-head", noDrag: "button, a",
      onDrop: () => { setTilesOrder(tilesOrderNow(root)); if (onChange) onChange(); } });
  }
  function getTileCollapsed() { try { return JSON.parse(localStorage.getItem("aurora-tiles-collapsed") || "[]"); } catch (e) { return []; } }
  function setTileCollapsed(name, isC) {
    let list = getTileCollapsed().filter((n) => n !== name);
    if (isC) list.push(name);
    try { localStorage.setItem("aurora-tiles-collapsed", JSON.stringify(list)); } catch (e) {}
  }

  function rootDisk(disks) {
    return disks.find((d) => d.mountpoint === "/" || /^[A-Za-z]:\\?$/.test(d.mountpoint)) || disks[0];
  }

  // ---- mini sparkline (used by the network view) ----
  function sparklineSvg(data, color, w = 96, h = 34) {
    const n = data.length;
    if (n < 2) return `<svg class="scard-spark" viewBox="0 0 ${w} ${h}" preserveAspectRatio="none"></svg>`;
    const max = Math.max(1, ...data), min = Math.min(...data);
    const rng = Math.max(1, max - min);
    const y = (v) => (h - 3 - ((v - min) / rng) * (h - 6)).toFixed(2);
    const x = (i) => (i / (n - 1) * w).toFixed(2);
    const pts = data.map((v, i) => `${x(i)},${y(v)}`).join(" ");
    const gid = "sp" + (_sparkId++);
    return `<svg class="scard-spark" viewBox="0 0 ${w} ${h}" preserveAspectRatio="none">
      <defs><linearGradient id="${gid}" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stop-color="${color}" stop-opacity="0.4"/><stop offset="100%" stop-color="${color}" stop-opacity="0"/></linearGradient></defs>
      <path d="M0,${h} L${pts.split(" ").join(" L")} L${w},${h} Z" fill="url(#${gid})"/>
      <polyline points="${pts}" fill="none" stroke="${color}" stroke-width="1.6" vector-effect="non-scaling-stroke" stroke-linejoin="round"/>
    </svg>`;
  }
  let _sparkId = 0;

  function infoRow(k, v) {
    return el("div", { class: "info-row" }, [el("span", { class: "k", text: k }), el("span", { class: "v", text: v })]);
  }

  // ======================================================================
  //  Services
  // ======================================================================
  function viewServices(root) {
    // Group units by what they're doing, so the page answers "what's running / what's broken" at a glance.
    const KINDS = [
      ["running", "Running", "good", "Services working right now."],
      ["failed", "Failed", "bad", "Crashed or couldn't start, these need a look (Status shows why)."],
      ["exited", "Finished", "dim", "One-shot jobs that ran at boot and exited. That's normal: there's nothing to keep running."],
      ["stopped", "Stopped", "dim", "Not running. Many are started only when needed (timers, sockets), not an error."],
      ["all", "All", "", ""],
    ];
    const kindOf = (s) => (s.active === "failed" || s.sub === "failed" ? "failed" : s.active === "active" || s.active === "reloading" || s.active === "activating"
      ? (s.sub === "exited" ? "exited" : "running") : "stopped");
    let all = [], kind = null;
    const search = el("input", { id: "svc-filter", type: "search", placeholder: "Filter services…", style: "max-width:280px" });
    const chips = el("div", { class: "svc-kinds" });
    const hint = el("p", { class: "muted svc-hint" });
    const body = el("div", { id: "svc-body" }, el("div", { class: "loading", text: "Loading services…" }));
    root.append(el("div", { class: "toolbar svc-bar" }, [chips, el("span", { class: "grow" }), search]), hint, body);

    const row = (s) => {
      const k = kindOf(s), running = k === "running";
      const label = { running: "running", failed: "failed", exited: "finished", stopped: "stopped" }[k];
      return el("tr", { class: `svc-${k}` }, [
        el("td", {}, el("span", { class: "svc-unit", text: s.unit.replace(/\.service$/, "") })),
        el("td", {}, el("span", { class: `pill ${k === "running" ? "good" : k === "failed" ? "bad" : "dim"}`, text: label })),
        el("td", { class: "muted svc-desc", text: s.description, title: s.description }),
        el("td", { class: "actions svc-act" }, [  // always three slots, so rows and tabs line up
          running ? el("button", { class: "btn btn-sm btn-danger", text: "Stop", onclick: () => svcAction(s.unit, "stop") })
                  : el("button", { class: "btn btn-sm btn-primary", text: "Start", onclick: () => svcAction(s.unit, "start") }),
          el("button", { class: "btn btn-sm", text: "Restart", disabled: running ? null : "", title: running ? "" : "Not running", onclick: () => svcAction(s.unit, "restart") }),
          el("button", { class: "btn btn-sm btn-ghost", text: "Status", onclick: () => svcShowStatus(s.unit) }),
        ]),
      ]);
    };
    const table = (list) => el("div", { class: "table-wrap" }, el("table", { class: "svc-table" }, [
      el("thead", {}, el("tr", {}, ["Service", "State", "Description", ""].map((h) => el("th", { text: h })))),
      el("tbody", {}, list.map(row)),
    ]));
    const render = () => {
      const q = search.value.toLowerCase();
      const match = all.filter((s) => s.unit.toLowerCase().includes(q) || (s.description || "").toLowerCase().includes(q));
      const counts = { all: match.length };
      match.forEach((s) => { const k = kindOf(s); counts[k] = (counts[k] || 0) + 1; });
      if (!kind) kind = all.some((s) => kindOf(s) === "failed") ? "failed" : "running";
      chips.innerHTML = "";
      KINDS.forEach(([k, l, tone]) => chips.append(el("button", { type: "button", class: `svc-kind ${k === kind ? "on" : ""} ${tone} ${k === "failed" && counts.failed ? "alert" : ""}`,
        onclick: () => { kind = k; render(); } }, [el("span", { text: l }), el("b", { text: String(counts[k] || 0) })])));
      const info = KINDS.find((x) => x[0] === kind);
      hint.textContent = info[3];
      hint.hidden = !info[3];
      body.innerHTML = "";
      if (!all.length) { body.append(el("p", { class: "empty", text: "No systemd services (this host isn't running systemd)." })); return; }
      if (kind === "all") {
        for (const [k, l, h] of KINDS.slice(0, 4)) {
          const list = match.filter((s) => kindOf(s) === k);
          if (!list.length) continue;
          body.append(el("div", { class: "svc-group" }, [el("h3", {}, [l, el("span", { class: "muted", text: ` · ${list.length}` })]), el("p", { class: "muted svc-hint", text: h }), table(list)]));
        }
        return;
      }
      const list = match.filter((s) => kindOf(s) === kind);
      body.append(list.length ? table(list) : el("p", { class: "empty", text: kind === "failed" ? "Nothing has failed, every service started cleanly." : "Nothing here." }));
    };

    const load = async () => {
      await guardedLoad(async () => {
        const res = await API.services();
        all = res.services;
        render();
      });
    };
    search.addEventListener("input", render);
    state.refreshHandler = load;
    load();

    window.__svcReload = load;
  }

  async function svcAction(unit, action) {
    try {
      await API.serviceControl(unit, action);
      toast(`${action} → ${unit}`, "good");
      if (window.__svcReload) setTimeout(window.__svcReload, 600);
    } catch (err) { toast(err.message, "bad"); }
  }

  async function svcShowStatus(unit) {
    try {
      const r = await API.serviceStatus(unit);
      openModal(unit, el("pre", { class: "log", text: r.output || "(no output)" }), []);
    } catch (err) { toast(err.message, "bad"); }
  }

  // ======================================================================
  //  Processes
  // ======================================================================
  // Processes: grouped by what they are doing, sortable by any column, searchable. Kernel helpers are hidden
  // by default (they can't be ended anyway) so what's left is the owner's apps and services.
  const PROC_STATE = { running: ["Running", "good", "Using the CPU right now"], sleeping: ["Sleeping", "dim", "Waiting for work, normal for almost every program"],
    idle: ["Idle", "dim", "A kernel helper with nothing to do"], "disk-sleep": ["Waiting for disk", "warn", "Blocked on a disk or network read, fine for a moment, a problem if it stays"],
    stopped: ["Stopped", "warn", "Paused with a STOP signal, resume it or end it"], zombie: ["Zombie", "bad", "Finished, but its parent hasn't collected it yet. Harmless unless they pile up"],
    "tracing-stop": ["In debugger", "warn", "Stopped by a debugger or strace"], dead: ["Dead", "bad", "Being torn down"], parked: ["Idle", "dim", "A kernel helper, parked"], waking: ["Waking", "dim", "About to run"] };
  function viewProcesses(root) {
    // small local helpers (the shared ones live in extras.js, outside this file's scope)
    const LS = { get: (k, dflt) => { try { const v = localStorage.getItem("aurora." + k); return v == null ? dflt : JSON.parse(v); } catch (e) { return dflt; } },
      set: (k, v) => { try { localStorage.setItem("aurora." + k, JSON.stringify(v)); } catch (e) {} } };
    const tile = (label, value, sub, ico, kind, onclick) => el("button", { class: `mx-tile ${kind || ""}`, type: "button", onclick },
      [el("div", { class: "mx-tile-l" }, [ico ? icon(ico, 15) : null, el("span", { text: label })]), el("div", { class: "mx-tile-v", text: value }), sub ? el("div", { class: "mx-tile-s", text: sub }) : null]);
    const seg = (options, value, onChange) => { const box = el("div", { class: "mx-seg", role: "tablist" });
      const drawSeg = (v) => { box.innerHTML = ""; options.forEach(([k, label]) => box.append(el("button", { type: "button", class: k === v ? "on" : "", text: label, onclick: () => { drawSeg(k); onChange(k); } }))); };
      drawSeg(value); return box; };
    const empty = (ico, title, text) => el("div", { class: "em-empty" }, [el("span", { class: "em-empty-ico" }, icon(ico, 26)), el("b", { text: title }), el("p", { class: "muted", text })]);
    let d = null, filt = LS.get("proc.filt", "apps"), q = "", sort = LS.get("proc.sort", { key: "cpu_percent", dir: -1 }), live = false, timer = null;
    const search = el("input", { type: "search", class: "em-search", placeholder: "Search by name, user, PID or command…" });
    let qt; search.addEventListener("input", () => { clearTimeout(qt); qt = setTimeout(() => { q = search.value.trim().toLowerCase(); draw(); }, 150); });
    const tiles = el("div", { class: "mx-tiles mx-tiles-6" });
    const segHost = el("div");
    const liveSw = el("input", { type: "checkbox", class: "sf-switch" });
    liveSw.onchange = () => { live = liveSw.checked; clearInterval(timer); if (live) timer = setInterval(() => load(true), 5000); };
    const bar = el("div", { class: "card em-pad0 pr-bar" }, [el("div", { class: "mx-toolbar" }, [search, segHost, el("span", { class: "grow" }),
      el("label", { class: "mx-live" }, [liveSw, el("span", { text: "Live (5 s)" })])])]);
    const body = el("div", { class: "pr-body" }, el("div", { class: "loading", text: "Loading…" }));
    const note = el("p", { class: "muted mx-small mx-p", text: "Sleeping is normal, a program waits until there is work for it. Idle rows are kernel helpers. A zombie has finished but its parent hasn't noticed yet; harmless unless they pile up. Click a column to sort." });
    root.append(tiles, bar, body, note);
    state.cleanups.push(() => clearInterval(timer));

    async function load(quiet) {
      try { d = await API.processes("cpu"); } catch (e) { if (!quiet) { body.innerHTML = ""; body.append(el("p", { class: "empty", text: e.message })); } return; }
      draw();
    }
    const tile2 = (label, value, sub, ico, key, kind) => tile(label, String(value), sub, ico, `${kind || ""} ${filt === key ? "accent" : ""}`, () => { filt = key; LS.set("proc.filt", key); draw(); });
    function matches(p) {
      if (filt === "apps" && p.kernel) return false;
      if (filt === "busy" && p.group !== "busy") return false;
      if (filt === "sleeping" && p.group !== "sleeping") return false;
      if (filt === "idle" && !(p.group === "idle" || p.kernel)) return false;
      if (filt === "attention" && p.group !== "attention") return false;
      if (!q) return true;
      return `${p.pid} ${p.name} ${p.username} ${p.cmd}`.toLowerCase().includes(q);
    }
    function draw() {
      if (!d) return;
      const c = d.counts || {};
      tiles.innerHTML = "";
      tiles.append(
        tile2("Apps & services", c.total - c.kernel, "what you run", "processes", "apps"),
        tile2("Busy now", c.busy, "using the CPU", "t_bolt", "busy", c.busy > (d.cpus || 1) * 2 ? "warnt" : ""),
        tile2("Sleeping", c.sleeping, "waiting for work", "clock", "sleeping"),
        tile2("Kernel & idle", c.kernel, "helpers, can't be ended", "t_cpu", "idle"),
        tile2("Needs a look", c.attention, c.attention ? "stopped, zombie or stuck on disk" : "nothing stuck", "warning", "attention", c.attention ? "warnt" : ""),
        tile2("Everything", c.total, `on ${d.cpus} cores`, "listing", "all"),
      );
      segHost.innerHTML = "";
      segHost.append(seg([["apps", "Apps & services"], ["busy", "Busy"], ["sleeping", "Sleeping"], ["idle", "Kernel"], ["attention", "Attention"], ["all", "All"]], filt, (v) => { filt = v; LS.set("proc.filt", v); draw(); }));
      const rows = d.processes.filter(matches);
      const dir = sort.dir, k = sort.key;
      rows.sort((x, y) => { const a = x[k], b = y[k]; if (typeof a === "string") return a.localeCompare(b) * dir; return ((a || 0) - (b || 0)) * dir || x.pid - y.pid; });
      const cols = [["pid", "PID", "num"], ["name", "Process"], ["username", "User"], ["cpu_percent", "CPU", "num"], ["memory_percent", "Memory", "num"], ["threads", "Threads", "num"], ["status", "State"], ["", ""]];
      const th = (key, label, num) => el("th", { class: `${key ? "pr-th" : ""} ${num ? "num" : ""} ${sort.key === key ? "on" : ""}`, onclick: key ? () => {
        sort = { key, dir: sort.key === key ? -sort.dir : (key === "name" || key === "username" || key === "status" || key === "pid" ? 1 : -1) };
        LS.set("proc.sort", sort); draw();
      } : null }, key ? [el("span", { text: label }), el("i", { class: "pr-arrow", text: sort.key === key ? (sort.dir > 0 ? "▲" : "▼") : "" })] : []);
      const cpuMax = Math.max(1, ...rows.map((p) => p.cpu_percent));
      body.innerHTML = "";
      if (!rows.length) { body.append(el("div", { class: "card" }, empty("processes", "Nothing here", q ? "No process matches the search." : "Nothing in this group right now."))); return; }
      body.append(el("div", { class: "table-wrap" }, el("table", { class: "pr-table" }, [
        el("thead", {}, el("tr", {}, cols.map(([k2, l, n]) => th(k2, l, n)))),
        el("tbody", {}, rows.map((p) => {
          const st = PROC_STATE[p.status] || [p.status, "dim", ""];
          const locked = p.kernel || p.pid === 1;
          return el("tr", { class: p.group === "attention" ? "pr-attn" : "" }, [
            el("td", { class: "muted pr-mono num", text: p.pid }),
            el("td", { class: "pr-name" }, [el("b", { text: p.name }), p.cmd && p.cmd !== p.name ? el("span", { class: "muted mx-ell", title: p.cmd, text: p.cmd }) : (p.kernel ? el("span", { class: "muted", text: "kernel thread" }) : null)]),
            el("td", {}, el("span", { class: `pr-user ${p.username === "root" ? "root" : ""}`, text: p.username })),
            el("td", { class: "num" }, el("div", { class: "pr-meter" }, [el("span", { text: `${p.cpu_percent}%` }), el("i", {}, el("b", { style: `width:${Math.min(100, p.cpu_percent / cpuMax * 100)}%` }))])),
            el("td", { class: "num", title: p.rss ? fmtBytes(p.rss) : "" }, el("div", { class: "pr-meter" }, [el("span", { text: p.rss ? fmtBytes(p.rss) : `${p.memory_percent}%` }), el("i", {}, el("b", { class: "mem", style: `width:${Math.min(100, p.memory_percent * 4)}%` }))])),
            el("td", { class: "muted num", text: p.threads }),
            el("td", {}, el("span", { class: `pill ${st[1]}`, title: st[2], text: st[0] })),
            el("td", { class: "actions pr-act" }, locked ? el("span", { class: "muted mx-small", title: p.pid === 1 ? "The init process keeps the system running" : "Kernel threads can't be ended", text: "system" })
              : endBtn(p)),
          ]);
        })),
      ])));
    }
    function endBtn(p) {
      let t = null;
      const b = el("button", { class: "btn btn-sm btn-ghost pr-end", text: "End" });
      b.onclick = async () => {
        if (!b.classList.contains("armed")) { b.classList.add("armed"); b.textContent = "Sure?"; t = setTimeout(() => { b.classList.remove("armed"); b.textContent = "End"; }, 4000); return; }
        clearTimeout(t); b.disabled = true;
        try { await API.killProcess(p.pid); toast(`Ended ${p.name} (${p.pid})`, "good"); setTimeout(() => load(true), 600); }
        catch (err) { toast(err.message, "bad"); b.disabled = false; b.classList.remove("armed"); b.textContent = "End"; }
      };
      return b;
    }
    state.refreshHandler = () => load(true);
    load();
    window.__procReload = () => load(true);
  }

  async function killProc(pid, name) {
    if (!confirmInline(`Terminate process ${pid} (${name})?`)) return;
    try {
      await API.killProcess(pid);
      toast(`Terminated ${pid}`, "good");
      if (window.__procReload) setTimeout(window.__procReload, 500);
    } catch (err) { toast(err.message, "bad"); }
  }

  // ======================================================================
  //  File manager
  // ======================================================================
  function viewFiles(root) {
    const crumb = el("div", { class: "breadcrumb", id: "fm-crumb" });
    const pathIn = el("input", { type: "text", id: "fm-path", class: "cw-mono", placeholder: "/var/www/html", autocomplete: "off", spellcheck: "false",
      onkeydown: (e) => { if (e.key === "Enter") { e.preventDefault(); fmGo(); } } });
    const fmGo = () => { const p = pathIn.value.trim(); if (p) fmLoad(p); };
    const pathBar = el("div", { class: "fm-pathbar" }, [
      pathIn, el("button", { class: "btn btn-sm", text: "Go", onclick: fmGo }), el("div", { class: "fm-roots", id: "fm-roots" })]);
    const bar = el("div", { class: "fm-toolbar" }, [
      el("button", { class: "btn btn-sm", text: "↑ Up", id: "fm-up" }),
      el("button", { class: "btn btn-sm", text: "＋ New folder", onclick: fmNewFolder }),
      el("label", { class: "btn btn-sm", style: "position:relative;overflow:hidden" }, [
        "⬆ Upload",
        el("input", { type: "file", id: "fm-upload", multiple: "multiple", style: "position:absolute;inset:0;opacity:0;cursor:pointer", onchange: fmUpload }),
      ]),
      el("button", { class: "btn btn-sm", id: "fm-zip-btn", text: "🗜 Zip selected", onclick: fmZipSelected }),
      el("button", { class: "btn btn-sm btn-ghost", text: "🗑 Recycle Bin", onclick: fmRecycleBin }),
      el("label", { class: "muted", style: "display:flex;align-items:center;gap:7px;margin-left:auto;font-size:13px" }, [
        el("input", { type: "checkbox", id: "fm-hidden", style: "width:auto", onchange: () => { fmState.showHidden = $("#fm-hidden").checked; fmLoad(fmState.cwd); } }),
        "Show hidden",
      ]),
    ]);
    const body = el("div", { id: "fm-body" }, el("div", { class: "loading", text: "Loading…" }));
    const zone = el("div", { class: "fm-dropzone", id: "fm-zone" }, [
      body,
      el("div", { class: "fm-drop-overlay", text: "⬇ Drop files here to upload" }),
    ]);
    const bulkBar = el("div", { class: "fm-bulkbar", id: "fm-bulk", hidden: "" }, [
      el("span", { class: "fm-bulk-count", id: "fm-bulk-count", text: "0 selected" }),
      el("span", { class: "fm-bulk-actions" }, [
        el("button", { class: "btn btn-sm", text: "➜ Move", onclick: () => fmMoveCopy("move") }),
        el("button", { class: "btn btn-sm", text: "⧉ Copy", onclick: () => fmMoveCopy("copy") }),
        el("button", { class: "btn btn-sm", text: "🗜 Zip", onclick: fmZipSelected }),
        el("button", { class: "btn btn-sm btn-danger", text: "🗑 Delete", onclick: fmDeleteSelected }),
        el("button", { class: "btn btn-sm btn-ghost", text: "✕ Clear", onclick: fmClearSel }),
      ]),
    ]);
    root.append(pathBar, bar, bulkBar, crumb, zone);

    // Drag-and-drop upload.
    let dragDepth = 0;
    zone.addEventListener("dragenter", (e) => { e.preventDefault(); if (e.dataTransfer && [...e.dataTransfer.types].includes("Files")) { dragDepth++; zone.classList.add("dragging"); } });
    zone.addEventListener("dragover", (e) => { e.preventDefault(); if (e.dataTransfer) e.dataTransfer.dropEffect = "copy"; });
    zone.addEventListener("dragleave", (e) => { e.preventDefault(); if (--dragDepth <= 0) { dragDepth = 0; zone.classList.remove("dragging"); } });
    zone.addEventListener("drop", (e) => {
      e.preventDefault(); dragDepth = 0; zone.classList.remove("dragging");
      if (e.dataTransfer && e.dataTransfer.files && e.dataTransfer.files.length) fmUploadFiles(e.dataTransfer.files);
    });

    fmState.cwd = fmState.cwd || "";
    $("#fm-up").addEventListener("click", () => { if (fmState.parent != null) fmLoad(fmState.parent); });
    state.refreshHandler = () => fmLoad(fmState.cwd);
    if (typeof state.viewArg === "string" && state.viewArg.startsWith("/")) fmState.cwd = state.viewArg;  // opened at a folder (My Websites → Files)
    fmLoad(fmState.cwd);
  }

  const fmState = { cwd: "", parent: null, showHidden: false, selected: new Set() };

  async function fmLoad(path) {
    await guardedLoad(async () => {
      let data;
      try { data = await API.filesList(path); }
      catch (err) {
        if (err.status === 401) throw err;
        toast(err.message, "bad");
        if ($("#fm-path")) $("#fm-path").value = fmState.cwd;
        if (!$("#fm-body table") && path) return fmLoad("");  // first load of a folder that's gone
        return;
      }
      fmState.cwd = data.cwd;
      fmState.parent = data.parent;
      fmState.selected = new Set();
      $("#fm-path").value = data.cwd;
      // Each segment is clickable; the ones outside the allowed folders are plain text.
      const crumbs = $("#fm-crumb"); crumbs.innerHTML = "";
      const parts = data.cwd.split("/").filter(Boolean);
      const top = (data.roots || []).includes("/");
      if (!parts.length) crumbs.append(el("b", { text: "/" }));
      else if (top) crumbs.append(el("a", { href: "#", text: "/", title: "Open /", onclick: (e) => { e.preventDefault(); fmLoad("/"); } }));
      parts.forEach((p, i) => {
        const full = "/" + parts.slice(0, i + 1).join("/");
        const open = (data.roots || []).some((r) => full === r || full.startsWith(r + "/"));
        crumbs.append(i === 0 && top ? "" : el("span", { class: "muted", text: "/" }),
          i === parts.length - 1 ? el("b", { text: p }) : open ? el("a", { href: "#", text: p, onclick: (e) => { e.preventDefault(); fmLoad(full); } }) : el("span", { class: "muted", text: p }));
      });
      const roots = $("#fm-roots"); roots.innerHTML = "";
      (data.roots || []).forEach((r) => roots.append(el("button", { class: `btn btn-sm btn-ghost${data.cwd === r ? " active" : ""}`, text: r, title: `Open ${r}`, onclick: () => fmLoad(r) })));
      $("#fm-up").disabled = data.parent == null;
      const body = $("#fm-body");
      body.innerHTML = "";
      let entries = data.entries;
      if (!fmState.showHidden) entries = entries.filter((e) => !e.is_hidden);
      if (!entries.length) { body.append(el("p", { class: "empty", text: fmState.showHidden ? "Empty folder" : "Empty (or only hidden files, tick “Show hidden”)" })); return; }
      const rows = entries.map((e) => {
        const cb = el("input", { type: "checkbox", class: "fm-row-cb", style: "width:auto",
          onchange: (ev) => { ev.target.checked ? fmState.selected.add(e.name) : fmState.selected.delete(e.name); fmSelChanged(); } });
        cb.dataset.name = e.name;
        if (fmState.selected.has(e.name)) cb.checked = true;
        const nameCell = el("td", {}, el("span", { class: `fm-name ${e.is_dir ? "dir" : ""}`,
          onclick: () => e.is_dir ? fmLoad(e.path) : fmOpenFile(e) }, [
          el("span", { class: "fm-ico" }, icon(e.is_dir ? "folder" : (/\.zip$/i.test(e.name) ? "backup" : "mime"), 15)),
          e.name + (e.is_symlink ? " ↳" : "") + (e.is_hidden ? "" : ""),
        ]));
        return el("tr", {}, [
          el("td", { style: "width:34px" }, cb),
          nameCell,
          el("td", { class: "muted", text: e.is_dir ? ", " : fmtBytes(e.size) }),
          el("td", { class: "muted", text: e.mode }),
          el("td", { class: "muted", text: new Date(e.modified * 1000).toLocaleString() }),
          el("td", { class: "actions" }, [
            /\.zip$/i.test(e.name) ? el("button", { class: "btn btn-sm btn-ghost", text: "Extract", onclick: () => fmUnzip(e) }) : null,
            e.is_dir ? null : el("a", { class: "btn btn-sm btn-ghost", href: API.downloadUrl(e.path), text: "↓" }),
            el("button", { class: "btn btn-sm btn-danger", text: "✕", onclick: () => fmDelete(e) }),
          ]),
        ]);
      });
      const selAll = el("input", { type: "checkbox", id: "fm-selall", title: "Select all", style: "width:auto",
        onchange: (ev) => fmToggleAll(ev.target.checked) });
      body.append(el("div", { class: "table-wrap" }, el("table", {}, [
        el("thead", {}, el("tr", {}, [el("th", { style: "width:34px" }, selAll), ...["Name", "Size", "Mode", "Modified", ""].map((h) => el("th", { text: h }))])),
        el("tbody", {}, rows),
      ])));
      fmSelChanged();
    });
  }

  async function fmZipSelected() {
    const names = [...fmState.selected];
    if (!names.length) { toast("Select files/folders first (checkboxes)", "bad"); return; }
    const arc = promptInline("Archive name:", "archive.zip");
    if (!arc) return;
    try {
      await API.filesZip(fmState.cwd, names, arc);
      toast(`Zipped ${names.length} item(s)`, "good"); fmLoad(fmState.cwd);
    } catch (err) {
      if (/overwrite/i.test(err.message) && confirmInline(err.message + "\n\nOverwrite?")) {
        try { await API.filesZip(fmState.cwd, names, arc, true); toast("Zipped (overwritten)", "good"); fmLoad(fmState.cwd); }
        catch (e) { toast(e.message, "bad"); }
      } else toast(err.message, "bad");
    }
  }

  // ---- multi-select + bulk actions ----
  function fmSelChanged() {
    const n = fmState.selected.size;
    const bar = document.getElementById("fm-bulk");
    if (bar) bar.hidden = n === 0;
    const count = document.getElementById("fm-bulk-count");
    if (count) count.textContent = `${n} selected`;
    const all = document.getElementById("fm-selall");
    if (all) {
      const rows = [...document.querySelectorAll(".fm-row-cb")];
      const checked = rows.filter((r) => r.checked).length;
      all.checked = rows.length > 0 && checked === rows.length;
      all.indeterminate = checked > 0 && checked < rows.length;
    }
  }
  function fmToggleAll(check) {
    document.querySelectorAll(".fm-row-cb").forEach((cb) => {
      cb.checked = check;
      check ? fmState.selected.add(cb.dataset.name) : fmState.selected.delete(cb.dataset.name);
    });
    fmSelChanged();
  }
  function fmClearSel() {
    fmState.selected.clear();
    document.querySelectorAll(".fm-row-cb").forEach((cb) => { cb.checked = false; });
    fmSelChanged();
  }
  const fmJoin = (dir, name) => (dir === "/" ? "" : dir.replace(/\/+$/, "")) + "/" + name;
  async function fmDeleteSelected() {
    const names = [...fmState.selected];
    if (!names.length) return;
    if (!confirmInline(`Move ${names.length} item${names.length > 1 ? "s" : ""} to the Recycle Bin?`)) return;
    let ok = 0;
    for (const name of names) {
      try { await API.filesDelete(fmJoin(fmState.cwd, name), false); ok++; }
      catch (err) { toast(`${name}: ${err.message}`, "bad"); }
    }
    if (ok) toast(`Moved ${ok} item${ok > 1 ? "s" : ""} to the Recycle Bin`, "good");
    fmClearSel();
    fmLoad(fmState.cwd);
  }
  // Move / Copy, with a folder picker you can browse.
  function fmMoveCopy(mode) {
    const names = [...fmState.selected];
    if (!names.length) return;
    const verb = mode === "move" ? "Move" : "Copy";
    let dest = fmState.cwd;
    const crumb = el("div", { class: "fm-picker-path" });
    const rootsRow = el("div", { class: "fm-picker-roots" });
    const listBox = el("div", { class: "fm-picker-list" });
    const note = el("span", { class: "muted", style: "font-size:12.5px" });
    const goBtn = el("button", { class: "btn btn-primary" });
    const run = async (overwrite) => {
      goBtn.disabled = true;
      try {
        const r = mode === "move" ? await API.filesMove(fmState.cwd, names, dest, overwrite)
                                  : await API.filesCopy(fmState.cwd, names, dest, overwrite);
        const did = (r.moved || r.copied || []).length;
        if (r.clashed && r.clashed.length) {
          const msg = `${r.clashed.length} item${r.clashed.length > 1 ? "s" : ""} already exist in that folder. Overwrite ${r.clashed.length > 1 ? "them" : "it"}?`;
          if (confirmInline(msg)) return run(true);
        }
        closeModal();
        if (did) toast(`${mode === "move" ? "Moved" : "Copied"} ${did} item${did > 1 ? "s" : ""} to ${dest}`, "good");
        fmClearSel();
        fmLoad(fmState.cwd);
      } catch (err) { toast(err.message, "bad"); goBtn.disabled = false; }
    };
    goBtn.onclick = () => run(false);
    async function draw(path) {
      listBox.innerHTML = ""; listBox.append(el("div", { class: "loading", text: "Loading…" }));
      let data;
      try { data = await API.filesList(path); }
      catch (err) { listBox.innerHTML = ""; listBox.append(el("p", { class: "empty", text: err.message })); return; }
      dest = data.cwd;
      crumb.textContent = data.cwd;
      const same = data.cwd === fmState.cwd;
      goBtn.textContent = same ? `${verb} here` : `${verb} here`;
      goBtn.disabled = same;
      note.textContent = same ? `This is where the items already are, pick another folder`
        : `${verb} ${names.length} item${names.length > 1 ? "s" : ""} into this folder`;
      rootsRow.innerHTML = "";
      (data.roots || []).forEach((r) => rootsRow.append(el("button", { class: `btn btn-sm btn-ghost${data.cwd === r ? " active" : ""}`, text: r, onclick: () => draw(r) })));
      listBox.innerHTML = "";
      if (data.parent != null) listBox.append(el("button", { class: "fm-picker-item up", onclick: () => draw(data.parent) }, [icon("folder", 15), el("span", { text: ".. (up one level)" })]));
      const dirs = (data.entries || []).filter((e) => e.is_dir && (fmState.showHidden || !e.is_hidden));
      dirs.forEach((e) => listBox.append(el("button", { class: "fm-picker-item", onclick: () => draw(e.path) }, [icon("folder", 15), el("span", { text: e.name })])));
      if (!dirs.length && data.parent == null) listBox.append(el("p", { class: "empty", text: "No subfolders here" }));
    }
    const body = el("div", { class: "fm-picker" }, [
      el("div", { class: "fm-picker-head" }, [el("span", { class: "muted", text: "Destination" }), crumb]),
      rootsRow, listBox,
      el("div", { class: "fm-picker-foot" }, [note]),
    ]);
    openModal(`${verb} ${names.length} item${names.length > 1 ? "s" : ""}`, body, [goBtn]);
    draw(fmState.cwd);
  }

  // ======================================================================
  //  Reverse Proxy: expose a local app/service at a domain over HTTPS
  // ======================================================================
  function viewRevProxy(root) {
    const domain = el("input", { type: "text", placeholder: "app.example.com" });
    const target = el("input", { type: "text", placeholder: "3000   (or localhost:3000, or http://127.0.0.1:3000)" });
    const ws = el("input", { type: "checkbox" }); ws.checked = true;
    const aliases = el("input", { type: "text", placeholder: "optional: www.app.example.com, api.app.example.com" });
    const list = el("div", { id: "rp-list" });
    const createBtn = btn("Create reverse proxy", async () => {
      const d = domain.value.trim(), t = target.value.trim();
      if (!d || !t) { toast("Enter a domain and where to forward to", "bad"); return; }
      createBtn.disabled = true;
      try {
        const r = await API.proxyCreate(d, t, ws.checked, aliases.value.split(",").map((x) => x.trim()).filter(Boolean));
        toast(`Reverse proxy created: ${d} forwards to ${r.target}`, "good");
        domain.value = ""; target.value = ""; aliases.value = ""; ws.checked = true;
        load();
      } catch (e) { toast(e.message, "bad"); }
      createBtn.disabled = false;
    }, "btn-primary");

    root.append(el("div", { class: "card" }, [
      el("h3", { text: "Expose a local app at a domain" }),
      el("p", { class: "muted", text: "Put a service running on this machine (any port) on a domain over HTTPS. The panel builds an Apache reverse proxy, so the WAF, IP bans and AutoSSL all apply. It starts on a self-signed certificate: point the domain here, then switch it to Let's Encrypt under Domains for a browser-trusted one." }),
      kv([
        ["Domain", domain],
        ["Forward to", target],
        ["Aliases", aliases],
        ["WebSockets", el("label", { class: "rp-ws" }, [ws, el("span", { class: "muted", text: "Keep on unless the app has no live or realtime features" })])],
      ]),
      el("div", { class: "toolbar", style: "margin-top:12px" }, createBtn),
    ]), list);

    async function rpDelete(p) {
      if (!confirmInline(`Delete the reverse proxy for ${p.domain}? The app it forwards to is not touched.`)) return;
      try { await API.proxyDelete(p.domain); toast(`Deleted ${p.domain}`, "good"); load(); }
      catch (e) { toast(e.message, "bad"); }
    }
    async function load() {
      await guardedLoad(async () => {
        let data;
        try { data = await API.proxyList(); }
        catch (e) { list.innerHTML = ""; list.append(el("div", { class: "card" }, el("p", { class: "empty", text: e.message }))); return; }
        list.innerHTML = "";
        if (!data.proxies.length) { list.append(el("div", { class: "card" }, empty("redirect", "No reverse proxies yet", "Create one above to put a local app on a domain."))); return; }
        const rows = data.proxies.map((p) => el("tr", {}, [
          el("td", {}, el("a", { href: p.url, target: "_blank", rel: "noopener", text: p.domain + " ↗" })),
          el("td", { class: "muted", text: "→ " + p.target }),
          el("td", {}, [pill(p.ssl === "letsencrypt" ? "Let's Encrypt" : p.ssl === "selfsigned" ? "self-signed" : p.ssl, p.ssl === "letsencrypt" ? "good" : "warn"),
            p.websockets ? pill("ws", "dim") : null]),
          el("td", { class: "actions" }, [
            el("button", { class: "btn btn-sm btn-ghost", text: "HTTPS / manage", onclick: () => navigate("vhosts") }),
            el("button", { class: "btn btn-sm btn-danger", text: "Delete", onclick: () => rpDelete(p) }),
          ]),
        ]));
        list.append(el("div", { class: "card" }, [
          el("h3", { text: `Reverse proxies (${data.proxies.length})` }),
          el("div", { class: "table-wrap" }, el("table", {}, [
            el("thead", {}, el("tr", {}, ["Domain", "Forwards to", "Certificate", ""].map((h) => el("th", { text: h })))),
            el("tbody", {}, rows),
          ])),
        ]));
      });
    }
    load();
  }

  async function fmUnzip(entry) {
    try {
      const r = await API.filesUnzip(entry.path);
      toast(`Extracted ${r.count} item(s) → ${r.extracted_to}`, "good"); fmLoad(fmState.cwd);
    } catch (err) {
      if (/overwrite|already exists/i.test(err.message) && confirmInline(err.message + "\n\nExtract anyway (overwrite)?")) {
        try { const r = await API.filesUnzip(entry.path, true); toast(`Extracted ${r.count} item(s)`, "good"); fmLoad(fmState.cwd); }
        catch (e) { toast(e.message, "bad"); }
      } else toast(err.message, "bad");
    }
  }

  async function fmRecycleBin() {
    let data;
    try { data = await API.trashList(); } catch (e) { toast(e.message, "bad"); return; }
    const body = el("div", {});
    const render = (items) => {
      body.innerHTML = "";
      if (!items.length) { body.append(el("p", { class: "empty", text: "Recycle bin is empty." })); return; }
      const rows = items.map((it) => el("tr", {}, [
        el("td", {}, [el("span", { class: "fm-ico" }, icon(it.is_dir ? "folder" : "mime", 15)), " " + it.name]),
        el("td", { class: "muted", text: it.original }),
        el("td", { class: "muted", text: fmtBytes(it.size) }),
        el("td", { class: "muted", text: new Date(it.deleted_at * 1000).toLocaleString() }),
        el("td", { class: "actions" }, [
          el("button", { class: "btn btn-sm", text: "Restore", onclick: () => fmRestore(it, () => refresh()) }),
          el("button", { class: "btn btn-sm btn-danger", text: "Delete", onclick: async () => {
            if (!confirmInline(`Permanently delete "${it.name}"?`)) return;
            try { await API.trashDelete(it.id); refresh(); } catch (e) { toast(e.message, "bad"); } } }),
        ]),
      ]));
      body.append(simpleTable(["Name", "Original location", "Size", "Deleted", ""], rows));
    };
    const refresh = async () => { try { render((await API.trashList()).items); } catch (e) { toast(e.message, "bad"); } };
    render(data.items);
    openModal("♻ Recycle Bin", body, [
      el("button", { class: "btn btn-danger", text: "Empty bin", onclick: async () => {
        if (!confirmInline("Permanently delete everything in the recycle bin?")) return;
        try { const r = await API.trashEmpty(); toast(`Emptied ${r.emptied} item(s)`, "good"); refresh(); } catch (e) { toast(e.message, "bad"); } } }),
    ]);
  }

  async function fmRestore(it, done) {
    try { await API.trashRestore(it.id); toast(`Restored ${it.name}`, "good"); done && done(); fmLoad(fmState.cwd); }
    catch (err) {
      if (/overwrite|already exists/i.test(err.message) && confirmInline(err.message + "\n\nOverwrite the existing item?")) {
        try { await API.trashRestore(it.id, true); toast("Restored (overwritten)", "good"); done && done(); fmLoad(fmState.cwd); }
        catch (e) { toast(e.message, "bad"); }
      } else toast(err.message, "bad");
    }
  }

  async function fmOpenFile(entry) {
    try {
      const data = await API.filesRead(entry.path);
      const ta = el("textarea", { class: "editor", spellcheck: "false" });
      ta.value = data.content;
      openModal(entry.name, ta, [
        el("button", { class: "btn btn-primary", text: "Save", onclick: async (ev) => {
          try {
            await API.filesWrite(entry.path, ta.value);
            toast("Saved", "good");
            closeModal();
          } catch (err) { toast(err.message, "bad"); }
        } }),
      ]);
    } catch (err) {
      // Non-text or too large, offer download instead.
      toast(err.message + ", use ↓ to download", "bad");
    }
  }

  async function fmDelete(entry) {
    if (!confirmInline(`Move ${entry.is_dir ? "folder" : "file"} "${entry.name}" to the recycle bin?`)) return;
    try {
      await API.filesDelete(entry.path, false);
      toast("Moved to recycle bin", "good");
      fmLoad(fmState.cwd);
    } catch (err) { toast(err.message, "bad"); }
  }

  async function fmNewFolder() {
    const name = promptInline("New folder name:");
    if (!name) return;
    try {
      await API.filesMkdir(fmState.cwd, name);
      toast("Folder created", "good");
      fmLoad(fmState.cwd);
    } catch (err) { toast(err.message, "bad"); }
  }

  async function fmUpload(ev) {
    await fmUploadFiles(ev.target.files);
    ev.target.value = "";
  }
  async function fmUploadFiles(files) {
    const list = [...(files || [])];
    if (!list.length) return;
    // Orange progress bar while files upload.
    const fill = el("span");
    const label = el("div", { class: "fm-up-label", text: "Preparing upload…" });
    const panel = el("div", { class: "fm-upload-progress" }, [label, el("div", { class: "fm-upbar" }, fill)]);
    (document.getElementById("fm-zone") || document.body).prepend(panel);
    let ok = 0;
    for (let i = 0; i < list.length; i++) {
      const file = list[i];
      fill.style.width = "0%";
      let lastSent = 0, lastT = Date.now(), rate = 0;
      const nth = list.length > 1 ? `  ·  file ${i + 1} of ${list.length}` : "";
      try {
        await API.fileUpload(fmState.cwd, file, (sent, total) => {
          const pct = total ? (sent / total) * 100 : 0;
          fill.style.width = pct.toFixed(1) + "%";
          const now = Date.now();
          if (now - lastT > 350) { rate = (sent - lastSent) / ((now - lastT) / 1000); lastSent = sent; lastT = now; }
          label.textContent = `Uploading ${file.name}  ·  ${fmtBytes(sent)} of ${fmtBytes(total)}  ·  ${pct.toFixed(0)}%` + (rate ? `  ·  ${fmtBytes(rate)}/s` : "") + nth;
        });
        ok++;
      } catch (err) { toast(`${file.name}: ${err.message}`, "bad"); }
    }
    panel.remove();
    if (ok) toast(`Uploaded ${ok} file${ok > 1 ? "s" : ""}`, "good");
    fmLoad(fmState.cwd);
  }

  // ======================================================================
  //  Network
  // ======================================================================
  const netHist = { rx: [], tx: [] };
  // ======================================================================
  //  Network, Overview · Wi-Fi · IP settings · Hotspot · Devices · Ports · Hostname
  // ======================================================================
  const NET_TABS = [["overview", "Overview", "dashboard"], ["wifi", "Wi-Fi", "wifi"], ["ip", "IP & DNS", "network"],
    ["hotspot", "Hotspot", "dns"], ["devices", "Devices on LAN", "users"], ["ports", "Open ports", "shield"], ["host", "Hostname", "home"]];
  const netView = { tab: "overview" };

  function viewNetwork(root) {
    const tabs = el("div", { class: "cw-seg net-tabs" });
    const body = el("div", { class: "net-body" });
    const banner = el("div", { id: "net-pending" });
    root.append(banner, tabs, body);
    let tabCleanups = [];
    NET_TABS.forEach(([k, l, ic]) => tabs.append(el("button", { type: "button", "data-t": k, class: k === netView.tab ? "active" : "", onclick: () => show(k) }, [icon(ic, 14), " ", l])));
    // Without NetworkManager (Ubuntu servers, VPSs) there's no Wi-Fi, hotspot or IP setting to manage here.
    API.netOverview().then((o) => {
      if (o.nm) return;
      tabs.querySelectorAll('[data-t="wifi"], [data-t="hotspot"], [data-t="ip"]').forEach((b) => b.remove());
      if (["wifi", "hotspot", "ip"].includes(netView.tab)) show("overview");
    }).catch(() => {});
    function show(k) {
      tabCleanups.forEach((f) => { try { f(); } catch (e) {} }); tabCleanups = [];
      netView.tab = k;
      tabs.querySelectorAll("button").forEach((b) => b.classList.toggle("active", b.dataset.t === k));
      body.innerHTML = "";
      const before = (state.cleanups || []).length;
      ({ overview: netOverviewTab, wifi: netWifiTab, ip: netIPTab, hotspot: netHotspotTab, devices: netDevicesTab, ports: netPortsTab, host: netHostTab })[k](body);
      tabCleanups = (state.cleanups || []).splice(before);
    }
    (state.cleanups = state.cleanups || []).push(() => tabCleanups.forEach((f) => { try { f(); } catch (e) {} }));
    const pt = setInterval(() => pollPending(banner), 3000);
    state.cleanups.push(() => clearInterval(pt));
    pollPending(banner);
    show(netView.tab);
  }

  // ---- confirm-or-revert banner ----
  async function pollPending(box, known) {
    let p = known;
    if (!p) { try { p = (await API.netPending()).pending; } catch (e) { return; } }
    box.innerHTML = "";
    if (!p) return;
    box.append(el("div", { class: "net-pending" }, [
      el("div", { class: "net-count", text: p.seconds_left }),
      el("div", { class: "grow" }, [el("b", { text: `Keep this change?, ${p.label}` }),
        el("span", { html: p.new_url ? `If this page stops responding, open <a href="${esc(p.new_url)}">${esc(p.new_url.split("?")[0])}</a> and it will confirm automatically. Otherwise everything is put back in <b>${p.seconds_left}s</b>.` : `If the panel still works, click Keep. Otherwise it's put back automatically in <b>${p.seconds_left}s</b>.` })]),
      el("button", { class: "btn btn-ghost", text: "Revert now", onclick: async () => { try { await API.netRevert(p.id); toast("Reverted", "good"); pollPending(box); } catch (e) { toast(e.message, "bad"); } } }),
      el("button", { class: "btn btn-primary", text: "Keep", onclick: async () => { try { await API.netConfirm(p.id); toast("Change kept", "good"); pollPending(box); } catch (e) { toast(e.message, "bad"); } } }),
    ]));
  }
  // Arriving at the new address after an IP change: confirm with the one-time code.
  (function handleNetConfirm() {
    const code = new URLSearchParams(location.search).get("netconfirm");
    if (!code) return;
    history.replaceState(null, "", location.pathname);
    API.netConfirm(code).then(() => toast("✔ New network settings kept", "good")).catch((e) => toast(e.message, "bad"));
  })();

  const netCard = (ico, title, sub, ...kids) => el("div", { class: "card dmm-card" }, [el("div", { class: "cw-card-h" }, [icon(ico, 16), el("div", {}, [el("h3", { text: title }), sub ? el("p", { text: sub }) : null])]), ...kids]);

  // ---- Overview ----
  function netOverviewTab(body) {
    const top = el("div", { class: "net-sum" }, el("div", { class: "loading", text: "Reading network…" }));
    const legacy = el("div", { style: "margin-top:16px" });
    body.append(top, legacy);
    API.netOverview().then((o) => {
      top.innerHTML = "";
      const tile = (ico, k, v, sub) => el("div", { class: "card net-tile" }, [el("span", { class: "scard-ico" }, icon(ico, 16)), el("div", {}, [el("span", { class: "muted", text: k }), el("b", { text: v }), sub ? el("span", { class: "dm-hint", text: sub }) : null])]);
      top.append(
        tile("home", "Hostname", o.hostname, `${o.hostname}.local on your LAN`),
        tile("link", "You're connected via", o.panel_iface || "?", o.panel_ip || ""),
        tile("network", "Gateway (router)", o.gateway ? o.gateway.ip : ", ", o.gateway ? `via ${o.gateway.device}` : ""),
        tile("dns", "DNS servers", o.dns.join(", ") || ", ", ""));
      if (!o.nm) top.append(el("div", { class: "dm-note", style: "grid-column:1/-1" }, [icon("info", 15), el("span", { text: "This machine's network is set up with netplan / systemd-networkd (normal on Ubuntu servers and VPSs), so it's shown read-only here. Wi-Fi, hotspot and IP changes need NetworkManager." })]));
      o.devices.forEach((d) => {
        const c = o.connections.find((x) => x.device === d.device);
        top.append(el("div", { class: "card net-dev" }, [
          el("span", { class: `net-dot ${/^connected/.test(d.state) ? "on" : ""}` }),
          el("div", {}, [el("b", { text: `${d.device} · ${d.type}` }), el("span", { class: "muted", text: `${d.state}${d.connection ? " · " + d.connection : ""}` }),
            c ? el("span", { class: "dm-hint", text: `${(c.live_addresses[0] || "no address")} · ${c.method === "manual" ? "static" : "DHCP"}` })
              : d.addresses ? el("span", { class: "dm-hint", text: d.addresses.join(", ") || "no address" }) : null]),
        ]));
      });
    }).catch((e) => { top.innerHTML = ""; top.append(el("p", { class: "empty", text: e.message })); });
    netLegacy(legacy);
  }

  // ---- Wi-Fi ----
  function bars(sig) {
    const n = sig >= 75 ? 4 : sig >= 55 ? 3 : sig >= 35 ? 2 : 1;
    return el("span", { class: "net-bars", title: `${sig}%` }, [1, 2, 3, 4].map((i) => el("i", { class: i <= n ? "on" : "", style: `height:${i * 25}%` })));
  }
  function netWifiTab(body) {
    const head = el("div", { class: "dm-bar" });
    const listBox = el("div", {}, el("div", { class: "loading", text: "Scanning for networks…" }));
    body.append(head, listBox);
    const load = async (rescan = true) => {
      let d;
      try { d = await API.netWifi(rescan); } catch (e) { listBox.innerHTML = ""; listBox.append(el("p", { class: "empty", text: e.message })); return; }
      head.innerHTML = "";
      head.append(el("span", { class: "net-radio" }, [icon("wifi", 15), " Wi-Fi radio ", sw(d.radio === "enabled", async (v, i) => { try { await API.netWifiRadio(v); toast(`Wi-Fi ${v ? "on" : "off"}`, "good"); load(); } catch (e) { i.checked = !v; toast(e.message, "bad"); } })]),
        el("span", { class: "grow" }),
        el("button", { class: "btn btn-sm", onclick: () => connectModal("", true, true) }, [icon("lock", 12), " Hidden network"]),
        el("button", { class: "btn btn-sm btn-primary", onclick: () => { listBox.innerHTML = '<div class="loading">Scanning…</div>'; load(true); } }, [icon("refresh", 12), " Rescan"]));
      listBox.innerHTML = "";
      if (!d.networks.length) { listBox.append(el("p", { class: "empty", text: "No networks found." })); return; }
      listBox.append(el("div", { class: "net-wifi" }, d.networks.map((n) => el("div", { class: `net-ap ${n.in_use ? "on" : ""}` }, [
        bars(n.signal),
        el("div", { class: "grow" }, [el("b", { text: n.ssid }), el("span", { class: "muted", text: `${n.band} · ch ${n.channel} · ${n.security === "open" ? "open" : n.security}` })]),
        n.in_use ? el("span", { class: "pill good", text: "connected" }) : n.saved ? el("span", { class: "pill dim", text: "saved" }) : null,
        n.security !== "open" ? icon("lock", 13) : null,
        !n.in_use ? el("button", { class: "btn btn-sm", text: "Connect", onclick: () => connectModal(n.ssid, n.security !== "open" && !n.saved, false) }) : null,
        n.saved && !n.in_use ? el("button", { class: "btn btn-sm btn-ghost", title: "Forget", onclick: async () => { if (!confirmInline(`Forget ${n.ssid}?`)) return; try { await API.netWifiForget(n.ssid); toast("Forgotten", "good"); load(false); } catch (e) { toast(e.message, "bad"); } } }, icon("error", 12)) : null,
      ]))));
    };
    function connectModal(ssid, needPw, hidden) {
      const f = el("div", { class: "dm-form" });
      const s = el("input", { type: "text", value: ssid, placeholder: "Network name (SSID)" }); if (ssid) s.readOnly = true;
      const p = el("input", { type: "password", placeholder: needPw || hidden ? "Wi-Fi password" : "(saved or open, leave empty)", autocomplete: "off" });
      f.append(el("label", { class: "cw-lbl" }, ["Network", s]), el("label", { class: "cw-lbl" }, ["Password", p]),
        el("div", { class: "dm-note" }, [icon("error", 15), el("span", { text: "If you're using the panel over Wi-Fi, switching networks will disconnect this page. You'll have 2 minutes to confirm from the new network; otherwise the Pi reconnects to the current one automatically." })]));
      const go = el("button", { class: "btn btn-primary", text: "Connect", onclick: async () => {
        go.disabled = true;
        try { const r = await API.netWifiConnect({ ssid: s.value.trim(), password: p.value, hidden }); closeModal(); toast(r.pending ? "Switching… confirm when you're reconnected" : `Connected to ${s.value}`, "good"); pollPending($("#net-pending"), r.pending); setTimeout(() => load(false), 4000); }
        catch (e) { go.disabled = false; toast(e.message, "bad"); }
      } });
      openModal(hidden ? "Connect to a hidden network" : `Connect to ${ssid}`, f, [go]);
      setTimeout(() => (ssid ? p : s).focus(), 40);
    }
    load(false).then(() => load(true));
  }

  // ---- IP & DNS ----
  const DNS_PRESETS = [["Cloudflare", "1.1.1.1, 1.0.0.1"], ["Google", "8.8.8.8, 8.8.4.4"], ["Quad9", "9.9.9.9, 149.112.112.112"], ["Router (DHCP)", ""]];
  function netIPTab(body) {
    body.append(el("div", { class: "loading", text: "Loading connections…" }));
    API.netOverview().then((o) => {
      body.innerHTML = "";
      const conns = o.connections.filter((c) => (c.type === "ethernet" || c.type === "wifi") && c.mode !== "ap");
      if (!conns.length) { body.append(el("p", { class: "empty", text: "No Ethernet or Wi-Fi connections found." })); return; }
      body.append(el("p", { class: "muted dm-intro", text: "Give the Pi a fixed (static) address so bookmarks, port-forwards and SSH always find it, or leave it on DHCP. Changes to the connection you're using are applied with a 2-minute safety timer." }));
      conns.forEach((c) => {
        const live = (c.live_addresses[0] || c.addresses[0] || "");
        const s = { method: c.method === "manual" ? "manual" : "auto", address: c.addresses[0] || live, gateway: c.gateway_cfg || c.live_gateway || (o.gateway && o.gateway.ip) || "", dns: (c.dns_cfg.length ? c.dns_cfg : []).join(", ") };
        const mine = c.device && c.device === o.panel_iface;
        const addr = el("input", { type: "text", value: s.address, placeholder: "192.168.0.50/24", oninput: (e) => { s.address = e.target.value; } });
        const gw = el("input", { type: "text", value: s.gateway, placeholder: "192.168.0.1", oninput: (e) => { s.gateway = e.target.value; } });
        const dns = el("input", { type: "text", value: s.dns, placeholder: "empty = use the router's DNS", oninput: (e) => { s.dns = e.target.value; } });
        const staticBox = el("div", { class: "dm-row2 net-static" }, [el("label", { class: "cw-lbl" }, ["IP address / prefix", addr]), el("label", { class: "cw-lbl" }, ["Gateway (router)", gw])]);
        const segm = el("div", { class: "cw-seg cw-seg-sm" }, [["auto", "DHCP (automatic)"], ["manual", "Static IP"]].map(([m, l]) => el("button", { type: "button", class: s.method === m ? "active" : "", text: l, onclick: (e) => {
          s.method = m; segm.querySelectorAll("button").forEach((b) => b.classList.toggle("active", b === e.target)); staticBox.classList.toggle("dm-dim", m !== "manual");
        } })));
        staticBox.classList.toggle("dm-dim", s.method !== "manual");
        const save = el("button", { class: "btn btn-primary", onclick: async () => {
          if (mine && !confirmInline(`You're using ${c.device} right now.\n\nThe change is applied and you'll have 2 minutes to confirm it. If the panel can't be reached, the old settings come back automatically.\n\nApply?`)) return;
          save.disabled = true;
          try {
            const r = await API.netIPv4({ uuid: c.uuid, method: s.method, address: s.address.trim(), gateway: s.gateway.trim(), dns: s.dns.split(/[\s,]+/).filter(Boolean) });
            toast(r.pending ? "Applied, confirm to keep it" : "Applied", "good");
            pollPending($("#net-pending"), r.pending);
            if (r.pending && r.pending.new_url) setTimeout(() => { location.href = r.pending.new_url; }, 4500);
          } catch (e) { toast(e.message, "bad"); }
          save.disabled = false;
        } }, [icon("backup", 13), " Apply"]);
        body.append(netCard(c.type === "wifi" ? "wifi" : "network", `${c.name}`, `${c.device || "not active"} · now ${live || "no address"} · ${c.method === "manual" ? "static" : "DHCP"}`,
          mine ? el("div", { class: "dm-note" }, [icon("link", 15), el("span", { text: "You're connected to the panel through this connection." })]) : null,
          segm, staticBox,
          el("label", { class: "cw-lbl" }, ["DNS servers", dns, el("div", { class: "zn-presets" }, DNS_PRESETS.map(([l, v]) => el("button", { type: "button", class: "cw-chip", text: l, onclick: () => { dns.value = v; s.dns = v; } })))]),
          el("div", { class: "cw-actions" }, save)));
      });
    }).catch((e) => { body.innerHTML = ""; body.append(el("p", { class: "empty", text: e.message })); });
  }

  // ---- Hotspot ----
  function netHotspotTab(body) {
    body.append(el("div", { class: "loading", text: "Loading…" }));
    Promise.all([API.netHotspot(), API.netOverview(), API.netWifi(false).catch(() => ({ devices: [] }))]).then(([h, o, wf]) => {
      body.innerHTML = "";
      const devs = wf.devices.length ? wf.devices : ["wlan0"];
      const f = { ssid: h.ssid || `${o.hostname}-hotspot`, password: "", device: devs.find((d) => d !== o.panel_iface) || devs[0], band: "bg" };
      const blocked = f.device === o.panel_iface;
      const status = h.active ? el("div", { class: "dm-note good" }, [icon("wifi", 15), el("span", { html: `Hotspot <b>${esc(h.ssid || "")}</b> is on (${esc(h.device || "")}${h.address ? ", " + esc(h.address) : ""}). Devices that join get internet through the Pi's other connection.` }),
        el("button", { class: "btn btn-sm", text: "Stop hotspot", onclick: async () => { try { await API.netHotspotStop(); toast("Hotspot stopped", "good"); netHotspotTab((body.innerHTML = "", body)); } catch (e) { toast(e.message, "bad"); } } })]) : null;
      const ss = el("input", { type: "text", value: f.ssid, oninput: (e) => { f.ssid = e.target.value; } });
      const pw = el("input", { type: "text", placeholder: "8–63 characters", oninput: (e) => { f.password = e.target.value; } });
      const dev = el("select", { onchange: (e) => { f.device = e.target.value; } }, devs.map((d) => el("option", { value: d, text: d + (d === o.panel_iface ? " (you're using this)" : "") }))); dev.value = f.device;
      const band = el("select", { onchange: (e) => { f.band = e.target.value; } }, [el("option", { value: "bg", text: "2.4 GHz (best range)" }), el("option", { value: "a", text: "5 GHz (faster)" })]);
      body.append(status, netCard("wifi", "Turn the Pi into a Wi-Fi hotspot", "Great for travel, workshops or setting up gadgets with no router around.",
        blocked ? el("div", { class: "dm-note" }, [icon("error", 15), el("span", { text: `You're reaching the panel through ${f.device}. A Wi-Fi chip can't be a hotspot and a client at the same time, plug in Ethernet or add a USB Wi-Fi adapter first.` })]) : null,
        el("div", { class: "dm-row2" }, [el("label", { class: "cw-lbl" }, ["Hotspot name", ss]), el("label", { class: "cw-lbl" }, ["Password", el("div", { class: "wp-pw" }, [pw, el("button", { type: "button", class: "btn btn-sm", text: "Generate", onclick: async () => { const r = await API.appPassword(); pw.value = r.password.replace(/[^A-Za-z0-9]/g, "").slice(0, 16); f.password = pw.value; } })])])]),
        el("div", { class: "dm-row2" }, [el("label", { class: "cw-lbl" }, ["Wi-Fi adapter", dev]), el("label", { class: "cw-lbl" }, ["Band", band])]),
        el("div", { class: "cw-actions" }, el("button", { class: "btn btn-primary", onclick: async () => {
          try { await API.netHotspotStart(f); toast("Hotspot started", "good"); body.innerHTML = ""; netHotspotTab(body); } catch (e) { toast(e.message, "bad"); }
        } }, [icon("wifi", 13), h.active ? " Restart hotspot" : " Start hotspot"]))));
    }).catch((e) => { body.innerHTML = ""; body.append(el("p", { class: "empty", text: e.message })); });
  }

  // ---- Devices on LAN ----
  function netDevicesTab(body) {
    const box = el("div", {}, el("div", { class: "loading", text: "Looking around the network…" }));
    body.append(el("div", { class: "dm-bar" }, [el("span", { class: "muted", text: "Devices the Pi has talked to recently (ARP/neighbour table), with names where the network provides them." }), el("span", { class: "grow" }),
      el("button", { class: "btn btn-sm", onclick: () => { box.innerHTML = '<div class="loading">Refreshing…</div>'; load(); } }, [icon("refresh", 12), " Refresh"])]), box);
    const load = () => API.netNeighbours().then((d) => {
      box.innerHTML = "";
      if (!d.devices.length) { box.append(el("p", { class: "empty", text: "No neighbours seen yet." })); return; }
      box.append(el("div", { class: "dm-count muted", text: `${d.devices.length} device(s)` }), simpleTable(["IP address", "Name", "Vendor", "MAC", "Status"], d.devices.map((x) => el("tr", {}, [
        el("td", {}, el("code", { text: x.ip })), el("td", { text: x.hostname || ", " }), el("td", { class: "muted", text: x.vendor || ", " }),
        el("td", { class: "muted" }, el("code", { text: x.mac })),
        el("td", {}, el("span", { class: `pill ${x.state === "reachable" ? "good" : "dim"}`, text: x.state === "reachable" ? "online" : "seen recently" })),
      ]))));
    }).catch((e) => { box.innerHTML = ""; box.append(el("p", { class: "empty", text: e.message })); });
    load();
  }

  // ---- Open ports ----
  const PORT_HINTS = { 22: "SSH", 53: "DNS", 80: "HTTP (web)", 443: "HTTPS (web)", 3306: "MariaDB", 5432: "PostgreSQL", 8088: "AuroraPanel", 139: "Samba", 445: "Samba", 137: "Samba names", 138: "Samba", 5353: "mDNS / .local", 111: "rpcbind", 631: "Printing (CUPS)", 25: "Mail (SMTP)", 953: "BIND control", 3389: "Remote desktop", 5900: "VNC" };
  function netPortsTab(body) {
    const box = el("div", {}, el("div", { class: "loading", text: "Listing listening ports…" }));
    body.append(el("p", { class: "muted dm-intro", html: "Programs waiting for connections. Anything on <b>all interfaces</b> can be reached from your network, close what you don't use, or limit it with the Firewall." }), box);
    API.netPorts().then((d) => {
      box.innerHTML = "";
      box.append(simpleTable(["Port", "Protocol", "What it is", "Program", "Reachable from"], d.ports.map((p) => el("tr", {}, [
        el("td", {}, el("b", { text: p.port })), el("td", { class: "muted", text: p.proto.toUpperCase() }), el("td", { text: PORT_HINTS[p.port] || ", " }),
        el("td", {}, el("code", { text: p.process })),
        el("td", {}, el("span", { class: `pill ${p.scope === "all interfaces" ? "warn" : p.scope === "this machine only" ? "good" : "dim"}`, text: p.scope })),
      ]))));
    }).catch((e) => { box.innerHTML = ""; box.append(el("p", { class: "empty", text: e.message })); });
  }

  // ---- Hostname ----
  function netHostTab(body) {
    API.netOverview().then((o) => {
      const i = el("input", { type: "text", value: o.hostname });
      body.append(netCard("home", "Hostname", "The Pi's name on your network. With mDNS you can reach it as name.local from most computers and phones.",
        el("label", { class: "cw-lbl" }, ["Hostname", i, el("span", { class: "dm-hint", text: "Letters, digits and hyphens. /etc/hosts is updated too." })]),
        el("div", { class: "cw-actions" }, el("button", { class: "btn btn-primary", onclick: async () => {
          try { const r = await API.netHostname(i.value); toast(`Renamed to ${r.hostname}, now ${r.mdns}`, "good"); $("#host-badge").textContent = r.hostname; } catch (e) { toast(e.message, "bad"); }
        } }, [icon("backup", 13), " Save hostname"]))));
    }).catch((e) => body.append(el("p", { class: "empty", text: e.message })));
  }

  function netLegacy(root) {
    // Ping tool
    const ping = el("div", { class: "card", style: "margin-bottom:16px" }, [
      el("h3", { text: "Network test, ping" }),
      el("div", { class: "toolbar", style: "margin:0" }, [
        el("input", { id: "ping-host", type: "text", placeholder: "host or IP (e.g. google.com)", value: "8.8.8.8", style: "flex:1;min-width:200px", onkeydown: (e) => { if (e.key === "Enter") doPing(); } }),
        el("button", { class: "btn btn-sm btn-primary", text: "Ping", onclick: doPing }),
        el("button", { class: "btn btn-sm", text: "Traceroute", onclick: () => navigate("dns") }),
      ]),
      el("div", { id: "ping-out", style: "margin-top:12px" }),
    ]);
    const tiles = el("div", { class: "gauge-row", id: "net-tiles" });
    const chart = el("div", { class: "chart-row", id: "net-chart", style: "grid-template-columns:1fr;margin-bottom:16px" });
    const body = el("div", { id: "net-body" }, el("div", { class: "loading", text: "Loading…" }));
    root.append(ping, tiles, chart, body);

    let prev = null, prevT = 0;
    const load = async () => {
      await guardedLoad(async () => {
        const data = await API.network();
        const now = Date.now();
        // Aggregate totals across interfaces (skip loopback).
        let rx = 0, tx = 0;
        data.interfaces.forEach((n) => { if (n.name !== "lo") { rx += n.bytes_recv; tx += n.bytes_sent; } });
        let rxRate = 0, txRate = 0;
        if (prev && now > prevT) { const dt = (now - prevT) / 1000; rxRate = Math.max(0, (rx - prev.rx) / dt); txRate = Math.max(0, (tx - prev.tx) / dt); }
        prev = { rx, tx }; prevT = now;
        netHist.rx.push(rxRate); netHist.tx.push(txRate);
        if (netHist.rx.length > 40) { netHist.rx.shift(); netHist.tx.shift(); }

        tiles.innerHTML = "";
        tiles.append(netStat("Download", "↓", "#22c9a0", rxRate, rx));
        tiles.append(netStat("Upload", "↑", "#5aa2ff", txRate, tx));
        // throughput chart (scale to max)
        chart.innerHTML = "";
        chart.append(throughputChart(netHist));

        body.innerHTML = "";
        const rows = data.interfaces.map((n) => el("tr", {}, [
          el("td", { text: n.name }),
          el("td", {}, el("span", { class: `pill ${n.is_up ? "good" : "dim"}`, text: n.is_up ? "up" : "down" })),
          el("td", { class: "muted", text: n.ipv4 || ", " }),
          el("td", { class: "muted", text: n.mac || ", " }),
          el("td", { text: fmtBytes(n.bytes_recv) }),
          el("td", { text: fmtBytes(n.bytes_sent) }),
          el("td", { class: "muted", text: n.speed_mbps ? `${n.speed_mbps} Mbps` : ", " }),
        ]));
        body.append(el("div", { class: "table-wrap" }, el("table", {}, [
          el("thead", {}, el("tr", {}, ["Interface", "State", "IPv4", "MAC", "↓ Recv", "↑ Sent", "Speed"].map((h) => el("th", { text: h })))),
          el("tbody", {}, rows),
        ])));
      });
    };
    async function doPing() {
      const host = $("#ping-host").value.trim(); if (!host) return;
      $("#ping-out").innerHTML = '<div class="loading">Pinging…</div>';
      try {
        const r = await API.ping(host);
        $("#ping-out").innerHTML = "";
        $("#ping-out").append(el("div", { style: "display:flex;gap:10px;margin-bottom:10px;flex-wrap:wrap" }, [
          el("span", { class: `pill ${r.loss_pct === 0 ? "good" : r.loss_pct === 100 ? "bad" : "warn"}`, text: `${r.loss_pct != null ? r.loss_pct : "?"}% loss` }),
          r.avg_ms != null ? el("span", { class: "pill dim", text: `avg ${r.avg_ms} ms` }) : null,
        ]));
        $("#ping-out").append(el("pre", { class: "log", text: r.output }));
      } catch (e) { $("#ping-out").innerHTML = ""; toast(e.message, "bad"); }
    }
    const timer = setInterval(load, 2000);
    (state.cleanups = state.cleanups || []).push(() => clearInterval(timer));
    state.refreshHandler = load;
    load();
  }
  function netStat(title, arrow, color, rate, total) {
    const hist = (title === "Download" ? netHist.rx : netHist.tx);
    const card = el("div", { class: "card scard" });
    card.innerHTML = `
      <div class="scard-head"><span class="scard-ico" style="color:${color};background:color-mix(in srgb, ${color} 16%, transparent);font-weight:800">${arrow}</span><span class="scard-title">${title}</span></div>
      <div class="scard-main"><div><div class="scard-val">${fmtBytes(rate)}<span class="scard-unit">/s</span></div>
      <div class="scard-delta flat"><span class="scard-subtxt">total ${fmtBytes(total)}</span></div></div>
      ${sparklineSvg(hist, color)}</div>`;
    return card;
  }
  function throughputChart(h) {
    const W = 100, H = 40;
    const all = h.rx.concat(h.tx);
    const max = Math.max(1, ...all);
    const line = (data, color) => {
      if (data.length < 2) return "";
      const pts = data.map((v, i) => `${(i / (data.length - 1) * W).toFixed(2)},${(H - (v / max) * (H - 2)).toFixed(2)}`).join(" ");
      return `<polyline points="${pts}" fill="none" stroke="${color}" stroke-width="1.6" vector-effect="non-scaling-stroke" stroke-linejoin="round"/>`;
    };
    const card = el("div", { class: "card chart-card" });
    card.innerHTML = `<div class="chart-head"><span class="chart-title">Live throughput</span>
      <span style="font-size:12px"><span style="color:#22c9a0">↓ ${fmtBytes(h.rx[h.rx.length-1]||0)}/s</span>&nbsp;&nbsp;<span style="color:#5aa2ff">↑ ${fmtBytes(h.tx[h.tx.length-1]||0)}/s</span></span></div>
      <svg class="chart-svg" style="height:80px" viewBox="0 0 ${W} ${H}" preserveAspectRatio="none">
        ${[0.25,0.5,0.75].map(g=>`<line x1="0" y1="${(H*g).toFixed(1)}" x2="${W}" y2="${(H*g).toFixed(1)}" stroke="rgba(150,180,220,0.09)" stroke-width="0.5" vector-effect="non-scaling-stroke"/>`).join("")}
        ${line(h.rx, "#22c9a0")}${line(h.tx, "#5aa2ff")}</svg>`;
    return card;
  }

  // ======================================================================
  //  Shared: background-job output panel
  // ======================================================================
  function jobPanel(root) {
    // A running job shows a bar (progress when the job reports it, a sliding orange bar when it doesn't) and one line of
    // status; the full output sits under "Details", opened on request, or automatically when the job fails.
    const panel = el("div", { class: "card jp", style: "margin-top:16px", hidden: true });
    const title = el("h3", {});
    const pre = el("pre", { class: "log" });
    const bar = el("div", { class: "ax-bar" }, el("span"));
    const stage = el("div", { class: "ax-stage" });
    const prog = el("div", { class: "ax-progress", style: "margin-bottom:10px" }, [stage, bar]);
    const sum = el("summary", { text: "Details" });
    const details = el("details", { class: "jp-details" }, [sum, pre]);
    panel.append(title, prog, details);
    root.append(panel);

    let timer = null;
    const stop = () => { if (timer) { clearInterval(timer); timer = null; } };
    return {
      async run(jobId, label) {
        stop();
        panel.hidden = false;
        title.textContent = label || "Working…";
        pre.textContent = "Starting…";
        prog.classList.remove("ok", "bad"); bar.classList.add("indet"); bar.firstChild.style.width = "";
        details.open = false; sum.textContent = "Details";
        stage.innerHTML = ""; stage.append(el("span", { class: "bk-spin" }), el("b", { text: "Starting…" }));
        const tick = async () => {
          try {
            const j = await API.job(jobId);
            pre.textContent = j.output || "(no output yet)";
            if (details.open) pre.scrollTop = pre.scrollHeight;
            const running = j.status === "running", done = j.status === "done";
            title.textContent = j.title || label || "Working…";
            const known = j.progress != null;
            const pct = done ? 100 : known ? j.progress : running ? null : 100;
            bar.classList.toggle("indet", pct == null);
            bar.firstChild.style.width = pct == null ? "" : `${Math.max(2, pct)}%`;
            prog.classList.toggle("ok", done); prog.classList.toggle("bad", !running && !done);
            stage.innerHTML = "";
            stage.append(...[running ? el("span", { class: "bk-spin" }) : el("span", { class: `bk-badge ${done ? "good" : "bad"}`, text: done ? "✓" : "!" }),
              el("b", { text: running ? j.stage || "Working…" : done ? "Finished" : "Failed" }),
              known && running ? el("span", { class: "bk-pct", text: `${Math.floor(pct)}%` }) : null,
              !running ? el("span", { class: "muted", style: "font-size:12px", text: `exit ${j.returncode}` }) : null].filter(Boolean));
            const n = (j.output || "").split("\n").filter(Boolean).length;
            sum.textContent = `Details · ${n} line${n === 1 ? "" : "s"}`;
            if (!running) {
              stop();
              if (!done) details.open = true;
              toast(`${j.title}: ${j.status}`, done ? "good" : "bad");
            }
          } catch (err) { stop(); toast(err.message, "bad"); }
        };
        await tick();
        timer = setInterval(tick, 1300);
      },
      stop,
    };
  }

  // ======================================================================
  //  Terminal (xterm.js over WebSocket PTY)
  // ======================================================================
  const termCtx = {};
  function viewTerminal(root) {
    const note = el("p", { class: "muted", style: "margin:0 0 12px",
      text: "Live shell on the Pi (runs as the panel's user). Type 'exit' or leave the tab to end the session." });
    const host = el("div", { id: "term-host", style: "height:70vh;border:1px solid var(--border);border-radius:10px;overflow:hidden;background:#000;padding:6px" });
    root.append(note, host);

    if (typeof Terminal === "undefined") {
      host.innerHTML = '<p class="empty">Terminal library failed to load.</p>';
      return;
    }
    const term = new Terminal({
      cursorBlink: true, fontSize: 13, fontFamily: '"Cascadia Code","Consolas",monospace',
      theme: { background: "#000000", foreground: "#e6edf3" },
    });
    let fit = null;
    try { fit = new FitAddon.FitAddon(); term.loadAddon(fit); } catch (e) {}
    term.open(host);
    if (fit) { try { fit.fit(); } catch (e) {} }

    const proto = location.protocol === "https:" ? "wss" : "ws";
    const ws = new WebSocket(`${proto}://${location.host}/api/terminal/ws`);
    const sendResize = () => {
      if (ws.readyState === 1) ws.send(JSON.stringify({ type: "resize", cols: term.cols, rows: term.rows }));
    };
    ws.onopen = () => { term.focus(); sendResize(); };
    ws.onmessage = (ev) => {
      try {
        const msg = JSON.parse(ev.data);
        if (msg.type === "output") term.write(msg.data);
        else if (msg.type === "exit") term.write("\r\n\x1b[90m[session ended]\x1b[0m\r\n");
      } catch (e) {}
    };
    ws.onclose = () => { try { term.write("\r\n\x1b[90m[disconnected]\x1b[0m\r\n"); } catch (e) {} };
    term.onData((d) => { if (ws.readyState === 1) ws.send(JSON.stringify({ type: "input", data: d })); });
    const onResize = () => { if (fit) { try { fit.fit(); } catch (e) {} } sendResize(); };
    window.addEventListener("resize", onResize);

    termCtx.dispose = () => {
      window.removeEventListener("resize", onResize);
      try { ws.close(); } catch (e) {}
      try { term.dispose(); } catch (e) {}
      termCtx.dispose = null;
    };
    setTimeout(onResize, 60);
  }

  // ======================================================================
  //  Packages (apt)
  // ======================================================================
  function viewPackages(root) {
    const tabs = el("div", { class: "toolbar" }, [
      el("button", { class: "btn btn-sm", text: "↻ Update lists", onclick: () => runPkgJob(API.pkgUpdate(), "apt update") }),
      el("button", { class: "btn btn-sm btn-primary", text: "⬆ Upgrade all", onclick: () => confirmInline("Upgrade all upgradable packages?") && runPkgJob(API.pkgUpgrade(), "apt upgrade") }),
    ]);
    const searchBar = el("div", { class: "toolbar" }, [
      el("input", { id: "pkg-q", type: "text", placeholder: "Search apt packages…", style: "max-width:320px",
        onkeydown: (e) => { if (e.key === "Enter") doSearch(); } }),
      el("button", { class: "btn btn-sm", text: "Search", onclick: () => doSearch() }),
    ]);
    const upg = el("div", { class: "card", style: "margin-bottom:16px" }, el("div", { class: "loading", text: "Loading upgradable…" }));
    const results = el("div", {});
    root.append(tabs, upg, searchBar, results);
    const jp = jobPanel(root);

    async function runPkgJob(promise, label) {
      try { const r = await promise; jp.run(r.job, label); }
      catch (err) { toast(err.message, "bad"); }
    }
    window.__pkgJob = runPkgJob;

    const loadUpg = async () => {
      await guardedLoad(async () => {
        upg.innerHTML = ""; upg.append(el("h3", { text: "Upgradable packages" }));
        let data;
        try { data = await API.pkgUpgradable(); }
        catch (e) { upg.append(el("p", { class: "muted", text: e.message })); return; }
        if (!data.packages.length) { upg.append(el("p", { class: "muted", text: "Everything is up to date." })); return; }
        const rows = data.packages.map((p) => el("tr", {}, [
          el("td", { text: p.name }), el("td", { class: "muted", text: p.current }),
          el("td", { text: p.new_version }), el("td", { class: "muted", text: p.arch }),
        ]));
        upg.append(el("div", { class: "table-wrap" }, el("table", {}, [
          el("thead", {}, el("tr", {}, ["Package", "Current", "New", "Arch"].map((h) => el("th", { text: h })))),
          el("tbody", {}, rows),
        ])));
      });
    };

    async function doSearch() {
      const q = $("#pkg-q").value.trim();
      if (!q) return;
      results.innerHTML = '<div class="loading">Searching…</div>';
      try {
        const data = await API.pkgSearch(q);
        results.innerHTML = "";
        if (!data.results.length) { results.append(el("p", { class: "empty", text: "No matches." })); return; }
        const rows = data.results.map((r) => el("tr", {}, [
          el("td", { text: r.name }), el("td", { class: "muted", text: r.summary }),
          el("td", { class: "actions" }, el("button", { class: "btn btn-sm btn-primary", text: "Install",
            onclick: () => confirmInline(`Install ${r.name}?`) && window.__pkgJob(API.pkgInstall([r.name]), `install ${r.name}`) })),
        ]));
        results.append(el("div", { class: "table-wrap" }, el("table", {}, [
          el("thead", {}, el("tr", {}, ["Package", "Summary", ""].map((h) => el("th", { text: h })))),
          el("tbody", {}, rows),
        ])));
      } catch (err) { results.innerHTML = ""; toast(err.message, "bad"); }
    }

    state.refreshHandler = loadUpg;
    loadUpg();
  }

  // ======================================================================
  //  Cron
  // ======================================================================
  // ======================================================================
  //  Cron, expression engine (parse / describe / next runs)
  // ======================================================================
  const CRON_FIELDS = [
    { key: "minute", label: "minute", min: 0, max: 59 },
    { key: "hour", label: "hour", min: 0, max: 23 },
    { key: "dom", label: "day", long: "day-of-month", min: 1, max: 31 },
    { key: "month", label: "month", min: 1, max: 12, names: ["JAN", "FEB", "MAR", "APR", "MAY", "JUN", "JUL", "AUG", "SEP", "OCT", "NOV", "DEC"] },
    { key: "dow", label: "weekday", long: "day-of-week", min: 0, max: 7, names: ["SUN", "MON", "TUE", "WED", "THU", "FRI", "SAT"] },
  ];
  const MONTHS_L = ["January", "February", "March", "April", "May", "June", "July", "August", "September", "October", "November", "December"];
  const DAYS_L = ["Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday"];
  const CRON_MACROS = {
    "@yearly": "0 0 1 1 *", "@annually": "0 0 1 1 *", "@monthly": "0 0 1 * *", "@weekly": "0 0 * * 0",
    "@daily": "0 0 * * *", "@midnight": "0 0 * * *", "@hourly": "0 * * * *",
  };
  const pad2 = (n) => String(n).padStart(2, "0");
  const ordinal = (n) => { const s = ["th", "st", "nd", "rd"], v = n % 100; return n + (s[(v - 20) % 10] || s[v] || s[0]); };
  const joinList = (a) => a.length <= 1 ? a.join("") : a.length === 2 ? `${a[0]} and ${a[1]}` : `${a.slice(0, -1).join(", ")}, and ${a[a.length - 1]}`;
  const topOf = (f) => (f.max === 7 ? 6 : f.max);

  function cronToken(s, f) {
    if (f.names) {
      const i = f.names.indexOf(s.toUpperCase());
      if (i >= 0) return i + (f.key === "month" ? 1 : 0);
    }
    if (!/^\d+$/.test(s)) throw new Error(`"${s}" isn't a valid ${f.long || f.label}`);
    const n = +s;
    if (n < f.min || n > f.max) throw new Error(`${f.long || f.label} must be between ${f.min} and ${f.max}`);
    return n;
  }
  function cronParseField(txt, f) {
    const vals = new Set();
    for (const part of txt.split(",")) {
      if (!part) throw new Error(`Empty value in the ${f.label} field`);
      const bits = part.split("/");
      if (bits.length > 2) throw new Error(`Only one "/" allowed in "${part}"`);
      const [range, step] = bits;
      let st = 1;
      if (step !== undefined) {
        if (!/^\d+$/.test(step) || +step === 0) throw new Error(`"/${step}" isn't a valid step`);
        st = +step;
      }
      let lo, hi;
      if (range === "*") { lo = f.min; hi = topOf(f); }
      else if (range.includes("-")) {
        const [a, b, extra] = range.split("-");
        if (extra !== undefined) throw new Error(`Bad range "${range}"`);
        lo = cronToken(a, f); hi = cronToken(b, f);
        if (lo > hi) throw new Error(`Range ${range} goes backwards`);
      } else { lo = cronToken(range, f); hi = step !== undefined ? topOf(f) : lo; }
      for (let v = lo; v <= hi; v += st) vals.add(f.key === "dow" && v === 7 ? 0 : v);
    }
    return vals;
  }
  function cronParse(expr) {
    const s = (expr || "").trim().replace(/\s+/g, " ");
    if (!s) return { error: "Enter a schedule", parts: [] };
    if (s === "@reboot") return { expr: s, reboot: true, parts: [] };
    if (s.startsWith("@")) {
      if (!CRON_MACROS[s]) return { error: `Unknown shortcut ${s}`, parts: [] };
      return { ...cronParse(CRON_MACROS[s]), expr: s, macro: s };
    }
    const parts = s.split(" ");
    if (parts.length !== 5) return { error: parts.length < 5 ? `Missing fields, need 5, got ${parts.length}` : `Too many fields, need 5, got ${parts.length}`, parts, badField: parts.length > 5 ? 5 : parts.length };
    const sets = [];
    for (let i = 0; i < 5; i++) {
      try { sets.push(cronParseField(parts[i], CRON_FIELDS[i])); }
      catch (e) { return { error: e.message, parts, badField: i }; }
    }
    return { expr: s, parts, sets, domAny: parts[2].startsWith("*"), dowAny: parts[4].startsWith("*") };
  }
  function cronDayOk(p, d) {
    const dom = p.sets[2].has(d.getUTCDate()), dow = p.sets[4].has(d.getUTCDay());
    return (p.domAny || p.dowAny) ? dom && dow : dom || dow;  // Vixie cron OR rule
  }
  // Dates are "server wall-clock" timestamps: read/write with getUTC*/setUTC*.
  function cronNext(p, fromMs, n) {
    const out = [];
    if (!p || p.error || p.reboot) return out;
    const d = new Date(fromMs);
    d.setUTCSeconds(0, 0); d.setUTCMinutes(d.getUTCMinutes() + 1);
    const limit = fromMs + 5 * 366 * 864e5;
    let guard = 0;
    while (out.length < n && d.getTime() < limit && guard++ < 200000) {
      if (!p.sets[3].has(d.getUTCMonth() + 1)) { d.setUTCMonth(d.getUTCMonth() + 1, 1); d.setUTCHours(0, 0, 0, 0); continue; }
      if (!cronDayOk(p, d)) { d.setUTCDate(d.getUTCDate() + 1); d.setUTCHours(0, 0, 0, 0); continue; }
      if (!p.sets[1].has(d.getUTCHours())) { d.setUTCHours(d.getUTCHours() + 1, 0, 0, 0); continue; }
      if (!p.sets[0].has(d.getUTCMinutes())) { d.setUTCMinutes(d.getUTCMinutes() + 1, 0, 0); continue; }
      out.push(new Date(d));
      d.setUTCMinutes(d.getUTCMinutes() + 1, 0, 0);
    }
    return out;
  }
  function cronName(fi, v) { return fi === 3 ? MONTHS_L[v - 1] : fi === 4 ? DAYS_L[v % 7] : String(v); }
  const cronPlain = (txt) => !/[*\/-]/.test(txt);
  function cronFieldPhrase(txt, fi) {
    const f = CRON_FIELDS[fi], unit = f.long || f.label;
    const tok = (s) => cronName(fi, cronToken(s, f) % (fi === 4 ? 7 : 1000));
    if (cronPlain(txt)) return (fi >= 3 ? "" : unit + " ") + joinList(txt.split(",").map(tok));
    return joinList(txt.split(",").map((part) => {
      const [range, step] = part.split("/");
      const every = step ? `every ${ordinal(+step)} ${unit}` : `every ${unit}`;
      if (range === "*") return every;
      if (range.includes("-")) { const [a, b] = range.split("-"); return `${every} from ${tok(a)} through ${tok(b)}`; }
      if (step) return `${every} from ${tok(range)} through ${cronName(fi, topOf(f))}`;
      return tok(range);
    }));
  }
  function cronDescribe(p) {
    if (!p || p.error) return null;
    if (p.reboot) return "At system startup.";
    const [mi, h, dom, mon, dow] = p.parts;
    let s;
    if (cronPlain(mi) && cronPlain(h)) {
      const ms = mi.split(",").map(Number), hs = h.split(",").map(Number);
      s = ms.length * hs.length <= 4
        ? "At " + joinList(hs.flatMap((hh) => ms.map((mm) => `${pad2(hh)}:${pad2(mm)}`)))
        : `At minute ${joinList(ms.map(String))} past hour ${joinList(hs.map(String))}`;
    } else if (mi === "*" && h === "*") s = "At every minute";
    else {
      s = "At " + cronFieldPhrase(mi, 0);
      if (h !== "*") s += " past " + cronFieldPhrase(h, 1);
    }
    const days = [];
    if (dom !== "*") days.push("on " + cronFieldPhrase(dom, 2));
    if (dow !== "*") days.push("on " + cronFieldPhrase(dow, 4));
    if (days.length) s += " " + days.join(" and ");
    if (mon !== "*") s += " in " + cronFieldPhrase(mon, 3);
    return s + ".";
  }
  function cronRandom() {
    const r = (n) => Math.floor(Math.random() * n);
    const pick = (a) => a[r(a.length)];
    return pick([
      () => `${r(60)} ${r(24)} * * *`,
      () => `*/${pick([5, 10, 15, 20, 30])} * * * *`,
      () => `${r(60)} ${r(24)} * * ${r(7)}`,
      () => `${pick([0, 15, 30, 45])} ${8 + r(10)} * * 1-5`,
      () => `${r(60)} ${r(24)} ${1 + r(28)} * *`,
      () => `${r(60)} */${pick([2, 3, 4, 6, 12])} * * *`,
      () => `0 ${r(24)} 1 */${pick([2, 3, 6])} *`,
      () => `${r(60)} ${r(24)} * * 6,0`,
    ])();
  }
  const cronState = { offMin: -new Date().getTimezoneOffset(), tz: "" };
  const cronNow = () => Date.now() + cronState.offMin * 60000;
  const cronFmt = (d, opts) => d.toLocaleString([], { timeZone: "UTC", ...opts });
  function cronRel(ms) {
    const m = Math.round(ms / 60000);
    if (m < 1) return "in under a minute";
    if (m < 60) return `in ${m} min`;
    const h = Math.floor(m / 60), mm = m % 60;
    if (h < 24) return `in ${h}h${mm ? " " + mm + "m" : ""}`;
    const d = Math.floor(h / 24), hh = h % 24;
    return `in ${d}d${hh ? " " + hh + "h" : ""}`;
  }
  // cron treats a bare % in the command as a newline, escape it.
  const cronEscape = (cmd) => cmd.replace(/(^|[^\\])%/g, "$1\\%").replace(/(^|[^\\])%/g, "$1\\%");

  // ======================================================================
  //  Cron Jobs view, wizard + job list
  // ======================================================================
  const CRON_PRESETS = [
    ["Every minute", "* * * * *"], ["Every 5 min", "*/5 * * * *"], ["Every 15 min", "*/15 * * * *"],
    ["Hourly", "0 * * * *"], ["Daily at midnight", "0 0 * * *"], ["Daily at 3 AM", "0 3 * * *"],
    ["Weekdays 9 AM", "0 9 * * 1-5"], ["Weekends 10 AM", "0 10 * * 6,0"], ["Sundays 4 AM", "0 4 * * 0"],
    ["1st of month", "0 0 1 * *"], ["Every quarter", "0 0 1 */3 *"], ["At boot", "@reboot"],
  ];
  const CRON_TEMPLATES = [
    { icon: "backup", label: "Back up /home", cmd: "mkdir -p /root/aurora-backups && tar -czf /root/aurora-backups/home-$(date +%F).tar.gz /home", sched: "0 3 * * *" },
    { icon: "packages", label: "Refresh package lists", cmd: "apt-get update -qq", sched: "0 4 * * 0" },
    { icon: "lock", label: "Renew SSL certificates", cmd: "certbot renew --quiet", sched: "17 3 * * *" },
    { icon: "services", label: "Restart a service", cmd: "systemctl restart apache2", sched: "0 5 * * 1" },
    { icon: "folder", label: "Clean old /tmp files", cmd: "find /tmp -type f -mtime +7 -delete", sched: "30 2 * * *" },
    { icon: "network", label: "Ping a health-check URL", cmd: "curl -fsS -m 10 --retry 3 https://example.com/health", sched: "*/5 * * * *" },
    { icon: "terminal", label: "Run a script", get cmd() { return `${sysHome()}/scripts/job.sh`; }, sched: "0 * * * *" },
    { icon: "refresh", label: "Weekly reboot", cmd: "/sbin/shutdown -r now", sched: "0 5 * * 0" },
  ];
  const CRON_LEGEND = [
    [["*", "any value"], [",", "value list separator"], ["-", "range of values"], ["/", "step values"], ["0-59", "allowed values"]],
    [["*", "any value"], [",", "value list separator"], ["-", "range of values"], ["/", "step values"], ["0-23", "allowed values"]],
    [["*", "any value"], [",", "value list separator"], ["-", "range of values"], ["/", "step values"], ["1-31", "allowed values"]],
    [["*", "any value"], [",", "value list separator"], ["-", "range of values"], ["/", "step values"], ["1-12", "allowed values"], ["JAN-DEC", "alternative single values"]],
    [["*", "any value"], [",", "value list separator"], ["-", "range of values"], ["/", "step values"], ["0-6", "allowed values"], ["SUN-SAT", "alternative single values"], ["7", "sunday (non-standard)"]],
  ];
  const CRON_MACRO_LEGEND = [["@yearly", "once a year, Jan 1 00:00"], ["@monthly", "1st of the month, 00:00"], ["@weekly", "Sundays at 00:00"], ["@daily", "every day at 00:00"], ["@hourly", "at minute 0 of every hour"], ["@reboot", "once, when the Pi boots"]];

  function viewCron(root) {
    const w = { expr: "5 4 * * *", field: -1, editing: null, output: "keep" };

    const hero = el("div", { class: "cw-hero" });
    hero.innerHTML = `
      <div class="cw-hero-top"><span class="cw-badge">${I("wizard", 14)} Cron wizard</span><span class="cw-tz" id="cw-tz"></span></div>
      <div class="cw-quote" id="cw-desc"></div>
      <div class="cw-next" id="cw-next"></div>
      <div class="cw-editor">
        <button class="cw-tag cw-random" id="cw-random" type="button">${I("refresh", 12)} random</button>
        <input id="cw-expr" class="cw-input" spellcheck="false" autocomplete="off" aria-label="Cron expression" />
        <button class="cw-copy" id="cw-copy" type="button">Copy</button>
      </div>
      <div class="cw-fields" id="cw-fields">${CRON_FIELDS.map((f, i) => `<button type="button" data-f="${i}">${f.label}</button>`).join("")}</div>
      <div class="cw-err" id="cw-err" hidden></div>
      <div class="cw-lower">
        <table class="cw-legend" id="cw-legend"></table>
        <div class="cw-runs"><div class="cw-runs-h">Next runs</div><ol id="cw-runs"></ol></div>
      </div>
      <div class="cw-presets">${CRON_PRESETS.map(([l, e]) => `<button type="button" class="cw-chip" data-e="${esc(e)}">${esc(l)}</button>`).join("")}</div>`;

    // ---- visual builder ----
    const builder = el("div", { class: "card cw-card" });
    const MODES = ["Minutes", "Hourly", "Daily", "Weekly", "Monthly", "Yearly"];
    builder.innerHTML = `<div class="cw-card-h">${I("wizard", 16)}<div><h3>Build it visually</h3><p>Pick a rhythm, the expression updates as you go.</p></div></div>
      <div class="cw-seg" id="cw-modes">${MODES.map((m, i) => `<button type="button" data-m="${i}" class="${i === 2 ? "active" : ""}">${m}</button>`).join("")}</div>
      <div class="cw-build" id="cw-build"></div>`;

    // ---- command ----
    const cmdCard = el("div", { class: "card cw-card" });
    cmdCard.innerHTML = `<div class="cw-card-h">${I("terminal", 16)}<div><h3 id="cw-cmd-h">What should it run?</h3><p>Runs as <b>root</b> on the Pi, from the root crontab.</p></div></div>
      <div class="cw-templates">${CRON_TEMPLATES.map((t, i) => `<button type="button" class="cw-tpl" data-t="${i}">${I(t.icon, 14)}<span>${esc(t.label)}</span></button>`).join("")}</div>
      <label class="cw-lbl"><span>Name<span class="muted">(optional)</span></span><input id="cw-label" type="text" placeholder="e.g. Nightly backup" maxlength="80" /></label>
      <label class="cw-lbl">Command<textarea id="cw-cmd" rows="2" class="cw-mono" placeholder="/usr/bin/python3 ${esc(sysHome())}/script.py" spellcheck="false"></textarea></label>
      <div class="cw-warn" id="cw-pct" hidden>${I("error", 13)} <span>cron treats <code>%</code> as a newline, it will be escaped to <code>\\%</code> automatically.</span></div>
      <div class="cw-lbl">Output</div>
      <div class="cw-seg cw-seg-sm" id="cw-out">
        <button type="button" data-o="keep" class="active">Keep (mail)</button>
        <button type="button" data-o="null">Discard</button>
        <button type="button" data-o="log">Log to file</button>
      </div>
      <div class="cw-lbl">Crontab line</div>
      <pre class="cw-preview" id="cw-preview"></pre>
      <div class="cw-actions">
        <button class="btn btn-ghost" id="cw-cancel" type="button" hidden>Cancel edit</button>
        <button class="btn btn-primary" id="cw-save" type="button">${I("cron", 14)} <span>Schedule job</span></button>
      </div>`;

    const cols = el("div", { class: "cw-cols" }, [builder, cmdCard]);
    const upcoming = el("div", { class: "cw-upcoming", id: "cw-upcoming" });
    const listWrap = el("div", { id: "cron-body" }, el("div", { class: "loading", text: "Loading…" }));
    root.append(hero, cols, el("div", { class: "cw-list-h" }, [el("h2", { class: "section-title", id: "cw-count", text: "Scheduled jobs" })]), upcoming, listWrap);

    const exprIn = $("#cw-expr", hero);
    exprIn.value = w.expr;

    // ---------- hero logic ----------
    function fieldAtCaret() {
      const v = exprIn.value, pos = exprIn.selectionStart ?? v.length;
      if (v.trim().startsWith("@")) return -1;
      const before = v.slice(0, pos).replace(/^\s+/, "");
      return Math.min(4, before.split(/\s+/).length - 1);
    }
    function renderLegend() {
      const lg = $("#cw-legend", hero);
      const rows = w.field >= 0 ? CRON_LEGEND[w.field] : CRON_MACRO_LEGEND;
      lg.innerHTML = rows.map(([k, v]) => `<tr${w.field < 0 ? ` class="cw-macro" data-e="${k}"` : ""}><td>${esc(k)}</td><td>${esc(v)}</td></tr>`).join("");
      hero.querySelectorAll("#cw-fields button").forEach((b) => b.classList.toggle("on", +b.dataset.f === w.field));
    }
    function update(fromInput) {
      if (!fromInput) exprIn.value = w.expr;
      w.expr = exprIn.value;
      const p = cronParse(w.expr);
      w.parsed = p;
      const desc = $("#cw-desc", hero), err = $("#cw-err", hero), next = $("#cw-next", hero), runs = $("#cw-runs", hero);
      hero.classList.toggle("invalid", !!p.error);
      hero.querySelectorAll("#cw-fields button").forEach((b) => b.classList.toggle("bad", p.badField === +b.dataset.f));
      if (p.error) {
        desc.textContent = "“…”"; err.hidden = false; err.textContent = p.error; next.innerHTML = "&nbsp;"; runs.innerHTML = "";
      } else {
        err.hidden = true;
        desc.textContent = `“${cronDescribe(p)}”`;
        const now = cronNow(), list = cronNext(p, now, 6);
        if (p.reboot) { next.textContent = "runs once each time the Pi boots"; runs.innerHTML = `<li class="muted">No clock schedule</li>`; }
        else if (!list.length) { next.textContent = "never matches, check day/month combination"; runs.innerHTML = ""; }
        else {
          next.innerHTML = `next at <b>${esc(cronFmt(list[0], { year: "numeric", month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit", hour12: false }))}</b> · ${cronRel(list[0] - now)}`;
          runs.innerHTML = list.map((d) => `<li><span>${esc(cronFmt(d, { weekday: "short", month: "short", day: "numeric" }))}</span><b>${esc(cronFmt(d, { hour: "2-digit", minute: "2-digit", hour12: false }))}</b></li>`).join("");
        }
      }
      renderPreview();
    }
    exprIn.addEventListener("input", () => { w.field = fieldAtCaret(); renderLegend(); update(true); });
    ["click", "keyup", "focus"].forEach((ev) => exprIn.addEventListener(ev, () => { w.field = fieldAtCaret(); renderLegend(); }));
    hero.addEventListener("click", (e) => {
      const fb = e.target.closest("#cw-fields button");
      if (fb) { // select that field's text in the input
        const i = +fb.dataset.f, v = exprIn.value; const re = /\S+/g; let m, k = 0;
        while ((m = re.exec(v))) { if (k++ === i) { exprIn.focus(); exprIn.setSelectionRange(m.index, m.index + m[0].length); break; } }
        w.field = i; renderLegend(); return;
      }
      const chip = e.target.closest("[data-e]");
      if (chip) { w.expr = chip.dataset.e; update(); exprIn.focus(); w.field = fieldAtCaret(); renderLegend(); }
    });
    $("#cw-random", hero).addEventListener("click", () => { w.expr = cronRandom(); update(); });
    $("#cw-copy", hero).addEventListener("click", async () => {
      try { await navigator.clipboard.writeText(exprIn.value.trim()); toast("Copied", "good"); }
      catch (e) { exprIn.select(); document.execCommand("copy"); toast("Copied", "good"); }
    });

    // ---------- builder ----------
    const hourOpts = (sel) => Array.from({ length: 24 }, (_, h) => `<option value="${h}" ${h === sel ? "selected" : ""}>${pad2(h)}</option>`).join("");
    const minOpts = (sel, stepv) => Array.from({ length: 60 / (stepv || 1) }, (_, i) => i * (stepv || 1)).map((m) => `<option value="${m}" ${m === sel ? "selected" : ""}>${pad2(m)}</option>`).join("");
    const timePick = (h, m) => `<span class="cw-time"><select data-k="h">${hourOpts(h)}</select><b>:</b><select data-k="m">${minOpts(m)}</select></span>`;
    let mode = 2;
    function renderBuilder() {
      const b = $("#cw-build", builder);
      const days = [1, 2, 3, 4, 5, 6, 0];
      b.innerHTML = [
        `<div class="cw-row">Every <select data-k="n">${[1, 2, 3, 5, 10, 15, 20, 30].map((n) => `<option value="${n}" ${n === 5 ? "selected" : ""}>${n}</option>`).join("")}</select> minute(s)</div>`,
        `<div class="cw-row">Every <select data-k="n">${[1, 2, 3, 4, 6, 8, 12].map((n) => `<option value="${n}">${n}</option>`).join("")}</select> hour(s), at minute <select data-k="m">${minOpts(0)}</select></div>`,
        `<div class="cw-row">Every day at ${timePick(3, 0)}</div><div class="cw-row cw-sub"><label class="cw-check"><input type="checkbox" data-k="wd" /> Weekdays only (Mon–Fri)</label></div>`,
        `<div class="cw-row">On</div><div class="cw-days">${days.map((d) => `<button type="button" data-d="${d}" class="${d === 1 ? "on" : ""}">${DAYS_L[d].slice(0, 3)}</button>`).join("")}</div><div class="cw-row">at ${timePick(9, 0)}</div>`,
        `<div class="cw-row">On day <select data-k="dom">${Array.from({ length: 31 }, (_, i) => `<option value="${i + 1}">${ordinal(i + 1)}</option>`).join("")}</select> of every <select data-k="every">${[[1, "month"], [2, "2 months"], [3, "3 months"], [6, "6 months"]].map(([v, l]) => `<option value="${v}">${l}</option>`).join("")}</select></div><div class="cw-row">at ${timePick(0, 0)}</div>`,
        `<div class="cw-row">Every year on <select data-k="mon">${MONTHS_L.map((m, i) => `<option value="${i + 1}">${m}</option>`).join("")}</select> <select data-k="dom">${Array.from({ length: 31 }, (_, i) => `<option value="${i + 1}">${i + 1}</option>`).join("")}</select></div><div class="cw-row">at ${timePick(0, 0)}</div>`,
      ][mode];
      b.querySelectorAll(".cw-days button").forEach((x) => x.addEventListener("click", () => { x.classList.toggle("on"); fromBuilder(); }));
      b.querySelectorAll("select, input").forEach((x) => x.addEventListener("change", fromBuilder));
      fromBuilder();
    }
    function fromBuilder() {
      const b = $("#cw-build", builder), v = (k) => { const x = b.querySelector(`[data-k="${k}"]`); return x ? (x.type === "checkbox" ? x.checked : +x.value) : null; };
      const h = v("h"), m = v("m");
      let e;
      if (mode === 0) e = v("n") === 1 ? "* * * * *" : `*/${v("n")} * * * *`;
      else if (mode === 1) e = `${m} ${v("n") === 1 ? "*" : "*/" + v("n")} * * *`;
      else if (mode === 2) e = `${m} ${h} * * ${v("wd") ? "1-5" : "*"}`;
      else if (mode === 3) {
        const ds = [...b.querySelectorAll(".cw-days button.on")].map((x) => +x.dataset.d).sort((a, c) => a - c);
        e = `${m} ${h} * * ${ds.length && ds.length < 7 ? ds.join(",") : "*"}`;
        if (ds.join(",") === "1,2,3,4,5") e = `${m} ${h} * * 1-5`;
      } else if (mode === 4) e = `${m} ${h} ${v("dom")} ${v("every") === 1 ? "*" : "*/" + v("every")} *`;
      else e = `${m} ${h} ${v("dom")} ${v("mon")} *`;
      w.expr = e; update();
    }
    $("#cw-modes", builder).addEventListener("click", (e) => {
      const b = e.target.closest("button"); if (!b) return;
      mode = +b.dataset.m;
      builder.querySelectorAll("#cw-modes button").forEach((x) => x.classList.toggle("active", x === b));
      renderBuilder();
    });

    // ---------- command ----------
    const cmdIn = $("#cw-cmd", cmdCard), labelIn = $("#cw-label", cmdCard);
    const slug = () => (labelIn.value.trim() || cmdIn.value.trim().split(/\s+/)[0].split("/").pop() || "job").toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "").slice(0, 40) || "job";
    function finalCommand() {
      let c = cronEscape(cmdIn.value.trim());
      if (!c) return "";
      if (w.output === "null") c += " >/dev/null 2>&1";
      else if (w.output === "log") c += ` >> /var/log/aurora-cron-${slug()}.log 2>&1`;
      return c;
    }
    function renderPreview() {
      const pv = $("#cw-preview", cmdCard); if (!pv) return;
      $("#cw-pct", cmdCard).hidden = !/(^|[^\\])%/.test(cmdIn.value);
      const lab = labelIn.value.trim(), c = finalCommand();
      const sched = (w.parsed && !w.parsed.error) ? w.expr.trim().replace(/\s+/g, " ") : "<schedule>";
      pv.innerHTML = (lab ? `<span class="c-com"># aurora: ${esc(lab)}</span>\n` : "") + `<span class="c-sch">${esc(sched)}</span> ${c ? esc(c) : '<span class="muted">&lt;command&gt;</span>'}`;
      $("#cw-save", cmdCard).disabled = !(w.parsed && !w.parsed.error && c);
    }
    [cmdIn, labelIn].forEach((x) => x.addEventListener("input", renderPreview));
    $("#cw-out", cmdCard).addEventListener("click", (e) => {
      const b = e.target.closest("button"); if (!b) return;
      w.output = b.dataset.o;
      cmdCard.querySelectorAll("#cw-out button").forEach((x) => x.classList.toggle("active", x === b));
      renderPreview();
    });
    cmdCard.querySelector(".cw-templates").addEventListener("click", (e) => {
      const b = e.target.closest(".cw-tpl"); if (!b) return;
      const t = CRON_TEMPLATES[+b.dataset.t];
      cmdIn.value = t.cmd; labelIn.value = t.label; w.expr = t.sched; update();
      cmdIn.focus();
    });
    function splitOutput(cmd) {
      let m;
      if ((m = cmd.match(/^(.*?)\s*>\s*\/dev\/null\s+2>&1\s*$/))) return { cmd: m[1], output: "null" };
      if ((m = cmd.match(/^(.*?)\s*>>\s*\/var\/log\/aurora-cron-[\w-]+\.log\s+2>&1\s*$/))) return { cmd: m[1], output: "log" };
      return { cmd, output: "keep" };
    }
    function loadIntoWizard(j, asCopy) {
      const so = splitOutput(j.command);
      cmdIn.value = so.cmd.replace(/\\%/g, "%");
      labelIn.value = (j.label || "") + (asCopy && j.label ? " (copy)" : "");
      w.output = so.output;
      cmdCard.querySelectorAll("#cw-out button").forEach((x) => x.classList.toggle("active", x.dataset.o === so.output));
      w.expr = j.schedule; update();
      w.editing = asCopy ? null : j;
      $("#cw-cmd-h", cmdCard).textContent = w.editing ? "Editing job" : "What should it run?";
      $("#cw-save span", cmdCard).textContent = w.editing ? "Save changes" : "Schedule job";
      $("#cw-cancel", cmdCard).hidden = !w.editing;
      cmdCard.classList.toggle("editing", !!w.editing);
      hero.scrollIntoView({ behavior: "smooth", block: "start" });
    }
    function resetWizard() {
      w.editing = null; cmdIn.value = ""; labelIn.value = "";
      $("#cw-cmd-h", cmdCard).textContent = "What should it run?";
      $("#cw-save span", cmdCard).textContent = "Schedule job";
      $("#cw-cancel", cmdCard).hidden = true; cmdCard.classList.remove("editing");
      renderPreview();
    }
    $("#cw-cancel", cmdCard).addEventListener("click", resetWizard);
    $("#cw-save", cmdCard).addEventListener("click", async () => {
      const schedule = w.expr.trim().replace(/\s+/g, " "), command = finalCommand(), label = labelIn.value.trim() || null;
      if (!w.parsed || w.parsed.error || !command) return;
      try {
        if (w.editing) { await API.cronUpdate({ raw: w.editing.raw, schedule, command, label, paused: w.editing.paused }); toast("Job updated", "good"); }
        else { await API.cronAdd(schedule, command, label); toast("Job scheduled", "good"); }
        resetWizard(); load();
      } catch (e) { toast(e.message, "bad"); }
    });

    // ---------- job list ----------
    async function runNow(j) {
      if (!confirmInline(`Run this job now as root?\n\n${j.command}`)) return;
      try {
        const r = await API.cronRun(j.raw);
        const pre = el("pre", { class: "log", text: "Starting…" });
        const status = el("div", { class: "cw-runstate" }, [el("span", { class: "pill dim", text: "running" })]);
        openModal(`Run now, ${j.label || j.command.split(/\s+/)[0]}`, el("div", {}, [status, pre]), []);
        const tick = async () => {
          if (!$("#modal")) { clearInterval(t); return; }
          try {
            const s = await API.job(r.job_id);
            pre.textContent = s.output || "(no output)";
            pre.scrollTop = pre.scrollHeight;
            if (s.status !== "running") {
              clearInterval(t);
              status.innerHTML = "";
              status.append(el("span", { class: `pill ${s.status === "done" ? "good" : "bad"}`, text: `${s.status} · exit ${s.returncode}` }),
                el("span", { class: "muted", text: ` ${((s.finished - s.started)).toFixed(1)}s` }));
            }
          } catch (e) { clearInterval(t); }
        };
        const t = setInterval(tick, 1000); tick();
      } catch (e) { toast(e.message, "bad"); }
    }
    function renderList(data) {
      listWrap.innerHTML = ""; upcoming.innerHTML = "";
      if (data.tz) { cronState.tz = data.tz; }
      if (data.utc_offset_min != null) cronState.offMin = data.utc_offset_min;
      $("#cw-tz", hero).textContent = `Pi time · ${cronFmt(new Date(cronNow()), { hour: "2-digit", minute: "2-digit", hour12: false })}${cronState.tz ? " " + cronState.tz : ""}`;
      update(true);
      if (!data.supported) { listWrap.append(el("p", { class: "empty", text: "cron is not available on this host." })); return; }
      const jobs = data.jobs;
      $("#cw-count").textContent = `Scheduled jobs · ${jobs.length}`;
      if (!jobs.length) {
        listWrap.append(el("div", { class: "cw-empty" }, [icon("cron", 28), el("b", { text: "No jobs scheduled yet" }), el("span", { class: "muted", text: "Pick a template above, or build a schedule and add your command." })]));
        return;
      }
      const now = cronNow();
      const up = [];
      const rows = jobs.map((j) => {
        const p = cronParse(j.schedule), nx = j.paused ? [] : cronNext(p, now, 3);
        nx.forEach((d) => up.push({ d, j }));
        const name = j.label || j.command.split(/\s+/)[0].split("/").pop();
        const row = el("div", { class: `cw-job ${j.paused ? "paused" : ""}` });
        row.innerHTML = `
          <div class="cw-job-ico">${I(j.paused ? "cron" : "cron", 18)}</div>
          <div class="cw-job-main">
            <div class="cw-job-t"><b>${esc(name)}</b>${j.paused ? '<span class="pill warn">paused</span>' : ""}<code class="cw-expr-pill">${esc(j.schedule)}</code></div>
            <div class="cw-job-d">${esc(cronDescribe(p) || p.error || "")}${nx.length ? ` <span class="cw-job-n">· next ${esc(cronFmt(nx[0], { weekday: "short", hour: "2-digit", minute: "2-digit", hour12: false }))} (${cronRel(nx[0] - now)})</span>` : ""}</div>
            <div class="cw-job-c">${esc(j.command)}</div>
          </div>
          <div class="cw-job-a"></div>`;
        const a = row.querySelector(".cw-job-a");
        const act = (ic, title, fn, cls) => a.append(el("button", { class: `rbtn cw-rb ${cls || ""}`, title, onclick: fn }, icon(ic, 14)));
        act("chevron", "Run now", () => runNow(j), "go");
        act(j.paused ? "refresh" : "ban", j.paused ? "Resume" : "Pause", async () => {
          try { await API.cronPause(j.raw, !j.paused); toast(j.paused ? "Resumed" : "Paused", "good"); load(); } catch (e) { toast(e.message, "bad"); }
        });
        act("indexes", "Edit", () => loadIntoWizard(j));
        act("backup", "Duplicate", () => loadIntoWizard(j, true));
        act("error", "Delete", async () => {
          if (!confirmInline(`Delete "${name}"?`)) return;
          try { await API.cronDelete(j.raw); toast("Deleted", "good"); if (w.editing && w.editing.raw === j.raw) resetWizard(); load(); } catch (e) { toast(e.message, "bad"); }
        }, "bad");
        return row;
      });
      up.sort((x, y) => x.d - y.d);
      if (up.length) {
        upcoming.append(el("div", { class: "cw-up-h", text: "Coming up" }));
        const strip = el("div", { class: "cw-up-strip" });
        up.slice(0, 6).forEach(({ d, j }) => {
          strip.append(el("div", { class: "cw-up" }, [
            el("span", { class: "cw-up-when", text: cronFmt(d, { weekday: "short", hour: "2-digit", minute: "2-digit", hour12: false }) }),
            el("b", { text: j.label || j.command.split(/\s+/)[0].split("/").pop() }),
            el("span", { class: "muted", text: cronRel(d - now) }),
          ]));
        });
        upcoming.append(strip);
      }
      listWrap.append(el("div", { class: "cw-jobs" }, rows));
    }
    const load = async () => {
      await guardedLoad(async () => {
        let data;
        try { data = await API.cronList(); }
        catch (e) { listWrap.innerHTML = ""; listWrap.append(el("p", { class: "empty", text: e.message })); return; }
        renderList(data);
      });
    };

    renderLegend();
    renderBuilder();
    w.expr = "5 4 * * *"; update();
    state.refreshHandler = load;
    load();
    const t = setInterval(() => { if (document.activeElement !== exprIn) update(true); }, 30000);
    (state.cleanups = state.cleanups || []).push(() => clearInterval(t));
  }

  // ======================================================================
  //  Disk usage
  // ======================================================================
  const duState = { path: "/" };
  function viewDisk(root) {
    const crumb = el("div", { class: "breadcrumb", id: "du-crumb" });
    const bar = el("div", { class: "toolbar" }, [
      el("button", { class: "btn btn-sm", id: "du-up", text: "↑ Up" }),
      el("input", { id: "du-path", type: "text", style: "flex:1;min-width:220px", placeholder: "/absolute/path" }),
      el("button", { class: "btn btn-sm", text: "Go", onclick: () => duLoad($("#du-path").value.trim() || "/") }),
    ]);
    const body = el("div", { id: "du-body" }, el("div", { class: "loading", text: "Scanning…" }));
    root.append(bar, crumb, body);
    $("#du-up").addEventListener("click", () => { if (duState.parent) duLoad(duState.parent); });
    state.refreshHandler = () => duLoad(duState.path);
    duLoad(duState.path);
  }
  async function duLoad(path) {
    await guardedLoad(async () => {
      const body = $("#du-body"); body.innerHTML = '<div class="loading">Scanning…</div>';
      let data;
      try { data = await API.diskUsage(path); }
      catch (e) { body.innerHTML = ""; body.append(el("p", { class: "empty", text: e.message })); return; }
      duState.path = data.path; duState.parent = data.parent;
      $("#du-path").value = data.path;
      $("#du-crumb").innerHTML = `<b>${esc(data.path)}</b>, total ${esc(fmtBytes(data.total))}`;
      $("#du-up").disabled = !data.parent;
      body.innerHTML = "";
      if (!data.entries.length) { body.append(el("p", { class: "empty", text: "Empty." })); return; }
      const max = data.entries[0].size || 1;
      const rows = data.entries.map((e) => el("tr", {}, [
        el("td", {}, el("span", { class: `fm-name ${e.is_dir ? "dir" : ""}`, onclick: () => e.is_dir && duLoad(e.path) }, [
          el("span", { class: "fm-ico", text: e.is_dir ? "🗀" : "🗎" }), e.name])),
        el("td", { text: fmtBytes(e.size) }),
        el("td", {}, el("div", { class: "meter", style: "width:160px;margin:0" }, el("span", { style: `width:${(e.size / max * 100).toFixed(1)}%` }))),
      ]));
      body.append(el("div", { class: "table-wrap" }, el("table", {}, [
        el("thead", {}, el("tr", {}, ["Name", "Size", ""].map((h) => el("th", { text: h })))),
        el("tbody", {}, rows),
      ])));
    });
  }

  // ======================================================================
  //  Backups
  // ======================================================================
  function viewBackups(root) {
    const CATS = [["all", "All"], ["files", "Folders"], ["databases", "Databases"], ["full", "Full"]];
    const ENG = { mysql: "MariaDB", pgsql: "PostgreSQL" };
    const inCat = (b, c) => c === "all" ? true
      : c === "full" ? b.category === "full"
      : c === "databases" ? b.kind === "sql" || (b.kind === "wizard" && ((b.mysql || []).length + (b.pgsql || []).length) > 0)
      : b.kind === "plain" || b.kind === "unknown" || (b.kind === "wizard" && (b.paths || []).length > 0);
    let cat = CATS.some(([k]) => k === state.viewArg) ? state.viewArg : "all";
    let data = null, query = "";
    const items = new Map();          // archive name -> { node, jobHost, restoreBtn, panel }
    const jobNodes = new Map();       // job id -> node
    const seenRunning = new Set();    // jobs we watched run, so we toast when they end
    const openPanels = new Set();
    let dismissed;
    try { dismissed = new Set(JSON.parse(sessionStorage.getItem("aurora-bk-dismissed") || "[]")); } catch (e) { dismissed = new Set(); }
    const dismiss = (id) => { dismissed.add(id); try { sessionStorage.setItem("aurora-bk-dismissed", JSON.stringify([...dismissed])); } catch (e) {} };

    // ---- "Click again to confirm" buttons instead of browser dialogs ----
    function armed(label, armedLabel, action, cls) {
      let t = null;
      const b = btn(label, async () => {
        if (!b.classList.contains("armed")) {
          b.classList.add("armed"); b.textContent = armedLabel;
          t = setTimeout(() => { b.classList.remove("armed"); b.textContent = label; }, 4000);
          return;
        }
        clearTimeout(t); b.classList.remove("armed"); b.textContent = label;
        await action(b);
      }, cls);
      return b;
    }
    const when = (ts) => {
      const s = Date.now() / 1000 - ts;
      if (s < 60) return "just now";
      if (s < 3600) return `${Math.round(s / 60)} min ago`;
      if (s < 86400) return `${Math.round(s / 3600)} h ago`;
      if (s < 86400 * 30) return `${Math.round(s / 86400)} days ago`;
      return new Date(ts * 1000).toLocaleDateString();
    };
    const dur = (s) => s < 60 ? `${Math.max(1, Math.round(s))}s` : s < 3600 ? `${Math.floor(s / 60)}m ${Math.round(s % 60)}s` : `${Math.floor(s / 3600)}h ${Math.round((s % 3600) / 60)}m`;

    // ---------------- Create / import card ----------------
    const createBody = el("div", { class: "bk-create-body" });
    let mode = "folder";
    const seg = el("div", { class: "cw-seg cw-seg-sm" }, [["folder", "Folder"], ["database", "Database"], ["upload", "Upload / import"]].map(([k, l]) =>
      el("button", { type: "button", class: k === mode ? "active" : "", text: l, onclick: (e) => {
        mode = k; seg.querySelectorAll("button").forEach((x) => x.classList.toggle("active", x === e.target)); drawCreate(); } })));
    const createCard = el("div", { class: "card bk-create" }, [
      el("div", { class: "bk-create-head" }, [el("h3", { text: "New backup" }), seg]), createBody]);

    function drawCreate() {
      createBody.innerHTML = "";
      if (mode === "folder") {
        const src = el("input", { type: "text", placeholder: `${(data && data.home) || sysHome()}  (folder to back up)` });
        const label = el("input", { type: "text", placeholder: "name (optional)", maxlength: 60 });
        const quick = el("div", { class: "bk-quick" }, [data && data.home, "/var/www", "/etc"].filter(Boolean).map((p) =>
          el("button", { type: "button", class: "bk-chip", text: p, onclick: () => { src.value = p; src.focus(); } })));
        const go = btn("Back up folder", async () => {
          const s = src.value.trim();
          if (!s) { toast("Type the folder to back up", "bad"); src.focus(); return; }
          go.disabled = true;
          try { await API.backupCreate(s, label.value.trim()); toast("Backup started", "good"); src.value = ""; label.value = ""; poll(true); }
          catch (e) { toast(e.message, "bad"); }
          go.disabled = false;
        }, "btn-primary");
        src.addEventListener("keydown", (e) => { if (e.key === "Enter") go.click(); });
        createBody.append(el("div", { class: "bk-row" }, [src, label, go]), quick,
          el("p", { class: "dm-hint", text: "Packs the folder into a .tar.gz. Restoring puts it back in the same place (or anywhere you pick)." }));
      } else if (mode === "database") {
        const dbs = (data && data.databases) || { mysql: [], pgsql: [] };
        if (!dbs.mysql.length && !dbs.pgsql.length) {
          createBody.append(el("p", { class: "muted", text: dbs.mysql_ok || dbs.pgsql_ok ? "No databases yet." : "No database server is running (install MariaDB or PostgreSQL in System Applications)." }));
          return;
        }
        const sel = el("select", {}, ["mysql", "pgsql"].filter((e) => dbs[e].length).map((e) =>
          el("optgroup", { label: ENG[e] }, dbs[e].map((d) => el("option", { value: `${e}:${d}`, text: d })))));
        const label = el("input", { type: "text", placeholder: "name (optional)", maxlength: 40 });
        const go = btn("Back up database", async () => {
          const [engine, db] = sel.value.split(/:(.*)/);
          go.disabled = true;
          try { await API.backupDatabase(engine, db, label.value.trim()); toast(`Backing up ${db}`, "good"); label.value = ""; poll(true); }
          catch (e) { toast(e.message, "bad"); }
          go.disabled = false;
        }, "btn-primary");
        createBody.append(el("div", { class: "bk-row" }, [sel, label, go]),
          el("p", { class: "dm-hint", text: "Saves one database as a compressed .sql.gz dump. Restore it into the same database, or import it into a new one (handy for a test copy)." }));
      } else {
        const input = el("input", { type: "file", accept: ".sql,.gz,.tgz", class: "bk-file" });
        const bar = el("div", { class: "bk-bar", hidden: true }, el("span"));
        const status = el("div", { class: "bk-job-line muted" });
        const zone = el("label", { class: "bk-drop" }, [input, icon("backup", 22),
          el("b", { text: "Drop a .sql, .sql.gz or .tar.gz file here" }), el("span", { class: "muted", text: "or click to pick one, it lands in the backups folder, then you choose where it goes" })]);
        const send = (file) => {
          if (!file) return;
          bar.hidden = false; zone.classList.add("busy");
          const t0 = Date.now();
          API.backupUpload(file, (sent, total) => {
            const pct = total ? (sent / total) * 100 : 0;
            bar.firstChild.style.width = `${pct}%`;
            const rate = sent / Math.max(0.5, (Date.now() - t0) / 1000);
            status.textContent = `Uploading ${file.name} · ${fmtBytes(sent)} of ${fmtBytes(total)} · ${pct.toFixed(0)}% · ${fmtBytes(rate)}/s`;
          }).then(async (r) => {
            toast(`Uploaded ${r.name}`, "good");
            status.textContent = ""; bar.hidden = true; zone.classList.remove("busy"); input.value = "";
            openPanels.add(r.name);
            if (cat !== "all" && !inCat(r, cat)) setCat("all");
            await load();
            const it = items.get(r.name);
            if (it) it.node.scrollIntoView({ behavior: "smooth", block: "center" });
          }).catch((e) => { toast(e.message, "bad"); status.textContent = e.message; bar.hidden = true; zone.classList.remove("busy"); });
        };
        input.addEventListener("change", () => send(input.files[0]));
        zone.addEventListener("dragover", (e) => { e.preventDefault(); zone.classList.add("over"); });
        zone.addEventListener("dragleave", () => zone.classList.remove("over"));
        zone.addEventListener("drop", (e) => { e.preventDefault(); zone.classList.remove("over"); send(e.dataTransfer.files[0]); });
        createBody.append(zone, bar, status);
      }
    }

    // ---------------- List ----------------
    const chips = el("div", { class: "bk-cats" });
    const search = el("input", { type: "search", class: "bk-search", placeholder: "Filter by name…" });
    search.addEventListener("input", () => { query = search.value.trim().toLowerCase(); drawList(); });
    const pending = el("div", { class: "bk-list bk-pending" });
    const list = el("div", { class: "bk-list" });
    const where = el("p", { class: "muted bk-where" });
    root.append(createCard, el("div", { class: "bk-toolbar" }, [chips, search]), pending, list, where);

    function setCat(c) {
      cat = c;
      try { history.replaceState(null, "", `#/backups${c === "all" ? "" : "/" + c}`); } catch (e) {}
      state.viewArg = c === "all" ? null : c;
      drawList();
    }
    function drawChips() {
      chips.innerHTML = "";
      for (const [k, l] of CATS) {
        const n = data.backups.filter((b) => inCat(b, k)).length;
        chips.append(el("button", { type: "button", class: `bk-cat${k === cat ? " active" : ""}`, onclick: () => setCat(k) },
          [l, el("span", { class: "bk-count", text: String(n) })]));
      }
    }

    function describe(b) {
      if (b.kind === "sql") return [pill(ENG[b.engine] || "SQL dump", "db"), el("span", { text: b.db ? `database ${b.db}` : "" })];
      if (b.kind === "wizard") {
        const bits = [];
        if ((b.paths || []).length) bits.push(`${b.paths.length} folder${b.paths.length > 1 ? "s" : ""}`);
        if ((b.mysql || []).length) bits.push(`${b.mysql.length} MariaDB`);
        if ((b.pgsql || []).length) bits.push(`${b.pgsql.length} PostgreSQL`);
        return [pill(b.category === "full" ? "Full" : b.category === "databases" ? "Databases" : b.category === "mixed" ? "Files + DB" : "Folders", b.category === "full" ? "full" : b.category === "databases" ? "db" : "files"),
          el("span", { text: `Wizard · ${bits.join(" · ")}` })];
      }
      if (b.kind === "unknown") return [pill("unreadable", "bad"), el("span", { text: b.error || "" })];
      const from = b.parent ? `${b.parent.replace(/\/$/, "")}/${b.top}` : b.top;
      return [pill("Folder", "files"), el("span", { class: "net-mono", text: from || "" }), b.guessed && b.parent ? el("span", { class: "muted", text: "(guessed)" }) : null];
    }

    function itemIcon(b) {
      const k = b.kind === "sql" ? "db" : b.category === "full" ? "full" : b.category === "databases" ? "db" : "files";
      return el("div", { class: `bk-ico ${k}` }, icon(k === "db" ? "database" : k === "full" ? "backup" : "folder", 18));
    }

    function buildItem(b) {
      const jobHost = el("div", { class: "bk-jobs" });
      const panel = el("div", { class: "bk-panel", hidden: true });
      const restoreBtn = btn(b.kind === "sql" ? "Restore / import" : "Restore", () => togglePanel(b, panel, restoreBtn), "bk-restore");
      if (b.kind === "unknown") restoreBtn.disabled = true;
      const node = el("div", { class: "bk-item" }, [
        el("div", { class: "bk-main" }, [
          itemIcon(b),
          el("div", { class: "bk-name" }, [el("div", { class: "bk-title", title: b.name, text: b.name }), el("div", { class: "bk-meta" }, describe(b))]),
          el("div", { class: "bk-size", text: fmtBytes(b.size) }),
          el("div", { class: "bk-date muted", title: new Date(b.modified * 1000).toLocaleString(), text: when(b.modified) }),
          el("div", { class: "bk-actions" }, [
            el("a", { class: "btn btn-sm btn-ghost", href: API.backupDownloadUrl(b.name), title: "Download", "aria-label": `Download ${b.name}` }, "↓"),
            restoreBtn,
            armed("✕", "Delete?", async () => {
              try { await API.backupDelete(b.name); toast("Deleted", "good"); load(); } catch (e) { toast(e.message, "bad"); }
            }, "btn-danger"),
          ]),
        ]),
        panel, jobHost,
      ]);
      const it = { node, jobHost, restoreBtn, panel, b };
      if (openPanels.has(b.name)) togglePanel(b, panel, restoreBtn, true);
      return it;
    }

    function togglePanel(b, panel, rb, forceOpen) {
      if (!panel.hidden && !forceOpen) { panel.hidden = true; panel.innerHTML = ""; openPanels.delete(b.name); rb.classList.remove("active"); return; }
      openPanels.add(b.name); rb.classList.add("active");
      panel.innerHTML = ""; panel.hidden = false;
      const close = () => togglePanel(b, panel, rb);
      const put = (...nodes) => panel.append(...nodes.filter(Boolean)); // append() would print a null as "null"
      const started = (r, what) => { toast(what, "good"); close(); poll(true); return r; };
      if (b.kind === "plain") {
        const dest = el("input", { type: "text", value: b.parent || (data && data.home) || "/" });
        const note = el("p", { class: "dm-hint" });
        const upd = () => { note.textContent = `“${b.top}” is recreated as ${dest.value.replace(/\/$/, "") || ""}/${b.top}, files with the same name are replaced, other files are left alone.`; };
        dest.addEventListener("input", upd); upd();
        put(el("h4", { text: "Restore this folder" }),
          b.parent ? null : el("p", { class: "bk-warnline", text: "This archive doesn't say where it came from, pick the folder to restore into." }),
          b.guessed && b.parent ? el("p", { class: "muted", style: "margin:0 0 8px", text: `Original place guessed from the folder ${b.parent}/${b.top} that exists on this Pi.` }) : null,
          field("Restore into", dest), note,
          el("div", { class: "bk-row-btns" }, [
            armed("Restore", "Click again to overwrite", async (x) => {
              x.disabled = true;
              try { started(await API.backupRestore(b.name, dest.value.trim()), "Restore started"); } catch (e) { toast(e.message, "bad"); }
              x.disabled = false;
            }, "btn-primary"),
            btn("Cancel", close, "btn-ghost")]));
      } else if (b.kind === "sql") {
        const dbs = (data && data.databases) || { mysql: [], pgsql: [] };
        let engine = b.engine || (dbs.mysql_ok ? "mysql" : "pgsql");
        const engSel = el("select", {}, ["mysql", "pgsql"].map((e) => el("option", { value: e, text: ENG[e] })));
        engSel.value = engine;
        const dl = el("datalist", { id: `bk-dl-${Math.random().toString(36).slice(2)}` });
        const target = el("input", { type: "text", value: b.db || "", list: dl.id, maxlength: 64 });
        const wipe = el("input", { type: "checkbox" }); wipe.checked = true;
        const note = el("p", { class: "dm-hint" });
        const upd = () => {
          engine = engSel.value;
          dl.innerHTML = ""; (dbs[engine] || []).forEach((d) => dl.append(el("option", { value: d })));
          const t = target.value.trim(), exists = (dbs[engine] || []).includes(t);
          note.textContent = !t ? "Type a database name." : exists
            ? (wipe.checked ? `${t} exists: it's emptied, then filled from the dump.` : `${t} exists: tables in the dump replace the same tables; anything else stays.`)
            : `${t} doesn't exist yet: it's created and the dump is imported into it.`;
        };
        [engSel, target, wipe].forEach((x) => x.addEventListener(x === target ? "input" : "change", upd)); upd();
        put(el("h4", { text: "Restore or import this dump" }),
          el("div", { class: "net-form" }, [b.engine ? null : field("Database server", engSel), field("Into database", target, b.db_guessed ? "Name suggested from the file, pick an existing database or type any new name." : `Original: ${b.db}. Type another name to import a copy.`), dl].filter(Boolean)),
          el("label", { class: "dm-check", style: "margin:10px 0 4px" }, [wipe, el("span", { text: "Empty the database first (recommended, leftovers can clash with the dump)" })]),
          note,
          el("div", { class: "bk-row-btns" }, [
            armed("Restore database", "Click again to confirm", async (x) => {
              x.disabled = true;
              try { started(await API.backupRestoreDb({ name: b.name, target: target.value.trim(), engine: engSel.value, wipe: wipe.checked }), "Import started"); }
              catch (e) { toast(e.message, "bad"); }
              x.disabled = false;
            }, "btn-primary"),
            btn("Cancel", close, "btn-ghost")]));
      } else if (b.kind === "wizard") {
        const picks = [];
        const grp = (title, list2, kind) => list2.length ? el("div", { class: "bw-group" }, [el("h4", { text: title }), ...list2.map((it) => {
          const c = el("input", { type: "checkbox" }); c.checked = true;
          const into = kind === "path" ? null : el("input", { type: "text", value: it, maxlength: 64, class: "bk-into", title: "Database to restore into" });
          picks.push({ kind, it, c, into });
          return el("div", { class: "bk-pick" }, [el("label", { class: "dm-check" }, [c, el("code", { class: "net-mono", text: it })]),
            into ? el("span", { class: "bk-into-wrap" }, ["→", into]) : null]);
        })]) : null;
        const dest = el("input", { type: "text", value: "/" });
        const wipe = el("input", { type: "checkbox" }); wipe.checked = true;
        put(el("h4", { text: "Pick what to bring back" }),
          kv([["Made", b.created ? new Date(b.created * 1000).toLocaleString() : ", "], ["On", b.host || ", "]]),
          grp("Folders", b.paths || [], "path"), grp("MariaDB databases", b.mysql || [], "mysql"), grp("PostgreSQL databases", b.pgsql || [], "pgsql"),
          (b.paths || []).length ? field("Put folders under", dest, "/ = their original location. Any other folder keeps the full path inside it (e.g. /tmp/check/home/a51).") : null,
          ((b.mysql || []).length + (b.pgsql || []).length) ? el("label", { class: "dm-check", style: "margin:10px 0 4px" }, [wipe, el("span", { text: "Empty each database first (rename the target to import a copy instead)" })]) : null,
          el("div", { class: "bk-row-btns" }, [
            armed("Restore selected", "Click again to overwrite", async (x) => {
              const sel = picks.filter((p) => p.c.checked);
              if (!sel.length) { toast("Tick what to restore", "bad"); return; }
              const body = { name: b.name, dest: dest.value.trim() || "/", wipe: wipe.checked, rename: {},
                paths: sel.filter((p) => p.kind === "path").map((p) => p.it),
                mysql: sel.filter((p) => p.kind === "mysql").map((p) => p.it), pgsql: sel.filter((p) => p.kind === "pgsql").map((p) => p.it) };
              sel.filter((p) => p.into && p.into.value.trim() && p.into.value.trim() !== p.it).forEach((p) => { body.rename[`${p.kind}:${p.it}`] = p.into.value.trim(); });
              x.disabled = true;
              try { started(await API.backupWizardRestore(body), "Restore started"); } catch (e) { toast(e.message, "bad"); }
              x.disabled = false;
            }, "btn-primary"),
            btn("Cancel", close, "btn-ghost")]));
      }
    }

    function drawList() {
      if (!data) return;
      drawChips();
      list.innerHTML = "";
      const shown = data.backups.filter((b) => inCat(b, cat) && (!query || b.name.toLowerCase().includes(query)));
      if (!data.backups.length) list.append(el("div", { class: "bk-empty" }, [icon("backup", 28), el("b", { text: "No backups yet" }), el("span", { class: "muted", text: "Back up a folder or a database above, or upload a dump to import." })]));
      else if (!shown.length) list.append(el("p", { class: "empty", text: query ? "Nothing matches that filter." : "Nothing in this category yet." }));
      for (const b of shown) list.append(items.get(b.name).node);
      where.textContent = `Stored in ${data.dir} · ${data.backups.length} file${data.backups.length === 1 ? "" : "s"}, ${fmtBytes(data.backups.reduce((a, b) => a + b.size, 0))}`;
      renderJobs(lastJobs);
    }

    // ---------------- Jobs: one orange bar per running job, under its file ----------------
    let lastJobs = [], timer = null, alive = true, firstLoad = true, skew = 0;
    function jobNode(j) {
      let n = jobNodes.get(j.id);
      if (!n) {
        const bar = el("div", { class: "bk-bar" }, el("span"));
        const line = el("div", { class: "bk-job-line" });
        const tools = el("div", { class: "bk-job-tools" });
        const log = el("pre", { class: "log bk-log", hidden: true });
        n = el("div", { class: "bk-job" }, [el("div", { class: "bk-job-top" }, [line, tools]), bar, log]);
        Object.assign(n, { bar, line, tools, log });
        jobNodes.set(j.id, n);
      }
      return n;
    }
    function fillJob(n, j) {
      const op = j.meta.op;
      const pct = j.progress;
      const el2 = (Date.now() / 1000 + skew) - j.started;  // the Pi's clock, not the browser's
      n.className = `bk-job ${j.status}`;
      n.bar.classList.toggle("indet", j.status === "running" && pct == null);
      n.bar.firstChild.style.width = `${j.status === "running" ? (pct == null ? 35 : Math.max(2, pct)) : 100}%`;
      n.line.innerHTML = "";
      if (j.status === "running") {
        const verb = op === "create" ? "Creating" : "Restoring";
        const eta = pct > 3 ? el2 / pct * (100 - pct) : null;
        n.line.append(el("span", { class: "bk-spin" }), el("b", { text: `${verb}${j.meta.dest ? " into " + j.meta.dest : ""}` }),
          el("span", { class: "muted", text: ` · ${j.stage || "Working…"}` }),
          el("span", { class: "bk-pct", text: pct == null ? dur(el2) : `${pct.toFixed(pct < 10 ? 1 : 0)}%` }),
          eta != null ? el("span", { class: "muted", text: ` · ~${dur(eta)} left` }) : "");
      } else {
        const ok = j.status === "done";
        const last = (j.output || "").trim().split("\n").filter(Boolean).pop() || "";
        n.line.append(el("span", { class: `bk-badge ${ok ? "good" : "bad"}`, text: ok ? "✓" : "!" }),
          el("b", { text: ok ? (op === "create" ? "Created" : `Restored${j.meta.dest ? " to " + j.meta.dest : ""}`) : "Failed" }),
          el("span", { class: "muted", text: ok ? ` · took ${dur((j.finished || j.started) - j.started)} · ${new Date((j.finished || j.started) * 1000).toLocaleTimeString()}` : ` · ${last.replace(/^✖\s*/, "")}` }));
      }
      n.tools.innerHTML = "";
      n.tools.append(el("button", { type: "button", class: "bk-mini", text: n.log.hidden ? "Log" : "Hide log", onclick: async () => {
        n.log.hidden = !n.log.hidden;
        if (!n.log.hidden) { try { const full = await API.job(j.id); n.log.textContent = full.output || "(no output)"; } catch (e) { n.log.textContent = e.message; } }
        fillJob(n, j);
      } }));
      if (j.status !== "running") n.tools.append(el("button", { type: "button", class: "bk-mini", title: "Dismiss", "aria-label": "Dismiss", text: "✕", onclick: () => { dismiss(j.id); n.remove(); jobNodes.delete(j.id); } }));
      if (!n.log.hidden && j.status === "running") n.log.textContent = j.output || "";
    }
    function renderJobs(jobsList) {
      const live = new Set();
      const pendingNames = new Set(), hasResult = new Set();
      for (const j of jobsList) {  // newest first
        if (dismissed.has(j.id)) continue;
        // Under each file: whatever is running, plus only the latest finished result.
        if (j.status !== "running") { if (hasResult.has(j.meta.archive)) continue; hasResult.add(j.meta.archive); }
        const name = j.meta.archive;
        const it = items.get(name);
        // A finished backup whose file has since been deleted has nothing left to show.
        if (!it && j.meta.op !== "create") continue;
        if (!it && j.meta.op === "create" && j.status === "done") continue;
        const n = jobNode(j);
        fillJob(n, j);
        live.add(j.id);
        if (it && !(j.meta.op === "create" && j.status === "running")) {
          it.jobHost.append(n);  // re-appending keeps newest-first order
        } else if (j.meta.op === "create" && (j.status === "running" || !it)) {
          pendingNames.add(name);
          let p = pending.querySelector(`[data-name="${CSS.escape(name)}"]`);
          if (!p) {
            p = el("div", { class: "bk-item pending", "data-name": name }, [el("div", { class: "bk-main" }, [
              el("div", { class: `bk-ico ${j.meta.engine ? "db" : "files"}` }, icon(j.meta.engine ? "database" : "folder", 18)),
              el("div", { class: "bk-name" }, [el("div", { class: "bk-title", text: name }), el("div", { class: "bk-meta muted", text: j.title })])])]);
            pending.append(p);
          }
          if (n.parentNode !== p) p.append(n);
        }
      }
      pending.querySelectorAll(".bk-item.pending").forEach((p) => { if (!pendingNames.has(p.dataset.name)) p.remove(); });
      for (const [id, n] of jobNodes) if (!live.has(id)) { n.remove(); jobNodes.delete(id); }
      for (const [name, it] of items) {
        const run = jobsList.find((j) => j.meta.archive === name && j.status === "running");
        it.restoreBtn.classList.toggle("busy", !!run);
        it.restoreBtn.textContent = run ? (run.meta.op === "create" ? "Creating…" : `Restoring${run.progress != null ? " " + Math.floor(run.progress) + "%" : "…"}`) : (it.b.kind === "sql" ? "Restore / import" : "Restore");
      }
    }
    async function poll(soon) {
      if (!alive) return;
      clearTimeout(timer);
      if (soon) { timer = setTimeout(() => poll(), 400); return; }
      let anyRunning = false;
      try {
        const r = await API.backupJobs();
        skew = r.now - Date.now() / 1000;
        let reload = false;
        for (const j of r.jobs) {
          if (j.status === "running") { anyRunning = true; seenRunning.add(j.id); continue; }
          if (seenRunning.has(j.id)) {
            seenRunning.delete(j.id);
            const ok = j.status === "done";
            toast(`${j.title}: ${ok ? "finished" : "failed"}`, ok ? "good" : "bad");
            if (j.meta.op === "create") reload = true;
          }
        }
        lastJobs = r.jobs;
        if (reload) await load(); else renderJobs(r.jobs);
      } catch (e) { if (e.status === 401) return location.reload(); }
      if (alive) timer = setTimeout(() => poll(), anyRunning ? 1000 : 5000);
    }
    state.cleanups.push(() => { alive = false; clearTimeout(timer); });

    async function load() {
      try {
        data = await API.backups();
      } catch (e) {
        if (e.status === 401) return location.reload();
        list.innerHTML = ""; list.append(el("p", { class: "empty", text: e.message })); return;
      }
      const names = new Set(data.backups.map((b) => b.name));
      for (const n of [...openPanels]) if (!names.has(n)) openPanels.delete(n);
      items.clear();
      for (const b of data.backups) items.set(b.name, buildItem(b));
      if (firstLoad || mode === "database") drawCreate();
      firstLoad = false;
      drawList();
    }
    list.append(el("div", { class: "loading", text: "Loading…" }));
    drawCreate();
    state.refreshHandler = load;
    load().then(() => poll());
  }

  // ======================================================================
  //  Files: Backup Wizard (files + databases in one archive, selective restore)
  // ======================================================================
  function viewBackupWizard(root) {
    const body = el("div", {}, el("div", { class: "loading", text: "Loading…" }));
    root.append(body);
    const jp = jobPanel(root);
    state.cleanups.push(jp.stop);
    const cb = (checked) => { const c = el("input", { type: "checkbox" }); c.checked = !!checked; return c; };
    const load = () => guardedLoad(async () => {
      const o = await API.backupWizard();
      const list = await API.backups();
      body.innerHTML = "";
      subTabs(body, [["backup", "1 · Back up"], ["restore", "2 · Restore"]], (tab, pane) => tab === "backup" ? backupPane(pane) : restorePane(pane));

      function backupPane(pane) {
        let kind = "full";
        const seg = el("div", { class: "cw-seg" }, [["full", "Full backup"], ["files", "Website & home files"], ["databases", "Databases"], ["custom", "Custom"]].map(([k, l]) =>
          el("button", { type: "button", class: k === kind ? "active" : "", text: l, onclick: (e) => { kind = k; seg.querySelectorAll("button").forEach((b) => b.classList.toggle("active", b === e.target)); draw(); } })));
        const opts = el("div");
        const label = el("input", { type: "text", placeholder: "optional name, e.g. before-update", maxlength: 60 });
        const picks = { paths: {}, mysql: {}, pgsql: {} };
        const extra = el("input", { type: "text", placeholder: "/srv/data  /etc/nginx   (space separated, optional)" });
        function group(title, items, bucket, preset) {
          if (!items.length) return null;
          return el("div", { class: "bw-group" }, [el("h4", { text: title }), ...items.map((it) => {
            const c = cb(preset); picks[bucket][it] = c;
            return el("label", { class: "dm-check" }, [c, el("code", { class: "net-mono", text: it })]);
          })]);
        }
        function draw() {
          opts.innerHTML = ""; picks.paths = {}; picks.mysql = {}; picks.pgsql = {};
          const fileItems = [o.web_root, o.home].filter(Boolean);
          if (kind === "full") {
            opts.append(el("p", { class: "muted", text: "Everything needed to rebuild this Pi's sites: your home folder, the web root, all databases and the server configuration (Apache/PHP/MariaDB/VPN/FTP/fail2ban/panel settings)." }),
              kv([["Folders", [...fileItems, ...o.configs].join(", ")], ["MariaDB databases", o.mysql.join(", ") || "none"], ["PostgreSQL databases", o.pgsql.join(", ") || "none"]]),
              el("p", { class: "dm-hint", text: "The archive contains private keys and password hashes (VPN, FTP), keep downloads somewhere safe." }));
          } else {
            // append() would render a null as the text "null", drop empty/hidden groups.
            const add = (...nodes) => opts.append(...nodes.filter(Boolean));
            if (kind === "files" || kind === "custom") add(group("Folders", fileItems, "paths", kind === "files"), kind === "custom" ? group("Server configuration", o.configs, "paths", false) : null);
            if (kind === "databases" || kind === "custom") add(group("MariaDB / MySQL databases", o.mysql, "mysql", kind === "databases"), group("PostgreSQL databases", o.pgsql, "pgsql", kind === "databases"));
            if (kind === "custom") opts.append(field("Other folders / files", extra));
          }
        }
        draw();
        const go = btn("Create backup", async () => {
          const sel = (b) => Object.entries(picks[b]).filter(([, c]) => c.checked).map(([k]) => k);
          const body2 = { kind, label: label.value.trim(), paths: sel("paths").concat(kind === "custom" ? extra.value.split(/\s+/).filter(Boolean) : []), mysql: sel("mysql"), pgsql: sel("pgsql") };
          go.disabled = true;
          try { const r = await API.backupWizardCreate(body2); watchJob(jp, r.job, "Creating backup", () => { go.disabled = false; load(); }); }
          catch (e) { toast(e.message, "bad"); go.disabled = false; }
        }, "btn-primary");
        pane.append(el("div", { class: "card" }, [el("h3", { text: "What should be backed up?" }), seg, opts,
          el("div", { class: "net-form" }, [field("Name", label)]), el("div", { style: "margin-top:14px" }, go),
          el("p", { class: "dm-hint", text: `Archives are stored in ${o.dir} and can be downloaded from the Restore tab or the Backup page. Tip: schedule this with Cron Jobs for automatic backups.` })]));
      }

      function restorePane(pane) {
        if (!list.backups.length) { pane.append(el("p", { class: "empty", text: "No backups yet, create one first." })); return; }
        const sel = el("select", {}, list.backups.map((b) => el("option", { value: b.name, text: `${b.name}, ${fmtBytes(b.size)}, ${new Date(b.modified * 1000).toLocaleString()}` })));
        const detail = el("div");
        const show = async () => {
          detail.innerHTML = ""; detail.append(el("div", { class: "loading", text: "Reading backup…" }));
          try {
            const m = await API.backupManifest(sel.value);
            detail.innerHTML = "";
            if (!m.wizard) { detail.append(el("p", { class: "muted", text: `This is a simple backup (contains: ${m.top.join(", ") || "?"}). Restore it from the Backup page.` }), btn("Open Backup page", () => navigate("backups"), "btn-ghost")); return; }
            const picks = { paths: {}, mysql: {}, pgsql: {} };
            const grp = (title, items, bucket) => items.length ? el("div", { class: "bw-group" }, [el("h4", { text: title }), ...items.map((it) => { const c = cb(false); picks[bucket][it] = c; return el("label", { class: "dm-check" }, [c, el("code", { class: "net-mono", text: it })]); })]) : null;
            detail.append(kv([["Made", new Date(m.created * 1000).toLocaleString()], ["Type", m.kind], ["On", m.host]]),
              grp("Folders (restored to their original location, overwriting files)", m.paths, "paths"),
              grp("MariaDB databases (tables are replaced)", m.mysql, "mysql"), grp("PostgreSQL databases", m.pgsql, "pgsql"));
            const go = btn("Restore selected", async () => {
              const s = (b) => Object.entries(picks[b]).filter(([, c]) => c.checked).map(([k]) => k);
              const b2 = { name: sel.value, paths: s("paths"), mysql: s("mysql"), pgsql: s("pgsql") };
              if (!b2.paths.length && !b2.mysql.length && !b2.pgsql.length) { toast("Tick what to restore", "bad"); return; }
              if (!confirmInline("Restore now? Current files/data for the selected items will be overwritten.")) return;
              try { const r = await API.backupWizardRestore(b2); watchJob(jp, r.job, "Restoring"); } catch (e) { toast(e.message, "bad"); }
            }, "btn-danger");
            detail.append(el("div", { class: "toolbar", style: "margin:14px 0 0" }, [go, el("a", { class: "btn btn-sm btn-ghost", href: API.backupDownloadUrl(sel.value), text: "Download archive" })]));
          } catch (e) { detail.innerHTML = ""; detail.append(el("p", { class: "empty", text: e.message })); }
        };
        sel.onchange = show;
        pane.append(el("div", { class: "card" }, [el("h3", { text: "Pick a backup" }), sel, detail]));
        show();
      }
    });
    state.refreshHandler = load; load();
  }

  // ======================================================================
  //  Files: Images (thumbnails, scale, convert)
  // ======================================================================
  function viewImages(root) {
    const pathIn = el("input", { type: "text", placeholder: "folder or image inside the web root, e.g. uploads/photos", value: state.viewArg || "" });
    const info = el("div");
    const jp = jobPanel(root);
    state.cleanups.push(jp.stop);
    let current = null;
    const look = async () => {
      info.innerHTML = ""; info.append(el("div", { class: "loading", text: "Reading…" }));
      try {
        const d = await API.imageInfo(pathIn.value.trim());
        info.innerHTML = ""; current = d;
        if (!d.available) { info.append(el("p", { class: "empty", text: "The image library isn't installed on this Pi (pip install Pillow)." })); return; }
        if (d.type === "folder") {
          info.append(el("p", { class: "muted", text: `${d.count} image(s) in ${("/" + d.path).replace(/^\/+/, "/")}` }), d.images.length ? el("div", { class: "net-chips" }, d.images.slice(0, 60).map((i) =>
            el("button", { type: "button", class: "net-chip", text: `${i.name} (${fmtBytes(i.size)})`, onclick: () => { pathIn.value = (d.path ? d.path + "/" : "") + i.name; look(); } }))) : "");
        } else {
          info.append(kv([["Image", ("/" + d.path).replace(/^\/+/, "/")], ["Size", `${d.width} × ${d.height} px`], ["Format", d.format], ["File size", fmtBytes(d.size)]]));
        }
        draw();
      } catch (e) { info.innerHTML = ""; info.append(el("p", { class: "empty", text: e.message })); }
    };
    const tools = el("div");
    function draw() {
      tools.innerHTML = "";
      if (!current || !current.available) return;
      const isDir = current.type === "folder";
      // Scaler
      if (!isDir) {
        const w = el("input", { type: "number", min: 1, placeholder: "width px" }), h = el("input", { type: "number", min: 1, placeholder: "height px" });
        const pct = el("input", { type: "number", min: 1, max: 1000, placeholder: "or %" });
        const aspect = el("input", { type: "checkbox" }); aspect.checked = true;
        const keep = el("input", { type: "checkbox" }); keep.checked = true;
        tools.append(el("div", { class: "card" }, [el("h3", { text: "Scale (resize)" }),
          el("div", { class: "net-form" }, [field("Width", w), field("Height", h), field("Percent", pct)]),
          el("div", { class: "toolbar", style: "margin:10px 0 0" }, [el("label", { class: "dm-check" }, [aspect, el("span", { text: "Keep proportions" })]), el("label", { class: "dm-check" }, [keep, el("span", { text: "Keep a copy of the original" })]),
            btn("Resize", async () => { try { const r = await API.imageScale({ path: current.path, width: +w.value || null, height: +h.value || null, percent: +pct.value || null, keep_aspect: aspect.checked, keep_original: keep.checked }); toast(`Resized ${r.from.join("×")} → ${r.to.join("×")}`, "good"); look(); } catch (e) { toast(e.message, "bad"); } }, "btn-primary")])]));
      }
      // Thumbnailer
      if (isDir) {
        const pct = el("input", { type: "number", min: 1, max: 100, value: 25 }), mx = el("input", { type: "number", min: 16, max: 4000, placeholder: "or max px (e.g. 300)" });
        const rec = el("input", { type: "checkbox" });
        tools.append(el("div", { class: "card" }, [el("h3", { text: "Thumbnailer" }), el("p", { class: "muted", text: "Creates tn_<name> copies in a 'thumbnails' folder next to each image. Originals are untouched." }),
          el("div", { class: "net-form" }, [field("Scale to %", pct), field("Max size (px)", mx)]),
          el("div", { class: "toolbar", style: "margin:10px 0 0" }, [el("label", { class: "dm-check" }, [rec, el("span", { text: "Include sub-folders" })]),
            btn("Make thumbnails", async () => { try { const r = await API.imageThumbs({ path: current.path, percent: +pct.value || null, max_px: +mx.value || null, recursive: rec.checked }); watchJob(jp, r.job, "Thumbnails", look); } catch (e) { toast(e.message, "bad"); } }, "btn-primary")])]));
      }
      // Converter
      const to = el("select", {}, ["webp", "jpg", "png", "gif", "bmp"].map((f) => el("option", { value: f, text: f.toUpperCase() + (f === "webp" ? " (smallest for the web)" : "") })));
      const q = el("input", { type: "number", min: 30, max: 100, value: 85 });
      const del = el("input", { type: "checkbox" });
      tools.append(el("div", { class: "card" }, [el("h3", { text: isDir ? "Convert all images in this folder" : "Convert this image" }),
        el("div", { class: "net-form" }, [field("To format", to), field("Quality (JPG/WebP)", q)]),
        el("div", { class: "toolbar", style: "margin:10px 0 0" }, [el("label", { class: "dm-check" }, [del, el("span", { text: "Delete originals after converting" })]),
          btn("Convert", async () => { if (del.checked && !confirmInline("Delete the original images after converting?")) return; try { const r = await API.imageConvert({ path: current.path, to: to.value, quality: +q.value, delete_original: del.checked }); watchJob(jp, r.job, "Converting", look); } catch (e) { toast(e.message, "bad"); } }, "btn-primary")])]));
    }
    root.prepend(el("div", { class: "card" }, [el("h3", { text: "Pick a folder or an image" }),
      el("div", { class: "toolbar", style: "margin:0" }, [pathIn, btn("Open", look, "btn-primary"), btn("Web root", () => { pathIn.value = ""; look(); }, "btn-ghost")]),
      el("p", { class: "dm-hint", text: "Paths are relative to the File Manager's folder (the web root)." })]), info, tools);
    pathIn.addEventListener("keydown", (e) => { if (e.key === "Enter") look(); });
    look();
  }

  // ======================================================================
  //  Files: Directory Privacy (password-protected folders)
  // ======================================================================
  function viewDirPrivacy(root) {
    const body = el("div", {}, el("div", { class: "loading", text: "Loading…" }));
    root.append(el("p", { class: "muted", style: "margin:0 0 14px", text: "Password-protect folders of your websites. Visitors get a login prompt from the browser; only the users you add here get in." }), body);
    const load = () => guardedLoad(async () => {
      const d = await API.dirPrivacy();
      body.innerHTML = "";
      if (!d.apache) { body.append(el("p", { class: "empty", text: "Directory Privacy needs Apache (System Applications)." })); return; }
      body.append(el("h2", { class: "section-title", text: `Protected folders (${d.folders.length})` }));
      body.append(d.folders.length ? simpleTable(["Folder", "Prompt", "Users", "Status", ""], d.folders.map((f) => row(
        el("span", {}, [el("code", { class: "net-mono", text: f.path }), f.exists ? null : pill("missing", "bad")]), f.label || ", ",
        el("div", { class: "net-chips" }, f.users.map((u) => el("button", { type: "button", class: "net-chip", title: "Remove user", text: `${u} ✕`, onclick: async () => {
          if (!confirmInline(`Remove ${u} from ${f.path}?`)) return; try { await API.dirPrivacyUser({ path: f.path, name: u, remove: true }); toast("Removed", "good"); load(); } catch (e) { toast(e.message, "bad"); } } }))),
        pill(f.enabled ? "protected" : "off", f.enabled ? "good" : "dim"),
        el("div", { class: "net-actions" }, [
          btn("Add user", () => userDialog(f.path)),
          btn(f.enabled ? "Turn off" : "Turn on", async () => { try { await API.dirPrivacyToggle(f.path, !f.enabled); load(); } catch (e) { toast(e.message, "bad"); } }, "btn-ghost"),
          btn("Remove", async () => { if (!confirmInline(`Remove protection from ${f.path}? It becomes public again.`)) return; try { await API.dirPrivacyRemove(f.path); toast("Protection removed", "good"); load(); } catch (e) { toast(e.message, "bad"); } }, "btn-danger")]),
      ))) : el("p", { class: "empty", text: "No protected folders yet." }));
      const path = el("input", { type: "text", class: "cw-mono", placeholder: "/var/www/html/private", spellcheck: "false" });
      const label = el("input", { type: "text", placeholder: "e.g. Staff area", maxlength: 60 });
      const user = el("input", { type: "text", placeholder: "username", maxlength: 32, autocomplete: "off" });
      const pw = passwordField();
      body.append(el("div", { class: "card" }, [el("h3", { text: "Protect a folder" }),
        el("div", { class: "net-form wide" }, [(() => { const f = field("Folder", path, "Everything inside it (and sub-folders) needs a login."); f.classList.add("span-all"); return f; })(),
          field("Login prompt text", label), field("First user", user), field("Password", pw.node, "Leave empty to generate one.")]),
        el("div", { style: "margin-top:12px" }, btn("Protect folder", async () => {
          const password = pw.value() || genPassword();
          try { await API.dirPrivacyProtect({ path: path.value.trim(), label: label.value.trim(), name: user.value.trim(), password }); load(); showPw(user.value.trim(), password); } catch (e) { toast(e.message, "bad"); }
        }, "btn-primary"))]));
    });
    function showPw(user, password) {
      openModal("Folder protected", el("div", {}, [kv([["Username", user]]), el("div", { class: "net-cred" }, [el("span", { class: "net-k", text: "Password" }), el("input", { type: "text", readonly: "readonly", class: "net-mono net-pw-out", value: password }), btn("Copy", async () => toast(await copyText(password) ? "Copied" : "Copy failed", "good"))]),
        el("p", { class: "dm-hint", text: "Browsers send these credentials unencrypted over plain http, use https (SSL/TLS) or the VPN for anything sensitive." })]), []);
    }
    function userDialog(path) {
      const user = el("input", { type: "text", maxlength: 32 }); const pw = passwordField();
      const go = btn("Save", async () => { const password = pw.value() || genPassword(); try { await API.dirPrivacyUser({ path, name: user.value.trim(), password }); closeModal(); load(); showPw(user.value.trim(), password); } catch (e) { toast(e.message, "bad"); } }, "btn-primary");
      openModal(`Add user, ${path}`, el("div", {}, [field("Username (existing = change password)", user), field("Password", pw.node, "Leave empty to generate one.")]), [go]);
    }
    state.refreshHandler = load; load();
  }

  // ======================================================================
  //  Files: Web Disk (WebDAV network drive)
  // ======================================================================
  function viewWebDisk(root) {
    const body = el("div", {}, el("div", { class: "loading", text: "Loading…" }));
    root.append(el("p", { class: "muted", style: "margin:0 0 14px", text: "Web Disk lets you open a folder of this Pi like a drive on your computer or phone (WebDAV), drag files in and out with Explorer, Finder or the Files app." }), body);
    const url = (n, secure) => `${secure ? "https" : "http"}://${location.hostname}/webdisk/${n}/`;
    let certInfo = null;
    let pageCertSlot = null;
    const load = () => guardedLoad(async () => {
      const d = await API.webdisk();
      try { certInfo = await API.webdiskCert(location.hostname); }
      catch (e) { certInfo = { ready: false, needs_trust: true, names: [], message: e.message, filename: "aurora.crt" }; }
      body.innerHTML = "";
      if (!d.apache) { body.append(el("p", { class: "empty", text: "Web Disk needs Apache (System Applications)." })); return; }
      pageCertSlot = el("div");
      body.append(pageCertSlot);
      paintCert(pageCertSlot, null, null);
      body.append(el("h2", { class: "section-title", text: `Web Disk accounts (${d.accounts.length})` }));
      body.append(d.accounts.length ? simpleTable(["User", "Folder", "Access", "Address", "Status", ""], d.accounts.map((a) => row(
        el("b", { text: a.name }), el("span", {}, [el("code", { class: "net-mono", text: a.path }), a.exists ? null : pill("missing", "bad")]),
        a.readonly ? "Read only" : "Read & write", el("code", { class: "net-mono", text: url(a.name, true) }),
        pill(a.disabled ? "disabled" : "active", a.disabled ? "bad" : "good"),
        el("div", { class: "net-actions" }, [
          btn("Connect…", () => connectHelp(a.name)),
          btn("Password", () => { const pw = passwordField(); openModal(`Password, ${a.name}`, field("New password", pw.node, "Leave empty to generate one."), [btn("Save", async () => { const password = pw.value() || genPassword(); try { await API.webdiskUpdate({ name: a.name, password }); closeModal(); openModal("New password", el("div", { class: "net-cred" }, [el("span", { class: "net-k", text: "Password" }), el("input", { type: "text", readonly: "readonly", class: "net-mono net-pw-out", value: password }), btn("Copy", async () => toast(await copyText(password) ? "Copied" : "Copy failed", "good"))]), []); } catch (e) { toast(e.message, "bad"); } }, "btn-primary")]); }),
          btn(a.readonly ? "Allow writing" : "Make read-only", async () => { try { await API.webdiskUpdate({ name: a.name, readonly: !a.readonly }); load(); } catch (e) { toast(e.message, "bad"); } }, "btn-ghost"),
          btn(a.disabled ? "Enable" : "Disable", async () => { try { await API.webdiskUpdate({ name: a.name, disabled: !a.disabled }); load(); } catch (e) { toast(e.message, "bad"); } }, "btn-ghost"),
          btn("Delete", async () => { if (!confirmInline(`Delete Web Disk account ${a.name}? Files are kept.`)) return; try { await API.webdiskDelete(a.name); toast("Deleted", "good"); load(); } catch (e) { toast(e.message, "bad"); } }, "btn-danger")]),
      ))) : el("p", { class: "empty", text: "No Web Disk accounts yet." }));
      const name = el("input", { type: "text", maxlength: 32, placeholder: "e.g. laptop", autocomplete: "off" });
      const pw = passwordField();
      const folder = el("input", { type: "text", value: "/var/www/html" });
      const ro = el("input", { type: "checkbox" });
      body.append(el("div", { class: "card" }, [el("h3", { text: "Create a Web Disk account" }),
        el("div", { class: "net-form" }, [field("Username", name), field("Password", pw.node, "Leave empty to generate one."), field("Folder", folder, "Created if it doesn't exist.")]),
        el("div", { class: "toolbar", style: "margin:10px 0 0" }, [el("label", { class: "dm-check" }, [ro, el("span", { text: "Read only" })]),
          btn("Create", async () => { const password = pw.value() || genPassword(); try { const r = await API.webdiskCreate({ name: name.value.trim(), password, path: folder.value.trim(), readonly: ro.checked }); load(); connectHelp(r.name, password); } catch (e) { toast(e.message, "bad"); } }, "btn-primary")]),
        el("p", { class: "dm-hint", text: "Scripts are never run from the Web Disk, PHP and other files are always transferred as files." })]));
    });
    function connectHelp(n, password) {
      const secure = url(n, true), plain = url(n, false);
      const certSlot = el("div");
      openModal(`Connect to Web Disk, ${n}`, el("div", {}, [
        kv([["Address (https)", el("code", { class: "net-mono", text: secure })], ["Address (http, LAN only)", el("code", { class: "net-mono", text: plain })], ["Username", n]]),
        password ? el("div", { class: "net-cred" }, [el("span", { class: "net-k", text: "Password" }), el("input", { type: "text", readonly: "readonly", class: "net-mono net-pw-out", value: password }), btn("Copy", async () => toast(await copyText(password) ? "Copied" : "Copy failed", "good"))]) : null,
        el("div", { class: "net-os" }, [el("h4", { text: "Windows" }), el("p", { class: "muted", text: "File Explorer → This PC → Map network drive → Folder: the https address → tick 'Connect using different credentials'. Windows only sends the password over https, and only after the certificate below is trusted." }), certSlot]),
        el("div", { class: "net-os" }, [el("h4", { text: "macOS" }), el("p", { class: "muted", text: `Finder → Go → Connect to Server (⌘K) → ${secure}` })]),
        el("div", { class: "net-os" }, [el("h4", { text: "Linux" }), el("p", { class: "muted", text: `Files → Other Locations → Connect to Server → davs://${location.hostname}/webdisk/${n}/` })]),
        el("div", { class: "net-os" }, [el("h4", { text: "iPhone / Android" }), el("p", { class: "muted", text: "Any WebDAV app (e.g. Documents, Solid Explorer, Cx File Explorer) with the address above." })]),
        el("p", { class: "dm-hint", text: "From outside your home network, connect through the VPN rather than opening port 80/443 for this." }),
      ]), []);
      paintCert(certSlot, n, secure);
    }
    function paintCert(slot, account, secure) {
      slot.replaceChildren();
      const info = certInfo;
      if (!info) { slot.append(el("p", { class: "muted", text: "Checking the certificate…" })); return; }
      const lines = [];
      if (info.ready && info.needs_trust) {
        lines.push(
          "# PowerShell as Administrator. The file is saved to Downloads.",
          `Import-Certificate -FilePath "$env:USERPROFILE\\Downloads\\${info.filename}" -CertStoreLocation Cert:\\LocalMachine\\Root`,
          "Restart-Service WebClient");
        if (account) lines.push(`net use W: ${secure} /user:${account} *`);
      } else if (account && info.ready) {
        lines.push(`net use W: ${secure} /user:${account} *`);
      }
      slot.append(el("div", { class: "net-note" }, [
        el("p", { text: info.message || "Certificate" }),
        info.names && info.names.length ? el("p", { class: "dm-hint", text: "Issued for " + info.names.join(", ") }) : null,
        el("div", { class: "toolbar" }, [
          btn(info.ready ? "Download certificate" : "Create and download certificate", () => downloadCert(slot, account, secure), "btn-primary"),
        ]),
        lines.length ? el("pre", { class: "log", text: lines.join("\n") }) : null,
      ]));
    }
    async function downloadCert(slot, account, secure) {
      try {
        let info = certInfo;
        const fresh = !info || !info.ready || !info.pem;
        if (fresh) {
          info = await API.webdiskCertCreate(location.hostname);
          certInfo = info;
          paintCert(slot, account, secure);
          if (pageCertSlot && pageCertSlot !== slot && pageCertSlot.isConnected) paintCert(pageCertSlot, null, null);
        }
        if (!info.pem) throw new Error("The certificate has no public file to download");
        downloadText(info.filename || "aurora.crt", info.pem, "application/x-x509-ca-cert");
        toast(fresh && info.generated ? "Certificate created and downloaded" : "Certificate downloaded", "good");
      } catch (e) { toast(e.message, "bad"); }
    }
    state.refreshHandler = load; load();
  }

  // ======================================================================
  //  Files: Git Version Control
  // ======================================================================
  function viewGit(root) {
    const body = el("div", {}, el("div", { class: "loading", text: "Loading…" }));
    root.append(body);
    const jp = jobPanel(root);
    state.cleanups.push(jp.stop);
    const load = () => guardedLoad(async () => {
      const d = await API.git();
      body.innerHTML = "";
      if (!d.git) { body.append(el("p", { class: "empty", text: "git is not installed (Packages → git)." })); return; }
      body.append(el("h2", { class: "section-title", text: `Repositories (${d.repos.length})` }));
      body.append(d.repos.length ? simpleTable(["Repository", "Branch", "Last commit", "Remote", "Deploys to", ""], d.repos.map((r) => row(
        el("div", {}, [el("b", { text: r.name }), el("div", { class: "dm-hint", text: `${r.path} · owner ${r.owner}` })]),
        r.exists ? el("span", {}, [el("code", { text: r.branch || ", " }), r.dirty ? pill(`${r.dirty} changed`, "warn") : null]) : pill("missing", "bad"),
        r.last ? el("div", {}, [el("span", { text: r.last.subject }), el("div", { class: "dm-hint", text: `${r.last.hash} · ${r.last.author} · ${ago(r.last.time)}` })]) : ", ",
        r.remote || ", ", r.deploy_path || ", ",
        el("div", { class: "net-actions" }, [
          r.remote ? btn("Pull", async () => { try { const j = await API.gitPull(r.name); watchJob(jp, j.job, `Pull ${r.name}`, load); } catch (e) { toast(e.message, "bad"); } }) : null,
          btn("Deploy", async () => { try { const j = await API.gitDeploy(r.name); watchJob(jp, j.job, `Deploy ${r.name}`, load); } catch (e) { toast(e.message, "bad"); } }, "btn-primary"),
          btn("Manage", () => manage(r)),
          btn("Remove", async () => { const del = confirmInline(`Remove ${r.name} from the list?\n\nOK = also DELETE the folder ${r.path}\nCancel = keep the files`); try { await API.gitRemove(r.name, del); toast("Removed", "good"); load(); } catch (e) { toast(e.message, "bad"); } }, "btn-danger")]),
      ))) : el("p", { class: "empty", text: "No repositories yet." }));
      // create / clone
      const name = el("input", { type: "text", placeholder: "e.g. my-site", maxlength: 64 });
      const url = el("input", { type: "text", placeholder: "https://github.com/me/my-site.git  (empty = new empty repo)" });
      const branch = el("input", { type: "text", placeholder: "default branch" });
      const owner = el("input", { type: "text", value: sysUser() });
      const path = el("input", { type: "text", placeholder: `${sysHome()}/repositories/my-site` });
      const priv = el("input", { type: "checkbox" });
      name.addEventListener("input", () => { path.placeholder = `${sysHome()}/repositories/${name.value.trim() || "my-site"}`; });
      const keyBox = el("div");
      priv.addEventListener("change", async () => {
        keyBox.innerHTML = "";
        if (!priv.checked) return;
        if (!name.value.trim()) { toast("Enter a name first", "bad"); priv.checked = false; return; }
        try { const k = await API.gitKey(name.value.trim(), owner.value.trim()); keyBox.append(el("p", { class: "muted", text: "Add this deploy key to the repository (GitHub: Settings → Deploy keys → Add; GitLab: Settings → Repository → Deploy keys), then use the SSH clone URL (git@github.com:me/site.git)." }), el("pre", { class: "log", text: k.public_key }), btn("Copy key", async () => toast(await copyText(k.public_key) ? "Copied" : "Copy failed", "good"))); }
        catch (e) { toast(e.message, "bad"); priv.checked = false; }
      });
      body.append(el("div", { class: "card" }, [el("h3", { text: "Create or clone a repository" }),
        el("div", { class: "net-form" }, [field("Name", name), field("Clone URL", url), field("Branch", branch), field("Owner (Linux user)", owner), field("Folder", path)]),
        el("label", { class: "dm-check", style: "margin-top:10px" }, [priv, el("span", { text: "Private repository, create a deploy key (SSH)" })]), keyBox,
        el("div", { style: "margin-top:12px" }, btn("Create", async () => {
          const p = path.value.trim() || path.placeholder;
          try { const j = await API.gitCreate({ name: name.value.trim(), path: p, owner: owner.value.trim(), clone_url: url.value.trim() || null, branch: branch.value.trim() || null, use_key: priv.checked }); watchJob(jp, j.job, `Creating ${name.value.trim()}`, load); }
          catch (e) { toast(e.message, "bad"); }
        }, "btn-primary"))]));
    });
    async function manage(r) {
      let d;
      try { d = await API.gitDetails(r.name); } catch (e) { toast(e.message, "bad"); return; }
      const br = el("select", {}, d.branches.map((b) => el("option", { value: b, text: b }))); br.value = r.branch;
      const dp = el("input", { type: "text", value: d.deploy_path, placeholder: "/var/www/html/my-site (optional)" });
      const dc = el("input", { type: "text", value: d.deploy_cmd, placeholder: "e.g. npm ci && npm run build (optional)" });
      openModal(`Repository, ${r.name}`, el("div", {}, [
        el("h4", { text: "Branch" }), el("div", { class: "toolbar" }, [br, btn("Switch", async () => { try { await API.gitCheckout(r.name, br.value); toast(`Now on ${br.value}`, "good"); closeModal(); load(); } catch (e) { toast(e.message, "bad"); } })]),
        el("h4", { text: "Deployment" }), el("p", { class: "dm-hint", text: "Deploy = pull, then copy the files (without .git) to the folder below and/or run the command, as the repository owner." }),
        el("div", { class: "net-form" }, [field("Copy to folder", dp), field("Then run", dc)]),
        el("div", { style: "margin:10px 0 16px" }, btn("Save deployment", async () => { try { await API.gitDeploySettings(r.name, dp.value.trim(), dc.value.trim()); toast("Saved", "good"); closeModal(); load(); } catch (e) { toast(e.message, "bad"); } }, "btn-primary")),
        d.public_key ? el("div", {}, [el("h4", { text: "Deploy key" }), el("pre", { class: "log", text: d.public_key })]) : null,
        d.status.length ? el("div", {}, [el("h4", { text: `Uncommitted changes (${d.status.length})` }), el("pre", { class: "log", text: d.status.join("\n") })]) : null,
        el("h4", { text: "History" }), simpleTable(["Commit", "Message", "Author", "When"], d.log.map((c) => row(el("code", { text: c.hash }), c.subject, c.author, ago(c.time)))),
      ]), []);
    }
    state.refreshHandler = load; load();
  }

  // ======================================================================
  //  Files: Inodes Usage
  // ======================================================================
  function viewInodes(root) {
    const body = el("div", {}, el("div", { class: "loading", text: "Loading…" }));
    root.append(el("p", { class: "muted", style: "margin:0 0 14px", text: "Every file and folder uses one inode. A disk can run out of inodes (\"no space left\") even with free gigabytes, typically from millions of tiny cache or session files. Drill down to find them." }), body);
    const go = (path) => guardedLoad(async () => {
      body.innerHTML = ""; body.append(el("div", { class: "loading", text: `Counting ${path}…` }));
      const d = await API.inodes(path);
      setViewArg(path === "/" ? null : path, true);
      body.innerHTML = "";
      if (d.filesystem) {
        const f = d.filesystem;
        body.append(el("div", { class: "card" }, [el("h3", { text: `Filesystem ${f.mount}` }),
          kv([["Inodes used", `${f.used.toLocaleString()} of ${f.total.toLocaleString()} (${f.percent}%)`], ["Free", f.free.toLocaleString()]]),
          el("div", { class: `meter ${meterClass(f.percent)}`, style: "margin-top:10px" }, el("span", { style: `width:${Math.max(1, f.percent)}%` }))]));
      }
      const max = Math.max(1, ...d.entries.map((e) => e.inodes));
      body.append(el("div", { class: "toolbar" }, [el("code", { class: "net-mono", text: d.path }), d.parent ? btn("↑ Up", () => go(d.parent), "btn-ghost") : null, el("span", { class: "muted", text: `${d.total.toLocaleString()} inodes below` })]),
        simpleTable(["Name", "Inodes", ""], d.entries.map((e) => row(
          e.is_dir ? el("button", { type: "button", class: "linklike", text: `📁 ${e.name}`, onclick: () => go(e.path) }) : el("span", { text: e.name }),
          e.inodes.toLocaleString(),
          el("div", { class: "meter", style: "min-width:120px;margin-top:0" }, el("span", { style: `width:${Math.max(1, Math.round(e.inodes / max * 100))}%` }))))));
    });
    state.refreshHandler = () => go(state.viewArg || "/");
    go(state.viewArg || "/");
  }

  // ======================================================================
  //  Firewall (ufw)
  // ======================================================================
  function viewFirewall(root) {
    const body = el("div", { id: "fw-body" }, el("div", { class: "loading", text: "Loading…" }));
    root.append(body);
    const load = async () => {
      await guardedLoad(async () => {
        const data = await API.firewall();
        body.innerHTML = "";
        if (!data.available) {
          body.append(el("p", { class: "empty", text: "ufw is not installed. Install it from the Packages section to manage the firewall." }));
          return;
        }
        const head = el("div", { class: "card", style: "margin-bottom:16px" }, [
          el("h3", { text: "Firewall status" }),
          el("div", { style: "display:flex;align-items:center;gap:14px" }, [
            el("span", { class: `pill ${data.active ? "good" : "dim"}`, text: data.active ? "active" : "inactive" }),
            el("button", { class: "btn btn-sm", text: data.active ? "Disable" : "Enable",
              onclick: async () => {
                const msg = data.active ? "Disable the firewall?"
                  : `Enable the firewall?\n\nSSH (22) and the panel (${location.port || (location.protocol === "https:" ? 443 : 80)}) will be auto-allowed first so you won't be locked out.`;
                if (!confirmInline(msg)) return;
                try { const r = await API.firewallToggle(!data.active);
                  toast(!data.active && r.preallowed ? `Firewall on, allowed ${r.preallowed.join(", ")}` : "Done", "good"); load(); }
                catch (e) { toast(e.message, "bad"); } } }),
          ]),
          data.active ? null : el("p", { class: "muted", style: "margin:10px 0 0;font-size:12px",
            text: "Safeguard: enabling here always allows SSH (22) + the panel port first, you can't lock yourself out via the panel." }),
        ]);
        const addForm = el("div", { class: "card", style: "margin-bottom:16px" }, [
          el("h3", { text: "Add rule" }),
          el("div", { class: "toolbar" }, [
            el("select", { id: "fw-action", style: "max-width:120px" }, ["allow", "deny", "reject", "limit"].map((a) => el("option", { value: a, text: a }))),
            el("input", { id: "fw-port", type: "text", placeholder: "port (e.g. 22)", style: "max-width:140px" }),
            el("select", { id: "fw-proto", style: "max-width:100px" }, ["tcp", "udp"].map((p) => el("option", { value: p, text: p }))),
            el("button", { class: "btn btn-sm btn-primary", text: "Add", onclick: async () => {
              try { await API.firewallRule($("#fw-action").value, $("#fw-port").value.trim(), $("#fw-proto").value);
                toast("Rule added", "good"); load(); } catch (e) { toast(e.message, "bad"); } } }),
          ]),
        ]);
        const rulesWrap = el("div", { class: "card" }, [el("h3", { text: "Rules" })]);
        if (!data.rules.length) { rulesWrap.append(el("p", { class: "muted", text: "No rules." })); }
        else {
          const rows = data.rules.map((r) => el("tr", {}, [
            el("td", { class: "muted", text: r.num }), el("td", { text: r.rule }),
            el("td", { class: "actions" }, el("button", { class: "btn btn-sm btn-danger", text: "Delete",
              onclick: async () => { if (!confirmInline(`Delete rule [${r.num}] ${r.rule}?`)) return;
                try { await API.firewallDelete(r.num); toast("Deleted", "good"); load(); } catch (e) { toast(e.message, "bad"); } } })),
          ]));
          rulesWrap.append(el("div", { class: "table-wrap" }, el("table", {}, [
            el("thead", {}, el("tr", {}, ["#", "Rule", ""].map((h) => el("th", { text: h })))),
            el("tbody", {}, rows),
          ])));
        }
        body.append(head, addForm, rulesWrap);
      });
    };
    state.refreshHandler = load;
    load();
  }

  // ======================================================================
  //  Users
  // ======================================================================
  function viewUsers(root) {
    const bar = el("div", { class: "toolbar" }, [
      el("input", { id: "u-name", type: "text", placeholder: "new username", style: "max-width:180px" }),
      el("select", { id: "u-shell", style: "max-width:170px" }, ["/bin/bash", "/bin/sh", "/usr/sbin/nologin", "/bin/false"].map((s) => el("option", { value: s, text: s }))),
      el("label", { class: "muted", style: "display:flex;align-items:center;gap:6px" }, [el("input", { id: "u-home", type: "checkbox", checked: "checked", style: "width:auto" }), "create home"]),
      el("button", { class: "btn btn-sm btn-primary", text: "Add user", onclick: addUser }),
      el("label", { class: "muted", style: "display:flex;align-items:center;gap:6px;margin-left:auto" }, [el("input", { id: "u-sys", type: "checkbox", style: "width:auto", onchange: () => load() }), "show system"]),
    ]);
    const body = el("div", { id: "u-body" }, el("div", { class: "loading", text: "Loading…" }));
    root.append(bar, body);

    const load = async () => {
      await guardedLoad(async () => {
        const sys = $("#u-sys") && $("#u-sys").checked;
        const data = await API.usersList(sys);
        body.innerHTML = "";
        if (!data.supported) { body.append(el("p", { class: "empty", text: "User management is only available on Linux." })); return; }
        const rows = data.users.map((u) => el("tr", {}, [
          el("td", { text: u.name }), el("td", { class: "muted", text: u.uid }),
          el("td", { class: "muted", text: u.home }), el("td", { class: "muted", text: u.shell }),
          el("td", { class: "actions" }, [
            el("button", { class: "btn btn-sm btn-ghost", text: "Password", onclick: () => setUserPw(u.name) }),
            el("button", { class: "btn btn-sm btn-danger", text: "Delete", onclick: () => delUser(u.name) }),
          ]),
        ]));
        body.append(el("div", { class: "table-wrap" }, el("table", {}, [
          el("thead", {}, el("tr", {}, ["User", "UID", "Home", "Shell", ""].map((h) => el("th", { text: h })))),
          el("tbody", {}, rows),
        ])));
      });
    };
    async function addUser() {
      const name = $("#u-name").value.trim();
      if (!name) { toast("Username required", "bad"); return; }
      try { await API.userAdd({ name, shell: $("#u-shell").value, create_home: $("#u-home").checked });
        toast("User added", "good"); $("#u-name").value = ""; load(); }
      catch (err) { toast(err.message, "bad"); }
    }
    async function delUser(name) {
      const rmHome = confirmInline(`Delete user "${name}"?\n\nOK = also remove home directory, Cancel = keep it.\n(To abort entirely, dismiss the next prompt.)`);
      if (!confirmInline(`Confirm deleting user "${name}"${rmHome ? " and their home directory" : ""}?`)) return;
      try { await API.userDelete(name, rmHome); toast("User deleted", "good"); load(); }
      catch (err) { toast(err.message, "bad"); }
    }
    async function setUserPw(name) {
      const pw = promptInline(`Set a new password for ${name}:`);
      if (!pw) return;
      try { await API.userPassword(name, pw); toast("Password set", "good"); }
      catch (err) { toast(err.message, "bad"); }
    }
    state.refreshHandler = load;
    load();
  }

  // ======================================================================
  //  Security (2FA)
  // ======================================================================
  function viewSecurity(root, only) {
    const body = el("div", { id: "sec-body" }, el("div", { class: "loading", text: "Loading…" }));
    root.append(body);
    const load = async () => {
      await guardedLoad(async () => {
        if (only === "https") {
          const c = await httpsCard();
          c.style.marginTop = "0";
          body.innerHTML = "";
          body.append(c);
          return;
        }
        const st = await API.twofaStatus();
        body.innerHTML = "";
        const card = el("div", { class: "card" }, [
          el("h3", { text: "Two-factor authentication (TOTP)" }),
          el("p", { class: "muted", style: "margin:0 0 14px",
            text: "Add a second step at login using an authenticator app (Google Authenticator, Authy, etc.)." }),
          el("div", { style: "display:flex;align-items:center;gap:12px" }, [
            el("span", { class: `pill ${st.enabled ? "good" : "dim"}`, text: st.enabled ? "enabled" : "disabled" }),
            st.enabled
              ? el("button", { class: "btn btn-sm btn-danger", text: "Disable 2FA", onclick: disable2fa })
              : el("button", { class: "btn btn-sm btn-primary", text: "Enable 2FA", onclick: enroll2fa }),
          ]),
        ]);
        body.append(card);
        body.append(await httpsCard());
      });
    };

    // ---- Panel HTTPS (the panel's own port) ----
    const panelUrl = (proto, host, port) => `${proto}//${host || location.hostname}:${port || location.port}/`;
    // Go to `url` once this page's server has gone down for its restart (the new
    // address can't be probed: a self-signed cert or mixed content blocks fetch).
    async function moveWhenRestarted(url) {
      const t0 = Date.now();
      while (Date.now() - t0 < 30000) {
        await new Promise((r) => setTimeout(r, 1000));
        try { await fetch("/api/status", { cache: "no-store" }); } catch (e) { break; }
      }
      setTimeout(() => { location.href = url; }, 3000);
    }
    async function httpsCard() {
      let st;
      try { st = await API.panelHttps(); }
      catch (e) { return el("div", { class: "card" }, [el("h3", { text: "Panel HTTPS" }), el("p", { class: "muted", text: e.message })]); }
      const pill = st.enabled
        ? el("span", { class: `pill ${st.pending ? "warn" : "good"}`, text: st.pending ? "waiting for confirmation" : "on" })
        : el("span", { class: "pill bad", text: "off, plain HTTP" });
      const rows = [
        el("h3", { text: "Panel HTTPS" }),
        el("p", { class: "muted", style: "margin:0 0 14px",
          text: "Encrypts everything between your browser and this panel, including your password and login cookie. Without it, anyone on the same network can read them." }),
        el("div", { style: "display:flex;align-items:center;gap:12px;flex-wrap:wrap" }, [
          pill,
          st.enabled
            ? el("button", { class: "btn btn-sm", text: "Turn off", onclick: () => disableHttps(st) })
            : el("button", { class: "btn btn-sm btn-primary", text: "Turn on HTTPS", onclick: () => enableHttps(st) }),
          st.enabled && st.source === "self"
            ? el("button", { class: "btn btn-sm", text: "New certificate", title: "Regenerate for the current hostname and IP addresses",
                onclick: () => enableHttps(st, "self", true) }) : null,
        ].filter(Boolean)),
      ];
      if (st.enabled && st.cert) {
        rows.push(el("p", { class: "muted", style: "margin:12px 0 0;font-size:13px",
          text: `${st.source === "self" ? "Self-signed certificate" : `Let's Encrypt: ${st.source}`} · valid for ${st.cert.names.join(", ")} · expires ${st.cert.expires}` }));
      }
      if (st.enabled && st.covers === false && st.host) {
        rows.push(el("div", { class: "mx-note", style: "margin-top:12px" }, [icon("warning", 16), el("div", {}, [
          el("span", { text: `You opened the panel as ${st.host}, but the certificate isn't valid for that name, browsers and scanners report “certificate does not match the host name”. ` }),
          st.source === "self"
            ? el("button", { class: "btn btn-sm btn-primary", style: "margin-left:8px", text: `New certificate for ${st.host}`, onclick: () => enableHttps(st, "self", true) })
            : el("span", { text: `Open the panel as https://${st.source}:${st.port} (that's what the Let's Encrypt certificate is for), or switch to the self-signed certificate, which covers ${st.host}.` }),
        ])]));
      }
      if (st.enabled && !st.hardened) {
        rows.push(el("div", { class: "mx-note", style: "margin-top:12px" }, [icon("shield", 16), el("div", {}, [
          el("span", { text: "The panel still accepts older TLS 1.2 cipher suites and sends a “server: uvicorn” header. Hardening keeps only modern suites (no CBC / SHA-1) and drops the header; every browser since 2014 works. " }),
          el("button", { class: "btn btn-sm btn-primary", style: "margin-left:8px", text: "Harden TLS & restart", onclick: async (ev) => {
            ev.currentTarget.disabled = true;
            try { await API.panelHttpsHarden(); toast("Restarting with strong ciphers, reloading in a moment", "good"); setTimeout(() => location.reload(), 4000); }
            catch (e) { toast(e.message, "bad"); ev.currentTarget.disabled = false; }
          } }),
        ])]));
      }
      if (st.enabled && st.redirect) {
        rows.push(el("p", { class: "muted", style: "margin:12px 0 0;font-size:13px", text: `Plain http://…:${st.port} is redirected to https automatically, so old bookmarks and typed addresses keep working.` }));
      } else if (st.enabled) {
        rows.push(el("div", { class: "mx-note", style: "margin-top:12px" }, [icon("warning", 16), el("div", {}, [
          el("span", { text: `Plain http://…:${st.port} is not redirected yet: a browser that goes there gets a “connection reset” instead of the panel. One restart turns the redirect on. ` }),
          el("button", { class: "btn btn-sm btn-primary", style: "margin-left:8px", text: "Redirect http → https & restart", onclick: async (ev) => {
            ev.currentTarget.disabled = true;
            try { await API.panelHttpsRedirect(); toast("Restarting with the redirect, reloading in a moment", "good"); setTimeout(() => location.reload(), 4000); }
            catch (e) { toast(e.message, "bad"); ev.currentTarget.disabled = false; }
          } }),
        ])]));
      }
      if (st.enabled && !st.active) {
        rows.push(el("p", { style: "margin:12px 0 0" }, [
          el("a", { href: panelUrl("https:", null, st.port), text: `Open ${panelUrl("https:", null, st.port)}` })]));
      }
      return el("div", { class: "card", style: "margin-top:16px" }, rows);
    }

    function enableHttps(st, source, regenerate) {
      const choice = el("select", { id: "https-src" }, [
        el("option", { value: "self", text: "Self-signed certificate (works on any LAN)" }),
        ...st.letsencrypt.map((d) => el("option", { value: d, text: `Let's Encrypt, ${d}` })),
      ]);
      const content = el("div", {}, [
        source ? null : el("label", { style: "display:flex;flex-direction:column;gap:6px;margin-bottom:12px" }, ["Certificate", choice]),
        el("p", { class: "muted", text: `The panel will restart and move to https://…:${st.port}. Plain http:// on that port is redirected to https, so old bookmarks keep working.` }),
        el("p", { class: "muted", text: "With a self-signed certificate your browser warns once (\"Not private\"): choose Advanced → Proceed. The connection is still encrypted." }),
        el("p", { class: "muted", text: "Safety net: if the panel isn't reached over HTTPS within 3 minutes, it switches back to HTTP by itself." }),
      ].filter(Boolean));
      openModal(regenerate ? "New panel certificate" : "Turn on panel HTTPS", content, [
        el("button", { class: "btn btn-primary", text: regenerate ? "Regenerate & restart" : "Turn on & restart", onclick: async (ev) => {
          const src = source || choice.value;
          ev.target.disabled = true;
          try {
            const r = await API.panelHttpsEnable(src, !!regenerate);
            closeModal();
            const url = panelUrl("https:", r.host, r.port) + location.hash;
            toast("Restarting the panel on HTTPS…", "good");
            moveWhenRestarted(url);
          } catch (e) { ev.target.disabled = false; toast(e.message, "bad"); }
        } }),
      ]);
    }

    function disableHttps(st) {
      openModal("Turn off panel HTTPS", el("p", { class: "muted",
        text: `The panel will restart on plain http://…:${st.port}. Your password and login cookie will travel unencrypted again.` }), [
        el("button", { class: "btn btn-danger", text: "Turn off & restart", onclick: async (ev) => {
          ev.target.disabled = true;
          try {
            const r = await API.panelHttpsDisable();
            closeModal();
            toast("Restarting the panel on HTTP…", "good");
            moveWhenRestarted(panelUrl("http:", null, r.port) + location.hash);
          } catch (e) { ev.target.disabled = false; toast(e.message, "bad"); }
        } }),
      ]);
    }

    async function enroll2fa() {
      try {
        const d = await API.twofaEnroll();
        const code = el("input", { id: "sec-code", type: "text", inputmode: "numeric", autocomplete: "one-time-code", maxlength: 6, placeholder: "123456", class: "tf-code" });
        const enable = async () => {
          try { await API.twofaEnable(code.value.trim()); toast("2FA enabled", "good"); closeModal(); load(); }
          catch (e) { toast(e.message, "bad"); }
        };
        code.addEventListener("keydown", (e) => { if (e.key === "Enter") enable(); });
        code.addEventListener("input", () => { code.value = code.value.replace(/\D/g, "").slice(0, 6); if (code.value.length === 6) enable(); });
        const manual = el("details", { class: "tf-manual" }, [el("summary", { text: "Can't scan? Enter the key by hand" }),
          el("p", { class: "muted", text: `Account: ${d.issuer || "AuroraPanel"} · type: time-based` }),
          el("div", { class: "tf-secret", text: d.secret.replace(/(.{4})/g, "$1 ").trim() }),
          el("p", { class: "muted mx-small", style: "word-break:break-all", text: d.otpauth_uri })]);
        const content = el("div", { class: "tf-enroll" }, [
          el("div", { class: "tf-row" }, [
            d.qr ? el("img", { class: "tf-qr", src: d.qr, alt: "QR code for your authenticator app", width: 196, height: 196 }) : null,
            el("div", { class: "tf-steps" }, [
              el("p", {}, [el("b", { text: "1. Scan the code" }), el("br"), el("span", { class: "muted", text: "In Microsoft Authenticator: + → Other account (Google, Facebook, etc.) → scan. Google Authenticator, Authy and 1Password work the same way." })]),
              el("p", {}, [el("b", { text: "2. Type the 6-digit code it shows" })]),
              code,
            ]),
          ]),
          manual,
        ]);
        if (!d.qr) manual.open = true;
        openModal("Turn on two-factor sign-in", content, [el("button", { class: "btn btn-primary", text: "Confirm & enable", onclick: enable })]);
        setTimeout(() => code.focus(), 50);
      } catch (err) { toast(err.message, "bad"); }
    }
    async function disable2fa() {
      const content = el("div", {}, [
        el("p", { class: "muted", text: "Enter a current authenticator code to disable 2FA:" }),
        el("input", { id: "sec-code", type: "text", inputmode: "numeric", placeholder: "123456", style: "max-width:160px" }),
      ]);
      openModal("Disable 2FA", content, [
        el("button", { class: "btn btn-danger", text: "Disable", onclick: async () => {
          try { await API.twofaDisable($("#sec-code").value.trim()); toast("2FA disabled", "good"); closeModal(); load(); }
          catch (e) { toast(e.message, "bad"); } } }),
      ]);
    }
    state.refreshHandler = load;
    load();
  }

  // ======================================================================
  //  Advanced: shared Apache directory bar
  // ======================================================================
  const apDir = {}; // per-view current dir
  // Where a .htaccess tool works: a site (or folder site) picked from a list, plus an optional sub-folder.
  // Paths are relative to /var/www, the way the backend wants them; "html" is the main site.
  async function apacheLocations() {
    if (state.apLocs) return state.apLocs;
    const opts = [{ v: "html", l: "Main site · /var/www/html", url: "" }];
    try { for (const x of (await API.sites()).sites || []) if (!x.system && x.docroot && x.docroot.startsWith("/var/www/")) opts.push({ v: x.docroot.slice(9).replace(/\/+$/, ""), l: `${x.server_name} · ${x.docroot}`, url: "" }); } catch (e) {}
    try { for (const x of (await API.folderSites()).sites || []) if (x.path.startsWith("/var/www/")) opts.push({ v: x.path.slice(9), l: `/${x.name} · ${x.path}`, url: `/${x.name}` }); } catch (e) {}
    opts.push({ v: "", l: "Everything under /var/www", url: "" });
    const seen = new Set();
    state.apLocs = opts.filter((o) => !seen.has(o.v) && seen.add(o.v));
    return state.apLocs;
  }
  function apacheDirBar(view, hint, onGo) {
    if (apDir[view] == null) apDir[view] = "html";
    const sel = el("select", { style: "min-width:240px;max-width:440px" }, [el("option", { value: apDir[view], text: "Loading sites…" })]);
    const sub = el("input", { type: "text", placeholder: "sub-folder (optional)", style: "max-width:200px" });
    const cur = () => { const x = sub.value.trim().replace(/^\/+|\/+$/g, ""); return [sel.value, x].filter(Boolean).join("/"); };
    const go = () => { apDir[view] = cur(); onGo(); };
    sel.onchange = go; sub.onkeydown = (e) => { if (e.key === "Enter") go(); }; sub.onchange = go;
    const bar = el("div", { class: "toolbar ap-where" }, [el("span", { class: "muted", text: "Site" }), sel, el("span", { class: "muted", text: "folder" }), sub]);
    apacheLocations().then((locs) => {
      const base = locs.filter((o) => o.v && (apDir[view] === o.v || apDir[view].startsWith(o.v + "/"))).sort((a, b) => b.v.length - a.v.length)[0];
      const bv = base ? base.v : "";
      sel.innerHTML = ""; locs.forEach((o) => sel.append(el("option", { value: o.v, text: o.l })));
      sel.value = bv; sub.value = apDir[view].slice(bv.length).replace(/^\/+/, "");
    });
    const note = el("p", { class: "muted", style: "margin:-6px 0 12px;font-size:12px", text: hint });
    return { bar, note, get dir() { return apDir[view]; },
      // the URL prefix visitors use for the picked folder (folder sites live under /<name>/)
      get url() { const o = (state.apLocs || []).find((x) => x.v === sel.value); const x = sub.value.trim().replace(/^\/+|\/+$/g, ""); return ((o && o.url) || "") + (x ? "/" + x : ""); } };
  }

  // ---- Indexes ----
  function viewIndexes(root) {
    const db = apacheDirBar("indexes", "What a visitor sees when a folder has no index page, and which file counts as the index. Saved to that folder's .htaccess.", () => load());
    const body = el("div", { id: "idx-body" }, el("div", { class: "loading", text: "Loading…" }));
    root.append(db.bar, db.note, body);
    const ORDERS = [["index.html index.php", "HTML first"], ["index.php index.html", "PHP first"], ["index.html", "Only index.html"], ["home.html index.html", "home.html"]];
    async function load() {
      body.innerHTML = '<div class="loading">Loading…</div>';
      try {
        const d = await API.apacheIndexes(db.dir);
        body.innerHTML = "";
        const listing = d.listing === true;
        const di = el("input", { type: "text", value: d.directory_index || "", placeholder: "index.html index.php", style: "max-width:360px" });
        const lsw = sw(listing, () => {}, { title: "Show the files when there is no index page" });
        body.append(el("div", { class: "card" }, [
          el("h3", { text: `Folder behaviour · /var/www/${db.dir}`.replace(/\/$/, "") }),
          el("label", { class: "dm-check", style: "margin-bottom:14px" }, [lsw, el("span", {}, [el("b", { text: "Show a file list when there is no index page" }), el("span", { class: "muted", style: "display:block;font-size:12px", text: d.listing === null ? "Not set here yet, the server default applies (usually off). Off means visitors get 403 Forbidden instead." : `Currently ${listing ? "on" : "off"} for this folder.` })])]),
          el("div", { class: "cw-lbl" }, ["Index page order", di, el("span", { class: "dm-hint", text: "The first file in this list that exists is shown for the folder itself." })]),
          el("div", { style: "display:flex;gap:6px;flex-wrap:wrap;margin:8px 0 14px" }, ORDERS.map(([v, l]) => el("button", { class: "btn btn-sm btn-ghost", title: v, onclick: () => { di.value = v; } }, [icon("listing", 12), ` ${l}`]))),
          el("div", { class: "toolbar", style: "margin:0" }, [btn("Save", async () => {
            try { await API.apacheSetIndexes({ dir: db.dir, listing: lsw.querySelector("input").checked, directory_index: di.value.trim() || null }); toast("Saved to .htaccess", "good"); load(); }
            catch (e) { toast(e.message, "bad"); }
          }, "btn-primary")]),
        ]));
      } catch (e) { body.innerHTML = ""; body.append(el("p", { class: "empty", text: e.message })); }
    }
    state.refreshHandler = load; load();
  }

  // ---- MIME Types ----
  function viewMime(root) {
    const db = apacheDirBar("mime", "Tell browsers what a file type is when the server doesn't know it (AddType in .htaccess): new formats, custom extensions.", () => load());
    const PRESETS = [["JSON", "application/json", "json map"], ["WebP", "image/webp", "webp"], ["AVIF", "image/avif", "avif"], ["WOFF2 font", "font/woff2", "woff2"], ["WebAssembly", "application/wasm", "wasm"],
      ["SVG", "image/svg+xml", "svg svgz"], ["MP4", "video/mp4", "mp4 m4v"], ["WebM", "video/webm", "webm"], ["Web manifest", "application/manifest+json", "webmanifest"], ["Android APK", "application/vnd.android.package-archive", "apk"], ["Calendar", "text/calendar", "ics"], ["Markdown", "text/markdown", "md"]];
    const mt = el("input", { type: "text", placeholder: "type, e.g. application/json", style: "max-width:280px" });
    const mx = el("input", { type: "text", placeholder: "extensions, e.g. json map", style: "max-width:220px" });
    const addForm = el("div", { class: "card", style: "margin-bottom:16px" }, [
      el("h3", { text: "Add a type" }),
      el("div", { style: "display:flex;gap:6px;flex-wrap:wrap;margin-bottom:12px" }, PRESETS.map(([l, t, e]) => el("button", { class: "btn btn-sm btn-ghost", title: `${t} → .${e.split(" ").join(" .")}`, onclick: () => { mt.value = t; mx.value = e; } }, [icon("plus", 12), ` ${l}`]))),
      el("div", { class: "toolbar", style: "margin:0" }, [mt, mx, btn("Add", add, "btn-primary")]),
    ]);
    const body = el("div", { id: "mime-body" }, el("div", { class: "loading", text: "Loading…" }));
    root.append(db.bar, db.note, addForm, body);
    async function load() {
      body.innerHTML = '<div class="loading">Loading…</div>';
      try {
        const d = await API.apacheMime(db.dir);
        body.innerHTML = "";
        const custom = el("div", { class: "card", style: "margin-bottom:16px" }, [el("h3", { text: "Types set in this folder" })]);
        if (!d.entries.length) custom.append(el("p", { class: "muted", text: "None yet, most files are already known to the server; add one only when a download comes out wrong." }));
        else custom.append(directiveTable(d.entries, "mime", db));
        body.append(custom);
        if (d.system && d.system.available) {
          const q = el("input", { type: "search", placeholder: "Search the server's built-in types… (e.g. pdf)", style: "max-width:360px;margin-bottom:10px" });
          const list = el("div");
          const draw = () => {
            const needle = q.value.trim().toLowerCase();
            const rows = (needle ? d.system.entries.filter((e) => e.type.toLowerCase().includes(needle) || e.extensions.toLowerCase().includes(needle)) : d.system.entries).slice(0, 150);
            list.innerHTML = "";
            list.append(rows.length ? el("div", { class: "table-wrap" }, el("table", {}, [el("thead", {}, el("tr", {}, [el("th", { text: "Type" }), el("th", { text: "Extensions" })])),
              el("tbody", {}, rows.map((e) => el("tr", {}, [el("td", { text: e.type }), el("td", { class: "muted", text: e.extensions })])))])) : el("p", { class: "muted", text: "No built-in type matches, add it above." }));
          };
          q.oninput = draw; draw();
          body.append(el("details", { class: "card" }, [el("summary", { style: "cursor:pointer" }, el("h3", { style: "display:inline;margin:0", text: `Already known to the server (${d.system.entries.length} types)` })), el("div", { style: "margin-top:12px" }, [q, list])]));
        }
      } catch (e) { body.innerHTML = ""; body.append(el("p", { class: "empty", text: e.message })); }
    }
    async function add() {
      try { await API.apacheAddMime({ dir: db.dir, mime: mt.value.trim(), extensions: mx.value.trim() }); toast("Type added", "good"); mt.value = ""; mx.value = ""; load(); }
      catch (e) { toast(e.message, "bad"); }
    }
    state.refreshHandler = load; load();
  }

  // ---- Error Pages ----
  function viewErrorPages(root) {
    const db = apacheDirBar("errorpages", "Your own page instead of the server's bare error text. Pick the error, say which page to show, the panel can create a simple one for you to edit.", () => load());
    const CODES = [["404", "Page not found"], ["403", "Forbidden"], ["500", "Server error"], ["503", "Maintenance"], ["401", "Sign-in required"], ["400", "Bad request"], ["429", "Too many requests"], ["502", "Bad gateway"]];
    const LBL = Object.fromEntries(CODES);
    const code = el("select", { style: "max-width:220px" }, CODES.map(([c, l]) => el("option", { value: c, text: `${c} · ${l}` })));
    const doc = el("input", { type: "text", placeholder: "/404.html  or  https://…", style: "flex:1;min-width:220px" });
    const create = el("input", { type: "checkbox" }); create.checked = true;
    const suggest = () => { if (!doc.value.trim() || /^\/\d{3}\.html$/.test(doc.value.trim().replace(db.url, ""))) doc.value = `${db.url}/${code.value}.html`; };
    code.onchange = suggest;
    const addForm = el("div", { class: "card", style: "margin-bottom:16px" }, [
      el("h3", { text: "Set an error page" }),
      el("div", { class: "toolbar", style: "margin:0 0 10px" }, [code, doc, btn("Save", save, "btn-primary")]),
      el("label", { class: "dm-check" }, [create, el("span", {}, ["Create the page if it doesn't exist yet, a simple styled page you can edit under ", el("b", { text: "Files → File Manager" })])]),
      el("p", { class: "dm-hint", text: "A path like /404.html is relative to the website's root; a full https:// address sends the visitor elsewhere." }),
    ]);
    const body = el("div", { id: "err-body" }, el("div", { class: "loading", text: "Loading…" }));
    root.append(db.bar, db.note, addForm, body);
    setTimeout(suggest, 400);
    async function load() {
      body.innerHTML = '<div class="loading">Loading…</div>';
      try {
        const d = await API.apacheErrors(db.dir);
        body.innerHTML = "";
        const card = el("div", { class: "card" }, [el("h3", { text: "Error pages in this folder" })]);
        if (!d.entries.length) card.append(el("p", { class: "muted", text: "None yet, visitors see the server's plain error text." }));
        else {
          const host = location.hostname;
          const rows = d.entries.map((e) => el("tr", {}, [
            el("td", {}, [el("b", { text: e.code }), el("span", { class: "muted", text: LBL[e.code] ? ` · ${LBL[e.code]}` : "" })]),
            el("td", {}, el("code", { text: e.document })),
            el("td", { class: "actions" }, [
              /^\//.test(e.document) ? el("a", { class: "btn btn-sm btn-ghost", href: `http://${host}${e.document}`, target: "_blank", rel: "noopener", text: "Preview" }) : null,
              btn("Remove", () => removeDirective(e.raw, db, load), "btn-danger"),
            ].filter(Boolean)),
          ]));
          card.append(el("div", { class: "table-wrap" }, el("table", {}, [el("thead", {}, el("tr", {}, ["Error", "Page", ""].map((h) => el("th", { text: h })))), el("tbody", {}, rows)])));
        }
        body.append(card);
      } catch (e) { body.innerHTML = ""; body.append(el("p", { class: "empty", text: e.message })); }
    }
    async function save() {
      const d0 = doc.value.trim(); if (!d0) return toast("Which page should be shown?", "bad");
      // the starter page is written into the picked folder: strip the folder's URL prefix from the path
      let file = "";
      if (create.checked && d0.startsWith("/") && !/^https?:/i.test(d0)) { file = d0; if (db.url && file.startsWith(db.url + "/")) file = file.slice(db.url.length); file = file.replace(/^\/+/, ""); }
      try { const r = await API.apacheSetError({ dir: db.dir, code: code.value, document: d0, create: file }); toast(r.created === false ? "Saved" : "Saved, page created", "good"); load(); }
      catch (e) { toast(e.message, "bad"); }
    }
    state.refreshHandler = load; load();
  }

  // ---- Apache Handlers ----
  function viewHandlers(root) {
    const db = apacheDirBar("handlers", "Which program handles which files in a folder: run .cgi scripts, process includes in .shtml, treat .html as PHP… Written to that folder's .htaccess.", () => load());
    const HANDLERS = ["cgi-script", "server-parsed", "application/x-httpd-php", "default-handler", "send-as-is", "type-map", "imap-file"];
    const PRESETS = [
      ["CGI scripts", "cgi-script", "cgi pl", "Perl / shell CGI programs, turn on “Run CGI programs” below too."],
      ["Python CGI", "cgi-script", "py", "Python scripts as CGI, turn on “Run CGI programs” below too."],
      ["Server-side includes", "server-parsed", "shtml shtm", "<!--#include --> in .shtml pages, turn on “Server-side includes” below too."],
      ["PHP inside .html", "application/x-httpd-php", "html htm", "Run PHP code in .html files (needs mod_php)."],
      ["Serve, don't run", "default-handler", "php phtml", "Hand these files out as they are instead of running them."],
    ];
    const hName = el("input", { type: "text", list: "h-known", placeholder: "handler, e.g. cgi-script", style: "max-width:240px" });
    const dl = el("datalist", { id: "h-known" }, HANDLERS.map((h) => el("option", { value: h })));
    const hExt = el("input", { type: "text", placeholder: "extensions, e.g. cgi pl", style: "max-width:220px" });
    const scope = el("select", {}, [el("option", { value: "ext", text: "files with these extensions" }), el("option", { value: "all", text: "every file in this folder" })]);
    scope.onchange = () => { hExt.hidden = scope.value === "all"; };
    const addCard = el("div", { class: "card", style: "margin-bottom:16px" }, [
      el("h3", { text: "Add a handler" }),
      el("div", { style: "display:flex;gap:6px;flex-wrap:wrap;margin-bottom:12px" }, PRESETS.map(([l, h, e, tip]) => el("button", { class: "btn btn-sm btn-ghost", title: tip, onclick: () => { hName.value = h; hExt.value = e; scope.value = "ext"; hExt.hidden = false; } }, [icon("plus", 12), ` ${l}`]))),
      el("div", { class: "toolbar", style: "margin:0" }, [hName, dl, el("span", { class: "muted", text: "for" }), scope, hExt, btn("Add", add, "btn-primary")]),
    ]);
    const body = el("div", { id: "h-body" }, el("div", { class: "loading", text: "Loading…" }));
    root.append(db.bar, db.note, addCard, body);
    const OPTS = [["ExecCGI", "Run CGI programs", "Needed for the cgi-script handler. Off: CGI files are sent as plain text."],
      ["Includes", "Server-side includes", "Lets .shtml pages include files and run commands (with the server-parsed handler)."],
      ["IncludesNOEXEC", "Includes, no exec", "Server-side includes with #exec refused, the safer choice."],
      ["FollowSymLinks", "Follow symbolic links", "Serve files reached through symlinks."],
      ["SymLinksIfOwnerMatch", "Follow own symlinks only", "Symlinks are followed only when link and target have the same owner."],
      ["MultiViews", "Content negotiation", "/page serves page.html or page.php, and picks the visitor's language."]];
    async function load() {
      body.innerHTML = '<div class="loading">Loading…</div>';
      try {
        const [d, o] = await Promise.all([API.apacheHandlers(db.dir), API.apacheOptions(db.dir)]);
        body.innerHTML = "";
        const card = el("div", { class: "card", style: "margin-bottom:16px" }, [el("h3", { text: "Handlers in this folder" })]);
        if (!d.entries.length) card.append(el("p", { class: "muted", text: "None yet, pick a preset above or type a handler." }));
        else card.append(directiveTable(d.entries, "handlers", db));
        body.append(card);
        body.append(el("div", { class: "card" }, [el("h3", { text: "Folder options" }), el("p", { class: "dm-hint", style: "margin:0 0 10px", text: "Switch on what the handlers need. Anything left off follows the server's defaults." }),
          el("div", { class: "sh-settings" }, OPTS.map(([k, l, tip]) => el("label", { class: "dm-check", title: tip }, [
            sw(o.options[k] === true, async (v, inp) => { try { await API.apacheSetOption(db.dir, k, v); toast(`${l} ${v ? "on" : "off"}`, "good"); } catch (e) { inp.checked = !v; toast(e.message, "bad"); } }),
            el("span", {}, [el("b", { text: l }), el("span", { class: "muted", style: "display:block;font-size:12px", text: tip })])])))]));
      } catch (e) { body.innerHTML = ""; body.append(el("p", { class: "empty", text: e.message })); }
    }
    async function add() {
      const h = hName.value.trim(), ex = scope.value === "all" ? "" : hExt.value.trim();
      if (!h) return toast("Type or pick a handler", "bad");
      if (scope.value === "ext" && !ex) return toast("Which extensions?", "bad");
      try { await API.apacheAddHandler({ dir: db.dir, handler: h, extensions: ex }); toast("Handler added", "good"); hName.value = ""; hExt.value = ""; load(); }
      catch (e) { toast(e.message, "bad"); }
    }
    state.refreshHandler = load; load();
  }

  function directiveTable(entries, view, db) {
    const rows = entries.map((e) => el("tr", {}, [
      el("td", { class: "muted", text: e.raw }),
      el("td", { class: "actions" }, el("button", { class: "btn btn-sm btn-danger", text: "Remove",
        onclick: () => removeDirective(e.raw, db, () => navigate(state.view)) })),
    ]));
    return el("div", { class: "table-wrap" }, el("table", {}, [
      el("thead", {}, el("tr", {}, [el("th", { text: "Directive" }), el("th", { text: "" })])), el("tbody", {}, rows)]));
  }
  async function removeDirective(raw, db, reload) {
    if (!confirmInline(`Remove:\n${raw}`)) return;
    try { await API.apacheRemove(db.dir, raw); toast("Removed", "good"); reload(); }
    catch (e) { toast(e.message, "bad"); }
  }

  // ---- Virus Scanner (with progress bar) ----
  function viewVirus(root) {
    const body = el("div", {});
    const scanUi = el("div", { id: "scan-ui" });
    const jp = jobPanel(root); // used for "Update virus DB" job
    root.append(body, scanUi);
    let scanTimer = null;
    const stopScan = () => { if (scanTimer) { clearInterval(scanTimer); scanTimer = null; } };
    (state.cleanups = state.cleanups || []).push(stopScan);

    const load = async () => {
      await guardedLoad(async () => {
        const st = await API.avStatus();
        body.innerHTML = "";
        if (!st.available) {
          body.append(el("div", { class: "card" }, [
            el("h3", { text: "ClamAV not installed" }),
            el("p", { class: "muted", text: "Install the 'clamav' package (Packages section, or apt install clamav) to enable on-demand virus scanning." }),
          ]));
          return;
        }
        body.append(el("div", { class: "card" }, [
          el("h3", { text: "On-demand scan (ClamAV)" }),
          el("div", { class: "toolbar" }, [
            el("input", { id: "av-path", type: "text", placeholder: `${sysHome()}  (absolute path to scan)`, style: "flex:1;min-width:240px" }),
            el("button", { class: "btn btn-sm btn-primary", text: "Scan", onclick: scan }),
            el("button", { class: "btn btn-sm", text: "Update virus DB", onclick: update }),
          ]),
          el("div", { class: "av-quick" }, [["Home", sysHome()], ["Main site", "/var/www/html"], ["All sites", "/var/www"], ["Mail", "/var/mail"], ["Temp", "/tmp"], ["Whole system", "/"]].map(([l, p]) =>
            el("button", { class: "btn btn-sm btn-ghost", title: p, onclick: () => { $("#av-path").value = p; } }, [icon("folder", 12), ` ${l}`]))),
          el("p", { class: "muted", style: "font-size:12px;margin:8px 0 0", text: "Scans run in the background, watch progress below." }),
        ]));
        // every website's folder as a quick pick too
        API.sites().then((s) => { const q = $(".av-quick", body); if (!q) return; for (const x of (s.sites || []).filter((x) => !x.system && x.docroot)) q.append(el("button", { class: "btn btn-sm btn-ghost", title: x.docroot, onclick: () => { $("#av-path").value = x.docroot; } }, [icon("globe", 12), ` ${x.server_name}`])); }).catch(() => {});
      });
    };

    function renderScan(job) {
      const total = (job.meta && job.meta.total_files) || 0;
      const lines = (job.output || "").split("\n");
      // Per-file lines look like "<path>: OK" or "<path>: <sig> FOUND".
      const scanned = lines.filter((l) => /: OK\s*$/.test(l) || /FOUND\s*$/.test(l)).length;
      const infected = lines.filter((l) => /FOUND\s*$/.test(l));
      const lastFile = [...lines].reverse().find((l) => /: OK\s*$/.test(l) || /FOUND\s*$/.test(l)) || "";
      const running = job.status === "running";
      const known = total > 0;
      const pct = known ? Math.min(100, Math.round((scanned / total) * 100)) : (running ? 0 : 100);

      // Pull the clamscan summary block (after "SCAN SUMMARY") once finished.
      let summary = "";
      const sumIdx = lines.findIndex((l) => /SCAN SUMMARY/.test(l));
      if (sumIdx >= 0) summary = lines.slice(sumIdx).join("\n");

      scanUi.innerHTML = "";
      const meterCls = infected.length ? "bad" : "";
      const meter = el("div", { class: `meter big ${meterCls} ${known ? "" : (running ? "indeterminate" : "")}` },
        el("span", { style: known ? `width:${pct}%` : "" }));
      const statusPill = running
        ? el("span", { class: "pill warn", text: "scanning" })
        : el("span", { class: `pill ${job.status === "done" && !infected.length ? "good" : "bad"}`,
            text: job.status === "done" ? (infected.length ? `${infected.length} infected` : "clean") : "failed" });

      const card = el("div", { class: "card" }, [
        el("div", { style: "display:flex;justify-content:space-between;align-items:center" }, [
          el("h3", { text: "Scan progress", style: "margin:0" }), statusPill,
        ]),
        meter,
        el("div", { class: "scan-stat" }, [
          el("span", { class: "muted", text: known ? `${scanned.toLocaleString()} / ${total.toLocaleString()} files` : `${scanned.toLocaleString()} files scanned` }),
          el("span", { text: known ? `${pct}%` : (running ? "…" : "done") }),
        ]),
        running && lastFile ? el("div", { class: "scan-current", text: lastFile.replace(/: OK\s*$/, "").replace(/: .*FOUND\s*$/, "") }) : null,
      ]);
      scanUi.append(card);

      if (infected.length) {
        scanUi.append(el("div", { class: "card", style: "margin-top:14px" }, [
          el("h3", { text: `⚠ Infected files (${infected.length})` }),
          el("div", {}, infected.map((l) => el("div", { class: "infected-line", text: l }))),
        ]));
      }
      if (summary && !running) {
        scanUi.append(el("div", { class: "card", style: "margin-top:14px" }, [
          el("h3", { text: "Summary" }), el("pre", { class: "log", text: summary }),
        ]));
      }
    }

    async function scan() {
      const path = $("#av-path").value.trim();
      if (!path) { toast("Path required", "bad"); return; }
      stopScan();
      scanUi.innerHTML = '<div class="card"><div class="loading">Counting files & starting scan…</div></div>';
      let jobId;
      try { const r = await API.avScan(path, true); jobId = r.job; }
      catch (e) { scanUi.innerHTML = ""; toast(e.message, "bad"); return; }
      const tick = async () => {
        try {
          const job = await API.job(jobId);
          renderScan(job);
          if (job.status !== "running") {
            stopScan();
            const inf = (job.output || "").split("\n").filter((l) => /FOUND\s*$/.test(l)).length;
            toast(inf ? `Scan complete, ${inf} infected` : "Scan complete, clean", inf ? "bad" : "good");
          }
        } catch (e) { stopScan(); toast(e.message, "bad"); }
      };
      await tick();
      scanTimer = setInterval(tick, 1000);
    }
    async function update() {
      try { const r = await API.avUpdate(); jp.run(r.job, "Updating virus DB"); } catch (e) { toast(e.message, "bad"); }
    }
    state.refreshHandler = load; load();
  }

  // ---- Track DNS ----
  function viewDns(root) {
    const TYPES = ["A", "AAAA", "CNAME", "MX", "TXT", "NS", "SOA", "CAA", "SRV"];
    const RES = [["system", "Ask this Pi"], ["cloudflare", "Cloudflare 1.1.1.1"], ["google", "Google 8.8.8.8"], ["quad9", "Quad9 9.9.9.9"], ["opendns", "OpenDNS"]];
    let hist = []; try { hist = JSON.parse(localStorage.getItem("aurora.dns.recent") || "[]"); } catch (e) {}
    const input = el("input", { type: "text", placeholder: "domain or IP address, example.com", list: "dns-recent", style: "flex:1;min-width:240px", onkeydown: (e) => { if (e.key === "Enter") run("records"); } });
    const dl = el("datalist", { id: "dns-recent" }, hist.map((h) => el("option", { value: h })));
    const server = el("select", { title: "Which resolver answers", style: "max-width:220px;flex:0 1 220px" }, RES.map(([v, l]) => el("option", { value: v, text: l })));
    let types = new Set(["A", "AAAA", "CNAME", "MX", "TXT", "NS"]);
    const typeChips = el("div", { class: "cw-seg cw-seg-sm" });
    const drawTypes = () => {
      typeChips.innerHTML = "";
      TYPES.forEach((t) => typeChips.append(el("button", { type: "button", class: types.has(t) ? "active" : "", text: t, onclick: () => { if (types.has(t)) types.delete(t); else types.add(t); drawTypes(); } })));
      typeChips.append(el("button", { type: "button", class: types.size === TYPES.length ? "active" : "", text: "All", onclick: () => { types = new Set(TYPES); drawTypes(); } }));
    };
    drawTypes();
    const TOOLS = [["records", "Lookup", "btn-primary", "The chosen record types"], ["propagation", "Propagation", "", "Has a change reached the big public resolvers yet?"], ["mail", "Mail records", "", "MX, SPF, DKIM, DMARC, what a mail domain needs"],
      ["ns", "Name servers", "", "Do all authoritative servers carry the same zone?"], ["whois", "WHOIS", "", "Registrar, dates, name servers, or the owner of an IP range"], ["reverse", "Reverse (PTR)", "", "The name behind an IP address"], ["trace", "Traceroute", "", "The path packets take from this Pi"]];
    const quick = el("div", { class: "dns-quick" });
    const body = el("div", {});
    root.append(el("div", { class: "card", style: "margin-bottom:16px" }, [
      el("div", { class: "toolbar", style: "margin:0 0 10px" }, [input, dl, server]),
      el("div", { class: "toolbar", style: "margin:0 0 10px;gap:8px" }, [el("span", { class: "muted", style: "font-size:12.5px", text: "Records" }), typeChips]),
      el("div", { class: "toolbar", style: "margin:0" }, TOOLS.map(([k, l, c, tip]) => btn(l, () => run(k), c || "btn-ghost", tip))),
      quick,
    ]), body);
    // the user's own names, one click away
    (async () => {
      const names = new Set();
      try { for (const x of (await API.sites()).sites || []) if (!x.system && !isIp(x.server_name)) names.add(x.server_name); } catch (e) {}
      try { for (const z of (await API.dnsZones()).zones || []) names.add(z.domain); } catch (e) {}
      if (!names.size) return;
      quick.append(el("span", { class: "muted", style: "font-size:12.5px", text: "Yours:" }), ...[...names].slice(0, 12).map((n) => el("button", { class: "btn btn-sm btn-ghost", text: n, onclick: () => { input.value = n; run("records"); } })));
    })();
    const remember = (h) => { hist = [h, ...hist.filter((x) => x !== h)].slice(0, 12); try { localStorage.setItem("aurora.dns.recent", JSON.stringify(hist)); } catch (e) {} dl.innerHTML = ""; hist.forEach((x) => dl.append(el("option", { value: x }))); };
    const copyBtn = (text) => btn("Copy", async () => toast(await copyText(text) ? "Copied" : "Copy failed", "good"), "btn-ghost");
    const vals = (arr) => el("div", { class: "dns-vals" }, arr.map((v) => el("code", { text: v })));
    const table = (heads, rows) => el("div", { class: "table-wrap" }, el("table", {}, [el("thead", {}, el("tr", {}, heads.map((h) => el("th", { text: h })))), el("tbody", {}, rows)]));
    async function run(kind) {
      const host = input.value.trim(); if (!host) { input.focus(); return; }
      remember(host);
      const msg = { records: "Resolving…", propagation: "Asking five resolvers…", mail: "Checking MX, SPF, DKIM and DMARC…", ns: "Asking the authoritative servers…", whois: "Asking the registry…", reverse: "Looking up…", trace: "Tracing the route (up to a minute)…" }[kind];
      body.innerHTML = ""; body.append(el("div", { class: "loading", text: msg }));
      try {
        let d, card;
        if (kind === "records") {
          d = await API.dnsRecords(host, [...types], server.value);
          const all = Object.values(d.records).flat();
          card = el("div", { class: "card" }, [el("div", { style: "display:flex;align-items:center;gap:10px;margin-bottom:10px" }, [el("h3", { style: "margin:0", text: `${d.host} · answered by ${d.server}` }), el("span", { class: "grow" }), all.length ? copyBtn(Object.entries(d.records).map(([t, v]) => v.map((x) => `${t}\t${x}`).join("\n")).filter(Boolean).join("\n")) : null]),
            table(["Type", "Value", ""], Object.entries(d.records).map(([t, v]) => el("tr", {}, [el("td", {}, el("b", { text: t })), el("td", { class: "muted" }, v.length ? vals(v) : el("span", { text: ", " })), el("td", { class: "actions" }, v.length ? copyBtn(v.join("\n")) : null)]))),
            all.length ? null : el("p", { class: "dm-hint", style: "margin-top:10px", text: "Nothing came back. Typo? Not delegated yet? Try WHOIS to see whether the name is registered at all." })]);
        } else if (kind === "propagation") {
          const t = [...types][0] || "A";
          d = await API.dnsPropagation(host, t);
          card = el("div", { class: "card" }, [el("h3", { text: `${t} record of ${d.host}, as the world sees it` }),
            el("div", { class: `mx-note ${d.agree ? "" : "warn"}`, style: "margin-bottom:12px" }, [icon(d.agree ? "check" : "warning", 16), el("span", { text: d.agree ? "Every resolver gives the same answer, the record has propagated." : "Resolvers disagree: a recent change is still spreading. Old answers live on until their TTL runs out, usually under an hour, up to a day." })]),
            table(["Resolver", "Answer"], d.resolvers.map((r) => el("tr", {}, [el("td", { text: `${r.name}${r.ip ? ` · ${r.ip}` : ""}` }), el("td", { class: "muted" }, r.answers.length ? vals(r.answers) : el("span", { class: "pill warn", text: "no answer" }))])))]);
        } else if (kind === "mail") {
          d = await API.dnsMailCheck(host);
          const row = (ok, name, v, hint) => el("div", { class: "dns-mail-row" }, [el("span", { class: `pill ${ok ? "good" : "warn"}`, text: ok ? "ok" : "missing" }), el("div", { style: "min-width:0" }, [el("b", { text: name }), v.length ? vals(v) : el("p", { class: "muted", style: "margin:2px 0 0;font-size:12.5px", text: hint })])]);
          const n = Object.values(d.ok).filter(Boolean).length;
          card = el("div", { class: "card" }, [el("h3", { text: `Mail records of ${d.domain} · ${n} of 4 in place` }),
            row(d.ok.mx, "MX, where mail for this domain is delivered", d.mx, "No MX record: nobody can send mail to this domain."),
            row(d.ok.spf, "SPF, which servers may send as this domain", d.spf, "Add a TXT record such as   v=spf1 mx -all"),
            row(d.ok.dmarc, "DMARC, what receivers do with forgeries", d.dmarc, `Add a TXT record at _dmarc.${d.domain}:   v=DMARC1; p=quarantine; rua=mailto:postmaster@${d.domain}`),
            row(d.ok.dkim, "DKIM, signed mail", Object.entries(d.dkim).map(([sel, v]) => `${sel}: ${v.join(" ")}`), "No key under the usual selectors (default, mail, dkim, selector1, selector2, google, k1, s1). Your mail server's documentation names its selector."),
            el("p", { class: "dm-hint", style: "margin-top:10px", text: "For domains hosted here, Email → Deliverability shows the exact records to publish." })]);
        } else if (kind === "ns") {
          d = await API.dnsNsCheck(host);
          card = el("div", { class: "card" }, [el("h3", { text: `Name servers of ${d.domain}` }),
            el("p", { class: "muted", style: "margin:0 0 10px", text: !d.ns.length ? "No NS records: the domain isn't delegated (or isn't a zone, try its parent domain)." : d.agree ? "All name servers answer and carry the same zone version (SOA serial)." : "The name servers carry different zone versions, or one doesn't answer, a change hasn't reached all of them yet." }),
            d.ns.length ? table(["Name server", "Address", "Zone serial", "Answers"], d.servers.map((x) => el("tr", {}, [el("td", { text: x.ns }), el("td", { class: "muted", text: x.ip || "?" }), el("td", {}, el("code", { text: x.serial || ", " })), el("td", {}, el("span", { class: `pill ${x.ok ? "good" : "bad"}`, text: x.ok ? "yes" : "no" }))]))) : null]);
        } else if (kind === "whois") {
          d = await API.dnsWhois(host);
          const keys = Object.entries(d.summary);
          card = el("div", { class: "card" }, [el("h3", { text: `WHOIS · ${d.host}` }),
            keys.length ? el("div", { class: "dns-kv" }, keys.map(([k, v]) => el("div", {}, [el("span", { class: "muted", text: k }), el("b", { text: v })]))) : el("p", { class: "muted", text: "No structured fields recognised, the full record is below." }),
            el("details", { style: "margin-top:12px" }, [el("summary", { class: "muted", style: "cursor:pointer;font-size:13px", text: "Full record" }), el("pre", { class: "log", style: "margin-top:8px", text: d.text || "(empty)" })])]);
        } else if (kind === "reverse") {
          d = await API.dnsReverse(host);
          card = el("div", { class: "card" }, [el("h3", { text: `Reverse DNS · ${d.ip}` }), el("pre", { class: "log", text: d.result })]);
        } else {
          d = await API.dnsTrace(host);
          card = el("div", { class: "card" }, [el("h3", { text: `Traceroute · ${d.host}` }), el("pre", { class: "log", text: d.output })]);
        }
        body.innerHTML = ""; body.append(card);
      } catch (e) { body.innerHTML = ""; body.append(el("p", { class: "empty", text: e.message })); }
    }
  }

  // ======================================================================
  //  Shared helpers for Security / Domains / Databases
  // ======================================================================
  function installCard(title, msg, onInstall) {
    return el("div", { class: "card" }, [
      el("h3", { text: title }),
      el("p", { class: "muted", style: "margin:0 0 12px", text: msg }),
      onInstall ? el("button", { class: "btn btn-sm btn-primary", text: "Install now", onclick: onInstall }) : null,
    ]);
  }
  function simpleTable(headers, rows) {
    return el("div", { class: "table-wrap" }, el("table", {}, [
      el("thead", {}, el("tr", {}, headers.map((h) => el("th", { text: h })))),
      el("tbody", {}, rows),
    ]));
  }

  // ---- SSH Access ----
  function viewSSH(root) {
    const status = el("div", { id: "ssh-status" }, el("div", { class: "loading", text: "Loading…" }));
    const keysWrap = el("div", { style: "margin-top:16px" });
    root.append(status, keysWrap);
    let userSel = sysUser();
    const load = async () => {
      await guardedLoad(async () => {
        const st = await API.sshStatus();
        status.innerHTML = "";
        if (!st.supported) { status.append(el("p", { class: "empty", text: "SSH management is Linux-only." })); return; }
        const c = st.config;
        status.append(el("div", { class: "card" }, [
          el("div", { style: "display:flex;justify-content:space-between;align-items:center" }, [
            el("h3", { text: "SSH daemon", style: "margin:0" }),
            el("span", { class: `pill ${st.active === "active" ? "good" : "bad"}`, text: st.active || "unknown" }),
          ]),
          el("div", { class: "stat-sub", style: "margin-top:10px",
            html: `Port <b>${esc(c.port)}</b> · PermitRootLogin <b>${esc(c.permit_root_login)}</b> · PasswordAuth <b>${esc(c.password_auth)}</b> · startup <b>${esc(st.enabled || "?")}</b>` }),
          el("div", { style: "margin-top:12px" }, el("button", { class: "btn btn-sm", text: "↻ Restart sshd",
            onclick: async () => { if (!confirmInline("Restart the SSH daemon? Existing sessions stay connected.")) return;
              try { await API.sshRestart(); toast("sshd restarted", "good"); } catch (e) { toast(e.message, "bad"); } } })),
        ]));
        loadKeys();
      });
    };
    async function loadKeys() {
      await state.meReady;
      userSel = sysUser();
      const data = await API.sshKeys(userSel);
      keysWrap.innerHTML = "";
      const addForm = el("div", { class: "card", style: "margin-bottom:16px" }, [
        el("h3", { text: `Authorized keys for ${userSel}` }),
        el("textarea", { id: "ssh-newkey", class: "editor", style: "min-height:80px", placeholder: "ssh-ed25519 AAAA… user@host" }),
        el("div", { style: "margin-top:10px" }, el("button", { class: "btn btn-sm btn-primary", text: "Add key", onclick: async () => {
          try { await API.sshKeyAdd(userSel, $("#ssh-newkey").value.trim()); toast("Key added", "good"); loadKeys(); }
          catch (e) { toast(e.message, "bad"); } } })),
      ]);
      keysWrap.append(addForm);
      if (!data.keys.length) { keysWrap.append(el("p", { class: "empty", text: "No authorized keys." })); return; }
      const rows = data.keys.map((k) => el("tr", {}, [
        el("td", { text: k.type }), el("td", { class: "muted", text: k.comment || ", " }),
        el("td", { class: "muted", style: "font-family:monospace;font-size:11px", text: k.fingerprint }),
        el("td", { class: "actions" }, el("button", { class: "btn btn-sm btn-danger", text: "Remove", onclick: async () => {
          if (!confirmInline("Remove this key?")) return;
          try { await API.sshKeyRemove(userSel, k.raw); toast("Removed", "good"); loadKeys(); } catch (e) { toast(e.message, "bad"); } } })),
      ]));
      keysWrap.append(simpleTable(["Type", "Comment", "Fingerprint", ""], rows));
    }
    state.refreshHandler = load; load();
  }

  // ---- IP Blocker ----
  // ======================================================================
  //  IP Blocker & Trust, bans (IPs / ranges, expiry), fail2ban bans, trusted list
  // ======================================================================
  const BAN_DURATIONS = [[3600, "1 hour"], [86400, "1 day"], [604800, "1 week"], [2592000, "30 days"], [0, "Permanent"]];
  // one colour rule for every IP shown: banned = red, trusted = green, reported (and nothing else) = orange
  const ipCls = (st, rep) => (st === "banned" ? "ip-banned" : st === "trusted" ? "ip-trusted" : rep ? "ip-reported" : "");
  const fmtDur = (s) => s == null ? ", " : s < 3600 ? `${Math.ceil(s / 60)} min` : s < 86400 ? `${Math.round(s / 3600)} h` : `${Math.round(s / 86400)} d`;
  function rangeOf(ip, bits) {
    const p = String(ip).split(".").map(Number);
    if (p.length !== 4) return ip;
    if (bits === 24) return `${p[0]}.${p[1]}.${p[2]}.0/24`;
    if (bits === 16) return `${p[0]}.${p[1]}.0.0/16`;
    return ip;
  }
  // Ban dialog (IP, its /24 or /16, or any custom range), used by the Monitor and the IP Blocker.
  function banDialog(ip, done) {
    const target = el("input", { type: "text", value: ip || "", placeholder: "203.0.113.7  or  203.0.113.0/24" });
    const scope = isIPv4(ip) ? el("div", { class: "cw-seg cw-seg-sm" }, [["ip", `Just ${ip}`], [24, "Its /24 (256 addresses)"], [16, "Its /16 (65,536)"]].map(([k, l]) =>
      el("button", { type: "button", class: k === "ip" ? "active" : "", text: l, onclick: (e) => {
        target.value = k === "ip" ? ip : rangeOf(ip, k); e.target.parentNode.querySelectorAll("button").forEach((b) => b.classList.toggle("active", b === e.target)); } }))) : null;
    const dur = el("select", {}, BAN_DURATIONS.map(([v, l]) => el("option", { value: v, text: l })));
    dur.value = "86400";
    const reason = el("input", { type: "text", maxlength: 120, placeholder: "e.g. SSH brute force" });
    const go = btn("Ban", async () => {
      go.disabled = true;
      try {
        const r = await API.guardBan(target.value.trim(), reason.value.trim(), +dur.value || null, TITLES[state.view] || state.view);
        closeModal(); toast(`Banned ${r.ban.cidr}${r.replaced.length ? ` (replaced ${r.replaced.length} narrower ban${r.replaced.length > 1 ? "s" : ""})` : ""}`, "good"); done && done();
      } catch (e) { toast(e.message, "bad"); go.disabled = false; }
    }, "btn-danger");
    openModal("Ban an address", el("div", {}, [
      scope, field("Address or range", target, "A single IP, or CIDR like 203.0.113.0/24."), el("div", { class: "net-form" }, [field("For how long", dur), field("Reason (optional)", reason)]),
      el("p", { class: "dm-hint", text: "Banned addresses can't reach anything on this Pi. Your own address, this Pi, your router and trusted addresses can't be banned." }),
    ]), [go]);
  }
  function trustDialog(ip, done) {
    const target = el("input", { type: "text", value: ip || "", placeholder: "192.168.0.2  or  192.168.0.0/24" });
    const note = el("input", { type: "text", maxlength: 120, placeholder: "e.g. my laptop / office network" });
    const go = btn("Trust", async () => {
      go.disabled = true;
      try { const r = await API.guardTrust(target.value.trim(), note.value.trim()); closeModal(); toast(`Trusted${r.unbanned.length ? `, lifted ${r.unbanned.length} ban(s)` : ""}`, "good"); done && done(); }
      catch (e) { toast(e.message, "bad"); go.disabled = false; }
    }, "btn-primary");
    openModal("Trust an address", el("div", {}, [field("Address or range", target), field("Note (optional)", note),
      el("p", { class: "dm-hint", text: "Trusted addresses are never blocked: existing bans on them are lifted, manual bans are refused, and fail2ban ignores them (they're added to its ignore list automatically)." })]), [go]);
  }
  function viewIPBlocker(root) {
    const body = el("div", {}, el("div", { class: "loading", text: "Loading…" }));
    root.append(el("div", { class: "toolbar" }, [btn("Ban an address…", () => banDialog("", load), "btn-danger"), btn("Trust an address…", () => trustDialog("", load), "btn-primary"),
      btn("Fail2ban settings", () => navigate("leech"), "btn-ghost"), btn("Network Monitor", () => navigate("netmon"), "btn-ghost")]), body);
    const when = (ts) => (ts ? `${new Date(ts * 1000).toLocaleString()} (${ago(ts)})` : ", ");
    const bare = (cidr) => String(cidr || "").replace(/\/(32|128)$/, "");
    const lookup = (ip) => { const f = (extraViews()._ui || {}).ipCard; if (f) f(ip, load); };
    const reportIp = (ip, done) => { const f = (extraViews()._ui || {}).reportIp; if (f) f(ip, done); };
    const single = (cidr) => !String(cidr).includes("/") || /\/(32|128)$/.test(cidr);
    const unban = (t) => btn("Unban", async () => { try { await API.guardUnban(t); toast(`${t} unbanned`, "good"); load(); } catch (e) { toast(e.message, "bad"); } });
    const load = () => guardedLoad(async () => {
      let reported = {};
      const [d] = await Promise.all([API.guard(), API.abuseReported().then((r) => { reported = r || {}; }).catch(() => {})]);
      const bannedSet = new Set([...d.bans.map((b) => bare(b.cidr)), ...d.fail2ban.map((a) => a.ip)]);
      // "reported" pill: when the address was sent to its network's abuse desk (click it to read or send again)
      const repPill = (ip) => { const r = reported[ip]; return r ? el("button", { type: "button", class: "pill warn pill-btn-rep", text: `reported ${ago(r.ts)}`,
        title: `Reported to ${(r.to || []).join(", ")} on ${new Date(r.ts * 1000).toLocaleString()}, click to read or send again`, onclick: () => reportIp(ip, load) }) : null; };
      const addr = (ip, cidr, st) => el("div", { class: "net-actions" }, [el("code", { class: `net-mono ${ipCls(st || "banned", reported[ip])}`, text: cidr || ip }), repPill(ip)]);
      body.innerHTML = "";
      if (!d.enabled) body.append(el("p", { class: "dm-hint", text: "The ban list is created the first time you ban or trust something." }));
      body.append(el("h2", { class: "section-title", text: `Banned by you (${d.bans.length})` }));
      body.append(el("p", { class: "dm-hint", text: "Every ban made from the panel, the IP card, Network Monitor, WAF Firewall, Visitors or here, with when, from where and why. “reported” means its abuse desk was told." }));
      body.append(d.bans.length ? simpleTable(["Address / range", "Banned at", "Banned from", "Reason", "Expires", "Blocked packets", ""], d.bans.map((b) => row(
        addr(bare(b.cidr), b.cidr), when(b.created), el("span", { class: "pill dim", text: b.source || "IP Blocker" }), b.reason || ", ",
        b.expires ? `${new Date(b.expires * 1000).toLocaleString()} (in ${fmtDur(b.expires - Date.now() / 1000)})` : "never",
        b.packets, el("div", { class: "net-actions" }, [
          single(b.cidr) ? btn("Lookup", () => lookup(bare(b.cidr)), "btn-ghost") : null,
          single(b.cidr) && !reported[bare(b.cidr)] ? btn("Report", () => reportIp(bare(b.cidr), load), "btn-ghost") : null,
          unban(b.cidr)].filter(Boolean)),
      ))) : el("p", { class: "empty", text: "No manual bans." }));
      body.append(el("h2", { class: "section-title", text: `Banned by fail2ban (${d.fail2ban.length})` }));
      body.append(d.fail2ban.length ? simpleTable(["Address", "Caught by", "Time left", "Blocked packets", ""], d.fail2ban.map((a) => row(
        addr(a.ip), el("span", { class: "pill warn", text: `fail2ban · ${a.jails.join(", ") || "jail"}` }), a.expires_in ? fmtDur(a.expires_in) : "until unbanned", a.packets,
        el("div", { class: "net-actions" }, [
          btn("Lookup", () => lookup(a.ip), "btn-ghost"),
          reported[a.ip] ? null : btn("Report", () => reportIp(a.ip, load), "btn-ghost"),
          unban(a.ip),
          btn("Ban permanently", () => banDialog(a.ip, load), "btn-ghost")].filter(Boolean)),
      ))) : el("p", { class: "empty", text: "Nothing is banned automatically right now." }));
      // Reported to abuse desks, with whether the address is (still) banned here
      const reps = Object.entries(reported).sort((x, y) => y[1].ts - x[1].ts);
      body.append(el("h2", { class: "section-title", text: `Reported to abuse desks (${reps.length})` }));
      body.append(reps.length ? simpleTable(["Address", "Reported at", "To", "From", "Evidence", "Status here", ""], reps.map(([ip, r]) => row(
        el("code", { class: `net-mono ${bannedSet.has(ip) ? "ip-banned" : "ip-reported"}`, text: ip }), when(r.ts), (r.to || []).join(", "), r.from || ", ", r.events ? `${r.events} event${r.events === 1 ? "" : "s"}` : ", ",
        bannedSet.has(ip) ? pill("banned", "bad") : pill("not banned", "dim"),
        el("div", { class: "net-actions" }, [btn("Lookup", () => lookup(ip), "btn-ghost"), btn("Read / send again", () => reportIp(ip, load), "btn-ghost"),
          bannedSet.has(ip) ? null : btn("Ban", () => banDialog(ip, load), "btn-danger")].filter(Boolean)),
      ))) : el("p", { class: "empty", text: "No abuse reports sent yet. Report an attacker from its IP card, the WAF Firewall or Network Monitor, the owner's abuse desk gets the evidence by email." }));
      body.append(el("h2", { class: "section-title", text: `Trusted (${d.trusted.length})` }));
      body.append(d.trusted.length ? simpleTable(["Address / range", "Note", "Added", ""], d.trusted.map((t) => row(
        el("code", { class: "net-mono ip-trusted", text: t.cidr }), t.note || ", ", new Date(t.created * 1000).toLocaleDateString(),
        el("div", { class: "net-actions" }, [btn("Remove", async () => { if (!confirmInline(`Stop trusting ${t.cidr}? It can then be banned by fail2ban again.`)) return; try { await API.guardUntrust(t.cidr); toast("Removed", "good"); load(); } catch (e) { toast(e.message, "bad"); } }, "btn-danger")]),
      ))) : el("p", { class: "empty", text: "No trusted addresses. Tip: trust your own devices (or your LAN range) so a mistyped password never locks you out." }));
      body.append(el("p", { class: "dm-hint", text: `Always protected: ${d.protected.join(", ")}.` }));
    });
    state.refreshHandler = load; load();
    const t = setInterval(load, 15000); state.cleanups.push(() => clearInterval(t));
  }

  // ---- SSL/TLS Certificates ----
  function viewSSL(root) {
    const form = el("div", { class: "card", style: "margin-bottom:16px" }, [
      el("h3", { text: "Generate self-signed certificate" }),
      el("div", { class: "toolbar" }, [
        el("input", { id: "ssl-cn", type: "text", placeholder: "common name (e.g. pi.local)", style: "max-width:240px" }),
        el("input", { id: "ssl-days", type: "number", value: "365", style: "max-width:100px" }),
        el("button", { class: "btn btn-sm btn-primary", text: "Generate", onclick: gen }),
      ]),
    ]);
    const body = el("div", { id: "ssl-body" }, el("div", { class: "loading", text: "Loading…" }));
    root.append(form, body);
    const load = async () => {
      await guardedLoad(async () => {
        const d = await API.sslCerts();
        body.innerHTML = "";
        body.append(el("p", { class: "muted", style: "margin:0 0 10px", text: `Self-signed certs are written to ${d.cert_dir}` }));
        if (!d.certs.length) { body.append(el("p", { class: "empty", text: "No certificates found." })); return; }
        const rows = d.certs.map((c) => el("tr", {}, [
          el("td", { text: c.name }), el("td", { class: "muted", text: c.subject || ", " }),
          el("td", { class: "muted", text: c.expires || ", " }),
          el("td", {}, el("span", { class: `pill ${c.self_signed ? "warn" : "good"}`, text: c.self_signed ? "self-signed" : "CA" })),
        ]));
        body.append(simpleTable(["File", "Subject", "Expires", "Type"], rows));
      });
    };
    async function gen() {
      try { const r = await API.sslSelfSigned($("#ssl-cn").value.trim(), parseInt($("#ssl-days").value) || 365);
        toast("Certificate generated", "good"); load(); }
      catch (e) { toast(e.message, "bad"); }
    }
    state.refreshHandler = load; load();
  }

  // ---- Manage API Tokens ----
  function viewAPITokens(root) {
    const form = el("div", { class: "card", style: "margin-bottom:16px" }, [
      el("h3", { text: "Create API token" }),
      el("p", { class: "muted", style: "margin:0 0 10px;font-size:12px", text: "Tokens authenticate API calls via header  Authorization: Bearer <token>.  Shown once." }),
      el("div", { class: "toolbar" }, [
        el("input", { id: "tok-name", type: "text", placeholder: "token name", style: "max-width:240px" }),
        el("button", { class: "btn btn-sm btn-primary", text: "Create", onclick: create }),
      ]),
    ]);
    const body = el("div", { id: "tok-body" }, el("div", { class: "loading", text: "Loading…" }));
    root.append(form, body);
    const load = async () => {
      await guardedLoad(async () => {
        const d = await API.tokens();
        body.innerHTML = "";
        if (!d.tokens.length) { body.append(el("p", { class: "empty", text: "No tokens." })); return; }
        const rows = d.tokens.map((t) => el("tr", {}, [
          el("td", { text: t.name }), el("td", { class: "muted", style: "font-family:monospace", text: t.prefix + "…" }),
          el("td", { class: "muted", text: new Date(t.created * 1000).toLocaleString() }),
          el("td", { class: "actions" }, el("button", { class: "btn btn-sm btn-danger", text: "Revoke", onclick: async () => {
            if (!confirmInline(`Revoke token "${t.name}"?`)) return;
            try { await API.tokenRevoke(t.id); toast("Revoked", "good"); load(); } catch (e) { toast(e.message, "bad"); } } })),
        ]));
        body.append(simpleTable(["Name", "Prefix", "Created", ""], rows));
      });
    };
    async function create() {
      const name = $("#tok-name").value.trim(); if (!name) return;
      try {
        const r = await API.tokenCreate(name);
        const ta = el("input", { type: "text", value: r.token, readonly: "readonly", style: "font-family:monospace;width:100%" });
        openModal("API token created", el("div", {}, [
          el("p", { class: "muted", text: "Copy this token now, it will not be shown again:" }),
          ta,
        ]), [el("button", { class: "btn btn-primary", text: "Copy", onclick: () => { ta.select(); try { document.execCommand("copy"); toast("Copied", "good"); } catch (e) {} } })]);
        $("#tok-name").value = ""; load();
      } catch (e) { toast(e.message, "bad"); }
    }
    state.refreshHandler = load; load();
  }

  // ---- Hotlink Protection ----
  function viewHotlink(root) {
    const db = apacheDirBar("hotlink", "Blocks other sites from embedding your images (writes RewriteRules to .htaccess).", () => load());
    const body = el("div", { id: "hl-body" }, el("div", { class: "loading", text: "Loading…" }));
    root.append(db.bar, db.note, body);
    async function load() {
      body.innerHTML = '<div class="loading">Loading…</div>';
      try {
        const d = await API.hotlink(db.dir);
        body.innerHTML = "";
        body.append(el("div", { class: "card" }, [
          el("label", { class: "muted", style: "display:flex;align-items:center;gap:8px;margin-bottom:12px" }, [
            el("input", { id: "hl-enabled", type: "checkbox", style: "width:auto", ...(d.enabled ? { checked: "checked" } : {}) }),
            "Enable hotlink protection",
          ]),
          el("h3", { text: "Allowed hosts (your domains)" }),
          el("input", { id: "hl-hosts", type: "text", value: d.allowed_hosts || "", placeholder: "example.com www.example.com", style: "max-width:420px" }),
          el("h3", { text: "Protected extensions", style: "margin-top:12px" }),
          el("input", { id: "hl-ext", type: "text", value: d.extensions || "jpg jpeg png gif webp svg", style: "max-width:420px" }),
          el("div", { style: "margin-top:14px" }, el("button", { class: "btn btn-sm btn-primary", text: "Save", onclick: save })),
        ]));
      } catch (e) { body.innerHTML = ""; body.append(el("p", { class: "empty", text: e.message })); }
    }
    async function save() {
      try { await API.hotlinkSet({ dir: db.dir, enabled: $("#hl-enabled").checked, allowed_hosts: $("#hl-hosts").value.trim(), extensions: $("#hl-ext").value.trim() });
        toast("Saved", "good"); load(); }
      catch (e) { toast(e.message, "bad"); }
    }
    state.refreshHandler = load; load();
  }

  // ---- Redirects ----
  function viewRedirects(root) {
    const db = apacheDirBar("redirects", "HTTP redirects written to .htaccess (Redirect directive).", () => load());
    const form = el("div", { class: "card", style: "margin-bottom:16px" }, [
      el("h3", { text: "Add redirect" }),
      el("div", { class: "toolbar" }, [
        el("select", { id: "rd-code", style: "max-width:110px" }, [["301", "301 permanent"], ["302", "302 temporary"]].map(([v, t]) => el("option", { value: v, text: t }))),
        el("input", { id: "rd-src", type: "text", placeholder: "/old-path", style: "max-width:180px" }),
        el("input", { id: "rd-dst", type: "text", placeholder: "https://new-target/…", style: "flex:1;min-width:200px" }),
        el("button", { class: "btn btn-sm btn-primary", text: "Add", onclick: add }),
      ]),
    ]);
    const body = el("div", { id: "rd-body" }, el("div", { class: "loading", text: "Loading…" }));
    root.append(db.bar, db.note, form, body);
    async function load() {
      body.innerHTML = '<div class="loading">Loading…</div>';
      try {
        const d = await API.redirects(db.dir);
        body.innerHTML = "";
        if (!d.entries.length) { body.append(el("p", { class: "empty", text: "No redirects." })); return; }
        const rows = d.entries.map((e) => el("tr", {}, [
          el("td", { class: "muted", text: e.raw }),
          el("td", { class: "actions" }, el("button", { class: "btn btn-sm btn-danger", text: "Remove", onclick: () => removeDirective(e.raw, db, load) })),
        ]));
        body.append(simpleTable(["Redirect", ""], rows));
      } catch (e) { body.innerHTML = ""; body.append(el("p", { class: "empty", text: e.message })); }
    }
    async function add() {
      try { await API.redirectAdd({ dir: db.dir, code: $("#rd-code").value, source: $("#rd-src").value.trim(), target: $("#rd-dst").value.trim() });
        toast("Added", "good"); $("#rd-src").value = ""; $("#rd-dst").value = ""; load(); }
      catch (e) { toast(e.message, "bad"); }
    }
    state.refreshHandler = load; load();
  }

  // ---- Leech Protection (fail2ban) ----
  // ======================================================================
  //  Fail2ban, automatic brute-force protection
  // ======================================================================
  function viewLeech(root) {
    const body = el("div", {}, el("div", { class: "loading", text: "Loading…" }));
    root.append(el("p", { class: "muted", style: "margin:0 0 14px", text: "fail2ban watches login logs and temporarily bans addresses that keep guessing passwords. Its bans go into the same ban list as yours (IP Blocker & Trust), and trusted addresses are never banned." }), body);
    const jp = jobPanel(root);
    state.cleanups.push(jp.stop);
    const minsInput = (v, allowForever) => el("input", { type: "number", min: allowForever ? -1 : 1, value: v, style: "max-width:110px" });
    const load = () => guardedLoad(async () => {
      const d = await API.fail2ban();
      body.innerHTML = "";
      if (!d.installed) {
        body.append(installCard("fail2ban is not installed", "Install it to protect SSH, this panel, OpenVPN, FTP, web logins and MariaDB from password guessing.",
          async () => { try { const r = await API.fail2banInstall(); watchJob(jp, r.job, "Installing fail2ban", load); } catch (e) { toast(e.message, "bad"); } }));
        return;
      }
      const cfg = d.config, g = cfg.global;
      body.append(el("div", { class: "card" }, [
        el("div", { class: "net-card-h" }, [icon("trap", 20), el("h3", { text: "fail2ban" }), el("span", { style: "flex:1" }), pill(d.active ? "protecting" : "off", d.active ? "good" : "bad"),
          btn(d.active ? "Turn off" : (cfg.configured ? "Turn on" : "Turn on with recommended settings"), async () => {
            if (d.active && !confirmInline("Turn fail2ban off? Brute-force attempts will no longer be banned.")) return;
            try { await API.fail2banService(!d.active); toast(d.active ? "fail2ban stopped" : "fail2ban is protecting this Pi", "good"); load(); } catch (e) { openModal("Couldn't change fail2ban", el("pre", { class: "log", text: e.message }), []); }
          }, d.active ? "btn-ghost" : "btn-primary")]),
        !cfg.configured ? el("p", { class: "dm-hint", text: "Not yet managed by the panel, turning it on (or saving below) writes the panel's settings; the stock config is left untouched." }) : null,
      ]));
      // global
      const gf = {
        bantime: minsInput(g.bantime, true), findtime: minsInput(g.findtime), maxretry: el("input", { type: "number", min: 1, max: 1000, value: g.maxretry, style: "max-width:110px" }),
        increment: (() => { const c = el("input", { type: "checkbox", class: "sf-switch" }); c.checked = g.increment; return c; })(),
        maxtime_days: el("input", { type: "number", min: 1, max: 3650, value: g.maxtime_days, style: "max-width:110px" }),
        extra_ignore: el("input", { type: "text", value: g.extra_ignore, placeholder: "extra IPs / ranges, space separated" }),
      };
      body.append(el("div", { class: "card" }, [
        el("h3", { text: "Default rules (every jail unless it overrides them)" }),
        el("div", { class: "net-form" }, [
          field("Ban for (minutes, -1 = forever)", gf.bantime), field("Count failures within (minutes)", gf.findtime), field("Failures before a ban", gf.maxretry),
          el("label", { class: "sf-field sf-bool" }, [gf.increment, el("span", { class: "sf-label", text: "Longer bans for repeat offenders" }), el("small", { class: "dm-hint", text: "Each new ban of the same address lasts longer (up to the maximum)." })]),
          field("Longest ban (days)", gf.maxtime_days), field("Also never ban", gf.extra_ignore, "Trusted addresses are added automatically."),
        ]),
      ]));
      // jails
      const jf = {};
      const rows = d.jails.filter((j) => j.available).map((j) => {
        const on = el("input", { type: "checkbox", class: "sf-switch" }); on.checked = j.enabled;
        const mr = el("input", { type: "number", min: 1, max: 1000, value: j.maxretry, style: "max-width:80px" });
        const ft = el("input", { type: "number", min: 1, value: j.findtime === -2 ? "" : j.findtime, placeholder: "default", style: "max-width:90px" });
        const bt = el("input", { type: "number", min: -1, value: j.bantime === -2 ? "" : j.bantime, placeholder: "default", style: "max-width:90px" });
        jf[j.id] = { on, mr, ft, bt, j };
        const live = j.live;
        return row(el("div", {}, [el("b", { text: j.label }), el("div", { class: "dm-hint", text: j.desc })]), on, mr, ft, bt,
          live ? el("span", {}, [pill(`${live.banned_now} banned`, live.banned_now ? "warn" : "dim"), el("div", { class: "dm-hint", text: `${live.failed_total} failures, ${live.banned_total} bans total` })]) : el("span", { class: "dm-hint", text: j.enabled ? "not running" : "off" }),
          live && live.banned_ips.length ? el("div", { class: "net-chips" }, live.banned_ips.map((ip) => el("button", { type: "button", class: "net-chip ip-banned", title: "Unban", text: `${ip} ✕`, onclick: async () => {
            try { await API.fail2banUnban(j.id, ip); await API.guardUnban(ip).catch(() => {}); toast(`${ip} unbanned`, "good"); load(); } catch (e) { toast(e.message, "bad"); } } }))) : null);
      });
      body.append(el("h2", { class: "section-title", text: "Protections (jails)" }), el("p", { class: "dm-hint", text: "Leave time fields empty to use the defaults above. Jails for software that isn't installed are hidden." }),
        simpleTable(["Protects", "On", "Failures", "Within (min)", "Ban (min)", "Status", "Banned now"], rows));
      const save = btn("Save & apply", async () => {
        const global = { bantime: +gf.bantime.value, findtime: +gf.findtime.value, maxretry: +gf.maxretry.value, increment: gf.increment.checked, maxtime_days: +gf.maxtime_days.value, extra_ignore: gf.extra_ignore.value.trim() };
        const jails = {};
        for (const [id, x] of Object.entries(jf)) jails[id] = { enabled: x.on.checked, maxretry: +x.mr.value, findtime: x.ft.value === "" ? -2 : +x.ft.value, bantime: x.bt.value === "" ? -2 : +x.bt.value };
        save.disabled = true;
        try { await API.fail2banSave(global, jails); toast("fail2ban updated", "good"); load(); }
        catch (e) { openModal("Settings not applied", el("pre", { class: "log", text: e.message }), []); save.disabled = false; }
      }, "btn-primary");
      const manualIp = el("input", { type: "text", placeholder: "IP to ban", style: "max-width:200px" });
      const manualJail = el("select", {}, d.jails.filter((j) => j.live).map((j) => el("option", { value: j.id, text: j.label })));
      body.append(...[el("div", { class: "sf-actions" }, [save, btn("View log", async () => { const r = await API.fail2banLogs(); openModal("fail2ban log", el("pre", { class: "log app-log", text: r.text || "(empty)" }), []); }, "btn-ghost")]),
        d.active ? el("div", { class: "card" }, [el("h3", { text: "Ban an address through a jail" }), el("div", { class: "toolbar", style: "margin:0" }, [manualIp, manualJail,
          btn("Ban", async () => { try { await API.fail2banBan(manualJail.value, manualIp.value.trim()); toast("Banned", "good"); manualIp.value = ""; load(); } catch (e) { toast(e.message, "bad"); } }, "btn-danger")]),
          el("p", { class: "dm-hint", text: "Uses that jail's ban time and repeat-offender rules. For permanent or range bans use IP Blocker & Trust." })]) : null].filter(Boolean));
      if (d.installed) body.append(f2bActivity(d));
    });
    // What fail2ban actually did: the failed attempts it noticed, the bans, the unbans, from its log.
    function f2bActivity(d) {
      const box = el("div", { class: "card", style: "margin-top:16px" }, [el("h3", { text: "Recent activity" }), el("div", { class: "loading", text: "Reading the log…" })]);
      const names = Object.fromEntries((d.jails || []).map((j) => [j.id, j.label]));
      const KIND = { ban: ["banned", "bad"], failure: ["failed attempt", "warn"], unban: ["unbanned", "dim"] };
      const look = (ip) => { const f = (extraViews()._ui || {}).ipCard; if (f) f(ip); };
      const fmt = (ts) => { const f = (extraViews()._ui || {}).t2s; return f ? f(ts) : new Date(ts * 1000).toLocaleString(); };
      const since = (ts) => (typeof ago === "function" ? ago(ts) : "");
      const report = (ip) => { const f = (extraViews()._ui || {}).reportIp; if (f) f(ip); };
      let only = "";
      (async () => {
        let r;
        try { r = await API.fail2banEvents(); } catch (e) { box.innerHTML = ""; box.append(el("h3", { text: "Recent activity" }), el("p", { class: "muted", text: e.message })); return; }
        const draw = () => {
          box.innerHTML = "";
          const ev = r.events.filter((e) => !only || e.kind === only);
          const n = (k) => r.events.filter((e) => e.kind === k).length;
          const chips = el("div", { class: "cw-seg cw-seg-sm" }, [["", `All · ${r.events.length}`], ["ban", `Bans · ${n("ban")}`], ["failure", `Failed attempts · ${n("failure")}`], ["unban", `Unbans · ${n("unban")}`]].map(([k, l]) =>
            el("button", { type: "button", class: k === only ? "active" : "", text: l, onclick: () => { only = k; draw(); } })));
          box.append(el("div", { style: "display:flex;align-items:center;gap:12px;flex-wrap:wrap;margin-bottom:8px" }, [el("h3", { style: "margin:0", text: "Recent activity" }), el("span", { class: "grow" }), chips]));
          box.append(el("p", { class: "muted", style: "font-size:12.5px;margin:0 0 10px", text: `Everything fail2ban wrote to its log (${r.source}): each failed attempt it noticed, every ban and unban. Bans also show under IP Blocker & Trust.` }));
          if (!ev.length) { box.append(el("p", { class: "muted", text: r.events.length ? "Nothing of that kind." : "Quiet so far: no failed attempts or bans in the log. fail2ban only writes here when a jail notices something." })); return; }
          box.append(el("div", { class: "table-wrap" }, el("table", { class: "dm-table" }, [
            el("thead", {}, el("tr", {}, ["When", "Jail", "Event", "Address", ""].map((h) => el("th", { text: h })))),
            el("tbody", {}, ev.slice(0, 300).map((e) => el("tr", {}, [
              el("td", { title: new Date(e.ts * 1000).toLocaleString(), text: `${fmt(e.ts)} · ${since(e.ts)}` }),
              el("td", { text: names[e.jail] || e.jail }),
              el("td", {}, el("span", { class: `pill ${KIND[e.kind][1]}`, text: KIND[e.kind][0] + (e.restored ? " again" : "") })),
              el("td", {}, el("code", { class: ipCls(r.status[e.ip]), text: e.ip })),
              el("td", { class: "actions" }, [btn("Lookup", () => look(e.ip), "btn-ghost"), r.status[e.ip] === "trusted" ? null : btn("Report", () => report(e.ip), "btn-ghost")].filter(Boolean)),
            ]))),
          ])));
        };
        draw();
      })();
      return box;
    }
    state.refreshHandler = load; load();
  }

  // ---- Fix Home Permissions ----
  function viewFixPerms(root) {
    const bar = el("div", { class: "card" }, [
      el("h3", { text: "Fix Home Permissions" }),
      el("p", { class: "muted", style: "margin:0 0 12px", text: "Reset a user's home directory ownership + safe permissions (home 711, .ssh 700, keys 600)." }),
      el("div", { class: "toolbar" }, [
        el("input", { id: "fp-user", type: "text", value: sysUser(), placeholder: "username", style: "max-width:200px" }),
        el("button", { class: "btn btn-sm btn-primary", text: "Fix permissions", onclick: fix }),
      ]),
    ]);
    const body = el("div", { id: "fp-body", style: "margin-top:16px" });
    root.append(bar, body);
    async function fix() {
      const name = $("#fp-user").value.trim(); if (!name) return;
      if (!confirmInline(`Reset permissions for ${name}'s home directory?`)) return;
      body.innerHTML = '<div class="loading">Working…</div>';
      try {
        const r = await API.fixPerms(name);
        body.innerHTML = "";
        const rows = r.actions.map((a) => el("tr", {}, [
          el("td", { text: a.action }), el("td", {}, el("span", { class: `pill ${a.ok ? "good" : "bad"}`, text: a.ok ? "ok" : "failed" })),
          el("td", { class: "muted", text: a.error || "" })]));
        body.append(el("div", { class: "card" }, [el("h3", { text: `${r.user}, ${r.home}` }), simpleTable(["Action", "Result", "Detail"], rows)]));
        toast(r.ok ? "Permissions fixed" : "Completed with warnings", r.ok ? "good" : "bad");
      } catch (e) { body.innerHTML = ""; toast(e.message, "bad"); }
    }
  }

  // ---- Domains (vhosts) ----
  // ======================================================================
  //  Domains, cPanel-style list + per-domain Manage page
  // ======================================================================
  const domState = { manage: null };
  const zoneState = { manage: null };
  const openDomain = (name) => { domState.manage = name; navigate("vhosts"); };
  const openZone = (name) => { zoneState.manage = name; navigate("zones"); };

  function sw(checked, onchange, opts = {}) {
    const input = el("input", { type: "checkbox", class: "sw-in", onchange: (e) => onchange(e.target.checked, e.target) });
    input.checked = !!checked;
    if (opts.disabled) input.disabled = true;
    return el("label", { class: `sw ${opts.disabled ? "disabled" : ""}`, title: opts.title || "" }, [input, el("span", { class: "sw-track" }, el("span", { class: "sw-knob" }))]);
  }
  const isIp = (n) => /^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}$/.test(n || "");

  function sslPill(s) {
    if (s.ssl === "none") return el("span", { class: "pill dim", text: "No SSL" });
    const label = { selfsigned: "Self-signed", letsencrypt: "Let's Encrypt", custom: "Custom cert" }[s.ssl] || s.ssl;
    const exp = s.cert_expires ? new Date(s.cert_expires) : null;
    const days = exp ? Math.round((exp - Date.now()) / 864e5) : null;
    const cls = s.ssl === "selfsigned" ? "warn" : days != null && days < 14 ? "bad" : "good";
    return el("span", { class: `pill ${cls}`, title: exp ? `Expires ${exp.toLocaleDateString()}` : "", text: label + (days != null ? ` · ${days}d` : "") });
  }

  // Domains this server knows without a website: mail-only domains and DNS-only zones.
  async function otherDomains(box, sitesData, reload) {
    const [mailD, zones] = await Promise.all([API.mailDomains().catch(() => null), API.dnsZones().catch(() => null)]);
    const siteNames = new Set();
    (sitesData.sites || []).forEach((x) => [x.server_name, ...(x.aliases || [])].forEach((n) => n && siteNames.add(n.toLowerCase())));
    const map = new Map();
    const add = (d, k, extra) => { if (siteNames.has(d)) return; const e = map.get(d) || { domain: d }; e[k] = extra || true; map.set(d, e); };
    (mailD ? mailD.domains : []).forEach((d) => add(d.domain, "mail", d));
    (zones ? zones.zones : []).forEach((z) => add(z.domain, "zone", z));
    box.innerHTML = "";
    if (!map.size) return;
    const rows = [...map.values()].sort((a, b) => a.domain.localeCompare(b.domain));
    box.append(el("div", { class: "card", style: "margin-top:16px" }, [
      el("h3", { text: "Domains without a website" }),
      el("p", { class: "muted", style: "margin:0 0 12px", text: "Domains this server handles mail or DNS for, but no site. Remove them here when you no longer need them." }),
      el("div", { class: "table-wrap" }, el("table", { class: "dm-table" }, [
        el("thead", {}, el("tr", {}, ["Domain", "Used for", "Actions"].map((h) => el("th", { text: h })))),
        el("tbody", {}, rows.map((r) => {
          const accounts = r.mail && r.mail.accounts ? r.mail.accounts : 0;
          const rm = btn("Remove", async (e) => {
            const b = e.currentTarget;
            if (!b.classList.contains("armed")) { b.classList.add("armed"); b.textContent = "Click again to remove"; setTimeout(() => { b.classList.remove("armed"); b.textContent = "Remove"; }, 4000); return; }
            b.disabled = true;
            try {
              if (r.mail) await API.mailDomainRemove(r.domain);
              if (r.zone) await API.dnsZoneDelete(r.domain);
              toast(`${r.domain} removed`, "good"); reload();
            } catch (err) { toast(err.message, "bad"); b.disabled = false; b.classList.remove("armed"); b.textContent = "Remove"; }
          }, "btn-ghost");
          return el("tr", {}, [
            el("td", {}, el("b", { text: r.domain })),
            el("td", {}, el("div", { style: "display:flex;gap:6px;flex-wrap:wrap" }, [
              r.mail ? pill(`Email${accounts ? ` · ${accounts} account${accounts === 1 ? "" : "s"}` : ""}`, "good") : null,
              r.zone ? pill("DNS zone", "dim") : null].filter(Boolean))),
            el("td", { class: "actions" }, [
              r.mail ? btn("Email", () => { state.mailDomain = r.domain; navigate("mailaccounts"); }, "btn-ghost") : null,
              r.zone ? btn("Zone", () => navigate("zones"), "btn-ghost") : null,
              accounts ? el("span", { class: "muted", style: "font-size:12px", text: "Delete its email accounts to remove it" }) : rm].filter(Boolean)),
          ]);
        })),
      ])),
    ]));
  }

  function viewDomains(root) {
    if (domState.manage) { const n = domState.manage; domState.manage = null; return viewDomainManage(root, n); }
    const bar = el("div", { class: "dm-bar" });
    const search = el("input", { type: "search", placeholder: "Search domains…", class: "dm-search" });
    const bulk = el("select", { class: "dm-bulk" }, [
      el("option", { value: "", text: "Bulk actions…" }),
      el("option", { value: "force_https:1", text: "Enable Force HTTPS Redirect" }),
      el("option", { value: "force_https:0", text: "Disable Force HTTPS Redirect" }),
      el("option", { value: "enabled:1", text: "Enable site" }),
      el("option", { value: "enabled:0", text: "Disable site" }),
      el("option", { value: "maintenance:1", text: "Turn on maintenance mode" }),
      el("option", { value: "maintenance:0", text: "Turn off maintenance mode" }),
    ]);
    const applyBtn = el("button", { class: "btn btn-sm", text: "Apply" });
    bar.append(search, bulk, applyBtn, el("span", { class: "grow" }),
      el("button", { class: "btn btn-primary", onclick: createDomainModal }, [icon("globe", 15), " Create a New Domain"]));
    const body = el("div", {}, el("div", { class: "loading", text: "Loading…" }));
    root.append(el("p", { class: "muted dm-intro", text: "Manage your websites: document roots, HTTPS, redirects and more. Changes are tested with apache2ctl before they go live." }), bar, body);
    let data = null;
    const selected = new Set();

    function render() {
      body.innerHTML = "";
      if (!data.supported) { body.append(el("p", { class: "empty", text: "Apache is not available on this host." })); return; }
      const q = search.value.trim().toLowerCase();
      const list = data.sites.filter((s) => !q || s.server_name.includes(q) || s.aliases.some((a) => a.includes(q)) || (s.docroot || "").toLowerCase().includes(q));
      const all = el("input", { type: "checkbox", class: "dm-cb", onchange: (e) => { list.filter((s) => !s.system).forEach((s) => e.target.checked ? selected.add(s.server_name) : selected.delete(s.server_name)); render(); } });
      all.checked = list.filter((s) => !s.system).length > 0 && list.filter((s) => !s.system).every((s) => selected.has(s.server_name));
      const rows = list.map((s) => {
        const cb = el("input", { type: "checkbox", class: "dm-cb", onchange: (e) => { e.target.checked ? selected.add(s.server_name) : selected.delete(s.server_name); } });
        cb.checked = selected.has(s.server_name); if (s.system) cb.disabled = true;
        const scheme = s.ssl !== "none" ? "https" : "http";
        return el("tr", { class: s.enabled ? "" : "dm-off" }, [
          el("td", {}, cb),
          el("td", {}, el("div", { class: "dm-name" }, [
            el("a", { href: `${scheme}://${s.server_name}/`, target: "_blank", rel: "noopener", title: "Open site" }, [icon("link", 13), " ", s.server_name]),
            s.aliases.length ? el("span", { class: "dm-alias", text: "+ " + s.aliases.join(", ") }) : null,
            // The two stock sites usually share one name, say which is the http and which the https one.
            s.system ? el("span", { class: "dm-alias", text: s.has_http ? `${s.conf} · http (port 80)` : `${s.conf} · https (port 443)` }) : null,
            el("span", { class: "dm-tags" }, [
              s.system ? el("span", { class: "pill dim", text: "system" }) : null,
              !s.managed && !s.system ? el("span", { class: "pill dim", title: "Hand-written config, saving it once lets AuroraPanel manage it (original is backed up)", text: "manual" }) : null,
              !s.enabled ? el("span", { class: "pill warn", text: "disabled" }) : null,
              s.maintenance ? el("span", { class: "pill warn", text: "maintenance" }) : null,
            ]),
          ])),
          el("td", {}, el("span", { class: "dm-root" }, [icon("home", 13), " ", s.docroot || ", "])),
          el("td", { class: s.redirect_url ? "" : "muted", text: s.redirect_url || "Not Redirected" }),
          s.system && !s.has_http ? el("td", { class: "muted", title: "This is the https site itself, Force HTTPS is set on the http (port 80) row", text: "already https" }) : el("td", {}, sw(s.force_https, async (v, inp) => {
            if (v && s.ssl === "none" && !s.system && !confirmInline(`${s.server_name} has no certificate yet.\n\nA self-signed certificate will be created so HTTPS works now (browsers will warn). You can switch to a free Let's Encrypt certificate in Manage.\n\nContinue?`)) { inp.checked = false; return; }
            try { await API.siteToggle(s.system ? s.conf : s.server_name, "force_https", v); toast(`Force HTTPS ${v ? "on" : "off"} · ${s.server_name}`, "good"); load(); }
            catch (e) { inp.checked = !v; toast(e.message, "bad"); }
          }, { title: "Redirect all HTTP traffic to HTTPS" })),
          el("td", {}, sslPill(s.https_via ? { ...s, ...s.https_via } : s)),  // http built-in site: https comes from default-ssl
          el("td", { class: "actions" }, [
            el("button", { class: "btn btn-sm", onclick: () => openDomain(s.system ? s.conf : s.server_name) }, [icon("services", 13), " Manage"]),
            isIp(s.server_name) ? null : el("button", { class: "btn btn-sm btn-ghost", title: "DNS zone", onclick: () => openZone(s.server_name.replace(/^www\./, "")) }, [icon("zone", 13), " Zone"]),
            isIp(s.server_name) ? null : el("button", { class: "btn btn-sm btn-ghost", title: "DNS & WHOIS check", onclick: () => showDomainInfo(s.server_name) }, icon("search", 13)),
            s.docroot ? shadowBtn(`site:${s.server_name}`) : null,
          ].filter(Boolean)),
        ]);
      });
      body.append(el("div", { class: "dm-count muted", text: `Displaying ${list.length} of ${data.sites.length} domain${data.sites.length === 1 ? "" : "s"}` }));
      if (!list.length) body.append(el("div", { class: "cw-empty" }, [icon("globe", 28), el("b", { text: q ? "No matches" : "No domains yet" }), el("span", { class: "muted", text: "Create one to get a site running on this Pi." })]));
      else body.append(el("div", { class: "table-wrap" }, el("table", { class: "dm-table" }, [
        el("thead", {}, el("tr", {}, [el("th", {}, all), ...["Domain", "Document Root", "Redirects To", "Force HTTPS", "SSL", "Actions"].map((h) => el("th", { text: h }))])),
        el("tbody", {}, rows),
      ])));
      body.append(folderSection(q));
    }

    // Sites served from a folder on this Pi's own address: http(s)://<ip>/<name>.
    function folderSection(q) {
      const host = location.hostname;
      const items = (folders.sites || []).filter((f) => !q || f.name.includes(q) || f.path.toLowerCase().includes(q));
      const found = (folders.found || []).filter((f) => !q || f.name.toLowerCase().includes(q) || f.path.toLowerCase().includes(q));
      const box = el("div", { class: "dm-folders" }, [el("div", { class: "dm-folders-h" }, [
        icon("folder", 16), el("h3", { text: "Folder sites" }),
        el("span", { class: "muted", style: "font-size:13px", text: `http(s)://${host}/name, no domain needed` }),
        el("span", { class: "grow" }),
        el("button", { class: "btn btn-sm", onclick: () => createDomainModal("folder") }, [icon("folder", 13), " New folder site"])])]);
      if (!items.length && !found.length) {
        box.append(el("p", { class: "muted", text: q ? "No folder sites match." : `None yet. A folder site lives at http://${host}/<name>/, in ${folders.base || "/var/www/html"}/<name> or any folder you pick.` }));
        return box;
      }
      box.append(el("div", { class: "table-wrap" }, el("table", { class: "dm-table" }, [
        el("thead", {}, el("tr", {}, ["Address", "Folder", "File list", ""].map((h) => el("th", { text: h })))),
        el("tbody", {}, [...items.map((f) => el("tr", { class: f.exists ? "" : "dm-off" }, [
          el("td", {}, el("div", { class: "dm-name" }, [
            el("a", { href: `http://${host}/${f.name}/`, target: "_blank", rel: "noopener", title: "Open site" }, [icon("link", 13), ` ${host}/${f.name}/`]),
            el("span", { class: "dm-tags" }, [
              f.alias ? el("span", { class: "pill dim", title: "Outside the default site's folder, served through an Apache Alias", text: "alias" }) : null,
              f.exists ? null : el("span", { class: "pill warn", text: "folder missing" }),
              // No index page + no file list = Apache answers 403 Forbidden.
              f.exists && !f.has_index && !f.indexes ? el("span", { class: "pill warn", title: "Visitors get 403 Forbidden at this address: add an index.html, or turn on the file list", text: "no index page" }) : null]),
          ])),
          el("td", {}, el("span", { class: "dm-root" }, [icon("home", 13), " ", f.path])),
          el("td", {}, sw(f.indexes, async (v, inp) => {
            try { await API.folderSiteIndexes(f.name, v); toast(`File list ${v ? "on" : "off"} · /${f.name}`, "good"); load(); }
            catch (e) { inp.checked = !v; toast(e.message, "bad"); }
          }, { title: "Show a list of the files when the folder has no index page" })),
          el("td", { class: "actions" }, [
            el("button", { class: "btn btn-sm", onclick: () => { fmState.cwd = f.path; navigate("files"); } }, [icon("folder", 13), " Files"]),
            shadowBtn(`folder:${f.name}`),
            el("button", { class: "btn btn-sm btn-ghost", title: "Remove this folder site (optionally its files, with a backup first)", onclick: () => removeFolderSite(f) }, icon("error", 13)),
          ]),
        ])),
        // Folders already in the web root that nobody set up here: Apache serves them anyway, so show them and offer to adopt them.
        ...found.map((f) => el("tr", { class: "dm-found" }, [
          el("td", {}, el("div", { class: "dm-name" }, [
            el("a", { href: `http://${host}/${encodeURIComponent(f.name)}/`, target: "_blank", rel: "noopener", title: "Open" }, [icon("link", 13), ` ${host}/${f.name}/`]),
            el("span", { class: "dm-tags" }, [
              el("span", { class: "pill warn", title: `Found in ${folders.base} but not set up as a folder site. Apache serves it all the same.`, text: "found, not set up" }),
              f.has_index ? null : el("span", { class: "pill dim", title: "No index page: visitors see a file list or 403 Forbidden", text: "no index page" }),
              el("span", { class: "pill dim", text: `${f.entries} item${f.entries === 1 ? "" : "s"}` }),
            ]),
          ])),
          el("td", {}, el("span", { class: "dm-root" }, [icon("home", 13), " ", f.path])),
          el("td", {}, el("span", { class: "muted", title: "Set it up to manage the file list here", text: ", " })),
          el("td", { class: "actions" }, [
            el("button", { class: "btn btn-sm", onclick: () => { fmState.cwd = f.path; navigate("files"); } }, [icon("folder", 13), " Files"]),
            el("button", { class: "btn btn-sm btn-primary", disabled: f.addable ? null : "",
              title: f.addable ? "Manage it here: file list, shadow copies, backup and removal. Nothing in the folder changes." : "Rename the folder first: lowercase letters, numbers, dots, dashes or underscores",
              onclick: async (ev) => {
                const b = ev.currentTarget; b.disabled = true;
                try { await API.folderSiteCreate(f.name, f.path); toast(`/${f.name} is a folder site now`, "good"); load(); }
                catch (e) { toast(e.message, "bad"); b.disabled = false; }
              } }, [icon("plus", 13), " Set up"]),
          ]),
        ]))]),
      ])));
      return box;
    }
    let folders = { sites: [] }, shadowInfo = { sites: [] };
    // Shadow Copies button: lit when the site keeps a version history; opens its timeline.
    const shadowBtn = (id) => {
      const s = (shadowInfo.sites || []).find((x) => x.id === id);
      const on = !!(s && s.enabled);
      return el("button", { class: `btn btn-sm btn-ghost sh-btn ${on ? "on" : ""}`, title: on ? `Shadow copies on · ${s.usage.versions} versions, ${fmtBytes(s.usage.bytes)}, open the history` : "Shadow copies off, keep a version history of this site's files",
        onclick: () => navigate("shadow", { arg: id }) }, [icon("shadow", 13), on && s.usage.versions ? el("span", { class: "sh-badge", text: s.usage.versions > 999 ? "999+" : String(s.usage.versions) }) : null]);
    };
    const otherBox = el("div");
    root.append(otherBox);
    const jpFolder = jobPanel(root);
    // Remove a folder site: stop serving it, and optionally delete its folder, after a backup that shows under Backups.
    function removeFolderSite(f) {
      const host = location.hostname;
      const delFiles = el("input", { type: "checkbox" });
      const bk = el("input", { type: "checkbox" }); bk.checked = true;
      const bkRow = el("label", { class: "dm-check", style: "margin-left:26px" }, [bk, el("span", {}, ["Back up the folder first, the archive appears under ", el("b", { text: "Backups" }), " and can be restored any time"])]);
      bkRow.hidden = true;
      delFiles.onchange = () => { bkRow.hidden = !delFiles.checked; };
      const keepNote = f.alias ? `Without deleting the files, ${f.path} stays where it is.`
        : `Without deleting the files, the folder stays inside ${folders.base}, so it keeps answering at /${f.name} until it's deleted.`;
      const go = el("button", { class: "btn btn-danger", text: "Remove", onclick: async () => {
        go.disabled = true;
        try {
          const r = await API.folderSiteRemove(f.name, delFiles.checked, delFiles.checked && bk.checked);
          closeModal();
          if (r.job) {
            jpFolder.run(r.job, `Delete folder site /${f.name}`);
            const t = setInterval(async () => { try { const j = await API.job(r.job); if (j.status !== "running") { clearInterval(t); load(); } } catch (e) { clearInterval(t); } }, 1500);
          } else { toast(`Removed /${f.name}`, "good"); }
          load();
        } catch (e) { toast(e.message, "bad"); go.disabled = false; }
      } });
      openModal(`Remove folder site /${f.name}`, el("div", { class: "em-form" }, [
        el("p", { class: "muted", text: `It stops being served at http://${host}/${f.name}/. Its shadow copies, if any, are removed as well.` }),
        el("label", { class: "dm-check" }, [delFiles, el("span", {}, ["Also delete its files in ", el("code", { text: f.path })])]),
        bkRow,
        el("p", { class: "dm-hint", text: keepNote }),
      ]), [go]);
    }
    const load = async () => { await guardedLoad(async () => {
      [data, folders, shadowInfo] = await Promise.all([API.sites(), API.folderSites().catch(() => ({ sites: [] })), API.shadow().catch(() => ({ sites: [] }))]);
      render();
      otherDomains(otherBox, data, load);
    }); };
    search.addEventListener("input", render);
    applyBtn.addEventListener("click", async () => {
      if (!bulk.value) return toast("Pick a bulk action", "bad");
      if (!selected.size) return toast("Select one or more domains first", "bad");
      const [key, v] = bulk.value.split(":");
      applyBtn.disabled = true;
      let ok = 0;
      for (const n of selected) {
        try { await API.siteToggle(n, key, v === "1"); ok++; } catch (e) { toast(`${n}: ${e.message}`, "bad"); }
      }
      applyBtn.disabled = false; selected.clear();
      if (ok) toast(`Updated ${ok} domain(s)`, "good");
      load();
    });
    state.refreshHandler = load; load();
  }

  function createDomainModal(mode) {
    const f = el("div", { class: "dm-form" });
    // Two kinds: a domain/IP of its own, or a folder at http(s)://<this Pi>/<name>.
    const kind = el("div", { class: "cw-seg cw-seg-sm", style: "margin-bottom:14px" });
    const domainBox = el("div", {}), folderBox = el("div", { hidden: true });
    // Three kinds: Local = a folder at http(s)://<this Pi>/<name>; IP = a site of its own on an IP address; Domain = a domain name.
    const setKind = (k) => {
      kind.querySelectorAll("button").forEach((b) => b.classList.toggle("active", b.dataset.k === k));
      domainBox.hidden = k === "local"; folderBox.hidden = k !== "local";
      go.textContent = k === "local" ? "Create local site" : k === "ip" ? "Create IP site" : "Create domain";
      if (k !== "local") {
        const ipKind = k === "ip";
        $("#nd-lbl", domainBox).firstChild.textContent = ipKind ? "IP address" : "Domain";
        name.placeholder = ipKind ? "e.g. 192.168.0.50, another address of this Pi" : "example.com, or a local name like mysite.test";
        $("#nd-hint-ip", domainBox).hidden = !ipKind; $("#nd-hint-dom", domainBox).hidden = ipKind;
        // Let's Encrypt only certifies names: an IP site keeps a self-signed (or uploaded) certificate.
        $("#nd-ssl-hint", domainBox).textContent = ipKind ? "(an IP address can't get a Let's Encrypt certificate, use a domain name for that)" : "(switch to Let's Encrypt later)";
        ["#nd-www", "#nd-zone"].forEach((id) => { $(id, f).parentElement.hidden = ipKind; if (ipKind) $(id, f).checked = false; });
        if (!ipKind) $("#nd-www", f).checked = true;
        if (name.value.trim() && isIp(name.value.trim()) !== ipKind) { name.value = ""; name.dispatchEvent(new Event("input")); }
      }
      setTimeout(() => (k === "local" ? fName : name).focus(), 30);
    };
    kind.append(
      el("button", { type: "button", "data-k": "local", text: `Local · ${location.hostname}/name`, title: "A folder on this Pi's address, no domain needed", onclick: () => setKind("local") }),
      el("button", { type: "button", "data-k": "ip", text: "IP address", title: "A site of its own on an IP address", onclick: () => setKind("ip") }),
      el("button", { type: "button", "data-k": "domain", text: "Domain", title: "A domain name, or a local name like mysite.test", onclick: () => setKind("domain") }));
    folderBox.innerHTML = `
      <label class="cw-lbl">Site name<div class="dm-prefix"><span>http(s)://${esc(location.hostname)}/</span><input id="nf-name" type="text" placeholder="mysite" autocomplete="off" /></div></label>
      <label class="cw-lbl">Folder<input id="nf-path" type="text" class="cw-mono" placeholder="/var/www/html/mysite" autocomplete="off" spellcheck="false" /></label>
      <p class="muted" style="font-size:12px;margin:4px 0 0">No domain needed: the site answers on this Pi's address, over http and (when the default HTTPS site is on) https. The folder is created with a starter <code>index.html</code>; <code>.htaccess</code> files work in it. A folder outside <code id="nf-base">/var/www/html</code> is linked in with an Apache Alias, so <code>/name</code> then also works on the other sites this Pi hosts.</p>`;
    const fName = $("#nf-name", folderBox), fPath = $("#nf-path", folderBox);
    let base = "/var/www/html", pathTouched = false;
    API.folderSites().then((r) => { if (r.base) { base = r.base; $("#nf-base", folderBox).textContent = base; syncPath(); } }).catch(() => {});
    const syncPath = () => { const n = fName.value.trim().toLowerCase() || "mysite"; fPath.placeholder = `${base}/${n}`; if (!pathTouched) fPath.value = fName.value.trim() ? `${base}/${n}` : ""; };
    fName.addEventListener("input", syncPath);
    fPath.addEventListener("input", () => { pathTouched = !!fPath.value.trim(); });
    f.append(kind, domainBox, folderBox);
    domainBox.innerHTML = `
      <label class="cw-lbl" id="nd-lbl">Domain<input id="nd-name" type="text" placeholder="example.com" autocomplete="off" /></label>
      <label class="cw-lbl">Document root<input id="nd-root" type="text" placeholder="/var/www/example.com" /></label>
      <label class="dm-check"><input id="nd-www" type="checkbox" checked /> Also answer on <b id="nd-www-l">www.example.com</b></label>
      <label class="dm-check"><input id="nd-ssl" type="checkbox" /> Create a self-signed certificate &amp; force HTTPS <span class="muted" id="nd-ssl-hint">(switch to Let's Encrypt later)</span></label>
      <label class="dm-check"><input id="nd-zone" type="checkbox" /> Create a DNS zone for it in the Zone Editor</label>
      <p class="muted" id="nd-hint-dom" style="font-size:12px;margin:4px 0 0">Local names like <code>mysite.test</code> work too, you'll get the hosts-file line to add on your computer.</p>
      <p class="muted" id="nd-hint-ip" hidden style="font-size:12px;margin:4px 0 0">The site answers on <code>http://&lt;ip&gt;/</code>. For this Pi's own address (<code>${esc(location.hostname)}</code>), which Apache's built-in site already uses, enter a folder such as <code>/var/www/html/mysite</code> and it's served at <code>http://${esc(location.hostname)}/mysite/</code>, or use <b>Local</b>.</p>`;
    const name = $("#nd-name", domainBox), rootIn = $("#nd-root", domainBox);
    // The document root fills itself in from the name until it's edited by hand.
    let rootTouched = false;
    rootIn.addEventListener("input", () => { rootTouched = !!rootIn.value.trim(); });
    name.addEventListener("input", () => {
      const n = name.value.trim().toLowerCase() || "example.com";
      rootIn.placeholder = `/var/www/${n}`;
      // The Pi's own address is the built-in site, so a folder under its web root becomes http://<ip>/<name>.
      const own = n === location.hostname.toLowerCase();
      if (own) rootIn.placeholder = "/var/www/html/mysite";
      if (!rootTouched) rootIn.value = !name.value.trim() ? "" : own ? "/var/www/html/" : `/var/www/${n}`;
      $("#nd-www-l", f).textContent = n.startsWith("www.") ? n.slice(4) : "www." + n;
      const ip = isIp(n);
      ["#nd-www", "#nd-zone"].forEach((id) => { const c = $(id, f); c.disabled = ip; if (ip) c.checked = false; c.parentElement.classList.toggle("dm-dim", ip); });
    });
    const go = el("button", { class: "btn btn-primary", text: "Create domain", onclick: async () => {
      if (!folderBox.hidden) {
        const n = fName.value.trim().toLowerCase().replace(/^\/+|\/+$/g, "");
        if (!n) return toast("Enter a name for the site", "bad");
        go.disabled = true;
        try {
          const r = await API.folderSiteCreate(n, fPath.value.trim());
          closeModal(); toast(`Created http://${location.hostname}/${r.name}/ → ${r.path}`, "good");
          state.refreshHandler && state.refreshHandler();
        } catch (e) { toast(e.message, "bad"); go.disabled = false; }
        return;
      }
      const n = name.value.trim().toLowerCase();
      if (!n) return toast("Enter a domain", "bad");
      const ssl = $("#nd-ssl", f).checked;
      const settings = { server_name: n, docroot: rootIn.value.trim(), aliases: $("#nd-www", f).checked && !isIp(n) ? [n.startsWith("www.") ? n.slice(4) : "www." + n] : [],
        ssl: ssl ? "selfsigned" : "none", force_https: ssl };
      go.disabled = true;
      try {
        const r = await API.siteCreate(settings);
        if ($("#nd-zone", f).checked && !isIp(n)) { try { await API.dnsZoneCreate(n.replace(/^www\./, ""), "", "default"); } catch (e) { toast("Zone: " + e.message, "bad"); } }
        if (r.folder_site) {  // the Pi's own address + a folder → a folder site at http://<ip>/<name>
          closeModal(); toast(`Created ${r.url} → ${r.path}`, "good");
          return state.refreshHandler && state.refreshHandler();
        }
        closeModal(); toast(`Created ${r.server_name}`, "good"); openDomain(r.server_name);
      } catch (e) { toast(e.message, "bad"); go.disabled = false; }
    } });
    openModal("Create a new site", f, [go]);
    setKind(mode === "folder" ? "local" : "domain");
  }

  function viewDomainManage(root, name) {
    root.append(el("div", { class: "loading", text: `Loading ${name}…` }));
    const jp = { t: null };
    (state.cleanups = state.cleanups || []).push(() => clearInterval(jp.t));
    const load = async () => {
      let d;
      try { d = await API.siteGet(name); }
      catch (e) { root.innerHTML = ""; root.append(el("div", { class: "cw-empty" }, [icon("error", 28), el("b", { text: e.message }), el("button", { class: "btn btn-sm", text: "← Back to domains", onclick: () => navigate("vhosts") })])); return; }
      render(d);
    };
    state.refreshHandler = load;

    function render(d) {
      const orig = JSON.stringify(d.settings);
      const s = JSON.parse(orig);
      const ro = d.system;
      const ipSite = isIp(d.settings.server_name);
      root.innerHTML = "";
      const dirty = () => { const x = JSON.stringify(s) !== orig; saveBar.classList.toggle("show", x && !ro); };
      if (!d.enabled && d.system && !d.has_http) s.ssl = "none";  // a disabled https site serves nothing

      const head = el("div", { class: "dmm-head" }, [
        el("button", { class: "btn btn-sm btn-ghost", onclick: () => navigate("vhosts") }, [el("span", { class: "dmm-back", html: "&larr;" }), " Domains"]),
        el("h2", {}, ["Manage ", el("span", { class: "accent", text: `“${d.settings.server_name}”` }), ro ? el("span", { class: "muted", style: "font-size:.6em;margin-left:10px", text: d.has_http ? "http · port 80" : "https · port 443" }) : null]),
        el("span", { class: "grow" }),
        el("a", { class: "btn btn-sm", href: `${d.settings.ssl !== "none" ? "https" : "http"}://${d.settings.server_name}/`, target: "_blank", rel: "noopener" }, [icon("link", 13), " Visit site"]),
      ]);
      root.append(head);
      if (ro) root.append(el("div", { class: "dm-note warn" }, [icon("lock", 15), el("span", { text: "This is one of Apache's two built-in sites (" + d.conf + (d.has_http ? ", http on port 80" : ", https on port 443") + "). Both answer on this Pi's address, so they show the same name. They can't be removed (Apache falls back to them), and the rest of their settings are read-only, but you can turn them on or off" + (d.has_http ? " and use Force HTTPS." : " and change the certificate.") }),
        el("button", { class: "btn btn-sm", style: "margin-left:auto;flex-shrink:0", text: d.enabled ? "Disable site" : "Enable site", onclick: async (e) => {
          if (d.hand_copy) return fixLayout();  // a2dissite can't touch a hand-made copy: walk the user through fixing that first
          e.target.disabled = true;
          try { await API.siteToggle(d.conf, "enabled", !d.enabled); toast(`${d.settings.server_name} ${d.enabled ? "disabled" : "enabled"}`, "good"); load(); }
          catch (err) { toast(err.message, "bad"); e.target.disabled = false; }
        } })]));
      else if (!d.managed) root.append(el("div", { class: "dm-note" }, [icon("error", 15), el("span", { html: `This site uses a hand-written config (<code>${esc(d.conf)}</code>). Settings below were read from it, saving once lets AuroraPanel manage it, and the original is kept as <code>${esc(d.conf)}.aurora-bak</code>.` })]));
      // sites-enabled/<conf> is a regular file someone copied and edited there, not the link a2ensite makes:
      // Apache serves it, but on/off can't work until the layout is put right. Explain, and do it on request.
      function fixLayout() {
        const cmds = `cp /etc/apache2/sites-enabled/${d.conf} /etc/apache2/sites-available/${d.conf}\nrm /etc/apache2/sites-enabled/${d.conf}\na2ensite ${d.conf} && apache2ctl configtest && systemctl reload apache2`;
        const go = el("button", { class: "btn btn-primary", text: "Fix & reload Apache", onclick: async () => {
          go.disabled = true;
          try {
            const r = await API.siteSystemAdopt(d.conf); closeModal();
            toast(r.changed ? `${d.conf} is a normal link again, the site can be turned on and off` : `${d.conf} already has the normal layout`, "good"); load();
          } catch (e) { toast(e.message, "bad"); go.disabled = false; }
        } });
        openModal(`Fix the layout of ${d.conf}`, el("div", { class: "em-form" }, [
          el("p", { class: "muted", html: `<code>sites-enabled/${esc(d.conf)}</code> is a regular file that was copied and edited by hand, not the link to <code>sites-available/${esc(d.conf)}</code> that Apache's tools expect. Apache loads it fine, but <code>a2dissite</code> / <code>a2ensite</code>, what “Disable site” and “Enable site” use, can't manage it. The panel can put it right in one go:` }),
          el("ol", { style: "margin:0 0 12px 18px;padding:0;display:grid;gap:6px;font-size:13px" }, [
            el("li", { html: `Back up both files to <code>/var/lib/aurora/site-backups</code>.` }),
            el("li", { html: `Keep exactly what Apache serves now: the text of the hand-edited copy becomes <code>sites-available/${esc(d.conf)}</code>.` }),
            el("li", { html: `Replace the copy with the normal link, the way <code>a2ensite</code> makes it.` }),
            el("li", { text: "Test the configuration and reload Apache. Nothing changes for visitors." }),
          ]),
          el("details", {}, [el("summary", { class: "muted", style: "cursor:pointer;font-size:13px", text: "Prefer to do it yourself? The same steps as root" }),
            el("pre", { style: "margin:8px 0 0;padding:10px 12px;border-radius:10px;background:rgba(255,255,255,.05);font-size:12px;white-space:pre-wrap", text: cmds })]),
        ]), [go]);
      }
      if (ro && d.hand_copy) root.append(el("div", { class: "dm-note" }, [icon("error", 15), el("span", { style: "flex:1", html: `<b>Hand-edited copy.</b> <code>sites-enabled/${esc(d.conf)}</code> is a regular file, not a link to <code>sites-available</code>, so “${d.enabled ? "Disable" : "Enable"} site” can't work until the layout is fixed. The panel keeps the file as it is served now and backs both copies up.` }),
        el("button", { class: "btn btn-sm btn-primary", style: "margin-left:auto;flex-shrink:0", text: "Fix the layout", onclick: fixLayout })]));

      const left = el("div", { class: "dmm-left" }), right = el("div", { class: "dmm-right" });
      root.append(el("div", { class: "dmm-cols" }, [left, right]));

      const card = (ico, title, sub, ...kids) => el("div", { class: "card dmm-card" }, [
        el("div", { class: "cw-card-h" }, [icon(ico, 16), el("div", {}, [el("h3", { text: title }), sub ? el("p", { text: sub }) : null])]), ...kids]);
      const field = (label, input, hint) => el("label", { class: "cw-lbl" }, [label, input, hint ? el("span", { class: "dm-hint", text: hint }) : null]);
      // The built-in sites keep their settings read-only except the certificate, applied with its own button.
      // The http one (000-default) gets its https from default-ssl, so its card shows and changes that certificate.
      const viaHttps = ro && d.has_http ? d.https : null;
      const sysSsl = ro && (!d.has_http || !!viaHttps);
      const sslConf = viaHttps ? viaHttps.conf : d.conf;
      if (viaHttps) Object.assign(s, { ssl: viaHttps.ssl, cert: viaHttps.cert, key: viaHttps.key, chain: viaHttps.chain });
      const text = (key, ph, editable) => { const i = el("input", { type: "text", value: s[key] || "", placeholder: ph || "", oninput: (e) => { s[key] = e.target.value; dirty(); } }); if (ro && !editable) i.disabled = true; return i; };
      const toggleRow = (key, title, desc, onChange) => el("div", { class: "dm-trow" }, [
        el("div", {}, [el("b", { text: title }), el("span", { text: desc })]),
        sw(s[key], (v) => { s[key] = v; onChange && onChange(v); dirty(); }, { disabled: ro }),
      ]);
      const seg = (key, opts, onChange, editable) => {
        const box = el("div", { class: "cw-seg cw-seg-sm" });
        opts.forEach(([v, l]) => box.append(el("button", { type: "button", class: s[key] === v ? "active" : "", text: l, disabled: ro && !editable ? "" : null, onclick: () => {
          s[key] = v; box.querySelectorAll("button").forEach((b) => b.classList.toggle("active", b.textContent === l)); onChange && onChange(v); dirty();
        } })));
        return box;
      };

      // ---- General ----
      const chips = el("div", { class: "dm-chips" });
      const drawChips = () => {
        chips.innerHTML = "";
        s.aliases.forEach((a, i) => chips.append(el("span", { class: "dm-chip" }, [a, ro ? null : el("button", { type: "button", title: "Remove", html: "&times;", onclick: () => { s.aliases.splice(i, 1); drawChips(); dirty(); } })])));
        if (!ro) {
          const inp = el("input", { type: "text", placeholder: s.aliases.length ? "add alias…" : "www.example.com, shop.example.com…", onkeydown: (e) => {
            if (e.key === "Enter" || e.key === "," || e.key === " ") {
              e.preventDefault(); const v = inp.value.trim().toLowerCase().replace(/,$/, "");
              if (v && !s.aliases.includes(v)) { s.aliases.push(v); drawChips(); dirty(); chips.querySelector("input").focus(); }
            } else if (e.key === "Backspace" && !inp.value && s.aliases.length) { s.aliases.pop(); drawChips(); dirty(); chips.querySelector("input").focus(); }
          } });
          chips.append(inp);
        } else if (!s.aliases.length) chips.append(el("span", { class: "muted", text: "None, the built-in sites answer on any name that reaches this Pi." }));
      };
      drawChips();
      left.append(card("globe", "Update the domain", "Where the files live and which names this site answers on.",
        field("Document root", text("docroot", "/var/www/" + s.server_name), "Apache serves files from this folder. It's created if missing."),
        el("div", { class: "cw-lbl" }, ["Aliases", chips, el("span", { class: "dm-hint", text: "Extra hostnames for this site, press Enter after each." })]),
        ipSite ? null : el("div", { class: "cw-lbl" }, ["www handling", seg("www", [["none", "Leave as is"], ["force_www", "Always www"], ["force_bare", "Never www"]]),
          el("span", { class: "dm-hint", text: "Pick one canonical address so search engines don't see duplicates (301 redirect)." })]),
        toggleRow("enabled", "Site enabled", "Turn off to take the site offline without deleting anything."),
      ));

      // ---- HTTPS ----
      const sslDetail = el("div", { class: "dm-ssl-detail" });
      const shownCert = viaHttps ? viaHttps.cert_info : d.cert;
      const certRow = shownCert ? el("div", { class: "dm-cert" }, [icon("lock", 14), el("span", { html: `<b>${esc(shownCert.subject || "")}</b> · issued by ${esc(shownCert.issuer || "?")} · expires <b>${esc(shownCert.expires || "?")}</b>` })]) : null;
      const le = {};  // the Let's Encrypt controls, so Save can start issuing too
      // Self-signed certificates can be made again (new key and dates, current names).
      const savedSsl = viaHttps ? viaHttps.ssl : d.settings.ssl;
      const regenBtn = () => el("button", { class: "btn btn-sm", type: "button", title: "Make a new self-signed certificate: new key, new dates, current names", onclick: async (e) => {
        if (!confirmInline("Make a new self-signed certificate? Browsers that trusted the old one will warn once more.")) return;
        e.currentTarget.disabled = true;
        try { await API.siteRegenCert(d.system ? d.conf : d.settings.server_name); toast("New certificate made & Apache reloaded", "good"); load(); }
        catch (err) { openModal("Couldn't make a new certificate", el("pre", { class: "log", text: err.message }), []); }
      } }, [icon("refresh", 13), " Regenerate certificate"]);
      const drawSsl = () => {
        sslDetail.innerHTML = "";
        if (s.ssl === "none") sslDetail.append(el("p", { class: "dm-hint", text: "Visitors can only reach the site over plain http://. Pick a certificate to enable HTTPS." }));
        if (s.ssl === "selfsigned") sslDetail.append(...[el("p", { class: "dm-hint", text: "A certificate is generated on this Pi (covers the domain + aliases). Encrypts traffic, but browsers show a warning, fine for LAN/.test sites." }),
          !sysSsl && savedSsl === "selfsigned" ? el("div", {}, regenBtn()) : null].filter(Boolean));
        if (sysSsl) { sslDetail.innerHTML = ""; sslDetail.append(el("p", { class: "dm-hint", text: (viaHttps ? `https:// for this address is served by Apache's built-in https site (${sslConf}); this changes its certificate. ` : "") +
          (s.ssl === "none" ? `None turns ${sslConf} (https on port 443) off. http:// keeps working.` : s.ssl === "selfsigned" ? "A certificate is generated on this Pi for its address. Browsers show a warning, fine on a LAN." : "Point to your own certificate and key files.") })); }
        if (s.ssl === "custom") sslDetail.append(field("Certificate file (.crt / fullchain.pem)", text("cert", "/etc/ssl/certs/site.crt", sysSsl)), field("Private key", text("key", "/etc/ssl/private/site.key", sysSsl)), field("Chain (optional)", text("chain", "", sysSsl)));
        if (sysSsl) {
          const apply = el("button", { class: "btn btn-primary btn-sm", type: "button", onclick: async () => {
            if (s.ssl === "none" && !confirmInline(`Turn off ${sslConf} (https on port 443)?${d.settings.force_https ? " Force HTTPS on this site will be turned off too, so http keeps working." : ""} You can turn it back on with Self-signed or Custom.`)) return;
            apply.disabled = true;
            try {
              // Without an https site a Force HTTPS redirect would lead nowhere.
              if (s.ssl === "none" && viaHttps && d.settings.force_https) await API.siteToggle(d.conf, "force_https", false);
              await API.siteSystemSsl(sslConf, s.ssl, s.cert, s.key, s.chain); toast(s.ssl === "none" ? `${sslConf} turned off` : "Certificate applied & Apache reloaded", "good"); load();
            }
            catch (e) { openModal("Couldn't change the certificate", el("pre", { class: "log", text: e.message }), []); apply.disabled = false; }
          } }, [icon("lock", 13), " Apply certificate"]);
          sslDetail.append(el("div", { class: "dm-btnrow" }, [apply, s.ssl === "selfsigned" && savedSsl === "selfsigned" ? regenBtn() : null]));
          return;
        }
        if (s.ssl === "letsencrypt") {
          const email = el("input", { type: "email", placeholder: "you@gmail.com, optional", value: (() => { try { return localStorage.getItem("aurora-le-email") || ""; } catch (e) { return ""; } })() });
          const withAliases = el("input", { type: "checkbox" }); withAliases.checked = true;
          const force = el("input", { type: "checkbox" });
          const log = el("pre", { class: "log", hidden: true });
          const issue = el("button", { class: "btn btn-primary btn-sm", type: "button", onclick: async () => {
            if (!d.certbot) {
              try { const r = await API.certbotInstall(); follow(r.job, "Installing certbot…", () => load()); } catch (e) { toast(e.message, "bad"); }
              return;
            }
            // Optional; but Let's Encrypt refuses addresses on a network-only domain (you@ns0.local).
            const em = email.value.trim();
            if (em && !/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(em)) { email.focus(); return toast("That email address doesn't look right", "bad"); }
            if (em && /@(.*\.(local|lan|home|internal|intranet|localdomain|localhost|test|example|invalid|home\.arpa)|[0-9.]+|[^.]+)$/i.test(em)) {
              email.focus(); return toast("Let's Encrypt only accepts an email on a real internet domain, use your normal address, or leave it empty", "bad");
            }
            // Picking "Let's Encrypt" (and its Force HTTPS / HSTS switches) is saved once the certificate
            // exists; any other unsaved edits are saved first, keeping the current certificate for now.
            const others = { ...s, ssl: d.settings.ssl, force_https: d.settings.force_https, hsts: d.settings.hsts };
            if (JSON.stringify(others) !== orig) {
              try { await API.siteSave(name, others); name = s.server_name; } catch (e) { return openModal("Couldn't save", el("pre", { class: "log", text: e.message }), []); }
            }
            try { localStorage.setItem("aurora-le-email", email.value.trim()); } catch (e) {}
            try { const r = await API.siteLE(s.server_name, email.value.trim(), withAliases.checked, force.checked); follow(r.job, "Requesting certificate…", async (ok) => {
              if (!ok) return;
              try {
                const cur = (await API.siteGet(name)).settings;
                Object.assign(cur, { ssl: "letsencrypt", force_https: s.force_https, hsts: s.hsts });
                await API.siteSave(name, cur); toast("Let's Encrypt certificate installed", "good");
              } catch (e) { toast(e.message, "bad"); }
              load();
            }); } catch (e) { toast(e.message, "bad"); }
          } }, [icon("lock", 13), d.certbot ? " Issue / renew certificate" : " Install certbot"]);
          function follow(jobId, label, done) {
            log.hidden = false; log.textContent = label; issue.disabled = true;
            clearInterval(jp.t);
            jp.t = setInterval(async () => {
              try {
                const j = await API.job(jobId);
                log.textContent = j.output || label; log.scrollTop = log.scrollHeight;
                if (j.status !== "running") { clearInterval(jp.t); issue.disabled = false; toast(`${j.title}: ${j.status}`, j.status === "done" ? "good" : "bad"); done && done(j.status === "done"); }
              } catch (e) { clearInterval(jp.t); issue.disabled = false; }
            }, 1300);
          }
          sslDetail.append(...[
            el("p", { class: "dm-hint", html: d.le_available ? "✅ A Let's Encrypt certificate exists for this domain, save to use it. It renews automatically via certbot's timer." : "Free, trusted certificate. The domain must already point at this Pi's <b>public IP</b> and port <b>80</b> must be forwarded to it, so Let's Encrypt can verify it." }),
            field("Email for expiry notices (optional)", email, "A real address (not @…local). Empty is fine: certificates still renew automatically, you just won't get Let's Encrypt's reminder emails."),
            el("label", { class: "dm-check" }, [withAliases, " Include aliases (", s.aliases.filter((a) => !a.startsWith("*")).join(", ") || "none", ")"]),
            d.le_available ? el("label", { class: "dm-check" }, [force, " Renew now, even if it isn't due yet ", el("span", { class: "muted", text: "(Let's Encrypt allows only a few of these per week)" })]) : null,
            el("p", { class: "dm-hint", html: "By issuing you agree to the <a href='https://letsencrypt.org/repository/' target='_blank' rel='noopener'>Let's Encrypt Subscriber Agreement</a>." }),
            el("div", {}, issue), log].filter(Boolean));  // optional rows are null: append() would print "null"
          Object.assign(le, { issue });
        }
      };
      drawSsl();
      // System sites: Force HTTPS applies right away (no save bar, the rest of the page is read-only).
      const sysForce = () => el("div", { class: "dm-trow" }, [
        el("div", {}, [el("b", { text: "Force HTTPS redirect" }), el("span", { text: d.has_http ? "Send every http:// visit to https:// (301). Applied immediately." : "This is the HTTPS site, use Force HTTPS on the default (http) site." })]),
        sw(d.settings.force_https, async (v, inp) => {
          try { await API.siteToggle(d.conf, "force_https", v); toast(`Force HTTPS ${v ? "on" : "off"}`, "good"); load(); }
          catch (e) { inp.checked = !v; toast(e.message, "bad"); }
        }, { disabled: !d.has_http }),
      ]);
      const httpsToggles = el("div", {}, [
        ro ? sysForce() : toggleRow("force_https", "Force HTTPS redirect", "Send every http:// visit to https:// (301). Let's Encrypt renewals still work."),
        toggleRow("hsts", "HSTS", "Tell browsers to only ever use HTTPS for a year. Enable once HTTPS is working reliably."),
      ]);
      const syncHttps = () => httpsToggles.classList.toggle("dm-dim", s.ssl === "none" && !ro);
      if (sysSsl && !viaHttps) httpsToggles.hidden = true;  // Force HTTPS lives on the http site
      if (ro) httpsToggles.querySelectorAll(".dm-trow")[1].hidden = true;  // HSTS isn't set on the built-in sites
      left.append(card("lock", "HTTPS / SSL", "Encrypt traffic and choose where the certificate comes from.",
        seg("ssl", [["none", "None"], ["selfsigned", "Self-signed"], ...(ipSite || sysSsl ? [] : [["letsencrypt", "Let's Encrypt"]]), ["custom", "Custom"]], (v) => { if (v === "none" && !sysSsl) { s.force_https = false; s.hsts = false; httpsToggles.querySelectorAll(".sw-in").forEach((i) => { i.checked = false; }); } drawSsl(); syncHttps(); }, sysSsl),
        ipSite ? el("p", { class: "dm-hint", text: "Why no Let's Encrypt? It only issues certificates for domain names that point at this server from the internet, never for an IP address like this one. For a trusted certificate, point a domain (even a free one, e.g. from DuckDNS) at this server and add it as a domain site; or upload your own certificate with Custom." }) : null,
        certRow, sslDetail, httpsToggles));
      syncHttps();

      // ---- Redirect ----
      const code = el("select", { onchange: (e) => { s.redirect_code = +e.target.value; dirty(); } }, [el("option", { value: "301", text: "301 · Permanent" }), el("option", { value: "302", text: "302 · Temporary" })]);
      code.value = String(s.redirect_code || 301); if (ro) code.disabled = true;
      left.append(card("redirect", "Redirect this domain", "Send all visitors (keeping the path) to another address. Leave empty for no redirect.",
        el("div", { class: "dm-row2" }, [field("Redirect to", text("redirect_url", "https://www.example.org")), field("Type", code)])));

      // ---- Performance & security ----
      left.append(card("shield", "Performance & security", "One-click Apache tuning for this site.",
        toggleRow("gzip", "Gzip compression", "Compress HTML, CSS, JS and JSON, pages load faster."),
        toggleRow("cache_static", "Browser caching", "Let browsers keep images, fonts, CSS and JS for a week/month."),
        toggleRow("security_headers", "Security headers", "X-Frame-Options, nosniff and a safe Referrer-Policy."),
        toggleRow("indexes", "Directory listing", "Show a file list for folders without an index page."),
        toggleRow("allow_override", "Allow .htaccess", "Needed by WordPress & most PHP apps (and the Redirects / Indexes tools)."),
        toggleRow("maintenance", "Maintenance mode", "Visitors get a friendly “be right back” page (HTTP 503)."),
      ));

      // ---- Advanced ----
      const custom = el("textarea", { class: "cw-mono", rows: 5, placeholder: "# Extra Apache directives for this site, e.g.\nHeader set X-Robots-Tag \"noindex\"\nProxyPass /api http://127.0.0.1:3000/api", oninput: (e) => { s.custom = e.target.value; dirty(); } });
      custom.value = s.custom || "";
      // Built-in sites: the directives go in a marked block of their own, applied with this button.
      const applyCustom = ro ? el("button", { class: "btn btn-primary btn-sm", type: "button", onclick: async () => {
        applyCustom.disabled = true;
        try { await API.siteSystemCustom(d.conf, custom.value); toast("Directives applied & Apache reloaded", "good"); load(); }
        catch (e) { openModal("Couldn't apply the directives", el("pre", { class: "log", text: e.message }), []); applyCustom.disabled = false; }
      } }, [icon("backup", 13), " Apply directives"]) : null;
      left.append(card("terminal", "Advanced", ro ? `Raw directives added inside the ${d.has_http ? "http (port 80)" : "https (port 443)"} VirtualHost of ${d.conf}, in a marked block, the rest of the file is left alone. Validated with apache2ctl first.` : "Raw directives added inside the VirtualHost. Validated with apache2ctl before saving.",
        custom, applyCustom ? el("div", {}, applyCustom) : null,
        el("div", {}, el("button", { class: "btn btn-sm btn-ghost", type: "button", onclick: () => {
          // Full-file editor: checked with apache2ctl and put back if Apache rejects it.
          const ed = el("textarea", { class: "cw-mono dm-conf-ed", rows: 24, spellcheck: "false" }); ed.value = d.config_text;
          const saveConf = el("button", { class: "btn btn-primary", onclick: async () => {
            saveConf.disabled = true;
            try { await API.siteConfSave(d.system ? d.conf : d.settings.server_name, ed.value); closeModal(); toast(`${d.conf} saved & Apache reloaded`, "good"); load(); }
            catch (e) { toast(e.message.split("\n").slice(0, 3).join(" · "), "bad"); saveConf.disabled = false; }
          } }, [icon("backup", 14), " Save file"]);
          openModal(d.conf, el("div", {}, [
            el("p", { class: "dm-hint", style: "margin:0 0 8px", text: d.managed ? "AuroraPanel manages this file: saving the settings form later rewrites it from the form, so put lasting extras in Advanced instead." : "Edit the file Apache loads. It's checked with apache2ctl first, a backup goes to /var/lib/aurora/site-backups, and nothing changes if Apache rejects it." }),
            ed]), [saveConf]);
        } }, [icon("mime", 13), " View / edit config file"]))));

      // ---- right column ----
      const info = (k, v) => el("div", { class: "info-row" }, [el("span", { class: "k", text: k }), el("span", { class: "v" }, v)]);
      right.append(el("div", { class: "card" }, [el("h3", { text: "Domain information" }), el("div", { class: "info-list" }, [
        info("Domain", d.settings.server_name),
        info("Aliases", d.settings.aliases.join(", ") || ", "),
        info("Redirects to", d.settings.redirect_url || "Not Redirected"),
        info("Document root", d.settings.docroot),
        info("SSL", sslPill({ ...d.settings, cert_expires: d.cert && d.cert.expires })),
        info("Force HTTPS", d.settings.force_https ? "On" : "Off"),
        info("Status", el("span", { class: `pill ${d.enabled ? "good" : "warn"}`, text: d.enabled ? "enabled" : "disabled" })),
        info("Config", d.conf),
      ])]));
      const res = (ico, label, fn) => el("button", { class: "dm-res", type: "button", onclick: fn }, [icon(ico, 15), el("span", { text: label }), el("span", { class: "tile-chev", text: "›" })]);
      right.append(el("div", { class: "card" }, [el("h3", { text: "Additional resources" }),
        ipSite ? null : res("zone", "Modify the DNS zone", () => openZone(d.settings.server_name.replace(/^www\./, ""))),
        ipSite ? null : res("search", "Check DNS & WHOIS", () => showDomainInfo(d.settings.server_name)),
        res("redirect", "Path redirects (.htaccess)", () => navigate("redirects")),
        res("lock", "SSL/TLS certificates", () => navigate("ssl")),
      ].filter(Boolean)));
      if (!ro) right.append(el("div", { class: "card dm-danger" }, [el("h3", { text: "Remove the domain" }),
        el("p", { class: "muted", html: `Removes the Apache site for <b>${esc(d.settings.server_name)}</b>. Files in <code>${esc(d.settings.docroot)}</code> are kept.` }),
        el("button", { class: "btn btn-danger btn-sm", onclick: async () => {
          if (!confirmInline(`Remove ${d.settings.server_name}? The document root is kept.`)) return;
          try { await API.siteRemove(d.settings.server_name); toast("Domain removed", "good"); navigate("vhosts"); } catch (e) { toast(e.message, "bad"); }
        } }, [icon("error", 13), " Remove domain"])]));

      // ---- save bar ----
      const saveBtn = el("button", { class: "btn btn-primary", onclick: async () => {
        // Let's Encrypt picked but not issued yet: Save does what "Issue / renew certificate" does.
        if (s.ssl === "letsencrypt" && !d.le_available && le.issue) { le.issue.scrollIntoView({ block: "center" }); return le.issue.click(); }
        saveBtn.disabled = true;
        try {
          const r = await API.siteSave(name, s);
          toast(r.adopted ? "Saved, AuroraPanel now manages this site" : "Saved & Apache reloaded", "good");
          name = s.server_name; load();
        } catch (e) { openModal("Couldn't save", el("pre", { class: "log", text: e.message }), []); saveBtn.disabled = false; }
      } }, [icon("backup", 14), " Save changes"]);
      const saveBar = el("div", { class: "dm-savebar" }, [el("span", { class: "dm-dot" }), el("span", { text: "Unsaved changes" }), el("span", { class: "grow" }),
        el("button", { class: "btn btn-ghost", text: "Discard", onclick: () => render(d) }), saveBtn]);
      root.append(saveBar);
    }
    load();
  }

  async function showDomainInfo(name) {
    const box = el("div", { class: "loading", text: "Looking up WHOIS + DNS…" });
    openModal(name, box, []);
    let d;
    try { d = await API.domainInfo(name); } catch (e) { box.className = ""; box.textContent = e.message; return; }
    const w = d.whois || {};
    const rows = [];
    rows.push(el("div", { class: "info-row" }, [el("span", { class: "k", text: "Registered" }), el("span", { class: "v" }, el("span", { class: `pill ${d.registered ? "good" : "dim"}`, text: d.registered ? "yes" : "no / unregistered" }))]));
    if (w.expiry) rows.push(infoRow("Expires", w.expiry));
    if (w.registrar) rows.push(infoRow("Registrar", w.registrar));
    if (w.created) rows.push(infoRow("Created", w.created));
    rows.push(infoRow("Resolves to", d.resolved_ip || ", "));
    rows.push(infoRow("This Pi (LAN)", d.local_ip));
    if (d.public_ip) rows.push(infoRow("This Pi (public)", d.public_ip));

    const content = el("div", {}, [el("div", { class: "card", style: "margin-bottom:14px" }, [el("h3", { text: "Domain" }), el("div", { class: "info-list" }, rows)])]);

    if (d.mode === "local") {
      content.append(el("div", { class: "card", style: "margin-bottom:14px" }, [
        el("h3", { text: "🖥 Local / virtual domain, access it from your computer" }),
        el("p", { class: "muted", style: "margin:0 0 8px", text: "This domain isn't publicly registered/pointed here. To open it in your browser, add this line to your hosts file:" }),
        el("pre", { class: "log", text: d.hosts_line }),
        el("p", { class: "muted", style: "font-size:12px", text: "Windows: C:\\Windows\\System32\\drivers\\etc\\hosts   ·   macOS/Linux: /etc/hosts   (edit as administrator/root)" }),
      ]));
    } else {
      content.append(el("div", { class: "card" }, [
        el("h3", { text: "🌐 Make this domain live" }),
        el("p", { class: "muted", style: "margin:0 0 8px", text: "At your registrar's DNS, create this record so the domain points at this Pi:" }),
        el("pre", { class: "log", text: d.dns_record ? `${d.dns_record.type}   ${d.dns_record.name}   →   ${d.dns_record.value}` : "(public IP unavailable, check the Pi's internet)" }),
        el("p", { class: "muted", style: "font-size:12px", text: "Then forward ports 80/443 on your router to this Pi, and issue an SSL cert (Security → SSL/TLS). " + (d.resolves_here_wan ? "✅ It already points here!" : "") }),
      ]));
    }
    openModal(name, content, []);
  }

  // ======================================================================
  //  Network: VPN servers, Dynamic DNS, Port Checker, Network Monitor
  //  Security note: data here includes attacker-controlled text (usernames
  //  from failed logins, log lines, provider replies). It is only ever put
  //  into the DOM via el(..., { text }) / textContent, never `html:`.
  // ======================================================================
  const ago = (ts) => {
    if (!ts) return "never";
    const s = Math.max(0, Math.round(Date.now() / 1000 - ts));
    if (s < 60) return `${s}s ago`;
    if (s < 3600) return `${Math.floor(s / 60)}m ago`;
    if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
    return `${Math.floor(s / 86400)}d ago`;
  };
  const when = (ts) => ts ? new Date(ts * 1000).toLocaleString([], { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit", second: "2-digit", hour12: false }) : ", ";
  const isIPv4 = (s) => /^\d{1,3}(\.\d{1,3}){3}$/.test(String(s || ""));
  function downloadText(filename, text, mime) {
    const url = URL.createObjectURL(new Blob([text], { type: mime || "text/plain" }));
    const a = el("a", { href: url, download: filename });
    document.body.append(a); a.click(); a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 2000);
  }
  const pill = (text, kind) => el("span", { class: `pill ${kind || "dim"}`, text });
  const row = (...cells) => el("tr", {}, cells.map((c) => el("td", {}, c == null ? ", " : (typeof c === "object" ? c : String(c)))));
  const btn = (text, onclick, cls) => el("button", { class: `btn btn-sm ${cls || ""}`, text, onclick });
  const kv = (pairs) => el("div", { class: "net-kv" }, pairs.filter(Boolean).map(([k, v]) =>
    el("div", {}, [el("span", { class: "net-k", text: k }), typeof v === "object" && v ? v : el("span", { class: "net-v", text: v == null ? ", " : String(v) })])));
  function field(label, input, hint) {
    return el("label", { class: "net-field" }, [el("span", { text: label }), input, hint ? el("small", { class: "dm-hint", text: hint }) : null]);
  }
  function gotoPortCheck(port, proto) { state.portPreset = { port, proto }; navigate("portcheck"); }

  // Watch a background job in the job panel, then call done() once it ends.
  async function watchJob(jp, jobId, label, done) {
    await jp.run(jobId, label);
    const t = setInterval(async () => {
      try { const j = await API.job(jobId); if (j.status !== "running") { clearInterval(t); done && done(j); } }
      catch (e) { clearInterval(t); }
    }, 1500);
    state.cleanups.push(() => clearInterval(t));
  }

  const VPN_INFO = {
    wireguard: { name: "WireGuard", view: "wireguard", icon: "tunnel",
      desc: "Modern, fast and simple. Best choice for phones and laptops, scan a QR code and you're in. Apps for every OS.",
      ports: (s) => [{ port: s.port, proto: "udp" }] },
    openvpn: { name: "OpenVPN", view: "openvpn", icon: "key",
      desc: "The classic. Works almost everywhere, can run over TCP to get through strict networks. One .ovpn file per device.",
      ports: (s) => [{ port: s.port, proto: s.proto }] },
    ipsec: { name: "IPsec / IKEv2", view: "ipsec", icon: "shield",
      desc: "Built into iPhone, Mac, Windows and Android (strongSwan app), no extra VPN app needed. Username + password login.",
      ports: () => [{ port: 500, proto: "udp" }, { port: 4500, proto: "udp" }] },
  };

  function vpnStatusPill(s) {
    if (!s || s.error) return pill("error", "bad");
    if (!s.installed) return pill("Not installed");
    if (!s.configured) return pill("Not set up", "warn");
    return s.active ? pill("Running", "good") : pill("Stopped", "bad");
  }

  function endpointCard(settings, onSaved) {
    const ep = el("input", { type: "text", value: settings.endpoint || "", placeholder: settings.ddns_hostname || settings.public_ip || "vpn.example.com" });
    const dns = el("input", { type: "text", value: settings.dns || "" });
    const src = { custom: "your custom setting", ddns: "your Dynamic DNS hostname", public_ip: "your current public IP (changes? set up Dynamic DNS)" }[settings.endpoint_source];
    return el("div", { class: "card" }, [
      el("h3", { text: "Where clients connect" }),
      kv([["Clients will connect to", el("b", { text: settings.effective_endpoint || "unknown" })], ["Source", src], ["Public IP right now", settings.public_ip]]),
      el("div", { class: "net-form" }, [
        field("Endpoint override (hostname or IP)", ep, "Leave empty to use Dynamic DNS, or else the public IP."),
        field("DNS servers for VPN clients", dns, "Comma separated IPv4, e.g. 1.1.1.1, 9.9.9.9"),
      ]),
      el("div", { class: "toolbar", style: "margin:12px 0 0" }, [
        btn("Save", async () => {
          try { await API.vpnSettings({ endpoint: ep.value.trim(), dns: dns.value.trim() }); toast("Saved, re-download client configs to pick up changes", "good"); onSaved && onSaved(); }
          catch (e) { toast(e.message, "bad"); }
        }, "btn-primary"),
        btn("Set up Dynamic DNS", () => navigate("dyndns"), "btn-ghost"),
      ]),
    ]);
  }

  // ---- VPN Overview ----
  function viewVPNOverview(root) {
    root.append(el("p", { class: "muted", style: "margin:0 0 14px", text: "Run your own VPN server on this Pi so your devices can reach home, and browse through your home connection, from anywhere. Pick any (or all) of the three; each is independent." }));
    const body = el("div", {}, el("div", { class: "loading", text: "Loading…" }));
    root.append(body);
    const load = () => guardedLoad(async () => {
      const d = await API.vpnOverview();
      body.innerHTML = "";
      const cards = Object.entries(VPN_INFO).map(([k, info]) => {
        const s = d[k] || {};
        const ports = s.error ? [] : info.ports(s);
        const clients = (s.peers || s.clients || s.users || []).filter((c) => !c.revoked);
        return el("div", { class: "card net-vpn-card" }, [
          el("div", { class: "net-card-h" }, [icon(info.icon, 20), el("h3", { text: info.name }), el("span", { style: "flex:1" }), vpnStatusPill(s)]),
          el("p", { class: "muted", text: info.desc }),
          kv([
            ["Port", ports.map((p) => `${p.proto.toUpperCase()} ${p.port}`).join(" + ")],
            s.configured ? ["Clients", `${clients.length} (${clients.filter((c) => c.online).length} online)`] : null,
            s.configured ? ["Subnet", s.subnet] : null,
          ]),
          el("div", { class: "toolbar", style: "margin:auto 0 0" }, [
            btn(s.configured ? "Manage" : s.installed ? "Set up" : "Install", () => navigate(info.view), "btn-primary"),
            ports.length ? btn("Check port", () => gotoPortCheck(ports[0].port, ports[0].proto), "btn-ghost") : null,
          ]),
        ]);
      });
      body.append(el("div", { class: "net-grid" }, cards), endpointCard(d.settings, load),
        el("div", { class: "card" }, [
          el("h3", { text: "Reaching the VPN from outside" }),
          el("p", { class: "muted", text: "Your router must forward the VPN's port to this Pi. Use the Port Checker: it tests the port from the internet, detects double NAT / CGNAT and tells you exactly what to change on the router." }),
          btn("Open Port Checker", () => navigate("portcheck"), "btn-primary"),
        ]));
    });
    state.refreshHandler = load; load();
  }

  // Shared server header: status, controls, self-test, port shortcut.
  function vpnServerCard(kind, s, reload, jp) {
    const info = VPN_INFO[kind];
    const ports = info.ports(s);
    const ctl = async (action) => {
      try { await API.vpnControl(kind, action); toast(`${info.name}: ${action}`, "good"); reload(); } catch (e) { toast(e.message, "bad"); }
    };
    return el("div", { class: "card" }, [
      el("div", { class: "net-card-h" }, [icon(info.icon, 20), el("h3", { text: `${info.name} server` }), el("span", { style: "flex:1" }), vpnStatusPill(s)]),
      kv([
        ["Listening on", ports.map((p) => `${p.proto.toUpperCase()} ${p.port}`).join(" + ")],
        ["VPN subnet", s.subnet],
        ["IP forwarding", pill(s.forwarding ? "on" : "off", s.forwarding ? "good" : "bad")],
        ["NAT for clients", pill(s.nat ? "on" : "off", s.nat ? "good" : "bad")],
        kind === "wireguard" ? ["Server public key", el("code", { class: "net-mono", text: s.public_key })] : null,
        kind === "ipsec" ? ["Certificate issued for", s.host] : null,
      ]),
      el("div", { class: "toolbar", style: "margin:14px 0 0" }, [
        s.active ? btn("Restart", () => ctl("restart")) : btn("Start", () => ctl("start"), "btn-primary"),
        s.active ? btn("Stop", () => { if (confirmInline(`Stop ${info.name}? Connected clients will drop.`)) ctl("stop"); }, "btn-ghost") : null,
        kind !== "ipsec" ? btn("Run self-test", async () => {
          try { const r = await API.vpnSelftest(kind); watchJob(jp, r.job, `${info.name} self-test`, reload); } catch (e) { toast(e.message, "bad"); }
        }) : null,
        ...ports.map((p) => btn(`Check ${p.proto.toUpperCase()} ${p.port}`, () => gotoPortCheck(p.port, p.proto), "btn-ghost")),
      ]),
      kind !== "ipsec" ? el("p", { class: "dm-hint", style: "margin-top:10px", text: "Self-test connects a real temporary client from an isolated network namespace on this Pi, pings through the tunnel and out to the internet, then removes it." }) : null,
    ]);
  }

  // Generic 3-phase VPN view scaffold: install → set up → manage (auto-refresh).
  function vpnView(root, kind, { setupForm, manage }) {
    const info = VPN_INFO[kind];
    const body = el("div", {}, el("div", { class: "loading", text: "Loading…" }));
    root.append(body);
    const jp = jobPanel(root);
    state.cleanups.push(jp.stop);
    let phase = null, parts = null;
    const load = () => guardedLoad(async () => {
      const s = await API.vpn(kind);
      const p = !s.installed ? "install" : !s.configured ? "setup" : "manage";
      if (p !== phase) {
        phase = p; body.innerHTML = ""; parts = null;
        if (p === "install") {
          body.append(installCard(`${info.name} is not installed`, info.desc,
            async () => { try { const r = await API.vpnInstall(kind); watchJob(jp, r.job, `Installing ${info.name}`, load); } catch (e) { toast(e.message, "bad"); } }));
        } else if (p === "setup") {
          body.append(setupForm(s, jp, load));
        } else {
          parts = manage(s, jp, load);
          body.append(parts.node);
        }
      } else if (parts && parts.update) {
        parts.update(s);
      }
    });
    state.refreshHandler = load; load();
    const t = setInterval(() => { if (phase === "manage") load(); }, 5000);
    state.cleanups.push(() => clearInterval(t));
  }

  function subnetInput(v) { return el("input", { type: "text", value: v }); }

  // ---- WireGuard ----
  function viewWireGuard(root) {
    vpnView(root, "wireguard", {
      setupForm(s, jp, reload) {
        const port = el("input", { type: "number", min: 1, max: 65535, value: s.port });
        const subnet = subnetInput(s.subnet);
        const go = btn("Create WireGuard server", async () => {
          go.disabled = true;
          try { await API.vpnSetup("wireguard", { port: +port.value, subnet: subnet.value.trim() }); toast("WireGuard is running", "good"); reload(); }
          catch (e) { toast(e.message, "bad"); go.disabled = false; }
        }, "btn-primary");
        return el("div", { class: "card" }, [
          el("h3", { text: "Set up the WireGuard server" }),
          el("p", { class: "muted", text: "Generates the server keys, creates wg0, enables IP forwarding + NAT and starts it on boot." }),
          el("div", { class: "net-form" }, [field("UDP port", port, "Default 51820. Forward this UDP port on your router."), field("VPN subnet", subnet, "Private range not used on your LAN.")]),
          el("div", { style: "margin-top:14px" }, go),
        ]);
      },
      manage(s, jp, reload) {
        const head = el("div");
        const list = el("div");
        const name = el("input", { type: "text", placeholder: "e.g. phone", maxlength: 32 });
        const tunnel = el("select", {}, [el("option", { value: "full", text: "Full tunnel, all traffic via home" }), el("option", { value: "split", text: "Split, only home network via VPN" })]);
        const add = btn("Add client", async () => {
          try { const r = await API.vpnClientAdd("wireguard", { name: name.value.trim(), tunnel: tunnel.value }); name.value = ""; toast(`Client ${r.name} added (${r.ip})`, "good"); await reload(); showWgConfig(r.name); }
          catch (e) { toast(e.message, "bad"); }
        }, "btn-primary");
        const addCard = el("div", { class: "card" }, [el("h3", { text: "Add a client (device)" }), el("div", { class: "net-form" }, [field("Name", name), field("Routing", tunnel)]), el("div", { style: "margin-top:12px" }, add)]);
        const update = (st) => {
          head.innerHTML = ""; head.append(vpnServerCard("wireguard", st, reload, jp));
          list.innerHTML = "";
          list.append(el("h2", { class: "section-title", text: `Clients (${st.peers.length})` }));
          if (!st.peers.length) { list.append(el("p", { class: "empty", text: "No clients yet, add one below." })); return; }
          list.append(simpleTable(["Name", "VPN IP", "Status", "Last handshake", "Connected from", "Received / Sent", "Routing", ""],
            st.peers.map((p) => row(
              el("b", { text: p.name }), p.ip,
              p.disabled ? pill("disabled") : pill(p.online ? "online" : "offline", p.online ? "good" : "dim"),
              ago(p.latest_handshake), p.endpoint || ", ", `${fmtBytes(p.rx)} / ${fmtBytes(p.tx)}`, p.tunnel,
              el("div", { class: "net-actions" }, [
                btn("Config / QR", () => showWgConfig(p.name)),
                btn(p.disabled ? "Enable" : "Disable", async () => { try { await API.wgToggle(p.name, !p.disabled); reload(); } catch (e) { toast(e.message, "bad"); } }, "btn-ghost"),
                btn("Remove", async () => { if (!confirmInline(`Remove client ${p.name}? Its config stops working immediately.`)) return; try { await API.vpnClientRemove("wireguard", p.name); toast("Removed", "good"); reload(); } catch (e) { toast(e.message, "bad"); } }, "btn-danger"),
              ]),
            ))));
        };
        update(s);
        return { node: el("div", {}, [head, list, addCard]), update };
      },
    });
  }
  async function showWgConfig(name) {
    try {
      const c = await API.vpnClientConfig("wireguard", name);
      // QR is shown through <img src=data:>: an SVG loaded as an image can't run script.
      const qr = c.qr_svg ? el("img", { class: "net-qr", alt: "QR code", src: "data:image/svg+xml;base64," + btoa(unescape(encodeURIComponent(c.qr_svg))) }) : null;
      openModal(`WireGuard, ${name}`, el("div", { class: "net-cfg" }, [
        qr ? el("div", { class: "net-qr-wrap" }, [qr, el("p", { class: "dm-hint", text: "Scan with the WireGuard app (Android / iOS): + → Scan from QR code." })]) : null,
        el("div", {}, [
          el("p", { class: "muted", text: "Desktop: install WireGuard, then Import tunnel from file." }),
          el("pre", { class: "log", text: c.config }),
          el("p", { class: "dm-hint", text: "This file contains the device's private key, treat it like a password." }),
        ]),
      ]), [btn("Download .conf", () => downloadText(c.filename, c.config), "btn-primary")]);
    } catch (e) { toast(e.message, "bad"); }
  }

  // ---- OpenVPN ----
  function openvpnForm(s, label, onGo) {
    const port = el("input", { type: "number", min: 1, max: 65535, value: s.port });
    const proto = el("select", {}, [el("option", { value: "udp", text: "UDP (faster, recommended)" }), el("option", { value: "tcp", text: "TCP (gets through strict firewalls)" })]);
    proto.value = s.proto;
    const subnet = subnetInput(s.subnet);
    const redirect = el("select", {}, [el("option", { value: "1", text: "Full tunnel, all traffic via home" }), el("option", { value: "0", text: "Split, only home network via VPN" })]);
    redirect.value = s.redirect ? "1" : "0";
    const go = btn(label, () => onGo({ port: +port.value, proto: proto.value, subnet: subnet.value.trim(), redirect: redirect.value === "1" }, go), "btn-primary");
    return el("div", {}, [
      el("div", { class: "net-form" }, [field("Port", port, "Default 1194."), field("Protocol", proto), field("VPN subnet", subnet), field("Routing", redirect)]),
      el("div", { style: "margin-top:14px" }, go),
    ]);
  }
  function viewOpenVPN(root) {
    vpnView(root, "openvpn", {
      setupForm(s, jp, reload) {
        return el("div", { class: "card" }, [
          el("h3", { text: "Set up the OpenVPN server" }),
          el("p", { class: "muted", text: "Creates a private certificate authority (EC P-256), server certificate and tls-crypt key, writes the server config, enables forwarding + NAT and starts openvpn-server@aurora. Takes a few seconds." }),
          openvpnForm(s, "Create OpenVPN server", async (body, go) => {
            go.disabled = true;
            try { const r = await API.vpnSetup("openvpn", body); watchJob(jp, r.job, "Setting up OpenVPN", () => { go.disabled = false; reload(); }); }
            catch (e) { toast(e.message, "bad"); go.disabled = false; }
          }),
        ]);
      },
      manage(s, jp, reload) {
        const head = el("div"), banner = el("div"), list = el("div");
        // ---- add user ----
        const name = el("input", { type: "text", placeholder: "e.g. alice", maxlength: 32, autocomplete: "off" });
        const mode = el("select", {}, Object.entries(OVPN_MODES).map(([k, m]) => el("option", { value: k, text: m.label })));
        const modeHelp = el("p", { class: "dm-hint" });
        const pw = passwordField();
        const pwWrap = field("Password (8+ characters)", pw.node, "Leave empty to generate a strong one.");
        const syncMode = () => { modeHelp.textContent = OVPN_MODES[mode.value].help; pwWrap.hidden = mode.value === "cert"; };
        mode.addEventListener("change", syncMode); syncMode();
        const add = btn("Create user", async () => {
          add.disabled = true;
          try {
            const r = await API.ovpnUserAdd(name.value.trim(), mode.value, mode.value === "cert" ? null : pw.value());
            name.value = ""; pw.clear(); reload();
            ovpnCredentials(r, "User created");
          } catch (e) { toast(e.message, "bad"); }
          add.disabled = false;
        }, "btn-primary");
        const settings = el("details", { class: "card net-details" }, [
          el("summary", { text: "Server settings (port, protocol, routing)" }),
          el("p", { class: "dm-hint", text: "Changing port or protocol means every device needs its profile downloaded again." }),
          openvpnForm(s, "Apply & restart", async (body, go) => {
            go.disabled = true;
            try { const r = await API.vpnSetup("openvpn", body); watchJob(jp, r.job, "Reconfiguring OpenVPN", () => { go.disabled = false; reload(); }); }
            catch (e) { toast(e.message, "bad"); go.disabled = false; }
          }),
        ]);
        const addCard = el("div", { class: "card" }, [
          el("h3", { text: "Add a user" }),
          el("p", { class: "muted", text: "Each user gets their own .ovpn profile to import in OpenVPN Connect (any OS). Only you, the panel admin, can create users or change their passwords." }),
          el("div", { class: "net-form" }, [field("Username", name), field("Login type", mode), pwWrap]),
          modeHelp,
          el("div", { style: "margin-top:12px" }, add),
        ]);
        const act = (fn, ok) => async () => { try { await fn(); if (ok) toast(ok, "good"); reload(); } catch (e) { toast(e.message, "bad"); } };
        const update = (st) => {
          head.innerHTML = ""; head.append(vpnServerCard("openvpn", st, reload, jp));
          banner.innerHTML = "";
          if (!st.logins_enabled) banner.append(el("div", { class: "card net-warn" }, [
            el("p", { text: "Per-user logins are not enabled on this server yet. Enabling restarts OpenVPN (connected devices reconnect by themselves). Existing profiles keep working as 'Certificate only' users." }),
            btn("Enable user logins", async (e) => {
              e.target.disabled = true;
              try { const r = await API.vpnSetup("openvpn", { port: st.port, proto: st.proto, subnet: st.subnet, redirect: st.redirect }); watchJob(jp, r.job, "Enabling user logins", reload); }
              catch (err) { toast(err.message, "bad"); e.target.disabled = false; }
            }, "btn-primary"),
          ]));
          addCard.hidden = !st.logins_enabled;
          list.innerHTML = "";
          list.append(el("h2", { class: "section-title", text: `Users (${st.clients.length})` }));
          if (!st.clients.length) { list.append(el("p", { class: "empty", text: "No users yet, add one below." })); return; }
          list.append(simpleTable(["User", "Login type", "Status", "Connected from", "VPN IP", "Received / Sent", ""],
            st.clients.map((c) => row(
              el("b", { text: c.name }),
              pill(c.mode_label || c.mode, c.mode === "cert+password" ? "good" : "dim"),
              c.disabled ? pill("disabled", "bad") : pill(c.online ? (c.sessions > 1 ? `online ×${c.sessions}` : "online") : "offline", c.online ? "good" : "dim"),
              c.real_address || ", ", c.virtual_address || ", ", c.online ? `${fmtBytes(c.rx)} / ${fmtBytes(c.tx)}` : ", ",
              el("div", { class: "net-actions" }, [
                btn("Profile", () => downloadOvpn(c.name)),
                c.mode !== "cert" ? btn("Password", () => ovpnPasswordDialog(c.name, reload)) : null,
                st.logins_enabled ? btn("Login type", () => ovpnModeDialog(c, reload), "btn-ghost") : null,
                st.logins_enabled ? btn(c.disabled ? "Enable" : "Disable", act(() => API.ovpnUserToggle(c.name, !c.disabled), c.disabled ? `${c.name} enabled` : `${c.name} disabled, disconnected`), "btn-ghost") : null,
                btn("Delete", async () => {
                  if (!confirmInline(`Delete user ${c.name}? They are disconnected and their profile stops working for good.`)) return;
                  await act(() => API.vpnClientRemove("openvpn", c.name), `${c.name} deleted`)();
                }, "btn-danger"),
              ]),
            ))));
        };
        update(s);
        return { node: el("div", {}, [head, banner, list, addCard, settings]), update };
      },
    });
  }
  async function downloadOvpn(name) {
    try { const c = await API.vpnClientConfig("openvpn", name); downloadText(c.filename, c.config, "application/x-openvpn-profile"); }
    catch (e) { toast(e.message, "bad"); }
  }

  const OVPN_MODES = {
    "cert+password": { label: "Certificate + password (most secure)",
      help: "The user needs their own profile AND their password. A copied .ovpn file alone is useless." },
    "password": { label: "Password only",
      help: "Everybody can use the same kind of profile, the username + password decide who gets in. Easiest to hand out." },
    "cert": { label: "Certificate only (no password)",
      help: "Whoever has the profile file is in, no password prompt. Keep the file safe." },
  };

  // Random password from the browser's CSPRNG (works on plain-http LAN too).
  // Passwords are never shown in clear on screen by default: each password field (class
  // pw-secret, or one of the panel's password rows / "copy it now" boxes) is masked with an eye
  // button to reveal it. Applied to fields as they appear, so every form gets it.
  const PW_SEL = "input.pw-secret, input.net-pw-out, .em-pw-row > input, .op-pwrow > input, .wp-pw > input";
  function maskPw(inp) {
    if (inp.dataset.pwm || inp.type === "hidden") return;
    inp.dataset.pwm = "1";
    inp.type = "password";
    inp.setAttribute("spellcheck", "false");
    if (!inp.getAttribute("autocomplete") || inp.getAttribute("autocomplete") === "off") inp.setAttribute("autocomplete", inp.readOnly ? "off" : "new-password");
    const eye = el("button", { type: "button", class: "pw-eye", title: "Show password", "aria-label": "Show password", "aria-pressed": "false" }, icon("eye", 16));
    eye.onclick = () => {
      const on = inp.type === "password";
      inp.type = on ? "text" : "password";
      eye.replaceChildren(icon(on ? "eyeOff" : "eye", 16));
      eye.title = on ? "Hide password" : "Show password";
      eye.setAttribute("aria-label", eye.title);
      eye.setAttribute("aria-pressed", on ? "true" : "false");
    };
    const wrap = el("span", { class: "pw-wrap" });
    inp.replaceWith(wrap);
    wrap.append(inp, eye);
  }
  new MutationObserver((muts) => {
    for (const m of muts) for (const n of m.addedNodes) {
      if (n.nodeType !== 1) continue;
      if (n.matches && n.matches(PW_SEL)) maskPw(n);
      n.querySelectorAll && n.querySelectorAll(PW_SEL).forEach(maskPw);
    }
  }).observe(document.body, { childList: true, subtree: true });

  function genPassword(len = 16) {
    const abc = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789";
    const buf = new Uint32Array(len); crypto.getRandomValues(buf);
    return Array.from(buf, (n) => abc[n % abc.length]).join("");
  }
  // Clipboard API needs https; fall back to selecting a hidden field + execCommand.
  async function copyText(text) {
    try { await navigator.clipboard.writeText(text); return true; }
    catch (e) {
      const t = el("textarea", { style: "position:fixed;opacity:0;left:-9999px" }); t.value = text;
      document.body.append(t); t.select();
      let ok = false; try { ok = document.execCommand("copy"); } catch (e2) {}
      t.remove(); return ok;
    }
  }
  // Password input with Generate / Show as small icon buttons *inside* the box,
  // so the field always fits its column (no buttons spilling into the next field).
  function passwordField() {
    const inp = el("input", { type: "password", autocomplete: "new-password", placeholder: "optional", maxlength: 128 });
    const iconBtn = (ico, label, onclick) => el("button", { type: "button", class: "net-pw-btn", title: label, "aria-label": label, onclick }, icon(ico, 16));
    const setShown = (on) => {
      inp.type = on ? "text" : "password";
      show.replaceChildren(icon(on ? "eyeOff" : "eye", 16));
      show.title = on ? "Hide password" : "Show password"; show.setAttribute("aria-label", show.title);
      show.setAttribute("aria-pressed", on ? "true" : "false");
    };
    const show = iconBtn("eye", "Show password", () => setShown(inp.type === "password"));
    const gen = iconBtn("wand", "Generate a strong password", () => { inp.value = genPassword(); setShown(true); inp.focus(); });
    return { node: el("div", { class: "net-pw" }, [inp, el("div", { class: "net-pw-btns" }, [gen, show])]),
      value: () => inp.value, clear: () => { inp.value = ""; setShown(false); }, input: inp };
  }
  // Shown once after create / password change, the panel never shows it again.
  function ovpnCredentials(r, title) {
    const rows = [["Username", r.name], ["Login type", (OVPN_MODES[r.mode] || {}).label || r.mode]];
    const body = [kv(rows)];
    if (r.password) {
      const pwBox = el("input", { type: "text", readonly: "readonly", class: "net-mono net-pw-out", value: r.password });
      body.push(el("div", { class: "net-cred" }, [el("span", { class: "net-k", text: "Password" }), pwBox,
        btn("Copy", async () => toast(await copyText(r.password) ? "Password copied" : "Copy failed, select it manually", "good"))]));
      body.push(el("p", { class: "dm-hint", text: "Write it down or send it to the user now, for security it is stored only as a hash and can't be shown again (you can always set a new one)." }));
    }
    if (r.new_profile || title === "User created") body.push(el("p", { class: "muted", text: "Give the user their .ovpn profile and import it in OpenVPN Connect." + (r.password ? " The app asks for the username and password when connecting." : "") }));
    openModal(title, el("div", {}, body), [btn(`Download ${r.name}.ovpn`, () => downloadOvpn(r.name), "btn-primary")]);
  }
  function ovpnPasswordDialog(name, reload) {
    const pw = passwordField();
    const save = btn("Set password", async () => {
      save.disabled = true;
      try { const r = await API.ovpnUserPassword(name, pw.value()); closeModal(); reload(); ovpnCredentials({ ...r, mode: null }, `New password for ${name}`); }
      catch (e) { toast(e.message, "bad"); save.disabled = false; }
    }, "btn-primary");
    openModal(`Change password, ${name}`, el("div", {}, [
      field("New password (8+ characters)", pw.node, "Leave empty to generate a strong one."),
      el("p", { class: "dm-hint", text: "The user is disconnected right away and must log in with the new password. Their profile file stays the same." }),
    ]), [save]);
    setTimeout(() => pw.input.focus(), 30);
  }
  function ovpnModeDialog(c, reload) {
    const sel = el("select", {}, Object.entries(OVPN_MODES).map(([k, m]) => el("option", { value: k, text: m.label })));
    sel.value = c.mode;
    const help = el("p", { class: "dm-hint" });
    const pw = passwordField();
    const pwWrap = field("Password for this user", pw.node, "Needed because this user has no password yet. Leave empty to generate.");
    const sync = () => { help.textContent = OVPN_MODES[sel.value].help; pwWrap.hidden = !(sel.value !== "cert" && c.mode === "cert"); };
    sel.addEventListener("change", sync); sync();
    const save = btn("Change login type", async () => {
      if (sel.value === c.mode) { closeModal(); return; }
      save.disabled = true;
      try { const r = await API.ovpnUserMode(c.name, sel.value, pw.value()); closeModal(); reload(); ovpnCredentials(r, `${c.name}: login type changed`); }
      catch (e) { toast(e.message, "bad"); save.disabled = false; }
    }, "btn-primary");
    openModal(`Login type, ${c.name}`, el("div", {}, [field("Login type", sel), help, pwWrap,
      el("p", { class: "muted", text: "The user is disconnected and needs to import their new profile (download it on the next screen)." })]), [save]);
  }

  // ---- IPsec / IKEv2 ----
  function viewIPsec(root) {
    vpnView(root, "ipsec", {
      setupForm(s, jp, reload) {
        const subnet = subnetInput(s.subnet);
        const go = btn("Create IKEv2 server", async () => {
          go.disabled = true;
          try { const r = await API.vpnSetup("ipsec", { subnet: subnet.value.trim() }); watchJob(jp, r.job, "Setting up strongSwan", () => { go.disabled = false; reload(); }); }
          catch (e) { toast(e.message, "bad"); go.disabled = false; }
        }, "btn-primary");
        return el("div", { class: "card" }, [
          el("h3", { text: "Set up the IPsec / IKEv2 server" }),
          el("p", { class: "muted", text: `Creates a certificate authority and a server certificate for ${s.endpoint || "your public address"} (set Dynamic DNS first if your IP changes, the certificate is tied to the name), then starts strongSwan. Users log in with username + password (EAP-MSCHAPv2).` }),
          el("div", { class: "net-form" }, [field("VPN subnet", subnet)]),
          el("div", { style: "margin-top:14px" }, go),
        ]);
      },
      manage(s, jp, reload) {
        const head = el("div"), warn = el("div"), list = el("div");
        const name = el("input", { type: "text", placeholder: "e.g. iphone", maxlength: 32 });
        const pw = el("input", { type: "text", class: "pw-secret", placeholder: "leave empty to generate" });
        const add = btn("Add user", async () => {
          try {
            const r = await API.vpnClientAdd("ipsec", { name: name.value.trim(), password: pw.value });
            name.value = pw.value = ""; reload(); showIpsecProfiles(r.name);
          } catch (e) { toast(e.message, "bad"); }
        }, "btn-primary");
        const update = (st) => {
          head.innerHTML = ""; head.append(vpnServerCard("ipsec", st, reload, jp));
          warn.innerHTML = "";
          if (st.host_mismatch) warn.append(el("div", { class: "card net-warn" }, [
            el("p", { text: `The server certificate is for ${st.host}, but clients now connect to ${st.endpoint}. Devices will reject the server until the certificate is reissued (then re-install profiles).` }),
            btn(`Reissue certificate for ${st.endpoint}`, async () => { try { const r = await API.vpnSetup("ipsec", { subnet: st.subnet }); watchJob(jp, r.job, "Reissuing certificate", reload); } catch (e) { toast(e.message, "bad"); } }, "btn-primary"),
          ]));
          list.innerHTML = "";
          list.append(el("h2", { class: "section-title", text: `Users (${st.users.length})` }));
          if (!st.users.length) { list.append(el("p", { class: "empty", text: "No users yet, add one below." })); return; }
          list.append(simpleTable(["User", "Status", "Connected from", "VPN IP", "Received / Sent", "Since", ""],
            st.users.map((u) => row(
              el("b", { text: u.name }), pill(u.online ? "online" : "offline", u.online ? "good" : "dim"),
              u.remote || ", ", u.virtual_address || ", ", u.online ? `${fmtBytes(u.rx)} / ${fmtBytes(u.tx)}` : ", ", u.since ? ago(u.since) : ", ",
              el("div", { class: "net-actions" }, [
                btn("Profiles", () => showIpsecProfiles(u.name)),
                btn("Remove", async () => { if (!confirmInline(`Remove user ${u.name}?`)) return; try { await API.vpnClientRemove("ipsec", u.name); toast("Removed", "good"); reload(); } catch (e) { toast(e.message, "bad"); } }, "btn-danger"),
              ]),
            ))));
        };
        update(s);
        return { node: el("div", {}, [head, warn, list,
          el("div", { class: "card" }, [el("h3", { text: "Add a user" }), el("div", { class: "net-form" }, [field("Username", name), field("Password (8+ chars)", pw)]), el("div", { style: "margin-top:12px" }, add)])]), update };
      },
    });
  }
  async function showIpsecProfiles(name) {
    try {
      const c = await API.vpnClientConfig("ipsec", name);
      const pwBox = el("code", { class: "net-mono", text: "••••••••" });
      const block = (title, text, dl) => el("div", { class: "net-os" }, [el("h4", { text: title }), el("p", { class: "muted", text }), dl]);
      openModal(`IKEv2, ${name}`, el("div", {}, [
        kv([["Server", c.host], ["Username", c.name], ["Password", el("span", {}, [pwBox, " ", btn("Show", (e) => { pwBox.textContent = c.password; e.target.remove(); }, "btn-ghost")])], ["Type", "IKEv2, EAP-MSCHAPv2"]]),
        block("iPhone / iPad / Mac", "Download the profile, open it, then install it under Settings → Profile Downloaded (Mac: System Settings → Profiles). CA + VPN + login in one step.",
          btn("Download .mobileconfig", () => downloadText(`aurora-${c.name}.mobileconfig`, c.mobileconfig, "application/x-apple-aspen-config"), "btn-primary")),
        block("Android", "Install the free strongSwan VPN Client app, then open this file with it and enter the password.",
          btn("Download .sswan", () => downloadText(`aurora-${c.name}.sswan`, c.sswan, "application/vnd.strongswan.profile"))),
        block("Windows 10/11", "Download the CA certificate and run the PowerShell below as Administrator in the same folder, then connect from the network menu.",
          el("div", {}, [btn("Download aurora-ca.crt", () => downloadText("aurora-ca.crt", c.ca_pem, "application/x-x509-ca-cert")), el("pre", { class: "log", text: c.windows_ps })])),
        block("Linux / other", "Use the CA certificate with any IKEv2 client (NetworkManager strongSwan plugin): server = the address above, auth = EAP username/password.", null),
      ]), []);
    } catch (e) { toast(e.message, "bad"); }
  }

  // ---- Dynamic DNS ----
  function viewDynDNS(root) {
    const statusBox = el("div"), formBox = el("div");
    root.append(el("p", { class: "muted", style: "margin:0 0 14px", text: "Home internet IPs change. Dynamic DNS gives you a fixed hostname (e.g. myhome.duckdns.org) that this Pi keeps pointed at your current IP, every 5 minutes, even when the panel is closed. VPN clients then connect to the hostname." }), statusBox, formBox);
    let d = null, chosen = null;
    function drawStatus() {
      statusBox.innerHTML = "";
      const c = d.config || {}, last = d.last || {};
      if (d.ddclient_active) statusBox.append(el("div", { class: "card net-warn" }, [
        el("p", { text: "The old ddclient service is also running. Two updaters for the same name fight each other, stop ddclient once you use this page." }),
        btn("Stop & disable ddclient", async () => { try { d = await API.ddnsStopDdclient(); drawStatus(); toast("ddclient stopped", "good"); } catch (e) { toast(e.message, "bad"); } }),
      ]));
      if (!c.provider) return;
      const match = d.resolved_ip && last.ip && d.resolved_ip === last.ip;
      statusBox.append(el("div", { class: "card" }, [
        el("div", { class: "net-card-h" }, [icon("refresh", 20), el("h3", { text: c.hostname || "" }), el("span", { style: "flex:1" }),
          c.enabled ? (last.ok ? pill("Updating", "good") : pill("Failing", "bad")) : pill("Disabled")]),
        kv([
          ["Provider", (d.providers[c.provider] || {}).name || c.provider],
          ["Public IP", last.ip],
          ["Hostname resolves to", el("span", {}, [el("span", { text: d.resolved_ip || "not resolving yet" }), " ", d.resolved_ip ? pill(match ? "matches" : "stale (DNS TTL, wait a few min)", match ? "good" : "warn") : null])],
          ["Last update", `${ago(last.ts)}, ${last.message || ""}`],
          ["Automatic updates", pill(d.timer_active ? "every 5 min" : "off", d.timer_active ? "good" : "dim")],
        ]),
        el("div", { class: "toolbar", style: "margin:14px 0 0" }, [
          btn("Update now", async () => { try { const r = await API.ddnsUpdate(); toast(`Sent ${r.ip}: ${r.message}`, "good"); load(); } catch (e) { toast(e.message, "bad"); load(); } }, "btn-primary"),
          c.enabled ? btn("Disable", async () => { try { d = await API.ddnsDisable(); drawStatus(); } catch (e) { toast(e.message, "bad"); } }, "btn-ghost") : null,
        ]),
      ]));
    }
    function drawForm() {
      formBox.innerHTML = "";
      const c = d.config || {};
      chosen = chosen || c.provider || "duckdns";
      const prov = d.providers[chosen];
      const seg = el("div", { class: "cw-seg" }, Object.entries(d.providers).map(([k, p]) =>
        el("button", { type: "button", class: k === chosen ? "active" : "", text: p.name, onclick: () => { chosen = k; drawForm(); } })));
      const inputs = {};
      const fields = prov.fields.map(([key, label, ph, secret]) => {
        const same = c.provider === chosen;
        const inp = el("input", { type: secret ? "password" : "text", placeholder: secret && same && c[key + "_set"] ? "(saved, leave empty to keep)" : ph || "", autocomplete: "off",
          value: !secret && same && c[key] ? (chosen === "duckdns" && key === "hostname" ? String(c[key]).replace(/\.duckdns\.org$/, "") : c[key]) : "" });
        inputs[key] = inp;
        const [lbl, hint] = String(label).split(", ");
        return field(lbl, inp, hint || "");
      });
      const save = btn(c.provider ? "Save & update" : "Save & get my address online", async () => {
        save.disabled = true;
        const vals = {}; for (const [k, i] of Object.entries(inputs)) vals[k] = i.value.trim();
        try { const r = await API.ddnsSave(chosen, vals, true); toast(`${r.config.hostname} → ${r.result ? r.result.ip : "?"}`, "good"); load(); }
        catch (e) { toast(e.message, "bad"); save.disabled = false; }
      }, "btn-primary");
      formBox.append(el("div", { class: "card" }, [
        el("h3", { text: c.provider ? "Change provider / credentials" : "Get a free hostname" }),
        seg,
        el("p", { class: "muted", style: "margin:12px 0" }, [
          el("span", { text: prov.note + " " }),
          prov.signup ? el("a", { href: prov.signup, target: "_blank", rel: "noopener noreferrer", text: `Sign up at ${prov.name} ↗` }) : null,
        ]),
        el("div", { class: "net-form" }, fields),
        el("div", { style: "margin-top:14px" }, save),
      ]));
    }
    const load = () => guardedLoad(async () => { d = await API.ddns(); drawStatus(); drawForm(); });
    state.refreshHandler = load; load();
  }

  // ---- Port Checker ----
  function viewPortCheck(root) {
    const preset = state.portPreset || {}; state.portPreset = null;
    const port = el("input", { type: "number", min: 1, max: 65535, value: preset.port || "", placeholder: "e.g. 51820" });
    let proto = preset.proto || "udp";
    const seg = el("div", { class: "cw-seg cw-seg-sm" }, ["tcp", "udp"].map((p) => el("button", { type: "button", class: p === proto ? "active" : "", text: p.toUpperCase(),
      onclick: (e) => { proto = p; seg.querySelectorAll("button").forEach((b) => b.classList.toggle("active", b === e.target)); } })));
    const presets = el("div", { class: "net-presets" });
    const result = el("div");
    const jp = jobPanel(root);
    state.cleanups.push(jp.stop);
    const go = btn("Check port", () => check(), "btn-primary");
    root.prepend(
      el("p", { class: "muted", style: "margin:0 0 14px", text: "Tests whether a port on this Pi can be reached from the internet, and if not, pinpoints where it's blocked: the service, the Pi's firewall, your router, or a second router / ISP NAT in front of it." }),
      el("div", { class: "card" }, [
        el("div", { class: "net-form" }, [field("Port", port), field("Protocol", seg)]),
        presets,
        el("div", { style: "margin-top:14px" }, go),
      ]), result);
    API.vpnOverview().then((o) => {
      const list = [];
      if (o.wireguard && o.wireguard.configured) list.push(["WireGuard", o.wireguard.port, "udp"]);
      if (o.openvpn && o.openvpn.configured) list.push(["OpenVPN", o.openvpn.port, o.openvpn.proto]);
      if (o.ipsec && o.ipsec.configured) list.push(["IPsec IKE", 500, "udp"], ["IPsec NAT-T", 4500, "udp"]);
      list.push(["SSH", 22, "tcp"], ["HTTP", 80, "tcp"], ["HTTPS", 443, "tcp"]);
      presets.append(el("span", { class: "dm-hint", text: "Quick pick: " }), ...list.map(([n, p, pr]) => el("button", { type: "button", class: "cw-chip", text: `${n} ${pr.toUpperCase()} ${p}`,
        onclick: () => { port.value = p; proto = pr; seg.querySelectorAll("button").forEach((b) => b.classList.toggle("active", b.textContent.toLowerCase() === pr)); check(); } })));
    }).catch(() => {});

    const line = (ok, title, text) => el("div", { class: `net-chk ${ok === true ? "ok" : ok === false ? "bad" : "unk"}` }, [
      el("span", { class: "net-chk-i", text: ok === true ? "✔" : ok === false ? "✖" : "?" }), el("div", {}, [el("b", { text: title }), el("div", { class: "muted", text })])]);

    async function check() {
      const p = +port.value;
      if (!p) { toast("Enter a port", "bad"); return; }
      go.disabled = true;
      result.innerHTML = ""; result.append(el("div", { class: "loading", text: `Checking ${proto.toUpperCase()} ${p} from outside… (up to ~20 s)` }));
      try { draw(await API.portCheck(p, proto)); }
      catch (e) { result.innerHTML = ""; toast(e.message, "bad"); }
      go.disabled = false;
    }

    function draw(r) {
      result.innerHTML = "";
      const P = `${r.proto.toUpperCase()} ${r.port}`;
      const verdict = { open: ["Open, reachable from the internet", "good"], closed: ["Closed, not reachable from the internet", "bad"], unverified: ["Can't be verified automatically (UDP)", "warn"] }[r.verdict];
      const L = r.listen || {}, F = r.firewall || {}, U = r.upnp || {};
      const checks = [
        line(L.listening ? true : r.temp_listener ? null : false, "Service on this Pi",
          L.listening ? `${L.process || "Something"} is listening on ${L.address}` : r.temp_listener ? "Nothing listens here, a temporary listener was used for the test" : `Nothing is listening on ${P}`),
        line(!F.active || F.allowed ? true : false, "Pi firewall (ufw)", !F.installed ? "Not installed" : !F.active ? "Inactive, not blocking" : F.allowed ? `Allows ${P}` : `Active and does NOT allow ${P}`),
        line(r.nat ? false : U.available ? true : null, "Router / NAT",
          r.nat === "double" ? `Double NAT: your router (${r.gateway}) gets ${U.router_wan_ip} from another router in front of it` :
          r.nat === "cgnat" ? `Carrier-grade NAT: router WAN ${U.router_wan_ip} is not a public address` :
          U.available ? `Router holds the public IP ${r.public_ip}` : "Router doesn't answer UPnP, can't inspect it (that's fine)"),
        r.inner_hop != null ? line(r.inner_hop, `Forward on your router (${r.gateway})`, r.inner_hop ? `Works: ${U.router_wan_ip}:${r.port} reaches this Pi` : `${U.router_wan_ip}:${r.port} does not reach this Pi`) : null,
        line(r.external, "From the internet", r.evidence ? r.evidence : r.external === true ? `${r.public_ip}:${r.port} answered the outside probe` : r.external === false ? `${r.public_ip}:${r.port} did not answer the outside probe` :
          "UDP has no handshake an outside prober can see. It counts as proven once a VPN client connects from outside (e.g. phone on mobile data)."),
      ].filter(Boolean);
      const steps = r.steps.length ? el("ol", { class: "net-steps" }, r.steps.map((s) => el("li", { text: s }))) : null;
      const links = [];
      if (isIPv4(r.gateway)) links.push(el("a", { class: "btn btn-sm", href: `http://${r.gateway}/`, target: "_blank", rel: "noopener noreferrer", text: `Open router ${r.gateway} ↗` }));
      if (r.nat === "double" && isIPv4(r.upstream_router)) links.push(el("a", { class: "btn btn-sm", href: `http://${r.upstream_router}/`, target: "_blank", rel: "noopener noreferrer", text: `Open upstream router ${r.upstream_router} ↗` }));
      const upnp = [];
      if (!U.installed) upnp.push(btn("Install UPnP tools", async () => { try { const j = await API.upnpInstall(); watchJob(jp, j.job, "Installing miniupnpc", () => check()); } catch (e) { toast(e.message, "bad"); } }, "btn-ghost"));
      else if (U.available && !r.upnp_mapping) upnp.push(btn(`Open ${P} automatically (UPnP)`, async () => { try { await API.upnpOpen(r.port, r.proto); toast("Router accepted the mapping", "good"); check(); } catch (e) { toast(e.message, "bad"); } }));
      else if (r.upnp_mapping) upnp.push(btn("Remove UPnP mapping", async () => { try { await API.upnpClose(r.port, r.proto); toast("Mapping removed", "good"); check(); } catch (e) { toast(e.message, "bad"); } }, "btn-ghost"));
      result.append(el("div", { class: "card" }, [
        el("div", { class: "net-card-h" }, [icon("plug", 20), el("h3", { text: P }), el("span", { style: "flex:1" }), pill(verdict[0], verdict[1])]),
        el("div", { class: "net-checks" }, checks),
      ]));
      if (steps) result.append(el("div", { class: "card" }, [
        el("h3", { text: "What to do" }), steps,
        kv([["This Pi (LAN)", r.lan_ip], ["Router", r.gateway], ["Public IP", r.public_ip], ["Protocol", r.proto.toUpperCase()], ["Port", r.port]]),
        el("div", { class: "toolbar", style: "margin:14px 0 0" }, [...links, ...upnp, btn("Check again", () => check(), "btn-primary")]),
        U.available && r.nat === "double" ? el("p", { class: "dm-hint", text: "UPnP only opens your own router, the upstream one still needs a manual forward." }) : null,
      ]));
    }
    if (preset.port) check();
  }

  // ---- Network Monitor ----
  function viewNetMon(root) {
    let hours = 24, scope = "internet";
    const ctrl = el("div", { class: "card net-mon-ctrl" });
    const body = el("div", {}, el("div", { class: "loading", text: "Loading…" }));
    root.append(el("p", { class: "muted", style: "margin:0 0 14px", text: "Who tried to reach this Pi: every new inbound connection attempt (also on closed or firewalled ports), plus logins and VPN handshakes, successful and failed." }), ctrl, body);
    const segOf = (opts, cur, set) => el("div", { class: "cw-seg cw-seg-sm" }, opts.map(([v, l]) => el("button", { type: "button", class: v === cur ? "active" : "", text: l,
      onclick: (e) => { set(v); e.target.parentNode.querySelectorAll("button").forEach((b) => b.classList.toggle("active", b === e.target)); load(); } })));
    const tile = (label, value, kind) => el("div", { class: `nm-tile ${kind || ""}` }, [el("div", { class: "nm-tile-v", text: String(value) }), el("div", { class: "nm-tile-l", text: label })]);
    const scopePill = (s) => pill({ internet: "internet", lan: "LAN", private: "private", local: "local" }[s] || s, s === "internet" ? "warn" : "dim");
    const outcomePill = (o) => pill({ ok: "success", fail: "failed", attempt: "attempt" }[o] || o, o === "ok" ? "good" : o === "fail" ? "bad" : "dim");
    // Ban / Trust / Unban for one address, depending on its current status.
    function ipActions(ip, status, scope) {
      if (!ip || scope === "local") return null;
      if (status === "trusted") return el("div", { class: "net-actions" }, [pill("trusted", "good")]);
      if (status === "banned") return el("div", { class: "net-actions" }, [pill("banned", "bad"),
        btn("Unban", async () => { try { await API.guardUnban(ip); toast(`${ip} unbanned`, "good"); load(); } catch (e) { toast(e.message, "bad"); } }, "btn-ghost")]);
      const rep = reported[ip];
      return el("div", { class: "net-actions" }, [
        scope === "internet" ? (rep ? el("button", { type: "button", class: "pill warn pill-btn-rep", title: `Reported to ${(rep.to || []).join(", ")}, click to read or send again`, text: "reported", onclick: (e) => reportIp(ip, null) })
          : btn("Report", (e) => reportIp(ip, e.currentTarget), "btn-ghost")) : null,
        btn("Ban", () => banDialog(ip, load), "btn-danger"), btn("Trust", () => trustDialog(ip, load), "btn-ghost")].filter(Boolean));
    }
    let reported = {};
    // Report to the network's abuse contact, sent by this server's mail from the remembered account.
    async function reportIp(ip, button) {
      let p;
      if (button) { button.disabled = true; button.textContent = "Looking up…"; }
      try { p = await API.abusePreview(ip); }
      catch (e) { toast(e.message, "bad"); if (button) { button.disabled = false; button.textContent = "Report"; } return; }
      if (button) { button.disabled = false; button.textContent = "Report"; }
      if (!p.mail_ready) { toast("Reports go out through this server's mail, set up Email first", "bad"); return; }
      if (!p.info.contacts.length) { toast(`No abuse contact is published for ${ip}`, "bad"); return; }
      const from = el("select", {}, p.accounts.map((a) => el("option", { value: a, text: a })));
      if (p.from) from.value = p.from;
      // Editable abuse contact: the registry sometimes lists the wrong or a personal address;
      // abuse@<domain> is offered, and the WHOIS link lets the user check the real one.
      const sugg = p.info.suggestions && p.info.suggestions.length ? p.info.suggestions : p.info.contacts;
      const toList = el("datalist", { id: "nm-abuse-to" }, sugg.map((a) => el("option", { value: a })));
      const to = el("input", { type: "email", class: "em-select", value: p.info.contacts[0] || "", list: "nm-abuse-to", autocomplete: "off", spellcheck: "false" });
      const whois = p.info.whois_url ? el("p", { class: "muted mx-small", style: "margin:4px 0 0" },
        [el("a", { href: p.info.whois_url, target: "_blank", rel: "noopener noreferrer", text: p.info.whois_label || "Look up the registry record" }), ", check the abuse address if it looks wrong."]) : null;
      openModal(`Report ${ip}`, el("div", { class: "em-form" }, [
        kv([["Network", `${p.info.network || ", "}${p.info.country ? ` (${p.info.country})` : ""}`],
          ["Evidence", p.summary || `${p.events} event${p.events === 1 ? "" : "s"} in the last 7 days`]]),
        p.reported ? el("div", { class: "dm-note" }, [icon("info", 15), el("span", { text: `Reported to ${p.reported.to.join(", ")} on ${new Date(p.reported.ts * 1000).toLocaleString()} from ${p.reported.from}. Sending again repeats the report.` })]) : null,
        p.accounts.length ? el("div", { class: "mx-grid2" }, [field("Send from", from, "Remembered for next time."), field("To (abuse contact)", el("div", { style: "display:contents" }, [to, toList]), "Pre-filled from the registry, edit it if the desk differs.")])
          : el("p", { class: "empty", text: "Create an email account first (Email → Email Accounts)." }),
        el("h4", { class: "em-sub", text: "The message" }), el("pre", { class: "log", style: "max-height:260px", text: p.body }),
        whois,
      ].filter(Boolean)), p.accounts.length ? [el("button", { class: "btn btn-primary", text: p.reported ? "Send again" : "Send report", onclick: async (e) => {
        const dest = to.value.trim();
        if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(dest)) { to.focus(); return toast("Enter the abuse contact's email address", "bad"); }
        e.currentTarget.disabled = true;
        try { const r = await API.abuseReport({ ip, sender: from.value, to: dest, force: !!p.reported }); toast(`Reported ${ip} to ${r.to.join(", ")}`, "good"); reported[ip] = { to: r.to }; closeModal(); load(); }
        catch (err) { toast(err.message, "bad"); e.currentTarget.disabled = false; }
      } })] : []);
    }
    const load = () => guardedLoad(async () => {
      const d = await API.netmon(hours, scope);
      try { reported = await API.abuseReported(); } catch (e) { reported = {}; }
      ctrl.innerHTML = "";
      ctrl.append(...[
        el("div", { class: "net-card-h" }, [icon("radar", 20), el("h3", { text: "Connection logging" }), el("span", { style: "flex:1" }),
          pill(d.logging ? "recording" : "off", d.logging ? "good" : "dim"),
          d.logging ? btn("Turn off", async () => { try { await API.netmonLogging(false); load(); } catch (e) { toast(e.message, "bad"); } }, "btn-ghost")
                    : btn("Turn on", async () => { try { await API.netmonLogging(true); toast("Recording new connection attempts", "good"); load(); } catch (e) { toast(e.message, "bad"); } }, "btn-primary")]),
        !d.logging ? el("p", { class: "dm-hint", text: d.nft ? "Off: only logins and VPN events are shown. Turn on to also record every inbound connection attempt (rate-limited, stored in the system journal)." : "nftables is not installed, install any VPN first to enable connection logging." }) : null,
        el("div", { class: "toolbar", style: "margin:12px 0 0" }, [
          segOf([["internet", "Internet only"], ["all", "Everything"], ["lan", "LAN only"]], scope, (v) => { scope = v; }),
          segOf([[1, "1 h"], [24, "24 h"], [168, "7 days"]], hours, (v) => { hours = v; }),
        ]),
      ].filter(Boolean));
      body.innerHTML = "";
      const top = d.ports[0];
      body.append(el("div", { class: "nm-tiles" }, [
        tile("connection attempts", d.total), tile("unique sources", d.sources.length),
        tile("failed logins", d.failed_logins, d.failed_logins ? "bad" : ""), tile("blocked by bans", d.blocked_total || 0),
        tile(top && top.service ? `most targeted · ${top.service}` : "most targeted", top ? (top.port != null ? `:${top.port}` : top.service || ", ") : ", "),
      ]));
      body.append(el("div", { class: "toolbar" }, [btn("Bans & trusted list", () => navigate("ipblocker"), "btn-ghost"), btn("Fail2ban", () => navigate("leech"), "btn-ghost")]));
      body.append(el("h2", { class: "section-title", text: "Logins & VPN events" }));
      body.append(d.events.length ? simpleTable(["When", "Via", "Result", "User", "From", ""],
        d.events.slice(0, 150).map((e) => {
          const tr = row(when(e.ts), e.source, outcomePill(e.outcome), e.user || ", ", el("span", {}, [el("span", { class: `net-mono ${ipCls(e.status, reported[e.ip])}`, text: e.ip || ", " }), " ", e.scope ? scopePill(e.scope) : null]),
            ipActions(e.ip, e.status, e.scope));
          tr.title = e.detail || "";
          return tr;
        })) : el("p", { class: "empty", text: "No login or VPN events in this period." }));
      body.append(el("h2", { class: "section-title", text: "Sources" }));
      body.append(d.sources.length ? simpleTable(["IP address", "Where", "Attempts", "Ports tried", "First seen", "Last seen", ""],
        d.sources.map((s) => row(el("code", { class: `net-mono ${ipCls(s.status, reported[s.ip])}`, text: s.ip }), scopePill(s.scope),
          s.blocked ? `${s.count} (${s.blocked} blocked)` : s.count,
          el("div", { class: "net-chips" }, s.ports.map((p) => el("span", { class: "net-chip", text: `${p.key}${p.count > 1 ? " ×" + p.count : ""}` }))),
          ago(s.first), ago(s.last), ipActions(s.ip, s.status, s.scope))))
        : el("p", { class: "empty", text: d.logging ? "No connection attempts recorded in this period." : "Connection logging is off." }));
      if (d.ports.length) {
        body.append(el("h2", { class: "section-title", text: "Targeted ports" }));
        body.append(simpleTable(["Port", "Service", "Attempts", "Sources"], d.ports.map((p) => row(`${p.port ?? ", "}/${p.proto}`, p.service || ", ", p.count, p.sources))));
      }
      if (d.recent.length) {
        body.append(el("h2", { class: "section-title", text: "Latest attempts" }));
        body.append(simpleTable(["When", "From", "To port", "Service", "Result"],
          d.recent.slice(0, 100).map((c) => row(when(c.ts), c.src, `${c.port ?? ", "}/${c.proto}`, c.service || ", ",
            c.blocked ? pill("blocked (banned)", "bad") : pill("reached the Pi", "dim")))));
      }
    });
    state.refreshHandler = load; load();
    const t = setInterval(load, 20000);
    state.cleanups.push(() => clearInterval(t));
  }

  // ======================================================================
  //  Zone Editor, structured DNS records
  // ======================================================================
  const REC_TYPES = ["A", "AAAA", "CNAME", "MX", "TXT", "NS", "SRV", "CAA"];
  const REC_HELP = {
    A: "Points a name at an IPv4 address.", AAAA: "Points a name at an IPv6 address.",
    CNAME: "Makes a name an alias of another hostname.", MX: "Where email for the domain is delivered.",
    TXT: "Free text, SPF, DKIM, DMARC, site verification…", NS: "Delegates a name to nameservers.",
    SRV: "Service location (e.g. _sip._tcp).", CAA: "Which CAs may issue certificates.",
  };
  const TTL_OPTS = [[300, "5 min"], [3600, "1 hour"], [14400, "4 hours"], [86400, "1 day"]];
  const dot = (s) => String(s || "").replace(/\.$/, "");

  function recordSummary(r) {
    const t = r.type;
    if (t === "A" || t === "AAAA") return esc(r.address);
    if (t === "CNAME" || t === "NS") return esc(dot(r.target));
    if (t === "MX") return `<b>Priority:</b> ${r.priority}<br><b>Destination:</b> ${esc(dot(r.target))}`;
    if (t === "SRV") return `<b>Priority:</b> ${r.priority} &nbsp;<b>Weight:</b> ${r.weight} &nbsp;<b>Port:</b> ${r.port}<br><b>Target:</b> ${esc(dot(r.target))}`;
    if (t === "TXT") return `<span class="zn-txt">${esc(r.text)}</span>`;
    if (t === "CAA") return `${r.flags} <b>${esc(r.tag)}</b> “${esc(r.value)}”`;
    return esc(r.raw || "");
  }

  // Record form: returns { node, read() }
  function recordForm(domain, rec, lockType) {
    const r = { type: "A", name: "", ttl: 14400, ...rec };
    const node = el("div", { class: "zn-form" });
    const typeSel = el("select", { class: "zn-type" }, REC_TYPES.map((t) => el("option", { value: t, text: t })));
    typeSel.value = r.type; if (lockType) typeSel.disabled = true;
    const nameIn = el("input", { type: "text", value: r.name ? dot(r.name) : "", placeholder: `sub  or  ${domain}` });
    const ttlIn = el("input", { type: "number", min: 60, max: 604800, value: r.ttl });
    const ttlQuick = el("select", { class: "zn-ttlq", onchange: (e) => { if (e.target.value) ttlIn.value = e.target.value; e.target.value = ""; } },
      [el("option", { value: "", text: "⏱" }), ...TTL_OPTS.map(([v, l]) => el("option", { value: v, text: l }))]);
    const fields = el("div", { class: "zn-fields" });
    const help = el("div", { class: "dm-hint" });
    const inp = (key, ph, type = "text", val) => el("input", { type, "data-k": key, placeholder: ph, value: val != null ? val : (r[key] != null ? (key === "target" ? dot(r[key]) : r[key]) : "") });
    const lab = (l, i, cls) => el("label", { class: `cw-lbl ${cls || ""}` }, [l, i]);
    function draw() {
      const t = typeSel.value;
      fields.innerHTML = ""; help.textContent = REC_HELP[t] || "";
      if (t === "A") fields.append(lab("IPv4 address", inp("address", "203.0.113.10")));
      if (t === "AAAA") fields.append(lab("IPv6 address", inp("address", "2001:db8::1")));
      if (t === "CNAME") fields.append(lab("Points to (hostname)", inp("target", domain)));
      if (t === "NS") fields.append(lab("Nameserver", inp("target", "ns1.example.net")));
      if (t === "MX") fields.append(lab("Priority", inp("priority", "10", "number", r.priority != null ? r.priority : 10), "zn-narrow"), lab("Mail server", inp("target", "mail." + domain)));
      if (t === "SRV") fields.append(lab("Priority", inp("priority", "0", "number", r.priority != null ? r.priority : 0), "zn-narrow"), lab("Weight", inp("weight", "0", "number", r.weight != null ? r.weight : 0), "zn-narrow"), lab("Port", inp("port", "443", "number"), "zn-narrow"), lab("Target", inp("target", domain)));
      if (t === "TXT") {
        const ta = el("textarea", { "data-k": "text", rows: 2, class: "cw-mono", placeholder: "v=spf1 a mx ~all" }); ta.value = r.text || "";
        const presets = el("div", { class: "zn-presets" }, [["SPF", `v=spf1 a mx ~all`], ["DMARC", "v=DMARC1; p=none; rua=mailto:postmaster@" + domain], ["Google verify", "google-site-verification="]].map(([l, v]) =>
          el("button", { type: "button", class: "cw-chip", text: l, onclick: () => { ta.value = v; if (l === "DMARC" && !nameIn.value) nameIn.value = "_dmarc"; } })));
        fields.append(lab("Text value", ta, "zn-wide"), presets);
      }
      if (t === "CAA") {
        const tag = el("select", { "data-k": "tag" }, ["issue", "issuewild", "iodef"].map((x) => el("option", { value: x, text: x }))); tag.value = r.tag || "issue";
        fields.append(lab("Flags", inp("flags", "0", "number", r.flags != null ? r.flags : 0), "zn-narrow"), lab("Tag", tag, "zn-narrow"), lab("Value", inp("value", "letsencrypt.org")));
      }
    }
    typeSel.addEventListener("change", draw);
    draw();
    node.append(el("div", { class: "zn-row1" }, [lab("Name", nameIn, "zn-name"), lab("TTL (seconds)", el("span", { class: "zn-ttl" }, [ttlIn, ttlQuick]), "zn-ttlw"), lab("Type", typeSel, "zn-narrow")]), fields, help);
    return {
      node,
      read() {
        const out = { type: typeSel.value, name: nameIn.value.trim() || "@", ttl: +ttlIn.value || 14400 };
        fields.querySelectorAll("[data-k]").forEach((i) => { out[i.dataset.k] = i.type === "number" ? +i.value : i.value.trim(); });
        return out;
      },
      focus() { (nameIn.value ? fields.querySelector("[data-k]") : nameIn)?.focus(); },
    };
  }

  function quickAddRecord(domain, type, done) {
    const f = recordForm(domain, { type }, false);
    const go = el("button", { class: "btn btn-primary", text: `Add ${type} record`, onclick: async () => {
      go.disabled = true;
      try { await API.dnsRecordAdd(domain, f.read()); closeModal(); toast(`${type} record added to ${domain}`, "good"); done && done(); }
      catch (e) { toast(e.message, "bad"); go.disabled = false; }
    } });
    openModal(`Add a record · ${domain}`, f.node, [go]);
    setTimeout(() => f.focus(), 40);
  }

  function createZoneModal(domain, done) {
    const body = el("div", { class: "dm-form" });
    body.innerHTML = `
      <label class="cw-lbl">Domain<input id="zc-d" type="text" placeholder="example.com" /></label>
      <div class="cw-lbl">Start from</div>
      <label class="dm-check"><input type="radio" name="zc-m" value="default" checked /> <span><b>Point at this Pi</b>, NS, A, www, mail, MX and SPF records like a fresh cPanel zone</span></label>
      <label class="dm-check"><input type="radio" name="zc-m" value="import" /> <span><b>Import current public DNS</b>, copies what the internet sees today (A, AAAA, CNAME, MX, TXT, NS, CAA)</span></label>
      <label class="cw-lbl" id="zc-ipw">IP address for the records<input id="zc-ip" type="text" placeholder="this Pi's LAN IP" /></label>
      <p class="dm-hint">Use your <b>public IP</b> if the domain should be reachable from the internet, or the LAN IP for a home-only domain.</p>`;
    const dIn = $("#zc-d", body); dIn.value = domain || "";
    body.querySelectorAll("[name=zc-m]").forEach((r) => r.addEventListener("change", () => { $("#zc-ipw", body).hidden = body.querySelector("[name=zc-m]:checked").value === "import"; }));
    API.domainInfo(domain || "example.com").then((i) => { $("#zc-ip", body).placeholder = `LAN ${i.local_ip}${i.public_ip ? "  ·  public " + i.public_ip : ""}`; }).catch(() => {});
    const go = el("button", { class: "btn btn-primary", text: "Create zone", onclick: async () => {
      go.disabled = true;
      try { const d = dIn.value.trim().toLowerCase(); await API.dnsZoneCreate(d, $("#zc-ip", body).value.trim(), body.querySelector("[name=zc-m]:checked").value); closeModal(); toast(`Zone created for ${d}`, "good"); done ? done(d) : openZone(d); }
      catch (e) { toast(e.message, "bad"); go.disabled = false; }
    } });
    openModal("Create a DNS zone", body, [go]);
  }

  function zoneBanner(bind) {
    if (bind) return el("div", { class: "dm-note good" }, [icon("shield", 15), el("span", { text: "BIND9 is running on this Pi, saved zones are served immediately." })]);
    return el("div", { class: "dm-note" }, [icon("error", 15), el("span", { html: "BIND9 isn't installed, so this Pi isn't answering DNS yet. Zones are still validated and saved, <b>Export</b> them to your registrar's DNS panel, or install BIND9 to serve them yourself." }),
      el("button", { class: "btn btn-sm", onclick: async (e) => {
        if (!confirmInline("Install BIND9 (apt-get install bind9)?")) return;
        e.target.disabled = true;
        try { const r = await API.bindInstall(); toast("Installing BIND9…", "good"); const t = setInterval(async () => { const j = await API.job(r.job); if (j.status !== "running") { clearInterval(t); toast(`BIND9: ${j.status}`, j.status === "done" ? "good" : "bad"); navigate("zones"); } }, 2000); }
        catch (err) { toast(err.message, "bad"); e.target.disabled = false; }
      } }, "Install BIND9")]);
  }

  function viewZoneEditor(root) {
    if (zoneState.manage) { const d = zoneState.manage; zoneState.manage = null; return viewZoneManage(root, d); }
    const search = el("input", { type: "search", placeholder: "Filter by domain…", class: "dm-search" });
    const body = el("div", {}, el("div", { class: "loading", text: "Loading…" }));
    const bannerBox = el("div");
    root.append(el("p", { class: "muted dm-intro", text: "DNS turns domain names into IP addresses. Create a zone per domain and manage its records here, every change is checked with named-checkzone before it's saved." }),
      bannerBox, el("div", { class: "dm-bar" }, [search, el("span", { class: "grow" }), el("button", { class: "btn btn-primary", onclick: () => createZoneModal("", null) }, [icon("zone", 15), " Create a zone"])]), body);
    let data;
    function render() {
      body.innerHTML = "";
      const q = search.value.trim().toLowerCase();
      const rows = [
        ...data.zones.map((z) => ({ domain: z.domain, zone: z })),
        ...data.without_zone.map((d) => ({ domain: d, zone: null })),
      ].filter((x) => !q || x.domain.includes(q)).sort((a, b) => a.domain.localeCompare(b.domain));
      body.append(el("div", { class: "dm-count muted", text: `Displaying ${rows.length} domain${rows.length === 1 ? "" : "s"}` }));
      if (!rows.length) { body.append(el("div", { class: "cw-empty" }, [icon("zone", 28), el("b", { text: "No zones yet" }), el("span", { class: "muted", text: "Create a zone for a domain you own, or add a site in Domains first." })])); return; }
      body.append(el("div", { class: "table-wrap" }, el("table", { class: "dm-table" }, [
        el("thead", {}, el("tr", {}, ["Domain", "Zone", "Actions"].map((h) => el("th", { text: h })))),
        el("tbody", {}, rows.map((x) => el("tr", {}, [
          el("td", {}, x.zone ? el("a", { class: "zn-dom", href: "#", onclick: (e) => { e.preventDefault(); openZone(x.domain); }, text: x.domain }) : el("span", { text: x.domain })),
          el("td", {}, x.zone ? el("span", { class: "pill good", text: `${x.zone.records} records` }) : el("span", { class: "pill dim", text: "no zone" })),
          el("td", { class: "actions" }, x.zone ? [
            ...["A", "CNAME", "MX"].map((t) => el("button", { class: "btn btn-sm", onclick: () => quickAddRecord(x.domain, t, load) }, ["+ ", t, " Record"])),
            el("button", { class: "btn btn-sm btn-ghost", onclick: () => openZone(x.domain) }, [icon("services", 13), " Manage"]),
          ] : [el("button", { class: "btn btn-sm btn-primary", onclick: () => createZoneModal(x.domain, () => load()) }, [icon("zone", 13), " Create zone"])]),
        ]))),
      ])));
    }
    const secBox = el("div");
    root.append(secBox);
    const load = async () => { await guardedLoad(async () => { data = await API.dnsZones(); bannerBox.innerHTML = ""; bannerBox.append(zoneBanner(data.bind_installed)); render(); if (data.bind_installed) secondaryCard(secBox); }); };
    search.addEventListener("input", render);
    state.refreshHandler = load; load();
  }

  // Secondary DNS: who may copy our zones (zone transfers). Detected from the zones' NS
  // records; a provider's fetching address that isn't a nameserver shows up as "refused".
  async function secondaryCard(box) {
    let d;
    try { d = await API.dnsSecondaries(); } catch (e) { return; }
    box.innerHTML = "";
    const extra = el("input", { type: "text", value: d.extra.join(", "), placeholder: "e.g. 195.88.209.83" });
    const autoSw = sw(d.auto, () => {});
    const save = async (ex) => {
      try {
        await API.dnsSecondariesSet(autoSw.querySelector("input").checked, (ex || extra.value).split(/[\s,;]+/).filter(Boolean));
        toast("Secondary DNS saved", "good"); secondaryCard(box);
      } catch (e) { toast(e.message, "bad"); }
    };
    const det = Object.entries(d.detected);
    box.append(el("div", { class: "card", style: "margin-top:16px" }, [
      el("h3", { text: "Secondary DNS (zone transfers)" }),
      el("p", { class: "muted", style: "margin:0 0 12px", text: "Servers allowed to copy your zones, e.g. your hosting provider's DNS when this server is the master. They're told at once whenever a zone changes. Everyone else is refused, and this server only answers lookups for itself, its local network and VPN clients." }),
      el("div", { class: "em-toggle" }, [autoSw, el("div", {}, [el("b", { text: "Detect automatically from NS records (recommended)" }),
        el("span", { class: "muted", text: det.length ? det.map(([h, ips]) => `${h} (${ips.join(", ")})`).join(" · ") : "No other nameservers in your zones yet." })])]),
      field("Also allow these IP addresses", extra, "Comma separated. For providers that fetch from an address that isn't one of their nameservers."),
      ...d.refused.map((r) => el("div", { class: "dm-note" }, [icon("info", 15), el("span", { text: `${r.ip} tried to copy ${r.zones.join(", ")} and was refused.` }),
        btn("Allow it", () => save([...d.extra, r.ip].join(",")), "btn-primary")])),
      el("div", { class: "toolbar", style: "margin:12px 0 0" }, [btn("Save", () => save(), "btn-primary"),
        el("span", { class: "muted", text: d.allowed.length ? `Allowed now: ${d.allowed.join(", ")}` : "Nobody may copy zones right now." })]),
    ]));
  }

  function viewZoneManage(root, domain) {
    const filt = { q: "", type: "All" };
    let z = null, editing = null; // editing: index | "new"
    const load = async () => {
      try { z = await API.dnsZone(domain); }
      catch (e) {
        root.innerHTML = "";
        root.append(el("div", { class: "cw-empty" }, [icon("zone", 28), el("b", { text: e.message }),
          el("div", { style: "display:flex;gap:8px" }, [el("button", { class: "btn btn-sm btn-primary", text: `Create zone for ${domain}`, onclick: () => createZoneModal(domain, () => load()) }),
            el("button", { class: "btn btn-sm", text: "← Zone Editor", onclick: () => navigate("zones") })])]));
        return;
      }
      render();
    };
    state.refreshHandler = load;
    const done = (msg) => { toast(msg, "good"); editing = null; load(); };

    function render() {
      root.innerHTML = "";
      const nsMatch = z.ns_live.length && z.ns_zone.length && z.ns_live.join() === z.ns_zone.join();
      root.append(el("div", { class: "dmm-head" }, [
        el("button", { class: "btn btn-sm btn-ghost", onclick: () => navigate("zones") }, [el("span", { html: "&larr;" }), " Zone Editor"]),
        el("h2", {}, ["Zone records for ", el("span", { class: "accent", text: `“${domain}”` })]),
        el("span", { class: "grow" }),
        el("button", { class: "btn btn-sm", onclick: () => openDomain(domain) }, [icon("globe", 13), " Domain settings"]),
      ]));
      root.append(zoneBanner(z.bind_installed));
      root.append(el("div", { class: "zn-ns" }, [
        el("span", { class: "muted", text: "Nameservers in this zone:" }), ...(z.ns_zone.length ? z.ns_zone.map((n) => el("span", { class: "zn-nschip", text: n })) : [el("span", { class: "muted", text: "none" })]),
        el("span", { class: "zn-sep" }),
        el("span", { class: "muted", text: "Live (registrar):" }), ...(z.ns_live.length ? z.ns_live.map((n) => el("span", { class: `zn-nschip ${nsMatch ? "ok" : "live"}`, text: n })) : [el("span", { class: "muted", text: "not resolving" })]),
        !nsMatch && z.ns_live.length ? el("span", { class: "dm-hint", text: "Live DNS is served elsewhere, copy records there, or point the registrar at your nameservers." }) : null,
      ]));

      const typeChips = el("div", { class: "zn-typef" }, ["All", ...REC_TYPES].map((t) => {
        const n = t === "All" ? z.records.length : z.records.filter((r) => r.type === t).length;
        if (t !== "All" && !n) return null;
        return el("button", { type: "button", class: `zn-tf ${filt.type === t ? "on" : ""}`, onclick: () => { filt.type = t; render(); } }, [t, el("small", { text: n })]);
      }));
      const q = el("input", { type: "search", class: "dm-search", placeholder: "Filter by name…", value: filt.q, oninput: (e) => { filt.q = e.target.value; drawTable(); } });
      const addSel = el("select", { class: "zn-addsel", onchange: (e) => { if (e.target.value) { editing = "new:" + e.target.value; drawTable(); } e.target.value = ""; } },
        [el("option", { value: "", text: "+ Add Record" }), ...REC_TYPES.map((t) => el("option", { value: t, text: `${t}, ${REC_HELP[t].split(", ")[0].replace(/\.$/, "")}` }))]);
      root.append(el("div", { class: "dm-bar" }, [q, typeChips, el("span", { class: "grow" }), addSel,
        el("button", { class: "btn btn-sm", onclick: exportZone }, [icon("mime", 13), " Export"]),
        el("button", { class: "btn btn-sm btn-danger", title: "Delete zone", onclick: async () => {
          if (!confirmInline(`Delete the whole DNS zone for ${domain}? (a backup copy of the file is kept)`)) return;
          try { await API.dnsZoneDelete(domain); toast("Zone deleted", "good"); navigate("zones"); } catch (e) { toast(e.message, "bad"); }
        } }, icon("error", 13))]));
      const tableBox = el("div");
      root.append(tableBox);
      root.append(el("p", { class: "dm-hint zn-foot", text: `SOA serial ${z.soa.serial} · refresh ${z.soa.refresh}s · default TTL ${z.ttl}s, the serial is bumped automatically on every save.` }));

      function drawTable() {
        tableBox.innerHTML = "";
        const rows = [];
        if (editing && String(editing).startsWith("new:")) rows.push(editRow(null, { type: editing.slice(4), ttl: 14400 }));
        z.records.forEach((r, i) => {
          if (filt.type !== "All" && r.type !== filt.type) return;
          if (filt.q && !r.name.includes(filt.q.toLowerCase())) return;
          rows.push(editing === i ? editRow(i, r) : el("tr", {}, [
            el("td", { class: "zn-name", text: r.name }),
            el("td", { class: "muted", text: r.ttl }),
            el("td", {}, el("span", { class: `zn-badge t-${r.type}`, text: r.type })),
            el("td", { class: "zn-rec", html: recordSummary(r) }),
            el("td", { class: "actions" }, [
              el("button", { class: "btn btn-sm", onclick: () => { editing = i; drawTable(); } }, [icon("indexes", 12), " Edit"]),
              el("button", { class: "btn btn-sm btn-danger", onclick: async () => {
                if (!confirmInline(`Delete ${r.type} record ${r.name}?`)) return;
                try { await API.dnsRecordDelete(domain, i, { name: r.name, type: r.type }); done("Record deleted"); } catch (e) { toast(e.message, "bad"); }
              } }, [icon("error", 12), " Delete"]),
            ]),
          ]));
        });
        if (!rows.length) { tableBox.append(el("p", { class: "empty", text: "No records match." })); return; }
        tableBox.append(el("div", { class: "table-wrap" }, el("table", { class: "dm-table zn-table" }, [
          el("thead", {}, el("tr", {}, ["Name", "TTL", "Type", "Record", "Actions"].map((h) => el("th", { text: h })))),
          el("tbody", {}, rows),
        ])));
        const f = tableBox.querySelector(".zn-editrow input, .zn-editrow textarea");
        if (f) f.focus();
      }
      function editRow(index, r) {
        const f = recordForm(domain, r, index != null);
        const save = el("button", { class: "btn btn-sm btn-primary", onclick: async () => {
          save.disabled = true;
          try {
            if (index == null) await API.dnsRecordAdd(domain, f.read());
            else await API.dnsRecordUpdate(domain, index, f.read(), { name: r.name, type: r.type });
            done(index == null ? "Record added" : "Record saved");
          } catch (e) { toast(e.message, "bad"); save.disabled = false; }
        } }, index == null ? "Add record" : "Save record");
        const cancel = el("button", { class: "btn btn-sm btn-ghost", text: "Cancel", onclick: () => { editing = null; drawTable(); } });
        f.node.addEventListener("keydown", (e) => { if (e.key === "Enter" && e.target.tagName === "INPUT") save.click(); if (e.key === "Escape") cancel.click(); });
        return el("tr", { class: "zn-editrow" }, el("td", { colspan: 5 }, [f.node, el("div", { class: "zn-editact" }, [cancel, save])]));
      }
      drawTable();
    }
    function exportZone() {
      const pre = el("pre", { class: "log", text: z.zone_text });
      const copy = el("button", { class: "btn btn-primary", text: "Copy", onclick: async () => { try { await navigator.clipboard.writeText(z.zone_text); toast("Zone file copied", "good"); } catch (e) { toast("Select the text and copy it manually", "bad"); } } });
      openModal(`db.${domain}`, el("div", {}, [el("p", { class: "dm-hint", text: "Standard BIND zone file, most registrars and DNS hosts (Cloudflare, Namecheap…) can import it." }), pre]), [copy]);
    }
    load();
  }

  // ---- MySQL / MariaDB (Manage Databases) ----
  function viewMySQL(root) {
    subTabs(root, [["mysql", "MariaDB / MySQL"], ["pgsql", "PostgreSQL"]], (tab, pane) => tab === "pgsql" ? pgManager(pane) : mysqlManager(pane));
  }

  // Shared bits of the MariaDB and PostgreSQL pages.
  const dbChk = (label, checked, hint) => {
    const c = el("input", { type: "checkbox" }); c.checked = !!checked;
    return { input: c, node: el("label", { class: "dm-check" }, [c, el("span", {}, [label, hint ? el("span", { class: "muted", text: `, ${hint}` }) : null].filter(Boolean))]) };
  };
  const dbPwField = () => {
    const inp = el("input", { type: "text", class: "pw-secret", placeholder: "password (6+ characters)", autocomplete: "new-password", spellcheck: "false", style: "min-width:0;flex:1" });
    return { input: inp, node: el("div", { class: "toolbar", style: "margin:0;flex-wrap:nowrap" }, [inp,
      btn("Generate", () => { inp.value = genPassword(18); }, "btn-ghost"),
      btn("Copy", async () => { if (!inp.value) return toast("Nothing to copy yet", "bad"); toast(await copyText(inp.value) ? "Password copied" : "Copy failed", "good"); }, "btn-ghost")]) };
  };
  const MY_HOSTS = [["localhost", "This Pi only (localhost)"], ["%", "Any computer (%)"]];
  const myHostLabel = (h) => h === "localhost" ? "this Pi only" : h === "%" ? "any computer" : h;
  const myHostSelect = () => el("select", {}, MY_HOSTS.map(([v, t]) => el("option", { value: v, text: t })));
  const MY_HOST_HINT = "Apps on this Pi use localhost. “Any computer” also needs MariaDB to listen on the network (System Applications → MariaDB → configure).";

  // ---- Manage Databases → MariaDB / MySQL ----
  function mysqlManager(root) {
    const body = el("div", {}, el("div", { class: "loading", text: "Loading…" }));
    root.append(body);
    const jp = jobPanel(root);
    state.cleanups.push(jp.stop);
    // Every action reloads afterwards, also on failure, so a server that went away shows the install/start card.
    const call = async (fn, okMsg) => {
      try { const r = await fn(); if (okMsg) toast(okMsg, "good"); load(); return r || true; }
      catch (e) { toast(e.message, "bad"); load(); return null; }
    };
    const manageable = (u) => !u.system && !u.app;

    function phpMyAdminCard(p) {
      let status, actions;
      if (!p.installed) {
        status = pill("not installed", "dim");
        actions = [btn("Install phpMyAdmin", async () => {
          const r = await call(() => API.phpmyadminInstall());
          if (r && r.job) watchJob(jp, r.job, "Installing phpMyAdmin…", load);
        }, "btn-primary")];
      } else if (!p.apache) {
        status = pill("Apache stopped", "warn");
        actions = [btn("Open System Applications", () => navigate("sysapps"), "btn-primary")];
      } else {
        status = pill("ready", "good");
        actions = [el("a", { class: "btn btn-sm btn-primary", href: `http://${location.hostname}${p.path}`, target: "_blank", rel: "noopener noreferrer", text: "Open phpMyAdmin ↗" })];
      }
      return el("div", { class: "card", style: "margin-bottom:16px" }, [
        el("div", { class: "net-card-h" }, [icon("database", 20), el("h3", { text: "phpMyAdmin" }), el("span", { style: "flex:1" }), status]),
        el("p", { class: "muted", style: "margin:6px 0 10px", text: p.installed
          ? "Web tool for browsing tables and running SQL. Log in with a user below that has a password, root has none (it only works from the Pi's own terminal). Tick “Admin” on a user for full access to every database."
          : "Optional web tool for browsing tables and running SQL. Needs Apache; it's added at /phpmyadmin." }),
        p.installed && !p.apache ? el("p", { class: "dm-hint", text: "Apache isn't running, start it in System Applications to use phpMyAdmin." }) : null,
        el("div", { class: "toolbar", style: "margin:0" }, actions),
      ]);
    }

    function createCards(d) {
      const dbName = el("input", { type: "text", placeholder: "myapp", style: "min-width:0" });
      const dbCard = el("div", { class: "db-form" }, [
        el("h3", { text: "Create database" }),
        field("Name", dbName, "Letters, digits and underscore. Created with utf8mb4 (full Unicode, emoji included)."),
        btn("Create database", async () => {
          const name = dbName.value.trim(); if (!name) return toast("Enter a database name", "bad");
          if (await call(() => API.mysqlCreate(name), `Database ${name} created`)) dbName.value = "";
        }, "btn-primary"),
      ]);
      const uName = el("input", { type: "text", placeholder: "myapp_user", autocomplete: "off", style: "min-width:0" });
      const uHost = myHostSelect();
      const uPw = dbPwField();
      const uDb = el("select", {}, [el("option", { value: "", text: ", none, " }),
        ...d.databases.filter((x) => !x.system && !x.app).map((x) => el("option", { value: x.name, text: x.name }))]);
      const uAdmin = dbChk("Admin", false, "every privilege on every database; use for phpMyAdmin");
      const userCard = el("div", { class: "db-form" }, [
        el("h3", { text: "Create user" }),
        field("Username", uName),
        field("Allow connections from", uHost, MY_HOST_HINT),
        field("Password", uPw.node, "Save it somewhere, it can be changed later but not shown again."),
        field("Give full access to", uDb, "Optional, you can grant access to more databases later."),
        el("div", { style: "margin:4px 0 12px" }, uAdmin.node),
        btn("Create user", async () => {
          const user = uName.value.trim(); if (!user) return toast("Enter a username", "bad");
          if (await call(() => API.mysqlUserCreate({ user, host: uHost.value, password: uPw.input.value, db: uDb.value, admin: uAdmin.input.checked }),
            `User ${user} created${uDb.value ? ` with access to ${uDb.value}` : ""}`)) { uName.value = ""; uPw.input.value = ""; }
        }, "btn-primary"),
      ]);
      return el("div", { class: "card db-create" }, [dbCard, userCard]);
    }

    function manageDb(db, d) {
      const users = d.users.filter(manageable);
      const list = el("div", { style: "display:flex;flex-direction:column;gap:6px" }, users.length ? users.map((u) => {
        const c = dbChk(`${u.user}@${u.host}`, db.access.includes(u.account) || u.admin, u.admin ? "admin, always has access" : "");
        if (u.admin) c.input.disabled = true;
        c.input.onchange = async () => {
          c.input.disabled = true;
          try { await API.mysqlGrant(db.name, u.user, u.host, c.input.checked); toast(`${u.user}: access ${c.input.checked ? "granted" : "removed"}`, "good"); }
          catch (e) { c.input.checked = !c.input.checked; toast(e.message, "bad"); }
          c.input.disabled = false; load();
        };
        return c.node;
      }) : [el("p", { class: "muted", text: "No users yet, create one first." })]);
      openModal(`Database ${db.name}`, el("div", { style: "display:flex;flex-direction:column;gap:14px;min-width:min(520px,80vw)" }, [
        kv([["Size", db.size], ["Tables", String(db.tables)], ["Character set", db.charset]]),
        el("div", {}, [el("h4", { text: "Users with full access", style: "margin:0 0 6px" }), list,
          el("p", { class: "dm-hint", text: "Full access = every privilege on this database: read, write, and create or change tables." })]),
        el("div", {}, [el("h4", { text: "Connect from an app", style: "margin:0 0 6px" }),
          el("pre", { class: "log", style: "margin:0;white-space:pre-wrap", text:
            `mysql://<user>:<password>@localhost:3306/${db.name}\n\nmysql -u <user> -p ${db.name}` })]),
      ]), []);
    }

    function editUser(u, d) {
      const admin = dbChk("Admin", u.admin, "every privilege on every database");
      const dbs = d.databases.filter((x) => !x.system && !x.app).map((x) => ({ name: x.name, c: dbChk(x.name, u.databases.includes(x.name)) }));
      const syncDisabled = () => dbs.forEach(({ c }) => { c.input.disabled = admin.input.checked; });
      admin.input.onchange = syncDisabled; syncDisabled();
      openModal(`User ${u.user}@${u.host}`, el("div", { style: "display:flex;flex-direction:column;gap:10px;min-width:min(440px,80vw)" }, [
        kv([["Connects from", myHostLabel(u.host)], ["Password", u.has_password ? "set" : "none"]]),
        admin.node,
        el("h4", { text: "Full access to", style: "margin:6px 0 0" }),
        dbs.length ? el("div", { style: "display:flex;flex-direction:column;gap:6px" }, dbs.map((x) => x.c.node)) : el("p", { class: "muted", text: "No databases yet." }),
        el("p", { class: "dm-hint", text: "An admin already has access to everything, so the list is locked while Admin is ticked." }),
      ]), [btn("Save", async () => {
        try {
          if (admin.input.checked !== u.admin) await API.mysqlUserAdmin(u.user, u.host, admin.input.checked);
          for (const x of dbs) {
            const want = x.c.input.checked, had = u.databases.includes(x.name);
            if (!admin.input.checked && want !== had) await API.mysqlGrant(x.name, u.user, u.host, want);
          }
          toast(`${u.user} updated`, "good"); closeModal();
        } catch (e) { toast(e.message, "bad"); }
        load();
      }, "btn-primary")]);
    }

    function setPassword(u) {
      const pw = dbPwField();
      openModal(`Password for ${u.user}@${u.host}`, el("div", { style: "min-width:min(420px,80vw)" }, [field("New password", pw.node, "Apps using the old password will need the new one.")]),
        [btn("Set password", async () => {
          if (await call(() => API.mysqlUserPassword(u.user, u.host, pw.input.value), `Password changed for ${u.user}`)) closeModal();
        }, "btn-primary")]);
    }

    function render(d) {
      body.innerHTML = "";
      body.append(phpMyAdminCard(d.phpmyadmin), createCards(d));
      const tag = (x) => x.system ? el("span", { class: "pill dim", style: "margin-left:6px", text: "system" })
        : x.app ? el("span", { class: "pill dim", style: "margin-left:6px", text: x.app }) : null;
      const dbRows = d.databases.map((db) => el("tr", {}, [
        el("td", {}, [el("b", { text: db.name }), tag(db)].filter(Boolean)),
        el("td", { class: "muted", text: db.size }), el("td", { class: "muted", text: String(db.tables) }),
        el("td", {}, db.access.length ? db.access.map((a) => el("span", { class: "pill", style: "margin:0 4px 2px 0", text: a })) : el("span", { class: "muted", text: db.system || db.app ? "" : "admins only" })),
        el("td", { class: "actions" }, db.system || db.app ? "" : [
          btn("Manage", () => manageDb(db, d)),
          el("button", { class: "btn btn-sm btn-danger", text: "Drop", onclick: () => {
            if (!confirmInline(`Drop database "${db.name}"? All its data is deleted. This can't be undone.`)) return;
            call(() => API.mysqlDrop(db.name), `Dropped ${db.name}`); } })]),
      ]));
      body.append(el("div", { class: "card", style: "margin-bottom:16px" }, [el("h3", { text: "Databases" }),
        simpleTable(["Database", "Size", "Tables", "Users with access", ""], dbRows)]));
      const userRows = d.users.map((u) => el("tr", {}, [
        el("td", {}, [el("b", { text: u.user }), u.system ? el("span", { class: "pill dim", style: "margin-left:6px", text: "built-in" }) : u.app ? el("span", { class: "pill dim", style: "margin-left:6px", text: u.app }) : null].filter(Boolean)),
        el("td", { class: "muted", text: myHostLabel(u.host) }),
        el("td", {}, u.admin ? pill("admin", "warn") : u.databases.length ? u.databases.map((x) => el("span", { class: "pill", style: "margin:0 4px 2px 0", text: x })) : el("span", { class: "muted", text: "no databases" })),
        el("td", {}, u.has_password ? pill("set", "good") : el("span", { class: "muted", text: u.system ? "none (local only)" : "none" })),
        el("td", { class: "actions" }, manageable(u) ? [
          btn("Password", () => setPassword(u)), btn("Edit", () => editUser(u, d)),
          el("button", { class: "btn btn-sm btn-danger", text: "Delete", onclick: () => {
            if (!confirmInline(`Delete user "${u.user}@${u.host}"? Apps logging in with it will stop working. Databases are kept.`)) return;
            call(() => API.mysqlUserDrop(u.user, u.host), `Deleted ${u.user}`); } })] : ""),
      ]));
      body.append(el("div", { class: "card" }, [el("h3", { text: "Users" }),
        el("p", { class: "muted", style: "margin:0 0 10px", text: "Apps and phpMyAdmin log in with a user that has a password. Built-in accounts are managed by the system and can't be changed here." }),
        simpleTable(["User", "Connects from", "Access", "Password", ""], userRows)]));
    }

    const load = async () => {
      await guardedLoad(async () => {
        let d;
        try { d = await API.mysql(); }
        catch (e) { body.innerHTML = ""; body.append(el("p", { class: "empty", text: e.message })); return; }
        if (!dbOffer("mariadb", d, body, jp, load)) return;
        render(d);
      });
    };
    state.refreshHandler = load; load();
  }

  // ---- Database wizards (MariaDB and PostgreSQL share the layout) ----
  // spec: { app, title, intro, userLabel, fetch, create(vals), result(r, vals) → [[k, v]…], conn(vals) → text, host }
  function dbWizard(root, spec) {
    const gate = el("div", {});
    const jp = jobPanel(root);
    state.cleanups.push(jp.stop);
    const name = el("input", { type: "text", placeholder: "myapp", autocomplete: "off", style: "min-width:0" });
    const user = el("input", { type: "text", placeholder: "myapp_user", autocomplete: "off", style: "min-width:0" });
    const host = spec.host ? myHostSelect() : null;
    const pw = dbPwField();
    const out = el("div", {});
    const createBtn = btn("Create database and user", async () => {
      const vals = { db: name.value.trim(), user: user.value.trim(), host: host ? host.value : "localhost", password: pw.input.value };
      if (!vals.db) return toast("Enter a database name", "bad");
      if (!vals.user) return toast(`Enter a ${spec.userLabel.toLowerCase()}`, "bad");
      createBtn.disabled = true;
      try { const r = await spec.create(vals); showResult(r, vals); }
      catch (e) { toast(e.message, "bad"); check(); }
      createBtn.disabled = false;
    }, "btn-primary");
    const form = el("div", { class: "db-form", style: "max-width:520px" }, [
      field("Database name", name, "Letters, digits and underscore."),
      field(spec.userLabel, user, spec.userHint),
      host ? field("Allow connections from", host, MY_HOST_HINT) : null,
      field("Password", pw.node, "Click Generate for a strong one, and save it, it can't be shown again later."),
      el("div", {}, createBtn),
    ].filter(Boolean));
    const wiz = el("div", { class: "card", hidden: true }, [
      el("h3", { text: spec.title }),
      el("p", { class: "muted", style: "margin:0 0 14px", text: spec.intro }), form, out,
    ]);
    function showResult(r, vals) {
      out.innerHTML = "";
      form.hidden = true;
      out.append(
        el("div", { class: "net-card-h", style: "margin-bottom:10px" }, [pill("created", "good"), el("span", { class: "muted", text: "Save these details now, the password isn't stored anywhere you can see it again." })]),
        kv([...spec.result(r, vals), ["Password", vals.password]]),
        el("h4", { text: "Connect from an app", style: "margin:14px 0 6px" }),
        el("pre", { class: "log", style: "margin:0 0 14px;white-space:pre-wrap", text: spec.conn(vals) }),
        el("div", { class: "toolbar", style: "margin:0" }, [
          btn("Copy password", async () => toast(await copyText(vals.password) ? "Password copied" : "Copy failed", "good"), "btn-primary"),
          btn("Create another", () => { out.innerHTML = ""; form.hidden = false; name.value = user.value = pw.input.value = ""; name.focus(); }),
          btn("Manage databases", () => navigate(spec.manage), "btn-ghost"),
        ]));
    }
    const check = async () => {
      try { const d = await spec.fetch(); wiz.hidden = !dbOffer(spec.app, d, gate, jp, check); if (!wiz.hidden) gate.innerHTML = ""; }
      catch (e) { gate.innerHTML = ""; wiz.hidden = false; }  // errors surface on Create
    };
    root.prepend(gate, wiz);
    state.refreshHandler = check; check();
  }

  function viewMySQLWizard(root) {
    dbWizard(root, {
      app: "mariadb", title: "MariaDB Database Wizard", manage: "mysql", host: true,
      intro: "Creates a new database and a new user in one step, and gives that user full access to the database, what most apps (WordPress, Nextcloud, …) ask for.",
      userLabel: "Username", userHint: "The account your app logs in with.",
      fetch: () => API.mysql(),
      create: (v) => API.mysqlWizard({ db: v.db, user: v.user, host: v.host, password: v.password }),
      result: (r, v) => [["Database", v.db], ["User", r.user], ["Connects from", myHostLabel(v.host)]],
      conn: (v) => `mysql://${v.user}:<password>@localhost:3306/${v.db}\n\nmysql -u ${v.user} -p ${v.db}`,
    });
  }

  // ---- Database server missing / stopped / half-installed → offer to install, start or
  // repair it (same System Applications endpoints). Returns true when the server is ready;
  // otherwise renders the offer into box.
  const DB_SERVERS = {
    postgresql: { name: "PostgreSQL", size: "about 50 MB download; uses ~30–60 MB RAM while running",
      stopped: "The PostgreSQL server is installed but no database cluster is online. Start it to manage databases here." },
    mariadb: { name: "MariaDB", size: "about 40 MB download; uses ~80–150 MB RAM while running",
      stopped: "The MariaDB server is installed but not running. Start it to manage databases here." },
  };
  function dbOffer(app, d, box, jp, reload) {
    if (d.installed && d.running) return true;
    const s = DB_SERVERS[app];
    box.innerHTML = "";
    const install = !d.installed;
    const act = install
      ? el("button", { class: "btn btn-primary", text: d.broken ? `Repair ${s.name}` : `Install ${s.name}`, onclick: async (e) => {
          const b = e.currentTarget; b.disabled = true;
          try {
            const r = await API.sysappInstall(app);
            await jp.run(r.job, d.broken ? `Repairing ${s.name}…` : `Installing ${s.name}…`);
            const t = setInterval(async () => {
              try { const j = await API.job(r.job); if (j.status !== "running") { clearInterval(t); reload(); } }
              catch (err) { clearInterval(t); }
            }, 2000);
            state.cleanups.push(() => clearInterval(t));
          } catch (err) { b.disabled = false; toast(err.message, "bad"); } } })
      : el("button", { class: "btn btn-primary", text: `Start ${s.name}`, onclick: async () => {
          try { await API.sysappControl(app, "start"); toast(`${s.name} started`, "good"); reload(); }
          catch (err) { toast(err.message, "bad"); } } });
    box.append(el("div", { class: "card" }, [
      el("h3", { text: d.broken ? `${s.name}'s installation didn't finish` : install ? `${s.name} isn't installed` : `${s.name} isn't running` }),
      el("p", { class: "muted", style: "margin:0 0 14px", text: d.broken
        ? `${s.name} was only partly installed (its setup stopped part-way), so the server can't run. Repair finishes the installation; existing databases are kept.`
        : install ? `${s.name} isn't on this system yet. Install it now (${s.size}), or manage it later from System Applications → Extras.` : s.stopped }),
      el("div", { class: "toolbar" }, [act, btn("Open System Applications", () => navigate("sysapps"), "btn-ghost")]),
    ]));
    return false;
  }
  const pgOffer = (d, box, jp, reload) => dbOffer("postgresql", d, box, jp, reload);

  // ---- PostgreSQL Databases ----
  function viewPgSQL(root) { pgManager(root); }

  // Full PostgreSQL management: databases (owner, size, access), users/roles (password,
  // privileges), and phpPgAdmin. Also the "PostgreSQL" tab of Manage Databases.
  function pgManager(root) {
    const body = el("div", {}, el("div", { class: "loading", text: "Loading…" }));
    root.append(body);
    const jp = jobPanel(root);
    state.cleanups.push(jp.stop);
    const chk = (label, checked, hint) => {
      const c = el("input", { type: "checkbox" }); c.checked = !!checked;
      return { input: c, node: el("label", { class: "dm-check" }, [c, el("span", {}, [label, hint ? el("span", { class: "muted", text: `, ${hint}` }) : null].filter(Boolean))]) };
    };
    const pwField = (id) => {
      const inp = el("input", { id, type: "text", class: "pw-secret", placeholder: "password (6+ characters)", autocomplete: "new-password", style: "min-width:0;flex:1" });
      return { input: inp, node: el("div", { class: "toolbar", style: "margin:0;flex-wrap:nowrap" }, [inp,
        btn("Generate", () => { inp.value = genPassword(18); }, "btn-ghost"),
        btn("Copy", async () => toast(await copyText(inp.value) ? "Password copied" : "Copy failed", "good"), "btn-ghost")]) };
    };
    const call = async (fn, okMsg) => {
      try { const r = await fn(); if (okMsg) toast(okMsg, "good"); load(); return r || true; }
      catch (e) { toast(e.message, "bad"); load(); return null; }
    };

    function permissionError(e) {
      body.append(el("div", { class: "card" }, [
        el("h3", { text: "PostgreSQL can't read its data files" }),
        el("p", { class: "muted", style: "margin:0 0 10px", text: "The database folder is no longer owned by the postgres user, so every connection is refused. Repair gives it back to postgres and restarts the server (a few seconds of downtime; your data isn't touched)." }),
        el("pre", { class: "log", style: "margin:0 0 14px;white-space:pre-wrap", text: e.message }),
        el("button", { class: "btn btn-primary", text: "Repair permissions", onclick: async (ev) => {
          ev.currentTarget.disabled = true;
          try { await API.pgRepair(); toast("PostgreSQL repaired", "good"); load(); }
          catch (err) { ev.target.disabled = false; toast(err.message, "bad"); } } }),
      ]));
    }

    function phpPgAdminCard(p) {
      let status, actions;
      if (!p.installed) {
        status = pill("not installed", "dim");
        actions = [btn("Install phpPgAdmin", async () => {
          const r = await call(() => API.phppgadminInstall());
          if (r) { await jp.run(r.job, "Installing phpPgAdmin…"); const t = setInterval(async () => {
            try { const j = await API.job(r.job); if (j.status !== "running") { clearInterval(t); load(); } } catch (e) { clearInterval(t); } }, 2000);
            state.cleanups.push(() => clearInterval(t)); }
        }, "btn-primary")];
      } else if (!p.lan) {
        status = pill("only works on the Pi itself", "warn");
        actions = [btn("Allow from my network", () => call(() => API.phppgadminLan(true), "phpPgAdmin is now reachable from your network"), "btn-primary")];
      } else {
        status = pill("ready", "good");
        actions = [el("a", { class: "btn btn-sm btn-primary", href: `http://${location.hostname}${p.path}`, target: "_blank", rel: "noopener noreferrer", text: "Open phpPgAdmin ↗" }),
          btn("Limit to this Pi only", () => call(() => API.phppgadminLan(false), "phpPgAdmin now only answers on the Pi itself"), "btn-ghost")];
      }
      return el("div", { class: "card", style: "margin-bottom:16px" }, [
        el("div", { class: "net-card-h" }, [icon("database", 20), el("h3", { text: "phpPgAdmin" }), el("span", { style: "flex:1" }), status]),
        el("p", { class: "muted", style: "margin:6px 0 10px", text: p.installed
          ? "Web tool for browsing tables and running SQL. Log in with a user below that has a password, the built-in postgres account has none and is blocked. Tick “Superuser” on a user for full admin rights."
          : "Optional web tool for browsing tables and running SQL. It's opened to your local network and VPN automatically (never the internet)." }),
        p.installed && !p.apache ? el("p", { class: "dm-hint", text: "Apache isn't running, start it in System Applications to use phpPgAdmin." }) : null,
        el("div", { class: "toolbar", style: "margin:0" }, actions),
      ]);
    }

    function createCards(d) {
      const owners = d.roles.filter((r) => r.login || r.system);
      const dbName = el("input", { type: "text", placeholder: "myapp", style: "min-width:0" });
      const dbOwner = el("select", {}, [el("option", { value: "", text: "postgres (default)" }),
        ...owners.filter((r) => !r.system).map((r) => el("option", { value: r.name, text: r.name }))]);
      const dbCard = el("div", { class: "db-form" }, [
        el("h3", { text: "Create database" }),
        field("Name", dbName, "Letters, digits and underscore."),
        field("Owner", dbOwner, "The owner has full control. Pick the user your app logs in with."),
        btn("Create database", async () => {
          const name = dbName.value.trim(); if (!name) return toast("Enter a database name", "bad");
          if (await call(() => API.pgCreate(name, dbOwner.value), `Database ${name} created`)) dbName.value = "";
        }, "btn-primary"),
      ]);
      const uName = el("input", { type: "text", placeholder: "myapp_user", autocomplete: "off", style: "min-width:0" });
      const uPw = pwField("pg-new-pw");
      const cdb = chk("Can create databases"), csu = chk("Superuser", false, "full admin; use for phpPgAdmin");
      const uDb = el("select", {}, [el("option", { value: "", text: ", none, " }),
        ...d.databases.filter((x) => !x.system).map((x) => el("option", { value: x.name, text: x.name }))]);
      const userCard = el("div", { class: "db-form" }, [
        el("h3", { text: "Create user" }),
        field("Username", uName),
        field("Password", uPw.node, "Save it somewhere, it can be changed later but not shown again."),
        field("Give full access to", uDb, "Optional, you can grant access to more databases later."),
        el("div", { style: "display:flex;flex-direction:column;gap:6px;margin:4px 0 12px" }, [cdb.node, csu.node]),
        btn("Create user", async () => {
          const name = uName.value.trim(); if (!name) return toast("Enter a username", "bad");
          try {
            await API.pgRoleCreate({ name, password: uPw.input.value, login: true, createdb: cdb.input.checked, superuser: csu.input.checked });
            if (uDb.value) await API.pgGrant(uDb.value, name, true);
            toast(`User ${name} created${uDb.value ? ` with access to ${uDb.value}` : ""}`, "good");
            uName.value = ""; uPw.input.value = ""; load();
          } catch (e) { toast(e.message, "bad"); load(); }
        }, "btn-primary"),
      ]);
      return el("div", { class: "card db-create" }, [dbCard, userCard]);
    }

    function manageDb(db, d) {
      const users = d.roles.filter((r) => !r.system && r.login);
      const owner = el("select", {}, [el("option", { value: "postgres", text: "postgres" }),
        ...users.map((r) => el("option", { value: r.name, text: r.name }))]);
      owner.value = db.owner;
      const list = el("div", { style: "display:flex;flex-direction:column;gap:6px" }, users.length ? users.filter((r) => r.name !== db.owner).map((r) => {
        const c = chk(r.name, db.access.includes(r.name) || r.superuser, r.superuser ? "superuser, always has access" : "");
        if (r.superuser) c.input.disabled = true;
        c.input.onchange = async () => {
          c.input.disabled = true;
          try { await API.pgGrant(db.name, r.name, c.input.checked); toast(`${r.name}: access ${c.input.checked ? "granted" : "removed"}`, "good"); }
          catch (e) { c.input.checked = !c.input.checked; toast(e.message, "bad"); }
          c.input.disabled = false; load();
        };
        return c.node;
      }) : [el("p", { class: "muted", text: "No users yet, create one first." })]);
      const host = location.hostname;
      openModal(`Database ${db.name}`, el("div", { style: "display:flex;flex-direction:column;gap:14px;min-width:min(520px,80vw)" }, [
        kv([["Size", db.size], ["Encoding", db.encoding], ["Open connections", String(db.connections)]]),
        el("div", {}, [el("h4", { text: "Owner", style: "margin:0 0 6px" }),
          el("div", { class: "toolbar", style: "margin:0" }, [owner, btn("Change owner", async () => {
            if (owner.value === db.owner) return;
            if (await call(() => API.pgOwner(db.name, owner.value), `${db.name} is now owned by ${owner.value}`)) closeModal();
          }, "btn-primary")])]),
        el("div", {}, [el("h4", { text: "Users with full access", style: "margin:0 0 6px" }), list,
          el("p", { class: "dm-hint", text: "Full access = read and write every table, including tables created later. The owner always has it." })]),
        el("div", {}, [el("h4", { text: "Connect from an app", style: "margin:0 0 6px" }),
          el("pre", { class: "log", style: "margin:0;white-space:pre-wrap", text:
            `postgresql://<user>:<password>@localhost:5432/${db.name}\n\npsql -h ${host} -U <user> -d ${db.name}` })]),
      ]), []);
    }

    function editRole(r) {
      const login = chk("Can log in", r.login), cdb = chk("Can create databases", r.createdb),
        crole = chk("Can create users", r.createrole), su = chk("Superuser", r.superuser, "full admin, bypasses all permissions");
      const lim = el("input", { type: "number", min: -1, max: 10000, value: r.conn_limit, style: "max-width:120px" });
      openModal(`User ${r.name}`, el("div", { style: "display:flex;flex-direction:column;gap:8px;min-width:min(420px,80vw)" }, [
        login.node, cdb.node, crole.node, su.node, field("Connection limit", lim, "-1 = unlimited"),
      ]), [btn("Save", async () => {
        if (await call(() => API.pgRoleUpdate({ name: r.name, login: login.input.checked, createdb: cdb.input.checked,
          createrole: crole.input.checked, superuser: su.input.checked, conn_limit: parseInt(lim.value, 10) }), `${r.name} updated`)) closeModal();
      }, "btn-primary")]);
    }

    function setPassword(r) {
      const pw = pwField("pg-set-pw");
      openModal(`Password for ${r.name}`, el("div", { style: "min-width:min(420px,80vw)" }, [field("New password", pw.node, "Apps using the old password will need the new one.")]),
        [btn("Set password", async () => {
          if (await call(() => API.pgRolePassword(r.name, pw.input.value), `Password changed for ${r.name}`)) closeModal();
        }, "btn-primary")]);
    }

    function render(d) {
      body.innerHTML = "";
      body.append(phpPgAdminCard(d.phppgadmin), createCards(d));
      const dbRows = d.databases.map((db) => el("tr", {}, [
        el("td", {}, [el("b", { text: db.name }), db.system ? el("span", { class: "pill dim", style: "margin-left:6px", text: "system" }) : null].filter(Boolean)),
        el("td", { text: db.owner }), el("td", { class: "muted", text: db.size }),
        el("td", {}, db.access.length ? db.access.map((a) => el("span", { class: "pill", style: "margin:0 4px 2px 0", text: a })) : el("span", { class: "muted", text: db.system ? "" : "owner only" })),
        el("td", { class: "muted", text: String(db.connections) }),
        el("td", { class: "actions" }, db.system ? "" : [
          btn("Manage", () => manageDb(db, d)),
          el("button", { class: "btn btn-sm btn-danger", text: "Drop", onclick: () => {
            if (!confirmInline(`Drop database "${db.name}"? All its data is deleted${db.connections ? ` and ${db.connections} open connection(s) are closed` : ""}. This can't be undone.`)) return;
            call(() => API.pgDrop(db.name), `Dropped ${db.name}`); } })]),
      ]));
      body.append(el("div", { class: "card", style: "margin-bottom:16px" }, [el("h3", { text: "Databases" }),
        simpleTable(["Database", "Owner", "Size", "Users with access", "Connections", ""], dbRows)]));
      const flags = (r) => [r.superuser ? pill("superuser", "warn") : null, r.createdb ? pill("create databases", "dim") : null,
        r.createrole ? pill("create users", "dim") : null, !r.login ? pill("can't log in", "dim") : null].filter(Boolean);
      const roleRows = d.roles.map((r) => el("tr", {}, [
        el("td", {}, [el("b", { text: r.name }), r.system ? el("span", { class: "pill dim", style: "margin-left:6px", text: "built-in" }) : null].filter(Boolean)),
        el("td", {}, flags(r).length ? flags(r) : el("span", { class: "muted", text: "regular user" })),
        el("td", {}, r.has_password ? pill("set", "good") : el("span", { class: "muted", text: r.system ? "none (local only)" : "none" })),
        el("td", { class: "muted", text: r.owns.join(", ") || ", " }),
        el("td", { class: "actions" }, r.system ? "" : [
          btn("Password", () => setPassword(r)), btn("Edit", () => editRole(r)),
          el("button", { class: "btn btn-sm btn-danger", text: "Delete", onclick: () => {
            if (!confirmInline(`Delete user "${r.name}"?${r.owns.length ? `\n\nIt owns ${r.owns.join(", ")}, ownership goes to postgres; the data is kept.` : ""}`)) return;
            call(() => API.pgRoleDrop(r.name), `Deleted ${r.name}`); } })]),
      ]));
      body.append(el("div", { class: "card" }, [el("h3", { text: "Users" }),
        el("p", { class: "muted", style: "margin:0 0 10px", text: "PostgreSQL calls them roles. Apps and phpPgAdmin log in with a user that has a password." }),
        simpleTable(["User", "Privileges", "Password", "Owns", ""], roleRows)]));
    }

    const load = async () => {
      await guardedLoad(async () => {
        let d;
        try { d = await API.pg(); }
        catch (e) { body.innerHTML = ""; if (/permission denied/i.test(e.message)) permissionError(e); else body.append(el("p", { class: "empty", text: e.message })); return; }
        if (!pgOffer(d, body, jp, load)) return;
        render(d);
      });
    };
    state.refreshHandler = load; load();
  }

  // ---- PostgreSQL Wizard ----
  function viewPgWizard(root) {
    dbWizard(root, {
      app: "postgresql", title: "PostgreSQL Database Wizard", manage: "pgsql", host: false,
      intro: "Creates a new database and a new user in one step, and makes that user the database's owner, what most apps (Django, Rails, Nextcloud, …) ask for.",
      userLabel: "Username", userHint: "The account your app logs in with (PostgreSQL calls it a role).",
      fetch: () => API.pg(),
      create: (v) => API.pgWizard({ db: v.db, role: v.user, password: v.password }),
      result: (r, v) => [["Database", v.db], ["User (owner)", r.role]],
      conn: (v) => `postgresql://${v.user}:<password>@localhost:5432/${v.db}\n\npsql -h ${location.hostname} -U ${v.user} -d ${v.db}`,
    });
  }

  function labeledInput(id, label, placeholder, value, type) {
    return el("label", { class: "muted", style: "display:flex;flex-direction:column;gap:6px;font-size:13px" }, [
      label, el("input", { id, type: type || "text", placeholder: placeholder || "", value: value || "" }),
    ]);
  }

  // ======================================================================
  //  Software: Application Manager
  // ======================================================================
  const APP_TEMPLATES = {
    node: { label: "Node.js", cmd: "node app.js" },
    python: { label: "Python", cmd: "python3 app.py" },
    ruby: { label: "Ruby", cmd: "ruby app.rb" },
    custom: { label: "Custom", cmd: "" },
  };
  function viewAppManager(root) {
    const form = el("div", { class: "card", style: "margin-bottom:16px" }, [
      el("h3", { text: "Create application (runs as a systemd service)" }),
      el("div", { style: "display:grid;gap:12px;max-width:560px" }, [
        el("div", { class: "toolbar", style: "margin:0" }, [
          el("label", { class: "muted", text: "Runtime:" }),
          el("select", { id: "app-runtime", style: "max-width:150px", onchange: () => { $("#app-cmd").value = APP_TEMPLATES[$("#app-runtime").value].cmd; } },
            Object.entries(APP_TEMPLATES).map(([k, v]) => el("option", { value: k, text: v.label }))),
        ]),
        labeledInput("app-name", "App name (slug)", "myapp"),
        labeledInput("app-dir", "Working directory", `${sysHome()}/myapp`),
        labeledInput("app-cmd", "Start command", "node app.js"),
        el("label", { class: "muted", style: "display:flex;align-items:center;gap:8px" }, [el("input", { id: "app-auto", type: "checkbox", checked: "checked", style: "width:auto" }), "Start now + enable on boot"]),
        el("button", { class: "btn btn-primary", style: "justify-self:start", text: "Create app", onclick: createApp }),
      ]),
    ]);
    const body = el("div", { id: "app-body" }, el("div", { class: "loading", text: "Loading…" }));
    root.append(form, body);
    const load = async () => {
      await guardedLoad(async () => {
        const d = await API.apps();
        body.innerHTML = "";
        if (!d.supported) { body.append(el("p", { class: "empty", text: "systemd not available." })); return; }
        if (!d.apps.length) { body.append(el("p", { class: "empty", text: "No apps yet." })); return; }
        const rows = d.apps.map((a) => el("tr", {}, [
          el("td", { text: a.name }),
          el("td", {}, el("span", { class: `pill ${a.active === "active" ? "good" : "dim"}`, text: a.active })),
          el("td", { class: "muted", text: a.command, style: "max-width:280px;overflow:hidden;text-overflow:ellipsis" }),
          el("td", { class: "actions" }, [
            el("button", { class: "btn btn-sm", text: a.active === "active" ? "Restart" : "Start", onclick: () => appCtl(a.name, a.active === "active" ? "restart" : "start", load) }),
            a.active === "active" ? el("button", { class: "btn btn-sm btn-ghost", text: "Stop", onclick: () => appCtl(a.name, "stop", load) }) : null,
            el("button", { class: "btn btn-sm btn-ghost", text: "Logs", onclick: () => showAppLogs(a.name) }),
            el("button", { class: "btn btn-sm btn-danger", text: "Remove", onclick: async () => { if (!confirmInline(`Remove app "${a.name}"?`)) return; try { await API.appRemove(a.name); toast("Removed", "good"); load(); } catch (e) { toast(e.message, "bad"); } } }),
          ]),
        ]));
        body.append(simpleTable(["App", "Status", "Command", ""], rows));
      });
    };
    async function createApp() {
      const b = { name: $("#app-name").value.trim(), workdir: $("#app-dir").value.trim(), command: $("#app-cmd").value.trim(), autostart: $("#app-auto").checked };
      if (!b.name || !b.workdir || !b.command) { toast("Fill name, directory and command", "bad"); return; }
      try { await API.appCreate(b); toast("App created", "good"); $("#app-name").value = ""; load(); }
      catch (e) { toast(e.message, "bad"); }
    }
    state.refreshHandler = load; load();
  }
  async function appCtl(name, action, done) { try { await API.appControl(name, action); toast(`${action} → ${name}`, "good"); done && setTimeout(done, 500); } catch (e) { toast(e.message, "bad"); } }
  async function showAppLogs(name) { try { const r = await API.appLogs(name); openModal(`Logs, ${name}`, el("pre", { class: "log", text: r.output }), []); } catch (e) { toast(e.message, "bad"); } }

  // ======================================================================
  //  Software: System Applications (one-click web servers / PHP-FPM / DB / FTP)
  // ======================================================================
  function viewSysApps(root) {
    const appArg = (state.viewArg || "").split(":")[0];
    if (appArg) return viewAppConfig(root, appArg);
    const intro = el("p", { class: "muted", style: "margin:0 0 14px",
      text: "Install and manage server software with one click. Only one web server can use port 80 at a time, switching stops the running one. Uninstall keeps config files and website content." });
    const body = el("div", {}, el("div", { class: "loading", text: "Loading…" }));
    const jp = jobPanel(root);
    root.prepend(intro, body);
    state.cleanups.push(jp.stop);

    // Run an action; on 409 (port 80 busy) ask to switch and retry.
    async function withSwitch(fn, okMsg) {
      try { return await fn(false); }
      catch (e) {
        if (e.status !== 409) { toast(e.message, "bad"); return null; }
        if (!confirmInline(e.message + "\n\nApache-only features (phpMyAdmin, .htaccess tools) stop working while another server is active.")) return null;
        try { return await fn(true); } catch (e2) { toast(e2.message, "bad"); return null; }
      }
    }
    async function watch(jobId, label) {
      await jp.run(jobId, label);
      const t = setInterval(async () => {
        try { const j = await API.job(jobId); if (j.status !== "running") { clearInterval(t); load(); } }
        catch (e) { clearInterval(t); }
      }, 2000);
      state.cleanups.push(() => clearInterval(t));
    }
    async function doInstall(a) {
      const r = await withSwitch((sw) => API.sysappInstall(a.id, sw));
      if (r) watch(r.job, `${a.broken ? "Repairing" : "Installing"} ${a.name}…`);
    }
    async function doUninstall(a) {
      const extra = a.id === "apache" ? "\n\nphpMyAdmin and your Apache sites will stop being served." : (a.id === "mariadb" || a.id === "postgresql") ? "\n\nDatabases stay on disk but nothing can use them until it is reinstalled." : "";
      if (!confirmInline(`Uninstall ${a.name}? Config files and website content are kept.${extra}`)) return;
      try { const r = await API.sysappUninstall(a.id); watch(r.job, `Uninstalling ${a.name}…`); }
      catch (e) { toast(e.message, "bad"); }
    }
    async function doCtl(a, action) {
      const r = await withSwitch((sw) => API.sysappControl(a.id, action, sw));
      if (r) { toast(`${a.name}: ${action}`, "good"); load(); }
    }

    function card(a) {
      const server = a.group === "server";
      const noUnits = server && !(a.units || []).length;
      const pill = a.broken ? el("span", { class: "pill bad", text: "Install incomplete" })
        : a.job ? el("span", { class: "pill warn", text: "Installing…" })
        : !a.installed ? el("span", { class: "pill dim", text: "Not installed" })
        : noUnits ? el("span", { class: "pill good", text: "Installed" })
        : a.partial ? el("span", { class: "pill warn", text: "Partly running" })
        : el("span", { class: `pill ${a.active ? "good" : "dim"}`, text: a.active ? "Running" : "Stopped" });
      const facts = [
        a.version ? `Version <b>${esc(a.version)}</b>` : null,
        a.ram_mb != null ? `RAM <b>${a.ram_mb} MB</b>` : `Typical RAM ${esc(a.ram_typical)}`,
        a.docroot ? `Web folder <code>${esc(a.docroot)}</code>` : null,
      ].filter(Boolean).join(" · ");
      const configure = server && a.installed ? el("button", { class: "btn btn-sm btn-primary", text: "Configure", onclick: () => navigate(a.view) }) : null;
      const btns = a.job ? [el("button", { class: "btn btn-sm", text: "Show progress", onclick: () => watch(a.job, `Installing ${a.name}…`) })]
        : !a.installed
        ? [el("button", { class: "btn btn-sm btn-primary", text: a.broken ? "Repair" : "Install", title: a.broken ? "The last install stopped part-way, finish it" : (a.needs || []).length ? `Also installs: ${a.needs.join(", ")}` : "", onclick: () => doInstall(a) })]
        : server ? [configure,
            a.ext ? el("a", { class: "btn btn-sm btn-ghost", href: `https://${location.hostname}${a.ext}`, target: "_blank", rel: "noopener", text: "Open ↗" }) : null,
            noUnits ? null : a.active ? el("button", { class: "btn btn-sm", text: "Restart", onclick: () => doCtl(a, "restart") })
                     : el("button", { class: "btn btn-sm", text: "Start", onclick: () => doCtl(a, "start") }),
            noUnits || !a.active ? null : el("button", { class: "btn btn-sm btn-ghost", text: "Stop", onclick: () => doCtl(a, "stop") }),
          ]
        : [
            a.active ? el("button", { class: "btn btn-sm", text: "Restart", onclick: () => doCtl(a, "restart") })
                     : el("button", { class: "btn btn-sm btn-primary", text: "Start", onclick: () => doCtl(a, "start") }),
            a.active ? el("button", { class: "btn btn-sm btn-ghost", text: "Stop", onclick: () => doCtl(a, "stop") }) : null,
            el("button", { class: "btn btn-sm btn-ghost sa-uninstall", text: "Uninstall", onclick: () => doUninstall(a) }),
          ];
      // Round icon buttons in the header: settings (gear) and, for FTP, its accounts.
      const iconBtn = (ico, label, onclick) => el("button", { class: "sa-icon-btn", type: "button", title: label, "aria-label": label, onclick }, icon(ico, 17));
      const headBtns = a.installed ? [
        server ? iconBtn("gear", `Configure ${a.name}`, () => navigate(a.view)) : null,
        a.id === "vsftpd" ? iconBtn("users", "FTP accounts", () => navigate("ftpaccounts")) : null,
        a.id === "postgresql" ? iconBtn("database", "PostgreSQL databases", () => navigate("pgsql")) : null,
        APP_NAMES[a.id] ? iconBtn("gear", `Configure ${a.name}`, () => navigate("sysapps", { arg: a.id })) : null,
      ] : [];
      return el("div", { class: `card sa-card ${a.installed ? "" : "sa-off"} ${a.id === "docker" ? "sa-docker" : ""}` }, [
        el("div", { class: "sa-head" }, [a.id === "docker" ? el("span", { class: "sa-ship" }, icon("t_ship", 18)) : null, el("h3", { text: a.name }), el("span", { style: "flex:1" }), pill, ...headBtns]),
        el("p", { class: "muted sa-desc", text: a.desc }),
        el("p", { class: "muted sa-facts", html: facts }),
        server && a.installed && (a.units || []).length > 1 ? el("div", { class: "em-svcs sa-units" }, a.units.map((u) => el("span", { class: `em-svc ${u.active ? "on" : ""}`, title: u.active ? "running" : "stopped" }, [el("i"), u.unit]))) : null,
        el("div", { class: "sa-actions" }, btns.filter(Boolean)),
      ]);
    }
    const grid = (apps) => el("div", { class: "sa-grid" }, apps.map(card));

    async function load() {
      await guardedLoad(async () => {
        const d = await API.sysapps();
        body.innerHTML = "";
        if (!d.supported) { body.append(el("p", { class: "empty", text: "apt/systemd not available on this host." })); return; }
        body.append(
          el("h3", { text: "Web servers" }), grid(d.apps.filter((a) => a.group === "web")),
          el("h3", { text: "Extras" }), grid(d.apps.filter((a) => a.group === "extra")),
          el("h3", { text: "Mail, DNS & security" }), grid(d.apps.filter((a) => a.group === "server")),
        );
      });
    }
    state.refreshHandler = load; load();
  }

  // ======================================================================
  //  Software: Select PHP Version
  // ======================================================================
  // ======================================================================
  //  Software: one system application's configuration (#/sysapps/<id>[:tab])
  // ======================================================================
  const APP_NAMES = { apache: "Apache", nginx: "Nginx", lighttpd: "Lighttpd", caddy: "Caddy", phpfpm: "PHP-FPM", mariadb: "MariaDB", postgresql: "PostgreSQL", vsftpd: "vsftpd (FTP)" };
  function viewAppConfig(root, id) {
    $("#view-title").textContent = `${APP_NAMES[id] || id}, configuration`;
    document.title = `${APP_NAMES[id] || id} · AuroraPanel`;
    const head = el("div", { class: "toolbar" }, [btn("← All applications", () => navigate("sysapps")), el("span", { class: "muted", text: "Changes are checked before they're applied, if the app rejects them, the previous config is restored automatically." })]);
    const body = el("div", {}, el("div", { class: "loading", text: "Loading…" }));
    root.append(head, body);
    (async () => {
      let info;
      try { info = await API.appConfig(id); } catch (e) { body.innerHTML = ""; body.append(el("p", { class: "empty", text: e.message })); return; }
      body.innerHTML = "";
      const tabs = [];
      if (info.has_settings) tabs.push(["settings", "Settings"]);
      if (info.ftp_accounts) tabs.push(["accounts", "FTP accounts"]);
      if (info.has_modules) tabs.push(["modules", "Modules"]);
      if (info.files.length) tabs.push(["files", "Config files"]);
      tabs.push(["logs", "Logs"]);
      subTabs(body, tabs, (tab, pane) => {
        if (tab === "settings") appSettingsTab(pane);
        else if (tab === "accounts") ftpAccountsPanel(pane);
        else if (tab === "modules") appModulesTab(pane);
        else if (tab === "files") appFilesTab(pane);
        else appLogsTab(pane);
      }, id);

      function appSettingsTab(pane) {
        pane.append(el("div", { class: "loading", text: "Reading the current configuration…" }));
        (async () => {
          try {
            const d = await API.appSettings(id);
            pane.innerHTML = "";
            if (d.pool_file) pane.append(el("p", { class: "dm-hint", text: `PHP ${d.version} pool: ${d.pool_file}` }));
            const form = settingsForm(d.schema, d.values, { boolValues: d.bool_values });
            const save = btn("Save & apply", async () => {
              const ch = form.changes();
              if (!Object.keys(ch).length) { toast("Nothing changed", "good"); return; }
              save.disabled = true;
              try { await API.appSettingsSave(id, ch); toast(`${APP_NAMES[id]} updated`, "good"); pane.innerHTML = ""; appSettingsTab(pane); }
              catch (e) { toast("Not applied, see details", "bad"); openModal("Settings not applied", el("pre", { class: "log", text: e.message }), []); save.disabled = false; }
            }, "btn-primary");
            pane.append(form.node, el("div", { class: "sf-actions" }, [save]));
          } catch (e) { pane.innerHTML = ""; pane.append(el("p", { class: "empty", text: e.message })); }
        })();
      }

      function appModulesTab(pane) {
        const filter = el("input", { type: "search", placeholder: "Filter modules…", style: "max-width:260px" });
        const list = el("div");
        pane.append(el("div", { class: "toolbar" }, [filter, el("span", { class: "dm-hint", text: "Popular modules are listed first. The server restarts after each change." })]), list);
        let mods = [];
        const draw = () => {
          const q = filter.value.trim().toLowerCase();
          const rows = mods.filter((m) => !q || m.name.includes(q) || (m.desc || "").toLowerCase().includes(q))
            .sort((a, b) => (b.popular - a.popular) || a.name.localeCompare(b.name));
          list.innerHTML = "";
          list.append(simpleTable(["Module", "What it does", "Enabled"], rows.map((m) => {
            const c = el("input", { type: "checkbox", class: "sf-switch" }); c.checked = m.enabled; c.disabled = m.protected && m.enabled;
            c.title = m.protected ? "Required, can't be turned off here" : "";
            c.onchange = async () => {
              c.disabled = true;
              try { await API.appModule(id, m.name, c.checked); m.enabled = c.checked; toast(`${m.name} ${c.checked ? "enabled" : "disabled"}`, "good"); }
              catch (e) { c.checked = !c.checked; openModal("Module change undone", el("pre", { class: "log", text: e.message }), []); }
              c.disabled = m.protected && m.enabled;
            };
            return row(el("code", { text: m.name }), m.desc || (m.protected ? "required" : ""), c);
          })));
        };
        filter.addEventListener("input", draw);
        API.appModules(id).then((d) => { mods = d.modules; draw(); }).catch((e) => list.append(el("p", { class: "empty", text: e.message })));
      }

      function appFilesTab(pane) {
        const sel = el("select", {}, info.files.map((f) => el("option", { value: f, text: f })));
        const ta = el("textarea", { class: "cw-mono app-editor", spellcheck: "false", rows: 26 });
        let orig = "";
        const load = async () => { try { const f = await API.appFile(id, sel.value); ta.value = orig = f.content; } catch (e) { toast(e.message, "bad"); } };
        sel.onchange = () => { if (ta.value !== orig && !confirmInline("Discard unsaved changes?")) return; load(); };
        const save = btn("Check & save", async () => {
          if (ta.value === orig) { toast("Nothing changed", "good"); return; }
          save.disabled = true;
          try { await API.appFileSave(id, sel.value, ta.value); orig = ta.value; toast("Saved, checked and applied", "good"); }
          catch (e) { openModal("Not saved, the file was left as it was", el("pre", { class: "log", text: e.message }), []); }
          save.disabled = false;
        }, "btn-primary");
        pane.append(el("div", { class: "card net-warn" }, [el("p", { text: "Advanced: edit the raw configuration. It's validated before saving; if the application refuses it, the old file is put back." })]),
          el("div", { class: "toolbar" }, [sel, save, btn("Reload from disk", load, "btn-ghost")]), ta);
        load();
      }

      function appLogsTab(pane) {
        const src = el("select", {}, [el("option", { value: "", text: `System journal (${info.unit || id})` }), ...info.logs.map((f) => el("option", { value: f, text: f }))]);
        if (id === "postgresql" && info.logs.length) src.value = info.logs[0];  // PostgreSQL logs to its own file, not the journal
        const lines = el("select", {}, [100, 300, 1000].map((n) => el("option", { value: n, text: `last ${n} lines` })));
        const pre = el("pre", { class: "log app-log" });
        const load = async () => { try { const r = await API.appCfgLogs(id, src.value, lines.value); pre.textContent = r.text || "(empty)"; pre.scrollTop = pre.scrollHeight; } catch (e) { pre.textContent = e.message; } };
        src.onchange = load; lines.onchange = load;
        pane.append(el("div", { class: "toolbar" }, [src, lines, btn("Refresh", load)]), pre);
        load();
      }
    })();
  }

  // ---- FTP accounts (System Applications → vsftpd, and Files → FTP Accounts) ----
  function ftpAccountsPanel(pane) {
    const box = el("div", {}, el("div", { class: "loading", text: "Loading…" }));
    pane.append(box);
    const ACC = { full: "Full access", readonly: "Read only", upload: "Upload only (drop box)", custom: "Custom" };
    const load = async () => {
      let d;
      try { d = await API.ftpAccounts(); } catch (e) { box.innerHTML = ""; box.append(el("p", { class: "empty", text: e.message })); return; }
      box.innerHTML = "";
      if (!d.installed) {
        box.append(installCard("The FTP server (vsftpd) is not installed", "Install it from System Applications, then come back to create FTP accounts.", null),
          btn("Open System Applications", () => navigate("sysapps"), "btn-primary"));
        return;
      }
      const s = d.server;
      const lan = (await API.vpnOverview().catch(() => ({ settings: {} }))).settings || {};
      box.append(el("div", { class: "card" }, [
        el("div", { class: "net-card-h" }, [icon("folder", 20), el("h3", { text: "FTP server" }), el("span", { style: "flex:1" }), pill(s.active ? "running" : "stopped", s.active ? "good" : "bad")]),
        kv([["Host (LAN)", location.hostname], ["Host (internet)", lan.effective_endpoint || ", "], ["Port", s.port],
            ["Encryption", s.ssl ? "FTPS available (explicit TLS)" : "Off, plain FTP sends passwords unencrypted"],
            ["Passive ports", s.passive[0] ? `${s.passive[0]}–${s.passive[1]}` : "any (set a range for access from the internet)"],
            ["Who can log in", s.only_listed ? "Only the FTP accounts below" : "Any Linux user on this Pi"]]),
        el("div", { class: "toolbar", style: "margin:12px 0 0" }, [
          btn("Server settings", () => navigate("sysapps", { arg: "vsftpd" }), "btn-ghost"),
          btn(`Check port ${s.port}`, () => gotoPortCheck(+s.port, "tcp"), "btn-ghost"),
        ]),
      ]));
      box.append(el("h2", { class: "section-title", text: `FTP accounts (${d.accounts.length})` }));
      box.append(d.accounts.length ? simpleTable(["Username", "Folder", "Access", "Status", ""], d.accounts.map((a) => row(
        el("span", {}, [el("b", { text: a.name }), a.managed ? null : el("span", { class: "dm-hint", text: " (existing Linux user)" })]),
        el("span", {}, [el("code", { class: "net-mono", text: a.folder }), a.folder_exists ? null : pill("missing", "bad")]),
        ACC[a.access] || a.access,
        pill(a.enabled ? "active" : "disabled", a.enabled ? "good" : "bad"),
        el("div", { class: "net-actions" }, [
          btn("Password", () => ftpPasswordDialog(a.name)),
          btn("Edit", () => ftpEditDialog(a)),
          btn(a.enabled ? "Disable" : "Enable", async () => { try { await API.ftpToggle(a.name, !a.enabled); toast(`${a.name} ${a.enabled ? "disabled" : "enabled"}`, "good"); load(); } catch (e) { toast(e.message, "bad"); } }, "btn-ghost"),
          btn("Delete", async () => {
            if (!confirmInline(a.managed ? `Delete FTP account ${a.name}? Files in ${a.folder} are kept.` : `Remove FTP access for ${a.name}? The Linux user itself is kept.`)) return;
            try { const r = await API.ftpDelete(a.name); toast(r.note || `${a.name} deleted`, "good"); load(); } catch (e) { toast(e.message, "bad"); }
          }, "btn-danger"),
        ]),
      ))) : el("p", { class: "empty", text: "No FTP accounts yet." }));
      // create form
      const name = el("input", { type: "text", placeholder: "e.g. webdev", maxlength: 32, autocomplete: "off" });
      const pw = passwordField();
      const folder = el("input", { type: "text", value: "/var/www/html", placeholder: "/var/www/html" });
      const picks = el("div", { class: "net-presets" }, [el("span", { class: "dm-hint", text: "Quick pick:" }),
        ...["/var/www/html", sysHome(), "/srv/ftp"].map((p) => el("button", { type: "button", class: "cw-chip", text: p, onclick: () => { folder.value = p; } }))]);
      const access = el("select", {}, Object.entries(d.access_levels).map(([k, l]) => el("option", { value: k, text: l })));
      const add = btn("Create FTP account", async () => {
        const password = pw.value() || genPassword();
        add.disabled = true;
        try {
          const r = await API.ftpCreate({ name: name.value.trim(), password, folder: folder.value.trim(), access: access.value, create_folder: true });
          name.value = ""; pw.clear(); load();
          ftpCredentials({ name: r.name, password, folder: r.folder, server: s, host: location.hostname });
        } catch (e) { toast(e.message, "bad"); }
        add.disabled = false;
      }, "btn-primary");
      box.append(el("div", { class: "card" }, [
        el("h3", { text: "Create an FTP account" }),
        el("p", { class: "muted", text: "The account can only see its folder (it's locked in). Permissions are added with ACLs, so the folder's owner and existing permissions don't change." }),
        el("div", { class: "net-form" }, [field("Username", name), field("Password (8+ characters)", pw.node, "Leave empty to generate one."), field("Folder", folder, "Created if it doesn't exist."), field("Access", access)]),
        picks, el("div", { style: "margin-top:12px" }, add),
      ]));
    };
    function ftpCredentials(c) {
      const pwBox = el("input", { type: "text", readonly: "readonly", class: "net-mono net-pw-out", value: c.password });
      openModal(`FTP account ${c.name} created`, el("div", {}, [
        kv([["Host", c.host], ["Port", c.server.port], ["Username", c.name], ["Folder", c.folder], ["Encryption", c.server.ssl ? "FTPS (explicit TLS) available" : "none"]]),
        el("div", { class: "net-cred" }, [el("span", { class: "net-k", text: "Password" }), pwBox, btn("Copy", async () => toast(await copyText(c.password) ? "Password copied" : "Copy failed, select it manually", "good"))]),
        el("p", { class: "dm-hint", text: "The password isn't shown again. In FileZilla: File → Site Manager → Host, port, Logon type Normal." }),
      ]), []);
    }
    function ftpPasswordDialog(nm) {
      const pw = passwordField();
      const save = btn("Set password", async () => {
        const password = pw.value() || genPassword();
        save.disabled = true;
        try { await API.ftpPassword(nm, password); closeModal(); openModal(`New password for ${nm}`, el("div", {}, [el("div", { class: "net-cred" }, [el("span", { class: "net-k", text: "Password" }), el("input", { type: "text", readonly: "readonly", class: "net-mono net-pw-out", value: password }), btn("Copy", async () => toast(await copyText(password) ? "Copied" : "Copy failed", "good"))])]), []); }
        catch (e) { toast(e.message, "bad"); save.disabled = false; }
      }, "btn-primary");
      openModal(`Change password, ${nm}`, field("New password (8+ characters)", pw.node, "Leave empty to generate one."), [save]);
      setTimeout(() => pw.input.focus(), 30);
    }
    function ftpEditDialog(a) {
      const folder = el("input", { type: "text", value: a.folder });
      const access = el("select", {}, Object.entries(ACC).filter(([k]) => k !== "custom").map(([k, l]) => el("option", { value: k, text: l })));
      access.value = a.access === "custom" ? "full" : a.access;
      const save = btn("Save", async () => {
        save.disabled = true;
        try { await API.ftpModify({ name: a.name, folder: folder.value.trim(), access: access.value, create_folder: true }); closeModal(); toast("Updated", "good"); load(); }
        catch (e) { toast(e.message, "bad"); save.disabled = false; }
      }, "btn-primary");
      openModal(`Edit ${a.name}`, el("div", { class: "net-form" }, [field("Folder", folder), field("Access", access)]), [save]);
    }
    load();
  }

  // ---- shared: sub-tabs inside a view, remembered in the URL (#/view/tab) ----
  // prefix: when the URL arg also carries something else (e.g. an app id): "#/sysapps/vsftpd:logs"
  function subTabs(root, tabs, render, prefix) {
    const bar = el("div", { class: "cw-seg cw-seg-sm sub-tabs" });
    const pane = el("div", { class: "sub-pane" });
    root.append(bar, pane);
    const keys = tabs.map((t) => t[0]);
    const pre = prefix ? prefix + ":" : "";
    const show = (key, push) => {
      if (!keys.includes(key)) key = keys[0];
      bar.querySelectorAll("button").forEach((b) => b.classList.toggle("active", b.dataset.k === key));
      if (push) setViewArg(key === keys[0] ? (prefix || null) : pre + key);
      (state.subCleanups || []).forEach((fn) => { try { fn(); } catch (e) {} });
      state.subCleanups = [];
      pane.innerHTML = "";
      render(key, pane);
    };
    tabs.forEach(([k, label]) => bar.append(el("button", { type: "button", "data-k": k, text: label, onclick: () => show(k, true) })));
    state.cleanups.push(() => (state.subCleanups || []).forEach((fn) => { try { fn(); } catch (e) {} }));
    const arg = state.viewArg || "";
    show(pre ? (arg.startsWith(pre) ? arg.slice(pre.length) : keys[0]) : (arg || keys[0]), false);
    return { show };
  }

  // ---- shared: settings form rendered from a schema ----
  // schema: [{title, fields:[{key,label,type,help,options,min,max}]}]
  // types: bool | int | size | text | select | timezone | password | path | port
  const isOn = (v) => v === true || ["on", "yes", "true", "1"].includes(String(v == null ? "" : v).toLowerCase());
  function settingsForm(schema, values, opts = {}) {
    const inputs = {};
    const initial = { ...values };
    const overridden = new Set(opts.overridden || []);
    const reset = new Set();
    const tzList = opts.timezones || [];
    const sections = schema.map((sec) => el("div", { class: "card sf-sec" }, [
      el("h3", { text: sec.title }),
      sec.desc ? el("p", { class: "dm-hint", text: sec.desc }) : null,
      el("div", { class: "sf-grid" }, sec.fields.map((f) => {
        const v = values[f.key];
        let inp;
        if (f.type === "bool") {
          inp = el("input", { type: "checkbox", class: "sf-switch" }); inp.checked = isOn(v);
        } else if (f.type === "select") {
          inp = el("select", {}, (f.options || []).map((o) => el("option", { value: Array.isArray(o) ? o[0] : o, text: Array.isArray(o) ? o[1] : o })));
          if (v != null && ![...inp.options].some((o) => o.value === String(v))) inp.append(el("option", { value: String(v), text: `${v} (current)` }));
          inp.value = v == null ? "" : String(v);
        } else if (f.type === "timezone") {
          const listId = "tz-" + Math.random().toString(36).slice(2);
          inp = el("span", { class: "sf-combo" }, [
            el("input", { type: "text", list: listId, value: v || "", placeholder: "e.g. America/Los_Angeles" }),
            el("datalist", { id: listId }, tzList.map((z) => el("option", { value: z }))),
          ]);
          Object.defineProperty(inp, "value", { get: () => inp.firstChild.value });
        } else if (f.type === "int" || f.type === "port") {
          inp = el("input", { type: "number", value: v == null ? "" : v, min: f.min ?? (f.type === "port" ? 1 : null), max: f.max ?? (f.type === "port" ? 65535 : null) });
        } else if (f.type === "password") {
          inp = el("input", { type: "password", value: "", placeholder: v ? "(set, leave empty to keep)" : "", autocomplete: "new-password" });
        } else if (f.type === "textarea") {
          inp = el("textarea", { rows: 4, class: "cw-mono" }); inp.value = v == null ? "" : String(v);
        } else {
          inp = el("input", { type: "text", value: v == null ? "" : v, placeholder: f.placeholder || (f.type === "size" ? "e.g. 128M" : "") });
        }
        inputs[f.key] = { inp, f };
        const tag = overridden.has(f.key) ? el("button", { type: "button", class: "sf-reset", title: "Back to the default", text: "custom · reset", onclick: (e) => {
          reset.add(f.key); e.target.textContent = "will reset"; e.target.disabled = true; } }) : null;
        return el("label", { class: `sf-field ${f.type === "bool" ? "sf-bool" : ""}` }, [
          el("span", { class: "sf-label" }, [el("span", { text: f.label }), tag]),
          inp,
          f.help ? el("small", { class: "dm-hint", text: f.help }) : null,
        ]);
      })),
    ]));
    const readVal = ({ inp, f }) => f.type === "bool" ? (opts.boolValues ? (inp.checked ? opts.boolValues[0] : opts.boolValues[1]) : (inp.checked ? "On" : "Off")) : inp.value.trim();
    return {
      node: el("div", { class: "sf" }, sections),
      // Only what the user actually changed (passwords only when typed).
      changes() {
        const out = {};
        for (const [k, x] of Object.entries(inputs)) {
          const nv = readVal(x);
          if (x.f.type === "password") { if (nv) out[k] = nv; continue; }
          if (x.f.type === "bool") { if (x.inp.checked !== isOn(initial[k])) out[k] = nv; continue; }
          if (nv !== (initial[k] == null ? "" : String(initial[k]))) out[k] = nv;
        }
        return out;
      },
      resets: () => [...reset],
    };
  }

  // ======================================================================
  //  Software: PHP (settings, extensions, versions)
  // ======================================================================
  function viewPHPVersion(root) {
    const body = el("div", {}, el("div", { class: "loading", text: "Loading…" }));
    root.append(body);
    const jp = jobPanel(root);
    state.cleanups.push(jp.stop);
    let ov = null, ver = null;
    const load = () => guardedLoad(async () => {
      ov = await API.phpOverview();
      body.innerHTML = "";
      if (!ov.supported || !ov.versions.length) { body.append(el("p", { class: "empty", text: "No PHP installed. Install Apache + PHP from System Applications or Packages." })); return; }
      const webVers = ov.versions.filter((v) => v.sapis.some((s) => s !== "cli"));
      ver = ver || ov.apache || (webVers[0] || ov.versions[ov.versions.length - 1]).version;
      const verSel = el("select", { onchange: () => { ver = verSel.value; load(); } }, ov.versions.map((v) => el("option", { value: v.version, text: `PHP ${v.version}${v.version === ov.apache ? ", used by Apache" : v.sapis.includes("fpm") ? ", PHP-FPM" : v.sapis.length === 1 && v.sapis[0] === "cli" ? ", command line only" : ""}` })));
      verSel.value = ver;
      body.append(el("div", { class: "toolbar php-head" }, [el("span", { class: "muted", text: "Version:" }), verSel]));
      const host = el("div");
      body.append(host);
      subTabs(host, [["settings", "Settings"], ["extensions", "Extensions"], ["versions", "Versions"]], (tab, pane) => {
        if (tab === "settings") phpSettingsTab(pane);
        else if (tab === "extensions") phpExtensionsTab(pane);
        else phpVersionsTab(pane);
      });
    });

    function phpSettingsTab(pane) {
      const v = ov.versions.find((x) => x.version === ver);
      const labels = ov.sapi_labels;
      const primary = v.sapis.find((s) => s !== "cli") || v.sapis[0];
      const targets = {};
      const targetBox = el("div", { class: "php-targets" }, [el("span", { class: "muted", text: "Apply to:" }), ...v.sapis.map((s) => {
        const c = el("input", { type: "checkbox" }); c.checked = s !== "cli" || v.sapis.length === 1; targets[s] = c;
        return el("label", { class: "dm-check" }, [c, el("span", { text: labels[s] || s })]);
      })]);
      const formHost = el("div", {}, el("div", { class: "loading", text: "Loading…" }));
      pane.append(el("p", { class: "muted", text: `Showing the values PHP ${ver} uses for ${labels[primary] || primary}. Changes are saved as overrides, php.ini itself is never edited, and "reset" returns a value to the php.ini default.` }), targetBox, formHost);
      (async () => {
        try {
          const d = await API.phpSettings(ver, primary);
          const form = settingsForm(ov.schema, d.values, { overridden: d.overridden, timezones: ov.timezones });
          const save = btn("Save settings", async () => {
            const sapis = Object.entries(targets).filter(([, c]) => c.checked).map(([s]) => s);
            const changes = form.changes(), resets = form.resets();
            if (!Object.keys(changes).length && !resets.length) { toast("Nothing changed", "good"); return; }
            save.disabled = true;
            try { const r = await API.phpSettingsSave(ver, sapis, changes, resets); toast(`Saved${r.reloaded.length ? ", reloaded " + r.reloaded.join(", ") : ""}`, "good"); phpSettingsTabReload(); }
            catch (e) { toast(e.message, "bad"); }
            save.disabled = false;
          }, "btn-primary");
          formHost.innerHTML = "";
          formHost.append(form.node, el("div", { class: "sf-actions" }, [save, el("span", { class: "dm-hint", text: "Tip: for big uploads also raise the web server limit (Nginx client_max_body_size / Apache LimitRequestBody) in System Applications." })]));
        } catch (e) { formHost.innerHTML = ""; formHost.append(el("p", { class: "empty", text: e.message })); }
      })();
      function phpSettingsTabReload() { pane.innerHTML = ""; phpSettingsTab(pane); }
    }

    function phpExtensionsTab(pane) {
      pane.append(el("div", { class: "loading", text: "Loading extensions…" }));
      (async () => {
        try {
          const d = await API.phpExtensions(ver);
          pane.innerHTML = "";
          const labels = ov.sapi_labels;
          pane.append(el("h3", { class: "section-title", text: "Popular extensions" }),
            el("div", { class: "php-ext-grid" }, d.popular.filter((p) => p.installed || p.available).map((p) => el("div", { class: "php-ext" }, [
              el("div", {}, [el("b", { text: p.ext }), el("div", { class: "dm-hint", text: p.desc })]),
              p.installed ? pill("installed", "good") : btn("Install", async () => { try { const r = await API.phpExtInstall(ver, p.ext); watchJob(jp, r.job, `Installing ${p.package}`, () => { pane.innerHTML = ""; phpExtensionsTab(pane); }); } catch (e) { toast(e.message, "bad"); } }),
            ]))));
          pane.append(el("h3", { class: "section-title", text: "Enable / disable" }),
            el("p", { class: "dm-hint", text: "Turn loaded extensions on or off per mode. The web server reloads automatically." }),
            simpleTable(["Extension", ...d.sapis.map((s) => labels[s] || s)], d.modules.map((m) => row(el("code", { text: m.name }),
              ...d.sapis.map((s) => { const c = el("input", { type: "checkbox", class: "sf-switch" }); c.checked = m.enabled[s];
                c.onchange = async () => { c.disabled = true; try { await API.phpExtToggle(ver, m.name, s, c.checked); toast(`${m.name} ${c.checked ? "enabled" : "disabled"} (${s})`, "good"); } catch (e) { c.checked = !c.checked; toast(e.message, "bad"); } c.disabled = false; };
                return c; })))));
        } catch (e) { pane.innerHTML = ""; pane.append(el("p", { class: "empty", text: e.message })); }
      })();
    }

    function phpVersionsTab(pane) {
      pane.append(el("div", { class: "card" }, [
        el("h3", { text: "Websites (Apache)" }),
        ov.apache_available.length ? el("div", { class: "toolbar", style: "margin:8px 0 0" }, ov.apache_available.map((v) => btn(`PHP ${v}`, async () => {
          if (v === ov.apache) return;
          if (!confirmInline(`Switch Apache to PHP ${v}? Apache restarts; check your sites afterwards.`)) return;
          try { await API.phpApacheVersion(v); toast(`Apache now uses PHP ${v}`, "good"); load(); } catch (e) { toast(e.message, "bad"); }
        }, v === ov.apache ? "btn-primary" : ""))) : el("p", { class: "muted", text: "Apache has no PHP module installed." }),
      ]), el("div", { class: "card" }, [
        el("h3", { text: "Command line & cron (php)" }),
        el("div", { class: "toolbar", style: "margin:8px 0 0" }, ov.versions.filter((x) => x.sapis.includes("cli")).map((x) => btn(`PHP ${x.version}`, async () => {
          try { await API.phpSet(x.version); toast(`Command-line PHP → ${x.version}`, "good"); load(); } catch (e) { toast(e.message, "bad"); }
        }, x.version === ov.cli_default ? "btn-primary" : ""))),
      ]));
    }
    state.refreshHandler = load; load();
  }

  // ======================================================================
  //  Preferences
  // ======================================================================
  function viewPassword(root) {
    root.append(el("div", { class: "card" }, [
      el("h3", { text: "Change panel password" }),
      el("div", { style: "display:flex;flex-direction:column;gap:12px;max-width:380px" }, [
        labeledInput("pw-cur", "Current password", "", "", "password"),
        labeledInput("pw-new", "New password (min 8)", "", "", "password"),
        labeledInput("pw-new2", "Confirm new password", "", "", "password"),
        el("button", { class: "btn btn-primary", style: "align-self:flex-start", text: "Update password", onclick: async () => {
          const cur = $("#pw-cur").value, nw = $("#pw-new").value, nw2 = $("#pw-new2").value;
          if (nw !== nw2) { toast("Passwords don't match", "bad"); return; }
          try { await API.passwordChange(cur, nw); toast("Password updated", "good"); $("#pw-cur").value = $("#pw-new").value = $("#pw-new2").value = ""; }
          catch (e) { toast(e.message, "bad"); } } }),
      ]),
      el("p", { class: "muted", style: "margin-top:14px;font-size:12px", text: "Tip: also enable Two-Factor Authentication (Security → Two-Factor) for extra protection." }),
    ]));
  }
  function viewAccountPrefs(root) {
    const body = el("div", {}, el("div", { class: "loading", text: "Loading…" }));
    root.append(body);
    (async () => {
      const p = await API.prefs().catch(() => ({}));
      body.innerHTML = "";
      body.append(el("div", { class: "card" }, [
        el("h3", { text: "Account preferences" }),
        el("div", { style: "display:flex;flex-direction:column;gap:12px;max-width:380px" }, [
          labeledInput("ac-user", "Admin username", "", p.username || ""),
          el("label", { class: "muted", style: "display:flex;flex-direction:column;gap:6px;font-size:13px" }, ["Default theme",
            el("select", { id: "ac-theme" }, ["dark", "light"].map((t) => el("option", { value: t, text: t, ...(p.default_theme === t ? { selected: "selected" } : {}) })))]),
          el("button", { class: "btn btn-primary", style: "align-self:flex-start", text: "Save", onclick: async () => {
            try {
              const u = $("#ac-user").value.trim();
              if (u && u !== p.username) await API.renameUser(u);
              await API.prefsSet({ default_theme: $("#ac-theme").value });
              applyTheme($("#ac-theme").value); try { localStorage.setItem("aurora-theme", $("#ac-theme").value); } catch (e) {}
              toast("Saved", "good");
            } catch (e) { toast(e.message, "bad"); } } }),
        ]),
      ]));
    })();
  }
  function viewContact(root) {
    const body = el("div", {}, el("div", { class: "loading", text: "Loading…" }));
    root.append(body);
    (async () => {
      const p = await API.prefs().catch(() => ({}));
      body.innerHTML = "";
      body.append(el("div", { class: "card" }, [
        el("h3", { text: "Contact information" }),
        el("p", { class: "muted", style: "margin:0 0 12px", text: "Where the panel would send notifications (informational for now)." }),
        el("div", { style: "display:flex;gap:10px;max-width:440px" }, [
          el("input", { id: "ct-email", type: "email", placeholder: "you@example.com", value: p.contact_email || "", style: "flex:1" }),
          el("button", { class: "btn btn-primary", text: "Save", onclick: async () => { try { await API.prefsSet({ contact_email: $("#ct-email").value.trim() }); toast("Saved", "good"); } catch (e) { toast(e.message, "bad"); } } }),
        ]),
      ]));
    })();
  }
  // ---- About & Updates ----
  const FORUM_URL = "https://forums.raspberrypi.com/viewtopic.php?p=2388892";
  const GITHUB_URL = "https://github.com/opensourcewhcp/AuroraPanel";
  function viewAbout(root) {
    const body = el("div", {}, el("div", { class: "loading", text: "Loading…" }));
    root.append(body);
    const result = el("div");
    (async () => {
      let a;
      try { a = await API.about(); } catch (e) { body.innerHTML = ""; body.append(el("p", { class: "empty", text: e.message })); return; }
      body.innerHTML = "";
      const check = btn("Check for updates", async () => {
        check.disabled = true; result.innerHTML = ""; result.append(el("div", { class: "loading", text: "Asking aurora51.com…" }));
        try { showResult(await API.aboutCheck()); }
        catch (e) { result.innerHTML = ""; result.append(el("div", { class: "card net-warn" }, el("p", { text: e.message }))); }
        check.disabled = false;
      }, "btn-primary");
      const changes = el("div");
      const viewChanges = btn("View changes", async () => {
        if (changes.childNodes.length) { changes.innerHTML = ""; return; }  // toggle
        viewChanges.disabled = true; changes.append(el("div", { class: "loading", text: "Loading the change log…" }));
        try { showChanges(await API.aboutChangelog()); }
        catch (e) { changes.innerHTML = ""; changes.append(el("div", { class: "card net-warn" }, el("p", { text: e.message }))); }
        viewChanges.disabled = false;
      }, "btn-ghost");
      body.append(el("div", { class: "card about-card" }, [
        el("div", { class: "about-head" }, [
          el("span", { class: "about-logo" }, el("img", { src: "/img/logo-mark-128.png", alt: "AuroraPanel", width: "48", height: "48" })),
          el("div", {}, [el("h2", { text: "AuroraPanel" }), el("div", { class: "about-ver" }, [pill(a.label, "warn"), el("span", { class: "muted", text: ` released ${a.released}` })])]),
        ]),
        el("p", { class: "muted", text: "A free, open-source (MIT) control panel for the Raspberry Pi and Ubuntu / Debian servers. Found something odd? Please report it." }),
        kv([["Version", a.version], ["Installed in", a.install_dir],
          ["Website", el("a", { href: a.site, target: "_blank", rel: "noopener noreferrer", text: "aurora51.com ↗" })],
          ["Source", el("a", { href: GITHUB_URL, target: "_blank", rel: "noopener noreferrer", text: "github.com/opensourcewhcp/AuroraPanel ↗" })]]),
        el("div", { class: "toolbar", style: "margin:16px 0 0" }, [check, viewChanges,
          el("a", { class: "btn btn-sm btn-ghost", href: GITHUB_URL, target: "_blank", rel: "noopener noreferrer", text: "GitHub repository ↗" }),
          el("a", { class: "btn btn-sm btn-ghost", href: FORUM_URL, target: "_blank", rel: "noopener noreferrer", text: "Feedback on the Raspberry Pi Forums ↗" })]),
        el("div", { class: "about-privacy" }, [icon("lock", 14), el("span", { text: "The panel never contacts the internet on its own, it only asks aurora51.com for the latest version or the change log when you click one of these buttons." })]),
      ]), changes, result);

      function showChanges(c) {
        changes.innerHTML = "";
        changes.append(el("div", { class: "card about-changes" }, [
          el("div", { class: "net-card-h" }, [icon("info", 20), el("h3", { text: "What's changed" }), el("span", { style: "flex:1" }), pill(`you have ${c.label}`, "warn")]),
          ...(c.releases.length ? c.releases.map((rel) => el("div", { class: `about-rel${rel.newer ? " about-rel-new" : ""}` }, [
            el("h4", {}, [rel.label, " ", el("span", { class: "muted", text: rel.released ? `· ${rel.released}` : "" }), " ",
              rel.newer ? pill("new", "good") : rel.current ? pill("installed", "dim") : null].filter(Boolean)),
            el("ul", { class: "about-notes" }, rel.notes.map((n) => el("li", { text: n }))),
          ])) : [el("p", { class: "muted", text: "No releases listed yet." })]),
        ]));
      }

      // One-click update: the server downloads + verifies the release and a background
      // job installs it; the panel restarts, so poll until the new version answers.
      async function installUpdate(r, box) {
        if (!confirmInline(`Install ${r.latest_label} now?\n\nThe panel restarts during the update (about a minute). Your admin account, settings, VPNs and sites are kept, and the previous version is restored automatically if the new one doesn't start.`)) return;
        box.innerHTML = "";
        const pre = el("pre", { class: "log ax-log", text: "Downloading and verifying the release…", hidden: true });
        const title = el("h4", { text: `Installing ${r.latest_label}…` });
        // The orange bar follows the installer's milestones (the log has the details).
        const STEPS = [[/updating AuroraPanel/, 8, "Preparing"], [/Backing up/, 14, "Backing up the current version"], [/Copying the new files/, 22, "Copying the new files"],
          [/Checking system packages/, 32, "Checking system packages"], [/Setting up Python environment/, 42, "Setting up Python"], [/Dependencies installed/, 66, "Python packages installed"],
          [/Writing \/etc\/systemd/, 74, "Updating the service"], [/Service enabled/, 82, "Restarting the panel"], [/Waiting for AuroraPanel/, 88, "Waiting for the panel to start"],
          [/Panel is up|is installed/, 95, "New version running"]];
        const bar = el("div", { class: "ax-bar" }, el("span"));
        const stage = el("div", { class: "ax-stage" });
        const logBtn = el("button", { type: "button", class: "bk-mini", text: "Show log", onclick: () => { pre.hidden = !pre.hidden; logBtn.textContent = pre.hidden ? "Show log" : "Hide log"; } });
        const prog = el("div", { class: "ax-progress" }, [el("div", { class: "ax-prog-top" }, [stage, logBtn]), bar]);
        let pct = 3, label = "Downloading and verifying the release";
        const started = Date.now();
        const draw = (done) => {
          bar.firstChild.style.width = `${pct}%`;
          stage.innerHTML = "";
          stage.append(done ? el("span", { class: `bk-badge ${done === "ok" ? "good" : "bad"}`, text: done === "ok" ? "✓" : "!" }) : el("span", { class: "bk-spin" }),
            el("b", { text: label }), el("span", { class: "bk-pct", text: `${Math.floor(pct)}%` }),
            el("span", { class: "muted", text: ` · ${Math.floor((Date.now() - started) / 60000)}:${String(Math.floor((Date.now() - started) / 1000) % 60).padStart(2, "0")}` }));
        };
        box.append(title, prog, pre);
        try { await API.aboutUpdate(); }
        catch (e) { title.textContent = "Update not started"; prog.classList.add("bad"); label = e.message; draw("bad"); pre.textContent = e.message; return; }
        draw();
        const t = setInterval(async () => {
          try {
            const s = await API.aboutUpdateStatus();
            if (s.log.length) {
              pre.textContent = s.log.join("\n");
              for (const [rx, p, l] of STEPS) if (s.log.some((x) => rx.test(x)) && p > pct) { pct = p; label = l; }
            }
            pre.scrollTop = pre.scrollHeight;
            if (s.version === r.latest) {
              clearInterval(t); title.textContent = `Updated to ${r.latest_label}`;
              pct = 100; label = `Updated to ${r.latest_label}, reloading`; prog.classList.add("ok"); draw("ok");
              toast(`Updated to ${r.latest_label}, reloading`, "good");
              setTimeout(() => location.reload(), 1500);
              return;
            } else if (!s.running && s.log.some((l) => l.startsWith("✖"))) {
              clearInterval(t); title.textContent = "Update failed, the previous version was kept";
              prog.classList.add("bad"); label = "Update failed, the previous version was kept"; draw("bad");
              pre.hidden = false; logBtn.textContent = "Hide log";
              return;
            }
            draw();
          } catch (e) {
            // The panel is restarting into the new version: keep the bar moving gently.
            if (pct < 96) { pct = Math.max(pct, 88) + 0.5; label = "Panel restarting into the new version"; }
            draw();
            pre.textContent = pre.textContent.replace(/\n?… panel restarting$/, "") + "\n… panel restarting";
          }
          if (Date.now() - started > 6 * 60 * 1000) {
            clearInterval(t); title.textContent = "Still not done after 6 minutes";
            pre.textContent += "\nCheck it over SSH: sudo journalctl -u aurorapanel-update  (log: /var/lib/aurora/updates/update.log)";
          }
        }, 2000);
        state.cleanups.push(() => clearInterval(t));
      }

      function showResult(r) {
        result.innerHTML = "";
        if (!r.update_available) {
          result.append(el("div", { class: "card about-result" }, [el("div", { class: "net-card-h" }, [icon("shield", 20), el("h3", { text: "You're up to date" }), el("span", { style: "flex:1" }), pill(r.label, "good")]),
            el("p", { class: "muted", text: `The newest release is ${r.latest_label}${r.latest_released ? ` (${r.latest_released})` : ""}.` })]));
          return;
        }
        const cmd = el("pre", { class: "log", text: r.update_command || a.update_command });
        const progress = el("div");
        result.append(el("div", { class: "card about-update" }, [
          el("div", { class: "net-card-h" }, [icon("refresh", 20), el("h3", { text: `${r.latest_label} is available` }), el("span", { style: "flex:1" }), pill(`you have ${r.label}`, "warn")]),
          r.latest_released ? el("p", { class: "muted", text: `Released ${r.latest_released}.` }) : null,
          r.notes.length ? el("div", {}, [el("h4", { text: "What's new" }), el("ul", { class: "about-notes" }, r.notes.map((n) => el("li", { text: n })))]) : null,
          r.auto_update ? el("div", { class: "toolbar", style: "margin:14px 0 0" }, [
            btn(`Install ${r.latest_label}`, () => installUpdate(r, progress), "btn-primary"),
            el("span", { class: "muted", text: "Downloads from aurora51.com, checks the file's checksum, and installs it." })]) : null,
          progress,
          el("h4", { text: r.auto_update ? "Or update manually" : "How to update" }),
          el("p", { class: "muted", text: "Run this in the Terminal (Advanced → Terminal) or over SSH. It downloads the new version over this install and re-runs the installer, your admin account, settings, VPNs and sites are kept." }),
          cmd,
          el("div", { class: "toolbar", style: "margin:10px 0 0" }, [
            btn("Copy command", async () => toast(await copyText(cmd.textContent) ? "Command copied" : "Copy failed, select it manually", "good"), "btn-primary"),
            btn("Open Terminal", () => navigate("terminal"), "btn-ghost"),
            el("a", { class: "btn btn-sm btn-ghost", href: r.download, text: "Download zip" })]),
        ]));
      }
    })();
  }

  function viewLanguage(root) {
    root.append(el("div", { class: "card" }, [
      el("h3", { text: "Change language" }),
      el("p", { class: "muted", style: "margin:0 0 12px", text: "Interface language. Only English is bundled right now, more can be added." }),
      el("select", { id: "lang-sel", style: "max-width:220px", onchange: async () => { try { await API.prefsSet({ language: $("#lang-sel").value }); toast("Saved", "good"); } catch (e) {} } },
        [["en", "English"]].map(([v, t]) => el("option", { value: v, text: t }))),
    ]));
  }

  // ======================================================================
  //  Modal + inline confirm/prompt (no native dialogs)
  // ======================================================================
  function openModal(title, bodyNode, footButtons) {
    closeModal();
    // A click beside the window closes it only when there's nothing to lose (no fields to fill).
    // A form stays open and gives a small bump instead, ✕, Close or Esc close it. A press that
    // started inside (selecting text in a field, released outside) never counts as an outside click.
    let downInside = false;
    const backdrop = el("div", { class: "modal-backdrop", id: "modal",
      onmousedown: (e) => { downInside = e.target.id !== "modal"; },
      onclick: (e) => {
        if (e.target.id !== "modal" || downInside) return;
        const box = backdrop.querySelector(".modal");
        if (!box.querySelector("input:not([type=hidden]):not([type=checkbox]):not([type=radio]), textarea, select")) return closeModal();
        box.classList.remove("bump"); void box.offsetWidth; box.classList.add("bump");
      } }, [
      el("div", { class: "modal" }, [
        el("div", { class: "modal-head" }, [
          el("h3", { text: title }),
          el("button", { class: "btn btn-sm btn-ghost", text: "✕", onclick: closeModal }),
        ]),
        el("div", { class: "modal-body" }, bodyNode),
        el("div", { class: "modal-foot" }, [
          ...footButtons,
          el("button", { class: "btn", text: "Close", onclick: closeModal }),
        ]),
      ]),
    ]);
    document.body.appendChild(backdrop);
  }
  function closeModal() { const m = $("#modal"); if (m) m.remove(); }

  // Lightweight synchronous confirm/prompt using window dialogs where allowed,
  // falling back gracefully. (Served over http on the LAN, dialogs are fine.)
  function confirmInline(msg) { return window.confirm(msg); }
  function promptInline(msg, def) { return window.prompt(msg, def !== undefined ? def : ""); }

  document.addEventListener("keydown", (e) => { if (e.key === "Escape") closeModal(); });

  // ======================================================================
  //  Applications → WordPress one-click installer
  // ======================================================================
  const WP_LOGO = '<svg viewBox="0 0 24 24" width="34" height="34" fill="currentColor"><path d="M12 2a10 10 0 1 0 0 20 10 10 0 0 0 0-20zm-8.8 10c0-1.3.3-2.5.8-3.6l4.2 11.6A8.8 8.8 0 0 1 3.2 12zm8.8 8.8c-.9 0-1.7-.1-2.5-.4l2.6-7.7 2.7 7.4v.1c-.9.4-1.8.6-2.8.6zm1.2-12.9c.5 0 1-.1 1-.1.5-.1.4-.8-.1-.7 0 0-1.4.1-2.3.1-.9 0-2.3-.1-2.3-.1-.5 0-.5.7-.1.7 0 0 .4.1.9.1l1.3 3.6-1.9 5.6L6.5 7.9c.5 0 1-.1 1-.1.5-.1.4-.8-.1-.7 0 0-1.4.1-2.3.1h-.5A8.8 8.8 0 0 1 17.9 5.5h-.1c-.9 0-1.5.8-1.5 1.6 0 .7.4 1.3.9 2.1.3.6.7 1.3.7 2.4 0 .7-.3 1.6-.6 2.8l-.8 2.8-3.1-9.3zm3.2 11.8 2.7-7.8c.5-1.3.7-2.3.7-3.2l-.1-.9a8.8 8.8 0 0 1-3.3 11.9z"/></svg>';

  // ======================================================================
  //  App Installer: catalog → app page → install wizard (Softaculous-style)
  // ======================================================================
  const APPX = { cat: null, st: null, stAt: 0 };
  const KIND_LABEL = {
    cli: ["1-click setup", "good", "Fully set up here, admin account included."],
    web: ["Setup page", "warn", "Unpacked and given a database here; you finish in its own setup page."],
    static: ["Ready to use", "good", "Nothing to set up, it works right away."],
    composer: ["Composer", "dim", "Created with Composer, PHP's package manager."],
    unavailable: ["Not available", "bad", ""],
  };
  async function appCatalog() {
    if (!APPX.cat) APPX.cat = await API.appCatalog();
    return APPX.cat;
  }
  async function appStatus(force) {
    if (force || !APPX.st || Date.now() - APPX.stAt > 15000) { APPX.st = await API.appsStatus(); APPX.stAt = Date.now(); }
    return APPX.st;
  }
  function appTile(a, size) {
    const t = el("div", { class: `ax-tile ${size || ""}`, style: `--c:${a.color || "#ff7a1a"}` });
    if (a.id === "wordpress") t.innerHTML = WP_LOGO;
    else t.textContent = a.name.replace(/[^A-Za-z0-9 ]/g, "").split(/\s+/).map((w) => w[0]).join("").slice(0, 2).toUpperCase() || a.name[0];
    return t;
  }
  const appMine = (st, id) => (st ? st.installed.filter((i) => i.app === id) : []);

  function viewAppStore(root) {
    let q = "", cat = state.viewArg || "all";
    const hero = el("div", { class: "ax-hero" });
    const body = el("div", { class: "ax-body" });
    root.append(hero, body);
    hero.append(el("div", { class: "ax-hero-txt" }, [
      el("h2", {}, ["App Installer ", el("span", { class: "ax-spark", text: "✦" })]),
      el("p", { text: "Pick an app, choose where it lives, and AuroraPanel downloads the latest release, makes its database and sets it up, blogs, shops, forums, wikis, clouds and frameworks." }),
      el("div", { class: "wp-checks", id: "ax-checks" }, el("span", { class: "loading", style: "padding:0", text: "Checking PHP & MariaDB…" })),
    ]));
    const search = el("input", { type: "search", class: "ax-search", placeholder: "Search apps…  (WordPress, forum, wiki, cloud…)", oninput: (e) => { q = e.target.value.trim().toLowerCase(); draw(); } });
    hero.append(el("div", { class: "ax-search-wrap" }, [icon("search", 16), search]));
    let C = null, st = null;
    function draw() {
      if (!C) return;
      body.innerHTML = "";
      const mineCount = st ? st.installed.length : 0;
      const counts = {}; C.apps.forEach((a) => { counts[a.cat] = (counts[a.cat] || 0) + 1; });
      const rail = el("nav", { class: "ax-rail" }, [
        ...[{ id: "all", name: "All apps", icon: "apps" }, { id: "mine", name: "My apps", icon: "folder" }, ...C.categories].map((c) => {
          const n = c.id === "all" ? C.apps.length : c.id === "mine" ? mineCount : counts[c.id] || 0;
          if (!n && c.id !== "mine") return null;
          return el("button", { type: "button", class: `ax-cat${cat === c.id ? " active" : ""}`, onclick: () => {
            cat = c.id; try { history.replaceState(null, "", `#/appstore${cat === "all" ? "" : "/" + cat}`); } catch (e) {} state.viewArg = cat === "all" ? null : cat; draw();
          } }, [icon(c.icon, 15), el("span", { class: "ax-cat-name", text: c.name }), el("b", { text: String(n) })]);
        }).filter(Boolean)]);
      const main = el("div", { class: "ax-main" });
      body.append(rail, main);
      if (cat === "mine") { main.append(myApps(C, st)); return; }
      const match = (a) => !q || `${a.name} ${a.tagline} ${a.cat}`.toLowerCase().includes(q);
      const list = C.apps.filter((a) => (cat === "all" || a.cat === cat) && match(a));
      if (cat === "all" && !q) {
        const top = C.apps.filter((a) => a.popular);
        main.append(el("h3", { class: "ax-h", text: "Top apps" }), el("div", { class: "ax-grid top" }, top.map((a) => appCard(a, st))));
        // Categories flow side by side like shelves, so small ones don't leave half the page empty.
        const shelves = el("div", { class: "ax-shelves" });
        for (const c of C.categories) {
          const items = C.apps.filter((a) => a.cat === c.id);
          if (!items.length) continue;
          shelves.append(el("section", { class: "ax-shelf" }, [
            el("button", { type: "button", class: "ax-h ax-shelf-h", title: `Show only ${c.name}`, onclick: () => rail.querySelectorAll(".ax-cat").forEach((b) => { if (b.textContent.startsWith(c.name)) b.click(); }) },
              [icon(c.icon, 15), " ", c.name, el("span", { class: "ax-shelf-n", text: String(items.length) })]),
            el("div", { class: "ax-grid fit" }, items.map((a) => appCard(a, st)))]));
        }
        main.append(shelves);
      } else {
        const c = C.categories.find((x) => x.id === cat);
        main.append(el("h3", { class: "ax-h", text: q ? `${list.length} match${list.length === 1 ? "" : "es"}` : (c ? c.name : "") }));
        main.append(list.length ? el("div", { class: "ax-grid" }, list.map((a) => appCard(a, st))) : el("p", { class: "empty", text: "No app matches that." }));
      }
    }
    function appCard(a, st) {
      const [kl, kc, kd] = KIND_LABEL[a.kind];
      const mine = appMine(st, a.id).length;
      return el("div", { class: `ax-card${a.kind === "unavailable" ? " off" : ""}`, style: `--c:${a.color || "#ff7a1a"}` }, [
        el("div", { class: "ax-card-top" }, [el("div", { class: "ax-tile-wrap" }, [appTile(a),
            mine ? el("button", { type: "button", class: "ax-count", title: `${mine} installed, show them`, "aria-label": `${mine} installed`, text: String(mine), onclick: () => navigate("app", { arg: a.id }) }) : null]),
          el("div", { class: "ax-card-name" }, [el("b", { text: a.name }), el("span", { class: `pill ${kc}`, title: kd || a.why || "", text: kl })])]),
        el("p", { text: a.tagline }),
        el("div", { class: "ax-card-btns" }, [
          a.kind === "unavailable" ? el("span", { class: "muted ax-why", text: a.why }) :
            el("button", { class: "btn btn-sm btn-primary", onclick: (e) => { e.stopPropagation(); openAppWizard(a, () => draw()); } }, [icon("gear", 13), " Install"]),
          el("button", { class: "btn btn-sm btn-ghost", text: "Details", onclick: () => navigate("app", { arg: a.id }) }),
        ]),
      ]);
    }
    const load = () => guardedLoad(async () => {
      C = await appCatalog(); draw();
      st = await appStatus(true); draw();
      appChecks($("#ax-checks", hero), st);
    });
    state.refreshHandler = load; load();
  }

  function appChecks(host, st) {
    if (!host) return;
    host.innerHTML = "";
    const ok = (b, t, tip) => el("span", { class: `pill ${b ? "good" : "bad"}`, title: tip || "", text: `${b ? "✓" : "✕"} ${t}` });
    host.append(ok(!!st.php_bin, `PHP ${st.php_version || "missing"}`, st.php_bin ? "" : "Install Apache + PHP in System Applications"),
      ok(st.mysql, "MariaDB", st.mysql ? "" : "Install MariaDB in System Applications"),
      el("span", { class: "pill dim", text: `${st.installed.length} app${st.installed.length === 1 ? "" : "s"} installed` }));
  }

  function myApps(C, st) {
    const box = el("div");
    if (!st || !st.installed.length) {
      box.append(el("div", { class: "cw-empty" }, [icon("apps", 28), el("b", { text: "No apps installed yet" }), el("span", { class: "muted", text: "Pick one from the catalog, it takes a minute." })]));
      return box;
    }
    box.append(el("h3", { class: "ax-h", text: "My apps" }), installedList(st.installed, C, () => { APPX.stAt = 0; state.refreshHandler && state.refreshHandler(); }));
    return box;
  }

  function installedList(items, C, reload) {
    return el("div", { class: "wp-list" }, items.map((it) => {
      const a = C.apps.find((x) => x.id === it.app) || { id: it.app, name: it.app, color: "#888" };
      const open = it.url ? el("a", { class: "btn btn-sm", href: it.url + "/", target: "_blank", rel: "noopener" }, [icon("link", 12), " Open"]) : null;
      const admin = it.setup_url ? el("a", { class: "btn btn-sm btn-primary", href: it.setup_url, target: "_blank", rel: "noopener" }, [icon("wand", 12), " Finish setup"])
        : it.admin_url ? el("a", { class: "btn btn-sm", href: it.admin_url, target: "_blank", rel: "noopener" }, [icon("lock", 12), " Admin"]) : null;
      return el("div", { class: `wp-item ${it.exists ? "" : "gone"}` }, [
        appTile(a, "sm"),
        el("div", { class: "wp-item-main" }, [
          el("b", { text: it.url || it.path }),
          el("span", { class: "muted", html: `${esc(a.name)} · <code>${esc(it.path)}</code>${it.db ? ` · DB <code>${esc(it.db)}</code>` : ""}` }),
          el("span", { class: "dm-tags" }, [it.version && it.version !== "latest" ? el("span", { class: "pill good", text: "v" + it.version }) : null,
            it.detected ? el("span", { class: "pill dim", text: "found on disk" }) : null, !it.exists ? el("span", { class: "pill bad", text: "folder missing" }) : null,
            it.installed ? el("span", { class: "pill dim", text: new Date(it.installed * 1000).toLocaleDateString() }) : null]),
        ]),
        el("div", { class: "actions ax-item-btns" }, [open, admin,
          el("button", { class: "btn btn-sm btn-danger", onclick: async () => {
            if (!confirmInline(`Remove ${a.name} at ${it.url || it.path}?\n\nFiles are moved to /var/lib/aurora/trash (recoverable)${it.db ? ` and the database ${it.db} is DELETED` : ""}.`)) return;
            const rmSite = it.created_site && confirmInline("Also remove the site that was created for it?");
            try { const r = await API.appRemove2(it.path, true, !!rmSite); toast(`Removed · files kept in ${r.files_moved_to}`, "good"); reload(); } catch (e) { toast(e.message, "bad"); }
          } }, [icon("error", 12), " Remove"])]),
      ]);
    }));
  }

  function viewWordPress(root) { viewAppPage(root, "wordpress"); }
  function viewAppPageRoute(root) { viewAppPage(root, state.viewArg || "wordpress"); }

  function viewAppPage(root, id) {
    const load = () => guardedLoad(async () => {
      const C = await appCatalog();
      const a = C.apps.find((x) => x.id === id);
      root.innerHTML = "";
      if (!a) { root.append(el("div", { class: "cw-empty" }, [icon("error", 28), el("b", { text: "Unknown app" }), btn("← App Installer", () => navigate("appstore"))])); return; }
      const st = await appStatus(true);
      const vt = $("#view-title"); if (vt) vt.textContent = a.name;
      const [kl, kc, kd] = KIND_LABEL[a.kind];
      const ver = el("span", { class: "pill dim", text: a.kind === "composer" ? "latest via Composer" : "checking version…" });
      const installBtn = a.kind === "unavailable" ? null : el("button", { class: "btn btn-primary ax-go", style: `--c:${a.color}`, onclick: () => openAppWizard(a, load) },
        [el("span", { class: "ax-gear" }, icon("gear", 18)), el("span", { text: `Install ${a.name}` })]);
      root.append(
        el("button", { class: "btn btn-sm btn-ghost ax-back", onclick: () => navigate("appstore", { arg: a.cat }) }, [el("span", { html: "&larr;" }), " App Installer"]),
        el("div", { class: "ax-app-hero", style: `--c:${a.color || "#ff7a1a"}` }, [
          appTile(a, "lg"),
          el("div", { class: "ax-app-txt" }, [
            el("h2", { text: a.name }),
            el("p", { text: a.tagline }),
            el("div", { class: "wp-checks" }, [el("span", { class: `pill ${kc}`, title: kd, text: kl }), ver,
              a.db ? el("span", { class: "pill dim", text: "MariaDB database" }) : el("span", { class: "pill dim", text: "No database" }),
              ...(a.missing_exts || []).length ? [el("span", { class: "pill warn", title: "Installed automatically during setup", text: `+ PHP ${a.missing_exts.join(", ")}` })] : [],
              el("a", { class: "pill dim ax-site", href: a.site, target: "_blank", rel: "noopener noreferrer", text: "Website ↗" })]),
            a.kind === "unavailable" ? el("div", { class: "dm-note warn", style: "margin-top:14px" }, [icon("info", 15), el("span", { text: a.why })]) : el("p", { class: "dm-hint", text: kd }),
          ]),
          installBtn ? el("div", { class: "ax-app-cta" }, installBtn) : null,
        ]));
      const mine = appMine(st, a.id);
      root.append(el("div", { class: "ax-mine-head" }, [el("h2", { class: "section-title", text: `Your ${a.name} installs` }),
        el("span", { class: "grow" }), mine.length && installBtn ? el("button", { class: "btn btn-sm", onclick: () => openAppWizard(a, load) }, [icon("gear", 13), " Install another"]) : null]));
      root.append(mine.length ? installedList(mine, C, load)
        : el("div", { class: "cw-empty ax-empty" }, [appTile(a, "md"), el("b", { text: `No ${a.name} yet` }),
          el("span", { class: "muted", text: a.kind === "unavailable" ? a.why : "One click on Install and a minute later it's running." }),
          installBtn ? el("button", { class: "btn btn-primary", onclick: () => openAppWizard(a, load) }, [icon("gear", 13), ` Install ${a.name}`]) : null]));
      if (a.kind !== "composer" && a.kind !== "unavailable") {
        API.appLatest(a.id).then((r) => { ver.textContent = `${r.version && r.version !== "latest" ? "v" + r.version : "Latest release"}${r.size ? " · " + fmtBytes(r.size) : ""}`; ver.className = "pill good"; })
          .catch(() => { ver.textContent = "version check failed"; });
      }
    });
    state.refreshHandler = load; load();
  }

  // ---------------------------------------------------------------- wizard
  function openAppWizard(a, onDone) {
    const ex = $("#ax-wiz"); if (ex) ex.remove();
    const w = { mode: "local", name: a.id.replace(/[^a-z0-9]/g, ""), www: true, ssl: false, setup: true, subfolder: a.id.replace(/[^a-z0-9]/g, ""), host: location.hostname };
    let st = APPX.st, step = 0, job = null, timer = null, closed = false;
    // Clicking outside doesn't close it (too easy to lose what was typed), the box just nudges.
    const overlay = el("div", { class: "ax-wiz-back", id: "ax-wiz", onclick: (e) => {
      if (e.target !== overlay) return;
      sheet.classList.remove("nudge"); void sheet.offsetWidth; sheet.classList.add("nudge");
    } });
    const sheet = el("div", { class: "ax-wiz", style: `--c:${a.color || "#ff7a1a"}`, role: "dialog", "aria-label": `Install ${a.name}` });
    const steps = ["Where", "Details", "Install"];
    const stepper = el("div", { class: "ax-steps" });
    const content = el("div", { class: "ax-wiz-body" });
    const foot = el("div", { class: "ax-wiz-foot" });
    sheet.append(el("div", { class: "ax-wiz-head" }, [appTile(a, "sm"), el("div", {}, [el("h3", { text: `Install ${a.name}` }), el("span", { class: "muted", text: a.tagline })]),
      el("span", { class: "grow" }), el("button", { class: "btn btn-sm btn-ghost", "aria-label": "Close", text: "✕", onclick: () => close() })]), stepper, content, foot);
    overlay.append(sheet); document.body.append(overlay);
    const onKey = (e) => { if (e.key === "Escape") close(); };
    document.addEventListener("keydown", onKey);
    function close() {
      if (job && job.status === "running") toast(`${a.name} keeps installing in the background, you'll get a message when it's done`, "good");
      closed = true; overlay.remove(); document.removeEventListener("keydown", onKey);
      if (!(job && job.status === "running")) clearInterval(timer);
    }
    function drawSteps() {
      stepper.innerHTML = "";
      steps.forEach((s, i) => stepper.append(el("div", { class: `ax-step${i === step ? " on" : ""}${i < step ? " done" : ""}` }, [el("span", { text: i < step ? "✓" : String(i + 1) }), el("b", { text: s })]),
        i < steps.length - 1 ? el("i") : ""));
    }
    const inp = (key, ph, extra = {}) => el("input", { type: "text", placeholder: ph, value: w[key] == null ? "" : w[key], oninput: (e) => { w[key] = e.target.value.trim(); check(); }, ...extra });
    const lab = (l, i, hint) => el("label", { class: "cw-lbl" }, [l, i, hint ? el("span", { class: "dm-hint", text: hint }) : null]);
    const chk = (key, label) => { const c = el("input", { type: "checkbox", onchange: (e) => { w[key] = e.target.checked; check(); } }); c.checked = !!w[key]; return el("label", { class: "dm-check" }, [c, el("span", { html: label })]); };
    const preview = el("div", { class: "ax-preview" });
    let pvTimer = null, pvOk = false;
    function opts() {
      return { mode: w.mode, name: w.name, path: w.mode === "folder" || (w.mode === "local" && w.pathTouched) ? w.path : "", url: w.url, ip: w.ip, domain: w.domain,
        www: w.www, ssl: w.ssl, subdomain: w.subdomain, parent: w.parent, site: w.site, subfolder: w.mode === "existing" ? w.subfolder : "",
        overwrite: w.overwrite, host: w.host, setup: w.setup, title: w.title, admin_user: w.admin_user, admin_email: w.admin_email, admin_pass: w.admin_pass,
        hide_search: w.hide_search };
    }
    function check() {
      clearTimeout(pvTimer);
      preview.className = "ax-preview busy";
      pvTimer = setTimeout(async () => {
        try {
          const r = await API.appPreview(a.id, opts());
          pvOk = r.ok;
          preview.className = `ax-preview ${r.ok ? "ok" : "bad"}`;
          preview.innerHTML = "";
          if (r.path) preview.append(el("div", { class: "ax-pv-row" }, [icon("link", 14), el("b", { text: r.url + "/" })]), el("div", { class: "ax-pv-row muted" }, [icon("folder", 14), el("code", { text: r.path })]));
          if (r.error) preview.append(el("div", { class: "ax-pv-err" }, [icon("error", 14), el("span", { text: r.error })]));
        } catch (e) { pvOk = false; preview.className = "ax-preview bad"; preview.textContent = e.message; }
        drawFoot();
      }, 280);
    }
    const userSites = () => (st ? st.sites.filter((s) => !s.system && s.enabled) : []);
    function stepWhere() {
      const modes = [["local", "Local", `${location.hostname}/name`], ["ip", "IP address", "a site of its own"], ["new_domain", "Domain", "example.com, blog.test"],
        ["subdomain", "Subdomain", "blog.example.com"], ["existing", "Existing site", "into a site you have"], ["folder", "Custom folder", "any folder"]];
      const seg = el("div", { class: "ax-modes" }, modes.map(([m, l, d]) => el("button", { type: "button", class: m === w.mode ? "on" : "", onclick: () => { w.mode = m; render(); } }, [el("b", { text: l }), el("span", { text: d })])));
      const box = el("div", { class: "ax-where" });
      if (w.mode === "local") {
        const base = (st && st.folder_base) || "/var/www/html";
        const path = el("input", { type: "text", class: "cw-mono", value: w.pathTouched ? w.path : `${base}/${w.name || ""}`, oninput: (e) => { w.path = e.target.value.trim(); w.pathTouched = !!w.path; check(); } });
        const name = inp("name", "blog", { oninput: (e) => { w.name = e.target.value.trim().toLowerCase(); if (!w.pathTouched) path.value = `${base}/${w.name}`; check(); } });
        box.append(lab("Site name", el("div", { class: "dm-prefix" }, [el("span", { text: `${location.hostname}/` }), name]), "No domain needed, it answers on this Pi's address."),
          lab("Folder", path, "Created for you. Change it only if you want the files elsewhere."));
      }
      if (w.mode === "ip") box.append(lab("IP address", inp("ip", "192.168.0.50"), `Another address of this Pi. This Pi's own address (${location.hostname}) becomes ${location.hostname}/${w.name || a.id} instead.`));
      if (w.mode === "new_domain") box.append(lab("Domain", inp("domain", "myblog.com  or  blog.test")), chk("www", "Also answer on <b>www.</b>"), chk("ssl", "Turn on HTTPS now <span class='muted'>(self-signed, switch to Let's Encrypt in Domains)</span>"));
      if (w.mode === "subdomain") {
        const sites2 = userSites().filter((s) => !isIp(s.server_name));
        const sel = el("select", { onchange: (e) => { w.parent = e.target.value; check(); } }, sites2.map((s) => el("option", { value: s.server_name.replace(/^www\./, ""), text: s.server_name.replace(/^www\./, "") })));
        if (!w.parent && sites2.length) w.parent = sel.value; else if (w.parent) sel.value = w.parent;
        box.append(el("div", { class: "wp-row" }, [lab("Subdomain", inp("subdomain", "blog")), el("span", { class: "wp-dot", text: "." }), lab("Of domain", sites2.length ? sel : el("span", { class: "muted", text: "No domains yet, add one in Domains" }))]),
          chk("ssl", "Turn on HTTPS now (self-signed)"), el("p", { class: "dm-hint", text: "Add the subdomain in DNS (Zone Editor → A record) or your computer's hosts file." }));
      }
      if (w.mode === "existing") {
        const opts2 = [];
        (st ? st.sites.filter((s) => s.system && s.has_http && s.enabled) : []).forEach((s) => opts2.push([s.conf, `${location.hostname}, this Pi's address (${s.docroot})`]));
        (st ? st.folder_sites : []).forEach((f) => opts2.push([`folder:${f.name}`, `${location.hostname}/${f.name}, folder site (${f.path})`]));
        userSites().forEach((s) => opts2.push([s.server_name, `${s.server_name}, ${s.docroot}`]));
        const sel = el("select", { onchange: (e) => { w.site = e.target.value; check(); } }, opts2.map(([v, t]) => el("option", { value: v, text: t })));
        if (!w.site && opts2.length) w.site = sel.value; else if (w.site) sel.value = w.site;
        box.append(lab("Site", opts2.length ? sel : el("span", { class: "muted", text: "No sites yet" })),
          lab("Sub-folder", inp("subfolder", `${a.id}  →  example.com/${a.id}`), "Leave empty to install at the site's root."), chk("overwrite", "Install even if the folder already has files"));
      }
      if (w.mode === "folder") box.append(lab("Folder", inp("path", "/var/www/html/blog", { class: "cw-mono" })),
        lab("Its address (optional)", inp("url", `${location.hostname}/blog`), "Leave empty: AuroraPanel finds it, or, if nothing serves that folder yet, makes it a local site at /<folder name>."),
        chk("overwrite", "Install even if the folder already has files"));
      content.append(el("h4", { class: "ax-q", text: "Where should it live?" }), seg, box, preview);
      check();
    }
    function stepDetails() {
      const pw = el("input", { type: "password", placeholder: "at least 12 characters", autocomplete: "new-password", value: w.admin_pass || "", oninput: (e) => { w.admin_pass = e.target.value; meter(); drawFoot(); } });
      const pwMeter = el("div", { class: "wp-meter" }, el("span"));
      function meter() { const v = pw.value; let s = 0; if (v.length >= 12) s++; if (v.length >= 16) s++; if (/[A-Z]/.test(v) && /[a-z]/.test(v)) s++; if (/\d/.test(v)) s++; if (/[^A-Za-z0-9]/.test(v)) s++; pwMeter.firstChild.style.width = `${(s / 5) * 100}%`; pwMeter.className = `wp-meter s${s}`; }
      const gen = el("button", { type: "button", class: "btn btn-sm", onclick: async () => { try { const r = await API.appPassword(); pw.value = r.password; pw.type = "text"; w.admin_pass = r.password; eye.textContent = "Hide"; meter(); drawFoot(); } catch (e) { toast(e.message, "bad"); } } }, [icon("refresh", 12), " Generate"]);
      const eye = el("button", { type: "button", class: "btn btn-sm btn-ghost", text: "Show", onclick: () => { pw.type = pw.type === "password" ? "text" : "password"; eye.textContent = pw.type === "password" ? "Show" : "Hide"; } });
      const fields = el("div", { class: "wp-setup" }, [
        lab(a.cat === "forums" ? "Forum name" : a.cat === "wikis" ? "Wiki name" : "Site title", inp("title", `My ${a.name} site`)),
        el("div", { class: "dm-row2 wp-two" }, [a.fixed_user ? lab("Admin username", el("input", { type: "text", value: a.fixed_user, disabled: "" }), `${a.name} always names the first account “${a.fixed_user}”.`)
          : lab("Admin username", inp("admin_user", "not “admin”", { autocomplete: "off" })), lab("Admin email", inp("admin_email", "you@example.com", { type: "email" }))]),
        el("label", { class: "cw-lbl" }, ["Admin password", el("div", { class: "wp-pw" }, [pw, eye, gen]), pwMeter,
          el("span", { class: "dm-hint", text: a.strong_pw ? "Mix upper- and lower-case letters and a number. Save it in your password manager, AuroraPanel doesn't keep a copy." : "Save it in your password manager, AuroraPanel doesn't keep a copy." })]),
        a.id === "wordpress" ? chk("hide_search", "Ask search engines not to index this site (good for test sites)") : null,
      ]);
      content.append(el("h4", { class: "ax-q", text: a.kind === "cli" && a.admin !== false ? "Your site and admin account" : "Your site" }));
      if (a.kind === "cli" && a.admin !== false) {
        if (a.optional_setup) {
          content.append(el("div", { class: "dm-trow" }, [el("div", {}, [el("b", { text: "Set up the admin account now" }), el("span", { text: `Off = you'll finish ${a.name}'s own setup in the browser.` })]),
            sw(w.setup, (v) => { w.setup = v; fields.classList.toggle("dm-dim", !v); drawFoot(); })]));
          fields.classList.toggle("dm-dim", !w.setup);
        }
        content.append(fields); meter();
      } else {
        content.append(lab("Name (for your list)", inp("title", `My ${a.name}`)),
          el("div", { class: "dm-note" }, [icon("info", 15), el("span", { text: a.kind === "web" ? `${a.name} sets up its admin account in its own setup page. AuroraPanel downloads it, ${a.db ? "creates its database (you'll get the details to paste), " : ""}fixes permissions and opens the setup page for you.`
            : a.kind === "composer" ? `AuroraPanel runs Composer to create a fresh ${a.name} project${a.composer_lib ? " with a small demo page" : ""}. Edit it in the File Manager or over FTP/Git.`
            : a.first_login || `${a.name} is ready as soon as it's unpacked.` })]),
          a.first_login && a.kind !== "static" ? el("div", { class: "dm-note warn" }, [icon("lock", 15), el("span", { text: a.first_login })]) : "");
      }
    }
    function stepInstall() {
      const p = opts();
      const where = preview.querySelector("b") ? preview.querySelector("b").textContent : "";
      const sum = el("div", { class: "ax-summary" }, [
        appTile(a, "md"),
        el("div", {}, [el("b", { text: `${a.name} → ${where}` }), el("span", { class: "muted", text: `${preview.querySelector("code") ? preview.querySelector("code").textContent : ""}${a.db ? " · new MariaDB database" : ""}${p.setup && a.kind === "cli" && a.admin !== false ? ` · admin “${a.fixed_user || p.admin_user}”` : ""}` })]),
      ]);
      const bar = el("div", { class: "ax-bar" }, el("span"));
      const stage = el("div", { class: "ax-stage", text: "Ready when you are." });
      const checklist = el("ul", { class: "ax-check" });
      const STEPS = [["Check PHP & extensions", 0], [a.kind === "composer" ? "Create the project with Composer" : "Download the latest release", 8], [a.kind === "composer" ? "Composer packages" : "Unpack", 56],
        [a.db ? "Create the database" : "Prepare", 62], [`Set up ${a.name}`, 66], ["Permissions & Apache", 92]];
      const items = STEPS.map(([t]) => el("li", { text: t }));
      checklist.append(...items);
      const log = el("pre", { class: "log ax-log", hidden: true });
      const logBtn = el("button", { type: "button", class: "bk-mini", text: "Show log", onclick: () => { log.hidden = !log.hidden; logBtn.textContent = log.hidden ? "Show log" : "Hide log"; } });
      const result = el("div");
      content.append(el("h4", { class: "ax-q", text: "Ready to install" }), sum, el("div", { class: "ax-progress" }, [el("div", { class: "ax-prog-top" }, [stage, logBtn]), bar, checklist, log]), result);
      content._go = async (goBtn) => {
        goBtn.disabled = true; goBtn.textContent = "Installing…";
        try {
          const r = await API.appInstall(a.id, opts());
          job = { id: r.job, status: "running" };
          sheet.classList.add("busy");
          const backBtn = foot.firstChild;
          if (backBtn) backBtn.style.visibility = "hidden";  // no going back while it installs
          const t0 = Date.now();
          const tick = async () => {
            let j;
            try { j = await API.job(r.job); } catch (e) { return; }
            job.status = j.status;
            const pct = j.progress == null ? 2 : j.progress;
            bar.firstChild.style.width = `${Math.max(2, pct)}%`;
            const secs = (Date.now() - t0) / 1000;
            stage.innerHTML = "";
            stage.append(el("span", { class: "bk-spin" }), el("b", { text: j.stage || "Working…" }), el("span", { class: "bk-pct", text: `${Math.floor(pct)}%` }),
              el("span", { class: "muted", text: ` · ${Math.floor(secs / 60)}:${String(Math.floor(secs % 60)).padStart(2, "0")}` }));
            STEPS.forEach(([, at], i) => { const next = STEPS[i + 1] ? STEPS[i + 1][1] : 101; items[i].className = pct >= next || j.status === "done" ? "done" : pct >= at ? "on" : ""; });
            log.textContent = j.output || ""; log.scrollTop = log.scrollHeight;
            if (j.status === "running") return;
            clearInterval(timer); sheet.classList.remove("busy");
            APPX.stAt = 0;
            if (j.status === "done") {
              bar.parentNode.classList.add("ok"); bar.firstChild.style.width = "100%";
              stage.innerHTML = ""; stage.append(el("span", { class: "bk-badge good", text: "✓" }), el("b", { text: `${a.name} is installed` }), el("span", { class: "muted", text: ` · took ${Math.round(secs)}s` }));
              if (closed) toast(`${a.name} is installed, ${j.result.url}/`, "good");
              step = 3; drawSteps();  // every step ticked
              showDone(j.result); onDone && onDone();
              goBtn.replaceWith(el("button", { class: "btn btn-primary", text: "Done", onclick: close }));
            } else {
              bar.parentNode.classList.add("bad");
              const last = (j.output || "").trim().split("\n").filter(Boolean).pop() || "Install failed";
              stage.innerHTML = ""; stage.append(el("span", { class: "bk-badge bad", text: "!" }), el("b", { text: "Install failed" }));
              result.innerHTML = ""; result.append(el("div", { class: "ax-fail" }, [el("b", { text: last.replace(/^✖\s*/, "") }), el("span", { class: "muted", text: "Nothing was left half-installed. Fix the problem and try again." })]));
              log.hidden = false; logBtn.textContent = "Hide log";
              if (closed) toast(`${a.name} install failed, open the app page to retry`, "bad");
              goBtn.disabled = false; goBtn.textContent = "Try again";
              if (backBtn) backBtn.style.visibility = "";
            }
          };
          timer = setInterval(tick, 1000); tick();
        } catch (e) { toast(e.message, "bad"); goBtn.disabled = false; goBtn.textContent = `Install ${a.name}`; }
      };
      function showDone(e) {
        result.innerHTML = "";
        const copy = (v) => el("button", { type: "button", class: "bk-mini", text: "Copy", onclick: (ev) => { try { navigator.clipboard.writeText(v); ev.target.textContent = "Copied"; } catch (x) {} } });
        const rows = [];
        if (e.db && e.db_pass) rows.push(["Database", e.db], ["DB user", e.db_user], ["DB password", e.db_pass], ["DB host", "localhost"]);
        result.append(el("div", { class: "ax-done" }, [
          el("div", { class: "ax-done-glow" }),
          el("h3", { text: `${a.name} ${e.version && e.version !== "latest" ? e.version + " " : ""}is ready 🎉` }),
          el("div", { class: "wp-links" }, [
            el("a", { class: "btn btn-sm", href: e.url + "/", target: "_blank", rel: "noopener" }, [icon("link", 13), " Visit"]),
            e.setup_url ? el("a", { class: "btn btn-sm btn-primary", href: e.setup_url, target: "_blank", rel: "noopener" }, [icon("wand", 13), " Finish setup"]) : null,
            !e.setup_url && e.admin_url ? el("a", { class: "btn btn-sm btn-primary", href: e.admin_url, target: "_blank", rel: "noopener" }, [icon("lock", 13), " Open admin"]) : null]),
          rows.length ? el("div", { class: "ax-creds" }, [el("span", { class: "dm-hint", text: "The setup page asks for these, copy them now (the password isn't shown again):" }),
            ...rows.map(([k, v]) => el("div", {}, [el("span", { text: k }), el("code", { text: v }), copy(v)]))]) : null,
          ...(e.notes || []).map((n) => el("p", { class: "dm-hint", text: "• " + n })),
          /\.(test|local|localhost)(\/|:|$)/.test(e.url) ? el("p", { class: "dm-hint", text: "Local domain: add it to your computer's hosts file (Domains → 🔍 shows the exact line)." }) : null,
        ]));
      }
    }
    function drawFoot() {
      foot.innerHTML = "";
      const back = step > 0 && !(job && job.status !== "failed") ? el("button", { class: "btn", text: "← Back", onclick: () => { step--; render(); } }) : el("span");
      let next;
      if (step < 2) {
        const p = opts();
        let ok = step === 0 ? pvOk : true, why = "";
        if (step === 1 && a.kind === "cli" && a.admin !== false && (!a.optional_setup || w.setup)) {
          if (!a.fixed_user && !(p.admin_user || "").trim()) { ok = false; why = "Enter an admin username"; }
          else if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(p.admin_email || "")) { ok = false; why = "Enter the admin email"; }
          else if ((p.admin_pass || "").length < 12) { ok = false; why = "Password: 12+ characters"; }
        }
        next = el("button", { class: "btn btn-primary", disabled: ok ? null : "", title: why, text: why || "Next →", onclick: () => { step++; render(); } });
      } else if (!(job && job.status === "done")) {
        next = el("button", { class: "btn btn-primary ax-go", style: `--c:${a.color}`, onclick: (e) => content._go(e.currentTarget) }, [el("span", { class: "ax-gear" }, icon("gear", 16)), el("span", { text: `Install ${a.name}` })]);
      } else next = el("button", { class: "btn btn-primary", text: "Done", onclick: close });
      foot.append(back, el("span", { class: "grow" }), next);
    }
    function render() { drawSteps(); content.innerHTML = ""; [stepWhere, stepDetails, stepInstall][step](); drawFoot(); }
    (async () => { try { st = await appStatus(); } catch (e) {} render(); })();
  }

  // ---- Activity log, alerts, scheduled backups, updates, AutoSSL… (frontend/js/ops.js) ----
  let OPSV = null;
  function opsViews() {
    if (!OPSV && window.AuroraOps) {
      OPSV = window.AuroraOps({ el, $, icon, btn, pill, kv, field, sw, toast, API, navigate, state, openModal, closeModal, copyText, fmtBytes, ago, downloadText, esc,
        requireCard, jobPanel, ...(extraViews()._ui || {}), el });
    }
    return OPSV || {};
  }

  // ---- WAF, Dynamic DNS and Metrics views (frontend/js/extras.js) ----
  let EXTRAV = null;
  function extraViews() {
    if (!EXTRAV && window.AuroraExtras) {
      EXTRAV = window.AuroraExtras({ el, $, icon, btn, pill, kv, field, sw, toast, API, navigate, state, openModal, closeModal, copyText, fmtBytes, ago, downloadText, esc });
    }
    return EXTRAV || {};
  }

  // ---- Email views (frontend/js/mail.js, loaded before this file) ----
  let MAILV = null;
  function mailViews() {
    if (!MAILV && window.AuroraMail) {
      MAILV = window.AuroraMail({ el, $, icon, btn, pill, kv, field, sw, toast, API, navigate, state, openModal, closeModal, copyText,
        genPassword, fmtBytes, ago, downloadText, esc, requireCard, jobPanel });
    }
    return MAILV || {};
  }

  // ---- go ----
  boot();
  // Installable as an app (needs https with a trusted certificate; plain http just skips this).
  if ("serviceWorker" in navigator && window.isSecureContext) {
    navigator.serviceWorker.register("/sw.js").catch(() => {});
  }
})();
