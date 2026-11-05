/* Caddy Websites: set up and run sites on Caddy. Loaded before app.js. */
window.AuroraCaddy = (ui) => {
  "use strict";
  const { el, icon, btn, pill, field, toast, API, openModal, closeModal, navigate } = ui;
  const MODE = { php: "PHP", static: "Static files", proxy: "Reverse proxy (an app on a port)" };
  const HTTPS = { none: "Off", internal: "Caddy's own certificate (browsers warn)", auto: "Automatic, from a public certificate authority" };

  function siteForm(site, after) {
    const editing = !!site;
    const s = site || { mode: "php", https: "none", aliases: [] };
    const name = el("input", { type: "text", value: s.server_name || "", placeholder: "blog.example.com", disabled: editing });
    const aliases = el("input", { type: "text", value: (s.aliases || []).join(" "), placeholder: "www.blog.example.com" });
    const mode = el("select", {}, Object.entries(MODE).map(([v, t]) => el("option", { value: v, text: t })));
    mode.value = s.mode;
    const docroot = el("input", { type: "text", value: s.docroot || "", placeholder: "Leave empty for /var/www/<name>" });
    const proxy = el("input", { type: "text", value: s.proxy || "", placeholder: "http://127.0.0.1:3000" });
    const https = el("select", {}, Object.entries(HTTPS).map(([v, t]) => el("option", { value: v, text: t })));
    https.value = s.https;
    const custom = el("textarea", { rows: 4, placeholder: "Extra Caddy settings for this site. Checked with caddy validate before they apply." });
    custom.value = s.custom || "";
    const folderRow = field("Web folder", docroot), proxyRow = field("Forward to", proxy);
    const sync = () => { folderRow.style.display = mode.value === "proxy" ? "none" : ""; proxyRow.style.display = mode.value === "proxy" ? "" : "none"; };
    mode.onchange = sync;
    sync();
    const notice = el("div");
    openModal(editing ? `Edit ${s.server_name}` : "New website on Caddy", el("div", {}, [
      field("Domain or subdomain", name), field("Other names", aliases), field("Type", mode), folderRow, proxyRow, field("HTTPS", https), field("Extra settings", custom), notice,
    ]), [btn("Cancel", closeModal, "btn-ghost"), btn(editing ? "Save" : "Create site", async () => {
      const data = { server_name: name.value.trim(), aliases: aliases.value.split(/[\s,]+/).filter(Boolean), mode: mode.value, docroot: docroot.value.trim(), proxy: proxy.value.trim(), https: https.value, custom: custom.value };
      try {
        if (editing) await API.caddySiteSave(s.server_name, data); else await API.caddySiteCreate(data);
        closeModal();
        toast("Saved and checked", "good");
        after();
      } catch (e) { notice.replaceChildren(el("p", { class: "dm-note warn", style: "white-space:pre-wrap", text: e.message })); }
    }, "btn-primary")]);
  }

  function deleteDialog(s, after) {
    const files = el("input", { type: "checkbox" });
    openModal(`Remove ${s.server_name}?`, el("div", {}, [el("p", { text: "The site stops answering." }),
      s.mode === "proxy" ? "" : el("label", { style: "display:flex;gap:8px;align-items:center" }, [files, el("span", { text: `Also move ${s.docroot} to the recycle bin` })]),
    ]), [btn("Cancel", closeModal, "btn-ghost"), btn("Remove site", async () => {
      try { await API.caddySiteDelete(s.server_name, files.checked); closeModal(); toast("Removed", "good"); after(); } catch (e) { toast(e.message, "bad"); }
    }, "btn-danger")]);
  }

  function logsDialog(s) {
    const box = el("pre", { style: "max-height:50vh;overflow:auto;white-space:pre-wrap;font-size:12px", text: "Loading…" });
    openModal(`Visitors: ${s.server_name}`, box, [btn("Close", closeModal, "btn-ghost")]);
    API.caddySiteLogs(s.server_name).then((r) => { box.textContent = r.lines.length ? r.lines.join("\n") : `${r.path} has nothing in it yet.`; }).catch((e) => { box.textContent = e.message; });
  }

  function viewCaddy(root) {
    const body = el("div", {}, el("div", { class: "loading", text: "Loading…" }));
    root.append(el("div", { class: "em-head" }, [el("div", { class: "em-head-txt" }, [el("h2", { text: "Caddy Websites" }), el("p", { class: "muted", text: "Create and run websites on Caddy. Only the web server that's running can serve its sites." })])]), body);
    const act = (label, fn, cls = "btn-ghost") => btn(label, async () => {
      try { await fn(); } catch (e) { toast(e.message, "bad"); }
      load();
    }, cls);

    async function load() {
      let d;
      try { d = await API.caddyStatus(); } catch (e) {
        body.replaceChildren(el("p", { class: "dm-note warn", text: `Couldn't read Caddy's state: ${e.message}` }));
        return;
      }
      body.replaceChildren();
      if (!d.installed) {
        body.append(el("p", { class: "dm-note warn", text: "Caddy isn't installed. Install it under System Applications." }), btn("Open System Applications", () => navigate("sysapps"), "btn-primary"));
        return;
      }
      if (!d.active) {
        const other = d.nginx_active ? "Nginx" : d.apache_active ? "Apache" : "";
        body.append(el("div", { class: "dm-note warn", style: "margin-bottom:14px" }, [icon("error", 15), el("span", { text: `Caddy isn't running, so the sites below can't be reached.${other ? ` ${other} has port 80. Switching stops ${other} and the sites on it.` : ""}` }),
          act("Switch to Caddy", async () => { await API.sysappControl("caddy", "start", true); toast("Caddy is running", "good"); }, "btn-sm btn-primary")]));
      }
      if (!d.config.ok) body.append(el("pre", { class: "dm-note warn", style: "white-space:pre-wrap", text: `The Caddy configuration has an error:\n${d.config.output}` }));
      if (d.active) body.append(el("p", { class: "dm-note warn", text: "Nothing is checking requests to these sites for attacks: Caddy has no WAF here. For one, make Caddy listen on 127.0.0.1 and put an Nginx reverse proxy site with its WAF in front. Fail2ban and bans still apply." }));
      body.append(el("div", { class: "toolbar" }, [pill(d.active ? "running" : "stopped", d.active ? "good" : "bad"), el("span", { class: "muted", text: `Version ${d.version}${d.php_socket ? ", PHP ready" : ", PHP-FPM not found"}` }),
        btn("New website", () => siteForm(null, load), "btn-primary"), act("Reload", async () => { await API.caddyControl("reload"); toast("Reloaded", "good"); })]));
      if (!d.sites.length) {
        body.append(el("p", { class: "empty", text: "No websites on Caddy yet." }));
        return;
      }
      body.append(el("div", { class: "table-wrap mx-table-wrap" }, el("table", { class: "mx-table" }, [
        el("thead", {}, el("tr", {}, ["Site", "Type", "Folder or target", "HTTPS", "State", "Answers", ""].map((c) => el("th", { text: c })))),
        el("tbody", {}, d.sites.map((s) => el("tr", {}, [el("td", { text: s.server_name }), el("td", { text: s.mode }), el("td", { text: s.mode === "proxy" ? s.proxy : s.docroot }), el("td", { text: s.https }),
          el("td", {}, pill(s.enabled ? "on" : "off", s.enabled ? "good" : "dim")), el("td", { text: s.answer === null || s.answer === undefined ? "" : s.answer }),
          el("td", {}, el("div", { class: "toolbar" }, [btn("Edit", () => siteForm(s, load), "btn-sm btn-ghost"), act(s.enabled ? "Turn off" : "Turn on", () => API.caddySiteEnable(s.server_name, !s.enabled), "btn-sm btn-ghost"),
            btn("Visitors", () => logsDialog(s), "btn-sm btn-ghost"), btn("Remove", () => deleteDialog(s, load), "btn-sm btn-danger")])),
        ]))),
      ])));
    }
    load();
  }

  return { caddy: viewCaddy };
};
