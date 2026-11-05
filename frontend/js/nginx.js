/* Nginx Websites: set up and run sites on Nginx. Loaded before app.js. */
window.AuroraNginx = (ui) => {
  "use strict";
  const { el, icon, btn, pill, field, toast, API, openModal, closeModal, navigate } = ui;
  const MODE = { php: "PHP (WordPress and most apps)", static: "Static files", proxy: "Reverse proxy (an app on a port)" };

  function siteForm(site, after) {
    const editing = !!site;
    const s = site || { mode: "php", https: "none", max_body_mb: 64, aliases: [] };
    const name = el("input", { type: "text", value: s.server_name || "", placeholder: "blog.example.com", disabled: editing });
    const aliases = el("input", { type: "text", value: (s.aliases || []).join(" "), placeholder: "www.blog.example.com" });
    const mode = el("select", {}, Object.entries(MODE).map(([v, t]) => el("option", { value: v, text: t })));
    mode.value = s.mode;
    const docroot = el("input", { type: "text", value: s.docroot || "", placeholder: "Leave empty for /var/www/<name>" });
    const proxy = el("input", { type: "text", value: s.proxy || "", placeholder: "http://127.0.0.1:3000" });
    const https = el("select", {}, [el("option", { value: "none", text: "Off" }), el("option", { value: "selfsigned", text: "Self-signed certificate" })]);
    https.value = s.https;
    const force = el("input", { type: "checkbox" });
    force.checked = !!s.force_https;
    const body = el("input", { type: "number", min: 1, max: 10240, value: String(s.max_body_mb || 64) });
    const custom = el("textarea", { rows: 4, placeholder: "Extra Nginx settings for this site. Checked with nginx -t before they apply." });
    custom.value = s.custom || "";
    const folderRow = field("Web folder", docroot), proxyRow = field("Forward to", proxy);
    const sync = () => { folderRow.style.display = mode.value === "proxy" ? "none" : ""; proxyRow.style.display = mode.value === "proxy" ? "" : "none"; };
    mode.onchange = sync;
    sync();
    const notice = el("div");
    const save = btn(editing ? "Save" : "Create site", async () => {
      const data = { server_name: name.value.trim(), aliases: aliases.value.split(/[\s,]+/).filter(Boolean), mode: mode.value, docroot: docroot.value.trim(), proxy: proxy.value.trim(),
        https: https.value, force_https: force.checked, max_body_mb: Number(body.value), custom: custom.value };
      try {
        const r = editing ? await API.nginxSiteSave(s.server_name, data) : await API.nginxSiteCreate(data);
        closeModal();
        toast(editing ? "Saved and checked" : `Created${r.answer ? `: this server answers ${r.answer} for it` : ""}`, "good");
        after();
      } catch (e) { notice.replaceChildren(el("p", { class: "dm-note warn", style: "white-space:pre-wrap", text: e.message })); }
    }, "btn-primary");
    openModal(editing ? `Edit ${s.server_name}` : "New website on Nginx", el("div", {}, [
      field("Domain or subdomain", name), field("Other names", aliases), field("Type", mode), folderRow, proxyRow, field("HTTPS", https),
      el("label", { style: "display:flex;gap:8px;align-items:center;margin:8px 0" }, [force, el("span", { text: "Send visitors from HTTP to HTTPS" })]),
      field("Upload limit (MB)", body), field("Extra settings", custom), notice,
    ]), [btn("Cancel", closeModal, "btn-ghost"), save]);
  }

  function logsDialog(s) {
    const box = el("pre", { style: "max-height:50vh;overflow:auto;white-space:pre-wrap;font-size:12px" });
    const show = async (kind) => {
      box.textContent = "Loading…";
      try {
        const r = await API.nginxSiteLogs(s.server_name, kind);
        box.textContent = r.lines.length ? r.lines.join("\n") : `${r.path} has nothing in it yet.`;
      } catch (e) { box.textContent = e.message; }
    };
    openModal(`Logs: ${s.server_name}`, el("div", {}, [el("div", { class: "toolbar" }, [btn("Errors", () => show("error"), "btn-sm btn-ghost"), btn("Visitors", () => show("access"), "btn-sm btn-ghost")]), box]), [btn("Close", closeModal, "btn-ghost")]);
    show("error");
  }

  function deleteDialog(s, after) {
    const files = el("input", { type: "checkbox" });
    openModal(`Remove ${s.server_name}?`, el("div", {}, [
      el("p", { text: "The site stops answering. Its database, if it has one, isn't touched." }),
      s.mode === "proxy" ? "" : el("label", { style: "display:flex;gap:8px;align-items:center" }, [files, el("span", { text: `Also move ${s.docroot} to the recycle bin` })]),
    ]), [btn("Cancel", closeModal, "btn-ghost"), btn("Remove site", async () => {
      try { await API.nginxSiteDelete(s.server_name, files.checked); closeModal(); toast("Removed", "good"); after(); } catch (e) { toast(e.message, "bad"); }
    }, "btn-danger")]);
  }

  function viewNginx(root) {
    const body = el("div", {}, el("div", { class: "loading", text: "Loading…" }));
    root.append(el("div", { class: "em-head" }, [el("div", { class: "em-head-txt" }, [el("h2", { text: "Nginx Websites" }), el("p", { class: "muted", text: "Create and run websites on Nginx. Sites on the Domains page are Apache's; only the web server that's running can serve its sites." })])]), body);

    const act = (label, fn, cls = "btn-ghost") => btn(label, async () => {
      try { await fn(); } catch (e) { toast(e.message, "bad"); }
      load();
    }, cls);

    async function load() {
      let d;
      try { d = await API.nginxStatus(); } catch (e) {
        body.replaceChildren(el("p", { class: "dm-note warn", text: `Couldn't read Nginx's state: ${e.message}` }));
        return;
      }
      body.replaceChildren();
      if (!d.installed) {
        body.append(el("p", { class: "dm-note warn", text: "Nginx isn't installed. Install it under System Applications." }), btn("Open System Applications", () => navigate("sysapps"), "btn-primary"));
        return;
      }
      if (!d.active) {
        body.append(el("div", { class: "dm-note warn", style: "margin-bottom:14px" }, [icon("error", 15), el("span", { text: `Nginx isn't running, so the sites below can't be reached.${d.apache_active ? " Apache has port 80. Switching stops Apache and the sites and WAF protection that run on it." : ""}` }),
          act("Switch to Nginx", async () => { await API.sysappControl("nginx", "start", true); toast("Nginx is running", "good"); }, "btn-sm btn-primary")]));
      }
      if (!d.config.ok) body.append(el("pre", { class: "dm-note warn", style: "white-space:pre-wrap", text: `The Nginx configuration has an error:\n${d.config.output}` }));
      if (d.active) body.append(el("p", { class: "dm-note warn", text: "WAF Firewall runs inside Apache, so it isn't checking requests to Nginx sites. Fail2ban and bans still apply." }));
      body.append(el("div", { class: "toolbar" }, [
        pill(d.active ? "running" : "stopped", d.active ? "good" : "bad"), el("span", { class: "muted", text: `Version ${d.version}${d.php_socket ? ", PHP ready" : ", PHP-FPM not found"}` }),
        btn("New website", () => siteForm(null, load), "btn-primary"),
        act("Copy sites from Apache", async () => {
          const r = await API.nginxImport();
          toast(`Copied ${r.imported.length}${r.skipped.length ? `, skipped ${r.skipped.length}: ${r.skipped[0].why}` : ""}`, r.skipped.length ? "warn" : "good");
        }),
        act("Test config", async () => { const r = await API.nginxTest(); toast(r.ok ? "Configuration is fine" : r.output, r.ok ? "good" : "bad"); }),
        act("Reload", async () => { await API.nginxControl("reload"); toast("Reloaded", "good"); }), act("Restart", async () => { await API.nginxControl("restart"); toast("Restarted", "good"); }),
      ]));
      if (!d.default_site && !d.other_default) body.append(el("div", { class: "dm-note warn", style: "margin:10px 0" }, [icon("error", 15), el("span", { text: "Requests by IP address or an unknown name get Nginx's sample page, not /var/www/html, so folder sites aren't visible." }),
        act("Serve /var/www/html", async () => { await API.nginxDefault(); toast("Done", "good"); }, "btn-sm btn-primary")]));
      if (!d.sites.length) {
        body.append(el("p", { class: "empty", text: "No websites on Nginx yet. Create one, or copy your Apache sites." }));
        return;
      }
      body.append(el("div", { class: "table-wrap mx-table-wrap" }, el("table", { class: "mx-table" }, [
        el("thead", {}, el("tr", {}, ["Site", "Type", "Folder or target", "HTTPS", "State", "Answers", ""].map((c) => el("th", { text: c })))),
        el("tbody", {}, d.sites.map((s) => el("tr", {}, [
          el("td", {}, [el("a", { href: `http://${s.server_name}/`, target: "_blank", rel: "noopener", text: s.server_name }), s.aliases.length ? el("div", { class: "muted", text: s.aliases.join(", ") }) : ""]),
          el("td", { text: s.mode }), el("td", { text: s.mode === "proxy" ? s.proxy : s.docroot }), el("td", { text: s.https === "none" ? "off" : s.force_https ? "self-signed, forced" : "self-signed" }),
          el("td", {}, pill(s.enabled ? "on" : "off", s.enabled ? "good" : "dim")), el("td", { text: s.answer === null || s.answer === undefined ? "" : s.answer }),
          el("td", {}, el("div", { class: "toolbar" }, [btn("Edit", () => siteForm(s, load), "btn-sm btn-ghost"), act(s.enabled ? "Turn off" : "Turn on", () => API.nginxSiteEnable(s.server_name, !s.enabled), "btn-sm btn-ghost"),
            btn("Logs", () => logsDialog(s), "btn-sm btn-ghost"), btn("Remove", () => deleteDialog(s, load), "btn-sm btn-danger")])),
        ]))),
      ])));
      if (d.other_configs.length) body.append(el("p", { class: "muted", text: `Other Nginx config files, left alone: ${d.other_configs.join(", ")}` }));
    }
    load();
  }

  return { nginx: viewNginx };
};
