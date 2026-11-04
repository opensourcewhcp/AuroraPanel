/* AuroraPanel, Cloud Apps (AWS, Google Cloud, Azure) and Third-party Apps (Google Drive, Google Photos).
   Loaded before app.js; app.js calls window.AuroraCloud(ui) once with its helpers (and extras.js's). */
window.AuroraCloud = (ui) => {
  "use strict";
  const { el, icon, btn, field, toast, API, navigate, state, openModal, closeModal, copyText, fmtBytes, ago,
    pageHead, empty, call, armed, seg, LS, requireCard, jobPanel } = ui;

  const PROVIDER_VIEW = { aws: "cloudaws", gcp: "cloudgcp", azure: "cloudazure" };
  const tone = (s) => {
    const v = String(s || "").toLowerCase();
    if (/^(running|available|active|ready|succeeded|runnable|online|deployed)/.test(v)) return "good";
    if (/(stop|deallocat|terminat|fail|error|suspend|delet)/.test(v)) return "bad";
    return v ? "warn" : "dim";
  };
  const status = (s) => (s ? el("span", { class: `pill ${tone(s)}`, text: s }) : null);
  const ext = (href, text, cls) => el("a", { class: `btn btn-sm ${cls || "btn-ghost"}`, href, target: "_blank", rel: "noopener noreferrer" }, [icon("link", 13), ` ${text}`]);
  const input = (attrs) => el("input", { class: "cl-input", autocomplete: "off", spellcheck: "false", ...attrs });
  const loading = () => el("div", { class: "loading", text: "Loading…" });
  const fail = (box, e) => { box.innerHTML = ""; box.append(el("p", { class: "empty", text: e.message || String(e) })); };

  async function waitJob(jobId) {
    for (;;) {
      let j;
      try { j = await API.job(jobId); } catch (e) { return null; }
      if (j.status !== "running") return j;
      await new Promise((r) => setTimeout(r, 1500));
    }
  }

  // ======================================================================
  //  Two-pane copier: this server on the left, the cloud or Google on the right
  // ======================================================================
  function transferPane(opts) {
    // opts: { remoteName, list(path) -> {path, entries}, push(local, remote), pull(local, remote), jp, startPath, pushTarget(path) -> remote|Error }
    let lpath = LS.get("cl.local", ""), rpath = opts.startPath || "", lsel = null, rsel = null, lres = null, rres = null;
    const lbox = el("div", { class: "cl-list" }), rbox = el("div", { class: "cl-list" });
    const lcrumb = el("div", { class: "cl-crumb" }), rcrumb = el("div", { class: "cl-crumb" });
    const pushB = el("button", { class: "btn btn-primary cl-go", disabled: "", onclick: () => go("push") }, [el("span", { text: "Push" }), icon("chevron", 14)]);
    const pullB = el("button", { class: "btn btn-primary cl-go", disabled: "", onclick: () => go("pull") }, [el("span", { class: "cl-flip" }, icon("chevron", 14)), el("span", { text: "Pull" })]);
    const hint = el("p", { class: "dm-hint cl-hint", text: "Pick a file or folder on one side, open the folder it should go to on the other, then Push or Pull. Nothing is ever deleted." });
    const extra = el("div", { class: "cl-extra" });

    function row(e, selected, onpick, onopen) {
      const r = el("button", { type: "button", class: `cl-row${selected ? " on" : ""}`, title: e.detail || e.name,
        onclick: () => onpick(e), ondblclick: () => e.dir && onopen(e) }, [
        el("span", { class: "cl-ico" }, icon(e.dir ? "folder" : "listing", 15)),
        el("span", { class: "cl-name", text: e.name }),
        el("span", { class: "cl-meta muted", text: e.dir ? (e.detail || "") : e.size != null ? fmtBytes(e.size) : "" }),
        e.dir ? el("span", { class: "cl-open", title: "Open", onclick: (ev) => { ev.stopPropagation(); onopen(e); } }, icon("chevron", 13)) : null,
      ]);
      return r;
    }
    function crumbs(box, parts, onjump, rootLabel) {
      box.innerHTML = "";
      box.append(el("button", { type: "button", class: "cl-cr", text: rootLabel, onclick: () => onjump("") }));
      let acc = "";
      parts.forEach((p) => { acc = acc ? `${acc}/${p}` : p; const to = acc; box.append(el("span", { class: "muted", text: "/" }), el("button", { type: "button", class: "cl-cr", text: p, onclick: () => onjump(to) })); });
    }
    async function loadLocal(path) {
      lbox.innerHTML = ""; lbox.append(loading());
      try { lres = await API.filesList(path); } catch (e) { if (path) return loadLocal(""); return fail(lbox, e); }
      lpath = lres.cwd; LS.set("cl.local", lpath); lsel = null; drawLocal();
    }
    function drawLocal() {
      lcrumb.innerHTML = "";
      lcrumb.append(el("span", { class: "cl-cr-path", text: lres.cwd }));
      if (lres.parent) lcrumb.prepend(el("button", { type: "button", class: "cl-cr", title: "Up one folder", onclick: () => loadLocal(lres.parent) }, el("span", { class: "cl-upi" }, icon("chevron", 13))));
      lbox.innerHTML = "";
      const ents = lres.entries.filter((e) => !e.is_hidden).map((e) => ({ name: e.name, dir: e.is_dir, size: e.size, path: e.path }));
      if (!ents.length) lbox.append(el("p", { class: "empty", text: "This folder is empty" }));
      ents.forEach((e) => lbox.append(row(e, lsel && lsel.path === e.path, (x) => { lsel = lsel && lsel.path === x.path ? null : x; drawLocal(); buttons(); }, (x) => loadLocal(x.path))));
      buttons();
    }
    async function loadRemote(path) {
      rbox.innerHTML = ""; rbox.append(loading());
      try { rres = await opts.list(path); } catch (e) { return fail(rbox, e); }
      rpath = rres.path || ""; rsel = null; drawRemote();
    }
    function drawRemote() {
      crumbs(rcrumb, rpath ? rpath.split("/") : [], loadRemote, opts.remoteName);
      rbox.innerHTML = "";
      if (!rres.entries.length) rbox.append(el("p", { class: "empty", text: rpath ? "This folder is empty" : "Nothing here yet" }));
      rres.entries.forEach((e) => {
        const full = rpath ? `${rpath}/${e.name}` : e.name;
        rbox.append(row(e, rsel && rsel.full === full, (x) => { rsel = rsel && rsel.full === full ? null : { ...x, full }; drawRemote(); }, () => loadRemote(full)));
      });
      if (rres.more) rbox.append(el("p", { class: "dm-hint", text: "Showing the first 5,000 items." }));
      extra.innerHTML = "";
      if (opts.extra) { const x = opts.extra(rpath, buttons); if (x) extra.append(x); }
      buttons();
    }
    function buttons() {
      const t = opts.pushTarget ? opts.pushTarget(rpath) : rpath;
      pushB.disabled = !(lsel && rpath !== undefined && !(t instanceof Error) && (rpath || opts.pushAtRoot));
      pushB.title = t instanceof Error ? t.message : !lsel ? "Pick a file or folder on this server" : !rpath && !opts.pushAtRoot ? `Open a folder in ${opts.remoteName} first` : `Copy ${lsel.name} into ${opts.remoteName}/${t}`;
      pullB.disabled = !(rsel && opts.pull);
      pullB.title = rsel ? `Copy ${rsel.name} into ${lpath}` : `Pick a file or folder in ${opts.remoteName}`;
    }
    async function go(dir) {
      let r;
      try {
        if (dir === "push") {
          const t = opts.pushTarget ? opts.pushTarget(rpath) : rpath;
          if (t instanceof Error) throw t;
          r = await opts.push(lsel.path, t);
        } else {
          r = await opts.pull(lpath, rsel.dir ? `${rsel.full}/` : rsel.full);
        }
      } catch (e) { toast(e.message, "bad"); return; }
      opts.jp.run(r.job, dir === "push" ? `Pushing ${lsel.name}` : `Pulling ${rsel.name}`);
      const j = await waitJob(r.job);
      if (j && j.status === "done") toast(dir === "push" ? "Pushed" : "Pulled", "good");
      if (dir === "push") loadRemote(rpath); else loadLocal(lpath);
    }
    const node = el("div", { class: "cl-xfer" }, [
      el("div", { class: "card cl-pane" }, [el("div", { class: "cl-pane-h" }, [icon("disk", 15), el("b", { text: "This server" })]), lcrumb, lbox]),
      el("div", { class: "cl-mid" }, [pushB, pullB]),
      el("div", { class: "card cl-pane" }, [el("div", { class: "cl-pane-h" }, [icon("t_cloud", 15), el("b", { text: opts.remoteName }), el("span", { class: "grow" }),
        btn("Refresh", () => loadRemote(rpath), "btn-ghost")]), rcrumb, extra, rbox]),
    ]);
    loadLocal(lpath); loadRemote(rpath);
    return el("div", {}, [node, hint]);
  }

  // ======================================================================
  //  Cloud Apps → Overview
  // ======================================================================
  async function viewCloud(root) {
    root.append(pageHead("Cloud Apps", "Manage Amazon Web Services, Google Cloud and Microsoft Azure from this server. The servers, databases and computing run in the cloud, this Pi sends the commands through each provider's official command-line tool.", []));
    const body = el("div", {}, loading());
    root.append(body);
    let d;
    try { d = await API.cloud(); } catch (e) { return fail(body, e); }
    body.innerHTML = "";
    body.append(el("div", { class: "cl-cards" }, d.providers.map((p) => el("button", { type: "button", class: "card cl-prov", onclick: () => navigate(PROVIDER_VIEW[p.id]) }, [
      el("div", { class: "cl-prov-h" }, [el("span", { class: "cl-badge" }, icon("t_cloud", 22)), el("div", {}, [el("h3", { text: p.name }),
        el("p", { class: "muted mx-small", text: p.connected ? (p.account.identity || "Connected") : p.installed ? "Not connected yet" : "Command-line tool not installed" })])]),
      el("div", { class: "cl-prov-f" }, [el("span", { class: `pill ${p.connected ? "good" : p.installed ? "warn" : "dim"}`, text: p.connected ? "Connected" : p.installed ? "Ready to connect" : "Set up" }),
        el("span", { class: "grow" }), el("span", { class: "muted mx-small", text: "Open" }), icon("chevron", 14)]),
    ]))));
    const svc = d.providers[0].services;
    body.append(el("div", { class: "card mx-card" }, [el("div", { class: "mx-card-h" }, [el("h3", { text: "The same job on each cloud" })]),
      el("table", { class: "table cl-table" }, [
        el("thead", {}, el("tr", {}, [el("th", { text: "What for" }), ...d.providers.map((p) => el("th", { text: p.short }))])),
        el("tbody", {}, svc.map((s, i) => el("tr", {}, [el("td", { text: s.label }), ...d.providers.map((p) => el("td", { text: p.services[i].product }))]))),
      ]),
      el("p", { class: "dm-hint", text: "The match between providers is approximate. Each page lists what you have, starts and stops virtual servers, and copies files to and from storage." })]));
    body.append(el("div", { class: "card mx-card" }, [el("div", { class: "mx-card-h" }, [el("h3", { text: "Ways this Pi can manage the cloud" })]),
      el("ul", { class: "cl-ways" }, [
        ["Here, in Cloud Apps", "Connect an account once, then list, start, stop and copy files from these pages."],
        ["Command-line tools", "The AWS CLI and Google Cloud CLI have 64-bit ARM builds, and the Azure CLI comes from Debian. Each provider page installs its tool with one click."],
        ["Python and the APIs", "Automate checks, collect data and run tasks on a schedule with Cron Jobs."],
        ["SSH", "Sign in to your cloud Linux servers from the Terminal page."],
        ["The provider's web console", "Each provider page links straight to it."],
      ].map(([t, x]) => el("li", {}, [el("b", { text: t }), el("span", { class: "muted", text: x })])) )]));
    body.append(el("div", { class: "cl-cards" }, d.providers.map((p) => freeCard(p))));
  }

  function freeCard(p) {
    return el("div", { class: "card mx-card cl-free" }, [el("div", { class: "mx-card-h" }, [el("h3", { text: `${p.short} free options` }), el("span", { class: "grow" }), ext(p.free.url, "Details")]),
      el("ul", { class: "cl-ways" }, p.free.items.map(([t, x]) => el("li", {}, [el("b", { text: t }), el("span", { class: "muted", text: x })]))),
      el("p", { class: "dm-hint", text: "Free amounts have limits, and anything beyond them is billed. Check the provider's page for the current terms." })]);
  }

  // ======================================================================
  //  Cloud Apps → one provider
  // ======================================================================
  const HOWTO = {
    aws: ["Open the AWS console, then IAM, Users, Create user (for example aurora-panel).",
      "Give it only what it needs, for example AmazonEC2FullAccess and AmazonS3FullAccess, or ReadOnlyAccess to look without changing anything.",
      "Open the user, Security credentials, Create access key, choose Command Line Interface, and copy both values here."],
    gcp: ["Open the Google Cloud console, then IAM & Admin, Service Accounts, Create service account.",
      "Give it a role, for example Compute Admin and Storage Admin, or Viewer to look without changing anything.",
      "Open the account, Keys, Add key, Create new key, JSON. Paste the downloaded file here."],
    azure: ["In the Azure portal open Microsoft Entra ID, App registrations, New registration (for example aurora-panel).",
      "In the app open Certificates & secrets, New client secret, and copy its Value.",
      "In your subscription open Access control (IAM), Add role assignment, give the app Contributor (or Reader), and for files also Storage Blob Data Contributor."],
  };
  const AWS_REGIONS = ["us-east-1", "us-east-2", "us-west-1", "us-west-2", "ca-central-1", "eu-west-1", "eu-west-2", "eu-west-3", "eu-central-1", "eu-central-2", "eu-north-1", "eu-south-1",
    "ap-south-1", "ap-southeast-1", "ap-southeast-2", "ap-northeast-1", "ap-northeast-2", "ap-northeast-3", "sa-east-1", "me-central-1", "af-south-1"];

  function connectForm(p, done) {
    const f = {};
    let fields;
    if (p.id === "aws") {
      f.access_key_id = input({ placeholder: "AKIA…" });
      f.secret_access_key = input({ type: "password", placeholder: "40 characters" });
      f.region = el("select", { class: "em-select" }, AWS_REGIONS.map((r) => el("option", { value: r, text: r })));
      fields = [field("Access key ID", f.access_key_id), field("Secret access key", f.secret_access_key), field("Default region", f.region, "Where new things go and what the lists show first")];
    } else if (p.id === "gcp") {
      f.key_json = el("textarea", { class: "cl-input cl-key", rows: 6, spellcheck: "false", placeholder: '{ "type": "service_account", "project_id": … }' });
      const file = el("input", { type: "file", accept: ".json,application/json", onchange: async () => { if (file.files[0]) f.key_json.value = await file.files[0].text(); } });
      f.project = input({ placeholder: "Taken from the key when left empty" });
      fields = [field("Service account key (JSON)", f.key_json), el("label", { class: "cl-file" }, [icon("upload", 14), el("span", { text: "Or choose the downloaded .json file" }), file]),
        field("Project ID", f.project)];
    } else {
      f.tenant_id = input({ placeholder: "Directory (tenant) ID" });
      f.client_id = input({ placeholder: "Application (client) ID" });
      f.client_secret = input({ type: "password", placeholder: "Client secret value" });
      f.subscription_id = input({ placeholder: "Optional, the default subscription is used otherwise" });
      fields = [field("Directory (tenant) ID", f.tenant_id), field("Application (client) ID", f.client_id), field("Client secret", f.client_secret), field("Subscription ID", f.subscription_id)];
    }
    const go = el("button", { class: "btn btn-primary", text: `Connect ${p.short}` });
    go.onclick = async () => {
      const body = Object.fromEntries(Object.entries(f).map(([k, v]) => [k, v.value]));
      go.disabled = true; go.textContent = "Checking the account…";
      try { await API.cloudConnect(p.id, body); toast(`${p.short} connected`, "good"); done(); }
      catch (e) { toast(e.message, "bad"); }
      finally { go.disabled = false; go.textContent = `Connect ${p.short}`; }
    };
    return el("div", { class: "card mx-card" }, [
      el("div", { class: "mx-card-h" }, [el("h3", { text: `Connect your ${p.name} account` })]),
      el("div", { class: "cl-connect" }, [
        el("ol", { class: "cl-steps" }, HOWTO[p.id].map((t) => el("li", { text: t }))),
        el("div", { class: "cl-form" }, [...fields, el("p", { class: "dm-hint", text: "Kept on this server only, readable by root, and never shown again or written to the Activity Log." }), el("div", { class: "toolbar" }, [go])]),
      ]),
    ]);
  }

  function viewProvider(pid) {
    return async function (root) {
      const body = el("div", {}, loading());
      const head = el("div");
      root.append(head, body);
      const jp = jobPanel(root);
      let tab = LS.get(`cl.${pid}.tab`, "vms");
      async function load() {
        let p;
        try { p = await API.cloudProvider(pid); } catch (e) { return fail(body, e); }
        head.innerHTML = "";
        head.append(pageHead(p.name, p.connected ? `Signed in as ${p.account.identity}` : "Connect an account to manage it from this server.",
          [ext(p.console, "Open the console"), p.connected ? armed("Disconnect", "Click again to sign this server out", () => call(() => API.cloudDisconnect(pid), `${p.short} disconnected`, load), "btn-ghost") : null]));
        body.innerHTML = "";
        if (!p.installed) {
          const host = el("div");
          body.append(host, freeCard(p));
          try {
            const st = await API.requires([p.component]);
            host.append(requireCard([st.components[p.component]], p.name, false, load));
          } catch (e) { fail(host, e); }
          return;
        }
        if (!p.connected) { body.append(connectForm(p, load), freeCard(p)); return; }
        const a = p.account;
        const facts = [["Account", a.identity], a.account_id ? ["Account ID", a.account_id] : null, a.region ? ["Region", a.region] : null, a.project ? ["Project", a.project] : null,
          a.subscription_name ? ["Subscription", `${a.subscription_name} (${a.subscription})`] : null, ["Connected", ago(a.connected)], p.version ? ["Tool", p.version] : null].filter(Boolean);
        body.append(el("div", { class: "card mx-card cl-acct" }, [
          el("div", { class: "cl-facts" }, facts.map(([k, v]) => el("div", {}, [el("span", { class: "muted", text: k }), el("b", { text: v })]))),
          el("div", { class: "cl-term" }, [el("span", { class: "muted mx-small", text: "Same sign-in in the Terminal: put this in front of a command" }),
            el("div", { class: "cl-term-row" }, [el("code", { text: p.shell_env }), btn("Copy", () => copyText(p.shell_env), "btn-ghost")])]),
        ]));
        const panel = el("div");
        body.append(el("div", { class: "cl-tabs" }, seg(p.services.map((s) => [s.id, s.product]), tab, (v) => { tab = v; LS.set(`cl.${pid}.tab`, v); show(); })), panel);
        const show = () => {
          panel.innerHTML = "";
          const s = p.services.find((x) => x.id === tab) || p.services[0];
          panel.append(el("p", { class: "muted cl-sub", text: `${s.label}: ${s.product}` }));
          if (s.id === "storage") {
            panel.append(transferPane({ remoteName: s.product, jp,
              list: (path) => API.cloudBrowse(pid, path),
              push: (local, remote) => API.cloudTransfer(pid, "push", local, remote),
              pull: (local, remote) => API.cloudTransfer(pid, "pull", local, remote),
              pushTarget: (path) => (pid === "azure" && path && !path.includes("/") ? new Error("Open a container inside the storage account first") : path) }));
            return;
          }
          const box = el("div", { class: "card em-pad0" }, loading());
          panel.append(box);
          listItems(pid, s, box);
        };
        show();
      }
      load();
    };
  }

  async function listItems(pid, s, box) {
    let d;
    try { d = await API.cloudItems(pid, s.id); } catch (e) { return fail(box, e); }
    box.innerHTML = "";
    if (!d.items.length) {
      box.append(empty("t_cloud", `No ${s.product} yet`, "Nothing in this account and region. Create one in the provider's console.", ext(d.console, "Open the console")));
      return;
    }
    box.append(el("table", { class: "table cl-table" }, [
      el("thead", {}, el("tr", {}, [el("th", { text: "Name" }), el("th", { text: "State" }), el("th", { text: "Details" }), el("th", {})])),
      el("tbody", {}, d.items.map((it) => el("tr", {}, [
        el("td", {}, el("b", { text: it.name })),
        el("td", {}, status(it.status)),
        el("td", { class: "muted", text: it.detail || "" }),
        el("td", { class: "cl-act" }, (it.actions || []).map((a) => a === "start"
          ? btn("Start", () => call(() => API.cloudVm(pid, it.id, "start"), null, (r) => { toast(r.message, "good"); setTimeout(() => listItems(pid, s, box), 4000); }), "btn-ghost")
          : armed("Stop", "Click again to stop it", () => call(() => API.cloudVm(pid, it.id, "stop"), null, (r) => { toast(r.message, "good"); setTimeout(() => listItems(pid, s, box), 4000); }), "btn-ghost"))),
      ]))),
    ]));
    box.append(el("div", { class: "toolbar cl-foot" }, [btn("Refresh", () => { box.innerHTML = ""; box.append(loading()); listItems(pid, s, box); }, "btn-ghost"), el("span", { class: "grow" }), ext(d.console, "Manage in the console")]));
  }

  // ======================================================================
  //  Third-party Apps → Overview, Google Drive, Google Photos
  // ======================================================================
  const SVC_VIEW = { drive: "gdrive", photos: "gphotos" };

  async function viewConnect(root) {
    root.append(pageHead("Third-party Apps", "Connect online services to this server and copy files between them: back up a folder to Google Drive, bring a Drive folder down to a website, or put photos into a Google Photos album.", []));
    const body = el("div", {}, loading());
    root.append(body);
    let d;
    try { d = await API.connectors(); } catch (e) { return fail(body, e); }
    body.innerHTML = "";
    body.append(el("div", { class: "cl-cards" }, d.services.map((s) => {
      const mine = d.accounts.filter((a) => a.service === s.id);
      return el("button", { type: "button", class: "card cl-prov", onclick: () => navigate(SVC_VIEW[s.id]) }, [
        el("div", { class: "cl-prov-h" }, [el("span", { class: "cl-badge" }, icon(s.icon, 22)), el("div", {}, [el("h3", { text: s.name }), el("p", { class: "muted mx-small", text: s.about })])]),
        el("div", { class: "cl-prov-f" }, [el("span", { class: `pill ${mine.length ? "good" : "dim"}`, text: mine.length ? `${mine.length} connected` : "Not connected" }),
          el("span", { class: "grow" }), el("span", { class: "muted mx-small", text: mine.length ? "Open" : "Connect" }), icon("chevron", 14)]),
      ]);
    })));
    if (d.accounts.length) {
      body.append(el("div", { class: "card mx-card" }, [el("div", { class: "mx-card-h" }, [el("h3", { text: "Connected accounts" })]),
        el("table", { class: "table cl-table" }, [el("tbody", {}, d.accounts.map((a) => el("tr", {}, [
          el("td", {}, el("b", { text: a.label })), el("td", { text: a.name }), el("td", { class: "muted", text: a.email || "" }), el("td", { class: "muted", text: `connected ${ago(a.created)}` }),
          el("td", { class: "cl-act" }, btn("Open", () => navigate(SVC_VIEW[a.service], { arg: a.id }), "btn-ghost")),
        ])))])]));
    }
  }

  function signInModal(svc, done) {
    const label = input({ placeholder: svc.name, maxlength: 60 });
    const cid = input({ placeholder: "…apps.googleusercontent.com" });
    const csec = input({ type: "password", placeholder: "Client secret" });
    const needOwn = svc.id === "photos";
    const own = needOwn
      ? el("div", { class: "cl-own" }, [el("b", { text: "Your own Google app (required for Google Photos)" }),
        el("p", { class: "dm-hint", text: "Google blocks the shared app for Photos, so it takes five minutes in the Google Cloud console, once:" }),
        el("ol", { class: "cl-steps" }, [
          el("li", {}, ["Open ", el("a", { href: "https://console.cloud.google.com/projectcreate", target: "_blank", rel: "noopener noreferrer", text: "console.cloud.google.com" }), " and create a project (any name)."]),
          el("li", {}, ["APIs & Services, Library: enable the ", el("a", { href: "https://console.cloud.google.com/apis/library/photoslibrary.googleapis.com", target: "_blank", rel: "noopener noreferrer", text: "Photos Library API" }), "."]),
          el("li", { text: "Google Auth Platform: Get started, choose External, give the app a name and your email. Under Audience add your own Google address as a test user, or press Publish app so the access doesn't expire after 7 days." }),
          el("li", { text: "Data access, Add or remove scopes: add photoslibrary.appendonly, photoslibrary.readonly.appcreateddata and photoslibrary.edit.appcreateddata." }),
          el("li", { text: "Clients, Create client, type Desktop app. Copy its client ID and secret into the two fields below." }),
        ]),
        field("Client ID", cid), field("Client secret", csec)])
      : el("details", { class: "cl-own" }, [el("summary", { text: "Use my own Google app (optional)" }),
        el("p", { class: "dm-hint", text: "Without one, the sign-in uses rclone's shared Google app, which works but is slower when many people use it. To make your own: Google Cloud console, APIs & Services, enable the Google Drive API, then Google Auth Platform, Clients, Create client, type Desktop app." }),
        field("Client ID", cid), field("Client secret", csec)]);
    const paste = el("textarea", { class: "cl-input", rows: 3, spellcheck: "false", placeholder: "http://127.0.0.1:53682/?state=…&code=…" });
    const step1 = el("div", { class: "cl-step" }, [field("Name", label, "Shown on these pages, for example Family photos or Work drive"), own]);
    const step2 = el("div", { class: "cl-step", hidden: "" }, [
      el("ol", { class: "cl-steps" }, [
        el("li", { text: "A Google tab opened. Sign in and allow access." }),
        el("li", { text: "Google then opens a page on 127.0.0.1 that can't load. That is expected." }),
        el("li", { text: "Copy that page's whole address from the address bar and paste it below." }),
      ]),
      el("p", { class: "dm-hint cl-again" }),
      field("Address from the browser", paste)]);
    let session = null;
    const go = el("button", { class: "btn btn-primary", text: "Sign in with Google" });
    go.onclick = async () => {
      if (!session) {
        if (needOwn && !(cid.value.trim() && csec.value.trim())) { toast("Fill in your Google app's client ID and secret first", "bad"); cid.focus(); return; }
        const tab = window.open("about:blank", "_blank");
        go.disabled = true; go.textContent = "Starting…";
        try {
          const r = await API.connectStart(svc.id, cid.value, csec.value, label.value);
          session = r.session;
          if (tab) tab.location.href = r.url;
          step2.querySelector(".cl-again").replaceChildren(el("span", { text: "No tab opened? " }), el("a", { href: r.url, target: "_blank", rel: "noopener noreferrer", text: "Open the Google sign-in" }));
          step1.hidden = true; step2.hidden = false; go.textContent = "Finish"; paste.focus();
        } catch (e) { if (tab) tab.close(); toast(e.message, "bad"); go.textContent = "Sign in with Google"; }
        finally { go.disabled = false; }
        return;
      }
      go.disabled = true; go.textContent = "Connecting…";
      try { const a = await API.connectFinish(session, paste.value); session = null; closeModal(); toast(`${a.label} connected`, "good"); done(a); }
      catch (e) { toast(e.message, "bad"); go.textContent = "Finish"; }
      finally { go.disabled = false; }
    };
    openModal(`Connect ${svc.name}`, el("div", { class: "cl-modal" }, [step1, step2]), [go]);
    const m = document.querySelector("#modal");
    if (m) {
      const obs = new MutationObserver(() => { if (!document.body.contains(m)) { obs.disconnect(); if (session) API.connectCancel(session).catch(() => {}); } });
      obs.observe(document.body, { childList: true });
    }
  }

  function viewService(sid) {
    return async function (root) {
      const head = el("div"), body = el("div", {}, loading());
      root.append(head, body);
      const jp = jobPanel(root);
      let pick = typeof state.viewArg === "string" ? state.viewArg : LS.get(`cl.${sid}.acct`, "");
      async function load() {
        let d;
        try { d = await API.connectors(); } catch (e) { return fail(body, e); }
        const svc = d.services.find((s) => s.id === sid);
        const mine = d.accounts.filter((a) => a.service === sid);
        const acct = mine.find((a) => a.id === pick) || mine[0];
        head.innerHTML = "";
        head.append(pageHead(svc.name, svc.about, [d.rclone && (sid !== "photos" || d.photos_ok) ? btn(mine.length ? "Connect another" : "Connect", () => signInModal(svc, (a) => { pick = a.id; LS.set(`cl.${sid}.acct`, a.id); load(); }), mine.length ? "btn-ghost" : "btn-primary") : null]));
        body.innerHTML = "";
        if (!d.rclone) {
          const host = el("div");
          body.append(host);
          try { const st = await API.requires(["rclone"]); host.append(requireCard([st.components.rclone], svc.name, false, load)); } catch (e) { fail(host, e); }
          return;
        }
        if (sid === "photos" && !d.photos_ok) {
          const host = el("div");
          body.append(el("div", { class: "dm-note warn" }, [icon("info", 16), el("span", { text: `This server has rclone ${d.rclone_version || "(unknown version)"}. Google retired the access it asks for in March 2025 and blocks the sign-in ("This app is blocked"). Update rclone to the current release first.` })]), host);
          try { const st = await API.requires(["rclone-new"]); host.append(requireCard([st.components["rclone-new"]], svc.name, false, load)); } catch (e) { fail(host, e); }
          return;
        }
        if (sid === "photos") {
          body.append(el("div", { class: "dm-note warn" }, [icon("info", 16), el("span", { text: "Google only lets apps see the photos and albums they uploaded themselves (since March 2025). Pushing works for all your photos and videos. Pulling brings back what this server uploaded." })]));
        }
        if (!acct) {
          body.append(el("div", { class: "card" }, empty(svc.icon, `Connect ${svc.name}`, "Sign in with Google once. The panel keeps the access on this server only, and you can disconnect it here or in your Google account at any time.",
            btn("Connect", () => signInModal(svc, (a) => { pick = a.id; load(); }), "btn-primary"))));
          return;
        }
        LS.set(`cl.${sid}.acct`, acct.id);
        const sel = el("select", { class: "em-select mx-narrow", onchange: () => { pick = sel.value; load(); } }, mine.map((a) => el("option", { value: a.id, text: a.email ? `${a.label} (${a.email})` : a.label })));
        sel.value = acct.id;
        body.append(el("div", { class: "card mx-card cl-acct" }, [el("div", { class: "cl-acct-row" }, [
          mine.length > 1 ? sel : el("div", {}, [el("b", { text: acct.label }), acct.email ? el("span", { class: "muted", text: ` · ${acct.email}` }) : null]),
          el("span", { class: "muted mx-small", text: `connected ${ago(acct.created)}${acct.own_client ? " · your own Google app" : ""}` }),
          el("span", { class: "grow" }),
          btn("Rename", () => {
            const n = input({ value: acct.label, maxlength: 60 });
            openModal("Rename connection", field("Name", n), [el("button", { class: "btn btn-primary", text: "Save", onclick: () => call(() => API.connectRename(acct.id, n.value), "Renamed", () => { closeModal(); load(); }) })]);
          }, "btn-ghost"),
          armed("Disconnect", "Click again to remove this connection", () => call(() => API.connectRemove(acct.id), null, (r) => {
            toast("Disconnected. You can also remove the access in your Google account.", "good"); window.open(r.revoke, "_blank", "noopener"); pick = ""; load();
          }), "btn-ghost"),
        ])]));
        const albumName = input({ placeholder: "New or existing album name", maxlength: 120 });
        body.append(transferPane({ remoteName: svc.name, jp, pushAtRoot: sid === "drive",
          list: (path) => API.connectBrowse(acct.id, path),
          push: (local, remote) => API.connectTransfer(acct.id, "push", local, remote),
          pull: (local, remote) => API.connectTransfer(acct.id, "pull", local, remote),
          extra: sid === "photos" ? (path, refresh) => { albumName.oninput = refresh; return path === "album" ? el("div", { class: "cl-album" }, [field("Push into album", albumName, "Pick photos or a folder on the left, type an album name, then Push")]) : null; } : null,
          pushTarget: sid === "photos" ? (path) => {
            if (path === "upload" || /^album\/[^/]+$/.test(path)) return path;
            if (path === "album") return albumName.value.trim() ? `album/${albumName.value.trim().replace(/\//g, "-")}` : new Error("Type an album name first");
            return new Error("Open upload, or album and type an album name");
          } : null }));
      }
      load();
    };
  }

  return { cloud: viewCloud, cloudaws: viewProvider("aws"), cloudgcp: viewProvider("gcp"), cloudazure: viewProvider("azure"),
    connect: viewConnect, gdrive: viewService("drive"), gphotos: viewService("photos") };
};
