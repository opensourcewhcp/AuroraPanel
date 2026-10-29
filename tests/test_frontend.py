"""Frontend: every script parses, and the API helpers point at routes that exist."""
import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest

from backend.app import app

JS = sorted((Path(__file__).resolve().parent.parent / "frontend" / "js").glob("*.js"))


@pytest.mark.skipif(not shutil.which("node"), reason="Node.js not installed")
@pytest.mark.parametrize("path", JS, ids=lambda p: p.name)
def test_js_parses(path):
    r = subprocess.run(["node", "--check", str(path)], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr


def test_api_js_routes_exist():
    api = (Path(__file__).resolve().parent.parent / "frontend" / "js" / "api.js").read_text(encoding="utf-8")
    routes = [re.compile("^" + re.sub(r"\{[^}]+\}", "[^/]+", r.path) + "$") for r in app.routes if hasattr(r, "path")]
    used = set()
    for m in re.finditer(r"[\"'`](/api/[^\"'`?]*)", api):
        path = re.sub(r"\$\{[^}]+\}", "x", m.group(1)).rstrip("/")
        if path:
            used.add(path)
    missing = sorted(p for p in used if not any(rx.match(p) for rx in routes))
    assert not missing, f"api.js calls routes the backend doesn't have: {missing}"


def test_login_401_detail_reaches_the_login_form():
    """2FA sign-in: /api/login answers 401 "otp_required" to ask for the code. The fetch wrapper must pass
    that detail on as the error message (1.0.4–1.1.7 replaced every 401 with "Not authenticated", so the
    code field never appeared and owners with 2FA were locked out)."""
    api = (Path(__file__).resolve().parent.parent / "frontend" / "js" / "api.js").read_text(encoding="utf-8")
    block = api[api.index("res.status === 401"):api.index("err.status = 401")]
    assert "detail" in block and "res.json()" in block
    login = (Path(__file__).resolve().parent.parent / "frontend" / "js" / "app.js").read_text(encoding="utf-8")
    assert 'err.message === "otp_required"' in login


FRONT = Path(__file__).resolve().parent.parent / "frontend"


def test_about_page_proposes_server_updates_beside_the_panel_version():
    """Preferences → About & Updates: the server's apt updates (security first) sit beside the panel's own
    version, with one click to install them, a switch for nightly security updates, and a way to the
    Updates page or Crontab; every kept version can be put back from one picker; "up to date" is a
    notice that slides in at the right instead of another card."""
    app_js = (FRONT / "js" / "app.js").read_text(encoding="utf-8")
    about = app_js[app_js.index("function viewAbout("):app_js.index("function viewLanguage(")]
    for needle in ("API.updates()", "API.updatesInstall(", "API.updatesRefresh()", 'API.updatesAuto(true, "security"',
                   'navigate("cron")', 'navigate("updates")', "API.aboutRollback(", "about-back-prev",
                   "popNotice({ title: \"You're up to date\""):
        assert needle in about, needle
    assert "card about-result" not in about  # the old inline "you're up to date" card is gone
    assert "function popNotice(" in app_js and '"aria-label": "Close"' in app_js
    css = (FRONT / "css" / "style.css").read_text(encoding="utf-8")
    for cls in (".about-grid {", ".about-col {", ".about-srv.bad", ".about-back-row {", ".pop-notice {", ".pop-notice.out", "@keyframes popOut"):
        assert cls in css, cls


def test_dashboard_tool_tiles_keep_one_line_per_tool():
    """All tools: every group uses the same column width and a tool's name never wraps (the old 200px
    columns left ~110px for the label, so "Manage Databases" broke onto two lines next to one-liners)."""
    css = (FRONT / "css" / "style.css").read_text(encoding="utf-8")
    last = css.rindex(".tile-grid { grid-template-columns: repeat(")
    assert re.search(r"minmax\((2[3-9]\d|[3-9]\d\d)px, 1fr\)", css[last:last + 200]), "tile columns too narrow"
    rule = css[css.index(".tile-grid .tile-label {"):]
    rule = rule[:rule.index("}")]
    assert "white-space: nowrap" in rule and "text-overflow: ellipsis" in rule


def test_dashboard_all_tools_header_keeps_reset_layout_on_the_right():
    """Dashboard: "All tools" and "Reset layout" share one header row between the cards and the tool
    panels (title left, button right, padded like the panel titles) instead of a lone button above the cards."""
    app_js = (FRONT / "js" / "app.js").read_text(encoding="utf-8")
    css = (FRONT / "css" / "style.css").read_text(encoding="utf-8")
    assert 'class: "dash-section-row" }, [el("h2", { class: "section-title dash-section", text: "All tools" }), resetBtn]' in app_js
    assert 'class: "dash-tools"' not in app_js and ".dash-tools" not in css
    rule = css[css.index(".dash-section-row {"):]
    rule = rule[:rule.index("}")]
    assert "justify-content: space-between" in rule and "padding: 0 20px" in rule


def test_applications_section_opens_on_an_overview_of_everything_installed():
    """Applications: the section lands on an Overview that lists every installed thing (App Installer apps,
    Docker apps, WordPress sites) with a way to open and manage each, plus the doors to add more. The
    duplicate "WordPress" tab is gone (the page stays at #/wordpress and highlights App Installer)."""
    html = (FRONT / "index.html").read_text(encoding="utf-8")
    nav = html[html.index('<div class="nav-group">Applications</div>'):html.index('<div class="nav-group">Software</div>')]
    views = re.findall(r'data-view="([a-z]+)"', nav)
    assert views == ["apphub", "appstore", "dockerapps", "wptoolkit"], views
    app_js = (FRONT / "js" / "app.js").read_text(encoding="utf-8")
    assert "apphub: viewAppHub," in app_js and 'apphub: "Applications",' in app_js
    assert 'view === "app" || view === "wordpress" ? "appstore"' in app_js
    hub = app_js[app_js.index("function viewAppHub("):app_js.index("function viewAppPage(")]
    for needle in ("appStatus(true)", "API.docker()", "appCatalog()", 'navigate("appstore")', '"dockerapps"', '"wptoolkit"', 'navigate("wordpress")', '{ arg: "mine" }', "Installed on this server", "need a look", "Nothing installed yet", "Finish setup", "const dkTrouble = "):
        assert needle in hub, needle
    assert '{ label: "Applications Overview", icon: "apps", view: "apphub" }' in app_js
    css = (FRONT / "css" / "style.css").read_text(encoding="utf-8")
    for cls in (".ah-hero {", ".ah-stat {", ".ah-start {", ".ah-go {", ".ah-attn {", ".ah-chip.active"):
        assert cls in css, cls


def test_docker_container_actions_queue_up_with_a_panel_at_the_right():
    """Docker: Stop/Start/Restart clicks are queued and run one at a time; a slide-in panel at the right shows
    each container as "In queue to stop", then "Stopping…", then "Stopped" (or the error)."""
    ops_js = (FRONT / "js" / "ops.js").read_text(encoding="utf-8")
    assert "const dkQueue = {" in ops_js and "In queue to ${j.action}" in ops_js and '"Working on your containers"' in ops_js
    assert "dkQueue.add({ key: `${c.name}:${action}`" in ops_js
    assert 'act(c, "stop")' in ops_js and 'act(c, "start")' in ops_js and 'act(c, "restart")' in ops_js
    assert "API.dockerAction(c.name, action)" in ops_js
    assert 'class: "pop-notice dk-queue"' in ops_js  # same slide-in look as the "You're up to date" notice
    css = (FRONT / "css" / "style.css").read_text(encoding="utf-8")
    assert ".dk-q.working .dk-q-dot" in css and "@keyframes dkSpin" in css


def test_local_site_dialog_lets_you_pick_html_www_or_any_folder():
    """Domains: a local site's folder is chosen with a switch: inside the web root (html, highlighted), a folder of
    its own next to the other sites (www), or any folder typed by hand; the path is built from that choice."""
    app_js = (FRONT / "js" / "app.js").read_text(encoding="utf-8")
    seg = app_js[app_js.index('id="nf-where"'):app_js.index("function viewDomainManage(")]
    for needle in ('["html", ', '["www", ', '["custom", ', 'class: "nf-hl"', "API.folderSiteCreate(n, folderPath())",
                   "Enter the folder for the site", "Pick a folder"):
        assert needle in seg, needle
    css = (FRONT / "css" / "style.css").read_text(encoding="utf-8")
    assert ".nf-hl" in css and ".dm-prefix span[hidden]" in css


def test_interface_languages_ship_as_dictionaries():
    """Change Language: a dictionary per language, applied where text is made; English stays the fallback."""
    app_js = (FRONT / "js" / "app.js").read_text(encoding="utf-8")
    langs = re.findall(r'\["([a-zA-Z-]+)", "[^"]+", "[^"]+"\]', app_js[app_js.index("const LANGS = ["):app_js.index("const I18N = ")])
    assert langs[0] == "en" and {"es", "de", "ru", "uk", "pl", "fr", "it", "pt-BR", "tr", "zh-CN", "ja", "hi"} <= set(langs)
    for lang in langs[1:]:
        d = json.loads((FRONT / "i18n" / f"{lang}.json").read_text(encoding="utf-8"))
        assert d["Preferences"] and d["Sign in"] and d["Save"] and d["Password & Security"], lang
    assert "const h = attrs.raw ? (s) => s : (s) => host(tr(s));" in app_js and "t.textContent = host(tr(msg));" in app_js
    assert 'tr(TITLES[view] || view)' in app_js and "translateStatic(document.body)" in app_js
    assert 'class: `lang-opt' in app_js


def test_preferences_pages_got_their_depth():
    app_js = (FRONT / "js" / "app.js").read_text(encoding="utf-8")
    for s in ("More ways to protect this panel", "Turn on two-factor", 'navigate("security")', "Account name", "You're ${r.username} from now on",
              "Mailboxes on this server", "API.contactSuggestions()", "Previous build", "Go back to ${prev.label}", "none kept"):
        assert s in app_js, s
    css = (FRONT / "css" / "style.css").read_text(encoding="utf-8")
    for c in (".ps-grid {", ".ct-chip {", ".lang-opt {", ".about-back-prev {", ".u-legend {", ".am-mail-item {", ".mx-sel {", ".dk-gone {", ".fm-trash td"):
        assert c in css, c
    assert "align-items: stretch; margin-bottom: 16px; }\n.about-grid > .about-card { display: flex" in css


def test_users_page_two_factor_delete_dialog_and_no_native_prompts():
    app_js = (FRONT / "js" / "app.js").read_text(encoding="utf-8")
    users = app_js[app_js.index("function viewUsers("):app_js.index("\n  function ", app_js.index("function viewUsers(") + 10)]
    assert "confirmInline" not in users and "promptInline" not in users
    for s in ("API.userTwofa()", "API.userTwofaEnroll(u.name)", "API.userTwofaConfirm(u.name, code.value.trim())", "API.userTwofaDisable(u.name)",
              "API.userDelete(u.name, rm.checked, bk.checked)", "u.home_owner", "openModal(`Delete user ${u.name}`", "SSH on", "Panel ${tf.panel.enabled"):
        assert s in users, s


def test_small_fixes_everywhere():
    app_js = (FRONT / "js" / "app.js").read_text(encoding="utf-8")
    ops_js = (FRONT / "js" / "ops.js").read_text(encoding="utf-8")
    extras = (FRONT / "js" / "extras.js").read_text(encoding="utf-8")
    mail_js = (FRONT / "js" / "mail.js").read_text(encoding="utf-8")
    assert 'if (n == null) return "n/a";' in app_js and '|| ", "' not in app_js   # the lost dash: no stray commas
    assert 'popNotice({ title: "Panel HTTPS is on"' in app_js
    assert 'tbl.classList.add("fm-trash")' in app_js and 'm.classList.add("em-modal")' in app_js
    assert ".filter((j) => j.live).length + (S.f2b.other_jails || []).length)} jails" in ops_js   # only running jails are counted
    assert 'popNotice({ title: `Report done: ${d.last.grade}' in ops_js and 'fetch("/api/secreport/html"' in ops_js
    assert 'a.state === "missing"' in ops_js and 'API.dockerCtl(a.name, "start")' in ops_js and "Forget" in ops_js
    assert "onRange" in extras and 'class: "mx-sel"' in extras and "Selected: ${f(from)} to ${f(to)}" in extras
    assert "remoteAccounts(remoteBox)" in mail_js and "API.mailRemoteAdd(data)" in mail_js and "password never stored here" in mail_js
    assert "mailGuard(guardBox)" in mail_js and 'jails.forEach((j) => { jl[j.id] = { enabled, maxretry: +sel.value' in mail_js
    assert "inboxMenu.start();" in app_js and "API.mailInbox()" in app_js and 'text: "View all"' in app_js
    html = (FRONT / "index.html").read_text(encoding="utf-8")
    assert 'id="am-mail"' in html and 'id="avatar-dot"' in html


def test_instaban_and_activity_cleanup_in_the_interface():
    """Security → InstaBan: patterns are shown as text only (never HTML), the page is registered everywhere;
    Activity Log has a Clean up dialog whose copy goes to the Recycle Bin."""
    extras = (FRONT / "js" / "extras.js").read_text(encoding="utf-8")
    view = extras[extras.index("async function viewInstaBan("):extras.index("//  Metrics → Raw Access")]
    assert "html:" not in view and "innerHTML =" not in view.replace("body.innerHTML = \"\"", "")   # attacker text is never rendered as HTML
    for s in ("API.instaban()", "API.instabanAdd(pat.value, kind.value, note.value)", "API.instabanImport(ta.value)", "API.instabanDelete(p.id)", "API.instabanClear()",
              'raw: true, text: p.pattern', 'raw: true, text: `${h.method} ${h.target}`', "reportIp(h.ip, load)", "ipCard(h.ip, load)", "Trusted addresses are never banned"):
        assert s in view, s
    assert "instaban: viewInstaBan" in extras
    app_js = (FRONT / "js" / "app.js").read_text(encoding="utf-8")
    assert 'instaban: "InstaBan"' in app_js and '{ label: "InstaBan", icon: "trap", view: "instaban" }' in app_js
    assert 'data-view="instaban"' in (FRONT / "index.html").read_text(encoding="utf-8")
    ops = (FRONT / "js" / "ops.js").read_text(encoding="utf-8")
    assert '["ib", API.instaban]' in ops and 'view: "instaban"' in ops
    assert "API.auditPurge(mode, 30, keep.checked)" in ops and "Keep a copy in the Recycle Bin" in ops
