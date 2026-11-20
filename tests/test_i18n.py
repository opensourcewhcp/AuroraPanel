"""Interface translations: the extractor finds what the panel shows, the language files are sound, and the
page's tr() turns a rendered string (values and all) into its translation."""
import importlib.util
import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("aurora_i18n_tool", ROOT / "tools" / "i18n.py")
T = importlib.util.module_from_spec(spec)
spec.loader.exec_module(T)


# ----------------------------------------------------------------------------- reading the JavaScript
def keys(js: str) -> set:
    return T.extract_js(js)


def test_text_in_el_calls_is_found_and_code_is_not():
    js = r'''
    const a = el("div", { class: "card sa-card", id: "main", style: "margin:0 0 14px", title: "Open the site", onclick: () => navigate("sites") }, [
      el("h3", { text: "Web servers" }), el("span", { class: `pill ${on ? "good" : "dim"}`, text: on ? "running" : "stopped" }),
      "Loose child text", icon("globe", 14)]);
    if (s.status === "running" || kind == 'weird value') API.thing("some/path", "POST");
    document.querySelector(".dm-table td");
    x["some key"] = 1;
    '''
    assert keys(js) == {"Open the site", "Web servers", "running", "stopped", "Loose child text"}


def test_templates_and_joined_strings_become_patterns():
    js = r'''
    toast(`${n} files scanned`, "good");
    toast("Saved " + name + " to the list");
    el("p", { text: `Force HTTPS ${v ? "on" : "off"} · ${s.server_name}` });
    el("p", { text: count + " sites found" });
    el("p", { text: `${a}${b}` });
    el("p", { text: `${a} · ${b}` });
    const msg = cond ? "Nothing to do here" : `Removed ${x} from ${y}`;
    '''
    got = keys(js)
    assert {"{0} files scanned", "Saved {0} to the list", "Force HTTPS {0} · {1}", "on", "off", "{0} sites found",
            "Nothing to do here", "Removed {0} from {1}"} <= got
    assert not any(k in got for k in ("{0}{1}", "{0} · {1}", "good"))
    assert "Saved " in got and " to the list" in got     # the pieces too: often they are separate children on screen


def test_escapes_comments_and_regexes_do_not_confuse_it():
    js = r'''
    // el("p", { text: "In a comment" })
    /* toast("Also a comment") */
    const rx = /"not a string"/g, half = a / b / c;
    toast("It\'s \"quoted\"\nand on two lines ✓");
    toast('Single ${not} a template');
    toast(`Back\`tick and \${literal}`);
    el("p", { html: "Use <b>Export</b> to save, or <code>dig</code>" });
    '''
    got = keys(js)
    assert "It's \"quoted\"\nand on two lines ✓" in got and "Single ${not} a template" in got
    assert "Back`tick and ${literal}" in got and "Use <b>Export</b> to save, or <code>dig</code>" in got
    assert not any("comment" in k or "not a string" in k for k in got)


def test_layout_html_gives_its_text_pieces_not_the_markup():
    js = r'''
    c.innerHTML = `<div class="bc-head"><span class="pill">${state}</span></div><p class="muted">Firewall is off</p><b>Open ports</b> ${n}`;
    '''
    got = keys(js)
    assert {"Firewall is off", "Open ports"} <= got and not any("<div" in k or "class=" in k for k in got)


def test_wordy_tells_text_from_code():
    yes = ["Not installed", "Loading…", "about 40 MB download; uses ~80–150 MB RAM while running", "Version <b>{0}</b>", "2 files changed"]
    no = ["btn btn-sm btn-ghost", "margin:0 0 14px", "display:flex;gap:8px", "/var/www/html", "https://example.com/x", "app.js",
          "click", "text/plain", "{0}px", "ip", "find /tmp -type f -mtime +7 -delete", "v=spf1 a mx ~all", "#toast", "a51@example.com"]
    assert all(T._wordy(s, False) for s in yes), [s for s in yes if not T._wordy(s, False)]
    assert not any(T._wordy(s, False) for s in no), [s for s in no if T._wordy(s, False)]
    assert T._wordy("stopped", True) and not T._wordy("stopped", False)   # a lone lowercase word only where it is plainly shown
    assert T._wordy("on", True) and not T._wordy("xy", True) and not T._wordy("", True) and not T._wordy("123", True)


def test_static_page_shell():
    html = '<html><head><title>Aurora</title><style>.a{color:red}</style><script>var x = "Not this";</script></head>' \
           '<body><h1>Sign in to your Raspberry Pi</h1><input placeholder="Search tools" title="Find a tool"><span>42</span></body></html>'
    assert T.extract_html(html) == {"Sign in to your Raspberry Pi", "Search tools", "Find a tool", "Aurora"}


# ----------------------------------------------------------------------------- reading the Python
def test_backend_messages_and_descriptions():
    py = '''
class E(Exception): pass
def f(name, n):
    if n:
        raise E(f"No such user {name}@{n}")
    if name:
        raise HTTPException(status_code=400, detail="Password must be 6–128 characters")
    raise E("Refusing to remove " + name + " while it is in use")
CATALOG = {"x": {"name": "Nginx", "desc": "Fast, event-driven web server.", "pkg": "nginx-full", "ram": "~5 MB"},
           "y": {"desc": "Shown when on" if n else "Shown when off"}}
def g():
    return thing(label="Restricted area", name="internal-id", path="/var/www/html")
log.info("Not shown to anyone at all")
'''
    assert T.extract_py(py) == {"No such user {0}@{1}", "Password must be 6–128 characters", "Refusing to remove {0} while it is in use",
                                "Nginx", "Fast, event-driven web server.", "Shown when on", "Shown when off", "Restricted area"}


def test_server_wording_gets_its_own_entry():
    assert T._server_variant("Reboot this Pi") == "Reboot this server"
    assert T._server_variant("The Pi's address") == "The server's address"
    assert T._server_variant("Raspberry Pi OS and Pi-hole") == "Raspberry Pi OS and Pi-hole"


# ----------------------------------------------------------------------------- the files that ship
def test_template_is_current():
    """tools/i18n/template.json is what translators work from: re-run `python tools/i18n.py extract` after changing text."""
    have = set(json.loads(T.TEMPLATE.read_text(encoding="utf-8")))
    assert have == set(T.extract())


def test_every_language_file_is_sound():
    app_js = (ROOT / "frontend" / "js" / "app.js").read_text(encoding="utf-8")
    langs = re.findall(r'\["([a-zA-Z-]+)", "[^"]+", "[^"]+"\]', app_js[app_js.index("const LANGS = ["):app_js.index("const I18N = ")])
    assert set(langs[1:]) == set(T.languages())
    for lang in T.languages():
        bad = {k: T.problems(k, v) for k, v in T.load(lang).items() if T.problems(k, v)}
        assert not bad, (lang, list(bad.items())[:5])


def test_problems_catches_what_would_break_a_page():
    p = T.problems
    assert p("Saved", "Enregistré") is None and p("{0} of {1}", "{1} sur {0}") is None
    assert p("Saved", " ") == "empty" and p("Saved", None) == "empty"
    assert "placeholders" in p("{0} files", "{1} fichiers") and "placeholders" in p("Saved", "Enregistré {0}")
    assert p("{0} domain{1}", "{0} доменов") is None      # an English plural "s" has no place in most languages
    assert p("Use <b>Export</b>", "Utilisez Export") == "HTML tags differ"
    assert "space" in p("Saved ", "Enregistré") and "space" in p(" to", "à")
    assert "paragraph" in p("One.\n\nTwo.", "Un. Deux.")


def test_command_line(tmp_path, monkeypatch, capsys):
    i18n = tmp_path / "i18n"; i18n.mkdir()
    (i18n / "fr.json").write_text(json.dumps({"Saved": "Enregistré", "Gone": "Parti"}), encoding="utf-8")
    monkeypatch.setattr(T, "I18N", i18n)
    monkeypatch.setattr(T, "TEMPLATE", tmp_path / "tools" / "template.json")
    monkeypatch.setattr(T, "ROOT", tmp_path)
    monkeypatch.setattr(T, "extract", lambda: {"Saved": ["a.js"], "{0} files": ["a.js"], "Use <b>it</b>": ["b.py"]})
    assert T.main(["extract"]) == 0 and json.loads(T.TEMPLATE.read_text(encoding="utf-8")) == {"Saved": "", "{0} files": "", "Use <b>it</b>": ""}
    assert T.main(["status"]) == 0 and "1 / 3" in capsys.readouterr().out
    assert T.main(["missing", "fr"]) == 0
    todo = tmp_path / "tools" / "missing-fr.json"
    assert json.loads(todo.read_text(encoding="utf-8")) == {"{0} files": "", "Use <b>it</b>": ""}
    todo.write_text(json.dumps({"{0} files": "{0} fichiers", "Use <b>it</b>": "Utilisez-le", "Unknown": "Inconnu"}), encoding="utf-8")
    assert T.main(["merge", "fr", str(todo)]) == 0
    out = capsys.readouterr().out
    assert "1 added, 2 skipped" in out and "HTML tags differ" in out and "not in the template" in out
    assert T.load("fr")["{0} files"] == "{0} fichiers" and "Use <b>it</b>" not in T.load("fr")
    assert T.main(["check"]) == 0
    (i18n / "fr.json").write_text(json.dumps({"{0} files": "{3} fichiers"}), encoding="utf-8")
    assert T.main(["check"]) == 1
    assert T.main(["nonsense"]) == 2 and T.main([]) == 0


# ----------------------------------------------------------------------------- the page's tr()
@pytest.mark.skipif(not shutil.which("node"), reason="Node.js not installed")
def test_tr_matches_whole_strings_then_patterns(tmp_path):
    d = {"Saved": "Enregistré", "on": "activé", "off": "désactivé", "{0} files scanned": "{0} fichiers analysés",
         "Force HTTPS {0} · {1}": "HTTPS forcé {0} · {1}", "Removed {0} from {1}": "{1} : {0} retiré",
         "File list {0}": "Liste des fichiers {0}", "File list {0} · {1}{2}": "Liste des fichiers {0} · {1}{2}",
         "{0} on {1}": "never used, too little text", "Use (a+b)? {0} [now]": "Utilisez (a+b) ? {0} [maintenant]"}
    cases = ["Saved", "  Saved\n", "12 files scanned", "Force HTTPS on · example.com", "Removed bob from the list", "File list off · a.com (http)",
             "File list off", "Linux on ARM", "Unknown text", "", "Use (a+b)? x [now]", "files scanned"]
    (tmp_path / "d.json").write_text(json.dumps(d), encoding="utf-8")
    (tmp_path / "c.json").write_text(json.dumps(cases), encoding="utf-8")
    r = subprocess.run(["node", str(ROOT / "tests" / "i18n_runtime.js"), str(ROOT / "frontend" / "js" / "app.js"), str(tmp_path / "d.json"), str(tmp_path / "c.json")],
                       capture_output=True, text=True, encoding="utf-8")
    assert r.returncode == 0, r.stderr
    assert json.loads(r.stdout) == ["Enregistré", "  Enregistré\n", "12 fichiers analysés", "HTTPS forcé activé · example.com", "the list : bob retiré",
                                    "Liste des fichiers désactivé · a.com (http)", "Liste des fichiers désactivé", "Linux on ARM", "Unknown text", "",
                                    "Utilisez (a+b) ? x [maintenant]", "files scanned"]


def test_the_page_translates_what_el_never_saw():
    app_js = (ROOT / "frontend" / "js" / "app.js").read_text(encoding="utf-8")
    for needle in ("function compilePatterns(dict)", "new MutationObserver(", "attributeFilter: TR_ATTRS", "watchTranslations();",
                   'if (k === "raw") { if (v) node.setAttribute("data-raw", ""); continue; }', "window.confirm(tr(host(msg)))"):
        assert needle in app_js, needle


def test_text_on_screen_is_never_used_as_a_key():
    """A translated label is not the English name: the rail icons and tab highlights are found by a fixed key."""
    js = {f.name: f.read_text(encoding="utf-8") for f in (ROOT / "frontend" / "js").glob("*.js")}
    assert "const name = g.dataset.group || enText(g);" in js["app.js"]
    for name, text in js.items():
        assert not re.search(r"textContent(\.trim\(\))? ===? [a-z]\w*\)", text), name
