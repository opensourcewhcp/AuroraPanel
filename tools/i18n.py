"""Interface translations: find every string the panel shows, and keep the language files complete.

    python tools/i18n.py extract            write tools/i18n/template.json (every English string, empty values)
    python tools/i18n.py status             how much of the template each frontend/i18n/<lang>.json covers
    python tools/i18n.py missing fr         the strings French still lacks, as a JSON file to fill in
    python tools/i18n.py merge fr FILE...   add filled-in files to frontend/i18n/fr.json (checked first)
    python tools/i18n.py check              placeholders and tags of every translation match their English

How it fits together. frontend/i18n/<lang>.json maps an English string to its translation. A string with
values in it is stored once as a pattern, the values written {0}, {1}, ...:

    "{0} files scanned": "{0} fichiers analysés"

At run time tr() in frontend/js/app.js looks a rendered string up as it is, then against the patterns.
Nothing in the JavaScript or Python is marked up for this: the strings are found by reading the source.
"""
from __future__ import annotations

import ast
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
FRONT = ROOT / "frontend"
I18N = FRONT / "i18n"
TEMPLATE = ROOT / "tools" / "i18n" / "template.json"
PH = re.compile(r"\{(\d+)\}")

# ----------------------------------------------------------------------------- JavaScript: tokens
KEYWORDS_BEFORE_REGEX = {"return", "typeof", "case", "in", "of", "delete", "void", "throw", "new", "else", "do", "await", "yield"}
PUNCT = sorted(["===", "!==", "**=", "...", "<<=", ">>=", "&&=", "||=", "??=", "=>", "==", "!=", "<=", ">=", "&&", "||", "??", "?.",
                "++", "--", "+=", "-=", "*=", "/=", "%=", "&=", "|=", "^=", "**", "<<", ">>"], key=len, reverse=True)
ESC = {"n": "\n", "t": "\t", "r": "\r", "b": "\b", "f": "\f", "v": "\v", "0": "\0"}


class Tok:
    __slots__ = ("kind", "val", "parts")

    def __init__(self, kind, val, parts=None):
        self.kind, self.val, self.parts = kind, val, parts  # kind: id, num, str, tpl, re, p

    def __repr__(self):
        return f"{self.kind}:{self.val!r}"


def _unescape(src: str, i: int) -> tuple[str, int]:
    """The character an escape at src[i] (just after the backslash) stands for, and where it ends."""
    c = src[i]
    if c == "u":
        if src[i + 1] == "{":
            j = src.index("}", i)
            return chr(int(src[i + 2:j], 16)), j + 1
        return chr(int(src[i + 1:i + 5], 16)), i + 5
    if c == "x":
        return chr(int(src[i + 1:i + 3], 16)), i + 3
    if c == "\n":
        return "", i + 1
    return ESC.get(c, c), i + 1


def tokenize(src: str, i: int = 0, in_template: bool = False) -> tuple[list[Tok], int]:
    """Tokens of JavaScript source from i. Inside a template's ${...} it stops at the closing brace."""
    out: list[Tok] = []
    depth = 0
    n = len(src)
    while i < n:
        c = src[i]
        if c in " \t\r\n":
            i += 1
        elif src.startswith("//", i):
            j = src.find("\n", i)
            i = n if j < 0 else j
        elif src.startswith("/*", i):
            i = src.index("*/", i) + 2
        elif c in "\"'":
            j, buf = i + 1, []
            while src[j] != c:
                if src[j] == "\\":
                    ch, j = _unescape(src, j + 1)
                    buf.append(ch)
                else:
                    buf.append(src[j])
                    j += 1
            out.append(Tok("str", "".join(buf)))
            i = j + 1
        elif c == "`":
            j, buf, parts = i + 1, [], []
            while src[j] != "`":
                if src[j] == "\\":
                    ch, j = _unescape(src, j + 1)
                    buf.append(ch)
                elif src.startswith("${", j):
                    parts.append("".join(buf))
                    buf = []
                    inner, j = tokenize(src, j + 2, True)
                    parts.append(inner)
                else:
                    buf.append(src[j])
                    j += 1
            parts.append("".join(buf))
            out.append(Tok("tpl", None, parts))
            i = j + 1
        elif c == "/" and _regex_allowed(out):
            j, in_class = i + 1, False
            while src[j] != "/" or in_class:
                if src[j] == "\\":
                    j += 1
                elif src[j] == "[":
                    in_class = True
                elif src[j] == "]":
                    in_class = False
                j += 1
            j += 1
            while j < n and src[j].isalpha():
                j += 1
            out.append(Tok("re", src[i:j]))
            i = j
        elif c.isalpha() or c in "_$":
            j = i + 1
            while j < n and (src[j].isalnum() or src[j] in "_$"):
                j += 1
            out.append(Tok("id", src[i:j]))
            i = j
        elif c.isdigit():
            j = i + 1
            while j < n and (src[j].isalnum() or src[j] in "._"):
                j += 1
            out.append(Tok("num", src[i:j]))
            i = j
        else:
            if in_template:
                if c == "{":
                    depth += 1
                elif c == "}":
                    if depth == 0:
                        return out, i + 1
                    depth -= 1
            p = next((x for x in PUNCT if src.startswith(x, i)), c)
            out.append(Tok("p", p))
            i += len(p)
    return out, i


def _regex_allowed(out: list[Tok]) -> bool:
    if not out:
        return True
    t = out[-1]
    if t.kind == "p":
        return t.val not in (")", "]", "}", "++", "--")
    return t.kind == "id" and t.val in KEYWORDS_BEFORE_REGEX


# ----------------------------------------------------------------------------- JavaScript: which strings are shown
UI_KEYS = {"text", "title", "placeholder", "html", "label", "hint", "desc", "description", "help", "msg", "message", "tooltip", "note",
           "summary", "why", "sub", "subtitle", "heading", "caption", "stopped", "size", "blurb", "tip", "explain", "empty", "warn",
           "info", "about", "what", "tagline", "long", "short", "legend", "question", "answer", "detail", "details", "aria-label"}
NONUI_KEYS = {"class", "style", "id", "type", "href", "src", "value", "name", "for", "rel", "target", "method", "autocomplete", "icon",
              "view", "key", "kind", "mode", "cat", "group", "arg", "role", "accept", "pattern", "inputmode", "spellcheck", "tabindex",
              "min", "max", "step", "rows", "cols", "maxlength", "minlength", "width", "height", "viewBox", "d", "fill", "stroke",
              "path", "url", "unit", "field", "col", "sort", "dir", "align", "cls", "color", "colour", "tag", "event", "action",
              "history", "cache", "credentials", "headers", "body", "lang", "tab", "pkg", "service", "conf", "port", "proto", "ext"}
UI_CALLS = {"toast", "pill", "confirmInline", "promptInline", "openModal", "tr", "on", "off", "warn"}
NONUI_CALLS = {"navigate", "icon", "request", "$", "querySelector", "querySelectorAll", "getAttribute", "setAttribute", "removeAttribute",
               "addEventListener", "removeEventListener", "createElement", "createElementNS", "startsWith", "endsWith", "includes",
               "indexOf", "lastIndexOf", "split", "replace", "replaceAll", "match", "matchAll", "test", "getItem", "setItem",
               "removeItem", "fetch", "encodeURIComponent", "decodeURIComponent", "RegExp", "parseInt", "parseFloat", "toFixed",
               "padStart", "padEnd", "slice", "substring", "closest", "matches", "add", "remove", "toggle", "contains", "has", "get",
               "set", "delete", "dispatchEvent", "CustomEvent", "Event", "getElementById", "getContext", "toLocaleString",
               "toLocaleDateString", "toLocaleTimeString", "DateTimeFormat", "NumberFormat", "Error", "TypeError", "require",
               "log", "warn_", "error", "debug", "setProperty", "getPropertyValue", "insertAdjacentHTML", "replaceState", "pushState",
               "open", "import", "charAt", "localeCompare", "trimEnd", "repeat", "createObjectURL", "Blob", "File", "URL",
               "URLSearchParams", "append_", "Intl", "sw", "dmSlot", "shadowBtn", "watchJob_"}
COMPARE = {"===", "!==", "==", "!=", "<", ">", "<=", ">=", "case", "in", "instanceof", "typeof"}
INLINE_TAGS = r"b|i|em|strong|code|br|a|u|kbd|small|sup|sub|span|mark|wbr"
STRUCT = re.compile(rf"<(?!/?(?:{INLINE_TAGS})\b)[a-zA-Z!/]")
WORD = re.compile(r"[A-Za-z][A-Za-z']+")
SHORT_WORDS = {"on", "off", "no", "yes", "ok", "or", "and", "to", "of", "at", "in", "is", "by", "any", "all", "new", "old", "now", "set", "day", "ago"}


def _wordy(s: str, ui: bool) -> bool:
    """Does this read as text for a person, not as an identifier, a path, CSS or a class list?"""
    t = PH.sub(" ", s).strip()
    if not t or not WORD.search(t):
        return False
    if "{0}" in s and len(re.sub(r"[^A-Za-z]", "", PH.sub("", s))) < 4:
        return False  # a pattern needs enough text of its own to be told from data (tr() in app.js has the same floor)
    if len(t) <= 3 and t.islower() and t not in SHORT_WORDS:
        return False
    if re.match(r"(sudo|apt|apt-get|find|curl|wget|ssh|scp|psql|mysql|systemctl|git|docker|chmod|chown|cd|ls|tar|rsync|pip|npm|php|python3?|certbot|ufw|nginx|v=spf1|v=DMARC1|SELECT|CREATE|GRANT) \S", t) and not re.search(r"[.!?]$", t):
        return False  # a command line shown as an example
    words = WORD.findall(re.sub(r"<[^>]*>|&[a-z]+;", " ", t))
    if not words:
        return False
    if re.search(r"^(https?:|/|\.{1,2}/|#[\w-]+$|\.[\w-]+$|[\w.-]+@[\w-]+\.)|^[\w.-]+\.(js|css|json|png|svg|conf|php|html|sh|py)$", t):
        return False
    toks = t.split()
    if re.fullmatch(r"[a-z-]+\s*:\s*[^ ].*", t) and (";" in t or len(toks) <= 3 or re.search(r"\d(px|em|%|rem|s)\b|var\(--", t)):
        return False  # CSS
    idish = [x for x in toks if re.fullmatch(r"[a-z][a-z0-9_]*(-[a-z0-9_]+)*", x)]
    hyph = [x for x in idish if "-" in x or "_" in x]
    if len(idish) == len(toks) and hyph and len(hyph) * 2 >= len(toks):
        return False  # a class list
    if ui:
        return True
    if re.fullmatch(r"[A-Za-z0-9_$.\-:/\[\]=*#@%+|]+", t) and not re.fullmatch(r"[A-Z][a-z]{2,}(…|\.\.\.|:|\?|!)?", t):
        return False  # one token of code: an id, a selector, an event name, a MIME type
    if re.search(r"[{};]\s*$|=>|\bfunction\b|\(\)|^\s*[.#\[][\w-]|[a-z]\.[a-z]+\(", t):
        return False
    letters = sum(len(w) for w in words)
    if letters * 2 < len(re.sub(r"\s", "", t)):
        return False  # mostly symbols and digits
    if t[0].isupper() or t[0] in "“\"'(¡¿…⚠✓✗→←0123456789":
        return len(words) >= 2 or any(len(w) >= 3 for w in words)
    return len(words) >= 4 and len(idish) < len(toks)  # a lowercase sentence, with punctuation or capitals somewhere


class Frame:
    __slots__ = ("open", "callee", "arg", "key", "block")

    def __init__(self, open_, callee=None, block=False):
        self.open, self.callee, self.arg, self.key, self.block = open_, callee, 0, None, block


def _callee(toks: list[Tok], i: int) -> str | None:
    """The dotted name right before the "(" at toks[i]."""
    j, names = i - 1, []
    while j >= 0 and toks[j].kind == "id":
        names.append(toks[j].val)
        if j >= 1 and toks[j - 1].kind == "p" and toks[j - 1].val in (".", "?."):
            j -= 2
        else:
            break
    return ".".join(reversed(names)) if names else None


def _decide(stack: list[Frame], prev: Tok | None, nxt: Tok | None) -> bool | None:
    """True: shown to the user. False: code. None: can't tell from where it stands."""
    if prev is not None and prev.kind in ("p", "id") and prev.val in COMPARE:
        return False
    if nxt is not None and nxt.kind == "p" and nxt.val in ("===", "!==", "==", "!=", "."):
        return False
    top = stack[-1] if stack else None
    if top is not None and top.open == "tpl" and top.callee:
        return top.callee == "@text"  # a value written straight into layout HTML: text between tags, or part of a tag
    if nxt is not None and nxt.kind == "p" and nxt.val == ":" and top is not None and top.open == "{" and not top.block \
            and prev is not None and prev.kind == "p" and prev.val in ("{", ","):
        return False  # an object key
    if top is not None and top.open == "[" and top.callee == "@index":
        return False  # x["key"]
    for f in reversed(stack):
        if f.open == "{":
            if f.block:
                return None
            if f.key in UI_KEYS:
                return True
            if f.key in NONUI_KEYS or (f.key or "").startswith(("on", "data-")):
                return False
        elif f.open == "(" and f.callee:
            base = f.callee.split(".")[-1]
            if f.callee == "el":
                if f.arg == 0:
                    return False
                if f.arg >= 2:
                    return True
            elif base in UI_CALLS:
                return True if f.arg == 0 else None
            elif base in NONUI_CALLS or f.callee.startswith(("API.", "localStorage.", "sessionStorage.", "console.", "JSON.", "Object.", "Math.", "classList.")) \
                    or ".classList." in f.callee or ".style." in f.callee or ".dataset." in f.callee:
                return False
    return None


def _walk(toks: list[Tok], stack: list[Frame], found: list[tuple[str, bool | None]]) -> None:
    base = len(stack)
    i, n = 0, len(toks)
    while i < n:
        t = toks[i]
        prev = toks[i - 1] if i else None
        nxt = toks[i + 1] if i + 1 < n else None
        if t.kind == "p":
            v = t.val
            if v == "(":
                stack.append(Frame("(", _callee(toks, i)))
            elif v == "[":
                index = prev is not None and (prev.kind == "id" and prev.val not in KEYWORDS_BEFORE_REGEX or prev.kind == "p" and prev.val in (")", "]"))
                stack.append(Frame("[", "@index" if index else None))
            elif v == "{":
                block = prev is not None and prev.kind == "p" and prev.val in ("=>", ")") or prev is not None and prev.kind == "id" and prev.val in ("else", "try", "finally", "do")
                stack.append(Frame("{", block=block))
            elif v in (")", "]", "}"):
                if len(stack) > base:
                    stack.pop()
            elif v == "," and len(stack) > base:
                stack[-1].arg += 1
                stack[-1].key = None
            elif v == ":" and len(stack) > base and stack[-1].open == "{" and not stack[-1].block and prev is not None \
                    and prev.kind in ("id", "str") and i >= 2 and toks[i - 2].kind == "p" and toks[i - 2].val in ("{", ","):
                stack[-1].key = prev.val
        elif t.kind in ("str", "tpl"):
            verdict = _decide(stack, prev, nxt)
            # a + "text" + b: one string at run time, so one pattern
            chain, j = [t], i
            if verdict is not False:
                while j + 2 < n and toks[j + 1].kind == "p" and toks[j + 1].val == "+":
                    k = j + 2
                    if toks[k].kind in ("str", "tpl"):
                        chain.append(toks[k])
                        j = k
                        continue
                    depth = 0
                    while k < n:  # skip one operand that isn't a literal
                        tk = toks[k]
                        if tk.kind == "p":
                            if tk.val in ("(", "[", "{"):
                                depth += 1
                            elif tk.val in (")", "]", "}"):
                                if depth == 0:
                                    break
                                depth -= 1
                            elif depth == 0 and tk.val in ("+", ",", ";", "?", ":", "=>", "&&", "||", "===", "!=="):
                                break
                        k += 1
                    chain.append(None)
                    j = k - 1
                    if not (k < n and toks[k].kind == "p" and toks[k].val == "+"):
                        break
                lead = prev is not None and prev.kind == "p" and prev.val == "+" and i >= 2 and toks[i - 2].kind not in ("str", "tpl")
                if lead:
                    chain.insert(0, None)
            for part in chain:
                if part is not None and part.kind == "tpl":
                    before = ""
                    layout = _is_layout("".join(x for x in part.parts if isinstance(x, str)))
                    for piece in part.parts:
                        if isinstance(piece, str):
                            before += piece
                        if isinstance(piece, list):
                            where = None if not layout else "@tag" if before.rfind("<") > before.rfind(">") else "@text"
                            stack.append(Frame("tpl", where))
                            _walk(piece, stack, found)
                            stack.pop()
            if verdict is not False:
                if len(chain) > 1:
                    found.append((_pattern(chain), verdict))
                for part in chain:  # each piece on its own too: el() children are often translated one by one
                    if part is not None:
                        found.append((_pattern([part]), verdict))
            i = j
        i += 1
    del stack[base:]


def _pattern(chain: list[Tok | None]) -> str:
    """A string or template (or a + chain of them) as a key: text kept, every value a {n}."""
    out, k = [], 0
    for part in chain:
        if part is None:
            out.append(f"{{{k}}}")
            k += 1
        elif part.kind == "str":
            out.append(part.val.replace("{", "{").replace("}", "}"))
        else:
            for piece in part.parts:
                if isinstance(piece, list):
                    out.append(f"{{{k}}}")
                    k += 1
                else:
                    out.append(piece)
    return re.sub(r"(\{\d+\})(?=\{\d+\})", r"\1", "".join(out))


def _renumber(key: str) -> str:
    seen: dict[str, int] = {}
    return PH.sub(lambda m: "{%d}" % seen.setdefault(m.group(1), len(seen)), key)


def _is_layout(text: str) -> bool:
    return bool(STRUCT.search(text) or re.search(r"\bclass=|\bstyle=|\bhref=", text))


def _keys_from(text: str, ui: bool | None) -> list[str]:
    """What to store for one literal: itself, or (for a block of layout HTML) the pieces of text inside it."""
    if "{0}" in text and not PH.sub("", text).strip(" \n\t·:,.()[]/-—–|"):
        return []  # nothing but values
    if _is_layout(text):
        out = []
        for piece in re.split(r"<[^>]*>", text):  # what stands between two tags is on screen as it is
            piece = piece.strip()
            if piece and _wordy(piece, True):
                out.append(_renumber(piece))
        return [p for p in out if PH.sub("", p).strip()]
    if not _wordy(text, bool(ui)):
        return []
    return [_renumber(text)]


def extract_js(src: str) -> set[str]:
    toks, _ = tokenize(src)
    found: list[tuple[str, bool | None]] = []
    _walk(toks, [], found)
    keys: set[str] = set()
    for text, ui in found:
        if text.strip() != text and not ui:
            text = text  # leading/trailing space matters: pieces are joined on screen
        keys.update(_keys_from(text, ui))
    return keys


def extract_html(src: str) -> set[str]:
    """Text and title/placeholder/aria-label attributes of the static page shell."""
    body = re.sub(r"(?is)<(script|style)\b.*?</\1>", " ", src)
    keys = {m.strip() for m in re.findall(r">([^<>]+)<", body)}
    keys |= {m for m in re.findall(r"""(?:title|placeholder|aria-label)="([^"]+)\"""", body)}
    return {k for k in keys if k and _wordy(k, True) and not k.isdigit()}


# ----------------------------------------------------------------------------- Python: what the API says back
PY_KEYS = {"desc", "why", "label", "title", "hint", "note", "message", "msg", "summary", "detail", "text", "help", "reason", "warning",
           "error", "name", "fix", "advice", "what", "how", "tip", "subtitle", "explain", "status_text", "headline", "problem"}


def _py_text(node: ast.AST) -> str | None:
    """A string, f-string or + chain of them as a pattern; None for anything else."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.JoinedStr):
        out, k = [], 0
        for v in node.values:
            if isinstance(v, ast.Constant):
                out.append(str(v.value))
            else:
                out.append("\x00")
        return "".join(out)
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        a, b = _py_text(node.left), _py_text(node.right)
        if a is None and b is None:
            return None
        return (a if a is not None else "\x00") + (b if b is not None else "\x00")
    return None


def _py_key(text: str) -> str:
    parts = re.split("\x00+", text)
    return "".join(p + (f"{{{i}}}" if i < len(parts) - 1 else "") for i, p in enumerate(parts))


def extract_py(src: str) -> set[str]:
    keys: set[str] = set()
    tree = ast.parse(src)

    def add(node, ui):
        text = _py_text(node)
        if text is None:
            return
        key = _py_key(text)
        if "{0}" in key and not PH.sub("", key).strip(" \n\t·:,.()[]/-—–|"):
            return
        if _wordy(key, ui):
            keys.add(key)

    for node in ast.walk(tree):
        if isinstance(node, ast.Raise) and isinstance(node.exc, ast.Call):
            for a in node.exc.args[:2]:
                add(a, True)
            for kw in node.exc.keywords:
                if kw.arg in ("detail", "message", "msg"):
                    add(kw.value, True)
        elif isinstance(node, ast.Call) and getattr(node.func, "id", getattr(node.func, "attr", "")) in ("HTTPException", "JSONResponse"):
            for kw in node.keywords:
                if kw.arg == "detail":
                    add(kw.value, True)
        elif isinstance(node, ast.Dict):
            for k, v in zip(node.keys, node.values):
                if isinstance(k, ast.Constant) and k.value in PY_KEYS:
                    add(v, False)
                    if isinstance(v, ast.IfExp):
                        add(v.body, False)
                        add(v.orelse, False)
        elif isinstance(node, ast.Call):
            for kw in node.keywords:
                if kw.arg in PY_KEYS and kw.arg != "name":
                    add(kw.value, False)
    return keys


# ----------------------------------------------------------------------------- the whole template
def _server_variant(key: str) -> str:
    """The same text as host() in app.js shows it on a machine that isn't a Raspberry Pi."""
    s = re.sub(r"(?<!Raspberry )\bPi's\b", "server's", key)
    return re.sub(r"(?<!Raspberry )(?<!\w\.)\bPi\b(?![-.]\w)", "server", s)


def extract() -> dict[str, list[str]]:
    """Every string to translate -> the files it comes from."""
    where: dict[str, set[str]] = {}

    def put(keys, name):
        for k in keys:
            for v in {k, _server_variant(k)}:
                where.setdefault(v, set()).add(name)

    for f in sorted((FRONT / "js").glob("*.js")):
        put(extract_js(f.read_text(encoding="utf-8")), f"frontend/js/{f.name}")
    put(extract_html((FRONT / "index.html").read_text(encoding="utf-8")), "frontend/index.html")
    for f in sorted((ROOT / "backend").glob("*.py")):
        put(extract_py(f.read_text(encoding="utf-8")), f"backend/{f.name}")
    return {k: sorted(v) for k, v in sorted(where.items())}


def languages() -> list[str]:
    return sorted(p.stem for p in I18N.glob("*.json"))


def load(lang: str) -> dict[str, str]:
    return json.loads((I18N / f"{lang}.json").read_text(encoding="utf-8"))


def save(lang: str, d: dict[str, str]) -> None:
    (I18N / f"{lang}.json").write_text(json.dumps(d, ensure_ascii=False, indent=0, sort_keys=True).replace("\r\n", "\n") + "\n", encoding="utf-8", newline="\n")


def problems(key: str, val: str) -> str | None:
    """Why a translation can't be used, or None when it can."""
    if not isinstance(val, str) or not val.strip():
        return "empty"
    if not set(PH.findall(val)) <= set(PH.findall(key)):  # leaving one out is fine (an English plural "s"), inventing one is not
        return f"unknown placeholders: {sorted(set(PH.findall(val)) - set(PH.findall(key)))}"
    tags = lambda s: sorted(re.findall(rf"</?({INLINE_TAGS}|p|div|li|ul|ol|h[1-6]|td|tr|pre)\b", s))  # real tags; "<user>" in a path is text
    if tags(key) != tags(val):
        return "HTML tags differ"
    if (key[:1] == " ") != (val[:1] == " ") or (key[-1:] == " ") != (val[-1:] == " "):
        return "leading or trailing space differs"
    if key.count("\n") != val.count("\n") and "\n\n" in key:
        return "paragraph breaks differ"
    return None


def main(argv: list[str]) -> int:
    cmd = argv[0] if argv else "status"
    if cmd == "extract":
        keys = extract()
        TEMPLATE.parent.mkdir(parents=True, exist_ok=True)
        TEMPLATE.write_text(json.dumps({k: "" for k in keys}, ensure_ascii=False, indent=0) + "\n", encoding="utf-8", newline="\n")
        (TEMPLATE.parent / "sources.json").write_text(json.dumps(keys, ensure_ascii=False, indent=0) + "\n", encoding="utf-8", newline="\n")
        print(f"{len(keys)} strings ({sum('{0}' in k for k in keys)} with values in them) -> {TEMPLATE.relative_to(ROOT)}")
        return 0
    template = json.loads(TEMPLATE.read_text(encoding="utf-8"))
    if cmd == "status":
        for lang in languages():
            d = load(lang)
            done = sum(1 for k in template if k in d)
            print(f"{lang:6} {done:5} / {len(template)}  {100 * done / max(1, len(template)):5.1f}%   ({len(set(d) - set(template))} no longer used)")
        return 0
    if cmd == "missing":
        d = load(argv[1])
        out = {k: "" for k in template if k not in d}
        dest = TEMPLATE.parent / f"missing-{argv[1]}.json"
        dest.write_text(json.dumps(out, ensure_ascii=False, indent=0) + "\n", encoding="utf-8", newline="\n")
        print(f"{len(out)} strings -> {dest.relative_to(ROOT)}")
        return 0
    if cmd == "merge":
        lang, d, bad, added = argv[1], load(argv[1]), 0, 0
        for name in argv[2:]:
            for k, v in json.loads(Path(name).read_text(encoding="utf-8")).items():
                why = problems(k, v) if k in template else "not in the template"
                if why:
                    bad += 1
                    print(f"  skipped ({why}): {k[:70]!r}")
                    continue
                added += k not in d
                d[k] = v
        save(lang, d)
        print(f"{lang}: {added} added, {bad} skipped, {len(d)} in the file")
        return 0
    if cmd == "check":
        bad = 0
        for lang in languages():
            for k, v in load(lang).items():
                why = problems(k, v)
                if why:
                    bad += 1
                    print(f"{lang}: {why}: {k[:70]!r}")
        print(f"{bad} problems")
        return 1 if bad else 0
    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
