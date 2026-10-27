"""Apache per-directory config via .htaccess (Indexes, MIME types, Error pages,
Handlers) — mirroring cPanel's Advanced tools.

All edits target a `.htaccess` file inside a directory confined to APACHE_ROOT
(default /var/www). These directives only take effect if Apache is configured
with `AllowOverride` for that directory.
"""
from __future__ import annotations

import os
import re
from pathlib import Path

APACHE_ROOT = Path(os.environ.get("AURORA_APACHE_ROOT", "/var/www")).resolve()
SYSTEM_MIME = Path("/etc/mime.types")


class ApacheError(RuntimeError):
    pass


# ---- path + file helpers ---------------------------------------------------
def _resolve_dir(rel: str) -> Path:
    rel = (rel or "").lstrip("/\\")
    try:
        base = APACHE_ROOT
        candidate = (base / rel).resolve()
    except OSError as exc:
        raise ApacheError(str(exc)) from exc
    if candidate != APACHE_ROOT and APACHE_ROOT not in candidate.parents:
        raise ApacheError("Path escapes the Apache root")
    if not candidate.is_dir():
        raise ApacheError("Not a directory (create it first)")
    return candidate


def _htaccess(rel: str) -> Path:
    return _resolve_dir(rel) / ".htaccess"


def _read_lines(rel: str) -> list[str]:
    p = _htaccess(rel)
    if not p.exists():
        return []
    try:
        return p.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeDecodeError) as exc:
        raise ApacheError(f"Cannot read .htaccess: {exc}") from exc


def _write_lines(rel: str, lines: list[str]) -> None:
    p = _htaccess(rel)
    content = "\n".join(lines).rstrip("\n")
    if content:
        content += "\n"
    try:
        p.write_text(content, encoding="utf-8")
    except OSError as exc:
        raise ApacheError(f"Cannot write .htaccess: {exc}") from exc


def _no_newline(*vals: str) -> None:
    for v in vals:
        if v is None or "\n" in v or "\r" in v:
            raise ApacheError("Value must be a single line")


def raw(rel: str) -> dict:
    p = _htaccess(rel)
    return {"dir": str(_resolve_dir(rel)), "root": str(APACHE_ROOT),
            "exists": p.exists(), "content": "\n".join(_read_lines(rel))}


# ---- Indexes ---------------------------------------------------------------
def get_indexes(rel: str) -> dict:
    lines = _read_lines(rel)
    listing = None  # None = not set, True/False = explicit
    directory_index = None
    for ln in lines:
        s = ln.strip()
        m = re.match(r"(?i)^Options\s+(.*)", s)
        if m:
            opts = m.group(1)
            if re.search(r"(?i)(^|\s)[+]?Indexes(\s|$)", opts):
                listing = True
            if re.search(r"(?i)(^|\s)-Indexes(\s|$)", opts):
                listing = False
        m2 = re.match(r"(?i)^DirectoryIndex\s+(.*)", s)
        if m2:
            directory_index = m2.group(1).strip()
    return {"listing": listing, "directory_index": directory_index}


def set_indexes(rel: str, listing: bool, directory_index: str | None) -> dict:
    if directory_index is not None:
        _no_newline(directory_index)
    lines = [ln for ln in _read_lines(rel)
             if not re.match(r"(?i)^\s*Options\s+[+-]?Indexes\s*$", ln.strip())
             and not re.match(r"(?i)^\s*DirectoryIndex\s+", ln.strip())]
    lines.append(f"Options {'+' if listing else '-'}Indexes")
    if directory_index:
        lines.append(f"DirectoryIndex {directory_index.strip()}")
    _write_lines(rel, lines)
    return {"ok": True}


# ---- generic directive listing/removal ------------------------------------
def _list_directive(rel: str, keyword: str) -> list[dict]:
    out = []
    for idx, ln in enumerate(_read_lines(rel)):
        if re.match(rf"(?i)^\s*{keyword}\s+", ln):
            out.append({"raw": ln.strip(), "line": idx})
    return out


def _remove_line(rel: str, raw_line: str) -> dict:
    target = (raw_line or "").strip()
    _no_newline(target)
    lines = _read_lines(rel)
    kept, removed = [], False
    for ln in lines:
        if not removed and ln.strip() == target:
            removed = True
            continue
        kept.append(ln)
    if not removed:
        raise ApacheError("Directive not found")
    _write_lines(rel, kept)
    return {"ok": True}


# ---- MIME types ------------------------------------------------------------
def list_mime(rel: str) -> dict:
    return {"entries": _list_directive(rel, "AddType")}


def add_mime(rel: str, mime: str, extensions: str) -> dict:
    _no_newline(mime, extensions)
    if not re.match(r"^[\w.+-]+/[\w.+-]+$", mime or ""):
        raise ApacheError("Invalid MIME type (expected type/subtype)")
    exts = " ".join(e.lstrip(".") for e in (extensions or "").split())
    if not re.match(r"^[\w. -]+$", exts):
        raise ApacheError("Invalid extensions")
    lines = _read_lines(rel)
    lines.append(f"AddType {mime} {exts}")
    _write_lines(rel, lines)
    return {"ok": True}


def system_mime(limit: int = 400) -> dict:
    if not SYSTEM_MIME.exists():
        return {"available": False, "entries": []}
    entries = []
    for ln in SYSTEM_MIME.read_text(encoding="utf-8", errors="replace").splitlines():
        if ln.startswith("#") or not ln.strip():
            continue
        parts = ln.split()
        if len(parts) >= 2:
            entries.append({"type": parts[0], "extensions": " ".join(parts[1:])})
        if len(entries) >= limit:
            break
    return {"available": True, "entries": entries}


# ---- Error pages -----------------------------------------------------------
def list_errors(rel: str) -> dict:
    entries = []
    for item in _list_directive(rel, "ErrorDocument"):
        m = re.match(r"(?i)^ErrorDocument\s+(\d{3})\s+(.*)$", item["raw"])
        if m:
            entries.append({"code": m.group(1), "document": m.group(2).strip(), "raw": item["raw"]})
    return {"entries": entries}


ERROR_TITLES = {"400": "Bad request", "401": "Sign-in required", "403": "Forbidden", "404": "Page not found", "429": "Too many requests",
                "500": "Something went wrong on the server", "502": "Bad gateway", "503": "Down for maintenance — back soon"}
_ERROR_HTML = """<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{code} — {title}</title>
<style>body{{margin:0;min-height:100vh;display:grid;place-items:center;font-family:system-ui,sans-serif;background:#0b0a0a;color:#f4efeb}}
main{{text-align:center;padding:32px}}h1{{font-size:72px;margin:0;color:#ff8a33;letter-spacing:-.03em}}p{{color:#b9b1aa;font-size:18px}}a{{color:#ff8a33}}</style>
<main><h1>{code}</h1><p>{title}</p><p><a href="/">Back to the start page</a></p></main></html>
"""


def create_error_page(rel: str, code: str, filename: str) -> dict:
    """A simple styled page for an ErrorDocument, written into the folder unless it already exists."""
    _no_newline(filename)
    name = (filename or "").strip().lstrip("/")
    if not name or ".." in name.split("/") or not re.match(r"^[\w./-]+$", name):
        raise ApacheError("Invalid page name")
    base = _resolve_dir(rel)
    target = (base / name).resolve()
    if base != target and base not in target.parents:
        raise ApacheError("The page must live inside this folder")
    if target.exists():
        return {"ok": True, "created": False, "path": str(target)}
    try:
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(_ERROR_HTML.format(code=code, title=ERROR_TITLES.get(str(code), "Error")), encoding="utf-8")
    except OSError as exc:
        raise ApacheError(f"Cannot write {target}: {exc}") from exc
    return {"ok": True, "created": True, "path": str(target)}


def set_error(rel: str, code: str, document: str, create: str = "") -> dict:
    _no_newline(code, document)
    if not re.match(r"^\d{3}$", str(code)):
        raise ApacheError("Invalid HTTP status code")
    if not document.strip():
        raise ApacheError("Document/URL required")
    if create:
        create_error_page(rel, code, create)
    lines = [ln for ln in _read_lines(rel)
             if not re.match(rf"(?i)^\s*ErrorDocument\s+{code}\s+", ln)]
    lines.append(f"ErrorDocument {code} {document.strip()}")
    _write_lines(rel, lines)
    return {"ok": True}


# ---- Handlers --------------------------------------------------------------
def list_handlers(rel: str) -> dict:
    add = _list_directive(rel, "AddHandler")
    setr = _list_directive(rel, "SetHandler")
    return {"entries": add + setr}


def add_handler(rel: str, handler: str, extensions: str) -> dict:
    """AddHandler for the given extensions — or, with none, SetHandler for every file in the folder."""
    _no_newline(handler, extensions)
    if not re.match(r"^[\w.+/-]+$", handler or ""):
        raise ApacheError("Invalid handler name")
    exts = " ".join(e.lstrip(".") for e in (extensions or "").split())
    lines = _read_lines(rel)
    if not exts:
        lines = [ln for ln in lines if not re.match(r"(?i)^\s*SetHandler\s", ln)]
        lines.append(f"SetHandler {handler}")
    else:
        if not re.match(r"^[\w. -]+$", exts):
            raise ApacheError("Invalid extensions")
        lines.append(f"AddHandler {handler} {exts}")
    _write_lines(rel, lines)
    return {"ok": True}


# Per-folder Options a .htaccess may switch (one line each, the way the panel writes them).
OPTION_NAMES = ("ExecCGI", "Includes", "IncludesNOEXEC", "FollowSymLinks", "SymLinksIfOwnerMatch", "MultiViews")


def list_options(rel: str) -> dict:
    out: dict[str, bool | None] = {n: None for n in OPTION_NAMES}
    for ln in _read_lines(rel):
        m = re.match(r"(?i)^\s*Options\s+(.+?)\s*$", ln)
        if not m:
            continue
        for tok in m.group(1).split():
            name = tok.lstrip("+-")
            for n in OPTION_NAMES:
                if n.lower() == name.lower():
                    out[n] = not tok.startswith("-")
    return {"options": out}


def set_option(rel: str, name: str, on: bool) -> dict:
    """Turn one Option on (Options +Name) or back to the server default (line removed)."""
    real = next((n for n in OPTION_NAMES if n.lower() == (name or "").strip().lower()), None)
    if not real:
        raise ApacheError("Unknown option")
    lines = [ln for ln in _read_lines(rel) if not re.match(rf"(?i)^\s*Options\s+[+-]?{real}\s*$", ln)]
    if on:
        lines.append(f"Options +{real}")
    _write_lines(rel, lines)
    return {"ok": True}


def remove_directive(rel: str, raw_line: str) -> dict:
    return _remove_line(rel, raw_line)


# ---- Redirects -------------------------------------------------------------
def list_redirects(rel: str) -> dict:
    entries = []
    for item in _list_directive(rel, "Redirect") + _list_directive(rel, "RedirectMatch"):
        entries.append(item)
    return {"entries": entries}


def add_redirect(rel: str, code: str, source: str, target: str) -> dict:
    _no_newline(code, source, target)
    if str(code) not in ("301", "302", "303", "307"):
        raise ApacheError("Code must be 301, 302, 303 or 307")
    if not source.strip().startswith("/"):
        raise ApacheError("Source path must start with /")
    if not target.strip():
        raise ApacheError("Target is required")
    lines = _read_lines(rel)
    lines.append(f"Redirect {code} {source.strip()} {target.strip()}")
    _write_lines(rel, lines)
    return {"ok": True}


# ---- Hotlink protection ----------------------------------------------------
_HL_START = "# AURORA-HOTLINK-START"
_HL_END = "# AURORA-HOTLINK-END"


def get_hotlink(rel: str) -> dict:
    lines = _read_lines(rel)
    enabled = _HL_START in [l.strip() for l in lines]
    allowed = ""
    exts = "jpg jpeg png gif webp svg bmp"
    if enabled:
        for l in lines:
            m = re.search(r"HTTP_REFERER}\s+!\^https\?://\(\?:([^)]*)\)", l)
            if m:
                allowed = m.group(1).replace("|", " ")
            m2 = re.search(r"RewriteRule\s+\\\.\(([^)]*)\)\$", l)
            if m2:
                exts = m2.group(1).replace("|", " ")
    return {"enabled": enabled, "allowed_hosts": allowed, "extensions": exts}


def set_hotlink(rel: str, enabled: bool, allowed_hosts: str, extensions: str) -> dict:
    _no_newline(allowed_hosts or "", extensions or "")
    lines = _read_lines(rel)
    # Strip any existing block first.
    out, skip = [], False
    for l in lines:
        if l.strip() == _HL_START:
            skip = True
            continue
        if l.strip() == _HL_END:
            skip = False
            continue
        if not skip:
            out.append(l)
    if enabled:
        hosts = [h.strip() for h in re.split(r"[\s,]+", allowed_hosts or "") if h.strip()]
        for h in hosts:
            if not re.match(r"^[A-Za-z0-9.*_-]+$", h):
                raise ApacheError(f"Invalid host: {h}")
        exts = [e.strip().lstrip(".") for e in re.split(r"[\s,]+", extensions or "") if e.strip()]
        for e in exts:
            if not re.match(r"^[A-Za-z0-9]+$", e):
                raise ApacheError(f"Invalid extension: {e}")
        if not exts:
            exts = ["jpg", "jpeg", "png", "gif", "webp", "svg"]
        host_group = "|".join(re.escape(h).replace("\\*", "[^/]*") for h in hosts) if hosts else "localhost"
        out += [
            _HL_START,
            "RewriteEngine On",
            "RewriteCond %{HTTP_REFERER} !^$",
            f"RewriteCond %{{HTTP_REFERER}} !^https?://(?:{host_group}) [NC]",
            f"RewriteRule \\.({'|'.join(exts)})$ - [F,NC]",
            _HL_END,
        ]
    _write_lines(rel, out)
    return {"ok": True, "enabled": enabled}
