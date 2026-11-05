"""Stage 8: knowing what's installed. The Core Rule Set comes from signed distro packages, so the package manager checks the
signature. This records each rule file's hash and notices changes made any other way. The SBOM lists what the panel runs on.
"""
from __future__ import annotations

import glob
import hashlib
import importlib.metadata
import json
import re
import time
from pathlib import Path

CRS_GLOBS = ("/etc/httpd/modsecurity.d/activated_rules/*.conf", "/usr/share/modsecurity-crs/rules/*.conf", "/usr/share/modsecurity-crs/rules/*.data", "/etc/httpd/modsecurity.d/activated_rules/*.data")


def hash_crs(globs=CRS_GLOBS) -> dict[str, str]:
    out = {}
    for g in globs:
        for f in sorted(glob.glob(g)):
            try:
                out[f] = hashlib.sha256(Path(f).read_bytes()).hexdigest()
            except OSError:
                continue
    return out


def _version_marker(files: dict) -> str:
    """A package update changes a file, and that's fine. The rule set's version is in its own setup rules."""
    for f in files:
        if "REQUEST-901" in f:
            try:
                m = re.search(r"ver:'?OWASP_CRS/([\d.]+)", Path(f).read_text(encoding="utf-8", errors="replace"))
                if m:
                    return m.group(1)
            except OSError:
                pass
    return ""


def check_crs(store, globs=CRS_GLOBS) -> dict:
    now = hash_crs(globs)
    version = _version_marker(now)
    base = store.setting("crs_baseline")
    if not base or base.get("version") != version:
        store.set_setting("crs_baseline", {"version": version, "files": now, "ts": time.time()})
        return {"baseline": True, "version": version, "files": len(now), "changed": []}
    changed = sorted(k for k in set(now) | set(base["files"]) if now.get(k) != base["files"].get(k))
    return {"baseline": False, "version": version, "files": len(now), "changed": changed, "since": base["ts"]}


def sbom(requirements: Path | str = "requirements.txt") -> dict:
    """CycloneDX's JSON shape, listing what's installed, and whether each direct dependency is pinned to one version."""
    pinned, unpinned = {}, []
    try:
        for line in Path(requirements).read_text(encoding="utf-8").splitlines():
            line = line.split("#")[0].strip()
            if not line:
                continue
            m = re.match(r"^([A-Za-z0-9_.-]+)(\[[^\]]*\])?(==|>=|~=)?(.*)$", line)
            if m:
                if m.group(3) == "==":
                    pinned[m.group(1).lower()] = m.group(4)
                else:
                    unpinned.append(m.group(1))
    except OSError:
        pass
    comps = []
    for d in importlib.metadata.distributions():
        name = d.metadata["Name"] or ""
        comps.append({"type": "library", "name": name, "version": d.version, "purl": f"pkg:pypi/{name.lower()}@{d.version}", "licenses": [{"license": {"name": str(d.metadata.get("License") or "")[:60]}}]})
    comps.sort(key=lambda c: c["name"].lower())
    return {"bomFormat": "CycloneDX", "specVersion": "1.5", "metadata": {"timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}, "components": comps, "direct_pinned": sorted(pinned), "direct_not_pinned": sorted(unpinned)}


def dumps(doc: dict) -> str:
    return json.dumps(doc, indent=1)
