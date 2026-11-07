"""Cloud Apps: manage Amazon Web Services, Google Cloud and Microsoft Azure from this server.

The Pi does not run anything in the cloud itself. It drives each provider through its official
command-line tool (aws, gcloud, az), which the panel installs on request, signed in with an
account the owner creates for the panel:

  AWS          an IAM access key (access key ID + secret) and a default region
  Google Cloud a service account key (the JSON file) and a project
  Azure        a service principal (tenant, app/client ID, secret) and a subscription

Every provider keeps its sign-in in its own folder under /var/lib/aurora/cloud, readable by root
only, and the tools are pointed there through their environment variables, so nothing lands in
/root and nothing is shared with the Terminal unless the owner exports the same variables.

The page shows each provider's common services side by side: virtual servers, file storage,
databases, Kubernetes, functions, containers and analytics. Virtual servers can be started and
stopped, and files can be copied between this server and cloud storage in both directions.
Everything else is listed with a link to the provider's console.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import time
from pathlib import Path

from . import distro
from . import jobs
from . import problems

BASE = Path("/var/lib/aurora/cloud")
PATH = distro.PATH + ":/usr/local/bin"

PROVIDERS = {
    "aws": {"name": "Amazon Web Services", "short": "AWS", "cli": "aws", "component": "awscli",
            "console": "https://console.aws.amazon.com/"},
    "gcp": {"name": "Google Cloud", "short": "Google Cloud", "cli": "gcloud", "component": "gcloud",
            "console": "https://console.cloud.google.com/"},
    "azure": {"name": "Microsoft Azure", "short": "Azure", "cli": "az", "component": "azurecli",
              "console": "https://portal.azure.com/"},
}

# The same job on each cloud. The match between providers is approximate.
SERVICES = [
    ("vms", "Virtual servers", {"aws": "EC2", "gcp": "Compute Engine", "azure": "Virtual Machines"}),
    ("storage", "Files and backups", {"aws": "S3", "gcp": "Cloud Storage", "azure": "Blob Storage"}),
    ("databases", "PostgreSQL / MySQL databases", {"aws": "RDS / Aurora", "gcp": "Cloud SQL", "azure": "Azure SQL"}),
    ("kubernetes", "Kubernetes", {"aws": "EKS", "gcp": "GKE", "azure": "AKS"}),
    ("functions", "Code that runs on events", {"aws": "Lambda", "gcp": "Cloud Run functions", "azure": "Azure Functions"}),
    ("containers", "Containers", {"aws": "ECS / Fargate", "gcp": "Cloud Run", "azure": "Container Instances"}),
    ("analytics", "Big data analytics", {"aws": "Redshift", "gcp": "BigQuery", "azure": "Synapse Analytics"}),
]
SERVICE_IDS = [s[0] for s in SERVICES]

# Free options, as the providers advertise them. Terms change, so the page links the official page.
FREE = {
    "aws": {"url": "https://aws.amazon.com/free/", "items": [
        ["Free plan for new accounts", "Credits to try services for up to 6 months, no charge unless you upgrade"],
        ["Lambda", "1 million requests a month, always free"],
        ["DynamoDB", "25 GB of storage, always free"],
    ]},
    "gcp": {"url": "https://cloud.google.com/free", "items": [
        ["Trial credit", "$300 to spend in the first 90 days for new customers"],
        ["Compute Engine", "One e2-micro virtual server a month in selected US regions, always free"],
        ["Cloud Storage", "5 GB a month in selected US regions, always free"],
        ["BigQuery", "1 TB of queries and 10 GB of storage a month, always free"],
        ["Cloud Run", "2 million requests a month, always free"],
    ]},
    "azure": {"url": "https://azure.microsoft.com/free/", "items": [
        ["Trial account", "$200 credit for 30 days for new customers"],
        ["Virtual machine", "Up to 750 hours a month of eligible sizes for 12 months"],
        ["Static Web Apps, Free plan", "A small website with HTTPS, your own domain and 100 GB of traffic a month"],
        ["Azure Functions", "1 million calls a month on the Consumption plan"],
        ["Cosmos DB free tier", "25 GB and 1,000 RU/s"],
        ["No surprise bills", "The trial never charges you. It continues only if you switch to Pay-as-you-go yourself"],
    ]},
}


class CloudError(RuntimeError):
    pass


# --------------------------------------------------------------------------- state
def _state_path() -> Path:
    return BASE / "accounts.json"


def _check(provider: str) -> dict:
    if provider not in PROVIDERS:
        raise CloudError("Unknown cloud provider")
    return PROVIDERS[provider]


def _dir(provider: str) -> Path:
    return BASE / provider


def load() -> dict:
    try:
        d = json.loads(_state_path().read_text())
    except (OSError, ValueError):
        d = {}
    return d if isinstance(d, dict) else {}


def _save(d: dict) -> None:
    _private_dir(BASE)
    _write_private(_state_path(), json.dumps(d, indent=1))


def _private_dir(p: Path) -> None:
    p.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(p, 0o700)
    except OSError as quiet_exc:
        problems.quiet(quiet_exc)


def _write_private(p: Path, text: str) -> None:
    tmp = p.with_name(f".{p.name}.{os.getpid()}.tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(text)
    tmp.replace(p)


def env(provider: str) -> dict:
    """The environment that points the provider's tool at the panel's own sign-in."""
    d = _dir(provider)
    e = {"PATH": PATH, "HOME": str(d), "LANG": "C.UTF-8"}
    if provider == "aws":
        e |= {"AWS_SHARED_CREDENTIALS_FILE": str(d / "credentials"), "AWS_CONFIG_FILE": str(d / "config"),
              "AWS_PAGER": "", "AWS_CLI_AUTO_PROMPT": "off"}
    elif provider == "gcp":
        e |= {"CLOUDSDK_CONFIG": str(d / "gcloud"), "CLOUDSDK_CORE_DISABLE_PROMPTS": "1",
              "CLOUDSDK_CORE_DISABLE_USAGE_REPORTING": "1",
              # The Python bundled with the Google Cloud CLI crashes on some Raspberry Pi kernels.
              "CLOUDSDK_PYTHON": distro.system_python()}
    elif provider == "azure":
        e |= {"AZURE_CONFIG_DIR": str(d / "azure"), "AZURE_CORE_COLLECT_TELEMETRY": "0",
              "AZURE_CORE_ONLY_SHOW_ERRORS": "1", "AZURE_CORE_NO_COLOR": "1"}
    return e


def shell_env(provider: str) -> str:
    """What to put in front of a command in the Terminal to use the same sign-in by hand."""
    e = env(provider)
    return " ".join(f"{k}={e[k]}" for k in e if k not in ("PATH", "HOME", "LANG", "AWS_PAGER"))


def cli_path(provider: str) -> str | None:
    return shutil.which(PROVIDERS[provider]["cli"], path=PATH)


def _run(provider: str, args: list[str], timeout: int = 90, mkdir: bool = True) -> subprocess.CompletedProcess:
    exe = cli_path(provider)
    if not exe:
        raise CloudError(f"The {PROVIDERS[provider]['short']} command-line tool isn't installed yet")
    if mkdir:
        _private_dir(_dir(provider))
    try:
        return subprocess.run([exe, *args], capture_output=True, text=True, timeout=timeout, env=env(provider))
    except subprocess.TimeoutExpired:
        raise CloudError(f"{PROVIDERS[provider]['short']} took longer than {timeout} seconds to answer")
    except OSError as exc:
        raise CloudError(str(exc))


def _clean_err(text: str) -> str:
    lines = [ln.strip() for ln in (text or "").splitlines() if ln.strip()]
    lines = [ln for ln in lines if not ln.lower().startswith(("warning:", "please let us know", "to re-authenticate"))]
    msg = " ".join(lines[-3:]) or "The command failed"
    msg = re.sub(r"(?i)(secret|password|key)([=:]\s*)\S+", r"\1\2•••", msg)
    return msg[-500:]


def _json(provider: str, args: list[str], timeout: int = 90):
    r = _run(provider, args, timeout)
    if r.returncode != 0:
        raise CloudError(_clean_err(r.stderr or r.stdout))
    out = (r.stdout or "").strip()
    if not out:
        return []
    try:
        return json.loads(out)
    except ValueError:
        raise CloudError("The answer wasn't JSON: " + out[:200])


def _version(provider: str) -> str:
    if not cli_path(provider):
        return ""
    try:
        r = _run(provider, ["--version"], 60, mkdir=False)
    except CloudError:
        return ""
    first = ((r.stdout or "") + (r.stderr or "")).strip().splitlines()
    return first[0].strip()[:80] if first else ""


# --------------------------------------------------------------------------- overview
def _public(acct: dict) -> dict:
    return {k: v for k, v in acct.items() if k in ("identity", "account_id", "region", "project", "subscription",
                                                   "subscription_name", "tenant", "connected", "key_id")}


def _console(provider: str, acct: dict | None) -> str:
    url = PROVIDERS[provider]["console"]
    if acct and provider == "gcp" and acct.get("project"):
        url += f"home/dashboard?project={acct['project']}"
    if acct and provider == "aws" and acct.get("region"):
        url = f"https://{acct['region']}.console.aws.amazon.com/console/home?region={acct['region']}"
    return url


def _provider_row(pid: str, acct: dict | None) -> dict:
    p = PROVIDERS[pid]
    return {"id": pid, "name": p["name"], "short": p["short"], "component": p["component"],
            "installed": cli_path(pid) is not None, "connected": bool(acct),
            "account": _public(acct) if acct else None, "console": _console(pid, acct),
            "services": [{"id": s, "label": lbl, "product": names[pid]} for s, lbl, names in SERVICES],
            "free": FREE[pid], "shell_env": shell_env(pid)}


def listing() -> dict:
    d = load()
    return {"providers": [_provider_row(pid, d.get(pid)) for pid in PROVIDERS]}


def provider_info(provider: str) -> dict:
    _check(provider)
    info = _provider_row(provider, load().get(provider))
    info["version"] = _version(provider)
    return info


# --------------------------------------------------------------------------- connect
_REGION = re.compile(r"^[a-z]{2}(-gov)?-[a-z]+-\d$")
_PROJECT = re.compile(r"^[a-z][a-z0-9-]{4,28}[a-z0-9]$")
_GUID = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")


def connect(provider: str, body: dict) -> dict:
    _check(provider)
    if not cli_path(provider):
        raise CloudError(f"Install the {PROVIDERS[provider]['short']} command-line tool first")
    fn = {"aws": _connect_aws, "gcp": _connect_gcp, "azure": _connect_azure}[provider]
    fn(body, None)  # validate everything before the old sign-in is touched
    d = _dir(provider)
    shutil.rmtree(d, ignore_errors=True)
    _private_dir(d)
    try:
        acct = fn(body, d)
    except Exception:
        shutil.rmtree(d, ignore_errors=True)
        st = load()
        if st.pop(provider, None) is not None:
            _save(st)
        raise
    acct["connected"] = time.time()
    st = load()
    st[provider] = acct
    _save(st)
    return provider_info(provider)


def _connect_aws(body: dict, d: Path | None) -> dict:
    kid = (body.get("access_key_id") or "").strip()
    secret = (body.get("secret_access_key") or "").strip()
    region = (body.get("region") or "us-east-1").strip()
    if not re.fullmatch(r"(AKIA|ASIA)[A-Z0-9]{12,20}", kid):
        raise CloudError("The access key ID looks like AKIA followed by 16 letters and digits")
    if not re.fullmatch(r"[A-Za-z0-9/+=]{30,60}", secret):
        raise CloudError("Paste the whole secret access key (40 characters)")
    if not _REGION.fullmatch(region):
        raise CloudError("Pick a region, for example us-east-1 or eu-central-1")
    if d is None:
        return {}
    _write_private(d / "credentials", f"[default]\naws_access_key_id = {kid}\naws_secret_access_key = {secret}\n")
    _write_private(d / "config", f"[default]\nregion = {region}\noutput = json\n")
    who = _json("aws", ["sts", "get-caller-identity", "--output", "json"], 60)
    return {"identity": who.get("Arn", ""), "account_id": who.get("Account", ""), "region": region,
            "key_id": kid[:4] + "…" + kid[-4:]}


def _connect_gcp(body: dict, d: Path | None) -> dict:
    raw = (body.get("key_json") or "").strip()
    try:
        key = json.loads(raw)
    except ValueError:
        raise CloudError("Paste the whole service account key file (it starts with {)")
    if not isinstance(key, dict) or key.get("type") != "service_account" or not key.get("client_email") or not key.get("private_key"):
        raise CloudError("That isn't a service account key. Create one under IAM & Admin, Service Accounts, Keys, Add key, JSON")
    project = (body.get("project") or key.get("project_id") or "").strip()
    if not _PROJECT.fullmatch(project):
        raise CloudError("Enter the project ID, for example my-project-123456")
    if d is None:
        return {}
    _write_private(d / "key.json", json.dumps(key))
    r = _run("gcp", ["auth", "activate-service-account", key["client_email"], f"--key-file={d / 'key.json'}"], 90)
    if r.returncode != 0:
        raise CloudError(_clean_err(r.stderr))
    r = _run("gcp", ["config", "set", "project", project], 60)
    if r.returncode != 0:
        raise CloudError(_clean_err(r.stderr))
    return {"identity": key["client_email"], "project": project}


def _connect_azure(body: dict, d: Path | None) -> dict:
    tenant = (body.get("tenant_id") or "").strip()
    client = (body.get("client_id") or "").strip()
    secret = (body.get("client_secret") or "").strip()
    sub = (body.get("subscription_id") or "").strip()
    for v, what in ((tenant, "Directory (tenant) ID"), (client, "Application (client) ID")):
        if not _GUID.fullmatch(v):
            raise CloudError(f"The {what} is a GUID like 0b1c2d3e-4f50-6172-8394-a5b6c7d8e9f0")
    if sub and not _GUID.fullmatch(sub):
        raise CloudError("The subscription ID is a GUID like 0b1c2d3e-4f50-6172-8394-a5b6c7d8e9f0")
    if len(secret) < 8:
        raise CloudError("Paste the client secret's value (not its ID)")
    if d is None:
        return {}
    r = _run("azure", ["login", "--service-principal", "--username", client, "--password", secret, "--tenant", tenant, "--output", "none"], 120)
    if r.returncode != 0:
        raise CloudError(_clean_err(r.stderr))
    if sub:
        r = _run("azure", ["account", "set", "--subscription", sub], 60)
        if r.returncode != 0:
            raise CloudError(_clean_err(r.stderr))
    acct = _json("azure", ["account", "show", "--output", "json"], 60)
    return {"identity": client, "tenant": tenant, "subscription": acct.get("id", sub), "subscription_name": acct.get("name", "")}


def disconnect(provider: str) -> dict:
    _check(provider)
    if provider == "azure" and cli_path("azure") and _dir("azure").exists():
        try:
            _run("azure", ["logout"], 30)
        except CloudError as quiet_exc:
            problems.quiet(quiet_exc)
    shutil.rmtree(_dir(provider), ignore_errors=True)
    st = load()
    st.pop(provider, None)
    _save(st)
    return provider_info(provider)


def _need(provider: str) -> dict:
    _check(provider)
    acct = load().get(provider)
    if not acct:
        raise CloudError(f"Connect your {PROVIDERS[provider]['short']} account first")
    return acct


# --------------------------------------------------------------------------- inventory
def _g(o, *path, default=""):
    for p in path:
        if isinstance(o, dict):
            o = o.get(p)
        elif isinstance(o, list) and isinstance(p, int) and len(o) > p:
            o = o[p]
        else:
            return default
        if o is None:
            return default
    return o


def _tail(url: str) -> str:
    return (url or "").rstrip("/").rsplit("/", 1)[-1]


def _join(*xs) -> str:
    return " · ".join(str(x) for x in xs if x not in (None, "", 0))


def _aws_name(inst: dict) -> str:
    for t in inst.get("Tags") or []:
        if t.get("Key") == "Name":
            return t.get("Value", "")
    return ""


def items(provider: str, service: str) -> dict:
    acct = _need(provider)
    if service not in SERVICE_IDS:
        raise CloudError("Unknown service")
    rows = _INVENTORY[provider][service](acct)
    return {"provider": provider, "service": service, "items": rows, "console": _console(provider, acct)}


def _inv_aws_vms(a):
    res = _json("aws", ["ec2", "describe-instances", "--output", "json"]) or {}
    out = []
    for r in res.get("Reservations", []):
        for i in r.get("Instances", []):
            out.append({"id": i.get("InstanceId", ""), "name": _aws_name(i) or i.get("InstanceId", ""), "status": _g(i, "State", "Name"),
                        "detail": _join(i.get("InstanceType"), _g(i, "Placement", "AvailabilityZone"), i.get("PublicIpAddress")),
                        "actions": ["start", "stop"]})
    return out


def _inv_aws_storage(a):
    res = _json("aws", ["s3api", "list-buckets", "--output", "json"]) or {}
    return [{"id": b["Name"], "name": b["Name"], "status": "", "detail": f"created {str(b.get('CreationDate', ''))[:10]}", "browse": b["Name"]}
            for b in res.get("Buckets", [])]


def _inv_aws_db(a):
    res = _json("aws", ["rds", "describe-db-instances", "--output", "json"]) or {}
    return [{"id": x["DBInstanceIdentifier"], "name": x["DBInstanceIdentifier"], "status": x.get("DBInstanceStatus", ""),
             "detail": _join(x.get("Engine"), x.get("EngineVersion"), x.get("DBInstanceClass"))} for x in res.get("DBInstances", [])]


def _inv_aws_eks(a):
    res = _json("aws", ["eks", "list-clusters", "--output", "json"]) or {}
    return [{"id": n, "name": n, "status": "", "detail": ""} for n in res.get("clusters", [])]


def _inv_aws_lambda(a):
    res = _json("aws", ["lambda", "list-functions", "--output", "json"]) or {}
    return [{"id": f["FunctionName"], "name": f["FunctionName"], "status": f.get("State", ""),
             "detail": _join(f.get("Runtime"), f"{f['MemorySize']} MB" if f.get("MemorySize") else "", str(f.get("LastModified") or "")[:10])}
            for f in res.get("Functions", [])]


def _inv_aws_ecs(a):
    res = _json("aws", ["ecs", "list-clusters", "--output", "json"]) or {}
    return [{"id": c, "name": _tail(c), "status": "", "detail": c} for c in res.get("clusterArns", [])]


def _inv_aws_redshift(a):
    res = _json("aws", ["redshift", "describe-clusters", "--output", "json"]) or {}
    return [{"id": c["ClusterIdentifier"], "name": c["ClusterIdentifier"], "status": c.get("ClusterStatus", ""),
             "detail": _join(c.get("NodeType"), f"{c['NumberOfNodes']} nodes" if c.get("NumberOfNodes") else "")} for c in res.get("Clusters", [])]


def _inv_gcp_vms(a):
    out = []
    for i in _json("gcp", ["compute", "instances", "list", "--format=json"]):
        zone = _tail(i.get("zone", ""))
        out.append({"id": f"{zone}/{i.get('name', '')}", "name": i.get("name", ""), "status": i.get("status", ""),
                    "detail": _join(_tail(i.get("machineType", "")), zone, _g(i, "networkInterfaces", 0, "accessConfigs", 0, "natIP")),
                    "actions": ["start", "stop"]})
    return out


def _inv_gcp_storage(a):
    out = []
    for b in _json("gcp", ["storage", "buckets", "list", "--format=json"]):
        name = b.get("name") or str(b.get("storage_url", "")).replace("gs://", "").strip("/")
        out.append({"id": name, "name": name, "status": "", "detail": _join(b.get("location"), b.get("default_storage_class")), "browse": name})
    return out


def _inv_gcp_sql(a):
    return [{"id": x.get("name", ""), "name": x.get("name", ""), "status": x.get("state", ""),
             "detail": _join(x.get("databaseVersion"), _g(x, "settings", "tier"), x.get("region"))}
            for x in _json("gcp", ["sql", "instances", "list", "--format=json"])]


def _inv_gcp_gke(a):
    return [{"id": c.get("name", ""), "name": c.get("name", ""), "status": c.get("status", ""),
             "detail": _join(c.get("location"), f"{c['currentNodeCount']} nodes" if c.get("currentNodeCount") else "")}
            for c in _json("gcp", ["container", "clusters", "list", "--format=json"])]


def _inv_gcp_functions(a):
    return [{"id": f.get("name", ""), "name": _tail(f.get("name", "")), "status": f.get("state", "") or f.get("status", ""),
             "detail": _join(f.get("environment"), f.get("runtime") or _g(f, "buildConfig", "runtime"))}
            for f in _json("gcp", ["functions", "list", "--format=json"])]


def _inv_gcp_run(a):
    out = []
    for s in _json("gcp", ["run", "services", "list", "--format=json"]):
        conds = _g(s, "status", "conditions", default=[]) or []
        ready = any(c.get("type") == "Ready" and c.get("status") == "True" for c in conds)
        out.append({"id": _g(s, "metadata", "name"), "name": _g(s, "metadata", "name"), "status": "Ready" if ready else "",
                    "detail": _g(s, "status", "url")})
    return out


def _inv_gcp_bq(a):
    exe = shutil.which("bq", path=PATH)
    if not exe:
        raise CloudError("BigQuery's bq tool isn't installed (it comes with the Google Cloud CLI)")
    try:
        r = subprocess.run([exe, "ls", "--format=json", f"--project_id={a.get('project', '')}"], capture_output=True, text=True,
                           timeout=90, env=env("gcp"))
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise CloudError(str(exc))
    if r.returncode != 0:
        raise CloudError(_clean_err(r.stderr or r.stdout))
    try:
        res = json.loads(r.stdout or "[]")
    except ValueError:
        res = []
    return [{"id": _g(x, "datasetReference", "datasetId"), "name": _g(x, "datasetReference", "datasetId"), "status": "",
             "detail": x.get("location", "")} for x in res]


def _inv_az_vms(a):
    return [{"id": f"{v.get('resourceGroup', '')}/{v.get('name', '')}", "name": v.get("name", ""),
             "status": (v.get("powerState") or "").replace("VM ", ""),
             "detail": _join(_g(v, "hardwareProfile", "vmSize"), v.get("location"), v.get("publicIps")), "actions": ["start", "stop"]}
            for v in _json("azure", ["vm", "list", "--show-details", "--output", "json"], 120)]


def _inv_az_storage(a):
    return [{"id": s.get("name", ""), "name": s.get("name", ""), "status": s.get("statusOfPrimary", ""),
             "detail": _join(s.get("location"), s.get("kind"), s.get("resourceGroup")), "browse": s.get("name", "")}
            for s in _json("azure", ["storage", "account", "list", "--output", "json"])]


def _inv_az_sql(a):
    return [{"id": s.get("name", ""), "name": s.get("name", ""), "status": s.get("state", ""), "detail": _join(s.get("location"), s.get("resourceGroup"))}
            for s in _json("azure", ["sql", "server", "list", "--output", "json"])]


def _inv_az_aks(a):
    return [{"id": c.get("name", ""), "name": c.get("name", ""), "status": _g(c, "powerState", "code"),
             "detail": _join(f"Kubernetes {c['kubernetesVersion']}" if c.get("kubernetesVersion") else "", c.get("location"))}
            for c in _json("azure", ["aks", "list", "--output", "json"])]


def _inv_az_functions(a):
    return [{"id": f.get("name", ""), "name": f.get("name", ""), "status": f.get("state", ""), "detail": f.get("defaultHostName", "")}
            for f in _json("azure", ["functionapp", "list", "--output", "json"])]


def _inv_az_containers(a):
    return [{"id": c.get("name", ""), "name": c.get("name", ""), "status": c.get("provisioningState", ""), "detail": _join(c.get("location"), c.get("osType"))}
            for c in _json("azure", ["container", "list", "--output", "json"])]


def _inv_az_synapse(a):
    return [{"id": w.get("name", ""), "name": w.get("name", ""), "status": w.get("provisioningState", ""), "detail": w.get("location", "")}
            for w in _json("azure", ["synapse", "workspace", "list", "--output", "json"])]


_INVENTORY = {
    "aws": {"vms": _inv_aws_vms, "storage": _inv_aws_storage, "databases": _inv_aws_db, "kubernetes": _inv_aws_eks,
            "functions": _inv_aws_lambda, "containers": _inv_aws_ecs, "analytics": _inv_aws_redshift},
    "gcp": {"vms": _inv_gcp_vms, "storage": _inv_gcp_storage, "databases": _inv_gcp_sql, "kubernetes": _inv_gcp_gke,
            "functions": _inv_gcp_functions, "containers": _inv_gcp_run, "analytics": _inv_gcp_bq},
    "azure": {"vms": _inv_az_vms, "storage": _inv_az_storage, "databases": _inv_az_sql, "kubernetes": _inv_az_aks,
              "functions": _inv_az_functions, "containers": _inv_az_containers, "analytics": _inv_az_synapse},
}


# --------------------------------------------------------------------------- virtual servers
_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._()-]{0,89}$")


def vm_action(provider: str, vm_id: str, action: str) -> dict:
    _need(provider)
    if action not in ("start", "stop"):
        raise CloudError("Start or stop only")
    vm_id = (vm_id or "").strip()
    if provider == "aws":
        if not re.fullmatch(r"i-[0-9a-f]{8,17}", vm_id):
            raise CloudError("Unknown instance")
        args = ["ec2", f"{action}-instances", "--instance-ids", vm_id, "--output", "json"]
    else:
        parts = vm_id.split("/")
        if len(parts) != 2 or not all(_NAME.fullmatch(p) for p in parts):
            raise CloudError("Unknown virtual server")
        where, name = parts
        if provider == "gcp":
            args = ["compute", "instances", action, name, f"--zone={where}", "--async", "--format=json"]
        else:
            # Azure keeps billing a stopped VM's compute unless it is deallocated, so "stop" deallocates.
            args = ["vm", "start" if action == "start" else "deallocate", "--resource-group", where, "--name", name, "--no-wait"]
    r = _run(provider, args, 180)
    if r.returncode != 0:
        raise CloudError(_clean_err(r.stderr))
    verb = "Starting" if action == "start" else "Stopping"
    return {"ok": True, "message": f"{verb} {vm_id.split('/')[-1]}. It takes a minute or two."}


# --------------------------------------------------------------------------- storage
def _split(path: str) -> tuple[str, str]:
    path = (path or "").strip().lstrip("/")
    if re.search(r"[\x00-\x1f\\]", path) or ".." in path.split("/"):
        raise CloudError("That path isn't allowed")
    bucket, _, rest = path.partition("/")
    if bucket and not re.fullmatch(r"[a-z0-9][a-z0-9._-]{1,221}[a-z0-9]", bucket):
        raise CloudError("That isn't a bucket or storage account name")
    return bucket, rest


def browse(provider: str, path: str = "") -> dict:
    acct = _need(provider)
    bucket, rest = _split(path)
    if rest and not rest.endswith("/"):
        rest += "/"
    if not bucket:
        rows = _INVENTORY[provider]["storage"](acct)
        return {"path": "", "entries": [{"name": r["name"], "dir": True, "size": None, "detail": r["detail"]} for r in rows]}
    if provider == "aws":
        res = _json("aws", ["s3api", "list-objects-v2", "--bucket", bucket, "--prefix", rest, "--delimiter", "/",
                            "--max-items", "1000", "--output", "json"], 120) or {}
        ents = [{"name": p["Prefix"][len(rest):].rstrip("/"), "dir": True, "size": None} for p in res.get("CommonPrefixes") or []]
        ents += [{"name": o["Key"][len(rest):], "dir": False, "size": o.get("Size"), "modified": o.get("LastModified", "")}
                 for o in res.get("Contents") or [] if o["Key"] != rest]
    elif provider == "gcp":
        r = _run("gcp", ["storage", "ls", "--long", f"gs://{bucket}/{rest}"], 120)
        if r.returncode != 0 and "matched no objects" not in (r.stderr or ""):
            raise CloudError(_clean_err(r.stderr))
        ents = _parse_gs_ls(r.stdout, bucket, rest)
    else:
        container, _, prefix = rest.partition("/")
        if not container:
            res = _json("azure", ["storage", "container", "list", "--account-name", bucket, "--auth-mode", "login", "--output", "json"], 120)
            ents = [{"name": c.get("name", ""), "dir": True, "size": None} for c in res]
        else:
            res = _json("azure", ["storage", "blob", "list", "--account-name", bucket, "--container-name", container, "--prefix", prefix,
                                  "--delimiter", "/", "--num-results", "1000", "--auth-mode", "login", "--output", "json"], 120)
            ents = []
            for b in res:
                n = (b.get("name") or "")[len(prefix):]
                if not n:
                    continue
                if n.endswith("/") or not b.get("properties"):
                    ents.append({"name": n.rstrip("/"), "dir": True, "size": None})
                else:
                    ents.append({"name": n, "dir": False, "size": _g(b, "properties", "contentLength", default=None),
                                 "modified": _g(b, "properties", "lastModified")})
    ents.sort(key=lambda e: (not e["dir"], e["name"].lower()))
    return {"path": "/".join(x for x in (bucket, rest.rstrip("/")) if x), "entries": ents}


def _parse_gs_ls(text: str, bucket: str, rest: str) -> list[dict]:
    pre = f"gs://{bucket}/{rest}"
    out = []
    for ln in (text or "").splitlines():
        parts = ln.split()
        if not parts or parts[0] == "TOTAL:":
            continue
        url = parts[-1]
        if not url.startswith(pre) or url == pre:
            continue
        name = url[len(pre):]
        if url.endswith("/"):
            out.append({"name": name.rstrip("/"), "dir": True, "size": None})
        else:
            out.append({"name": name, "dir": False, "size": int(parts[0]) if parts[0].isdigit() else None,
                        "modified": parts[1] if len(parts) > 2 else ""})
    return out


def _local(path: str) -> Path:
    from . import files
    try:
        return files._resolve(path)
    except files.FileError as exc:
        raise CloudError(str(exc))


def transfer(provider: str, direction: str, local: str, remote: str) -> dict:
    """Copy between this server and cloud storage. Never deletes anything on either side."""
    _need(provider)
    if direction not in ("push", "pull"):
        raise CloudError("Push (to the cloud) or pull (to this server)")
    bucket, key = _split(remote)
    if not bucket:
        raise CloudError("Pick a bucket (or a storage account and container) first")
    if not (local or "").strip():
        raise CloudError("Pick a file or folder on this server")
    lp = _local(local)
    short = PROVIDERS[provider]["short"]
    if direction == "push":
        if not lp.exists():
            raise CloudError("That file or folder doesn't exist on this server")
        argv = _push_argv(provider, lp, bucket, key)
        title = f"Upload {lp.name} to {short} {bucket}/{key}".rstrip("/")
    else:
        if not lp.is_dir():
            raise CloudError("Pull into a folder on this server")
        folder = (remote or "").rstrip().endswith("/") or not key
        argv = _pull_argv(provider, bucket, key, lp, folder)
        title = f"Download {short} {bucket}/{key} to {lp}"
    job = jobs.launch(title, argv, env=env(provider), meta={"cloud": provider})
    return {"job": job.id}


def _push_argv(provider: str, lp: Path, bucket: str, key: str) -> list[str]:
    exe = cli_path(provider) or PROVIDERS[provider]["cli"]
    key = key.strip("/")
    is_dir = lp.is_dir()
    if provider == "aws":
        target = "/".join(x for x in (key, lp.name) if x)
        return [exe, "s3", "cp", str(lp), f"s3://{bucket}/{target}" + ("/" if is_dir else ""), *(["--recursive"] if is_dir else []), "--no-progress"]
    if provider == "gcp":
        return [exe, "storage", "cp", *(["--recursive"] if is_dir else []), str(lp), f"gs://{bucket}/{key + '/' if key else ''}"]
    container, _, prefix = key.partition("/")
    if not container:
        raise CloudError("Pick a container inside the storage account first")
    dest = "/".join(x for x in (prefix, lp.name) if x)
    if is_dir:
        return [exe, "storage", "blob", "upload-batch", "--account-name", bucket, "--destination", container, "--destination-path", dest,
                "--source", str(lp), "--auth-mode", "login", "--overwrite", "false"]
    return [exe, "storage", "blob", "upload", "--account-name", bucket, "--container-name", container, "--name", dest, "--file", str(lp),
            "--auth-mode", "login", "--overwrite", "false"]


def _pull_argv(provider: str, bucket: str, key: str, lp: Path, folder: bool) -> list[str]:
    exe = cli_path(provider) or PROVIDERS[provider]["cli"]
    stem = key.rstrip("/").rsplit("/", 1)[-1] or bucket
    if provider == "aws":
        if folder:
            return [exe, "s3", "cp", f"s3://{bucket}/{key}", str(lp / stem), "--recursive", "--no-progress"]
        return [exe, "s3", "cp", f"s3://{bucket}/{key}", str(lp) + "/", "--no-progress"]
    if provider == "gcp":
        src = f"gs://{bucket}/{key.rstrip('/')}" if key else f"gs://{bucket}"
        return [exe, "storage", "cp", *(["--recursive"] if folder else []), src, str(lp)]
    container, _, prefix = key.partition("/")
    if not container:
        raise CloudError("Pick a container inside the storage account first")
    if folder:
        pattern = (prefix.rstrip("/") + "/*") if prefix.strip("/") else "*"
        return [exe, "storage", "blob", "download-batch", "--account-name", bucket, "--source", container, "--destination", str(lp),
                "--pattern", pattern, "--auth-mode", "login"]
    return [exe, "storage", "blob", "download", "--account-name", bucket, "--container-name", container, "--name", prefix,
            "--file", str(lp / prefix.rsplit("/", 1)[-1]), "--auth-mode", "login", "--no-progress"]
