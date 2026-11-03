"""Cloud Apps (backend/cloudapps.py): AWS, Google Cloud and Azure through their command-line tools.

Nothing here reaches a cloud: the tools are "installed" by a fake shutil.which, and every call to
subprocess.run is answered by a small rule table that also records the argv and environment, so the
tests check both what the panel sends and how it reads the answers."""
from __future__ import annotations

import json
import subprocess
import sys

import pytest

from backend import cloudapps, jobs

TOOLS = {"aws", "gcloud", "az", "bq"}


class Fake:
    def __init__(self):
        self.rules: list[tuple[tuple[str, ...], int, str, str]] = []
        self.calls: list[list[str]] = []
        self.envs: list[dict] = []

    def on(self, *words, rc=0, out="", err=""):
        if not isinstance(out, str):
            out = json.dumps(out)
        self.rules.insert(0, (words, rc, out, err))

    def __call__(self, argv, **kw):
        self.calls.append(list(argv))
        self.envs.append(kw.get("env") or {})
        joined = " ".join(argv)
        for words, rc, out, err in self.rules:
            if all(w in joined for w in words):
                return subprocess.CompletedProcess(argv, rc, out, err)
        return subprocess.CompletedProcess(argv, 0, "", "")

    def last(self, *words):
        for c in reversed(self.calls):
            if all(w in " ".join(c) for w in words):
                return c
        raise AssertionError(f"no call with {words}: {self.calls}")


@pytest.fixture
def fake(tmp_path, monkeypatch):
    monkeypatch.setattr(cloudapps, "BASE", tmp_path / "cloud")
    monkeypatch.setattr(cloudapps.shutil, "which", lambda name, path=None: f"/usr/bin/{name}" if name in TOOLS else None)
    f = Fake()
    monkeypatch.setattr(subprocess, "run", f)
    return f


@pytest.fixture
def launched(monkeypatch):
    seen = []

    class J:
        id = "job1"

    monkeypatch.setattr(jobs, "launch", lambda title, argv, env=None, meta=None: seen.append({"title": title, "argv": argv, "env": env}) or J())
    return seen


def _connect_aws(fake):
    fake.on("sts", "get-caller-identity", out={"Arn": "arn:aws:iam::123456789012:user/aurora", "Account": "123456789012"})
    return cloudapps.connect("aws", {"access_key_id": "AKIAABCDEFGHIJKLMNOP", "secret_access_key": "a" * 40, "region": "eu-central-1"})


def _connect_gcp(fake):
    key = {"type": "service_account", "client_email": "panel@my-project-123.iam.gserviceaccount.com", "private_key": "-----BEGIN PRIVATE KEY-----", "project_id": "my-project-123"}
    return cloudapps.connect("gcp", {"key_json": json.dumps(key)})


def _connect_azure(fake):
    fake.on("account", "show", out={"id": "11111111-2222-3333-4444-555555555555", "name": "Pay-As-You-Go"})
    g = "0b1c2d3e-4f50-6172-8394-a5b6c7d8e9f0"
    return cloudapps.connect("azure", {"tenant_id": g, "client_id": g, "client_secret": "s3cr3t-value", "subscription_id": "11111111-2222-3333-4444-555555555555"})


# ------------------------------------------------------------------ overview and connect
def test_listing_shows_three_providers_with_the_same_services(fake):
    d = cloudapps.listing()
    assert [p["id"] for p in d["providers"]] == ["aws", "gcp", "azure"]
    for p in d["providers"]:
        assert p["installed"] and not p["connected"] and p["account"] is None
        assert [s["id"] for s in p["services"]] == cloudapps.SERVICE_IDS
        assert p["free"]["url"].startswith("https://") and p["free"]["items"]
    products = {p["id"]: {s["id"]: s["product"] for s in p["services"]} for p in d["providers"]}
    assert products["aws"]["vms"] == "EC2" and products["gcp"]["analytics"] == "BigQuery" and products["azure"]["storage"] == "Blob Storage"


def test_not_installed_tools_are_reported_and_block_connecting(fake, monkeypatch):
    monkeypatch.setattr(cloudapps.shutil, "which", lambda name, path=None: None)
    assert not any(p["installed"] for p in cloudapps.listing()["providers"])
    assert cloudapps.provider_info("aws")["version"] == ""
    with pytest.raises(cloudapps.CloudError, match="Install"):
        cloudapps.connect("aws", {})
    with pytest.raises(cloudapps.CloudError, match="isn't installed"):
        cloudapps._run("aws", ["--version"])


def test_unknown_provider_and_service_are_refused(fake):
    with pytest.raises(cloudapps.CloudError, match="Unknown cloud"):
        cloudapps.provider_info("oracle")
    _connect_aws(fake)
    with pytest.raises(cloudapps.CloudError, match="Unknown service"):
        cloudapps.items("aws", "mainframes")


@pytest.mark.parametrize("body,msg", [
    ({"access_key_id": "nope", "secret_access_key": "a" * 40}, "AKIA"),
    ({"access_key_id": "AKIAABCDEFGHIJKLMNOP", "secret_access_key": "short"}, "secret"),
    ({"access_key_id": "AKIAABCDEFGHIJKLMNOP", "secret_access_key": "a" * 40, "region": "mars-1"}, "region"),
])
def test_aws_connect_checks_the_fields_before_touching_anything(fake, body, msg):
    with pytest.raises(cloudapps.CloudError, match=msg):
        cloudapps.connect("aws", body)
    assert not fake.calls and not (cloudapps.BASE / "aws").exists()


def test_aws_connect_writes_private_credentials_and_keeps_no_secret_in_the_listing(fake):
    info = _connect_aws(fake)
    assert info["connected"] and info["account"]["identity"].endswith("user/aurora")
    assert info["account"]["region"] == "eu-central-1" and info["account"]["key_id"] == "AKIA…MNOP"
    cred = (cloudapps.BASE / "aws" / "credentials").read_text()
    assert "aws_secret_access_key = " + "a" * 40 in cred
    assert "region = eu-central-1" in (cloudapps.BASE / "aws" / "config").read_text()
    env = fake.envs[fake.calls.index(fake.last("sts"))]
    assert env["AWS_SHARED_CREDENTIALS_FILE"].endswith("credentials") and env["HOME"].endswith("aws")
    assert "a" * 40 not in json.dumps(cloudapps.listing())
    if sys.platform.startswith("linux"):
        assert (cloudapps.BASE / "aws" / "credentials").stat().st_mode & 0o077 == 0


def test_a_rejected_key_leaves_nothing_behind(fake):
    _connect_aws(fake)
    fake.on("sts", rc=254, err="An error occurred (InvalidClientTokenId): The security token included in the request is invalid. secret=abc")
    with pytest.raises(cloudapps.CloudError, match="InvalidClientTokenId") as e:
        cloudapps.connect("aws", {"access_key_id": "AKIAABCDEFGHIJKLMNOQ", "secret_access_key": "b" * 40})
    assert "abc" not in str(e.value)
    assert not (cloudapps.BASE / "aws").exists() and "aws" not in cloudapps.load()


def test_gcp_connect_activates_the_service_account_and_sets_the_project(fake):
    with pytest.raises(cloudapps.CloudError, match="whole service account key"):
        cloudapps.connect("gcp", {"key_json": "not json"})
    with pytest.raises(cloudapps.CloudError, match="isn't a service account"):
        cloudapps.connect("gcp", {"key_json": json.dumps({"type": "authorized_user"})})
    key = {"type": "service_account", "client_email": "a@b", "private_key": "k"}
    with pytest.raises(cloudapps.CloudError, match="project ID"):
        cloudapps.connect("gcp", {"key_json": json.dumps(key)})
    info = _connect_gcp(fake)
    assert info["account"] == {"identity": "panel@my-project-123.iam.gserviceaccount.com", "project": "my-project-123", "connected": info["account"]["connected"]}
    assert "--key-file=" in " ".join(fake.last("activate-service-account"))
    assert fake.last("config", "set", "project")[-1] == "my-project-123"
    assert "project=my-project-123" in info["console"]
    fake.on("activate-service-account", rc=1, err="ERROR: (gcloud.auth) Invalid key")
    with pytest.raises(cloudapps.CloudError, match="Invalid key"):
        _connect_gcp(fake)
    fake.rules.pop(0)
    fake.on("config", "set", rc=1, err="ERROR: bad project")
    with pytest.raises(cloudapps.CloudError, match="bad project"):
        _connect_gcp(fake)


def test_azure_connect_signs_in_the_service_principal(fake):
    g = "0b1c2d3e-4f50-6172-8394-a5b6c7d8e9f0"
    with pytest.raises(cloudapps.CloudError, match="tenant"):
        cloudapps.connect("azure", {"tenant_id": "x", "client_id": g, "client_secret": "longenough"})
    with pytest.raises(cloudapps.CloudError, match="subscription"):
        cloudapps.connect("azure", {"tenant_id": g, "client_id": g, "client_secret": "longenough", "subscription_id": "x"})
    with pytest.raises(cloudapps.CloudError, match="secret"):
        cloudapps.connect("azure", {"tenant_id": g, "client_id": g, "client_secret": "x"})
    info = _connect_azure(fake)
    assert info["account"]["subscription_name"] == "Pay-As-You-Go"
    assert "--service-principal" in fake.last("login") and fake.envs[-1]["AZURE_CONFIG_DIR"].endswith("azure")
    fake.on("account", "set", rc=1, err="ERROR: The subscription doesn't exist")
    with pytest.raises(cloudapps.CloudError, match="subscription"):
        _connect_azure(fake)
    fake.on("login", rc=1, err="AADSTS7000215: Invalid client secret provided.")
    with pytest.raises(cloudapps.CloudError, match="AADSTS"):
        _connect_azure(fake)


def test_disconnect_forgets_the_account_and_its_folder(fake):
    _connect_azure(fake)
    assert (cloudapps.BASE / "azure").exists()
    info = cloudapps.disconnect("azure")
    assert not info["connected"] and not (cloudapps.BASE / "azure").exists()
    assert fake.last("logout")
    with pytest.raises(cloudapps.CloudError, match="Connect your Azure"):
        cloudapps.items("azure", "vms")


def test_version_and_shell_env(fake):
    fake.on("--version", out="aws-cli/2.23.6 Python/3.13.5 Linux/6.12 source/aarch64\n")
    assert cloudapps.provider_info("aws")["version"].startswith("aws-cli/2.23.6")
    assert "AWS_CONFIG_FILE=" in cloudapps.shell_env("aws") and "HOME=" not in cloudapps.shell_env("aws")
    assert "CLOUDSDK_CONFIG=" in cloudapps.shell_env("gcp") and "AZURE_CONFIG_DIR=" in cloudapps.shell_env("azure")


def test_errors_are_short_and_secrets_masked():
    msg = cloudapps._clean_err("WARNING: noise\nline one\npassword: hunter2 and key=AKIA123\n")
    assert "hunter2" not in msg and "AKIA123" not in msg and "noise" not in msg
    assert cloudapps._clean_err("") == "The command failed"


def test_timeouts_and_non_json_answers_become_readable_errors(fake, monkeypatch):
    _connect_aws(fake)
    fake.on("ec2", out="this is not json")
    with pytest.raises(cloudapps.CloudError, match="wasn't JSON"):
        cloudapps.items("aws", "vms")

    def slow(argv, **kw):
        raise subprocess.TimeoutExpired(argv, 1)
    monkeypatch.setattr(subprocess, "run", slow)
    with pytest.raises(cloudapps.CloudError, match="longer than"):
        cloudapps.items("aws", "vms")


# ------------------------------------------------------------------ inventory
SAMPLES = {
    ("aws", "vms"): ("describe-instances", {"Reservations": [{"Instances": [{"InstanceId": "i-0abc12345678", "State": {"Name": "running"}, "InstanceType": "t3.micro",
                                                                            "Placement": {"AvailabilityZone": "eu-central-1a"}, "PublicIpAddress": "3.3.3.3", "Tags": [{"Key": "Name", "Value": "web"}]}]}]}),
    ("aws", "storage"): ("list-buckets", {"Buckets": [{"Name": "my-backups", "CreationDate": "2026-01-02T00:00:00Z"}]}),
    ("aws", "databases"): ("describe-db-instances", {"DBInstances": [{"DBInstanceIdentifier": "db1", "DBInstanceStatus": "available", "Engine": "postgres", "EngineVersion": "16", "DBInstanceClass": "db.t4g.micro"}]}),
    ("aws", "kubernetes"): ("list-clusters", {"clusters": ["k1"]}),
    ("aws", "functions"): ("list-functions", {"Functions": [{"FunctionName": "f1", "Runtime": "python3.12", "MemorySize": 128, "LastModified": "2026-02-02T00:00"}]}),
    ("aws", "containers"): ("ecs list-clusters", {"clusterArns": ["arn:aws:ecs:eu:1:cluster/c1"]}),
    ("aws", "analytics"): ("describe-clusters", {"Clusters": [{"ClusterIdentifier": "r1", "ClusterStatus": "available", "NodeType": "ra3.xlplus", "NumberOfNodes": 2}]}),
    ("gcp", "vms"): ("instances list", [{"name": "vm1", "zone": "https://x/zones/us-central1-a", "status": "TERMINATED", "machineType": "https://x/machineTypes/e2-micro",
                                         "networkInterfaces": [{"accessConfigs": [{"natIP": "4.4.4.4"}]}]}]),
    ("gcp", "storage"): ("buckets list", [{"name": "b1", "location": "US", "default_storage_class": "STANDARD"}, {"storage_url": "gs://b2/"}]),
    ("gcp", "databases"): ("sql instances", [{"name": "sql1", "state": "RUNNABLE", "databaseVersion": "MYSQL_8_0", "settings": {"tier": "db-f1-micro"}, "region": "us-central1"}]),
    ("gcp", "kubernetes"): ("container clusters", [{"name": "g1", "status": "RUNNING", "location": "us-central1", "currentNodeCount": 3}]),
    ("gcp", "functions"): ("functions list", [{"name": "projects/p/locations/l/functions/fn1", "state": "ACTIVE", "environment": "GEN_2", "buildConfig": {"runtime": "python312"}}]),
    ("gcp", "containers"): ("run services", [{"metadata": {"name": "svc1"}, "status": {"url": "https://svc1.run.app", "conditions": [{"type": "Ready", "status": "True"}]}}]),
    ("gcp", "analytics"): ("bq ls", [{"datasetReference": {"datasetId": "ds1"}, "location": "US"}]),
    ("azure", "vms"): ("vm list", [{"name": "avm", "resourceGroup": "rg1", "powerState": "VM deallocated", "hardwareProfile": {"vmSize": "B1s"}, "location": "westeurope", "publicIps": ""}]),
    ("azure", "storage"): ("storage account list", [{"name": "acct1", "location": "westeurope", "kind": "StorageV2", "resourceGroup": "rg1", "statusOfPrimary": "available"}]),
    ("azure", "databases"): ("sql server list", [{"name": "sqls", "state": "Ready", "location": "westeurope", "resourceGroup": "rg1"}]),
    ("azure", "kubernetes"): ("aks list", [{"name": "aks1", "powerState": {"code": "Running"}, "kubernetesVersion": "1.30", "location": "westeurope"}]),
    ("azure", "functions"): ("functionapp list", [{"name": "fa1", "state": "Running", "defaultHostName": "fa1.azurewebsites.net"}]),
    ("azure", "containers"): ("container list", [{"name": "ci1", "provisioningState": "Succeeded", "location": "westeurope", "osType": "Linux"}]),
    ("azure", "analytics"): ("synapse workspace", [{"name": "syn1", "provisioningState": "Succeeded", "location": "westeurope"}]),
}


@pytest.mark.parametrize("provider,service", list(SAMPLES))
def test_every_service_is_listed_in_one_shape(fake, provider, service):
    {"aws": _connect_aws, "gcp": _connect_gcp, "azure": _connect_azure}[provider](fake)
    words, out = SAMPLES[(provider, service)]
    fake.on(*words.split(), out=out)
    d = cloudapps.items(provider, service)
    assert d["items"], d
    for it in d["items"]:
        assert set(it) >= {"id", "name", "status", "detail"} and it["name"]
    if service == "vms":
        assert d["items"][0]["actions"] == ["start", "stop"]
    if service == "storage":
        assert all(it["browse"] for it in d["items"])


def test_inventory_details_read_the_right_fields(fake):
    _connect_aws(fake)
    fake.on("describe-instances", out=SAMPLES[("aws", "vms")][1])
    vm = cloudapps.items("aws", "vms")["items"][0]
    assert vm["name"] == "web" and vm["status"] == "running" and vm["detail"] == "t3.micro · eu-central-1a · 3.3.3.3"
    _connect_gcp(fake)
    fake.on("instances list", out=SAMPLES[("gcp", "vms")][1])
    g = cloudapps.items("gcp", "vms")["items"][0]
    assert g["id"] == "us-central1-a/vm1" and g["detail"] == "e2-micro · us-central1-a · 4.4.4.4"
    fake.on("buckets list", out=SAMPLES[("gcp", "storage")][1])
    assert [b["name"] for b in cloudapps.items("gcp", "storage")["items"]] == ["b1", "b2"]
    _connect_azure(fake)
    fake.on("vm list", out=SAMPLES[("azure", "vms")][1])
    a = cloudapps.items("azure", "vms")["items"][0]
    assert a["id"] == "rg1/avm" and a["status"] == "deallocated"


def test_empty_answers_are_empty_lists(fake):
    _connect_aws(fake)
    fake.on("describe-instances", out="")
    assert cloudapps.items("aws", "vms")["items"] == []


def test_bigquery_needs_bq_and_reports_its_errors(fake, monkeypatch):
    _connect_gcp(fake)
    fake.on("bq ls", rc=1, err="BigQuery error: Access Denied")
    with pytest.raises(cloudapps.CloudError, match="Access Denied"):
        cloudapps.items("gcp", "analytics")
    monkeypatch.setattr(cloudapps.shutil, "which", lambda name, path=None: None if name == "bq" else f"/usr/bin/{name}")
    with pytest.raises(cloudapps.CloudError, match="bq tool"):
        cloudapps.items("gcp", "analytics")


# ------------------------------------------------------------------ virtual servers
def test_vm_actions_send_the_provider_specific_command(fake):
    _connect_aws(fake)
    assert "Starting" in cloudapps.vm_action("aws", "i-0abc12345678", "start")["message"]
    assert fake.last("start-instances")[-3:] == ["i-0abc12345678", "--output", "json"]
    with pytest.raises(cloudapps.CloudError, match="Unknown instance"):
        cloudapps.vm_action("aws", "i-; rm -rf /", "stop")
    with pytest.raises(cloudapps.CloudError, match="Start or stop"):
        cloudapps.vm_action("aws", "i-0abc12345678", "terminate")
    _connect_gcp(fake)
    cloudapps.vm_action("gcp", "us-central1-a/vm1", "stop")
    assert "--zone=us-central1-a" in fake.last("instances", "stop")
    _connect_azure(fake)
    r = cloudapps.vm_action("azure", "rg1/avm", "stop")
    assert "Stopping avm" in r["message"] and "deallocate" in fake.last("vm", "avm")
    with pytest.raises(cloudapps.CloudError, match="Unknown virtual server"):
        cloudapps.vm_action("azure", "rg1/avm/../x", "start")
    fake.on("vm", "start", rc=1, err="ERROR: (AuthorizationFailed) no permission")
    with pytest.raises(cloudapps.CloudError, match="AuthorizationFailed"):
        cloudapps.vm_action("azure", "rg1/avm", "start")


# ------------------------------------------------------------------ storage
def test_browse_root_lists_buckets_and_rejects_bad_paths(fake):
    _connect_aws(fake)
    fake.on("list-buckets", out=SAMPLES[("aws", "storage")][1])
    d = cloudapps.browse("aws", "")
    assert d["path"] == "" and d["entries"][0]["name"] == "my-backups" and d["entries"][0]["dir"]
    for bad in ("my-backups/../etc", "BAD_BUCKET", "b\\x"):
        with pytest.raises(cloudapps.CloudError):
            cloudapps.browse("aws", bad)


def test_browse_s3_folders_and_files(fake):
    _connect_aws(fake)
    fake.on("list-objects-v2", out={"CommonPrefixes": [{"Prefix": "pics/2026/"}], "Contents": [{"Key": "pics/", "Size": 0}, {"Key": "pics/a.jpg", "Size": 12, "LastModified": "x"}]})
    d = cloudapps.browse("aws", "my-backups/pics")
    assert d["path"] == "my-backups/pics"
    assert d["entries"] == [{"name": "2026", "dir": True, "size": None}, {"name": "a.jpg", "dir": False, "size": 12, "modified": "x"}]
    assert "--prefix" in fake.last("list-objects-v2") and "pics/" in fake.last("list-objects-v2")


def test_browse_gcs_parses_ls_long(fake):
    _connect_gcp(fake)
    fake.on("storage ls", out="                                 gs://bk1/docs/sub/\n      1234  2026-03-01T10:00:00Z  gs://bk1/docs/a.txt\nTOTAL: 1 objects, 1234 bytes (1.21kiB)\n")
    d = cloudapps.browse("gcp", "bk1/docs")
    assert d["entries"] == [{"name": "sub", "dir": True, "size": None}, {"name": "a.txt", "dir": False, "size": 1234, "modified": "2026-03-01T10:00:00Z"}]
    fake.on("storage ls", rc=1, err="ERROR: One or more URLs matched no objects.")
    assert cloudapps.browse("gcp", "bk1/empty")["entries"] == []
    fake.on("storage ls", rc=1, err="ERROR: 403 forbidden")
    with pytest.raises(cloudapps.CloudError, match="403"):
        cloudapps.browse("gcp", "bk1")


def test_browse_azure_accounts_containers_and_blobs(fake):
    _connect_azure(fake)
    fake.on("container list --account-name", out=[{"name": "photos"}])
    assert cloudapps.browse("azure", "acct1")["entries"] == [{"name": "photos", "dir": True, "size": None}]
    fake.on("blob list", out=[{"name": "2026/"}, {"name": "a.png", "properties": {"contentLength": 5, "lastModified": "t"}}, {"name": ""}])
    d = cloudapps.browse("azure", "acct1/photos")
    assert [e["name"] for e in d["entries"]] == ["2026", "a.png"] and d["entries"][1]["size"] == 5


def test_transfers_build_safe_copy_commands(fake, launched, files_root):
    (files_root / "site").mkdir()
    (files_root / "site" / "index.html").write_text("hi")
    _connect_aws(fake)
    cloudapps.transfer("aws", "push", str(files_root / "site" / "index.html"), "my-backups/www")
    a = launched[-1]["argv"]
    assert a[1:3] == ["s3", "cp"] and a[-2] == "s3://my-backups/www/index.html" and "--recursive" not in a
    cloudapps.transfer("aws", "push", str(files_root / "site"), "my-backups")
    assert launched[-1]["argv"][4] == "s3://my-backups/site/" and "--recursive" in launched[-1]["argv"]
    cloudapps.transfer("aws", "pull", str(files_root), "my-backups/www/")
    assert launched[-1]["argv"][3:5] == ["s3://my-backups/www/", str(files_root / "www")]
    cloudapps.transfer("aws", "pull", str(files_root), "my-backups/www/index.html")
    assert launched[-1]["argv"][4] == str(files_root) + "/"
    assert launched[-1]["env"]["AWS_CONFIG_FILE"].endswith("config")
    with pytest.raises(cloudapps.CloudError, match="doesn't exist"):
        cloudapps.transfer("aws", "push", str(files_root / "nope"), "my-backups")
    with pytest.raises(cloudapps.CloudError, match="into a folder"):
        cloudapps.transfer("aws", "pull", str(files_root / "site" / "index.html"), "my-backups/x")
    with pytest.raises(cloudapps.CloudError, match="Pick a bucket"):
        cloudapps.transfer("aws", "push", str(files_root / "site"), "")
    with pytest.raises(cloudapps.CloudError, match="Pick a file"):
        cloudapps.transfer("aws", "push", "", "my-backups")
    with pytest.raises(cloudapps.CloudError, match="Push"):
        cloudapps.transfer("aws", "sync", str(files_root), "my-backups")


def test_transfers_on_google_cloud_and_azure(fake, launched, files_root):
    (files_root / "pics").mkdir()
    (files_root / "pics" / "a.jpg").write_text("x")
    _connect_gcp(fake)
    cloudapps.transfer("gcp", "push", str(files_root / "pics"), "bk1/backup")
    assert launched[-1]["argv"][1:4] == ["storage", "cp", "--recursive"] and launched[-1]["argv"][-1] == "gs://bk1/backup/"
    cloudapps.transfer("gcp", "pull", str(files_root), "bk1/backup/")
    assert launched[-1]["argv"][-2:] == ["gs://bk1/backup", str(files_root)]
    _connect_azure(fake)
    with pytest.raises(cloudapps.CloudError, match="container"):
        cloudapps.transfer("azure", "push", str(files_root / "pics"), "acct1")
    cloudapps.transfer("azure", "push", str(files_root / "pics"), "acct1/photos/2026")
    a = launched[-1]["argv"]
    assert "upload-batch" in a and a[a.index("--destination-path") + 1] == "2026/pics" and a[a.index("--overwrite") + 1] == "false"
    cloudapps.transfer("azure", "push", str(files_root / "pics" / "a.jpg"), "acct1/photos")
    assert launched[-1]["argv"][launched[-1]["argv"].index("--name") + 1] == "a.jpg"
    cloudapps.transfer("azure", "pull", str(files_root), "acct1/photos/2026/")
    assert "download-batch" in launched[-1]["argv"] and "2026/*" in launched[-1]["argv"]
    cloudapps.transfer("azure", "pull", str(files_root), "acct1/photos/2026/a.jpg")
    assert launched[-1]["argv"][-4] == str(files_root / "a.jpg")
    with pytest.raises(cloudapps.CloudError, match="container"):
        cloudapps.transfer("azure", "pull", str(files_root), "acct1")


def test_local_paths_stay_inside_the_file_manager(fake, launched, files_root):
    _connect_aws(fake)
    with pytest.raises(cloudapps.CloudError, match="limited"):
        cloudapps.transfer("aws", "push", "/etc/shadow", "my-backups")


# ------------------------------------------------------------------ API
def test_api_lists_and_reports_errors_as_400(admin, fake):
    r = admin.get("/api/cloud")
    assert r.status_code == 200 and len(r.json()["providers"]) == 3
    assert admin.get("/api/cloud/oracle").status_code == 400
    r = admin.post("/api/cloud/aws/connect", json={"access_key_id": "x"})
    assert r.status_code == 400 and "AKIA" in r.json()["detail"]
    assert admin.get("/api/cloud/aws/services/vms").status_code == 400
    assert admin.post("/api/cloud/aws/vm", json={"id": "i-1", "action": "start"}).status_code == 400
    assert admin.get("/api/cloud/aws/browse?path=").status_code == 400
    assert admin.post("/api/cloud/aws/transfer", json={"direction": "push", "local": "/x", "remote": "b"}).status_code == 400
    fake.on("sts", out={"Arn": "arn:x", "Account": "1"})
    r = admin.post("/api/cloud/aws/connect", json={"access_key_id": "AKIAABCDEFGHIJKLMNOP", "secret_access_key": "c" * 40})
    assert r.status_code == 200 and r.json()["connected"] and "c" * 40 not in r.text
    fake.on("describe-instances", out={"Reservations": []})
    assert admin.get("/api/cloud/aws/services/vms").json()["items"] == []
    assert admin.post("/api/cloud/aws/disconnect").json()["connected"] is False


def test_frontend_wires_both_panels():
    """Cloud Apps and Third-party Apps: a sidebar group each, dashboard tiles, titles, and cloud.js loaded before app.js."""
    from pathlib import Path
    front = Path(__file__).resolve().parent.parent / "frontend"
    html = (front / "index.html").read_text(encoding="utf-8")
    assert html.index("/js/cloud.js") < html.index("/js/app.js")
    for view in ("cloud", "cloudaws", "cloudgcp", "cloudazure", "connect", "gdrive", "gphotos"):
        assert f'data-view="{view}"' in html, view
    assert '<div class="nav-group">Cloud Apps</div>' in html and '<div class="nav-group">Third-party Apps</div>' in html
    app_js = (front / "js" / "app.js").read_text(encoding="utf-8")
    assert "cloudViews()[view]" in app_js and '"Cloud Apps": "t_cloud"' in app_js and '{ name: "Third-party Apps", icon: "plug", tiles: [' in app_js
    cloud_js = (front / "js" / "cloud.js").read_text(encoding="utf-8")
    for needle in ("API.cloudTransfer(pid, \"push\"", "API.connectStart(", "API.connectFinish(", "requireCard(", "Nothing is ever deleted"):
        assert needle in cloud_js, needle


def test_google_cloud_cli_installs_with_debians_python(monkeypatch):
    """The Python bundled with google-cloud-cli segfaults on some Pi kernels, so its install (and the
    panel's own gcloud calls) use /usr/bin/python3; the Google apt source is added first."""
    from backend import requires
    seen = {"apt": [], "pre": 0}

    class Log:
        def __call__(self, line):
            pass

        def progress(self, pct, stage=None):
            pass

        def apt(self, args, span=(0, 100), timeout=1800, env=None):
            seen["apt"].append((args[0], env))
            return 0

    def launch_fn(title, fn, meta=None):
        seen["result"] = fn(Log())
        return type("J", (), {"id": "j"})()

    comp = dict(requires.COMPONENTS["gcloud"])
    comp["pre"] = lambda: seen.__setitem__("pre", seen["pre"] + 1) or []
    comp["check"] = lambda: True
    monkeypatch.setitem(requires.COMPONENTS, "gcloud", comp)
    monkeypatch.setattr(requires.shutil, "which", lambda name, path=None: "/usr/bin/apt-get")
    monkeypatch.setattr(requires.jobs, "launch_fn", launch_fn)
    monkeypatch.setattr(requires.jobs, "find", lambda **m: [])
    requires.install("gcloud")
    assert seen["pre"] == 1 and seen["result"] == {"installed": ["gcloud"]}
    assert ("install", {"CLOUDSDK_PYTHON": "/usr/bin/python3"}) in seen["apt"]
    assert cloudapps.env("gcp")["CLOUDSDK_PYTHON"] == "/usr/bin/python3"
