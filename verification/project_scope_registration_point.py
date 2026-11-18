#!/usr/bin/env python3
"""One private API metadata point; preparation starts no processes or database.

Root GO + immutable newly built server required. Two paused managed repositories
and one observed-read-only source coexist. Actual worker bearer registration
scope denials preserve SQL state. No Worker/model/browser/Cargo or main service.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import secrets
import signal
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
import uuid

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "verification"))
sys.path.insert(0, str(ROOT / "benchmarks"))
from guarded_api_chain import create_database, database_command, secure_save

SOURCES = ("crates/api/src/workers.rs", "crates/api/src/auth.rs", "crates/api/src/catalog.rs",
           "crates/api/src/lib.rs", "crates/store/src/lifecycle.rs", "crates/store/src/admission.rs",
           "crates/store/src/catalog.rs", "crates/domain/src/model.rs", "crates/domain/src/commands.rs")
HELPERS = ("verification/guarded_api_chain.py", "verification/algorithm_check.py",
           "benchmarks/control_load.py", "verification/oracle.py", "benchmarks/metrics.py")
COUNTS = "SELECT json_build_object('workers',(SELECT count(*) FROM workers),'attempts',(SELECT count(*) FROM attempts),'leases',(SELECT count(*) FROM leases),'allocations',(SELECT count(*) FROM resource_allocations),'allocated',(SELECT COALESCE(sum(allocated),0) FROM resource_limits),'provider_requests',(SELECT count(*) FROM provider_requests),'model_requests',(SELECT count(*) FROM model_request_permit),'native_model_requests',(SELECT count(*) FROM native_model_requests),'commands',(SELECT count(*) FROM idempotency_records),'events',(SELECT count(*) FROM events));"


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def save(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x") as stream:
        json.dump(value, stream, ensure_ascii=False, indent=2)
        stream.write("\n")


def pins(receipt_path):
    receipt = json.loads(Path(receipt_path).read_text())
    source = {}
    for relative in SOURCES:
        expected = receipt["source_files"][relative]
        if sha(Path(receipt["snapshot_root"]) / relative) != expected:
            raise RuntimeError("immutable source pin mismatch: " + relative)
        source[relative] = {"checkpoint_sha256": expected, "working_sha256": sha(ROOT / relative)}
    server = receipt["binaries"]["forgeflow-server"]
    if sha(server["path"]) != server["sha256"]:
        raise RuntimeError("immutable server pin mismatch")
    text = (Path(receipt["snapshot_root"]) / "crates/api/src/workers.rs").read_text()
    if "body.project_id.as_deref()" not in text or "project identity is required by deployment worker scope" not in text:
        raise RuntimeError("build does not contain the precise registration scope correction")
    return receipt, {"source_identity": receipt["source_identity"], "receipt_sha256": sha(receipt_path),
                     "source_files": source, "server": server}


class Client:
    def __init__(self, url, token, role, output, private):
        self.url, self.token, self.role, self.output, self.private = url, token, role, output, private
        self.number = 0
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

    def request(self, method, path, body=None):
        self.number += 1
        raw = None if body is None else json.dumps(body, ensure_ascii=False, separators=(",", ":")).encode()
        headers = {"Authorization": "Bearer " + self.token, "Content-Type": "application/json",
                   "Idempotency-Key": "g02-" + uuid.uuid4().hex}
        url = self.url + ("" if path == "/healthz" else "/api/v1") + path
        req = urllib.request.Request(url, data=raw, headers=headers, method=method)
        try:
            response = self.opener.open(req, timeout=15)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            data, status = response.read(), response.status
        value = json.loads(data)
        # No raw authorization/credentials are persisted in public evidence.
        stem = f"{self.role}-{self.number:03d}"
        secure_save(self.private / (stem + ".json"), {"method": method, "path": path,
                    "body": body, "status": status, "response": value})
        save(self.output / "requests" / (stem + ".json"), {"method": method, "path": path,
             "principal_role": self.role, "body": body, "status": status, "response": value,
             "request_sha256": hashlib.sha256(raw or b"").hexdigest(), "response_sha256": hashlib.sha256(data).hexdigest()})
        return status, value

    def ok(self, method, path, body=None):
        status, value = self.request(method, path, body)
        if not 200 <= status < 300:
            raise RuntimeError(f"actual {self.role} API {method} {path}: {status}/{value.get('code')}")
        return value.get("data", value)


def state(database_url):
    result = database_command(database_url, COUNTS)
    if result.returncode:
        raise RuntimeError("read-only private SQL count failed")
    return json.loads(result.stdout)


def fingerprint(sources):
    facts = {}
    for name, root in sources.items():
        facts[name] = {"canonical_root": str(root.resolve()), "input_sha256": sha(root / "input.json")}
        if name != "S":
            result = subprocess.run(["git", "-C", str(root), "rev-parse", "HEAD"], capture_output=True, check=True, text=True)
            facts[name]["git_head"] = result.stdout.strip()
            facts[name]["git_status"] = subprocess.run(["git", "-C", str(root), "status", "--porcelain"], capture_output=True, check=True, text=True).stdout
    return facts


def prepare(args):
    manifest = {"status": "PREPARED_NOT_RUN", "source_ready": {p: sha(ROOT / p) for p in SOURCES},
        "helpers": {p: sha(ROOT / p) for p in HELPERS}, "harness_sha256": sha(__file__),
        "port": args.port, "runtime_budget_seconds": 120, "needs_new_approved_build_and_root_go": True,
        "scope": "fresh private DB/API; two paused managed projects + observed-read-only source; bearer registration metadata only",
        "cases": ["wrong_project_Q", "missing_project", "wrong_worker_identity", "correct_P", "worker_owner_write_denied", "worker_owner_read_denied"],
        "no": ["Worker process", "model", "browser", "Cargo", "main8787 mutation", "whole business-chain rerun"]}
    if args.build_receipt:
        manifest["source_binding"] = pins(args.build_receipt)[1]
    save(Path(args.output) / "preparation.json", manifest)
    print(json.dumps({"status": manifest["status"], "port": args.port, "runtime_budget_seconds": 120}))
    return 0


def run(args):
    if args.root_go != "G02_PRIVATE_REGISTRATION_ONLY" or not args.build_receipt:
        raise RuntimeError("Root GO and new immutable build receipt required")
    if args.port != 8898:
        raise RuntimeError("only registered private port8898 is authorized")
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", args.port))
    receipt, binding = pins(args.build_receipt)
    output = Path(args.output)
    if (output / "report.json").exists() or (output / "requests").exists():
        raise RuntimeError("preserve prior evidence; no automatic full rerun")
    output.mkdir(parents=True, exist_ok=True)
    private = Path(tempfile.mkdtemp(prefix="forgeflow-g02-point-", dir="/home/chenyoujian/.cache"))
    private.chmod(0o700)
    tag = uuid.uuid4().hex[:12]
    projects = {name: "g02-" + name.lower() + "-" + tag for name in ("P", "Q", "S")}
    worker = "g02-worker-" + tag
    env = {"DATABASE_URL": create_database(json.loads(Path(args.database_env).read_text()), "forgeflow_g02_" + tag, private),
        "FORGEFLOW_BIND": "127.0.0.1:8898", "FORGEFLOW_DATA_ROOT": str(private / "state"),
        "FORGEFLOW_OWNER_TOKEN": secrets.token_hex(32), "FORGEFLOW_WORKER_TOKEN": secrets.token_hex(32),
        "FORGEFLOW_WORKER_ID": worker, "FORGEFLOW_WORKER_PROJECT_ID": projects["P"], "RUST_LOG": "info"}
    secure_save(private / "runtime-env.json", env)
    sources = {}
    for name in projects:
        root = private / ("source-" + name)
        root.mkdir(mode=0o700)
        (root / "input.json").write_text(json.dumps({"source": name, "scope": "G02_METADATA_ONLY"}) + "\n")
        if name != "S":
            for argv in [["git", "init", "--initial-branch=main", str(root)],
                         ["git", "-C", str(root), "add", "input.json"],
                         ["git", "-C", str(root), "-c", "user.name=G02 fixture", "-c", "user.email=g02@example.invalid", "commit", "-m", "metadata source"]]:
                subprocess.run(argv, capture_output=True, check=True, timeout=10)
        sources[name] = root
    original_sources = fingerprint(sources)
    owner = Client("http://127.0.0.1:8898", env["FORGEFLOW_OWNER_TOKEN"], "owner", output, private)
    scoped = Client("http://127.0.0.1:8898", env["FORGEFLOW_WORKER_TOKEN"], "worker", output, private)
    result = {"status": "FAIL", "scope": "bounded actual private API registration/coexistence point", "source_binding": binding,
        "helpers": {p: sha(ROOT / p) for p in HELPERS}, "harness_sha256": sha(__file__), "checks": [],
        "models_started": 0, "workers_started": 0, "browsers_started": 0, "projects": projects,
        "private_runtime": str(private), "source_fingerprints_before": original_sources, "not_proven": ["per-individual-worker credentials in an unscoped fleet", "complete G02 or production Gate", "actual author isolation rerun"]}
    server, log = None, None
    def check(name, passed, facts=None):
        result["checks"].append({"name": name, "status": "PASS" if passed else "FAIL", "facts": facts})
        if not passed:
            raise RuntimeError("point failed: " + name)
    try:
        log = os.fdopen(os.open(private / "server.log", os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600), "wb")
        server = subprocess.Popen([receipt["binaries"]["forgeflow-server"]["path"]], env={"PATH": "/usr/bin:/bin", **env}, stdout=log, stderr=subprocess.STDOUT)
        result["own_server_pid"] = server.pid
        deadline = time.monotonic() + 30
        while True:
            if server.poll() is not None:
                raise RuntimeError("private server exited before readiness")
            try:
                code, health = owner.request("GET", "/healthz")
                if code == 200 and health.get("database") == "postgres":
                    break
            except OSError:
                pass
            if time.monotonic() >= deadline:
                raise RuntimeError("private server readiness timeout")
            time.sleep(.25)
        persisted = {}
        for name, project in projects.items():
            persisted[name] = owner.ok("POST", "/projects", {"project_id": project, "name": "G02 point " + name,
                "root_path": str(sources[name]), "authority_mode": "OBSERVED_READ_ONLY" if name == "S" else "MANAGED",
                "data_origin": "NATIVE", "goal": "registration scope metadata point", "technology_stack": [], "timezone": "UTC",
                "paused": True, "archived": False, "revision": 0})
        roots = {name: value["root_path"] for name, value in persisted.items()}
        check("two_paused_managed_and_readonly_source_coexist", len(set(roots.values())) == 3 and
              persisted["P"]["authority_mode"] == persisted["Q"]["authority_mode"] == "MANAGED" and persisted["S"]["authority_mode"] == "OBSERVED_READ_ONLY", {"roots": roots})
        before = state(env["DATABASE_URL"])
        check("zero_registered_or_execution_actors_before_negatives", not any(before[k] for k in ("workers", "attempts", "leases", "allocations", "allocated", "provider_requests", "model_requests", "native_model_requests")), before)
        base = {"worker_id": worker, "boot_id": "g02-metadata-boot", "capabilities": [], "executor_profile_ids": []}
        for name, body in [("wrong_project_Q", {**base, "project_id": projects["Q"]}),
                           ("missing_project", {**base, "project_id": None}),
                           ("wrong_worker_identity", {**base, "worker_id": "other-worker", "project_id": projects["P"]})]:
            code, value = scoped.request("POST", "/workers/register", body)
            check(name, code == 403 and value.get("code") == "WORKER_SCOPE_DENIED", {"status": code, "code": value.get("code")})
            check(name + "_no_authority_change", state(env["DATABASE_URL"]) == before)
        for method, path, body in [("GET", "/projects/" + projects["Q"], None),
                                   ("PATCH", "/projects/" + projects["Q"], {"project": {**persisted["Q"], "name": "unauthorized"}, "expected_revision": persisted["Q"]["revision"]})]:
            code, value = scoped.request(method, path, body)
            check("worker_owner_" + ("read" if method == "GET" else "write") + "_denied", code == 403 and value.get("code") == "FORBIDDEN", {"status": code, "code": value.get("code")})
            check(method + "_no_authority_change", state(env["DATABASE_URL"]) == before)
        scoped.ok("POST", "/workers/register", {**base, "project_id": projects["P"]})
        after = state(env["DATABASE_URL"])
        expected = {**before, "workers": 1}
        check("correct_project_P_metadata_registration_only", after == expected, after)
        rows = database_command(env["DATABASE_URL"], "SELECT json_agg(json_build_object('worker_id',worker_id,'project_id',project_id,'boot_id',boot_id)) FROM workers;")
        if rows.returncode:
            raise RuntimeError("read-only actual registration identity lookup failed")
        check("registered_identity_exact_P", json.loads(rows.stdout) == [{"worker_id": worker, "project_id": projects["P"], "boot_id": base["boot_id"]}])
        for name in projects:
            check("persisted_root_unchanged_" + name, owner.ok("GET", "/projects/" + projects[name])["root_path"] == roots[name])
        result["source_fingerprints_after"] = fingerprint(sources)
        check("all_source_bytes_HEADs_roots_unchanged", original_sources == result["source_fingerprints_after"])
        result["final_authority"] = after
        result["status"] = "PASS_BOUNDED_ACTUAL_POINT"
    except Exception as error:
        message = str(error)
        for secret in (env["DATABASE_URL"], env["FORGEFLOW_OWNER_TOKEN"], env["FORGEFLOW_WORKER_TOKEN"]):
            message = message.replace(secret, "[PRIVATE]")
        result["error"] = {"type": type(error).__name__, "message": message}
    finally:
        if server is not None:
            if server.poll() is None:
                server.send_signal(signal.SIGTERM)
                try:
                    server.wait(timeout=20)
                except subprocess.TimeoutExpired:
                    server.kill()
                    server.wait(timeout=5)
                    result["status"] = "FAIL"
                    result["shutdown_error"] = "own server needed SIGKILL"
            result["own_server_exit"] = {"pid": server.pid, "code": server.returncode, "exited": server.poll() is not None}
        if log is not None:
            log.close()
        result["source_binding_after"] = pins(args.build_receipt)[1]
        result["assertions"] = len(result["checks"])
        save(output / "report.json", result)
    print(json.dumps({"status": result["status"], "assertions": result["assertions"]}))
    return 0 if result["status"] == "PASS_BOUNDED_ACTUAL_POINT" else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build-receipt")
    parser.add_argument("--output", default="evidence/goal-gap-points-r1/g02")
    parser.add_argument("--database-env", default="/home/chenyoujian/.local/state/forgeflow/control/runtime-env.json")
    parser.add_argument("--port", type=int, default=8898)
    parser.add_argument("--run", action="store_true")
    parser.add_argument("--root-go")
    args = parser.parse_args()
    return run(args) if args.run else prepare(args)


if __name__ == "__main__":
    sys.exit(main())
