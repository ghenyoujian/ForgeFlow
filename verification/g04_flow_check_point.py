#!/usr/bin/env python3
"""Six bounded G04 API points; preparation never starts a process or database.

Runtime requires an explicit Root GO and an immutable server build receipt.
Only a fresh isolated database, paused read-only project and planning metadata
are used. No Worker, execution, model, browser, Cargo or production DB mutation.
All cases use the read-only unsaved-draft compiler endpoint, not graph saves.
"""
import argparse
import hashlib
import json
import os
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
from pathlib import Path

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "verification"))
sys.path.insert(0, str(ROOT / "benchmarks"))
from algorithm_check import make_compile, requirement_digest

SOURCES = ("crates/planner/src/lib.rs", "crates/api/src/catalog.rs",
           "crates/api/src/lib.rs", "crates/store/src/catalog.rs",
           "crates/domain/src/model.rs", "crates/domain/src/lib.rs")
STATE_COUNTS = "SELECT json_build_object('flows',(SELECT count(*) FROM flow_revisions),'tasks',(SELECT count(*) FROM tasks),'task_revisions',(SELECT count(*) FROM task_revisions),'documents',(SELECT count(*) FROM documents),'events',(SELECT count(*) FROM events),'commands',(SELECT count(*) FROM idempotency_records));"
INPUT = b'{"source":"actual finite G04 planning input","version":1}\n'
CASES = (("valid", None), ("cycle", "DEPENDENCY_CYCLE"),
         ("missing_predecessor", "DANGLING_DEPENDENCY"),
         ("territory_conflict", "WRITE_SCOPE_CONFLICT"),
         ("stale_input", "INPUT_HASH_DRIFT"),
         ("contract_missing_evidence", "CONTRACT_NOT_FROZEN"))


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def save(path, value):
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    with Path(path).open("x") as stream:
        json.dump(value, stream, indent=2, ensure_ascii=False)
        stream.write("\n")


def fixture(project, revision, name):
    value = make_compile(3)
    flow, context = value["flow"], value["context"]
    flow.update(project_id=project, flow_revision=revision)
    requirement = {"project_id": project, "requirement_id": "R01", "title": "G04 finite planning points",
        "source_anchor": "g04-point#R01", "outcome": "locate invalid planning inputs",
        "scope": "six finite planning-only API cases", "acceptance": ["return source-bound blocking location"],
        "priority": 1, "weight": 1, "deferred_reason": None, "revision": 0}
    context["requirements"] = [{"requirement_id": "R01", "source_document": "g04-point",
        "anchor": "R01", "acceptance": requirement["acceptance"][0], "priority": 1, "deferred_reason": None}]
    context["requirement_semantic_digests"] = {"R01": requirement_digest(requirement)}
    digest = hashlib.sha256(INPUT).hexdigest()
    context["current_inputs"] = {"input.json": digest}
    for task in flow["tasks"]:
        task.update(project_id=project, flow_revision=revision, task_revision=revision)
        spec = context["task_specs"][task["task_id"]]
        spec["design_anchors"] = ["g04-point#R01"]
        spec["requirement_digest_refs"] = context["requirement_semantic_digests"].copy()
        spec["inputs"][0]["sha256"] = digest
        for edge in spec["dependency_refs"]:
            edge["project_id"] = project
    if name in {"cycle", "missing_predecessor"}:
        task = flow["tasks"][0]
        predecessor = "t00002" if name == "cycle" else "absent-task"
        task["dependencies"].append(predecessor)
        context["task_specs"][task["task_id"]]["dependency_refs"].append({
            "task_id": predecessor, "project_id": project, "kind": "integrated", "binding_id": "receipt-" + predecessor})
    elif name == "territory_conflict":
        for task in flow["tasks"]:
            task["dependencies"] = []
            context["task_specs"][task["task_id"]]["dependency_refs"] = []
        for task in flow["tasks"][:2]:
            task["write_set"] = ["outputs/shared.json"]
    elif name == "stale_input":
        context["task_specs"]["t00000"]["inputs"][0]["sha256"] = hashlib.sha256(b"prior input version\n").hexdigest()
    elif name == "contract_missing_evidence":
        context["task_specs"]["t00000"]["contract_consumes"] = [{
            "contract_id": "undelivered-contract", "version": 1, "spec_sha256": "d" * 64}]
    return {"flow": flow, "expected_revision": None, "context": context}, requirement


def pins(receipt_path):
    receipt = json.loads(Path(receipt_path).read_text())
    files = {}
    for relative in SOURCES:
        expected = receipt["source_files"][relative]
        snapshot = Path(receipt["snapshot_root"]) / relative
        if sha(snapshot) != expected:
            raise RuntimeError("immutable source pin mismatch: " + relative)
        files[relative] = {"checkpoint_sha256": expected, "working_sha256": sha(ROOT / relative)}
    server = receipt["binaries"]["forgeflow-server"]
    if sha(server["path"]) != server["sha256"]:
        raise RuntimeError("immutable server pin mismatch")
    return receipt, {"receipt_path": str(Path(receipt_path).resolve()), "receipt_sha256": sha(receipt_path),
        "source_identity": receipt["source_identity"], "source_files": files, "server": server}


class Client:
    def __init__(self, url, token, output):
        self.url, self.token, self.output, self.number = url, token, output, 0
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

    def request(self, method, path, body=None):
        self.number += 1
        raw = b"" if body is None else json.dumps(body, separators=(",", ":"), ensure_ascii=False).encode()
        stem = self.output / "requests" / f"{self.number:03d}"
        stem.parent.mkdir(parents=True, exist_ok=True)
        stem.with_suffix(".request.bin").write_bytes(raw)
        headers = {"Authorization": "Bearer " + self.token, "Content-Type": "application/json"}
        if method == "POST":
            headers["Idempotency-Key"] = "g04-" + uuid.uuid4().hex
            headers["X-Operation-ID"] = "g04-" + uuid.uuid4().hex
        request = urllib.request.Request(self.url + ("" if path == "/healthz" else "/api/v1") + path,
            data=raw if body is not None else None, headers=headers, method=method)
        try:
            response = self.opener.open(request, timeout=15)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            data, status = response.read(), response.status
        stem.with_suffix(".response.bin").write_bytes(data)
        save(stem.with_suffix(".meta.json"), {"method": method, "path": path, "status": status,
            "request_sha256": hashlib.sha256(raw).hexdigest(), "response_sha256": hashlib.sha256(data).hexdigest()})
        return status, json.loads(data)

    def ok(self, method, path, body=None):
        status, value = self.request(method, path, body)
        if not 200 <= status < 300:
            raise RuntimeError(f"actual API {method} {path}: {status}/{value.get('code')}")
        return value.get("data", value)


def locate(name, rule, status, value):
    report = value.get("data", value)
    findings = report.get("findings", [])
    matching = [finding for finding in findings if finding.get("rule_id") == rule]
    precise = status == 200 and report.get("passed") is False and bool(matching) and all(
        f.get("severity") == "BLOCKING" and f.get("subject_ref") and f.get("blocked_tasks") and
        f.get("evidence_refs") and f.get("suggested_action") and f.get("source_revision") and f.get("observed_at") for f in matching)
    if name == "cycle" and precise:
        path = matching[0]["evidence_refs"]
        precise = len(path) >= 4 and path[0] == path[-1] and set(path) == {"t00000", "t00001", "t00002"}
    if name == "missing_predecessor" and precise:
        precise = "absent-task" in matching[0]["evidence_refs"] and "t00000" in matching[0]["blocked_tasks"]
    if name == "territory_conflict" and precise:
        precise = set(matching[0]["blocked_tasks"]) == {"t00000", "t00001"}
    return {"name": name, "expected_rule": rule, "http_status": status,
        "actual_error_code": value.get("code"), "precise_localization": precise,
        "outcome": "PASS" if precise else "UNPROVEN", "matching_findings": matching}


def prepare(args):
    _, binding = pins(args.build_receipt)
    output = Path(args.output)
    output.mkdir(parents=True, exist_ok=True)
    cases = []
    for revision, (name, rule) in enumerate(CASES, 1):
        body, _ = fixture("g04-private-at-runtime", revision, name)
        file = output / "prepared" / (name + ".json")
        save(file, body)
        cases.append({"name": name, "fixture_path": str(file), "fixture_sha256": sha(file), "expected_rule": rule})
    save(output / "preparation.json", {"status": "PREPARED_NOT_RUN", "source_binding": binding,
        "case_count": len(CASES), "cases": cases, "runtime_requires_root_go": True,
        "runtime_scope": "fresh private DB/API; paused OBSERVED_READ_ONLY project; zero workers/models/attempts",
        "runtime_endpoint": "POST /projects/{project}/flow-checks",
        "source_ready_change": "check unsaved proposals against authoritative inputs without persisting Flow/findings/events; generic graph-save rejection is not a passing oracle",
        "source_locations": {"saved_flow_check": "crates/api/src/catalog.rs:279", "graph_save_rejection": "crates/store/src/catalog.rs:1405",
            "compiler_graph_findings": "crates/planner/src/lib.rs:2300", "input_snapshot": "crates/api/src/catalog.rs:949"}})


def run(args):
    if args.root_go != "G04_PRIVATE_METADATA_ONLY":
        raise RuntimeError("explicit Root GO required")
    if not 1024 <= args.port <= 65535 or args.port == 8787:
        raise RuntimeError("use a dedicated private high port, never main 8787")
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", args.port))
    receipt, binding = pins(args.build_receipt)
    output = Path(args.output)
    output.mkdir(parents=True, exist_ok=True)
    if (output / "report.json").exists() or (output / "requests").exists():
        raise RuntimeError("runtime output exists; preserve it and do not repeat")
    from guarded_api_chain import create_database, database_command, secure_save
    private = Path(tempfile.mkdtemp(prefix="forgeflow-g04-", dir="/home/chenyoujian/.cache"))
    tag = uuid.uuid4().hex[:16]
    main = json.loads(Path(args.database_env).read_text())
    env = {"DATABASE_URL": create_database(main, "forgeflow_g04_" + tag, private),
        "FORGEFLOW_BIND": f"127.0.0.1:{args.port}", "FORGEFLOW_DATA_ROOT": str(private / "state"),
        "FORGEFLOW_OWNER_TOKEN": secrets.token_hex(32), "FORGEFLOW_WORKER_TOKEN": secrets.token_hex(32), "RUST_LOG": "info"}
    secure_save(private / "runtime-env.json", env)
    source = private / "source"
    source.mkdir(mode=0o700)
    (source / "input.json").write_bytes(INPUT)
    client = Client(f"http://127.0.0.1:{args.port}", env["FORGEFLOW_OWNER_TOKEN"], output)
    server = None
    log = None
    result = {"outcome": "FAIL", "source_binding": binding, "cases": [], "private_runtime": str(private),
        "models_started": 0, "workers_started": 0, "browsers_started": 0}
    try:
        log = os.fdopen(os.open(private / "server.log", os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600), "wb")
        server = subprocess.Popen([receipt["binaries"]["forgeflow-server"]["path"]],
            env={"PATH": "/usr/bin:/bin", **env}, stdout=log, stderr=subprocess.STDOUT)
        result["server_pid"] = server.pid
        deadline = time.monotonic() + 30
        while True:
            if server.poll() is not None:
                raise RuntimeError("isolated server exited before readiness")
            try:
                status, value = client.request("GET", "/healthz")
                if status == 200 and value.get("status") == "ok" and value.get("database") == "postgres":
                    break
                if 400 <= status < 500:
                    raise RuntimeError("readiness route returned actual HTTP " + str(status))
            except OSError:
                if time.monotonic() >= deadline:
                    raise RuntimeError("isolated server readiness timeout")
                time.sleep(.25)
            if time.monotonic() >= deadline:
                raise RuntimeError("isolated server readiness timeout")
        project = "g04-" + tag
        client.ok("POST", "/projects", {"project_id": project, "name": "G04 planning-only points", "root_path": str(source),
            "authority_mode": "OBSERVED_READ_ONLY", "data_origin": "NATIVE", "goal": "precise planning error localization",
            "technology_stack": [], "timezone": "Asia/Shanghai", "paused": True, "archived": False, "revision": 0})
        client.ok("POST", f"/projects/{project}/teams", {"project_id": project, "team_id": "team", "parent_team_id": None,
            "name": "G04 planning owner", "paused": True, "revision": 0})
        client.ok("POST", f"/projects/{project}/owners", {"id": "o", "value": {"owner_id": "o", "root_team_id": "team", "include": ["outputs/"], "exclude": []}})
        _, requirement = fixture(project, 1, "valid")
        client.ok("POST", f"/projects/{project}/requirements", requirement)
        snapshots = client.ok("POST", f"/projects/{project}/input-snapshots", {"paths": ["input.json"]})
        result["actual_input"] = {"sha256": sha(source / "input.json"), "api_snapshots": snapshots}
        before = database_command(env["DATABASE_URL"], STATE_COUNTS)
        if before.returncode:
            raise RuntimeError("private check-state baseline failed")
        result["check_state_before"] = json.loads(before.stdout)
        for revision, (name, rule) in enumerate(CASES, 1):
            body, _ = fixture(project, revision, name)
            status, value = client.request("POST", f"/projects/{project}/flow-checks", body)
            if name == "valid":
                report = value.get("data", value)
                result["cases"].append({"name": name, "http_status": status, "actual_report": report,
                    "outcome": "PASS" if status == 200 and report.get("passed") is True and not report.get("findings") else "FAIL"})
            else:
                result["cases"].append(locate(name, rule, status, value))
        after = database_command(env["DATABASE_URL"], STATE_COUNTS)
        if after.returncode:
            raise RuntimeError("private check-state final count failed")
        result["check_state_after"] = json.loads(after.stdout)
        result["six_checks_no_authority_writes"] = result["check_state_after"] == result["check_state_before"]
        counts = database_command(env["DATABASE_URL"], "SELECT json_build_object('workers',(SELECT count(*) FROM workers),'attempts',(SELECT count(*) FROM attempts),'leases',(SELECT count(*) FROM leases),'provider_requests',(SELECT count(*) FROM provider_requests),'model_requests',(SELECT count(*) FROM model_request_permit),'native_model_requests',(SELECT count(*) FROM native_model_requests));")
        if counts.returncode:
            raise RuntimeError("private zero-actor count failed")
        result["actual_zero_actor_counts"] = json.loads(counts.stdout)
        result["outcome"] = "PASS" if all(c["outcome"] == "PASS" for c in result["cases"]) and not any(result["actual_zero_actor_counts"].values()) and result["six_checks_no_authority_writes"] else "INCONCLUSIVE"
    except Exception as error:
        result["error_type"] = type(error).__name__
        result["error"] = str(error)
    finally:
        if server is not None:
            if server.poll() is None:
                server.send_signal(signal.SIGTERM)
                try:
                    server.wait(timeout=20)
                except subprocess.TimeoutExpired:
                    server.kill()
                    server.wait(timeout=5)
            result["own_server_exit_code"] = server.returncode
        if log is not None:
            log.close()
        result["source_binding_after"] = pins(args.build_receipt)[1]
        save(output / "report.json", result)
    print(json.dumps({"outcome": result["outcome"], "case_outcomes": [{"name": c["name"], "outcome": c["outcome"]} for c in result["cases"]]}))
    return 0 if result["outcome"] == "PASS" else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build-receipt", required=True)
    parser.add_argument("--output", default="evidence/goal-gap-points-r1/g04")
    parser.add_argument("--run", action="store_true")
    parser.add_argument("--root-go")
    parser.add_argument("--database-env", default="/home/chenyoujian/.local/state/forgeflow/control/runtime-env.json")
    parser.add_argument("--port", type=int, default=8794)
    args = parser.parse_args()
    return run(args) if args.run else prepare(args)


if __name__ == "__main__":
    sys.exit(main())
