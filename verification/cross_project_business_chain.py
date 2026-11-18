#!/usr/bin/env python3
"""Bounded actual cross-project business chain; execute only on Root's signal.

One fresh database, one shared global budget, two four-level projects and two
project-bound Workers. CONTROLLED_LIGHTWEIGHT, zero models, no DSH qualification.
Public evidence is a redacted projection. Exact HTTP/journal/lease material stays
in a fresh mode0700 Linux directory with mode0600 files. No authority SQL writes
are used (the sole SQL mutation creates the isolated database).
"""
import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import secrets
import signal
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from datetime import datetime, timedelta, timezone

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "verification"))
sys.path.insert(0, str(ROOT / "benchmarks"))
from algorithm_check import make_compile, refresh_digest, requirement_digest, vector
from guarded_api_chain import create_database, database_command, secure_save
from metrics import process_fingerprint

PINNED = "d2e52b7e6313def8d520e0e6971b7ce2f681fb9d423b98492add5aba22d168ed"
TERMINAL = {"SUCCEEDED", "FAILED", "CANCELLED"}
AUTHOR = """import json,os,pathlib,signal,sys,time
finished=False
def finish(*args):
 global finished
 finished=True
signal.signal(signal.SIGUSR1,finish)
pathlib.Path(sys.argv[1]).write_text(json.dumps({'kind':'CONTROL_LOAD','seed':int(sys.argv[2])})+'\\n')
print(json.dumps({'kind':'CONTROL_LOAD','project':sys.argv[3],'pid':os.getpid(),'started':True}),flush=True)
for tick in range(900):
 if finished: break
 if tick%5==0: print(json.dumps({'kind':'CONTROL_LOAD','tick':tick}),flush=True)
 time.sleep(1)
"""


def utc():
    return datetime.now(timezone.utc).isoformat()


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def sensitive_key(key):
    normalized = "".join(character for character in str(key).lower() if character.isalnum())
    return normalized in {"leaseid", "secretrefs", "secretref", "authorization", "password", "token", "ownertoken", "workertoken", "databaseurl", "apikey", "accesskey", "credentials"} or normalized.endswith("token") or normalized.startswith("password")


def project_public(value):
    """Do not publish API/lease/secret credentials, including nested envelopes."""
    if isinstance(value, dict):
        out = {}
        for key, item in value.items():
            if sensitive_key(key):
                out[key] = {"redacted": True, "sha256": hashlib.sha256(json.dumps(item, sort_keys=True).encode()).hexdigest()}
            else:
                out[key] = project_public(item)
        return out
    if isinstance(value, list):
        return [project_public(item) for item in value]
    return value


def save(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(project_public(value), ensure_ascii=False, indent=2) + "\n")


def private_bytes(path, raw):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(raw)


class Client:
    def __init__(self, base, token, output, private):
        self.base_url, self.token, self.output, self.private = base, token, output, private
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        self.count = 0
        self.sensitive = {token}
        self.workers = []

    def request(self, method, path, body=None, key=None):
        key = key or uuid.uuid4().hex
        headers = {"Authorization": "Bearer " + self.token, "Accept": "application/json", "Idempotency-Key": key}
        raw = None if body is None else json.dumps(body, ensure_ascii=False, separators=(",", ":")).encode()
        if raw is not None:
            headers["Content-Type"] = "application/json"
        request = urllib.request.Request(self.base_url + "/api/v1" + path, data=raw, headers=headers, method=method)
        began = time.monotonic()
        try:
            response = self.opener.open(request, timeout=30)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            status, data = response.status, response.read()
        value = json.loads(data) if data else None
        def remember(item):
            if isinstance(item, dict):
                for key, nested in item.items():
                    if sensitive_key(key) and isinstance(nested, str):
                        self.sensitive.add(nested)
                    remember(nested)
            elif isinstance(item, list):
                for nested in item:
                    remember(nested)
        remember(value)
        self.count += 1
        stem = f"http-{self.count:07d}"
        record = {"method": method, "path": path, "status": status, "request": body,
                  "idempotency_key": key, "response": value, "received_at": utc(),
                  "latency_ms": (time.monotonic() - began) * 1000,
                  "request_sha256": hashlib.sha256(raw or b"").hexdigest(),
                  "response_sha256": hashlib.sha256(data).hexdigest(),
                  "scope": "PUBLIC_REDACTED_PROJECTION; exact bodies retained mode0600 in private Linux state; Authorization never logged"}
        projection = json.dumps(project_public(value), ensure_ascii=False).encode()
        record["public_response_projection_sha256"] = hashlib.sha256(projection).hexdigest()
        private_bytes(self.private / "http" / (stem + ".response.bin"), data)
        private_bytes(self.private / "http" / (stem + ".json"), json.dumps(record).encode())
        save(self.output / (stem + ".json"), record)
        # This .bin is deliberately a projection, never described as exact wire bytes.
        (self.output / (stem + ".response.bin")).write_bytes(projection)
        return status, value

    def api(self, method, path, body=None, key=None):
        status, value = self.request(method, path, body, key)
        if not 200 <= status < 300:
            code = value.get("code") if isinstance(value, dict) else "NON_JSON"
            raise RuntimeError(f"actual API {method} {path} returned {status}/{code}")
        return value["data"] if isinstance(value, dict) and "data" in value else value


class Events:
    def __init__(self, client, project, after=0):
        self.client, self.project = client, project
        self.after = after
        self.rows, self.errors, self.done = [], [], threading.Event()
        self.response = None
        self.thread = threading.Thread(target=self.run, daemon=True)
        self.thread.start()

    def run(self):
        after = self.after
        while not self.done.is_set():
            try:
                request = urllib.request.Request(self.client.base_url + f"/api/v1/projects/{self.project}/events?after={after}",
                    headers={"Authorization": "Bearer " + self.client.token, "Accept": "text/event-stream"})
                with self.client.opener.open(request, timeout=3) as response:
                    self.response = response
                    data, event_id = [], None
                    while not self.done.is_set():
                        raw_line = response.readline()
                        if not raw_line:
                            break
                        line = raw_line.decode().rstrip("\r\n")
                        if not line and data:
                            value = json.loads("\n".join(data))
                            row = {"project_id": self.project, "id": event_id, "received_at": utc(), "event": value}
                            self.rows.append(row)
                            if event_id and ":" in event_id:
                                after = int(event_id.rsplit(":", 1)[1])
                            data, event_id = [], None
                        elif line.startswith("data:"):
                            data.append(line[5:].lstrip())
                        elif line.startswith("id:"):
                            event_id = line[3:].strip()
                        elif not line and not data:
                            continue
            except (TimeoutError, OSError):
                if not self.done.is_set():
                    time.sleep(.1)
            except Exception as error:
                self.errors.append(type(error).__name__)
                return

    def close(self):
        self.done.set()
        if self.response is not None:
            try:
                self.response.close()
            except OSError:
                pass
        self.thread.join(timeout=4)


def wait(callback, description, timeout=90):
    until = time.monotonic() + timeout
    while time.monotonic() < until:
        value = callback()
        if value:
            return value
        time.sleep(.4)
    raise RuntimeError(description + " timed out")


def git(root, *args):
    result = subprocess.run(["git", "-C", str(root), "-c", "core.hooksPath=/dev/null", "-c", "commit.gpgsign=false", *args], capture_output=True, text=True, timeout=30)
    if result.returncode:
        raise RuntimeError("private Git operation failed: " + args[0])
    return result.stdout.strip()


def budget(slots):
    result = vector(slots)
    result.update(coding_slot=slots, cpu_units=slots, memory_bytes=slots * 16 * 1024 * 1024)
    return result


def policy(client, identity, project=None, team=None, worker=None, parent=None, slots=1, expected=None):
    value = {"scope_id": identity, "parent_scope_id": parent, "project_id": project,
             "team_id": team, "worker_id": worker, "limits": budget(slots), "revision": 0, "paused": False}
    return client.api("POST", "/resource-policies", {"policy": value, "expected_revision": expected})


def provision(client, private, checkpoint, name, count, priority, seed):
    project = f"fair-{name}-{uuid.uuid4().hex[:12]}"
    root = private / project
    root.mkdir(mode=0o700)
    seed_root = root / "seed"
    seed_root.mkdir()
    git(seed_root, "init", "--initial-branch=main")
    (seed_root / "README.txt").write_text("Actual bounded controlled fairness workload. No models or DSH qualification.\n")
    git(seed_root, "add", "README.txt")
    git(seed_root, "-c", "user.name=Fairness fixture", "-c", "user.email=fixture@localhost", "commit", "-m", "Controlled baseline")
    bare = root / "canonical.git"
    subprocess.run(["git", "clone", "--bare", "--no-hardlinks", str(seed_root), str(bare)], check=True, capture_output=True)
    base = git(seed_root, "rev-parse", "HEAD")
    created = client.api("POST", "/projects", {"project_id": project, "name": f"Actual fairness {name}", "root_path": str(bare),
        "authority_mode": "MANAGED", "data_origin": "NATIVE", "goal": "actual cross-project progress, conservative draining and legal refill",
        "technology_stack": ["controlled Python"], "timezone": "Asia/Shanghai", "paused": True, "archived": False, "revision": 0})
    bare = Path(created["root_path"])
    for index in range(4):
        client.api("POST", f"/projects/{project}/teams", {"project_id": project, "team_id": f"level-{index}",
            "parent_team_id": f"level-{index-1}" if index else None, "name": f"{name} level{index}", "paused": False, "revision": 0})
    paths = [f"result-{index}.json" for index in range(count)]
    client.api("POST", f"/projects/{project}/owners", {"id": "level-3", "value": {"owner_id": "level-3", "root_team_id": "level-0", "include": paths, "exclude": []}})
    req = client.api("POST", f"/projects/{project}/requirements", {"project_id": project, "requirement_id": "R01", "title": "Bounded fairness result",
        "source_anchor": "controlled-fairness#R01", "outcome": "actual controlled output and fair legal execution", "scope": "finite controlled receipt files",
        "acceptance": ["other project progresses while high-priority legal backlog remains; lowered budget conservatively drains"], "priority": 1,
        "weight": 1, "deferred_reason": None, "revision": 0})
    worker = "worker-" + project
    home = root / "home"
    home.mkdir()
    program = "/usr/bin/python3"
    programs = {program: sha(program)}
    config = {"control_url": client.base_url, "worker_id": worker, "project_id": project, "data_root": str(private / "state"),
        "model_route_id": "controlled-none", "max_active_attempts": 1, "poll_seconds": 1, "max_log_bytes": 1048576,
        "controlled_workload_programs": programs, "strict_resource_handoff": False,
        "profile": {"id": "controlled-lightweight.v1", "program": program, "prefix_args": [], "home": str(home), "profile_name": "headless",
        "artifact_pins": [], "resume_verified": False, "model_route_id": "controlled-none", "gateway_coverage_verified": False}}
    cfg = root / "worker-config.json"
    secure_save(cfg, config)
    worker_log = client.private / "logs" / (worker + ".log")
    worker_log.parent.mkdir(exist_ok=True)
    log = os.fdopen(os.open(worker_log, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb")
    process = subprocess.Popen([checkpoint["binaries"]["forgeflow-worker"]["path"], "--config", str(cfg)],
        env={"PATH": "/usr/bin:/bin", "RUST_LOG": "info", "FORGEFLOW_WORKER_TOKEN": client.worker_token}, stdout=log, stderr=subprocess.STDOUT)
    result = {"project_id": project, "worker_id": worker, "process": process, "log": log, "priority": priority, "seed": seed, "tasks": {}, "root": root, "canonical": bare}
    client.workers.append(result)  # Cleanup owns the Worker even if later provisioning fails.
    # Worker registration is protocol-created. SQL below is read-only observation.
    def registered():
        if process.poll() is not None:
            raise RuntimeError("actual Worker exited before registration")
        row = database_command(client.database_url, "SELECT json_build_object('worker_id',worker_id,'project_id',project_id,'executor_profile_ids',executor_profile_ids) FROM workers WHERE worker_id='" + worker + "'")
        return json.loads(row.stdout) if row.returncode == 0 and row.stdout.strip() else None
    result["registration"] = wait(registered, "project-bound Worker registration", 30)
    policy(client, project + ":project", project=project, parent="global")
    policy(client, project + ":worker", worker=worker, parent="global")
    for index in range(4):
        policy(client, project + f":level-{index}", project=project, team=f"level-{index}", parent=project + (f":level-{index-1}" if index else ":project"))
    for collection, identity, value in [
        ("executor_profiles", "controlled-lightweight.v1", {"id": "controlled-lightweight.v1", "kind": "CONTROLLED_LIGHTWEIGHT", "approved_programs": programs}),
        ("resource_profiles", "controlled-active-slot.v1", {"id": "controlled-active-slot.v1", "scope": "CONTROL_LOAD", "stage_resource_mode": "ATTEMPT_RESERVATION", "max_log_bytes": 1048576}),
        ("model_routes", "controlled-none", {"id": "controlled-none", "kind": "NO_MODEL", "model_requests": 0})]:
        client.api("POST", f"/projects/{project}/documents/{collection}", {"id": identity, "value": value})
    prompt = client.api("POST", f"/projects/{project}/artifacts", {"content_utf8": "Run exactly the pinned finite controlled command; no models.\n", "kind": "PROMPT"})
    manifest_text = '{"files":[],"mandatory_paths":[],"artifact_inputs":[]}'
    manifest = client.api("POST", f"/projects/{project}/artifacts", {"content_utf8": manifest_text, "kind": "CONTEXT_MANIFEST"})
    oracle = ROOT / "verification/fixtures/control_verifier.py"
    verifier = str(Path(sys.executable).resolve())
    import control_verifier
    meaning = requirement_digest(req)
    case = make_compile(count)
    case["flow"]["project_id"] = project
    case["context"].update(owners=[{"owner_id": "level-3", "root_team_id": "level-0", "include": paths, "exclude": []}],
        current_inputs={}, resolved_paths={}, requirement_semantic_digests={"R01": meaning},
        requirements=[{"requirement_id": "R01", "source_document": "controlled-fairness", "anchor": "R01", "acceptance": "\n".join(req["acceptance"]), "priority": 1, "deferred_reason": None}])
    now = datetime.now(timezone.utc)
    for index, task in enumerate(case["flow"]["tasks"]):
        plan = "verify-" + task["task_id"]
        task.update(project_id=project, owner_id="level-3", team_id="level-3", read_set=[], write_set=[paths[index]], dependencies=[], resource_request=budget(1))
        spec = case["context"]["task_specs"][task["task_id"]]
        spec.update(inputs=[], mandatory_paths=[], dependency_refs=[], requirement_digest_refs={"R01": meaning}, design_anchors=["controlled-fairness#R01"],
                    execution_profile="controlled-lightweight.v1", verification_plan=plan, verification_case_count=8)
        task["envelope"] = {"schema_version": "forgeflow.execution.v1", "operation_id": "pending", "project_id": project, "task_id": task["task_id"],
            "task_revision": 1, "attempt_id": "pending", "lease_id": "pending", "generation": 1, "worker_id": worker, "workspace_root": str(bare), "base_sha": base,
            "context_manifest": {"artifact_id": manifest["artifact_id"], "sha256": manifest["sha256"], "mandatory_paths": [], "rendered_utf8_bytes": len(manifest_text), "token_estimate": None, "tokenizer_id": None},
            "write_set": task["write_set"], "prompt_artifact": {"artifact_id": prompt["artifact_id"], "sha256": prompt["sha256"]}, "model_route_id": "controlled-none",
            "executor_profile_id": "controlled-lightweight.v1", "resource_profile_id": "controlled-active-slot.v1", "verification_plan_id": plan,
            "allowed_effects": ["READ_WORKSPACE", "WRITE_DECLARED_PATHS", "RUN_APPROVED_COMMANDS"], "issued_at": now.isoformat(), "expires_at": (now + timedelta(seconds=120)).isoformat(),
            "deadline_at": (now + timedelta(minutes=30)).isoformat(), "artifact_prefix": str(private / "state/artifacts"), "secret_refs": [], "idempotency_key": "pending", "trace_id": "controlled",
            "enforcement": {"model_budget_mode": "direct_observed", "stage_resource_mode": "ATTEMPT_RESERVATION", "build_capable": False, "gateway_coverage_receipt_id": None,
                "tool_guard_receipt_id": None, "attempt_reserved_build_permits": 0, "all_model_routes_covered": False, "disabled_tool_entry_ids": []},
            "session_purpose": "EXECUTION", "max_model_requests": 0, "resume_session_id": None,
            "command": {"program": program, "args": ["-I", "-B", "-c", AUTHOR, paths[index], str(seed), project]}}
        refresh_digest(task, spec)
        commands = [{"role": role, "program": verifier, "args": [str(oracle)], "env": {"FORGEFLOW_VERIFICATION_ROLE": role, "FORGEFLOW_EXPECTED_SEED": str(seed), "FORGEFLOW_OUTPUT_PATH": paths[index]},
            "executable_hash": sha(verifier), "bound_inputs": [{"path": str(oracle), "sha256": sha(oracle)}], "report_path": role + ".json",
            "expected_cases": [{"name": n, "kind": k} for n, k in control_verifier.CASES[role]], "timeout_seconds": 30} for role in ("author", "consumer", "independent")]
        client.api("POST", f"/projects/{project}/documents/verification_plans", {"id": plan, "value": {"plan_id": plan, "task_revision": 1, "input_hash": task["input_digest"],
            "contract_version": "controlled-output.v1", "environment_profile": "bounded-local-controlled-output", "oracle_id": control_verifier.ORACLE,
            "verifier_id": "independent-controlled-output-oracle", "author_id": worker, "commands": commands}})
    saved = client.api("POST", f"/projects/{project}/flow-revisions", {"flow": case["flow"], "context": case["context"]})
    committed = client.api("POST", f"/flows/{project}:1/commit", {"expected_revision": saved["revision"]})
    result["tasks"] = {t["task_id"]: t for t in committed["tasks"]}
    for task in committed["tasks"]:
        client.api("POST", f"/projects/{project}/queue-entries", {"task_id": task["task_id"], "expected_revision": task["revision"], "worker_id": worker,
            "worker_scope_id": project + ":worker", "scope_ids": [], "priority": priority, "lease_seconds": 120})
    save(client.output / "fixture-inputs" / (project + ".json"), {"flow": committed, "registration": result["registration"], "worker_config": config, "priority": priority})
    return result


def paused(client, project, value):
    row = client.api("GET", "/projects/" + project)
    if row["paused"] != value:
        client.api("PATCH", "/projects/" + project, {"project": dict(row, paused=value), "expected_revision": row["revision"]})


def snapshots(client, projects, label):
    result = {}
    for project in projects:
        result[project] = client.api("GET", f"/projects/{project}/snapshot")
    save(client.output / "snapshots" / (label + ".json"), result)
    return result


def ledger_totals(states):
    """Compare whole positive vectors at quiescent observed boundaries only.

    The two API snapshots have independent transactions. They are not described
    as one global atomic snapshot; callers first wait for a stable living author
    or Owner-paused/drained boundary before invoking this oracle.
    """
    allocations, limits = {}, {}
    for state in states.values():
        for row in state["allocations"]:
            allocations[row["allocation_id"]] = row
        for row in state["resource_limits"]:
            limits[(row["scope_id"], row["dimension"])] = row
    totals = {}
    for row in allocations.values():
        if row["state"] != "RELEASED":
            key = (row["scope_id"], row["dimension"])
            totals[key] = totals.get(key, 0) + row["amount"]
    mismatches = [{"scope_id": key[0], "dimension": key[1], "ledger_allocated": row["allocated"], "allocation_sum": totals.get(key, 0)}
                  for key, row in limits.items() if row["allocated"] != totals.get(key, 0)]
    return {"mismatches": mismatches, "global_active": limits[("global", "active_slot")],
            "allocated_vectors": [{"scope_id": k[0], "dimension": k[1], "amount": v} for k, v in sorted(totals.items())]}


def actual_running(client, projects, private, excluded=()):
    found = []
    for project in projects:
        state = client.api("GET", f"/projects/{project}/snapshot")
        for attempt in state["attempts"]:
            if attempt["attempt_id"] in excluded or attempt["state"] != "RUNNING":
                continue
            journal = private / "state/attempts" / attempt["attempt_id"]
            receipt = journal / "launch-receipt.json"
            if not receipt.is_file():
                continue
            launch = json.loads(receipt.read_text())
            fingerprint = process_fingerprint(launch["process"]["pid"])
            if not fingerprint or fingerprint["start_ticks"] != launch["process"]["start_ticks"] or launch["process"]["boot_id"] != Path("/proc/sys/kernel/random/boot_id").read_text().strip():
                continue
            raw = (journal / "stdout.ndjson").read_bytes()
            if b'"started": true' not in raw and b'"started":true' not in raw:
                continue
            envelope = json.loads((journal / "envelope.json").read_text())
            artifact = private / "state/worktrees" / attempt["attempt_id"] / envelope["write_set"][0]
            if not artifact.is_file() or not artifact.stat().st_size:
                continue
            found.append({"attempt": attempt, "launch": launch, "fingerprint": fingerprint, "journal": journal,
                          "artifact": {"sha256": sha(artifact), "bytes": artifact.stat().st_size, "content": json.loads(artifact.read_text())}})
    return found


def stop_attempt(client, attempt):
    for _ in range(5):
        row = client.api("GET", f"/attempts/{attempt['attempt_id']}?project_id={attempt['project_id']}")
        if row["state"] in TERMINAL:
            return row
        status, response = client.request("POST", f"/attempts/{row['attempt_id']}/cancel", {"project_id": row["project_id"], "expected_revision": row["revision"], "reason": "Owner closes bounded actual fairness business journey"})
        if status == 409 and response.get("code") == "REVISION_CONFLICT":
            continue
        if status >= 400:
            raise RuntimeError("Owner stop rejected: " + str(response.get("code")))
        return wait(lambda: terminal(client, row), "actual confirmed terminal stop")
    raise RuntimeError("Owner stop CAS did not converge")


def terminal(client, attempt):
    row = client.api("GET", f"/attempts/{attempt['attempt_id']}?project_id={attempt['project_id']}")
    return row if row["state"] in TERMINAL else None


def complete(client, running):
    old = running["fingerprint"]
    current = process_fingerprint(old["pid"])
    if not current or current["start_ticks"] != old["start_ticks"]:
        raise RuntimeError("refuse completion signal after PID identity drift")
    os.kill(old["pid"], signal.SIGUSR1)
    attempt = running["attempt"]
    def verifying():
        row = client.api("GET", f"/attempts/{attempt['attempt_id']}?project_id={attempt['project_id']}")
        if row["state"] in {"FAILED", "CANCELLED", "RECOVERY_REQUIRED"}:
            raise RuntimeError("actual author failed before verification: " + row["state"])
        return row if row["state"] == "VERIFYING" else None
    wait(verifying, "actual controlled exit reaches verification")
    accepted = client.api("POST", f"/attempts/{attempt['attempt_id']}/verify-and-integrate", {"project_id": attempt["project_id"]})
    def done():
        operation = client.api("GET", "/operations/" + accepted["operation_id"])
        if operation["status"] in {"FAILED", "RECOVERY_REQUIRED"}:
            raise RuntimeError("registered actual verification failed: " + operation["status"])
        return operation if operation["status"] == "SUCCEEDED" else None
    return wait(done, "actual registered independent verification and fenced integration", 120)


def scheduler_projection(client, project):
    rows, cursor = [], None
    while True:
        path = f"/projects/{project}/documents/operations?limit=100"
        if cursor:
            path += "&cursor=" + urllib.parse.quote(cursor, safe="")
        status, page = client.request("GET", path)
        if status != 200:
            raise RuntimeError("supported operations list failed")
        rows.extend(page["data"])
        cursor = page.get("next_cursor")
        if not cursor:
            break
    # This public catalog does not expose document IDs. Record the one observed
    # scheduler projection by its typed cursor/scanned fields; do not pretend
    # the API proved an unexposed single-document route.
    candidates = [row for row in rows if "cursor" in row and "scanned" in row]
    if len(candidates) != 1:
        raise RuntimeError("operations list has no unique scheduler projection")
    return {"scope": "SUPPORTED_PAGINATED_OPERATIONS_LIST_SCHEMA_PROJECTION", "value": candidates[0]}


def restart_existing_worker(client, private, checkpoint, project):
    config_path = private / project / "worker-config.json"
    config = json.loads(config_path.read_text())
    if config["project_id"] != project or config["control_url"] != client.base_url:
        raise RuntimeError("continuation Worker configuration identity changed")
    log_path = client.private / "logs" / (config["worker_id"] + ".log")
    log_path.parent.mkdir(exist_ok=True)
    log = os.fdopen(os.open(log_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb")
    process = subprocess.Popen([checkpoint["binaries"]["forgeflow-worker"]["path"], "--config", str(config_path)],
        env={"PATH": "/usr/bin:/bin", "RUST_LOG": "info", "FORGEFLOW_WORKER_TOKEN": client.worker_token}, stdout=log, stderr=subprocess.STDOUT)
    worker = {"project_id": project, "worker_id": config["worker_id"], "process": process, "log": log, "tasks": {}}
    client.workers.append(worker)
    flow = client.api("GET", f"/projects/{project}/flows/1")
    worker["tasks"] = {task["task_id"]: task for task in flow["tasks"]}
    wait(lambda: process.poll() is None and database_command(client.database_url, "SELECT worker_id FROM workers WHERE worker_id='" + config["worker_id"] + "' AND project_id='" + project + "'").stdout.strip(), "continuation registered Worker", 30)
    return worker


def run(args):
    if not args.execute_authorized:
        raise RuntimeError("No runtime launch: --execute-authorized requires the explicit Root execution signal")
    if args.port in {8787, 8788}:
        raise RuntimeError("refuse main/old QA ports")
    checkpoint = json.loads(args.build_receipt.read_text())
    if checkpoint["source_identity"] != PINNED or not checkpoint["consistent_copy"] or not checkpoint["source_unchanged_after_build"] or any(x["exit_code"] for x in checkpoint["commands"]):
        raise RuntimeError("exact successful Root-approved d2e52 build required")
    for name in ("forgeflow-server", "forgeflow-worker"):
        if sha(checkpoint["binaries"][name]["path"]) != checkpoint["binaries"][name]["sha256"]:
            raise RuntimeError("pinned runtime binary mismatch")
    output = args.output.resolve()
    if (output / "server.log").exists():
        raise RuntimeError("prior runtime evidence exists; refuse replay/overwrite")
    output.mkdir(parents=True, exist_ok=True)
    prior = json.loads(args.resume_from_report.read_text()) if args.resume_from_report else None
    if prior:
        if prior["source_identity"] != PINNED or len(prior["errors"]) != 1 or "documents/operations/scheduler-state returned 404/ENDPOINT_UNAVAILABLE" not in prior["errors"][0]["message"]:
            raise RuntimeError("point continuation is only for the recorded observational route failure")
        if not all(actor["confirmed"] for actor in prior["process_shutdown"].values()):
            raise RuntimeError("previous actors have not positively stopped")
        private = Path(prior["private_root"])
        database = prior["database_name"]
        env = json.loads((private / "runtime-env.json").read_text())
        if env["FORGEFLOW_BIND"] != f"127.0.0.1:{args.port}":
            raise RuntimeError("continuation loopback identity changed")
    else:
        private = Path(tempfile.mkdtemp(prefix="forgeflow-fairness-", dir="/home/chenyoujian/.cache"))
        private.chmod(0o700)
        (private / "state").mkdir(mode=0o700)
        database = "forgeflow_fairness_" + uuid.uuid4().hex[:16]
        main_env = json.loads(args.private_env.read_text())
        env = {"DATABASE_URL": create_database(main_env, database, private), "FORGEFLOW_BIND": f"127.0.0.1:{args.port}",
               "FORGEFLOW_DATA_ROOT": str(private / "state"), "FORGEFLOW_OWNER_TOKEN": secrets.token_hex(32), "FORGEFLOW_WORKER_TOKEN": secrets.token_hex(32),
               "FORGEFLOW_CONSOLE_DIR": str(ROOT / "console/dist"), "RUST_LOG": "info"}
        secure_save(private / "runtime-env.json", env)
    diagnostics = private / ("run-diagnostics-" + uuid.uuid4().hex[:12])
    diagnostics.mkdir(mode=0o700)
    client = Client(f"http://127.0.0.1:{args.port}", env["FORGEFLOW_OWNER_TOKEN"], output, diagnostics)
    client.database_url, client.worker_token = env["DATABASE_URL"], env["FORGEFLOW_WORKER_TOKEN"]
    client.sensitive.add(env["FORGEFLOW_WORKER_TOKEN"])
    sys.path.insert(0, str(ROOT / "verification/fixtures"))
    report = {"schema_version": "forgeflow.actual-cross-project-business-chain.v1", "at": utc(), "status": "RUNNING", "scope": "Actual bounded API/Workers/PIDs/output/events fairness and drain/refill; controlled/no models",
        "source_identity": PINNED, "build_receipt_sha256": sha(args.build_receipt), "binaries": checkpoint["binaries"], "harness_sha256": sha(__file__),
        "private_root": str(private), "database_name": database, "public_evidence_scope": "REDACTED_PROJECTION; exact HTTP/lease/journal material private mode0600", "real_dsh": False,
        "model_requests": 0, "production_qualified": False, "G3_promotion": False, "checks": [], "errors": [], "projects": [], "process_shutdown": {},
        "not_proven": ["native DSH qualification", "128/3600 seconds", "complete CPU/memory OS enforcement", "unbounded starvation theorem", "full business-chain or product-Gate promotion"]}
    server, workers, streams, log = None, client.workers, [], None
    if prior:
        report["inherited_actual_evidence"] = {"path": str(args.resume_from_report), "sha256": sha(args.resume_from_report),
            "status_preserved": prior["status"], "checks_inherited": [c for c in prior["checks"] if c["name"] in {"two_managed_projects_four_levels_each_project_bound_workers", "first_high_priority_A_actual_PID", "actual_verified_completion_0", "actual_verified_completion_1", "B_runs_while_high_priority_A_backlog_remains"}],
            "scope": "Only observed-readback error corrected; no project creation, completed author, verification/Git or first B fairness step repeated"}
        report["point_continuation_entry"] = {"path": sys.argv[0], "sha256": sha(sys.argv[0])}
    def check(name, condition, facts=None):
        report["checks"].append({"name": name, "status": "PASS" if condition else "FAIL", "facts": project_public(facts)})
        save(output / "report.json", report)
        if not condition:
            raise RuntimeError("failed actual assertion: " + name)
    try:
        server_log = client.private / "server.log"
        log = os.fdopen(os.open(server_log, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb")
        server = subprocess.Popen([checkpoint["binaries"]["forgeflow-server"]["path"]], env={"PATH": "/usr/bin:/bin", **env}, stdout=log, stderr=subprocess.STDOUT)
        def healthy():
            if server.poll() is not None:
                raise RuntimeError("isolated server exited")
            try:
                return client.request("GET", "/me")[0] == 200
            except urllib.error.URLError:
                return False
        wait(healthy, "isolated server readiness", 30)
        if prior:
            projects = prior["projects"]
            report["projects"] = projects
            initial = snapshots(client, projects, "continuation-zero-before-workers")
            check("point_resume_from_owner_paused_zero_resource_authority", all(s["project"]["paused"] and all(a["state"] in TERMINAL for a in s["attempts"]) and not any(a["state"] != "RELEASED" for a in s["allocations"]) and not any(l["revoked_at"] is None for l in s["leases"]) for s in initial.values()))
            a, b = [restart_existing_worker(client, private, checkpoint, project) for project in projects]
            streams = [Events(client, p, initial[p]["revision"]) for p in projects]
            shared = next(p for p in client.api("GET", "/resources") if p["scope_id"] == "global")
            cursor = scheduler_projection(client, a["project_id"])
            save(output / "snapshots" / "inherited-persisted-fair-cursor.json", cursor)
            report["fairness_policy"] = {"inherited_observed_B_progress": True, "persisted_cursor_after_original_run": cursor["value"].get("cursor")}
            seen = {a["attempt_id"] for s in initial.values() for a in s["attempts"]}
            completed = []
            paused(client, a["project_id"], False)
            before = wait(lambda: actual_running(client, projects, private, seen), "existing queued A author for point drain")[0]
            check("point_continuation_fresh_actual_A_author_and_artifact", before["attempt"]["project_id"] == a["project_id"], before["artifact"])
            seen.add(before["attempt"]["attempt_id"])
            paused(client, b["project_id"], False)
        else:
            shared = policy(client, "global")
            a = provision(client, private, checkpoint, "a", 4, 100, 311)
            b = provision(client, private, checkpoint, "b", 2, 0, 812)
            projects = [a["project_id"], b["project_id"]]
            report["projects"] = projects
            streams = [Events(client, p) for p in projects]
            check("two_managed_projects_four_levels_each_project_bound_workers", all(w["registration"]["project_id"] == w["project_id"] and "controlled-lightweight.v1" in w["registration"]["executor_profile_ids"] for w in workers))
            snapshots(client, projects, "prepared-paused")
            paused(client, a["project_id"], False)
            first = wait(lambda: actual_running(client, projects, private), "first actual A author")[0]
            check("first_high_priority_A_actual_PID", first["attempt"]["project_id"] == a["project_id"], {"attempt": first["attempt"], "fingerprint": first["fingerprint"]})
            paused(client, b["project_id"], False)
            snapshots(client, projects, "both-competing")
            completed, seen = [], {first["attempt"]["attempt_id"]}
            running = first
            # Dynamic addition of B can preserve cursor0 from the former one-project
            # set. Bound two actual releases; never invent immediate next-turn policy.
            for index in range(2):
                operation = complete(client, running)
                completed.append(operation)
                save(output / "snapshots" / f"completion-{index}.json", operation)
                check("actual_verified_completion_" + str(index), operation["status"] == "SUCCEEDED")
                running = wait(lambda: actual_running(client, projects, private, seen), "automatic next actual author")[0]
                seen.add(running["attempt"]["attempt_id"])
                if running["attempt"]["project_id"] == b["project_id"]:
                    break
            queues = client.api("GET", f"/projects/{a['project_id']}/queue-entries")
            check("B_runs_while_high_priority_A_backlog_remains", running["attempt"]["project_id"] == b["project_id"] and any(q["status"] == "QUEUED" and q["priority"] == 100 for q in queues), {"B_attempt": running["attempt"], "A_queue": queues, "completion_release_count": len(completed)})
            scheduler_state = scheduler_projection(client, a["project_id"])
            save(output / "snapshots" / "persisted-fair-cursor-B-progress.json", scheduler_state)
            report["fairness_policy"] = {"declared": "persisted round-robin project cursor with per-project priority and aging; bounded existing queue reservoir",
                "A_priority": 100, "B_priority": 0, "maximum_legal_releases_before_B": 2,
                "actual_legal_releases_before_B": len(completed), "cursor_at_B_progress": scheduler_state["value"].get("cursor")}
            b_snapshot = snapshots(client, projects, "B-progress")
            b_ledger = ledger_totals(b_snapshot)
            check("shared_global_and_all_ancestor_vectors_conserved", not b_ledger["mismatches"] and b_ledger["global_active"]["allocated"] == 1, b_ledger)
            report["B_actual_artifact"] = running["artifact"]
            stopped_b = stop_attempt(client, running["attempt"])
            check("Owner_B_stop_confirmed", stopped_b["state"] == "CANCELLED")
            before = wait(lambda: actual_running(client, projects, private, seen), "A legal refill after B stop")[0]
            seen.add(before["attempt"]["attempt_id"])
        shared = policy(client, "global", slots=0, expected=shared["revision"])
        before_snapshot = snapshots(client, projects, "lowered-budget-retains-author")
        draining_ledger = ledger_totals(before_snapshot)
        check("lowered_budget_is_conservative_draining", not draining_ledger["mismatches"] and draining_ledger["global_active"]["hard_limit"] == 0 and draining_ledger["global_active"]["allocated"] == 1, draining_ledger)
        old_fingerprint = before["fingerprint"]
        time.sleep(3)
        after_fingerprint = process_fingerprint(old_fingerprint["pid"])
        check("lowered_global_budget_does_not_kill_author", after_fingerprint is not None and after_fingerprint["start_ticks"] == old_fingerprint["start_ticks"])
        # Find one real READY card for a direct authoritative negative, never a
        # made-up admission envelope or invented state field.
        probe = next(t for w in workers for t in w["tasks"].values() if not any(t["task_id"] == r["task_id"] and w["project_id"] == r["project_id"] for state in before_snapshot.values() for r in state["attempts"]))
        proposal = {"actor_id": "overwritten", "idempotency_key": "overwritten", "project_id": probe["project_id"], "task_id": probe["task_id"],
            "task_revision": probe["task_revision"], "flow_revision": probe["flow_revision"], "policy_revision": 1, "input_digest": probe["input_digest"],
            "worker_id": probe["envelope"]["worker_id"], "lease_seconds": 120, "envelope": probe["envelope"]}
        status, negative = client.request("POST", f"/projects/{probe['project_id']}/admissions", proposal)
        check("lowered_budget_rejects_new_admission", status == 409 and negative.get("code") == "CAPACITY_EXHAUSTED", {"status": status, "response": negative})
        stopped = stop_attempt(client, before["attempt"])
        check("drain_Owner_stop_confirmed", stopped["state"] == "CANCELLED")
        time.sleep(3)
        drained = snapshots(client, projects, "drained-still-zero-limit")
        check("zero_limit_holds_new_queue_without_unproven_release", all(not any(x["state"] not in TERMINAL for x in state["attempts"]) and not any(x["state"] != "RELEASED" for x in state["allocations"]) for state in drained.values()))
        shared = policy(client, "global", slots=1, expected=shared["revision"])
        resumed = wait(lambda: actual_running(client, projects, private, seen), "legal refill after reviewed restored budget")[0]
        seen.add(resumed["attempt"]["attempt_id"])
        check("restored_budget_real_fresh_PID_refill", resumed["attempt"]["attempt_id"] not in {x["attempt_id"] for state in drained.values() for x in state["attempts"]}, {"attempt": resumed["attempt"], "fingerprint": resumed["fingerprint"]})
        snapshots(client, projects, "restored-legal-refill")
        report["completed_operations"] = [{"operation_id": o["operation_id"], "attempt_id": o["attempt_id"], "status": o["status"]} for o in completed]
    except Exception as error:
        report["errors"].append({"type": type(error).__name__, "message": str(error)})
    finally:
        # Pause authority first. Keep actual Workers alive until positive stop
        # acknowledgements settle; uncertain cleanup retains resource quarantine.
        for worker in workers:
            try:
                paused(client, worker["project_id"], True)
            except Exception as error:
                report["errors"].append({"cleanup": "pause", "type": type(error).__name__})
        for worker in workers:
            try:
                snapshot = client.api("GET", f"/projects/{worker['project_id']}/snapshot")
                for attempt in snapshot["attempts"]:
                    if attempt["state"] not in TERMINAL:
                        stop_attempt(client, attempt)
            except Exception as error:
                report["errors"].append({"cleanup": "stop", "type": type(error).__name__, "message": str(error)})
        if workers:
            try:
                projects = [w["project_id"] for w in workers]
                final = snapshots(client, projects, "final-owner-stopped")
                report["final_authority"] = {p: {"attempt_states": [a["state"] for a in s["attempts"]], "held_allocations": sum(a["state"] != "RELEASED" for a in s["allocations"]),
                    "unrevoked_leases": sum(l["revoked_at"] is None for l in s["leases"])} for p, s in final.items()}
                check("final_owner_pause_confirmed_stops_zero_resources", all(all(a["state"] in TERMINAL for a in s["attempts"]) and not any(a["state"] != "RELEASED" for a in s["allocations"]) and not any(l["revoked_at"] is None for l in s["leases"]) for s in final.values()))
                final_ledger = ledger_totals(final)
                check("final_scope_ledgers_zero_and_equal_released_vectors", not final_ledger["mismatches"] and not final_ledger["allocated_vectors"], final_ledger)
                model_rows = database_command(client.database_url, "SELECT count(*) FROM model_request_permit")
                check("actual_isolated_zero_model_permits", model_rows.returncode == 0 and model_rows.stdout.strip() == b"0")
                # Exact originals remain private. Copy only explicitly redacted
                # projections, with hashes binding each to the private original.
                for state in final.values():
                    for attempt in state["attempts"]:
                        journal = private / "state/attempts" / attempt["attempt_id"]
                        for name in ("envelope.json", "launch-receipt.json", "result.json", "stop.json"):
                            p = journal / name
                            if p.is_file():
                                save(output / "authors" / attempt["attempt_id"] / name, {"scope": "PUBLIC_REDACTED_PRIVATE_ORIGINAL", "original_sha256": sha(p), "value": json.loads(p.read_text())})
                        p = journal / "stdout.ndjson"
                        if p.is_file():
                            (output / "authors" / attempt["attempt_id"] / "stdout.ndjson").write_bytes(p.read_bytes())
                        envelope = json.loads((journal / "envelope.json").read_text())
                        artifact = private / "state/worktrees" / attempt["attempt_id"] / envelope["write_set"][0]
                        if artifact.is_file():
                            report.setdefault("actual_output_artifacts", []).append({"attempt_id": attempt["attempt_id"], "sha256": sha(artifact), "bytes": artifact.stat().st_size, "content": json.loads(artifact.read_text())})
            except Exception as error:
                report["errors"].append({"cleanup": "authority", "type": type(error).__name__, "message": str(error)})
        for events in streams:
            # Allow already committed final stop events to reach the existing SSE
            # observer; this is evidence capture, not an additional workload.
            time.sleep(.3)
            events.close()
        event_rows = [r for s in streams for r in s.rows]
        public_events = output / "events.jsonl"
        public_events.write_text("".join(json.dumps(project_public(r), ensure_ascii=False) + "\n" for r in event_rows))
        private_bytes(client.private / "events.jsonl", "".join(json.dumps(r) + "\n" for r in event_rows).encode())
        report["event_denominator"] = {"delivered_events": len(event_rows), "errors": [e for s in streams for e in s.errors],
            "observed_kinds": sorted({r["event"].get("kind", "UNKNOWN") for r in event_rows if isinstance(r["event"], dict)})}
        leased_projects = {r["project_id"] for r in event_rows if r["event"].get("kind") == "attempt.leased"}
        report["checks"].append({"name": "actual_admission_events_for_remaining_phase" if prior else "actual_admission_events_from_both_projects",
            "status": "PASS" if len(leased_projects) >= (1 if prior else 2) and not report["event_denominator"]["errors"] else "FAIL",
            "facts": {"observed_projects_this_phase": sorted(leased_projects), "original_both_project_events_inherited": bool(prior)}})
        report["global_budget_change_event_scope"] = "API CAS command receipts are archived; do not invent a named global budget.policy.changed event when service emits none."
        for name, process in [(w["worker_id"], w["process"]) for w in workers] + [("server", server)]:
            if process is None:
                continue
            if process.poll() is None:
                process.send_signal(signal.SIGTERM)
                try:
                    process.wait(timeout=35)
                except subprocess.TimeoutExpired:
                    # Do not SIGKILL an unresolved author fleet to manufacture
                    # cleanup. Report uncertainty and retain the private state.
                    report["errors"].append({"shutdown": name, "error": "positive bounded process exit unconfirmed"})
            report["process_shutdown"][name] = {"pid": process.pid, "exit_code": process.poll(), "confirmed": process.poll() is not None}
        for worker in workers:
            worker["log"].close()
        live_authors = []
        for receipt in (private / "state/attempts").glob("*/launch-receipt.json"):
            identity = json.loads(receipt.read_text())["process"]
            fingerprint = process_fingerprint(identity["pid"])
            if fingerprint and fingerprint["start_ticks"] == identity["start_ticks"]:
                live_authors.append(fingerprint)
        report["checks"].append({"name": "final_actual_author_PIDs_zero_and_workers_stopped", "status": "PASS" if not live_authors and all(w["process"].poll() is not None for w in workers) else "FAIL", "facts": {"live_authors": live_authors}})
        if log is not None:
            log.close()
        for source, destination in [(client.private / "server.log", output / "server.log")] + [(client.private / "logs" / (w["worker_id"] + ".log"), output / "workers" / (w["worker_id"] + ".log")) for w in workers]:
            if source.is_file():
                text = source.read_text(errors="replace")
                for sensitive in client.sensitive:
                    if sensitive:
                        text = text.replace(sensitive, "<REDACTED_CREDENTIAL>")
                destination.parent.mkdir(exist_ok=True)
                destination.write_text("PUBLIC_REDACTED_LOG_PROJECTION; private original SHA256=" + sha(source) + "\n" + text)
        report["status"] = "PASS_BOUNDED_ACTUAL_CHAIN" if not report["errors"] and report["checks"] and all(c["status"] == "PASS" for c in report["checks"]) and event_rows else "FAIL"
        report["assertions"] = len(report["checks"])
        report["failed"] = sum(c["status"] != "PASS" for c in report["checks"])
        report["ended_at"] = utc()
        save(output / "report.json", report)
    print(json.dumps({"report": str(output / "report.json"), "status": report["status"], "assertions": report["assertions"], "failed": report["failed"]}))
    return 0 if report["status"] == "PASS_BOUNDED_ACTUAL_CHAIN" else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build-receipt", type=Path, required=True)
    parser.add_argument("--private-env", type=Path, required=True)
    parser.add_argument("--output", type=Path, default=ROOT / "evidence/cross-project-business-chain-r1")
    parser.add_argument("--port", type=int, default=8876)
    parser.add_argument("--resume-from-report", type=Path, help="Root-authorized remaining drain/refill only; prior actual failure retained")
    parser.add_argument("--execute-authorized", action="store_true", help="Only after explicit Root signal; starts isolated actual processes")
    args = parser.parse_args()
    return run(args)


if __name__ == "__main__":
    sys.exit(main())
