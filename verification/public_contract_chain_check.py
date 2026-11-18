#!/usr/bin/env python3
"""Actual public contract freeze after an approved producer/consumer probe DAG.

The producer content SHA256 is independently computed from actual tracked base
blobs plus the finite fixture's approved producer bytes, before its output exists.
Actual Worker authors, registered independent verifiers and fenced Git integration
must agree with it. Consumer compatibility uses ISOLATED_CANDIDATE_PROBE; only
POST /contracts/{id}/freeze-requests can promote this contract to FROZEN.
No authority rows are written through SQL. No native DSH/capacity Gate is claimed.
Run once with a Root-approved immutable build receipt; credentials remain private.
"""
import argparse
import copy
import hashlib
import json
import os
import secrets
import signal
import stat
import subprocess
import sys
import tempfile
import time
import uuid
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "benchmarks"))
sys.path.insert(0, str(ROOT / "verification"))
from algorithm_check import make_compile, requirement_digest, vector
from control_load import Client
from guarded_api_chain import create_database, secure_save, wait_for, operation, stop_process, database_command
from live_control_adapter import api, git

PRODUCER = '''def build_index(records):
    if type(records) is not list:
        raise TypeError("records must be a list")
    result=[]
    names=set()
    for record in records:
        if type(record) is not dict or set(record)!={"name","size"}:
            raise TypeError("exact name and size fields required")
        name,size=record["name"],record["size"]
        if type(name) is not str or not name or type(size) is not int or size<0:
            raise TypeError("nonempty name and nonnegative integer size required")
        if name in names:
            raise ValueError("duplicate name")
        names.add(name)
        result.append({"name":name,"size":size})
    return sorted(result,key=lambda row:row["name"])
'''
CONSUMER = '''from producer import build_index
def summarize(records):
    rows=build_index(records)
    return {"format_version":1,"names":[row["name"] for row in rows],"total_bytes":sum(row["size"] for row in rows)}
'''
AUTHOR = '''import importlib.util,json,pathlib,sys
sys.dont_write_bytecode=True
phase=sys.argv[1]
if phase=="producer":
    pathlib.Path("producer.py").write_text(sys.argv[2])
else:
    pathlib.Path("consumer.py").write_text(sys.argv[2])
    sys.path.insert(0,str(pathlib.Path.cwd()))
    spec=importlib.util.spec_from_file_location("consumer",pathlib.Path("consumer.py"))
    app=importlib.util.module_from_spec(spec);spec.loader.exec_module(app)
    value=app.summarize(json.loads(pathlib.Path("input-data.json").read_text()))
    pathlib.Path("consumer-result.json").write_text(json.dumps(value,ensure_ascii=False,sort_keys=True)+"\\n")
print(json.dumps({"phase":phase,"kind":"CONTROLLED_PRODUCER_CONSUMER","real_dsh":False}),flush=True)
'''
ORACLE = '''import importlib.util,json,os,pathlib,random,sys
sys.dont_write_bytecode=True
sys.path.insert(0,str(pathlib.Path.cwd()))
spec=importlib.util.spec_from_file_location("producer",pathlib.Path("producer.py"))
app=importlib.util.module_from_spec(spec);spec.loader.exec_module(app)
role=os.environ["CHAIN_ROLE"];phase=os.environ["CHAIN_PHASE"];checks=[]
def check(name,kind,condition):checks.append({"name":name,"kind":kind,"outcome":"passed" if condition else "failed"})
def rejects(records):
    try:app.build_index(records)
    except (TypeError,ValueError):return True
    return False
if role=="author":
    rows=[{"name":"zeta","size":5},{"name":"alpha","size":0}]
    check("typed_sorted_output","positive",app.build_index(rows)==[{"name":"alpha","size":0},{"name":"zeta","size":5}])
    check("boolean_size_rejected","negative",rejects([{"name":"alpha","size":True}]))
elif role=="consumer":
    rows=[{"name":"文件A","size":3},{"name":"beta","size":5}]
    expected=[{"name":"beta","size":5},{"name":"文件A","size":3}]
    valid=app.build_index(rows)==expected
    if phase=="consumer":
        module_spec=importlib.util.spec_from_file_location("consumer",pathlib.Path("consumer.py"))
        consumer=importlib.util.module_from_spec(module_spec);module_spec.loader.exec_module(consumer)
        summary={"format_version":1,"names":["beta","文件A"],"total_bytes":8}
        valid=valid and consumer.summarize(rows)==summary and json.loads(pathlib.Path("consumer-result.json").read_text())==summary
    check("unicode_consumer_readback","positive",valid)
    check("duplicate_name_rejected","negative",rejects([{"name":"a","size":1},{"name":"a","size":2}]))
else:
    rng=random.Random(20261009);rows=[{"name":f"entry-{i:03d}","size":rng.randrange(1000)} for i in range(40)]
    rng.shuffle(rows)
    expected=sorted(({"name":row["name"],"size":row["size"]} for row in rows),key=lambda row:row["name"])
    check("independent_reference_matrix","positive",app.build_index(rows)==expected and app.build_index([])==[])
    bad=[None,{},[{"name":"x","size":-1}],[{"name":"x","size":"1"}],[{"name":"","size":1}],[{"name":"x","size":1,"extra":0}]]
    check("independent_invalid_matrix","negative",all(rejects(value) for value in bad))
pathlib.Path(os.environ["FORGEFLOW_REPORT_PATH"]).write_text(json.dumps({"binding":json.loads(os.environ["FORGEFLOW_EVIDENCE_BINDING"]),"oracle_id":"independent-producer-consumer.v1","cases":checks}))
print(json.dumps({"role":role,"phase":phase,"executed":len(checks),"failed":sum(c["outcome"]!="passed" for c in checks)}),flush=True)
if any(c["outcome"]!="passed" for c in checks):sys.exit(1)
'''
CASES = {
    "author": [("typed_sorted_output", "positive"), ("boolean_size_rejected", "negative")],
    "consumer": [("unicode_consumer_readback", "positive"), ("duplicate_name_rejected", "negative")],
    "independent": [("independent_reference_matrix", "positive"), ("independent_invalid_matrix", "negative")],
}


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def save(path, value):
    Path(path).write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n")


def task_digest(task, spec):
    # Independently encode the public typed field order; optional empty future
    # inputs are omitted exactly as the Rust semantic contract specifies.
    fields = ("outcome", "requirement_digest_refs", "design_anchors", "inputs", "producer_inputs", "mandatory_paths", "dependency_refs",
              "contract_produces", "contract_consumes", "execution_profile", "verification_plan", "verification_case_count", "rollback_plan",
              "known_unknowns", "not_proven", "isolated_contract_probe")
    ordered = {key: spec[key] for key in fields if key in spec and (key != "producer_inputs" or spec[key])}
    spec.clear()
    spec.update(ordered)
    identity = ["forgeflow.task.input.v2"] + [task[key] for key in ("project_id", "task_id", "task_revision", "owner_id", "team_id",
        "requirement_ids", "read_set", "write_set", "dependencies", "resource_request")] + [spec]
    task["input_digest"] = hashlib.sha256(json.dumps(identity, ensure_ascii=False, separators=(",", ":")).encode()).hexdigest()


def source_manifest(repo, revision, overlays=None):
    """Independent encoding of forgeflow.source-content.v1 over raw Git blobs."""
    env = {"PATH": "/usr/bin:/bin", "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null"}
    def read(*argv):
        return subprocess.check_output(["git", "--no-replace-objects", "-C", str(repo), *argv], env=env, timeout=20)
    entries = {}
    for record in read("ls-tree", "-rz", "--full-tree", revision).split(b"\0"):
        if not record:
            continue
        header, path = record.split(b"\t", 1)
        mode, kind, oid = header.split(b" ")
        if kind != b"blob" or mode not in (b"100644", b"100755", b"120000"):
            raise RuntimeError("unsupported source manifest object")
        entries[path] = (mode.decode("ascii"), read("cat-file", "blob", oid.decode("ascii")))
    for path, blob in (overlays or {}).items():
        encoded = path.encode("utf-8")
        if encoded in entries:
            raise RuntimeError("future fixture output already exists: " + path)
        entries[encoded] = ("100644", blob)
    digest = hashlib.sha256(b"forgeflow.source-content.v1\0" + len(entries).to_bytes(8, "big"))
    manifest = []
    for path, (mode, blob) in sorted(entries.items()):
        blob_hash = hashlib.sha256(blob).digest()
        digest.update(int(mode, 8).to_bytes(4, "big"))
        digest.update(len(path).to_bytes(8, "big"))
        digest.update(path)
        digest.update(len(blob).to_bytes(8, "big"))
        digest.update(blob_hash)
        manifest.append({"path_hex": path.hex(), "mode": mode, "blob_bytes": len(blob), "blob_sha256": blob_hash.hex()})
    result = {"algorithm": "forgeflow.source-content.v1", "source_sha256": digest.hexdigest(),
        "tracked_entries": len(entries), "total_blob_bytes": sum(len(blob) for mode, blob in entries.values()), "entries": manifest}
    if overlays:
        result["basis_base_sha"] = revision
        result["future_overlay_paths"] = sorted(overlays)
    else:
        result["commit_sha"] = read("rev-parse", "--verify", "--end-of-options", revision + "^{commit}").decode().strip()
        result["tree_oid"] = read("rev-parse", "--verify", "--end-of-options", revision + "^{tree}").decode().strip()
    return result


class RawEvidenceClient(Client):
    """Keep exact response bytes as well as decoded public API observations."""
    def request(self, method, path, body=None, headers=None):
        hdrs = {"Accept": "application/json", "Authorization": "Bearer " + self.token}
        hdrs.update(headers or {})
        data = None if body is None else json.dumps(body).encode()
        if data is not None:
            hdrs["Content-Type"] = "application/json"
        req = urllib.request.Request(self.base_url + path, data=data, method=method, headers=hdrs)
        started = time.perf_counter_ns()
        try:
            response = self.opener.open(req, timeout=30)
        except urllib.error.HTTPError as error:
            response = error
        except (OSError, urllib.error.URLError) as error:
            self.failed += 1
            self.count += 1
            elapsed = (time.perf_counter_ns() - started) / 1e6
            self.latencies.append({"method": method, "path": path, "latency_ms": elapsed, "status": None})
            raise RuntimeError(f"transport failed for {method} {path}: {error}") from error
        raw = response.read()
        elapsed = (time.perf_counter_ns() - started) / 1e6
        self.count += 1
        self.failed += int(response.status >= 500)
        filename = f"http-{self.count:07d}"
        (self.output / (filename + ".response.bin")).write_bytes(raw)
        record = {"method": method, "path": path, "status": response.status, "latency_ms": elapsed,
            "request": body, "idempotency_key": hdrs.get("Idempotency-Key"),
            "response_sha256": hashlib.sha256(raw).hexdigest(), "response_bytes_path": filename + ".response.bin",
            "received_at": datetime.now(timezone.utc).isoformat(), "response": json.loads(raw) if raw else None}
        self.latencies.append({k: record[k] for k in ("method", "path", "status", "latency_ms")})
        (self.output / (filename + ".json")).write_text(json.dumps(record, ensure_ascii=False) + "\n")
        return response.status, record["response"]


def run(args):
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    if any(output.iterdir()):
        raise RuntimeError("preserve previous evidence: use a new output directory")
    checkpoint = json.loads(args.build_receipt.read_text())
    if not checkpoint.get("consistent_copy") or not checkpoint.get("source_unchanged_after_build") or any(c["exit_code"] for c in checkpoint["commands"]):
        raise RuntimeError("root-approved immutable build did not finish successfully")
    required = ("crates/store/src/materialization.rs", "crates/planner/src/lib.rs", "crates/store/src/admission.rs", "crates/store/src/integration.rs", "crates/git/src/lib.rs")
    if any(path not in checkpoint["source_files"] for path in required):
        raise RuntimeError("approved build has no complete producer materialization source")
    snapshot = Path(checkpoint["snapshot_root"])
    for relative, expected in checkpoint["source_files"].items():
        if sha(snapshot / relative) != expected:
            raise RuntimeError("immutable build source pin mismatch: " + relative)
    if "source_content_manifest" not in (snapshot / "crates/store/src/integration.rs").read_text() or "source_content_sha256" not in (snapshot / "crates/git/src/lib.rs").read_text():
        raise RuntimeError("approved checkpoint does not contain public source-content freeze binding")
    binaries = checkpoint["binaries"]
    for name in ("forgeflow-server", "forgeflow-worker", "forgeflow-sandbox-guard"):
        if sha(binaries[name]["path"]) != binaries[name]["sha256"]:
            raise RuntimeError("approved binary hash mismatch: " + name)
    tag = uuid.uuid4().hex[:16]
    private_root = Path(tempfile.mkdtemp(prefix="forgeflow-public-contract-", dir="/home/chenyoujian/.cache"))
    state_root = private_root / "state"
    state_root.mkdir(mode=0o700)
    source_private = json.loads(args.private_env.read_text())
    database_name = "forgeflow_public_contract_" + tag
    private = {"DATABASE_URL": create_database(source_private, database_name, private_root), "FORGEFLOW_BIND": "127.0.0.1:" + str(args.port),
        "FORGEFLOW_DATA_ROOT": str(state_root), "FORGEFLOW_OWNER_TOKEN": secrets.token_hex(32), "FORGEFLOW_WORKER_TOKEN": secrets.token_hex(32),
        "FORGEFLOW_CONSOLE_DIR": str(ROOT / "console/dist"), "RUST_LOG": "info"}
    secure_save(private_root / "runtime-env.json", private)
    report = {"schema_version": "forgeflow.verification.public-contract-chain.v1", "at": datetime.now(timezone.utc).isoformat(),
        "scope": "Real public contract freeze: pre-approved producer and isolated compatibility consumer, actual controlled Worker/independent verification/Git, actual content SHA256/schema/receipt closure",
        "execution_kind": "CONTROLLED_LIGHTWEIGHT", "real_dsh": False, "model_requests": 0, "production_qualified": False,
        "contract_mode": "ISOLATED_CANDIDATE_PROBE_THEN_PUBLIC_FREEZE", "gate_status": "INCONCLUSIVE", "build_source_identity": checkpoint["source_identity"],
        "build_receipt_sha256": sha(args.build_receipt), "binaries": binaries, "harness_sha256": sha(__file__),
        "isolated_database_name": database_name, "private_root": str(private_root), "credential_values_disclosed": False,
        "private_env_mode": oct(stat.S_IMODE((private_root / "runtime-env.json").stat().st_mode)), "checks": [], "errors": [], "process_shutdown": {},
        "not_proven": ["native DSH author chain", "multiple real producers", "production capacity", "hostile candidate forging the oracle process's own report", "postfreeze normal consumer compilation", "full product Gates"],
        "source_digest_contract": "Git tree OID remains provenance. Public freeze must recompute actual forgeflow.source-content.v1 SHA256 and bind Producer integration plus every required Consumer receipt."}
    (output / "build-receipt.json").write_bytes(args.build_receipt.read_bytes())
    (output / "harness-source.py").write_bytes(Path(__file__).read_bytes())
    (output / "producer-source.py").write_text(PRODUCER)
    (output / "consumer-source.py").write_text(CONSUMER)
    (output / "oracle-source.py").write_text(ORACLE)
    report["helper_source_hashes"] = {}
    helper_root = output / "harness-helpers"
    helper_root.mkdir()
    for relative in ("verification/algorithm_check.py", "verification/guarded_api_chain.py", "benchmarks/control_load.py", "benchmarks/live_control_adapter.py", "benchmarks/metrics.py", "verification/oracle.py"):
        source = ROOT / relative
        if source.is_file():
            report["helper_source_hashes"][relative] = sha(source)
            (helper_root / source.name).write_bytes(source.read_bytes())
    server = worker = client = None
    server_log = worker_log = None
    project = "public-contract-" + tag
    worker_id = "public-contract-worker-" + tag
    report["project_id"] = project

    def check(name, condition, facts=None):
        report["checks"].append({"name": name, "status": "PASS" if condition else "FAIL", "facts": facts})
        if not condition:
            raise RuntimeError("failed assertion: " + name)

    try:
        server_log = (output / "server.log").open("wb")
        server = subprocess.Popen([binaries["forgeflow-server"]["path"]], env={"PATH": "/usr/bin:/bin", **private}, stdout=server_log, stderr=subprocess.STDOUT)
        client = RawEvidenceClient("http://127.0.0.1:" + str(args.port), private["FORGEFLOW_OWNER_TOKEN"], output)
        def healthy():
            if server.poll() is not None:
                raise RuntimeError("isolated server exited before readiness")
            try:
                return client.request("GET", "/api/v1/me")[0] == 200
            except RuntimeError:
                return False
        wait_for(healthy, 30, "isolated API readiness")
        seed = private_root / "seed"
        seed.mkdir()
        git(seed, "init", "--initial-branch=main")
        data_bytes = json.dumps([{"name": "文件A", "size": 3}, {"name": "beta", "size": 5}], ensure_ascii=False).encode()
        (seed / "input-data.json").write_bytes(data_bytes)
        (seed / "README.txt").write_text("Real public contract producer/compatibility consumer chain; no native DSH/model claim.\n")
        git(seed, "add", "--all")
        git(seed, "-c", "user.name=Producer chain verifier", "-c", "user.email=fixture@localhost", "commit", "-m", "Known immutable public contract input")
        base = git(seed, "rev-parse", "HEAD")
        project_row = api(client, "POST", "/projects", {"project_id": project, "name": "Actual producer input DAG chain", "root_path": str(seed),
            "authority_mode": "MANAGED", "data_origin": "NATIVE", "goal": "approved future producer inputs materialize without replanning",
            "technology_stack": ["Python standard library"], "timezone": "Asia/Shanghai", "paused": False, "archived": False, "revision": 0})["data"]
        canonical = Path(project_row["root_path"])
        api(client, "POST", f"/projects/{project}/teams", {"project_id": project, "team_id": "root", "parent_team_id": None, "name": "Finite chain", "paused": False, "revision": 0})
        api(client, "POST", f"/projects/{project}/owners", {"id": "root", "value": {"owner_id": "root", "root_team_id": "root", "include": ["producer.py", "consumer.py", "consumer-result.json"], "exclude": []}})
        requirement = api(client, "POST", f"/projects/{project}/requirements", {"project_id": project, "requirement_id": "R01", "title": "Producer contract and consumer",
            "source_anchor": "chain-contract#R01", "outcome": "typed sorted index consumed without manual replan", "scope": "exact producer module and finite consumer summary",
            "acceptance": ["actual independent positive/negative producer and consumer readback, fenced integration, immutable approved task semantics"],
            "priority": 1, "weight": 1, "deferred_reason": None, "revision": 0})["data"]
        snapshot_value = {"path": "input-data.json", "relative_path": "input-data.json", "sha256": hashlib.sha256(data_bytes).hexdigest(), "source_kind": "GIT_BLOB", "base_sha": base}
        check("known_input_snapshot_matches_actual_base_blob", hashlib.sha256(subprocess.check_output(["git", "-C", str(canonical), "cat-file", "blob", base + ":input-data.json"])).hexdigest() == snapshot_value["sha256"])
        api(client, "POST", f"/projects/{project}/documents/input_snapshots", {"id": "input-data.json", "value": snapshot_value})
        expected_manifest = source_manifest(canonical, base, {"producer.py": PRODUCER.encode("utf-8")})
        base_manifest = source_manifest(canonical, base)
        save(output / "expected-producer-content-manifest.json", expected_manifest)
        save(output / "actual-initial-base-content-manifest.json", base_manifest)
        contract_write = {"contract_id": "typed-index", "version": 1, "producer_task_id": "t00000",
            "schema": {"function": "build_index", "input": "list of exact nonempty string name and nonnegative integer size", "output": "unique typed rows sorted by name"},
            "source_sha256": expected_manifest["source_sha256"], "required_consumers": ["t00001"]}
        contract = api(client, "POST", f"/projects/{project}/contract-versions", contract_write)["data"]
        save(output / "public-contract-draft-before-producer.json", contract)
        check("public_draft_source_pins_independent_future_fixture_manifest", contract["source_sha256"] == expected_manifest["source_sha256"] and contract["frozen"] is False)
        binding = {"contract_id": "typed-index", "version": 1, "spec_sha256": contract["spec_sha256"]}
        oracle = private_root / "registered-chain-oracle.py"
        oracle.write_text(ORACLE)
        readonly = [str(Path(path)) for path in ("/usr", "/bin", "/lib", "/lib64") if Path(path).exists()] + [str(oracle)]
        sandbox = {"bwrap_program": "/usr/bin/bwrap", "bwrap_sha256": sha("/usr/bin/bwrap"), "guard_program": binaries["forgeflow-sandbox-guard"]["path"],
            "guard_sha256": binaries["forgeflow-sandbox-guard"]["sha256"], "readonly_paths": readonly, "network_allowed": False}
        home = private_root / "controlled-home"
        home.mkdir()
        config = {"control_url": client.base_url, "worker_id": worker_id, "project_id": project, "data_root": str(state_root), "model_route_id": "controlled-none",
            "max_active_attempts": 1, "poll_seconds": 1, "max_log_bytes": 1024 * 1024, "controlled_workload_programs": {"/usr/bin/python3": sha("/usr/bin/python3")}, "sandbox": sandbox,
            "profile": {"id": "controlled-lightweight.v1", "program": "/usr/bin/python3", "prefix_args": [], "home": str(home), "profile_name": "headless",
                "artifact_pins": [], "resume_verified": False, "model_route_id": "controlled-none", "gateway_coverage_verified": False}}
        config_path = private_root / "worker-config.json"
        secure_save(config_path, config)
        save(output / "worker-config.json", config)
        worker_log = (output / "worker.log").open("wb")
        worker = subprocess.Popen([binaries["forgeflow-worker"]["path"], "--config", str(config_path)], env={"PATH": "/usr/bin:/bin", "RUST_LOG": "info", "FORGEFLOW_WORKER_TOKEN": private["FORGEFLOW_WORKER_TOKEN"]}, stdout=worker_log, stderr=subprocess.STDOUT)
        def registered():
            if worker.poll() is not None:
                raise RuntimeError("actual Worker exited before registration")
            # Read-only SQL observes the actual Worker registration, never creates it.
            value = database_command(private["DATABASE_URL"], "SELECT count(*) FROM workers WHERE worker_id='" + worker_id + "' AND project_id='" + project + "'")
            return value.returncode == 0 and value.stdout.strip() == b"1"
        wait_for(registered, 30, "actual standalone Worker registration")
        limits = vector(2)
        limits.update(coding_slot=2, cpu_units=2, memory_bytes=128 * 1024 * 1024)
        for scope, p, t, w in [("global-" + tag, None, None, None), ("project-" + tag, project, None, None),
                ("team-" + tag, project, "root", None), ("worker-" + tag, None, None, worker_id)]:
            api(client, "POST", "/resource-policies", {"policy": {"scope_id": scope, "parent_scope_id": None, "project_id": p, "team_id": t, "worker_id": w, "limits": limits, "revision": 0, "paused": False}})
        for collection, identity, value in [("executor_profiles", "controlled-lightweight.v1", {"id": "controlled-lightweight.v1", "kind": "CONTROLLED_LIGHTWEIGHT", "approved_programs": config["controlled_workload_programs"]}),
            ("resource_profiles", "producer-chain.v1", {"id": "producer-chain.v1", "sandbox": sandbox, "qualification": "ACTUAL_FINITE_CONTROLLED_CHAIN"}),
            ("model_routes", "controlled-none", {"id": "controlled-none", "kind": "NO_MODEL", "model_requests": 0})]:
            api(client, "POST", f"/projects/{project}/documents/{collection}", {"id": identity, "value": value})
        case = make_compile(2)
        case["flow"]["project_id"] = project
        meaning = requirement_digest(requirement)
        case["context"].update(owners=[{"owner_id": "root", "root_team_id": "root", "include": ["producer.py", "consumer.py", "consumer-result.json"], "exclude": []}],
            current_inputs={"input-data.json": snapshot_value["sha256"]}, requirement_semantic_digests={"R01": meaning}, requirements=[{"requirement_id": "R01", "source_document": "chain-contract", "anchor": "R01",
            "acceptance": "\n".join(requirement["acceptance"]), "priority": 1, "deferred_reason": None}])
        now = datetime.now(timezone.utc)
        artifact_root = state_root / "artifacts"
        artifact_root.mkdir(exist_ok=True)
        for index, task in enumerate(case["flow"]["tasks"]):
            phase = "producer" if index == 0 else "consumer"
            paths = ["producer.py"] if index == 0 else ["consumer.py", "consumer-result.json"]
            reads = ["input-data.json"] if index == 0 else ["input-data.json", "producer.py"]
            plan_id = "chain-plan-" + task["task_id"]
            task.update(project_id=project, owner_id="root", team_id="root", read_set=reads, write_set=paths, dependencies=[] if index == 0 else ["t00000"])
            task["resource_request"].update(coding_slot=1, cpu_units=1, memory_bytes=64 * 1024 * 1024)
            spec = case["context"]["task_specs"][task["task_id"]]
            spec.update(outcome="Typed index producer" if index == 0 else "Consume typed index and produce a finite independently read summary", inputs=[{"path": "input-data.json", "sha256": snapshot_value["sha256"], "producer_task_id": None}],
                mandatory_paths=reads, dependency_refs=[] if index == 0 else [{"task_id": "t00000", "project_id": project, "kind": "integrated", "binding_id": "t00000:integrated"}],
                contract_produces=[binding] if index == 0 else [], contract_consumes=[] if index == 0 else [binding], isolated_contract_probe=index == 1,
                design_anchors=["chain-contract#R01"], requirement_digest_refs={"R01": meaning}, execution_profile="controlled-lightweight.v1", verification_plan=plan_id, verification_case_count=6)
            if index == 1:
                producer = case["flow"]["tasks"][0]
                spec["producer_inputs"] = [{"path": "producer.py", "producer_task_id": "t00000", "producer_task_revision": producer["task_revision"],
                    "producer_input_digest": producer["input_digest"], "dependency_binding_id": "t00000:integrated", "contract": binding}]
            task_digest(task, spec)
            prompt_text = "Execute the approved finite typed-index " + phase + ". The admission authority supplies the exact execution base and producer hashes; preserve known inputs.\n"
            prompt = api(client, "POST", f"/projects/{project}/artifacts", {"content_utf8": prompt_text, "kind": "PROMPT"})["data"]
            manifest_text = json.dumps({"files": [{"path": "input-data.json", "sha256": snapshot_value["sha256"]}], "mandatory_paths": reads, "artifact_inputs": []}, separators=(",", ":"))
            manifest = api(client, "POST", f"/projects/{project}/artifacts", {"content_utf8": manifest_text, "kind": "CONTEXT_MANIFEST"})["data"]
            task["envelope"] = {"schema_version": "forgeflow.execution.v1", "operation_id": "pending-" + task["task_id"], "project_id": project, "task_id": task["task_id"], "task_revision": 1,
                "attempt_id": "pending-" + task["task_id"], "lease_id": "pending-" + task["task_id"], "generation": 1, "worker_id": worker_id, "workspace_root": str(canonical), "base_sha": base,
                "context_manifest": {"artifact_id": manifest["artifact_id"], "sha256": manifest["sha256"], "mandatory_paths": reads, "rendered_utf8_bytes": len(prompt_text.encode()), "token_estimate": None, "tokenizer_id": None},
                "write_set": paths, "prompt_artifact": {"artifact_id": prompt["artifact_id"], "sha256": prompt["sha256"]}, "model_route_id": "controlled-none", "executor_profile_id": "controlled-lightweight.v1",
                "resource_profile_id": "producer-chain.v1", "verification_plan_id": plan_id, "allowed_effects": ["READ_WORKSPACE", "WRITE_DECLARED_PATHS", "RUN_APPROVED_COMMANDS"],
                "issued_at": now.isoformat(), "expires_at": (now + timedelta(seconds=120)).isoformat(), "deadline_at": (now + timedelta(minutes=20)).isoformat(), "artifact_prefix": str(artifact_root),
                "secret_refs": [], "idempotency_key": "pending-" + task["task_id"], "trace_id": "trace-" + task["task_id"],
                "enforcement": {"model_budget_mode": "direct_observed", "stage_resource_mode": "ATTEMPT_RESERVATION", "build_capable": False, "gateway_coverage_receipt_id": None, "tool_guard_receipt_id": None,
                    "attempt_reserved_build_permits": 0, "all_model_routes_covered": False, "disabled_tool_entry_ids": []}, "session_purpose": "EXECUTION", "max_model_requests": 0, "resume_session_id": None,
                "command": {"program": "/usr/bin/python3", "args": ["-I", "-B", "-c", AUTHOR, phase, PRODUCER if index == 0 else CONSUMER]}}
            commands = [{"role": role, "program": "/usr/bin/python3", "args": ["-I", "-B", str(oracle)], "env": {"CHAIN_ROLE": role, "CHAIN_PHASE": phase, "PYTHONDONTWRITEBYTECODE": "1"},
                "executable_hash": sha("/usr/bin/python3"), "bound_inputs": [{"path": str(oracle), "sha256": sha(oracle)}], "report_path": role + ".json",
                "expected_cases": [{"name": name, "kind": kind} for name, kind in CASES[role]], "timeout_seconds": 20} for role in ("author", "consumer", "independent")]
            api(client, "POST", f"/projects/{project}/documents/verification_plans", {"id": plan_id, "value": {"plan_id": plan_id, "task_revision": 1, "contract_version": "typed-index:1", "input_hash": task["input_digest"],
                "environment_profile": "actual-controlled-chain", "oracle_id": "independent-producer-consumer.v1", "verifier_id": "independent-chain-oracle", "author_id": worker_id, "commands": commands}})
        saved = api(client, "POST", f"/projects/{project}/flow-revisions", {"flow": case["flow"], "context": case["context"]})["data"]
        check("server_typed_task_digest_matches_independent_encoding", all(t["input_digest"] == case["flow"]["tasks"][i]["input_digest"] for i, t in enumerate(saved["tasks"])))
        committed = api(client, "POST", f"/flows/{project}:1/commit", {"expected_revision": saved["revision"]})["data"]
        save(output / "approved-flow-before-producer.json", committed)
        missing = subprocess.run(["git", "-C", str(canonical), "cat-file", "-e", base + ":producer.py"], capture_output=True)
        check("whole_two_task_dag_approved_before_producer_exists", missing.returncode != 0 and len(committed["tasks"]) == 2 and committed["state"] == "COMMITTED")
        frozen_consumer = copy.deepcopy(committed["tasks"][1])
        def admission(task, key):
            return client.request("POST", f"/api/v1/projects/{project}/admissions", {"actor_id": "overwritten", "idempotency_key": "overwritten", "project_id": project,
                "task_id": task["task_id"], "task_revision": task["task_revision"], "flow_revision": 1, "policy_revision": 1, "input_digest": task["input_digest"],
                "worker_id": worker_id, "lease_seconds": 120, "envelope": task["envelope"]}, {"Idempotency-Key": key})
        status, early = admission(frozen_consumer, "early-consumer-" + tag)
        check("future_consumer_refused_before_verified_producer_integration", status >= 400 and early.get("code") == "DEPENDENCY_UNSATISFIED", {"http_status": status, "code": early.get("code")})
        operations = []
        admissions = []
        for index, task in enumerate(committed["tasks"]):
            status, admitted = admission(task, "chain-admit-" + str(index) + "-" + tag)
            check("actual_admission_" + task["task_id"], status < 400, {"http_status": status, "code": admitted.get("code")})
            admitted = admitted["data"]
            admissions.append(admitted)
            attempt_id = admitted["attempt"]["attempt_id"]
            save(output / ("producer-admission.json" if index == 0 else "consumer-admission.json"), admitted)
            def verifying():
                value = api(client, "GET", f"/attempts/{attempt_id}?project_id={project}")["data"]
                if value["state"] in {"FAILED", "CANCELLED", "RECOVERY_REQUIRED"}:
                    raise RuntimeError("actual author failed before verification: " + value["state"])
                return value if value["state"] == "VERIFYING" else None
            authority = wait_for(verifying, 60, "actual finite author execution")
            journal = state_root / "attempts" / attempt_id
            stop = json.loads((journal / "stop.json").read_text())
            result = json.loads((journal / "result.json").read_text())
            check("actual_worker_author_stopped_" + task["task_id"], stop["process_exit_confirmed"] and stop["exit_code"] == 0 and result["evidence"]["real_dsh"] is False)
            if index == 1:
                check("consumer_admission_keeps_approved_task_semantics", authority["task_revision"] == frozen_consumer["task_revision"] and admitted["envelope"]["verification_plan_id"] == frozen_consumer["envelope"]["verification_plan_id"])
                check("consumer_materializes_new_verified_execution_base", admitted["envelope"]["base_sha"] != base and admitted["envelope"]["base_sha"] == operations[0]["result"]["integration"]["integrated_sha"])
                bindings = api(client, "GET", f"/attempts/{attempt_id}/bindings?project_id={project}&worker_id={worker_id}&generation={authority['generation']}")["data"]
                materialization = bindings["producer_input_materialization"]
                save(output / "consumer-materialization-proof.json", materialization)
                blob_bytes = subprocess.check_output(["git", "-C", str(canonical), "cat-file", "blob", admitted["envelope"]["base_sha"] + ":producer.py"])
                check("consumer_manifest_and_proof_bind_actual_producer_bytes", materialization["inputs"][0]["sha256"] == hashlib.sha256(blob_bytes).hexdigest()
                    and materialization["inputs"][0]["producer_attempt_id"] == admissions[0]["attempt"]["attempt_id"] and materialization["recipe"]["task_input_digest"] == frozen_consumer["input_digest"])
                check("consumer_frozen_template_is_preserved_behind_materialization", materialization["recipe"]["approved_manifest_sha256"] == frozen_consumer["envelope"]["context_manifest"]["sha256"]
                    and materialization["manifest_sha256"] == admitted["envelope"]["context_manifest"]["sha256"] and admitted["envelope"]["prompt_artifact"] == frozen_consumer["envelope"]["prompt_artifact"])
            value = operation(client, attempt_id, project, True)
            operations.append(value)
            save(output / ("producer-operation.json" if index == 0 else "consumer-operation.json"), value)
            integration = value["result"]["integration"]
            check("actual_fenced_integration_" + task["task_id"], integration["state"] == "FINALIZED" and integration["receipt"]["commit_decided"] and integration["receipt"]["ref_updated"])
            check("exact_integrated_write_scope_" + task["task_id"], git(canonical, "diff", "--name-only", integration["expected_sha"], integration["integrated_sha"]).splitlines() == sorted(task["write_set"]))
            receipt = integration["receipt"]["verification"]
            check("independent_positive_negative_execution_" + task["task_id"], receipt["total"] == 6 and receipt["failed"] == receipt["skipped"] == 0 and receipt["positive_cases"] == receipt["negative_cases"] == 3)
            evidence = value["result"]["evidence"]
            check("public_receipt_exact_version_binding_" + task["task_id"], evidence["details"]["binding"]["contract_version"] == "typed-index:1"
                and receipt["binding"]["contract_version"] == "typed-index:1" and evidence["attempt_id"] == attempt_id)
            if index == 0:
                actual_manifest = source_manifest(canonical, integration["integrated_sha"])
                save(output / "actual-integrated-producer-content-manifest.json", actual_manifest)
                check("public_actual_integrated_source_matches_preapproved_manifest", actual_manifest["source_sha256"] == expected_manifest["source_sha256"]
                    and actual_manifest["entries"] == expected_manifest["entries"])
                check("public_integration_receipt_carries_actual_content_and_git_provenance", integration["receipt"]["source_content_sha256"] == actual_manifest["source_sha256"]
                    and integration["receipt"]["source_content_algorithm"] == actual_manifest["algorithm"]
                    and integration["receipt"]["source_tree_oid"] == actual_manifest["tree_oid"] == receipt["binding"]["source_hash"])
                missing_body = {"project_id": project, "version": 1, "expected_revision": contract["revision"],
                    "producer_receipt_id": evidence["receipt_id"], "consumer_receipt_ids": []}
                status, missing = client.request("POST", "/api/v1/contracts/typed-index/freeze-requests", missing_body,
                    {"Idempotency-Key": "missing-consumer-freeze-" + tag})
                check("public_freeze_refuses_missing_actual_consumer", status >= 400 and missing.get("code") == "CONTRACT_NOT_FROZEN",
                    {"http_status": status, "code": missing.get("code")})
                current_draft = api(client, "GET", f"/projects/{project}/documents/contract_versions")["data"][0]
                proofs = api(client, "GET", f"/projects/{project}/documents/operations")["data"]
                check("public_failed_freeze_rolls_back_source_proof_and_state", current_draft == contract
                    and not any(p.get("kind") == "CONTRACT_SOURCE_FREEZE" for p in proofs))
            metadata = Path(integration["receipt"]["artifact_root"])
            check("actual_durable_integration_log_hash_" + task["task_id"], sha(metadata / receipt["log_path"]) == receipt["log_hash"])
            branch_roots = [("candidate", artifact_root / value["operation_id"]),
                            ("integration", Path(integration["receipt"]["verifier_scratch_root"])),
                            ("integration-canonical", metadata)]
            for branch, source_root in branch_roots:
                destination = output / "verifiers" / task["task_id"] / branch
                destination.mkdir(parents=True)
                for path in source_root.rglob("*"):
                    if path.is_file():
                        copied = destination / path.relative_to(source_root)
                        copied.parent.mkdir(parents=True, exist_ok=True)
                        copied.write_bytes(path.read_bytes())
                if branch != "integration-canonical":
                    actual_receipt = json.loads((source_root / "verification-receipt.json").read_text())
                    check("actual_six_cases_" + task["task_id"] + "_" + branch, actual_receipt["total"] == 6 and actual_receipt["failed"] == actual_receipt["skipped"] == 0
                          and actual_receipt["positive_cases"] == actual_receipt["negative_cases"] == 3 and sha(source_root / actual_receipt["log_path"]) == actual_receipt["log_hash"])
                    launches = list((source_root / "verification-runs").glob("*/launch-receipt.json"))
                    stops = list((source_root / "verification-runs").glob("*/stop.json"))
                    check("three_actual_guarded_oracle_processes_" + task["task_id"] + "_" + branch, len(launches) == len(stops) == 3
                          and all(json.loads(path.read_text())["command_program"] == sandbox["bwrap_program"] for path in launches)
                          and all(json.loads(path.read_text())["process_exit_confirmed"] and json.loads(path.read_text())["exit_code"] == 0 for path in stops))
            author_copy = output / "authors" / attempt_id
            author_copy.mkdir(parents=True)
            for name in ("envelope.json", "execution-bindings.json", "launch-receipt.json", "stop.json", "result.json", "stdout.ndjson", "stderr.log"):
                (author_copy / name).write_bytes((journal / name).read_bytes())
        current_flow = api(client, "GET", f"/flows/{project}:1")["data"]
        check("original_committed_flow_unchanged_through_entire_chain", current_flow == committed)
        save(output / "approved-flow-after-chain.json", current_flow)
        final_snapshot = api(client, "GET", f"/projects/{project}/snapshot")["data"]
        save(output / "final-authoritative-snapshot.json", final_snapshot)
        check("both_actual_attempts_successful", len(final_snapshot["attempts"]) == 2 and all(a["state"] == "SUCCEEDED" for a in final_snapshot["attempts"]))
        check("all_chain_resource_allocations_released", all(a["state"] == "RELEASED" for a in final_snapshot["allocations"]))
        check("public_contract_still_unfrozen_before_explicit_owner_freeze", api(client, "GET", f"/projects/{project}/documents/contract_versions")["data"][0]["frozen"] is False)
        producer_evidence = operations[0]["result"]["evidence"]
        consumer_evidence = operations[1]["result"]["evidence"]
        # The negative source is an actual different tracked tree, never a fake digest.
        wrong_source_body = {**contract_write, "expected_revision": contract["revision"], "source_sha256": base_manifest["source_sha256"]}
        wrong_source = api(client, "POST", f"/projects/{project}/contract-versions", wrong_source_body)["data"]
        freeze_body = {"project_id": project, "version": 1, "expected_revision": wrong_source["revision"],
            "producer_receipt_id": producer_evidence["receipt_id"], "consumer_receipt_ids": [consumer_evidence["receipt_id"]]}
        status, wrong = client.request("POST", "/api/v1/contracts/typed-index/freeze-requests", freeze_body,
            {"Idempotency-Key": "wrong-actual-source-freeze-" + tag})
        check("public_freeze_rejects_actual_different_source_tree", status >= 400 and wrong.get("code") == "EVIDENCE_BINDING_MISMATCH",
            {"http_status": status, "code": wrong.get("code"), "rejected_actual_base_source_sha256": base_manifest["source_sha256"]})
        check("public_source_mismatch_keeps_contract_unfrozen", api(client, "GET", f"/projects/{project}/documents/contract_versions")["data"][0] == wrong_source)
        contract = api(client, "POST", f"/projects/{project}/contract-versions", {**contract_write, "expected_revision": wrong_source["revision"]})["data"]
        freeze_body["expected_revision"] = contract["revision"]
        freeze_key = "actual-public-freeze-" + tag
        status, response = client.request("POST", "/api/v1/contracts/typed-index/freeze-requests", freeze_body, {"Idempotency-Key": freeze_key})
        check("public_freeze_request_succeeds", status < 400, {"http_status": status, "code": response.get("code")})
        frozen = response["data"]
        save(output / "public-freeze-request.json", freeze_body)
        save(output / "public-frozen-contract.json", frozen)
        check("public_frozen_contract_binds_real_producer_and_all_consumers", frozen["frozen"] is True and frozen["source_sha256"] == expected_manifest["source_sha256"]
            and frozen["spec_sha256"] == binding["spec_sha256"] and frozen["required_consumers"] == frozen["passing_consumers"] == ["t00001"]
            and frozen["independent_receipt_id"] == producer_evidence["receipt_id"]
            and frozen["integration_receipt_id"] == operations[0]["result"]["integration"]["intent_id"] and frozen["revision"] == contract["revision"] + 1)
        status, replayed = client.request("POST", "/api/v1/contracts/typed-index/freeze-requests", freeze_body, {"Idempotency-Key": freeze_key})
        check("public_freeze_same_intent_replays_exact_frozen_contract", status < 400 and replayed["data"] == frozen)
        status, conflict = client.request("POST", "/api/v1/contracts/typed-index/freeze-requests", {**freeze_body, "consumer_receipt_ids": []}, {"Idempotency-Key": freeze_key})
        check("public_freeze_changed_intent_same_key_is_rejected", status == 409 and conflict.get("code") == "IDEMPOTENCY_CONFLICT",
            {"http_status": status, "code": conflict.get("code")})
        status, immutable = client.request("POST", f"/api/v1/projects/{project}/contract-versions", {**contract_write, "expected_revision": frozen["revision"]},
            {"Idempotency-Key": "frozen-contract-mutation-" + tag})
        check("public_frozen_contract_blocks_draft_rewrite", status >= 400 and immutable.get("code") == "CONTRACT_NOT_FROZEN",
            {"http_status": status, "code": immutable.get("code")})
        current_contract = api(client, "GET", f"/projects/{project}/documents/contract_versions")["data"][0]
        check("public_contract_authority_remains_exact_frozen_result", current_contract == frozen)
        proofs = api(client, "GET", f"/projects/{project}/documents/operations")["data"]
        proofs = [p for p in proofs if p.get("kind") == "CONTRACT_SOURCE_FREEZE"]
        save(output / "public-contract-source-freeze-proof.json", proofs)
        check("public_freeze_persists_exactly_one_real_source_proof", len(proofs) == 1 and proofs[0]["producer_attempt_id"] == admissions[0]["attempt"]["attempt_id"]
            and proofs[0]["source_content_sha256"] == expected_manifest["source_sha256"] and proofs[0]["source_content_algorithm"] == "forgeflow.source-content.v1"
            and proofs[0]["integrated_sha"] == operations[0]["result"]["integration"]["integrated_sha"]
            and proofs[0]["source_tree_oid"] == operations[0]["result"]["integration"]["receipt"]["source_tree_oid"])
        postfreeze_snapshot = api(client, "GET", f"/projects/{project}/snapshot")["data"]
        save(output / "postfreeze-authoritative-snapshot.json", postfreeze_snapshot)
        check("public_freeze_preserves_terminal_attempts_and_resource_ledger", postfreeze_snapshot["attempts"] == final_snapshot["attempts"]
            and postfreeze_snapshot["allocations"] == final_snapshot["allocations"])
        report["public_contract_freeze_status"] = "PASS"
        report["completed_public_contract_freeze"] = True
        final_sha = git(canonical, "rev-parse", "refs/heads/main")
        result_bytes = subprocess.check_output(["git", "-C", str(canonical), "cat-file", "blob", final_sha + ":consumer-result.json"])
        check("final_main_contains_independent_consumer_summary", json.loads(result_bytes) == {"format_version": 1, "names": ["beta", "文件A"], "total_bytes": 8})
        report.update(attempt_ids=[a["attempt"]["attempt_id"] for a in admissions], initial_base_sha=base, final_integrated_sha=final_sha,
            actual_independent_integration_cases=12, actual_candidate_and_integration_cases=24, flow_revisions_created=1, postapproval_replans=0)
        check("public_freeze_does_not_rewrite_approved_flow", api(client, "GET", f"/flows/{project}:1")["data"] == committed)
        report["completed_chain"] = True
    except BaseException as error:
        report["errors"].append({"type": type(error).__name__, "message": str(error)})
    finally:
        stop_process(worker, "worker", report)
        stop_process(server, "server", report)
        for stream in (worker_log, server_log):
            if stream is not None:
                stream.close()
        report["failed"] = sum(row["status"] == "FAIL" for row in report["checks"])
        report["assertions"] = len(report["checks"])
        report["status"] = "FAIL" if report["failed"] or report["errors"] or not report.get("completed_chain") or not report.get("completed_public_contract_freeze") else "PASS"
        report["public_freeze_checks"] = [check for check in report["checks"] if check["name"].startswith("public_")]
        report["public_contract_freeze_status"] = "PASS" if report["status"] == "PASS" else "FAIL"
        report["reproduce_argv"] = [sys.executable, *sys.argv]
        report["artifact_hashes"] = [{"path": str(path.relative_to(output)), "sha256": sha(path)} for path in output.rglob("*") if path.is_file() and path.name != "report.json"]
        save(output / "report.json", report)
        print(json.dumps({key: report[key] for key in ("status", "assertions", "failed", "gate_status", "private_root")}))
    return 1 if report["status"] == "FAIL" else 0


if __name__ == "__main__":
    def interrupted(number, frame):
        raise KeyboardInterrupt("public contract chain harness shutdown requested")
    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGINT, interrupted)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build-receipt", type=Path, required=True)
    parser.add_argument("--private-env", type=Path, default=Path("/home/chenyoujian/.local/state/forgeflow/control/runtime-env.json"))
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--port", type=int, default=8794)
    raise SystemExit(run(parser.parse_args()))
