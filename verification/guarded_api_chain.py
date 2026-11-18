#!/usr/bin/env python3
"""Actual guarded controlled-author/API/verifier/Git probes in a private database.

Requires an A00-approved immutable build receipt. No model requests are made.
Controlled Review stdout is explicitly promoted by this controller, after its
real process stops, to exercise the artifact mapper; native extraction is not
claimed. Credentials remain in a mode0600 file outside the repository.
"""
import argparse
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
import urllib.parse
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.dont_write_bytecode = True
sys.path.insert(0, str(ROOT / "benchmarks"))
sys.path.insert(0, str(ROOT / "verification"))
from algorithm_check import make_compile, refresh_digest, requirement_digest, vector
from control_load import Client
from live_control_adapter import api, git
from metrics import process_fingerprint


CASES = [
    ("business_positive", "positive"), ("business_negative", "negative"),
    ("candidate_write_denied", "negative"), ("git_metadata_write_denied", "negative"),
    ("canonical_read_denied", "negative"), ("canonical_write_denied", "negative"),
    ("other_project_read_denied", "negative"), ("other_project_write_denied", "negative"),
    ("prior_role_report_read_denied", "negative"), ("prior_role_report_write_denied", "negative"),
    ("hardlink_candidate_write_denied", "negative"), ("symlink_candidate_write_denied", "negative"),
    ("report_neighbor_create_denied", "negative"), ("artifact_or_neighbor_readonly_write_denied", "negative"),
    ("current_report_write_allowed", "positive"),
]

ORACLE = r'''import importlib.util,json,os,pathlib,sys
cases=[]
def check(name,kind,value): cases.append({'name':name,'kind':kind,'outcome':'passed' if value else 'failed'})
def denied(action):
    try: action()
    except OSError: return True
    return False
workspace=pathlib.Path.cwd();report=pathlib.Path(os.environ['FORGEFLOW_REPORT_PATH'])
artifact=os.environ.get('FORGEFLOW_ARTIFACT_PATH')
if artifact:
    def valid(value): return isinstance(value,dict) and value.get('kind')=='CONTROL_LOAD' and value.get('purpose')=='REVIEW' and value.get('author_fence')=={'outside_write_denied':True,'canonical_read_denied':True,'other_project_read_denied':True}
    check('business_positive','positive',valid(json.loads(pathlib.Path(artifact).read_text())))
    check('business_negative','negative',not valid({'kind':'untrusted-pass','purpose':'REVIEW'}))
else:
    spec=importlib.util.spec_from_file_location('candidate',workspace/'application.py')
    app=importlib.util.module_from_spec(spec);spec.loader.exec_module(app)
    check('business_positive','positive',app.add(2,3)==5)
    try: app.add('invalid',3)
    except TypeError: rejected=True
    else: rejected=False
    check('business_negative','negative',rejected)
canonical=pathlib.Path(os.environ['CANONICAL_CANARY']);other=pathlib.Path(os.environ['OTHER_PROJECT_CANARY'])
check('candidate_write_denied','negative',denied(lambda:(workspace/'application.py').write_text('unauthorized')))
check('git_metadata_write_denied','negative',denied(lambda:(workspace/'.git/forgeflow-author-canary').write_text('unauthorized')))
check('canonical_read_denied','negative',denied(lambda:canonical.read_bytes()))
check('canonical_write_denied','negative',denied(lambda:canonical.write_text('unauthorized')))
check('other_project_read_denied','negative',denied(lambda:other.read_bytes()))
check('other_project_write_denied','negative',denied(lambda:other.write_text('unauthorized')))
role=os.environ['VERIFIER_ROLE'];prior=report.parent/('author.json' if role!='author' else 'consumer.json')
check('prior_role_report_read_denied','negative',denied(lambda:prior.read_bytes()))
check('prior_role_report_write_denied','negative',denied(lambda:prior.write_text('forged prior or future report')))
def alias_write(kind):
    alias=pathlib.Path('/tmp')/('forgeflow-api-'+kind+'-'+str(os.getpid()))
    try:
        if kind=='hardlink':os.link(workspace/'application.py',alias)
        else:alias.symlink_to(workspace/'application.py')
        alias.write_text('unauthorized')
    finally:
        try:alias.unlink()
        except FileNotFoundError:pass
check('hardlink_candidate_write_denied','negative',denied(lambda:alias_write('hardlink')))
check('symlink_candidate_write_denied','negative',denied(lambda:alias_write('symlink')))
check('report_neighbor_create_denied','negative',denied(lambda:(report.parent/'forged-neighbor.json').write_text('unauthorized')))
readonly=pathlib.Path(artifact) if artifact else workspace/'outside.txt'
check('artifact_or_neighbor_readonly_write_denied','negative',denied(lambda:readonly.write_text('unauthorized')))
try:report.write_text('current-output-inode-is-writable');writable=True
except OSError:writable=False
check('current_report_write_allowed','positive',writable)
report.write_text(json.dumps({'binding':json.loads(os.environ['FORGEFLOW_EVIDENCE_BINDING']),'oracle_id':'actual-api-single-output-fence.v1','cases':cases}))
print(json.dumps({'role':role,'actual_attack_cases':len(cases),'failed':sum(c['outcome']!='passed' for c in cases)}),flush=True)
if any(c['outcome']!='passed' for c in cases):sys.exit(1)
'''

AUTHOR = r'''import json,pathlib,sys,time
canonical,other,purpose=sys.argv[1:]
def denied(action):
    try:action()
    except OSError:return True
    return False
fence={'outside_write_denied':denied(lambda:pathlib.Path('outside.txt').write_text('unauthorized')),'canonical_read_denied':denied(lambda:pathlib.Path(canonical).read_bytes()),'other_project_read_denied':denied(lambda:pathlib.Path(other).read_bytes())}
if purpose=='EXECUTION':
    pathlib.Path('application.py').write_text("# Actual zero-model controlled author\ndef add(a,b):\n    if not isinstance(a,int) or not isinstance(b,int):\n        raise TypeError('integer operands required')\n    return a+b\n")
pathlib.Path('.git/forgeflow-author-canary').write_text('private author metadata scratch\n')
time.sleep(2)
print(json.dumps({'kind':'CONTROL_LOAD','purpose':purpose,'author_fence':fence}),flush=True)
if not all(fence.values()):sys.exit(1)
'''


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def save(path, value):
    Path(path).write_text(json.dumps(value, indent=2) + "\n")


def secure_save(path, value):
    descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(descriptor, "w") as stream:
        json.dump(value, stream)
        stream.write("\n")


def database_command(database_url, statement):
    original = urllib.parse.urlsplit(database_url)
    options = urllib.parse.parse_qs(original.query)
    env = {"PATH": "/usr/bin:/bin", "PGHOST": options.get("host", [original.hostname or "127.0.0.1"])[0], "PGPORT": options.get("port", [str(original.port or 5432)])[0],
           "PGUSER": options.get("user", [urllib.parse.unquote(original.username or "")])[0], "PGPASSWORD": urllib.parse.unquote(original.password or ""),
           "PGDATABASE": original.path.lstrip("/")}
    psql = Path("/home/chenyoujian/.cache/forgeflow-postgres/root/usr/lib/postgresql/16/bin/psql")
    library = psql.parents[3] / "x86_64-linux-gnu"
    env["LD_LIBRARY_PATH"] = str(library)
    return subprocess.run([str(psql), "--no-psqlrc", "--no-password", "--tuples-only", "--no-align", "--set", "ON_ERROR_STOP=1", "--command", statement], env=env, capture_output=True, timeout=30)


def create_database(main_private, name, private_root):
    original = urllib.parse.urlsplit(main_private["DATABASE_URL"])
    result = database_command(main_private["DATABASE_URL"], 'CREATE DATABASE "' + name + '"')
    diagnostic = private_root / "database-create.stderr"
    descriptor = os.open(diagnostic, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(result.stderr)
    if result.returncode:
        raise RuntimeError("isolated database creation failed; private diagnostic retained")
    return urllib.parse.urlunsplit(original._replace(path="/" + name))


def group_processes(group):
    found = []
    for process in Path("/proc").iterdir():
        if not process.name.isdigit():
            continue
        try:
            fields = (process / "stat").read_text().rsplit(") ", 1)[1].split()
            if int(fields[2]) == group and fields[0] not in {"Z", "X"}:
                found.append(int(process.name))
        except (OSError, ValueError, IndexError):
            continue
    return found


def wait_for(callback, timeout, description):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        value = callback()
        if value:
            return value
        time.sleep(.25)
    raise RuntimeError(description + " timed out")


def operation(client, attempt, project, integrate):
    accepted = api(client, "POST", f"/attempts/{attempt}/" + ("verify-and-integrate" if integrate else "verify"), {"project_id": project})
    def settled():
        value = api(client, "GET", "/operations/" + accepted["operation_id"])["data"]
        if value["status"] in {"FAILED", "RECOVERY_REQUIRED"}:
            raise RuntimeError("actual verification operation failed: " + json.dumps(value.get("error")))
        return value if value["status"] == "SUCCEEDED" else None
    return wait_for(settled, 120, "actual verification operation")


def stop_process(process, name, report):
    if process is None:
        return
    try:
        if process.poll() is None:
            process.send_signal(signal.SIGTERM)
            try:
                process.wait(timeout=35)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
                report["errors"].append(name + " required SIGKILL after bounded shutdown")
    except Exception as error:
        report["errors"].append({"shutdown": name, "type": type(error).__name__, "message": str(error)})
    report["process_shutdown"][name] = {"pid": process.pid, "exit_code": process.returncode, "exited": process.poll() is not None}


def run(args):
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    if any(output.iterdir()):
        raise RuntimeError("preserve previous evidence: choose a new output directory")
    checkpoint = json.loads(args.build_receipt.read_text())
    if not checkpoint.get("consistent_copy") or not checkpoint.get("source_unchanged_after_build") or any(c.get("exit_code") != 0 for c in checkpoint["commands"]):
        raise RuntimeError("approved checkpoint build did not finish successfully")
    commands = [command["argv"] for command in checkpoint["commands"]]
    if not (any("build" in argv and "--workspace" in argv for argv in commands)
            and any("test" in argv and "--workspace" in argv for argv in commands)
            and any("test" in argv and "forgeflow-store" in argv and "authority" in argv and "--ignored" in argv for argv in commands)):
        raise RuntimeError("approved checkpoint requires successful workspace build/test and live PostgreSQL authority checks")
    snapshot_root = Path(checkpoint["snapshot_root"])
    for relative, expected in checkpoint["source_files"].items():
        if sha(snapshot_root / relative) != expected:
            raise RuntimeError("approved immutable checkpoint source pin mismatch: " + relative)
    working_changes = [{"path": relative, "checkpoint_sha256": expected, "working_tree_sha256": sha(ROOT / relative) if (ROOT / relative).is_file() else None}
                       for relative, expected in checkpoint["source_files"].items()
                       if not (ROOT / relative).is_file() or sha(ROOT / relative) != expected]
    added_inputs = []
    for directory in ("crates", "migrations", "contracts"):
        for path in (ROOT / directory).rglob("*"):
            if not path.is_file() or not (path.suffix in {".rs", ".sql"} or path.name == "Cargo.toml" or directory == "contracts"):
                continue
            relative = str(path.relative_to(ROOT))
            if relative not in checkpoint["source_files"]:
                added_inputs.append({"path": relative, "working_tree_sha256": sha(path)})
    binaries = checkpoint["binaries"]
    for name in ("forgeflow-server", "forgeflow-worker", "forgeflow-sandbox-guard"):
        if sha(binaries[name]["path"]) != binaries[name]["sha256"]:
            raise RuntimeError("immutable checkpoint binary pin mismatch: " + name)
    tag = uuid.uuid4().hex[:16]
    private_root = Path(tempfile.mkdtemp(prefix="forgeflow-guarded-api-", dir="/home/chenyoujian/.cache"))
    state_root = private_root / "state"
    state_root.mkdir(mode=0o700)
    main_private = json.loads(args.private_env.read_text())
    database_name = "forgeflow_guarded_api_" + tag
    private = {"DATABASE_URL": create_database(main_private, database_name, private_root), "FORGEFLOW_BIND": "127.0.0.1:8790",
               "FORGEFLOW_DATA_ROOT": str(state_root), "FORGEFLOW_OWNER_TOKEN": secrets.token_hex(32), "FORGEFLOW_WORKER_TOKEN": secrets.token_hex(32),
               "FORGEFLOW_CONSOLE_DIR": str(ROOT / "console/dist"), "RUST_LOG": "info"}
    secure_save(private_root / "runtime-env.json", private)
    report = {"schema_version": "forgeflow.verification.actual-guarded-api.v1", "at": datetime.now(timezone.utc).isoformat(),
              "scope": "Actual strong registered controlled author, all three guarded API verifier branches, independent business/attack oracle and fenced Git integration in isolated database",
              "model_kind": "NO_MODEL", "author_execution_kind": "CONTROLLED_LIGHTWEIGHT", "real_dsh": False, "gate_status": "INCONCLUSIVE",
              "build_receipt_sha256": sha(args.build_receipt), "source_identity": checkpoint["source_identity"], "binaries": binaries,
              "qualification_source_root": str(snapshot_root), "working_tree_changes_outside_qualification": working_changes,
              "working_tree_added_inputs_outside_qualification": added_inputs,
              "latest_working_tree_qualified": False,
              "private_root": str(private_root), "private_env_mode": oct(stat.S_IMODE((private_root / "runtime-env.json").stat().st_mode)),
              "isolated_database_name": database_name, "credential_values_disclosed": False, "checks": [], "errors": [], "operations": [], "process_shutdown": {},
              "not_proven": ["actual model/DSH author under strong isolation", "native artifact extraction", "real model concurrency", "CPU/memory OS enforcement", "hostile candidate import sharing its oracle process cannot forge that oracle's own report", "full P0 gates"],
              "prior_role_denominator_scope": "Consumer and independent commands probe earlier reports that exist on the host; the first author command probes forbidden future-report creation, whose read case alone is not a prior-report confidentiality proof."}
    server = worker = client = None
    project = "guarded-api-" + tag
    report["project_id"] = project
    def check(name, condition, facts=None):
        report["checks"].append({"name": name, "status": "PASS" if condition else "FAIL", "facts": facts})
    try:
        server_log = (output / "server.log").open("wb")
        server = subprocess.Popen([binaries["forgeflow-server"]["path"]], env={"PATH": "/usr/bin:/bin", **private}, stdout=server_log, stderr=subprocess.STDOUT)
        client = Client("http://127.0.0.1:8790", private["FORGEFLOW_OWNER_TOKEN"], output)
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
        application = "def add(a,b):\n    if not isinstance(a,int) or not isinstance(b,int):\n        raise TypeError('integer operands required')\n    return a+b\n"
        (seed / "application.py").write_text(application)
        (seed / "outside.txt").write_text("synthetic immutable neighbor\n")
        git(seed, "add", "--all")
        git(seed, "-c", "user.name=Isolation oracle", "-c", "user.email=oracle@localhost", "commit", "-m", "Private controlled baseline")
        base = git(seed, "rev-parse", "HEAD")
        created = api(client, "POST", "/projects", {"project_id": project, "name": "Actual registered isolation API probe", "root_path": str(seed), "authority_mode": "MANAGED", "data_origin": "NATIVE", "goal": "actual guards with controlled zero-model author", "technology_stack": ["Python standard library"], "timezone": "Asia/Shanghai", "paused": False, "archived": False, "revision": 0})["data"]
        canonical = Path(created["root_path"])
        canary = canonical / "forgeflow-host-canary"
        canary.write_text("synthetic canonical marker\n")
        other = private_root / "other-project-canary"
        other.write_text("synthetic other project marker\n")
        canary_hashes = {str(path): sha(path) for path in (canary, other)}
        oracle = private_root / "registered-oracle.py"
        oracle.write_text(ORACLE)
        (output / "oracle-source.py").write_bytes(oracle.read_bytes())
        (output / "author-source.py").write_text(AUTHOR)
        readonly = [str(Path(path)) for path in ("/usr", "/bin", "/lib", "/lib64") if Path(path).exists()] + [str(oracle)]
        sandbox = {"bwrap_program": "/usr/bin/bwrap", "bwrap_sha256": sha("/usr/bin/bwrap"), "guard_program": binaries["forgeflow-sandbox-guard"]["path"], "guard_sha256": binaries["forgeflow-sandbox-guard"]["sha256"], "readonly_paths": readonly, "network_allowed": False}
        worker_id = "guarded-worker-" + tag
        home = private_root / "controlled-home"
        home.mkdir()
        config = {"control_url": client.base_url, "worker_id": worker_id, "project_id": project, "data_root": str(state_root), "model_route_id": "controlled-none", "max_active_attempts": 1, "poll_seconds": 1, "max_log_bytes": 1024 * 1024,
                  "controlled_workload_programs": {"/usr/bin/python3": sha("/usr/bin/python3")}, "sandbox": sandbox,
                  "profile": {"id": "controlled-lightweight.v1", "program": "/usr/bin/python3", "prefix_args": [], "home": str(home), "profile_name": "headless", "artifact_pins": [], "resume_verified": False, "model_route_id": "controlled-none", "gateway_coverage_verified": False}}
        config_path = private_root / "worker-config.json"
        secure_save(config_path, config)
        save(output / "worker-config.json", config)
        api(client, "POST", f"/projects/{project}/teams", {"project_id": project, "team_id": "root", "parent_team_id": None, "name": "Controlled isolation", "paused": False, "revision": 0})
        api(client, "POST", f"/projects/{project}/owners", {"id": "root", "value": {"owner_id": "root", "root_team_id": "root", "include": ["application.py"], "exclude": []}})
        requirement = api(client, "POST", f"/projects/{project}/requirements", {"project_id": project, "requirement_id": "R01", "title": "Real verifier isolation", "source_anchor": "controlled-isolation#R01", "outcome": "real process guards and unchanged protected bytes", "scope": "single-file process outputs and private Git integration", "acceptance": ["candidate and canonical fences deny real unauthorized operations"], "priority": 1, "weight": 1, "deferred_reason": None, "revision": 0})["data"]
        worker_log = (output / "worker.log").open("wb")
        worker = subprocess.Popen([binaries["forgeflow-worker"]["path"], "--config", str(config_path)], env={"PATH": "/usr/bin:/bin", "RUST_LOG": "info", "FORGEFLOW_WORKER_TOKEN": private["FORGEFLOW_WORKER_TOKEN"]}, stdout=worker_log, stderr=subprocess.STDOUT)
        def registered():
            if worker.poll() is not None:
                raise RuntimeError("actual controlled Worker exited before registration")
            row = database_command(private["DATABASE_URL"], "SELECT json_build_object('worker_id',worker_id,'project_id',project_id,'executor_profile_ids',executor_profile_ids) FROM workers WHERE worker_id='" + worker_id + "' AND project_id='" + project + "' AND executor_profile_ids @> '[\"controlled-lightweight.v1\"]'::jsonb")
            return json.loads(row.stdout) if row.returncode == 0 and row.stdout.strip() else None
        registration = wait_for(registered, 30, "actual project/profile-bound Worker registration")
        save(output / "actual-worker-registration.json", {"source": "read-only isolated PostgreSQL worker row created by real Worker protocol", "registration": registration})
        for scope, scope_project, scope_team, scope_worker in (("global", None, None, None), ("project", project, None, None), ("worker", None, None, worker_id), ("team", project, "root", None)):
            limits = vector(1)
            limits.update(coding_slot=1, memory_bytes=64 * 1024 * 1024)
            api(client, "POST", "/resource-policies", {"policy": {"scope_id": scope, "parent_scope_id": None, "project_id": scope_project, "team_id": scope_team, "worker_id": scope_worker, "limits": limits, "revision": 0, "paused": False}})
        for collection, identity, value in (("executor_profiles", "controlled-lightweight.v1", {"id": "controlled-lightweight.v1", "kind": "CONTROLLED_LIGHTWEIGHT", "approved_programs": config["controlled_workload_programs"]}), ("resource_profiles", "guarded-control.v1", {"id": "guarded-control.v1", "scope": "CONTROL_LOAD", "stage_resource_mode": "ATTEMPT_RESERVATION", "isolation_profile": "PRIVATE_GIT_METADATA", "sandbox": sandbox}), ("model_routes", "controlled-none", {"id": "controlled-none", "kind": "NO_MODEL", "model_requests": 0})):
            api(client, "POST", f"/projects/{project}/documents/{collection}", {"id": identity, "value": value})
        prompt = api(client, "POST", f"/projects/{project}/artifacts", {"content_utf8": "Run approved zero-model controlled probe.\n", "kind": "PROMPT"})["data"]
        manifest_text = json.dumps({"files": [], "mandatory_paths": [], "artifact_inputs": []}, separators=(",", ":"))
        manifest = api(client, "POST", f"/projects/{project}/artifacts", {"content_utf8": manifest_text, "kind": "CONTEXT_MANIFEST"})["data"]
        case = make_compile(2)
        case["flow"]["project_id"] = project
        meaning = requirement_digest(requirement)
        case["context"].update(owners=[{"owner_id": "root", "root_team_id": "root", "include": ["application.py"], "exclude": []}], current_inputs={}, requirement_semantic_digests={"R01": meaning}, requirements=[{"requirement_id": "R01", "source_document": "controlled-isolation", "anchor": "R01", "acceptance": "\n".join(requirement["acceptance"]), "priority": 1, "deferred_reason": None}])
        now = datetime.now(timezone.utc)
        for index, task in enumerate(case["flow"]["tasks"]):
            purpose = "EXECUTION" if index == 0 else "REVIEW"
            plan_id = "guard-plan-" + task["task_id"]
            task.update(project_id=project, owner_id="root", team_id="root", read_set=[], write_set=["application.py"] if index == 0 else [], dependencies=[])
            task["resource_request"].update(coding_slot=1 if index == 0 else 0, memory_bytes=64 * 1024 * 1024)
            spec = case["context"]["task_specs"][task["task_id"]]
            spec.update(inputs=[], mandatory_paths=[], dependency_refs=[], design_anchors=["controlled-isolation#R01"], requirement_digest_refs={"R01": meaning}, execution_profile="controlled-lightweight.v1", verification_plan=plan_id, verification_case_count=45)
            envelope = {"schema_version": "forgeflow.execution.v1", "operation_id": "pending-" + task["task_id"], "project_id": project, "task_id": task["task_id"], "task_revision": 1, "attempt_id": "pending-" + task["task_id"], "lease_id": "pending-" + task["task_id"], "generation": 1, "worker_id": worker_id, "workspace_root": str(canonical), "base_sha": base,
                        "context_manifest": {"artifact_id": manifest["artifact_id"], "sha256": manifest["sha256"], "mandatory_paths": [], "rendered_utf8_bytes": len(manifest_text.encode()), "token_estimate": None, "tokenizer_id": None}, "write_set": task["write_set"], "prompt_artifact": {"artifact_id": prompt["artifact_id"], "sha256": prompt["sha256"]}, "model_route_id": "controlled-none", "executor_profile_id": "controlled-lightweight.v1", "resource_profile_id": "guarded-control.v1", "verification_plan_id": plan_id,
                        "allowed_effects": ["READ_WORKSPACE", "RUN_APPROVED_COMMANDS"] + (["WRITE_DECLARED_PATHS"] if index == 0 else []), "issued_at": now.isoformat(), "expires_at": (now + timedelta(seconds=120)).isoformat(), "deadline_at": (now + timedelta(minutes=10)).isoformat(), "artifact_prefix": str(state_root / "artifacts"), "secret_refs": [], "idempotency_key": "pending-" + task["task_id"], "trace_id": "trace-" + task["task_id"], "enforcement": {"model_budget_mode": "direct_observed", "stage_resource_mode": "ATTEMPT_RESERVATION", "build_capable": False, "gateway_coverage_receipt_id": None, "tool_guard_receipt_id": None, "attempt_reserved_build_permits": 0, "all_model_routes_covered": False, "disabled_tool_entry_ids": []}, "session_purpose": purpose, "max_model_requests": 0, "resume_session_id": None, "command": {"program": "/usr/bin/python3", "args": ["-I", "-B", "-c", AUTHOR, str(canary), str(other), purpose]}}
            task["envelope"] = envelope
            refresh_digest(task, spec)
            commands = [{"role": role, "program": "/usr/bin/python3", "args": ["-I", "-B", str(oracle)], "env": {"VERIFIER_ROLE": role, "CANONICAL_CANARY": str(canary), "OTHER_PROJECT_CANARY": str(other), "PYTHONDONTWRITEBYTECODE": "1"}, "executable_hash": sha("/usr/bin/python3"), "bound_inputs": [{"path": str(oracle), "sha256": sha(oracle)}], "report_path": role + ".json", "expected_cases": [{"name": name, "kind": kind} for name, kind in CASES], "timeout_seconds": 20} for role in ("author", "consumer", "independent")]
            api(client, "POST", f"/projects/{project}/documents/verification_plans", {"id": plan_id, "value": {"plan_id": plan_id, "task_revision": 1, "contract_version": "guarded-probe.v1", "input_hash": task["input_digest"], "environment_profile": "registered-profile-label-alone-is-not-qualification", "oracle_id": "actual-api-single-output-fence.v1", "verifier_id": "independent-isolation-oracle", "author_id": worker_id, "commands": commands}})
        saved = api(client, "POST", f"/projects/{project}/flow-revisions", {"flow": case["flow"], "context": case["context"]})["data"]
        committed = api(client, "POST", f"/flows/{project}:1/commit", {"expected_revision": saved["revision"]})["data"]
        for index, task in enumerate(committed["tasks"]):
            admitted = api(client, "POST", f"/projects/{project}/admissions", {"actor_id": "overwritten", "idempotency_key": "overwritten", "project_id": project, "task_id": task["task_id"], "task_revision": task["task_revision"], "flow_revision": task["flow_revision"], "policy_revision": 1, "input_digest": task["input_digest"], "worker_id": worker_id, "lease_seconds": 120, "envelope": task["envelope"]})["data"]
            attempt_id = admitted["attempt"]["attempt_id"]
            report.setdefault("attempt_ids", []).append(attempt_id)
            def verifying():
                attempt = api(client, "GET", f"/attempts/{attempt_id}?project_id={project}")["data"]
                if attempt["state"] in {"FAILED", "CANCELLED", "RECOVERY_REQUIRED"}:
                    raise RuntimeError("actual author failed before verifying: " + attempt["state"])
                return attempt if attempt["state"] == "VERIFYING" else None
            authority = wait_for(verifying, 60, "actual guarded author")
            journal = state_root / "attempts" / attempt_id
            stop = json.loads((journal / "stop.json").read_text())
            launch = json.loads((journal / "launch-receipt.json").read_text())
            result = json.loads((journal / "result.json").read_text())
            check("actual_author_stopped_" + task["task_id"], stop["process_exit_confirmed"] and stop["exit_code"] == 0 and not process_fingerprint(launch["process"]["pid"]))
            check("actual_author_zero_model_provenance_" + task["task_id"], result["evidence"]["real_dsh"] is False and result["evidence"]["executor_kind"] == "CONTROLLED_LIGHTWEIGHT" and result["outcome"]["final_artifact"] is None)
            check("actual_author_guarded_launch_" + task["task_id"], launch["command_program"] == sandbox["bwrap_program"] and sandbox["guard_program"] in launch["command_args"])
            stdout = (journal / "stdout.ndjson").read_bytes()
            stdout_bound = hashlib.sha256(stdout).hexdigest() == result["outcome"]["raw_event_digest"]
            check("actual_author_stdout_hash_bound_" + task["task_id"], stdout_bound)
            if not stdout_bound:
                raise RuntimeError("actual controlled stdout differs from Worker raw-event digest")
            artifact_value = json.loads(stdout)
            check("actual_author_attacks_refused_" + task["task_id"], all(artifact_value["author_fence"].values()))
            if index == 1:
                promoted = journal / "final.json"
                promoted.write_bytes(stdout)
                save(output / "controller-controlled-stdout-promotion.json", {"scope": "Harness controller promotion after real controlled process exit; not native Worker/model artifact extraction", "attempt_id": attempt_id, "generation": authority["generation"], "execution_id": result["outcome"]["execution_id"], "source": str(journal / "stdout.ndjson"), "target": str(promoted), "source_sha256": sha(journal / "stdout.ndjson"), "target_sha256": sha(promoted), "worker_final_artifact": None, "real_dsh": False})
            value = operation(client, attempt_id, project, index == 0)
            report["operations"].append({"attempt_id": attempt_id, "operation_id": value["operation_id"], "status": value["status"], "kind": "VERIFY_AND_INTEGRATE" if index == 0 else "READ_ONLY_ARTIFACT"})
            save(output / ("execution-operation.json" if index == 0 else "artifact-operation.json"), value)
            for name in ("envelope.json", "execution-bindings.json", "sandbox.json", "launch-receipt.json", "stop.json", "result.json", "stdout.ndjson", "stderr.log"):
                destination = output / "authors" / attempt_id / name
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_bytes((journal / name).read_bytes())
            operation_roots = [state_root / "artifacts" / value["operation_id"]]
            if index == 0:
                integration = value["result"]["integration"]
                operation_roots.append(state_root / "worktrees" / ("integration-" + value["operation_id"] + "-verification"))
                check("controlled_git_integration_finalized", integration["state"] == "FINALIZED" and integration["receipt"]["commit_decided"] and integration["receipt"]["ref_updated"])
                check("canonical_main_actual_integrated_sha", git(canonical, "rev-parse", "refs/heads/main") == integration["integrated_sha"])
                check("exact_integrated_write_scope", git(canonical, "diff", "--name-only", base, integration["integrated_sha"]).splitlines() == ["application.py"])
            for branch_index, root in enumerate(operation_roots):
                branch = "integration" if branch_index else "candidate" if index == 0 else "artifact"
                disk_receipt = json.loads((root / "verification-receipt.json").read_text())
                check(branch + "_45_actual_business_attack_cases", disk_receipt["total"] == 45 and disk_receipt["failed"] == disk_receipt["skipped"] == 0 and disk_receipt["positive_cases"] > 0 and disk_receipt["negative_cases"] > 0)
                check(branch + "_raw_log_hash_bound", sha(root / disk_receipt["log_path"]) == disk_receipt["log_hash"])
                destination = output / "verifiers" / branch
                destination.mkdir(parents=True)
                for path in root.rglob("*"):
                    if path.is_file():
                        copied = destination / path.relative_to(root)
                        copied.parent.mkdir(parents=True, exist_ok=True)
                        copied.write_bytes(path.read_bytes())
                receipts = list((root / "verification-runs").glob("*/launch-receipt.json"))
                check(branch + "_three_actual_guarded_oracle_launches", len(receipts) == 3 and all(json.loads(p.read_text())["command_program"] == sandbox["bwrap_program"] and sandbox["guard_program"] in json.loads(p.read_text())["command_args"] for p in receipts))
                stops = list((root / "verification-runs").glob("*/stop.json"))
                check(branch + "_all_oracle_groups_stopped", len(stops) == 3 and all(json.loads(p.read_text())["process_exit_confirmed"] and json.loads(p.read_text())["exit_code"] == 0 for p in stops))
        check("canonical_other_project_canaries_unchanged", all(sha(path) == digest for path, digest in canary_hashes.items()))
        snapshot = api(client, "GET", f"/projects/{project}/snapshot")["data"]
        save(output / "final-snapshot.json", snapshot)
        check("both_actual_author_attempts_succeeded", len(snapshot["attempts"]) == 2 and all(a["state"] == "SUCCEEDED" for a in snapshot["attempts"]))
        check("all_allocations_released_all_leases_revoked", bool(snapshot["allocations"]) and all(a["state"] == "RELEASED" for a in snapshot["allocations"]) and all(l["revoked_at"] for l in snapshot["leases"]))
        model_rows = database_command(private["DATABASE_URL"], "SELECT count(*) FROM provider_requests WHERE project_id='" + project + "'")
        check("isolated_authority_has_zero_model_requests", model_rows.returncode == 0 and model_rows.stdout.strip() == b"0")
    except Exception as error:
        report["errors"].append({"type": type(error).__name__, "message": str(error)})
    finally:
        if client is not None:
            try:
                for attempt in api(client, "GET", f"/projects/{project}/snapshot")["data"]["attempts"]:
                    if attempt["state"] not in {"SUCCEEDED", "FAILED", "CANCELLED"}:
                        api(client, "POST", f"/attempts/{attempt['attempt_id']}/cancel", {"project_id": project, "expected_revision": attempt["revision"], "reason": "private isolated qualification cleanup"})
            except Exception as error:
                report["errors"].append({"cleanup": type(error).__name__, "message": str(error)})
        stop_process(worker, "worker", report)
        stop_process(server, "server", report)
        author_pids = []
        for launch_path in state_root.glob("attempts/*/launch-receipt.json"):
            identity = json.loads(launch_path.read_text())["process"]
            fingerprint = process_fingerprint(identity["pid"])
            if fingerprint and fingerprint["start_ticks"] == identity["start_ticks"]:
                author_pids.append(identity["pid"])
        check("zero_actual_author_processes_after_bounded_shutdown", not author_pids, {"still_alive_author_pids": author_pids})
        verifier_pids = []
        verifier_launches = list(state_root.glob("**/verification-runs/*/launch-receipt.json"))
        for launch_path in verifier_launches:
            identity = json.loads(launch_path.read_text())["process"]
            verifier_pids.extend(group_processes(identity["pgid"]))
        check("zero_actual_verifier_groups_after_bounded_shutdown", not verifier_pids, {"recorded_verifier_launches": len(verifier_launches), "still_alive_pids": sorted(set(verifier_pids))})
        check("all_three_actual_api_branches_completed", len(report["operations"]) == 2 and len(verifier_launches) == 9
              and all(any(row["name"] == branch + "_45_actual_business_attack_cases" and row["status"] == "PASS" for row in report["checks"]) for branch in ("candidate", "integration", "artifact")))
        report["failed"] = sum(c["status"] == "FAIL" for c in report["checks"])
        report["assertions"] = len(report["checks"])
        report["actual_business_attack_cases"] = 135 if len(report["operations"]) == 2 and not report["errors"] else None
        report["status"] = "FAIL" if report["failed"] or report["errors"] else "PASS"
        report["artifact_hashes"] = [{"path": str(path.relative_to(output)), "sha256": sha(path)} for path in output.rglob("*") if path.is_file() and path.name != "report.json"]
        report["harness_sha256"] = sha(__file__)
        report["reproduce_argv"] = [sys.executable, *sys.argv]
        save(output / "report.json", report)
        print(json.dumps({"status": report["status"], "assertions": report["assertions"], "failed": report["failed"], "errors": len(report["errors"]), "gate_status": report["gate_status"], "private_root": str(private_root)}))
    return 1 if report["status"] == "FAIL" else 0


if __name__ == "__main__":
    interrupted = False
    def stop_requested(number, frame):
        global interrupted
        if not interrupted:
            interrupted = True
            raise RuntimeError("qualification interrupted by signal; bounded private process cleanup follows")
    signal.signal(signal.SIGTERM, stop_requested)
    signal.signal(signal.SIGINT, stop_requested)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build-receipt", type=Path, required=True)
    parser.add_argument("--private-env", type=Path, default=Path("/home/chenyoujian/.local/state/forgeflow/control/runtime-env.json"))
    parser.add_argument("--output", type=Path, required=True)
    raise SystemExit(run(parser.parse_args()))
