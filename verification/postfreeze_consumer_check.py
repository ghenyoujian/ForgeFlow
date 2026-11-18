#!/usr/bin/env python3
"""Append one normal consumer to an actual preserved public FROZEN contract.

Reuses the public-contract-chain database and immutable producer delivery. Only
public API commands may create/check/commit/admit the new Flow. Existing producer
and compatibility-preview attempts are never rerun. SQL authority writes are not
used. This is controlled author qualification, not native DSH/capacity qualification.
"""
import argparse
import copy
import hashlib
import json
import os
import signal
import stat
import subprocess
import sys
import time
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "verification"))
sys.path.insert(0, str(ROOT / "benchmarks"))
from public_contract_chain_check import RawEvidenceClient, source_manifest, task_digest, sha, save
from guarded_api_chain import wait_for, operation, stop_process, secure_save, database_command
from live_control_adapter import api, git, collection

AUTHOR = '''import importlib.util,json,pathlib,sys
sys.dont_write_bytecode=True
spec=importlib.util.spec_from_file_location("producer",pathlib.Path("producer.py"))
app=importlib.util.module_from_spec(spec);spec.loader.exec_module(app)
rows=app.build_index(json.loads(pathlib.Path("input-data.json").read_text()))
value={"format_version":1,"contract_version":"typed-index:1","contract_source_sha256":sys.argv[1],"contract_spec_sha256":sys.argv[2],"workflow":"PUBLIC_FROZEN_NORMAL_CONSUMER","names":[row["name"] for row in rows],"total_bytes":sum(row["size"] for row in rows)}
pathlib.Path("consumer-result.json").write_text(json.dumps(value,ensure_ascii=False,sort_keys=True)+"\\n")
print(json.dumps({"kind":"CONTROLLED_NORMAL_PUBLIC_CONSUMER","real_dsh":False,"isolated_contract_probe":False}),flush=True)
'''
ORACLE = '''import json,os,pathlib,sys
sys.dont_write_bytecode=True
value=json.loads(pathlib.Path("consumer-result.json").read_text());records=json.loads(pathlib.Path("input-data.json").read_text());role=os.environ["NORMAL_ROLE"];checks=[]
def check(name,kind,condition):checks.append({"name":name,"kind":kind,"outcome":"passed" if condition else "failed"})
def valid(candidate):
    return type(candidate) is dict and set(candidate)=={"format_version","contract_version","contract_source_sha256","contract_spec_sha256","workflow","names","total_bytes"} and type(candidate["format_version"]) is int and candidate["format_version"]==1 and candidate["contract_version"]=="typed-index:1" and candidate["contract_source_sha256"]==os.environ["CONTRACT_SOURCE_SHA256"] and candidate["contract_spec_sha256"]==os.environ["CONTRACT_SPEC_SHA256"] and candidate["workflow"]=="PUBLIC_FROZEN_NORMAL_CONSUMER" and candidate["names"]==sorted(row["name"] for row in records) and type(candidate["total_bytes"]) is int and candidate["total_bytes"]==sum(row["size"] for row in records)
if role=="author":
    check("normal_typed_delivery","positive",valid(value))
    bad=dict(value,format_version=True);check("boolean_version_rejected","negative",not valid(bad))
elif role=="consumer":
    check("normal_contract_bound_readback","positive",valid(value) and value["names"]==["beta","文件A"] and value["total_bytes"]==8)
    bad=dict(value,contract_version="typed-index:2");check("other_contract_version_rejected","negative",not valid(bad))
else:
    check("independent_source_and_summary_binding","positive",valid(value))
    bad=dict(value,contract_source_sha256=os.environ["OTHER_ACTUAL_SOURCE_SHA256"]);check("other_actual_source_rejected","negative",not valid(bad))
pathlib.Path(os.environ["FORGEFLOW_REPORT_PATH"]).write_text(json.dumps({"binding":json.loads(os.environ["FORGEFLOW_EVIDENCE_BINDING"]),"oracle_id":"normal-frozen-contract-consumer.v1","cases":checks}))
print(json.dumps({"role":role,"executed":len(checks),"failed":sum(c["outcome"]!="passed" for c in checks)}),flush=True)
if any(c["outcome"]!="passed" for c in checks):sys.exit(1)
'''
CASES = {
    "author": [("normal_typed_delivery", "positive"), ("boolean_version_rejected", "negative")],
    "consumer": [("normal_contract_bound_readback", "positive"), ("other_contract_version_rejected", "negative")],
    "independent": [("independent_source_and_summary_binding", "positive"), ("other_actual_source_rejected", "negative")],
}


def typed_task_digest(task, spec):
    """Encode typed field order after reading unordered PostgreSQL JSON objects."""
    task["resource_request"] = {key: task["resource_request"][key] for key in
        ("active_slot", "coding_slot", "cpu_units", "memory_bytes", "build_permit", "gpu_permit", "provider_inflight")}
    def contract(value):
        return {key: value[key] for key in ("contract_id", "version", "spec_sha256")}
    spec["inputs"] = [{key: value[key] for key in ("path", "sha256", "producer_task_id")} for value in spec["inputs"]]
    spec["producer_inputs"] = [{**{key: value[key] for key in ("path", "producer_task_id", "producer_task_revision", "producer_input_digest", "dependency_binding_id")},
        "contract": contract(value["contract"])} for value in spec.get("producer_inputs", [])]
    for key in ("contract_produces", "contract_consumes"):
        spec[key] = [contract(value) for value in spec[key]]
    task_digest(task, spec)


def run(args):
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    if any(output.iterdir()):
        raise RuntimeError("use a new output directory; retain original failures")
    parent = args.parent_evidence.resolve()
    parent_bytes = (parent / "report.json").read_bytes()
    previous = json.loads(parent_bytes)
    if previous["status"] != "PASS" or previous["public_contract_freeze_status"] != "PASS":
        raise RuntimeError("a real successful public freeze qualification is required")
    checkpoint = json.loads(args.build_receipt.read_text())
    if not checkpoint["consistent_copy"] or not checkpoint["source_unchanged_after_build"] or any(c["exit_code"] for c in checkpoint["commands"]):
        raise RuntimeError("approved immutable build did not finish successfully")
    snapshot = Path(checkpoint["snapshot_root"])
    for relative, expected in checkpoint["source_files"].items():
        if sha(snapshot / relative) != expected:
            raise RuntimeError("immutable source pin mismatch: " + relative)
    binaries = checkpoint["binaries"]
    for name in ("forgeflow-server", "forgeflow-worker", "forgeflow-sandbox-guard"):
        if sha(binaries[name]["path"]) != binaries[name]["sha256"]:
            raise RuntimeError("immutable binary pin mismatch: " + name)
    private_root = Path(previous["private_root"])
    private_path = private_root / "runtime-env.json"
    private = json.loads(private_path.read_text())
    private["FORGEFLOW_BIND"] = "127.0.0.1:" + str(args.port)
    project = previous["project_id"]
    tag = uuid.uuid4().hex[:12]
    task_id = "postfreeze-" + tag
    report = {"schema_version": "forgeflow.verification.postfreeze-consumer.v1", "at": datetime.now(timezone.utc).isoformat(),
        "scope": "One ordinary consumer after actual public contract freeze: public Flow checks/compile/commit/admission, actual controlled Worker, independent verification and fenced Git",
        "execution_kind": "CONTROLLED_LIGHTWEIGHT", "real_dsh": False, "model_requests": 0,
        "gate_status": "INCONCLUSIVE", "production_qualified": False, "project_id": project, "task_id": task_id,
        "parent_evidence": str(parent), "parent_report_sha256": hashlib.sha256(parent_bytes).hexdigest(),
        "build_source_identity": checkpoint["source_identity"], "build_receipt_sha256": sha(args.build_receipt),
        "harness_sha256": sha(__file__), "binaries": binaries, "checks": [], "errors": [], "process_shutdown": {},
        "credential_values_disclosed": False, "private_env_mode": oct(stat.S_IMODE(private_path.stat().st_mode)),
        "not_proven": ["native DSH normal consumer", "production capacity", "hostile candidate oracle report forgery", "full product Gates"]}
    for target, source in [("build-receipt.json", args.build_receipt), ("parent-report.original.json", parent / "report.json"), ("harness-source.py", Path(__file__))]:
        (output / target).write_bytes(source.read_bytes())
    helpers = output / "harness-helpers"
    helpers.mkdir()
    for relative in ("verification/public_contract_chain_check.py", "verification/guarded_api_chain.py", "verification/algorithm_check.py", "benchmarks/control_load.py", "benchmarks/live_control_adapter.py", "benchmarks/metrics.py", "verification/oracle.py"):
        (helpers / Path(relative).name).write_bytes((ROOT / relative).read_bytes())
    (output / "author-source.py").write_text(AUTHOR)
    (output / "oracle-source.py").write_text(ORACLE)
    server = worker = None
    streams = []
    def check(name, condition, facts=None):
        report["checks"].append({"name": name, "status": "PASS" if condition else "FAIL", "facts": facts})
        if not condition:
            raise RuntimeError("failed assertion: " + name)
    try:
        server_log = (output / "server.txt").open("wb")
        streams.append(server_log)
        server = subprocess.Popen([binaries["forgeflow-server"]["path"]], env={"PATH": "/usr/bin:/bin", **private}, stdout=server_log, stderr=subprocess.STDOUT)
        client = RawEvidenceClient("http://127.0.0.1:" + str(args.port), private["FORGEFLOW_OWNER_TOKEN"], output)
        def healthy():
            if server.poll() is not None:
                raise RuntimeError("server exited before readiness")
            try:
                return client.request("GET", "/api/v1/me")[0] == 200
            except RuntimeError:
                return False
        wait_for(healthy, 30, "preserved public contract database readiness")
        frozen = api(client, "GET", f"/projects/{project}/documents/contract_versions")["data"][0]
        baseline = api(client, "GET", f"/projects/{project}/snapshot")["data"]
        old_flow = api(client, "GET", f"/flows/{project}:1")["data"]
        context = api(client, "GET", f"/flows/{project}:1/context")["data"]
        canonical = Path(baseline["project"]["root_path"])
        initial_main = git(canonical, "rev-parse", "refs/heads/main")
        source_proof = json.loads((parent / "public-contract-source-freeze-proof.json").read_text())[0]
        actual_content = source_manifest(canonical, source_proof["integrated_sha"])
        check("reuses_real_frozen_contract_and_actual_producer", frozen == json.loads((parent / "public-frozen-contract.json").read_text())
            and frozen["frozen"] is True and actual_content["source_sha256"] == frozen["source_sha256"]
            and actual_content["tree_oid"] == source_proof["source_tree_oid"])
        save(output / "initial-frozen-contract.json", frozen)
        save(output / "initial-authoritative-snapshot.json", baseline)
        save(output / "actual-reused-producer-source-manifest.json", actual_content)
        # A normal bounded server shutdown pauses projects durably. Resume only
        # this already authorized private project through the public Owner CAS.
        if baseline["project"]["paused"]:
            resumed_project = copy.deepcopy(baseline["project"])
            resumed_project["paused"] = False
            resumed = api(client, "PATCH", f"/projects/{project}", {"project": resumed_project,
                "expected_revision": baseline["project"]["revision"]})["data"]
            check("private_project_resumed_through_public_owner_cas", resumed["paused"] is False
                and resumed["revision"] == baseline["project"]["revision"] + 1)
        worker_config = json.loads((private_root / "worker-config.json").read_text())
        worker_id = worker_config["worker_id"]
        if args.resume_approved_flow is not None:
            if args.approved_evidence is None:
                raise RuntimeError("approved evidence is required when resuming the already committed consumer")
            revision = args.resume_approved_flow
            committed = api(client, "GET", f"/flows/{project}:{revision}")["data"]
            approved_context = api(client, "GET", f"/flows/{project}:{revision}/context")["data"]
            previous_approved = json.loads((args.approved_evidence / "normal-consumer-approved-flow.json").read_text())
            previous_checks = json.loads((args.approved_evidence / "normal-consumer-public-checks.json").read_text())
            new = committed["tasks"][-1]
            spec = approved_context["task_specs"][new["task_id"]]
            task_id = new["task_id"]
            report["task_id"] = task_id
            report["approved_flow_evidence"] = str(args.approved_evidence.resolve())
            for name in ("normal-consumer-approved-flow.json", "normal-consumer-public-checks.json"):
                (output / ("reused-" + name)).write_bytes((args.approved_evidence / name).read_bytes())
            check("reuses_exact_publicly_checked_and_committed_ordinary_consumer", committed == previous_approved
                and committed["state"] == "COMMITTED" and previous_checks["passed"] is True and spec["isolated_contract_probe"] is False
                and any(ref["kind"] == "contract_frozen" and ref["binding_id"] == "typed-index:1" for ref in spec["dependency_refs"]))
            save(output / "normal-consumer-approved-flow.json", committed)
        else:
            all_flows = collection(client, f"/projects/{project}/flows")
            revision = max(f["flow_revision"] for f in all_flows) + 1
            flow = copy.deepcopy(old_flow)
            flow.update(flow_revision=revision, parent_revision=1, state="DRAFT", revision=1, approved_by=None)
            for existing in flow["tasks"]:
                existing["flow_revision"] = revision
            new = copy.deepcopy(flow["tasks"][1])
            new.update(task_id=task_id, title="Normal consumer of the publicly frozen typed-index contract", task_revision=1,
                state="PLANNED", revision=1, write_set=["consumer-result.json"], dependencies=["t00000", "t00001"])
            spec = copy.deepcopy(context["task_specs"]["t00001"])
            plan_id = "normal-contract-" + tag
            spec.update(outcome="Consume the actual publicly frozen typed-index contract and deliver a contract/source-bound summary", isolated_contract_probe=False,
                verification_plan=plan_id, dependency_refs=[{"task_id": "t00000", "project_id": project, "kind": "integrated", "binding_id": "t00000:integrated"},
                    {"task_id": "t00000", "project_id": project, "kind": "contract_frozen", "binding_id": "typed-index:1"},
                    {"task_id": "t00001", "project_id": project, "kind": "integrated", "binding_id": "t00001:integrated"}])
            typed_task_digest(new, spec)
            context["task_specs"][task_id] = spec
            context["contracts"] = [{key: frozen[key] for key in ("contract_id", "version", "spec_sha256", "source_sha256", "frozen", "required_consumers", "passing_consumers", "independent_receipt_id", "integration_receipt_id")}]
            now = datetime.now(timezone.utc)
            prompt_text = "Execute one normal consumer of the actually FROZEN typed-index:1 contract. Preserve frozen producer inputs and all undeclared paths.\n"
            prompt = api(client, "POST", f"/projects/{project}/artifacts", {"content_utf8": prompt_text, "kind": "PROMPT"})["data"]
            old_manifest = new["envelope"]["context_manifest"]
            new["envelope"].update(task_id=task_id, task_revision=1, operation_id="pending-" + task_id, attempt_id="pending-" + task_id,
                lease_id="pending-" + task_id, idempotency_key="pending-" + task_id, trace_id="trace-" + task_id,
                write_set=new["write_set"], verification_plan_id=plan_id, issued_at=now.isoformat(), expires_at=(now + timedelta(seconds=120)).isoformat(),
                deadline_at=(now + timedelta(minutes=20)).isoformat(), prompt_artifact={"artifact_id": prompt["artifact_id"], "sha256": prompt["sha256"]},
                command={"program": "/usr/bin/python3", "args": ["-I", "-B", "-c", AUTHOR, frozen["source_sha256"], frozen["spec_sha256"]]})
            old_manifest["rendered_utf8_bytes"] = len(prompt_text.encode())
            oracle = private_root / ("postfreeze-oracle-" + tag + ".py")
            oracle.write_text(ORACLE)
            other_source = json.loads((parent / "actual-initial-base-content-manifest.json").read_text())["source_sha256"]
            commands = [{"role": role, "program": "/usr/bin/python3", "args": ["-I", "-B", str(oracle)],
                "env": {"NORMAL_ROLE": role, "CONTRACT_SOURCE_SHA256": frozen["source_sha256"], "CONTRACT_SPEC_SHA256": frozen["spec_sha256"], "OTHER_ACTUAL_SOURCE_SHA256": other_source},
                "executable_hash": sha("/usr/bin/python3"), "bound_inputs": [{"path": str(oracle), "sha256": sha(oracle)}], "report_path": role + ".json",
                "expected_cases": [{"name": name, "kind": kind} for name, kind in CASES[role]], "timeout_seconds": 20} for role in ("author", "consumer", "independent")]
            api(client, "POST", f"/projects/{project}/documents/verification_plans", {"id": plan_id, "value": {"plan_id": plan_id, "task_revision": 1,
                "contract_version": "typed-index:1", "input_hash": new["input_digest"], "environment_profile": "actual-controlled-normal-consumer", "oracle_id": "normal-frozen-contract-consumer.v1",
                "verifier_id": "independent-normal-contract-oracle", "author_id": worker_id, "commands": commands}})
            flow["tasks"].append(new)
            save(output / "normal-consumer-proposal.json", {"flow": flow, "context": context})
            saved = api(client, "POST", f"/projects/{project}/flow-revisions", {"flow": flow, "context": context})["data"]
            check("ordinary_consumer_draft_uses_exact_frozen_public_contract", len(saved["tasks"]) == 3 and spec["isolated_contract_probe"] is False
                and new["input_digest"] == saved["tasks"][-1]["input_digest"])
            checked = api(client, "POST", f"/flows/{project}:{revision}/checks")["data"]
            save(output / "normal-consumer-public-checks.json", checked)
            check("ordinary_consumer_public_compile_checks_pass", checked["passed"] is True, {"findings": checked["findings"]})
            committed = api(client, "POST", f"/flows/{project}:{revision}/commit", {"expected_revision": saved["revision"]})["data"]
            save(output / "normal-consumer-approved-flow.json", committed)
            check("ordinary_consumer_flow_publicly_committed", committed["state"] == "COMMITTED")
            new = committed["tasks"][-1]
        worker_config["control_url"] = client.base_url
        config_path = private_root / ("postfreeze-worker-config-" + tag + ".json")
        secure_save(config_path, worker_config)
        save(output / "worker-config.json", worker_config)
        worker_log = (output / "worker.txt").open("wb")
        streams.append(worker_log)
        worker = subprocess.Popen([binaries["forgeflow-worker"]["path"], "--config", str(config_path)],
            env={"PATH": "/usr/bin:/bin", "RUST_LOG": "info", "FORGEFLOW_WORKER_TOKEN": private["FORGEFLOW_WORKER_TOKEN"]}, stdout=worker_log, stderr=subprocess.STDOUT)
        def registered():
            if worker.poll() is not None:
                raise RuntimeError("Worker exited before registration")
            result = database_command(private["DATABASE_URL"], "SELECT count(*) FROM workers WHERE worker_id='" + worker_id + "' AND heartbeat_at>clock_timestamp()-interval '15 seconds'")
            return result.returncode == 0 and result.stdout.strip() == b"1"
        wait_for(registered, 30, "actual resumed Worker registration")
        admitted = api(client, "POST", f"/projects/{project}/admissions", {"actor_id": "overwritten", "idempotency_key": "overwritten", "project_id": project,
            "task_id": task_id, "task_revision": 1, "flow_revision": revision, "policy_revision": 1, "input_digest": new["input_digest"],
            "worker_id": worker_id, "lease_seconds": 120, "envelope": new["envelope"]})["data"]
        save(output / "normal-consumer-admission.json", admitted)
        attempt_id = admitted["attempt"]["attempt_id"]
        check("ordinary_consumer_admitted_against_real_frozen_dependency", admitted["envelope"]["base_sha"] == initial_main)
        def verifying():
            value = api(client, "GET", f"/attempts/{attempt_id}?project_id={project}")["data"]
            if value["state"] in {"FAILED", "CANCELLED", "RECOVERY_REQUIRED"}:
                raise RuntimeError("actual normal consumer failed before verification: " + value["state"])
            return value if value["state"] == "VERIFYING" else None
        wait_for(verifying, 60, "actual normal consumer author execution")
        journal = Path(private["FORGEFLOW_DATA_ROOT"]) / "attempts" / attempt_id
        stop = json.loads((journal / "stop.json").read_text())
        result = json.loads((journal / "result.json").read_text())
        check("ordinary_consumer_actual_author_stops_successfully", stop["process_exit_confirmed"] and stop["exit_code"] == 0 and result["evidence"]["real_dsh"] is False)
        executed = operation(client, attempt_id, project, True)
        save(output / "normal-consumer-operation.json", executed)
        integration = executed["result"]["integration"]
        receipt = integration["receipt"]["verification"]
        check("ordinary_consumer_independent_verification_and_git_finalize", integration["state"] == "FINALIZED" and receipt["total"] == 6
            and receipt["failed"] == receipt["skipped"] == 0 and receipt["binding"]["contract_version"] == "typed-index:1")
        check("ordinary_consumer_exact_write_scope_integrated", git(canonical, "diff", "--name-only", integration["expected_sha"], integration["integrated_sha"]).splitlines() == ["consumer-result.json"])
        author_copy = output / "author"
        author_copy.mkdir()
        for name in ("envelope.json", "execution-bindings.json", "launch-receipt.json", "stop.json", "result.json", "stdout.ndjson", "stderr.log"):
            (author_copy / name).write_bytes((journal / name).read_bytes())
        branches = {"candidate": Path(private["FORGEFLOW_DATA_ROOT"]) / "artifacts" / executed["operation_id"],
            "integration": Path(integration["receipt"]["verifier_scratch_root"]), "integration-canonical": Path(integration["receipt"]["artifact_root"])}
        for branch, source in branches.items():
            for path in source.rglob("*"):
                if path.is_file():
                    target = output / "verifiers" / branch / path.relative_to(source)
                    target.parent.mkdir(parents=True, exist_ok=True)
                    target.write_bytes(path.read_bytes())
        final = api(client, "GET", f"/projects/{project}/snapshot")["data"]
        save(output / "final-authoritative-snapshot.json", final)
        old_ids = {a["attempt_id"] for a in baseline["attempts"]}
        check("exactly_one_new_attempt_without_producer_or_preview_rerun", len(final["attempts"]) == len(baseline["attempts"]) + 1
            and all(a["state"] == "SUCCEEDED" for a in final["attempts"]) and {a["attempt_id"] for a in final["attempts"]} - old_ids == {attempt_id})
        check("ordinary_consumer_allocations_release_without_changing_frozen_contract", all(a["state"] == "RELEASED" for a in final["allocations"])
            and api(client, "GET", f"/projects/{project}/documents/contract_versions")["data"][0] == frozen)
        check("historical_flow_and_qualification_report_preserved", api(client, "GET", f"/flows/{project}:1")["data"] == old_flow
            and (parent / "report.json").read_bytes() == parent_bytes)
        final_blob = json.loads(subprocess.check_output(["git", "-C", str(canonical), "cat-file", "blob", integration["integrated_sha"] + ":consumer-result.json"], timeout=20))
        check("final_main_contains_normal_contract_bound_delivery", final_blob["workflow"] == "PUBLIC_FROZEN_NORMAL_CONSUMER"
            and final_blob["contract_source_sha256"] == frozen["source_sha256"] and final_blob["names"] == ["beta", "文件A"] and final_blob["total_bytes"] == 8)
        report.update(completed_normal_consumer=True, attempt_id=attempt_id, flow_revision=revision, initial_main_sha=initial_main,
            final_integrated_sha=integration["integrated_sha"], actual_candidate_and_integration_cases=12, producer_attempts_rerun=0)
    except BaseException as error:
        report["errors"].append({"type": type(error).__name__, "message": str(error)})
    finally:
        stop_process(worker, "worker", report)
        stop_process(server, "server", report)
        for stream in streams:
            stream.close()
        report["failed"] = sum(c["status"] == "FAIL" for c in report["checks"])
        report["assertions"] = len(report["checks"])
        report["status"] = "PASS" if report.get("completed_normal_consumer") and not report["errors"] and report["failed"] == 0 else "FAIL"
        report["reproduce_argv"] = [sys.executable, *sys.argv]
        report["artifact_hashes"] = [{"path": str(p.relative_to(output)), "sha256": sha(p)} for p in output.rglob("*") if p.is_file() and p.name != "report.json"]
        save(output / "report.json", report)
        print(json.dumps({k: report[k] for k in ("status", "assertions", "failed", "gate_status", "errors")}))
    return 0 if report["status"] == "PASS" else 1


if __name__ == "__main__":
    def interrupted(number, frame):
        raise KeyboardInterrupt("postfreeze consumer shutdown requested")
    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGINT, interrupted)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build-receipt", type=Path, required=True)
    parser.add_argument("--parent-evidence", type=Path, default=ROOT / "verification/evidence/public-contract-chain/6fceb88e-r2")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--port", type=int, default=8794)
    parser.add_argument("--resume-approved-flow", type=int)
    parser.add_argument("--approved-evidence", type=Path)
    raise SystemExit(run(parser.parse_args()))
