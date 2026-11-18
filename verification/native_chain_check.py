#!/usr/bin/env python3
"""Read-only independent audit of an actual native Worker/Git business chain."""
import argparse
import hashlib
import json
import subprocess
import sys
import urllib.request
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def run(args):
    output = Path(args.output).resolve()
    output.mkdir(parents=True, exist_ok=True)
    private = json.loads(Path(args.private_env).read_text())
    journal = Path(private["FORGEFLOW_DATA_ROOT"]) / "attempts" / args.attempt
    qualification = Path(args.qualification)
    recorded = json.loads((qualification / "receipt.json").read_text())
    operation = json.loads((qualification / "verification-integration-operation.json").read_text())
    checks = []
    def check(name, condition, facts=None):
        checks.append({"name": name, "status": "PASS" if condition else "FAIL", "facts": facts})
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    def get(path, filename):
        request = urllib.request.Request(args.base_url.rstrip("/") + "/api/v1" + path,
            headers={"Authorization": "Bearer " + private["FORGEFLOW_OWNER_TOKEN"]})
        with opener.open(request, timeout=30) as response:
            raw = response.read()
        (output / filename).write_bytes(raw)
        return json.loads(raw)["data"]
    actual = get(f"/attempts/{args.attempt}?project_id={args.project}", "actual-attempt.json")
    snapshot = get(f"/projects/{args.project}/snapshot", "actual-snapshot.json")
    current_op = get("/operations/" + operation["operation_id"], "actual-operation.json")
    result = json.loads((journal / "result.json").read_text())
    launch = json.loads((journal / "launch-receipt.json").read_text())
    stop = json.loads((journal / "stop.json").read_text())
    bindings = json.loads((journal / "execution-bindings.json").read_text())
    worktree = json.loads((journal / "worktree.json").read_text())
    envelope = json.loads((journal / "envelope.json").read_text())
    check("authoritative_native_attempt_succeeded", actual["state"] == "SUCCEEDED" and current_op["status"] == "SUCCEEDED")
    check("attempt_generation_project_worker_bound", all(result[k] == actual[k] for k in ("attempt_id", "generation", "project_id", "worker_id", "lease_id")))
    check("real_native_profile_not_controlled", result["evidence"].get("real_dsh") is True and result["evidence"].get("executor_kind") == "DSH_HEADLESS" and envelope.get("command") is None)
    check("execution_uuid_native_session_separate", result["outcome"]["execution_id"] == launch["execution_id"] == recorded["execution_id"] and result["outcome"]["upstream_session_id"] == recorded["native_session_id"] and recorded["execution_id"] != recorded["operation_id"])
    stream = journal / "stdout.ndjson"
    events = [json.loads(line) for line in stream.read_text().splitlines() if line]
    check("raw_native_stream_hash_bound", digest(stream) == result["outcome"]["raw_event_digest"] == recorded["native_stdout_sha256"])
    check("native_completed_turn_and_final", any(v.get("type") == "status" and v.get("phase") == "turn_end" and v.get("reason", {}).get("kind") == "completed" for v in events) and any(v.get("type") == "final" and v.get("text") for v in events))
    check("real_model_steps_observed", any(v.get("type") == "status" and v.get("phase") == "step_end" and v.get("usage", {}).get("inputTokens", 0) > 0 for v in events))
    check("native_exit_stop_acknowledged", stop["process_exit_confirmed"] and stop["exit_code"] == 0 and (journal / "result-ack.json").exists())
    rows = [r for r in snapshot["allocations"] if r["attempt_id"] == args.attempt]
    leases = [l for l in snapshot["leases"] if l["attempt_id"] == args.attempt]
    check("terminal_allocations_released_lease_revoked", bool(rows) and all(r["state"] == "RELEASED" for r in rows) and bool(leases) and all(l["revoked_at"] for l in leases), {"allocation_rows": len(rows)})
    pin_errors = []
    for pin in bindings["executor_profile"]["artifact_pins"]:
        if not Path(pin["path"]).is_file() or digest(pin["path"]) != pin["sha256"]:
            pin_errors.append(pin["path"])
    check("loaded_native_artifact_pins_still_match", not pin_errors, {"pins": len(bindings["executor_profile"]["artifact_pins"]), "mismatches": pin_errors})
    plan = bindings["verification_plan"]
    integration = current_op["result"]["integration"]
    receipt = integration["receipt"]["verification"]
    task = next(t for t in snapshot["tasks"] if t["task_id"] == actual["task_id"])
    check("verifier_frozen_input_and_task_revision", receipt["binding"]["input_hash"] == task["input_digest"] == plan["input_hash"] and task["task_revision"] == actual["task_revision"])
    check("verifier_immutable_plan_binding", receipt["binding"]["verification_plan_id"] == plan["plan_id"] and receipt["binding"]["task_revision"] == actual["task_revision"] == plan["task_revision"] and receipt["binding"]["generation"] == actual["generation"])
    check("registered_nonzero_distinct_roles_cases", {c["role"] for c in plan["commands"]} == {"author", "consumer", "independent"} and receipt["total"] == sum(len(c["expected_cases"]) for c in plan["commands"]) == 8 and receipt["failed"] == receipt["skipped"] == 0 and receipt["positive_cases"] > 0 and receipt["negative_cases"] > 0 and receipt["verifier_id"] != receipt["author_id"])
    metadata = Path(integration["receipt"]["artifact_root"])
    check("raw_verifier_log_and_disk_receipt_match", digest(metadata / receipt["log_path"]) == receipt["log_hash"] and json.loads((metadata / "verification-receipt.json").read_text()) == receipt)
    for command in plan["commands"]:
        expected = {(c["name"], c["kind"]) for c in command["expected_cases"]}
        report = json.loads((metadata / command["report_path"]).read_text())
        check("executed_structured_cases_" + command["role"], {(c["name"], c["kind"]) for c in report["cases"]} == expected and all(c["outcome"] == "passed" for c in report["cases"]) and report["binding"] == receipt["binding"] and report["oracle_id"] == plan["oracle_id"])
        check("external_pinned_runner_" + command["role"], digest(command["program"]) == command["executable_hash"] and all(digest(p["path"]) == p["sha256"] and not Path(p["path"]).resolve().is_relative_to(Path(worktree["worktree"]["absolute_path"]).resolve()) for p in command["bound_inputs"]))
    repository = worktree["repository"]
    def git(*argv, binary=False):
        return subprocess.run(["git", "--git-dir", repository, *argv], capture_output=True, check=True, timeout=30).stdout if binary else subprocess.run(["git", "--git-dir", repository, *argv], capture_output=True, text=True, check=True, timeout=30).stdout.strip()
    integrated, candidate = integration["integrated_sha"], integration["candidate_sha"]
    ancestry = subprocess.run(["git", "--git-dir", repository, "merge-base", "--is-ancestor", integrated, "refs/heads/main"], capture_output=True, timeout=30)
    check("real_git_intent_finalized_and_main_reachable", integration["state"] == "FINALIZED" and integration["receipt"]["commit_decided"] and integration["receipt"]["ref_updated"] and ancestry.returncode == 0)
    check("candidate_integrated_source_trees_identical", git("rev-parse", candidate + "^{tree}") == git("rev-parse", integrated + "^{tree}") == receipt["binding"]["source_hash"])
    check("exact_declared_integrated_write_scope", git("diff", "--name-only", integration["expected_sha"], integrated).splitlines() == ["indexer.py"] and envelope["write_set"] == ["indexer.py"])
    extracted = output / "integrated-indexer.py"
    extracted.write_bytes(git("show", integrated + ":indexer.py", binary=True))
    oracle_output = output / "business-oracle.json"
    oracle = subprocess.run([sys.executable, str(Path(__file__).with_name("verify_indexer.py")), "--candidate", str(extracted), "--output", str(oracle_output)], capture_output=True, text=True, timeout=120)
    business = json.loads(oracle_output.read_text()) if oracle_output.exists() else {}
    check("integrated_business_output_independent_15_cases", oracle.returncode == 0 and business.get("status") == "PASS" and business.get("attempted_assertions") == 15 and business.get("failed") == 0)
    evidence_paths = [Path(__file__)] + list(qualification.glob("*.json")) + [journal / n for n in ("stdout.ndjson", "stderr.log", "launch-receipt.json", "stop.json", "result.json", "envelope.json", "execution-bindings.json")] + [p for p in output.glob("*.json") if p.name != "report.json"]
    report = {"schema_version": "forgeflow.verification.native-chain.v1", "scope": "Single actual native DSH author via API/Worker, registered 8-case verifier, durable Git integration and additional independent 15-case business oracle",
        "at": datetime.now(timezone.utc).isoformat(), "project_id": args.project, "attempt_id": args.attempt,
        "integrated_sha": integrated, "candidate_sha": candidate, "checks": checks, "assertions": len(checks), "failed": sum(c["status"] == "FAIL" for c in checks),
        "native_event_types": dict(Counter(v.get("type") for v in events)), "transcript_completeness": result["outcome"]["transcript_completeness"],
        "source_artifacts": [{"path": str(p), "sha256": digest(p)} for p in evidence_paths],
        "not_proven": ["full rendered create-to-integration UI workflow", "real DSH concurrency4/10/100", "all model inflight requests and cost", "full raw hidden reasoning beyond native projection", "128 controlled channels/3600 seconds", "complete product Gate qualification"]}
    report["status"] = "FAIL" if report["failed"] else "PASS"
    (output / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({k: report[k] for k in ("status", "assertions", "failed", "integrated_sha")}))


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    for option in ("private-env", "project", "attempt", "qualification", "output"):
        p.add_argument("--" + option, required=True)
    p.add_argument("--base-url", default="http://127.0.0.1:8787")
    run(p.parse_args())
