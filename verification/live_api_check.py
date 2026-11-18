#!/usr/bin/env python3
"""Independent real HTTP/PostgreSQL probes. Never mock a successful command."""
import argparse
import copy
import json
import sys
import subprocess
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "benchmarks"))
from control_load import Client
from algorithm_check import make_compile, vector, refresh_digest


def run(args):
    output = Path(args.output).resolve()
    output.mkdir(parents=True, exist_ok=True)
    private = json.loads(Path(args.private_env).read_text())
    owner = Client(args.url, private["FORGEFLOW_OWNER_TOKEN"], output)
    checks = []
    project_id = "a10-" + uuid.uuid4().hex
    fixture_root = output / "fixture-repository"
    fixture_root.mkdir()
    (fixture_root / "input.json").write_text('{"fixture":"independent"}\n')
    def git(*args):
        subprocess.run(["git", "-C", str(fixture_root), "-c", "core.hooksPath=/dev/null", "-c", "commit.gpgsign=false", *args], check=True, capture_output=True)
    git("init", "--initial-branch=main")
    git("add", "input.json")
    git("-c", "user.name=A10 verifier", "-c", "user.email=a10@localhost", "commit", "-m", "Independent API fixture")
    def check(name, success, facts):
        checks.append({"name": name, "status": "PASS" if success else "FAIL", "facts": facts})
    def request(method, path, body=None, key=None, client=owner):
        return client.request(method, path, body, {"Idempotency-Key": key or uuid.uuid4().hex})
    project = {"project_id": project_id, "name": "A10 independent API counterexamples", "root_path": str(fixture_root),
               "authority_mode": "MANAGED", "data_origin": "NATIVE", "goal": "verify real authority boundaries", "technology_stack": ["Python"],
               "timezone": "Asia/Shanghai", "paused": False, "archived": False, "revision": 0}
    status, created = request("POST", "/api/v1/projects", project, "create-" + project_id)
    check("real_postgres_project_creation", status == 200 and created.get("data", {}).get("project_id") == project_id,
          {"http_status": status, "source": created.get("source")})
    if status != 200:
        raise RuntimeError("project fixture creation failed; cannot test dependent assertions")
    status, replay = request("POST", "/api/v1/projects", project, "create-" + project_id)
    check("same_payload_key_replays_stable_operation", status == 200 and replay.get("operation_id") == created.get("operation_id") and replay.get("replayed") is True,
          {"http_status": status, "original_operation_id": created.get("operation_id"), "replay_operation_id": replay.get("operation_id")})
    mutated = {**project, "name": "changed request"}
    status, conflict = request("POST", "/api/v1/projects", mutated, "create-" + project_id)
    check("same_key_changed_payload_rejected", status == 409, {"http_status": status, "code": conflict.get("code")})
    worker_output = output / "worker-role"
    worker_output.mkdir()
    worker = Client(args.url, private["FORGEFLOW_WORKER_TOKEN"], worker_output)
    status, rejection = request("POST", "/api/v1/projects", {**project, "project_id": project_id + "-worker"}, client=worker)
    check("worker_role_cannot_create_project", status == 403, {"http_status": status, "code": rejection.get("code")})
    race_project = created["data"]
    def competing_edit(index):
        directory = output / f"race-{index:02d}"
        directory.mkdir()
        client = Client(args.url, private["FORGEFLOW_OWNER_TOKEN"], directory)
        body = {"project": {**race_project, "name": f"competing-name-{index}"}, "expected_revision": 1}
        return request("PATCH", "/api/v1/projects/" + project_id, body, client=client)
    with ThreadPoolExecutor(max_workers=16) as pool:
        races = list(pool.map(competing_edit, range(16)))
    check("16_concurrent_revision_cas_one_winner", sum(status == 200 for status, _ in races) == 1 and sum(status == 409 for status, _ in races) == 15,
          {"attempted": 16, "accepted": sum(s == 200 for s, _ in races), "conflicts": sum(s == 409 for s, _ in races), "statuses": [s for s, _ in races]})
    status, after_race = request("GET", "/api/v1/projects/" + project_id)
    check("revision_after_race_is_two", status == 200 and after_race["data"]["revision"] == 2, {"revision": after_race.get("data", {}).get("revision")})
    request("POST", f"/api/v1/projects/{project_id}/teams", {"project_id": project_id, "team_id": "team", "parent_team_id": None, "name": "verification", "paused": False, "revision": 0})
    request("POST", f"/api/v1/projects/{project_id}/requirements", {"project_id": project_id, "requirement_id": "R01", "title": "independent fixture", "source_anchor": "input.json#R01", "outcome": "verified finite result", "scope": "outputs/", "acceptance": ["real independent result"], "priority": 1, "weight": 1, "deferred_reason": None, "revision": 0})
    case = make_compile(1)
    case["flow"]["project_id"] = project_id
    case["flow"]["tasks"][0]["project_id"] = project_id
    # Existing organization identity avoids mistaking an unrelated FK rejection
    # for authoritative territory/input checks.
    case["flow"]["tasks"][0]["owner_id"] = "team"
    case["context"]["owners"][0]["owner_id"] = "team"
    refresh_digest(case["flow"]["tasks"][0], case["context"]["task_specs"]["t00000"])
    forged_committed = copy.deepcopy(case["flow"])
    forged_committed["state"] = "COMMITTED"
    forged_committed["approved_by"] = "forged-actor"
    status, rejection = request("POST", f"/api/v1/projects/{project_id}/flow-revisions", {"flow": forged_committed, "context": case["context"]})
    check("http_generic_flow_cannot_grant_committed", status >= 400, {"http_status": status, "code": rejection.get("code")})
    status, saved = request("POST", f"/api/v1/projects/{project_id}/flow-revisions", {"flow": case["flow"], "context": case["context"]})
    # Compiler authority facts are intentionally hostile: no persisted owner o,
    # current_inputs claims all-a hash although actual input bytes differ.
    if status == 200:
        revision = saved["data"]["revision"]
        status, commit = request("POST", f"/api/v1/flows/{project_id}:1/commit", {"expected_revision": revision})
        check("self_asserted_owner_and_input_context_cannot_commit", status >= 400,
              {"http_status": status, "code": commit.get("code"), "counterexample": "no authoritative owner territory and fake current_inputs a*64 conflict with real fixture bytes"})
    else:
        semantic_rejection = saved.get("code") in {"INPUT_HASH_DRIFT", "CONTEXT_UNTRUSTED", "OWNER_TERRITORY", "OWNER_UNREGISTERED"}
        check("self_asserted_owner_and_input_context_cannot_commit", semantic_rejection, {"rejected_before_commit": True, "http_status": status, "code": saved.get("code")})
        if not semantic_rejection:
            checks[-1]["status"] = "INCONCLUSIVE"
    status, snapshot = request("GET", f"/api/v1/projects/{project_id}/attempts")
    check("planning_calls_created_no_running_attempt", status == 200 and snapshot.get("data") == [], {"http_status": status, "attempt_count": len(snapshot.get("data", []))})
    report = {"scope": "real authenticated API and PostgreSQL independent counterexamples", "url": args.url,
              "source_revision": args.source_revision, "project_id": project_id, "checks": checks,
              "attempted_assertions": len(checks), "failed": sum(c["status"] == "FAIL" for c in checks), "skipped": 0,
              "status": "FAIL" if any(c["status"] == "FAIL" for c in checks) else "INCONCLUSIVE" if any(c["status"] == "INCONCLUSIVE" for c in checks) else "PASS", "gate_status": "INCONCLUSIVE",
              "not_proven": ["DSH full chain", "admission races and actual process fencing", "restart persistence", "full G01/G03/G05"]}
    (output / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({k: report[k] for k in ("status", "attempted_assertions", "failed", "project_id", "gate_status")}))


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", required=True)
    parser.add_argument("--private-env", required=True)
    parser.add_argument("--source-revision", required=True)
    parser.add_argument("--output", required=True)
    run(parser.parse_args())
