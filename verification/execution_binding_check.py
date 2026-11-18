#!/usr/bin/env python3
"""Real admission authority negatives with an unchanged-template guard control."""
import argparse
import copy
import json
import sys
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "benchmarks"))
from control_load import Client


def run(args):
    output = Path(args.output).resolve()
    output.mkdir(parents=True, exist_ok=True)
    private = json.loads(Path(args.private_env).read_text())
    client = Client(args.base_url, private["FORGEFLOW_OWNER_TOKEN"], output)
    project = json.loads(Path(args.smoke_cleanup).read_text())["snapshot"]["project"]["project_id"]
    def snapshot():
        status, value = client.request("GET", f"/api/v1/projects/{project}/snapshot")
        if status != 200:
            raise RuntimeError("actual authority snapshot unavailable")
        return value["data"]
    before = snapshot()
    attempted = {a["task_id"] for a in before["attempts"]}
    task = next(t for t in before["tasks"] if t["task_id"] not in attempted)
    body = {"actor_id": "overwritten", "idempotency_key": "overwritten", "project_id": project,
        "task_id": task["task_id"], "task_revision": task["task_revision"], "flow_revision": task["flow_revision"],
        "policy_revision": 1, "input_digest": task["input_digest"], "worker_id": task["envelope"]["worker_id"],
        "lease_seconds": 120, "envelope": task["envelope"]}
    rows = []
    def submit(name, value, expected):
        status, response = client.request("POST", f"/api/v1/projects/{project}/admissions", value,
            {"Idempotency-Key": "a10-bound-negative-" + uuid.uuid4().hex})
        rows.append({"name": name, "expected_code": expected, "actual_code": response.get("code"),
            "http_status": status, "status": "PASS" if status >= 400 and response.get("code") == expected else "FAIL"})
    submit("unchanged_template_reaches_worker_liveness_guard", body, "WORKER_STALE")
    changes = {
        "command": lambda e: e["command"].update(args=["-c", "raise SystemExit('unauthorized override')"]),
        "base_sha": lambda e: e.update(base_sha="0" * 40),
        "model_route": lambda e: e.update(model_route_id="unapproved-model-route"),
        "executor_profile": lambda e: e.update(executor_profile_id="unapproved-executor"),
        "verification_plan": lambda e: e.update(verification_plan_id="unapproved-plan"),
        "prompt_hash": lambda e: e["prompt_artifact"].update(sha256="0" * 64),
        "context_hash": lambda e: e["context_manifest"].update(sha256="0" * 64),
        "deadline": lambda e: e.update(deadline_at="2099-01-01T00:00:00Z"),
        "model_request_budget": lambda e: e.update(max_model_requests=5),
        "workspace": lambda e: e.update(workspace_root="/tmp/unapproved-authority.git"),
    }
    for name, mutate in changes.items():
        request = copy.deepcopy(body)
        mutate(request["envelope"])
        submit(name, request, "CONTEXT_STALE")
    after = snapshot()
    conserved = all(before[k] == after[k] for k in ("attempts", "leases", "allocations"))
    rows.append({"name": "all_negatives_create_zero_attempt_lease_allocation_mutations", "status": "PASS" if conserved else "FAIL"})
    report = {"scope": "Actual PostgreSQL/API frozen execution template authority; unchanged guard control and10 altered authority fields",
        "source_revision": args.source_revision, "project_id": project, "task_id": task["task_id"],
        "assertions": len(rows), "failed": sum(r["status"] == "FAIL" for r in rows), "checks": rows,
        "not_proven": ["fresh Worker association and lost claim ACK races", "full G05 or G11", "128 channel capacity"],
        "http_requests": client.count}
    report["status"] = "FAIL" if report["failed"] else "PASS"
    (output / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({k: report[k] for k in ("status", "assertions", "failed")}))


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    for name in ("private-env", "smoke-cleanup", "source-revision", "output"):
        p.add_argument("--" + name, required=True)
    p.add_argument("--base-url", default="http://127.0.0.1:8788")
    run(p.parse_args())
