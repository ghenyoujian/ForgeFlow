#!/usr/bin/env python3
"""Generate controlled valid/broken snapshots and exercise the independent oracle."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import subprocess
from typing import Any

from independent_oracles import evaluate


def valid_snapshot() -> dict[str, Any]:
    return {
        "attempts": [{"project_id": "p", "task_id": "t", "attempt_id": "a", "state": "RUNNING", "terminal_at": None}],
        "limits": [{"scope_id": "s", "dimension": "active_slot", "hard_limit": 2}],
        "allocations": [{"scope_id": "s", "dimension": "active_slot", "amount": 1, "state": "HELD"}],
        "write_sets": [{"project_id": "p", "attempt_id": "a", "state": "RUNNING", "paths": ["src/a.rs"]}, {"project_id": "p", "attempt_id": "b", "state": "DONE", "paths": ["src/a.rs"]}],
        "tasks": [{"task_id": "t", "state": "READY", "flow_committed": True, "dependencies_ready": True, "contract_ok": True, "project_paused": False}],
        "events": [{"event_id": "e", "attempt_id": "a", "generation": 1, "lease_id": "l", "worker_id": "w", "fence_epoch": 1, "accepted": True}],
        "current_identities": {"a": {"attempt_id": "a", "generation": 1, "lease_id": "l", "worker_id": "w", "fence_epoch": 1}},
        "event_effects": [{"event_id": "e", "payload_digest": "same"}],
        "blocked_tasks": [{"task_id": "b", "blocked_reason": "CAPACITY"}],
        "failure_mutations": [{"failure_project_id": "p", "failure_task_id": "t", "mutation_project_id": "p", "mutation_task_id": "t", "deleted_evidence_count": 0}],
        "scoped_reads": [{"requested_workspace_id": "w", "row_workspace_id": "w"}],
        "grants": [{"grant_id": "g", "revoked_at": "2026-01-01T00:00:00Z", "active_after_revoke": False}],
        "delegations": [{"delegation_id": "d", "parent_capabilities": ["read", "write"], "child_capabilities": ["read"]}],
        "receipts": [{"receipt_state": "ACK", "business_state": "PROCESSING", "decision_id": None}],
        "revisions": [{"aggregate_id": "m", "revision": 1}, {"aggregate_id": "m", "revision": 2}],
        "idempotency_records": [{"scope": "p", "key": "k", "payload_digest": "x"}, {"scope": "p", "key": "k", "payload_digest": "x"}],
        "cost_settlements": [{"usage_state": "UNKNOWN", "budget_released": False}],
        "restored_authority": [{"old_generation_accepted": False}],
    }


def broken_snapshot() -> dict[str, Any]:
    value = valid_snapshot()
    value["attempts"].append({"project_id": "p", "task_id": "t", "attempt_id": "a2", "state": "RUNNING", "terminal_at": None})
    value["allocations"][0]["amount"] = 3
    value["write_sets"][1]["state"] = "RUNNING"
    value["write_sets"][1]["paths"] = ["src/a.rs"]
    value["events"][0]["generation"] = 0
    value["event_effects"].append({"event_id": "e", "payload_digest": "different"})
    value["blocked_tasks"][0]["blocked_reason"] = "not-a-reason"
    value["delegations"][0]["child_capabilities"] = ["admin"]
    value["cost_settlements"][0]["budget_released"] = True
    value["restored_authority"][0]["old_generation_accepted"] = True
    return value


def main() -> int:
    parser = argparse.ArgumentParser(); parser.add_argument("--output", type=Path, required=True); parser.add_argument("--run", action="store_true"); args = parser.parse_args()
    source_root = Path(__file__).resolve().parents[2]
    try:
        source_sha = subprocess.check_output(["git", "-C", str(source_root), "rev-parse", "HEAD"], text=True).strip()
    except (OSError, subprocess.CalledProcessError):
        source_sha = None
    report = {"schema_version": "forgeflow.ecp-invariant-campaign.v1", "product_gate_effect": "NONE", "qualification": "NOT_RUN", "status": "NOT_RUN", "model_calls": 0, "source_root": str(source_root), "source_sha": source_sha, "cases": []}
    if not args.run:
        report["reason"] = "invariant campaign requires explicit --run"
    else:
        good = evaluate(valid_snapshot()); bad = evaluate(broken_snapshot())
        identified = bad["status"] == "FAIL" and bad["denominator"]["failed"] >= 1
        report.update({"status": "PASS" if good["status"] == "PASS" and identified else "FAIL", "qualification": "OBSERVED_NOT_GATE" if good["status"] == "PASS" and identified else "NOT_RUN", "cases": [{"name": "valid_snapshot", "expected": "PASS", "report": good}, {"name": "deliberately_broken_snapshot", "expected": "FAIL", "report": bad}], "denominator": {"cases": 2, "passed_expectations": int(good["status"] == "PASS") + int(identified), "failed_expectations": int(good["status"] != "PASS") + int(not identified)}})
    args.output.parent.mkdir(parents=True, exist_ok=True); args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"); print(json.dumps({"status": report["status"], "cases": len(report.get("cases", []))}))
    return 0 if report["status"] in {"PASS", "NOT_RUN"} else 20


if __name__ == "__main__":
    raise SystemExit(main())
