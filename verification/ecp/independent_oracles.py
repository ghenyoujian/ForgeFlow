#!/usr/bin/env python3
"""Independent, read-only checks for the ECP I01-I08/E01-E08 contracts.

The oracle consumes a JSON snapshot produced by a verifier or a database
export.  It deliberately does not import Store implementation code, mutate
the database, or infer missing sections as success.  Missing sections remain
NOT_RUN; a deliberately malformed snapshot must produce FAIL for the violated
invariant.
"""
from __future__ import annotations

import argparse
from collections import defaultdict
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
from typing import Any, Callable

STATUSES = {"PASS", "FAIL", "NOT_RUN", "BLOCKED", "INCONCLUSIVE"}
ACTIVE_STATES = {"HELD", "RUNNING", "STARTING", "STOPPING", "OPEN", "ACTIVE"}


def now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def digest(value: Any) -> str:
    return hashlib.sha256(json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def result(invariant: str, status: str, reason: str, denominator: int = 0, **details: Any) -> dict[str, Any]:
    if status not in STATUSES:
        raise ValueError(status)
    return {"invariant": invariant, "status": status, "reason": reason, "denominator": denominator, "details": details}


def pairs(values: list[dict[str, Any]], key: Callable[[dict[str, Any]], Any]):
    grouped: dict[Any, list[dict[str, Any]]] = defaultdict(list)
    for value in values:
        grouped[key(value)].append(value)
    return grouped


def active(row: dict[str, Any]) -> bool:
    return row.get("terminal_at") is None and row.get("state", "OPEN") in ACTIVE_STATES


def canonical_path(value: str) -> str:
    value = value.strip().replace("\\", "/")
    while "//" in value:
        value = value.replace("//", "/")
    return value.rstrip("/") or "/"


def path_overlap(left: str, right: str) -> bool:
    left, right = canonical_path(left), canonical_path(right)
    return left == right or left.startswith(right + "/") or right.startswith(left + "/")


def check_i01(data: dict[str, Any]) -> dict[str, Any]:
    rows = data.get("attempts")
    if not isinstance(rows, list): return result("I01", "NOT_RUN", "attempt snapshot is missing")
    grouped = pairs([r for r in rows if isinstance(r, dict) and active(r)], lambda r: (r.get("project_id"), r.get("task_id")))
    violations = {str(k): len(v) for k, v in grouped.items() if k[0] and k[1] and len(v) > 1}
    return result("I01", "FAIL" if violations else "PASS", "at most one open attempt per task" if not violations else "multiple open attempts share one task", len(rows), violations=violations)


def check_i02(data: dict[str, Any]) -> dict[str, Any]:
    limits, allocations = data.get("limits"), data.get("allocations")
    if not isinstance(limits, list) or not isinstance(allocations, list): return result("I02", "NOT_RUN", "limits or allocations snapshot is missing")
    hard = {(r.get("scope_id"), r.get("dimension")): int(r.get("hard_limit", 0)) for r in limits if isinstance(r, dict)}
    used: dict[tuple[Any, Any], int] = defaultdict(int)
    for row in allocations:
        if isinstance(row, dict) and row.get("state", "HELD") in ACTIVE_STATES:
            used[(row.get("scope_id"), row.get("dimension"))] += int(row.get("amount", 0))
    violations = {str(k): {"allocated": v, "hard_limit": hard.get(k)} for k, v in used.items() if k in hard and v > hard[k]}
    return result("I02", "FAIL" if violations else "PASS", "active resource allocations stay within hard limits" if not violations else "resource allocation exceeds hard limit", len(allocations), violations=violations)


def check_i03(data: dict[str, Any]) -> dict[str, Any]:
    rows = data.get("write_sets")
    if not isinstance(rows, list): return result("I03", "NOT_RUN", "write-set snapshot is missing")
    conflicts = []
    for index, left in enumerate(rows):
        if not isinstance(left, dict) or left.get("state") not in ACTIVE_STATES: continue
        for right in rows[index + 1 :]:
            if not isinstance(right, dict) or right.get("state") not in ACTIVE_STATES or left.get("project_id") != right.get("project_id"): continue
            for lpath in left.get("paths", []):
                for rpath in right.get("paths", []):
                    if path_overlap(str(lpath), str(rpath)):
                        conflicts.append({"left": left.get("attempt_id"), "right": right.get("attempt_id"), "left_path": lpath, "right_path": rpath})
    return result("I03", "FAIL" if conflicts else "PASS", "active write sets do not overlap" if not conflicts else "active write sets overlap", len(rows), conflicts=conflicts)


def check_i04(data: dict[str, Any]) -> dict[str, Any]:
    rows = data.get("tasks")
    if not isinstance(rows, list): return result("I04", "NOT_RUN", "task readiness snapshot is missing")
    allowed = {"READY", "BLOCKED", "WAITING", "DONE", "CANCELLED"}
    violations = []
    for row in rows:
        if not isinstance(row, dict) or row.get("state") not in allowed: continue
        ready_conditions = bool(row.get("flow_committed")) and bool(row.get("dependencies_ready")) and bool(row.get("contract_ok")) and not bool(row.get("project_paused"))
        if row.get("state") == "READY" and not ready_conditions:
            violations.append({"task_id": row.get("task_id"), "conditions": {k: row.get(k) for k in ("flow_committed", "dependencies_ready", "contract_ok", "project_paused")}})
    return result("I04", "FAIL" if violations else "PASS", "READY tasks satisfy flow, dependency, contract and pause preconditions" if not violations else "READY task misses a prerequisite", len(rows), violations=violations)


def check_i05(data: dict[str, Any]) -> dict[str, Any]:
    events, current = data.get("events"), data.get("current_identities")
    if not isinstance(events, list) or not isinstance(current, dict): return result("I05", "NOT_RUN", "event identity snapshot is missing")
    violations = []
    fields = ("attempt_id", "generation", "lease_id", "worker_id", "fence_epoch")
    for event in events:
        if not isinstance(event, dict): continue
        expected = current.get(str(event.get("attempt_id")))
        identity = {field: event.get(field) for field in fields}
        if event.get("accepted") is True and (not isinstance(expected, dict) or any(identity.get(field) != expected.get(field) for field in fields)):
            violations.append({"event_id": event.get("event_id"), "identity": identity, "expected": expected})
    return result("I05", "FAIL" if violations else "PASS", "accepted events match current fencing identity" if not violations else "stale identity was accepted", len(events), violations=violations)


def check_i06(data: dict[str, Any]) -> dict[str, Any]:
    rows = data.get("event_effects")
    if not isinstance(rows, list): return result("I06", "NOT_RUN", "event effect snapshot is missing")
    grouped = pairs([r for r in rows if isinstance(r, dict)], lambda r: r.get("event_id"))
    violations = []
    for event_id, effects in grouped.items():
        if not event_id: continue
        hashes = {r.get("payload_digest") or digest(r.get("payload")) for r in effects}
        if len(effects) > 1 or len(hashes) > 1:
            violations.append({"event_id": event_id, "effect_count": len(effects), "payload_digests": sorted(hashes)})
    return result("I06", "FAIL" if violations else "PASS", "duplicate events have one idempotent effect" if not violations else "duplicate event caused multiple or conflicting effects", len(rows), violations=violations)


def check_i07(data: dict[str, Any]) -> dict[str, Any]:
    rows = data.get("blocked_tasks")
    if not isinstance(rows, list): return result("I07", "NOT_RUN", "blocked-reason snapshot is missing")
    allowed = {"DEPENDENCY", "CAPACITY", "CONFLICT", "CONTRACT", "PAUSED", "WORKER", "DRAINING", "AUTHORIZATION", "UNKNOWN"}
    violations = [{"task_id": r.get("task_id"), "reason": r.get("blocked_reason")} for r in rows if isinstance(r, dict) and (not r.get("blocked_reason") or r.get("blocked_reason") not in allowed)]
    return result("I07", "FAIL" if violations else "PASS", "every blocked task has an explainable reason" if not violations else "blocked task reason is missing or unknown", len(rows), violations=violations)


def check_i08(data: dict[str, Any]) -> dict[str, Any]:
    rows = data.get("failure_mutations")
    if not isinstance(rows, list): return result("I08", "NOT_RUN", "failure isolation snapshot is missing")
    violations = []
    for row in rows:
        if not isinstance(row, dict): continue
        if row.get("failure_project_id") != row.get("mutation_project_id") or row.get("failure_task_id") != row.get("mutation_task_id") or int(row.get("deleted_evidence_count", 0)) != 0:
            violations.append(row)
    return result("I08", "FAIL" if violations else "PASS", "failure mutations stay within the failed task and preserve evidence" if not violations else "failure escaped its task or deleted evidence", len(rows), violations=violations)


def check_e01(data: dict[str, Any]) -> dict[str, Any]:
    rows = data.get("scoped_reads")
    if not isinstance(rows, list): return result("E01", "NOT_RUN", "tenant-scoped read snapshot is missing")
    violations = [r for r in rows if isinstance(r, dict) and r.get("requested_workspace_id") != r.get("row_workspace_id")]
    return result("E01", "FAIL" if violations else "PASS", "reads remain within the requested workspace" if not violations else "cross-workspace row was returned", len(rows), violations=violations)


def check_e02(data: dict[str, Any]) -> dict[str, Any]:
    rows = data.get("grants")
    if not isinstance(rows, list): return result("E02", "NOT_RUN", "grant revision snapshot is missing")
    violations = []
    for row in rows:
        if isinstance(row, dict) and row.get("revoked_at") is not None and row.get("active_after_revoke") is True:
            violations.append(row)
    return result("E02", "FAIL" if violations else "PASS", "revocation is monotonic" if not violations else "revoked grant became active again", len(rows), violations=violations)


def check_e03(data: dict[str, Any]) -> dict[str, Any]:
    rows = data.get("delegations")
    if not isinstance(rows, list): return result("E03", "NOT_RUN", "delegation snapshot is missing")
    violations = []
    for row in rows:
        if not isinstance(row, dict): continue
        parent, child = set(row.get("parent_capabilities", [])), set(row.get("child_capabilities", []))
        if not child.issubset(parent): violations.append({"delegation_id": row.get("delegation_id"), "extra": sorted(child - parent)})
    return result("E03", "FAIL" if violations else "PASS", "child capabilities are subsets of parent capabilities" if not violations else "child delegation expanded authority", len(rows), violations=violations)


def check_e04(data: dict[str, Any]) -> dict[str, Any]:
    rows = data.get("receipts")
    if not isinstance(rows, list): return result("E04", "NOT_RUN", "receipt/business-state snapshot is missing")
    violations = [r for r in rows if isinstance(r, dict) and r.get("receipt_state") == "ACK" and r.get("business_state") == "DONE" and r.get("decision_id") is None]
    return result("E04", "FAIL" if violations else "PASS", "receipt acknowledgement remains separate from business completion" if not violations else "ACK was treated as business completion", len(rows), violations=violations)


def check_e05(data: dict[str, Any]) -> dict[str, Any]:
    rows = data.get("revisions")
    if not isinstance(rows, list): return result("E05", "NOT_RUN", "revision snapshot is missing")
    violations = []
    for key, values in pairs([r for r in rows if isinstance(r, dict)], lambda r: r.get("aggregate_id")).items():
        seq = [int(r.get("revision", 0)) for r in values]
        if any(right <= left for left, right in zip(seq, seq[1:])): violations.append({"aggregate_id": key, "revisions": seq})
    return result("E05", "FAIL" if violations else "PASS", "aggregate revisions are strictly increasing" if not violations else "aggregate revision regressed or duplicated", len(rows), violations=violations)


def check_e06(data: dict[str, Any]) -> dict[str, Any]:
    rows = data.get("idempotency_records")
    if not isinstance(rows, list): return result("E06", "NOT_RUN", "idempotency snapshot is missing")
    violations = []
    for key, values in pairs([r for r in rows if isinstance(r, dict)], lambda r: (r.get("scope"), r.get("key"))).items():
        digests = {r.get("payload_digest") or digest(r.get("payload")) for r in values}
        if len(digests) > 1 and not any(r.get("conflict_rejected") is True for r in values): violations.append({"key": key, "payload_digests": sorted(digests)})
    return result("E06", "FAIL" if violations else "PASS", "same idempotency key replays or rejects conflicts" if not violations else "idempotency conflict was accepted", len(rows), violations=violations)


def check_e07(data: dict[str, Any]) -> dict[str, Any]:
    rows = data.get("cost_settlements")
    if not isinstance(rows, list): return result("E07", "NOT_RUN", "cost settlement snapshot is missing")
    violations = [r for r in rows if isinstance(r, dict) and r.get("usage_state") == "UNKNOWN" and r.get("budget_released") is True]
    return result("E07", "FAIL" if violations else "PASS", "unknown usage keeps the budget held" if not violations else "unknown usage released budget", len(rows), violations=violations)


def check_e08(data: dict[str, Any]) -> dict[str, Any]:
    rows = data.get("restored_authority")
    if not isinstance(rows, list): return result("E08", "NOT_RUN", "restore authority snapshot is missing")
    violations = [r for r in rows if isinstance(r, dict) and r.get("old_generation_accepted") is True]
    return result("E08", "FAIL" if violations else "PASS", "restore does not revive old authority" if not violations else "old session or generation was revived", len(rows), violations=violations)


CHECKS = [check_i01, check_i02, check_i03, check_i04, check_i05, check_i06, check_i07, check_i08, check_e01, check_e02, check_e03, check_e04, check_e05, check_e06, check_e07, check_e08]


def evaluate(data: dict[str, Any]) -> dict[str, Any]:
    checks = [check(data) for check in CHECKS]
    statuses = [item["status"] for item in checks]
    if "FAIL" in statuses: status = "FAIL"
    elif "BLOCKED" in statuses: status = "BLOCKED"
    elif "NOT_RUN" in statuses: status = "NOT_RUN"
    elif "INCONCLUSIVE" in statuses: status = "INCONCLUSIVE"
    else: status = "PASS"
    return {"schema_version": "forgeflow.ecp-independent-oracle.v1", "product_gate_effect": "NONE", "qualification": "OBSERVED_NOT_GATE" if status == "PASS" else "NOT_RUN", "status": status, "created_at": now(), "checks": checks, "denominator": {"total": len(checks), "passed": statuses.count("PASS"), "failed": statuses.count("FAIL"), "blocked": statuses.count("BLOCKED"), "not_run": statuses.count("NOT_RUN"), "inconclusive": statuses.count("INCONCLUSIVE")}}


def main() -> int:
    parser = argparse.ArgumentParser(); parser.add_argument("--input", type=Path, required=True); parser.add_argument("--output", type=Path, required=True); args = parser.parse_args()
    data = json.loads(args.input.read_text(encoding="utf-8")); report = evaluate(data)
    args.output.parent.mkdir(parents=True, exist_ok=True); args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"); print(json.dumps({"status": report["status"], "denominator": report["denominator"]}))
    return 0 if report["status"] in {"PASS", "NOT_RUN"} else 20


if __name__ == "__main__":
    raise SystemExit(main())
