"""Independent, deliberately simple reference algorithms; no production imports.

Normalized inputs are verification DTOs, not claims about production schemas.
Adapters must retain raw responses and state their JSON-pointer mapping.
"""
from __future__ import annotations

from collections import defaultdict

TERMINAL = {"SUCCEEDED", "FAILED", "CANCELLED"}
STATES = {"LEASED", "STARTING", "RUNNING", "VERIFYING", "REVIEW_READY",
          "MERGE_QUEUED", "MERGING", "STOPPING", "RECOVERY_REQUIRED"} | TERMINAL
NEXT = {
    "LEASED": {"STARTING", "CANCELLED"},
    "STARTING": {"RUNNING", "FAILED", "RECOVERY_REQUIRED"},
    "RUNNING": {"VERIFYING", "STOPPING", "FAILED"},
    "VERIFYING": {"REVIEW_READY", "FAILED", "STOPPING"},
    "REVIEW_READY": {"MERGE_QUEUED", "FAILED"},
    "MERGE_QUEUED": {"MERGING", "STOPPING"},
    "MERGING": {"SUCCEEDED", "FAILED", "RECOVERY_REQUIRED"},
    "STOPPING": {"CANCELLED", "RECOVERY_REQUIRED"},
    "RECOVERY_REQUIRED": {"CANCELLED", "FAILED"},
    "SUCCEEDED": set(), "FAILED": set(), "CANCELLED": set(),
}


def valid_path(path):
    return (isinstance(path, str) and bool(path) and not path.startswith("/")
            and "\\" not in path and ":" not in path and "\0" not in path
            and all(part not in {"", ".", ".."} for part in path.rstrip("/").split("/")))


def covers(scope, path):
    if not valid_path(scope) or not valid_path(path):
        return False
    return scope == path or (scope.endswith("/") and path.startswith(scope))


def overlap(a, b):
    return covers(a, b) or covers(b, a)


def dag_order(tasks):
    """Kahn algorithm: intentionally distinct from typical recursive DFS."""
    ids = [t["task_id"] for t in tasks]
    if len(ids) != len(set(ids)):
        raise ValueError("duplicate_task_id")
    pending = {t["task_id"]: set(t.get("depends_on", [])) for t in tasks}
    if any(not deps <= set(ids) for deps in pending.values()):
        raise ValueError("missing_dependency")
    ordered = []
    while pending:
        ready = sorted(k for k, v in pending.items() if not v)
        if not ready:
            raise ValueError("dependency_cycle")
        ordered.extend(ready)
        for key in ready:
            del pending[key]
        for deps in pending.values():
            deps.difference_update(ready)
    return ordered


def ancestors(owner_id, owners):
    result = []
    while owner_id is not None:
        if owner_id in result or owner_id not in owners:
            raise ValueError("invalid_owner_hierarchy")
        result.append(owner_id)
        owner_id = owners[owner_id].get("parent_id")
    return result


def ready(tasks, accepted):
    dag_order(tasks)
    return sorted(t["task_id"] for t in tasks
                  if t["task_id"] not in accepted
                  and set(t.get("depends_on", [])) <= set(accepted))


def admissible(task, owners, allocations, global_limit):
    """Count every unreleased allocation, including stopped/quarantined attempts."""
    chain = ancestors(task["owner_id"], owners)
    demand = task.get("resources", {})
    occupied = [a for a in allocations if not a.get("released", False)]
    limits = [(None, global_limit)] + [(o, owners[o]["limits"]) for o in chain]
    for owner, limit in limits:
        for resource, amount in demand.items():
            used = sum(a.get("resources", {}).get(resource, 0) for a in occupied
                       if owner is None or (a["project_id"] == task["project_id"]
                                            and owner in ancestors(a["owner_id"], owners)))
            if amount < 0 or used + amount > limit.get(resource, 0):
                return False
    for allocation in occupied:
        if allocation.get("project_id") == task["project_id"]:
            if any(overlap(a, b) for a in task.get("write_set", [])
                   for b in allocation.get("write_set", [])):
                return False
    return True


def assert_snapshot(snapshot):
    """Return all independent counterexamples rather than stopping at one."""
    violations = []
    attempts = snapshot["attempts"]
    leases = snapshot["leases"]
    allocations = snapshot["allocations"]
    indexed = {a["attempt_id"]: a for a in attempts}
    if len(indexed) != len(attempts):
        violations.append("duplicate_attempt")
    valid_by_task = defaultdict(list)
    for lease in leases:
        attempt = indexed.get(lease["attempt_id"])
        if attempt is None:
            violations.append("orphan_lease")
            continue
        valid = (not lease.get("revoked", False)
                 and lease["expires_at"] > snapshot["as_of_epoch"])
        if valid:
            valid_by_task[(attempt.get("project_id", lease.get("project_id", "")), attempt["task_id"])].append(lease)
            if attempt["generation"] != lease["generation"]:
                violations.append("lease_generation_mismatch")
            if attempt["state"] in TERMINAL | {"STOPPING", "RECOVERY_REQUIRED"}:
                violations.append("invalid_state_has_write_authority")
    if any(len(v) > 1 for v in valid_by_task.values()):
        violations.append("duplicate_valid_lease")
    held = [a for a in allocations if not a.get("released", False)]
    for allocation in held:
        attempt = indexed.get(allocation["attempt_id"])
        if not attempt:
            violations.append("orphan_allocation")
        elif attempt["state"] in TERMINAL:
            violations.append("terminal_allocation_unreleased")
    for attempt in attempts:
        if attempt["state"] not in STATES:
            violations.append("unknown_attempt_state")
        elif attempt["state"] not in TERMINAL:
            if not any(a["attempt_id"] == attempt["attempt_id"] for a in held):
                violations.append("active_attempt_unaccounted")
    owners = snapshot["owners"]
    for owner, limits in [(None, snapshot["global_limits"])] + [
            (key, value["limits"]) for key, value in owners.items()]:
        for resource, limit in limits.items():
            used = sum(a.get("resources", {}).get(resource, 0) for a in held
                       if owner is None or ((owners[owner].get("project_id") is None
                                             or owners[owner]["project_id"] == a["project_id"])
                                            and owner in ancestors(a["owner_id"], owners)))
            # A lowered limit is allowed to drain only when explicitly evidenced.
            if used > limit and not snapshot.get("draining_limits", {}).get(owner or "global", {}).get(resource):
                violations.append(f"resource_overflow:{owner}:{resource}")
    for n, left in enumerate(held):
        for right in held[n + 1:]:
            if left["attempt_id"] != right["attempt_id"] and left["project_id"] == right["project_id"]:
                if any(overlap(a, b) for a in left.get("write_set", []) for b in right.get("write_set", [])):
                    violations.append("concurrent_write_overlap")
    return sorted(set(violations))


def receipt_errors(receipt, expected):
    errors = []
    for field in ("attempt_id", "generation", "input_hash", "candidate_sha", "verification_plan_hash"):
        if receipt.get(field) != expected.get(field):
            errors.append("identity_mismatch:" + field)
    if receipt.get("assertions_passed", 0) < 1:
        errors.append("zero_assertions")
    if receipt.get("assertions_failed", 0) or receipt.get("assertions_skipped", 0):
        errors.append("failed_or_skipped_assertions")
    if not receipt.get("artifacts"):
        errors.append("missing_artifact")
    if receipt.get("author_id") == receipt.get("verifier_id"):
        errors.append("not_independent")
    if expected.get("execution_kind") == "CODING" and not receipt.get("integrated_sha"):
        errors.append("missing_integration")
    return errors
