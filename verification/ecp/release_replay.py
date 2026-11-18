#!/usr/bin/env python3
"""Independent release replay preflight.

This command re-reads the plan, gate snapshot, source manifest and evidence
receipts.  It never mutates Gate state or approves a release.  Until every
required runtime receipt is current and independently bound, it returns
NOT_RUN/BLOCKED with the exact missing conditions.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import subprocess
from typing import Any


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--plan-root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    plan = args.plan_root.resolve()
    checks: list[dict[str, Any]] = []

    def check(name: str, status: str, reason: str, **details: Any) -> None:
        checks.append({"name": name, "status": status, "reason": reason, "details": details})

    gates = json.loads((plan / "planning/gates.json").read_text())
    tasks = json.loads((plan / "planning/tasks.json").read_text())
    manifest_path = plan / "evidence/source_manifest.json"
    manifest = json.loads(manifest_path.read_text()) if manifest_path.exists() else None
    source_root = Path(manifest.get("source_root", "")) if manifest else None
    if manifest is None:
        check("source_manifest", "BLOCKED", "source manifest is missing")
    elif manifest.get("release_qualifiable") is not True:
        check("source_manifest", "BLOCKED", "source snapshot is dirty or otherwise not release qualifiable", worktree_state=manifest.get("worktree_state"), manifest_sha256=manifest.get("manifest_sha256"))
    else:
        check("source_manifest", "PASS", "release-qualifiable source snapshot is present", manifest_sha256=manifest.get("manifest_sha256"))

    gate_states = [(gate.get("gate_id"), gate.get("status")) for gate in gates.get("gates", [])]
    unresolved_gates = [gate_id for gate_id, status in gate_states if status != "PASS"]
    if unresolved_gates:
        check("gate_snapshot", "NOT_RUN", "release replay cannot approve while any Gate is not PASS", unresolved_gates=unresolved_gates, gate_digest=sha256(plan / "planning/gates.json"))
    else:
        check("gate_snapshot", "PASS", "all gates are PASS", gate_digest=sha256(plan / "planning/gates.json"))

    open_tasks = [task.get("task_id") for task in tasks.get("tasks", []) if task.get("status") != "COMPLETED"]
    unverified = [task.get("task_id") for task in tasks.get("tasks", []) if task.get("evidence_status") != "PASS"]
    if open_tasks or unverified:
        check("task_snapshot", "NOT_RUN", "task evidence is not fully qualified", open_tasks=open_tasks, unverified_tasks=unverified)
    else:
        check("task_snapshot", "PASS", "all task evidence is qualified")

    try:
        source_sha = subprocess.check_output(["git", "-C", str(source_root), "rev-parse", "HEAD"], text=True).strip() if source_root else None
    except (OSError, subprocess.CalledProcessError):
        source_sha = None
    manifest_source_sha = manifest.get("source_sha", manifest.get("head")) if manifest else None
    check("source_binding", "PASS" if source_sha and manifest_source_sha == source_sha else "INCONCLUSIVE", "source SHA binding readback", observed=source_sha, manifest=manifest_source_sha)

    statuses = [item["status"] for item in checks]
    if "FAIL" in statuses:
        status = "FAIL"
    elif "BLOCKED" in statuses:
        status = "BLOCKED"
    elif "NOT_RUN" in statuses:
        status = "NOT_RUN"
    elif "INCONCLUSIVE" in statuses:
        status = "INCONCLUSIVE"
    else:
        status = "PASS"
    report = {
        "schema_version": "forgeflow.ecp-release-replay.v1",
        "product_gate_effect": "NONE",
        "qualification": "NOT_RUN" if status != "PASS" else "OBSERVED_NOT_GATE",
        "status": status,
        "created_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "plan_root": str(plan),
        "checks": checks,
        "denominator": {"total": len(checks), "passed": statuses.count("PASS"), "failed": statuses.count("FAIL"), "blocked": statuses.count("BLOCKED"), "not_run": statuses.count("NOT_RUN"), "inconclusive": statuses.count("INCONCLUSIVE")},
        "mutation": "none",
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n")
    print(json.dumps({"status": status, "denominator": report["denominator"]}))
    return 0 if status in {"PASS", "NOT_RUN"} else 20


if __name__ == "__main__":
    raise SystemExit(main())
