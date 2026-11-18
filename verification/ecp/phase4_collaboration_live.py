#!/usr/bin/env python3
"""Disposable HTTP/PostgreSQL checks for ECP Phase 4 collaboration."""
from __future__ import annotations

import argparse
import json
import pathlib
import secrets
import sys
import uuid

import psycopg

ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "verification"))
from accounts_network_check import PG, request  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=pathlib.Path, required=True)
    args = parser.parse_args()
    output = args.output.resolve()
    run = json.loads((output / "private.json").read_text())
    checks: list[dict[str, object]] = []

    def verify(name: str, condition: bool) -> None:
        checks.append({"name": name, "passed": bool(condition)})
        if not condition:
            raise AssertionError(name)

    def call(route: str, body: dict | None, user: dict, workspace: str | None = None, expected: int = 200, key: str | None = None):
        code, value, _headers = request(run, route, body, token=user.get("token"), workspace=workspace, key=key or ("ecp4-" + secrets.token_hex(12)))
        if code != expected:
            checks.append({"name": f"{route} HTTP {expected} (actual {code})", "passed": False})
            raise AssertionError(f"{route} returned {code}: {value}")
        verify(f"{route} HTTP {expected} (actual {code})", True)
        return value.get("data", value)

    report = {"schema_version": "forgeflow.ecp-phase4-live.v1", "scope": "ECP_PHASE4_DISPOSABLE_LIVE", "product_gate_effect": "NONE", "qualification": "NOT_RUN", "status": "RUNNING", "model_calls": 0, "checks": checks}
    try:
        users = []
        for label in ("alice", "bob"):
            password = secrets.token_hex(16)
            email = f"ecp4-{label}-{secrets.token_hex(4)}@example.test"
            code, value, _ = request(run, "/registrations", {"email": email, "display_name": label, "password": password}, key="ecp4-registration-" + label + secrets.token_hex(4))
            verify(f"{label} registration", code == 200 and "token" in value.get("data", value))
            data = value.get("data", value)
            users.append({"token": data["token"], "email": email, "account_id": data["account"]["account_id"]})
        alice, bob = users
        workspace = call("/workspaces", {"name": "ECP Phase 4 disposable"}, alice, key="ecp4-workspace-" + secrets.token_hex(8))["workspace_id"]
        invite = call(f"/workspaces/{workspace}/invitations", {"role": "EDITOR", "email": bob["email"]}, alice, workspace=workspace, key="ecp4-invite-" + secrets.token_hex(8))
        call("/invitations/accept", {"token": invite["invite_token"]}, bob, key="ecp4-accept-" + secrets.token_hex(8))

        parent_id = str(uuid.uuid4())
        parent_key = "ecp4-assignment-parent-" + secrets.token_hex(5)
        parent = {"assignment_id": parent_id, "assignee_principal_id": f"human:{bob['account_id']}", "action_set": ["task.propose", "review.submit"], "project_set": [], "write_set": ["src/a"], "executor_set": [], "budget": {"tokens": 10}, "request_key": parent_key}
        created = call(f"/workspaces/{workspace}/assignments", parent, alice, workspace=workspace, key=parent_key)
        replayed = call(f"/workspaces/{workspace}/assignments", parent, alice, workspace=workspace, key=parent_key)
        verify("assignment retry is idempotent", created["assignment_id"] == replayed["assignment_id"] and replayed["replayed"])

        child = {"assignment_id": str(uuid.uuid4()), "parent_assignment_id": parent_id, "assignee_principal_id": f"human:{bob['account_id']}", "action_set": ["task.propose"], "project_set": [], "write_set": ["src/a"], "executor_set": [], "budget": {"tokens": 5}, "request_key": "ecp4-assignment-child-" + secrets.token_hex(5)}
        call(f"/workspaces/{workspace}/assignments", child, alice, workspace=workspace, key=child["request_key"])
        denied = dict(child); denied["assignment_id"] = str(uuid.uuid4()); denied["write_set"] = ["src/b"]; denied["request_key"] = "ecp4-assignment-denied-" + secrets.token_hex(5)
        call(f"/workspaces/{workspace}/assignments", denied, alice, workspace=workspace, expected=409, key=denied["request_key"])

        accept_key = "ecp4-accept-assignment-" + secrets.token_hex(5)
        accepted = call(f"/workspaces/{workspace}/assignments/{parent_id}/accept", {"expected_revision": 1, "request_key": accept_key}, bob, workspace=workspace, key=accept_key)
        verify("assignment acceptance advances revision", accepted["status"] == "ACCEPTED" and accepted["revision"] == 2)

        proposal = {"proposal_id": str(uuid.uuid4()), "assignment_id": parent_id, "base_revision": 2, "payload": {"change": "review src/a"}, "write_set": ["src/a"], "budget": {"tokens": 5}, "status": "SUBMITTED", "request_key": "ecp4-proposal-" + secrets.token_hex(6)}
        proposal_value = call(f"/workspaces/{workspace}/assignments/{parent_id}/proposals", proposal, bob, workspace=workspace, key=proposal["request_key"])
        review = {"review_id": str(uuid.uuid4()), "proposal_id": proposal["proposal_id"], "decision": "APPROVE", "expected_revision": proposal_value["revision"], "evidence": {"checks": ["scope"]}, "request_key": "ecp4-review-" + secrets.token_hex(6)}
        call(f"/workspaces/{workspace}/proposals/{proposal['proposal_id']}/reviews", review, alice, workspace=workspace, key=review["request_key"])
        decision = {"decision_id": str(uuid.uuid4()), "proposal_id": proposal["proposal_id"], "outcome": "APPROVE", "expected_revision": proposal_value["revision"], "reason": "independent disposable review", "evidence": {"review_id": review["review_id"]}, "request_key": "ecp4-decision-" + secrets.token_hex(6)}
        decided = call(f"/workspaces/{workspace}/proposals/{proposal['proposal_id']}/decisions", decision, alice, workspace=workspace, key=decision["request_key"])
        again = call(f"/workspaces/{workspace}/proposals/{proposal['proposal_id']}/decisions", decision, alice, workspace=workspace, key=decision["request_key"])
        verify("decision retry is idempotent", decided["decision_id"] == again["decision_id"] and again["replayed"])
        conflict = dict(decision); conflict["decision_id"] = str(uuid.uuid4()); conflict["request_key"] = "ecp4-decision-conflict-" + secrets.token_hex(5)
        call(f"/workspaces/{workspace}/proposals/{proposal['proposal_id']}/decisions", conflict, alice, workspace=workspace, expected=409, key=conflict["request_key"])

        escalation = {"escalation_id": str(uuid.uuid4()), "reason_code": "REVIEW_BLOCKED", "details": {"source": "disposable-live"}, "request_key": "ecp4-escalation-" + secrets.token_hex(6)}
        call(f"/workspaces/{workspace}/assignments/{parent_id}/escalations", escalation, bob, workspace=workspace, key=escalation["request_key"])
        with psycopg.connect(PG + " dbname=" + run["database"]) as db:
            rows = db.execute("SELECT kind FROM ecp_collaboration_outbox WHERE workspace_id=%s ORDER BY created_at, outbox_id", (workspace,)).fetchall()
        kinds = {row[0] for row in rows}
        for kind in ("ASSIGNMENT_CREATED", "ASSIGNMENT_ACCEPTED", "PROPOSAL_CREATED", "REVIEW_RECORDED", "DECISION_RECORDED", "ESCALATION_RAISED"):
            verify(f"outbox contains {kind}", kind in kinds)
        report["outbox_kinds"] = sorted(kinds); report["workspace_id"] = workspace; report["status"] = "PASS"
    except Exception as exc:
        report["status"] = "FAIL"; report["error"] = f"{type(exc).__name__}: {exc}"
    report["denominator"] = {"total": len(checks), "passed": sum(bool(c["passed"]) for c in checks), "failed": sum(not bool(c["passed"]) for c in checks)}
    (output / "phase4-collaboration-live.json").write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n")
    print(json.dumps(report, ensure_ascii=False))
    return 0 if report["status"] == "PASS" else 10


if __name__ == "__main__":
    raise SystemExit(main())
