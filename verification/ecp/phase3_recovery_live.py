#!/usr/bin/env python3
"""Disposable checks for ECP cursor, delivery recovery, and revocation."""
from __future__ import annotations

import argparse, json, pathlib, secrets, sys, uuid
import psycopg

ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "verification"))
from accounts_network_check import PG, request  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(); parser.add_argument("--output", type=pathlib.Path, required=True)
    args = parser.parse_args(); output = args.output.resolve(); run = json.loads((output / "private.json").read_text())
    checks: list[dict[str, object]] = []

    def verify(name: str, passed: bool) -> None:
        checks.append({"name": name, "passed": bool(passed)})
        if not passed: raise AssertionError(name)

    def call(route: str, body: dict | None, user: dict, workspace: str | None = None, expected: int = 200, key: str | None = None):
        code, value, _ = request(run, route, body, token=user.get("token"), workspace=workspace, key=key or ("ecp3r-" + secrets.token_hex(10)))
        verify(f"{route} HTTP {expected} (actual {code})", code == expected)
        if code != expected: raise AssertionError(value)
        return value.get("data", value)

    def register(label: str) -> dict:
        email = f"ecp3r-{label}-{secrets.token_hex(4)}@example.test"; password = secrets.token_hex(16)
        data = call("/registrations", {"email": email, "display_name": label, "password": password}, {})
        return {"token": data["token"], "account_id": data["account"]["account_id"], "email": email}

    report = {"schema_version": "forgeflow.ecp-phase3-recovery-live.v1", "scope": "ECP_PHASE3_RECOVERY_DISPOSABLE_LIVE", "status": "RUNNING", "qualification": "OBSERVED_NOT_GATE", "product_gate_effect": "NONE", "model_calls": 0, "checks": checks}
    try:
        alice, bob = register("alice"), register("bob")
        workspace = call("/workspaces", {"name": "ECP Phase 3 recovery"}, alice)["workspace_id"]
        invitation = call(f"/workspaces/{workspace}/invitations", {"role": "EDITOR", "email": bob["email"]}, alice, workspace=workspace)
        call("/invitations/accept", {"token": invitation["invite_token"]}, bob)
        conversation = "conversation-" + uuid.uuid4().hex
        thread = "thread-" + uuid.uuid4().hex
        conversation_key = "conversation-create-" + uuid.uuid4().hex
        call(f"/workspaces/{workspace}/conversations", {"conversation_id": conversation, "project_id": None, "participant_principal_ids": [f"human:{bob['account_id']}"], "request_key": conversation_key}, alice, workspace=workspace, key=conversation_key)
        thread_key = "thread-create-" + uuid.uuid4().hex
        call(f"/conversations/{conversation}/threads", {"thread_id": thread, "task_id": None, "request_key": thread_key}, alice, workspace=workspace, key=thread_key)
        msg = {"thread_id": thread, "message_kind": "chat.message", "client_request_id": "recovery-message-" + uuid.uuid4().hex, "payload": {"text": "recovery"}, "correlation_id": None, "causation_id": None, "expires_at": None}
        sent = call(f"/conversations/{conversation}/messages", msg, alice, workspace=workspace, key=msg["client_request_id"])
        checkpoint_key = "checkpoint-" + uuid.uuid4().hex
        cp = {"acknowledged_sequence": sent["sequence"], "request_key": checkpoint_key}
        first = call(f"/conversations/{conversation}/checkpoint", cp, bob, workspace=workspace, key=checkpoint_key)
        replay = call(f"/conversations/{conversation}/checkpoint", cp, bob, workspace=workspace, key=checkpoint_key)
        verify("checkpoint retry returns the durable command result", first["acknowledged_sequence"] == sent["sequence"] and replay["acknowledged_sequence"] == sent["sequence"])
        listed = call(f"/conversations/{conversation}/messages?after=0&limit=10", None, bob, workspace=workspace)
        verify("message cursor read returns checkpoint", listed["checkpoint"] == sent["sequence"])
        with psycopg.connect(PG + " dbname=" + run["database"]) as db:
            delivery = db.execute("SELECT delivery_id FROM ecp_deliveries WHERE message_id=%s", (sent["message_id"],)).fetchone()[0]
        claim = {"generation": 1, "request_key": "claim-" + uuid.uuid4().hex}
        claimed = call(f"/deliveries/{delivery}/claim", claim, bob, workspace=workspace, key=claim["request_key"])
        replay_claim = call(f"/deliveries/{delivery}/claim", claim, bob, workspace=workspace, key=claim["request_key"])
        verify("delivery claim is idempotent", claimed["attempt_id"] == replay_claim["attempt_id"])
        failure = {"generation": 1, "request_key": "failure-" + uuid.uuid4().hex, "error_code": "NETWORK_LOST", "max_attempts": 1}
        failed = call(f"/deliveries/{delivery}/failure", failure, bob, workspace=workspace, key=failure["request_key"])
        verify("terminal delivery failure creates a dead letter", failed["state"] == "DEAD_LETTER")
        msg2 = {**msg, "client_request_id": "recovery-message-" + uuid.uuid4().hex, "payload": {"text": "revoke"}}
        sent2 = call(f"/conversations/{conversation}/messages", msg2, alice, workspace=workspace, key=msg2["client_request_id"])
        revoke = {"request_key": "revoke-" + uuid.uuid4().hex, "reason_code": "MEMBERSHIP_REVOKED"}
        revoked = call(f"/conversations/{conversation}/revoke", revoke, alice, workspace=workspace, key=revoke["request_key"])
        verify("conversation revoke is durable", revoked["status"] == "REVOKED")
        with psycopg.connect(PG + " dbname=" + run["database"]) as db:
            state = db.execute("SELECT state FROM ecp_deliveries WHERE message_id=%s", (sent2["message_id"],)).fetchone()[0]
            dead = db.execute("SELECT count(*) FROM ecp_dead_letters WHERE delivery_id=%s", (delivery,)).fetchone()[0]
        verify("revocation stops pending delivery", state == "REVOKED")
        verify("dead-letter row is persisted", dead == 1)
        report.update({"status": "PASS", "database": run["database"]})
    except Exception as exc:
        report.update({"status": "FAIL", "error": f"{type(exc).__name__}: {exc}"})
    report["denominator"] = {"total": len(checks), "passed": sum(bool(c["passed"]) for c in checks), "failed": sum(not bool(c["passed"]) for c in checks)}
    (output / "phase3-recovery-live.json").write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n")
    print(json.dumps(report, ensure_ascii=False))
    return 0 if report["status"] == "PASS" else 10


if __name__ == "__main__": raise SystemExit(main())
