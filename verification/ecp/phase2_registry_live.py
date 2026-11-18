#!/usr/bin/env python3
"""Disposable HTTP/PostgreSQL Agent Registry/Profile checks; zero model calls."""
from __future__ import annotations
import argparse, hashlib, json, pathlib, secrets, urllib.error, urllib.request, uuid

OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))

def request(run, route, body=None, token=None, workspace=None, key=None):
    headers = {"Accept": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    if workspace:
        headers["X-ForgeFlow-Workspace"] = workspace
    if body is not None:
        headers.update({"Content-Type": "application/json", "Idempotency-Key": key or str(uuid.uuid4())})
    req = urllib.request.Request(run["base"] + "/api/v1" + route, data=json.dumps(body).encode() if body is not None else None, headers=headers)
    try:
        with OPENER.open(req, timeout=20) as response:
            return response.status, json.load(response)
    except urllib.error.HTTPError as error:
        return error.code, json.loads(error.read())

def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=pathlib.Path, required=True)
    args = parser.parse_args()
    out = args.output.resolve()
    run = json.loads((out / "private.json").read_text())
    checks = []
    def call(name, route, body=None, expected=200, key=None):
        status, payload = request(run, route, body, token=owner["token"], workspace=workspace, key=key)
        checks.append({"name": name, "passed": status == expected, "status": status, "expected": expected})
        if status != expected:
            raise AssertionError(f"{route}: expected {expected}, got {status}: {payload}")
        return payload.get("data", payload)
    try:
        email = f"registry-{secrets.token_hex(4)}@example.test"
        status, payload = request(run, "/registrations", {"email": email, "display_name": "registry-owner", "password": secrets.token_hex(16)})
        if status != 200:
            raise AssertionError(payload)
        owner = payload["data"]
        workspace = owner["account"]["workspace_id"]
        # Registration returns the durable identity; the principals projection
        # is the authoritative source for the immutable human principal.
        principals = call("human principal projection", f"/workspaces/{workspace}/principals")
        principal = next(item["principal_id"] for item in principals if item.get("account_id") == owner["account"]["account_id"])
        key = "registry-" + uuid.uuid4().hex
        body = {"principal_id": principal, "display_name": "DSH candidate", "executor_kinds": ["DSH"], "project_set": [], "request_key": key}
        registration = call("agent registration creates immutable identity", f"/workspaces/{workspace}/agent-registry", body, key=key)
        replay = call("agent registration retry is idempotent", f"/workspaces/{workspace}/agent-registry", body, key=key)
        checks.append({"name": "registration replay preserves identity", "passed": replay.get("registration_id") == registration.get("registration_id") and replay.get("replayed") is True})
        digest = "a" * 64
        profile = {"profile_id": "dsh-profile-" + uuid.uuid4().hex, "registration_id": registration["registration_id"], "provider": "dsh", "profile_version": "candidate-v1", "binary_digest": digest, "adapter_digest": digest, "configuration_digest": digest, "capabilities": {"structured_events": True, "cancel": False, "resume": False}, "support_status": "UNKNOWN", "evidence_status": "NOT_RUN"}
        frozen = call("profile freeze persists UNKNOWN/NOT_RUN boundary", f"/workspaces/{workspace}/executor-profiles", profile, key="profile-" + uuid.uuid4().hex)
        snapshot = call("registry snapshot returns registration and profile", f"/workspaces/{workspace}/registry")
        checks.append({"name": "snapshot contains immutable registration", "passed": any(row.get("registration_id") == registration["registration_id"] for row in snapshot.get("agents", []))})
        checks.append({"name": "snapshot preserves unqualified profile status", "passed": any(row.get("profile_id") == frozen.get("profile_id") and row.get("evidence_status") == "NOT_RUN" and row.get("support_status") == "UNKNOWN" for row in snapshot.get("profiles", []))})
        report = {"schema_version": "forgeflow.ecp-phase2-live.v1", "scope": "ECP_PHASE2_REGISTRY_DISPOSABLE_LIVE", "product_gate_effect": "NONE", "status": "PASS", "qualification": "OBSERVED_NOT_GATE", "model_calls": 0, "checks": checks, "denominator": {"total": len(checks), "passed": sum(item["passed"] for item in checks), "failed": sum(not item["passed"] for item in checks)}, "database": run.get("database")}
    except Exception as exc:
        report = {"schema_version": "forgeflow.ecp-phase2-live.v1", "scope": "ECP_PHASE2_REGISTRY_DISPOSABLE_LIVE", "product_gate_effect": "NONE", "status": "FAIL", "qualification": "NOT_RUN", "model_calls": 0, "checks": checks, "error": str(exc), "denominator": {"total": len(checks), "passed": sum(item["passed"] for item in checks), "failed": sum(not item["passed"] for item in checks)}}
        raise
    finally:
        (out / "phase2-registry-live-report.json").write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n")
    print(json.dumps({"status": report["status"], "checks": len(checks), "model_calls": 0}))
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
