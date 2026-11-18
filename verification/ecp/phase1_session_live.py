#!/usr/bin/env python3
"""Disposable account session/bootstrap checks; zero model calls."""
from __future__ import annotations
import argparse, json, pathlib, secrets, urllib.error, urllib.request, uuid

OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))

def call(run, route, body=None, token=None, csrf=None, expected=200, method=None):
    headers = {"Accept": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    if csrf:
        headers["X-CSRF-Token"] = csrf
    if body is not None:
        headers.update({"Content-Type": "application/json", "Idempotency-Key": "session-" + uuid.uuid4().hex})
    request = urllib.request.Request(run["base"] + "/api/v1" + route, data=json.dumps(body).encode() if body is not None else None, headers=headers, method=method)
    try:
        with OPENER.open(request, timeout=20) as response:
            status, payload = response.status, json.load(response)
    except urllib.error.HTTPError as error:
        status = error.code
        raw = error.read()
        try:
            payload = json.loads(raw)
        except (ValueError, UnicodeDecodeError):
            payload = {"raw": raw.decode("utf-8", "replace")}
    if status != expected:
        raise AssertionError(f"{route}: expected {expected}, got {status}: {payload}")
    return payload.get("data", payload)

def main() -> int:
    parser = argparse.ArgumentParser(); parser.add_argument("--output", type=pathlib.Path, required=True); args = parser.parse_args()
    out = args.output.resolve(); run = json.loads((out / "private.json").read_text()); checks = []
    def verify(name, condition):
        checks.append({"name": name, "passed": bool(condition)})
        if not condition: raise AssertionError(name)
    try:
        email = f"session-{secrets.token_hex(4)}@example.test"; password = secrets.token_hex(16)
        registered = call(run, "/registrations", {"email": email, "display_name": "session-owner", "password": password})
        verify("registration initializes one personal workspace", bool(registered["account"]["workspace_id"]) and registered["account"]["session_epoch"] == 1)
        logged = call(run, "/session", {"email": email, "password": password})
        verify("login issues a distinct account session", logged["token"] != registered["token"] and bool(logged["csrf_token"]))
        me = call(run, "/me", token=logged["token"])
        verify("new session reads the same account identity", me["role"] == "account" and me["account"]["account_id"] == registered["account"]["account_id"])
        call(run, "/logout", token=logged["token"], csrf=logged["csrf_token"], method="POST")
        call(run, "/me", token=logged["token"], expected=401)
        rotated = call(run, "/account/password", {"current_password": password, "new_password": secrets.token_hex(16)}, token=registered["token"], csrf=registered["csrf_token"])
        verify("password rotation returns a new session", rotated["token"] != registered["token"] and bool(rotated["csrf_token"]))
        call(run, "/me", token=registered["token"], expected=401)
        verify("rotated session remains readable", call(run, "/me", token=rotated["token"])["account"]["account_id"] == registered["account"]["account_id"])
        report = {"schema_version": "forgeflow.ecp-phase1-session-live.v1", "scope": "ECP_PHASE1_SESSION_DISPOSABLE_LIVE", "product_gate_effect": "NONE", "status": "PASS", "qualification": "OBSERVED_NOT_GATE", "model_calls": 0, "checks": checks, "denominator": {"total": len(checks), "passed": sum(x["passed"] for x in checks), "failed": sum(not x["passed"] for x in checks)}, "database": run.get("database")}
    except Exception as exc:
        report = {"schema_version": "forgeflow.ecp-phase1-session-live.v1", "scope": "ECP_PHASE1_SESSION_DISPOSABLE_LIVE", "product_gate_effect": "NONE", "status": "FAIL", "qualification": "NOT_RUN", "model_calls": 0, "checks": checks, "error": str(exc), "denominator": {"total": len(checks), "passed": sum(x["passed"] for x in checks), "failed": sum(not x["passed"] for x in checks)}}
        raise
    finally:
        (out / "phase1-session-live-report.json").write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n")
    print(json.dumps({"status": report["status"], "checks": len(checks), "model_calls": 0}))
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
