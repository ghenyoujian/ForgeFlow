#!/usr/bin/env python3
"""Recover one real retained REF_UPDATED intent through the Owner HTTP API.

Uses only SELECT statements for observation. Never launches a Worker, author,
model request or oracle; never updates SQL or creates a substitute merge intent.
Private runtime credentials are read from an existing mode-0600 file.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import time
import urllib.error
import urllib.request
import uuid

ROOT = Path(__file__).resolve().parents[1]
PG_ROOT = Path.home() / ".cache/forgeflow-postgres/root"


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def quoted(text):
    return "'" + text.replace("'", "''") + "'"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--receipt", required=True)
    parser.add_argument("--runtime-env", required=True)
    parser.add_argument("--project", required=True)
    parser.add_argument("--attempt", required=True)
    parser.add_argument("--intent", required=True)
    parser.add_argument("--original-operation", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--start-server", action="store_true")
    args = parser.parse_args()
    output = Path(args.output)
    output.mkdir(parents=True, exist_ok=False)
    cfg = json.loads(Path(args.runtime_env).read_text())
    receipt = json.loads(Path(args.receipt).read_text())
    binary = receipt["binaries"]["forgeflow-server"]
    assert digest(binary["path"]) == binary["sha256"], "server binary differs from approved immutable receipt"
    bind = cfg["FORGEFLOW_BIND"]
    host, port = bind.rsplit(":", 1)
    assert host in ("127.0.0.1", "localhost"), "qualification must use existing isolated loopback API"
    base = f"http://{bind}"
    http = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    secrets = [cfg.get("FORGEFLOW_OWNER_TOKEN", ""), cfg.get("FORGEFLOW_WORKER_TOKEN", ""), cfg.get("FORGEFLOW_OWNER_PASSWORD", "")]
    report = {"scope": "one original real REF_UPDATED Git intent; HTTP recovery without SQL mutation, author, model or oracle rerun",
              "source_identity": receipt["source_identity"], "server_sha256": binary["sha256"],
              "project_id": args.project, "attempt_id": args.attempt, "intent_id": args.intent,
              "checks": [], "http": [], "gate_status": "FAIL"}
    server = None
    log = None

    def save(name, value):
        encoded = json.dumps(value, ensure_ascii=False, indent=2)
        for secret in secrets:
            if secret:
                encoded = encoded.replace(secret, "[REDACTED]")
        (output / name).write_text(encoded + "\n")

    def check(name, condition):
        report["checks"].append({"name": name, "passed": bool(condition)})
        if not condition:
            raise AssertionError(name)

    def request(method, path, body=None, key=None, worker=False):
        headers = {"Authorization": "Bearer " + cfg["FORGEFLOW_WORKER_TOKEN" if worker else "FORGEFLOW_OWNER_TOKEN"]}
        if key:
            headers["Idempotency-Key"] = key
        data = None if body is None else json.dumps(body).encode()
        if data is not None:
            headers["Content-Type"] = "application/json"
        req = urllib.request.Request(base + "/api/v1" + path, data=data, method=method, headers=headers)
        started = time.monotonic()
        try:
            with http.open(req, timeout=30) as response:
                status, raw = response.status, response.read()
        except urllib.error.HTTPError as error:
            status, raw = error.code, error.read()
        try:
            value = json.loads(raw)
        except json.JSONDecodeError:
            value = {"non_json_body": raw.decode(errors="replace")[:2000]}
        report["http"].append({"method": method, "path": path, "status": status,
                               "elapsed_ms": (time.monotonic() - started) * 1000,
                               "response": value})
        return status, value

    def observe():
        project, attempt, intent, operation = map(quoted, (args.project, args.attempt, args.intent, args.original_operation))
        sql = f"""SELECT jsonb_build_object(
            'project',(SELECT data FROM projects WHERE project_id={project}),
            'attempt',(SELECT data FROM attempts WHERE project_id={project} AND attempt_id={attempt}),
            'intent',(SELECT data FROM merge_intents WHERE project_id={project} AND intent_id={intent}),
            'original_operation',(SELECT data FROM documents WHERE project_id={project} AND collection='operations' AND document_id={operation}),
            'allocations',COALESCE((SELECT jsonb_agg(jsonb_build_object('allocation_id',allocation_id,'scope_id',scope_id,'dimension',dimension,'amount',amount,'state',state)) FROM resource_allocations WHERE project_id={project} AND attempt_id={attempt}),'[]'::jsonb),
            'lease',COALESCE((SELECT jsonb_agg(jsonb_build_object('lease_id',lease_id,'generation',generation,'revoked_at',revoked_at)) FROM leases WHERE project_id={project} AND attempt_id={attempt}),'[]'::jsonb),
            'model_request_count',(SELECT count(*) FROM model_request_permit WHERE attempt_id={attempt}),
            'native_model_request_count',(SELECT count(*) FROM native_model_requests WHERE attempt_id={attempt}),
            'other_attempt',(SELECT attempt_id FROM attempts WHERE project_id={project} AND attempt_id!={attempt} ORDER BY attempt_id LIMIT 1)
        );"""
        env = dict(os.environ)
        env["LD_LIBRARY_PATH"] = str(PG_ROOT / "usr/lib/x86_64-linux-gnu")
        result = subprocess.run([str(PG_ROOT / "usr/lib/postgresql/16/bin/psql"), "-X", "-t", "-A", "-d", cfg["DATABASE_URL"], "-c", sql],
                                env=env, capture_output=True, timeout=30)
        if result.returncode:
            raise RuntimeError("read-only PostgreSQL observation failed")
        return json.loads(result.stdout)

    def frozen_files(before):
        root = Path(before["intent"]["receipt"]["artifact_root"])
        attempt_root = Path(cfg["FORGEFLOW_DATA_ROOT"]) / "attempts" / args.attempt
        paths = list(root.rglob("*")) + list(attempt_root.rglob("*"))
        return {str(path): digest(path) for path in paths if path.is_file()}

    try:
        before = observe()
        save("original-before.json", before)
        report["original_attempt_state"] = before["attempt"]["state"]
        check("original_real_ref_updated_intent", before["intent"]["state"] == "REF_UPDATED"
              and before["attempt"]["state"] in ("MERGING", "RECOVERY_REQUIRED") and before["intent"]["receipt"].get("commit_decided") is True
              and before["intent"]["receipt"].get("ref_updated") is True)
        check("owner_already_paused_and_no_resume_requested", before["project"]["paused"] is True)
        originals = frozen_files(before)
        save("original-artifact-sha256.json", originals)
        if args.start_server:
            with socket.socket() as probe:
                check("isolated_api_port_unoccupied_before_start", probe.connect_ex((host, int(port))) != 0)
            env = dict(os.environ)
            env.update({key: str(value) for key, value in cfg.items()})
            log = (output / "server.txt").open("wb")
            server = subprocess.Popen([binary["path"]], env=env, cwd=ROOT, stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
            report["server_pid"] = server.pid
        deadline = time.monotonic() + 40
        while True:
            if server is not None and server.poll() is not None:
                raise RuntimeError("isolated server terminated during startup")
            try:
                with http.open(base + "/healthz", timeout=2) as response:
                    if response.status == 200:
                        break
            except (urllib.error.URLError, TimeoutError):
                pass
            if time.monotonic() > deadline:
                raise RuntimeError("isolated API did not become ready")
            time.sleep(.2)
        path = f"/attempts/{args.attempt}/integration-recovery"
        body = {"project_id": args.project, "intent_id": args.intent,
                "expected_intent_revision": before["intent"]["revision"],
                "reason": "Owner recovers the original stopped-verifier REF_UPDATED intent; preserve original author and independent evidence"}
        status, _ = request("POST", path, dict(body, expected_intent_revision=body["expected_intent_revision"] + 100), uuid.uuid4().hex)
        check("wrong_intent_revision_rejected", status == 409)
        status, _ = request("POST", path, body, uuid.uuid4().hex, worker=True)
        check("worker_credentials_cannot_authorize_recovery", status == 403)
        if before["other_attempt"]:
            status, _ = request("POST", f"/attempts/{before['other_attempt']}/integration-recovery", body, uuid.uuid4().hex)
            check("real_other_attempt_cannot_recover_target_intent", status == 409)
        status, _ = request("POST", f"/projects/{args.project}/documents/operations",
                            {"id": "counterfeit-recovery-" + uuid.uuid4().hex, "value": {"kind": "INTEGRATION_RECOVERY", "status": "SUCCEEDED"}}, uuid.uuid4().hex)
        check("generic_operation_cannot_forge_recovery", status == 422)
        check("negative_requests_preserve_original_intent", observe()["intent"] == before["intent"])
        key = uuid.uuid4().hex
        status, accepted = request("POST", path, body, key)
        check("owner_recovery_accepted", status == 202 and accepted.get("replayed") is False)
        operation = accepted["operation_id"]
        report["recovery_operation_id"] = operation
        deadline = time.monotonic() + 120
        while True:
            status, value = request("GET", f"/operations/{operation}")
            check("recovery_operation_query_succeeded", status == 200)
            settled = value["data"]
            if settled["status"] != "ACCEPTED":
                break
            if time.monotonic() > deadline:
                raise RuntimeError("real original integration recovery did not settle")
            time.sleep(.2)
        save("recovery-operation.json", settled)
        check("recovery_reached_durable_success", settled["status"] == "SUCCEEDED")
        status, replayed = request("POST", path, body, key)
        check("exact_key_replays_original_settled_success", status == 202 and replayed.get("replayed") is True
              and replayed["operation_id"] == operation and replayed["data"]["status"] == "SUCCEEDED")
        status, _ = request("POST", path, dict(body, reason=body["reason"] + " changed"), key)
        check("changed_request_same_key_rejected", status == 409)
        after = observe()
        save("original-after.json", after)
        check("original_attempt_succeeded_and_intent_finalized", after["attempt"]["state"] == "SUCCEEDED" and after["intent"]["state"] == "FINALIZED")
        check("original_candidate_and_integrated_shas_unchanged", all(after["intent"][key] == before["intent"][key] for key in ("candidate_sha", "integrated_sha", "expected_sha")))
        check("original_receipt_and_old_operation_unchanged", after["intent"]["receipt"] == before["intent"]["receipt"] and after["original_operation"] == before["original_operation"])
        check("original_held_allocations_released_by_controller", len(after["allocations"]) == len(before["allocations"]) > 0 and all(row["state"] == "RELEASED" for row in after["allocations"]))
        check("original_lease_revoked", all(row["revoked_at"] for row in after["lease"]))
        check("no_model_requests_added", after["model_request_count"] == before["model_request_count"] and after["native_model_request_count"] == before["native_model_request_count"])
        check("no_original_author_or_verifier_artifact_changed", frozen_files(before) == originals)
        verification = after["intent"]["receipt"]["verification"]
        check("original_eight_independent_cases_retained", verification["total"] == 8 and verification["failed"] == 0 and verification["skipped"] == 0)
        result = settled["result"]
        check("recovery_records_zero_author_model_or_oracle_reruns", result["author_reexecuted"] is False and result["model_requests_started"] == 0 and result["verification_commands_rerun"] == 0)
        report["gate_status"] = "PASS"
    except Exception as error:
        report["error"] = {"type": type(error).__name__, "message": str(error)}
    finally:
        if server is not None and server.poll() is None:
            os.killpg(server.pid, signal.SIGTERM)
            try:
                server.wait(timeout=30)
            except subprocess.TimeoutExpired:
                os.killpg(server.pid, signal.SIGKILL)
                server.wait(timeout=5)
        if server is not None:
            report["server_exit"] = server.returncode
        if log is not None:
            log.close()
        report["passed"] = sum(row["passed"] for row in report["checks"])
        report["total"] = len(report["checks"])
        save("report.json", report)
        print(json.dumps({"gate_status": report["gate_status"], "passed": report["passed"], "total": report["total"], "report": str(output / "report.json")}, ensure_ascii=False))
    return 0 if report["gate_status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
