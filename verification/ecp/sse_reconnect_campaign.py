#!/usr/bin/env python3
"""Real disposable SSE reconnect/cursor campaign for ECP.

The campaign is opt-in and never changes a product Gate.  It uses a disposable
workspace and project, reads one durable event, closes the stream, emits the
next durable event, then reconnects from the last cursor and requires the next
frame to be exactly the contiguous event.  A missing frame, duplicate frame,
wrong project or cursor regression is a hard failure.
"""
from __future__ import annotations

import argparse
import json
import os
import socket
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from pathlib import Path
from typing import Any


def headers(token: str, workspace: str, *, accept: str = "application/json") -> dict[str, str]:
    return {
        "Accept": accept,
        "Authorization": f"Bearer {token}",
        "X-ForgeFlow-Workspace": workspace,
    }


def request_json(
    base: str,
    route: str,
    token: str,
    workspace: str,
    body: dict[str, Any] | None = None,
    key: str | None = None,
) -> tuple[int, dict[str, Any]]:
    request_headers = headers(token, workspace)
    if body is not None:
        request_headers.update({"Content-Type": "application/json", "Idempotency-Key": key or str(uuid.uuid4())})
    request = urllib.request.Request(
        base.rstrip("/") + "/api/v1" + route,
        data=json.dumps(body).encode() if body is not None else None,
        headers=request_headers,
        method="POST" if body is not None else "GET",
    )
    try:
        with urllib.request.urlopen(request, timeout=15) as response:
            return response.status, json.loads(response.read())
    except urllib.error.HTTPError as error:
        raw = error.read()
        try:
            payload = json.loads(raw)
        except (ValueError, UnicodeDecodeError):
            payload = {"raw": raw.decode("utf-8", "replace")}
        return error.code, payload


def data_body(payload: dict[str, Any]) -> dict[str, Any]:
    value = payload.get("data", payload)
    if not isinstance(value, dict):
        raise AssertionError(f"response data is not an object: {payload!r}")
    return value


def create_project(base: str, token: str, workspace: str) -> tuple[str, int]:
    project_id = str(uuid.uuid4())
    status, payload = request_json(
        base,
        "/projects",
        token,
        workspace,
        {
            "project_id": project_id,
            "name": "ECP SSE reconnect campaign",
            "root_path": "",
            "authority_mode": "MANAGED",
            "data_origin": "NATIVE",
            "goal": "prove cursor reconnect",
            "technology_stack": [],
            "timezone": "UTC",
            "paused": False,
            "archived": False,
            "revision": 0,
        },
        f"sse-reconnect-project-{project_id}",
    )
    if status >= 300:
        raise RuntimeError(f"project creation failed: HTTP {status} {payload}")
    cursor_status, cursor_payload = request_json(base, f"/projects/{project_id}/event-cursor", token, workspace)
    if cursor_status >= 300:
        raise RuntimeError(f"event cursor read failed: HTTP {cursor_status} {cursor_payload}")
    cursor = int(data_body(cursor_payload)["cursor"])
    return project_id, cursor


def create_requirement(base: str, token: str, workspace: str, project_id: str, label: str) -> tuple[str, int]:
    requirement_id = f"sse-requirement-{label}-{uuid.uuid4()}"
    status, payload = request_json(
        base,
        f"/projects/{urllib.parse.quote(project_id, safe='')}/requirements",
        token,
        workspace,
        {
            "project_id": project_id,
            "requirement_id": requirement_id,
            "title": f"SSE reconnect {label}",
            "source_anchor": f"sse-reconnect#{label}",
            "outcome": "durable cursor event",
            "scope": "verification",
            "acceptance": ["event is durable"],
            "priority": 0,
            "weight": 1,
            "deferred_reason": None,
            "revision": 1,
        },
        f"sse-reconnect-requirement-{label}-{requirement_id}",
    )
    if status >= 300:
        raise RuntimeError(f"requirement {label} failed: HTTP {status} {payload}")
    cursor_status, cursor_payload = request_json(base, f"/projects/{project_id}/event-cursor", token, workspace)
    if cursor_status >= 300:
        raise RuntimeError(f"event cursor read after {label} failed: HTTP {cursor_status} {cursor_payload}")
    cursor = int(data_body(cursor_payload)["cursor"])
    return requirement_id, cursor


def read_sse_frame(base: str, project_id: str, after: int, token: str, workspace: str, timeout: float) -> dict[str, Any]:
    route = f"/api/v1/projects/{urllib.parse.quote(project_id, safe='')}/events?after={after}"
    request = urllib.request.Request(
        base.rstrip("/") + route,
        headers={**headers(token, workspace, accept="text/event-stream"), "Last-Event-ID": f"{project_id}:{after}"},
    )
    deadline = time.monotonic() + timeout
    with urllib.request.urlopen(request, timeout=timeout) as response:
        if response.status != 200:
            raise AssertionError(f"SSE HTTP {response.status}")
        content_type = response.headers.get("content-type", "")
        if "text/event-stream" not in content_type:
            raise AssertionError(f"SSE content type mismatch: {content_type}")
        event_id: str | None = None
        data_lines: list[str] = []
        while time.monotonic() < deadline:
            try:
                line = response.readline()
            except socket.timeout as exc:
                raise AssertionError("SSE read timed out") from exc
            if not line:
                break
            decoded = line.decode("utf-8", "replace").rstrip("\r\n")
            if decoded.startswith("id:"):
                event_id = decoded[3:].strip()
            elif decoded.startswith("data:"):
                data_lines.append(decoded[5:].lstrip())
            elif decoded == "" and event_id and data_lines:
                try:
                    payload = json.loads("\n".join(data_lines))
                except json.JSONDecodeError as exc:
                    raise AssertionError(f"SSE data is not JSON: {data_lines!r}") from exc
                if not isinstance(payload, dict):
                    raise AssertionError("SSE data is not an object")
                return {"id": event_id, "payload": payload}
        raise AssertionError("SSE stream ended before a complete frame")


def run(args: argparse.Namespace) -> dict[str, Any]:
    report: dict[str, Any] = {
        "schema_version": "forgeflow.ecp-sse-reconnect.v1",
        "scope": "ECP_PHASE3_SSE_RECONNECT",
        "product_gate_effect": "NONE",
        "qualification": "NOT_RUN",
        "status": "NOT_RUN",
        "model_calls": 0,
        "checks": [],
        "denominator": {"checks": 5, "passed": 0, "failed": 0},
    }
    if not args.run:
        report["reason"] = "SSE reconnect campaign requires explicit --run"
        return report
    required = {"base_url": args.base_url, "token": args.token, "workspace": args.workspace}
    missing = [name for name, value in required.items() if not value]
    if missing:
        report.update({"status": "BLOCKED", "reason": f"missing required inputs: {', '.join(missing)}"})
        return report

    checks: list[dict[str, Any]] = []

    def check(name: str, passed: bool, **facts: Any) -> None:
        checks.append({"name": name, "status": "PASS" if passed else "FAIL", **facts})
        if not passed:
            raise AssertionError(name)

    project_id, cursor0 = create_project(args.base_url, args.token, args.workspace)
    req1, cursor1 = create_requirement(args.base_url, args.token, args.workspace, project_id, "first")
    frame1 = read_sse_frame(args.base_url, project_id, cursor0, args.token, args.workspace, args.timeout)
    seq1 = int(str(frame1["id"]).rsplit(":", 1)[-1])
    check(
        "first durable frame is contiguous",
        seq1 == cursor1 and frame1["id"].startswith(f"{project_id}:") and frame1["payload"].get("project_id") == project_id,
        cursor_before=cursor0,
        cursor_after=cursor1,
        event_id=frame1["id"],
        requirement_id=req1,
    )
    # The first response context is closed by read_sse_frame.  The next event
    # is emitted only after that close, so this is a real disconnect boundary.
    req2, cursor2 = create_requirement(args.base_url, args.token, args.workspace, project_id, "second")
    frame2 = read_sse_frame(args.base_url, project_id, cursor1, args.token, args.workspace, args.timeout)
    seq2 = int(str(frame2["id"]).rsplit(":", 1)[-1])
    check(
        "reconnect resumes from last acknowledged cursor",
        seq2 == cursor2 and seq2 == seq1 + 1 and frame2["id"].startswith(f"{project_id}:") and frame2["payload"].get("project_id") == project_id,
        reconnect_after=cursor1,
        cursor_after=cursor2,
        event_id=frame2["id"],
        requirement_id=req2,
    )
    check("reconnect has no duplicate frame", frame2["id"] != frame1["id"], first_event_id=frame1["id"], second_event_id=frame2["id"])
    check("reconnect payload sequence matches id", int(frame2["payload"].get("project_seq", -1)) == seq2, payload_sequence=frame2["payload"].get("project_seq"), id_sequence=seq2)
    check("reconnect identity remains project scoped", frame1["payload"].get("project_id") == frame2["payload"].get("project_id") == project_id, project_id=project_id)
    report.update({
        "status": "PASS",
        "qualification": "OBSERVED_NOT_GATE",
        "checks": checks,
        "denominator": {"checks": len(checks), "passed": len(checks), "failed": 0},
        "project_id": project_id,
        "cursors": {"before": cursor0, "first": cursor1, "reconnect": cursor2},
        "frames": [frame1, frame2],
        "disconnect_boundary": {"first_stream_closed_before_second_event": True},
        "limitations": ["Disposable single-project SSE reconnect campaign only; network partition, dispatcher crash, 100k message ordering and 72-hour stability remain NOT_RUN.", "No DSH/Claude model execution."],
    })
    return report


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-url", default=os.environ.get("FORGEFLOW_API_URL"))
    parser.add_argument("--token", default=os.environ.get("FORGEFLOW_OWNER_TOKEN"))
    parser.add_argument("--workspace", default=os.environ.get("FORGEFLOW_WORKSPACE"))
    parser.add_argument("--timeout", type=float, default=15.0)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--run", action="store_true")
    args = parser.parse_args()
    try:
        report = run(args)
    except (AssertionError, OSError, RuntimeError, ValueError, urllib.error.URLError) as exc:
        report = {
            "schema_version": "forgeflow.ecp-sse-reconnect.v1",
            "scope": "ECP_PHASE3_SSE_RECONNECT",
            "product_gate_effect": "NONE",
            "qualification": "NOT_RUN",
            "status": "INCONCLUSIVE",
            "model_calls": 0,
            "reason": str(exc),
            "checks": [],
            "denominator": {"checks": 5, "passed": 0, "failed": 0},
        }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"status": report.get("status"), "qualification": report.get("qualification"), "checks": report.get("denominator")}))
    return 0 if report.get("status") in {"PASS", "NOT_RUN"} else 20


if __name__ == "__main__":
    raise SystemExit(main())
