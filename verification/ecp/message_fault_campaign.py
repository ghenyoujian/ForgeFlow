#!/usr/bin/env python3
"""Real HTTP duplicate/out-of-order message campaign.

This harness is intentionally narrower than the final Phase 3 Gate: it sends
real durable messages and retries through the public API, while explicitly
reporting network partition, process crash and 100k-scale cases as uncovered.
"""
from __future__ import annotations

import argparse
import concurrent.futures
import json
import os
import random
import urllib.error
import urllib.request
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def call(base: str, route: str, token: str, workspace: str, body: dict[str, Any] | None = None, key: str | None = None) -> tuple[int, dict[str, Any]]:
    headers = {"Accept": "application/json", "Authorization": f"Bearer {token}", "X-ForgeFlow-Workspace": workspace}
    if body is not None:
        headers.update({"Content-Type": "application/json", "Idempotency-Key": key or str(uuid.uuid4())})
    request = urllib.request.Request(base.rstrip("/") + "/api/v1" + route, data=json.dumps(body).encode() if body is not None else None, headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            return response.status, json.loads(response.read())
    except urllib.error.HTTPError as error:
        try: payload = json.loads(error.read())
        except (ValueError, UnicodeDecodeError): payload = {"raw": "http error"}
        return error.code, payload


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-url", default=os.environ.get("FORGEFLOW_API_URL"))
    parser.add_argument("--token", default=os.environ.get("FORGEFLOW_OWNER_TOKEN"))
    parser.add_argument("--workspace", default=os.environ.get("FORGEFLOW_WORKSPACE"))
    parser.add_argument("--principal", default=os.environ.get("FORGEFLOW_PRINCIPAL"))
    parser.add_argument("--messages", type=int, default=20)
    parser.add_argument("--run", action="store_true")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    report: dict[str, Any] = {
        "schema_version": "forgeflow.ecp-message-fault-campaign.v1",
        "product_gate_effect": "NONE",
        "qualification": "NOT_RUN",
        "status": "NOT_RUN",
        "created_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "model_calls": 0,
        "requested": {"messages": args.messages, "duplicate_retries": args.messages, "out_of_order": True},
        "uncovered_faults": ["network partition", "dispatcher process crash", "100k-message fault denominator"],
    }
    if not args.run:
        report["reason"] = "message fault campaign requires explicit --run"
    elif not args.base_url or not args.token or not args.workspace or not args.principal:
        report.update({"status": "BLOCKED", "reason": "base URL, token, workspace and principal are required"})
    elif args.messages <= 0 or args.messages > 1000:
        report.update({"status": "FAIL", "reason": "messages must be between 1 and 1000"})
    else:
        conversation_id, thread_id = str(uuid.uuid4()), str(uuid.uuid4())
        conversation_key = f"fault-conversation-{conversation_id}-create"
        status, payload = call(args.base_url, f"/workspaces/{args.workspace}/conversations", args.token, args.workspace, {"conversation_id": conversation_id, "project_id": None, "participant_principal_ids": [args.principal], "request_key": conversation_key}, conversation_key)
        if status >= 300:
            report.update({"status": "FAIL", "reason": "conversation setup failed", "http": status, "payload": payload})
        else:
            thread_key = f"fault-thread-{thread_id}-create"
            status, payload = call(args.base_url, f"/conversations/{conversation_id}/threads", args.token, args.workspace, {"thread_id": thread_id, "task_id": None, "request_key": thread_key}, thread_key)
            if status >= 300:
                report.update({"status": "FAIL", "reason": "thread setup failed", "http": status, "payload": payload})
            else:
                messages = []
                for index in range(args.messages):
                    key = f"fault-message-{index}-{uuid.uuid4()}"
                    messages.append((key, {"thread_id": thread_id, "message_kind": "chat.message", "client_request_id": key, "payload": {"text": f"fault-{index}"}, "correlation_id": None, "causation_id": None, "expires_at": None}))
                random.Random(0xEC0).shuffle(messages)
                with concurrent.futures.ThreadPoolExecutor(max_workers=min(32, args.messages)) as pool:
                    first = list(pool.map(lambda item: call(args.base_url, f"/conversations/{conversation_id}/messages", args.token, args.workspace, item[1], item[0]), messages))
                replay = [call(args.base_url, f"/conversations/{conversation_id}/messages", args.token, args.workspace, body, key) for key, body in messages]
                accepted = sum(status < 300 for status, _ in first)
                replayed = sum(status < 300 and bool(payload.get("data", {}).get("replayed")) for status, payload in replay)
                report.update({"status": "PASS" if accepted == args.messages and replayed == args.messages else "FAIL", "qualification": "OBSERVED_NOT_GATE", "conversation_id": conversation_id, "thread_id": thread_id, "denominator": {"messages": args.messages, "accepted": accepted, "retries": args.messages, "replayed": replayed, "failed": (args.messages - accepted) + (args.messages - replayed)}})
    args.output.parent.mkdir(parents=True, exist_ok=True); args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n")
    print(json.dumps({"status": report["status"], "model_calls": 0}))
    return 0 if report["status"] in {"PASS", "NOT_RUN"} else 20


if __name__ == "__main__":
    raise SystemExit(main())
