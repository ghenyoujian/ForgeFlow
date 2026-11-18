#!/usr/bin/env python3
"""External ECP delivery consumer.

Queue discovery is read-only PostgreSQL; all state changes use the public
claim and RECEIVED receipt APIs.  Restarting this process is safe because the
claim and receipt keys are deterministic per delivery/generation.
"""
from __future__ import annotations

import argparse
import concurrent.futures
import json
import os
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

import psycopg


def http_json(base_url: str, token: str, workspace: str, route: str,
              body: dict[str, Any], request_key: str,
              timeout: float = 20.0) -> tuple[int, dict[str, Any]]:
    headers = {
        "Accept": "application/json",
        "Authorization": f"Bearer {token}",
        "X-ForgeFlow-Workspace": workspace,
        "Content-Type": "application/json",
        "Idempotency-Key": request_key,
    }
    request = urllib.request.Request(
        base_url.rstrip("/") + "/api/v1" + route,
        data=json.dumps(body, separators=(",", ":")).encode(),
        headers=headers,
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return response.status, json.loads(response.read())
    except urllib.error.HTTPError as error:
        try:
            payload = json.loads(error.read())
        except (ValueError, UnicodeDecodeError):
            payload = {"error": "HTTP_ERROR"}
        return error.code, payload
    except (OSError, TimeoutError) as error:
        return 0, {"error": type(error).__name__, "detail": str(error)}


def pending_deliveries(database_url: str, conversation_id: str,
                       limit: int = 256) -> list[dict[str, Any]]:
    """Read queue identity/state only; mutations never use this connection."""
    with psycopg.connect(database_url) as database:
        rows = database.execute(
            """
            SELECT d.delivery_id,d.state,d.attempt_count,d.recipient_principal_id,
                   latest.generation
              FROM ecp_deliveries d
              JOIN ecp_messages m ON m.message_id=d.message_id
              LEFT JOIN LATERAL (
                SELECT a.generation
                  FROM ecp_delivery_attempts a
                 WHERE a.delivery_id=d.delivery_id
                 ORDER BY a.attempt_number DESC
                 LIMIT 1
              ) latest ON TRUE
             WHERE m.conversation_id=%s
               AND d.state IN ('PENDING','RETRY_WAIT','UNCONFIRMED','IN_FLIGHT')
             ORDER BY d.created_at,d.delivery_id
             LIMIT %s
            """,
            (conversation_id, limit),
        ).fetchall()
    return [{"delivery_id": row[0], "state": row[1],
             "attempt_count": int(row[2]),
             "recipient_principal_id": row[3],
             "generation": int(row[4]) if row[4] is not None else None}
            for row in rows]


def delivery_row(database_url: str, delivery_id: str) -> dict[str, Any] | None:
    """Refresh one delivery after a fencing or transport race."""
    with psycopg.connect(database_url) as database:
        row = database.execute(
            """
            SELECT d.state,d.attempt_count,latest.generation
              FROM ecp_deliveries d
              LEFT JOIN LATERAL (
                SELECT a.generation
                  FROM ecp_delivery_attempts a
                 WHERE a.delivery_id=d.delivery_id
                 ORDER BY a.attempt_number DESC
                 LIMIT 1
              ) latest ON TRUE
             WHERE d.delivery_id=%s
            """, (delivery_id,)
        ).fetchone()
    if row is None:
        return None
    return {"delivery_id": delivery_id, "state": row[0],
            "attempt_count": int(row[1]),
            "generation": int(row[2]) if row[2] is not None else None}


def delivery_counts(database_url: str, conversation_id: str) -> dict[str, int]:
    with psycopg.connect(database_url) as database:
        rows = database.execute(
            """
            SELECT d.state,count(*)
              FROM ecp_deliveries d
              JOIN ecp_messages m ON m.message_id=d.message_id
             WHERE m.conversation_id=%s
             GROUP BY d.state ORDER BY d.state
            """, (conversation_id,)).fetchall()
    return {state: int(count) for state, count in rows}


def claim_key(delivery_id: str, generation: int) -> str:
    return f"ecp-dispatcher-claim-{delivery_id}-{generation}"


def receipt_key(delivery_id: str, generation: int) -> str:
    return f"ecp-dispatcher-receipt-{delivery_id}-{generation}"


def _consume_delivery(*, base_url: str, token: str, workspace: str,
                      database_url: str, row: dict[str, Any],
                      max_retries: int) -> dict[str, Any]:
    """Claim/receive one row while fencing stale queue snapshots.

    Dispatcher-owned IN_FLIGHT rows already have a durable generation.  The
    recipient records RECEIVED against that generation directly; claiming it
    again would create avoidable fencing races.  For other states, refresh the
    row before each bounded claim retry and derive a deterministic generation.
    """
    delivery_id = row["delivery_id"]
    result = {"claimed": 0, "acked": 0, "replayed": 0, "failed": 0,
              "errors": []}
    for attempt in range(max_retries):
        current = delivery_row(database_url, delivery_id)
        if current is None or current["state"] in {
            "ACKED", "DEAD_LETTER", "EXPIRED", "REVOKED"
        }:
            # A concurrent worker may have completed the row.  Treat ACKED as
            # success, while terminal failures remain a failed observation.
            if current is not None and current["state"] == "ACKED":
                result["acked"] = 1
            else:
                result["failed"] = 1
            return result
        generation = current.get("generation")
        direct_receipt = current["state"] == "IN_FLIGHT" and generation is not None
        if not direct_receipt:
            generation = max(1, int(current["attempt_count"]) + 1)
            ckey = claim_key(delivery_id, generation)
            status, payload = http_json(
                base_url, token, workspace, f"/deliveries/{delivery_id}/claim",
                {"request_key": ckey, "generation": generation}, ckey)
            if status >= 300 or status == 0:
                if attempt + 1 < max_retries:
                    time.sleep(0.05 * (attempt + 1))
                    continue
                result["failed"] = 1
                result["errors"].append({"delivery_id": delivery_id,
                                         "stage": "claim", "http": status,
                                         "payload": payload})
                return result
            data = payload.get("data", payload)
            generation = int(data.get("generation", generation))
            if data.get("replayed"):
                result["replayed"] = 1
            else:
                result["claimed"] = 1
        rkey = receipt_key(delivery_id, int(generation))
        status, receipt = http_json(
            base_url, token, workspace, f"/deliveries/{delivery_id}/receipts",
            {"request_key": rkey, "receipt_kind": "RECEIVED",
             "data": {"consumer": "forgeflow-ecp-delivery-consumer",
                      "generation": int(generation)}}, rkey)
        if status < 300 and status != 0:
            result["acked"] = 1
            return result
        if attempt + 1 < max_retries:
            time.sleep(0.05 * (attempt + 1))
            continue
        result["failed"] = 1
        result["errors"].append({"delivery_id": delivery_id,
                                 "stage": "receipt", "http": status,
                                 "payload": receipt})
        return result
    result["failed"] = 1
    return result


def consume_once(*, base_url: str, token: str, workspace: str,
                 conversation_id: str, database_url: str,
                 batch_size: int = 256, workers: int = 32,
                 max_retries: int = 4) -> dict[str, Any]:
    rows = pending_deliveries(database_url, conversation_id, batch_size)
    report: dict[str, Any] = {"scanned": len(rows), "claimed": 0,
                              "acked": 0, "replayed": 0, "failed": 0,
                              "errors": []}
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        futures = [pool.submit(_consume_delivery, base_url=base_url,
                               token=token, workspace=workspace,
                               database_url=database_url, row=row,
                               max_retries=max_retries) for row in rows]
        for future in futures:
            result = future.result()
            for key in ("claimed", "acked", "replayed", "failed"):
                report[key] += result[key]
            report["errors"].extend(result["errors"])
    report["counts_after"] = delivery_counts(database_url, conversation_id)
    return report


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-url", default=os.environ.get("FORGEFLOW_API_URL"))
    parser.add_argument("--token", default=os.environ.get("FORGEFLOW_OWNER_TOKEN"))
    parser.add_argument("--workspace", default=os.environ.get("FORGEFLOW_WORKSPACE"))
    parser.add_argument("--conversation", required=True)
    parser.add_argument("--database-url", required=True,
                        help="disposable PostgreSQL URL used only for queue reads")
    parser.add_argument("--batch-size", type=int, default=256)
    parser.add_argument("--workers", type=int, default=32)
    parser.add_argument("--max-retries", type=int, default=4)
    parser.add_argument("--poll-seconds", type=float, default=0.25)
    parser.add_argument("--max-rounds", type=int, default=1)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if not args.base_url or not args.token or not args.workspace:
        parser.error("base URL, token and workspace are required")
    if not (1 <= args.batch_size <= 1000 and 1 <= args.workers <= 128
            and 1 <= args.max_retries <= 8 and args.poll_seconds >= 0
            and args.max_rounds >= 1):
        parser.error("invalid batch/poll/max-rounds bounds")
    rounds: list[dict[str, Any]] = []
    for index in range(args.max_rounds):
        result = consume_once(base_url=args.base_url, token=args.token,
                              workspace=args.workspace,
                              conversation_id=args.conversation,
                              database_url=args.database_url,
                              batch_size=args.batch_size, workers=args.workers,
                              max_retries=args.max_retries)
        result["round"] = index + 1
        rounds.append(result)
        if result["scanned"] == 0 or result["failed"]:
            break
        if args.poll_seconds:
            time.sleep(args.poll_seconds)
    output = {"schema_version": "forgeflow.ecp-delivery-consumer.v1",
              "status": "PASS" if rounds and not any(r["failed"] for r in rounds) else "FAIL",
              "product_gate_effect": "NONE", "conversation_id": args.conversation,
              "rounds": rounds, "restart_safe": True,
              "mutation_path": "public HTTP claim and RECEIVED receipt APIs; PostgreSQL read-only queue discovery"}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(output, ensure_ascii=False, indent=2) + "\n")
    print(json.dumps({"status": output["status"], "rounds": len(rounds)}))
    return 0 if output["status"] == "PASS" else 20


if __name__ == "__main__":
    raise SystemExit(main())
