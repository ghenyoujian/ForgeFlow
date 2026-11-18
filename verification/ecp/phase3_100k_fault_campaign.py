#!/usr/bin/env python3
"""Current-head Phase 3 100k message fault campaign.

The campaign uses the real HTTP message endpoint and a disposable candidate
database.  It deliberately treats a server restart as the dispatcher fault
substitute because the current runtime has no independent dispatcher process.
The result never changes a product Gate: an absent dispatcher or undrained
outbox is reported as INCONCLUSIVE rather than being hidden behind a PASS.
"""
from __future__ import annotations

import argparse
import concurrent.futures
import json
import os
import signal
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
import uuid
from pathlib import Path
from typing import Any

import psycopg

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from benchmarks.fault_proxy import FaultProxy  # noqa: E402

PG = "host=/home/chenyoujian/.local/state/forgeflow/postgres port=55432 user=forgeflow"
OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def call(
    run: dict[str, Any],
    route: str,
    body: dict[str, Any] | None = None,
    key: str | None = None,
    timeout: float = 30,
) -> tuple[int, dict[str, Any], float]:
    headers = {
        "Accept": "application/json",
        "Authorization": "Bearer " + run["token"],
        "X-ForgeFlow-Workspace": run["workspace"],
    }
    if body is not None:
        headers.update(
            {
                "Content-Type": "application/json",
                "Idempotency-Key": key or str(uuid.uuid4()),
            }
        )
    request = urllib.request.Request(
        run["base"].rstrip("/") + "/api/v1" + route,
        data=json.dumps(body).encode() if body is not None else None,
        headers=headers,
    )
    started = time.perf_counter()
    try:
        with OPENER.open(request, timeout=timeout) as response:
            return response.status, json.loads(response.read()), (time.perf_counter() - started) * 1000
    except urllib.error.HTTPError as error:
        try:
            payload = json.loads(error.read())
        except (ValueError, UnicodeDecodeError):
            payload = {"raw": "http error"}
        return error.code, payload, (time.perf_counter() - started) * 1000
    except (OSError, TimeoutError) as error:
        return 0, {"error": str(error)}, (time.perf_counter() - started) * 1000


def send_batch(run: dict[str, Any], conversation: str, items: list[tuple[str, dict[str, Any]]], workers: int) -> list[dict[str, Any]]:
    def one(item: tuple[str, dict[str, Any]]) -> dict[str, Any]:
        key, body = item
        status, payload, latency = call(
            run,
            f"/conversations/{conversation}/messages",
            body,
            key,
        )
        data = payload.get("data", payload)
        return {
            "key": key,
            "http": status,
            "replayed": bool(data.get("replayed")),
            "sequence": data.get("sequence"),
            "message_id": data.get("message_id"),
            "latency_ms": latency,
            "error": payload.get("code") or payload.get("error"),
        }

    out: list[dict[str, Any]] = []
    for offset in range(0, len(items), workers * 4):
        batch = items[offset : offset + workers * 4]
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
            out.extend(pool.map(one, batch))
    return out


def stop_candidate(run: dict[str, Any]) -> None:
    pid = int(run["pid"])
    cmdline = Path(f"/proc/{pid}/cmdline")
    if not cmdline.exists() or b"forgeflow-server" not in cmdline.read_bytes():
        raise RuntimeError(f"candidate PID {pid} is not the expected forgeflow-server")
    os.kill(pid, signal.SIGTERM)
    for _ in range(200):
        if not Path(f"/proc/{pid}").exists():
            return
        time.sleep(0.1)
    raise RuntimeError("candidate did not stop after SIGTERM")


def restart_candidate(candidate_output: Path) -> None:
    root = Path(__file__).resolve().parents[2]
    env = os.environ.copy()
    # Preserve the opt-in dispatcher mode across the controlled restart. The
    # candidate setup script intentionally strips FORGEFLOW_* variables by
    # default, so a restart must carry this explicit probe contract forward.
    env["FORGEFLOW_ECP_DISPATCHER_ENABLED"] = "1"
    subprocess.run(
        [
            "python3",
            str(root / "verification/accounts_network_check.py"),
            "restart",
            "--output",
            str(candidate_output),
        ],
        check=True,
        timeout=180,
        env=env,
    )


def consumer_pending(database: str, conversation: str) -> list[tuple[str, int, str, int | None]]:
    with psycopg.connect(PG + " dbname=" + database) as db:
        return [
            (row[0], int(row[1]), row[2], int(row[3]) if row[3] is not None else None)
            for row in db.execute(
                """
                SELECT d.delivery_id,d.attempt_count,d.state,latest.generation
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
                 LIMIT 256
                """,
                (conversation,),
            ).fetchall()
        ]


def consumer_delivery(database: str, delivery_id: str) -> tuple[str, int, str | None, int | None] | None:
    with psycopg.connect(PG + " dbname=" + database) as db:
        row = db.execute(
            """
            SELECT d.state,d.attempt_count,latest.generation,d.recipient_principal_id
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
    return row[0], int(row[1]), row[2], row[3]


def consumer_counts(database: str, conversation: str) -> dict[str, int]:
    with psycopg.connect(PG + " dbname=" + database) as db:
        rows = db.execute(
            """
            SELECT d.state,count(*)
              FROM ecp_deliveries d
              JOIN ecp_messages m ON m.message_id=d.message_id
             WHERE m.conversation_id=%s
             GROUP BY d.state ORDER BY d.state
            """,
            (conversation,),
        ).fetchall()
    return {state: int(count) for state, count in rows}


def run_external_consumer(
    *,
    run: dict[str, Any],
    token: str,
    conversation: str,
    stop: threading.Event,
    report: dict[str, Any],
    poll_seconds: float,
    timeout_seconds: float,
    workers: int,
    max_retries: int,
) -> None:
    started = time.monotonic()
    stats = {"scanned": 0, "claimed": 0, "acked": 0, "replayed": 0, "failed": 0}
    while not stop.is_set() and time.monotonic() - started < timeout_seconds:
        rows = consumer_pending(run["database"], conversation)
        if not rows:
            counts = consumer_counts(run["database"], conversation)
            if counts and set(counts) <= {"ACKED"}:
                break
            time.sleep(poll_seconds)
            continue
        stats["scanned"] += len(rows)
        consumer_run = {**run, "token": token}
        def consume_one(row: tuple[str, int, str, int | None]) -> dict[str, Any]:
            delivery_id = row[0]
            result = {"claimed": 0, "acked": 0, "replayed": 0,
                      "failed": 0}
            for retry in range(max_retries):
                current = consumer_delivery(run["database"], delivery_id)
                if current is None or current[0] in {"ACKED", "DEAD_LETTER", "EXPIRED", "REVOKED"}:
                    if current is not None and current[0] == "ACKED":
                        result["acked"] = 1
                    else:
                        result["failed"] = 1
                    return result
                state, attempt_count, current_generation, _recipient = current
                direct_receipt = state == "IN_FLIGHT" and current_generation is not None
                generation = int(current_generation) if direct_receipt else max(1, attempt_count + 1)
                if not direct_receipt:
                    ckey = f"ecp-dispatcher-claim-{delivery_id}-{generation}"
                    status, payload, _ = call(
                        consumer_run,
                        f"/deliveries/{delivery_id}/claim",
                        {"request_key": ckey, "generation": generation},
                        ckey,
                    )
                    if status >= 300 or status == 0:
                        if retry + 1 < max_retries:
                            time.sleep(0.05 * (retry + 1))
                            continue
                        result["failed"] = 1
                        return result
                    data = payload.get("data", payload)
                    generation = int(data.get("generation", generation))
                    if bool(data.get("replayed")):
                        result["replayed"] = 1
                    else:
                        result["claimed"] = 1
                receipt_key = f"ecp-dispatcher-receipt-{delivery_id}-{generation}"
                status, _, _ = call(
                    consumer_run,
                    f"/deliveries/{delivery_id}/receipts",
                    {
                        "request_key": receipt_key,
                        "receipt_kind": "RECEIVED",
                        "data": {"consumer": "phase3-100k-external-consumer", "generation": generation},
                    },
                    receipt_key,
                )
                if status < 300 and status != 0:
                    result["acked"] = 1
                    return result
                if retry + 1 < max_retries:
                    time.sleep(0.05 * (retry + 1))
                    continue
                result["failed"] = 1
                return result
            result["failed"] = 1
            return result

        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
            for result in pool.map(consume_one, rows):
                for key in ("claimed", "acked", "replayed", "failed"):
                    stats[key] += result[key]
        if poll_seconds:
            time.sleep(poll_seconds)
    report.update({"stats": stats, "final_counts": consumer_counts(run["database"], conversation), "elapsed_seconds": time.monotonic() - started})


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--candidate-output", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--messages", type=int, default=100_000)
    parser.add_argument("--duplicate-percent", type=int, default=10)
    parser.add_argument("--reorder-percent", type=int, default=10)
    parser.add_argument("--partition-seconds", type=int, default=60)
    parser.add_argument("--workers", type=int, default=128)
    parser.add_argument("--batch-size", type=int, default=512)
    parser.add_argument("--external-consumer", action="store_true")
    parser.add_argument("--consumer-poll-seconds", type=float, default=0.25)
    parser.add_argument("--consumer-timeout-seconds", type=float, default=300.0)
    parser.add_argument("--consumer-workers", type=int, default=64)
    parser.add_argument("--consumer-max-retries", type=int, default=4)
    parser.add_argument("--run", action="store_true")
    args = parser.parse_args()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    report: dict[str, Any] = {
        "schema_version": "forgeflow.ecp-phase3-100k-fault-campaign.v1",
        "scope": "ECP_PHASE3_100K_MESSAGE_FAULT_CAMPAIGN",
        "status": "NOT_RUN",
        "qualification": "NOT_RUN",
        "product_gate_effect": "NONE",
        "model_calls": 0,
        "requested": {
            "logical_messages": args.messages,
            "duplicate_percent": args.duplicate_percent,
            "reorder_percent": args.reorder_percent,
            "partition_seconds": args.partition_seconds,
            "workers": args.workers,
        },
        "fault_model": {
            "dispatcher_process": "absent in current runtime",
            "dispatcher_restart_substitute": "candidate forgeflow-server restart",
            "network_partition": "candidate HTTP outage during controlled restart",
        },
    }
    if not args.run:
        report["reason"] = "campaign requires explicit --run"
        args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n")
        return 0
    if not (0 < args.messages <= 100_000):
        report.update({"status": "FAIL", "reason": "messages must be between 1 and 100000"})
        args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n")
        return 20
    if args.duplicate_percent != 10 or args.reorder_percent != 10 or args.partition_seconds != 60:
        report.update({"status": "FAIL", "reason": "this qualification harness requires exactly 10/10/60 fault parameters"})
        args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n")
        return 20
    if not (1 <= args.consumer_workers <= 128 and 1 <= args.consumer_max_retries <= 8):
        report.update({"status": "FAIL", "reason": "consumer workers/retries outside bounded harness limits"})
        args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n")
        return 20

    candidate_output = args.candidate_output.resolve()
    run = json.loads((candidate_output / "private.json").read_text())
    run["workspace"] = ""
    actual_base = run["base"]
    proxy = FaultProxy(actual_base)
    run["base"] = proxy.url
    try:
        email = f"ecp-g3-{uuid.uuid4().hex[:10]}@example.test"
        password = uuid.uuid4().hex + uuid.uuid4().hex
        status, payload, _ = call({**run, "workspace": ""}, "/registrations", {"email": email, "display_name": "ECP-G3-100k", "password": password})
        if status >= 300:
            raise RuntimeError(f"registration failed: {status} {payload}")
        account = payload.get("data", payload)
        run["token"] = account["token"]
        run["workspace"] = account["account"]["workspace_id"]
        principal = "human:" + account["account"]["account_id"]
        recipient_email = f"ecp-g3-recipient-{uuid.uuid4().hex[:10]}@example.test"
        recipient_password = uuid.uuid4().hex + uuid.uuid4().hex
        recipient_status, recipient_payload, _ = call(
            {**run, "workspace": ""},
            "/registrations",
            {"email": recipient_email, "display_name": "ECP-G3-recipient", "password": recipient_password},
        )
        if recipient_status >= 300:
            raise RuntimeError(f"recipient registration failed: {recipient_status} {recipient_payload}")
        recipient_account = recipient_payload.get("data", recipient_payload)
        recipient_run = {**run, "token": recipient_account["token"]}
        invitation_status, invitation_payload, _ = call(
            run,
            f"/workspaces/{run['workspace']}/invitations",
            {"role": "EDITOR", "email": recipient_email},
        )
        if invitation_status >= 300:
            raise RuntimeError(f"recipient invitation failed: {invitation_status} {invitation_payload}")
        invitation = invitation_payload.get("data", invitation_payload)
        accepted_status, accepted_payload, _ = call(
            recipient_run,
            "/invitations/accept",
            {"token": invitation["invite_token"]},
        )
        if accepted_status >= 300:
            raise RuntimeError(f"recipient invitation acceptance failed: {accepted_status} {accepted_payload}")
        recipient_principal = "human:" + recipient_account["account"]["account_id"]
        conversation = "g3-conversation-" + uuid.uuid4().hex
        ckey = "g3-conversation-create-" + uuid.uuid4().hex
        status, payload, _ = call(
            run,
            f"/workspaces/{run['workspace']}/conversations",
            {
                "conversation_id": conversation,
                "project_id": None,
                "participant_principal_ids": [principal, recipient_principal],
                "request_key": ckey,
            },
            ckey,
        )
        if status >= 300:
            raise RuntimeError(f"conversation setup failed: {status} {payload}")
        thread = "g3-thread-" + uuid.uuid4().hex
        tkey = "g3-thread-create-" + uuid.uuid4().hex
        status, payload, _ = call(
            run,
            f"/conversations/{conversation}/threads",
            {"thread_id": thread, "task_id": None, "request_key": tkey},
            tkey,
        )
        if status >= 300:
            raise RuntimeError(f"thread setup failed: {status} {payload}")

        consumer_stop = threading.Event()
        consumer_report: dict[str, Any] = {}
        consumer_thread: threading.Thread | None = None
        if args.external_consumer:
            # Let the opt-in dispatcher claim first; the consumer still fences
            # a stale attempt by advancing its generation through the public API.
            time.sleep(2)
            consumer_thread = threading.Thread(
                target=run_external_consumer,
                kwargs={
                    "run": run,
                    "token": recipient_account["token"],
                    "conversation": conversation,
                    "stop": consumer_stop,
                    "report": consumer_report,
                    "poll_seconds": args.consumer_poll_seconds,
                    "timeout_seconds": args.consumer_timeout_seconds,
                    "workers": args.consumer_workers,
                    "max_retries": args.consumer_max_retries,
                },
                daemon=True,
            )
            consumer_thread.start()

        keys = [f"g3-message-{index:06d}-{uuid.uuid4().hex[:12]}" for index in range(args.messages)]
        bodies = [
            (
                key,
                {
                    "thread_id": thread,
                    "message_kind": "chat.message",
                    "client_request_id": key,
                    "payload": {"text": f"g3-{index}", "logical_index": index},
                    "correlation_id": None,
                    "causation_id": None,
                    "expires_at": None,
                },
            )
            for index, key in enumerate(keys)
        ]
        reorder_count = args.messages * args.reorder_percent // 100
        order = list(range(args.messages))
        for index in range(0, reorder_count - 1, 2):
            order[index], order[index + 1] = order[index + 1], order[index]
        ordered = [bodies[index] for index in order]
        split = args.messages // 2
        first = send_batch(run, conversation, ordered[:split], args.workers)
        report["initial_first_half"] = {
            "submitted": len(first),
            "accepted": sum(row["http"] < 300 for row in first),
            "failed": sum(row["http"] >= 300 for row in first),
        }

        old_pid = int(run["pid"])
        outage_started = time.time()
        fault_event = proxy.disconnect(args.partition_seconds)
        probe_status, probe_payload, _ = call(run, "/projects", timeout=3)
        time.sleep(args.partition_seconds)
        stop_candidate(run)
        restart_candidate(candidate_output)
        run = json.loads((candidate_output / "private.json").read_text())
        run["base"] = proxy.url
        run["token"] = account["token"]
        run["workspace"] = account["account"]["workspace_id"]
        report["fault_injection"] = {
            "candidate_pid_before": old_pid,
            "candidate_pid_after": run.get("pid"),
            "partition_seconds_requested": args.partition_seconds,
            "partition_seconds_observed": round(time.time() - outage_started, 3),
            "outage_probe_http": probe_status,
            "outage_probe_failed": probe_status == 0,
            "dispatcher_restart_substitute": True,
            "tcp_fault_proxy": fault_event,
            "tcp_fault_proxy_metadata": proxy.metadata(),
        }
        second = send_batch(run, conversation, ordered[split:], args.workers)
        initial = first + second
        duplicates = [bodies[index] for index in range(0, args.messages, 10)]
        retries = send_batch(run, conversation, duplicates, args.workers)

        # Give the external consumer a bounded window to drain the durable
        # delivery/outbox state before taking the independent oracle snapshot.
        if consumer_thread is not None:
            consumer_thread.join(timeout=args.consumer_timeout_seconds)
            if consumer_thread.is_alive():
                consumer_stop.set()
                consumer_thread.join(timeout=30)

        with psycopg.connect(PG + " dbname=" + run["database"], autocommit=True) as db:
            message_count, unique_count = db.execute(
                "SELECT count(*), count(DISTINCT client_request_id) FROM ecp_messages WHERE conversation_id=%s",
                (conversation,),
            ).fetchone()
            delivery_count = db.execute(
                "SELECT count(*) FROM ecp_deliveries d JOIN ecp_messages m ON m.message_id=d.message_id WHERE m.conversation_id=%s",
                (conversation,),
            ).fetchone()[0]
            state_rows = db.execute(
                "SELECT d.state,count(*) FROM ecp_deliveries d JOIN ecp_messages m ON m.message_id=d.message_id WHERE m.conversation_id=%s GROUP BY d.state ORDER BY d.state",
                (conversation,),
            ).fetchall()
            outbox_pending = db.execute(
                "SELECT count(*) FROM ecp_message_outbox o JOIN ecp_messages m ON m.message_id=o.message_id WHERE m.conversation_id=%s AND o.delivered_at IS NULL",
                (conversation,),
            ).fetchone()[0]
            rows = db.execute(
                "SELECT (payload->>'logical_index')::int, sequence FROM ecp_messages WHERE conversation_id=%s ORDER BY sequence",
                (conversation,),
            ).fetchall()
        reorder_observed = sum(1 for position, (logical, _sequence) in enumerate(rows) if logical != position)
        accepted = sum(row["http"] < 300 and not row["replayed"] for row in initial)
        initial_failed = sum(row["http"] >= 300 for row in initial)
        replayed = sum(row["http"] < 300 and row["replayed"] for row in retries)
        report.update(
            {
                "status": "INCONCLUSIVE",
                "qualification": "INCONCLUSIVE",
                "conversation_id": conversation,
                "thread_id": thread,
                "denominator": {
                    "logical_messages": args.messages,
                    "initial_attempts": len(initial),
                    "initial_accepted": accepted,
                    "initial_failed": initial_failed,
                    "duplicate_attempts": len(retries),
                    "duplicate_replayed": replayed,
                    "message_rows": message_count,
                    "unique_client_request_ids": unique_count,
                    "delivery_rows": delivery_count,
                    "reorder_target": reorder_count,
                    "reorder_observed": reorder_observed,
                },
                "delivery_states": {state: count for state, count in state_rows},
                "outbox_pending": outbox_pending,
                "criteria": {
                    "all_initial_messages_accepted": accepted == args.messages,
                    "duplicate_business_submissions_zero": message_count == unique_count == args.messages,
                    "duplicate_retries_replayed": replayed == len(retries),
                    "ten_percent_reorder_observed": reorder_observed >= reorder_count,
                    "sixty_second_outage_probe_failed": report["fault_injection"]["outage_probe_failed"],
                    "server_restart_reconnected": run.get("pid") != old_pid,
                    # An empty delivery query is not evidence of a drained
                    # outbox.  Require at least one durable delivery row
                    # before accepting the ACK-state predicate; otherwise a
                    # missing dispatcher/outbox projection could pass by
                    # vacuous truth.
                    "outbox_drained_within_five_minutes": bool(state_rows)
                    and delivery_count > 0
                    and outbox_pending == 0
                    and all(state == "ACKED" for state, _ in state_rows),
                },
                "limitations": [
                    "Current runtime has no independent dispatcher process; candidate server restart is the explicit substitute.",
                    "Outbox drain criterion is reported from the observed delivery states and is not converted into a Gate decision.",
                    "ECP-G3 remains NOT_RUN until an authorized independent verifier accepts the full fault evidence.",
                ],
            }
        )
        if consumer_thread is not None:
            consumer_stop.set()
            consumer_thread.join(timeout=30)
            report["external_consumer"] = consumer_report
    except Exception as error:
        report.update({"status": "FAIL", "qualification": "INCONCLUSIVE", "error": f"{type(error).__name__}: {error}"})
    finally:
        proxy.close()
    args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n")
    print(json.dumps({"status": report["status"], "model_calls": 0, "output": str(args.output)}))
    return 0 if report["status"] in {"PASS", "NOT_RUN", "INCONCLUSIVE"} else 20


if __name__ == "__main__":
    raise SystemExit(main())
