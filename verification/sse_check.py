#!/usr/bin/env python3
"""Real persistent SSE replay assertions independent of the frontend reducer."""
import argparse
import json
import socket
import time
import urllib.error
import urllib.request
from pathlib import Path


def collect(url, token, cursor=None):
    headers = {"Authorization": "Bearer " + token, "Accept": "text/event-stream"}
    if cursor:
        headers["Last-Event-ID"] = cursor
    request = urllib.request.Request(url, headers=headers)
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    events, item = [], {}
    try:
        with opener.open(request, timeout=2) as response:
            status = response.status
            deadline = time.monotonic() + 5
            try:
                while len(events) < 1000 and time.monotonic() < deadline:
                    raw_line = response.readline()
                    if not raw_line:
                        break
                    line = raw_line.decode().rstrip("\r\n")
                    if not line:
                        if "id" in item and "data" in item:
                            events.append({"id": item["id"], "kind": item.get("event"), "data": json.loads(item["data"])})
                        item = {}
                    elif not line.startswith(":") and ":" in line:
                        key, value = line.split(":", 1)
                        item[key] = value.lstrip()
            except (socket.timeout, TimeoutError, OSError):
                pass
            return status, events
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read())


def run(args):
    private = json.loads(Path(args.private_env).read_text())
    token = private["FORGEFLOW_OWNER_TOKEN"]
    url = args.url.rstrip("/") + f"/api/v1/projects/{args.project_id}/events"
    checks = []
    status, events = collect(url + "?after=0", token)
    def check(name, ok, facts):
        checks.append({"name": name, "status": "PASS" if ok else "FAIL", "facts": facts})
    check("real_durable_stream_nonempty", status == 200 and bool(events), {"http_status": status, "events": len(events) if isinstance(events, list) else 0})
    ids = [e["data"]["project_seq"] for e in events] if isinstance(events, list) else []
    check("committed_sequence_unique_strictly_increasing", bool(ids) and ids == sorted(set(ids)), {"sequences": ids})
    replay = []
    if len(events) >= 3:
        cursor = events[-3]["id"]
        replay_status, replay = collect(url, token, cursor)
        watermark = events[-1]["data"]["project_seq"]
        known_tail = [e["id"] for e in replay if e["data"]["project_seq"] <= watermark]
        # Other authorized writers may continue producing events between reads.
        # Compare the exact committed interval we actually observed, and retain
        # newer events separately rather than treating correct publication as loss.
        check("reconnect_exact_missing_committed_tail", replay_status == 200 and known_tail == [e["id"] for e in events[-2:]],
              {"cursor": cursor, "watermark": watermark, "expected": [e["id"] for e in events[-2:]], "actual_within_observed_watermark": known_tail,
               "newer_events": sum(e["data"]["project_seq"] > watermark for e in replay)})
    else:
        checks.append({"name": "reconnect_exact_missing_committed_tail", "status": "INCONCLUSIVE", "facts": {"reason": "fewer than3real events"}})
    wrong_status, wrong = collect(url, token, "wrong-project:1")
    check("cross_project_cursor_requires_snapshot", wrong_status == 409 and wrong.get("code") == "SNAPSHOT_REQUIRED", {"http_status": wrong_status, "response": wrong})
    future_status, future = collect(url, token, args.project_id + ":1000000000000")
    check("future_cursor_explicit_resync_instead_of_silent_gap", future_status == 409 and isinstance(future, dict) and future.get("code") == "SNAPSHOT_REQUIRED",
          {"http_status": future_status, "response": future})
    report = {"scope": "actual committed PostgreSQL event stream and persistent project cursor replay", "project_id": args.project_id,
              "source_revision": args.source_revision, "checks": checks, "initial_events": events, "replayed_events": replay,
              "status": "FAIL" if any(c["status"] == "FAIL" for c in checks) else "INCONCLUSIVE" if any(c["status"] == "INCONCLUSIVE" for c in checks) else "PASS",
              "assertions": len(checks), "failed": sum(c["status"] == "FAIL" for c in checks), "gate_status": "INCONCLUSIVE",
              "not_proven": ["browser reducer duplicate and out-of-order handling", "retained-cursor expiration policy", "slow browser and heartbeat isolation", "G14 full scope"]}
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({k: report[k] for k in ("status", "assertions", "failed", "gate_status")}))


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", required=True)
    parser.add_argument("--private-env", required=True)
    parser.add_argument("--project-id", required=True)
    parser.add_argument("--source-revision", required=True)
    parser.add_argument("--output", required=True)
    run(parser.parse_args())
