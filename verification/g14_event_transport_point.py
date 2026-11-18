#!/usr/bin/env python3
"""One real-browser duplicate/out-of-order transport point using unchanged API frames.

This is transport fault injection, not invented authority or a retention/restore test.
Preparation launches no actors. Execution requires Root GO for this exact plan.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import time
import urllib.request

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "benchmarks"))
from guarded_api_chain import database_command

CHROME = "/home/chenyoujian/.cache/ms-playwright/chromium-1247/chrome-linux64/chrome"
STATE_SQL = "SELECT json_build_object('projects',(SELECT count(*) FROM projects),'tasks',(SELECT count(*) FROM tasks),'attempts',(SELECT count(*) FROM attempts),'workers',(SELECT count(*) FROM workers),'leases',(SELECT count(*) FROM leases),'events',(SELECT count(*) FROM events),'commands',(SELECT count(*) FROM idempotency_records),'native_models',(SELECT count(*) FROM native_model_requests))"


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def save(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n")


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--run", action="store_true")
    p.add_argument("--build-receipt", type=Path, required=True)
    p.add_argument("--frontend-receipt", type=Path, required=True)
    p.add_argument("--private-env", type=Path, required=True)
    p.add_argument("--project-id", required=True)
    p.add_argument("--output", type=Path, required=True)
    a = p.parse_args()
    build = json.loads(a.build_receipt.read_text())
    front = json.loads(a.frontend_receipt.read_text())
    env = json.loads(a.private_env.read_text())
    binary = build["binaries"]["forgeflow-server"]
    dist = Path(front["dist_path"])
    if sha(binary["path"]) != binary["sha256"]:
        raise RuntimeError("frozen ELF mismatch")
    for path, pin in front["files"].items():
        if sha(dist / path) != pin["sha256"]:
            raise RuntimeError("frozen frontend mismatch")
    if env["FORGEFLOW_BIND"] != "127.0.0.1:8897" or a.project_id != "g04-render-9666d58aef83":
        raise RuntimeError("requires exact existing private metadata fixture")
    plan = {"status": "PREPARED_NOT_EXECUTED", "driver_sha256": sha(__file__),
        "build_receipt_sha256": sha(a.build_receipt), "source_identity": build["source_identity"],
        "server": binary, "frontend_receipt_sha256": sha(a.frontend_receipt),
        "index_sha256": sha(dist / "index.html"), "browser": CHROME, "browser_sha256": sha(CHROME),
        "private_env": str(a.private_env), "project_id": a.project_id,
        "actor": "one private API8897 and one Chromium, terminated in finally; no new DB/metadata/Worker/model",
        "transport": "exact real API frames [2,2,1,3,5,4] from initial cursor1; only first browser SSE response intercepted",
        "oracle": "dispatch [2,3] exactly once; one real snapshot resync/head cursor; subsequent real event reconnect; authority counts/Flow/task definitions unchanged",
        "not_proven": ["retention expiration", "database restored-head", "slow-client heartbeat isolation", "runs history hook (no attempt created)"],
        "existing_proofs_not_repeated": ["event-resync-r1 409 recovery", "replay-batched-r1 7100 frames", "sse-checkpoint-watermark reconnect"]}
    if not a.run:
        save(a.output / "plan.json", plan)
        print(json.dumps({"status": plan["status"], "driver_sha256": plan["driver_sha256"]}))
        return 0
    previous = json.loads((a.output / "plan.json").read_text())
    if previous != plan or (a.output / "report.json").exists():
        raise RuntimeError("exact prepared plan required; original result must never be overwritten")
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 8897))
    env["FORGEFLOW_CONSOLE_DIR"] = str(dist)
    base = "http://127.0.0.1:8897"
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    report = {"status": "FAIL", "plan": plan, "checks": [], "http": [], "browser_errors": [],
              "business_writes": 0, "models_started": 0, "workers_started": 0, "main_changed": False}
    server = browser = log = None

    def check(name, ok, **facts):
        report["checks"].append({"name": name, "status": "PASS" if ok else "FAIL", **facts})
        if not ok:
            raise RuntimeError(name)

    def get(path):
        request = urllib.request.Request(base + path, headers={"Authorization": "Bearer " + env["FORGEFLOW_OWNER_TOKEN"]})
        with opener.open(request, timeout=15) as response:
            return json.loads(response.read())

    def counts():
        value = database_command(env["DATABASE_URL"], STATE_SQL)
        if value.returncode:
            raise RuntimeError("private readonly count query failed")
        return json.loads(value.stdout)

    try:
        report["authority_before"] = counts()
        check("no_execution_actors_in_existing_fixture", all(report["authority_before"][k] == 0 for k in ["attempts", "workers", "leases", "native_models"]))
        log = os.fdopen(os.open(a.output / "private-api.log", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb")
        server = subprocess.Popen([binary["path"]], env={"PATH": "/usr/bin:/bin", **env}, stdout=log, stderr=subprocess.STDOUT)
        report["private_api_pid"] = server.pid
        deadline = time.monotonic() + 30
        while True:
            if server.poll() is not None:
                raise RuntimeError("private API exited")
            try:
                get("/healthz")
                break
            except Exception:
                if time.monotonic() > deadline:
                    raise
                time.sleep(.2)
        check("live_frozen_server_pin", sha(f"/proc/{server.pid}/exe") == binary["sha256"])
        project_path = "/api/v1/projects/" + a.project_id
        before = get(project_path + "/snapshot")
        head = before["read_model_version"]
        check("paused_real_metadata_fixture", before["data"]["project"]["paused"] is True and head >= 5)
        flow_before = get(project_path + "/flows/1")["data"]
        frames = []
        request = urllib.request.Request(base + project_path + "/events?after=0",
            headers={"Authorization": "Bearer " + env["FORGEFLOW_OWNER_TOKEN"], "Accept": "text/event-stream"})
        with opener.open(request, timeout=15) as response:
            frame = b""
            while len(frames) < 5:
                line = response.readline()
                if not line:
                    raise RuntimeError("real event stream ended before five frames")
                frame += line
                if line in [b"\n", b"\r\n"]:
                    if b"data:" in frame:
                        frames.append(frame)
                    frame = b""
        raw = b"".join(frames)
        (a.output / "authority-original.sse").write_bytes(raw)
        facts = [json.loads(next(line[5:].strip() for line in f.splitlines() if line.startswith(b"data:"))) for f in frames]
        check("frames_are_real_contiguous_project_facts", [e["project_seq"] for e in facts] == [1,2,3,4,5]
              and all(e["project_id"] == a.project_id for e in facts))
        transport = b"".join(frames[i-1] for i in [2,2,1,3,5,4])
        (a.output / "transport-permuted.sse").write_bytes(transport)
        report["transport"] = {"original_sha256": hashlib.sha256(raw).hexdigest(),
            "permuted_sha256": hashlib.sha256(transport).hexdigest(), "order": [2,2,1,3,5,4],
            "event_ids": [e["event_id"] for e in facts], "authority_head": head}
        from playwright.sync_api import sync_playwright
        with sync_playwright() as pw:
            browser = pw.chromium.launch(headless=True, executable_path=CHROME, args=["--no-proxy-server"])
            context = browser.new_context(viewport={"width":1440,"height":1000})
            context.add_init_script("sessionStorage.setItem('forgeflow.owner-token'," + json.dumps(env["FORGEFLOW_OWNER_TOKEN"]) + ");"
                + "sessionStorage.setItem(" + json.dumps("forgeflow.cursor." + a.project_id) + "," + json.dumps(a.project_id + ":1") + ");"
                + "window.__observedEvents=[];window.__observedResync=[];"
                + "window.addEventListener('forgeflow-event',e=>window.__observedEvents.push({detail:e.detail,stored:sessionStorage.getItem('forgeflow.cursor.'+e.detail.projectId)}));"
                + "window.addEventListener('forgeflow-resync',e=>window.__observedResync.push(e.detail));")
            page = context.new_page()
            page.on("pageerror", lambda e: report["browser_errors"].append(type(e).__name__))
            def response_seen(response):
                if "/api/v1/" in response.url:
                    report["http"].append({"path": response.url.split(base)[-1], "method": response.request.method,
                        "status": response.status, "at": time.monotonic()})
            page.on("response", response_seen)
            injections = []
            def intercept(route):
                if not injections:
                    injections.append(route.request.url)
                    route.fulfill(status=200, content_type="text/event-stream", body=transport)
                else:
                    route.continue_()
            page.route("**/api/v1/projects/" + a.project_id + "/events?*", intercept)
            response = page.goto(base + "/projects/" + a.project_id + "/flows/1", wait_until="domcontentloaded")
            check("actual_pinned_frontend_rendered", sha(dist / "index.html") == hashlib.sha256(response.body()).hexdigest())
            page.wait_for_function("window.__observedResync.length===1", timeout=15000)
            page.get_by_text("事件已连接", exact=True).wait_for(timeout=20000)
            events = page.evaluate("window.__observedEvents")
            resync = page.evaluate("window.__observedResync")
            cursor = page.evaluate("sessionStorage.getItem(" + json.dumps("forgeflow.cursor." + a.project_id) + ")")
            report.update(browser_events=events, browser_resync=resync, final_cursor=cursor)
            check("duplicate_backward_frames_never_regress_or_overwrite", [e["detail"]["event"]["project_seq"] for e in events] == [2,3]
                and [e["detail"]["event"] for e in events] == facts[1:3]
                and [e["stored"] for e in events] == [a.project_id + ":2", a.project_id + ":3"])
            check("forward_gap_explicit_real_snapshot_resync", len(resync) == 1 and resync[0]["readModelVersion"] == head
                and cursor == a.project_id + ":" + str(head))
            snapshots = [h for h in report["http"] if "/snapshot" in h["path"] and h["status"] == 200]
            check("real_snapshot_then_head_reconnect", snapshots and any("/events?after=" + str(head) in h["path"]
                and h["status"] == 200 and h["at"] > snapshots[0]["at"] for h in report["http"]))
            check("rendered_authority_task_titles_survive_resync", all(page.get_by_text(t["title"], exact=True).count() > 0 for t in flow_before["tasks"]))
            check("browser_readonly_no_javascript_errors", not report["browser_errors"] and all(h["method"] == "GET" for h in report["http"]))
            page.screenshot(path=str(a.output / "after-gap-resync.png"))
            context.close()
            browser.close()
            browser = None
        after = get(project_path + "/snapshot")["data"]
        check("authority_flow_and_snapshot_unchanged", get(project_path + "/flows/1")["data"] == flow_before
            and {k:v for k,v in after.items() if k != "as_of"} == {k:v for k,v in before["data"].items() if k != "as_of"})
        report["authority_after"] = counts()
        check("all_private_authority_counts_unchanged", report["authority_after"] == report["authority_before"])
        report["status"] = "PASS_SCOPED_ACTUAL_TRANSPORT_POINT"
    except Exception as e:
        report["failure"] = {"type": type(e).__name__, "message": str(e).splitlines()[0][:180]}
    finally:
        if browser:
            browser.close()
        if server:
            server.terminate()
            try:
                server.wait(timeout=20)
            except subprocess.TimeoutExpired:
                server.kill()
                server.wait(timeout=10)
            report["private_api_exit_code"] = server.returncode
        if log:
            log.close()
        report["artifacts"] = [{"path": f.name, "sha256": sha(f)} for f in a.output.iterdir() if f.is_file() and f.name != "report.json"]
        save(a.output / "report.json", report)
    print(json.dumps({"status": report["status"], "checks": len(report["checks"]), "output": str(a.output)}))
    return 0 if report["status"].startswith("PASS") else 1


if __name__ == "__main__":
    raise SystemExit(main())
