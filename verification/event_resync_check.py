#!/usr/bin/env python3
"""One readonly actual-browser recovery of an authority-rejected event cursor.

This does not qualify a database restore, retention policy or production load.
The server rejection and snapshot come from the actual PostgreSQL-backed API.
"""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

sys.dont_write_bytecode = True


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def run(args):
    from playwright.sync_api import sync_playwright
    output = args.output
    output.mkdir(parents=True, exist_ok=True)
    if any(output.iterdir()):
        raise RuntimeError("Original evidence is retained; select a fresh output directory.")
    private = json.loads(args.private_env.read_text())
    token = private["FORGEFLOW_OWNER_TOKEN"]
    base = args.url.rstrip("/")
    report = {"status": "RUNNING", "scope": __doc__, "checks": [], "http": [],
              "browser_errors": [], "business_writes": 0, "models_started": 0,
              "workers_started": 0, "credentials_recorded": False,
              "driver_sha256": sha(__file__), "frontend_index_sha256": sha(args.frontend_dir / "index.html")}

    def check(name, ok, **facts):
        report["checks"].append({"name": name, "status": "PASS" if ok else "FAIL", **facts})
        if not ok:
            raise RuntimeError(name)

    def api(route):
        request = urllib.request.Request(base + "/api/v1" + route,
                                         headers={"Authorization": "Bearer " + token})
        with urllib.request.urlopen(request, timeout=20) as response:
            return json.loads(response.read())

    try:
        receipt = json.loads(args.server_receipt.read_text())
        pid = int(subprocess.check_output(["systemctl", "--user", "show", "forgeflow-control.service",
                                          "--property=MainPID", "--value"], text=True).strip())
        executable_sha = sha(Path("/proc") / str(pid) / "exe")
        check("actual_main_server_pin", executable_sha == receipt["binaries"]["forgeflow-server"]["sha256"])
        report.update(server_pid=pid, server_source_identity=receipt["source_identity"],
                      server_receipt_sha256=sha(args.server_receipt))
        projects = api("/projects?limit=500")["data"]
        project = args.project_id or next(row["project_id"] for row in projects if not row.get("archived"))
        before = api("/projects/" + urllib.parse.quote(project, safe="") + "/snapshot")
        head = before["read_model_version"]
        check("actual_snapshot_identity_and_watermark", before["data"]["project"]["project_id"] == project
              and isinstance(head, int) and head == before["data"]["revision"])
        report.update(project_id=project, initial_authority_watermark=head, deliberately_old_cursor=head + 1000000)
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(headless=True, executable_path=args.executable)
            context = browser.new_context(viewport={"width": 1440, "height": 1000})
            context.add_init_script("sessionStorage.setItem('forgeflow.owner-token'," + json.dumps(token) + ");"
                + "sessionStorage.setItem(" + json.dumps("forgeflow.cursor." + project) + ","
                + json.dumps(project + ":" + str(head + 1000000)) + ");"
                + "window.__actualResync=[];window.addEventListener('forgeflow-resync',e=>"
                + "window.__actualResync.push({...e.detail,at:performance.now()}));")
            page = context.new_page()
            page.on("pageerror", lambda error: report["browser_errors"].append(type(error).__name__))

            def response_seen(response):
                path = urllib.parse.urlsplit(response.url).path
                if path.startswith("/api/v1"):
                    report["http"].append({"path": path, "method": response.request.method,
                                           "status": response.status, "at_monotonic": time.monotonic()})
            page.on("response", response_seen)
            response = page.goto(base + "/projects/" + urllib.parse.quote(project, safe="") + "/runs",
                                 wait_until="domcontentloaded", timeout=30000)
            check("actual_built_console_served", response.status == 200 and
                  hashlib.sha256(response.body()).hexdigest() == report["frontend_index_sha256"])
            page.wait_for_function("window.__actualResync.length===1", timeout=15000)
            page.get_by_text("事件已连接", exact=True).wait_for(timeout=20000)
            resync = page.evaluate("window.__actualResync")
            report["resync"] = resync
            cursor = page.evaluate("sessionStorage.getItem(" + json.dumps("forgeflow.cursor." + project) + ")")
            check("one_real_snapshot_resync_and_new_cursor", len(resync) == 1 and resync[0]["projectId"] == project
                  and resync[0]["readModelVersion"] == head and cursor == project + ":" + str(head), cursor=cursor)
            rejected = [entry for entry in report["http"] if entry["path"].endswith("/events") and entry["status"] == 409]
            reopened = [entry for entry in report["http"] if entry["path"].endswith("/events") and entry["status"] == 200]
            snapshots = [entry for entry in report["http"] if entry["path"].endswith("/snapshot") and entry["status"] == 200]
            check("real_409_snapshot_200_reconnect_order", len(rejected) == 1 and len(reopened) == 1
                  and any(rejected[0]["at_monotonic"] < entry["at_monotonic"] < reopened[0]["at_monotonic"] for entry in snapshots))
            check("readonly_browser_requests", all(entry["method"] == "GET" for entry in report["http"]))
            check("no_unexpected_browser_or_http_errors", not report["browser_errors"]
                  and all(entry["status"] < 400 or entry in rejected for entry in report["http"]))
            page.screenshot(path=str(output / "reconnected.png"))
            context.close()
            browser.close()
        after = api("/projects/" + urllib.parse.quote(project, safe="") + "/snapshot")
        check("authority_business_facts_unchanged", all(after["data"].get(key) == before["data"].get(key)
              for key in ["project", "tasks", "attempts", "native_model_requests", "resource_limits"])
              and after["read_model_version"] == head)
        report["status"] = "PASS_SCOPED_ACTUAL_BROWSER_RESYNC"
    except Exception as error:
        report.update(status="FAIL", failure={"type": type(error).__name__, "message": str(error).splitlines()[0][:160]})
    finally:
        report["screenshots"] = [{"path": path.name, "sha256": sha(path)} for path in output.glob("*.png")]
        (output / "report.json").write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n")
    print(json.dumps({"status": report["status"], "checks": len(report["checks"]), "models_started": 0,
                      "workers_started": 0, "output": str(output)}))
    return 0 if report["status"].startswith("PASS") else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", action="store_true")
    parser.add_argument("--url", required=True)
    parser.add_argument("--private-env", required=True, type=Path)
    parser.add_argument("--server-receipt", required=True, type=Path)
    parser.add_argument("--frontend-dir", required=True, type=Path)
    parser.add_argument("--project-id")
    parser.add_argument("--executable", default="/usr/bin/chromium")
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    if not args.run:
        print(json.dumps({"status": "SOURCE_READY_NOT_EXECUTED", "models_started": 0, "workers_started": 0}))
        return 0
    return run(args)


if __name__ == "__main__":
    raise SystemExit(main())
