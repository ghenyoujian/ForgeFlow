#!/usr/bin/env python3
"""One actual Calendar milestone acceptance journey on the closed 3.7 fixture.

Without --run this prints preparation metadata only. Root schedules execution
after the hour campaign, semantic journey and new build have actually finished.
There is no Worker, model call, automatic whole-flow retry or synthetic receipt.
"""
import argparse
import hashlib
import json
import os
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.dont_write_bytecode = True
import user_journey_check as core

ROOT = Path(__file__).resolve().parents[1]
BASE = "http://127.0.0.1:8794"
TERMINAL = {"SUCCEEDED", "FAILED", "CANCELLED"}


class MilestoneJourney:
    def __init__(self, args):
        self.args, self.out = args, args.output
        self.handoff = json.loads(args.handoff.read_text())
        self.private = json.loads(Path(self.handoff["runtime_env_path"]).read_text())
        self.project = self.handoff["project_id"]
        self.receipt = json.loads(args.build_receipt.read_text())
        self.server, self.server_log, self.page = None, None, None
        self.http, self.js_errors, self.browser_http = [], [], []
        self.checks, self.screenshots = [], []
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        self.secrets = [value for key, value in self.private.items() if isinstance(value, str) and value
            and (key == "DATABASE_URL" or any(word in key.upper() for word in ("TOKEN", "PASSWORD", "SECRET", "API_KEY")))]
        self.report = {"schema_version": "forgeflow.milestone-acceptance-journey.v1", "status": "RUNNING",
            "business_chain": "3.9", "project_id": self.project, "handoff_sha256": core.sha(args.handoff),
            "build_receipt_sha256": core.sha(args.build_receipt), "driver_sha256": core.sha(__file__),
            "new_model_requests": "NOT_YET_OBSERVED", "workers_started": 0, "automatic_flow_retries": 0,
            "credential_values_disclosed": False, "api_bind": "127.0.0.1:8794", "main_8787_untouched": True,
            "formal_scope": "Calendar creation, two immutable baseline acceptances and retained history"}
        self.retained_created = None
        if args.resume_from:
            previous = json.loads(args.resume_from.read_text())
            cleanup = previous.get("cleanup", {})
            if previous.get("status") != "FAIL" or previous.get("failure") != {"type": "RuntimeError", "message": "Actual browser command HTTP 422 EVIDENCE_BINDING_MISMATCH"} \
                    or previous.get("new_model_requests") != 0 or previous.get("workers_started") != 0 \
                    or not all(cleanup.get(key) is True for key in ("server_stopped", "port8794_closed", "quiescent")):
                raise RuntimeError("Point continuation requires the retained closed descriptor-mismatch failure.")
            retained = []
            for entry in previous["http"]:
                if entry["origin"] != "ACTUAL_BROWSER_COMMAND": continue
                file = args.resume_from.parent / entry["file"]
                if core.sha(file) != entry["sha256"]: raise RuntimeError("Original browser command evidence changed.")
                retained.append((file, json.loads(file.read_text())))
            created = next((pair for pair in retained if pair[1]["route"] == f"/projects/{self.project}/milestones" and pair[1]["status"] == 200), None)
            rejected = next((pair for pair in retained if pair[1]["status"] == 422 and pair[1]["response"].get("code") == "EVIDENCE_BINDING_MISMATCH"
                and pair[1]["response"].get("message") == "candidate raw artifact descriptor differs from the verified receipt"), None)
            if not created or not rejected or len(retained) != 2:
                raise RuntimeError("Continue exactly one actual creation and its rejected first acceptance.")
            self.retained_created = created[1]["response"]["data"]
            if self.retained_created["project_id"] != self.project or self.retained_created["baseline_version"] != 1 \
                    or self.retained_created["required_work_packages"] != [self.handoff["task_id"]] \
                    or self.retained_created["required_gate_ids"] != [self.handoff["verification_plan_id"]] \
                    or rejected[1]["route"] != f"/projects/{self.project}/milestones/{self.retained_created['milestone_id']}/accept" \
                    or rejected[1]["request_body"] != {"baseline_version": 1, "expected_revision": self.retained_created["revision"]}:
                raise RuntimeError("Retained milestone and rejected command do not bind this actual semantic task.")
            self.report["point_continuation"] = {"original_failed_report": str(args.resume_from), "sha256": core.sha(args.resume_from),
                "actual_creation_response": str(created[0]), "creation_sha256": core.sha(created[0]),
                "actual_rejected_acceptance": str(rejected[0]), "rejection_sha256": core.sha(rejected[0]),
                "original_status_preserved": "FAIL", "new_milestone_creation_commands": 0,
                "milestone_id": self.retained_created["milestone_id"]}

    def redacted(self, value):
        if isinstance(value, dict): return {key: self.redacted(item) for key, item in value.items()}
        if isinstance(value, list): return [self.redacted(item) for item in value]
        if isinstance(value, str):
            for secret in self.secrets: value = value.replace(secret, "[PRIVATE_VALUE_WITHHELD]")
        return value

    def save(self, path, value):
        core.save(path, self.redacted(value))

    def check(self, name, condition, **facts):
        self.checks.append({"name": name, "status": "PASS" if condition else "FAIL", **facts})
        if not condition: raise RuntimeError("Actual milestone journey failed: " + name)

    def record_http(self, method, route, status, body, raw, origin):
        try: response = json.loads(raw)
        except (ValueError, UnicodeDecodeError): response = {"raw_non_json_bytes": len(raw)}
        record = {"origin": origin, "method": method, "route": route, "status": status,
            "request_body": body, "response": response, "response_sha256": hashlib.sha256(raw).hexdigest(),
            "authentication_headers_recorded": False}
        filename = f"http-{len(self.http) + 1:05d}.json"
        self.save(self.out / filename, record)
        self.http.append({"origin": origin, "method": method, "route": route, "status": status,
            "file": filename, "sha256": core.sha(self.out / filename)})
        return response

    def api(self, method, route, body=None, expected=200):
        headers = {"Authorization": "Bearer " + self.private["FORGEFLOW_OWNER_TOKEN"], "Accept": "application/json"}
        if method != "GET":
            headers.update({"Content-Type": "application/json", "Idempotency-Key": str(uuid.uuid4())})
        request = urllib.request.Request(BASE + "/api/v1" + route, method=method, headers=headers,
            data=None if body is None else json.dumps(body).encode())
        try: response = self.opener.open(request, timeout=30)
        except urllib.error.HTTPError as error: response = error
        raw = response.read()
        value = self.record_http(method, route, response.status, body, raw, "READ_ONLY_API" if method == "GET" else "EXPECTED_REJECTION")
        if response.status != expected:
            raise RuntimeError(f"Actual API {method} {route}: HTTP {response.status} {value.get('code')}")
        return value.get("data", value)

    def collect(self, route):
        result, cursor, version, seen = [], None, None, set()
        for _ in range(10000):
            full = route + ("&" if "?" in route else "?") + "limit=500"
            if cursor: full += "&cursor=" + urllib.parse.quote(cursor, safe="")
            headers = {"Authorization": "Bearer " + self.private["FORGEFLOW_OWNER_TOKEN"]}
            request = urllib.request.Request(BASE + "/api/v1" + full, headers=headers)
            with self.opener.open(request, timeout=30) as response:
                value = self.record_http("GET", full, response.status, None, response.read(), "READ_ONLY_API")
            if not isinstance(value.get("data"), list) or "next_cursor" not in value:
                raise RuntimeError("Actual collection lacks the complete cursor contract.")
            if version is not None and value.get("read_model_version") not in (None, version):
                raise RuntimeError("Actual collection changed while traversing its snapshot.")
            version = value.get("read_model_version", version)
            result.extend(value["data"])
            cursor = value["next_cursor"]
            if not cursor: return result
            if cursor in seen: raise RuntimeError("Actual collection returned a repeated cursor.")
            seen.add(cursor)
        raise RuntimeError("Actual collection exceeded its complete-read budget.")

    def db_facts(self):
        reader = core.Journey.__new__(core.Journey)
        reader.private = self.private
        quoted = self.project.replace("'", "''")
        return json.loads(reader.db("SELECT jsonb_build_object('project_paused',(SELECT (data->>'paused')::boolean FROM projects WHERE project_id='" + quoted + "'),"
            "'valid_leases',(SELECT count(*) FROM leases WHERE project_id='" + quoted + "' AND revoked_at IS NULL AND expires_at>clock_timestamp()),"
            "'held_allocations',(SELECT count(*) FROM resource_allocations WHERE project_id='" + quoted + "' AND state<>'RELEASED'),"
            "'active_attempts',(SELECT count(*) FROM attempts WHERE project_id='" + quoted + "' AND state NOT IN('SUCCEEDED','FAILED','CANCELLED')),"
            "'model_request_ids',(SELECT coalesce(jsonb_agg(request_id ORDER BY request_id),'[]'::jsonb) FROM native_model_requests WHERE project_id='" + quoted + "'));"))

    def semantic_history_closure(self, previous):
        """Admit only the separately bound catalog-revision observation failure."""
        report_path = self.args.handoff.parent / "report.json"
        closure_path = self.args.handoff.parent / "history-closure.json"
        closure = json.loads(closure_path.read_text())
        preserved = closure["old_observation_report_preserved"]
        bound = ROOT / preserved["path"]
        expected_failure = {"type": "RuntimeError", "message":
            "The distinct replanning chain requires unchanged historical inputs/SHA and at most six settled new requests."}
        self.check("history_closure_exact_failed_observer_binding", closure["status"] == "PASS" and closure["business_chain"] == "3.7"
            and closure["observation_only"] is True and all(closure[key] == 0 for key in ("api_requests_added", "model_requests_added", "workers_started"))
            and preserved["status"] == previous["status"] == "FAIL" and previous.get("failure") == preserved["failure"] == expected_failure
            and bound.resolve() == report_path.resolve() and core.sha(bound) == preserved["sha256"]
            and closure["checks"] and all(value is True for value in closure["checks"].values()))
        references = {}
        for reference in closure["evidence_references"]:
            file = ROOT / reference["path"]
            self.check("history_closure_evidence_pin", core.sha(file) == reference["sha256"], path=reference["path"])
            references[file.resolve()] = file
        self.check("history_closure_handoff_binding", (ROOT / closure["handoff_path"]).resolve() == self.args.handoff.resolve()
            and self.args.handoff.resolve() in references)
        before_file = references[(self.args.handoff.parent.parent / "retained-before.json").resolve()]
        after_file = references[(self.args.handoff.parent / "retained-after.json").resolve()]
        before, after = json.loads(before_file.read_text()), json.loads(after_file.read_text())
        unchanged = all(before["history"][key] == after["history"][key] for key in ("attempts", "flow_context", "task_revision"))
        unchanged = unchanged and before["artifact_hashes"] == after["artifact_hashes"] == closure["original_history"]["raw_artifact_inventory"]
        old_rows = {row["path"]: row for row in before["history"]["input_snapshots"]}
        new_rows = {row["path"]: row for row in after["history"]["input_snapshots"]}
        comparisons = {row["path"]: row for row in closure["input_snapshot_full_column_comparison"]}
        unchanged = unchanged and old_rows.keys() == new_rows.keys() == comparisons.keys()
        for key, old in old_rows.items():
            new, compared = new_rows[key], comparisons[key]
            unchanged = unchanged and compared["before_all_columns"] == old and compared["after_all_columns"] == new
            unchanged = unchanged and {k: v for k, v in old.items() if k != "revision"} == {k: v for k, v in new.items() if k != "revision"}
            unchanged = unchanged and isinstance(old.get("revision"), int) and isinstance(new.get("revision"), int) and new["revision"] >= old["revision"]
        before_flow = {key: value for key, value in before["flow"].items() if key not in {"state", "revision"}}
        after_flow = {key: value for key, value in after["old_flow"].items() if key not in {"state", "revision"}}
        unchanged = unchanged and before_flow == after_flow and before["flow"]["state"] == "COMMITTED" and after["old_flow"]["state"] == "SUPERSEDED"
        unchanged = unchanged and all(core.sha(file) == digest for file, digest in before["artifact_hashes"].items())
        old_blob = subprocess.check_output(["git", "-C", self.handoff["canonical_repository"], "show", closure["original_history"]["old_integrated_sha"] + ":journey-result.txt"])
        unchanged = unchanged and hashlib.sha256(old_blob).hexdigest() == after["old_integrated_blob_sha256"] == closure["original_history"]["old_git_blob_sha256"]
        self.check("history_closure_only_monotonic_input_catalog_revision_changes", unchanged)
        success = closure["new_success"]
        snapshot = json.loads(references[(self.args.handoff.parent / "final-snapshot.json").resolve()].read_text())
        database = json.loads(references[(self.args.handoff.parent / "database-facts.json").resolve()].read_text())
        attempt = next(row for row in snapshot["attempts"] if row["attempt_id"] == success["attempt_id"])
        merge = next(row for row in database["merges"] if row["attempt_id"] == success["attempt_id"])
        evidence = next(row for row in database["evidence"] if row["receipt_id"] == success["independent_receipt_id"])
        stages = previous["stages"]
        self.check("history_closure_actual_success_and_handoff_identity", success["task_id"] == self.handoff["task_id"]
            and success["actual_flow_revision"] == self.handoff["flow_revision"] and success["actual_task_revision"] == self.handoff["task_revision"]
            and success["integrated_sha"] == self.handoff["integrated_sha"] == merge["integrated_sha"] and merge["state"] == "FINALIZED"
            and attempt["state"] == "SUCCEEDED" and attempt["task_id"] == self.handoff["task_id"] and attempt["task_revision"] == self.handoff["task_revision"]
            and evidence["kind"] == "INDEPENDENT_VERIFICATION" and evidence["attempt_id"] == attempt["attempt_id"]
            and all((result["total"], result["failed"], result["skipped"]) == (4, 0, 0) for result in (evidence, merge["receipt"]["verification"]))
            and stages[core.STAGES[4]]["status"] == stages[core.STAGES[5]]["status"] == "PASS"
            and stages[core.STAGES[4]]["attempt_id"] == attempt["attempt_id"] and stages[core.STAGES[5]]["integrated_sha"] == success["integrated_sha"])
        new_requests = [row for row in snapshot["native_model_requests"] if row["request_id"] not in before["model_request_ids"]]
        cleanup = closure["cleanup"]
        self.check("history_closure_exact_budget_and_cleanup", len(new_requests) == previous["new_actual_model_request_count"] == closure["model_accounting"]["new_total"] == 6
            and all(row["status"] == "SETTLED" and row["usage_complete"] is True for row in new_requests)
            and cleanup["held_resource_allocation_count"] == cleanup["valid_lease_count"] == cleanup["port8794_listener_count"] == 0
            and cleanup["all_attempts_terminal"] is True and all(value is False for value in cleanup["process_ids_currently_present"].values())
            and cleanup["original_report_cleanup"] == previous["cleanup"])
        self.report["semantic_history_closure"] = {"path": str(closure_path), "sha256": core.sha(closure_path),
            "original_failed_report_sha256": core.sha(report_path), "original_report_status": "FAIL",
            "accepted_scope": "Only monotonic input-snapshot catalog revisions changed; original materials and actual successful delivery remain bound"}
        return True

    def preflight(self):
        previous = json.loads((self.args.handoff.parent / "report.json").read_text())
        qualified = previous.get("status") == "PASS"
        if not qualified and previous.get("status") == "FAIL":
            qualified = self.semantic_history_closure(previous)
        cleanup = previous.get("cleanup", {})
        self.check("semantic_journey_closed", qualified and cleanup.get("project_paused") is True
            and cleanup.get("worker_stopped_after_release") is True and cleanup.get("server_stopped_after_worker") is True)
        self.check("same_handoff_authority", self.handoff.get("no_model_replay_required") is True
            and self.handoff["data_root"] == self.private["FORGEFLOW_DATA_ROOT"]
            and self.handoff["api_bind"] == self.private["FORGEFLOW_BIND"] == "127.0.0.1:8794")
        binary = self.receipt["binaries"]["forgeflow-server"]
        self.check("pinned_server_binary", core.sha(binary["path"]) == binary["sha256"])
        self.check("independent_frontend_exists", (self.args.frontend_dir / "index.html").is_file())
        self.before_db = self.db_facts()
        self.check("actual_quiescent_preflight", self.before_db["project_paused"] is True and
            all(self.before_db[key] == 0 for key in ("valid_leases", "held_allocations", "active_attempts")), **self.before_db)
        with socket.socket() as probe:
            probe.settimeout(.3)
            self.check("scheduled_port_free", probe.connect_ex(("127.0.0.1", 8794)) != 0)
        self.report.update(server_binary_sha256=binary["sha256"], frontend_assets={str(file.relative_to(self.args.frontend_dir)): core.sha(file)
            for file in self.args.frontend_dir.rglob("*") if file.is_file()})
        self.server_log = (self.out / "server.log").open("wb")
        env = {**os.environ, **self.private, "FORGEFLOW_CONSOLE_DIR": str(self.args.frontend_dir.resolve())}
        self.server = subprocess.Popen([binary["path"]], cwd=ROOT, env=env,
            stdout=self.server_log, stderr=subprocess.STDOUT, start_new_session=True)
        self.report["server_pid"] = self.server.pid
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            if self.server.poll() is not None: raise RuntimeError("Scheduled API exited; original server.log retained.")
            try:
                with self.opener.open(BASE + "/healthz", timeout=1) as response:
                    if response.status == 200: break
            except (OSError, urllib.error.URLError): pass
            time.sleep(.2)
        else: raise RuntimeError("Scheduled API readiness timed out.")
        self.before = self.api("GET", f"/projects/{self.project}/snapshot")
        self.before_evidence = self.collect(f"/projects/{self.project}/evidence")
        self.before_head = subprocess.check_output(["git", "-C", self.handoff["canonical_repository"], "rev-parse", "refs/heads/main"]).decode().strip()
        self.check("handoff_current_success", self.before_head == self.handoff["integrated_sha"] and any(
            row["task_id"] == self.handoff["task_id"] and row["task_revision"] == self.handoff["task_revision"] and
            row["envelope"]["verification_plan_id"] == self.handoff["verification_plan_id"] for row in self.before["tasks"]))

    def browser_response(self, response):
        if "/api/v1/" not in response.url or "text/event-stream" in response.headers.get("content-type", ""): return
        route = response.url.replace(BASE + "/api/v1", "")
        self.browser_http.append({"method": response.request.method, "route": route, "status": response.status})
        if response.status >= 400: self.js_errors.append(f"Unexpected browser HTTP {response.status} {route}")

    def click(self, button, route):
        with self.page.expect_response(lambda response: response.request.method == "POST" and
            urllib.parse.unquote(urllib.parse.urlsplit(response.url).path) == "/api/v1" + route, timeout=30000) as waiting:
            button.click()
        response = waiting.value
        value = self.record_http("POST", route, response.status, response.request.post_data_json, response.body(), "ACTUAL_BROWSER_COMMAND")
        if response.status >= 400: raise RuntimeError(f"Actual browser command HTTP {response.status} {value.get('code')}")
        return value["data"]

    def run_browser(self):
        from playwright.sync_api import sync_playwright, expect
        title = "真实里程碑验收 · " + uuid.uuid4().hex[:10]
        due = datetime.now(timezone.utc) + timedelta(days=7)
        if self.retained_created:
            title = self.retained_created["title"]
            due = datetime.fromisoformat(self.retained_created["due_at"].replace("Z", "+00:00"))
        task = next(row for row in self.before["tasks"] if row["task_id"] == self.handoff["task_id"])
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(headless=True,
                executable_path="/home/chenyoujian/.cache/ms-playwright/chromium-1247/chrome-linux64/chrome", args=["--no-proxy-server"])
            try:
                self.page = browser.new_page(viewport={"width": 1440, "height": 1000}, reduced_motion="reduce")
                self.page.set_default_timeout(30000)
                self.page.on("pageerror", lambda error: self.js_errors.append(str(error)))
                self.page.on("response", self.browser_response)
                self.page.add_init_script("sessionStorage.setItem('forgeflow.owner-token', " + json.dumps(self.private["FORGEFLOW_OWNER_TOKEN"]) + ")")
                self.page.goto(BASE + f"/calendar?project={urllib.parse.quote(self.project)}", wait_until="domcontentloaded")
                expect(self.page.get_by_role("heading", name="日程与里程碑", exact=True)).to_be_visible()
                if not self.retained_created:
                    self.page.get_by_label("标题", exact=True).fill(title)
                    self.page.get_by_label("目标时刻（包含时区）", exact=True).fill(due.isoformat())
                    self.page.get_by_label("验证计划 ID（每行一项）", exact=True).fill(self.handoff["verification_plan_id"])
                    self.page.get_by_label("任务/工作单元 ID（每行一项）", exact=True).fill(self.handoff["task_id"])
                    self.page.get_by_label("需求 ID（每行一项）", exact=True).fill("\n".join(task["requirement_ids"]))
                    self.click(self.page.get_by_role("button", name="创建里程碑", exact=True), f"/projects/{self.project}/milestones")
                milestones = self.collect(f"/projects/{self.project}/milestones")
                milestone = next(row for row in milestones if row["title"] == title)
                self.milestone_id = milestone["milestone_id"]
                if self.retained_created:
                    self.check("retained_pending_creation_unchanged", milestone == self.retained_created)
                    prior_acceptances = self.collect(f"/projects/{self.project}/documents/milestone_acceptances")
                    self.check("no_acceptance_synthesized_after_rejection", not any(value["milestone_id"] == self.milestone_id for value in prior_acceptances))
                row = self.page.locator("tr.interactive-row").filter(has_text=title)
                expect(row).to_have_count(1)
                expect(row).to_contain_text("待验收")
                self.check("created_pending_in_actual_calendar", milestone["baseline_version"] == 1)
                route = f"/projects/{self.project}/milestones/{self.milestone_id}/accept"
                expect(row.get_by_role("button", name="接受当前基线", exact=True)).to_be_enabled()
                first = self.click(row.get_by_role("button", name="接受当前基线", exact=True), route)
                expect(row).to_contain_text("已接受")
                self.check("baseline_one_real_acceptance", first["status"] == "ACCEPTED" and first["baseline_version"] == 1
                    and first["milestone_revision"] == milestone["revision"] and bool(first["accepted_at"])
                    and bool(first["evidence_refs"]) and any(ref["integrated_sha"] == self.handoff["integrated_sha"] for ref in first["evidence_refs"]))
                self.check("accept_button_does_not_open_edit", self.page.get_by_role("button", name="保存里程碑新版本", exact=True).count() == 0)
                first_bytes = json.dumps(first, sort_keys=True, separators=(",", ":"))
                row.click()
                self.page.get_by_label("目标时刻（包含时区）", exact=True).fill((due + timedelta(days=2)).isoformat())
                self.page.get_by_label("日期／条件变更原因", exact=True).fill("真实用户确认交付窗口调整；保留原始基线及原始验收回执。")
                self.click(self.page.get_by_role("button", name="保存里程碑新版本", exact=True), f"/projects/{self.project}/milestones")
                expect(row).to_contain_text("需重新验收")
                milestone2 = next(value for value in self.collect(f"/projects/{self.project}/milestones") if value["milestone_id"] == self.milestone_id)
                self.check("new_baseline_requires_own_acceptance", milestone2["baseline_version"] == 2 and milestone2["revision"] > milestone["revision"])
                expect(row.get_by_role("button", name="接受当前基线", exact=True)).to_be_enabled()
                second = self.click(row.get_by_role("button", name="接受当前基线", exact=True), route)
                expect(row).to_contain_text("已接受")
                acceptances = [value for value in self.collect(f"/projects/{self.project}/documents/milestone_acceptances") if value["milestone_id"] == self.milestone_id]
                baselines = [value for value in self.collect(f"/projects/{self.project}/documents/milestone_baselines") if value["milestone_id"] == self.milestone_id]
                self.save(self.out / "retained-acceptances.json", acceptances)
                self.save(self.out / "retained-baselines.json", baselines)
                self.check("two_immutable_acceptance_receipts", len(acceptances) == 2 and {r["baseline_version"] for r in acceptances} == {1, 2}
                    and second["milestone_revision"] == milestone2["revision"] and second["status"] == "ACCEPTED"
                    and json.dumps(next(r for r in acceptances if r["baseline_version"] == 1), sort_keys=True, separators=(",", ":")) == first_bytes)
                self.check("original_baseline_retained", any(r["baseline_version"] == 1 and r["due_at"] == milestone["due_at"] for r in baselines)
                    and any(r["baseline_version"] == 2 and r["due_at"] == milestone2["due_at"] for r in baselines))
                row.get_by_role("button", name="查看验收记录", exact=True).click()
                expect(self.page.get_by_text("基线 v1", exact=False)).to_be_visible()
                expect(self.page.get_by_text("基线 v2", exact=False)).to_be_visible()
                for width, height, name in [(1440, 1000, "desktop.png"), (390, 844, "mobile.png")]:
                    self.page.set_viewport_size({"width": width, "height": height})
                    self.page.wait_for_timeout(200)
                    overflow = self.page.evaluate("document.documentElement.scrollWidth > innerWidth + 2")
                    self.check("no_outer_overflow_" + str(width), not overflow, width=width, height=height)
                    self.page.screenshot(path=str(self.out / name), full_page=True)
                    self.screenshots.append({"file": name, "sha256": core.sha(self.out / name)})
                rejection = self.api("POST", f"/projects/{self.project}/documents/milestone_acceptances",
                    {"id": "forbidden-" + uuid.uuid4().hex, "value": {"project_id": self.project, "milestone_id": self.milestone_id, "status": "ACCEPTED"}}, expected=422)
                self.check("generic_acceptance_forgery_rejected", rejection.get("code") == "COMMAND_REQUIRED", actual_code=rejection.get("code"))
                self.report.update(milestone_id=self.milestone_id, accepted_baseline_versions=[1, 2], evidence_refs=second["evidence_refs"])
                self.check("no_unexpected_browser_errors", not self.js_errors, javascript_and_http_errors=self.js_errors)
            finally:
                browser.close()

    def finish(self):
        quiescent = False
        try:
            final_db = self.db_facts()
            self.report["final_authority"] = final_db
            quiescent = final_db["project_paused"] is True and all(final_db[key] == 0 for key in ("valid_leases", "held_allocations", "active_attempts"))
            self.report["new_model_requests"] = len(set(final_db["model_request_ids"]) - set(self.before_db["model_request_ids"])) if hasattr(self, "before_db") else "UNMEASURED"
            if self.server and self.server.poll() is None and hasattr(self, "before"):
                after = self.api("GET", f"/projects/{self.project}/snapshot")
                after_evidence = self.collect(f"/projects/{self.project}/evidence")
                after_head = subprocess.check_output(["git", "-C", self.handoff["canonical_repository"], "rev-parse", "refs/heads/main"]).decode().strip()
                retained = all(after[key] == self.before[key] for key in ("tasks", "attempts", "native_model_requests")) and after_evidence == self.before_evidence and after_head == self.before_head
                self.check("semantic_tasks_models_git_and_receipts_preserved", retained)
            self.check("no_new_models_and_resources_closed", self.report["new_model_requests"] == 0 and quiescent)
        except Exception as failure:
            self.report["status"] = "FAIL"
            self.report["cleanup"] = {"status": "ROOT_INTERVENTION_REQUIRED", "error_type": type(failure).__name__,
                "message": str(failure), "server_pid": self.server.pid if self.server else None,
                "server_kept_alive": bool(self.server and self.server.poll() is None)}
        finally:
            # A failed observation preserves its outcome but need not leave a
            # proven-quiescent owned API behind. Never stop an unrelated actor.
            if quiescent:
                try:
                    if self.server:
                        if self.server.poll() is None: self.server.terminate()
                        self.server.wait(timeout=15)
                    with socket.socket() as probe:
                        probe.settimeout(.3)
                        closed = probe.connect_ex(("127.0.0.1", 8794)) != 0
                    self.report["cleanup"] = {"server_stopped": self.server is None or self.server.poll() is not None,
                        "port8794_closed": closed, "workers_started": 0, "quiescent": True}
                    self.check("scheduled_api_safely_closed", closed)
                except Exception as failure:
                    self.report["status"] = "FAIL"
                    self.report["cleanup"] = {"status": "ROOT_INTERVENTION_REQUIRED", "error_type": type(failure).__name__,
                        "message": str(failure), "server_pid": self.server.pid if self.server else None}
            if self.server_log: self.server_log.close()
            self.report.update(checks=self.checks, http=self.http, screenshots=self.screenshots)
            self.save(self.out / "browser-report.json", {"status": "PASS" if not self.js_errors and self.report["status"] == "PASS" else "FAIL",
                "javascript_and_unexpected_http_errors": self.js_errors, "http": self.browser_http, "screenshots": self.screenshots})
            self.save(self.out / "report.json", self.report)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", action="store_true")
    parser.add_argument("--build-receipt", required=True, type=Path)
    parser.add_argument("--frontend-dir", required=True, type=Path)
    parser.add_argument("--handoff", required=True, type=Path)
    parser.add_argument("--resume-from", type=Path, help="Root-authorized point continuation of the closed descriptor-mismatch failure")
    parser.add_argument("--output", type=Path, default=ROOT / "evidence/milestone-acceptance-r1")
    args = parser.parse_args()
    if not args.run:
        print(json.dumps({"status": "SOURCE_READY_NOT_EXECUTED", "business_chain": "3.9", "actors_started": [],
            "model_calls": 0, "requires_root_go": True, "driver_sha256": core.sha(__file__)}))
        return 0
    args.output.mkdir(parents=True, exist_ok=True)
    if any(args.output.iterdir()): raise RuntimeError("Retain original milestone evidence; this journey is not automatically repeated.")
    journey = MilestoneJourney(args)
    try:
        journey.preflight()
        journey.run_browser()
        journey.report["status"] = "PASS"
    except Exception as failure:
        journey.report.update(status="FAIL", failure={"type": type(failure).__name__, "message": str(failure)})
    finally:
        journey.finish()
    print(json.dumps({"status": journey.report["status"], "business_chain": "3.9", "new_model_requests": journey.report["new_model_requests"],
        "workers_started": 0, "cleanup": journey.redacted(journey.report.get("cleanup"))}, ensure_ascii=False))
    return 0 if journey.report["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
