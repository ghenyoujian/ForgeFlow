#!/usr/bin/env python3
"""One authorized legal delivery revision after the retained cap-three failure.

No new requirement edit or planning model. Exactly two remaining new native
requests are allowed by the new frozen delivery envelope. No raw repair.
"""
import argparse
import copy
import json
import os
import subprocess
from pathlib import Path

import user_journey_check as core
from semantic_replanning_check import SemanticJourney, NEW_BYTES, PROJECT, RECEIPT, ROOT

PREVIOUS = ROOT / "evidence/business-chain-semantic-replanning-r1/selector-corrected-run/report.json"
OUT = PREVIOUS.parent / "delivery-continuation-r1"


class DeliveryContinuation(SemanticJourney):
    def __init__(self, output):
        super().__init__(output, RECEIPT)
        previous = json.loads(PREVIOUS.read_text())
        if previous["status"] != "FAIL" or previous["new_actual_model_request_count"] != 4 \
                or previous["stages"][core.STAGES[2]]["status"] != "PASS" \
                or previous["v2_planning_verification"]["actual_case_denominator"] != 25:
            raise RuntimeError("Continue only the actual one-call planning success and closed three-call delivery failure.")
        self.report = copy.deepcopy(previous)
        self.report.update(status="RUNNING", failure=None, cleanup=None,
            delivery_continuation_driver_sha256=core.sha(__file__),
            inherited_actual_chain={"report": str(PREVIOUS), "sha256": core.sha(PREVIOUS),
                "stages": core.STAGES[:3], "new_planning_models": 0, "original_delivery_failed_preserved": True},
            delivery_model_request_cap=2, new_actual_model_request_ceiling=6)
        for stage in core.STAGES[:3]:
            self.report["stages"][stage]["evidence_origin"] = "INHERITED_ACTUAL_SEMANTIC_CHANGE_AND_DSH_PLANNING"
        for stage in core.STAGES[3:]:
            self.report["stages"][stage] = {"status": "NOT_RUN"}
        self.current_stage = core.STAGES[3]
        self.launch_seen = copy.deepcopy(previous["actual_launches"])
        retained = json.loads((PREVIOUS.parent / "retained-before.json").read_text())
        self.old_attempt_ids = {row["attempt_id"] for row in retained["history"]["attempts"]}
        self.old_model_ids = set(retained["model_request_ids"])
        self.baseline_history, self.baseline_artifacts = retained["history"], retained["artifact_hashes"]
        self.baseline_flow, self.baseline_sources = retained["flow"], retained["sources"]
        self.baseline_requirement, self.baseline_seq = retained["requirement"], retained["project_event_seq"]
        self.worker_config_path = Path(previous["private_worker_config_path"])
        self.worker_config = json.loads(self.worker_config_path.read_text())
        command = next(row["body"] for row in previous["browser_http"]
            if row["method"] == "POST" and row["route"].endswith("/execution-templates"))
        self.profile_id, self.resource_id = command["executor_profile_id"], command["resource_profile_id"]
        self.coding_template_id = command["verification_plan_id"]
        original = previous["stages"][core.STAGES[3]]
        self.parent_flow_revision, self.affected_task_id = original["flow_revision"], original["task_id"]
        self.config["delivery_model_request_cap"] = 2
        self.config["delivery_instruction"] = (
            "The current Owner-approved acceptance requires exact bytes FORGEFLOW_USER_JOURNEY_REPLANNED_OK followed by one LF in journey-result.txt. "
            "This finite task has exactly TWO model requests: one tool call, then one final response. "
            "Your first response must call the bash tool exactly once with ONLY command and description parameters. "
            "Do not include justification or sandbox_permissions. Do not read files, run a selfcheck, use other tools or delegate. "
            "Use this exact command to write in place:\n/usr/bin/python3 -I -B <<'FORGEFLOW_WRITE'\n"
            "from pathlib import Path\nPath('journey-result.txt').write_bytes(" + repr(NEW_BYTES) + ")\nFORGEFLOW_WRITE\n"
            "After the tool returns, emit one short final plain-text write summary and stop. "
            "The separate controller performs all independent verification and Git integration; do not perform or claim those actions.")

    def start_delivery_worker(self):
        before = self.api("GET", f"/projects/{PROJECT}/snapshot")
        if len(before["native_model_requests"]) != 15 or not before["project"]["paused"] \
                or any(row["state"] != "RELEASED" for row in before["allocations"]):
            raise RuntimeError("The remaining two requests require exactly the closed prior fifteen project requests before queueing.")
        self.worker_log = (self.out / "worker.log").open("wb")
        self.worker = subprocess.Popen([self.worker_binary["path"], "--config", str(self.worker_config_path)],
            env={"PATH": "/usr/bin:/bin", "FORGEFLOW_WORKER_TOKEN": self.private["FORGEFLOW_WORKER_TOKEN"], "RUST_LOG": "info"},
            stdout=self.worker_log, stderr=subprocess.STDOUT, start_new_session=True)
        self.report["worker_pid"] = self.worker.pid
        worker_id = self.worker_config["worker_id"]
        self.wait(lambda: self.db("SELECT count(*) FROM workers WHERE project_id='" + PROJECT
            + "' AND worker_id='" + worker_id + "' AND heartbeat_at>clock_timestamp()-interval '5 seconds';") == "1",
            45, "actual restarted Worker heartbeat before current-revision GUI enqueue")
        project = self.api("GET", "/projects/" + PROJECT)
        self.api("PATCH", "/projects/" + PROJECT, {"project": {**project, "paused": False},
            "expected_revision": project["revision"]}, "FIXTURE_CLEANUP")

    def click(self, button, route, method="POST"):
        # Keep the project paused through the user-visible new revision and
        # approval. Start the author only immediately before its actual enqueue.
        if route.endswith("/admission-checks") and method == "POST":
            self.start_delivery_worker()
        return super().click(button, route, method)

    def run(self):
        from playwright.sync_api import sync_playwright
        self.start_server()
        snapshot = self.api("GET", f"/projects/{PROJECT}/snapshot")
        self.canonical = snapshot["project"]["root_path"]
        if snapshot["project"].get("authority_mode") != "MANAGED" or not snapshot["project"]["paused"] \
                or len(snapshot["native_model_requests"]) != 15 \
                or any(row["status"] != "SETTLED" for row in snapshot["native_model_requests"]) \
                or any(row["state"] not in {"SUCCEEDED", "FAILED", "CANCELLED"} for row in snapshot["attempts"]) \
                or any(row["state"] != "RELEASED" for row in snapshot["allocations"]):
            raise RuntimeError("The prior real failure must be fully closed before its legal new task revision.")
        self.closed_failed_attempt = next(row for row in snapshot["attempts"]
            if row["task_id"] == self.affected_task_id and row["task_revision"] == 2)
        if self.closed_failed_attempt["state"] != "FAILED":
            raise RuntimeError("The original failed TaskRevision2 is immutable; never revive it.")
        repo = self.fixture / "source"
        source_head = subprocess.check_output(["git", "-C", str(repo), "rev-parse", "HEAD"]).decode().strip()
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(headless=True,
                executable_path="/home/chenyoujian/.cache/ms-playwright/chromium-1247/chrome-linux64/chrome", args=["--no-proxy-server"])
            self.page = browser.new_page(viewport={"width": 1440, "height": 1000}, reduced_motion="reduce")
            self.page.set_default_timeout(30000)
            self.page.on("pageerror", lambda error: self.errors.append(str(error)))
            self.page.on("response", self.browser_response)
            self.page.add_init_script("sessionStorage.setItem('forgeflow.owner-token', " + json.dumps(self.private["FORGEFLOW_OWNER_TOKEN"]) + ")")
            flow = self.api("GET", f"/flows/{PROJECT}:{self.parent_flow_revision}")
            self.navigate(f"/projects/{PROJECT}/flows/{self.parent_flow_revision}")
            self.page.get_by_role("button", name="任务表", exact=True).click()
            self.page.locator("tr.interactive-row").filter(has_text=self.affected_task_id).click()
            self.page.get_by_role("button", name="编辑并建立子版本", exact=True).click()
            drawer = self.page.get_by_role("dialog", name="编辑任务 · 新草案版本", exact=True)
            drawer.get_by_label("有限交付结果", exact=True).fill(flow["tasks"][0]["title"] + " · 单步原位写入")
            revised = self.click(drawer.get_by_role("button", name="保存新草案版本", exact=True), f"/projects/{PROJECT}/flow-revisions")
            if revised["parent_revision"] != self.parent_flow_revision or revised["tasks"][0]["task_revision"] <= 2:
                raise RuntimeError("Continue through an actual new Flow/TaskRevision only.")
            self.report["user_visible_delivery_revision"] = {"parent_revision": self.parent_flow_revision,
                "new_revision": revised["flow_revision"], "task_revision": revised["tasks"][0]["task_revision"],
                "original_failed_attempt": self.closed_failed_attempt["attempt_id"], "new_planning_models": 0}
            core.EXPECTED = NEW_BYTES
            self.deliver(revised, self.profile_id, self.resource_id, repo, source_head, browser)
        after = self.api("GET", f"/projects/{PROJECT}/snapshot")
        old = next(row for row in after["attempts"] if row["attempt_id"] == self.closed_failed_attempt["attempt_id"])
        if old != self.closed_failed_attempt:
            raise RuntimeError("The original failed attempt changed during the legal new revision.")
        self.traceability()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", action="store_true")
    args = parser.parse_args()
    OUT.mkdir(parents=True, exist_ok=True)
    if not args.run:
        core.save(OUT / "preparation.json", {"status": "READY_NOT_EXECUTED", "source_sha256": core.sha(__file__),
            "inherited_report": str(PREVIOUS), "inherited_report_sha256": core.sha(PREVIOUS),
            "planning_models_added": 0, "remaining_delivery_cap": 2, "new_aggregate_cap": 6,
            "old_cumulative_separate": 14, "automatic_retries": False})
        print('{"status":"READY_NOT_EXECUTED","remaining_delivery_cap":2}')
        return 0
    if (OUT / "report.json").exists():
        raise RuntimeError("No second delivery continuation is authorized.")
    journey = DeliveryContinuation(OUT)
    try:
        journey.run()
    except Exception as failure:
        journey.report.update(status="FAIL", failure={"type": type(failure).__name__, "message": str(failure)})
        if journey.report["stages"][journey.current_stage]["status"] != "PASS":
            journey.report["stages"][journey.current_stage] = {"status": "FAIL", "message": str(failure)}
    finally:
        try:
            final = journey.api("GET", f"/projects/{PROJECT}/snapshot")
            new = [row for row in final["native_model_requests"] if row["request_id"] not in journey.old_model_ids]
            journey.report.update(new_actual_model_request_count=len(new), new_continuation_model_request_count=len(new) - 4,
                new_model_request_states=[row["status"] for row in new], historical_cumulative_actual_model_requests=14,
                combined_actual_model_request_count=14 + len(new))
        except Exception as failure:
            journey.report["final_model_authority_observation"] = {"status": "UNCONFIRMED", "error_type": type(failure).__name__}
        journey.cleanup()
        journey.write_report()
    print(json.dumps({"status": journey.report["status"], "new_model_requests": journey.report.get("new_actual_model_request_count"),
        "old_history_preserved": journey.report.get("old_history_preserved"), "cleanup": journey.report.get("cleanup")}, ensure_ascii=False))
    return 0 if journey.report["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
