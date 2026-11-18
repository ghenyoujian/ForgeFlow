#!/usr/bin/env python3
"""Continue one persisted GUI command after a zero-model observation timeout."""
import argparse
import copy
import hashlib
import importlib.util
import json
import os
import subprocess
import urllib.request
from pathlib import Path

from user_journey_check import Journey, PLANNING_INTENT_SHA256, ROOT, STAGES, save, sha


class ContinueAccepted(Journey):
    def prerequisites(self, root_team, child_team):
        previous = self.previous
        command = next(row for row in previous["browser_http"]
            if row["method"] == "POST" and row["route"].endswith("/flow-generations") and row["status"] == 202)
        response = self.resume_from.parent / command["response_file"]
        if sha(response) != command["response_sha256"]:
            raise RuntimeError("Original accepted GUI response changed.")
        original = json.loads(response.read_text())["data"]
        body = command["body"]
        if original["operation_id"] != self.config["continue_operation_id"] or body["max_model_requests"] != 6:
            raise RuntimeError("Continue the original six-request command only.")
        self.worker_config_path = Path(previous["private_worker_config_path"])
        self.worker_config = json.loads(self.worker_config_path.read_text())
        if self.worker_config["project_id"] != self.project_id or self.worker_config["data_root"] != self.private["FORGEFLOW_DATA_ROOT"]:
            raise RuntimeError("Original Worker deployment differs from this project.")
        self.planning_template_id = body["verification_plan_id"]
        tag = body["resource_profile_id"].rsplit(".", 1)[1]
        self.coding_template_id = "ui-coding-template." + tag
        self.worker_scope_id, self.global_scope_id = f"ui-{tag}-worker", f"ui-{tag}-global"
        self.capacity_scope_ids = [f"ui-{tag}-{name}" for name in ("global", "project", "root", "child")]
        oracle = Path(previous["new_planning_method"]["oracle_path"])
        if sha(oracle) != PLANNING_INTENT_SHA256:
            raise RuntimeError("The original compact oracle changed.")
        spec = importlib.util.spec_from_file_location("continued_planning_cases", oracle)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        self.planning_expected_cases = module.CASES
        for key in ("new_planning_method", "scheduled_worker_id", "private_worker_config_path", "profile_id",
                "model_route_id", "sandbox_profile_sha256"):
            self.report[key] = previous[key]
        return body["executor_profile_id"], body["resource_profile_id"]


def delivery_only(config, original_report, output, revise_failed=False):
    """Reuse the successful immutable planning operation, never run it again."""
    from playwright.sync_api import sync_playwright
    previous = json.loads(original_report.read_text())
    if previous["passed_stages"] != (4 if revise_failed else 3) or previous["stages"][STAGES[2]]["status"] != "PASS" \
            or previous["v2_planning_verification"]["actual_case_denominator"] != 25:
        raise RuntimeError("Delivery continuation requires the retained actual 25-case planning success.")
    journey = Journey.__new__(Journey)
    journey.config, journey.out, journey.previous = config, output, previous
    journey.private = json.loads(Path(config["runtime_env_path"]).read_text())
    journey.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    journey.records, journey.browser_records, journey.errors, journey.observations = [], [], [], []
    journey.project_id, journey.fixture = previous["project_id"], Path(previous["private_fixture_root"])
    journey.worker, journey.server, journey.page = None, None, None
    journey.current_stage, journey.launch_seen = STAGES[3], copy.deepcopy(previous["actual_launches"])
    journey.report = copy.deepcopy(previous)
    journey.report.update(status="RUNNING", cleanup=None, failure=None,
        inherited_actual_stages={"report": str(original_report), "sha256": sha(original_report),
            "stages": STAGES[:3], "new_planning_command": False, "new_planning_model_calls": 0},
        driver_sha256=sha(ROOT / "verification/user_journey_check.py"), continuation_driver_sha256=sha(__file__))
    for stage in STAGES[:3]:
        journey.report["stages"][stage]["evidence_origin"] = "INHERITED_ACTUAL_GUI_AND_DSH"
    for stage in STAGES[3:]:
        journey.report["stages"][stage] = {"status": "NOT_RUN"}
    journey.receipt = json.loads(Path(config["build_receipt_path"]).read_text())
    journey.worker_binary = journey.receipt["binaries"]["forgeflow-worker"]
    if journey.report["build_receipt_sha256"] != sha(config["build_receipt_path"]) \
            or sha(journey.worker_binary["path"]) != journey.worker_binary["sha256"]:
        raise RuntimeError("Continue delivery on the same immutable build only.")
    journey.worker_config_path = Path(previous["private_worker_config_path"])
    journey.worker_config = json.loads(journey.worker_config_path.read_text())
    journey.worker_scope_id = previous["automatic_custom_worker_scope_mapping"]["registered_scope_id"]
    journey.prior_actual_model_requests = config["historical_model_requests"]
    planning_report, planning_previous = original_report, previous
    for _ in range(8):
        if any(row["method"] == "POST" and row["route"].endswith("/flow-generations") for row in planning_previous["browser_http"]):
            break
        reference = planning_previous["inherited_actual_stages"]
        planning_report = Path(reference["report"])
        if sha(planning_report) != reference["sha256"]:
            raise RuntimeError("Inherited actual planning report changed.")
        planning_previous = json.loads(planning_report.read_text())
    else:
        raise RuntimeError("No original GUI planning command in the continuation history.")
    command = next(row for row in planning_previous["browser_http"] if row["method"] == "POST" and row["route"].endswith("/flow-generations"))
    tag = command["body"]["resource_profile_id"].rsplit(".", 1)[1]
    journey.coding_template_id = "ui-coding-template." + tag
    try:
        journey.start_server()
        operation_id = previous["stages"][STAGES[2]]["operation_id"]
        operation = journey.api("GET", "/operations/" + operation_id)
        if operation["status"] != "SUCCEEDED":
            raise RuntimeError("The actual planning operation no longer proves success.")
        flow = operation["result"]["flow"]
        if revise_failed:
            flow = journey.api("GET", f"/flows/{journey.project_id}:{previous['stages'][STAGES[3]]['flow_revision']}")
            snapshot = journey.api("GET", "/projects/" + journey.project_id + "/snapshot")
            failed = next(value for value in snapshot["attempts"] if value["task_id"] == flow["tasks"][0]["task_id"]
                and value["task_revision"] == flow["tasks"][0]["task_revision"])
            requests = snapshot["native_model_requests"]
            if failed["state"] not in {"FAILED", "CANCELLED"} or any(value["state"] != "RELEASED" for value in snapshot["allocations"]) \
                    or len(requests) != config.get("prior_project_requests_expected", 4) or any(value["status"] != "SETTLED" for value in requests) \
                    or config["historical_model_requests"] + len(requests) + config["delivery_model_request_cap"] > config.get("cumulative_model_request_ceiling", 12):
                raise RuntimeError("The prior failure must be closed and all actual model use must fit the remaining budget.")
            journey.report["model_request_budget"] = {"historical_actual_requests": config["historical_model_requests"],
                "project_prior_actual_requests": len(requests), "new_delivery_cap": config["delivery_model_request_cap"],
                "cumulative_ceiling": config.get("cumulative_model_request_ceiling", 12),
                "budget_adjustment": config.get("budget_adjustment")}
            journey.report["preserved_failed_delivery"] = {"attempt_id": failed["attempt_id"], "state": failed["state"],
                "report": str(original_report), "sha256": sha(original_report), "prior_project_model_requests": len(requests)}
        if (flow["state"] != ("COMMITTED" if revise_failed else "DRAFT")) or len(flow["tasks"]) != 1:
            raise RuntimeError("Review the original single-task Draft Flow only.")
        repo = journey.fixture / "source"
        source_head = subprocess.check_output(["git", "-C", str(repo), "rev-parse", "HEAD"]).decode().strip()
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(headless=True,
                executable_path="/home/chenyoujian/.cache/ms-playwright/chromium-1247/chrome-linux64/chrome", args=["--no-proxy-server"])
            journey.page = browser.new_page(viewport={"width": 1440, "height": 1000}, reduced_motion="reduce")
            journey.page.set_default_timeout(30000)
            journey.page.on("pageerror", lambda error: journey.errors.append(str(error)))
            journey.page.on("response", journey.browser_response)
            journey.page.add_init_script("sessionStorage.setItem('forgeflow.owner-token', " + json.dumps(journey.private["FORGEFLOW_OWNER_TOKEN"]) + ")")
            if revise_failed:
                journey.navigate(f"/projects/{journey.project_id}/flows/{flow['flow_revision']}")
                journey.page.get_by_role("button", name="任务表", exact=True).click()
                journey.page.locator("tr.interactive-row").filter(has_text=flow["tasks"][0]["task_id"]).click()
                journey.page.get_by_role("button", name="编辑并建立子版本", exact=True).click()
                drawer = journey.page.get_by_role("dialog", name="编辑任务 · 新草案版本", exact=True)
                drawer.get_by_label("有限交付结果", exact=True).fill(flow["tasks"][0]["title"] + " · 原位交付修订")
                flow = journey.click(drawer.get_by_role("button", name="保存新草案版本", exact=True),
                    f"/projects/{journey.project_id}/flow-revisions")
                journey.report["user_visible_flow_revision"] = {"parent": previous["stages"][STAGES[3]]["flow_revision"],
                    "new_revision": flow["flow_revision"], "task_revision": flow["tasks"][0]["task_revision"],
                    "original_source_acceptance_changed": False}
                journey.page.screenshot(path=str(output / "flow-revision-desktop.png"), full_page=True)
            journey.worker_log = (output / "worker.log").open("wb")
            journey.worker = subprocess.Popen([journey.worker_binary["path"], "--config", str(journey.worker_config_path)],
                env={"PATH": "/usr/bin:/bin", "FORGEFLOW_WORKER_TOKEN": journey.private["FORGEFLOW_WORKER_TOKEN"], "RUST_LOG": "info"},
                stdout=journey.worker_log, stderr=subprocess.STDOUT, start_new_session=True)
            journey.report["worker_pid"] = journey.worker.pid
            project = journey.api("GET", "/projects/" + journey.project_id)
            journey.api("PATCH", "/projects/" + journey.project_id, {"project": {**project, "paused": False},
                "expected_revision": project["revision"]}, "FIXTURE_CLEANUP")
            journey.deliver(flow, command["body"]["executor_profile_id"], command["body"]["resource_profile_id"], repo, source_head, browser)
    except Exception as failure:
        journey.report["status"] = "FAIL"
        if journey.report["stages"][journey.current_stage]["status"] != "PASS":
            journey.report["stages"][journey.current_stage] = {"status": "FAIL", "error_type": type(failure).__name__, "message": str(failure)}
        journey.report["failure"] = {"type": type(failure).__name__, "message": str(failure)}
    finally:
        journey.cleanup()
        journey.write_report()
    print(json.dumps({"status": journey.report["status"], "passed": journey.report["passed_stages"],
        "total": len(STAGES), "project_id": journey.project_id, "cleanup": journey.report.get("cleanup")}, ensure_ascii=False))
    return 0 if journey.report["status"] == "PASS" else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True, type=Path)
    parser.add_argument("--original-report", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--delivery-only", action="store_true")
    parser.add_argument("--revise-failed-delivery", action="store_true")
    args = parser.parse_args()
    config = json.loads(args.config.read_text())
    config.update(observation_timeout_seconds=120, bootstrap_observation_seconds=900)
    args.output.mkdir(parents=True, exist_ok=True)
    if (args.output / "report.json").exists():
        raise RuntimeError("Existing continuation evidence is retained; no automatic repeat.")
    if args.delivery_only or args.revise_failed_delivery:
        return delivery_only(config, args.original_report, args.output, args.revise_failed_delivery)
    previous = json.loads(args.original_report.read_text())
    authority = json.loads((args.original_report.parent / "pre-worker-timeout-authority.json").read_text())
    if previous["passed_stages"] != 2 or previous.get("actual_launches") \
            or any(authority[name] for name in ("attempts", "allocations", "models")):
        raise RuntimeError("Continuation requires the preserved zero-execution timeout boundary.")
    config.update(observation_timeout_seconds=120, bootstrap_observation_seconds=120)
    args.output.mkdir(parents=True, exist_ok=True)
    if (args.output / "report.json").exists():
        raise RuntimeError("Existing continuation evidence is retained; no automatic repeat.")
    journey = ContinueAccepted(config, args.output, args.original_report)
    try:
        journey.run()
    except Exception as failure:
        journey.report["status"] = "FAIL"
        if journey.report["stages"][journey.current_stage]["status"] != "PASS":
            journey.report["stages"][journey.current_stage] = {"status": "FAIL", "error_type": type(failure).__name__, "message": str(failure)}
        journey.report["failure"] = {"type": type(failure).__name__, "message": str(failure)}
    finally:
        journey.cleanup()
        journey.write_report()
    print(json.dumps({"status": journey.report["status"], "passed": journey.report["passed_stages"], "total": len(STAGES),
        "project_id": journey.project_id, "cleanup": journey.report.get("cleanup")}, ensure_ascii=False))
    return 0 if journey.report["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
