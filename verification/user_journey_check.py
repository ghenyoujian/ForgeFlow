#!/usr/bin/env python3
"""One GUI-originated project-to-DSH-to-delivery journey on an isolated API.

Default mode writes the execution plan only. Root supplies a frozen build and
private deployment configuration and schedules --run after competing probes.
Business writes originate in actual browser controls. API writes only provision
registered execution prerequisites or perform separately labelled cleanup.
"""
import argparse
import copy
import hashlib
import importlib.util
import json
import os
import re
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from pathlib import Path

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OUT = ROOT / "evidence/enterprise-ux/user-journey-r1"
API_BASE = "http://127.0.0.1:8794"
RESULT_PATH = "journey-result.txt"
EXPECTED = b"FORGEFLOW_USER_JOURNEY_OK\n"
SOURCE = "# 独立用户业务旅程\n- 仅在 journey-result.txt 写入 UTF-8 文本 FORGEFLOW_USER_JOURNEY_OK 并以一个换行结尾；独立作者、消费者与验证者须核对准确字节，经受控 Git 集成后可追溯原始证据。\n"
STAGES = ["project_and_requirements", "hierarchical_teams_and_owner", "real_dsh_flow_generation",
          "execution_configuration_check_and_approval", "gui_enqueue_and_actual_dsh_execution",
          "independent_verification_git_and_evidence"]
CODING_ORACLE = r'''import hashlib,json,os,pathlib
expected=b"FORGEFLOW_USER_JOURNEY_OK\n"
raw=pathlib.Path("journey-result.txt").read_bytes()
role=os.environ["FORGEFLOW_VERIFICATION_ROLE"]
cases={
 "author":[("exact_delivered_bytes","positive",raw==expected)],
 "consumer":[("utf8_consumer_reads_result","positive",raw.decode("utf-8")==expected.decode("utf-8"))],
 "independent":[("independent_reference_bytes","positive",hashlib.sha256(raw).digest()==hashlib.sha256(expected).digest()),
                ("wrong_payload_is_rejected","negative",raw==expected and b"FORGEFLOW_USER_JOURNEY_OK"!=expected)],
}[role]
report={"binding":json.loads(os.environ["FORGEFLOW_EVIDENCE_BINDING"]),"oracle_id":"ui-journey-fixed-text.v1",
 "cases":[{"name":n,"kind":k,"outcome":"passed" if ok else "failed"} for n,k,ok in cases]}
pathlib.Path(os.environ["FORGEFLOW_REPORT_PATH"]).write_text(json.dumps(report)+"\n")
raise SystemExit(0 if all(ok for _,_,ok in cases) else 1)
'''
PLANNING_CASES = {
    "author": [("native_final_artifact", "positive"), ("draft_schema_and_request_binding", "positive")],
    "consumer": [("finite_dag_consumer", "positive"), ("cycle_rejected", "negative")],
    "independent": [("original_source_preserved", "positive"), ("source_tamper_rejected", "negative"),
                    ("authority_tamper_rejected", "negative"), ("strict_duplicate_keys_rejected", "negative")],
}
CODING_CASES = {"author": [("exact_delivered_bytes", "positive")],
                "consumer": [("utf8_consumer_reads_result", "positive")],
                "independent": [("independent_reference_bytes", "positive"), ("wrong_payload_is_rejected", "negative")]}
SOCKET_PREPARATION_FAILURE = "native Unix socket path exceeds bounded platform path; use a shorter data root"
PLANNING_GUIDANCE_VERSION = "ui-journey.provider-reservation.v2"
PLANNING_INTENT_ORACLE = "a10-source-bound-planning-intent.v2"
PLANNING_INTENT_SHA256 = "f7bba425b67ee9570904a06c56c94d3b39c0fc6a4f3a69ae92e7fa202b88ea24"
HANDOFF_METHOD = "compact-intent.v2.verifier-input-handoff.v1"

def planning_request_cap(config, prior_actual_requests):
    cap = config.get("planning_max_model_requests", 8)
    ceiling = config.get("cumulative_model_request_ceiling", 12)
    if type(cap) is not int or not 1 <= cap <= 8 or type(ceiling) is not int \
            or prior_actual_requests + cap + 3 > ceiling:
        raise RuntimeError("The fresh planning declaration must retain the actual prior use and fit the cumulative model ceiling.")
    if config.get("verifier_handoff_failure_seal_path") and (cap != 7 or ceiling != 12):
        raise RuntimeError("The separately approved handoff method requires exactly two prior calls plus seven planning plus three delivery within twelve.")
    return cap

def static_template_sha256(envelope):
    value = copy.deepcopy(envelope)
    for key in ("operation_id", "attempt_id", "lease_id", "generation", "worker_id", "issued_at", "expires_at", "trace_id", "idempotency_key"):
        value.pop(key, None)
    return hashlib.sha256(json.dumps(["forgeflow.execution.template.v2", value],
        sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()

def sha(file):
    return hashlib.sha256(Path(file).read_bytes()).hexdigest()

def save(file, value):
    Path(file).write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n")

def private_save(file, value):
    with os.fdopen(os.open(file, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w") as stream:
        json.dump(value, stream)

def plan():
    return {"status": "SOURCE_READY_NOT_EXECUTED", "scope": "one actual GUI-originated six-stage user journey",
        "api_base": API_BASE, "database_name_prefix": "forgeflow_ui_journey_", "stages": STAGES,
        "expected_minimum_dsh_sessions": 2, "expected_minimum_model_requests": 3,
        "model_budgets": {"planning": 8, "execution_gui_declaration": 3},
        "historical_suites_repeated": [], "simulated_execution": False,
        "prerequisites": ["Root schedules the sole model/Worker window after strict probes",
            "Root starts API 8794 on a fresh forgeflow_ui_journey_* database with the final pinned server",
            "Root supplies the final build receipt and an immutable actual DSH Worker deployment template",
            "Template reuses official Headless and actual combined sandbox; private HOME/model credentials remain private",
            "Root supplies seven-dimensional limits and a model route document; no provider credentials in documents",
            "One actual Worker; both sessions sequential; the harness does not start a second API or build"],
        "private_config_fields": ["runtime_env_path", "build_receipt_path", "worker_config_template",
                                  "resource_limits", "model_route_document", "allow_model_calls"],
        "api_setup_only": ["executor_profiles", "resource_profiles", "model_routes", "verification_plans", "resource-policies"],
        "gui_commands": ["create managed project", "import original source", "create root and child team",
            "register exact Owner territory", "submit real DSH Flow generation", "bind real execution configuration",
            "check Flow", "approve Flow", "admission precheck", "enqueue", "verify and request controlled integration"],
        "witnesses": ["raw browser-originated HTTP replies and request bodies without authentication headers",
            "actual frozen launch receipts and live PID start ticks", "PostgreSQL authority readback",
            "candidate and integrated refs, exact output blob and retained verification logs",
            "one desktop and 390px screenshot of this new journey"],
        "limitations": ["six stage witnesses do not earn all product gates or 100-session production qualification",
            "journey starts with a privately supplied authenticated Owner session; GUI login is outside this scope",
            "provider cost stays unknown unless authoritative usage/pricing actually exists",
            "failed native generation is retained and never replaced by a mock or automatic second model attempt",
            "API pause during fixture cleanup is recorded separately and never counted as a GUI control"],
        "source_sha256": {str(file.relative_to(ROOT)): sha(file) for file in [Path(__file__),
            ROOT / "verification/fixtures/planning_verifier.py", ROOT / "console/src/features/planning/index.tsx",
            ROOT / "console/src/features/flow/index.tsx", ROOT / "console/src/features/runs/index.tsx"]}}

class Journey:
    def __init__(self, config, out, resume_from=None):
        self.config, self.out = config, out
        self.private = json.loads(Path(config["runtime_env_path"]).read_text())
        parsed = urllib.parse.urlsplit(self.private["DATABASE_URL"])
        if not parsed.path.lstrip("/").startswith("forgeflow_ui_journey_"):
            raise RuntimeError("A fresh dedicated UI journey database is required.")
        if config.get("allow_model_calls") is not True:
            raise RuntimeError("Root must schedule the actual model run in the private configuration.")
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        self.records, self.browser_records, self.errors, self.observations = [], [], [], []
        self.report = {"status": "RUNNING", "stages": {stage: {"status": "NOT_RUN"} for stage in STAGES},
            "scope": plan()["scope"], "api_base": API_BASE, "historical_suites_repeated": [],
            "credential_values_disclosed": False, "production_qualification": "UNVERIFIED"}
        self.worker = None
        self.server = None
        self.project_id = None
        self.resume_from = resume_from
        previous = json.loads(resume_from.read_text()) if resume_from else None
        self.previous = previous
        self.resume_planning = bool(previous and previous.get("passed_stages") == 2)
        self.preparation_seal = None
        self.budget_seal = None
        self.model_failure_seal = None
        self.handoff_failure_seal = None
        self.prior_project_model_requests = 2 if config.get("verifier_handoff_failure_seal_path") else 1 if config.get("model_failure_seal_path") else 0
        historical = config.get("historical_model_requests", 0)
        if type(historical) is not int or historical < 0 or (historical and resume_from
                and not (config.get("continue_operation_id") or config.get("zero_model_retry"))):
            raise RuntimeError("Historical model use is a non-negative external denominator for a fresh journey only.")
        self.prior_actual_model_requests = self.prior_project_model_requests + historical
        self.planning_request_cap = planning_request_cap(config, self.prior_actual_model_requests)
        self.resume_history = []
        self.bootstrap_replacement_confirmed = False
        if previous and (previous.get("status") != "FAIL" or previous.get("passed_stages") not in {0, 2}
                or not (previous.get("resumes_preserved_gui_project_response") or any(value.get("method") == "POST" and value.get("route", "").endswith("/projects")
                    and value.get("status") == 200 for value in previous.get("browser_http", [])))):
            raise RuntimeError("Resume requires the preserved GUI project and no completed model stage.")
        if self.resume_planning:
            self.resume_history = self.read_resume_history(resume_from)
            if config.get("verifier_handoff_failure_seal_path"):
                if config.get("planning_protocol") != "compact-intent.v2" or config.get("new_method_id") != HANDOFF_METHOD \
                        or config.get("new_method_owner_approved") is not True or config.get("projection_review_approved") is not True:
                    raise RuntimeError("The failed verifier input placement requires explicit approval of the fresh handoff method.")
                authority_path = Path(config["verifier_handoff_failure_seal_path"])
                if sha(authority_path) != config.get("verifier_handoff_failure_seal_sha256"):
                    raise RuntimeError("The separately preserved actual verifier placement failure seal changed.")
                self.handoff_failure_seal = json.loads(authority_path.read_text())
                self.validate_handoff_failure_seal(resume_from)
                if sha(config["worker_config_template"]) != previous["worker_template_sha256"]:
                    raise RuntimeError("The handoff method must retain the actual DSH Worker template and Doctor identity.")
            elif config.get("model_failure_seal_path"):
                if config.get("planning_protocol") != "compact-intent.v2" or config.get("new_method_owner_approved") is not True \
                        or config.get("projection_review_approved") is not True:
                    raise RuntimeError("A prior real model failure requires explicit Owner approval for the new compact-intent method.")
                authority_path = Path(config["model_failure_seal_path"])
                if sha(authority_path) != config.get("model_failure_seal_sha256"):
                    raise RuntimeError("The explicitly reviewed prior real-model failure seal changed.")
                self.model_failure_seal = json.loads(authority_path.read_text())
                self.validate_model_failure_seal(resume_from)
                if sha(config["worker_config_template"]) != previous["worker_template_sha256"]:
                    raise RuntimeError("The new planning method must retain the existing DSH Worker template and Doctor identity.")
            elif config.get("budget_failure_seal_path"):
                authority_path = Path(config["budget_failure_seal_path"])
                if sha(authority_path) != config.get("budget_failure_seal_sha256"):
                    raise RuntimeError("The explicitly scheduled zero-call budget recovery seal changed.")
                self.budget_seal = json.loads(authority_path.read_text())
                self.validate_budget_seal(resume_from)
                if sha(config["worker_config_template"]) != previous["worker_template_sha256"]:
                    raise RuntimeError("Budget recovery must retain the original actual DSH Worker template and Doctor identity.")
            elif config.get("preparation_failure_seal_path"):
                authority_path = Path(config["preparation_failure_seal_path"])
                if sha(authority_path) != config.get("preparation_failure_seal_sha256"):
                    raise RuntimeError("The explicitly scheduled preparation recovery seal changed.")
                self.preparation_seal = json.loads(authority_path.read_text())
                self.validate_preparation_seal(resume_from)
                if sha(config["worker_config_template"]) != previous["worker_template_sha256"]:
                    raise RuntimeError("Preparation recovery must retain the original actual DSH Worker template and Doctor identity.")
            else:
                authority_path = resume_from.parent / "final-zero-actor-authority.json"
                authority = json.loads(authority_path.read_text())
                if authority != {"attempt_count": 0, "projects_paused": True, "allocation_count": 0,
                        "native_model_count": 0, "port8794_open": False} or previous.get("actual_launches"):
                    raise RuntimeError("Planning recovery requires retained zero-attempt/model authority and closed actors.")
            self.report["inherited_gui_stages"] = {"report_path": str(resume_from), "report_sha256": sha(resume_from),
                "authority_path": str(authority_path), "authority_sha256": sha(authority_path),
                "build_receipt_sha256": previous["build_receipt_sha256"],
                "stages": STAGES[:2], "counts_as_new_gui_execution": False}
            for stage in STAGES[:2]:
                if previous["stages"][stage]["status"] != "PASS":
                    raise RuntimeError("Both inherited GUI stages must already have actual PASS evidence.")
                self.report["stages"][stage] = {**previous["stages"][stage], "evidence_origin": "INHERITED_ACTUAL_GUI"}
            submitted = []
            for report_path, report in self.resume_history:
                for entry in report.get("browser_http", []):
                    if entry.get("method") == "POST" and entry.get("route", "").endswith("/flow-generations") and entry.get("status") == 202:
                        response_path = report_path.parent / entry["response_file"]
                        if sha(response_path) != entry["response_sha256"]:
                            raise RuntimeError("A preserved GUI planning HTTP 202 response changed.")
                        original = json.loads(response_path.read_text())["data"]
                        submitted.append({"operation_id": original["operation_id"], "task_id": "planning-" + original["operation_id"],
                            "report_path": str(report_path), "report_sha256": sha(report_path), "browser_http": entry,
                            "actual_model_requests": 0, "replayed": False})
            expected_commands = 5 if self.handoff_failure_seal else 4 if self.model_failure_seal else 3 if self.budget_seal else 2 if self.preparation_seal else 1
            if len(submitted) != expected_commands or len({entry["operation_id"] for entry in submitted}) != len(submitted):
                raise RuntimeError("Recovery must preserve every distinct prior GUI planning command at the sealed boundary.")
            retained_seal = self.handoff_failure_seal or self.model_failure_seal
            if retained_seal:
                attempts_by_task = {entry["task_id"]: entry["attempt_id"] for entry in retained_seal["authority"]["attempts"]}
                requests = retained_seal["native_authority"]["native_model_requests"]
                for entry in submitted:
                    attempt_id = attempts_by_task.get(entry["task_id"])
                    entry["actual_model_requests"] = sum(request["attempt_id"] == attempt_id for request in requests)
                if sum(entry["actual_model_requests"] for entry in submitted) != self.prior_actual_model_requests:
                    raise RuntimeError("Every retained real model request must remain attributed to its original GUI command.")
            self.old_planning_tasks = [entry["task_id"] for entry in submitted]
            self.old_planning_task = self.old_planning_tasks[-1]
            if config.get("zero_model_retry"):
                self.old_planning_tasks = []
                self.report["zero_model_operation_recovery"] = {
                    "previous_operation_id": submitted[-1]["operation_id"],
                    "previous_status": "RECOVERY_REQUIRED", "previous_model_requests": 0,
                    "new_command_owner_authorized": True,
                    "original_status_and_evidence_changed": False,
                    "restart_evidence": config.get("timeout_continuation_evidence")}
            self.report["preserved_planning_commands"] = submitted
            self.report["unexecuted_original_planning"] = {key: submitted[0][key]
                for key in ("operation_id", "task_id", "actual_model_requests", "replayed")}
        self.fixture = Path(previous["private_fixture_root"]) if previous else Path(tempfile.mkdtemp(prefix="forgeflow-ui-journey-"))
        self.fixture.chmod(0o700)
        self.report["private_fixture_root"] = str(self.fixture)
        self.page = None
        self.current_stage = STAGES[0]
        self.launch_seen = {}
        self.uses_intent_protocol = bool(self.handoff_failure_seal or self.model_failure_seal
            or config.get("planning_protocol") == "compact-intent.v2")
        if config.get("build_receipt_path") == "PENDING_ROOT_FROZEN_BUILD_RECEIPT":
            raise RuntimeError("The fresh method remains source-ready until Root supplies its qualified frozen build receipt.")
        self.receipt = json.loads(Path(config["build_receipt_path"]).read_text())
        self.worker_binary = self.receipt["binaries"]["forgeflow-worker"]
        if sha(self.worker_binary["path"]) != self.worker_binary["sha256"]:
            raise RuntimeError("The scheduled Worker binary differs from its immutable build receipt.")
        self.report["build_receipt_sha256"] = sha(config["build_receipt_path"])
        if self.handoff_failure_seal and (not re.fullmatch(r"[a-f0-9]{64}", str(config.get("required_build_receipt_sha256", "")))
                or self.report["build_receipt_sha256"] != config["required_build_receipt_sha256"]
                or self.receipt.get("source_identity") != config.get("required_build_source_identity")):
            raise RuntimeError("Root must supply the exact newly qualified handoff build receipt and source identity before this fresh method can launch.")
        if config.get("blocked_build_receipt_sha256") == self.report["build_receipt_sha256"]:
            raise RuntimeError("Root must supply the next frozen fix build receipt before this recovery can launch.")
        if config.get("required_scope_source_sha256") and self.receipt.get("source_files", {}).get("crates/scheduler/src/service.rs") != config["required_scope_source_sha256"]:
            raise RuntimeError("The scheduled build receipt does not contain the frozen custom Worker scope fix.")
        if (self.preparation_seal or self.budget_seal or self.model_failure_seal or self.handoff_failure_seal) and (not config.get("required_native_controller_source_sha256")
                or self.receipt.get("source_files", {}).get("crates/worker/src/native_controller.rs") != config["required_native_controller_source_sha256"]):
            raise RuntimeError("Root must supply the frozen long-root socket fix before preparation recovery can launch.")
        if (self.budget_seal or self.model_failure_seal or self.handoff_failure_seal) and (not config.get("required_generation_source_sha256")
                or self.receipt.get("source_files", {}).get("crates/api/src/generation.rs") != config["required_generation_source_sha256"]):
            raise RuntimeError("Root must supply the frozen, explicitly reviewed planning API source before this method can launch.")
        if self.handoff_failure_seal and (not config.get("required_operations_source_sha256")
                or self.receipt.get("source_files", {}).get("crates/api/src/operations.rs") != config["required_operations_source_sha256"]):
            raise RuntimeError("The fresh method requires the separately frozen verifier single-file handoff implementation.")
        if self.uses_intent_protocol and (sha(ROOT / "verification/fixtures/planning_intent_verifier.py") != PLANNING_INTENT_SHA256
                or config.get("required_planning_intent_oracle_sha256") != PLANNING_INTENT_SHA256):
            raise RuntimeError("The new compact planning oracle must match its separately reviewed immutable source.")
        self.report["worker_binary_sha256"] = self.worker_binary["sha256"]
        self.report["worker_template_sha256"] = sha(config["worker_config_template"])
        self.report["driver_sha256"] = sha(__file__)
        self.report["model_request_budget"] = {"historical_actual_requests": historical,
            "planning_cap": self.planning_request_cap, "delivery_cap": 3,
            "cumulative_ceiling": config.get("cumulative_model_request_ceiling", 12),
            "historical_evidence": config.get("historical_model_evidence", []),
            "automatic_repeat": False}
        if resume_from:
            self.report["resumes_preserved_gui_project_response"] = {"report_path": str(resume_from), "report_sha256": sha(resume_from),
                "scope": "same actual GUI-created project; no second project create or prior model execution"}

    @staticmethod
    def read_resume_history(report_path):
        history, seen = [], set()
        while report_path:
            report_path = report_path.resolve()
            if report_path in seen or len(history) >= 8:
                raise RuntimeError("Preserved journey report ancestry must be finite and unique.")
            seen.add(report_path)
            report = json.loads(report_path.read_text())
            history.append((report_path, report))
            reference = report.get("resumes_preserved_gui_project_response")
            if not reference:
                break
            report_path = Path(reference["report_path"])
            if sha(report_path) != reference["report_sha256"]:
                raise RuntimeError("An inherited actual GUI report changed.")
        return list(reversed(history))

    def validate_preparation_seal(self, resume_from):
        seal = self.preparation_seal
        if seal.get("schema_version") != "forgeflow.ui-journey.socket-preparation-recovery.v1" \
                or seal.get("report_path") != str(resume_from) or seal.get("report_sha256") != sha(resume_from) \
                or seal.get("reason") != SOCKET_PREPARATION_FAILURE or self.previous.get("actual_launches"):
            raise RuntimeError("Only the sealed, never-launched native socket preparation failure can resume.")
        for witness in seal["witnesses"]:
            if sha(witness["path"]) != witness["sha256"]:
                raise RuntimeError("A sealed preparation failure witness changed.")
        authority = seal["authority"]
        attempts, allocations = authority["attempts"], authority["allocations"]
        if len(attempts) != 1 or len(allocations) != 5 or not authority["projects_paused"] \
                or authority["native_model_count"] != 0 or authority["native_session_count"] != 0:
            raise RuntimeError("Preparation recovery retains exactly one failed attempt and five released allocations, with zero models/sessions.")
        attempt = attempts[0]
        result = attempt["result"]
        stop = result["evidence"]["stop"]
        terminal = seal["controller_terminal"]
        sealed_result = json.loads(Path(seal["result_path"]).read_text())
        sealed_stop = json.loads(Path(seal["stop_path"]).read_text())
        sealed_authority = json.loads(Path(seal["authority_path"]).read_text())
        sealed_terminal = json.loads(Path(seal["controller_terminal_path"]).read_text())
        if sealed_result != result or sealed_stop != stop or sealed_authority != authority or sealed_terminal != terminal:
            raise RuntimeError("The sealed recovery facts must equal the actual retained Worker and PostgreSQL witnesses.")
        if attempt["state"] != "FAILED" or attempt["attempt_id"] != seal["attempt_id"] \
                or attempt["project_id"] != self.previous["project_id"] \
                or result["outcome"]["completion_reason"] != "WORKER_PREPARATION_FAILED" \
                or result["outcome"]["error_class"] != SOCKET_PREPARATION_FAILURE \
                or result["outcome"]["upstream_session_id"] is not None or result["outcome"]["final_artifact"] is not None \
                or stop["reason"] != SOCKET_PREPARATION_FAILURE or stop["process_exit_confirmed"] is not True \
                or any(stop[key] is not None for key in ("exit_code", "signal", "log_error")) \
                or any(stop[key] != 0 for key in ("stdout_bytes", "stderr_bytes", "notification_overflow")) \
                or terminal["authority"]["attempt_id"] != attempt["attempt_id"] or terminal["authority"]["state"] != "FAILED" \
                or any(terminal["authority"][key] != attempt[key]
                    for key in ("project_id", "task_id", "worker_id", "lease_id", "generation", "operation_id", "task_revision", "base_sha")) \
                or terminal["local_stop"] != stop or terminal["local_stop_sha256"] != seal["stop_sha256"] \
                or any(entry["state"] != "RELEASED" or entry["attempt_id"] != attempt["attempt_id"] for entry in allocations):
            raise RuntimeError("Actual Worker stop and controller terminal authority do not prove the exact pre-launch failure.")
        journal = Path(self.private["FORGEFLOW_DATA_ROOT"]) / "attempts" / attempt["attempt_id"]
        if str(journal) != result["evidence"]["journal"] or any((journal / name).exists()
                for name in ("launch-intent.json", "launch-receipt.json", "launch.lock", "native-controller.json")) \
                or list((journal / "native-rpc").iterdir()):
            raise RuntimeError("Preparation recovery rejects any original physical launch or native transport evidence.")
        for name, digest in seal["journal_sha256"].items():
            if sha(journal / name) != digest:
                raise RuntimeError("The actual original Worker preparation journal changed.")
        closure = seal["actor_closure"]
        if closure != json.loads(Path(seal["actor_closure_path"]).read_text()):
            raise RuntimeError("The sealed actor closure must equal the retained actual cleanup witness.")
        if closure["port8794_open"] or any(entry["present"] for entry in closure["pids"]) \
                or closure["native_model_count"] != 0 or closure["native_session_count"] != 0:
            raise RuntimeError("The original preparation recovery actors must be closed.")
        self.report["retained_preparation_failure"] = {"seal_path": str(self.config["preparation_failure_seal_path"]),
            "seal_sha256": self.config["preparation_failure_seal_sha256"], "attempt_id": attempt["attempt_id"],
            "allocation_ids": sorted(entry["allocation_id"] for entry in allocations), "reason": SOCKET_PREPARATION_FAILURE,
            "actual_model_requests": 0, "actual_native_sessions": 0, "physical_launches": 0,
            "old_attempt_replayed": False, "old_authority_deleted_or_reset": False}

    def validate_budget_seal(self, resume_from):
        seal = self.budget_seal
        if seal.get("schema_version") != "forgeflow.ui-journey.zero-call-budget-recovery.v1" \
                or seal.get("report_path") != str(resume_from) or seal.get("report_sha256") != sha(resume_from):
            raise RuntimeError("Only the exact sealed first-model controller rejection can resume.")
        for witness in seal["witnesses"]:
            if sha(witness["path"]) != witness["sha256"]:
                raise RuntimeError("A sealed zero-call budget failure witness changed.")
        authority = seal["authority"]
        if authority != json.loads(Path(seal["authority_path"]).read_text()) or len(authority["attempts"]) != 2 \
                or len(authority["allocations"]) != 10 or not authority["projects_paused"] \
                or authority["native_session_count"] != 1 or authority["live_lease_count"] != 0 \
                or any(authority[key] != 0 for key in ("native_model_count", "gateway_model_count", "provider_request_count")) \
                or any(entry["state"] != "FAILED" for entry in authority["attempts"]) \
                or any(entry["state"] != "RELEASED" for entry in authority["allocations"]):
            raise RuntimeError("Budget recovery retains two failed attempts, ten released allocations, one real session, and zero model/provider calls.")
        prior = Journey.__new__(Journey)
        prior.private, prior.config, prior.report = self.private, self.config, {}
        prior.preparation_seal = json.loads(Path(seal["prior_preparation_seal_path"]).read_text())
        prior.previous = json.loads(Path(prior.preparation_seal["report_path"]).read_text())
        prior.validate_preparation_seal(Path(prior.preparation_seal["report_path"]))
        prior_attempt = prior.preparation_seal["authority"]["attempts"][0]
        if next((entry for entry in authority["attempts"] if entry["attempt_id"] == prior_attempt["attempt_id"]), None) != prior_attempt:
            raise RuntimeError("The original never-launched preparation attempt cannot be deleted or changed.")
        attempt = next(entry for entry in authority["attempts"] if entry["attempt_id"] == seal["attempt_id"])
        result, terminal = attempt["result"], json.loads(Path(seal["controller_terminal_path"]).read_text())
        stop = json.loads(Path(seal["stop_path"]).read_text())
        launch = json.loads(Path(seal["launch_receipt_path"]).read_text())
        final = json.loads(Path(seal["final_path"]).read_text())
        budget = json.loads(Path(seal["budget_authority_path"]).read_text())
        root = budget["native_lifecycles"]
        if result != json.loads(Path(seal["result_path"]).read_text()) or result["outcome"]["completion_reason"] != "PROCESS_FAILED" \
                or result["outcome"]["exit_code"] != 1 or result["evidence"]["real_dsh"] is not True \
                or result["evidence"]["stop"] != stop or stop["exit_code"] != 1 or stop["reason"] != "executor_exited" \
                or stop["process_exit_confirmed"] is not True or stop["signal"] is not None or stop["log_error"] is not None \
                or final != {"type": "final", "text": ""} \
                or Path(seal["stderr_path"]).read_text() != "dsh: UNKNOWN: Managed controller rejected model_request: NATIVE_MODEL_BUDGET_EXHAUSTED\n" \
                or terminal["authority"]["state"] != "FAILED" or terminal["local_stop"] != stop \
                or terminal["local_stop_sha256"] != sha(seal["stop_path"]) \
                or any(terminal["authority"][key] != attempt[key]
                    for key in ("attempt_id", "project_id", "task_id", "worker_id", "lease_id", "generation", "operation_id", "task_revision", "base_sha")) \
                or launch != result["evidence"]["launch_receipt"] or launch["process"]["attempt_id"] != attempt["attempt_id"] \
                or len(self.previous.get("actual_launches", {})) != 1 \
                or self.previous["actual_launches"][attempt["attempt_id"]]["process"] != launch["process"] \
                or self.previous["actual_launches"][attempt["attempt_id"]]["live_identity_confirmed"] is not True \
                or self.previous["actual_launches"][attempt["attempt_id"]]["receipt_sha256"] != sha(seal["launch_receipt_path"]):
            raise RuntimeError("Actual launch, stopped process, empty final result, and exact first-request rejection must remain proven.")
        audit = result["evidence"]["scope_audit"]
        if any(audit[key] for key in ("changes", "untracked", "patch")) or audit["head_sha"] != attempt["base_sha"] \
                or audit["base_sha"] != attempt["base_sha"] or budget["attempt_envelope"]["max_model_requests"] != 8 \
                or budget["planning_resource_request"]["provider_inflight"] != 0 or len(root) != 1 or budget["native_allocations"] \
                or root[0]["native_session_id"] != result["outcome"]["upstream_session_id"] \
                or root[0]["parent_session_id"] is not None or root[0]["borrowed_parent_reservation"] is not True \
                or root[0]["max_output_tokens"] != 4096 or root[0]["state"] != "RELEASED" \
                or root[0]["release_reason"] != "trusted_worker_process_stopped" or not root[0]["process_stopped_at"] \
                or not root[0]["released_at"]:
            raise RuntimeError("Budget recovery requires the unchanged eight-request cap, zero canonical reservation, released root session, and no business result.")
        native = json.loads(Path(seal["native_authority_path"]).read_text())
        if native != seal["native_authority"] or len(native["native_sessions"]) != 1 \
                or native["native_lifecycles"] != root or native["native_allocations"] or native["live_lease_count"] != 0:
            raise RuntimeError("The real released native session and zero live leases must remain bound to actual PostgreSQL witnesses.")
        canonical = seal["canonical_repository"]
        head = subprocess.check_output(["git", "--git-dir", canonical, "rev-parse", "refs/heads/main"]).decode().strip()
        delivered = subprocess.run(["git", "--git-dir", canonical, "cat-file", "-e", "refs/heads/main:" + RESULT_PATH], capture_output=True)
        if head != attempt["base_sha"] or delivered.returncode == 0:
            raise RuntimeError("Budget recovery rejects any produced business delivery or canonical Git change.")
        journal = Path(self.private["FORGEFLOW_DATA_ROOT"]) / "attempts" / attempt["attempt_id"]
        for name, digest in seal["journal_sha256"].items():
            if sha(journal / name) != digest:
                raise RuntimeError("The original physically launched DSH journal changed.")
        closure = json.loads(Path(seal["actor_closure_path"]).read_text())
        if closure["port8794_open"] or any(entry["present"] for entry in closure["pids"]) \
                or closure["native_session_count"] != 1 or closure["released_allocation_count"] != 10 \
                or closure["live_lease_count"] != 0:
            raise RuntimeError("The first rejected-model session and every original actor must be stopped and released.")
        self.report["retained_zero_call_budget_failure"] = {"seal_path": self.config["budget_failure_seal_path"],
            "seal_sha256": self.config["budget_failure_seal_sha256"], "attempt_ids": sorted(entry["attempt_id"] for entry in authority["attempts"]),
            "allocation_ids": sorted(entry["allocation_id"] for entry in authority["allocations"]),
            "physical_launches": 1, "actual_native_sessions": 1, "actual_model_requests": 0,
            "actual_provider_requests": 0, "parent_max_model_requests": 8, "first_request_controller_rejection": "NATIVE_MODEL_BUDGET_EXHAUSTED",
            "old_attempts_or_model_consumption_replayed": False, "old_authority_deleted_or_reset": False}

    def validate_model_failure_seal(self, resume_from):
        """Preserve real prior model use; authorize no launch or automatic retry."""
        seal = self.model_failure_seal
        if seal.get("schema_version") != "forgeflow.ui-journey.projected-output-invalid-new-method.v1" \
                or seal.get("report_path") != str(resume_from) or seal.get("report_sha256") != sha(resume_from):
            raise RuntimeError("The new method requires the exact sealed prior real-model projected-output failure.")
        for witness in seal["witnesses"]:
            if sha(witness["path"]) != witness["sha256"]:
                raise RuntimeError("An original real-model failure witness changed.")
        authority = json.loads(Path(seal["authority_path"]).read_text())
        native = json.loads(Path(seal["native_authority_path"]).read_text())
        if authority != seal["authority"] or native != seal["native_authority"] \
                or len(authority["attempts"]) != 3 or sorted(entry["state"] for entry in authority["attempts"]) != ["CANCELLED", "FAILED", "FAILED"] \
                or len(authority["allocations"]) != 20 or any(entry["state"] != "RELEASED" for entry in authority["allocations"]) \
                or not authority["projects_paused"] or authority["live_lease_count"] != 0 \
                or len(native["native_sessions"]) != 2 or len(native["native_lifecycles"]) != 2 \
                or any(entry["state"] != "RELEASED" for entry in native["native_lifecycles"]) \
                or native["native_allocations"] or native["live_lease_count"] != 0 \
                or len(native["native_model_requests"]) != 1 or native["native_model_requests"][0]["status"] != "SETTLED" \
                or native["native_model_requests"][0]["usage_complete"] is not True \
                or authority["gateway_model_count"] != 0 or authority["provider_request_table_count"] != 0:
            raise RuntimeError("The new method must retain three terminal attempts, twenty released allocations, two real sessions, and one settled actual model call.")
        attempt = next(entry for entry in authority["attempts"] if entry["attempt_id"] == seal["attempt_id"])
        original = json.loads(Path(seal["worker_result_path"]).read_text())
        terminal = json.loads(Path(seal["controller_terminal_path"]).read_text())
        stop = json.loads(Path(seal["stop_path"]).read_text())
        launch = json.loads(Path(seal["launch_receipt_path"]).read_text())
        raw = Path(seal["final_path"]).read_bytes()
        final = json.loads(raw)
        if attempt["state"] != "CANCELLED" or original["outcome"]["completion_reason"] != "EXECUTOR_COMPLETED" \
                or original["outcome"]["transcript_completeness"] != "UPSTREAM_PROJECTION_TRUNCATED" \
                or original["outcome"]["exit_code"] != 0 or original["evidence"]["real_dsh"] is not True \
                or original["evidence"]["stop"] != stop or original["evidence"]["launch_receipt"] != launch \
                or stop["process_exit_confirmed"] is not True or stop["exit_code"] != 0 or stop["reason"] != "executor_exited" \
                or terminal["authority"]["state"] != "CANCELLED" or terminal["local_stop"] != stop \
                or terminal["local_stop_sha256"] != sha(seal["stop_path"]) \
                or any(terminal["authority"][key] != attempt[key]
                    for key in ("attempt_id", "project_id", "task_id", "worker_id", "lease_id", "generation", "operation_id", "task_revision", "base_sha")) \
                or len(self.previous.get("actual_launches", {})) != 1 \
                or self.previous["actual_launches"][attempt["attempt_id"]]["process"] != launch["process"] \
                or self.previous["actual_launches"][attempt["attempt_id"]]["live_identity_confirmed"] is not True \
                or final.get("type") != "final" or len(final["text"].encode()) != 3197 \
                or hashlib.sha256(final["text"].encode()).hexdigest() != "5b5370a8e3058cdefac77eb70e4c2082738f9497fe0b805b3c3b3640bd60696d":
            raise RuntimeError("The exact stopped launch, truncated upstream projection, and unrepaired invalid terminal text must remain preserved.")
        try:
            json.loads(final["text"])
        except json.JSONDecodeError:
            pass
        else:
            raise RuntimeError("The original invalid projected output cannot be repaired or replaced.")
        operation = json.loads(Path(seal["failed_operation_path"]).read_text())
        if operation["status"] != "FAILED" or operation["error"]["code"] != "MODEL_DRAFT_INVALID" \
                or operation["execution"]["attempt_id"] != attempt["attempt_id"]:
            raise RuntimeError("The original failed planning operation must remain failed.")
        request = native["native_model_requests"][0]
        if request["attempt_id"] != attempt["attempt_id"] or request["max_output_tokens"] != 4096 \
                or request["settlement"]["finish_reason"] != "stop" or not request["usage_complete"]:
            raise RuntimeError("The actual settled provider use and original output grant cannot be erased or increased.")
        rows = [json.loads(line) for line in Path(seal["stdout_path"]).read_text().splitlines()]
        truncated = [row for row in rows if row.get("truncated") is True]
        if len(truncated) != 1 or truncated[0].get("type") != "thinking" \
                or len(truncated[0]["text"].encode()) != 8192 or rows[-1] != final:
            raise RuntimeError("Original headless truncation metadata must match the retained thinking and final events.")
        for entry in seal["journal_sha256"]:
            journal = Path(self.private["FORGEFLOW_DATA_ROOT"]) / "attempts" / entry["attempt_id"]
            if sha(journal / entry["name"]) != entry["sha256"]:
                raise RuntimeError("An original actual Worker journal changed.")
        closure = json.loads(Path(seal["actor_closure_path"]).read_text())
        if closure["port8794_open"] or any(entry["present"] for entry in closure["pids"]) \
                or closure["native_model_count"] != 1 or closure["native_session_count"] != 2 \
                or closure["released_allocation_count"] != 20 or closure["live_lease_count"] != 0:
            raise RuntimeError("Every prior actual actor, model request and native session must be settled and stopped.")
        head = subprocess.check_output(["git", "--git-dir", seal["canonical_repository"], "rev-parse", "refs/heads/main"]).decode().strip()
        delivered = subprocess.run(["git", "--git-dir", seal["canonical_repository"], "cat-file", "-e", "refs/heads/main:" + RESULT_PATH], capture_output=True)
        if head != attempt["base_sha"] or delivered.returncode == 0:
            raise RuntimeError("The preserved failed method must have produced no business delivery or integration.")
        self.report["prior_real_model_projected_output_failure"] = {"seal_path": self.config["model_failure_seal_path"],
            "seal_sha256": self.config["model_failure_seal_sha256"], "actual_model_requests": 1, "physical_launches": 2,
            "actual_native_sessions": 2, "released_allocations": 20, "prior_planning_commands": 4,
            "accepted_model_drafts": 0, "invalid_projected_model_drafts": 1, "whole_transcript": "UPSTREAM_PROJECTION_TRUNCATED",
            "upstream_raw_http_body": "UNAVAILABLE", "original_output_repaired_or_replaced": False,
            "method": "new explicitly approved compact intent command; previous actual model use remains in denominator",
            "automatic_model_retry": False}

    def validate_handoff_failure_seal(self, resume_from):
        """Retain the two actual model calls and the pre-oracle placement failure."""
        seal = self.handoff_failure_seal
        if seal.get("schema_version") != "forgeflow.ui-journey.verifier-input-handoff-recovery.v1" \
                or seal.get("report_path") != str(resume_from) or seal.get("report_sha256") != sha(resume_from):
            raise RuntimeError("The fresh handoff method requires the separately sealed actual V2 placement failure.")
        for witness in seal["witnesses"]:
            if sha(witness["path"]) != witness["sha256"]:
                raise RuntimeError("A retained actual V2 failure witness changed.")
        authority = json.loads(Path(seal["authority_path"]).read_text())
        native = json.loads(Path(seal["native_authority_path"]).read_text())
        if authority != seal["authority"] or native != seal["native_authority"] \
                or len(authority["attempts"]) != 4 \
                or sorted(entry["state"] for entry in authority["attempts"]) != ["CANCELLED", "CANCELLED", "FAILED", "FAILED"] \
                or len(authority["allocations"]) != 30 or any(entry["state"] != "RELEASED" for entry in authority["allocations"]) \
                or not authority["projects_paused"] or authority["live_lease_count"] != 0 \
                or any(authority[key] != 0 for key in ("gateway_model_count", "provider_request_table_count")) \
                or len(native["native_sessions"]) != 3 or len(native["native_lifecycles"]) != 3 \
                or any(entry["state"] != "RELEASED" for entry in native["native_lifecycles"]) \
                or native["native_allocations"] or native["live_lease_count"] != 0 \
                or len(native["native_model_requests"]) != 2 \
                or any(entry["status"] != "SETTLED" or not entry["usage_complete"] for entry in native["native_model_requests"]):
            raise RuntimeError("The handoff method retains four terminal attempts, thirty released allocations, three sessions and two settled actual model calls.")
        prior_path = Path(seal["prior_model_failure_seal_path"])
        if sha(prior_path) != seal["prior_model_failure_seal_sha256"]:
            raise RuntimeError("The earlier invalid V1 output seal cannot be changed or overwritten.")
        prior = Journey.__new__(Journey)
        prior.private, prior.report = self.private, {}
        prior.config = {**self.config, "model_failure_seal_path": str(prior_path),
            "model_failure_seal_sha256": seal["prior_model_failure_seal_sha256"]}
        prior.model_failure_seal = json.loads(prior_path.read_text())
        prior.previous = json.loads(Path(prior.model_failure_seal["report_path"]).read_text())
        prior.validate_model_failure_seal(Path(prior.model_failure_seal["report_path"]))
        for old in prior.model_failure_seal["authority"]["attempts"]:
            if next((entry for entry in authority["attempts"] if entry["attempt_id"] == old["attempt_id"]), None) != old:
                raise RuntimeError("No earlier actual attempt may be reset or normalized by the handoff method.")
        attempt = next(entry for entry in authority["attempts"] if entry["attempt_id"] == seal["attempt_id"])
        original = json.loads(Path(seal["worker_result_path"]).read_text())
        terminal = json.loads(Path(seal["controller_terminal_path"]).read_text())
        stop = json.loads(Path(seal["stop_path"]).read_text())
        launch = json.loads(Path(seal["launch_receipt_path"]).read_text())
        raw = Path(seal["final_path"]).read_bytes()
        final = json.loads(raw)
        operation = json.loads(Path(seal["failed_operation_path"]).read_text())
        primary = operation["error"]["details"]["primary"]
        closure = json.loads(Path(seal["actor_closure_path"]).read_text())
        if attempt["state"] != "CANCELLED" or original["outcome"]["completion_reason"] != "EXECUTOR_COMPLETED" \
                or original["outcome"]["exit_code"] != 0 or original["evidence"]["real_dsh"] is not True \
                or original["evidence"]["stop"] != stop or original["evidence"]["launch_receipt"] != launch \
                or stop["process_exit_confirmed"] is not True or stop["exit_code"] != 0 \
                or terminal["authority"]["state"] != "CANCELLED" or terminal["local_stop"] != stop \
                or terminal["local_stop_sha256"] != sha(seal["stop_path"]) \
                or any(terminal["authority"][key] != attempt[key]
                    for key in ("attempt_id", "project_id", "task_id", "worker_id", "lease_id", "generation", "operation_id", "task_revision", "base_sha")) \
                or len(self.previous.get("actual_launches", {})) != 1 \
                or self.previous["actual_launches"][attempt["attempt_id"]]["process"] != launch["process"] \
                or self.previous["actual_launches"][attempt["attempt_id"]]["live_identity_confirmed"] is not True \
                or len(raw) != 859 or len(final["text"].encode()) != 780 \
                or sha(seal["final_path"]) != "edd09b61224b9d06c5465f416da9b251b3241f5b3b0e44ca703dea6e8a54236d" \
                or json.loads(final["text"]).get("schema_version") != "forgeflow.planning-intent.v1" \
                or operation["status"] != "FAILED" or operation["error"]["code"] != "ARTIFACT_VERIFICATION_FAILED" \
                or operation["error"]["message"] != "VERIFIER_INVALID: verifier readonly input exposes canonical repository or control state" \
                or primary["planning_attempt_id"] != attempt["attempt_id"] or primary["model_text_utf8_bytes"] != 780 \
                or primary["output_artifact"]["sha256"] != sha(seal["final_path"]) \
                or closure["status"] != "PASS" or closure["actual_planning_case_execution_denominator"] != 0 \
                or closure["evidence_receipt_count_new_method"] != 0 or closure["actual_model_request_count_cumulative"] != 2:
            raise RuntimeError("The original V2 raw output and exact pre-oracle placement failure must remain unchanged.")
        for entry in seal["journal_sha256"]:
            journal = Path(self.private["FORGEFLOW_DATA_ROOT"]) / "attempts" / entry["attempt_id"]
            if sha(journal / entry["name"]) != entry["sha256"]:
                raise RuntimeError("An original V2 physical execution journal changed.")
        head = subprocess.check_output(["git", "--git-dir", seal["canonical_repository"], "rev-parse", "refs/heads/main"]).decode().strip()
        delivered = subprocess.run(["git", "--git-dir", seal["canonical_repository"], "cat-file", "-e", "refs/heads/main:" + RESULT_PATH], capture_output=True)
        if head != attempt["base_sha"] or delivered.returncode == 0:
            raise RuntimeError("The failed planning history must have no business delivery or canonical integration.")
        self.report["retained_verifier_input_placement_failure"] = {"seal_path": self.config["verifier_handoff_failure_seal_path"],
            "seal_sha256": self.config["verifier_handoff_failure_seal_sha256"], "attempt_id": attempt["attempt_id"],
            "actual_model_requests_cumulative": 2, "physical_launches_cumulative": 3, "actual_native_sessions": 3,
            "terminal_attempts": 4, "released_allocations": 30, "prior_planning_commands": 5,
            "actual_old_planning_verification_cases": 0, "old_operation_revived_or_retried": False,
            "raw_final_bytes": 859, "raw_model_text_bytes": 780, "original_raw_output_replaced": False}

    def api(self, method, route, body=None, purpose="READ_ONLY_WITNESS"):
        headers = {"Authorization": "Bearer " + self.private["FORGEFLOW_OWNER_TOKEN"], "Accept": "application/json"}
        if method != "GET":
            if purpose not in {"EXECUTION_PREREQUISITE", "FIXTURE_CLEANUP"}:
                raise RuntimeError("Business writes must originate in browser controls.")
            headers.update({"Content-Type": "application/json", "Idempotency-Key": uuid.uuid4().hex})
        request = urllib.request.Request(API_BASE + "/api/v1" + route, headers=headers, method=method,
            data=None if body is None else json.dumps(body).encode())
        try:
            response = self.opener.open(request, timeout=self.config.get("observation_timeout_seconds", 30))
        except urllib.error.HTTPError as error:
            response = error
        raw = response.read()
        filename = f"api-{len(self.records) + 1:04d}.response.bin"
        (self.out / filename).write_bytes(raw)
        value = json.loads(raw)
        self.records.append({"method": method, "route": route, "status": response.status, "body": body,
            "purpose": purpose, "response_file": filename, "response_sha256": hashlib.sha256(raw).hexdigest()})
        if response.status >= 400:
            raise RuntimeError(f"Actual API {method} {route}: HTTP {response.status} {value.get('code')}")
        return value["data"]

    def browser_response(self, response):
        if "/api/v1/" not in response.url or "text/event-stream" in response.headers.get("content-type", ""):
            return
        try:
            body = response.request.post_data_json if response.request.post_data else None
            self.browser_records.append({"method": response.request.method,
                "route": response.url.replace(API_BASE + "/api/v1", ""), "status": response.status,
                "body": body, "response_body_capture": "COMMAND_CLICK_OR_READ_ONLY_API_WITNESS"})
        except Exception:
            # Navigation can abort an old read; it is not upgraded to a successful response.
            self.browser_records.append({"method": response.request.method, "route": response.url,
                "status": response.status, "response_unavailable": True})

    def click(self, button, route, method="POST"):
        with self.page.expect_response(lambda response: response.request.method == method
                and urllib.parse.unquote(urllib.parse.urlsplit(response.url).path) == "/api/v1" + route, timeout=30000) as pending:
            button.click()
        response = pending.value
        try:
            raw = response.body()
            filename = f"command-{len(self.browser_records):05d}.response.bin"
            (self.out / filename).write_bytes(raw)
            matching = [entry for entry in self.browser_records if entry["method"] == method
                and urllib.parse.unquote(urllib.parse.urlsplit(entry["route"]).path) in {route, "/api/v1" + route}]
            if matching:
                matching[-1].update(response_file=filename, response_sha256=hashlib.sha256(raw).hexdigest())
            value = json.loads(raw)
        except Exception:
            # location.assign can discard Chromium's response-body resource after
            # a successful project POST. Read back the actual GUI request identity;
            # never submit another project command or fabricate its response body.
            if route != "/projects" or response.status >= 400:
                raise
            request_body = response.request.post_data_json
            if not request_body.get("project_id"):
                raise
            project = self.api("GET", "/projects/" + request_body["project_id"])
            self.report["project_navigation_response_readback"] = {"status": response.status,
                "browser_request_project_id": request_body["project_id"], "readback_project_id": project["project_id"]}
            return project
        if response.status >= 400:
            raise RuntimeError(f"Browser command {route}: HTTP {response.status} {value.get('code')}")
        return value["data"]

    def stage(self, stage, condition, **facts):
        self.current_stage = stage
        self.report["stages"][stage] = {"status": "PASS" if condition else "FAIL", **facts}
        self.write_report()
        if not condition:
            raise RuntimeError("Actual user journey failed at " + stage)
        print(json.dumps({"journey_stage": stage, "status": "PASS"}), flush=True)

    def wait(self, callback, seconds, label):
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            if self.worker and self.worker.poll() is not None:
                raise RuntimeError("The actual Worker exited while waiting for " + label)
            value = callback()
            if value:
                return value
            self.page.wait_for_timeout(2000)
        raise RuntimeError(label + " timed out; existing processes and evidence are retained.")

    def operation(self, operation_id):
        def done():
            value = self.api("GET", "/operations/" + operation_id)
            if value.get("execution", {}).get("attempt_id"):
                self.observe_launch(value["execution"]["attempt_id"])
            if value.get("status") in {"FAILED", "CANCELLED", "BLOCKED", "RECOVERY_REQUIRED"}:
                save(self.out / (operation_id + ".failed.json"), value)
                raise RuntimeError("Actual operation failed: " + str(value.get("error", {}).get("code", value.get("status"))))
            return value if value.get("status") == "SUCCEEDED" else None
        return self.wait(done, 900, "actual operation " + operation_id)

    def observe_launch(self, attempt_id):
        receipt_path = Path(self.private["FORGEFLOW_DATA_ROOT"]) / "attempts" / attempt_id / "launch-receipt.json"
        if not receipt_path.exists():
            return
        receipt = json.loads(receipt_path.read_text())
        process = receipt["process"]
        live = False
        try:
            fields = Path(f"/proc/{process['pid']}/stat").read_text().rsplit(") ", 1)[1].split()
            live = fields[0] not in {"Z", "X"} and int(fields[19]) == process["start_ticks"]
        except (OSError, ValueError, IndexError):
            pass
        if live:
            self.launch_seen[attempt_id] = {"receipt_sha256": sha(receipt_path), "process": process,
                "command_program": receipt["command_program"], "execution_id": receipt["execution_id"], "live_identity_confirmed": True}

    def retain_execution_artifacts(self, attempts):
        retained = []
        for attempt in attempts:
            directory = Path(self.private["FORGEFLOW_DATA_ROOT"]) / "attempts" / attempt["attempt_id"]
            for name in ("launch-receipt.json", "result.json", "stdout.ndjson", "stderr.log", "final.json"):
                source = directory / name
                if source.is_file():
                    target = self.out / (attempt["attempt_id"] + "." + name)
                    target.write_bytes(source.read_bytes())
                    retained.append({"attempt_id": attempt["attempt_id"], "kind": name,
                        "source": str(source), "evidence_file": target.name, "sha256": sha(target), "size": target.stat().st_size})
        self.report["retained_execution_artifacts"] = retained

    def retain_verification_artifacts(self, receipts):
        retained = []
        for receipt in receipts:
            reference = receipt.get("artifact")
            if not reference:
                continue
            route = f"/artifacts/{reference['artifact_id']}/content?project_id={self.project_id}"
            request = urllib.request.Request(API_BASE + "/api/v1" + route,
                headers={"Authorization": "Bearer " + self.private["FORGEFLOW_OWNER_TOKEN"]})
            with self.opener.open(request, timeout=30) as response:
                raw = response.read()
            digest = hashlib.sha256(raw).hexdigest()
            if digest != reference["sha256"]:
                raise RuntimeError("Actual verification artifact bytes differ from their receipt.")
            target = self.out / (receipt["receipt_id"] + ".raw-verification-log.bin")
            target.write_bytes(raw)
            retained.append({"receipt_id": receipt["receipt_id"], "artifact_id": reference["artifact_id"],
                "sha256": digest, "evidence_file": target.name})
        self.report["retained_verification_artifacts"] = retained

    def verification_plan(self, identity, oracle, cases, oracle_id, worker_id):
        program = "/usr/bin/python3"
        commands = [{"role": role, "program": program, "args": ["-I", "-B", str(oracle)], "env": {},
            "executable_hash": sha(program), "bound_inputs": [{"path": str(oracle), "sha256": sha(oracle)}],
            "report_path": role + ".json", "expected_cases": [{"name": name, "kind": kind} for name, kind in cases[role]],
            "timeout_seconds": 20} for role in ("author", "consumer", "independent")]
        return {"plan_id": identity, "task_revision": 1, "contract_version": "none", "input_hash": "unbound-template",
            "environment_profile": "actual-gui-journey", "oracle_id": oracle_id,
            "verifier_id": "independent-ui-journey-oracle", "author_id": worker_id, "commands": commands}

    def ensure_document(self, collection, identity, value):
        documents = self.api("GET", f"/projects/{self.project_id}/documents/{collection}?limit=500")
        if len(documents) >= 500:
            raise RuntimeError("Fixture prerequisite discovery is incomplete; never reuse a truncated collection.")
        found = next((document for document in documents if document.get("id", document.get("plan_id")) == identity), None)
        if found:
            if not isinstance(found.get("revision"), int) or {key: val for key, val in found.items() if key != "revision"} != value:
                raise RuntimeError("An immutable prerequisite already exists with different meaning: " + identity)
            self.report.setdefault("reused_immutable_documents", []).append({"collection": collection,
                "id": identity, "revision": found["revision"]})
            return found
        return self.api("POST", f"/projects/{self.project_id}/documents/{collection}",
            {"id": identity, "expected_revision": None, "value": value}, "EXECUTION_PREREQUISITE")

    def pre_model_authority(self):
        return json.loads(self.db("SELECT jsonb_build_object('attempt_count',(SELECT count(*) FROM attempts WHERE project_id='" + self.project_id
            + "'),'native_model_count',(SELECT count(*) FROM native_model_requests WHERE project_id='" + self.project_id
            + "'),'native_session_count',(SELECT count(*) FROM native_sessions WHERE project_id='" + self.project_id
            + "'),'gateway_model_count',(SELECT count(*) FROM model_request_permit m JOIN attempts a ON a.attempt_id=m.attempt_id WHERE a.project_id='" + self.project_id
            + "'),'provider_request_count',(SELECT count(*) FROM provider_requests WHERE project_id='" + self.project_id
            + "'),'allocation_count',(SELECT count(*) FROM resource_allocations WHERE project_id='" + self.project_id
            + "'),'project_paused',(SELECT paused FROM projects WHERE project_id='" + self.project_id
            + "'),'live_workers',(SELECT coalesce(jsonb_agg(worker_id),'[]'::jsonb) FROM workers WHERE project_id='" + self.project_id
            + "' AND heartbeat_at>clock_timestamp()-interval '2 minutes'));"))

    def assert_pre_model_paused(self, expected_live_workers=()):
        facts = self.pre_model_authority()
        expected_attempts, expected_allocations = (4, 30) if self.handoff_failure_seal else (3, 20) if self.model_failure_seal else (2, 10) if self.budget_seal else (1, 5) if self.preparation_seal else (0, 0)
        expected_sessions = 3 if self.handoff_failure_seal else 2 if self.model_failure_seal else 1 if self.budget_seal else 0
        expected_models = self.prior_project_model_requests
        if facts["attempt_count"] != expected_attempts or facts["allocation_count"] != expected_allocations \
                or facts["native_session_count"] != expected_sessions \
                or facts["native_model_count"] != expected_models \
                or any(facts[key] != 0 for key in ("gateway_model_count", "provider_request_count")) \
                or facts["project_paused"] is not True or set(facts["live_workers"]) != set(expected_live_workers):
            save(self.out / "pre-model-authority-blocked.json", facts)
            raise RuntimeError("The paused fixture must preserve its exact retained authority, real model use, and scheduled Worker identities.")
        if self.preparation_seal or self.budget_seal or self.model_failure_seal or self.handoff_failure_seal:
            live = json.loads(self.db("SELECT jsonb_build_object('attempts',(SELECT coalesce(jsonb_agg(data),'[]'::jsonb) FROM attempts WHERE project_id='" + self.project_id
                + "'),'allocations',(SELECT coalesce(jsonb_agg(row_to_json(a)),'[]'::jsonb) FROM resource_allocations a WHERE project_id='" + self.project_id + "'));"))
            sealed = (self.handoff_failure_seal or self.model_failure_seal or self.budget_seal or self.preparation_seal)["authority"]
            if sorted(live["attempts"], key=lambda entry: entry["attempt_id"]) != sorted(sealed["attempts"], key=lambda entry: entry["attempt_id"]) \
                    or sorted(live["allocations"], key=lambda entry: entry["allocation_id"]) \
                    != sorted(sealed["allocations"], key=lambda entry: entry["allocation_id"]):
                save(self.out / "pre-model-retained-authority-blocked.json", live)
                raise RuntimeError("The actual failed attempt or released allocations differ from the sealed original authority.")
            if self.handoff_failure_seal:
                self.validate_handoff_failure_seal(self.resume_from)
                native = self.model_native_authority()
                if native != self.handoff_failure_seal["native_authority"]:
                    save(self.out / "pre-model-retained-handoff-native-authority-blocked.json", native)
                    raise RuntimeError("The two settled calls and three released native sessions differ from the new immutable seal.")
                facts["retained_physical_launches"] = 3
            elif self.model_failure_seal:
                self.validate_model_failure_seal(self.resume_from)
                native = self.model_native_authority()
                if native != self.model_failure_seal["native_authority"]:
                    save(self.out / "pre-model-prior-real-model-authority-blocked.json", native)
                    raise RuntimeError("The actual settled prior model request or released real sessions changed.")
                facts["retained_physical_launches"] = 2
            elif self.budget_seal:
                self.validate_budget_seal(self.resume_from)
                native = json.loads(self.db("SELECT jsonb_build_object('native_sessions',(SELECT coalesce(jsonb_agg(row_to_json(n)),'[]'::jsonb) FROM native_sessions n WHERE project_id='" + self.project_id
                    + "'),'native_lifecycles',(SELECT coalesce(jsonb_agg(row_to_json(n)),'[]'::jsonb) FROM native_child_lifecycles n WHERE project_id='" + self.project_id
                    + "'),'native_allocations',(SELECT coalesce(jsonb_agg(row_to_json(n)),'[]'::jsonb) FROM native_child_allocations n WHERE project_id='" + self.project_id
                    + "'),'live_lease_count',(SELECT count(*) FROM leases WHERE project_id='" + self.project_id + "' AND revoked_at IS NULL AND expires_at>clock_timestamp()));"))
                if native != self.budget_seal["native_authority"] or native["live_lease_count"] != 0:
                    save(self.out / "pre-model-retained-native-authority-blocked.json", native)
                    raise RuntimeError("The actual released root session or live lease authority differs from the sealed original.")
                facts["retained_physical_launches"] = 1
            else:
                self.validate_preparation_seal(self.resume_from)
            facts["retained_attempt_ids"] = sorted(entry["attempt_id"] for entry in sealed["attempts"])
            facts["retained_allocation_ids"] = sorted(entry["allocation_id"] for entry in sealed["allocations"])
        return facts

    def model_native_authority(self):
        return json.loads(self.db("SELECT jsonb_build_object('native_sessions',(SELECT coalesce(jsonb_agg(row_to_json(n) ORDER BY upstream_session_id),'[]'::jsonb) FROM native_sessions n WHERE project_id='" + self.project_id
            + "'),'native_lifecycles',(SELECT coalesce(jsonb_agg(row_to_json(n) ORDER BY allocation_id),'[]'::jsonb) FROM native_child_lifecycles n WHERE project_id='" + self.project_id
            + "'),'native_allocations',(SELECT coalesce(jsonb_agg(row_to_json(n) ORDER BY resource_allocation_id),'[]'::jsonb) FROM native_child_allocations n WHERE project_id='" + self.project_id
            + "'),'native_model_requests',(SELECT coalesce(jsonb_agg(jsonb_build_object('request_id',request_id,'attempt_id',attempt_id,'status',status,'native_session_id',native_session_id,'max_output_tokens',max_output_tokens,'purpose',purpose,'usage',usage,'usage_complete',usage_complete,'settlement',settlement) ORDER BY request_id),'[]'::jsonb) FROM native_model_requests WHERE project_id='" + self.project_id
            + "'),'live_lease_count',(SELECT count(*) FROM leases WHERE project_id='" + self.project_id + "' AND revoked_at IS NULL AND expires_at>clock_timestamp()));"))

    def prerequisites(self, root_team, child_team):
        """Provision immutable documents and authority; launch no Worker here."""
        worker_id = "ui-journey-worker-" + uuid.uuid4().hex[:12]
        tag = uuid.uuid4().hex[:8]
        self.worker_scope_id = f"ui-{tag}-worker"
        config = json.loads(Path(self.config["worker_config_template"]).read_text())
        if config.get("controlled_workload_programs"):
            raise RuntimeError("This journey requires actual DSH, not controlled program execution.")
        config.update(control_url=API_BASE, project_id=self.project_id, worker_id=worker_id,
            data_root=self.private["FORGEFLOW_DATA_ROOT"], max_active_attempts=1, poll_seconds=1)
        self.worker_config = config
        profile = copy.deepcopy(config["profile"])
        if config.get("managed_dsh"):
            profile.update(kind="DSH_MANAGED", native_mode=config["managed_dsh"])
        profile_id = profile["id"]
        planning_source = ROOT / "verification/fixtures/planning_intent_verifier.py" if self.uses_intent_protocol else ROOT / "verification/fixtures/planning_verifier.py"
        planning_oracle = self.fixture / ("planning-intent-verifier-f7bba425b67e.v2.py" if self.uses_intent_protocol else "planning-verifier.py")
        coding_oracle = self.fixture / "coding-verifier.py"
        for file, expected in ((planning_oracle, planning_source.read_bytes()),
                               (coding_oracle, CODING_ORACLE.encode())):
            if file.exists():
                if file.read_bytes() != expected:
                    raise RuntimeError("A retained independent oracle differs from the frozen source.")
            else:
                file.write_bytes(expected)
                file.chmod(0o444)
        sandbox = copy.deepcopy(config["sandbox"])
        guard = self.receipt["binaries"]["forgeflow-sandbox-guard"]
        if sha(guard["path"]) != guard["sha256"]:
            raise RuntimeError("The sandbox guard differs from the scheduled immutable receipt.")
        sandbox.update(guard_program=guard["path"], guard_sha256=guard["sha256"])
        sandbox["readonly_paths"] = list(dict.fromkeys([*sandbox["readonly_paths"], str(planning_oracle), str(coding_oracle)]))
        config["sandbox"] = sandbox
        resource_id = "ui-journey-resource." + tag
        self.planning_template_id = "ui-planning-template." + tag
        if self.uses_intent_protocol:
            self.planning_template_id = "ui-planning-intent.v2." + tag
        self.coding_template_id = "ui-coding-template." + tag
        planning_cases, planning_oracle_id = PLANNING_CASES, "a10-source-bound-flow-draft.v1"
        if self.uses_intent_protocol:
            if sha(planning_oracle) != PLANNING_INTENT_SHA256:
                raise RuntimeError("The copied new oracle differs from its frozen V2 source.")
            spec = importlib.util.spec_from_file_location("forgeflow_planning_intent_cases", planning_oracle)
            oracle_module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(oracle_module)
            planning_cases, planning_oracle_id = oracle_module.CASES, oracle_module.ORACLE
            self.planning_expected_cases = planning_cases
            if planning_oracle_id != PLANNING_INTENT_ORACLE or {role: len(cases) for role, cases in planning_cases.items()} \
                    != {"author": 3, "consumer": 5, "independent": 17}:
                raise RuntimeError("The new independent V2 verification plan requires exactly 25 separately declared cases.")
            self.report["new_planning_method"] = {"method": HANDOFF_METHOD if self.handoff_failure_seal else "compact-intent.v2", "wire_schema": "forgeflow.planning-intent.v1",
                "oracle_id": planning_oracle_id, "oracle_path": str(planning_oracle), "oracle_sha256": sha(planning_oracle),
                "verification_template_id": self.planning_template_id, "planned_cases": {role: len(cases) for role, cases in planning_cases.items()},
                "prior_actual_model_requests": self.prior_actual_model_requests, "new_planning_request_cap": self.planning_request_cap, "delivery_request_cap": 3,
                "cumulative_declared_upper_bound": 12, "automatic_model_retry": False, "owner_approved_new_method": True,
                "old_oracle_and_failed_output_changed": False, "executor_profile_or_doctor_changed": False}
        documents = [("executor_profiles", profile_id, profile),
            ("resource_profiles", resource_id, {"id": resource_id, "sandbox": sandbox, "build_capable": False}),
            ("model_routes", profile["model_route_id"], self.config["model_route_document"]),
            ("verification_plans", self.planning_template_id, self.verification_plan(self.planning_template_id, planning_oracle,
                planning_cases, planning_oracle_id, worker_id)),
            ("verification_plans", self.coding_template_id, self.verification_plan(self.coding_template_id, coding_oracle,
                CODING_CASES, "ui-journey-fixed-text.v1", worker_id))]
        for collection, identity, value in documents:
            self.ensure_document(collection, identity, value)
        self.worker_config_path = self.fixture / ("worker-config-" + tag + ".json")
        private_save(self.worker_config_path, config)
        limits = self.config["resource_limits"]
        if set(limits) != {"active_slot", "coding_slot", "cpu_units", "memory_bytes", "build_permit", "gpu_permit", "provider_inflight"}:
            raise RuntimeError("Root must supply the exact seven-dimensional scheduled limits.")
        scopes = [("global", None, None, None, None), ("project", self.project_id, None, None, "global"),
            ("root", self.project_id, root_team, None, "project"), ("child", self.project_id, child_team, None, "root")]
        self.global_scope_id = f"ui-{tag}-global"
        self.capacity_scope_ids = []
        if self.resume_planning:
            current = self.api("GET", "/resources")
            retained_by_id = {}
            for _, report in self.resume_history:
                for entry in report.get("api_http", []):
                    if entry["method"] == "POST" and entry["route"] == "/resource-policies" and entry["status"] == 200:
                        policy = entry["body"]["policy"]
                        retained_by_id[policy["scope_id"]] = policy
            retained = list(retained_by_id.values())
            for name, project, team, worker, parent in scopes:
                selected = [policy for policy in retained if policy["project_id"] == project and policy["team_id"] == team
                    and policy["worker_id"] is None]
                if len(selected) != 1:
                    raise RuntimeError("Retained hierarchy lacks one exact prerequisite scope: " + name)
                found = next((policy for policy in current if policy["scope_id"] == selected[0]["scope_id"]), None)
                if not found or found["paused"] or any(found[key] != selected[0][key]
                        for key in ("scope_id", "parent_scope_id", "project_id", "team_id", "worker_id", "limits")):
                    raise RuntimeError("Retained resource hierarchy changed; no silent replacement is allowed.")
                if name == "global":
                    self.global_scope_id = found["scope_id"]
                self.capacity_scope_ids.append(found["scope_id"])
            for old in (policy for policy in retained if policy["worker_id"]):
                found = next((policy for policy in current if policy["scope_id"] == old["scope_id"]), None)
                if not found or found["worker_id"] != old["worker_id"]:
                    raise RuntimeError("Original Worker scope identity changed unexpectedly.")
                if not found["paused"]:
                    self.api("POST", "/resource-policies", {"policy": {**found, "paused": True},
                        "expected_revision": found["revision"]}, "EXECUTION_PREREQUISITE")
            self.report["retired_worker_ids"] = [policy["worker_id"] for policy in retained if policy["worker_id"]]
        else:
            for name, project, team, worker, parent in scopes:
                self.api("POST", "/resource-policies", {"policy": {"scope_id": f"ui-{tag}-{name}",
                    "parent_scope_id": f"ui-{tag}-{parent}" if parent else None, "project_id": project, "team_id": team,
                    "worker_id": worker, "limits": limits, "paused": False, "revision": 0}}, "EXECUTION_PREREQUISITE")
                self.capacity_scope_ids.append(f"ui-{tag}-{name}")
        if limits["provider_inflight"] < 1:
            raise RuntimeError("The scheduled Worker limits must already permit one provider request; the harness never raises capacity.")
        self.report["scheduled_worker_id"] = worker_id
        self.report["private_worker_config_path"] = str(self.worker_config_path)
        self.report["profile_id"] = profile_id
        self.report["model_route_id"] = profile["model_route_id"]
        self.report["sandbox_profile_sha256"] = hashlib.sha256(json.dumps(sandbox, sort_keys=True).encode()).hexdigest()
        return profile_id, resource_id

    def confirm_bootstrap_replacement(self, operation_id):
        """Read the legitimate bootstrap commit while project pause still blocks admission."""
        new_task_id = "planning-" + operation_id
        def committed():
            operation = self.api("GET", "/operations/" + operation_id)
            if operation.get("status") in {"FAILED", "CANCELLED", "BLOCKED", "RECOVERY_REQUIRED"}:
                raise RuntimeError("The new bootstrap failed before any Worker/model was launched.")
            if operation.get("execution", {}).get("phase") != "QUEUED":
                return None
            tasks = self.api("GET", f"/projects/{self.project_id}/tasks?limit=500")
            flows = self.api("GET", f"/projects/{self.project_id}/flows?limit=500")
            queues = self.api("GET", f"/projects/{self.project_id}/documents/queue_entries?limit=500")
            if any(len(values) >= 500 for values in (tasks, flows, queues)):
                raise RuntimeError("Bootstrap retirement witness cannot use a truncated canonical collection.")
            new_task = next((task for task in tasks if task["task_id"] == new_task_id), None)
            old_tasks = [next((task for task in tasks if task["task_id"] == task_id), None)
                for task_id in self.old_planning_tasks] if self.resume_planning else []
            latest = max(flows, key=lambda flow: flow["flow_revision"])
            if not new_task or latest["state"] != "COMMITTED" or [task["task_id"] for task in latest["tasks"]] != [new_task_id]:
                return None
            if (self.budget_seal or self.uses_intent_protocol) and (new_task["resource_request"]["provider_inflight"] != 1
                    or new_task["envelope"]["max_model_requests"] != self.planning_request_cap):
                raise RuntimeError("The new canonical planning bootstrap must reserve one provider slot under its explicitly declared planning cap.")
            if self.uses_intent_protocol:
                self.confirm_intent_prelaunch_binding(new_task, operation_id)
            if any(not task or task["state"] != "REMOVED_FROM_PLAN" for task in old_tasks):
                return None
            historical_queues = [entry for entry in queues if entry["task_id"] in {task["task_id"] for task in old_tasks}]
            eligible_old_queue = json.loads(self.db("SELECT coalesce(jsonb_agg(d.data),'[]'::jsonb) FROM documents d JOIN tasks t "
                "ON t.project_id=d.project_id AND t.task_id=d.document_id JOIN flow_revisions f ON f.project_id=t.project_id AND f.flow_revision=t.flow_revision "
                "WHERE d.project_id='" + self.project_id + "' AND d.collection='queue_entries' AND d.data->>'status'='QUEUED' "
                "AND t.state='READY_FOR_ADMISSION' AND f.state='COMMITTED' AND t.task_id <> '" + new_task_id
                + "' AND NOT EXISTS(SELECT 1 FROM attempts a WHERE a.project_id=t.project_id AND a.task_id=t.task_id AND a.terminal_at IS NULL);"))
            if eligible_old_queue:
                raise RuntimeError("A prior planning queue remains canonically eligible after the replacement bootstrap.")
            if self.handoff_failure_seal:
                queue = next(entry for entry in queues if entry["task_id"] == new_task_id)
                self.confirm_handoff_prelaunch_budget(operation, new_task, latest, queue)
            authority = self.assert_pre_model_paused()
            return {"new_operation_id": operation_id, "new_task_id": new_task_id, "bootstrap_revision": latest["flow_revision"],
                "old_task": old_tasks[-1] if old_tasks else None, "old_tasks": old_tasks, "new_task": new_task, "authority": authority,
                "historical_queue_documents": historical_queues, "eligible_prior_queue_count": 0,
                "historical_queue_semantics": "retained audit rows; canonical removed task and replacement Flow prohibit dispatch",
                "ordering": "paused → GUI bootstrap committed → every old task REMOVED_FROM_PLAN and no eligible prior queue readback → Worker release"}
        facts = self.wait(committed, self.config.get("bootstrap_observation_seconds", 60), "paused bootstrap commit and old-task retirement")
        save(self.out / "bootstrap-replacement-before-worker.json", facts)
        self.report["bootstrap_replacement"] = facts
        self.bootstrap_replacement_confirmed = True

    def confirm_handoff_prelaunch_budget(self, operation, task, flow, queue):
        cap = self.planning_request_cap
        if operation.get("request", {}).get("max_model_requests") != cap \
                or operation.get("execution", {}).get("queue", {}).get("envelope") != queue["envelope"] \
                or task["envelope"] != flow["tasks"][0]["envelope"] or task["envelope"] != queue["envelope"] \
                or task["envelope"]["max_model_requests"] != cap or cap != 7 \
                or task["envelope"]["session_purpose"] != "PLANNING" \
                or task["resource_request"]["provider_inflight"] != 1 \
                or self.prior_actual_model_requests + cap + 3 > 12:
            raise RuntimeError("The fresh GUI request, committed task/Flow and queued execution template must all retain the frozen seven-request declaration.")
        receipts = self.api("GET", f"/projects/{self.project_id}/documents/compiler_receipts?limit=500")
        selected = [value for value in receipts if value.get("flow_revision") == flow["flow_revision"]]
        if len(receipts) >= 500 or len(selected) != 1:
            raise RuntimeError("The fresh approved planning execution template requires one complete canonical compiler receipt.")
        receipt = selected[0]
        static_hash = static_template_sha256(task["envelope"])
        if receipt.get("passed") is not True or receipt.get("project_id") != self.project_id \
                or receipt.get("object_revision") != flow["revision"] or receipt.get("flow_digest") != flow["input_digest"] \
                or receipt.get("approved_by") != flow["approved_by"] \
                or receipt.get("digest_algorithm") != "forgeflow.flow.approval.v2" \
                or receipt.get("task_input_digest_algorithm") != "forgeflow.task.input.v2" \
                or receipt.get("static_template_digests", {}).get(task["task_id"]) != static_hash:
            raise RuntimeError("The compiler receipt must bind the actual seven-request static execution template before Worker launch.")
        facts = {"operation_id": operation["operation_id"], "task_id": task["task_id"],
            "request_model_cap": cap, "task_flow_and_queue_envelopes_identical": True,
            "compiler_receipt": receipt, "static_template_sha256": static_hash,
            "prior_actual_model_calls": self.prior_actual_model_requests, "delivery_cap": 3,
            "cumulative_declared_upper_bound": 12, "captured_before_worker": True,
            "execution_template_authority": "canonical task and committed Flow, queued envelope and append-only compiler receipt"}
        save(self.out / "handoff-prelaunch-model-budget.json", facts)
        self.report["handoff_prelaunch_model_budget"] = facts

    def confirm_intent_prelaunch_binding(self, task, operation_id):
        plan_id = "planning-verification-" + operation_id
        plans = self.api("GET", f"/projects/{self.project_id}/documents/verification_plans?limit=500")
        if len(plans) >= 500:
            raise RuntimeError("The V2 verification plan witness must not use a truncated collection.")
        plan = next(value for value in plans if value.get("plan_id") == plan_id)
        if plan["oracle_id"] != PLANNING_INTENT_ORACLE or plan_id != task["envelope"]["verification_plan_id"]:
            raise RuntimeError("The new GUI command must select the separately registered V2 oracle.")
        bindings = []
        keys = ("FORGEFLOW_DRAFT_REQUEST_PATH", "FORGEFLOW_DRAFT_REQUEST_SHA256", "FORGEFLOW_PLANNING_AUTHORITY_PATH",
            "FORGEFLOW_PLANNING_AUTHORITY_SHA256", "FORGEFLOW_PLANNING_SOURCE_PATH", "FORGEFLOW_PLANNING_SOURCE_SHA256",
            "FORGEFLOW_PLANNING_TASK_ID", "FORGEFLOW_PLANNING_INPUT_HASH", "FORGEFLOW_PLANNING_CONTEXT_SHA256", "FORGEFLOW_PLANNING_PROMPT_SHA256")
        for command in plan["commands"]:
            env = command["env"]
            expected = [{"name": name, "kind": kind} for name, kind in self.planning_expected_cases[command["role"]]]
            oracle_path = self.report["new_planning_method"]["oracle_path"]
            if command["expected_cases"] != expected or command["program"] != "/usr/bin/python3" \
                    or command["args"] != ["-I", "-B", oracle_path] or command["executable_hash"] != sha("/usr/bin/python3") \
                    or not any(str(entry["path"]) == oracle_path and entry["sha256"] == PLANNING_INTENT_SHA256 for entry in command["bound_inputs"]):
                raise RuntimeError("The V2 per-operation plan must retain the frozen oracle program and exact role case denominator.")
            if any(not env.get(key) for key in keys) or env["FORGEFLOW_PLANNING_TASK_ID"] != task["task_id"] \
                    or env["FORGEFLOW_PLANNING_INPUT_HASH"] != task["input_digest"] \
                    or env["FORGEFLOW_PLANNING_CONTEXT_SHA256"] != task["envelope"]["context_manifest"]["sha256"] \
                    or env["FORGEFLOW_PLANNING_PROMPT_SHA256"] != task["envelope"]["prompt_artifact"]["sha256"]:
                raise RuntimeError("V2 request/source/authority and task/context/prompt must be pinned before physical launch.")
            for label in ("DRAFT_REQUEST", "PLANNING_AUTHORITY", "PLANNING_SOURCE"):
                path, digest = env["FORGEFLOW_" + label + "_PATH"], env["FORGEFLOW_" + label + "_SHA256"]
                if sha(path) != digest or not any(str(entry["path"]) == path and entry["sha256"] == digest for entry in command["bound_inputs"]):
                    raise RuntimeError("A new V2 verification input lacks its actual immutable prelaunch bytes and hash.")
            bindings.append({"role": command["role"], "env": {key: env[key] for key in keys},
                "bound_inputs": command["bound_inputs"], "expected_cases": command["expected_cases"]})
        if sorted(binding["role"] for binding in bindings) != ["author", "consumer", "independent"] \
                or sum(len(binding["expected_cases"]) for binding in bindings) != 25:
            raise RuntimeError("The immutable per-operation V2 plan must bind all 25 author/consumer/independent cases.")
        facts = {"planning_task_id": task["task_id"], "verification_plan_id": plan_id, "oracle_id": PLANNING_INTENT_ORACLE,
            "bindings": bindings, "captured_before_worker": True, "result_dependent_pins": False}
        save(self.out / "v2-prelaunch-verification-binding.json", facts)
        self.report["v2_prelaunch_verification_binding"] = facts

    def start_worker(self):
        if not self.bootstrap_replacement_confirmed:
            raise RuntimeError("The Worker cannot launch before the paused bootstrap replacement is read back.")
        self.assert_pre_model_paused()
        worker_id = self.worker_config["worker_id"]
        self.worker_log = (self.out / "worker.log").open("wb")
        self.worker = subprocess.Popen([self.worker_binary["path"], "--config", str(self.worker_config_path)],
            env={"PATH": "/usr/bin:/bin", "FORGEFLOW_WORKER_TOKEN": self.private["FORGEFLOW_WORKER_TOKEN"], "RUST_LOG": "info"},
            stdout=self.worker_log, stderr=subprocess.STDOUT, start_new_session=True)
        self.report["worker_pid"] = self.worker.pid
        def registered():
            return self.db(f"SELECT count(*) FROM workers WHERE worker_id='{worker_id}' AND project_id='{self.project_id}';") == "1"
        self.wait(registered, 45, "actual Worker registration")
        worker_scope_id = self.worker_scope_id
        self.api("POST", "/resource-policies", {"policy": {"scope_id": worker_scope_id,
            "parent_scope_id": self.global_scope_id, "project_id": None, "team_id": None, "worker_id": worker_id,
            "limits": self.config["resource_limits"], "paused": False, "revision": 0}}, "EXECUTION_PREREQUISITE")
        self.assert_pre_model_paused((worker_id,))
        scopes = [*self.capacity_scope_ids, worker_scope_id]
        rows = json.loads(self.db("SELECT coalesce(jsonb_agg(jsonb_build_object('scope_id',s.scope_id,'paused',s.paused,'hard_limit',l.hard_limit,'allocated',l.allocated)),'[]'::jsonb) "
            "FROM resource_scopes s JOIN resource_limits l ON l.scope_id=s.scope_id WHERE l.dimension='provider_inflight' AND s.scope_id IN ("
            + ",".join("'" + scope + "'" for scope in scopes) + ");"))
        if {row["scope_id"] for row in rows} != set(scopes) or any(row["paused"] or row["hard_limit"] - row["allocated"] < 1 for row in rows):
            save(self.out / "provider-capacity-precondition-blocked.json", rows)
            raise RuntimeError("Every original hierarchy scope and the new Worker must already have one free provider slot before unpause.")
        self.report["provider_capacity_precondition"] = {"source": "actual PostgreSQL resource_limits and scopes", "rows": rows,
            "requested_simultaneous_provider_slots": 1, "capacity_limits_increased": False}
        project = self.api("GET", f"/projects/{self.project_id}")
        self.api("PATCH", f"/projects/{self.project_id}", {"project": {**project, "paused": False},
            "expected_revision": project["revision"]}, "FIXTURE_CLEANUP")
        self.report["fixture_pause_release"] = {"purpose": "restore dedicated fixture scheduling after retired-task confirmation",
            "counts_as_gui_witness": False, "worker_id": worker_id, "worker_scope_id": worker_scope_id,
            "old_task_removed_before_release": self.resume_planning}

    def db(self, statement):
        parsed = urllib.parse.urlsplit(self.private["DATABASE_URL"])
        query = urllib.parse.parse_qs(parsed.query)
        env = {"PATH": "/usr/bin:/bin", "PGHOST": query.get("host", [parsed.hostname or "127.0.0.1"])[0],
            "PGPORT": query.get("port", [str(parsed.port or 5432)])[0], "PGUSER": urllib.parse.unquote(parsed.username or ""),
            "PGPASSWORD": urllib.parse.unquote(parsed.password or ""), "PGDATABASE": parsed.path.lstrip("/"),
            "LD_LIBRARY_PATH": "/home/chenyoujian/.cache/forgeflow-postgres/root/usr/lib/x86_64-linux-gnu"}
        result = subprocess.run(["/home/chenyoujian/.cache/forgeflow-postgres/root/usr/lib/postgresql/16/bin/psql",
            "-X", "-t", "-A", "--set", "ON_ERROR_STOP=1", "-c", statement], env=env, capture_output=True, timeout=30)
        if result.returncode:
            raise RuntimeError("Dedicated journey PostgreSQL read failed; private connection details withheld.")
        return result.stdout.decode().strip()

    def navigate(self, route):
        self.page.goto(API_BASE + route, wait_until="domcontentloaded")

    def enterprise_planning_interactions(self, task):
        """Exercise real persisted planning controls after delivery; no model replay."""
        from datetime import datetime, timedelta, timezone
        now = datetime.now(timezone.utc).replace(second=0, microsecond=0)
        start, finish = (now + timedelta(hours=1)).isoformat(), (now + timedelta(hours=2)).isoformat()
        self.page.set_viewport_size({"width": 1440, "height": 1000})
        self.navigate(f"/projects/{self.project_id}/schedule?task={urllib.parse.quote(task['task_id'])}")
        studio = self.page.get_by_role("region", name="容量与工作量规划", exact=True)
        studio.get_by_label("选择工作量任务", exact=True).select_option(task["task_id"])
        effort = studio.get_by_role("region", name="任务工作量评估", exact=True)
        for label, value in [("乐观工作量（小时）", "1"), ("通常工作量（小时）", "2"),
                ("悲观工作量（小时）", "3"), ("排程占用时长（小时，可留空）", "1"),
                ("估计依据", "真实交付后的范围复核；工作量与排程占用独立记录。")]:
            effort.get_by_label(label, exact=True).fill(value)
        estimate = self.click(effort.get_by_role("button", name="保存工作量版本", exact=True),
            f"/projects/{self.project_id}/task-estimates")
        self.page.get_by_label("计划开始（ISO 8601 + 时区）", exact=True).fill(start)
        self.page.get_by_label("计划完成（ISO 8601 + 时区）", exact=True).fill(finish)
        schedule = self.click(self.page.get_by_role("button", name="保存排程版本", exact=True),
            f"/projects/{self.project_id}/schedule")
        self.page.get_by_role("img", name="任务甘特图：灰色基线，浅灰计划，黑色实际，纹理等待", exact=True).wait_for()
        self.page.get_by_label("时间轴缩放", exact=True).select_option("day")
        self.page.get_by_role("button", name="后移时间轴", exact=True).click()
        self.page.get_by_role("button", name="基线范围", exact=True).click()
        studio.get_by_role("button", name="刷新权威输入", exact=True).click()
        studio.get_by_label("Worker 资源范围", exact=True).select_option(self.worker_scope_id)
        preview = self.click(studio.get_by_role("button", name="计算只读预览", exact=True),
            f"/projects/{self.project_id}/planning-scenarios")
        self.page.screenshot(path=str(self.out / "planning-desktop.png"), full_page=True)
        self.page.set_viewport_size({"width": 390, "height": 844})
        overflow = self.page.evaluate("document.documentElement.scrollWidth > innerWidth + 2")
        self.page.screenshot(path=str(self.out / "planning-mobile.png"), full_page=True)
        self.page.set_viewport_size({"width": 1440, "height": 1000})
        self.navigate(f"/calendar?project={self.project_id}")
        self.page.get_by_label("项目范围", exact=True).select_option(self.project_id)
        for label, value in [("标题", "独立交付验收"), ("目标时刻（包含时区）", finish),
                ("必需 Gate ID（每行一项）", "independent-delivery-verification"),
                ("交付工作包 ID（每行一项）", task["task_id"])]:
            self.page.get_by_label(label, exact=True).fill(value)
        milestone = self.click(self.page.get_by_role("button", name="创建里程碑", exact=True),
            f"/projects/{self.project_id}/milestones")
        milestones = self.api("GET", f"/projects/{self.project_id}/milestones")
        saved = next(value for value in milestones if value["title"] == "独立交付验收")
        self.page.get_by_role("row").filter(has_text="独立交付验收").first.wait_for()
        self.page.screenshot(path=str(self.out / "milestone-desktop.png"), full_page=True)
        current = self.api("GET", f"/projects/{self.project_id}/tasks/{task['task_id']}")
        facts = {"status": "PASS" if not overflow and current["state"] == task["state"] else "FAIL",
            "task_id": task["task_id"], "task_estimate": estimate, "schedule": schedule,
            "preview": preview, "milestone": saved, "milestone_command_receipt": milestone,
            "planning_mobile_overflow": overflow, "task_state_after_date_edit": current["state"],
            "model_calls_added": 0, "milestone_gate_completion": "UNVERIFIED_NO_AUTOMATIC_SUCCESS"}
        save(self.out / "enterprise-planning-interactions.json", facts)
        self.report["enterprise_planning_interactions"] = facts

    def run(self):
        from playwright.sync_api import sync_playwright
        self.start_server()
        projects = self.api("GET", "/projects?limit=500")
        if projects and not self.resume_from:
            raise RuntimeError("The scheduled dedicated database is not empty; existing projects are never reused.")
        repo = self.fixture / "source"
        if not self.resume_from:
            repo.mkdir(mode=0o700)
            for command in (["init", "--initial-branch=main"], ["config", "user.name", "ForgeFlow UI Journey"],
                            ["config", "user.email", "ui-journey@localhost"]):
                subprocess.run(["git", "-C", str(repo), *command], check=True, capture_output=True)
            (repo / "README.md").write_text("Independent actual UI journey fixture.\n")
            subprocess.run(["git", "-C", str(repo), "add", "README.md"], check=True, capture_output=True)
            subprocess.run(["git", "-C", str(repo), "commit", "-m", "Create independent user journey fixture"], check=True, capture_output=True)
        source_head = subprocess.check_output(["git", "-C", str(repo), "rev-parse", "HEAD"]).decode().strip()
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(headless=True,
                executable_path="/home/chenyoujian/.cache/ms-playwright/chromium-1247/chrome-linux64/chrome", args=["--no-proxy-server"])
            self.page = browser.new_page(viewport={"width": 1440, "height": 1000}, reduced_motion="reduce")
            self.page.set_default_timeout(30000)
            self.page.on("pageerror", lambda error: self.errors.append(str(error)))
            self.page.on("response", self.browser_response)
            self.page.add_init_script("sessionStorage.setItem('forgeflow.owner-token', " + json.dumps(self.private["FORGEFLOW_OWNER_TOKEN"]) + ")")
            if self.resume_from:
                if len(projects) != 1:
                    raise RuntimeError("Preserved project-navigation recovery requires exactly the single original project.")
                project = self.api("GET", "/projects/" + projects[0]["project_id"])
                if project["project_id"] != self.previous.get("project_id"):
                    raise RuntimeError("The original GUI project identity cannot be replaced during recovery.")
                attempts = self.api("GET", f"/projects/{project['project_id']}/attempts")
                recovery = self.handoff_failure_seal or self.model_failure_seal or self.budget_seal or self.preparation_seal
                if attempts and (not recovery or sorted(attempts, key=lambda entry: entry["attempt_id"])
                        != sorted(recovery["authority"]["attempts"], key=lambda entry: entry["attempt_id"])):
                    raise RuntimeError("The pre-model navigation recovery never replays an existing model, physical launch, or source import.")
                self.navigate("/projects/" + project["project_id"])
            else:
                self.navigate("/projects/new")
                self.page.get_by_label("项目名称", exact=True).fill("真实用户业务旅程")
                self.page.get_by_label("真实根目录", exact=True).fill(str(repo))
                self.page.get_by_label("项目目标", exact=True).fill("从真实需求到单文件 DSH 交付、独立验证与可追溯 Git 集成。")
                project = self.click(self.page.get_by_role("button", name="创建项目", exact=True), "/projects")
            self.project_id = project["project_id"]
            self.report["project_id"] = self.project_id
            self.page.wait_for_url(re.compile(r"/projects/" + re.escape(self.project_id) + r"$"))
            if self.resume_planning:
                self.current_stage = STAGES[2]
                self.assert_pre_model_paused()
                identities = self.previous["stages"][STAGES[1]]
                teams = self.api("GET", f"/projects/{self.project_id}/teams?limit=500")
                owners = self.api("GET", f"/projects/{self.project_id}/owners?limit=500")
                root_team = next(team for team in teams if team["team_id"] == identities["root_team_id"])
                child_team = next(team for team in teams if team["team_id"] == identities["child_team_id"])
                owner = next(value for value in owners if value["owner_id"] == identities["owner_id"])
                if child_team["parent_team_id"] != root_team["team_id"] or owner["root_team_id"] != root_team["team_id"] \
                        or owner["include"] != [RESULT_PATH] or owner["exclude"]:
                    raise RuntimeError("The inherited GUI team/Owner facts changed; do not recreate them.")
                self.write_report()
            else:
                self.navigate(f"/projects/{self.project_id}/requirements")
                existing_sources = self.api("GET", f"/projects/{self.project_id}/sources") if self.resume_from else []
                if not existing_sources:
                    self.page.get_by_role("button", name="导入来源", exact=True).click()
                    drawer = self.page.get_by_role("dialog", name="导入真实需求来源", exact=True)
                    drawer.get_by_label("来源名称", exact=True).fill("用户旅程单文件验收")
                    drawer.get_by_label("完整原文", exact=True).fill(SOURCE)
                    self.click(drawer.get_by_role("button", name="导入并解析", exact=True), f"/projects/{self.project_id}/source-imports")
                requirements = self.api("GET", f"/projects/{self.project_id}/requirements")
                sources = self.api("GET", f"/projects/{self.project_id}/sources")
                source = self.api("GET", f"/projects/{self.project_id}/sources/{sources[0]['source_id']}")
                self.stage(STAGES[0], project["authority_mode"] == "MANAGED" and len(requirements) == 1
                    and len(sources) == 1 and source["content"] == SOURCE
                    and source["raw_sha256"] == hashlib.sha256(SOURCE.encode()).hexdigest(), source_id=source["source_id"])

                self.current_stage = STAGES[1]
                self.navigate(f"/projects/{self.project_id}/teams")
                self.page.get_by_label("新团队名称", exact=True).fill("根代码 Owner")
                root_team = self.click(self.page.get_by_role("button", name="创建根团队", exact=True), f"/projects/{self.project_id}/teams")
                self.page.locator(".tree-item").filter(has_text="根代码 Owner").click()
                self.page.get_by_label("新团队名称", exact=True).fill("交付执行子团队")
                child_team = self.click(self.page.get_by_role("button", name="创建子团队", exact=True), f"/projects/{self.project_id}/teams")
                owner_panel = self.page.locator(".owner-territories")
                owner_panel.get_by_role("button", name="登记 Owner", exact=True).click()
                owner_panel.get_by_label("新 Owner · 已有团队身份", exact=True).select_option(root_team["team_id"])
                owner_panel.get_by_label("允许路径 · 每行一个", exact=True).fill(RESULT_PATH)
                owner_panel.get_by_role("button", name="预览变化", exact=True).click()
                owner = self.click(owner_panel.get_by_role("button", name="登记领地", exact=True), f"/projects/{self.project_id}/owners")
                self.stage(STAGES[1], child_team["parent_team_id"] == root_team["team_id"]
                    and owner["root_team_id"] == root_team["team_id"] and owner["include"] == [RESULT_PATH],
                    root_team_id=root_team["team_id"], child_team_id=child_team["team_id"], owner_id=owner["owner_id"])
                if not project["paused"]:
                    project = self.api("PATCH", f"/projects/{self.project_id}", {"project": {**project, "paused": True},
                        "expected_revision": project["revision"]}, "FIXTURE_CLEANUP")

            self.current_stage = STAGES[2]
            profile_id, resource_id = self.prerequisites(root_team["team_id"], child_team["team_id"])
            if self.config.get("continue_operation_id"):
                generated = {"operation_id": self.config["continue_operation_id"]}
                self.old_planning_tasks = []
                self.report["continued_accepted_generation"] = {"operation_id": generated["operation_id"],
                    "original_report": str(self.resume_from), "original_report_sha256": sha(self.resume_from),
                    "new_generation_command_submitted": False, "model_replay": False}
            else:
                self.navigate(f"/projects/{self.project_id}/requirements")
                self.page.get_by_role("button", name="生成 Flow 草案", exact=True).click()
                drawer = self.page.get_by_role("dialog", name="真实 DSH 规划配置", exact=True)
                for label, value in [("根 Owner", owner["owner_id"]), ("预算团队", child_team["team_id"]),
                    ("DSH 执行器 Profile", profile_id), ("独立规划验证模板", self.planning_template_id), ("资源 Profile", resource_id)]:
                    drawer.get_by_label(label, exact=True).select_option(value)
                if self.uses_intent_protocol:
                    drawer.get_by_label("本次规划调用上限", exact=True).fill(str(self.planning_request_cap))
                self.report["planning_guidance_version"] = "ui-journey." + HANDOFF_METHOD if self.handoff_failure_seal else "ui-journey.compact-intent.v2" if self.uses_intent_protocol else PLANNING_GUIDANCE_VERSION
                self.report["prospective_delivery_provider_reservation"] = {"provider_inflight": 1, "max_model_requests": 3,
                    "parent_planning_max_model_requests": self.planning_request_cap, "changes_original_imported_source": False, "changes_prior_failure_metadata": False}
                if self.uses_intent_protocol:
                    guidance = "Instruction version: ui-journey.compact-intent.v2. Return one complete compact planning intent using the protocol in this prompt. " \
                        "Propose exactly one task with short ID T1 writing only journey-result.txt. Preserve the exact UTF-8 FORGEFLOW_USER_JOURNEY_OK marker followed by one newline acceptance. " \
                        "Use the exact source requirement ID and concise title, outcome and rollback_plan. Keep read_set, dependencies, producer_inputs and contracts empty. " \
                        "verification_case_count=4; resource_request active_slot=1,coding_slot=1,cpu_units=1,memory_bytes=67108864,build_permit=0,gpu_permit=0,provider_inflight=1 within frozen ancestor caps. " \
                        "Emit schema_version forgeflow.planning-intent.v1 and tasks only; the controller supplies authority, hashes and Flow fields. Finish every JSON object. " \
                        "Do not invoke delegation, workflow, teams or qualification tools. Do not write files, execute, complete or approve the task. Output complete JSON only."
                else:
                    guidance = "Instruction version: " + PLANNING_GUIDANCE_VERSION + ". Return exactly one canonical unapproved DraftBundle JSON task for the one source requirement. " \
                        "Write set exactly ['journey-result.txt']; read_set, inputs, producer_inputs and mandatory_paths empty; no contracts or dependencies. " \
                        "Preserve every supplied requirement/anchor and digest reference. Explicitly include all canonical schema fields from the example; input_digest may be null. " \
                        "verification_case_count=4; resources active_slot=1,coding_slot=1,cpu_units=1,memory_bytes=67108864,build_permit=0,gpu_permit=0,provider_inflight=1. " \
                        "Do not invoke subagents, workflow, teams or qualification tools. Do not write files, execute the task or approve the Flow. Output JSON only."
                drawer.get_by_label("规划指导", exact=True).fill(guidance)
                generated = self.click(drawer.get_by_role("button", name="提交真实规划操作", exact=True), f"/projects/{self.project_id}/flow-generations")
                if self.uses_intent_protocol:
                    command = next(entry for entry in reversed(self.browser_records) if entry["method"] == "POST"
                        and entry["route"] == f"/projects/{self.project_id}/flow-generations")
                    if command.get("body", {}).get("max_model_requests") != self.planning_request_cap:
                        raise RuntimeError("The actual GUI command must declare the scheduled planning request cap.")
            self.confirm_bootstrap_replacement(generated["operation_id"])
            self.start_worker()
            operation = self.operation(generated["operation_id"])
            flow = operation["result"]["flow"]
            planning_attempt = operation["result"]["planning_attempt_id"]
            planning_entries = self.api("GET", f"/projects/{self.project_id}/documents/queue_entries?limit=500")
            planning_entry = next(entry for entry in planning_entries if entry["task_id"] == "planning-" + generated["operation_id"])
            self.report["automatic_custom_worker_scope_mapping"] = {"registered_worker_id": self.worker_config["worker_id"],
                "registered_scope_id": self.worker_scope_id, "queue_worker_id": planning_entry["worker_id"],
                "queue_worker_scope_id": planning_entry["worker_scope_id"], "queue_status": planning_entry["status"],
                "gui_submitted_explicit_worker_id": False, "gui_submitted_explicit_worker_scope": False}
            if self.uses_intent_protocol:
                receipts = json.loads(self.db("SELECT coalesce(jsonb_agg(data),'[]'::jsonb) FROM evidence_receipts WHERE project_id='"
                    + self.project_id + "' AND attempt_id='" + planning_attempt + "';"))
                verified = [receipt for receipt in receipts if receipt["kind"] == "STRUCTURED_ARTIFACT"
                    and receipt["total"] == 25 and receipt["failed"] == 0 and receipt["skipped"] == 0]
                output = operation["result"].get("planning_output")
                original = Path(self.private["FORGEFLOW_DATA_ROOT"]) / "attempts" / planning_attempt / "final.json"
                if len(verified) != 1 or not output or output["sha256"] != sha(original):
                    raise RuntimeError("The new method requires 25 executed verification cases and the registered unchanged raw planning final.")
                facts = {"receipts": receipts, "planning_output": output, "original_final_sha256": sha(original),
                    "actual_case_denominator": 25, "original_output_repaired_or_replaced": False}
                save(self.out / "v2-planning-verification-evidence.json", facts)
                self.report["v2_planning_verification"] = facts
            self.stage(STAGES[2], operation["result"]["generation_method"] == "dsh_model_assisted"
                and flow["state"] == "DRAFT" and flow["approved_by"] is None and len(flow["tasks"]) == 1
                and planning_attempt in self.launch_seen and planning_entry["worker_id"] == self.worker_config["worker_id"]
                and planning_entry["worker_scope_id"] == self.worker_scope_id,
                operation_id=operation["operation_id"], planning_attempt_id=planning_attempt)

            self.deliver(flow, profile_id, resource_id, repo, source_head, browser)

    def deliver(self, flow, profile_id, resource_id, repo, source_head, browser):
        self.current_stage = STAGES[3]
        task = flow["tasks"][0]
        self.navigate(f"/projects/{self.project_id}/flows/{flow['flow_revision']}")
        self.page.get_by_role("button", name="任务表", exact=True).click()
        self.page.locator("tr.interactive-row").filter(has_text=task["task_id"]).click()
        self.page.get_by_role("button", name="配置真实执行", exact=True).click()
        drawer = self.page.get_by_role("dialog", name="绑定执行器与独立验证", exact=True)
        for label, value in [("执行器 Profile", profile_id), ("资源 Profile", resource_id),
                             ("独立验证模板", self.coding_template_id), ("会话用途", "EXECUTION")]:
            drawer.get_by_label(label, exact=True).select_option(value)
        delivery_cap = self.config.get("delivery_model_request_cap", 3)
        drawer.get_by_label("模型请求预算声明", exact=True).fill(str(delivery_cap))
        drawer.get_by_label("有限任务指令", exact=True).fill(self.config.get("delivery_instruction") or "Write only journey-result.txt in place, with exact UTF-8 bytes FORGEFLOW_USER_JOURNEY_OK followed by one newline. "
            "Do not create adjacent temporary files or edit README/Git metadata. Do not invoke delegation or qualification tools. "
            "The controller independently verifies and freezes the candidate; do not claim integration. After writing report only that finite result.")
        template = self.click(drawer.get_by_role("button", name="生成真实执行配置", exact=True), f"/flows/{self.project_id}:{flow['flow_revision']}/tasks/{task['task_id']}/execution-templates")
        configured = self.operation(template["operation_id"])
        flow = self.api("GET", f"/flows/{self.project_id}:{flow['flow_revision']}")
        self.navigate(f"/projects/{self.project_id}/flows/{flow['flow_revision']}")
        checked = self.click(self.page.get_by_role("button", name="检查版本", exact=True), f"/flows/{self.project_id}:{flow['flow_revision']}/checks")
        approved = self.click(self.page.get_by_role("button", name=f"审定并提交 R{flow['flow_revision']}", exact=True), f"/flows/{self.project_id}:{flow['flow_revision']}/commit")
        task = approved["tasks"][0]
        self.stage(STAGES[3], checked["passed"] is True and approved["state"] == "COMMITTED"
            and task["envelope"]["max_model_requests"] == delivery_cap and task["resource_request"]["provider_inflight"] == 1
            and task["write_set"] == [RESULT_PATH],
            flow_revision=approved["flow_revision"], task_id=task["task_id"], template_operation_id=template["operation_id"])

        self.current_stage = STAGES[4]
        self.navigate(f"/projects/{self.project_id}/tasks/{task['task_id']}")
        self.click(self.page.get_by_role("button", name="预检查准入", exact=True), f"/projects/{self.project_id}/tasks/{task['task_id']}/admission-checks")
        queued = self.click(self.page.get_by_role("button", name="合法入队", exact=True), "/queue-entries")
        def running():
            attempts = self.api("GET", f"/projects/{self.project_id}/attempts")
            matching = [value for value in attempts if value["task_id"] == task["task_id"]
                and value["task_revision"] == task["task_revision"]]
            attempt = max(matching, key=lambda value: value["generation"], default=None)
            if attempt:
                self.observe_launch(attempt["attempt_id"])
            return attempt if attempt and attempt["attempt_id"] in self.launch_seen else None
        attempt = self.wait(running, 60, "actual DSH execution launch")
        attempt_id = attempt["attempt_id"]
        self.navigate(f"/runs/{attempt_id}?project={self.project_id}")
        self.page.get_by_text(attempt_id, exact=False).first.wait_for()
        def stopped():
            value = self.api("GET", f"/attempts/{attempt_id}?project_id={self.project_id}")
            if value["attempt_id"] != attempt_id or value["task_revision"] != task["task_revision"] \
                    or value["generation"] != attempt["generation"]:
                raise RuntimeError("Observed attempt identity differs from the current task revision and fencing generation.")
            self.observe_launch(attempt_id)
            self.observations.append({"attempt_id": attempt_id, "state": value["state"]})
            if value["state"] in {"FAILED", "CANCELLED", "RECOVERY_REQUIRED"}:
                raise RuntimeError("Actual DSH execution entered " + value["state"])
            return value if value["state"] == "VERIFYING" else None
        attempt = self.wait(stopped, 600, "actual DSH exit and immutable verification readiness")
        self.page.get_by_role("button", name="重新读取", exact=True).click()
        self.page.get_by_role("button", name="验证并请求受控集成", exact=True).wait_for()
        self.stage(STAGES[4], attempt["result"]["evidence"]["real_dsh"] is True and attempt_id in self.launch_seen
            and self.page.get_by_role("button", name="验证并请求受控集成", exact=True).is_enabled(), attempt_id=attempt_id)

        self.current_stage = STAGES[5]
        integrated_request = self.click(self.page.get_by_role("button", name="验证并请求受控集成", exact=True), f"/attempts/{attempt_id}/verify-and-integrate")
        integrated = self.operation(integrated_request["operation_id"])
        snapshot = self.api("GET", f"/projects/{self.project_id}/snapshot")
        save(self.out / "final-snapshot.json", snapshot)
        db = json.loads(self.db("SELECT jsonb_build_object('attempts',(SELECT jsonb_agg(data) FROM attempts WHERE project_id='" + self.project_id
            + "'),'merges',(SELECT jsonb_agg(data) FROM merge_intents WHERE project_id='" + self.project_id
            + "'),'evidence',(SELECT jsonb_agg(data) FROM evidence_receipts WHERE project_id='" + self.project_id + "'));"))
        save(self.out / "database-facts.json", db)
        delivery = next(value for value in snapshot["attempts"] if value["attempt_id"] == attempt_id)
        merges = [value for value in db["merges"] or [] if value["attempt_id"] == attempt_id]
        evidence = [value for value in db["evidence"] or [] if value["attempt_id"] == attempt_id]
        self.retain_execution_artifacts(snapshot["attempts"])
        self.retain_verification_artifacts(evidence)
        canonical = snapshot["project"]["root_path"]
        integrated_sha = subprocess.check_output(["git", "-C", canonical, "rev-parse", "refs/heads/main"]).decode().strip()
        blob = subprocess.check_output(["git", "-C", canonical, "show", integrated_sha + ":" + RESULT_PATH])
        (self.out / "integrated-result.bin").write_bytes(blob)
        self.navigate(f"/projects/{self.project_id}/evidence")
        self.page.get_by_role("heading", name="证据收据", exact=True).wait_for()
        for value in evidence:
            self.page.get_by_text(value["receipt_id"], exact=False).first.wait_for()
        self.page.screenshot(path=str(self.out / "desktop.png"), full_page=True)
        self.page.set_viewport_size({"width": 390, "height": 844})
        mobile_overflow = self.page.evaluate("document.documentElement.scrollWidth > innerWidth + 2")
        self.page.screenshot(path=str(self.out / "mobile.png"), full_page=True)
        source_unchanged = subprocess.check_output(["git", "-C", str(repo), "rev-parse", "HEAD"]).decode().strip() == source_head
        source_clean = not subprocess.check_output(["git", "-C", str(repo), "status", "--porcelain"]).strip()
        self.stage(STAGES[5], delivery["state"] == "SUCCEEDED" and len(merges) == 1
            and merges[0]["state"] == "FINALIZED" and merges[0]["integrated_sha"] == integrated_sha
            and blob == EXPECTED and any(value["kind"] == "INDEPENDENT_VERIFICATION" and value["total"] == 4
                and value["failed"] == 0 and value["skipped"] == 0 for value in evidence)
            and all(value["state"] == "RELEASED" for value in snapshot["allocations"])
            and not self.errors and not mobile_overflow and source_unchanged and source_clean, integrated_sha=integrated_sha,
            evidence_receipt_ids=[value["receipt_id"] for value in evidence], mobile_overflow=mobile_overflow)
        self.report["source_git_unchanged"] = source_unchanged and source_clean
        requests = snapshot.get("native_model_requests", [])
        self.report["actual_model_request_count"] = len(requests) if requests else "UNMEASURED_DIRECT_OBSERVED"
        self.report["cumulative_actual_model_request_count"] = self.prior_actual_model_requests + len(requests) if requests else "UNMEASURED"
        self.report["actual_model_request_states"] = [value["status"] for value in requests]
        self.report["provider_cost"] = "UNKNOWN_UNLESS_AUTHORITATIVE_SETTLEMENT_EXISTS"
        self.report["actual_launches"] = self.launch_seen
        self.report["status"] = "PASS"
        if self.config.get("enterprise_planning_interactions"):
            try:
                self.enterprise_planning_interactions(task)
            except Exception as failure:
                self.report["enterprise_planning_interactions"] = {"status": "FAIL",
                    "error_type": type(failure).__name__, "message": str(failure), "model_calls_added": 0}
                self.page.screenshot(path=str(self.out / "planning-interaction-failure.png"), full_page=True)
        browser.close()

    def write_report(self):
        self.report.update(api_http=self.records, browser_http=self.browser_records,
            javascript_errors=self.errors, execution_observations=self.observations, actual_launches=self.launch_seen,
            passed_stages=sum(value["status"] == "PASS" for value in self.report["stages"].values()), total_stages=len(STAGES))
        save(self.out / "report.json", self.report)

    def cleanup(self):
        try:
            if not self.project_id:
                if self.server:
                    self.server.terminate()
                    self.server.wait(timeout=15)
                self.report["cleanup"] = {"server_stopped_before_project_creation": True}
                return
            snapshot = self.api("GET", f"/projects/{self.project_id}/snapshot")
            terminal = {"SUCCEEDED", "FAILED", "CANCELLED"}
            if self.report.get("failure") and (any(attempt["state"] not in terminal for attempt in snapshot["attempts"])
                    or any(value["state"] != "RELEASED" for value in snapshot["allocations"])):
                self.report["cleanup"] = {"status": "ROOT_INTERVENTION_REQUIRED",
                    "worker_kept_alive": bool(self.worker and self.worker.poll() is None),
                    "worker_pid": self.worker.pid if self.worker else None,
                    "server_pid": self.server.pid if self.server else None,
                    "active_attempts": [{"attempt_id": value["attempt_id"], "state": value["state"]}
                        for value in snapshot["attempts"] if value["state"] not in terminal],
                    "reason": "observation failure does not authorize cancelling genuine execution, verification or integration"}
                return
            for attempt in snapshot["attempts"]:
                if attempt["state"] not in terminal | {"STOPPING", "RECOVERY_REQUIRED"}:
                    self.api("POST", f"/attempts/{attempt['attempt_id']}/cancel", {"project_id": self.project_id,
                        "reason": "close bounded user journey fixture after retained outcome", "expected_revision": attempt["revision"]}, "FIXTURE_CLEANUP")
            deadline = time.monotonic() + 60
            while time.monotonic() < deadline and (any(value["state"] not in terminal for value in snapshot["attempts"])
                    or any(value["state"] != "RELEASED" for value in snapshot["allocations"])):
                time.sleep(1)
                snapshot = self.api("GET", f"/projects/{self.project_id}/snapshot")
            quiescent = all(value["state"] in terminal for value in snapshot["attempts"])
            released = all(value["state"] == "RELEASED" for value in snapshot["allocations"])
            if quiescent and released:
                project = self.api("GET", f"/projects/{self.project_id}")
                self.api("PATCH", f"/projects/{self.project_id}", {"project": {**project, "paused": True},
                    "expected_revision": project["revision"]}, "FIXTURE_CLEANUP")
                if self.worker:
                    self.worker.terminate()
                    self.worker.wait(timeout=15)
                if self.server:
                    self.server.terminate()
                    self.server.wait(timeout=15)
                self.report["cleanup"] = {"project_paused": True, "worker_stopped_after_release": True,
                    "server_stopped_after_worker": True,
                    "counts_as_gui_witness": False}
            else:
                self.report["cleanup"] = {"status": "ROOT_INTERVENTION_REQUIRED", "worker_kept_alive": bool(self.worker and self.worker.poll() is None),
                    "worker_pid": self.worker.pid if self.worker else None, "reason": "retain authority and Worker until actual attempt/allocation cleanup"}
        except Exception as failure:
            self.report["cleanup"] = {"status": "UNCONFIRMED", "error_type": type(failure).__name__}

    def start_server(self):
        if self.private.get("FORGEFLOW_BIND") != "127.0.0.1:8794":
            raise RuntimeError("The dedicated server must bind only the scheduled 8794 port.")
        with socket.socket() as probe:
            probe.settimeout(.3)
            if probe.connect_ex(("127.0.0.1", 8794)) == 0:
                raise RuntimeError("An existing 8794 actor is never reused or restarted by this harness.")
        binary = self.receipt["binaries"]["forgeflow-server"]
        if sha(binary["path"]) != binary["sha256"]:
            raise RuntimeError("Dedicated server differs from the immutable receipt.")
        env = {**os.environ, **self.private}
        self.server_log = (self.out / "server.log").open("wb")
        self.server = subprocess.Popen([binary["path"]], cwd=ROOT, env=env,
            stdout=self.server_log, stderr=subprocess.STDOUT, start_new_session=True)
        self.report["server_pid"] = self.server.pid
        self.report["server_binary_sha256"] = binary["sha256"]
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            if self.server.poll() is not None:
                raise RuntimeError("Dedicated 8794 server exited before readiness; original log retained.")
            try:
                with self.opener.open(API_BASE + "/healthz", timeout=1) as response:
                    if response.status == 200:
                        return
            except (OSError, urllib.error.URLError):
                pass
            time.sleep(.2)
        raise RuntimeError("Dedicated 8794 server readiness timed out; existing actor retained for cleanup.")

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", action="store_true", help="Root-scheduled actual model/Worker execution")
    parser.add_argument("--config", type=Path, help="Root-owned private configuration; never copied to evidence")
    parser.add_argument("--resume-from", type=Path, help="Preserved zero-model GUI failure; first two passed stages are inherited")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if not args.run:
        output = args.output or DEFAULT_OUT
        output.mkdir(parents=True, exist_ok=True)
        save(output / "execution-plan.json", plan())
        print(json.dumps({"status": "SOURCE_READY_NOT_EXECUTED", "stages": 6, "expected_minimum_model_requests": 3}))
        return 0
    if not args.config:
        parser.error("--run requires Root's private --config")
    config = json.loads(args.config.read_text())
    output = args.output or Path(config.get("output_path", str(DEFAULT_OUT)))
    resume_from = args.resume_from or (Path(config["resume_from_path"]) if config.get("resume_from_path") else None)
    output.mkdir(parents=True, exist_ok=True)
    if (output / "report.json").exists():
        parser.error("Existing attempt evidence is immutable; use a separately authorized output for any later repair run.")
    journey = Journey(config, output, resume_from)
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
    print(json.dumps({"status": journey.report["status"], "passed": journey.report["passed_stages"], "total": 6,
                      "project_id": journey.project_id, "cleanup": journey.report.get("cleanup")}, ensure_ascii=False))
    return 0 if journey.report["status"] == "PASS" else 1

if __name__ == "__main__":
    raise SystemExit(main())
