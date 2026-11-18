#!/usr/bin/env python3
"""One distinct semantic-change/replanning/delivery chain on the closed GUI fixture.

Default mode prepares evidence only: no API, DB, browser, Worker or model.
Root schedules --run after the concurrent qualification has fully stopped.
The original documents, attempts, raw output and Git objects remain untouched.
"""
import argparse
import ast
import copy
import hashlib
import importlib.util
import json
import subprocess
import sys
import urllib.parse
import urllib.request
import uuid
from pathlib import Path

sys.dont_write_bytecode = True
import user_journey_check as core

ROOT = core.ROOT
OUT = ROOT / "evidence/business-chain-semantic-replanning-r1"
OLD_REPORT = ROOT / "evidence/enterprise-ux/core-delivery-r1/final-current-revision-delivery/report.json"
PRIVATE_CONFIG = Path("/home/chenyoujian/.local/state/forgeflow/control/core-ui-491899eb8e00/private-config.json")
RECEIPT = Path("/home/chenyoujian/.cache/forgeflow-build-checkpoints/d2e52b7e6313def8-47cg2vmf/receipt.json")
PROJECT = "d3601b76-faa0-449b-97a1-9e676ef04469"
SOURCE_ID = "3d7cb07918bbcff35d4fac3bce1c1d0a"
REQ = SOURCE_ID + ":REQ-0001"
ROOT_TEAM = "d226415a-9253-46d9-bc8a-60771e228770"
CHILD_TEAM = "2cd94848-aeb7-4d77-8bb6-8b4d23c6a3bf"
OLD_SHA = "a9cb328d1d079ce626e7496afba7978a6eacba50"
OLD_BYTES = b"FORGEFLOW_USER_JOURNEY_OK\n"
NEW_BYTES = b"FORGEFLOW_USER_JOURNEY_REPLANNED_OK\n"
NEW_MARKER = NEW_BYTES.decode().strip()
ACCEPTANCE = ("仅在 journey-result.txt 写入 UTF-8 文本 " + NEW_MARKER
    + " 并以一个换行结尾；独立作者、消费者与验证者须核对准确字节，经受控 Git 集成后可追溯原始证据。")
REASON = "业务变更：下游自动化要求新版交付标记；原始文档、旧任务输入、尝试与 Git SHA 保留为历史证据。"
PLANNING_CAP = DELIVERY_CAP = 3
OLD_PROJECT_MODELS, OLD_CUMULATIVE_MODELS = 11, 14


def instruction():
    code = "from pathlib import Path\nPath('journey-result.txt').write_bytes(" + repr(NEW_BYTES) + ")\n"
    call = ast.parse(code).body[1].value
    if ast.literal_eval(call.args[0]) != NEW_BYTES:
        raise RuntimeError("The prospective in-place instruction has different requested bytes.")
    command = "/usr/bin/python3 -I -B <<'FORGEFLOW_WRITE'\n" + code + "FORGEFLOW_WRITE"
    return ("Fulfill the current Owner-edited requirement, whose immutable current acceptance is "
        + ACCEPTANCE + " The older imported document is retained history. Write only journey-result.txt in place. "
        "Use the bash tool and this exact Python heredoc, because adjacent temporary files exceed this task's exact write set:\n"
        + command + "\nDo not edit other files or Git metadata. Do not delegate or run qualification tools. "
        "The controller freezes, independently verifies and integrates the candidate. Report the finite write result only.")


def preparation():
    old = json.loads(OLD_REPORT.read_text())
    receipt = json.loads(RECEIPT.read_text())
    return {"status": "SOURCE_READY_NOT_EXECUTED", "business_chain": "3.7",
        "distinct_new_business_chain_count": 1, "scope": "semantic requirement change → real DSH replan → review → affected delivery → verify/Git/history",
        "execution_authorization": "WAIT_FOR_ROOT_GO_AFTER_128_HOUR", "actors_started": [],
        "project_id": PROJECT, "source_id": SOURCE_ID, "requirement_id": REQ,
        "original_success": {"report": str(OLD_REPORT), "sha256": core.sha(OLD_REPORT),
            "integrated_sha": OLD_SHA, "flow_revision": 5, "task_revision": 8,
            "actual_model_requests_in_project": OLD_PROJECT_MODELS, "historical_cumulative_actual_model_requests": OLD_CUMULATIVE_MODELS},
        "same_requirement_edit": {"expected_revision": 1, "title": ACCEPTANCE, "outcome": ACCEPTANCE,
            "scope": REASON, "acceptance": [ACCEPTANCE], "source_anchor_unchanged": True,
            "original_source_document_unchanged": True, "expected_utf8_hex": NEW_BYTES.hex()},
        "budget": {"planning_gui_request_and_frozen_envelope": PLANNING_CAP,
            "delivery_gui_template_and_frozen_envelope": DELIVERY_CAP, "new_actual_request_ceiling": 6,
            "original_cumulative_count_is_separate": 14, "combined_maximum": 20,
            "enforcement": "native gateway enforces each frozen max_model_requests=3; exactly one planning operation and one delivery attempt; no automatic repeats",
            "measurement": "new native_model_requests request_id set minus retained original 11 IDs"},
        "build_receipt": {"path": str(RECEIPT), "sha256": core.sha(RECEIPT),
            "binaries": {name: {"path": value["path"], "sha256": value["sha256"]}
                for name, value in receipt["binaries"].items()}},
        "private_config_path": str(PRIVATE_CONFIG), "api_port": 8794, "main_8787_untouched": True,
        "prospective_delivery_instruction": instruction(),
        "verification": {"planning_oracle_sha256": core.PLANNING_INTENT_SHA256, "planning_actual_case_denominator": 25,
            "coding_candidate_cases": 4, "coding_integrated_cases": 4,
            "old_traceability": ["unchanged old Attempt rows", "unchanged original input/raw artifact hashes",
                "old Flow R5 content with legitimate SUPERSEDED state, immutable TaskRevision8", "old integrated Git object retains original bytes"],
            "failure_policy": "retain raw failures; observation failure never cancels valid execution/verification/merge"},
        "milestone_3_9": {"status": "INCONCLUSIVE", "existing_document_command_sufficient": False,
            "reason": "Milestone denies unknown fields and has no acceptance state; generic document updates cannot create a formal adjudication.",
            "minimal_formal_path": "typed milestone_acceptances immutable authority + server-derived current verified task/Git bindings + idempotent acceptance API + Calendar verdict/button",
            "implementation_owner": "snapshot_transaction_fix; this harness does not invent Gate results"},
        "estimated_execution_minutes": [8, 15], "inherited_setup_stages_not_new_business_chains": core.STAGES[:2],
        "original_report_status": old["status"], "driver_sha256": core.sha(__file__)}


class SemanticJourney(core.Journey):
    def __init__(self, output, receipt_path):
        self.out = output
        self.config = json.loads(PRIVATE_CONFIG.read_text())
        if self.config.get("allow_model_calls") is not True:
            raise RuntimeError("The private fixture configuration does not authorize actual model execution.")
        self.config.update(build_receipt_path=str(receipt_path), planning_max_model_requests=3,
            delivery_model_request_cap=3, delivery_instruction=instruction(), enterprise_planning_interactions=False,
            observation_timeout_seconds=120, bootstrap_observation_seconds=900)
        self.private = json.loads(Path(self.config["runtime_env_path"]).read_text())
        self.receipt = json.loads(receipt_path.read_text())
        self.worker_binary = self.receipt["binaries"]["forgeflow-worker"]
        if core.sha(self.worker_binary["path"]) != self.worker_binary["sha256"]:
            raise RuntimeError("The actual Worker differs from the scheduled receipt.")
        self.previous = json.loads(OLD_REPORT.read_text())
        self.fixture = Path(self.previous["private_fixture_root"])
        self.project_id, self.worker, self.server, self.page = PROJECT, None, None, None
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        self.records, self.browser_records, self.errors, self.observations, self.launch_seen = [], [], [], [], {}
        self.current_stage = core.STAGES[0]
        self.planning_request_cap, self.prior_actual_model_requests = 3, 3
        self.resume_planning, self.old_planning_tasks = True, []
        self.budget_seal = self.handoff_failure_seal = None
        self.uses_intent_protocol, self.bootstrap_replacement_confirmed = True, False
        self.report = {"status": "RUNNING", "business_chain": "3.7", "distinct_new_business_chain_count": 1,
            "stages": {name: {"status": "NOT_RUN"} for name in core.STAGES}, "api_base": core.API_BASE,
            "scope": preparation()["scope"], "driver_sha256": core.sha(__file__),
            "build_receipt_path": str(receipt_path), "build_receipt_sha256": core.sha(receipt_path),
            "original_success_report": str(OLD_REPORT), "original_success_report_sha256": core.sha(OLD_REPORT),
            "historical_cumulative_actual_model_requests": 14, "credential_values_disclosed": False,
            "automatic_model_retries": False, "production_qualification": "UNVERIFIED", "historical_suites_repeated": []}

    def db_json(self, sql):
        return json.loads(self.db(sql))

    def old_history(self):
        return self.db_json("SELECT jsonb_build_object('attempts',(SELECT coalesce(jsonb_agg(data ORDER BY attempt_id),'[]'::jsonb) FROM attempts WHERE project_id='"
            + PROJECT + "' AND attempt_id IN (" + ",".join("'" + value + "'" for value in self.old_attempt_ids) + ")),'task_revision',"
            "(SELECT data FROM task_revisions WHERE project_id='" + PROJECT + "' AND task_id='"
            + self.previous["stages"][core.STAGES[3]]["task_id"] + "' AND task_revision=8),'flow_context',"
            "(SELECT data FROM documents WHERE project_id='" + PROJECT + "' AND collection='flow_contexts' AND document_id='5'),"
            "'input_snapshots',(SELECT coalesce(jsonb_agg(data ORDER BY document_id),'[]'::jsonb) FROM documents WHERE project_id='"
            + PROJECT + "' AND collection='input_snapshots' AND document_id IN (SELECT jsonb_object_keys(data->'current_inputs') "
            "FROM documents WHERE project_id='" + PROJECT + "' AND collection='flow_contexts' AND document_id='5')));")

    def artifact_inventory(self):
        data = Path(self.private["FORGEFLOW_DATA_ROOT"])
        files = {str(file): core.sha(file) for attempt_id in self.old_attempt_ids
            for file in (data / "attempts" / attempt_id).rglob("*")
            if file.is_file() and file.name in {"final.json", "launch-receipt.json", "result.json", "stdout.ndjson", "stderr.log"}}
        for ref in self.baseline_history["task_revision"]["envelope"].values():
            if isinstance(ref, dict) and ref.get("artifact_id"):
                file = data / "artifacts" / ref["artifact_id"]
                if not file.is_file() or core.sha(file) != ref["sha256"]:
                    raise RuntimeError("The retained old task context/prompt artifact is absent or differs from its original pin.")
                files[str(file)] = core.sha(file)
        return files

    def baseline(self):
        snapshot = self.api("GET", f"/projects/{PROJECT}/snapshot")
        project = snapshot["project"]
        if project.get("authority_mode") != "MANAGED" or project.get("archived") or not project["paused"]:
            raise RuntimeError("Reuse requires the original managed, unarchived and already paused project.")
        if len(snapshot["native_model_requests"]) != 11 or any(row["status"] != "SETTLED" for row in snapshot["native_model_requests"]) \
                or any(row["state"] not in {"SUCCEEDED", "FAILED", "CANCELLED"} for row in snapshot["attempts"]) \
                or any(row["state"] != "RELEASED" for row in snapshot["allocations"]):
            raise RuntimeError("The retained original business journey is not fully closed with its exact 11 native calls.")
        self.old_attempt_ids = {row["attempt_id"] for row in snapshot["attempts"]}
        self.old_model_ids = {row["request_id"] for row in snapshot["native_model_requests"]}
        self.baseline_counts = self.pre_model_authority()
        self.baseline_history = self.old_history()
        self.baseline_artifacts = self.artifact_inventory()
        self.baseline_flow = self.api("GET", f"/flows/{PROJECT}:5")
        self.baseline_sources = self.api("GET", f"/projects/{PROJECT}/documents/sources?limit=500")
        self.baseline_requirement = next(row for row in snapshot["requirements"] if row["requirement_id"] == REQ)
        if self.baseline_requirement["revision"] != 1 or len(snapshot["requirements"]) != 1:
            raise RuntimeError("The original requirement is already changed; no automatic alternate attempt is allowed.")
        self.canonical = project["root_path"]
        self.baseline_seq = int(self.db("SELECT event_seq FROM projects WHERE project_id='" + PROJECT + "';"))
        if subprocess.check_output(["git", "-C", self.canonical, "rev-parse", "refs/heads/main"]).decode().strip() != OLD_SHA \
                or subprocess.check_output(["git", "-C", self.canonical, "show", OLD_SHA + ":journey-result.txt"]) != OLD_BYTES:
            raise RuntimeError("The retained original integrated Git object is not the recorded successful delivery.")
        core.save(self.out / "retained-before.json", {"history": self.baseline_history, "artifact_hashes": self.baseline_artifacts,
            "flow": self.baseline_flow, "sources": self.baseline_sources, "requirement": self.baseline_requirement,
            "model_request_ids": sorted(self.old_model_ids), "project_event_seq": self.baseline_seq})

    def assert_pre_model_paused(self, expected_live_workers=()):
        facts = self.pre_model_authority()
        keys = ("attempt_count", "native_model_count", "native_session_count", "gateway_model_count", "provider_request_count", "allocation_count")
        if any(facts[key] != self.baseline_counts[key] for key in keys) or not facts["project_paused"] \
                or set(facts["live_workers"]) != set(expected_live_workers):
            core.save(self.out / "pre-model-authority-blocked.json", facts)
            raise RuntimeError("The closed fixture gained execution/model activity before the bounded new Worker release.")
        return facts

    def prerequisites(self, root_team, child_team):
        tag = uuid.uuid4().hex[:8]
        worker_id = "semantic-replanning-worker-" + tag
        config = json.loads(Path(self.config["worker_config_template"]).read_text())
        if config.get("controlled_workload_programs"):
            raise RuntimeError("The replanning chain requires actual product DSH.")
        config.update(control_url=core.API_BASE, project_id=PROJECT, worker_id=worker_id,
            data_root=self.private["FORGEFLOW_DATA_ROOT"], max_active_attempts=1, poll_seconds=1)
        private_dir = self.fixture / ("semantic-replanning-" + tag)
        private_dir.mkdir(mode=0o700)
        planning = private_dir / "planning-intent-verifier.v2.py"
        planning.write_bytes((ROOT / "verification/fixtures/planning_intent_verifier.py").read_bytes())
        if core.sha(planning) != core.PLANNING_INTENT_SHA256:
            raise RuntimeError("The actual planning verifier changed from the canonical compact V2 oracle.")
        spec = importlib.util.spec_from_file_location("semantic_planning_cases", planning)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        self.planning_expected_cases = module.CASES
        coding = private_dir / "coding-verifier.v2.py"
        coding.write_text(core.CODING_ORACLE.replace("FORGEFLOW_USER_JOURNEY_OK", NEW_MARKER)
            .replace("ui-journey-fixed-text.v1", "semantic-replanning-fixed-text.v2"))
        planning.chmod(0o444)
        coding.chmod(0o444)
        profile = copy.deepcopy(config["profile"])
        profile.update(kind="DSH_MANAGED", native_mode=config["managed_dsh"])
        sandbox = copy.deepcopy(config["sandbox"])
        guard = self.receipt["binaries"]["forgeflow-sandbox-guard"]
        if core.sha(guard["path"]) != guard["sha256"]:
            raise RuntimeError("The sandbox guard differs from the current receipt.")
        sandbox.update(guard_program=guard["path"], guard_sha256=guard["sha256"])
        sandbox["readonly_paths"] = list(dict.fromkeys([*sandbox["readonly_paths"], str(planning), str(coding)]))
        config["sandbox"] = sandbox
        resource_id = "semantic-resource." + tag
        self.planning_template_id, self.coding_template_id = "semantic-planning." + tag, "semantic-coding." + tag
        for collection, identity, value in [
                ("executor_profiles", profile["id"], profile),
                ("resource_profiles", resource_id, {"id": resource_id, "sandbox": sandbox, "build_capable": False}),
                ("model_routes", profile["model_route_id"], self.config["model_route_document"]),
                ("verification_plans", self.planning_template_id, self.verification_plan(self.planning_template_id,
                    planning, module.CASES, core.PLANNING_INTENT_ORACLE, worker_id)),
                ("verification_plans", self.coding_template_id, self.verification_plan(self.coding_template_id,
                    coding, core.CODING_CASES, "semantic-replanning-fixed-text.v2", worker_id))]:
            self.ensure_document(collection, identity, value)
        self.worker_config, self.worker_config_path = config, private_dir / "worker.json"
        core.private_save(self.worker_config_path, config)
        self.global_scope_id, self.worker_scope_id = "ui-a0546177-global", "semantic-" + tag + "-worker"
        self.capacity_scope_ids = ["ui-a0546177-" + name for name in ("global", "project", "root", "child")]
        policies = self.api("GET", "/resources")
        for scope_id in self.capacity_scope_ids:
            found = next(row for row in policies if row["scope_id"] == scope_id)
            if found["paused"] or found["limits"] != self.config["resource_limits"]:
                raise RuntimeError("The retained hierarchy differs; no capacity is raised by this scenario.")
        self.report.update(scheduled_worker_id=worker_id, private_worker_config_path=str(self.worker_config_path),
            profile_id=profile["id"], model_route_id=profile["model_route_id"],
            new_planning_method={"method": "compact-intent.v2", "oracle_path": str(planning),
                "oracle_sha256": core.sha(planning), "new_planning_request_cap": 3, "delivery_request_cap": 3},
            new_coding_oracle={"path": str(coding), "sha256": core.sha(coding), "prospective": True,
                "old_oracle_and_outputs_unchanged": True})
        return profile["id"], resource_id

    def retain_execution_artifacts(self, attempts):
        super().retain_execution_artifacts([row for row in attempts if row["attempt_id"] not in self.old_attempt_ids])

    def semantic_edit(self):
        self.navigate(f"/projects/{PROJECT}/requirements")
        self.page.locator("tr.interactive-row").filter(has_text=self.baseline_requirement["source_anchor"]).click()
        self.page.get_by_role("button", name="编辑需求与延期理由", exact=True).click()
        drawer = self.page.get_by_role("dialog", name="编辑需求", exact=True)
        for label, value in [("需求标题", ACCEPTANCE), ("业务结果", ACCEPTANCE), ("范围", REASON),
                             ("验收条件 · 每行一条", ACCEPTANCE)]:
            drawer.get_by_label(label, exact=True).fill(value)
        changed = self.click(drawer.get_by_role("button", name="创建需求", exact=True), f"/projects/{PROJECT}/requirements/{REQ}", "PATCH")
        old = self.baseline_requirement
        self.stage(core.STAGES[0], changed["revision"] == 2 and changed["source_anchor"] == old["source_anchor"]
            and changed["acceptance"] == [ACCEPTANCE] and changed["scope"] == REASON,
            original_requirement_revision=1, new_requirement_revision=2, changed_requirement=changed,
            setup_inherited=True, business_write_origin="ACTUAL_REQUIREMENT_FORM_PATCH")
        self.page.screenshot(path=str(self.out / "semantic-requirement-desktop.png"), full_page=False)
        self.page.get_by_role("button", name="关闭检查器", exact=True).click()
        self.stage(core.STAGES[1], True, root_team_id=ROOT_TEAM, child_team_id=CHILD_TEAM,
            owner_id=ROOT_TEAM, evidence_origin="RETAINED_CLOSED_ACTUAL_GUI_FIXTURE", counts_as_new_business_chain=False)

    def replan(self, profile_id, resource_id):
        self.current_stage = core.STAGES[2]
        self.navigate(f"/projects/{PROJECT}/requirements")
        self.page.get_by_role("button", name="生成 Flow 草案", exact=True).click()
        drawer = self.page.get_by_role("dialog", name="真实 DSH 规划配置", exact=True)
        for label, value in [("根 Owner", ROOT_TEAM), ("预算团队", CHILD_TEAM), ("DSH 执行器 Profile", profile_id),
                ("独立规划验证模板", self.planning_template_id), ("资源 Profile", resource_id)]:
            drawer.get_by_label(label, exact=True).select_option(value)
        drawer.get_by_label("本次规划调用上限", exact=True).fill("3")
        drawer.get_by_label("规划指导", exact=True).fill(
            "Instruction version: semantic-replanning.compact-intent.v2. The current Owner-edited structured requirement is the operation authority; "
            "the older imported document remains history. Return exactly one compact planning intent task T1 implementing the current acceptance: "
            + ACCEPTANCE + " Preserve the exact requirement ID and anchor from the current request. Write only journey-result.txt. "
            "Use concise title, outcome and rollback_plan; read_set, dependencies, producer_inputs and contracts empty. "
            "verification_case_count=4; resource_request active_slot=1,coding_slot=1,cpu_units=1,memory_bytes=67108864,build_permit=0,gpu_permit=0,provider_inflight=1. "
            "Emit schema_version forgeflow.planning-intent.v1 and tasks only. The controller supplies authority, hashes and Flow fields. "
            "Output complete JSON only; do not write files, execute, delegate, complete or approve any task.")
        generated = self.click(drawer.get_by_role("button", name="提交真实规划操作", exact=True), f"/projects/{PROJECT}/flow-generations")
        command = next(row for row in reversed(self.browser_records) if row["method"] == "POST" and row["route"] == f"/projects/{PROJECT}/flow-generations")
        if command["body"]["max_model_requests"] != 3:
            raise RuntimeError("The actual GUI planning request did not declare the fixed three-call cap.")
        self.confirm_bootstrap_replacement(generated["operation_id"])
        binding = self.report["v2_prelaunch_verification_binding"]["bindings"][0]["env"]
        source = json.loads(Path(binding["FORGEFLOW_PLANNING_SOURCE_PATH"]).read_text())
        request = json.loads(Path(binding["FORGEFLOW_DRAFT_REQUEST_PATH"]).read_text())
        current = next(row for row in source["requirements"] if row["requirement_id"] == REQ)
        if current["revision"] != 2 or current["acceptance"] != [ACCEPTANCE] \
                or self.old_history() != self.baseline_history or self.artifact_inventory() != self.baseline_artifacts:
            raise RuntimeError("The frozen new planning input or the original retained history differs before launch.")
        self.report["new_requirement_planning_binding"] = {"requirement_revision": 2,
            "semantic_sha256": request["source"]["semantic_sha256"], "raw_source_bundle_sha256": request["source"]["raw_sha256"],
            "source_bundle": str(Path(binding["FORGEFLOW_PLANNING_SOURCE_PATH"])), "acceptance": current["acceptance"]}
        self.start_worker()
        operation = self.operation(generated["operation_id"])
        flow, attempt_id = operation["result"]["flow"], operation["result"]["planning_attempt_id"]
        receipts = self.db_json("SELECT coalesce(jsonb_agg(data),'[]'::jsonb) FROM evidence_receipts WHERE project_id='"
            + PROJECT + "' AND attempt_id='" + attempt_id + "';")
        verified = [row for row in receipts if row["kind"] == "STRUCTURED_ARTIFACT" and row["total"] == 25 and row["failed"] == row["skipped"] == 0]
        original = Path(self.private["FORGEFLOW_DATA_ROOT"]) / "attempts" / attempt_id / "final.json"
        output = operation["result"].get("planning_output")
        self.report["v2_planning_verification"] = {"receipts": receipts, "planning_output": output,
            "original_final_sha256": core.sha(original), "actual_case_denominator": 25,
            "original_output_repaired_or_replaced": False}
        self.stage(core.STAGES[2], operation["result"]["generation_method"] == "dsh_model_assisted"
            and flow["state"] == "DRAFT" and flow["approved_by"] is None and len(flow["tasks"]) == 1
            and attempt_id in self.launch_seen and len(verified) == 1 and output["sha256"] == core.sha(original),
            operation_id=operation["operation_id"], planning_attempt_id=attempt_id, new_flow_revision=flow["flow_revision"])
        return flow

    def traceability(self):
        snapshot = self.api("GET", f"/projects/{PROJECT}/snapshot")
        requests = [row for row in snapshot["native_model_requests"] if row["request_id"] not in self.old_model_ids]
        history = self.old_history()
        old_flow = self.api("GET", f"/flows/{PROJECT}:5")
        sources = self.api("GET", f"/projects/{PROJECT}/documents/sources?limit=500")
        old_blob = subprocess.check_output(["git", "-C", self.canonical, "show", OLD_SHA + ":journey-result.txt"])
        events = self.db_json("SELECT coalesce(jsonb_agg(jsonb_build_object('event_id',event_id,'project_seq',project_seq,"
            "'object_id',object_id,'object_revision',object_revision,'kind',kind,'occurred_at',occurred_at) ORDER BY project_seq),'[]'::jsonb) "
            "FROM events WHERE project_id='" + PROJECT + "' AND project_seq>" + str(self.baseline_seq) + ";")
        core.save(self.out / "new-business-events.json", events)
        # Committing a new Flow legitimately supersedes the old row. Its tasks,
        # approved input digest and immutable compiler context remain history.
        flow_content = lambda value: {key: item for key, item in value.items() if key not in {"state", "revision"}}
        preserved = history == self.baseline_history and flow_content(old_flow) == flow_content(self.baseline_flow) \
            and old_flow["state"] == "SUPERSEDED" and sources == self.baseline_sources \
            and self.artifact_inventory() == self.baseline_artifacts and old_blob == OLD_BYTES
        budget = len(requests) <= 6 and all(row["status"] == "SETTLED" and row["usage_complete"] for row in requests)
        self.report.update(old_history_preserved=preserved, old_integrated_sha=OLD_SHA,
            new_actual_model_request_count=len(requests), new_actual_model_request_ceiling=6,
            historical_cumulative_actual_model_requests=14, combined_actual_model_request_count=14 + len(requests),
            new_model_request_ids=[row["request_id"] for row in requests],
            new_model_requests=[{key: row[key] for key in ("request_id", "attempt_id", "status", "purpose", "max_output_tokens", "usage_complete")} for row in requests],
            new_business_event_count=len(events), milestone_3_9_status="INCONCLUSIVE")
        core.save(self.out / "retained-after.json", {"history": history, "old_flow": old_flow,
            "artifact_hashes": self.artifact_inventory(), "old_integrated_blob_sha256": hashlib.sha256(old_blob).hexdigest(),
            "preserved": preserved, "new_model_budget_passed": budget})
        task_id = self.report["stages"][core.STAGES[3]]["task_id"]
        task = next(row for row in snapshot["tasks"] if row["task_id"] == task_id)
        core.save(self.out / "handoff.json", {"status": "WAIT_FOR_ZERO_LEASES_ALLOCATIONS_THEN_ROOT_NEW_BINARY",
            "project_id": PROJECT, "api_bind": "127.0.0.1:8794", "runtime_env_path": self.config["runtime_env_path"],
            "data_root": self.private["FORGEFLOW_DATA_ROOT"], "canonical_repository": self.canonical,
            "flow_revision": task["flow_revision"], "task_id": task_id, "task_revision": task["task_revision"],
            "verification_plan_id": task["envelope"]["verification_plan_id"],
            "integrated_sha": self.report["stages"][core.STAGES[5]]["integrated_sha"],
            "milestone_api_proposed": "POST /projects/{p}/milestones/{m}/accept",
            "required_work_packages": [task_id], "required_gate_ids": [task["envelope"]["verification_plan_id"]],
            "no_model_replay_required": True,
            "restart": "Root checks report cleanup and actual zero valid leases/held allocations; starts new server binary with the same private runtime-env and data root. No Worker is needed for the milestone adjudication."})
        if not preserved or not budget or not any(row["kind"] == "requirement.updated" for row in events) \
                or self.report["stages"][core.STAGES[5]]["integrated_sha"] == OLD_SHA:
            raise RuntimeError("The distinct replanning chain requires unchanged historical inputs/SHA and at most six settled new requests.")

    def run(self):
        from playwright.sync_api import sync_playwright
        self.start_server()
        self.baseline()
        profile_id, resource_id = self.prerequisites(ROOT_TEAM, CHILD_TEAM)
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
            self.semantic_edit()
            flow = self.replan(profile_id, resource_id)
            core.EXPECTED = NEW_BYTES  # This process only; old helper source and evidence are never modified.
            self.deliver(flow, profile_id, resource_id, repo, source_head, browser)
            self.traceability()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", action="store_true")
    parser.add_argument("--output", type=Path, default=OUT)
    parser.add_argument("--receipt", type=Path, default=RECEIPT)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    if not args.run:
        core.save(args.output / "preparation.json", preparation())
        print(json.dumps({"status": "SOURCE_READY_NOT_EXECUTED", "business_chain": "3.7", "new_call_cap": 6}))
        return 0
    if (args.output / "report.json").exists():
        raise RuntimeError("Retain this scenario's original outcome; no automatic repeat is authorized.")
    journey = SemanticJourney(args.output, args.receipt)
    try:
        journey.run()
    except Exception as failure:
        journey.report["status"] = "FAIL"
        journey.report["failure"] = {"type": type(failure).__name__, "message": str(failure)}
        if journey.report["stages"][journey.current_stage]["status"] != "PASS":
            journey.report["stages"][journey.current_stage] = {"status": "FAIL", "error_type": type(failure).__name__, "message": str(failure)}
    finally:
        if hasattr(journey, "old_model_ids"):
            try:
                final = journey.api("GET", f"/projects/{PROJECT}/snapshot")
                new = [row for row in final["native_model_requests"] if row["request_id"] not in journey.old_model_ids]
                journey.report.update(new_actual_model_request_count=len(new), new_actual_model_request_ceiling=6,
                    historical_cumulative_actual_model_requests=14, combined_actual_model_request_count=14 + len(new),
                    new_model_request_states=[row["status"] for row in new])
                if len(new) > 6:
                    journey.report.update(status="FAIL", failure={"type": "ModelBudgetExceeded", "message": "More than six new native model requests were admitted."})
            except Exception as failure:
                journey.report["final_model_authority_observation"] = {"status": "UNCONFIRMED", "error_type": type(failure).__name__}
        journey.cleanup()
        journey.write_report()
    print(json.dumps({"status": journey.report["status"], "business_chain": "3.7",
        "new_actual_model_request_count": journey.report.get("new_actual_model_request_count"),
        "old_history_preserved": journey.report.get("old_history_preserved"), "cleanup": journey.report.get("cleanup")}, ensure_ascii=False))
    return 0 if journey.report["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
