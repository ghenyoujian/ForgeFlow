#!/usr/bin/env python3
"""Source-only contract tests for the planning oracle, never model qualification."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
SPEC = importlib.util.spec_from_file_location("planning_intent_oracle", HERE / "planning_intent_verifier.py")
oracle = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(oracle)


def encode(value):
    return json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def constructed_contract():
    """Construct oracle inputs; no service, executor, model route, or API is called."""
    operation = "standalone-source-only"
    domain_requirement = {
        "project_id": "project-only-test", "requirement_id": "R-original",
        "title": "Original requirement", "source_anchor": "source-original#result",
        "outcome": "Deliver the original result", "scope": "out/",
        "acceptance": ["Preserve the exact original acceptance", "Retain failures"],
        "priority": 1, "weight": 1, "deferred_reason": None, "revision": 1,
    }
    source = {"documents": [{"id": "source-original", "text": "Original source kept intact"}],
              "requirements": [domain_requirement],
              "manual_requirement_policy": "explicit owner-entered requirement rows are immutable operation inputs; missing source documents are not claimed as loaded"}
    source_raw = encode(source)
    source_hash = oracle.sha(source_raw)
    source_path = "source-artifacts/planning-source-" + operation + ".json"
    request = {
        "project_id": "project-only-test", "flow_revision": 2,
        "source": {"source_document": "planning-source-" + operation, "raw_sha256": source_hash,
            "semantic_sha256": oracle.sha(encode(source["requirements"])), "requirements": [{
                "requirement_id": "R-original", "source_document": "source-original", "anchor": "result",
                "acceptance": "\n".join(domain_requirement["acceptance"]), "priority": 1, "deferred_reason": None}]},
        "owner_id": "owner-original", "team_id": "child-original", "write_set": ["out/"],
        "execution_profile": "original-executor-profile", "verification_plan": "original-review-template",
    }
    cap = {"active_slot": 4, "coding_slot": 2, "cpu_units": 4, "memory_bytes": 268435456,
           "build_permit": 1, "gpu_permit": 0, "provider_inflight": 1}
    scopes = []
    for scope_id, parent, project_id, team_id in (
            ("global", None, None, None), ("project", "global", request["project_id"], None),
            ("root", "project", request["project_id"], "root-original"),
            ("child", "root", request["project_id"], request["team_id"])):
        scopes.append({"worker_id": None, "scope_id": scope_id, "parent_scope_id": parent,
                       "project_id": project_id, "team_id": team_id, "limits": dict(cap),
                       "revision": 1, "paused": False})
    authority = {
        "schema_version": oracle.AUTHORITY_SCHEMA, "proposal_schema_version": oracle.SCHEMA,
        "max_tasks": 10000, "source_input": {"path": source_path, "sha256": source_hash, "producer_task_id": None},
        "current_inputs": {source_path: source_hash, "inputs/original.txt": oracle.sha(b"Original input")},
        "requirement_semantic_digests": {"R-original": oracle.requirement_digest(domain_requirement)},
        "owners": [{"owner_id": request["owner_id"], "root_team_id": "root-original", "include": ["out/"], "exclude": []}],
        "resolved_paths": {}, "contracts": [],
        "resources": {"scope": "GLOBAL_PROJECT_TEAM_CAPS_ONLY_WORKER_PLACEMENT_UNVERIFIED",
                      "scopes": scopes, "effective_limits": cap},
    }
    task = {
        "task_id": "T1", "title": "Finite source-bound result", "requirement_ids": ["R-original"],
        "outcome": "Deliver the exact original acceptance and retain failures",
        "read_set": ["inputs/original.txt"], "write_set": ["out/result.txt"], "dependencies": [],
        "resource_request": {"active_slot": 1, "coding_slot": 1, "cpu_units": 1, "memory_bytes": 67108864,
                             "build_permit": 0, "gpu_permit": 0, "provider_inflight": 0},
        "verification_case_count": 2, "rollback_plan": "Revert the exact task diff while preserving failed artifacts",
    }
    intent = {"schema_version": oracle.SCHEMA, "tasks": [task]}
    return intent, request, authority, source


def native_contract(intent, request, authority, source):
    request_raw, authority_raw, source_raw = map(encode, (request, authority, source))
    raw = encode({"type": "final", "text": encode(intent).decode("utf-8")})
    env = {
        "FORGEFLOW_DRAFT_REQUEST_SHA256": oracle.sha(request_raw),
        "FORGEFLOW_PLANNING_AUTHORITY_SHA256": oracle.sha(authority_raw),
        "FORGEFLOW_PLANNING_SOURCE_SHA256": oracle.sha(source_raw),
        "FORGEFLOW_PLANNING_TASK_ID": "planning-standalone-source-only",
        "FORGEFLOW_PLANNING_INPUT_HASH": oracle.sha(b"prelaunch canonical planning task/spec identity"),
        "FORGEFLOW_PLANNING_CONTEXT_SHA256": oracle.sha(b"prelaunch context manifest"),
        "FORGEFLOW_PLANNING_PROMPT_SHA256": oracle.sha(b"prelaunch prompt"),
    }
    binding = {"task_revision": 1, "attempt_id": "standalone-source-only-attempt", "generation": 1,
        "verification_plan_id": "planning-verification-standalone-source-only",
        "verification_plan_hash": oracle.sha(b"prelaunch registered verification plan"),
        "contract_version": "none", "input_hash": env["FORGEFLOW_PLANNING_INPUT_HASH"],
        "context_hash": env["FORGEFLOW_PLANNING_CONTEXT_SHA256"],
        "prompt_hash": env["FORGEFLOW_PLANNING_PROMPT_SHA256"], "artifact_hash": oracle.sha(raw)}
    return raw, request_raw, authority_raw, source_raw, env, binding


def future_contract():
    intent, request, authority, source = constructed_contract()
    producer = intent["tasks"][0]
    producer["write_set"] = ["out/producer.json"]
    binding = {"contract_id": "original-public-contract", "version": 1, "spec_sha256": oracle.sha(b"exact registered spec")}
    producer["contract_produces"] = [copy.deepcopy(binding)]
    consumer = copy.deepcopy(producer)
    consumer.update(task_id="T2", title="Finite consumer", write_set=["out/consumer.txt"],
                    read_set=["out/producer.json"], contract_produces=[], contract_consumes=[copy.deepcopy(binding)],
                    dependencies=[{"task_id": "T1", "kind": "integrated", "binding_id": "producer-exact-integration"}],
                    producer_inputs=[{"path": "out/producer.json", "producer_task_id": "T1",
                        "dependency_binding_id": "producer-exact-integration", "contract": copy.deepcopy(binding)}])
    intent["tasks"].append(consumer)
    authority["contracts"] = [dict(binding, source_sha256=oracle.sha(b"registered source"), frozen=True,
        required_consumers=["registered-consumer"], passing_consumers=["registered-consumer"],
        independent_receipt_id="original-independent-receipt", integration_receipt_id="original-integration-receipt")]
    return intent, request, authority, source


class PlanningIntentContractTests(unittest.TestCase):
    def setUp(self):
        self.intent, self.request, self.authority, self.source = constructed_contract()

    def valid(self):
        return oracle.validate(self.intent, self.request, self.authority, self.source)

    def reject(self, message=None):
        with self.assertRaises(ValueError) as raised:
            self.valid()
        if message:
            self.assertIn(message, str(raised.exception))

    def test_valid_source_bound_zero_model_intent(self):
        self.assertEqual(self.valid(), ["T1"])

    def test_provider_positive_is_allowed_within_original_cap(self):
        self.intent["tasks"][0]["resource_request"]["provider_inflight"] = 1
        self.valid()

    def test_read_only_zero_coding_is_allowed(self):
        self.intent["tasks"][0]["write_set"] = []
        self.intent["tasks"][0]["resource_request"]["coding_slot"] = 0
        self.valid()

    def test_deep_dag_accepts_existing_ten_thousand_task_scale(self):
        first = self.intent["tasks"][0]
        first["write_set"] = []
        first["read_set"] = []
        tasks = []
        for index in range(10000):
            task = copy.deepcopy(first)
            task["task_id"] = "T" + str(index)
            if index:
                task["dependencies"] = [{"task_id": "T" + str(index - 1), "kind": "integrated", "binding_id": "chain"}]
            tasks.append(task)
        self.intent["tasks"] = list(reversed(tasks))
        order = self.valid()
        self.assertEqual(len(order), 10000)
        self.assertEqual((order[0], order[-1]), ("T0", "T9999"))

    def test_more_than_ten_thousand_tasks_is_rejected(self):
        self.intent["tasks"] = [self.intent["tasks"][0]] * 10001
        self.reject("task denominator")

    def test_large_text_has_no_fixture_size_reduction(self):
        self.intent["tasks"][0]["outcome"] = "Original acceptance; " * 1000
        self.assertGreater(len(encode(self.intent)), 8192)
        oracle.verify_artifact(*native_contract(self.intent, self.request, self.authority, self.source))

    def test_all_three_roles_have_complete_nonzero_passed_cases(self):
        contract = native_contract(self.intent, self.request, self.authority, self.source)
        for role in oracle.CASES:
            with self.subTest(role=role):
                results, errors = oracle.run_cases(role, *contract)
                self.assertFalse(errors)
                self.assertGreater(len(results), 0)
                self.assertEqual(set(results), {n for n, _ in oracle.CASES[role]})
                self.assertTrue(all(results.values()), results)

    def test_invalid_actual_candidate_never_passes_mutation_cases(self):
        self.intent["tasks"][0]["verification_case_count"] = 0
        for role in oracle.CASES:
            results, errors = oracle.run_cases(role, *native_contract(self.intent, self.request, self.authority, self.source))
            self.assertTrue(errors)
            self.assertFalse(any(results.values()))

    def test_runtime_report_schema_case_identity_and_denominator(self):
        raw, request_raw, authority_raw, source_raw, env, binding = native_contract(
            self.intent, self.request, self.authority, self.source)
        with tempfile.TemporaryDirectory(prefix="forgeflow-intent-oracle-") as directory:
            directory = Path(directory)
            for name, payload in (("native.json", raw), ("request.json", request_raw),
                                  ("authority.json", authority_raw), ("source.json", source_raw)):
                (directory / name).write_bytes(payload)
            env.update({"FORGEFLOW_ARTIFACT_PATH": str(directory / "native.json"),
                        "FORGEFLOW_DRAFT_REQUEST_PATH": str(directory / "request.json"),
                        "FORGEFLOW_PLANNING_AUTHORITY_PATH": str(directory / "authority.json"),
                        "FORGEFLOW_PLANNING_SOURCE_PATH": str(directory / "source.json"),
                        "FORGEFLOW_EVIDENCE_BINDING": json.dumps(binding)})
            for role in oracle.CASES:
                report_path = directory / (role + ".json")
                env.update(FORGEFLOW_VERIFICATION_ROLE=role, FORGEFLOW_REPORT_PATH=str(report_path))
                completed = subprocess.run([sys.executable, "-I", "-B", str(HERE / "planning_intent_verifier.py")],
                    env={**os.environ, **env}, capture_output=True, text=True, timeout=30)
                self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
                report = json.loads(report_path.read_text())
                self.assertEqual(set(report), {"binding", "oracle_id", "cases"})
                self.assertEqual(report["binding"], binding)
                self.assertEqual(report["oracle_id"], oracle.ORACLE)
                self.assertEqual([(c["name"], c["kind"]) for c in report["cases"]], oracle.CASES[role])
                self.assertTrue(all(c["outcome"] == "passed" for c in report["cases"]))
                self.assertEqual((directory / "native.json").read_bytes(), raw)

    def test_prelaunch_original_hash_pins_reject_each_changed_input(self):
        contract = list(native_contract(self.intent, self.request, self.authority, self.source))
        for index in (1, 2, 3):
            changed = list(contract)
            changed[index] += b" "
            with self.subTest(input_index=index), self.assertRaises(ValueError):
                oracle.verify_artifact(*changed)

    def test_raw_artifact_byte_binding_is_exact(self):
        contract = list(native_contract(self.intent, self.request, self.authority, self.source))
        contract[0] += b"\n"
        with self.assertRaisesRegex(ValueError, "raw final bytes mismatch"):
            oracle.verify_artifact(*contract)

    def test_native_final_event_is_required(self):
        contract = list(native_contract(self.intent, self.request, self.authority, self.source))
        contract[0] = encode({"type": "tool", "text": encode(self.intent).decode()})
        contract[-1]["artifact_hash"] = oracle.sha(contract[0])
        with self.assertRaisesRegex(ValueError, "native terminal final"):
            oracle.verify_artifact(*contract)

    def test_each_binding_input_context_prompt_and_task_identity_is_pinned(self):
        for field in ("input_hash", "context_hash", "prompt_hash", "verification_plan_id", "task_revision"):
            contract = list(native_contract(self.intent, self.request, self.authority, self.source))
            contract[-1][field] = 2 if field == "task_revision" else "wrong"
            with self.subTest(field=field), self.assertRaises(ValueError):
                oracle.verify_artifact(*contract)

    def test_source_acceptance_scope_and_digests_are_bound(self):
        self.source["requirements"][0]["acceptance"][0] = "Silently lowered acceptance"
        self.reject("source projection changed")

    def test_full_source_scope_semantic_rewrite_is_rejected(self):
        self.source["requirements"][0]["scope"] = "out/plus-extra/"
        self.reject("semantic pins")

    def test_requirement_digest_pin_tamper_is_rejected(self):
        self.authority["requirement_semantic_digests"]["R-original"] = "0" * 64
        self.reject("semantic pins")

    def test_missing_original_requirement_denominator_is_rejected(self):
        self.request["source"]["requirements"] = []
        self.reject("requirement denominator")

    def test_coverage_gap_and_original_deferred_reason(self):
        row = copy.deepcopy(self.source["requirements"][0])
        row.update(requirement_id="R-unmapped", source_anchor="source-original#unmapped")
        self.source["requirements"].append(row)
        projected = copy.deepcopy(self.request["source"]["requirements"][0])
        projected.update(requirement_id="R-unmapped", anchor="unmapped")
        self.request["source"]["requirements"].append(projected)
        self.authority["requirement_semantic_digests"]["R-unmapped"] = oracle.requirement_digest(row)
        self.reject("coverage gap")
        row["deferred_reason"] = projected["deferred_reason"] = "Owner explicitly deferred in the ORIGINAL source"
        self.authority["requirement_semantic_digests"]["R-unmapped"] = oracle.requirement_digest(row)
        self.valid()

    def test_invented_requirement_is_rejected(self):
        self.intent["tasks"][0]["requirement_ids"] = ["R-invented"]
        self.reject("original requirements")

    def test_duplicate_task_and_requirement_ids_are_rejected(self):
        self.intent["tasks"].append(copy.deepcopy(self.intent["tasks"][0]))
        self.reject("unique short ASCII task")
        self.intent["tasks"].pop()
        self.intent["tasks"][0]["requirement_ids"] *= 2
        self.reject("duplicates")

    def test_model_authority_and_unknown_fields_are_rejected(self):
        for field in ("owner_id", "team_id", "state", "approved_by", "envelope", "inputs",
                      "input_digest", "execution_profile", "requirement_digest_refs", "isolated_contract_probe"):
            intent = copy.deepcopy(self.intent)
            intent["tasks"][0][field] = "invented"
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, "model authority/hashes"):
                oracle.validate(intent, self.request, self.authority, self.source)

    def test_compact_and_legacy_grammar_versions_remain_separate(self):
        self.intent = {"generation_method": "dsh_model_assisted", "flow": {}, "context": {}}
        self.reject("compact intent fields")

    def test_protocol_and_snapshot_task_scale_mismatch_are_rejected(self):
        self.intent["schema_version"] = "forgeflow.planning-intent.v2"
        self.reject("protocol version")
        self.intent["schema_version"] = oracle.SCHEMA
        self.authority["max_tasks"] = 16
        self.reject("task scale mismatch")

    def test_strict_json_duplicates_nonfinite_eof_and_invalid_unicode(self):
        for text in ('{"root":{"task_id":"one","task_id":"two"}}', '{"resource":NaN}',
                     '{"resource":Infinity}', '{"resource":1e309}', '{"tasks":[', '{"title":"\\ud800"}',
                     '{"tasks":[]} trailing', '{"tasks":[]} {"tasks":[]}'):
            with self.subTest(text=text), self.assertRaises(ValueError):
                oracle.strict_load(text)

    def test_native_final_and_model_text_duplicates_are_both_rejected(self):
        contract = list(native_contract(self.intent, self.request, self.authority, self.source))
        for raw in (b'{"type":"final","type":"final","text":"{}"}',
                    encode({"type": "final", "text": '{"schema_version":"' + oracle.SCHEMA + '","tasks":[],"tasks":[]}'})):
            contract[0] = raw
            contract[-1]["artifact_hash"] = oracle.sha(raw)
            with self.assertRaisesRegex(ValueError, "duplicate JSON key"):
                oracle.verify_artifact(*contract)

    def test_retained_actual_3197_byte_eof_remains_rejected_and_unmodified(self):
        path = ROOT / "evidence/enterprise-ux/user-journey-r1/continue-after-planning-reservation-fix/e587cdd0-1789-4bfb-847f-c77fd2ce2e2c.final.json"
        raw = path.read_bytes()
        text = oracle.strict_load(raw.decode())["text"]
        self.assertEqual(len(text.encode("utf-8")), 3197)
        with self.assertRaises(json.JSONDecodeError):
            oracle.strict_load(text)
        self.assertEqual(path.read_bytes(), raw)

    def test_write_scope_expansion_and_unsafe_paths_are_rejected(self):
        for path in ("outside/result.txt", "../outside", "/absolute", "out//double", "out/./dot", "out\\windows", "out/dir//"):
            self.intent["tasks"][0]["write_set"] = [path]
            with self.subTest(path=path):
                self.reject()

    def test_owner_exclude_and_symlink_escape_are_rejected(self):
        self.authority["owners"][0]["exclude"] = ["out/private/"]
        self.intent["tasks"][0]["write_set"] = ["out/private/result.txt"]
        self.reject("Owner territory/excludes")
        self.authority["owners"][0]["exclude"] = []
        self.authority["resolved_paths"]["out/private/result.txt"] = "other-owner/result.txt"
        self.reject("Owner territory/excludes")

    def test_overlapping_root_owners_are_rejected(self):
        self.authority["owners"].append({"owner_id": "another-owner", "root_team_id": "root-original", "include": ["out/"], "exclude": []})
        self.reject("unique original root Owner")

    def test_exact_read_input_hash_cannot_be_invented_or_missing(self):
        self.intent["tasks"][0]["read_set"] = ["inputs/not-snapshotted.txt"]
        self.reject("read input absent")
        self.intent["tasks"][0]["read_set"] = ["inputs/original.txt"]
        self.authority["current_inputs"]["inputs/original.txt"] = "placeholder"
        self.reject("snapshot identities")

    def test_source_input_current_snapshot_cannot_drift(self):
        path = self.authority["source_input"]["path"]
        self.authority["current_inputs"][path] = "0" * 64
        self.reject("source current-input snapshot mismatch")

    def test_zero_boolean_negative_float_and_overflow_resources_are_rejected(self):
        for value in (0, True, -1, 1.0, 2**64):
            self.intent["tasks"][0]["resource_request"]["active_slot"] = value
            with self.subTest(value=value):
                self.reject()

    def test_zero_coding_cannot_authorize_writes(self):
        self.intent["tasks"][0]["resource_request"]["coding_slot"] = 0
        self.reject("positive active/coding")

    def test_every_resource_dimension_stays_within_original_cap(self):
        for field in oracle.RESOURCE_FIELDS:
            task = copy.deepcopy(self.intent)
            task["tasks"][0]["resource_request"][field] = self.authority["resources"]["effective_limits"][field] + 1
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, "approved resource cap"):
                oracle.validate(task, self.request, self.authority, self.source)

    def test_cap_uses_limits_not_current_free_usage_and_no_worker_claim(self):
        self.intent["tasks"][0]["resource_request"]["provider_inflight"] = 1
        self.valid()
        self.authority["resources"]["scope"] = "WORKER_PLACEMENT_QUALIFIED"
        self.reject("worker-placement qualification")

    def test_effective_cap_is_minimum_of_all_ancestors(self):
        self.authority["resources"]["scopes"][0]["limits"]["active_slot"] = 1
        self.reject("cap differs")
        self.authority["resources"]["effective_limits"]["active_slot"] = 1
        self.valid()

    def test_resource_global_project_team_ancestor_denominators_are_required(self):
        original = copy.deepcopy(self.authority["resources"]["scopes"])
        for index in range(len(original)):
            self.authority["resources"]["scopes"] = original[:index] + original[index + 1:]
            with self.subTest(missing_scope=original[index]["scope_id"]):
                self.reject()

    def test_planned_denominator_is_strict_nonzero_u64(self):
        for value in (0, -1, True, 1.0, 2**64):
            self.intent["tasks"][0]["verification_case_count"] = value
            with self.subTest(value=value):
                self.reject("case denominator")

    def test_dag_cycles_missing_predecessors_and_duplicate_edges(self):
        for dependencies in (
                [{"task_id": "T1", "kind": "integrated", "binding_id": "self"}],
                [{"task_id": "T-missing", "kind": "artifact", "binding_id": "missing"}],
                [{"task_id": "T-missing", "kind": "artifact", "binding_id": "first"},
                 {"task_id": "T-missing", "kind": "artifact", "binding_id": "second"}]):
            self.intent["tasks"][0]["dependencies"] = dependencies
            with self.subTest(dependencies=dependencies):
                self.reject()

    def test_dependency_kind_and_binding_are_exact(self):
        self.intent["tasks"][0]["dependencies"] = [{"task_id": "T1", "kind": "success", "binding_id": ""}]
        self.reject("semantic dependency")

    def test_registered_frozen_contracts_and_future_producer_edges(self):
        self.intent, self.request, self.authority, self.source = future_contract()
        self.assertEqual(self.valid(), ["T1", "T2"])

    def test_registered_contract_hash_mismatch_is_rejected(self):
        self.intent, self.request, self.authority, self.source = future_contract()
        self.intent["tasks"][1]["contract_consumes"][0]["spec_sha256"] = "0" * 64
        self.reject("registered contract pins")

    def test_public_contract_requires_actual_frozen_receipts(self):
        for field, value in (("frozen", False), ("required_consumers", []), ("passing_consumers", []),
                             ("independent_receipt_id", None), ("integration_receipt_id", None)):
            self.intent, self.request, self.authority, self.source = future_contract()
            self.authority["contracts"][0][field] = value
            with self.subTest(field=field):
                self.reject("frozen evidence")

    def test_future_input_exact_integrated_binding_and_producer_path(self):
        for field, value in (("kind", "artifact"), ("binding_id", "wrong-binding")):
            self.intent, self.request, self.authority, self.source = future_contract()
            self.intent["tasks"][1]["dependencies"][0][field] = value
            with self.subTest(field=field):
                self.reject("integrated predecessor")
        self.intent, self.request, self.authority, self.source = future_contract()
        self.intent["tasks"][0]["write_set"] = ["out/different.json"]
        self.reject("producer path/contract")

    def test_future_input_unknown_hash_and_wrong_revision_are_rejected(self):
        self.intent, self.request, self.authority, self.source = future_contract()
        future = self.intent["tasks"][1]["producer_inputs"][0]
        future["sha256"] = "0" * 64
        self.reject("invented byte hashes")
        del future["sha256"]
        future["producer_task_revision"] = 2
        self.reject("revision pin")

    def test_future_semantic_pins_remain_expressible_and_unrepaired(self):
        self.intent, self.request, self.authority, self.source = future_contract()
        future = self.intent["tasks"][1]["producer_inputs"][0]
        future.update(producer_task_revision=1, producer_input_digest="a" * 64)
        before = copy.deepcopy(self.intent)
        self.valid()
        self.assertEqual(self.intent, before)
        # Exact semantic digest equality is a mandatory downstream strict-seal
        # check, explicitly outside this raw-only oracle's qualification.
        future["producer_input_digest"] = "placeholder"
        self.reject("semantic digest pin")

    def test_duplicate_future_input_and_source_input_override_are_rejected(self):
        self.intent, self.request, self.authority, self.source = future_contract()
        future = self.intent["tasks"][1]["producer_inputs"][0]
        self.intent["tasks"][1]["producer_inputs"].append(copy.deepcopy(future))
        self.reject("future input path/read")
        self.intent["tasks"][1]["producer_inputs"].pop()
        future["path"] = self.authority["source_input"]["path"]
        self.intent["tasks"][1]["read_set"] = [future["path"]]
        self.reject("future input path/read")

    def test_full_protocol_checks_do_not_mutate_any_input(self):
        before = copy.deepcopy((self.intent, self.request, self.authority, self.source))
        self.valid()
        self.assertEqual((self.intent, self.request, self.authority, self.source), before)


def main():
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(PlanningIntentContractTests)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    names = sorted(name for name in dir(PlanningIntentContractTests) if name.startswith("test_"))
    record = {
        "status": "SOURCE_SELF_TESTS_PASS" if result.wasSuccessful() else "SOURCE_SELF_TESTS_FAIL",
        "scope": "Constructed source-only independent oracle contract tests; no model qualification",
        "oracle_id": oracle.ORACLE, "protocol_schema": oracle.SCHEMA,
        "executed": result.testsRun, "failed": len(result.failures), "errors": len(result.errors),
        "skipped": len(result.skipped), "test_names": names,
        "runtime_expected_cases": {role: [{"name": name, "kind": kind} for name, kind in cases]
                                   for role, cases in oracle.CASES.items()},
        "model_requests": 0, "dsh_sessions": 0, "api_calls": 0,
        "production_gate_claim": False,
    }
    if len(sys.argv) == 2:
        out = Path(sys.argv[1])
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(record, indent=2, ensure_ascii=False) + "\n")
    print(json.dumps(record, ensure_ascii=False))
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    raise SystemExit(main())
