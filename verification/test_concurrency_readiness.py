import copy
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("readiness", ROOT / "ops/concurrency-readiness.py")
C = importlib.util.module_from_spec(spec); spec.loader.exec_module(C)
spec = importlib.util.spec_from_file_location("billing", ROOT / "ops/concurrency-reconcile.py")
B = importlib.util.module_from_spec(spec); spec.loader.exec_module(B)


class ReadinessTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.plan = C.template("fresh", self.root)
        self.plan["worker_configs"] = [{"path": "/not-started", "sha256": "0" * 64}]

    def tearDown(self): self.temporary.cleanup()

    def test_manifest_is_not_a_runtime_qualification(self):
        self.assertEqual(C.validate(self.plan)["qualification"], "NOT_RUN")
        self.assertEqual(sum(s["agents"] for s in self.plan["stages"]), 128)
        for n in (1, 4, 10, 32): self.assertIn(n, [s["tier"] for s in self.plan["stages"]])
        self.assertLessEqual(max(s["agents"] for s in self.plan["stages"]), 32)

    def test_every_tier_covers128contexts_without128live_agents(self):
        for cap in C.STAGES:
            plan=C.template("fresh",self.root,cap,128)
            plan["worker_configs"]=self.plan["worker_configs"]
            C.validate(plan)
            self.assertEqual(sum(s["agents"] for s in plan["stages"]),128)
            self.assertEqual(len({c for s in plan["stages"] for c in s["context_ids"]}),128)
            self.assertLessEqual(max(s["agents"] for s in plan["stages"]),cap)
        plan=copy.deepcopy(self.plan); plan["stages"][-1]["context_ids"][0]=plan["stages"][0]["context_ids"][0]
        with self.assertRaises(C.Blocked): C.validate(plan)

    def test_production_remote_redirect_like_and_provider_origins_rejected(self):
        for origin in ("http://127.0.0.1:8787", "http://127.0.0.1:17891", "http://127.0.0.1:3080",
                "http://example.com:1234", "http://127.0.0.1:1234/path", "http://user:pass@127.0.0.1:1234"):
            with self.assertRaises(C.Blocked): C.origin(origin)

    def test_shortened_hold_duplicate_tasks_and_skipped_stages_rejected(self):
        p = copy.deepcopy(self.plan); p["stages"][-1]["hold_seconds"] = 0
        with self.assertRaises(C.Blocked): C.validate(p)
        p = copy.deepcopy(self.plan); p["stages"][1]["task_ids"][0] = p["stages"][0]["task_ids"][0]
        with self.assertRaises(C.Blocked): C.validate(p)
        p = copy.deepcopy(self.plan); p["stages"].pop(2)
        with self.assertRaises(C.Blocked): C.validate(p)

    def test_fake_or_predeclared_pass_and_boolean_budget_rejected(self):
        for field, value in (("workload", "CONTROLLED_LIGHTWEIGHT"), ("qualification", "PASS"),
                ("provider_inflight", True), ("max_cost_usd", 0), ("poll_seconds", 30)):
            p = copy.deepcopy(self.plan); p[field] = value
            with self.assertRaises(C.Blocked): C.validate(p)

    def test_pin_tamper_private_mode_and_symlink_rejected(self):
        path = self.root / "config.json"
        C.write_json(path, {"not_a_secret": True})
        ref = {"path": str(path), "sha256": C.digest(path)}
        self.assertEqual(C.pin(ref, private=True), path)
        path.chmod(0o644)
        with self.assertRaises(C.Blocked): C.pin(ref, private=True)
        path.chmod(0o600); path.write_text("{}")
        with self.assertRaises(C.Blocked): C.pin(ref)
        link = self.root / "link"; link.symlink_to(path)
        with self.assertRaises(C.Blocked): C.pin({"path": str(link), "sha256": C.digest(path)})

    def test_duplicate_json_keys_are_rejected(self):
        path = self.root / "duplicate.json"; path.write_text('{"status":"NOT_RUN","status":"PASS"}')
        with self.assertRaises(C.Blocked): C.read_json(path)

    def test_live_process_fingerprint_does_not_accept_absent_pid(self):
        self.assertEqual(C.fingerprint(os.getpid())["pid"], os.getpid())
        self.assertIsNone(C.fingerprint(999999999))

    def test_configured_roles_and_allocations_never_count_as_agents(self):
        snapshot = {"revision": 1, "attempts": [], "native_child_lifecycles": [
            {"attempt_id": "nonexistent", "native_session_id": f"fake-{i}", "state": "HELD", "revoked": False,
                "parent_session_id": None} for i in range(128)], "native_model_requests": [], "resource_limits": []}
        value = C.observation(snapshot, {"task"}, {}, "model")
        self.assertEqual(value["real_root_agents"], 0)

    def test_unknown_usage_and_failed_attempt_block_observation(self):
        base = {"revision": 1, "attempts": [{"task_id": "task", "attempt_id": "attempt", "worker_id": "w", "state": "RUNNING"}],
            "native_child_lifecycles": [], "native_model_requests": [{"attempt_id": "attempt", "status": "QUARANTINED", "model": "model"}], "resource_limits": []}
        with patch.object(C, "physical_author", return_value=None):
            with self.assertRaises(C.Blocked): C.observation(base, {"task"}, {"w": {}}, "model")
        base["attempts"][0]["state"] = "RECOVERY_REQUIRED"
        with self.assertRaises(C.Blocked): C.observation(base, {"task"}, {"w": {}}, "model")

    def test_root_requires_matching_process_and_actual_model_session(self):
        base = {"revision": 1, "attempts": [{"task_id": "task", "attempt_id": "attempt", "worker_id": "w", "state": "RUNNING"}],
            "native_child_lifecycles": [{"attempt_id": "attempt", "native_session_id": "root", "state": "HELD", "revoked": False,
                "parent_session_id": None}], "native_model_requests": [], "resource_limits": []}
        with patch.object(C, "physical_author", return_value={"attempt_id": "attempt", "pid": 123}):
            self.assertEqual(C.observation(base, {"task"}, {"w": {}}, "model")["real_root_agents"], 0)

            base["native_model_requests"] = [{"attempt_id": "attempt", "native_session_id": "root", "status": "ADMITTED", "model": "model"}]
            self.assertEqual(C.observation(base, {"task"}, {"w": {}}, "model")["real_root_agents"], 0)
            base["native_model_requests"][0].update(status="SETTLED", purpose="conversation", usage_complete=True,
                dispatched_at="2026-11-06T00:00:00Z", usage={"inputTokens":10,"outputTokens":2},
                transport={"outcome":"RESPONSE_BODY_COMPLETED","upstream_status":200,"received_bytes":100})
            observed=C.observation(base, {"task"}, {"w": {}}, "model")
            self.assertEqual(observed["real_root_agents"], 1)
            self.assertEqual(observed["activated_root_sessions"], [])
            with patch.object(C, "durable_author", return_value={"attempt_id":"attempt", "pid":123}):
                self.assertEqual(C.observation(base,{"task"},{"w":{}},"model")["activated_root_sessions"], [["attempt","root"]])
            base["native_child_lifecycles"][0]["parent_session_id"] = "parent"
            self.assertEqual(C.observation(base, {"task"}, {"w": {}}, "model")["real_root_agents"], 0)

    def test_provider_billing_requires_exact_population_and_does_not_release_custody(self):
        snapshot = {"source": "POSTGRESQL_AUTHORITY", "native_model_requests": [
            {"request_id": "one", "status": "SETTLED", "usage_complete": True},
            {"request_id": "two", "status": "SETTLED", "usage_complete": True}]}
        billing = {"schema_version": "forgeflow.provider-billing.v1", "campaign_id": "fresh", "source_response_sha256": "a" * 64,
            "requests": [{"request_id": "one", "provider_request_id": "p-one", "cost_usd": "0.01"},
                {"request_id": "two", "provider_request_id": "p-two", "cost_usd": "0.02"}], "total_cost_usd": "0.03"}
        result = B.reconcile(snapshot, billing, "fresh", 1, "a" * 64)
        self.assertEqual(result["observed_cost_usd"], "0.03")
        self.assertFalse(result["custody_changed"])
        self.assertEqual(result["g20"], "INCONCLUSIVE")
        billing["requests"].pop()
        with self.assertRaises(B.C.Blocked): B.reconcile(snapshot, billing, "fresh", 1, "a" * 64)

    def test_provider_billing_rejects_malformed_identity_and_money(self):
        snapshot = {"source": "POSTGRESQL_AUTHORITY", "native_model_requests": [
            {"request_id": "one", "status": "SETTLED", "usage_complete": True}]}
        base = {"schema_version": "forgeflow.provider-billing.v1", "campaign_id": "fresh",
            "source_response_sha256": "a" * 64,
            "requests": [{"request_id": "one", "provider_request_id": "p-one", "cost_usd": "0.01"}],
            "total_cost_usd": "0.01"}
        for mutate in (
            lambda b: b["requests"][0].update(request_id=True),
            lambda b: b["requests"][0].update(provider_request_id=42),
            lambda b: b["requests"][0].update(cost_usd="NaN"),
            lambda b: b.update(total_cost_usd="not-a-number"),
            lambda b: b.update(requests=[]),
            lambda b: b["requests"][0].pop("provider_request_id"),
            lambda b: b.update(requests=["not-an-object"]),
        ):
            billing = copy.deepcopy(base); mutate(billing)
            with self.assertRaises(B.C.Blocked): B.reconcile(snapshot, billing, "fresh", 1, "a" * 64)

    def test_provider_billing_requires_strict_authority_denominator(self):
        snapshot = {"source": "POSTGRESQL_AUTHORITY", "native_model_requests": [
            {"request_id": "one", "status": "SETTLED", "usage_complete": True}]}
        billing = {"schema_version": "forgeflow.provider-billing.v1", "campaign_id": "fresh",
            "source_response_sha256": "a" * 64,
            "requests": [{"request_id": "one", "provider_request_id": "p-one", "cost_usd": "0.01"}],
            "total_cost_usd": "0.01"}
        for mutate in (
            lambda s: s.update(native_model_requests="one"),
            lambda s: s.update(native_model_requests=["not-an-object"]),
            lambda s: s["native_model_requests"][0].update(request_id=True),
            lambda s: s["native_model_requests"][0].update(usage_complete="false"),
            lambda s: s["native_model_requests"][0].update(status="settled"),
            lambda s: s["native_model_requests"].append(copy.deepcopy(s["native_model_requests"][0])),
        ):
            authority = copy.deepcopy(snapshot); mutate(authority)
            with self.assertRaises(B.C.Blocked): B.reconcile(authority, billing, "fresh", 1, "a" * 64)
        with self.assertRaises(B.C.Blocked): B.reconcile(snapshot, billing, "fresh", 1, "A" * 64)
        with self.assertRaises(B.C.Blocked): B.reconcile(snapshot, billing, True, 1, "a" * 64)



if __name__ == "__main__": unittest.main()
