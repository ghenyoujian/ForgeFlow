#!/usr/bin/env python3
"""Capacity contract and real file activation in temporary fixtures only.

No running service, database, installed profile or model is contacted. These
checks do not qualify native Agent concurrency or product-card completion.
"""
import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest


SOURCE = Path(__file__).resolve().parents[1] / "ops/native-configuration.py"
MODULE_SPEC = importlib.util.spec_from_file_location("native_configuration", SOURCE)
N = importlib.util.module_from_spec(MODULE_SPEC)
MODULE_SPEC.loader.exec_module(N)


class CapacityContract(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="forgeflow-capacity-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.config = self.root / "delivery.json"
        self.base_resource = {"id": "base-resources", "sandbox": {
            "network_allowed": False, "readonly_paths": [str(self.root)]}}
        self.resource = copy.deepcopy(self.base_resource)
        self.resource["id"] = "published-resources"
        binary = self.root / "worker-fixture"
        binary.write_bytes(b"not an executable: activation must not launch this")
        publication = self.root / "publication-pin.json"
        publication.write_text("{}")
        self.profile = {"id": "published", "kind": "DSH_NATIVE",
                        "native_mode": {"mode_id": "fixture"}, "artifact_pins": [
                            {"path": str(publication), "sha256": N.sha(publication.read_bytes())}]}
        workers, policies = [], []
        credentials = self.root / "credentials.json"
        N.write(credentials, {"schema_version": "forgeflow.worker-credentials.v1", "workers": [
            {"worker_id": "existing", "project_id": "p", "token": "fixture-existing-token-123456789"}]})
        runtime = self.root / "runtime.json"
        N.write(runtime, {"FORGEFLOW_WORKER_CREDENTIALS_FILE": str(credentials)})
        for index in range(2):
            config = self.root / f"base-worker-{index}.json"
            N.write(config, {"max_active_attempts": 7, "sandbox": self.base_resource["sandbox"]})
            env = self.root / f"base-env-{index}.json"
            N.write(env, {"FORGEFLOW_WORKER_TOKEN": "fixture-source-token-123456789"})
            workers.append({"worker_id": f"base-{index}", "config": str(config), "env_file": str(env),
                            "executor_profile_id": "base", "resource_profile_id": "base-resources",
                            "worker_scope_id": f"scope-{index}", "max_active_attempts": 7})
            policies.append({"scope_id": f"scope-{index}", "worker_id": f"base-{index}",
                             "project_id": None, "team_id": None, "revision": 1,
                             "limits": {"active_slot": 128, "build_permit": 1, "gpu_permit": 1}})
        N.write(self.config, {"project_id": "p", "executor_profile_id": "base", "workers": workers,
                             "state_dir": str(self.root), "resource_profile_id": "base-resources",
                             "runtime_env": str(runtime), "recipe_publication_policy": {"auto_stages": {
                                 "author": {"executor_profile_id": "base"}}}})
        self.spec = {"base_executor_profile_id": "base", "presets": [
            {"id": "p1", "name": "One", "description": "", "persona_prefix": "Role", "clone_from": "p1"}],
            "plugins": [{"entry_id": "optional", "enabled": True, "config": {}}],
            "role_bindings": [{"position_id": "A00", "preset_id": "p1"}]}
        self.input = {"project_id": "p", "config_path": str(self.config),
                      "base_config_sha256": N.sha(self.config.read_bytes()),
                      "base_resource_profile": self.base_resource, "published_resource_profile": self.resource,
                      "resource_policies": policies, "published_profile": self.profile,
                      "worker_binary": str(binary), "worker_binary_sha256": N.sha(binary.read_bytes()),
                      "draft": {"draft_id": "capacity-test", "status": "PUBLISHED",
                                "base_config_sha256": N.sha(self.config.read_bytes()),
                                "spec": copy.deepcopy(self.spec), "spec_sha256": N.sha(N.canonical(self.spec)),
                                "published_executor_profile_id": "published",
                                "published_resource_profile_id": self.resource["id"],
                                "published_resource_profile_sha256": N.sha(N.canonical(self.resource))}}

    def baseline(self):
        source = copy.deepcopy(self.spec)
        source["max_active_attempts_per_worker"] = 7
        return ({}, {"id": "base"}, None, None, None, {}, source)

    def set_capacity(self, value):
        draft = self.input["draft"]
        draft["spec"]["max_active_attempts_per_worker"] = value
        draft["spec_sha256"] = N.sha(N.canonical(draft["spec"]))

    def test_legacy_spec_preserves_its_bytes_and_hash(self):
        before = N.canonical(self.input["draft"]["spec"])
        self.assertEqual(N.validate(self.input, self.baseline()), self.spec)
        self.assertEqual(N.canonical(self.input["draft"]["spec"]), before)

    def test_integer_capacity_bounds_and_type_confusion(self):
        for value in [1, 12, 64]:
            with self.subTest(valid=value):
                self.set_capacity(value)
                self.assertEqual(N.validate(self.input, self.baseline())["max_active_attempts_per_worker"], value)
        for value in [True, False, 0, -1, 65, 12.0, "12", None, [], {}]:
            with self.subTest(invalid=value):
                self.set_capacity(value)
                with self.assertRaisesRegex(N.Invalid, "WORKER_CAPACITY_INVALID"):
                    N.validate(self.input, self.baseline())
        self.input["draft"]["spec"]["unknown_capacity"] = 12
        with self.assertRaisesRegex(N.Invalid, "SPEC_INVALID"):
            N.validate(self.input, self.baseline())

    def test_context_capacity_reads_private_worker_configuration(self):
        cfg = json.loads(self.config.read_text())
        self.assertEqual(N.current_worker_capacity(cfg, "base"), 7)
        worker = cfg["workers"][1]
        actual = json.loads(Path(worker["config"]).read_text())
        actual["max_active_attempts"] = 6
        N.write(Path(worker["config"]), actual)
        with self.assertRaisesRegex(N.Invalid, "WORKER_CAPACITY_BINDING_CHANGED"):
            N.current_worker_capacity(cfg, "base")
        worker["max_active_attempts"] = 6
        self.assertEqual(N.current_worker_capacity(cfg, "base"), 6)

    def test_activation_updates_both_capacities_preserves_originals_and_replays(self):
        self.set_capacity(12)
        before = json.loads(self.config.read_text())
        original_bytes = {w["config"]: Path(w["config"]).read_bytes() for w in before["workers"]}
        receipt = N.activate(self.input)
        after = json.loads(self.config.read_text())
        self.assertEqual(after["workers"][:2], before["workers"])
        created = after["workers"][2:]
        self.assertEqual(len(created), 2)
        self.assertEqual(sum(w["max_active_attempts"] for w in created), 24)
        for worker in created:
            self.assertEqual(worker["max_active_attempts"], 12)
            self.assertEqual(json.loads(Path(worker["config"]).read_text())["max_active_attempts"], 12)
        for path, raw in original_bytes.items():
            self.assertEqual(Path(path).read_bytes(), raw)
        for index, policy in enumerate(receipt["resource_policies"]):
            self.assertEqual(policy["limits"], self.input["resource_policies"][index]["limits"])
        self.assertIs(receipt["execution_rights_granted"], False)
        self.assertEqual(receipt["model_calls"], 0)
        committed = self.config.read_bytes()
        self.assertEqual(N.activate(self.input), receipt)
        self.assertEqual(self.config.read_bytes(), committed)
        # A retry must detect private Worker capacity drift rather than repair it.
        worker_config = Path(created[0]["config"])
        changed = json.loads(worker_config.read_text())
        changed["max_active_attempts"] = 13
        N.write(worker_config, changed)
        with self.assertRaisesRegex(N.Invalid, "WORKER_CAPACITY_BINDING_CHANGED"):
            N.activate(self.input)

    def test_legacy_activation_retains_each_capacity(self):
        cfg = json.loads(self.config.read_text())
        worker = cfg["workers"][1]
        worker["max_active_attempts"] = 9
        actual = json.loads(Path(worker["config"]).read_text())
        actual["max_active_attempts"] = 9
        N.write(Path(worker["config"]), actual)
        N.write(self.config, cfg)
        updated_sha = N.sha(self.config.read_bytes())
        self.input["base_config_sha256"] = updated_sha
        self.input["draft"]["base_config_sha256"] = updated_sha
        N.activate(self.input)
        created = json.loads(self.config.read_text())["workers"][2:]
        self.assertEqual([w["max_active_attempts"] for w in created], [7, 9])
        self.assertEqual([json.loads(Path(w["config"]).read_text())["max_active_attempts"] for w in created], [7, 9])

    def test_invalid_activation_does_not_change_configuration(self):
        before = self.config.read_bytes()
        for value in [True, 0, 65, 12.0]:
            with self.subTest(value=value):
                self.set_capacity(value)
                with self.assertRaisesRegex(N.Invalid, "WORKER_CAPACITY_INVALID"):
                    N.activate(self.input)
                self.assertEqual(self.config.read_bytes(), before)


if __name__ == "__main__":
    unittest.main()
