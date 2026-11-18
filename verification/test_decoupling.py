import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("project_pack", ROOT / "ops/project-pack.py")
PACK = importlib.util.module_from_spec(spec); spec.loader.exec_module(PACK)


class DecouplingTests(unittest.TestCase):
    def test_two_independent_projects_and_128_distinct_presets(self):
        for project in ("generic-alpha", "generic-beta"):
            mode, roster, patch = PACK.composition(project, 128, "provider", "model", "provider/model")
            self.assertEqual(roster["positions"], 128)
            self.assertEqual(len({r["preset_id"] for r in roster["roster"]}), 128)
            self.assertEqual(roster["project_id"], project)
            self.assertEqual(mode["role_catalog"]["planned_positions"], 128)
            self.assertEqual(roster["teams"][0]["planned_agents"], 128)
            self.assertEqual(mode["configured_limits"]["workflow_concurrent_agents"], 32)
            self.assertNotIn("splatforge", json.dumps([mode, roster, patch]).lower())

    def test_context_population_and_active_capacity_are_independent(self):
        for cap in (1,4,10,32,64):
            mode, roster, patch = PACK.composition("fresh", 128, "p", "m", "p/m", active_limit=cap)
            self.assertEqual(len(roster["roster"]),128)
            self.assertEqual(mode["runtime_capacity_policy"]["workflow_concurrent_agents"],cap)
            self.assertEqual(next(r for r in patch if r.get("id")=="workflow-ptc")["config"]["maxConcurrentAgents"],cap)
        for cap in (0,2,128,True):
            with self.assertRaises(ValueError): PACK.composition("fresh",128,"p","m","p/m",active_limit=cap)

    def test_zero_boolean_overlarge_and_duplicate_rosters_rejected(self):
        for n in (0, True, 10001):
            with self.assertRaises(ValueError): PACK.composition("fresh", n, "p", "m", "p/m")
        _, roster, _ = PACK.composition("fresh", 128, "p", "m", "p/m")
        duplicate = copy.deepcopy(roster); duplicate["roster"][-1] = duplicate["roster"][0]
        with self.assertRaises(ValueError): PACK.validate_roster(duplicate)
        with self.assertRaises(ValueError): PACK.composition("other", 128, "p", "m", "p/m", roster)

    def test_long_project_identity_keeps_unique_position_suffix(self):
        _, roster, _ = PACK.composition("a" * 128, 128, "p", "m", "p/m")
        self.assertEqual(len({r["preset_id"] for r in roster["roster"]}), 128)

    def test_materialized_pack_is_fresh_and_pinned(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "pack"
            manifest = PACK.materialize(path, "fresh", 128, "p", "m", "p/m")
            self.assertEqual(manifest["qualification"], "NOT_RUN")
            for name, digest in manifest["files"].items():
                import hashlib
                self.assertEqual(hashlib.sha256((path / name).read_bytes()).hexdigest(), digest)
            self.assertTrue((path / "team-binding.mjs").is_file())
            with self.assertRaises(FileExistsError): PACK.materialize(path, "fresh", 128, "p", "m", "p/m")

    def test_legacy_project_pack_keeps_original_roster_and_target(self):
        root = ROOT / "project-packs/splatforge"
        roster = json.loads((root / "presets/agent-roles.json").read_text())
        self.assertEqual(roster["positions"], 58)
        self.assertEqual(roster["delivery_target"]["cards"], 2884)
        self.assertEqual(len(roster["roster"]), 58)
        self.assertTrue(json.loads((root / "manifest.json").read_text())["opt_in_only"])


if __name__ == "__main__": unittest.main()
