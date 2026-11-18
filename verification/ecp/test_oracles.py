from __future__ import annotations

import json
from pathlib import Path
import subprocess
import tempfile
import unittest

from independent_oracles import evaluate
from invariant_campaign import broken_snapshot, valid_snapshot
from native_qualification import check as check_native


class IndependentOracleTests(unittest.TestCase):
    def test_valid_snapshot_passes_all_declared_contracts(self) -> None:
        report = evaluate(valid_snapshot())
        self.assertEqual(report["status"], "PASS")
        self.assertEqual(report["denominator"]["failed"], 0)
        self.assertEqual(report["denominator"]["not_run"], 0)

    def test_broken_snapshot_is_not_silently_accepted(self) -> None:
        report = evaluate(broken_snapshot())
        self.assertEqual(report["status"], "FAIL")
        self.assertGreaterEqual(report["denominator"]["failed"], 1)

    def test_missing_snapshot_sections_remain_not_run(self) -> None:
        report = evaluate({})
        self.assertEqual(report["status"], "NOT_RUN")
        self.assertEqual(report["denominator"]["not_run"], 16)

    def test_native_manifest_rejects_unsafe_or_missing_evidence_refs(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            manifest = {
                "source_sha256": "0" * 40,
                "profile_sha256": "0" * 64,
                "evidence_class": "REAL_MODEL",
                "capabilities": [
                    {
                        "name": name,
                        "support": "SUPPORTED" if name == "native_team" else "UNKNOWN",
                        "evidence": "VERIFIED" if name == "native_team" else "NOT_RUN",
                        "evidence_refs": ["../outside.json"] if name == "native_team" else [],
                    }
                    for name in sorted({
                        "managed_leaf", "subagent", "native_team", "workflow", "bot",
                        "session_resume", "cancel", "structured_events", "child_supervision",
                        "write_isolation", "cost_enforcement",
                    })
                ],
            }
            (root / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
            report = check_native(root)
            self.assertEqual(report["status"], "INCONCLUSIVE")
            self.assertGreaterEqual(report["denominator"]["failed"], 1)

    def test_native_manifest_rejects_verified_unknown_capability(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            names = {
                "managed_leaf", "subagent", "native_team", "workflow", "bot",
                "session_resume", "cancel", "structured_events", "child_supervision",
                "write_isolation", "cost_enforcement",
            }
            manifest = {
                "schema_version": "forgeflow.ecp-native-evidence-manifest.v1",
                "source_sha256": "0" * 40,
                "profile_sha256": "0" * 64,
                "evidence_class": "REAL_MODEL",
                "provider": "CLAUDE",
                "qualification": "VERIFIED",
                "capabilities": [
                    {
                        "name": name,
                        "support": "UNKNOWN" if name == "native_team" else "NOT_RUN",
                        "evidence": "VERIFIED" if name == "native_team" else "NOT_RUN",
                        "evidence_refs": ["receipt.json"] if name == "native_team" else [],
                    }
                    for name in sorted(names)
                ],
            }
            (root / "receipt.json").write_text("{}", encoding="utf-8")
            (root / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
            report = check_native(root)
            self.assertGreaterEqual(report["denominator"]["failed"], 1)

    def test_native_manifest_rejects_stale_source_when_live_checkout_is_bound(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            names = {
                "managed_leaf", "subagent", "native_team", "workflow", "bot",
                "session_resume", "cancel", "structured_events", "child_supervision",
                "write_isolation", "cost_enforcement",
            }
            manifest = {
                "schema_version": "forgeflow.ecp-native-evidence-manifest.v1",
                "source_sha256": "0" * 40,
                "profile_sha256": "0" * 64,
                "evidence_class": "OFFLINE_DISCOVERY",
                "provider": "CLAUDE",
                "qualification": "NOT_RUN",
                "capabilities": [
                    {"name": name, "support": "UNKNOWN", "evidence": "NOT_RUN", "evidence_refs": []}
                    for name in sorted(names)
                ],
            }
            (root / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
            source_root = Path(__file__).resolve().parents[2]
            report = check_native(root, source_root=source_root)
            binding = next(item for item in report["checks"] if item["name"] == "manifest source snapshot matches live checkout")
            self.assertFalse(binding["passed"])
            self.assertEqual(report["status"], "INCONCLUSIVE")

    def test_native_manifest_can_bind_current_source_head(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            names = {
                "managed_leaf", "subagent", "native_team", "workflow", "bot",
                "session_resume", "cancel", "structured_events", "child_supervision",
                "write_isolation", "cost_enforcement",
            }
            source_root = Path(__file__).resolve().parents[2]
            head = subprocess.check_output(["git", "-C", str(source_root), "rev-parse", "HEAD"], text=True).strip()
            manifest = {
                "schema_version": "forgeflow.ecp-native-evidence-manifest.v1",
                "source_sha256": head,
                "profile_sha256": "0" * 64,
                "evidence_class": "OFFLINE_DISCOVERY",
                "provider": "CLAUDE",
                "qualification": "NOT_RUN",
                "capabilities": [
                    {"name": name, "support": "UNKNOWN", "evidence": "NOT_RUN", "evidence_refs": []}
                    for name in sorted(names)
                ],
            }
            (root / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
            report = check_native(root, source_root=source_root)
            binding = next(item for item in report["checks"] if item["name"] == "manifest source snapshot matches live checkout")
            self.assertTrue(binding["passed"])


if __name__ == "__main__":
    unittest.main()
