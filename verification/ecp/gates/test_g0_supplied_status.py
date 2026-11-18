"""In-memory supplied-evidence tests; no subprocess, Git or database."""
import contextlib
import importlib.util
import io
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch


_spec = importlib.util.spec_from_file_location("candidate_g0", Path(__file__).with_name("g0.py"))
g0 = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(g0)


class SuppliedStatusTests(unittest.TestCase):
    def run_report(self, entries):
        # Entries represent pathname -> decoded JSON value or an exception;
        # None at the entry level represents a missing path, not JSON null.
        values = {name: value for name, exists, value in entries if exists}
        present = {name for name, exists, _ in entries if exists}
        argv = ["g0.py"]
        for name, _, _ in entries:
            argv += ["--evidence", name]
        argv += ["--output", "out.json"]
        def load(path):
            value = values[str(path)]
            if isinstance(value, BaseException):
                raise value
            return value
        output = io.StringIO()
        with patch.object(sys, "argv", argv), \
             patch.object(g0.Path, "exists", autospec=True, side_effect=lambda path: str(path) in present), \
             patch.object(g0, "load", side_effect=load), \
             patch.object(g0, "write_report_exclusive", autospec=True) as write, \
             contextlib.redirect_stdout(output):
            code = g0.main()
        self.assertEqual(write.call_count, 1)
        result = json.loads(write.call_args.args[2])
        self.assertEqual(json.loads(output.getvalue()), result)
        self.assertEqual(result["product_gate_effect"], "NONE")
        return code, result

    def test_reported_failure_and_missing_preserved_without_authentication(self):
        code, result = self.run_report([("failed", True, {"status": "FAIL"}), ("missing", False, None)])
        self.assertEqual(code, 10)
        self.assertEqual(result["status"], "FAIL")
        self.assertEqual(result["missing"], ["missing"])
        self.assertEqual(result["observed_statuses"], ["FAIL"])
        self.assertIn("not independently authenticated", result["reason"])

    def test_missing_without_reported_failure_is_blocked(self):
        code, result = self.run_report([("okay", True, {"status": "PASS"}), ("missing", False, None)])
        self.assertEqual((code, result["status"], result["missing"]), (20, "BLOCKED", ["missing"]))

    def test_empty_input_is_not_run(self):
        code, result = self.run_report([])
        self.assertEqual((code, result["status"]), (20, "NOT_RUN"))

    def test_only_pass_is_not_independent_qualification(self):
        code, result = self.run_report([("okay", True, {"status": "PASS"})])
        self.assertEqual((code, result["status"]), (20, "INCONCLUSIVE"))

    def test_json_non_objects_and_invalid_statuses_are_inconclusive(self):
        for value in (None, [], {}, {"status": []}, {"status": {}}, {"status": "OTHER"}):
            with self.subTest(value=value):
                code, result = self.run_report([("invalid", True, value)])
                self.assertEqual((code, result["status"]), (20, "INCONCLUSIVE"))
                self.assertEqual(result["invalid"][0]["path"], "invalid")

    def test_malformed_json_retains_local_failure_not_a_failure_claim(self):
        code, result = self.run_report([("bad", True, ValueError("malformed JSON"))])
        self.assertEqual((code, result["status"]), (10, "FAIL"))
        self.assertIn("local evidence read or JSON parse failed", result["reason"])
        self.assertEqual(result["invalid"], [{"path": "bad", "reason": "ValueError"}])

    def test_read_error_and_missing_preserve_local_failure(self):
        code, result = self.run_report([("bad", True, OSError("unavailable")), ("missing", False, None)])
        self.assertEqual((code, result["status"]), (10, "FAIL"))
        self.assertEqual(result["missing"], ["missing"])
        self.assertEqual(result["invalid"][0]["path"], "bad")

    def test_failure_claim_dominates_invalid_and_missing(self):
        code, result = self.run_report([("bad", True, {"status": []}), ("failed", True, {"status": "FAIL"}), ("missing", False, None)])
        self.assertEqual((code, result["status"]), (10, "FAIL"))
        self.assertEqual(result["missing"], ["missing"])
        self.assertEqual(result["invalid"][0]["path"], "bad")
        self.assertEqual(result["observed_statuses"], [[], "FAIL"])

    def test_unresolved_valid_status_is_inconclusive(self):
        for status in ("BLOCKED", "NOT_RUN", "INCONCLUSIVE"):
            with self.subTest(status=status):
                code, result = self.run_report([("pending", True, {"status": status})])
                self.assertEqual((code, result["status"]), (20, "INCONCLUSIVE"))


if __name__ == "__main__":
    unittest.main()
