from __future__ import annotations

import unittest
from pathlib import Path
import json
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "ops" / "ecp"))
import verify
ENTRY = ROOT / "ops" / "ecp" / "verify"


class P003ContractTests(unittest.TestCase):
    def test_nonzero_denominator_passes(self) -> None:
        status, counts, reason = verify.parse_unittest_denominator(
            "...\nRan 3 tests in 0.01s\n\nOK\n", "", 0
        )
        self.assertEqual(status, "PASS")
        self.assertEqual(counts["total"], 3)
        self.assertEqual(counts["passed"], 3)
        self.assertIn("nonzero", reason)

    def test_all_skipped_is_failure(self) -> None:
        status, counts, reason = verify.parse_unittest_denominator(
            "Ran 2 tests in 0.01s\nOK (skipped=2)\n", "", 0
        )
        self.assertEqual(status, "FAIL")
        self.assertEqual(counts["skipped"], 2)
        self.assertIn("skipped", reason)

    def test_missing_denominator_is_failure(self) -> None:
        status, counts, reason = verify.parse_unittest_denominator("", "worker crashed", 1)
        self.assertEqual(status, "FAIL")
        self.assertEqual(counts["total"], 0)
        self.assertEqual(counts["not_run"], 0)
        self.assertIn("no unittest denominator", reason)

    def test_original_test_failure_remains_failure(self) -> None:
        status, counts, reason = verify.parse_unittest_denominator(
            "Ran 2 tests in 0.01s\nFAILED (failures=1)\n", "", 1
        )
        self.assertEqual(status, "FAIL")
        self.assertEqual(counts["failures"], 1)
        self.assertEqual(counts["inconclusive"], 2)
        self.assertIn("original unittest failures", reason)

    def test_truncated_or_contradictory_summary_never_passes(self) -> None:
        for result in ("", "FAILED\n", "OK (expected failures=1)\n", "OK (skipped=4)\n"):
            with self.subTest(result=result):
                status, counts, _ = verify.parse_unittest_denominator(
                    "", "Ran 3 tests in 0.001s\n" + result, 0
                )
                self.assertNotEqual(status, "PASS")
                self.assertLess(counts["passed"], counts["total"])

    def test_real_unittest_process_output_and_partial_execution(self) -> None:
        script = '''import unittest
class Cases(unittest.TestCase):
    def test_ok(self): pass
    @unittest.skip("not available")
    def test_skip(self): pass
    @unittest.expectedFailure
    def test_expected_failure(self): self.fail("expected")
unittest.main(verbosity=2)
'''
        process = subprocess.run([sys.executable, "-c", script], text=True, capture_output=True, check=False)
        self.assertEqual(process.returncode, 0)
        status, counts, _ = verify.parse_unittest_denominator(process.stdout, process.stderr, process.returncode)
        self.assertEqual(status, "INCONCLUSIVE")
        self.assertEqual((counts["total"], counts["passed"], counts["skipped"], counts["inconclusive"]),
                         (3, 0, 1, 3))

    def test_ambiguous_and_oversized_denominators_fail_closed(self) -> None:
        for stdout, stderr in (("Ran 1 test in 0.01s\nOK\n", "Ran 1 test in 0.01s\nOK\n"),
                               ("", "Ran " + "9" * 5000 + " tests in 0.01s\nOK\n"),
                               ("", "Ran 1 test in 0.01s\nOK (skipped=" + "9" * 5000 + ")\n")):
            with self.subTest(stdout=stdout[:40], stderr=stderr[:40]):
                status, counts, _ = verify.parse_unittest_denominator(stdout, stderr, 0)
                self.assertNotEqual(status, "PASS")
                self.assertEqual(counts["passed"], 0)

    def test_real_subtest_and_setup_errors_preserve_event_counts(self) -> None:
        scripts = (
            ('''import unittest
class Cases(unittest.TestCase):
    def test_subtests(self):
        for i in range(3):
            with self.subTest(i=i): self.fail(str(i))
unittest.main(verbosity=2)
''', 1, 3, 0),
            ('''import unittest
class Cases(unittest.TestCase):
    @classmethod
    def setUpClass(cls): raise RuntimeError("setup failed")
    def test_unreached(self): pass
unittest.main(verbosity=2)
''', 0, 0, 1),
        )
        for script, total, failures, errors in scripts:
            with self.subTest(total=total):
                process = subprocess.run([sys.executable, "-c", script], text=True,
                                         capture_output=True, check=False)
                self.assertNotEqual(process.returncode, 0)
                status, counts, _ = verify.parse_unittest_denominator(process.stdout, process.stderr,
                                                                      process.returncode)
                self.assertEqual(status, "FAIL")
                self.assertEqual((counts["total"], counts["failures"], counts["errors"]),
                                 (total, failures, errors))
                self.assertEqual(counts["passed"], 0)
                self.assertEqual(counts["inconclusive"], total)

    def test_real_skipped_subtests_are_preserved_as_events(self) -> None:
        script = '''import unittest
class Cases(unittest.TestCase):
    def test_subtests(self):
        for i in range(3):
            with self.subTest(i=i): self.skipTest(str(i))
unittest.main(verbosity=2)
'''
        process = subprocess.run([sys.executable, "-c", script], text=True, capture_output=True, check=False)
        self.assertEqual(process.returncode, 0)
        status, counts, _ = verify.parse_unittest_denominator(process.stdout, process.stderr, process.returncode)
        self.assertNotEqual(status, "PASS")
        self.assertEqual((counts["total"], counts["skipped"], counts["passed"], counts["inconclusive"]),
                         (1, 3, 0, 1))

    def test_unknown_suite_fails_closed(self) -> None:
        completed = subprocess.run(
            [str(ENTRY), "--suite", "ECP-P0-UNKNOWN", "--profile", "isolated"],
            cwd=ROOT, text=True, capture_output=True, check=False,
        )
        value = json.loads(completed.stdout)
        self.assertEqual(completed.returncode, 20)
        self.assertEqual(value["status"], "BLOCKED")
        self.assertEqual(value["checks"][0]["name"], "suite_registry")


if __name__ == "__main__":
    unittest.main()
