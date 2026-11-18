import json
import tempfile
import unittest
from pathlib import Path
from argparse import Namespace

from rpo_rto_rehearsal import make_fixture, run


class RpoRtoRehearsalTests(unittest.TestCase):
    def test_default_is_fail_closed_without_side_effects(self):
        with tempfile.TemporaryDirectory() as temporary:
            report = run(Namespace(run=False, database_url=None, fixture_bytes=1024, max_fixture_bytes=1024, watermark_events=8, rto_threshold_seconds=30.0, timeout_seconds=5.0, private_root=Path(temporary), keep_private=False))
            self.assertEqual(report["status"], "NOT_RUN")
            self.assertEqual(report["denominator"]["not_run"], 1)
            self.assertEqual(list(Path(temporary).iterdir()), [])

    def test_fixture_generation_is_bounded_and_deterministic(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            size, rows = make_fixture(root, 4097)
            self.assertEqual(size, 4097)
            self.assertEqual(rows, 1)
            self.assertEqual((root / "data" / "fixture.bin").stat().st_size, 4097)

    def test_missing_database_url_is_blocked(self):
        report = run(Namespace(run=True, database_url=None, fixture_bytes=1024, max_fixture_bytes=1024, watermark_events=8, rto_threshold_seconds=30.0, timeout_seconds=5.0, private_root=Path(tempfile.gettempdir()), keep_private=False))
        self.assertEqual(report["status"], "BLOCKED")


if __name__ == "__main__":
    unittest.main()
