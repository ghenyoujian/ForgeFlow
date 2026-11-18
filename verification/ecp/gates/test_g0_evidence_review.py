"""Synthetic integrity cases only: these fixtures do not qualify a product Gate."""
import copy
import hashlib
import importlib.util
import json
import os
import shlex
import subprocess
import tempfile
import unittest
from unittest.mock import patch
from pathlib import Path

SPEC = importlib.util.spec_from_file_location("g0_evidence_review", Path(__file__).with_name("g0_evidence_review.py"))
m = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(m)


def digest(data):
    return hashlib.sha256(data).hexdigest()


class IntegrityReviewTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.source = self.base / "source"
        self.source.mkdir()
        subprocess.run(["git", "init", "-q", str(self.source)], check=True)
        (self.source / "source.txt").write_text("synthetic\n")
        subprocess.run(["git", "-C", str(self.source), "add", "source.txt"], check=True)
        subprocess.run(["git", "-C", str(self.source), "-c", "user.name=test", "-c", "user.email=test@example.invalid", "commit", "-qm", "fixture"], check=True)
        self.sha = subprocess.check_output(["git", "-C", str(self.source), "rev-parse", "HEAD"], text=True).strip()
        self.evidence = self.base / "evidence"
        self.evidence.mkdir()
        suites, runs = [], []
        for sid in sorted(m.SUITES):
            suites.append({"suite_id": sid, "case_ids": ["one", "two"]})
            logs = {}
            for kind in ("stdout", "stderr"):
                path = f"{sid}-{kind}.log"
                content = f"synthetic {sid} {kind}\n".encode()
                (self.evidence / path).write_bytes(content)
                logs[kind] = {"path": path, "sha256": digest(content)}
            runs.append({"suite_id": sid, "cases": [{"case_id": "one", "status": "PASS"}, {"case_id": "two", "status": "PASS"}],
                         "denominator": {"total": 2, "PASS": 2, "FAIL": 0, "BLOCKED": 0, "NOT_RUN": 0, "INCONCLUSIVE": 0, "SKIPPED": 0}, "exit_code": 0, "logs": logs})
        self.plan = {"schema_version": "forgeflow.ecp-g0-review-plan.v1", "source_sha": self.sha, "suites": suites}
        self.receipt = {"schema_version": "forgeflow.ecp-g0-review-input.v1", "run_id": "fixture-only", "source_sha": self.sha, "plan_sha256": "", "suites": runs}
        self.save()

    def save(self):
        plan = json.dumps(self.plan, sort_keys=True).encode()
        (self.evidence / "plan.json").write_bytes(plan)
        self.plan_hash = digest(plan)
        self.receipt["plan_sha256"] = self.plan_hash
        self.save_receipt()

    def save_receipt(self):
        (self.evidence / "receipt.json").write_text(json.dumps(self.receipt))

    def review(self):
        return m.review(self.source, self.evidence, "plan.json", self.plan_hash, "receipt.json")

    def rejects(self, message=None):
        with self.assertRaises(m.Invalid if message else (m.Invalid, OSError)) as ctx:
            self.review()
        if message:
            self.assertIn(message, str(ctx.exception))

    def test_fabricated_green_never_becomes_gate(self):
        result = self.review()
        self.assertEqual(result["status"], "INCONCLUSIVE")
        self.assertEqual(result["product_gate_effect"], "NONE")
        self.assertIn("cannot authenticate execution", result["reason"])

    def test_missing_and_duplicate_suite(self):
        self.receipt["suites"].pop()
        self.save_receipt()
        self.rejects("missing required")
        self.receipt["suites"].append(copy.deepcopy(self.receipt["suites"][0]))
        self.save_receipt()
        self.rejects("duplicate")

    def test_missing_duplicate_and_extra_case(self):
        for cases in ([{"case_id":"one", "status":"PASS"}], [{"case_id":"one", "status":"PASS"}] * 2,
                      [{"case_id":"one", "status":"PASS"}, {"case_id":"extra", "status":"PASS"}]):
            with self.subTest(cases=cases):
                self.receipt["suites"][0]["cases"] = cases
                self.save_receipt()
                self.rejects()

    def test_plan_missing_duplicate_suite_or_case(self):
        original = copy.deepcopy(self.plan)
        for mutation in ("missing", "duplicate", "zero", "dup_case"):
            with self.subTest(mutation=mutation):
                self.plan = copy.deepcopy(original)
                if mutation == "missing": self.plan["suites"].pop()
                elif mutation == "duplicate": self.plan["suites"][-1] = copy.deepcopy(self.plan["suites"][0])
                elif mutation == "zero": self.plan["suites"][0]["case_ids"] = []
                else: self.plan["suites"][0]["case_ids"] = ["one", "one"]
                self.save()
                self.rejects()

    def test_inconsistent_counts_and_invalid_numbers(self):
        for value in (3, -1, True, 2.0):
            with self.subTest(value=value):
                self.receipt["suites"][0]["denominator"]["total"] = value
                self.save_receipt()
                self.rejects()

    def test_nonpass_and_nonzero_exit(self):
        for status in m.STATUSES[1:]:
            with self.subTest(status=status):
                run = self.receipt["suites"][0]
                run["cases"][0]["status"] = status
                run["denominator"]["PASS"] = 1
                run["denominator"][status] = 1
                self.save_receipt()
                report = self.review()
                self.assertEqual(report["status"], "FAIL" if status == "FAIL" else "INCONCLUSIVE")
                self.assertEqual(report["suite_counts"][run["suite_id"]]["denominator"][status], 1)
                self.assertEqual(report["product_gate_effect"], "NONE")
                run["denominator"][status] = 0
        self.receipt["suites"][0]["cases"][0]["status"] = "PASS"
        self.receipt["suites"][0]["denominator"]["PASS"] = 2
        self.receipt["suites"][0]["exit_code"] = 1
        self.save_receipt()
        self.rejects("nonzero exit")

    def test_wrong_or_dirty_source(self):
        self.receipt["source_sha"] = "0" * 40
        self.save_receipt()
        self.rejects("source SHA mismatch")
        self.receipt["source_sha"] = self.sha
        self.save_receipt()
        (self.source / "source.txt").write_text("mutated\n")
        self.rejects("dirty")

    def test_git_environment_cannot_redirect_source(self):
        with patch.dict(os.environ, {"GIT_DIR": "/does-not-exist", "GIT_WORK_TREE": "/does-not-exist"}):
            self.assertEqual(self.review()["source_sha"], self.sha)

    def test_caller_path_git_is_not_executed(self):
        fake_dir = self.base / "fake-bin"
        fake_dir.mkdir()
        marker = self.base / "path-git-ran"
        fake = fake_dir / "git"
        fake.write_text("#!/bin/sh\nprintf called > \"$CANARY_MARKER\"\nexit 1\n")
        fake.chmod(0o755)
        with patch.dict(os.environ, {"PATH": str(fake_dir), "CANARY_MARKER": str(marker)}):
            self.assertEqual(self.review()["status"], "INCONCLUSIVE")
        self.assertFalse(marker.exists())

    def test_untrusted_git_clean_filter_is_not_executed(self):
        attributes = self.source / ".gitattributes"
        attributes.write_text("source.txt filter=review-canary\n")
        subprocess.run(["git", "-C", str(self.source), "add", ".gitattributes"], check=True)
        subprocess.run(["git", "-C", str(self.source), "-c", "user.name=test", "-c", "user.email=test@example.invalid", "commit", "-qm", "add attributes"], check=True)
        marker = self.base / "clean-filter-ran"
        script = self.base / "filter-canary"
        script.write_text("#!/bin/sh\nprintf called > " + shlex.quote(str(marker)) + "\ncat\n")
        script.chmod(0o755)
        subprocess.run(["git", "-C", str(self.source), "config", "filter.review-canary.clean", str(script)], check=True)
        tracked = self.source / "source.txt"
        info = tracked.stat()
        os.utime(tracked, ns=(info.st_atime_ns, info.st_mtime_ns + 2_000_000_000))
        expected_sha = subprocess.check_output(["git", "-C", str(self.source), "rev-parse", "HEAD"], text=True).strip()
        subprocess.run(["/usr/bin/git", "-C", str(self.source), "status", "--porcelain=v1"], capture_output=True, check=True)
        self.assertTrue(marker.exists(), "positive control must run the clean filter")
        marker.unlink()
        self.assertEqual(m.actual_source(self.source), expected_sha)
        self.assertFalse(marker.exists())

    def test_tracked_changes_are_checked_even_for_default_excluded_names(self):
        tracked = self.source / "notes.log"
        tracked.write_text("original\n")
        subprocess.run(["git", "-C", str(self.source), "add", "-f", "notes.log"], check=True)
        subprocess.run(["git", "-C", str(self.source), "-c", "user.name=test", "-c", "user.email=test@example.invalid", "commit", "-qm", "add log"], check=True)
        tracked.write_text("modified\n")
        with self.assertRaises((m.Invalid, OSError)):
            m.actual_source(self.source)

    def test_nonignored_untracked_default_excluded_name_is_rejected(self):
        (self.source / ".env").write_text("synthetic value\n")
        self.rejects("dirty")

    def _commit_fixture(self, *paths):
        subprocess.run(["git", "-C", str(self.source), "add", "-f", "--", *paths], check=True)
        subprocess.run(["git", "-C", str(self.source), "-c", "user.name=test", "-c",
                        "user.email=test@example.invalid", "commit", "-qm", "synthetic fixture"], check=True)
        self.sha = subprocess.check_output(["git", "-C", str(self.source), "rev-parse", "HEAD"], text=True).strip()
        self.plan["source_sha"] = self.sha
        self.receipt["source_sha"] = self.sha
        self.save()

    def test_tracked_evidence_file_is_checked_in_full_source_review(self):
        tracked = self.source / "evidence" / "fixture.txt"
        tracked.parent.mkdir()
        tracked.write_bytes(b"synthetic tracked evidence\n")
        self._commit_fixture("evidence/fixture.txt")
        self.assertEqual(m.actual_source(self.source), self.sha)
        self.assertEqual(self.review()["status"], "INCONCLUSIVE")
        tracked.write_bytes(b"synthetic changed evidence\n")
        with self.assertRaises(m.Invalid):
            m.actual_source(self.source)

    def test_untracked_and_ignored_evidence_directories_are_rejected(self):
        ignore = self.source / ".gitignore"
        ignore.write_text("evidence/\n", encoding="utf-8")
        self._commit_fixture(".gitignore")
        directory = self.source / "evidence" / "nested"
        directory.mkdir(parents=True)
        (directory / "untracked.txt").write_bytes(b"synthetic untracked\n")
        with self.assertRaises(m.Invalid):
            m.actual_source(self.source)

    def test_tracked_evidence_symlink_is_checked_without_following_target(self):
        link = self.source / "evidence" / "link"
        link.parent.mkdir()
        link.symlink_to("../source.txt")
        self._commit_fixture("evidence/link")
        self.assertEqual(m.actual_source(self.source), self.sha)
        link.unlink()
        link.symlink_to("../../outside")
        with self.assertRaises(m.Invalid):
            m.actual_source(self.source)

    def test_tracked_evidence_dirty_cli_is_structured(self):
        tracked = self.source / "evidence" / "fixture.txt"
        tracked.parent.mkdir()
        tracked.write_bytes(b"synthetic tracked evidence\n")
        self._commit_fixture("evidence/fixture.txt")
        tracked.write_bytes(b"synthetic changed evidence\n")
        proc = subprocess.run(["/usr/bin/python3", "-B", str(Path(m.__file__)), "--source", str(self.source),
            "--evidence-root", str(self.evidence), "--plan", "plan.json", "--plan-sha256", self.plan_hash,
            "--receipt", "receipt.json"], capture_output=True, text=True, check=False)
        self.assertEqual(proc.returncode, 10, proc.stderr)
        result = json.loads(proc.stdout)
        self.assertEqual((result["status"], result["product_gate_effect"]), ("FAIL", "NONE"))
        self.assertNotIn("Traceback", proc.stderr)

    def test_tracked_private_root_env_is_rejected_before_content_or_target_read(self):
        for kind in ("file", "symlink"):
            with self.subTest(kind=kind):
                env = self.source / ".env"
                if kind == "file":
                    env.write_bytes(b"synthetic private fixture\n")
                else:
                    env.symlink_to("source.txt")
                self._commit_fixture(".env")
                original_open, original_readlink = os.open, os.readlink
                def guarded_open(path, *args, **kwargs):
                    if os.fsdecode(path) in (".env", str(env)):
                        raise AssertionError("private fixture must not be opened")
                    return original_open(path, *args, **kwargs)
                def guarded_readlink(path, *args, **kwargs):
                    if os.fsdecode(path) in (".env", str(env)):
                        raise AssertionError("private symlink target must not be read")
                    return original_readlink(path, *args, **kwargs)
                try:
                    with patch.object(os, "open", side_effect=guarded_open), \
                         patch.object(os, "readlink", side_effect=guarded_readlink):
                        with self.assertRaises(m.Incomplete):
                            m.actual_source(self.source)
                finally:
                    env.unlink()
                    subprocess.run(["git", "-C", str(self.source), "rm", "-q", "--cached", "--", ".env"], check=True)

    def test_tracked_env_directory_is_business_not_private_file(self):
        child = self.source / ".env" / "fixture.txt"
        child.parent.mkdir()
        child.write_bytes(b"synthetic business fixture\n")
        self._commit_fixture(".env/fixture.txt")
        self.assertEqual(m.actual_source(self.source), self.sha)
        child.write_bytes(b"synthetic modified business fixture\n")
        with self.assertRaises(m.Invalid):
            m.actual_source(self.source)

    def test_incomplete_index_signatures_are_structured_incomplete(self):
        tool = m.source_snapshot_tool()
        for value in ({}, {"source.txt": (1, 2)}):
            with self.subTest(value=value), \
                 patch.object(tool, "_v3_verify_index_bytes", return_value=value), \
                 patch.object(m, "source_snapshot_tool", return_value=tool):
                with self.assertRaises(m.Incomplete):
                    m.actual_source(self.source)

    def test_projection_must_bind_only_the_explicit_git_boundary(self):
        for mutation in ("unexpected_boundary", "missing_git_boundary", "policy_digest"):
            with self.subTest(mutation=mutation):
                tool = m.source_snapshot_tool()
                real_scan = tool._v3_scan_projection
                def tamper(*args, **kwargs):
                    projection, observed = real_scan(*args, **kwargs)
                    projection = copy.deepcopy(projection)
                    if mutation == "unexpected_boundary":
                        projection["excluded_directory_boundaries"].append(
                            {"path": "evidence", "kind": "directory", "excluded_by": "evidence/"})
                    elif mutation == "missing_git_boundary":
                        projection["excluded_directory_boundaries"] = []
                    else:
                        projection["exclusion_policy_sha256"] = "0" * 64
                    return projection, observed
                with patch.object(tool, "_v3_scan_projection", side_effect=tamper), \
                     patch.object(m, "source_snapshot_tool", return_value=tool):
                    with self.assertRaises(m.Incomplete):
                        m.actual_source(self.source)

    def test_malformed_projection_or_observation_is_structured_incomplete(self):
        mutations = ("missing_directories", "directories_wrong_type", "directory_missing_origin",
                     "missing_files", "files_wrong_type", "invalid_file_signature", "second_missing_files")
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                tool = m.source_snapshot_tool()
                real_scan = tool._v3_scan_projection
                calls = 0
                def tamper(*args, **kwargs):
                    nonlocal calls
                    calls += 1
                    projection, observed = real_scan(*args, **kwargs)
                    projection, observed = copy.deepcopy(projection), copy.deepcopy(observed)
                    if mutation == "second_missing_files":
                        if calls == 2:
                            del observed["files"]
                    elif mutation == "missing_directories":
                        del projection["directories"]
                    elif mutation == "directories_wrong_type":
                        projection["directories"] = None
                    elif mutation == "directory_missing_origin":
                        del projection["directories"][0]["origin"]
                    elif mutation == "missing_files":
                        del observed["files"]
                    elif mutation == "files_wrong_type":
                        observed["files"] = []
                    else:
                        observed["files"]["source.txt"] = (1, 2)
                    return projection, observed
                with patch.object(tool, "_v3_scan_projection", side_effect=tamper), \
                     patch.object(m, "source_snapshot_tool", return_value=tool):
                    with self.assertRaises(m.Incomplete):
                        m.actual_source(self.source)

    def _actual_with_projection_mutation(self, source, mutation):
        tool = m.source_snapshot_tool()
        real_scan = tool._v3_scan_projection
        def tamper(*args, **kwargs):
            projection, observed = real_scan(*args, **kwargs)
            projection, observed = copy.deepcopy(projection), copy.deepcopy(observed)
            mutation(projection, observed)
            return projection, observed
        with patch.object(tool, "_v3_scan_projection", side_effect=tamper), \
             patch.object(m, "source_snapshot_tool", return_value=tool):
            return m.actual_source(source)

    def test_untracked_empty_directory_origin_cannot_be_laundered(self):
        rogue = self.source / "rogue"
        rogue.mkdir()
        for origin in ("git_ancestor", "excluded_container"):
            with self.subTest(origin=origin):
                def mutate(projection, observed):
                    matches = [row for row in projection["directories"] if row["path"] == "rogue"]
                    self.assertEqual([row["origin"] for row in matches], ["untracked_business"])
                    matches[0]["origin"] = origin
                with self.assertRaises(m.Invalid) as caught:
                    self._actual_with_projection_mutation(self.source, mutate)
                self.assertIs(type(caught.exception), m.Invalid)

    def test_untracked_directory_under_tracked_ancestor_cannot_be_laundered(self):
        tracked = self.source / "tracked" / "file.txt"
        tracked.parent.mkdir()
        tracked.write_bytes(b"synthetic tracked fixture\n")
        self._commit_fixture("tracked/file.txt")
        (tracked.parent / "empty").mkdir()
        def mutate(projection, observed):
            matches = [row for row in projection["directories"] if row["path"] == "tracked/empty"]
            self.assertEqual([row["origin"] for row in matches], ["untracked_business"])
            matches[0]["origin"] = "git_ancestor"
        with self.assertRaises(m.Invalid) as caught:
            self._actual_with_projection_mutation(self.source, mutate)
        self.assertIs(type(caught.exception), m.Invalid)

    def test_linked_worktree_marker_does_not_hide_untracked_directory(self):
        linked = self.base / "linked-origin-test"
        subprocess.run(["git", "-C", str(self.source), "worktree", "add", "--detach", "-q", str(linked)], check=True)
        self.assertTrue((linked / ".git").is_file())
        self.assertEqual(m.actual_source(linked), self.sha)
        (linked / "rogue").mkdir()
        def mutate(projection, observed):
            matches = [row for row in projection["directories"] if row["path"] == "rogue"]
            self.assertEqual([row["origin"] for row in matches], ["untracked_business"])
            matches[0]["origin"] = "excluded_container"
        with self.assertRaises(m.Invalid) as caught:
            self._actual_with_projection_mutation(linked, mutate)
        self.assertIs(type(caught.exception), m.Invalid)

    def test_missing_tracked_ancestor_is_incomplete_even_when_reports_agree(self):
        tracked = self.source / "tracked" / "file.txt"
        tracked.parent.mkdir()
        tracked.write_bytes(b"synthetic tracked fixture\n")
        self._commit_fixture("tracked/file.txt")
        def mutate(projection, observed):
            self.assertIn("tracked", observed["directories"])
            projection["directories"] = [row for row in projection["directories"] if row["path"] != "tracked"]
            del observed["directories"]["tracked"]
        with self.assertRaises(m.Incomplete) as caught:
            self._actual_with_projection_mutation(self.source, mutate)
        self.assertIs(type(caught.exception), m.Incomplete)

    def test_index_parent_derivation_is_bounded_and_deadlined(self):
        deadline = m.time.monotonic() + 10
        self.assertEqual(m._g0_index_parent_directories({"root.txt": None, "a/b/c.txt": None}, deadline),
                         {".", "a", "a/b"})
        for index, limit_name, limit in (({"a/b/c.txt": None}, "MAX_G0_INDEX_DEPTH", 2),
                                         ({"a/b": None, "c/d": None}, "MAX_G0_INDEX_DIRS", 2),
                                         ({"a/b": None, "c/d": None}, "MAX_G0_INDEX_DIR_BYTES", 600)):
            with self.subTest(limit=limit_name), patch.object(m, limit_name, limit):
                with self.assertRaises(m.Incomplete):
                    m._g0_index_parent_directories(index, deadline)
        with self.assertRaises(m.Incomplete):
            m._g0_index_parent_directories({"root.txt": None}, m.time.monotonic() - 1)
        for invalid in ("a//b", "a/../b", "invalid\npath", "\ud800"):
            with self.subTest(invalid=repr(invalid)):
                with self.assertRaises(m.Incomplete):
                    m._g0_index_parent_directories({invalid: None}, deadline)

    def test_linked_git_marker_is_allowed_but_git_symlink_rejected(self):
        linked = self.base / "linked-worktree"
        subprocess.run(["git", "-C", str(self.source), "worktree", "add", "--detach", "-q", str(linked)], check=True)
        self.assertTrue((linked / ".git").is_file())
        self.assertEqual(m.actual_source(linked), self.sha)
        for kind in ("symlink", "fifo"):
            with self.subTest(kind=kind):
                git_dir = self.source / ".git"
                moved = self.base / "outside-git"
                git_dir.rename(moved)
                if kind == "symlink":
                    git_dir.symlink_to(moved, target_is_directory=True)
                else:
                    os.mkfifo(git_dir)
                try:
                    with patch.object(m, "source_snapshot_tool", side_effect=AssertionError("Git helper must not be loaded")):
                        with self.assertRaises(m.Invalid):
                            m.actual_source(self.source)
                finally:
                    git_dir.unlink()
                    moved.rename(git_dir)

    def test_gitignored_untracked_business_input_is_rejected(self):
        ignore = self.source / ".gitignore"
        ignore.write_text("generated.py\n")
        subprocess.run(["git", "-C", str(self.source), "add", ".gitignore"], check=True)
        subprocess.run(["git", "-C", str(self.source), "-c", "user.name=test", "-c", "user.email=test@example.invalid", "commit", "-qm", "ignore fixture"], check=True)
        (self.source / "generated.py").write_text("value = 1\n")
        with self.assertRaises(m.Invalid):
            m.actual_source(self.source)

    def test_changed_helper_is_rejected_before_execution(self):
        helper = self.base / "fake-helper.py"
        marker = self.base / "helper-ran"
        helper.write_text("from pathlib import Path\nPath(" + repr(str(marker)) + ").write_text('called')\n")
        with patch.object(m, "SOURCE_SNAPSHOT_TOOL", helper):
            with self.assertRaises(m.Incomplete):
                m.source_snapshot_tool()
        self.assertFalse(marker.exists())

    def test_executable_blob_requires_owner_executable_permission(self):
        tracked = self.source / "executable"
        tracked.write_text("#!/bin/sh\nexit 0\n")
        tracked.chmod(0o755)
        subprocess.run(["git", "-C", str(self.source), "add", "executable"], check=True)
        subprocess.run(["git", "-C", str(self.source), "-c", "user.name=test", "-c", "user.email=test@example.invalid", "commit", "-qm", "add executable"], check=True)
        for mode in (0o654, 0o645, 0o611):
            with self.subTest(mode=oct(mode)):
                tracked.chmod(mode)
                with self.assertRaises(m.Invalid):
                    m.actual_source(self.source)

    def test_unknown_git_termination_is_not_reported_as_failure_or_success(self):
        tool = m.source_snapshot_tool()
        with patch.object(tool, "_v3_head_index", side_effect=RuntimeError("termination unknown")), \
             patch.object(m, "source_snapshot_tool", return_value=tool):
            with self.assertRaises(m.Incomplete):
                m.actual_source(self.source)

    def test_capture_limit_is_inconclusive(self):
        tool = m.source_snapshot_tool()
        with patch.object(tool, "_v3_head_index", side_effect=ValueError("v3 Git output exceeds bounded stream budget")), \
             patch.object(m, "source_snapshot_tool", return_value=tool):
            with self.assertRaises(m.Incomplete):
                m.actual_source(self.source)

    def test_unavailable_source_root_is_inconclusive_on_cli(self):
        proc = subprocess.run(["/usr/bin/python3", "-B", str(Path(m.__file__)), "--source", str(self.base / "missing"),
            "--evidence-root", str(self.evidence), "--plan", "plan.json", "--plan-sha256", self.plan_hash,
            "--receipt", "receipt.json"], capture_output=True, text=True, check=False)
        self.assertEqual(proc.returncode, 20)
        self.assertEqual(json.loads(proc.stdout)["status"], "INCONCLUSIVE")

    def test_nonignored_excluded_file_created_mid_observation_is_not_lost(self):
        tool = m.source_snapshot_tool()
        real_scan = tool._v3_scan_projection
        created = False
        def add_after_first_scan(*args, **kwargs):
            nonlocal created
            result = real_scan(*args, **kwargs)
            if not created:
                (self.source / ".env").write_text("synthetic\n")
                created = True
            return result
        with patch.object(tool, "_v3_scan_projection", side_effect=add_after_first_scan), \
             patch.object(m, "source_snapshot_tool", return_value=tool):
            with self.assertRaises(m.Incomplete):
                m.actual_source(self.source)
        self.assertTrue(created)

    def test_git_worktree_must_match_pinned_source_root(self):
        other = self.base / "other-worktree"
        other.mkdir()
        subprocess.run(["git", "-C", str(self.source), "config", "core.worktree", str(other)], check=True)
        (self.source / ".env").write_text("synthetic\n")
        with self.assertRaises(m.Incomplete):
            m.actual_source(self.source)

    def test_replaced_and_restored_root_cannot_hide_dirty_original(self):
        replacement = self.base / "replacement"
        original = self.base / "original"
        subprocess.run(["git", "clone", "-q", str(self.source), str(replacement)], check=True)
        (self.source / "source.txt").write_text("dirty original\n")
        tool = m.source_snapshot_tool()
        real_head = tool._v3_head_index
        real_recheck = tool._v3_recheck_tracked_signatures
        swapped = False
        def head_after_swap(*args):
            nonlocal swapped
            if not swapped:
                self.source.rename(original)
                replacement.rename(self.source)
                swapped = True
            return real_head(*args)
        def restore_then_finish(*args):
            nonlocal swapped
            result = real_recheck(*args)
            self.source.rename(replacement)
            original.rename(self.source)
            swapped = False
            return result
        try:
            with patch.object(tool, "_v3_head_index", side_effect=head_after_swap), \
                 patch.object(tool, "_v3_recheck_tracked_signatures", side_effect=restore_then_finish), \
                 patch.object(m, "source_snapshot_tool", return_value=tool):
                with self.assertRaises(m.Invalid):
                    m.actual_source(self.source)
        finally:
            if swapped:
                self.source.rename(replacement)
                original.rename(self.source)

    def test_temporary_changed_index_cannot_validate_dirty_contents(self):
        (self.source / "source.txt").write_text("dirty original\n")
        alternate = self.base / "alternate-index"
        env = dict(os.environ, GIT_INDEX_FILE=str(alternate))
        subprocess.run(["git", "-C", str(self.source), "read-tree", "HEAD"], env=env, check=True)
        subprocess.run(["git", "-C", str(self.source), "add", "source.txt"], env=env, check=True)
        index_path = self.source / ".git/index"
        original_bytes = index_path.read_bytes()
        alternate_bytes = alternate.read_bytes()
        self.assertNotEqual(original_bytes, alternate_bytes)
        tool = m.source_snapshot_tool()
        verify = tool._v3_verify_index_bytes
        invoked = False
        def with_temporary_index(*args, **kwargs):
            nonlocal invoked
            invoked = True
            index_path.write_bytes(alternate_bytes)
            try:
                return verify(*args, **kwargs)
            finally:
                index_path.write_bytes(original_bytes)
        with patch.object(tool, "_v3_verify_index_bytes", side_effect=with_temporary_index), \
             patch.object(m, "source_snapshot_tool", return_value=tool):
            with self.assertRaises(m.Incomplete):
                m.actual_source(self.source)
        self.assertTrue(invoked)
        self.assertEqual(index_path.read_bytes(), original_bytes)

    def test_unavailable_filesystem_modes_are_inconclusive(self):
        tool = m.source_snapshot_tool()
        with patch.object(tool, "_v3_mount_status", return_value=("UNAVAILABLE", ("fixture",))), \
             patch.object(m, "source_snapshot_tool", return_value=tool):
            with self.assertRaises(m.Incomplete):
                m.actual_source(self.source)

    def test_untracked_source_is_dirty(self):
        (self.source / "untracked").write_text("untracked")
        self.rejects("dirty")

    def test_hidden_modified_files_are_rejected_without_changing_index(self):
        # Each subcase uses a genuine Git flag, verifies status misses the
        # changed file, and compares actual index bytes across the review.
        for flag, clear in (("--assume-unchanged", "--no-assume-unchanged"),
                            ("--skip-worktree", "--no-skip-worktree")):
            with self.subTest(flag=flag):
                (self.source / "source.txt").write_text("hidden change\n")
                subprocess.run(["git", "-C", str(self.source), "update-index", flag, "source.txt"], check=True)
                try:
                    status = subprocess.check_output(["git", "-C", str(self.source), "status", "--porcelain=v1"], text=True)
                    self.assertEqual(status, "")  # Demonstrate the actual Git bypass.
                    index = self.source / ".git" / "index"
                    before = index.read_bytes()
                    self.rejects("source index has hidden or unsupported entry flags")
                    self.assertEqual(index.read_bytes(), before)
                finally:
                    subprocess.run(["git", "-C", str(self.source), "update-index", clear, "source.txt"], check=True)
                    (self.source / "source.txt").write_text("synthetic\n")

    def test_plan_pinning(self):
        self.plan_hash = "0" * 64
        self.rejects("plan hash mismatch")

    def test_changed_and_missing_log(self):
        log = self.evidence / self.receipt["suites"][0]["logs"]["stdout"]["path"]
        log.write_text("changed")
        self.rejects("log hash mismatch")
        log.unlink()
        self.rejects()

    def test_path_escape_and_absolute_paths(self):
        for path in ("../outside", "/etc/passwd", "foo/../bar", "foo//bar", "./foo", "null\0byte"):
            with self.subTest(path=path):
                self.receipt["suites"][0]["logs"]["stdout"]["path"] = path
                self.save_receipt()
                self.rejects()

    def test_symlink_leaf_parent_and_root(self):
        target = self.evidence / self.receipt["suites"][0]["logs"]["stdout"]["path"]
        target.unlink()
        target.symlink_to("/etc/passwd")
        self.rejects()
        target.unlink()
        (self.evidence / "linked").symlink_to(self.base, target_is_directory=True)
        self.receipt["suites"][0]["logs"]["stdout"]["path"] = "linked/outside"
        self.save_receipt()
        self.rejects()
        link = self.base / "linked-root"
        link.symlink_to(self.evidence, target_is_directory=True)
        with self.assertRaises(OSError):
            m.review(self.source, link, "plan.json", self.plan_hash, "receipt.json")

    def test_duplicate_path_and_hard_link(self):
        first = self.receipt["suites"][0]["logs"]["stdout"]
        second = self.receipt["suites"][0]["logs"]["stderr"]
        second["path"] = first["path"]
        self.save_receipt()
        self.rejects("duplicate evidence path")
        link = self.evidence / "hardlink.log"
        os.link(self.evidence / first["path"], link)
        second.update(path="hardlink.log", sha256=first["sha256"])
        self.save_receipt()
        self.rejects("duplicate evidence inode")

    def test_duplicate_json_key_and_unknown_fields(self):
        (self.evidence / "receipt.json").write_text('{"status":"PASS","status":"PASS"}')
        self.rejects("duplicate JSON key")
        self.receipt["authorization"] = "forged"
        self.save_receipt()
        self.rejects("invalid receipt fields")

    def test_extreme_json_numbers_and_nesting_are_structured_failures(self):
        for raw in (b"9" * 5000, b"1e10000", b"[" * 3000 + b"0" + b"]" * 3000):
            with self.subTest(case=raw[:12]):
                (self.evidence / "receipt.json").write_bytes(raw)
                proc = subprocess.run(["/usr/bin/python3", "-B", str(Path(m.__file__)), "--source", str(self.source),
                    "--evidence-root", str(self.evidence), "--plan", "plan.json", "--plan-sha256", self.plan_hash,
                    "--receipt", "receipt.json"], capture_output=True, text=True, check=False)
                self.assertEqual(proc.returncode, 10)
                self.assertEqual(json.loads(proc.stdout)["status"], "FAIL")
                self.assertEqual(proc.stderr, "")

    def test_cli_does_not_issue_gate(self):
        proc = subprocess.run(["python3", str(Path(m.__file__)), "--source", str(self.source), "--evidence-root", str(self.evidence), "--plan", "plan.json", "--plan-sha256", self.plan_hash, "--receipt", "receipt.json"], capture_output=True, text=True, check=False)
        self.assertEqual(proc.returncode, 20)
        self.assertEqual(json.loads(proc.stdout)["status"], "INCONCLUSIVE")
        self.assertEqual(json.loads(proc.stdout)["product_gate_effect"], "NONE")


if __name__ == "__main__":
    unittest.main()
