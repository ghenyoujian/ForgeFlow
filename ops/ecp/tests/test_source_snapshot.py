from __future__ import annotations
import contextlib
import hashlib
import io
import os
import signal
import subprocess
import tempfile
import unittest
from pathlib import Path
import sys
import time
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'ops' / 'ecp'))
import source_snapshot
import materialize_snapshot


class SourceSnapshotTests(unittest.TestCase):
    def test_index_visibility_shortcuts_are_never_clean_and_are_not_modified(self) -> None:
        for flag, field in [('--assume-unchanged', 'assume_unchanged'),
                            ('--skip-worktree', 'skip_worktree')]:
            with self.subTest(flag=flag), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                def git(*args):
                    return subprocess.run(['git', *args], cwd=root, check=True,
                                          capture_output=True, text=True).stdout
                git('init', '-q')
                git('config', 'user.email', 'ecp@example.invalid')
                git('config', 'user.name', 'ECP Test')
                file = root/' tracked file.rs'
                file.write_text('committed\n', encoding='utf-8')
                git('add', file.name)
                git('commit', '-qm', 'baseline')
                self.assertEqual(source_snapshot.build_manifest(root, source_snapshot.DEFAULT_EXCLUDES)['worktree_state'], 'CLEAN')
                git('update-index', flag, file.name)
                original_flags = git('ls-files', '-v')
                for content in ('committed\n', 'changed\n'):
                    file.write_text(content, encoding='utf-8')
                    manifest = source_snapshot.build_manifest(root, source_snapshot.DEFAULT_EXCLUDES)
                    self.assertEqual(manifest['worktree_state'], 'DIRTY_UNFROZEN')
                    self.assertFalse(manifest['inventory_complete'])
                    self.assertFalse(manifest['release_qualifiable'])
                    self.assertEqual(manifest['index_visibility_exceptions'][0]['path'], file.name)
                    self.assertTrue(manifest['index_visibility_exceptions'][0][field])
                    self.assertEqual(git('ls-files', '-v'), original_flags)

    def test_gitlink_cannot_be_silently_qualified(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            def git(*args):
                return subprocess.run(['git', *args], cwd=root, check=True,
                                      capture_output=True, text=True).stdout.strip()
            git('init', '-q')
            git('config', 'user.email', 'ecp@example.invalid')
            git('config', 'user.name', 'ECP Test')
            (root/'README').write_text('baseline\n')
            git('add', 'README')
            git('commit', '-qm', 'baseline')
            git('update-index', '--add', '--cacheinfo', '160000', git('rev-parse', 'HEAD'), 'module')
            git('commit', '-qm', 'gitlink')
            manifest = source_snapshot.build_manifest(root, source_snapshot.DEFAULT_EXCLUDES)
            self.assertFalse(manifest['release_qualifiable'])
            self.assertFalse(manifest['inventory_complete'])
            self.assertEqual(manifest['index_visibility_exceptions'], [{'path': 'module', 'gitlink': True}])

    def test_nested_legacy_evidence_is_excluded_but_sibling_business_source_is_bound(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            subprocess.run(['git', 'init', '-q'], cwd=root, check=True)
            subprocess.run(['git', 'config', 'user.email', 'ecp@example.invalid'], cwd=root, check=True)
            subprocess.run(['git', 'config', 'user.name', 'ECP Test'], cwd=root, check=True)
            (root / 'README.md').write_text('baseline\n', encoding='utf-8')
            subprocess.run(['git', 'add', 'README.md'], cwd=root, check=True)
            subprocess.run(['git', 'commit', '-qm', 'baseline'], cwd=root, check=True)
            before = source_snapshot.build_manifest(root, source_snapshot.DEFAULT_EXCLUDES)
            plan = root / 'docs/idea/ForgeFlow_ECP_完整开发规划'
            evidence = plan / 'evidence/old-run/receipt.json'
            evidence.parent.mkdir(parents=True)
            evidence.write_text('{"status":"PASS"}\n', encoding='utf-8')
            after = source_snapshot.build_manifest(root, source_snapshot.DEFAULT_EXCLUDES)
            self.assertEqual(after['worktree_state'], 'DIRTY_UNFROZEN')
            self.assertFalse(after['release_qualifiable'])
            self.assertNotEqual(before['manifest_sha256'], after['manifest_sha256'])
            entries = {row['path']: row for row in after['untracked_business_files']}
            self.assertEqual(entries['docs/idea']['kind'], 'directory_summary')
            self.assertEqual(entries[str(plan.relative_to(root))]['kind'], 'directory_summary')
            self.assertNotIn(str(evidence.relative_to(root)), entries)
            business = plan / 'contracts/new.schema.json'
            business.parent.mkdir(parents=True)
            business.write_text('{"type":"object"}\n', encoding='utf-8')
            changed = source_snapshot.build_manifest(root, source_snapshot.DEFAULT_EXCLUDES)
            self.assertEqual(changed['worktree_state'], 'DIRTY_UNFROZEN')
            self.assertIn(str(business.relative_to(root)), {row['path'] for row in changed['untracked_business_files']})

    def test_untracked_empty_directory_is_not_release_qualifiable(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            subprocess.run(['git', 'init', '-q'], cwd=root, check=True)
            subprocess.run(['git', 'config', 'user.email', 'ecp@example.invalid'], cwd=root, check=True)
            subprocess.run(['git', 'config', 'user.name', 'ECP Test'], cwd=root, check=True)
            (root/'README').write_text('baseline\n')
            subprocess.run(['git', 'add', 'README'], cwd=root, check=True)
            subprocess.run(['git', 'commit', '-qm', 'baseline'], cwd=root, check=True)
            (root/'console'/'empty').mkdir(parents=True)
            (root/'console'/'other'/'node_modules').mkdir(parents=True)
            (root/'console'/'other'/'node_modules'/'private.txt').write_text('generated')
            for scan_all in (False, True):
                manifest = source_snapshot.build_manifest(root, source_snapshot.DEFAULT_EXCLUDES, scan_all)
                self.assertEqual(manifest['worktree_state'], 'DIRTY_UNFROZEN')
                self.assertFalse(manifest['release_qualifiable'])
                entries = {row['path']: row for row in manifest['untracked_business_files']}
                self.assertEqual(entries['console/empty']['kind'], 'directory_summary')
                self.assertEqual(entries['console/other']['kind'], 'directory_summary')
                self.assertNotIn('console/other/node_modules/private.txt', entries)
                with self.assertRaisesRegex(ValueError, 'directory summaries'):
                    materialize_snapshot.materialize_snapshot(root, manifest, root.parent/'candidate')

    def test_unreadable_directory_cannot_produce_clean_manifest(self) -> None:
        if hasattr(os, 'geteuid') and os.geteuid() == 0:
            self.skipTest('root can read mode-000 directories')
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            subprocess.run(['git', 'init', '-q'], cwd=root, check=True)
            subprocess.run(['git', 'config', 'user.email', 'ecp@example.invalid'], cwd=root, check=True)
            subprocess.run(['git', 'config', 'user.name', 'ECP Test'], cwd=root, check=True)
            (root/'README').write_text('baseline\n')
            subprocess.run(['git', 'add', 'README'], cwd=root, check=True)
            subprocess.run(['git', 'commit', '-qm', 'baseline'], cwd=root, check=True)
            inaccessible = root/'unreadable'; inaccessible.mkdir(); inaccessible.chmod(0)
            try:
                manifest = source_snapshot.build_manifest(root, source_snapshot.DEFAULT_EXCLUDES)
                self.assertEqual(manifest['worktree_state'], 'DIRTY_UNFROZEN')
                self.assertFalse(manifest['inventory_complete'])
                self.assertFalse(manifest['release_qualifiable'])
                self.assertIn('untracked inventory unavailable', manifest['inventory_error'])
            finally:
                inaccessible.chmod(0o700)

    def test_untracked_scan_budget_exhaustion_is_not_clean(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            subprocess.run(['git', 'init', '-q'], cwd=root, check=True)
            subprocess.run(['git', 'config', 'user.email', 'ecp@example.invalid'], cwd=root, check=True)
            subprocess.run(['git', 'config', 'user.name', 'ECP Test'], cwd=root, check=True)
            (root/'README').write_text('baseline\n')
            subprocess.run(['git', 'add', 'README'], cwd=root, check=True)
            subprocess.run(['git', 'commit', '-qm', 'baseline'], cwd=root, check=True)
            with patch.object(source_snapshot, 'MAX_UNTRACKED_SCAN_ENTRIES', 1):
                manifest = source_snapshot.build_manifest(root, source_snapshot.DEFAULT_EXCLUDES)
            self.assertEqual(manifest['worktree_state'], 'DIRTY_UNFROZEN')
            self.assertFalse(manifest['inventory_complete'])
            self.assertFalse(manifest['release_qualifiable'])
            self.assertIn('entry budget exceeded', manifest['inventory_error'])

    def test_scanner_rejects_directory_replaced_by_external_symlink(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory); root = parent/'source'; root.mkdir()
            switch = root/'switch'; switch.mkdir()
            outside = parent/'outside'; outside.mkdir(); (outside/'secret').write_text('not source')
            entries = source_snapshot._bounded_walk(root, root, (), [0], None)
            self.assertEqual(next(entries), (switch, True))
            switch.rename(root/'old-switch')
            switch.symlink_to(outside, target_is_directory=True)
            with self.assertRaises(OSError):
                list(entries)

    def test_cli_refuses_to_write_manifest_inside_source_tree(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            subprocess.run(['git', 'init', '-q'], cwd=root, check=True)
            subprocess.run(['git', 'config', 'user.email', 'ecp@example.invalid'], cwd=root, check=True)
            subprocess.run(['git', 'config', 'user.name', 'ECP Test'], cwd=root, check=True)
            (root / 'README.md').write_text('baseline\n', encoding='utf-8')
            subprocess.run(['git', 'add', 'README.md'], cwd=root, check=True)
            subprocess.run(['git', 'commit', '-qm', 'baseline'], cwd=root, check=True)

            output = root / 'snapshot.json'
            completed = subprocess.run(
                [sys.executable, str(ROOT / 'ops' / 'ecp' / 'source_snapshot.py'),
                 '--source-root', str(root), '--output', str(output)],
                cwd=root, text=True, capture_output=True, check=False,
            )

            self.assertEqual(completed.returncode, 10)
            self.assertIn('manifest output must be outside', completed.stdout)
            self.assertFalse(output.exists())

    def test_cli_refuses_existing_or_symlinked_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            root = parent/'source'
            root.mkdir()
            existing = parent/'prior.json'
            existing.write_text('preserve\n')
            linked = parent/'link.json'
            linked.symlink_to(existing)
            missing = parent/'missing.json'
            dangling = parent/'dangling.json'
            dangling.symlink_to(missing)
            for target in (existing, linked, dangling):
                result = subprocess.run([sys.executable, str(ROOT/'ops/ecp/source_snapshot.py'),
                    '--source-root', str(root), '--output', str(target)], capture_output=True, text=True)
                self.assertEqual(result.returncode, 10, result.stdout + result.stderr)
                self.assertIn('manifest evidence already exists', result.stdout)
                self.assertEqual(existing.read_text(), 'preserve\n')
                self.assertFalse(missing.exists())

    def test_manifest_is_deterministic_for_same_tree(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            subprocess.run(['git', 'init', '-q'], cwd=root, check=True)
            subprocess.run(['git', 'config', 'user.email', 'ecp@example.invalid'], cwd=root, check=True)
            subprocess.run(['git', 'config', 'user.name', 'ECP Test'], cwd=root, check=True)
            (root / 'README.md').write_text('baseline\n', encoding='utf-8')
            subprocess.run(['git', 'add', 'README.md'], cwd=root, check=True)
            subprocess.run(['git', 'commit', '-qm', 'baseline'], cwd=root, check=True)
            (root / 'README.md').write_text('changed\n', encoding='utf-8')
            (root / 'ops' / 'ecp').mkdir(parents=True)
            (root / 'ops' / 'ecp' / 'new.py').write_text('print(1)\n', encoding='utf-8')
            first = source_snapshot.build_manifest(root, ['ignored/'])
            second = source_snapshot.build_manifest(root, ['ignored/'])
            self.assertEqual(first['manifest_sha256'], second['manifest_sha256'])
            self.assertEqual(first['worktree_state'], 'DIRTY_UNFROZEN')
            self.assertFalse(first['release_qualifiable'])
            self.assertIn('ops/ecp/new.py', {item['path'] for item in first['untracked_business_files']})

    def test_timed_out_inventory_is_dirty_and_never_release_qualifiable(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            subprocess.run(['git', 'init', '-q'], cwd=root, check=True)
            subprocess.run(['git', 'config', 'user.email', 'ecp@example.invalid'], cwd=root, check=True)
            subprocess.run(['git', 'config', 'user.name', 'ECP Test'], cwd=root, check=True)
            (root / 'README.md').write_text('baseline\n', encoding='utf-8')
            subprocess.run(['git', 'add', 'README.md'], cwd=root, check=True)
            subprocess.run(['git', 'commit', '-qm', 'baseline'], cwd=root, check=True)

            timeout = subprocess.TimeoutExpired(['git', 'status'], 0.1)
            with patch.object(source_snapshot, 'status_entries', side_effect=timeout):
                manifest = source_snapshot.build_manifest(root, source_snapshot.DEFAULT_EXCLUDES)

            self.assertEqual(manifest['worktree_state'], 'DIRTY_UNFROZEN')
            self.assertFalse(manifest['inventory_complete'])
            self.assertFalse(manifest['release_qualifiable'])
            self.assertIn('status inventory unavailable', manifest['inventory_error'])

    def test_manifest_binds_symlink_target_text_and_kind(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            subprocess.run(['git', 'init', '-q'], cwd=root, check=True)
            subprocess.run(['git', 'config', 'user.email', 'ecp@example.invalid'], cwd=root, check=True)
            subprocess.run(['git', 'config', 'user.name', 'ECP Test'], cwd=root, check=True)
            (root / 'README.md').write_text('baseline\n', encoding='utf-8')
            subprocess.run(['git', 'add', 'README.md'], cwd=root, check=True)
            subprocess.run(['git', 'commit', '-qm', 'baseline'], cwd=root, check=True)

            code = root / 'ops' / 'ecp'
            code.mkdir(parents=True)
            (code / 'first.txt').write_text('same bytes\n', encoding='utf-8')
            (code / 'second.txt').write_text('same bytes\n', encoding='utf-8')
            link = code / 'active.txt'
            link.symlink_to('first.txt')
            first = source_snapshot.build_manifest(root, ['ignored/'])
            first_record = next(row for row in first['untracked_business_files'] if row['path'] == 'ops/ecp/active.txt')
            self.assertEqual(first_record['kind'], 'symlink')
            self.assertEqual(first_record['target'], 'first.txt')

            link.unlink()
            link.symlink_to('second.txt')
            second = source_snapshot.build_manifest(root, ['ignored/'])
            second_record = next(row for row in second['untracked_business_files'] if row['path'] == 'ops/ecp/active.txt')
            self.assertEqual(second_record['kind'], 'symlink')
            self.assertEqual(second_record['target'], 'second.txt')
            self.assertNotEqual(first['manifest_sha256'], second['manifest_sha256'])

    def test_manifest_binds_executable_mode_and_symlinked_directory(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            subprocess.run(['git', 'init', '-q'], cwd=root, check=True)
            subprocess.run(['git', 'config', 'user.email', 'ecp@example.invalid'], cwd=root, check=True)
            subprocess.run(['git', 'config', 'user.name', 'ECP Test'], cwd=root, check=True)
            (root / 'README.md').write_text('baseline\n', encoding='utf-8')
            subprocess.run(['git', 'add', 'README.md'], cwd=root, check=True)
            subprocess.run(['git', 'commit', '-qm', 'baseline'], cwd=root, check=True)

            code = root / 'ops' / 'ecp'
            code.mkdir(parents=True)
            script = code / 'run.py'
            script.write_text('print(1)\n', encoding='utf-8')
            before = source_snapshot.build_manifest(root, ['ignored/'])
            script.chmod(0o755)
            after = source_snapshot.build_manifest(root, ['ignored/'])
            self.assertNotEqual(before['manifest_sha256'], after['manifest_sha256'])
            executable = next(row for row in after['untracked_business_files'] if row['path'] == 'ops/ecp/run.py')
            self.assertEqual(executable['mode'], '0755')

            external = root.parent / (root.name + '-outside')
            external.mkdir()
            try:
                (external / 'ignored.txt').write_text('outside content\n', encoding='utf-8')
                link = code / 'external-dir'
                link.symlink_to(external, target_is_directory=True)
                manifest = source_snapshot.build_manifest(root, ['ignored/'])
                row = next(item for item in manifest['untracked_business_files'] if item['path'] == 'ops/ecp/external-dir')
                self.assertEqual(row['kind'], 'symlink')
                self.assertEqual(row['target'], str(external))
                self.assertNotIn('ops/ecp/external-dir/ignored.txt', {item['path'] for item in manifest['untracked_business_files']})
            finally:
                (external / 'ignored.txt').unlink(missing_ok=True)
                external.rmdir()

    def test_status_parser_handles_leading_status_spaces_and_rename_paths(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            subprocess.run(['git', 'init', '-q'], cwd=root, check=True)
            subprocess.run(['git', 'config', 'user.email', 'ecp@example.invalid'], cwd=root, check=True)
            subprocess.run(['git', 'config', 'user.name', 'ECP Test'], cwd=root, check=True)
            original = root / 'old name.txt'
            original.write_text('tracked\n', encoding='utf-8')
            leading_space = root / ' changed.txt'
            leading_space.write_text('before\n', encoding='utf-8')
            subprocess.run(['git', 'add', 'old name.txt', ' changed.txt'], cwd=root, check=True)
            subprocess.run(['git', 'commit', '-qm', 'baseline'], cwd=root, check=True)
            moved = root / 'new name.txt'
            original.rename(moved)
            subprocess.run(['git', 'add', '-A'], cwd=root, check=True)
            leading_space.write_text('after\n', encoding='utf-8')
            entries = source_snapshot.status_entries(root)
            self.assertIn((' M', ' changed.txt'), entries)
            self.assertIn(('R ', 'new name.txt'), entries)

    def test_bounded_scan_captures_root_build_inputs_and_prunes_generated_trees(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            subprocess.run(['git', 'init', '-q'], cwd=root, check=True)
            subprocess.run(['git', 'config', 'user.email', 'ecp@example.invalid'], cwd=root, check=True)
            subprocess.run(['git', 'config', 'user.name', 'ECP Test'], cwd=root, check=True)
            (root / 'README.md').write_text('baseline\n', encoding='utf-8')
            subprocess.run(['git', 'add', 'README.md'], cwd=root, check=True)
            subprocess.run(['git', 'commit', '-qm', 'baseline'], cwd=root, check=True)

            (root / '.cargo').mkdir()
            (root / '.cargo' / 'config.toml').write_text('[build]\njobs = 1\n', encoding='utf-8')
            (root / '.dockerignore').write_text('target\n', encoding='utf-8')
            (root / 'src').mkdir()
            (root / 'src' / 'main.rs').write_text('fn main() {}\n', encoding='utf-8')
            (root / 'target').mkdir()
            (root / 'target' / 'generated.bin').write_bytes(b'generated')
            (root / 'evidence').mkdir()
            (root / 'evidence' / 'report.json').write_text('{}\n', encoding='utf-8')
            (root / 'console').mkdir()
            (root / 'console' / 'node_modules').mkdir()
            (root / 'console' / 'node_modules' / 'package.js').write_text('generated\n', encoding='utf-8')

            manifest = source_snapshot.build_manifest(root, source_snapshot.DEFAULT_EXCLUDES)
            paths = {row['path'] for row in manifest['untracked_business_files']}
            self.assertIn('.cargo/config.toml', paths)
            self.assertIn('.dockerignore', paths)
            self.assertIn('src/main.rs', paths)
            self.assertNotIn('target/generated.bin', paths)
            self.assertNotIn('evidence/report.json', paths)
            self.assertNotIn('console/node_modules/package.js', paths)

    def test_git_ignored_business_inputs_are_not_silently_omitted(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            subprocess.run(['git', 'init', '-q'], cwd=root, check=True)
            subprocess.run(['git', 'config', 'user.email', 'ecp@example.invalid'], cwd=root, check=True)
            subprocess.run(['git', 'config', 'user.name', 'ECP Test'], cwd=root, check=True)
            (root / 'README.md').write_text('baseline\n', encoding='utf-8')
            subprocess.run(['git', 'add', 'README.md'], cwd=root, check=True)
            subprocess.run(['git', 'commit', '-qm', 'baseline'], cwd=root, check=True)

            (root / '.gitignore').write_text('ignored-config.toml\nignored-build/\n', encoding='utf-8')
            (root / 'ignored-config.toml').write_text('feature = true\n', encoding='utf-8')
            (root / 'ignored-build').mkdir()
            (root / 'ignored-build' / 'input.rs').write_text('fn main() {}\n', encoding='utf-8')

            manifest = source_snapshot.build_manifest(root, source_snapshot.DEFAULT_EXCLUDES)
            paths = {row['path'] for row in manifest['untracked_business_files']}
            self.assertIn('.gitignore', paths)
            self.assertIn('ignored-config.toml', paths)
            self.assertIn('ignored-build/input.rs', paths)
            self.assertEqual(manifest['worktree_state'], 'DIRTY_UNFROZEN')
            self.assertFalse(manifest['release_qualifiable'])

    def test_tracked_deletion_is_recorded_and_materialized_from_head_patch(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            root = parent / 'source'
            root.mkdir()
            subprocess.run(['git', 'init', '-q'], cwd=root, check=True)
            subprocess.run(['git', 'config', 'user.email', 'ecp@example.invalid'], cwd=root, check=True)
            subprocess.run(['git', 'config', 'user.name', 'ECP Test'], cwd=root, check=True)
            (root / 'README.md').write_text('must disappear\n', encoding='utf-8')
            (root / 'keep.txt').write_text('keep\n', encoding='utf-8')
            subprocess.run(['git', 'add', 'README.md', 'keep.txt'], cwd=root, check=True)
            subprocess.run(['git', 'commit', '-qm', 'baseline'], cwd=root, check=True)
            (root / 'README.md').unlink()

            manifest = source_snapshot.build_manifest(root, source_snapshot.DEFAULT_EXCLUDES)
            deleted = next(item for item in manifest['tracked_changes'] if item['path'] == 'README.md')
            self.assertEqual(deleted['status'], ' D')
            self.assertEqual(deleted['kind'], 'deleted')
            self.assertIsNone(deleted['mode'])
            self.assertIsNone(deleted['sha256'])
            self.assertEqual(manifest['manifest_sha256'], source_snapshot.build_manifest(root, source_snapshot.DEFAULT_EXCLUDES)['manifest_sha256'])

            destination = parent / 'materialized'
            receipt = materialize_snapshot.materialize_snapshot(root, manifest, destination)
            self.assertEqual(receipt['status'], 'PASS')
            self.assertEqual(receipt['materialized_deleted_paths'], ['README.md'])
            self.assertFalse((destination / 'README.md').exists())
            self.assertEqual((destination / 'keep.txt').read_text(encoding='utf-8'), 'keep\n')
            self.assertTrue((root / 'keep.txt').exists())


class V3ProjectionTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name) / 'source'
        self.root.mkdir()
        self.git('init', '-q')
        self.git('config', 'user.email', 'ecp@example.invalid')
        self.git('config', 'user.name', 'ECP Test')
        (self.root / 'tracked').mkdir()
        (self.root / 'tracked/build_probe.py').write_text('print("baseline")\n', encoding='utf-8')
        self.git('add', 'tracked/build_probe.py')
        self.git('commit', '-qm', 'baseline')

    def git(self, *args):
        return subprocess.run(['git', *args], cwd=self.root, check=True, capture_output=True).stdout

    def test_v3_explicit_index_policy_verifies_excluded_tracked_files_and_links(self):
        evidence = self.root / 'evidence'
        evidence.mkdir()
        (evidence / 'tracked.txt').write_bytes(b'original synthetic evidence\n')
        (evidence / 'link').symlink_to('tracked.txt')
        self.git('add', '-f', 'evidence/tracked.txt', 'evidence/link')
        self.git('commit', '-qm', 'track evidence fixture')
        head, index, raw_index, _ = source_snapshot._v3_head_index(self.root)
        deadline = time.monotonic() + 30
        signatures = source_snapshot._v3_verify_index_bytes(
            self.root, set(index), (), 'VERIFIED', head, deadline, raw_index)
        self.assertEqual(set(signatures), set(index))
        (evidence / 'tracked.txt').write_bytes(b'modified synthetic evidence\n')
        with self.assertRaisesRegex(ValueError, 'tracked source bytes differ'):
            source_snapshot._v3_verify_index_bytes(
                self.root, set(index), (), 'VERIFIED', head, time.monotonic() + 30, raw_index)
        (evidence / 'tracked.txt').write_bytes(b'original synthetic evidence\n')
        (evidence / 'link').unlink()
        (evidence / 'link').symlink_to('../tracked/build_probe.py')
        with self.assertRaisesRegex(ValueError, 'tracked source bytes differ'):
            source_snapshot._v3_verify_index_bytes(
                self.root, set(index), (), 'VERIFIED', head, time.monotonic() + 30, raw_index)

    def test_v3_explicit_scan_policy_enumerates_evidence_and_binds_digest(self):
        evidence = self.root / 'evidence'
        evidence.mkdir()
        (evidence / 'tracked.txt').write_bytes(b'tracked fixture\n')
        self.git('add', '-f', 'evidence/tracked.txt')
        self.git('commit', '-qm', 'track evidence fixture')
        (evidence / 'untracked.txt').write_bytes(b'untracked fixture\n')
        head, index, _, _ = source_snapshot._v3_head_index(self.root)
        policy = ('.git/',)
        projection, observations = source_snapshot._v3_scan_projection(
            self.root, set(index), policy, 'VERIFIED', time.monotonic() + 30)
        self.assertIn('evidence', {row['path'] for row in projection['directories']})
        self.assertNotIn('evidence', {row['path'] for row in projection['excluded_directory_boundaries']})
        self.assertIn('evidence/tracked.txt', observations['files'])
        self.assertIn('evidence/untracked.txt', observations['files'])
        self.assertEqual(projection['exclusion_policy_sha256'],
                         hashlib.sha256(source_snapshot._v3_canonical(list(policy))).hexdigest())
        fixed, default_observations = source_snapshot._v3_scan_projection(
            self.root, set(index), source_snapshot.V3_EXCLUDES, 'VERIFIED', time.monotonic() + 30)
        self.assertIn('evidence', {row['path'] for row in fixed['excluded_directory_boundaries']})
        self.assertNotIn('evidence/tracked.txt', default_observations['files'])

    def test_v3_all_tracked_policy_rejects_private_root_env_before_open(self):
        env = self.root / '.env'
        env.write_bytes(b'synthetic private fixture, not a real secret')
        self.git('add', '-f', '.env')
        self.git('commit', '-qm', 'track private synthetic fixture')
        head, index, raw_index, _ = source_snapshot._v3_head_index(self.root)
        for policy in ((), ('.git/',)):
            with self.subTest(policy=policy), \
                 patch.object(source_snapshot, '_v3_open_root', side_effect=AssertionError('worktree root opened')):
                with self.assertRaisesRegex(ValueError, 'private'):
                    source_snapshot._v3_verify_index_bytes(
                        self.root, set(index), policy, 'VERIFIED', head, time.monotonic() + 30, raw_index)
        private = env.stat()
        original_read = os.read
        def guard_read(fd, size):
            info = os.fstat(fd)
            if (info.st_dev, info.st_ino) == (private.st_dev, private.st_ino):
                raise AssertionError('private fixture content read')
            return original_read(fd, size)
        with patch.object(source_snapshot.os, 'read', side_effect=guard_read):
            signatures = source_snapshot._v3_verify_index_bytes(
                self.root, set(index), source_snapshot.V3_EXCLUDES, 'VERIFIED',
                head, time.monotonic() + 30, raw_index)
        self.assertNotIn('.env', signatures)

    def test_v3_all_tracked_policy_rejects_private_root_env_symlink_before_open(self):
        env = self.root / '.env'
        env.symlink_to('unreadable-synthetic-target')
        self.git('add', '-f', '.env')
        self.git('commit', '-qm', 'track private synthetic symlink')
        head, index, raw_index, _ = source_snapshot._v3_head_index(self.root)
        for policy in ((), ('.git/',)):
            with self.subTest(policy=policy), \
                 patch.object(source_snapshot, '_v3_open_root', side_effect=AssertionError('worktree root opened')):
                with self.assertRaisesRegex(ValueError, 'private'):
                    source_snapshot._v3_verify_index_bytes(
                        self.root, set(index), policy, 'VERIFIED', head, time.monotonic() + 30, raw_index)
        original_readlink = os.readlink
        def guard_readlink(path, *args, **kwargs):
            if path == '.env':
                raise AssertionError('private fixture symlink target read')
            return original_readlink(path, *args, **kwargs)
        with patch.object(source_snapshot.os, 'readlink', side_effect=guard_readlink):
            with self.assertRaisesRegex(ValueError, 'symlink'):
                source_snapshot._v3_verify_index_bytes(
                    self.root, set(index), source_snapshot.V3_EXCLUDES, 'VERIFIED',
                    head, time.monotonic() + 30, raw_index)

    def test_v3_explicit_policy_keeps_env_directory_as_business(self):
        env = self.root / '.env'
        env.mkdir()
        (env / 'input.txt').write_bytes(b'synthetic business input')
        self.git('add', '-f', '.env/input.txt')
        self.git('commit', '-qm', 'track business env directory')
        head, index, raw_index, _ = source_snapshot._v3_head_index(self.root)
        signatures = source_snapshot._v3_verify_index_bytes(
            self.root, set(index), (), 'VERIFIED', head, time.monotonic() + 30, raw_index)
        self.assertIn('.env/input.txt', signatures)
        projection, observations = source_snapshot._v3_scan_projection(
            self.root, set(index), ('.git/',), 'VERIFIED', time.monotonic() + 30)
        self.assertIn('.env', {row['path'] for row in projection['directories']})
        self.assertIn('.env/input.txt', observations['files'])

    def test_v3_explicit_policy_rejects_unregistered_and_duplicate_patterns_early(self):
        for policy in (('**/node_modules/',), ('evidence/', 'evidence/')):
            with self.subTest(policy=policy), \
                 patch.object(source_snapshot, '_v3_open_root', side_effect=AssertionError('worktree opened')), \
                 patch.object(source_snapshot, 'run_git', side_effect=AssertionError('Git invoked')):
                with self.assertRaisesRegex(ValueError, 'policy'):
                    source_snapshot._v3_scan_projection(
                        self.root, set(), policy, 'VERIFIED', time.monotonic() + 30)
                with self.assertRaisesRegex(ValueError, 'policy'):
                    source_snapshot._v3_verify_index_bytes(
                        self.root, set(), policy, 'VERIFIED', 'a' * 40, time.monotonic() + 30)

    def test_v3_explicit_policy_allows_git_marker_but_rejects_git_symlink(self):
        fixture = self.root.parent / 'synthetic-marker'
        fixture.mkdir()
        marker = fixture / '.git'
        marker.write_text('gitdir: synthetic-metadata\n', encoding='utf-8')
        projection, observed = source_snapshot._v3_scan_projection(
            fixture, set(), ('.git/',), 'VERIFIED', time.monotonic() + 30)
        self.assertIn('.git', observed['files'])
        self.assertNotIn('.git', {row['path'] for row in projection['excluded_directory_boundaries']})
        marker.unlink()
        marker.symlink_to('nonexistent-metadata')
        with self.assertRaisesRegex(ValueError, 'symlink'):
            source_snapshot._v3_scan_projection(
                fixture, set(), ('.git/',), 'VERIFIED', time.monotonic() + 30)

    def test_v3_root_env_file_directory_symlink_and_special(self):
        env = self.root / '.env'
        baseline = source_snapshot.build_manifest_v3(self.root)
        env.write_bytes(b'synthetic private fixture')
        private_stat = env.stat()
        real_read = os.read
        observed = []
        def guarded_read(fd, size):
            info = os.fstat(fd)
            if (info.st_dev, info.st_ino) == (private_stat.st_dev, private_stat.st_ino):
                observed.append(fd)
                raise AssertionError('private fixture was read')
            return real_read(fd, size)
        with patch.object(source_snapshot.os, 'read', side_effect=guarded_read):
            self.assertEqual(baseline['manifest_sha256'], source_snapshot.build_manifest_v3(self.root)['manifest_sha256'])
        self.assertEqual(observed, [])
        self.git('add', '-f', '.env')
        self.git('commit', '-qm', 'track private fixture')
        with patch.object(source_snapshot.os, 'read', side_effect=guarded_read):
            tracked_manifest = source_snapshot.build_manifest_v3(self.root)
        env.write_bytes(b'changed synthetic fixture')
        with patch.object(source_snapshot.os, 'read', side_effect=guarded_read):
            self.assertEqual(tracked_manifest['manifest_sha256'], source_snapshot.build_manifest_v3(self.root)['manifest_sha256'])
        self.assertEqual(observed, [])
        self.git('rm', '-f', '.env')
        self.git('commit', '-qm', 'remove private fixture')
        env.mkdir()
        with self.assertRaisesRegex(ValueError, 'untracked business'):
            source_snapshot.build_manifest_v3(self.root)
        (env / 'input.txt').write_bytes(b'business directory input')
        self.git('add', '-f', '.env/input.txt')
        self.git('commit', '-qm', 'track env directory input')
        manifest = source_snapshot.build_manifest_v3(self.root)
        self.assertIn('.env', {x['path'] for x in manifest['directory_projection']['directories']})
        self.git('rm', '-f', '.env/input.txt')
        self.git('commit', '-qm', 'remove env directory input')
        if env.exists():
            env.rmdir()
        env.symlink_to('tracked', target_is_directory=True)
        with self.assertRaisesRegex(ValueError, 'symlink'):
            source_snapshot.build_manifest_v3(self.root)
        self.git('add', '-f', '.env')
        self.git('commit', '-qm', 'track env symlink')
        with self.assertRaisesRegex(ValueError, 'symlink'):
            source_snapshot.build_manifest_v3(self.root)
        self.git('rm', '-f', '.env')
        self.git('commit', '-qm', 'remove env symlink')
        os.mkfifo(env)
        with self.assertRaisesRegex(ValueError, 'unsupported source entry'):
            source_snapshot.build_manifest_v3(self.root)

    def test_v3_excluded_index_and_boundary_steps_honor_deadline(self):
        oid = 'a' * 40
        paths = ('evidence/a', 'evidence/b')
        raw = b''.join(f'100644 {oid} 0\t{p}\0'.encode() for p in paths)
        with patch.object(source_snapshot, 'run_git', return_value=raw), \
             patch.object(source_snapshot, '_v3_require_boundary_directory') as boundary, \
             patch.object(source_snapshot.time, 'monotonic', side_effect=[0.0, 2.0]):
            with self.assertRaisesRegex(TimeoutError, 'tracked blob verification exceeded deadline'):
                source_snapshot._v3_verify_index_bytes(self.root, set(paths), source_snapshot.V3_EXCLUDES,
                                                       'VERIFIED', oid, 1.0)
            self.assertEqual(boundary.call_count, 1)
        (self.root / 'benchmarks/evidence').mkdir(parents=True)
        fd = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY)
        try:
            with patch.object(source_snapshot.time, 'monotonic', side_effect=[0.0, 2.0]):
                with self.assertRaisesRegex(TimeoutError, 'excluded directory verification exceeded deadline'):
                    source_snapshot._v3_require_boundary_directory(fd, 'benchmarks/evidence/', deadline=1.0)
        finally:
            os.close(fd)

    def test_v3_boundary_open_completion_honors_deadline(self):
        (self.root / 'evidence').mkdir()
        fd = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY)
        real_open = os.open
        try:
            with patch.object(source_snapshot.os, 'open', wraps=real_open) as opened, \
                 patch.object(source_snapshot.time, 'monotonic', side_effect=[0.0, 2.0]):
                with self.assertRaisesRegex(TimeoutError, 'excluded directory verification exceeded deadline'):
                    source_snapshot._v3_require_boundary_directory(fd, 'evidence/', deadline=1.0)
                self.assertEqual(opened.call_count, 1)
        finally:
            os.close(fd)

    def test_v3_boundary_replacement_between_observations_is_rejected(self):
        boundary = self.root / 'benchmarks/evidence'
        boundary.mkdir(parents=True)
        fd = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY)
        real_open = os.open
        replaced = []
        def swap_after_open(path, flags, *args, **kwargs):
            child = real_open(path, flags, *args, **kwargs)
            if path == 'evidence' and not replaced:
                replaced.append(True)
                (self.root / 'benchmarks').rename(self.root / 'displaced-benchmarks')
                boundary.mkdir(parents=True)
            return child
        try:
            deadline = time.monotonic() + 30
            with patch.object(source_snapshot.os, 'open', side_effect=swap_after_open):
                with self.assertRaisesRegex(ValueError, 'boundary changed between observations'):
                    source_snapshot._v3_require_boundary_directory(fd, 'benchmarks/evidence/', deadline=deadline)
            self.assertEqual(replaced, [True])
        finally:
            os.close(fd)

    def test_v3_directory_names_as_regular_files_are_business(self):
        for name in ('evidence', 'target', 'node_modules', 'evidence2', 'target2', 'node_modules2'):
            with self.subTest(name=name):
                path = self.root / name
                path.write_bytes(('baseline-' + name).encode())
                self.git('add', '-f', name)
                self.git('commit', '-qm', 'add directory-named file')
                baseline = source_snapshot.build_manifest_v3(self.root)
                self.assertEqual(baseline['manifest_sha256'], source_snapshot.build_manifest_v3(self.root)['manifest_sha256'])
                path.write_bytes(b'changed')
                with self.assertRaisesRegex(ValueError, 'tracked source bytes differ'):
                    source_snapshot.build_manifest_v3(self.root)
                self.git('add', '-f', name)
                self.git('commit', '-qm', 'change directory-named file')
                changed = source_snapshot.build_manifest_v3(self.root)
                self.assertNotEqual(baseline['manifest_sha256'], changed['manifest_sha256'])

    def test_v3_directory_names_untracked_and_removed_globs_are_business(self):
        for name in ('evidence', 'target', 'node_modules'):
            with self.subTest(untracked=name):
                path = self.root / name
                path.write_bytes(b'untracked')
                with self.assertRaisesRegex(ValueError, 'untracked business'):
                    source_snapshot.build_manifest_v3(self.root)
                path.unlink()
        names = ('crates/demo/src/evidence/verification.rs',
                 'console/src/assets/node_modules/spec.json',
                 'console/src/__pycache__/golden.pyc')
        for name in names:
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(b'tracked business')
        self.git('add', '-f', *names)
        self.git('commit', '-qm', 'include nested business inputs')
        before = source_snapshot.build_manifest_v3(self.root)
        for name in names:
            with self.subTest(tracked=name):
                path = self.root / name
                path.write_bytes(b'modified business')
                with self.assertRaisesRegex(ValueError, 'tracked source bytes differ'):
                    source_snapshot.build_manifest_v3(self.root)
                path.write_bytes(b'tracked business')
            with self.subTest(untracked_nested=name):
                path = (self.root / name).with_name('extra-business')
                path.write_bytes(b'untracked')
                with self.assertRaisesRegex(ValueError, 'untracked business'):
                    source_snapshot.build_manifest_v3(self.root)
                path.unlink()
        self.assertEqual(before['manifest_sha256'], source_snapshot.build_manifest_v3(self.root)['manifest_sha256'])

    def test_v3_registered_boundaries_symlinks_worktree_and_private_env(self):
        boundaries = ('evidence', 'console/node_modules', 'target', '__pycache__')
        for name in boundaries:
            (self.root / name).mkdir(parents=True, exist_ok=True)
        baseline = source_snapshot.build_manifest_v3(self.root)
        actual = {x['path'] for x in baseline['directory_projection']['excluded_directory_boundaries']}
        self.assertTrue(set(boundaries).issubset(actual))
        for name in ('evidence', 'target', '__pycache__'):
            with self.subTest(boundary_symlink=name):
                path = self.root / name
                path.rmdir()
                path.symlink_to('tracked', target_is_directory=True)
                with self.assertRaisesRegex(ValueError, 'symlink'):
                    source_snapshot.build_manifest_v3(self.root)
                path.unlink()
                path.mkdir()
        (self.root / '.env').write_bytes(b'private fixture')
        self.assertEqual(baseline['manifest_sha256'], source_snapshot.build_manifest_v3(self.root)['manifest_sha256'])
        worktree = self.root.parent / 'linked-worktree'
        self.git('worktree', 'add', '--detach', str(worktree), 'HEAD')
        self.assertTrue((worktree / '.git').is_file())
        self.assertEqual(source_snapshot.build_manifest_v3(worktree)['worktree_state'], 'CLEAN')
        marker = self.root.parent / 'saved-git-marker'
        (worktree / '.git').rename(marker)
        (worktree / '.git').symlink_to(marker)
        with self.assertRaises((ValueError, OSError, subprocess.CalledProcessError)):
            source_snapshot.build_manifest_v3(worktree)

    def test_v3_registered_policy_keeps_business_formats_and_v2_unchanged(self):
        legacy = hashlib.sha256(source_snapshot._v3_canonical(list(source_snapshot.DEFAULT_EXCLUDES))).hexdigest()
        current = hashlib.sha256(source_snapshot._v3_canonical(list(source_snapshot.V3_EXCLUDES))).hexdigest()
        self.assertEqual(legacy, 'd839d523d6af3b32855d03570ddd1856c7d546c9dd8b39e3b9c9314b2c566c35')
        self.assertEqual(current, '693a01c306939936dea248c348d1ed09f44cfc230b27b7a6faeab85fb3926787')
        names = ('asset.png', 'fixture.log', 'bundle.tar.gz', 'module.pyc')
        for index, name in enumerate(names):
            (self.root/'tracked'/name).write_bytes(b'base\x00' + bytes([index]))
        self.git('add', '-f', *('tracked/' + name for name in names))
        self.git('commit', '-qm', 'add business inputs')
        previous = source_snapshot.build_manifest_v3(self.root)
        self.assertEqual(previous['exclude_patterns'], list(source_snapshot.V3_EXCLUDES))
        self.assertEqual(previous['manifest_sha256'], source_snapshot.build_manifest_v3(self.root)['manifest_sha256'])
        for name in names:
            with self.subTest(name=name):
                path = self.root/'tracked'/name
                path.write_bytes(path.read_bytes() + b'changed')
                with self.assertRaisesRegex(ValueError, 'tracked source bytes differ'):
                    source_snapshot.build_manifest_v3(self.root)
                self.git('add', '-f', 'tracked/' + name)
                self.git('commit', '-qm', 'change business input')
                changed = source_snapshot.build_manifest_v3(self.root)
                self.assertNotEqual(previous['manifest_sha256'], changed['manifest_sha256'])
                previous = changed
        with self.assertRaisesRegex(ValueError, 'fixed exclusion policy'):
            source_snapshot.build_manifest_v3(self.root, source_snapshot.DEFAULT_EXCLUDES)

    def test_v3_untracked_business_formats_are_rejected_but_boundaries_remain_excluded(self):
        evidence = self.root/'evidence'; evidence.mkdir()
        cache = self.root/'__pycache__'; cache.mkdir()
        baseline = source_snapshot.build_manifest_v3(self.root)
        names = ('asset.png', 'fixture.log', 'bundle.tar.gz', 'module.pyc')
        for name in names:
            with self.subTest(name=name):
                path = self.root/'tracked'/name
                path.write_bytes(b'untracked input')
                with self.assertRaisesRegex(ValueError, 'untracked business file'):
                    source_snapshot.build_manifest_v3(self.root)
                path.unlink()
                (evidence/name).write_bytes(b'historical evidence')
        (cache/'cached.pyc').write_bytes(b'generated cache')
        self.assertEqual(baseline['manifest_sha256'], source_snapshot.build_manifest_v3(self.root)['manifest_sha256'])

    @contextlib.contextmanager
    def redirect_v3_git_for_fault_injection(self, executable):
        """Inject bounded-stream faults without changing production Git lookup."""
        real_popen = subprocess.Popen
        def spawn(command, *args, **kwargs):
            if command and command[0] == '/usr/bin/git':
                command = [str(executable), *command[1:]]
            return real_popen(command, *args, **kwargs)
        with patch.object(source_snapshot.subprocess, 'Popen', side_effect=spawn):
            yield

    def evidence(self):
        directory = self.root / 'docs/idea/ForgeFlow_ECP_完整开发规划/evidence'
        directory.mkdir(parents=True)
        (directory/'retained.json').write_text('history', encoding='utf-8')
        return directory

    def test_v3_git_uses_system_binary_with_fixed_path_and_no_inherited_hooks(self):
        fake_bin = self.root.parent/'fake-bin'; fake_bin.mkdir()
        marker = self.root.parent/'path-git-ran'
        fake_git = fake_bin/'git'
        fake_git.write_text('#!/usr/bin/python3\nfrom pathlib import Path\n'
                            f'Path({str(marker)!r}).write_text("unexpected")\n')
        fake_git.chmod(0o755)
        hook_marker = self.root.parent/'fsmonitor-ran'
        hook = self.root.parent/'fsmonitor-hook'
        hook.write_text('#!/bin/sh\nprintf unexpected > ' + str(hook_marker) + '\n')
        hook.chmod(0o755)
        self.git('config', 'core.fsmonitor', str(hook))
        expected_home = os.environ.get('HOME')
        real_popen = subprocess.Popen
        invocations = []
        def observe(command, *args, **kwargs):
            if command and command[0] == '/usr/bin/git':
                invocations.append((command, dict(kwargs['env'])))
            return real_popen(command, *args, **kwargs)
        hostile = {'PATH':str(fake_bin), 'GIT_DIR':'/invalid-fixture-git-dir',
                   'GIT_INDEX_FILE':'/invalid-fixture-index', 'GIT_CONFIG_GLOBAL':'/invalid-fixture-config',
                   'GIT_CONFIG_COUNT':'1', 'GIT_CONFIG_KEY_0':'core.fsmonitor',
                   'GIT_CONFIG_VALUE_0':str(hook), 'GIT_EXTERNAL_DIFF':'/invalid-fixture-diff',
                   'GIT_ASKPASS':'/invalid-fixture-askpass', 'LD_PRELOAD':'/invalid-fixture-library',
                   'LD_LIBRARY_PATH':'/invalid-fixture-library-dir', 'PYTHONPATH':'/invalid-fixture-python',
                   'BASH_ENV':'/invalid-fixture-bash', 'ENV':'/invalid-fixture-shell'}
        with patch.dict(os.environ, hostile), patch.object(source_snapshot.subprocess, 'Popen', side_effect=observe):
            manifest = source_snapshot.build_manifest_v3(self.root)
        self.assertEqual(manifest['worktree_state'], 'CLEAN')
        self.assertFalse(manifest['release_qualifiable'])
        self.assertFalse(marker.exists())
        self.assertFalse(hook_marker.exists())
        self.assertTrue(invocations)
        for command, environment in invocations:
            self.assertEqual(command[0], '/usr/bin/git')
            self.assertEqual(environment['PATH'], '/usr/bin:/bin')
            self.assertEqual(environment.get('HOME'), expected_home)
            self.assertEqual(environment['GIT_CONFIG_GLOBAL'], '/dev/null')
            self.assertEqual(environment['GIT_CONFIG_COUNT'], '5')
            self.assertEqual(environment['GIT_CONFIG_VALUE_0'], 'false')
            for name in ('GIT_DIR', 'GIT_INDEX_FILE', 'GIT_EXTERNAL_DIFF', 'GIT_ASKPASS',
                         'LD_PRELOAD', 'LD_LIBRARY_PATH', 'PYTHONPATH', 'BASH_ENV', 'ENV'):
                self.assertNotIn(name, environment)

    def test_v3_git_receives_no_caller_stdin(self):
        fake_bin = self.root.parent/'fake-bin'; fake_bin.mkdir()
        fake_git = fake_bin/'git'
        fake_git.write_text('#!/usr/bin/python3\nimport os\nos.write(1,b"EOF" if not os.read(0,1) else b"INPUT")\n')
        fake_git.chmod(0o755)
        with self.redirect_v3_git_for_fault_injection(fake_git):
            self.assertEqual(source_snapshot._v3_bounded_git(self.root, ['status'], 3), b'EOF')

    def test_v3_selector_initialization_failure_reaps_own_child(self):
        fake_bin = self.root.parent/'fake-bin'; fake_bin.mkdir()
        fake_git = fake_bin/'git'
        fake_git.write_text('#!/usr/bin/python3\nimport time\ntime.sleep(10)\n')
        fake_git.chmod(0o755)
        sentinel = subprocess.Popen(['/usr/bin/sleep', '10'], start_new_session=True)
        try:
            with self.redirect_v3_git_for_fault_injection(fake_git), \
                 patch.object(source_snapshot.selectors, 'DefaultSelector', side_effect=OSError('fixture selector failure')), \
                 patch.object(source_snapshot.os, 'killpg', wraps=os.killpg) as signal_group:
                with self.assertRaisesRegex(OSError, 'fixture selector failure'):
                    source_snapshot._v3_bounded_git(self.root, ['status'], 3)
                signal_group.assert_called_once()
                self.assertIsNone(sentinel.poll())
        finally:
            sentinel.terminate()
            sentinel.wait(timeout=3)

    def test_v3_signal_failure_reports_unknown_and_does_not_touch_unrelated_process(self):
        fake_bin = self.root.parent/'fake-bin'; fake_bin.mkdir()
        fake_git = fake_bin/'git'
        fake_git.write_text('#!/usr/bin/python3\nimport time\ntime.sleep(30)\n')
        fake_git.chmod(0o755)
        sentinel = subprocess.Popen(['/usr/bin/sleep', '30'], start_new_session=True)
        real_popen = subprocess.Popen
        started = []
        def spawn(command, *args, **kwargs):
            if command and command[0] == '/usr/bin/git':
                command = [str(fake_git), *command[1:]]
            process = real_popen(command, *args, **kwargs)
            started.append(process)
            return process
        try:
            with patch.object(source_snapshot.subprocess, 'Popen', side_effect=spawn), \
                 patch.object(source_snapshot.selectors, 'DefaultSelector', side_effect=OSError('fixture selector failure')), \
                 patch.object(source_snapshot.os, 'killpg', side_effect=PermissionError('fixture signal denied')):
                with self.assertRaisesRegex(RuntimeError, 'process termination could not be confirmed'):
                    source_snapshot._v3_bounded_git(self.root, ['status'], 3)
            self.assertEqual(len(started), 1)
            self.assertIsNone(started[0].poll())
            self.assertIsNone(sentinel.poll())
        finally:
            for process in [*started, sentinel]:
                if process.poll() is None:
                    os.killpg(process.pid, signal.SIGKILL)
                process.wait(timeout=3)

    def test_container_projection_binds_directories_and_preserves_v2(self):
        self.evidence()
        before = source_snapshot.build_manifest(self.root, source_snapshot.DEFAULT_EXCLUDES)
        v3 = source_snapshot.build_manifest_v3(self.root)
        self.assertEqual(before['schema_version'], 'forgeflow.ecp-source-manifest.v2')
        self.assertEqual(before['worktree_state'], 'DIRTY_UNFROZEN')
        self.assertEqual(v3['worktree_state'], 'CLEAN')
        self.assertFalse(v3['release_qualifiable'])
        projection = v3['directory_projection']
        rows = {r['path']: r for r in projection['directories']}
        self.assertEqual(rows['.']['origin'], 'source_root')
        self.assertEqual(rows['tracked']['origin'], 'git_ancestor')
        for path in ('docs', 'docs/idea', 'docs/idea/ForgeFlow_ECP_完整开发规划'):
            self.assertEqual(rows[path]['origin'], 'excluded_container')
        boundaries = {r['path']: r['excluded_by'] for r in projection['excluded_directory_boundaries']}
        self.assertEqual(boundaries['.git'], '.git/')
        self.assertEqual(boundaries['docs/idea/ForgeFlow_ECP_完整开发规划/evidence'],
                         'docs/idea/ForgeFlow_ECP_完整开发规划/evidence/')
        self.assertEqual(v3['untracked_business_files'], [])
        again = source_snapshot.build_manifest_v3(self.root)
        self.assertEqual(v3['manifest_sha256'], again['manifest_sha256'])
        self.assertEqual(v3['projection_sha256'], again['projection_sha256'])
        self.assertEqual(before['manifest_sha256'], source_snapshot.build_manifest(self.root, source_snapshot.DEFAULT_EXCLUDES)['manifest_sha256'])

    def test_empty_hidden_and_excluded_regular_sibling_are_business(self):
        evidence = self.evidence()
        parent = evidence.parent
        for kind in ('empty', 'hidden', 'excluded-file'):
            with self.subTest(kind=kind):
                if kind == 'empty': path = parent/'empty'; path.mkdir()
                elif kind == 'hidden': path = parent/'.business'; path.write_text('private')
                else:
                    # The registered cache boundary is valid for a directory;
                    # a regular file with that name is not an exclusion-only container.
                    path = parent/'__pycache__'
                    path.write_text('also prevents container status')
                    self.assertIsNone(source_snapshot.v3_excluded(
                        path.relative_to(self.root).as_posix(), 'file'))
                with self.assertRaisesRegex(ValueError, 'untracked business'):
                    source_snapshot.build_manifest_v3(self.root)
                if path.is_dir(): path.rmdir()
                else: path.unlink()

    def test_excluded_symlink_is_never_a_directory_boundary(self):
        parent = self.root/'docs/idea/ForgeFlow_ECP_完整开发规划'
        parent.mkdir(parents=True)
        (parent/'evidence').symlink_to(self.root/'tracked', target_is_directory=True)
        with self.assertRaisesRegex(ValueError, 'symlink'):
            source_snapshot.build_manifest_v3(self.root)

    def test_untracked_external_symlink_is_never_followed(self):
        outside = self.root.parent/'outside-secret'
        outside.write_bytes(b'outside-sensitive-bytes')
        (self.root/'payload').symlink_to(outside)
        real_read = os.read
        outside_reads = []
        def checked_read(fd, size):
            if os.path.realpath(f'/proc/self/fd/{fd}') == str(outside):
                outside_reads.append(fd)
            return real_read(fd, size)
        with patch.object(source_snapshot.os, 'read', side_effect=checked_read):
            with self.assertRaisesRegex(ValueError, 'untracked business file'):
                source_snapshot.build_manifest_v3(self.root)
        self.assertEqual(outside_reads, [])
        self.assertEqual(outside.read_bytes(), b'outside-sensitive-bytes')

    def test_symlink_root_and_ancestor_rejected(self):
        link = self.root.parent/'alias'; link.symlink_to(self.root, target_is_directory=True)
        with self.assertRaises(OSError):
            source_snapshot.build_manifest_v3(link)
        with self.assertRaises(OSError):
            source_snapshot.build_manifest_v3(link/'tracked')

    def test_swapped_root_ancestor_is_not_followed_during_walk(self):
        parent = self.root.parent/'ancestor'; source = parent/'source'; source.mkdir(parents=True)
        outside = self.root.parent/'outside'; (outside/'source').mkdir(parents=True)
        (outside/'source'/'secret').write_text('must not enumerate')
        parent.rename(self.root.parent/'moved-ancestor')
        parent.symlink_to(outside, target_is_directory=True)
        with self.assertRaises(OSError):
            source_snapshot._v3_scan_projection(source, set(), source_snapshot.V3_EXCLUDES,
                                                'VERIFIED', time.monotonic() + 5)

    def test_git_cwd_remains_pinned_when_root_ancestor_is_swapped(self):
        parent = self.root.parent/'git-parent'; source = parent/'source'; source.mkdir(parents=True)
        (source/'marker').write_text('SAFE')
        outside = self.root.parent/'git-outside'; (outside/'source').mkdir(parents=True)
        (outside/'source'/'marker').write_text('UNSAFE')
        fake_bin = self.root.parent/'fake-bin'; fake_bin.mkdir()
        fake_git = fake_bin/'git'
        fake_git.write_text('#!/usr/bin/python3\nprint(open("marker").read())\n', encoding='utf-8')
        fake_git.chmod(0o755)
        original_open = source_snapshot._v3_open_root
        swapped = False
        def racing_open(path):
            nonlocal swapped
            fd = original_open(path)
            if Path(path) == source and not swapped:
                swapped = True
                parent.rename(self.root.parent/'git-parent-moved')
                parent.symlink_to(outside, target_is_directory=True)
            return fd
        with self.redirect_v3_git_for_fault_injection(fake_git), \
             patch.dict(os.environ, {'PATH': str(fake_bin)}), \
             patch.object(source_snapshot, '_v3_open_root', side_effect=racing_open):
            result = source_snapshot._v3_bounded_git(source, ['status'], 3)
        self.assertTrue(swapped)
        self.assertEqual(result, b'SAFE\n')

    def test_unavailable_modes_are_null_without_promoting_qualification(self):
        with patch.object(source_snapshot, '_v3_mount_status', return_value=('UNAVAILABLE', '9p')):
            v3 = source_snapshot.build_manifest_v3(self.root)
        self.assertEqual(v3['directory_projection']['mode_availability'], 'UNAVAILABLE')
        self.assertTrue(all(row['mode'] is None for row in v3['directory_projection']['directories']))
        self.assertFalse(v3['release_qualifiable'])

    def test_opt_in_supplement_keeps_default_manifest_and_api_unchanged(self):
        actual = source_snapshot._build_manifest_v3_bounded
        captured = []
        def compare(*args, **kwargs):
            ordinary = actual(*args, **kwargs)
            detailed = actual(*args, **kwargs, _collect_supplement=True)
            captured.append(detailed)
            self.assertIs(type(ordinary), dict)
            self.assertEqual({k:v for k,v in ordinary.items() if k != 'created_at'},
                             {k:v for k,v in detailed[0].items() if k != 'created_at'})
            return ordinary
        with patch.object(source_snapshot, '_build_manifest_v3_bounded', side_effect=compare):
            result = source_snapshot.build_manifest_v3(self.root)
        self.assertIs(type(result), dict)
        self.assertEqual(len(captured), 1)
        manifest, rows, head, raw_index, flags = captured[0]
        self.assertEqual(head, manifest['head'])
        self.assertTrue(raw_index.endswith(b'\0'))
        self.assertTrue(flags.endswith(b'\0'))
        self.assertEqual([row['path'] for row in rows], ['tracked/build_probe.py'])
        data = (self.root/'tracked/build_probe.py').read_bytes()
        self.assertEqual(rows[0]['sha256'], hashlib.sha256(data).hexdigest())
        self.assertFalse(manifest['release_qualifiable'])

    def test_same_device_nested_bind_mount_is_rejected(self):
        nested = str(self.root / 'tracked')
        mountinfo = ('1 0 8:1 / / rw - ext4 /dev/test rw\n'
                     f'2 1 8:1 /parent {nested} rw - ext4 /dev/test rw\n')
        with patch.object(Path, 'read_text', return_value=mountinfo):
            with self.assertRaisesRegex(ValueError, 'nested mount'):
                source_snapshot._v3_mount_status(self.root)

    def test_race_between_scans_fails_closed(self):
        real_scan = source_snapshot._v3_scan_projection
        calls = 0
        def race(*args, **kwargs):
            nonlocal calls
            result = real_scan(*args, **kwargs)
            calls += 1
            if calls == 1:
                (self.root/'new-directory').mkdir()
            return result
        with patch.object(source_snapshot, '_v3_scan_projection', side_effect=race):
            with self.assertRaisesRegex(ValueError, 'changed'):
                source_snapshot.build_manifest_v3(self.root)

    def test_scan_budget_and_policy_are_fail_closed(self):
        with self.assertRaisesRegex(ValueError, 'fixed exclusion policy'):
            source_snapshot.build_manifest_v3(self.root, (*source_snapshot.V3_EXCLUDES, 'extra/'))
        with patch.object(source_snapshot, 'MAX_UNTRACKED_SCAN_ENTRIES', 1):
            with self.assertRaises(ValueError):
                source_snapshot.build_manifest_v3(self.root)
        with patch.object(source_snapshot, 'V3_MAX_SCAN_IDENTITY_BYTES', 1):
            with self.assertRaisesRegex(ValueError, 'identity budget'):
                source_snapshot.build_manifest_v3(self.root)
        with patch.object(source_snapshot, 'V3_MAX_JSON_BYTES', 1):
            with self.assertRaisesRegex(ValueError, 'maximum raw JSON bytes'):
                source_snapshot.build_manifest_v3(self.root)

    def test_hidden_index_flag_cannot_produce_v3(self):
        self.git('update-index', '--skip-worktree', 'tracked/build_probe.py')
        with self.assertRaisesRegex(ValueError, 'visibility flags'):
            source_snapshot.build_manifest_v3(self.root)

    def test_git_stat_shortcut_cannot_hide_changed_tracked_bytes(self):
        self.git('config', 'core.trustctime', 'false')
        self.git('config', 'core.checkstat', 'minimal')
        path = self.root/'tracked/build_probe.py'
        old = path.stat()
        old_ns = old.st_mtime_ns - 20_000_000_000
        os.utime(path, ns=(old_ns, old_ns))
        self.git('update-index', '--refresh')
        before = path.stat()
        original = path.read_bytes()
        path.write_bytes(bytes((original[0] ^ 1,)) + original[1:])
        os.utime(path, ns=(before.st_atime_ns, before.st_mtime_ns))
        self.assertEqual(self.git('status', '--porcelain'), b'')
        with self.assertRaisesRegex(ValueError, 'bytes differ'):
            source_snapshot.build_manifest_v3(self.root)

    def test_v3_ignores_inherited_git_and_interpreter_overrides(self):
        expected = self.git('rev-parse', 'HEAD').decode('ascii').strip()
        other = self.root.parent/'other'; other.mkdir()
        subprocess.run(['git', 'init', '-q', str(other)], check=True)
        environment = {'GIT_DIR': str(other/'.git'), 'GIT_WORK_TREE': str(other),
                       'GIT_INDEX_FILE': str(other/'hostile-index'),
                       'GIT_CONFIG_COUNT': '1', 'GIT_CONFIG_KEY_0': 'core.fsmonitor',
                       'GIT_CONFIG_VALUE_0': '/nonexistent/hostile-hook',
                       'PYTHONPATH': '/nonexistent/hostile-python', 'LD_PRELOAD': '/nonexistent/hostile.so'}
        with patch.dict(os.environ, environment):
            value = source_snapshot.build_manifest_v3(self.root)
        self.assertEqual(value['head'], expected)
        self.assertEqual(value['worktree_state'], 'CLEAN')
        self.assertFalse(value['release_qualifiable'])

    def test_git_plumbing_does_not_run_local_fsmonitor_diff_or_filter_hooks(self):
        attributes = self.root/'.gitattributes'
        attributes.write_text('tracked/*.py filter=trap diff=trap\n', encoding='utf-8')
        self.git('add', '.gitattributes')
        self.git('commit', '-qm', 'tracked attributes')
        marker = self.root.parent/'hook-ran'
        hook = self.root.parent/'hook.sh'
        hook.write_text('#!/bin/sh\nprintf invoked > "' + str(marker) + '"\nexit 0\n', encoding='utf-8')
        hook.chmod(0o755)
        for key in ('core.fsmonitor', 'diff.external', 'diff.trap.textconv',
                    'filter.trap.clean', 'filter.trap.process'):
            self.git('config', key, str(hook))
        # Establish that ordinary status invokes the configured fsmonitor.
        subprocess.run(['git', 'status', '--porcelain'], cwd=self.root, capture_output=True, check=False)
        self.assertTrue(marker.exists())
        marker.unlink()
        calls = []
        original = source_snapshot._v3_bounded_git
        def observe(root, args, timeout):
            calls.append(args[0])
            return original(root, args, timeout)
        with patch.object(source_snapshot, 'build_manifest', side_effect=AssertionError('v2 status must not run')), \
             patch.object(source_snapshot, '_v3_bounded_git', side_effect=observe):
            value = source_snapshot.build_manifest_v3(self.root)
        self.assertFalse(marker.exists())
        self.assertEqual(set(calls), {'rev-parse', 'ls-files', 'ls-tree'})
        self.assertEqual(value['worktree_state'], 'CLEAN')
        self.assertFalse(value['release_qualifiable'])

    def test_v3_rejects_staged_index_different_from_head(self):
        (self.root/'tracked/build_probe.py').write_text('new staged bytes\n', encoding='utf-8')
        self.git('add', 'tracked/build_probe.py')
        with self.assertRaisesRegex(ValueError, 'index differs from HEAD'):
            source_snapshot.build_manifest_v3(self.root)

    def test_v3_rejects_a_git_subdirectory_as_root(self):
        with self.assertRaisesRegex(ValueError, 'not the Git worktree root'):
            source_snapshot.build_manifest_v3(self.root/'tracked')

    def test_v3_cli_reports_observation_not_qualification(self):
        output = self.root.parent/'snapshot.json'
        completed = subprocess.run([sys.executable, str(ROOT/'ops/ecp/source_snapshot.py'),
                                    '--source-root', str(self.root), '--output', str(output),
                                    '--manifest-version', '3'], capture_output=True, text=True, check=False)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        import json
        value = json.loads(completed.stdout)
        self.assertEqual(value['status'], 'OBSERVED_NOT_GATE')
        self.assertEqual(value['qualification'], 'NOT_RUN')
        self.assertEqual(value['product_gate_effect'], 'NONE')
        self.assertFalse(value['release_qualifiable'])

    def test_v3_cli_records_git_failure_digest_without_exposing_stderr(self):
        import hashlib
        import json
        fake_bin = self.root.parent/'fake-bin'; fake_bin.mkdir()
        fake_git = fake_bin/'git'
        fake_git.write_text('#!/usr/bin/python3\nimport os,sys\nos.write(2,b"bad\\xffstderr")\nsys.exit(3)\n', encoding='utf-8')
        fake_git.chmod(0o755)
        output = self.root.parent/'snapshot.json'
        captured = io.StringIO()
        with self.redirect_v3_git_for_fault_injection(fake_git), contextlib.redirect_stdout(captured):
            code = source_snapshot.main(['--source-root', str(self.root), '--output', str(output),
                                         '--manifest-version', '3'])
        self.assertEqual(code, 10)
        value = json.loads(captured.getvalue())
        expected = b'bad\xffstderr'
        self.assertEqual(value['git_stderr_sha256'], hashlib.sha256(expected).hexdigest())
        self.assertEqual(value['git_stderr_bytes'], len(expected))
        self.assertTrue(value['git_stderr_complete'])
        self.assertFalse(value['git_stderr_truncated'])
        self.assertFalse(value['git_stderr_raw_persisted'])
        self.assertNotIn('git_stderr_base64', value)
        self.assertNotIn('bad', captured.getvalue())
        self.assertEqual(value['qualification'], 'NOT_RUN')
        self.assertEqual(value['product_gate_effect'], 'NONE')
        self.assertFalse(output.exists())

    def test_v3_cli_reports_real_git_failure_without_persisting_raw_stderr(self):
        import json
        invalid_root = self.root.parent/'not-a-git-repository'; invalid_root.mkdir()
        output = self.root.parent/'unavailable-snapshot.json'
        completed = subprocess.run([sys.executable, str(ROOT/'ops/ecp/source_snapshot.py'),
                                    '--source-root', str(invalid_root), '--output', str(output),
                                    '--manifest-version', '3'], capture_output=True, text=True,
                                   check=False, timeout=10)
        self.assertEqual(completed.returncode, 10)
        result = json.loads(completed.stdout)
        self.assertEqual(result['status'], 'FAIL')
        self.assertEqual(result['qualification'], 'NOT_RUN')
        self.assertEqual(result['product_gate_effect'], 'NONE')
        self.assertGreater(result['git_stderr_bytes'], 0)
        self.assertTrue(result['git_stderr_complete'])
        self.assertFalse(result['git_stderr_raw_persisted'])
        self.assertNotIn('fatal: not a git repository', completed.stdout)
        self.assertFalse(output.exists())

    def test_v3_cli_reports_unknown_git_termination_without_claiming_failure_or_stop(self):
        import json
        output = self.root.parent/'unknown-termination.json'
        captured = io.StringIO()
        with patch.object(source_snapshot, 'build_manifest_v3',
                          side_effect=RuntimeError('v3 Git process termination could not be confirmed')), \
             contextlib.redirect_stdout(captured):
            code = source_snapshot.main(['--source-root', str(self.root), '--output', str(output),
                                         '--manifest-version', '3'])
        result = json.loads(captured.getvalue())
        self.assertEqual((code, result['status'], result['qualification'], result['product_gate_effect']),
                         (20, 'INCONCLUSIVE', 'NOT_RUN', 'NONE'))
        self.assertIsNone(result['leader_reaped'])
        self.assertIsNone(result['descendants_terminated'])
        self.assertFalse(result['git_stream_complete'])
        self.assertIsNone(result['git_stream_truncated'])
        self.assertEqual(result['git_stream_reason'], 'termination_unconfirmed')
        self.assertFalse(output.exists())

    def test_v3_cli_propagates_real_unreaped_child_to_inconclusive(self):
        import json
        fake_bin = self.root.parent/'fake-bin'; fake_bin.mkdir()
        fake_git = fake_bin/'git'
        fake_git.write_text('#!/usr/bin/python3\nimport time\ntime.sleep(30)\n')
        fake_git.chmod(0o755)
        real_popen = subprocess.Popen; started = []
        def spawn(command, *args, **kwargs):
            if command and command[0] == '/usr/bin/git':
                command = [str(fake_git), *command[1:]]
            process = real_popen(command, *args, **kwargs)
            started.append(process)
            return process
        output = self.root.parent/'unreaped-child.json'; captured = io.StringIO()
        try:
            with patch.object(source_snapshot.subprocess, 'Popen', side_effect=spawn), \
                 patch.object(source_snapshot.selectors, 'DefaultSelector', side_effect=OSError('fixture selector failure')), \
                 patch.object(source_snapshot.os, 'killpg', side_effect=PermissionError('fixture signal denied')), \
                 contextlib.redirect_stdout(captured):
                code = source_snapshot.main(['--source-root', str(self.root), '--output', str(output),
                                             '--manifest-version', '3'])
            result = json.loads(captured.getvalue())
            self.assertEqual((code, result['status'], result['qualification'], result['product_gate_effect']),
                             (20, 'INCONCLUSIVE', 'NOT_RUN', 'NONE'))
            self.assertIsNone(result['leader_reaped'])
            self.assertIsNone(result['descendants_terminated'])
            self.assertFalse(result['git_stream_complete'])
            self.assertEqual(len(started), 1)
            self.assertIsNone(started[0].poll())
            self.assertFalse(output.exists())
        finally:
            for process in started:
                if process.poll() is None:
                    os.killpg(process.pid, signal.SIGKILL)
                process.wait(timeout=3)

    def test_unrelated_and_v2_runtime_errors_keep_legacy_failure_status(self):
        import json
        cases = [('3', 'build_manifest_v3', 'different runtime error'),
                 ('2', 'build_manifest', 'v3 Git process termination could not be confirmed')]
        for version, function, message in cases:
            with self.subTest(version=version), tempfile.TemporaryDirectory() as directory:
                output = Path(directory)/'output.json'; captured = io.StringIO()
                with patch.object(source_snapshot, function, side_effect=RuntimeError(message)), \
                     contextlib.redirect_stdout(captured):
                    code = source_snapshot.main(['--source-root', str(self.root), '--output', str(output),
                                                 '--manifest-version', version])
                result = json.loads(captured.getvalue())
                self.assertEqual((code, result['status']), (10, 'FAIL'))
                self.assertNotIn('leader_reaped', result)
                self.assertFalse(output.exists())

    def test_v3_cli_timeout_reports_incomplete_stream_without_guessing_truncation(self):
        import json
        fake_bin = self.root.parent/'fake-bin'; fake_bin.mkdir()
        fake_git = fake_bin/'git'
        fake_git.write_text('#!/usr/bin/python3\nimport time\ntime.sleep(10)\n', encoding='utf-8')
        fake_git.chmod(0o755)
        output = self.root.parent/'snapshot.json'
        captured = io.StringIO()
        with self.redirect_v3_git_for_fault_injection(fake_git), \
             patch.dict(os.environ, {'ECP_SOURCE_SNAPSHOT_TIMEOUT_SECONDS':'0.2'}), \
             contextlib.redirect_stdout(captured):
            code = source_snapshot.main(['--source-root', str(self.root), '--output', str(output),
                                         '--manifest-version', '3'])
        self.assertEqual(code, 10)
        value = json.loads(captured.getvalue())
        self.assertFalse(value['git_stream_complete'])
        self.assertIsNone(value['git_stream_truncated'])
        self.assertEqual(value['git_stream_reason'], 'timeout')
        self.assertFalse(output.exists())

    def test_tracked_swap_after_hash_is_rejected_even_when_git_status_is_clean(self):
        self.git('config', 'core.trustctime', 'false')
        self.git('config', 'core.checkstat', 'minimal')
        path = self.root/'tracked/build_probe.py'
        old_ns = path.stat().st_mtime_ns - 20_000_000_000
        os.utime(path, ns=(old_ns, old_ns))
        self.git('update-index', '--refresh')
        original = source_snapshot._v3_verify_index_bytes
        def mutate_after_hash(*args, **kwargs):
            signatures = original(*args, **kwargs)
            before = path.stat()
            data = path.read_bytes()
            path.write_bytes(bytes((data[0] ^ 1,)) + data[1:])
            os.utime(path, ns=(before.st_atime_ns, before.st_mtime_ns))
            self.assertEqual(self.git('status', '--porcelain'), b'')
            return signatures
        with patch.object(source_snapshot, '_v3_verify_index_bytes', side_effect=mutate_after_hash):
            with self.assertRaisesRegex(ValueError, 'changed after blob verification'):
                source_snapshot.build_manifest_v3(self.root)

    def test_replaced_then_restored_source_root_cannot_hide_dirty_original(self):
        clean = self.root.parent/'clean-copy'
        parked = self.root.parent/'parked-source'
        subprocess.run(['git', 'clone', '-q', str(self.root), str(clean)], check=True)
        (self.root/'tracked/build_probe.py').write_text('changed original\n')
        self.assertTrue(self.git('status', '--porcelain'))
        head = source_snapshot._v3_head_index
        recheck = source_snapshot._v3_recheck_tracked_signatures
        switched = False
        def switch(*args, **kwargs):
            nonlocal switched
            if not switched:
                self.root.rename(parked)
                clean.rename(self.root)
                switched = True
            return head(*args, **kwargs)
        def restore(*args, **kwargs):
            nonlocal switched
            value = recheck(*args, **kwargs)
            self.root.rename(clean)
            parked.rename(self.root)
            switched = False
            return value
        try:
            with patch.object(source_snapshot, '_v3_head_index', side_effect=switch), \
                 patch.object(source_snapshot, '_v3_recheck_tracked_signatures', side_effect=restore):
                with self.assertRaises(ValueError):
                    source_snapshot.build_manifest_v3(self.root)
        finally:
            if switched:
                self.root.rename(clean)
                parked.rename(self.root)
        self.assertTrue(self.git('status', '--porcelain'))

    def test_index_temporarily_changed_during_blob_check_is_rejected(self):
        path = self.root/'tracked/build_probe.py'
        path.write_text('changed original\n')
        alternate = self.root.parent/'alternate-index'
        env = dict(os.environ, GIT_INDEX_FILE=str(alternate))
        subprocess.run(['git', 'read-tree', 'HEAD'], cwd=self.root, env=env, check=True)
        subprocess.run(['git', 'add', 'tracked/build_probe.py'], cwd=self.root, env=env, check=True)
        index_path = self.root/'.git/index'
        original = index_path.read_bytes()
        changed = alternate.read_bytes()
        self.assertNotEqual(original, changed)
        verify = source_snapshot._v3_verify_index_bytes
        invoked = False
        def swap_index(*args, **kwargs):
            nonlocal invoked
            invoked = True
            index_path.write_bytes(changed)
            try:
                return verify(*args, **kwargs)
            finally:
                index_path.write_bytes(original)
        with patch.object(source_snapshot, '_v3_verify_index_bytes', side_effect=swap_index):
            with self.assertRaises(ValueError):
                source_snapshot.build_manifest_v3(self.root)
        self.assertTrue(invoked)
        self.assertEqual(index_path.read_bytes(), original)
        self.assertTrue(self.git('status', '--porcelain'))

    def test_tracked_executable_must_be_executable_by_owner(self):
        path = self.root/'tracked/build_probe.py'
        path.chmod(0o755)
        self.git('add', 'tracked/build_probe.py')
        self.git('commit', '-qm', 'executable')
        for mode in (0o654, 0o645, 0o611):
            with self.subTest(mode=oct(mode)):
                path.chmod(mode)
                self.assertTrue(self.git('status', '--porcelain'))
                with self.assertRaises(ValueError):
                    source_snapshot.build_manifest_v3(self.root)

    def test_git_worktree_must_match_the_observed_source_root(self):
        other = self.root.parent/'different-worktree'
        other.mkdir()
        self.git('config', 'core.worktree', str(other))
        with self.assertRaises(ValueError):
            source_snapshot.build_manifest_v3(self.root)

    def test_v3_root_context_is_restored_and_fd_closed_on_error(self):
        descriptors = []
        def fail_after_capture(root, *args):
            expected, fd = source_snapshot._V3_PINNED_ROOT.get()
            self.assertEqual(expected, str(root))
            os.fstat(fd)
            descriptors.append(fd)
            raise RuntimeError('injected failure')
        before = source_snapshot._V3_PINNED_ROOT.get()
        with patch.object(source_snapshot, '_build_manifest_v3_bounded', side_effect=fail_after_capture):
            with self.assertRaisesRegex(RuntimeError, 'injected failure'):
                source_snapshot.build_manifest_v3(self.root)
        self.assertIs(source_snapshot._V3_PINNED_ROOT.get(), before)
        self.assertEqual(len(descriptors), 1)
        with self.assertRaises(OSError):
            os.fstat(descriptors[0])

    def test_v3_root_context_is_nested_and_thread_local(self):
        from concurrent.futures import ThreadPoolExecutor
        from threading import Barrier
        other = self.root.parent/'second-root'
        other.mkdir()
        barrier = Barrier(2)
        def check_concurrent(root, *args):
            expected, fd = source_snapshot._V3_PINNED_ROOT.get()
            barrier.wait(timeout=5)
            self.assertEqual(expected, str(root))
            self.assertEqual(os.fstat(fd).st_ino, root.stat().st_ino)
            return expected
        with patch.object(source_snapshot, '_build_manifest_v3_bounded', side_effect=check_concurrent):
            with ThreadPoolExecutor(max_workers=2) as pool:
                futures = [pool.submit(source_snapshot.build_manifest_v3, root) for root in (self.root, other)]
                self.assertEqual({f.result(timeout=10) for f in futures}, {str(self.root), str(other)})
        outer_fd = []
        def check_nested(root, *args):
            expected, fd = source_snapshot._V3_PINNED_ROOT.get()
            self.assertEqual(expected, str(root))
            if root == self.root:
                outer_fd.append(fd)
                self.assertEqual(source_snapshot.build_manifest_v3(other), str(other))
                self.assertEqual(source_snapshot._V3_PINNED_ROOT.get(), (str(self.root), fd))
                os.fstat(fd)
            return expected
        with patch.object(source_snapshot, '_build_manifest_v3_bounded', side_effect=check_nested):
            self.assertEqual(source_snapshot.build_manifest_v3(self.root), str(self.root))
        with self.assertRaises(OSError):
            os.fstat(outer_fd[0])

    def test_tracked_blob_limits_fail_closed(self):
        with patch.object(source_snapshot, 'V3_MAX_TRACKED_FILE_BYTES', 1):
            with self.assertRaisesRegex(ValueError, 'tracked bytes exceed'):
                source_snapshot.build_manifest_v3(self.root)
        with patch.object(source_snapshot, 'V3_MAX_GIT_METADATA_BYTES', 1):
            with self.assertRaisesRegex(ValueError, 'bounded stream budget'):
                source_snapshot.build_manifest_v3(self.root)

    def test_v3_git_streams_are_capped_while_v2_git_is_unchanged(self):
        fake_bin = self.root.parent/'fake-bin'; fake_bin.mkdir()
        fake_git = fake_bin/'git'
        fake_git.write_text('#!/usr/bin/python3\nimport os,sys\n'
                            'fd = 2 if "stderr" in sys.argv else 1\n'
                            'os.write(fd, b"x" * 2048)\n', encoding='utf-8')
        fake_git.chmod(0o755)
        with self.redirect_v3_git_for_fault_injection(fake_git), \
             patch.dict(os.environ, {'PATH': str(fake_bin)}), \
             patch.object(source_snapshot, 'V3_MAX_GIT_METADATA_BYTES', 1024):
            self.assertEqual(len(source_snapshot.run_git(self.root, ['stdout'])), 2048)
            with self.assertRaisesRegex(ValueError, 'bounded stream budget'):
                source_snapshot.build_manifest_v3(self.root)
            with self.assertRaisesRegex(ValueError, 'bounded stream budget'):
                source_snapshot._v3_bounded_git(self.root, ['stdout'], 2)
        fake_git.write_text('#!/usr/bin/python3\nimport os\nos.write(2, b"e" * 65537)\n', encoding='utf-8')
        with self.redirect_v3_git_for_fault_injection(fake_git), patch.dict(os.environ, {'PATH': str(fake_bin)}):
            with self.assertRaisesRegex(ValueError, 'bounded stream budget'):
                source_snapshot._v3_bounded_git(self.root, ['stderr'], 2)
        fake_git.write_text('#!/usr/bin/python3\nimport sys\nsys.exit(2)\n', encoding='utf-8')
        with self.redirect_v3_git_for_fault_injection(fake_git), \
             patch.dict(os.environ, {'PATH': str(fake_bin)}), patch.object(source_snapshot.os, 'killpg') as kill:
            with self.assertRaises(subprocess.CalledProcessError):
                source_snapshot._v3_bounded_git(self.root, ['fail'], 2)
            kill.assert_not_called()

    def test_every_v3_git_plumbing_command_is_capped(self):
        fake_bin = self.root.parent/'fake-bin'; fake_bin.mkdir()
        fake_git = fake_bin/'git'
        fake_git.write_text('#!/usr/bin/python3\nimport os,sys\n'
                            'if sys.argv[1:3] == ["rev-parse", "--show-prefix"]: os.write(1, b"\\n")\n'
                            'elif sys.argv[1:3] == ["rev-parse", "--show-toplevel"]: os.write(1, os.fsencode(os.getcwd()) + b"\\n")\n'
                            'elif sys.argv[1] == "rev-parse": os.write(1, b"a"*40 + b"\\n")\n'
                            'else: os.write(1, b"x"*2048)\n', encoding='utf-8')
        fake_git.chmod(0o755)
        with self.redirect_v3_git_for_fault_injection(fake_git), \
             patch.dict(os.environ, {'PATH': str(fake_bin)}), \
             patch.object(source_snapshot, 'V3_MAX_GIT_METADATA_BYTES', 1024):
            with self.assertRaisesRegex(ValueError, 'bounded stream budget'):
                source_snapshot.build_manifest_v3(self.root)

    def test_v3_git_timeout_terminates_only_its_own_process_group(self):
        fake_bin = self.root.parent/'fake-bin'; fake_bin.mkdir()
        fake_git = fake_bin/'git'; child_pid_path = self.root.parent/'child.pid'
        fake_git.write_text('#!/usr/bin/python3\nimport os,sys,time\n'
                            'child=os.fork()\n'
                            'if child == 0:\n time.sleep(30); os._exit(0)\n'
                            'open(sys.argv[1], "w").write(str(child))\n'
                            'time.sleep(30)\n', encoding='utf-8')
        fake_git.chmod(0o755)
        unrelated = subprocess.Popen(['/usr/bin/sleep', '10'], start_new_session=True)
        try:
            with self.redirect_v3_git_for_fault_injection(fake_git), patch.dict(os.environ, {'PATH': str(fake_bin)}):
                with self.assertRaises(subprocess.TimeoutExpired):
                    source_snapshot._v3_bounded_git(self.root, [str(child_pid_path)], 0.4)
            self.assertTrue(child_pid_path.is_file())
            child_pid = int(child_pid_path.read_text())
            deadline = time.monotonic() + 2
            while time.monotonic() < deadline:
                proc_stat = Path(f'/proc/{child_pid}/stat')
                if not proc_stat.exists() or proc_stat.read_text().split()[2] == 'Z':
                    break
                time.sleep(0.02)
            else:
                self.fail('owned Git descendant is still running after timeout')
            self.assertIsNone(unrelated.poll())
        finally:
            unrelated.terminate()
            unrelated.wait(timeout=3)

    def test_v3_total_deadline_prevents_late_git_and_source_reads(self):
        deadline = source_snapshot._V3_TOTAL_DEADLINE.set(time.monotonic() - 1)
        try:
            self.assertEqual(source_snapshot._bounded_timeout(), 0.0)
            with patch.object(source_snapshot.subprocess, 'Popen') as spawn:
                with self.assertRaises(subprocess.TimeoutExpired):
                    source_snapshot._v3_bounded_git(self.root, ['status'], source_snapshot._bounded_timeout())
                spawn.assert_not_called()
            with patch.object(source_snapshot.os, 'scandir') as scan:
                with self.assertRaises(TimeoutError):
                    source_snapshot._v3_scan_projection(self.root, set(), source_snapshot.V3_EXCLUDES,
                                                        'VERIFIED', time.monotonic() - 1)
                scan.assert_not_called()
        finally:
            source_snapshot._V3_TOTAL_DEADLINE.reset(deadline)

    def test_projected_modes_and_digests_bind_changes(self):
        self.evidence()
        before = source_snapshot.build_manifest_v3(self.root)
        (self.root/'docs/idea').chmod(0o700)
        after = source_snapshot.build_manifest_v3(self.root)
        if before['directory_projection']['mode_availability'] == 'VERIFIED':
            self.assertNotEqual(before['projection_sha256'], after['projection_sha256'])
            self.assertNotEqual(before['manifest_sha256'], after['manifest_sha256'])
        self.assertFalse(after['release_qualifiable'])


if __name__ == '__main__':
    unittest.main()
