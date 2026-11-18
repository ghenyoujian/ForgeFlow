from __future__ import annotations

import copy
import errno
import hashlib
import os
from pathlib import Path
import stat
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'ops/ecp'))
import normalized_materialize as materializer
import normalized_policy as policy_lib
import normalized_source
import source_snapshot as snapshot


class DraftMaterializerTests(unittest.TestCase):
    def setUp(self):
        prior = os.umask(0o077)
        self.addCleanup(os.umask, prior)
        self.temp = tempfile.TemporaryDirectory(prefix='ecp-norm-materialize-')
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.source = self.base/'source'; self.source.mkdir()
        self.parent = self.base/'private'; self.parent.mkdir(mode=0o700)
        self.candidate = self.parent/'candidate'
        self.git('init', '-q')
        (self.source/'data').mkdir()
        (self.source/'data/value.txt').write_bytes(b'fixture text\n')
        (self.source/'run.sh').write_bytes(b'#!/bin/sh\nexit 0\n')
        (self.source/'run.sh').chmod(0o755)
        (self.source/'link').symlink_to('data/value.txt')
        self.git('add', '.')
        self.git('-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid', 'commit', '-qm', 'fixture')
        actual_mount = snapshot._v3_mount_status
        def mode_status(path):
            if Path(path) == self.source:
                return ('UNAVAILABLE', ('fixture', 'fixture'))
            return actual_mount(path)
        self.mount = patch.object(snapshot, '_v3_mount_status', side_effect=mode_status)
        self.mount.start(); self.addCleanup(self.mount.stop)
        self.manifest = snapshot.build_manifest_v3(self.source)
        self.supplement = normalized_source.observe_source(self.source, self.manifest, self.manifest['manifest_sha256'])
        directories = {row['path']: ('0700' if row['path'] == '.' else '0750') for row in self.supplement['directories']}
        files = {row['path']: ('0750' if row['git_mode'] == '100755' else '0640')
                 for row in self.supplement['entries'] if row['kind'] == 'file'}
        self.policy = policy_lib.build_policy(self.manifest, self.supplement, directory_modes=directories,
            file_modes=files, uid=os.geteuid(), gid=os.getegid(),
            attributes={'access_acl': 'ABSENT', 'default_acl': 'ABSENT', 'xattrs': 'NONE',
                        'hardlinks': 'REJECT', 'symlinks': 'INTERNAL_PROJECTION_ONLY', 'umask': '0077'},
            limits={'max_entries': 100, 'max_file_bytes': 4096, 'max_total_bytes': 8192, 'max_depth': 16})
        self.manifest_sha = self.manifest['manifest_sha256']
        self.supplement_sha = policy_lib.canonical_sha256(self.supplement)
        self.policy_sha = policy_lib.canonical_sha256(self.policy)

    def git(self, *args):
        return subprocess.run(['/usr/bin/git', *args], cwd=self.source, check=True,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE).stdout

    def run_materializer(self, **overrides):
        args = {'manifest_sha256': self.manifest_sha, 'supplement_sha256': self.supplement_sha,
                'policy_sha256': self.policy_sha, 'candidate_root': self.candidate}
        args.update(overrides)
        return materializer.materialize_draft(self.source, self.manifest, self.supplement, self.policy, **args)

    def test_small_fixture_is_materialized_with_explicit_modes_without_gate(self):
        before = self.git('status', '--porcelain')
        result = self.run_materializer()
        self.assertEqual((result['status'], result['qualification'], result['product_gate_effect']),
                         ('OBSERVED_NOT_GATE', 'NOT_RUN', 'NONE'))
        self.assertEqual(result['source_permissions_preserved'], 'UNKNOWN')
        self.assertIn('successful fsync calls do not prove crash or power-loss durability', result['limitations'])
        self.assertIn('experimental source observation may use two fused scans with one fewer intermediate sample than the older implementation; atomic or continuous invariance is not proven', result['limitations'])
        self.assertIn('all file and directory fsync calls returned', result['sync_observation'])
        self.assertEqual(result['continuous_sync_identity'], 'UNKNOWN')
        self.assertEqual((self.candidate/'data/value.txt').read_bytes(), b'fixture text\n')
        self.assertEqual(os.readlink(self.candidate/'link'), 'data/value.txt')
        self.assertEqual(stat.S_IMODE(self.candidate.stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE((self.candidate/'data').stat().st_mode), 0o750)
        self.assertEqual(stat.S_IMODE((self.candidate/'data/value.txt').stat().st_mode), 0o640)
        self.assertEqual(stat.S_IMODE((self.candidate/'run.sh').stat().st_mode), 0o750)
        self.assertEqual(self.git('status', '--porcelain'), before)
        self.assertEqual(list(self.parent.glob('.forgeflow-draft-*')), [])

    def test_bad_pin_and_existing_destination_never_modify_target(self):
        with self.assertRaises((ValueError, materializer.DraftIncomplete)):
            self.run_materializer(supplement_sha256='0'*64)
        self.assertFalse(self.candidate.exists())
        self.candidate.mkdir(); sentinel = self.candidate/'sentinel'; sentinel.write_text('preserve')
        with self.assertRaises(FileExistsError):
            self.run_materializer()
        self.assertEqual(sentinel.read_text(), 'preserve')

    def test_each_file_and_directory_are_synced_before_rename_and_parent_after(self):
        sync = os.fsync
        rename = materializer._rename_noreplace
        events = []
        def record(fd):
            events.append(('sync', os.readlink(f'/proc/self/fd/{fd}')))
            return sync(fd)
        def record_rename(*args):
            events.append(('rename', ''))
            return rename(*args)
        with patch.object(materializer.os, 'fsync', side_effect=record), patch.object(materializer, '_rename_noreplace', side_effect=record_rename):
            self.run_materializer()
        point = events.index(('rename', ''))
        before = [path for kind, path in events[:point] if kind == 'sync']
        after = [path for kind, path in events[point+1:] if kind == 'sync']
        stage = next(p for p in before if p.endswith('/data/value.txt')).rsplit('/data/value.txt', 1)[0]
        for path in (stage+'/data/value.txt', stage+'/run.sh', stage+'/data', stage, str(self.parent)):
            self.assertEqual(before.count(path), 1, path)
        self.assertEqual(after.count(str(self.parent)), 1)
        self.assertLess(before.index(stage+'/data'), before.index(stage))

    def test_reopened_file_replacement_is_rejected_and_retained(self):
        original = materializer._sync_batch
        def replace(stage_fd, pending, end, synced_files):
            if pending:
                row, _ = pending[0]
                parent_fd, name = materializer._parent(stage_fd, row['path'])
                try:
                    os.unlink(name, dir_fd=parent_fd)
                    fd = os.open(name, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600, dir_fd=parent_fd)
                    os.close(fd)
                finally:
                    os.close(parent_fd)
            return original(stage_fd, pending, end, synced_files)
        with patch.object(materializer, '_sync_batch', side_effect=replace):
            with self.assertRaises(materializer.DraftRetained) as ctx:
                self.run_materializer()
        self.assertTrue(Path(ctx.exception.stage_path).is_dir())
        self.assertFalse(self.candidate.exists())

    def test_fsynced_file_replaced_by_identical_inode_is_detected(self):
        original = materializer._sync_directories
        def replace(stage_fd, directories, end):
            parent_fd, name = materializer._parent(stage_fd, 'data/value.txt')
            try:
                fd = os.open('replacement', os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600, dir_fd=parent_fd)
                try:
                    os.write(fd, b'fixture text\n')
                    os.fchmod(fd, 0o640)
                finally:
                    os.close(fd)
                os.rename('replacement', name, src_dir_fd=parent_fd, dst_dir_fd=parent_fd)
            finally:
                os.close(parent_fd)
            return original(stage_fd, directories, end)
        with patch.object(materializer, '_sync_directories', side_effect=replace):
            with self.assertRaises(materializer.DraftRetained):
                self.run_materializer()
        self.assertFalse(self.candidate.exists())

    def test_replacement_after_stage_inventory_is_publication_uncertain(self):
        original = materializer._inventory
        calls = 0
        def replace_after(stage_fd, *args, **kwargs):
            nonlocal calls
            value = original(stage_fd, *args, **kwargs)
            calls += 1
            if calls == 1:
                parent_fd, name = materializer._parent(stage_fd, 'data/value.txt')
                try:
                    fd = os.open('replacement', os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600, dir_fd=parent_fd)
                    try:
                        os.write(fd, b'fixture text\n')
                        os.fchmod(fd, 0o640)
                    finally:
                        os.close(fd)
                    os.rename('replacement', name, src_dir_fd=parent_fd, dst_dir_fd=parent_fd)
                finally:
                    os.close(parent_fd)
            return value
        with patch.object(materializer, '_inventory', side_effect=replace_after):
            with self.assertRaises(materializer.DraftPublicationUncertain):
                self.run_materializer()
        self.assertTrue(self.candidate.exists())

    def test_sync_failures_keep_pre_and_post_publish_state(self):
        sync = os.fsync
        for fail in ('file', 'directory', 'parent_before', 'parent_after'):
            with self.subTest(fail=fail):
                calls = 0
                def failing(fd):
                    nonlocal calls
                    path = os.readlink(f'/proc/self/fd/{fd}')
                    is_parent = path == str(self.parent)
                    if is_parent:
                        calls += 1
                    if ((fail == 'file' and path.endswith('/data/value.txt')) or
                        (fail == 'directory' and path.endswith('/data')) or
                        (fail == 'parent_before' and is_parent and calls == 1) or
                        (fail == 'parent_after' and is_parent and calls == 2)):
                        raise OSError('injected sync failure')
                    return sync(fd)
                with tempfile.TemporaryDirectory(dir=self.base) as isolated:
                    old_parent, old_candidate = self.parent, self.candidate
                    self.parent = Path(isolated); self.parent.chmod(0o700)
                    self.candidate = self.parent/'candidate'
                    try:
                        with patch.object(materializer.os, 'fsync', side_effect=failing):
                            expected = materializer.DraftPublicationUncertain if fail == 'parent_after' else materializer.DraftRetained
                            with self.assertRaises(expected):
                                self.run_materializer()
                        self.assertEqual(self.candidate.exists(), fail == 'parent_after')
                        self.assertTrue(any(self.parent.iterdir()))
                    finally:
                        self.parent, self.candidate = old_parent, old_candidate

    def test_batch_bound_and_one_reopened_file_at_a_time(self):
        fd = os.open(self.parent, os.O_RDONLY | os.O_DIRECTORY)
        self.addCleanup(os.close, fd)
        pending = []
        for i in range(9):
            name = f'f{i}'
            data = name.encode()
            (self.parent/name).write_bytes(data)
            pending.append(({'path': name, 'size': len(data), 'sha256': hashlib.sha256(data).hexdigest()}, materializer._sig((self.parent/name).stat())))
        with self.assertRaises(ValueError):
            materializer._sync_batch(fd, pending, materializer.time.monotonic()+5)
        open_files = []
        original_sync = os.fsync
        def record(current):
            actual = [p for p in Path('/proc/self/fd').iterdir() if p.exists() and p.resolve().parent == self.parent and p.resolve().is_file()]
            open_files.append(len(actual))
            return original_sync(current)
        with patch.object(materializer.os, 'fsync', side_effect=record):
            first = pending[:8]
            materializer._sync_batch(fd, first, materializer.time.monotonic()+5)
            last = pending[8:]
            materializer._sync_batch(fd, last, materializer.time.monotonic()+5)
        self.assertEqual(open_files, [1]*9)
        self.assertEqual((first, last), ([], []))

    def test_multiple_batches_include_every_real_file(self):
        for i in range(17):
            (self.source/f'added-{i:02d}').write_bytes(f'file-{i}'.encode())
        self.git('add', '.')
        self.git('-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid', 'commit', '-qm', 'more files')
        self.manifest = snapshot.build_manifest_v3(self.source)
        self.supplement = normalized_source.observe_source(self.source, self.manifest, self.manifest['manifest_sha256'])
        directories = {row['path']: ('0700' if row['path'] == '.' else '0750') for row in self.supplement['directories']}
        files = {row['path']: ('0750' if row['git_mode'] == '100755' else '0640') for row in self.supplement['entries'] if row['kind'] == 'file'}
        self.policy = policy_lib.build_policy(self.manifest, self.supplement, directory_modes=directories,
            file_modes=files, uid=os.geteuid(), gid=os.getegid(),
            attributes={'access_acl': 'ABSENT', 'default_acl': 'ABSENT', 'xattrs': 'NONE', 'hardlinks': 'REJECT', 'symlinks': 'INTERNAL_PROJECTION_ONLY', 'umask': '0077'},
            limits={'max_entries': 100, 'max_file_bytes': 4096, 'max_total_bytes': 8192, 'max_depth': 16})
        self.manifest_sha = self.manifest['manifest_sha256']
        self.supplement_sha = policy_lib.canonical_sha256(self.supplement)
        self.policy_sha = policy_lib.canonical_sha256(self.policy)
        original = materializer._sync_batch
        batches = []
        def record(stage_fd, pending, end, synced_files):
            batches.append([row['path'] for row, _ in pending])
            return original(stage_fd, pending, end, synced_files)
        with patch.object(materializer, '_sync_batch', side_effect=record):
            self.run_materializer()
        self.assertEqual([len(batch) for batch in batches], [8, 8, 3])
        self.assertEqual(set(sum(batches, [])), set(files))

    def test_no_replace_race_retains_both_unrelated_destination_and_stage(self):
        actual = materializer._rename_noreplace
        def race(parent_fd, stage, name):
            os.mkdir(name, 0o700, dir_fd=parent_fd)
            sentinel = os.open(name+'/sentinel', os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600, dir_fd=parent_fd)
            try:
                os.write(sentinel, b'unrelated')
            finally:
                os.close(sentinel)
            return actual(parent_fd, stage, name)
        with patch.object(materializer, '_rename_noreplace', side_effect=race):
            with self.assertRaises(materializer.DraftPublicationUncertain) as ctx:
                self.run_materializer()
        self.assertEqual((self.candidate/'sentinel').read_bytes(), b'unrelated')
        self.assertTrue(Path(ctx.exception.stage_path).is_dir())

    def test_insecure_parent_and_wrong_umask_stop_before_staging(self):
        self.parent.chmod(0o755)
        with self.assertRaises(materializer.DraftIncomplete):
            self.run_materializer()
        self.parent.chmod(0o700)
        prior = os.umask(0o022)
        try:
            with self.assertRaises(materializer.DraftIncomplete):
                self.run_materializer()
        finally:
            os.umask(prior)
        self.assertEqual(list(self.parent.iterdir()), [])

    def test_changed_source_is_rejected_before_staging(self):
        (self.source/'data/value.txt').write_bytes(b'changed\n')
        with self.assertRaises((ValueError, materializer.DraftIncomplete)):
            self.run_materializer()
        self.assertEqual(list(self.parent.iterdir()), [])

    def test_source_swap_during_observation_cannot_hide_untracked_input(self):
        clean = self.base/'clean-clone'
        parked = self.base/'parked-source'
        subprocess.run(['/usr/bin/git', 'clone', '-q', str(self.source), str(clean)], check=True)
        (self.source/'untracked-business.py').write_text('unsafe = True\n')
        actual_observe = normalized_source.observe_source
        swaps = []
        def observe_replaced(*args, **kwargs):
            self.source.rename(parked)
            clean.rename(self.source)
            swaps.append(True)
            try:
                return actual_observe(*args, **kwargs)
            finally:
                self.source.rename(clean)
                parked.rename(self.source)
        with patch.object(normalized_source, 'observe_source', side_effect=observe_replaced):
            with self.assertRaises((ValueError, materializer.DraftIncomplete)):
                self.run_materializer()
        self.assertTrue(swaps)
        self.assertTrue((self.source/'untracked-business.py').exists())
        self.assertFalse(self.candidate.exists())

    def test_copy_failure_retains_owned_stage_without_publishing(self):
        with patch.object(materializer, '_copy_entry', side_effect=OSError('injected')):
            with self.assertRaises(materializer.DraftRetained) as ctx:
                self.run_materializer()
        self.assertTrue(Path(ctx.exception.stage_path).is_dir())
        self.assertFalse(self.candidate.exists())

    def test_stage_creation_may_succeed_before_error_and_is_not_claimed_or_cleaned(self):
        actual_mkdir = os.mkdir
        def create_then_raise(path, mode=0o777, *, dir_fd=None):
            if isinstance(path, str) and path.startswith('.forgeflow-draft-'):
                actual_mkdir(path, mode, dir_fd=dir_fd)
                raise OSError('injected after creation')
            return actual_mkdir(path, mode, dir_fd=dir_fd)
        with patch.object(materializer.os, 'mkdir', side_effect=create_then_raise):
            with self.assertRaises(materializer.DraftRetained) as ctx:
                self.run_materializer()
        self.assertEqual(ctx.exception.stage_attribution, 'UNCONFIRMED')
        self.assertTrue(Path(ctx.exception.stage_path).is_dir())
        self.assertFalse(self.candidate.exists())

    def test_post_publication_failure_preserves_candidate_and_uncertainty(self):
        inventory = materializer._inventory
        calls = 0
        def fail_after_publish(*args, **kwargs):
            nonlocal calls
            calls += 1
            if calls == 2:
                raise OSError('injected after rename')
            return inventory(*args, **kwargs)
        with patch.object(materializer, '_inventory', side_effect=fail_after_publish):
            with self.assertRaises(materializer.DraftPublicationUncertain) as ctx:
                self.run_materializer()
        self.assertEqual(ctx.exception.candidate_path, str(self.candidate))
        self.assertTrue((self.candidate/'data/value.txt').is_file())
        self.assertEqual((self.candidate/'data/value.txt').read_bytes(), b'fixture text\n')

    def test_cleanup_failure_after_publication_keeps_unknown_state(self):
        actual_exit = materializer.ExitStack.__exit__
        def fail_after_exit(stack, *args):
            result = actual_exit(stack, *args)
            if self.candidate.exists():
                raise OSError('injected descriptor cleanup failure')
            return result
        with patch.object(materializer.ExitStack, '__exit__', new=fail_after_exit):
            with self.assertRaises(materializer.DraftPublicationUncertain):
                self.run_materializer()
        self.assertEqual((self.candidate/'data/value.txt').read_bytes(), b'fixture text\n')

    def test_parent_swap_after_final_inventory_never_returns_success(self):
        replacement = self.base/'replacement-parent'
        replacement.mkdir(mode=0o700)
        (replacement/'candidate').mkdir()
        (replacement/'candidate'/'unrelated').write_text('preserve')
        parked = self.base/'parked-parent'
        actual_inventory = materializer._inventory
        calls = 0
        swapped = False
        def inspect_then_swap(*args, **kwargs):
            nonlocal calls, swapped
            value = actual_inventory(*args, **kwargs)
            calls += 1
            if calls == 2:
                self.parent.rename(parked)
                replacement.rename(self.parent)
                swapped = True
            return value
        try:
            with patch.object(materializer, '_inventory', side_effect=inspect_then_swap):
                with self.assertRaises(materializer.DraftPublicationUncertain):
                    self.run_materializer()
        finally:
            if swapped:
                self.parent.rename(replacement)
                parked.rename(self.parent)
        self.assertTrue(swapped)
        self.assertEqual((replacement/'candidate'/'unrelated').read_text(), 'preserve')
        self.assertEqual((self.candidate/'data/value.txt').read_bytes(), b'fixture text\n')

    def test_external_hardlink_is_rejected_and_not_cleaned(self):
        original = materializer._inventory
        outsider = self.base/'external-link'
        calls = 0
        def attach(stage_fd, *args, **kwargs):
            nonlocal calls
            calls += 1
            if calls == 1:
                os.link(f'/proc/self/fd/{stage_fd}/data/value.txt', outsider, follow_symlinks=False)
            return original(stage_fd, *args, **kwargs)
        with patch.object(materializer, '_inventory', side_effect=attach):
            with self.assertRaises(materializer.DraftRetained):
                self.run_materializer()
        self.assertTrue(outsider.exists())
        self.assertEqual(outsider.read_bytes(), b'fixture text\n')
        self.assertFalse(self.candidate.exists())

    def test_extra_path_matching_source_exclusion_is_still_rejected(self):
        original = materializer._inventory
        def add_excluded(stage_fd, *args, **kwargs):
            os.mkdir('evidence', dir_fd=stage_fd)
            return original(stage_fd, *args, **kwargs)
        with patch.object(materializer, '_inventory', side_effect=add_excluded):
            with self.assertRaises(materializer.DraftRetained):
                self.run_materializer()
        self.assertFalse(self.candidate.exists())

    def test_inventory_fstat_failure_closes_new_child_descriptor(self):
        self.run_materializer()
        root_fd = os.open(self.candidate, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        self.addCleanup(os.close, root_fd)
        before = len(os.listdir('/proc/self/fd'))
        actual_fstat = os.fstat
        def fail_child(fd):
            try:
                name = os.readlink(f'/proc/self/fd/{fd}')
            except OSError:
                return actual_fstat(fd)
            if name == str(self.candidate/'data'):
                raise OSError('injected child fstat error')
            return actual_fstat(fd)
        with patch.object(materializer.os, 'fstat', side_effect=fail_child):
            with self.assertRaises(OSError):
                materializer._inventory(root_fd, self.supplement, self.policy, materializer.time.monotonic()+5)
        self.assertEqual(len(os.listdir('/proc/self/fd')), before)

    def test_parent_component_close_failure_does_not_leak_child_or_close_root(self):
        self.run_materializer()
        root_fd = os.open(self.candidate, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        self.addCleanup(os.close, root_fd)
        before = len(os.listdir('/proc/self/fd'))
        real_close = os.close
        injected = False
        def close_then_raise(fd):
            nonlocal injected
            real_close(fd)
            if not injected:
                injected = True
                raise OSError('injected after close')
        with patch.object(materializer.os, 'close', side_effect=close_then_raise):
            with self.assertRaises(OSError):
                materializer._parent(root_fd, 'data/value.txt')
        self.assertTrue(injected)
        os.fstat(root_fd)
        self.assertEqual(len(os.listdir('/proc/self/fd')), before)

    def test_inventory_iterator_and_cleanup_errors_close_all_ancestor_fds(self):
        self.run_materializer()
        root_fd = os.open(self.candidate, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        self.addCleanup(os.close, root_fd)
        before = len(os.listdir('/proc/self/fd'))
        actual_scandir = os.scandir
        class FailingIterator:
            def __init__(self, inner):
                self.inner = inner
            def __next__(self):
                raise OSError('injected iterator failure')
            def close(self):
                self.inner.close()
                raise OSError('injected iterator close failure')
        def fail_child(fd):
            inner = actual_scandir(fd)
            if os.readlink(f'/proc/self/fd/{fd}') == str(self.candidate/'data'):
                return FailingIterator(inner)
            return inner
        with patch.object(materializer.os, 'scandir', side_effect=fail_child):
            with self.assertRaises(materializer.DraftIncomplete):
                materializer._inventory(root_fd, self.supplement, self.policy, materializer.time.monotonic()+5)
        os.fstat(root_fd)
        self.assertEqual(len(os.listdir('/proc/self/fd')), before)

    def test_parent_default_acl_rejected_before_candidate_creation(self):
        named_uid = os.getuid()
        mappings = [tuple(map(int, row.split())) for row in
                    Path('/proc/self/uid_map').read_text(encoding='ascii').splitlines()]
        self.assertLess(named_uid, 0xffffffff)
        self.assertTrue(any(start <= named_uid < start + length for start, _, length in mappings),
                        'fixture named UID is not mapped in this user namespace')
        acl = struct.pack('<I', 2) + b''.join(struct.pack('<HHI', t, p, u) for t, p, u in (
            (1, 7, 0xffffffff), (2, 5, named_uid), (4, 5, 0xffffffff),
            (16, 5, 0xffffffff), (32, 0, 0xffffffff)))
        try:
            os.setxattr(self.parent, 'system.posix_acl_default', acl)
        except OSError as exc:
            if exc.errno in (errno.EOPNOTSUPP, errno.ENOTSUP):
                self.skipTest('fixture filesystem does not support POSIX ACL')
            raise
        self.assertIn('system.posix_acl_default', os.listxattr(self.parent))
        self.assertEqual(os.getxattr(self.parent, 'system.posix_acl_default'), acl)
        with self.assertRaisesRegex(ValueError, '^candidate has an unapproved xattr or POSIX ACL$'):
            self.run_materializer()
        self.assertFalse(self.candidate.exists())
        self.assertEqual(list(self.parent.iterdir()), [])
        self.assertEqual(os.getxattr(self.parent, 'system.posix_acl_default'), acl)


if __name__ == '__main__':
    unittest.main()
