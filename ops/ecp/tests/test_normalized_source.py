from __future__ import annotations

import hashlib
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'ops/ecp'))
import normalized_source as normalized
import source_snapshot as snapshot


class NormalizedSourceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='ecp-normalized-source-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / 'source'
        self.root.mkdir()
        self.git('init', '-q')
        self.git('config', 'user.name', 'Fixture')
        self.git('config', 'user.email', 'fixture@example.invalid')
        (self.root/'data').mkdir()
        (self.root/'data/value.txt').write_bytes(b'raw source\n')
        (self.root/'run.sh').write_bytes(b'#!/bin/sh\nexit 0\n')
        (self.root/'run.sh').chmod(0o755)
        (self.root/'latest').symlink_to('data/value.txt')
        self.git('add', '.')
        self.git('commit', '-qm', 'fixture')
        self.mount = patch.object(snapshot, '_v3_mount_status', return_value=('UNAVAILABLE', ('fixture', 'fixture')))
        self.mount.start()
        self.addCleanup(self.mount.stop)

    def git(self, *args):
        return subprocess.run(['/usr/bin/git', *args], cwd=self.root, check=True,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE).stdout

    def manifest(self):
        return snapshot.build_manifest_v3(self.root)

    def observe(self, manifest):
        return normalized.observe_source(self.root, manifest, manifest['manifest_sha256'])

    def test_directory_boundary_names_as_files_and_link_targets_are_preserved(self):
        names = ('evidence', 'target', 'node_modules')
        for name in names:
            (self.root/name).write_bytes(('business:' + name).encode())
            (self.root/('alias_' + name)).symlink_to(name)
        self.git('add', '-f', *(list(names) + ['alias_' + name for name in names]))
        self.git('commit', '-qm', 'boundary names as files')
        entries = {row['path']: row for row in self.observe(self.manifest())['entries']}
        for name in names:
            with self.subTest(name=name):
                self.assertEqual(entries[name]['kind'], 'file')
                self.assertEqual(entries[name]['sha256'],
                                 hashlib.sha256(('business:' + name).encode()).hexdigest())
                self.assertEqual(entries['alias_' + name]['target'], name)

    def test_directory_boundary_named_links_are_rejected(self):
        for name in ('evidence', 'target', 'node_modules'):
            with self.subTest(name=name):
                (self.root/name).symlink_to('data/value.txt')
                self.git('add', '-f', name)
                self.git('commit', '-qm', 'boundary named symlink')
                with self.assertRaises((ValueError, RuntimeError)):
                    self.observe(self.manifest())
                (self.root/name).unlink()
                self.git('add', '-A')
                self.git('commit', '-qm', 'remove boundary named symlink')

    def test_business_formats_remain_in_the_source_supplement(self):
        payloads = {'asset.png': b'png\x00data', 'fixture.log': b'log data',
                    'bundle.tar.gz': b'archive data', 'module.pyc': b'bytecode data'}
        for name, data in payloads.items():
            (self.root/'data'/name).write_bytes(data)
        self.git('add', '-f', *('data/' + name for name in payloads))
        self.git('commit', '-qm', 'add business inputs')
        result = self.observe(self.manifest())
        entries = {row['path']: row for row in result['entries']}
        for name, data in payloads.items():
            with self.subTest(name=name):
                self.assertEqual(entries['data/' + name]['sha256'], hashlib.sha256(data).hexdigest())

    def test_source_symlink_limit_counts_outer_link(self):
        import errno
        if os.environ.get('ECP_TEST_REAL_9P') == '1':
            # The dedicated 9p campaign verifies the actual mount; the usual
            # cross-platform unit fixture retains its explicit UNAVAILABLE mock.
            self.mount.stop()
            self.assertEqual(snapshot._v3_mount_status(self.root)[1][0], '9p')
        data = self.root/'data'
        for internal, usable in ((39, True), (40, False)):
            with self.subTest(internal_links=internal):
                for i in range(internal):
                    target = f'link-{i+1:02d}' if i+1 < internal else 'value.txt'
                    (data/f'link-{i:02d}').symlink_to(target)
                outer = data/'outer'; outer.symlink_to('link-00')
                if usable:
                    self.assertEqual(outer.read_bytes(), b'raw source\n')
                else:
                    with self.assertRaises(OSError) as error:
                        outer.read_bytes()
                    self.assertEqual(error.exception.errno, errno.ELOOP)
                self.git('add', 'data'); self.git('commit', '-qm', 'link limit fixture')
                manifest = self.manifest()
                if usable:
                    self.assertIn('data/outer', {row['path'] for row in self.observe(manifest)['entries']})
                else:
                    with self.assertRaisesRegex(ValueError, 'symlink cycle or depth exceeded'):
                        self.observe(manifest)
                outer.unlink()
                for i in range(internal):
                    (data/f'link-{i:02d}').unlink()
                self.git('add', '-A'); self.git('commit', '-qm', 'remove link fixture')

    def test_tracks_git_content_and_retains_unknown_source_permissions(self):
        manifest = self.manifest()
        before = self.git('status', '--porcelain')
        result = self.observe(manifest)
        self.assertEqual(result['source_manifest_sha256'], manifest['manifest_sha256'])
        self.assertEqual(result['source_head'], self.git('rev-parse', 'HEAD').decode().strip())
        self.assertEqual((result['source_mode_claim'], result['qualification'], result['product_gate_effect']),
                         ('UNKNOWN', 'NOT_RUN', 'NONE'))
        self.assertEqual(result['directories'], [{'path': '.', 'origin': 'source_root'},
                                                 {'path': 'data', 'origin': 'git_ancestor'}])
        entries = {row['path']: row for row in result['entries']}
        self.assertEqual(set(entries), {'data/value.txt', 'latest', 'run.sh'})
        self.assertEqual(entries['data/value.txt']['sha256'], hashlib.sha256(b'raw source\n').hexdigest())
        self.assertEqual(entries['run.sh']['git_mode'], '100755')
        self.assertEqual(entries['latest']['target'], 'data/value.txt')
        self.assertEqual(entries['latest']['size'], len(b'data/value.txt'))
        self.assertEqual(self.git('status', '--porcelain'), before)

    def test_fused_endpoint_scans_read_each_tracked_file_twice(self):
        manifest = self.manifest()
        wanted = {str(self.root/'data/value.txt'): len(b'raw source\n'),
                  str(self.root/'run.sh'): len(b'#!/bin/sh\nexit 0\n')}
        bytes_read = {path: 0 for path in wanted}
        link_reads = []
        real_read, real_readlink = os.read, os.readlink
        def count_read(fd, size):
            data = real_read(fd, size)
            if data:
                try:
                    name = real_readlink(f'/proc/self/fd/{fd}')
                except OSError:
                    name = ''
                if name in bytes_read:
                    bytes_read[name] += len(data)
            return data
        def count_readlink(path, *args, **kwargs):
            value = real_readlink(path, *args, **kwargs)
            if path == 'latest' and kwargs.get('dir_fd') is not None:
                link_reads.append(value)
            return value
        with patch.object(snapshot.os, 'read', side_effect=count_read), \
             patch.object(snapshot.os, 'readlink', side_effect=count_readlink):
            result = self.observe(manifest)
        self.assertEqual(bytes_read, {path: 2 * size for path, size in wanted.items()})
        self.assertEqual(link_reads, ['data/value.txt', 'data/value.txt'])
        self.assertEqual(len(result['entries']), 3)

    def test_late_scan_failure_returns_no_supplement_and_restores_context(self):
        manifest = self.manifest()
        actual = snapshot._v3_scan_projection
        calls = 0
        initial_root = snapshot._V3_PINNED_ROOT.get()
        initial_git = snapshot._V3_BOUNDED_GIT.get()
        initial_deadline = snapshot._V3_TOTAL_DEADLINE.get()
        def fail_after_complete_file_reads(*args, **kwargs):
            nonlocal calls
            calls += 1
            if calls == 1:
                raise OSError('injected after fused file reads')
            return actual(*args, **kwargs)
        with patch.object(snapshot, '_v3_scan_projection', side_effect=fail_after_complete_file_reads):
            with self.assertRaisesRegex(OSError, 'injected after fused'):
                self.observe(manifest)
        self.assertEqual(calls, 1)
        self.assertIs(snapshot._V3_PINNED_ROOT.get(), initial_root)
        self.assertEqual(snapshot._V3_BOUNDED_GIT.get(), initial_git)
        self.assertIs(snapshot._V3_TOTAL_DEADLINE.get(), initial_deadline)

    def test_file_growth_read_is_capped_at_declared_size_plus_one(self):
        manifest = self.manifest()
        target = self.root/'data/value.txt'
        original_size = target.stat().st_size
        readlink, real_read = os.readlink, os.read
        observed = []
        initial_root = snapshot._V3_PINNED_ROOT.get()
        def grow_during_read(fd, size):
            try:
                path = readlink(f'/proc/self/fd/{fd}')
            except OSError:
                path = ''
            if path == str(target) and not observed:
                with target.open('ab') as out:
                    out.write(b'x' * (128 * 1024))
                data = real_read(fd, size)
                observed.append((size, len(data)))
                return data
            return real_read(fd, size)
        with patch.object(snapshot.os, 'read', side_effect=grow_during_read):
            with self.assertRaisesRegex(ValueError, 'grew during verification'):
                self.observe(manifest)
        self.assertEqual(observed, [(original_size + 1, original_size + 1)])
        self.assertIs(snapshot._V3_PINNED_ROOT.get(), initial_root)

    def test_file_changed_between_fused_endpoints_returns_no_supplement(self):
        manifest = self.manifest()
        actual = snapshot._build_manifest_v3_bounded
        calls = 0
        def change_after_first(*args, **kwargs):
            nonlocal calls
            result = actual(*args, **kwargs)
            calls += 1
            if calls == 1:
                (self.root/'data/value.txt').write_bytes(b'changed bytes\n')
            return result
        with patch.object(snapshot, '_build_manifest_v3_bounded', side_effect=change_after_first):
            with self.assertRaises((ValueError, OSError)):
                self.observe(manifest)
        self.assertEqual(calls, 1)

    def test_index_flag_changed_between_fused_endpoints_returns_no_supplement(self):
        manifest = self.manifest()
        actual = snapshot._build_manifest_v3_bounded
        calls = 0
        def hide_after_first(*args, **kwargs):
            nonlocal calls
            result = actual(*args, **kwargs)
            calls += 1
            if calls == 1:
                self.git('update-index', '--skip-worktree', 'data/value.txt')
            return result
        try:
            with patch.object(snapshot, '_build_manifest_v3_bounded', side_effect=hide_after_first):
                with self.assertRaises(ValueError):
                    self.observe(manifest)
        finally:
            self.git('update-index', '--no-skip-worktree', 'data/value.txt')
        self.assertEqual(calls, 1)

    def test_sha256_git_object_id_is_distinct_from_raw_sha256(self):
        other = self.root.parent/'sha256-repository'
        init = subprocess.run(['/usr/bin/git', 'init', '-q', '--object-format=sha256', str(other)],
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if init.returncode:
            self.skipTest('installed Git lacks SHA-256 repository support')
        content = b'sha256 fixture bytes\n'
        (other/'input.txt').write_bytes(content)
        (other/'link').symlink_to('input.txt')
        def run(*args):
            return subprocess.run(['/usr/bin/git', *args], cwd=other, check=True,
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE).stdout
        run('add', '.')
        run('-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid', 'commit', '-qm', 'fixture')
        manifest = snapshot.build_manifest_v3(other)
        result = normalized.observe_source(other, manifest, manifest['manifest_sha256'])
        files = {row['path']: row for row in result['entries']}
        self.assertEqual(len(result['source_head']), 64)
        self.assertEqual(files['input.txt']['sha256'], hashlib.sha256(content).hexdigest())
        self.assertEqual(files['input.txt']['git_oid'], hashlib.sha256(b'blob '+str(len(content)).encode()+b'\0'+content).hexdigest())
        self.assertNotEqual(files['input.txt']['git_oid'], files['input.txt']['sha256'])
        self.assertEqual(files['link']['sha256'], hashlib.sha256(b'input.txt').hexdigest())

    def test_caller_source_fd_is_bound_and_remains_open(self):
        manifest = self.manifest()
        fd = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            result = normalized.observe_source(self.root, manifest, manifest['manifest_sha256'], source_fd=fd)
            self.assertEqual(result['source_manifest_sha256'], manifest['manifest_sha256'])
            os.fstat(fd)  # Ownership remains with the caller.
        finally:
            os.close(fd)

    def test_caller_source_fd_rejects_a_replaced_visible_root(self):
        manifest = self.manifest()
        replacement, parked = self.root.parent/'replacement', self.root.parent/'parked'
        subprocess.run(['/usr/bin/git', 'clone', '-q', str(self.root), str(replacement)], check=True)
        fd = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        self.root.rename(parked)
        replacement.rename(self.root)
        try:
            with self.assertRaisesRegex(ValueError, 'differs from visible'):
                normalized.observe_source(self.root, manifest, manifest['manifest_sha256'], source_fd=fd)
            os.fstat(fd)
        finally:
            self.root.rename(replacement)
            parked.rename(self.root)
            os.close(fd)

    def test_caller_source_fd_rejects_non_directory_and_path_only_handles(self):
        manifest = self.manifest()
        path_fd = os.open(self.root, os.O_PATH | os.O_DIRECTORY)
        file_fd = os.open(self.root/'data/value.txt', os.O_RDONLY)
        try:
            for fd in (path_fd, file_fd):
                with self.subTest(fd=fd), self.assertRaises(ValueError):
                    normalized.observe_source(self.root, manifest, manifest['manifest_sha256'], source_fd=fd)
                os.fstat(fd)
        finally:
            os.close(path_fd)
            os.close(file_fd)

    def test_rejects_wrong_manifest_pin_and_non_unknown_mode(self):
        manifest = self.manifest()
        with self.assertRaisesRegex(ValueError, 'manifest'):
            normalized.observe_source(self.root, manifest, '0' * 64)
        self.mount.stop()
        try:
            known_mode = snapshot.build_manifest_v3(self.root)
            with self.assertRaisesRegex(ValueError, 'unknown-mode'):
                self.observe(known_mode)
        finally:
            self.mount.start()

    def test_tracked_byte_change_after_manifest_is_rejected(self):
        manifest = self.manifest()
        (self.root/'data/value.txt').write_bytes(b'different!!\n')
        with self.assertRaises((ValueError, OSError)):
            self.observe(manifest)

    def test_nested_manifest_scan_is_bound_to_original_root_descriptor(self):
        manifest = self.manifest()
        replacement = self.root.parent/'replacement'
        parked = self.root.parent/'parked'
        subprocess.run(['/usr/bin/git', 'clone', '-q', str(self.root), str(replacement)], check=True)
        (self.root/'untracked.py').write_text('untracked business\n')
        actual_scan = snapshot._build_manifest_v3_bounded
        swapped = False
        calls = 0
        def scan_with_swap(*args, **kwargs):
            nonlocal swapped, calls
            calls += 1
            if not swapped:
                self.root.rename(parked)
                replacement.rename(self.root)
                swapped = True
            value = actual_scan(*args, **kwargs)
            if calls == 2:
                self.root.rename(replacement)
                parked.rename(self.root)
                swapped = False
            return value
        try:
            with patch.object(snapshot, '_build_manifest_v3_bounded', side_effect=scan_with_swap):
                with self.assertRaises((ValueError, OSError)):
                    self.observe(manifest)
        finally:
            if swapped:
                self.root.rename(replacement)
                parked.rename(self.root)
        self.assertTrue((self.root/'untracked.py').exists())

    def test_link_escape_cycle_and_dangling_are_rejected(self):
        for target in ('../outside', 'latest', 'missing', '.'):
            with self.subTest(target=target):
                (self.root/'latest').unlink()
                (self.root/'latest').symlink_to(target)
                self.git('add', 'latest')
                self.git('commit', '-qm', 'link fixture')
                manifest = self.manifest()
                with self.assertRaises(ValueError):
                    self.observe(manifest)

    def test_directory_symlink_graph_cycle_is_rejected(self):
        for name in ('one', 'two'):
            (self.root/name).mkdir()
            (self.root/name/'file').write_text('fixture\n')
        (self.root/'one/link').symlink_to('../two')
        (self.root/'two/link').symlink_to('../one')
        self.git('add', '.')
        self.git('commit', '-qm', 'directory cycle')
        with self.assertRaisesRegex(ValueError, 'directory symlink graph'):
            self.observe(self.manifest())

    def test_context_and_root_fd_are_released_on_initialization_error(self):
        manifest = self.manifest()
        real_open = snapshot._v3_open_root_by_path
        opened = []
        def track(path):
            fd = real_open(path)
            opened.append(fd)
            return fd
        old_root = snapshot._V3_PINNED_ROOT.get()
        old_git = snapshot._V3_BOUNDED_GIT.get()
        old_deadline = snapshot._V3_TOTAL_DEADLINE.get()
        with patch.object(snapshot, '_v3_open_root_by_path', side_effect=track), \
             patch.object(normalized.time, 'monotonic', side_effect=RuntimeError('injected clock failure')):
            with self.assertRaisesRegex(RuntimeError, 'injected clock failure'):
                self.observe(manifest)
        self.assertEqual(len(opened), 2)
        for fd in opened:
            with self.assertRaises(OSError):
                os.fstat(fd)
        self.assertIs(snapshot._V3_PINNED_ROOT.get(), old_root)
        self.assertEqual(snapshot._V3_BOUNDED_GIT.get(), old_git)
        self.assertIs(snapshot._V3_TOTAL_DEADLINE.get(), old_deadline)

    def test_untracked_business_path_is_not_hidden_by_gitignore(self):
        (self.root/'.gitignore').write_text('ignored.py\n')
        self.git('add', '.gitignore')
        self.git('commit', '-qm', 'ignore fixture')
        (self.root/'ignored.py').write_text('value = 1\n')
        with self.assertRaisesRegex(ValueError, 'untracked business'):
            self.manifest()

    def test_byte_budget_and_timeout_do_not_report_success(self):
        manifest = self.manifest()
        with patch.object(normalized, 'MAX_FILE', 1):
            with self.assertRaises(ValueError):
                self.observe(manifest)
        with self.assertRaises(ValueError):
            normalized.observe_source(self.root, manifest, manifest['manifest_sha256'], timeout=0)


if __name__ == '__main__':
    unittest.main()
