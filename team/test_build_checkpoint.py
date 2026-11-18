#!/usr/bin/env python3
"""Focused checks for build scope, immutable pins and safe cache retirement."""
from contextlib import redirect_stderr
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('build_checkpoint', Path(__file__).with_name('build_checkpoint.py'))
build = importlib.util.module_from_spec(spec)
spec.loader.exec_module(build)


class LightweightBuildTests(unittest.TestCase):
    def test_frozen_resources_compile_and_changes_invalidate_identity(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source, frozen = root / 'source', root / 'frozen'
            source.mkdir()
            (source / 'Cargo.toml').write_text('[workspace]\n')
            (source / 'Cargo.lock').write_text('version = 4\n')
            resources = (
                'project-packs/personal-website/plan.json',
                'plugins/dsh-forgeflow-network/package.json',
                'plugins/dsh-forgeflow-network/index.mjs',
                'plugins/dsh-forgeflow-network/client.mjs',
                'plugins/dsh-forgeflow-network/bin/forgeflow.mjs',
                'plugins/dsh-forgeflow-network/templates/personal-site.workflow.js',
                'plugins/dsh-forgeflow-network/README.md',
            )
            consumer = source / 'crates/api/src/lib.rs'
            consumer.parent.mkdir(parents=True)
            consumer.write_text('\n'.join(
                f'pub const INPUT_{i}: &str = include_str!("../../../{relative}");'
                for i, relative in enumerate(resources)
            ))
            for relative in resources:
                path = source / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(relative + '\n')
            before = build.inventory(source)
            for relative in before:
                destination = frozen / relative
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_bytes((source / relative).read_bytes())
            (root / 'compiled').mkdir()
            result = subprocess.run(['rustc', '--crate-type=lib', str(frozen / consumer.relative_to(source)),
                                     '--out-dir', str(root / 'compiled')], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(build.inventory(frozen), before)
            for relative in resources:
                with self.subTest(resource=relative):
                    self.assertIn(relative, before)
                    path = source / relative
                    path.write_text('changed bytes\n')
                    self.assertNotEqual(build.inventory(source), before)
                    path.write_text(relative + '\n')

    def test_resource_roots_reject_links_and_prune_dependency_trees(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'Cargo.toml').write_text('[workspace]\n')
            (root / 'Cargo.lock').write_text('version = 4\n')
            for name in ['plugins', 'project-packs']:
                with self.subTest(root=name):
                    base = root / name
                    base.symlink_to('/nonexistent', target_is_directory=True)
                    with self.assertRaisesRegex(RuntimeError, 'symlink'):
                        build.inventory(root)
                    base.unlink()
                    base.mkdir()
                    link = base / 'resource.txt'
                    link.symlink_to('/nonexistent')
                    with self.assertRaisesRegex(RuntimeError, 'symlink'):
                        build.inventory(root)
                    link.unlink()
                    ignored = base / 'node_modules'
                    ignored.mkdir()
                    (ignored / 'outside').symlink_to('/nonexistent')
            self.assertEqual(set(build.inventory(root)), {'Cargo.toml', 'Cargo.lock'})

    def test_focused_work_has_no_implicit_workspace_build(self):
        operations = (
            ['--targeted-test', 'forgeflow-store:native_configuration'],
            ['--lib-test', 'forgeflow-domain:state::transition'],
            ['--postgres-target', 'forgeflow-store:authority', '--database-env', '/private.json'],
            ['--test', '--test-packages', 'forgeflow-domain'],
            ['--check', '--check-packages', 'forgeflow-store'],
        )
        for argv in operations:
            with self.subTest(argv=argv):
                commands = build.command_plan(build.arguments(argv), Path('/unavailable'))
                self.assertEqual(len(commands), 1)
                self.assertNotEqual(commands[0][1][1], 'build')
                self.assertNotIn('--workspace', commands[0][1])
        commands = build.command_plan(build.arguments(['--build-bins', 'forgeflow-worker']), Path('/'))
        self.assertEqual(commands, [('build', ['cargo', 'build', '--locked', '--offline', '--bin', 'forgeflow-worker'])])
        self.assertIn('--workspace', build.command_plan(build.arguments(['--build']), Path('/'))[0][1])

    def test_invalid_operations_create_no_cache_or_checkpoint(self):
        with tempfile.TemporaryDirectory() as directory:
            cache = Path(directory) / 'absent'
            for argv in ([], ['--test-packages', 'forgeflow-store'], ['--check-packages', 'forgeflow-store'],
                         ['--check', '--postgres-target', 'forgeflow-store:authority'],
                         ['--check', '--postgres-suites', 'authority'],
                         ['--targeted-test', 'forgeflow-store:'], ['--build', '--build-bins', 'forgeflow-worker']):
                with self.subTest(argv=argv), patch.object(build, 'CACHE', cache), redirect_stderr(io.StringIO()):
                    with self.assertRaises(SystemExit) as error:
                        build.main(argv)
                    self.assertEqual(error.exception.code, 2)
                    self.assertFalse(cache.exists())

    def test_pin_is_independent_of_target_and_reuses_verified_readonly_pin(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / 'target' / 'forgeflow-worker'
            target.parent.mkdir()
            target.write_bytes(b'actual binary content')
            cache = root / 'checkpoints'
            first = cache / 'first' / 'bin' / target.name
            first.parent.mkdir(parents=True)
            record = build.pin_binary(target, first, cache)
            self.assertFalse(os.path.samefile(target, first))
            self.assertEqual(record['pin_method'], 'independent_copy')
            build.write_json(first.parent.parent / 'receipt.json', {'binaries': {target.name: record}})
            second = cache / 'second' / 'bin' / target.name
            second.parent.mkdir(parents=True)
            second_record = build.pin_binary(target, second, cache)
            self.assertTrue(os.path.samefile(first, second))
            self.assertFalse(os.path.samefile(target, second))
            self.assertEqual(second_record['pin_method'], 'checkpoint_hardlink')
            target.write_bytes(b'next compiler output')
            self.assertEqual(first.read_bytes(), b'actual binary content')
            self.assertEqual(second.read_bytes(), b'actual binary content')

    def test_cache_retirement_protects_actual_open_file_then_reclaims(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / 'target'
            target.mkdir()
            artifact = target / 'temporary-artifact'
            artifact.write_bytes(b'x' * 128 * 1024)
            child = subprocess.Popen([sys.executable, '-c',
                'import sys; f=open(sys.argv[1],"rb"); print("ready",flush=True); sys.stdin.read()', str(artifact)],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
            try:
                self.assertEqual(child.stdout.readline().strip(), 'ready')
                result = build.enforce_cache_budget(target, 64 * 1024)
                self.assertEqual(result['status'], 'protected')
                self.assertTrue(any(f'PROCESS_REFERENCE:{child.pid}:fd' == reason for reason in result['reasons']))
                self.assertTrue(artifact.exists())
            finally:
                child.communicate('done', timeout=5)
            # Isolate this deletion check from unrelated real builds on the host.
            with patch.object(build, 'target_references', return_value=[]):
                result = build.enforce_cache_budget(target, 64 * 1024)
            self.assertEqual(result['status'], 'cleaned')
            self.assertFalse(artifact.exists())
            self.assertEqual(result['reclaimed_allocated_bytes'], result['allocated_bytes_before'] - result['allocated_bytes_after'])
            self.assertTrue((target / 'debug/.cargo-lock').exists())

    def test_busy_cargo_lock_prevents_cache_retirement(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory)
            (target / 'debug').mkdir()
            artifact = target / 'debug/artifact'
            artifact.write_bytes(b'x' * 128 * 1024)
            with (target / 'debug/.cargo-lock').open('a+') as lock:
                build.fcntl.flock(lock, build.fcntl.LOCK_EX | build.fcntl.LOCK_NB)
                with patch.object(build, 'target_references', return_value=[]):
                    result = build.enforce_cache_budget(target, 64 * 1024)
                self.assertEqual(result['status'], 'protected')
                self.assertEqual(result['reasons'], ['CARGO_TARGET_LOCK_BUSY'])
                self.assertTrue(artifact.exists())

    def test_failed_command_still_records_source_integrity_and_preserves_exit(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source, cache = root / 'source', root / 'cache'
            source.mkdir()
            (source / 'Cargo.toml').write_text('[workspace]\n')
            (source / 'Cargo.lock').write_text('version = 4\n')
            def failed_command(argv, **kwargs):
                kwargs['stdout'].write(b'original cargo failure\n')
                path = kwargs['cwd'] / 'Cargo.toml'
                path.chmod(0o644)
                path.write_text('[workspace]\n# unexpected input change\n')
                return subprocess.CompletedProcess(argv, 17)
            with patch.multiple(build, CACHE=cache, COMPILE_SOURCE=cache / 'compile-source', TARGET=root / 'target'), \
                 patch.object(build.subprocess, 'run', side_effect=failed_command), \
                 patch.object(build, 'checkpoint_retention', side_effect=RuntimeError('maintenance unavailable')):
                self.assertEqual(build.main(['--check', '--source-root', str(source)]), 17)
            receipt = json.loads(next(cache.glob('*/receipt.json')).read_text())
            self.assertFalse(receipt['source_unchanged_after_commands'])
            self.assertEqual(receipt['commands'][0]['exit_code'], 17)
            self.assertEqual(receipt['cargo_result_exit_code'], 17)
            self.assertEqual(receipt['checkpoint_maintenance']['status'], 'error')
            self.assertIn('after', receipt['target_cache_maintenance'])

    def test_inventory_prunes_generated_directories_before_descent(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'Cargo.toml').write_text('[workspace]\n')
            (root / 'Cargo.lock').write_text('version = 4\n')
            ignored = root / 'crates/executors/qualification/deep/nested'
            ignored.mkdir(parents=True)
            (ignored / 'unreviewed-symlink').symlink_to('/nonexistent')
            self.assertEqual(set(build.inventory(root)), {'Cargo.toml', 'Cargo.lock'})


if __name__ == '__main__':
    unittest.main()
