from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

SOURCE = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(SOURCE / 'ops/ecp'))
import build_manifest


class BuildManifestTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)
        self.tools = self.base / 'tools'
        self.tools.mkdir()
        for name in ('cargo', 'rustc', 'node', 'npm'):
            tool = self.tools / name
            tool.write_text('#!/bin/sh\nprintf "%s version 1\\n" "' + name + '"\n')
            tool.chmod(0o755)
        self.env = {k: v for k, v in os.environ.items() if k not in (
            'RUSTC', 'RUSTC_WRAPPER', 'RUSTC_WORKSPACE_WRAPPER', 'CARGO_BUILD_RUSTC',
            'CARGO_BUILD_RUSTC_WRAPPER', 'CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER',
            'BASH_ENV', 'ENV', 'LD_PRELOAD', 'NODE_OPTIONS')}
        self.env['PATH'] = str(self.tools) + os.pathsep + self.env.get('PATH', '')
        self.root = self.base / 'source'
        self.root.mkdir()
        for relative, contents in [('Cargo.lock', 'version=4\n'), ('console/package-lock.json', '{}\n'),
                                   ('migrations/0001_test.sql', 'SELECT 1;\n'), ('README.md', 'original\n')]:
            path = self.root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(contents)
        for command in [['git', 'init', '-q'], ['git', 'config', 'user.name', 'Fixture'],
                        ['git', 'config', 'user.email', 'fixture@example.invalid'],
                        ['git', 'add', '.'], ['git', 'commit', '-qm', 'fixture']]:
            subprocess.run(command, cwd=self.root, check=True)
        (self.root / 'target').mkdir()
        (self.root / 'target/server').write_text('binary')
        (self.root / 'console/dist').mkdir()
        (self.root / 'console/dist/index.html').write_text('bundle')
        self.index = 0
        self.before = self.base / 'before.json'
        result = self.invoke(self.before)
        self.assertEqual(result.returncode, 0, result.stderr)

    def invoke(self, output, *arguments):
        return subprocess.run([sys.executable, str(SOURCE / 'ops/ecp/build_manifest.py'),
                               '--source-root', str(self.root), '--output', str(output),
                               *map(str, arguments)], cwd=self.root, env=self.env, capture_output=True, text=True, timeout=15)

    def check(self, expected, *arguments):
        self.index += 1
        output = self.base / f'result-{self.index}.json'
        result = self.invoke(output, '--verify-against', self.before, *arguments)
        self.assertEqual(result.returncode, expected, result.stdout + result.stderr)
        report = json.loads(output.read_text())
        self.assertEqual(report['status'], 'PASS' if expected == 0 else 'FAIL')
        return report

    def test_actual_unchanged_artifacts_and_absolute_inside_paths(self):
        report = self.check(0, '--binary', self.root / 'target/server', '--frontend-dir', self.root / 'console/dist')
        self.assertEqual(report['artifacts'][str(self.root / 'target/server')], hashlib.sha256(b'binary').hexdigest())
        self.assertEqual(report['artifacts']['frontend']['index.html'], hashlib.sha256(b'bundle').hexdigest())
        self.assertFalse(report['build_performed'])
        self.assertEqual(report['product_gate_effect'], 'NONE')

    def test_source_and_lockfile_drift_are_rejected(self):
        for relative, contents in [('README.md', 'changed\n'), ('console/package-lock.json', '{"changed":true}\n')]:
            with self.subTest(path=relative):
                path = self.root / relative
                original = path.read_text()
                path.write_text(contents)
                try:
                    report = self.check(10)
                    self.assertIn('FAIL', [row['status'] for row in report['checks'] if row['name'] == 'source_binding'])
                finally:
                    path.write_text(original)

    def test_outside_and_symlink_ancestor_artifacts_are_rejected(self):
        external = self.base / 'external'
        external.mkdir()
        (external / 'binary').write_text('external secret')
        (external / 'dist').mkdir()
        (external / 'dist/index.html').write_text('external')
        (self.root / 'target/linked').symlink_to(external, target_is_directory=True)
        (self.root / 'console/dist/linked').symlink_to(external, target_is_directory=True)
        for option, value in [('--binary', 'target/missing'), ('--binary', '../external/binary'), ('--binary', external / 'binary'),
                              ('--binary', 'target/linked/binary'), ('--frontend-dir', external / 'dist'),
                              ('--frontend-dir', 'console/dist/linked/dist'), ('--frontend-dir', 'console/dist')]:
            with self.subTest(option=option, value=str(value)):
                report = self.check(10, option, value)
                self.assertNotIn(hashlib.sha256(b'external secret').hexdigest(), json.dumps(report))

    def test_existing_and_dangling_symlink_evidence_are_not_overwritten(self):
        original = self.before.read_bytes()
        result = self.invoke(self.before)
        self.assertEqual(result.returncode, 20)
        self.assertEqual(json.loads(result.stdout)['status'], 'BLOCKED')
        self.assertEqual(self.before.read_bytes(), original)
        link = self.base / 'dangling.json'
        target = self.base / 'missing.json'
        link.symlink_to(target)
        result = self.invoke(link)
        self.assertEqual(result.returncode, 20)
        self.assertTrue(link.is_symlink())
        self.assertFalse(target.exists())

    def test_parent_replacement_does_not_read_external_bytes(self):
        external = self.base / 'external'
        external.mkdir()
        (external / 'server').write_text('external')
        fd = build_manifest.open_artifact(self.root.resolve(), Path('target/server'))
        try:
            (self.root / 'target').rename(self.root / 'target-held')
            (self.root / 'target').symlink_to(external, target_is_directory=True)
            self.assertEqual(build_manifest.digest_fd(fd), hashlib.sha256(b'binary').hexdigest())
        finally:
            os.close(fd)
            (self.root / 'target').unlink()
            (self.root / 'target-held').rename(self.root / 'target')

    def test_fifo_is_rejected_without_waiting(self):
        os.mkfifo(self.root / 'target/fifo')
        self.check(10, '--binary', 'target/fifo')

    def test_tool_content_and_path_drift_rejected_even_when_version_matches(self):
        tool = self.tools / 'rustc'
        tool.write_text(tool.read_text() + '# replacement with identical version output\n')
        report = self.check(10)
        self.assertEqual(next(c for c in report['checks'] if c['name'] == 'source_binding')['status'], 'FAIL')
        replacement = self.base / 'replacement'
        replacement.mkdir()
        for name in ('cargo', 'rustc', 'node', 'npm'):
            (replacement / name).write_bytes((self.tools / name).read_bytes())
            (replacement / name).chmod(0o755)
        self.env['PATH'] = str(replacement) + os.pathsep + self.env['PATH']
        self.check(10)

    def test_missing_tool_or_compiler_override_is_inconclusive(self):
        # PATH retains Git but replaces the four tools; use a nonzero fake tool
        # rather than falling through to any host installation.
        (self.tools / 'cargo').write_text('#!/bin/sh\nexit 12\n')
        output = self.base / 'unavailable.json'
        result = self.invoke(output, '--verify-against', self.before)
        self.assertEqual(result.returncode, 20, result.stdout + result.stderr)
        report = json.loads(output.read_text())
        self.assertEqual(report['status'], 'INCONCLUSIVE')
        self.assertEqual(next(c for c in report['checks'] if c['name'] == 'tool.cargo')['status'], 'INCONCLUSIVE')
        self.env['RUSTC_WRAPPER'] = '/unreviewed/wrapper'
        (self.tools / 'cargo').write_text('#!/bin/sh\necho cargo version 1\n')
        result = self.invoke(self.base / 'override.json')
        self.assertEqual(result.returncode, 20, result.stdout + result.stderr)
        self.assertEqual(json.loads(result.stdout)['status'], 'INCONCLUSIVE')

    def test_legacy_manifest_without_tool_identity_cannot_pass_binding(self):
        previous = json.loads(self.before.read_text())
        del previous['tool_identity']
        old = self.base / 'legacy.json'
        old.write_text(json.dumps(previous))
        result = self.invoke(self.base / 'legacy-result.json', '--verify-against', old)
        self.assertEqual(result.returncode, 10)
        self.assertEqual(json.loads(result.stdout)['status'], 'FAIL')

    def test_compiler_flags_drift_is_hashed_and_rejected(self):
        self.env['RUSTFLAGS'] = 'private-flag-value'
        report = self.check(10)
        self.assertNotIn('private-flag-value', json.dumps(report))
        self.assertEqual(report['tool_environment']['RUSTFLAGS'], hashlib.sha256(b'private-flag-value').hexdigest())

    def test_bash_startup_hook_is_not_inherited_by_tool_probes(self):
        hook = self.base / 'hook.sh'
        sentinel = self.base / 'hook-ran'
        hook.write_text('echo bad > ' + str(sentinel) + '\n')
        self.env['BASH_ENV'] = str(hook)
        (self.tools / 'rustc').write_text('#!/bin/bash\necho rustc version 1\n')
        result = self.invoke(self.base / 'hook-result.json')
        self.assertEqual(result.returncode, 20, result.stdout + result.stderr)
        self.assertEqual(json.loads(result.stdout)['status'], 'INCONCLUSIVE')
        self.assertFalse(sentinel.exists())

    def test_rustup_shim_binds_selected_toolchain_file(self):
        shim = self.tools / 'rustup'
        compiler = self.base / 'rustc-real'
        compiler.write_text('#!/bin/sh\necho rustc fixture\n')
        compiler.chmod(0o755)
        shim.write_text('#!/bin/sh\nif [ "$1" = which ]; then printf "%s\\n" "' + str(compiler) + '"; else echo rustc fixture; fi\n')
        shim.chmod(0o755)
        (self.tools / 'rustc').unlink()
        (self.tools / 'rustc').symlink_to(shim)
        from unittest.mock import patch
        with patch.dict(os.environ, {'PATH': self.env['PATH']}):
            identity = build_manifest.executable_identity('rustc', self.root)
        self.assertEqual(identity['launcher_path'], str(shim.resolve()))
        self.assertEqual(identity['executable_path'], str(compiler.resolve()))
        self.assertEqual(identity['executable_sha256'], hashlib.sha256(compiler.read_bytes()).hexdigest())
        (self.tools / 'rustc').unlink()
        os.link(shim, self.tools / 'rustc')
        with patch.dict(os.environ, {'PATH': self.env['PATH']}):
            hardlink_identity = build_manifest.executable_identity('rustc', self.root)
        self.assertEqual(hardlink_identity['executable_path'], str(compiler.resolve()))
        (self.tools / 'rustc').unlink()
        shim.rename(self.tools / 'rustup.exe')
        (self.tools / 'rustc').symlink_to(self.tools / 'rustup.exe')
        with patch.dict(os.environ, {'PATH': self.env['PATH']}):
            exe_identity = build_manifest.executable_identity('rustc', self.root)
        self.assertEqual(exe_identity['executable_path'], str(compiler.resolve()))

    def test_rustup_invalid_output_or_version_disagreement_fails_closed(self):
        shim = self.tools / 'rustup'
        compiler = self.base / 'rustc-real'
        compiler.write_text('#!/bin/sh\necho rustc actual-version\n')
        compiler.chmod(0o755)
        (self.tools / 'rustc').unlink()
        (self.tools / 'rustc').symlink_to(shim)
        from unittest.mock import patch
        for reported in ('relative/not-a-tool', str(compiler)):
            with self.subTest(reported=reported):
                shim.write_text('#!/bin/sh\nif [ "$1" = which ]; then printf "%s\\n" "' + reported + '"; else echo rustc shim-version; fi\n')
                shim.chmod(0o755)
                with patch.dict(os.environ, {'PATH': self.env['PATH']}):
                    with self.assertRaises(ValueError):
                        build_manifest.executable_identity('rustc', self.root)


if __name__ == '__main__':
    unittest.main()
