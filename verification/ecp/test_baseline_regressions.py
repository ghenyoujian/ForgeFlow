from pathlib import Path
import importlib.util
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('baseline_regressions', Path(__file__).with_name('baseline_regressions.py'))
baseline = importlib.util.module_from_spec(spec)
spec.loader.exec_module(baseline)

class BaselineRegressionTests(unittest.TestCase):
    def test_source_identity_requires_matching_current_head(self):
        root = Path('/source')
        doctor = {'payload': {'checks': [{'name': 'source_identity', 'status': 'PASS', 'details': {'source_sha': 'a' * 40, 'source_root': str(root), 'source_manifest_sha256': 'b' * 64, 'dirty': False}}]}}
        db = {'payload': {'status': 'BLOCKED', 'database_connections_attempted': 0}, 'exit_code': 20}
        result = baseline.findings(doctor, db, 'a' * 40, root)[0]
        self.assertEqual(result['status'], 'INCONCLUSIVE')
        self.assertIn('reports', result['reason'])
        self.assertIn('not independently authenticated', result['reason'])
        self.assertIn('unverified claims', result['scope'])
        doctor['payload']['checks'][0]['details']['dirty'] = True
        self.assertEqual(baseline.findings(doctor, db, 'a' * 40, root)[0]['status'], 'INCONCLUSIVE')
        doctor['payload']['checks'][0]['details']['dirty'] = False
        self.assertEqual(baseline.findings(doctor, db, 'b' * 40, root)[0]['status'], 'INCONCLUSIVE')
        self.assertEqual(baseline.findings(doctor, db, 'a' * 40, Path('/other'))[0]['status'], 'INCONCLUSIVE')
        doctor['payload']['checks'][0]['details']['source_manifest_sha256'] = 'invalid'
        self.assertEqual(baseline.findings(doctor, db, 'a' * 40, root)[0]['status'], 'INCONCLUSIVE')
        doctor['payload']['checks'][0]['details']['source_manifest_sha256'] = 'b' * 64
        self.assertEqual(baseline.findings({'payload': None}, db, 'a' * 40, root)[0]['status'], 'INCONCLUSIVE')
        doctor['payload']['checks'][0]['status'] = 'INCONCLUSIVE'
        self.assertEqual(baseline.findings(doctor, db, 'a' * 40, root)[0]['status'], 'INCONCLUSIVE')

    def test_guard_self_report_does_not_prove_no_connection(self):
        db = {'payload': {'status': 'BLOCKED', 'database_connections_attempted': 1}, 'exit_code': 20}
        result = baseline.findings({}, db, None, Path('/source'))[1]
        self.assertEqual(result['status'], 'FAIL')
        self.assertIn('reports', result['reason'])
        self.assertIn('not independently observed', result['reason'])
        db['payload']['database_connections_attempted'] = 0
        result = baseline.findings({}, db, None, Path('/source'))[1]
        self.assertEqual(result['status'], 'BLOCKED')
        self.assertIn('reports BLOCKED and zero attempts', result['reason'])
        self.assertIn('not independently observed', result['reason'])
        db['payload']['database_connections_attempted'] = False
        self.assertEqual(baseline.findings({}, db, None, Path('/source'))[1]['status'], 'INCONCLUSIVE')
        db['payload']['database_connections_attempted'] = 0
        db['exit_code'] = 0
        self.assertEqual(baseline.findings({}, db, None, Path('/source'))[1]['status'], 'INCONCLUSIVE')

    def test_reported_failure_is_labeled_as_claim(self):
        root = Path('/source')
        doctor = {'payload': {'checks': [{'name': 'source_identity', 'status': 'FAIL', 'details': {'source_sha': 'a' * 40, 'source_root': str(root), 'source_manifest_sha256': 'b' * 64}}]}}
        db = {'payload': {'status': 'FAIL', 'database_connections_attempted': 0}, 'exit_code': 10}
        source, database = baseline.findings(doctor, db, 'a' * 40, root)[:2]
        for result in (source, database):
            self.assertEqual(result['status'], 'FAIL')
            self.assertIn('reports', result['reason'])
            self.assertIn('not independently', result['reason'])

    def test_unbound_failure_claim_does_not_authenticate_source(self):
        head, root = 'a' * 40, Path('/source')
        valid = {'source_sha': head, 'source_root': str(root), 'source_manifest_sha256': 'b' * 64}
        variants = [
            ('missing_head', None, root, dict(valid)),
            ('wrong_head', 'c' * 40, root, dict(valid)),
            ('wrong_root', head, Path('/other'), dict(valid)),
            ('missing_digest', head, root, {'source_sha': head, 'source_root': str(root)}),
            ('short_digest', head, root, {**valid, 'source_manifest_sha256': 'b' * 63}),
            ('uppercase_digest', head, root, {**valid, 'source_manifest_sha256': 'B' * 64}),
            ('nonstr_digest', head, root, {**valid, 'source_manifest_sha256': False}),
        ]
        for label, supplied_head, supplied_root, details in variants:
            with self.subTest(label=label):
                doctor = {'payload': {'checks': [{'name': 'source_identity', 'status': 'FAIL', 'details': details}]}}
                result = baseline.findings(doctor, {}, supplied_head, supplied_root)[0]
                self.assertEqual(result['status'], 'INCONCLUSIVE')
                self.assertIn('reports failure', result['reason'])
                self.assertIn('not independently authenticated', result['reason'])

    def test_duplicate_source_claims_are_ambiguous_and_preserve_any_failure(self):
        head, root = 'a' * 40, Path('/source')
        details = {'source_sha': head, 'source_root': str(root), 'source_manifest_sha256': 'b' * 64, 'dirty': False}
        for first, second in [('PASS', 'FAIL'), ('FAIL', 'PASS'), ('FAIL', 'FAIL'), ('PASS', 'PASS'), ('INCONCLUSIVE', 'PASS')]:
            with self.subTest(first=first, second=second):
                doctor = {'payload': {'checks': [
                    {'name': 'source_identity', 'status': first, 'details': dict(details)},
                    {'name': 'source_identity', 'status': second, 'details': dict(details)},
                ]}}
                result = baseline.findings(doctor, {}, head, root)[0]
                self.assertEqual(result['status'], 'INCONCLUSIVE')
                self.assertIn('ambiguous', result['reason'])
                self.assertIn('not independently authenticated', result['reason'])
                if 'FAIL' in (first, second):
                    self.assertIn('reports failure', result['reason'])
                else:
                    self.assertNotIn('reports failure', result['reason'])

    def test_duplicate_failure_is_preserved_even_when_unbound(self):
        doctor = {'payload': {'checks': [
            {'name': 'source_identity', 'status': 'PASS', 'details': {'source_sha': 'a' * 40}},
            {'name': 'source_identity', 'status': 'FAIL', 'details': None},
        ]}}
        result = baseline.findings(doctor, {}, None, Path('/source'))[0]
        self.assertEqual(result['status'], 'INCONCLUSIVE')
        self.assertIn('ambiguous', result['reason'])
        self.assertIn('reports failure', result['reason'])
        self.assertIn('not independently authenticated', result['reason'])

    def test_main_head_and_database_claims_are_labeled_without_spawning(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / 'source'
            root.mkdir()
            output = Path(directory) / 'report.json'
            head = 'a' * 40
            doctor = {'payload': {'checks': [{'name': 'source_identity', 'status': 'PASS', 'details': {'source_sha': head, 'source_root': str(root), 'source_manifest_sha256': 'b' * 64, 'dirty': False}}]}}
            database = {'payload': {'status': 'BLOCKED', 'database_connections_attempted': 0}, 'exit_code': 20}
            with patch.object(sys, 'argv', ['baseline', '--source-root', str(root), '--output', str(output)]), \
                    patch.object(baseline.subprocess, 'Popen', side_effect=AssertionError('unexpected subprocess')), \
                    patch.object(baseline.subprocess, 'run') as git, \
                    patch.object(baseline, 'run', side_effect=[doctor, database]), \
                    patch.object(sys, 'stdout', new_callable=io.StringIO):
                git.return_value.stdout = head + '\n'
                self.assertEqual(baseline.main(), 20)
            report = json.loads(output.read_text())
            self.assertEqual(report['source_sha'], head)
            self.assertIn('unverified git subprocess claim', report['scope'])
            self.assertIn('self-reported, not independently observed', report['scope'])
            self.assertEqual(report['product_gate_effect'], 'NONE')
            self.assertEqual(report['findings'][0]['status'], 'INCONCLUSIVE')
            self.assertEqual(report['findings'][1]['status'], 'BLOCKED')

    def test_child_cannot_inherit_database_opt_in_or_postgres_settings(self):
        with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ, {
                'DATABASE_URL': 'private', 'ECP_DATABASE_URL': 'private',
                'ECP_DATABASE_DISPOSABLE': '1', 'PGHOST': '/production'}, clear=False):
            result = baseline.run([sys.executable, '-c',
                'import json,os; print(json.dumps({k:os.environ.get(k) for k in '
                '["DATABASE_URL","ECP_DATABASE_URL","ECP_DATABASE_DISPOSABLE","PGHOST"]}))'], Path(directory))
            self.assertEqual(result['exit_code'], 0)
            self.assertTrue(all(value is None for value in result['payload'].values()))

    def test_shell_startup_hook_cannot_restore_database_opt_in(self):
        with tempfile.TemporaryDirectory() as directory:
            hook = Path(directory) / 'hook.sh'
            hook.write_text('export ECP_DATABASE_DISPOSABLE=1\n')
            script = Path(__file__).resolve().parents[2] / 'ops/ecp/test_database.sh'
            with patch.dict(os.environ, {'BASH_ENV': str(hook)}, clear=False):
                result = baseline.run(['bash', str(script)], Path(directory))
            self.assertEqual(result['exit_code'], 20)
            self.assertIn('set ECP_DATABASE_DISPOSABLE=1', result['payload']['reason'])
            self.assertEqual(result['payload']['connections_attempted'], 0)

    def test_evidence_cannot_overwrite_or_write_into_source(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / 'source'
            root.mkdir()
            existing = Path(directory) / 'receipt.json'
            existing.write_text('preserve')
            broken_link = Path(directory) / 'broken.json'
            broken_link.symlink_to(Path(directory) / 'missing.json')
            script = str(Path(__file__).with_name('baseline_regressions.py'))
            for target in [existing, root / 'receipt.json', broken_link]:
                result = subprocess.run([sys.executable, script, '--source-root', str(root), '--output', str(target)], capture_output=True)
                self.assertEqual(result.returncode, 2)
            self.assertEqual(existing.read_text(), 'preserve')
            self.assertFalse((root / 'receipt.json').exists())
            self.assertFalse((Path(directory) / 'missing.json').exists())

if __name__ == '__main__':
    unittest.main()
