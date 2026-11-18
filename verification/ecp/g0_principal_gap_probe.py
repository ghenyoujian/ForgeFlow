"""Disposable PostgreSQL runner for a fixture-only Store characterization.

Requires ECP_G0_GAP_TEST_BINARY: a separately compiled test binary for the same
source and dependencies. A successful run does not prove binary provenance,
authenticate an HTTP actor, or qualify any product Gate.
"""
import json
import os
import shlex
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from ops.ecp.tests import test_database_guard as database_guard


class PrivateAuthorityGap(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Run last, after the guard's own stop-and-remove cleanup.
        cls.addClassCleanup(cls.assert_cluster_cleaned)
        database_guard.RealDisposableDatabaseGuard.setUpClass.__func__(cls)

    @classmethod
    def assert_cluster_cleaned(cls):
        if hasattr(cls, 'root'):
            if cls.root.exists():
                raise RuntimeError('Disposable fixture cluster was not fully cleaned')
            print('FIXTURE_CLUSTER_CLEANED:', cls.root)

    def test_store_principal_lease_gap(self):
        binary = os.environ.get('ECP_G0_GAP_TEST_BINARY')
        if not binary or not os.path.isfile(binary) or not os.access(binary, os.X_OK):
            raise RuntimeError('BLOCKED: ECP_G0_GAP_TEST_BINARY must name the built test executable')
        clean_guard = {key: value for key, value in self.guarded.items()
                       if key not in ('BASH_ENV', 'ENV') and not key.startswith(('PYTHON', 'BASH_FUNC_'))}
        guard = subprocess.run(['/usr/bin/bash', str(database_guard.SCRIPT)],
                               env=clean_guard, text=True, capture_output=True, timeout=30)
        self.assertEqual(guard.returncode, 0, guard.stdout + guard.stderr)
        env = {key: value for key, value in clean_guard.items() if not key.startswith('PG')}
        env['DATABASE_URL'] = self.url
        command = [binary, '--exact', 'store_claim_can_be_valid_without_principal_or_grant_binding', '--ignored', '--nocapture']
        wrong_url = dict(env, DATABASE_URL=self.url.replace('ecp_disposable_expected', 'ecp_disposable_other'))
        wrong = subprocess.run(command, env=wrong_url, text=True, capture_output=True, timeout=30)
        self.assertNotEqual(wrong.returncode, 0, 'different Store URL must be rejected before connecting')
        self.assertIn('Store URL differs from guarded URL', wrong.stderr)
        overridden = dict(env, PGHOST='/tmp/not-the-verified-socket')
        pg_override = subprocess.run(command, env=overridden, text=True, capture_output=True, timeout=30)
        self.assertNotEqual(pg_override.returncode, 0, 'libpq override must be rejected before connecting')
        self.assertIn('inherited PostgreSQL environment options are forbidden', pg_override.stderr)
        fake_bin = self.root / 'fake-bin'
        fake_bin.mkdir()
        fake_marker = self.root / 'fake-bash-was-run'
        fake_bash = fake_bin / 'bash'
        fake_bash.write_text('#!/bin/sh\ntouch "$ECP_TEST_FAKE_BASH_MARKER"\nexit 0\n')
        fake_bash.chmod(0o700)
        env['ECP_TEST_FAKE_BASH_MARKER'] = str(fake_marker)
        env['PATH'] = str(fake_bin) + os.pathsep + env['PATH']

        # Actual shell hook tries to make the child guard validate the expected
        # database while the parent test would connect to the other database.
        # Both databases live solely inside this fixture's private cluster.
        other_url = self.url.replace('ecp_disposable_expected', 'ecp_disposable_other')
        hook_marker = self.root / 'bash-env-ran'
        hook = self.root / 'bash-env.sh'
        hook.write_text('touch ' + shlex.quote(str(hook_marker)) + '\nexport ECP_DATABASE_URL=' + shlex.quote(self.url) + '\n')
        attack_env = dict(env, DATABASE_URL=other_url, ECP_DATABASE_URL=other_url,
                          BASH_ENV=str(hook), ENV=str(hook))
        def psql_other(query):
            result = subprocess.run([str(self.pgroot / 'psql'), '-X', '-At', '-h', str(self.sock),
                                     '-p', str(self.port), '-U', 'ecp_probe', '-d', 'ecp_disposable_other',
                                     '-c', query], env=self.env, text=True, capture_output=True, timeout=30)
            self.assertEqual(result.returncode, 0, result.stderr)
            return result.stdout.strip()
        before = psql_other("SELECT to_regclass('public._sqlx_migrations') IS NULL")
        self.assertEqual(before, 't')
        baseline_gap = os.environ.get('ECP_G0_GAP_BASELINE_BINARY')
        if baseline_gap:
            old = subprocess.run([baseline_gap, *command[1:]], env=attack_env, text=True, capture_output=True, timeout=180)
            self.assertEqual(old.returncode, 0, old.stdout + old.stderr)
            self.assertTrue(hook_marker.exists(), 'old gap guard must execute the real hook')
            hook_marker.unlink()
            print('BASELINE_GAP_WRONG_DATABASE_ACCEPTED:', old.returncode == 0)
            print('BASELINE_GAP_STDOUT:', old.stdout)
            print('BASELINE_GAP_STDERR:', old.stderr)
        else:
            print('BASELINE_GAP_WRONG_DATABASE_ACCEPTED: NOT_RUN')
        attacked_gap = subprocess.run(command, env=attack_env, text=True, capture_output=True, timeout=60)
        self.assertNotEqual(attacked_gap.returncode, 0, 'wrong database must fail')
        self.assertIn('private database guard refused', attacked_gap.stderr)
        self.assertFalse(hook_marker.exists(), 'gap guard must not execute BASH_ENV')
        print('FIXED_GAP_WRONG_DATABASE_REJECTED:', attacked_gap.returncode)
        print('FIXED_GAP_STDOUT:', attacked_gap.stdout)
        print('FIXED_GAP_STDERR:', attacked_gap.stderr)

        migration_command = ['--exact', 'failed_and_cancelled_migrations_release_advisory_lock', '--ignored', '--nocapture']
        baseline_migration = os.environ.get('ECP_MIGRATION_BASELINE_BINARY')
        if baseline_migration:
            old_migration = subprocess.run([baseline_migration, *migration_command], env=attack_env,
                                           text=True, capture_output=True, timeout=180)
            self.assertEqual(old_migration.returncode, 0, old_migration.stdout + old_migration.stderr)
            self.assertTrue(hook_marker.exists(), 'old migration guard must execute the real hook')
            hook_marker.unlink()
            self.assertEqual(psql_other("SELECT to_regclass('public._sqlx_migrations') IS NOT NULL"), 't')
            print('BASELINE_MIGRATION_WRONG_DATABASE_MIGRATED:', True)
            print('BASELINE_MIGRATION_STDOUT:', old_migration.stdout)
            print('BASELINE_MIGRATION_STDERR:', old_migration.stderr)
        else:
            print('BASELINE_MIGRATION_WRONG_DATABASE_MIGRATED: NOT_RUN')
        fixed_migration = os.environ.get('ECP_MIGRATION_RECOVERY_TEST_BINARY')
        if fixed_migration:
            rejected = subprocess.run([fixed_migration, *migration_command], env=attack_env,
                                      text=True, capture_output=True, timeout=60)
            self.assertNotEqual(rejected.returncode, 0, 'migration must reject wrong database')
            self.assertIn('disposable database guard rejected', rejected.stderr)
            self.assertFalse(hook_marker.exists(), 'migration guard must not execute BASH_ENV')
            print('FIXED_MIGRATION_WRONG_DATABASE_REJECTED:', rejected.returncode)
            print('FIXED_MIGRATION_STDOUT:', rejected.stdout)
            print('FIXED_MIGRATION_STDERR:', rejected.stderr)
        else:
            print('FIXED_MIGRATION_WRONG_DATABASE_REJECTED: NOT_RUN')

        # Python interpreter startup injection should also not affect the child guard.
        injected = self.root / 'python-injection'
        injected.mkdir()
        python_marker = self.root / 'python-startup-ran'
        (injected / 'sitecustomize.py').write_text('open(' + repr(str(python_marker)) + ", 'w').write('unexpected')\n")
        env.update(PYTHONPATH=str(injected), PYTHONHOME='/fixture-invalid-python-home',
                   BASH_ENV=str(hook), ENV=str(hook))
        run = subprocess.run(command, env=env, text=True, capture_output=True, timeout=180)
        self.assertFalse(hook_marker.exists(), 'gap child guard must strip shell startup hooks')
        self.assertFalse(python_marker.exists(), 'gap child guard must strip Python startup hooks')
        self.assertFalse(fake_marker.exists(), 'PATH bash must not replace the database guard interpreter')
        print('PRIVATE_FIXTURE_GUARD:', guard.stdout.strip())
        print('PATH_BASH_HIJACK_EXECUTED:', fake_marker.exists())
        print('NEGATIVE_WRONG_URL_EXIT:', wrong.returncode)
        print('NEGATIVE_PG_OVERRIDE_EXIT:', pg_override.returncode)
        print('FIXTURE_BINARY_STDOUT:', run.stdout)
        print('FIXTURE_BINARY_STDERR:', run.stderr)
        self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
        self.assertIn('1 passed; 0 failed; 0 ignored', run.stdout)
        self.assertIn('"product_gate_effect":"NONE"', run.stdout)
        if fixed_migration:
            normal_migration = subprocess.run([fixed_migration, *migration_command], env=env,
                                              text=True, capture_output=True, timeout=180)
            print('FIXED_MIGRATION_NORMAL_STDOUT:', normal_migration.stdout)
            print('FIXED_MIGRATION_NORMAL_STDERR:', normal_migration.stderr)
            self.assertEqual(normal_migration.returncode, 0, normal_migration.stdout + normal_migration.stderr)
            self.assertIn('1 passed; 0 failed; 0 ignored', normal_migration.stdout)
            self.assertIn('failure_granted_advisory_locks=0', normal_migration.stdout)
            self.assertIn('cancel_granted_advisory_locks=0', normal_migration.stdout)
            self.assertIn('same_pool_different_connection_retry=Ok(Ok("ok"))', normal_migration.stdout)
            self.assertIn('cancel_same_pool_different_connection_retry=Ok(Ok("ok"))', normal_migration.stdout)
            self.assertFalse(hook_marker.exists(), 'migration guard must strip shell hooks on normal target')
            self.assertFalse(python_marker.exists(), 'migration guard must strip Python hooks on normal target')
            print('FIXED_MIGRATION_NORMAL_WITH_INJECTION:', 'PASS')
        else:
            print('FIXED_MIGRATION_NORMAL_WITH_INJECTION: NOT_RUN')


def main():
    binary = os.environ.get('ECP_G0_GAP_TEST_BINARY')
    if not binary or not os.path.isfile(binary) or not os.access(binary, os.X_OK):
        print(json.dumps({'status': 'BLOCKED', 'product_gate_effect': 'NONE',
                          'reason': 'ECP_G0_GAP_TEST_BINARY must name the separately built fixture test'}))
        return 20
    try:
        database_guard.postgres_bin_dir()
    except RuntimeError as exc:
        print(json.dumps({'status': 'BLOCKED', 'product_gate_effect': 'NONE', 'reason': str(exc)}))
        return 20
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(PrivateAuthorityGap)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    if not result.wasSuccessful() or result.testsRun != 1 or result.skipped:
        print(json.dumps({'status': 'FAIL', 'product_gate_effect': 'NONE',
                          'tests_run': result.testsRun, 'failures': len(result.failures),
                          'errors': len(result.errors), 'skipped': len(result.skipped)}))
        return 10
    print(json.dumps({'status': 'OBSERVED_NOT_GATE', 'product_gate_effect': 'NONE',
                      'reason': 'fixture counterexample; not an authorized verifier, HTTP or Gate',
                      'tests_run': result.testsRun}))
    return 20  # Observation of a gap cannot qualify as a product Gate.


if __name__ == '__main__':
    raise SystemExit(main())
