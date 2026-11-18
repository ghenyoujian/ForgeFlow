"""Pure mock dispatch-order tests; never execute Git, DB or a child process."""
import importlib.util
import subprocess
from pathlib import Path
import sys
import types
import unittest
from unittest.mock import patch

stub = types.ModuleType('source_snapshot')
stub.DEFAULT_EXCLUDES = ()
stub.build_manifest = lambda *_args, **_kw: None
_MISSING = object()
_previous_source_snapshot = sys.modules.get('source_snapshot', _MISSING)
_candidate_name = 'p003_verify_candidate'
_previous_candidate = sys.modules.get(_candidate_name, _MISSING)
sys.modules['source_snapshot'] = stub
try:
    spec = importlib.util.spec_from_file_location(
        _candidate_name, Path(__file__).resolve().parent.parent / 'verify.py')
    verify = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = verify
    spec.loader.exec_module(verify)
finally:
    if _previous_candidate is _MISSING:
        sys.modules.pop(_candidate_name, None)
    else:
        sys.modules[_candidate_name] = _previous_candidate
    if _previous_source_snapshot is _MISSING:
        sys.modules.pop('source_snapshot', None)
    else:
        sys.modules['source_snapshot'] = _previous_source_snapshot
_restored_immediately = (('source_snapshot' not in sys.modules) if _previous_source_snapshot is _MISSING
                         else (sys.modules.get('source_snapshot') is _previous_source_snapshot))
_candidate_restored_immediately = ((_candidate_name not in sys.modules) if _previous_candidate is _MISSING
                                   else (sys.modules.get(_candidate_name) is _previous_candidate))


class SuiteRegistryOrderingTests(unittest.TestCase):
    def args(self, suite, *options):
        return verify.parser().parse_args(['suite', '--suite', suite, *options])

    def test_candidate_module_registry_restored_after_import(self):
        self.assertTrue(_candidate_restored_immediately, 'candidate module leaked during test module import')

    def test_unknown_suite_blocks_before_git_and_preserves_output_target(self):
        self.assertTrue(_restored_immediately, 'source_snapshot stub leaked during test module import')
        args = self.args('ECP-P0-UNKNOWN', '--output', 'caller-report.json')
        for registry in [(None, None, 'suite registry is unavailable'),
                         (Path('/fixture/registry.json'), None, 'suite ECP-P0-UNKNOWN is not declared in the registry')]:
            with self.subTest(registry=registry), \
                 patch.object(verify, 'resolve_source_root', return_value=Path('/fixture')), \
                 patch.object(verify, 'load_declared_suite', return_value=registry) as load, \
                 patch.object(verify, 'git_sha', side_effect=AssertionError('must not run Git')) as git, \
                 patch.object(verify, 'write_report', side_effect=lambda report, output: report) as write:
                report, code = verify.suite(args)
                self.assertEqual(code, 20)
                self.assertEqual((report['status'], report['qualification'], report['product_gate_effect']), ('BLOCKED', 'NOT_RUN', 'NONE'))
                self.assertIsNone(report['source_sha'])
                self.assertEqual(report['reason'], registry[2])
                self.assertEqual(report['checks'][0]['name'], 'suite_registry')
                self.assertEqual(report['denominator']['blocked'], 1)
                self.assertEqual(write.call_args.args[1], 'caller-report.json')
                git.assert_not_called()
                load.assert_called_once_with(Path('/fixture'), 'ECP-P0-UNKNOWN')

    def test_registered_unbound_suite_preserves_not_run_without_git(self):
        cases = [(['suite', '--suite', 'ECP-P0-99'], 'ECP-P0-99'),
                 (['suite', '--phase', '7'], 'phase-7'),
                 (['suite', '--release-candidate'], 'release-candidate')]
        for command, suite_id in cases:
            with self.subTest(suite_id=suite_id):
                args = verify.parser().parse_args(command + ['--profile', 'local', '--output', 'registered.json'])
                entry = {'suite_id': suite_id, 'offline_workload': {'runner': 'unused'}}
                with patch.object(verify, 'resolve_source_root', return_value=Path('/fixture')), \
                     patch.object(verify, 'load_declared_suite', return_value=(Path('/fixture/registry.json'), entry, None)) as load, \
                     patch.object(verify, 'git_sha', side_effect=AssertionError('unbound suite must not run Git')) as git, \
                     patch.object(verify, 'write_report', side_effect=lambda report, output: report) as write:
                    report, code = verify.suite(args)
                self.assertEqual((code, report['status'], report['source_sha']), (20, 'NOT_RUN', None))
                self.assertEqual(report['reason'], 'suite is registered but has no bound executable workload/oracle')
                self.assertEqual((report['suite_id'], report['profile'], report['product_gate_effect']), (suite_id, 'local', 'NONE'))
                self.assertEqual(report['checks'][0]['name'], suite_id)
                self.assertEqual(report['denominator'], {'total': 1, 'passed': 0, 'failed': 0, 'blocked': 0, 'not_run': 1, 'inconclusive': 0})
                self.assertEqual(write.call_args.args[1], 'registered.json')
                load.assert_called_once_with(Path('/fixture'), suite_id)
                git.assert_not_called()

    def test_v3_generic_and_p005_block_before_git(self):
        for suite in ('ECP-P0-UNKNOWN', 'ECP-P0-05'):
            with self.subTest(suite=suite), \
                 patch.object(verify, 'resolve_source_root', return_value=Path('/fixture')), \
                 patch.object(verify, 'load_declared_suite', side_effect=AssertionError('registry not used')) as load, \
                 patch.object(verify, 'git_sha', side_effect=AssertionError('must not run Git')) as git, \
                 patch.object(verify, 'write_report', side_effect=lambda report, output: report) as write:
                report, code = verify.suite(self.args(suite, '--source-manifest-version', '3', '--output', 'unused.json'))
                self.assertEqual((code, report['status'], report['qualification'], report['product_gate_effect']), (20, 'BLOCKED', 'NOT_RUN', 'NONE'))
                self.assertIsNone(report['source_sha'])
                self.assertEqual(report['suite_id'], suite)
                self.assertIn('only supported by ECP-P0-01', report['reason'])
                self.assertEqual(report['denominator']['total'], 0)
                self.assertIsNone(write.call_args.args[1])
                git.assert_not_called(); load.assert_not_called()

    def test_p002_v3_retains_special_version_guard(self):
        with patch.object(verify, 'resolve_source_root', return_value=Path('/fixture')), \
             patch.object(verify, 'run_database_suite', side_effect=AssertionError('must not run')) as run, \
             patch.object(verify, 'git_sha', side_effect=AssertionError('must not run Git')) as git, \
             patch.object(verify, 'load_declared_suite', side_effect=AssertionError('must not read registry')) as load, \
             patch.object(verify, 'write_report', side_effect=lambda report, output: report) as write:
            report, code = verify.suite(self.args('ECP-P0-02', '--source-manifest-version', '3', '--output', 'unused.json'))
        self.assertEqual((code, report['status'], report['suite_id']), (20, 'BLOCKED', 'ECP-P0-02'))
        self.assertIsNone(report['source_sha']); self.assertIn('only supported by ECP-P0-01', report['reason'])
        self.assertIsNone(write.call_args.args[1]); run.assert_not_called(); git.assert_not_called(); load.assert_not_called()

    def test_p003_v3_still_uses_existing_early_block(self):
        marker = ({'special':'p003-v3'}, 20)
        with patch.object(verify, 'resolve_source_root', return_value=Path('/fixture')), \
             patch.object(verify, 'run_phase0_offline_suite', return_value=marker) as run, \
             patch.object(verify, 'git_sha', side_effect=AssertionError('must not run Git')) as git, \
             patch.object(verify, 'load_declared_suite', side_effect=AssertionError('must not read registry')) as load:
            self.assertEqual(verify.suite(self.args('ECP-P0-03', '--source-manifest-version', '3')), marker)
        run.assert_called_once(); git.assert_not_called(); load.assert_not_called()

    def test_p001_v3_branch_precedes_source_and_registry(self):
        marker = ({'special':'p001-v3'}, 20)
        with patch.object(verify, '_blocked_p001_v3', return_value=marker) as blocked, \
             patch.object(verify, 'resolve_source_root', side_effect=AssertionError('not called')), \
             patch.object(verify, 'git_sha', side_effect=AssertionError('not called')), \
             patch.object(verify, 'load_declared_suite', side_effect=AssertionError('not called')):
            self.assertEqual(verify.suite(self.args('ECP-P0-01', '--source-manifest-version', '3')), marker)
        blocked.assert_called_once()

    def test_p003_remains_immediate_block(self):
        marker = ({'special':'p003'}, 20)
        with patch.object(verify, 'resolve_source_root', return_value=Path('/fixture')), \
             patch.object(verify, 'run_phase0_offline_suite', return_value=marker) as run, \
             patch.object(verify, 'git_sha', side_effect=AssertionError('not called')), \
             patch.object(verify, 'load_declared_suite', side_effect=AssertionError('not called')):
            self.assertEqual(verify.suite(self.args('ECP-P0-03')), marker)
        run.assert_called_once()

    def test_p002_remains_on_database_guard_without_git(self):
        marker = ({'special':'p002'}, 20)
        with patch.object(verify, 'resolve_source_root', return_value=Path('/fixture')), \
             patch.object(verify, 'run_database_suite', return_value=marker) as run, \
             patch.object(verify, 'git_sha', side_effect=AssertionError('not called')), \
             patch.object(verify, 'load_declared_suite', side_effect=AssertionError('not called')):
            self.assertEqual(verify.suite(self.args('ECP-P0-02')), marker)
        run.assert_called_once()

    def test_p001_v2_retains_git_and_snapshot_dispatch(self):
        marker = ({'special':'p001-v2'}, 20)
        with patch.object(verify, 'resolve_source_root', return_value=Path('/fixture')), \
             patch.object(verify, 'git_sha', return_value=('claimed-head', None)) as git, \
             patch.object(verify, 'run_source_snapshot_suite', return_value=marker) as run, \
             patch.object(verify, 'load_declared_suite', side_effect=AssertionError('not called')):
            self.assertEqual(verify.suite(self.args('ECP-P0-01')), marker)
        self.assertEqual(run.call_args.args[2], 'claimed-head'); git.assert_called_once()

    def test_p005_invalid_registry_blocks_before_git_and_output_write(self):
        cases = [
            (None, None, 'suite registry is unavailable', 'suite registry is unavailable'),
            (Path('/fixture/registry.json'), None, 'suite registry is unreadable: bad json', 'suite registry is unreadable: bad json'),
            (Path('/fixture/registry.json'), None, None, 'P0-05 registry entrypoint does not match the reviewed workflow'),
            (Path('/fixture/registry.json'), {'implementation_entrypoint':'other'}, None, 'P0-05 registry entrypoint does not match the reviewed workflow'),
        ]
        for path, entry, error, reason in cases:
            with self.subTest(entry=entry, error=error), \
                 patch.object(verify, 'resolve_source_root', return_value=Path('/fixture')), \
                 patch.object(verify, 'load_declared_suite', return_value=(path, entry, error)) as load, \
                 patch.object(verify, 'git_sha', side_effect=AssertionError('invalid P005 registry must not run Git')) as git, \
                 patch.object(verify, 'write_report', side_effect=lambda report, output: report) as write, \
                 patch.dict(sys.modules, {'p005_build_runner': None}):
                report, code = verify.suite(self.args('ECP-P0-05', '--output', 'existing.json'))
                self.assertEqual((code, report['status'], report['qualification'], report['product_gate_effect']), (20, 'BLOCKED', 'NOT_RUN', 'NONE'))
                self.assertIsNone(report['source_sha'])
                self.assertEqual(report['reason'], reason)
                self.assertEqual(report['checks'], [{'name':'suite_registry_binding','status':'BLOCKED'}])
                self.assertEqual(report['denominator'], {'total':1,'passed':0,'failed':0,'blocked':1,'not_run':0,'inconclusive':0})
                self.assertIsNone(write.call_args.args[1]); git.assert_not_called()
                load.assert_called_once_with(Path('/fixture'), 'ECP-P0-05')

    def test_p005_valid_registry_blocks_before_git_runner_and_output(self):
        entry = {'implementation_entrypoint':'control/.github/workflows/ecp-baseline.yml'}
        args = self.args('ECP-P0-05', '--output', '/never-write/report.json',
                         '--evidence-root', '/never-write/evidence', '--candidate-root', '/never-read/candidate')
        with patch.object(verify, 'resolve_source_root', return_value=Path('/fixture')), \
             patch.object(verify, 'load_declared_suite', return_value=(Path('/fixture/registry.json'), entry, None)) as load, \
             patch.object(verify, 'git_sha', side_effect=AssertionError('Git forbidden')) as git, \
             patch.object(verify, 'run_git', side_effect=AssertionError('Git forbidden')) as git_child, \
             patch.object(subprocess, 'Popen', side_effect=AssertionError('process forbidden')) as spawn, \
             patch.object(Path, 'read_bytes', side_effect=AssertionError('registry reread forbidden')) as reread, \
             patch.object(verify, 'write_report', side_effect=lambda report, output: report) as write, \
             patch.dict(sys.modules, {'p005_build_runner': None}):
            report, code = verify.suite(args)
        self.assertEqual((code, report['status'], report['qualification'], report['product_gate_effect']),
                         (20, 'BLOCKED', 'NOT_RUN', 'NONE'))
        self.assertIsNone(report['source_sha'])
        self.assertEqual(report['suite_id'], 'ECP-P0-05')
        self.assertEqual(report['profile'], 'isolated')
        self.assertFalse(report['workload_invoked'])
        self.assertEqual((report['source_review'], report['sandbox_probe']), ('NOT_RUN', 'NOT_RUN'))
        self.assertEqual(report['registry_path'], '/fixture/registry.json')
        self.assertIsNone(report['registry_sha256'])
        self.assertEqual(report['registry_authentication'], 'UNVERIFIED')
        self.assertEqual(report['workloads'], {name:'NOT_RUN' for name in ('npm_ci','cargo_build','cargo_test','npm_build')})
        self.assertEqual(report['denominator_scope'], 'declared_workloads')
        self.assertEqual(report['denominator'], {'total':4,'passed':0,'failed':0,'blocked':0,'not_run':4,'inconclusive':0,'skipped':0})
        self.assertEqual(report['checks'][0]['name'], 'process_supervision')
        self.assertEqual(report['checks'][0]['status'], 'BLOCKED')
        self.assertIn('bounded process-tree supervision', report['reason'])
        self.assertIsNone(write.call_args.args[1])
        load.assert_called_once_with(Path('/fixture'), 'ECP-P0-05')
        git.assert_not_called(); git_child.assert_not_called(); spawn.assert_not_called(); reread.assert_not_called()

    def test_p005_valid_registry_no_requested_profile_can_launch(self):
        entry = {'implementation_entrypoint':'control/.github/workflows/ecp-baseline.yml'}
        for profile, registry_path in (('isolated', Path('/fixture/registry.json')), ('other', Path('/fixture/registry.json')), ('isolated', None)):
            # Keep all assertions within this subTest: an expected red failure
            # must not access a result that was never assigned or skip cases.
            with self.subTest(profile=profile, registry_path=registry_path):
                with patch.object(verify, 'resolve_source_root', return_value=Path('/fixture')), \
                     patch.object(verify, 'load_declared_suite', return_value=(registry_path, entry, None)), \
                     patch.object(verify, 'git_sha', side_effect=AssertionError('Git forbidden')) as git, \
                     patch.object(verify, 'write_report', side_effect=lambda report, output: report) as write, \
                     patch.dict(sys.modules, {'p005_build_runner': None}):
                    report, code = verify.suite(self.args('ECP-P0-05', '--profile', profile))
                self.assertEqual((code, report['status'], report['source_sha'], report['profile']),
                                 (20, 'BLOCKED', None, profile))
                self.assertEqual(report['denominator']['not_run'], 4)
                self.assertEqual((report['source_review'], report['sandbox_probe']), ('NOT_RUN', 'NOT_RUN'))
                self.assertEqual(report['registry_path'], str(registry_path) if registry_path is not None else None)
                self.assertIsNone(report['registry_sha256'])
                self.assertEqual(report['registry_authentication'], 'UNVERIFIED')
                self.assertEqual(set(report['workloads'].values()), {'NOT_RUN'})
                self.assertIsNone(write.call_args.args[1]); git.assert_not_called()


if __name__ == '__main__':
    unittest.main()
