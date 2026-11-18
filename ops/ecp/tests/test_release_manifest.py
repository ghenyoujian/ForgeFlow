from __future__ import annotations
import copy
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'ops' / 'ecp'))
import release_manifest as release
import source_snapshot as source


def digest(document):
    core = {k: v for k, v in document.items() if k not in {'manifest_sha256', 'created_at', 'release_qualifiable'}}
    document['manifest_sha256'] = hashlib.sha256(release.canonical_json(core)).hexdigest()
    return document


class SourceManifestReleaseTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='ecp-source-v2-test-')
        self.addCleanup(self.temp.cleanup)
        self.parent = Path(self.temp.name)
        self.root = self.parent / 'source'
        self.root.mkdir()
        self.git('init', '-q')
        (self.root / 'tracked').write_text('original\n')
        self.git('add', 'tracked')
        self.git('-c', 'user.name=fixture', '-c', 'user.email=fixture@invalid', 'commit', '-qm', 'initial')
        self.head = self.git('rev-parse', 'HEAD').strip()
        self.manifest_file = self.parent / 'manifest.json'
        self.original = source.build_manifest(self.root, source.DEFAULT_EXCLUDES)
        assert self.original['inventory_complete'] is True
        # Bind the fixture to the current v2 producer.
        self.v2 = digest({**self.original, 'schema_version': release.SOURCE_V2})

    def git(self, *args):
        return subprocess.run(['git', *args], cwd=self.root, check=True, text=True, capture_output=True).stdout

    def inspect(self, document, *, dirty=None):
        self.manifest_file.write_text(json.dumps(document))
        return release.inspect_source_manifest(self.manifest_file, self.root, self.head, dirty or [])

    def test_fresh_strict_v2_matches_independent_source(self):
        status, _, detail = self.inspect(self.v2)
        self.assertEqual(status, 'PASS', detail)
        self.assertTrue(detail['inventory_verified'])

    def test_actual_v2_producer_dirty_and_incomplete_shapes_are_valid_but_not_qualifiable(self):
        (self.root/'empty-input').mkdir()
        dirty = source.build_manifest(self.root, source.DEFAULT_EXCLUDES)
        self.assertEqual(dirty['schema_version'], release.SOURCE_V2)
        self.assertIsNone(release._source_v2_error(dirty))
        self.assertEqual(self.inspect(dirty)[0], 'INCONCLUSIVE')
        (self.root/'empty-input').rmdir()
        self.git('update-index', '--skip-worktree', 'tracked')
        try:
            incomplete = source.build_manifest(self.root, source.DEFAULT_EXCLUDES)
            self.assertFalse(incomplete['inventory_complete'])
            self.assertIsNone(release._source_v2_error(incomplete))
            self.assertEqual(self.inspect(incomplete)[0], 'INCONCLUSIVE')
        finally:
            self.git('update-index', '--no-skip-worktree', 'tracked')

    def test_legacy_v1_and_nonconforming_v1_are_read_only_and_inconclusive(self):
        old_extended = digest({**self.original, 'schema_version': release.SOURCE_V1})
        legacy = digest({k: v for k, v in old_extended.items() if k not in {'inventory_complete', 'inventory_error', 'index_visibility_exceptions'}})
        for label, data in [('nonconforming-extended', old_extended), ('legacy-v1', legacy)]:
            with self.subTest(label=label):
                self.manifest_file.write_text(json.dumps(data))
                before = self.manifest_file.read_bytes()
                status, _, detail = release.inspect_source_manifest(self.manifest_file, self.root, self.head, [])
                self.assertEqual(status, 'INCONCLUSIVE', detail)
                self.assertEqual(before, self.manifest_file.read_bytes())
                self.assertEqual(data['schema_version'], release.SOURCE_V1)

    def test_unknown_version_or_tampered_digest_is_rejected(self):
        candidate = digest({**self.v2, 'schema_version': 'forgeflow.ecp-source-manifest.v3'})
        self.assertEqual(self.inspect(candidate)[0], 'REJECTED')
        candidate = {**self.v2, 'head': 'a' * 40}
        self.assertEqual(self.inspect(candidate)[0], 'REJECTED')

    def test_v2_missing_unknown_or_contradictory_fields_are_rejected(self):
        variants = []
        for key in ('inventory_complete', 'inventory_error', 'index_visibility_exceptions'):
            value = copy.deepcopy(self.v2); value.pop(key); variants.append(value)
        variants.extend([
            {**self.v2, 'unexpected': True},
            {**self.v2, 'inventory_complete': False},
            {**self.v2, 'inventory_complete': 'true'},
            {**self.v2, 'inventory_error': 'an error'},
            {**self.v2, 'index_visibility_exceptions': [{'path':'tracked', 'skip_worktree': True, 'assume_unchanged': False}]},
            {**self.v2, 'release_qualifiable': False},
            {**self.v2, 'head': 'a' * 41},
            {**self.v2, 'patch_sha256': 'a' * 64 + '\n'},
        ])
        for case in variants:
            with self.subTest(case=case):
                self.assertEqual(self.inspect(digest(case))[0], 'REJECTED')

    def test_real_producer_entry_shapes_match_stdlib_validator(self):
        (self.root / 'link').symlink_to('tracked')
        (self.root / 'summary').mkdir()
        entries = [
            source.source_entry(self.root, 'tracked', ' M'),
            source.source_entry(self.root, 'missing', ' D'),
            source.source_entry(self.root, 'link', '??'),
            source.source_entry(self.root, 'summary', '??'),
        ]
        self.assertEqual([entry['kind'] for entry in entries],
                         ['file', 'deleted', 'symlink', 'directory_summary'])
        for entry in entries:
            with self.subTest(kind=entry['kind']):
                candidate = {**self.v2, 'worktree_state':'DIRTY_UNFROZEN',
                             'release_qualifiable':False, 'tracked_changes':[entry]}
                self.assertIsNone(release._source_v2_error(candidate))
        invalid = {**entries[-1], 'mode': None}
        candidate = {**self.v2, 'worktree_state':'DIRTY_UNFROZEN',
                     'release_qualifiable':False, 'tracked_changes':[invalid]}
        self.assertIsNotNone(release._source_v2_error(candidate))

    def test_duplicate_keys_are_rejected(self):
        self.manifest_file.write_text('{"schema_version":"x","schema_version":"y"}')
        self.assertEqual(release.inspect_source_manifest(self.manifest_file, self.root, self.head, [])[0], 'REJECTED')

    def test_real_hidden_index_change_cannot_be_accepted(self):
        for flag in ('--assume-unchanged', '--skip-worktree'):
            with self.subTest(flag=flag):
                self.git('update-index', flag, 'tracked')
                (self.root / 'tracked').write_text('hidden change\n')
                head, dirty = release.git_identity(self.root)
                self.assertEqual(head, self.head)
                self.assertEqual(dirty, [])
                status, _, detail = self.inspect(self.v2)
                self.assertNotEqual(status, 'PASS', detail)
                self.assertEqual(status, 'INCONCLUSIVE', detail)
                self.git('update-index', '--no-assume-unchanged', '--no-skip-worktree', 'tracked')
                (self.root / 'tracked').write_text('original\n')

    def test_ignored_business_source_cannot_be_hidden(self):
        (self.root / '.gitignore').write_text('ignored-input\n')
        self.git('add', '.gitignore')
        self.git('-c', 'user.name=fixture', '-c', 'user.email=fixture@invalid', 'commit', '-qm', 'ignore')
        self.head = self.git('rev-parse', 'HEAD').strip()
        fresh = source.build_manifest(self.root, source.DEFAULT_EXCLUDES)
        candidate = digest({**fresh, 'schema_version': release.SOURCE_V2})
        (self.root / 'ignored-input').write_text('business input\n')
        _, dirty = release.git_identity(self.root)
        self.assertEqual(dirty, [])
        self.assertEqual(self.inspect(candidate)[0], 'INCONCLUSIVE')

    def test_independent_oracle_blocks_common_producer_omission(self):
        self.git('update-index', '--skip-worktree', 'tracked')
        (self.root / 'tracked').write_text('hidden change\n')
        # Even two identical falsely clean producer responses cannot bypass A10.
        with patch.object(release, '_current_source_snapshot', return_value=self.original):
            status, _, detail = self.inspect(self.v2)
        self.assertEqual(status, 'INCONCLUSIVE', detail)
        self.assertIn('independent source', detail['reason'])

    def test_empty_untracked_directory_and_policy_drift_fail_closed(self):
        (self.root / 'empty-business-dir').mkdir()
        with patch.object(release, '_current_source_snapshot', return_value=self.original):
            self.assertEqual(self.inspect(self.v2)[0], 'INCONCLUSIVE')
        (self.root / 'empty-business-dir').rmdir()
        value = digest({**self.v2, 'exclude_patterns': self.v2['exclude_patterns'] + ['src/']})
        status, _, detail = self.inspect(value)
        self.assertEqual(status, 'INCONCLUSIVE', detail)
        self.assertIn('policy differs', detail['reason'])

    def test_independent_mode_unavailable_timeout_missing_and_budget(self):
        oracle = release._load_independent_source_oracle()
        with patch.object(release, '_load_independent_source_oracle', return_value=oracle):
            with patch.object(oracle, 'source_mode_availability', return_value=('UNAVAILABLE', '9p')):
                status, _, detail = self.inspect(self.v2)
                self.assertEqual(status, 'INCONCLUSIVE', detail)
                self.assertEqual(detail['source_execution_mode'], 'UNAVAILABLE')
            with patch.object(oracle, 'source_clean_begin', side_effect=subprocess.TimeoutExpired('git', 1)):
                self.assertEqual(self.inspect(self.v2)[0], 'INCONCLUSIVE')
            with patch.object(oracle, 'MAX_SOURCE_BYTES', 1):
                self.assertEqual(self.inspect(self.v2)[0], 'INCONCLUSIVE')
        with patch.object(release, '_load_independent_source_oracle', side_effect=FileNotFoundError('oracle absent')):
            self.assertEqual(self.inspect(self.v2)[0], 'INCONCLUSIVE')

    def test_tracked_excluded_content_is_independently_verified(self):
        folder = self.root / 'evidence'
        folder.mkdir()
        tracked = folder / 'tracked.log'
        tracked.write_text('committed evidence source\n')
        self.git('add', '-f', 'evidence/tracked.log')
        self.git('-c', 'user.name=fixture', '-c', 'user.email=fixture@invalid', 'commit', '-qm', 'tracked excluded')
        self.head = self.git('rev-parse', 'HEAD').strip()
        fresh = source.build_manifest(self.root, source.DEFAULT_EXCLUDES)
        candidate = digest({**fresh, 'schema_version': release.SOURCE_V2})
        tracked.write_text('tampered source bytes\n')
        with patch.object(release, '_current_source_snapshot', return_value=fresh):
            status, _, detail = self.inspect(candidate)
        self.assertEqual(status, 'INCONCLUSIVE', detail)

    def test_independent_end_rejects_source_mutated_between_observations(self):
        calls = 0
        def lying_producer(*args):
            nonlocal calls
            calls += 1
            if calls == 2:
                (self.root / 'tracked').write_text('changed after independent read\n')
            return self.original
        with patch.object(release, '_current_source_snapshot', side_effect=lying_producer):
            status, _, detail = self.inspect(self.v2)
        self.assertEqual(status, 'INCONCLUSIVE', detail)
        self.assertIn('recheck', detail['reason'])

    def test_git_environment_redirect_fails_closed_and_symlink_root_rejected(self):
        with patch.dict('os.environ', {'GIT_DIR':'/not/a/repo','GIT_WORK_TREE':'/elsewhere'}):
            self.assertEqual(release.git_identity(self.root)[0], self.head)
            self.assertIn(self.inspect(self.v2)[0], ('BLOCKED', 'INCONCLUSIVE'))
        alias = self.parent / 'alias'
        alias.symlink_to(self.root, target_is_directory=True)
        observation, failure, _ = release._independent_begin(alias, self.head)
        self.assertIsNone(observation)
        self.assertEqual(failure, 'INCONCLUSIVE')

    def test_release_main_rechecks_source_after_other_inputs(self):
        self.manifest_file.write_text(json.dumps(self.v2))
        schema = self.parent / 'schema'; schema.mkdir(); (schema/'x').write_text('x')
        profile = self.parent / 'profile'; profile.mkdir(); (profile/'x').write_text('x')
        evidence = self.parent / 'evidence'; evidence.mkdir(); (evidence/'x').write_text('x')
        gate = self.parent / 'gate.json'; gate.write_text('{}')
        output = self.parent / 'release.json'
        def mutate_during_binary_inventory(_):
            (self.root / 'tracked').write_text('changed during release assembly\n')
            return ([{'name':'fixture','mode':'0755','sha256':'a'*64}], None)
        args=['--source-root',str(self.root),'--source-manifest',str(self.manifest_file),
              '--binary',str(self.parent/'unused-binary'),'--schema-root',str(schema),
              '--profile-root',str(profile),'--evidence-root',str(evidence),
              '--gate-snapshot',str(gate),'--output',str(output)]
        with patch.object(release, 'binary_inventory', side_effect=mutate_during_binary_inventory):
            self.assertEqual(release.main(args), 20)
        result=json.loads(output.read_text())
        check=next(item for item in result['checks'] if item['name']=='source_identity')
        self.assertEqual(check['status'], 'INCONCLUSIVE', check)
        self.assertNotEqual(result['status'], 'CANDIDATE')
        self.assertEqual(result['qualification'], 'NOT_RUN')

    def test_inventory_unavailable_and_changing_fail_closed(self):
        with patch.object(release, '_current_source_snapshot', side_effect=OSError('unavailable')):
            self.assertEqual(self.inspect(self.v2)[0], 'BLOCKED')
        altered = {**self.original, 'manifest_sha256': 'f' * 64}
        with patch.object(release, '_current_source_snapshot', side_effect=[self.original, altered]):
            self.assertEqual(self.inspect(self.v2)[0], 'INCONCLUSIVE')


if __name__ == '__main__':
    unittest.main()
