"""Draft-v3 schema and test-only semantic examples; no production qualification.

The standard-library evaluator deliberately supports only keywords used by the
schema and fails on unsupported keywords. A separate real JSON Schema engine
is needed for independent conformance; these fixtures do not inspect a source
filesystem or implement an authoritative validator.
"""
from __future__ import annotations

import copy
from datetime import datetime
import hashlib
import json
import re
import unittest
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parents[3]
SCHEMA = json.loads((ROOT / 'contracts/ecp/source_manifest.v3.schema.json').read_text(encoding='utf-8'))


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False,
                      allow_nan=False).encode('utf-8', 'strict')


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def seal(manifest):
    manifest['directory_projection']['exclusion_policy_sha256'] = digest(manifest['exclude_patterns'])
    manifest['projection_sha256'] = digest(manifest['directory_projection'])
    manifest['manifest_sha256'] = digest({k: v for k, v in manifest.items()
                                          if k not in {'manifest_sha256', 'created_at', 'release_qualifiable'}})
    return manifest


def fixture():
    return seal({
        'schema_version': 'forgeflow.ecp-source-manifest.v3', 'source_root': '/fixture/source',
        'head': 'a' * 40, 'worktree_state': 'CLEAN',
        'exclude_patterns': ['.git/', 'docs/idea/plan/evidence/'],
        'untracked_scan_mode': 'all', 'untracked_scan_roots': [], 'tracked_changes': [],
        'untracked_business_files': [], 'excluded_generated_files': [],
        'patch_sha256': hashlib.sha256(b'').hexdigest(), 'manifest_sha256': '0' * 64,
        'created_at': '2026-11-16T00:00:00Z', 'release_qualifiable': False,
        'inventory_complete': True, 'inventory_error': None, 'index_visibility_exceptions': [],
        'projection_sha256': '0' * 64,
        'directory_projection': {
            'version': 'forgeflow.ecp-directory-projection.v1', 'mode_availability': 'VERIFIED',
            'exclusion_policy_sha256': '0' * 64,
            'directories': [
                {'path': '.', 'kind': 'directory', 'mode': '0755', 'origin': 'source_root'},
                {'path': 'docs', 'kind': 'directory', 'mode': '0755', 'origin': 'git_ancestor'},
                {'path': 'docs/idea', 'kind': 'directory', 'mode': '0755', 'origin': 'excluded_container'},
                {'path': 'docs/idea/plan', 'kind': 'directory', 'mode': '0755', 'origin': 'excluded_container'},
            ],
            'excluded_directory_boundaries': [
                {'path': '.git', 'kind': 'directory', 'excluded_by': '.git/'},
                {'path': 'docs/idea/plan/evidence', 'kind': 'directory',
                 'excluded_by': 'docs/idea/plan/evidence/'},
            ],
        },
    })


ANNOTATIONS = {'$schema', '$id', '$defs', 'title', 'description', 'x-status', 'x-forgeflow-semantic-contract'}
KEYWORDS = ANNOTATIONS | {'$ref', 'type', 'const', 'enum', 'required', 'properties', 'additionalProperties',
    'items', 'minItems', 'maxItems', 'uniqueItems', 'contains', 'minContains', 'maxContains',
    'minLength', 'maxLength', 'pattern', 'format', 'allOf', 'anyOf', 'oneOf', 'not', 'if', 'then', 'else'}


def schema_matches(schema, value):
    """Small test oracle for this schema's explicit keywords, not a general validator."""
    unsupported = set(schema) - KEYWORDS
    if unsupported:
        raise AssertionError(f'unsupported schema keywords: {sorted(unsupported)}')
    if '$ref' in schema:
        ref = schema['$ref']
        if not ref.startswith('#/$defs/'):
            raise AssertionError('external or unsupported ref')
        return schema_matches(SCHEMA['$defs'][ref.removeprefix('#/$defs/')], value)
    if 'type' in schema:
        kinds = schema['type'] if isinstance(schema['type'], list) else [schema['type']]
        checks = {'object': isinstance(value, dict), 'array': isinstance(value, list),
                  'string': isinstance(value, str), 'boolean': type(value) is bool,
                  'null': value is None, 'integer': type(value) is int}
        if not any(checks.get(kind, False) for kind in kinds):
            return False
    if 'const' in schema and (type(value) is not type(schema['const']) or value != schema['const']):
        return False
    if 'enum' in schema and value not in schema['enum']:
        return False
    if isinstance(value, dict):
        if not set(schema.get('required', ())).issubset(value): return False
        props = schema.get('properties', {})
        if schema.get('additionalProperties') is False and set(value) - set(props): return False
        if any(k in value and not schema_matches(s, value[k]) for k, s in props.items()): return False
    if isinstance(value, list):
        if len(value) < schema.get('minItems', 0) or len(value) > schema.get('maxItems', float('inf')): return False
        if schema.get('uniqueItems') and len({canonical(x) for x in value}) != len(value): return False
        if 'items' in schema and any(not schema_matches(schema['items'], x) for x in value): return False
        if 'contains' in schema:
            count = sum(schema_matches(schema['contains'], x) for x in value)
            if count < schema.get('minContains', 1) or count > schema.get('maxContains', float('inf')): return False
    if isinstance(value, str):
        if len(value) < schema.get('minLength', 0) or len(value) > schema.get('maxLength', float('inf')): return False
        if 'pattern' in schema and re.search(schema['pattern'], value) is None: return False
        if schema.get('format') == 'date-time':
            try:
                if datetime.fromisoformat(value.replace('Z', '+00:00')).utcoffset() is None: return False
            except ValueError: return False
    for key, expected in (('allOf', 'all'), ('anyOf', 'any'), ('oneOf', 'one')):
        if key in schema:
            count = sum(schema_matches(item, value) for item in schema[key])
            if (expected == 'all' and count != len(schema[key])) or (expected == 'any' and not count) or (expected == 'one' and count != 1): return False
    if 'not' in schema and schema_matches(schema['not'], value): return False
    if 'if' in schema:
        branch = 'then' if schema_matches(schema['if'], value) else 'else'
        if branch in schema and not schema_matches(schema[branch], value): return False
    return True


def example_semantics(manifest, tracked_files=('docs/README',), registered_policy=None):
    """Check selected internal relations only, not observed filesystem truth."""
    try:
        p = manifest['directory_projection']
        dirs = p['directories']; boundaries = p['excluded_directory_boundaries']
        byte_sorted = lambda rows: [x['path'].encode('utf-8', 'strict') for x in rows]
        for rows in (dirs, boundaries):
            names = byte_sorted(rows)
            if names != sorted(set(names)): return False
        if registered_policy is not None and manifest['exclude_patterns'] != registered_policy: return False
        if p['exclusion_policy_sha256'] != digest(manifest['exclude_patterns']): return False
        if manifest['projection_sha256'] != digest(p): return False
        if manifest['manifest_sha256'] != digest({k: v for k, v in manifest.items() if k not in {'manifest_sha256', 'created_at', 'release_qualifiable'}}): return False
        names = {row['path'] for row in dirs}
        tracked_dirs = {str(parent) for path in tracked_files for parent in PurePosixPath(path).parents} - {'.'}
        for boundary in boundaries:
            if boundary['path'] in names or boundary['excluded_by'] not in manifest['exclude_patterns']: return False
            # This fixture uses exact directory exclusions. General glob matching
            # belongs to the eventual independent production oracle, not this test.
            if boundary['path'] + '/' != boundary['excluded_by']: return False
        for row in dirs:
            path, origin = row['path'], row['origin']
            if path != '.' and str(PurePosixPath(path).parent) not in names: return False
            if origin == 'git_ancestor' and path not in tracked_dirs: return False
            if origin == 'excluded_container':
                if path in tracked_dirs: return False
                if not any(b['path'].startswith(path + '/') for b in boundaries): return False
            if origin == 'untracked_business' and manifest['worktree_state'] == 'CLEAN': return False
        return True
    except (KeyError, TypeError, ValueError, UnicodeError):
        return False


class SourceManifestV3SchemaTests(unittest.TestCase):
    def test_valid_verified_and_unavailable_examples_are_not_qualifiable(self):
        good = fixture()
        self.assertTrue(schema_matches(SCHEMA, good)); self.assertTrue(example_semantics(good))
        self.assertFalse(good['release_qualifiable'])
        p = good['directory_projection']; p['mode_availability'] = 'UNAVAILABLE'
        for row in p['directories']: row['mode'] = None
        seal(good)
        self.assertTrue(schema_matches(SCHEMA, good)); self.assertTrue(example_semantics(good))
        self.assertFalse(good['release_qualifiable'])

    def test_structural_negative_cases(self):
        def mutate(case, fn):
            item = fixture(); fn(item)
            with self.subTest(case=case): self.assertFalse(schema_matches(SCHEMA, item))
        mutate('future qualification', lambda x: x.update(release_qualifiable=True))
        mutate('wrong version', lambda x: x.update(schema_version='forgeflow.ecp-source-manifest.v2'))
        mutate('unknown field', lambda x: x.update(unreviewed=True))
        mutate('missing root', lambda x: x['directory_projection']['directories'].pop(0))
        mutate('wrong root origin', lambda x: x['directory_projection']['directories'][0].update(origin='git_ancestor'))
        mutate('symlink directory', lambda x: x['directory_projection']['directories'][1].update(kind='symlink'))
        mutate('unverified numeric mode', lambda x: x['directory_projection'].update(mode_availability='UNAVAILABLE'))
        mutate('verified null mode', lambda x: x['directory_projection']['directories'][1].update(mode=None))
        mutate('invalid mode', lambda x: x['directory_projection']['directories'][1].update(mode='0899'))
        mutate('symlink excluded boundary', lambda x: x['directory_projection']['excluded_directory_boundaries'][1].update(kind='symlink'))
        mutate('relative source root', lambda x: x.update(source_root='relative/path'))
        mutate('timestamp timezone is not Z', lambda x: x.update(created_at='2026-11-16T00:00:00+00:00'))
        mutate('untracked traversal path', lambda x: (x.update(worktree_state='DIRTY_UNFROZEN'), x['untracked_business_files'].append({'path':'../outside','status':'??','kind':'file','mode':'0644','sha256':'a'*64})))
        mutate('untracked wrong status', lambda x: (x.update(worktree_state='DIRTY_UNFROZEN'), x['untracked_business_files'].append({'path':'docs/new','status':' M','kind':'file','mode':'0644','sha256':'a'*64})))
        mutate('clean untracked business', lambda x: x['directory_projection']['directories'][1].update(origin='untracked_business'))
        mutate('duplicate full record', lambda x: x['directory_projection']['directories'].append(copy.deepcopy(x['directory_projection']['directories'][1])))
        mutate('excessive directories', lambda x: x['directory_projection']['directories'].extend([x['directory_projection']['directories'][1]] * 100000))
        for path in ('/absolute', 'docs/../secret', 'docs/./x', 'docs//x', 'docs\\x', 'docs/x\n', ''):
            mutate('unsafe path ' + repr(path), lambda x, path=path: x['directory_projection']['directories'][1].update(path=path))

    def test_semantic_rejections_are_not_misrepresented_as_schema_features(self):
        def mutate(case, fn, reseal=True):
            item = fixture(); fn(item)
            if reseal: seal(item)
            with self.subTest(case=case):
                self.assertTrue(schema_matches(SCHEMA, item))
                self.assertFalse(example_semantics(item))
        mutate('order', lambda x: x['directory_projection']['directories'].reverse())
        mutate('duplicate path with different row', lambda x: x['directory_projection']['directories'].insert(2, {'path':'docs','kind':'directory','mode':'0700','origin':'git_ancestor'}))
        mutate('missing parent', lambda x: x['directory_projection']['directories'].pop(2))
        mutate('fabricated container', lambda x: x['directory_projection']['excluded_directory_boundaries'].pop())
        mutate('boundary also projected', lambda x: x['directory_projection']['excluded_directory_boundaries'][1].update(path='docs/idea/plan',excluded_by='docs/idea/plan/'))
        mutate('stale projection digest', lambda x: x['directory_projection']['directories'][1].update(mode='0700'), False)
        mutate('unlisted exclusion', lambda x: x['directory_projection']['excluded_directory_boundaries'][1].update(excluded_by='invented/'))
        item = fixture(); item['exclude_patterns'].append('sensitive/'); seal(item)
        self.assertTrue(schema_matches(SCHEMA, item))
        self.assertFalse(example_semantics(item, registered_policy=['.git/', 'docs/idea/plan/evidence/']))

    def test_dirty_input_remains_unqualified(self):
        item = fixture()
        item['worktree_state'] = 'DIRTY_UNFROZEN'
        item['untracked_business_files'].append({'path':'stray.txt','status':'??','kind':'file','mode':'0644','sha256':'a'*64})
        item['directory_projection']['directories'].append({'path':'other','kind':'directory','mode':'0755','origin':'untracked_business'})
        seal(item)
        self.assertTrue(schema_matches(SCHEMA, item))
        self.assertFalse(item['release_qualifiable'])

    def test_versions_and_limits_are_explicit(self):
        self.assertEqual(SCHEMA['x-status'], 'DRAFT_NOT_QUALIFIABLE')
        self.assertIn('not authentication', SCHEMA['x-forgeflow-semantic-contract']['claims'])
        self.assertEqual(SCHEMA['$defs']['directory_projection']['properties']['directories']['maxItems'], 100000)
        self.assertEqual(SCHEMA['$defs']['relative_path']['maxLength'], 4096)


if __name__ == '__main__':
    unittest.main()
