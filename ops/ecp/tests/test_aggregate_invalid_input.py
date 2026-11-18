"""Private synthetic red/green tests: no Git, DB, child or fixture files."""
import argparse
import contextlib
import importlib.util
import io
import json
from pathlib import Path
import sys
import types
import unittest
from unittest.mock import patch


def load_subject():
    stub = types.ModuleType('source_snapshot')
    stub.DEFAULT_EXCLUDES = ()
    stub.build_manifest = lambda *_a, **_k: (_ for _ in ()).throw(AssertionError('snapshot forbidden'))
    name = '_r47_aggregate_subject'
    missing = object()
    old_snapshot = sys.modules.get('source_snapshot', missing)
    old_subject = sys.modules.get(name, missing)
    try:
        sys.modules['source_snapshot'] = stub
        spec = importlib.util.spec_from_file_location(name, Path(__file__).resolve().parent.parent / 'verify.py')
        subject = importlib.util.module_from_spec(spec)
        sys.modules[name] = subject
        spec.loader.exec_module(subject)
        return subject
    finally:
        for key, old in (('source_snapshot', old_snapshot), (name, old_subject)):
            if old is missing: sys.modules.pop(key, None)
            else: sys.modules[key] = old


verify = load_subject()
SHA = 'a' * 40
BAD_UTF8 = object()


class AggregateInputIntegrityTests(unittest.TestCase):
    def run_case(self, inputs):
        root = Path('/synthetic-source')
        paths = [f'/synthetic-evidence/input-{i}.json' for i in range(len(inputs))]
        encoded = {path: (BAD_UTF8 if value is BAD_UTF8 else json.dumps(value, ensure_ascii=True))
                   for path, value in zip(paths, inputs)}
        display = [{'invalid_utf8': True} if value is BAD_UTF8 else value for value in inputs]
        trace = {'test_method': self._testMethodName, 'inputs': display, 'paths': paths}
        def read_input(path, *args, **kwargs):
            value = encoded[str(path)]
            if value is BAD_UTF8:
                return bytes([255]).decode('utf-8', errors='strict')
            return value
        args = argparse.Namespace(source_root=str(root), source_sha=SHA, input=paths, output=None)
        try:
            with patch.object(verify, 'resolve_source_root', return_value=root), \
                 patch.object(Path, 'expanduser', autospec=True, side_effect=lambda p: p), \
                 patch.object(Path, 'resolve', autospec=True, side_effect=lambda p: p), \
                 patch.object(Path, 'read_text', autospec=True, side_effect=read_input), \
                 patch.object(verify, 'git_sha', side_effect=AssertionError('Git forbidden')), \
                 patch.object(verify, 'run_git', side_effect=AssertionError('Git forbidden')), \
                 patch.object(verify.subprocess, 'Popen', side_effect=AssertionError('child forbidden')), \
                 contextlib.redirect_stdout(io.StringIO()) as output:
                result, code = verify.aggregate_reports(args)
        except BaseException as exc:
            trace['observation'] = {'kind': 'exception', 'type': type(exc).__name__}
            print(json.dumps(trace, ensure_ascii=True, sort_keys=True), flush=True)
            raise
        trace['observation'] = {'kind': 'returned', 'exit_code': code,
                                'status': result.get('status'), 'input_count': result.get('input_count'),
                                'denominator': result.get('denominator'), 'denominator_scope': result.get('denominator_scope'),
                                'evidence_refs': result.get('evidence_refs'), 'checks': result.get('checks')}
        print(json.dumps(trace, ensure_ascii=True, sort_keys=True), flush=True)
        self.assertEqual(json.loads(output.getvalue()), result)
        self.assertEqual(result['product_gate_effect'], 'NONE')
        self.assertEqual(result['input_count'], len(inputs))
        rows = [row for row in result['checks'] if row['name'].startswith('input:')]
        self.assertEqual([r['details']['path'] for r in rows], paths)
        self.assertEqual(len(rows), len(inputs))
        self.assertEqual(result['denominator_scope'], 'input_claims_and_source_binding_diagnostics')
        return result, code, rows

    def check_bad_refs(self, refs):
        result, code, rows = self.run_case([{'status':'PASS','source_sha':SHA,'evidence_refs':refs}])
        self.assertEqual((result['status'], code, rows[0]['status']), ('FAIL', 10, 'FAIL'))
        self.assertEqual(rows[0]['details']['declared_status'], 'PASS')
        self.assertEqual(rows[0]['details']['evidence_refs_error'], 'expected an array of UTF-8 strings')
        self.assertEqual(result['denominator']['passed'], 0)
        self.assertEqual(result['evidence_refs'], ['/synthetic-evidence/input-0.json'])

    def test_valid_pass_stays_unverified(self):
        result, code, rows = self.run_case([{'status':'PASS','source_sha':SHA}])
        self.assertEqual((result['status'],code,rows[0]['status']),('INCONCLUSIVE',20,'INCONCLUSIVE'))
        self.assertEqual(rows[0]['details']['declared_status'],'PASS')
        self.assertEqual(result['denominator']['passed'],0)

    def test_valid_refs_are_preserved(self):
        result, code, rows = self.run_case([{'status':'PASS','source_sha':SHA,'evidence_refs':['/synthetic/ref-one','/synthetic/ref-two']}])
        self.assertEqual((result['status'],code),('INCONCLUSIVE',20))
        self.assertEqual(result['evidence_refs'], ['/synthetic-evidence/input-0.json','/synthetic/ref-one','/synthetic/ref-two'])

    def test_valid_unicode_refs_preserved(self):
        result, code, rows = self.run_case([{'status':'PASS','source_sha':SHA,'evidence_refs':['/synthetic/汉字','/synthetic/café']}])
        self.assertEqual((result['status'],code),('INCONCLUSIVE',20))
        self.assertEqual(result['evidence_refs'], ['/synthetic-evidence/input-0.json','/synthetic/café','/synthetic/汉字'])

    def test_valid_failure_remains_failure(self):
        result, code, rows = self.run_case([{'status':'FAIL','source_sha':SHA,'reason':'known failure','evidence_refs':[]}])
        self.assertEqual((result['status'],code,rows[0]['status']),('FAIL',10,'FAIL'))
        self.assertEqual(rows[0]['details']['declared_reason'],'known failure')

    def test_null_refs_rejected(self): self.check_bad_refs(None)
    def test_numeric_refs_rejected(self): self.check_bad_refs(5)
    def test_string_refs_rejected(self): self.check_bad_refs('not-a-list')
    def test_object_refs_rejected(self): self.check_bad_refs({'not':'a-list'})
    def test_list_with_nonstring_rejected(self): self.check_bad_refs(['/synthetic/good', 9])

    def test_lone_surrogate_refs_rejected(self): self.check_bad_refs(['/synthetic/good', '\ud800'])

    def test_invalid_utf8_is_identified_failure(self):
        result, code, rows = self.run_case([BAD_UTF8])
        self.assertEqual((result['status'],code,rows[0]['status']),('FAIL',10,'FAIL'))
        self.assertIn('cannot read valid JSON',rows[0]['reason'])
        self.assertEqual(result['denominator']['passed'],0)

    def test_failure_then_malformed_refs_keeps_every_input(self):
        result, code, rows = self.run_case([{'status':'FAIL','source_sha':SHA,'reason':'prior failure'},
            {'status':'PASS','source_sha':SHA,'evidence_refs':None},{'status':'NOT_RUN','source_sha':SHA}])
        self.assertEqual((result['status'],code),('FAIL',10))
        self.assertEqual([x['status'] for x in rows],['FAIL','FAIL','NOT_RUN'])
        self.assertEqual(rows[0]['details']['declared_reason'],'prior failure')
        self.assertEqual(result['denominator']['total'],3)
        self.assertEqual(result['denominator']['passed'],0)

    def test_failure_then_surrogate_refs_keeps_every_input(self):
        result, code, rows = self.run_case([{'status':'FAIL','source_sha':SHA,'reason':'prior failure'},
            {'status':'PASS','source_sha':SHA,'evidence_refs':['/synthetic/good', '\ud800']},
            {'status':'NOT_RUN','source_sha':SHA}])
        self.assertEqual((result['status'],code),('FAIL',10))
        self.assertEqual([x['status'] for x in rows],['FAIL','FAIL','NOT_RUN'])
        self.assertEqual(rows[0]['details']['declared_reason'],'prior failure')
        self.assertNotIn('/synthetic/good',result['evidence_refs'])
        self.assertEqual(result['denominator']['total'],3)
        self.assertEqual(result['denominator']['passed'],0)

    def test_failure_then_invalid_utf8_keeps_every_input(self):
        result, code, rows = self.run_case([{'status':'FAIL','source_sha':SHA,'reason':'prior failure'},
                                            BAD_UTF8,{'status':'NOT_RUN','source_sha':SHA}])
        self.assertEqual((result['status'],code),('FAIL',10))
        self.assertEqual([x['status'] for x in rows],['FAIL','FAIL','NOT_RUN'])
        self.assertEqual(rows[0]['details']['declared_reason'],'prior failure')
        self.assertEqual(result['denominator']['total'],3)
        self.assertEqual(result['denominator']['passed'],0)


if __name__ == '__main__':
    unittest.main(verbosity=2)
