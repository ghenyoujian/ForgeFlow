"""Real 9p-to-ext4 fixtures; every successful observation remains non-Gate."""
from __future__ import annotations

import copy
import errno
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import struct
import subprocess
import tempfile
import time
import unittest
from unittest.mock import patch

import normalized_candidate_oracle as oracle


def sha(data):
    return hashlib.sha256(data).hexdigest()


class NormalizedOracleTests(unittest.TestCase):
    def setUp(self):
        # Own temporary fixtures only; this does not use the user repository
        # or assert any execution authority.
        self.work = tempfile.TemporaryDirectory(prefix='forgeflow-normal-oracle-')
        self.addCleanup(self.work.cleanup)
        self.source_tmp = tempfile.TemporaryDirectory(prefix='.forgeflow-normal-oracle-', dir='/mnt/d/Product/ForgeFlow')
        self.addCleanup(self.source_tmp.cleanup)
        self.source = Path(self.source_tmp.name)
        self.base = Path(self.work.name)
        self.candidate = self.base / 'candidate'
        self.candidate.mkdir(mode=0o700)
        self.candidate.chmod(0o700)
        (self.source / 'data').mkdir()
        (self.source / 'data/hello.txt').write_bytes(b'fixture-data\n')
        (self.source / 'run.sh').write_bytes(b'#!/bin/sh\nexit 0\n')
        (self.source / 'latest').symlink_to('data/hello.txt')
        self.git('init', '-q')
        self.git('add', 'data/hello.txt', 'run.sh', 'latest')
        self.git('update-index', '--chmod=-x', 'data/hello.txt')
        self.git('update-index', '--chmod=+x', 'run.sh')
        self.git('-c', 'user.name=fixture', '-c', 'user.email=fixture@example.invalid', 'commit', '-qm', 'fixture')
        self.head = self.git('rev-parse', 'HEAD').decode().strip()
        (self.candidate / 'data').mkdir(mode=0o750)
        (self.candidate / 'data').chmod(0o750)
        (self.candidate / 'data/hello.txt').write_bytes(b'fixture-data\n')
        (self.candidate / 'data/hello.txt').chmod(0o640)
        (self.candidate / 'run.sh').write_bytes(b'#!/bin/sh\nexit 0\n')
        (self.candidate / 'run.sh').chmod(0o750)
        (self.candidate / 'latest').symlink_to('data/hello.txt')
        projection = {'version': 'forgeflow.ecp-directory-projection.v1', 'mode_availability': 'UNAVAILABLE',
            'exclusion_policy_sha256': oracle.digest(list(oracle.EXCLUDES)),
            'directories': [{'path': '.', 'kind': 'directory', 'mode': None, 'origin': 'source_root'},
                            {'path': 'data', 'kind': 'directory', 'mode': None, 'origin': 'git_ancestor'}],
            'excluded_directory_boundaries': [{'path': '.git', 'kind': 'directory', 'excluded_by': '.git/'}]}
        self.manifest = {'schema_version':'forgeflow.ecp-source-manifest.v3', 'source_root':str(self.source),
            'head':self.head, 'worktree_state':'CLEAN', 'exclude_patterns':list(oracle.EXCLUDES),
            'untracked_scan_mode':'bounded', 'untracked_scan_roots':list(oracle.SCAN_ROOTS), 'tracked_changes':[],
            'untracked_business_files':[], 'excluded_generated_files':[], 'patch_sha256':sha(b''),
            'created_at':'2026-11-16T00:00:00Z', 'release_qualifiable':False, 'inventory_complete':True,
            'inventory_error':None, 'index_visibility_exceptions':[], 'directory_projection':projection,
            'projection_sha256':oracle.digest(projection)}
        self.manifest['manifest_sha256'] = oracle.digest({k:v for k,v in self.manifest.items()
            if k not in ('created_at','release_qualifiable')})
        files = []
        for path, mode in [('data/hello.txt','100644'), ('latest','120000'), ('run.sh','100755')]:
            data = os.fsencode(os.readlink(self.source/path)) if mode == '120000' else (self.source/path).read_bytes()
            oid = hashlib.sha1(b'blob '+str(len(data)).encode()+b'\0'+data).hexdigest()
            item = {'path':path, 'kind':'symlink' if mode == '120000' else 'file', 'git_mode':mode,
                    'git_oid':oid, 'size':len(data), 'sha256':sha(data)}
            if mode == '120000': item['target'] = data.decode('utf-8')
            files.append(item)
        self.supplement = {'schema_version':'forgeflow.ecp-source-supplement.v1',
            'source_manifest_sha256':self.manifest['manifest_sha256'], 'source_head':self.head,
            'source_mode_claim':'UNKNOWN', 'directories':[{'path':'.','origin':'source_root'},
                                                         {'path':'data','origin':'git_ancestor'}],
            'entries':files, 'qualification':'NOT_RUN', 'product_gate_effect':'NONE'}
        self.policy = {'schema_version':'forgeflow.ecp-normalization-policy.v1',
            'source_manifest_sha256':self.manifest['manifest_sha256'], 'source_supplement_sha256':oracle.digest(self.supplement),
            'source_head':self.head, 'source_mode_claim':'UNKNOWN',
            'directories':[{'path':'.','mode':'0700'},{'path':'data','mode':'0750'}],
            'entries':[{'path':'data/hello.txt','kind':'file','mode':'0640'},
                       {'path':'latest','kind':'symlink','mode':None},{'path':'run.sh','kind':'file','mode':'0750'}],
            'owner':{'uid':os.getuid(),'gid':os.getgid()},
            'attributes':{'access_acl':'ABSENT','default_acl':'ABSENT','xattrs':'NONE','hardlinks':'REJECT',
                          'symlinks':'INTERNAL_PROJECTION_ONLY','umask':'0077'},
            'limits':{'max_entries':100000,'max_file_bytes':67108864,'max_total_bytes':536870912,'max_depth':128},
            'authority':'UNVERIFIED','status':'DRAFT','qualification':'NOT_RUN','product_gate_effect':'NONE'}
        self.save()

    def git(self, *args):
        return subprocess.run(['/usr/bin/git', *args], cwd=self.source, check=True, stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, env={'PATH':'/usr/bin:/bin','HOME':str(self.base),
                                                         'GIT_CONFIG_NOSYSTEM':'1'}).stdout

    def save(self):
        self.policy['source_supplement_sha256'] = oracle.digest(self.supplement)
        for name, obj in [('manifest',self.manifest),('supplement',self.supplement),('policy',self.policy)]:
            (self.base / (name+'.json')).write_text(json.dumps(obj,ensure_ascii=False),encoding='utf-8')

    def review(self, *, manifest_hash=None, supplement_hash=None, policy_hash=None, receipt_path=None, receipt_hash=None):
        return oracle.review_normalized(self.source, self.candidate, self.base/'manifest.json',
            manifest_hash or self.manifest['manifest_sha256'], self.base/'supplement.json',
            supplement_hash or oracle.digest(self.supplement), self.base/'policy.json',
            policy_hash or oracle.digest(self.policy), receipt_path=receipt_path, receipt_sha256=receipt_hash)

    def receipt(self, extra_inventory=()):
        uid, gid = os.getuid(), os.getgid()
        common = {'uid': uid, 'gid': gid, 'visible_xattrs': []}
        inventory = [
            {'path': '.', 'kind': 'directory', 'mode': '0700', **common},
            {'path': 'data', 'kind': 'directory', 'mode': '0750', **common},
            {'path': 'data/hello.txt', 'kind': 'file', 'mode': '0640', 'size': len(b'fixture-data\n'),
             'sha256': sha(b'fixture-data\n'), 'nlink': 1, **common},
            {'path': 'latest', 'kind': 'symlink', 'target': 'data/hello.txt', 'nlink': 1, **common},
            {'path': 'run.sh', 'kind': 'file', 'mode': '0750', 'size': len(b'#!/bin/sh\nexit 0\n'),
             'sha256': sha(b'#!/bin/sh\nexit 0\n'), 'nlink': 1, **common},
        ]
        inventory.extend(extra_inventory)
        inventory.sort(key=lambda row: row['path'].encode('utf-8'))
        return {'schema_version': 'forgeflow.ecp-normalized-materialization.draft.v1',
                'status': 'OBSERVED_NOT_GATE', 'qualification': 'NOT_RUN', 'product_gate_effect': 'NONE',
                'source_mode_claim': 'UNKNOWN', 'source_permissions_preserved': 'UNKNOWN',
                'source_manifest_sha256': self.manifest['manifest_sha256'],
                'source_supplement_sha256': oracle.digest(self.supplement), 'policy_sha256': oracle.digest(self.policy),
                'candidate_root': str(self.candidate), 'candidate_inventory_sha256': oracle.digest(inventory),
                'candidate_entry_count': len(inventory),
                'candidate_file_bytes': sum(row['size'] for row in inventory if row['kind'] == 'file'),
                'authority': 'UNVERIFIED', 'sync_observation': 'untrusted test self-report',
                'continuous_sync_identity': 'UNKNOWN', 'limitations': ['untrusted test self-report']}

    def save_receipt(self, receipt):
        path = self.base/'receipt.json'
        raw = json.dumps(receipt, ensure_ascii=False).encode('utf-8')
        path.write_bytes(raw)
        return path, sha(raw)

    def test_v3_normalized_total_symlink_expansion_and_budgets(self):
        # The starting symlink itself counts: Linux accepts 40 total link
        # expansions, while a 41st gives ELOOP in the private OS fixture.
        dirs={'.':{},'src':{},'src/dir':{}}
        for nested in (2,39,40):
            with self.subTest(nested=nested,total=nested+1):
                files={'src/link':{'kind':'symlink','target':'a/../'*(nested-1)+'a/file'},
                       'src/a':{'kind':'symlink','target':'dir'},'src/dir/file':{'kind':'file'}}
                if nested<40:oracle.validate_link_graph(files,dirs)
                else:
                    with self.assertRaisesRegex(oracle.Invalid,'symlink chain exceeds 40'):
                        oracle.validate_link_graph(files,dirs)
        loop={'src/link':{'kind':'symlink','target':'a'},'src/a':{'kind':'symlink','target':'a'}}
        with self.assertRaises(oracle.Invalid):oracle.validate_link_graph(loop,dirs)
        dots='./'*1500
        operations={'src/link':{'kind':'symlink','target':'a/../a/../a/file'},
                    'src/a':{'kind':'symlink','target':dots+'dir'},'src/dir/file':{'kind':'file'}}
        with self.assertRaisesRegex(oracle.Invalid,'symlink.*budget'):
            oracle.validate_link_graph(operations,dirs)
        pending={'src/link':{'kind':'symlink','target':'a/file'},
                 'src/a':{'kind':'symlink','target':'a/'+dots},'src/dir/file':{'kind':'file'}}
        with self.assertRaisesRegex(oracle.Invalid,'symlink.*budget'):
            oracle.validate_link_graph(pending,dirs)

    def test_v3_four_business_formats_and_untracked_inputs(self):
        # Independent fixture bytes and expected paths, including pyc outside a
        # registered cache directory. It does not authenticate a principal.
        expected = {
            'data/logo.png': b'png-fixture\x00',
            'data/workload.log': b'business-log\n',
            'data/template.tar.gz': b'archive-fixture\x01',
            'data/fixture.pyc': b'bytecode-fixture\x02',
        }
        for path,payload in expected.items():
            (self.source/path).write_bytes(payload)
            (self.candidate/path).write_bytes(payload)
            (self.candidate/path).chmod(0o640)
        self.git('add','--',*expected)
        self.git('update-index','--chmod=-x','--',*expected)
        self.git('-c','user.name=fixture','-c','user.email=fixture@example.invalid','commit','-qm','four source formats')
        self.head=self.git('rev-parse','HEAD').decode().strip()
        self.manifest['head']=self.head
        self.manifest['manifest_sha256']=oracle.digest({k:v for k,v in self.manifest.items()
            if k not in ('manifest_sha256','created_at','release_qualifiable')})
        self.supplement['source_head']=self.head
        self.supplement['source_manifest_sha256']=self.manifest['manifest_sha256']
        self.policy['source_head']=self.head
        self.policy['source_manifest_sha256']=self.manifest['manifest_sha256']
        for path,payload in expected.items():
            oid=hashlib.sha1(b'blob '+str(len(payload)).encode()+b'\0'+payload).hexdigest()
            self.supplement['entries'].append({'path':path,'kind':'file','git_mode':'100644',
                'git_oid':oid,'size':len(payload),'sha256':sha(payload)})
            self.policy['entries'].append({'path':path,'kind':'file','mode':'0640'})
        self.supplement['entries'].sort(key=lambda row:row['path'].encode('utf-8'))
        self.policy['entries'].sort(key=lambda row:row['path'].encode('utf-8'))
        self.save()
        result=self.review()
        self.assertEqual(result['status'],'OBSERVED_NOT_GATE',result)
        for path,payload in expected.items():
            with self.subTest(path=path,check='independent-candidate-readback'):
                self.assertEqual((self.candidate/path).read_bytes(),payload)
            with self.subTest(path=path,check='candidate-tamper'):
                candidate=self.candidate/path
                candidate.write_bytes(payload+b'!')
                try:self.assertEqual(self.review()['status'],'FAIL')
                finally:candidate.write_bytes(payload)
            with self.subTest(path=path,check='candidate-missing'):
                candidate=self.candidate/path
                candidate.unlink()
                try:self.assertEqual(self.review()['status'],'FAIL')
                finally:
                    candidate.write_bytes(payload);candidate.chmod(0o640)
        for name in ('untracked.png','untracked.log','untracked.tar.gz','untracked.pyc'):
            with self.subTest(name=name,check='untracked-source-rejection'):
                path=self.source/'data'/name
                path.write_bytes(b'untracked-business')
                try:self.assertEqual(self.review()['status'],'FAIL')
                finally:path.unlink()

    def test_v3_git_tracked_env_directory_links_are_verified(self):
        (self.source/'.env').mkdir()
        (self.candidate/'.env').mkdir(mode=0o750); (self.candidate/'.env').chmod(0o750)
        content = b'public business fixture'
        (self.source/'.env/input.txt').write_bytes(content)
        (self.candidate/'.env/input.txt').write_bytes(content)
        (self.candidate/'.env/input.txt').chmod(0o640)
        for name, target in (('env-dir-link','.env'), ('env-file-link','.env/input.txt')):
            (self.source/name).symlink_to(target); (self.candidate/name).symlink_to(target)
        self.git('add','-f','--','.env/input.txt','env-dir-link','env-file-link')
        self.git('update-index','--chmod=-x','--','.env/input.txt')
        self.git('-c','user.name=fixture','-c','user.email=fixture@example.invalid',
                 'commit','-qm','business directory links')
        self.head = self.git('rev-parse','HEAD').decode().strip()
        projection = self.manifest['directory_projection']
        projection['directories'].append({'path':'.env','kind':'directory','mode':None,'origin':'git_ancestor'})
        projection['directories'].sort(key=lambda row:row['path'].encode())
        self.manifest['head'] = self.head
        self.manifest['projection_sha256'] = oracle.digest(projection)
        self.manifest['manifest_sha256'] = oracle.digest({k:v for k,v in self.manifest.items()
            if k not in ('manifest_sha256','created_at','release_qualifiable')})
        self.supplement['source_head'] = self.head
        self.supplement['source_manifest_sha256'] = self.manifest['manifest_sha256']
        self.supplement['directories'].append({'path':'.env','origin':'git_ancestor'})
        self.supplement['directories'].sort(key=lambda row:row['path'].encode())
        self.policy['source_head'] = self.head
        self.policy['source_manifest_sha256'] = self.manifest['manifest_sha256']
        self.policy['directories'].append({'path':'.env','mode':'0750'})
        self.policy['directories'].sort(key=lambda row:row['path'].encode())
        for path,mode,payload in (('.env/input.txt','100644',content), ('env-dir-link','120000',b'.env'),
                                  ('env-file-link','120000',b'.env/input.txt')):
            row={'path':path,'kind':'symlink' if mode=='120000' else 'file','git_mode':mode,
                 'git_oid':hashlib.sha1(b'blob '+str(len(payload)).encode()+b'\0'+payload).hexdigest(),
                 'size':len(payload),'sha256':sha(payload)}
            if mode=='120000': row['target']=payload.decode()
            self.supplement['entries'].append(row)
            self.policy['entries'].append({'path':path,'kind':row['kind'],'mode':None if mode=='120000' else '0640'})
        self.supplement['entries'].sort(key=lambda row:row['path'].encode())
        self.policy['entries'].sort(key=lambda row:row['path'].encode())
        self.save()
        result = self.review()
        self.assertEqual(result['status'],'OBSERVED_NOT_GATE',result)
        self.assertEqual((self.candidate/'env-file-link').read_bytes(), content)
        self.assertEqual(os.readlink(self.candidate/'env-dir-link'), '.env')
        for target in ('.env','evidence/secret'):
            with self.subTest(excluded_target=target), self.assertRaises(oracle.Invalid):
                oracle.validate_link_graph({'bad':{'kind':'symlink','target':target}}, {'.':{}})

    def test_v3_typed_boundaries_independently_bind_git_and_scan_types(self):
        names = ('target', 'node_modules', '__pycache__', '.local')
        expected = {name: ('independent-' + name).encode() for name in names}
        for name, payload in expected.items():
            (self.source/name).write_bytes(payload)
        self.git('add', '-f', '--', *names)
        self.git('update-index', '--chmod=-x', '--', *names)
        self.git('-c','user.name=fixture','-c','user.email=fixture@example.invalid',
                 'commit','-qm','typed boundary files')
        head = self.git('rev-parse', 'HEAD').decode().strip()
        fd = os.open(self.source, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        self.addCleanup(os.close, fd)
        entries, fmt, _, _ = oracle.parse_git_inventory(fd, head, time.monotonic()+20)
        for name, payload in expected.items():
            self.assertIn(name, entries)
            self.assertEqual(entries[name][1], hashlib.sha1(b'blob '+str(len(payload)).encode()+b'\0'+payload).hexdigest())
        limits = self.policy['limits']
        def scan():
            return oracle.walk(fd, source=True, expected_files=entries, expected_dirs={'.':{}, 'data':{}},
                               fmt=fmt, limits=limits, deadline=time.monotonic()+20)
        _, observed, boundaries, _, _ = scan()
        self.assertIn('.git', boundaries)
        for name, payload in expected.items():
            self.assertEqual(observed[name]['sha256'], sha(payload))
        (self.source/'audit').write_bytes(b'untracked business')
        with self.assertRaises(oracle.Invalid): scan()
        (self.source/'audit').unlink()
        private = self.source/'.env'
        private.write_bytes(b'private fixture')
        real_open = os.open
        def deny_private_read(path, *args, **kwargs):
            if isinstance(path, (str, bytes)) and os.fsdecode(path).split('/')[-1] == '.env':
                raise AssertionError('private file must not be opened by the oracle')
            return real_open(path, *args, **kwargs)
        with patch.object(oracle.os, 'open', side_effect=deny_private_read): scan()
        private.unlink(); private.symlink_to('data/hello.txt')
        with self.assertRaises(oracle.Invalid): scan()
        private.unlink(); private.mkdir()
        with self.assertRaises(oracle.Invalid): scan()
        private.rmdir(); os.mkfifo(private)
        with self.assertRaises(oracle.Invalid): scan()
        private.unlink()
        (self.source/'target').unlink(); (self.source/'target').symlink_to('data/hello.txt')
        with self.assertRaises(oracle.Invalid): scan()
        self.git('add', '-f', '--', 'target')
        self.git('-c','user.name=fixture','-c','user.email=fixture@example.invalid',
                 'commit','-qm','boundary symlink')
        head = self.git('rev-parse', 'HEAD').decode().strip()
        with self.assertRaises(oracle.Invalid):
            oracle.parse_git_inventory(fd, head, time.monotonic()+20)

    def test_v3_linked_worktree_regular_git_marker_is_not_a_boundary(self):
        linked = self.base/'linked-source'
        self.git('worktree','add','--detach',str(linked),self.head)
        self.assertTrue((linked/'.git').is_file())
        fd = os.open(linked, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        self.addCleanup(os.close, fd)
        entries, fmt, _, _ = oracle.parse_git_inventory(fd, self.head, time.monotonic()+20)
        _, observed, boundaries, _, _ = oracle.walk(fd, source=True, expected_files=entries,
            expected_dirs={'.':{}, 'data':{}}, fmt=fmt, limits=self.policy['limits'], deadline=time.monotonic()+20)
        self.assertNotIn('.git', boundaries)
        self.assertNotIn('.git', observed)
        self.assertEqual(set(observed), set(entries))

    def test_v3_fixed_policy_and_explicit_directory_boundaries(self):
        self.assertEqual(oracle.digest(list(oracle.EXCLUDES)),
                         '693a01c306939936dea248c348d1ed09f44cfc230b27b7a6faeab85fb3926787')
        for suffix in ('png','log','tar.gz','pyc'):
            with self.subTest(suffix=suffix):
                self.assertFalse(oracle.excluded('data/business.'+suffix))
                self.assertFalse(oracle.excluded('data/evidence2/business.'+suffix))
                self.assertTrue(oracle.excluded('evidence/business.'+suffix))
                self.assertFalse(oracle.excluded('data/__pycache__/business.'+suffix))
                self.assertTrue(oracle.excluded('__pycache__/business.'+suffix))
        self.assertIsNone(oracle.exclusion('crates/demo/src/evidence/real.txt'))
        old=list(oracle.EXCLUDES)
        old.insert(old.index('console/node_modules/'), '**/node_modules/')
        old.insert(old.index('verification/evidence/'), 'crates/**/evidence/')
        index=old.index('__pycache__/')
        old[index:index]=['*.log','*.png','*.tar.gz']
        old.extend(['*/__pycache__/', '*.pyc'])
        self.assertEqual(oracle.digest(old),'d839d523d6af3b32855d03570ddd1856c7d546c9dd8b39e3b9c9314b2c566c35')
        self.manifest['exclude_patterns']=old
        self.manifest['directory_projection']['exclusion_policy_sha256']=oracle.digest(old)
        self.manifest['projection_sha256']=oracle.digest(self.manifest['directory_projection'])
        self.manifest['manifest_sha256']=oracle.digest({k:v for k,v in self.manifest.items()
            if k not in ('manifest_sha256','created_at','release_qualifiable')})
        self.supplement['source_manifest_sha256']=self.manifest['manifest_sha256']
        self.policy['source_manifest_sha256']=self.manifest['manifest_sha256']
        self.save()
        self.assertEqual(self.review()['status'],'FAIL')

    def test_receipt_consistency_checks_observed_symlink_and_byte_denominator(self):
        path, pin = self.save_receipt(self.receipt())
        result = self.review(receipt_path=path, receipt_hash=pin)
        self.assertEqual(result['status'], 'OBSERVED_NOT_GATE', result)
        self.assertEqual(result['receipt_consistency']['status'], 'CONSISTENT_DRAFT')
        self.assertEqual(result['receipt_consistency']['authority'], 'UNVERIFIED')
        self.assertGreater(result['denominator']['symlink_target_bytes'], 0)
        self.assertNotEqual(result['denominator']['bytes'], self.receipt()['candidate_file_bytes'])
        self.assertTrue(any('historical replay remains unknown' in item for item in result['limitations']))
        self.assertTrue(any('unverified self-reports' in item for item in result['limitations']))

    def test_receipt_fields_are_bound_even_when_attacker_recomputes_byte_pin(self):
        changes = {'source_manifest_sha256':'0'*64, 'source_supplement_sha256':'0'*64,
                   'policy_sha256':'0'*64, 'candidate_root':str(self.base/'another-candidate'),
                   'candidate_inventory_sha256':'0'*64, 'candidate_entry_count':6,
                   'candidate_file_bytes':True, 'authority':'VERIFIED', 'qualification':'PASS',
                   'continuous_sync_identity':'VERIFIED', 'schema_version':'other'}
        for field, value in changes.items():
            with self.subTest(field=field):
                receipt = self.receipt()
                receipt[field] = value
                path, pin = self.save_receipt(receipt)
                self.assertEqual(self.review(receipt_path=path, receipt_hash=pin)['status'], 'FAIL')
        receipt = self.receipt()
        receipt['extra'] = 1
        path, pin = self.save_receipt(receipt)
        self.assertEqual(self.review(receipt_path=path, receipt_hash=pin)['status'], 'FAIL')

    def test_receipt_requires_independent_raw_byte_pin_and_unique_fields(self):
        path, pin = self.save_receipt(self.receipt())
        self.assertEqual(self.review(receipt_path=path)['status'], 'FAIL')
        self.assertEqual(self.review(receipt_hash=pin)['status'], 'FAIL')
        self.assertEqual(self.review(receipt_path=path, receipt_hash='0'*64)['status'], 'FAIL')
        data = path.read_bytes()
        raw = data[:-1] + b', "status": "OBSERVED_NOT_GATE"}'
        path.write_bytes(raw)
        self.assertEqual(self.review(receipt_path=path, receipt_hash=sha(raw))['status'], 'FAIL')
        path.write_bytes(data)
        self.assertEqual(self.review(receipt_path=self.base/'manifest.json',
                                     receipt_hash=sha((self.base/'manifest.json').read_bytes()))['status'], 'FAIL')

    def test_receipt_rewrite_between_endpoint_reads_is_rejected(self):
        path, pin = self.save_receipt(self.receipt())
        original_read = oracle.read_document
        reads = 0
        def rewrite_after_first_read(document_path, seen, **kwargs):
            nonlocal reads
            value = original_read(document_path, seen, **kwargs)
            if Path(document_path) == path:
                reads += 1
                if reads == 1:
                    path.write_bytes(path.read_bytes() + b' ')
            return value
        with patch.object(oracle, 'read_document', side_effect=rewrite_after_first_read):
            result = self.review(receipt_path=path, receipt_hash=pin)
        self.assertEqual(result['status'], 'FAIL', result)
        self.assertEqual(reads, 1)

    def test_receipt_from_other_candidate_path_is_rejected_without_writes(self):
        path, pin = self.save_receipt(self.receipt())
        other = self.base/'other'
        shutil.copytree(self.candidate, other, symlinks=True)
        before = {str(p.relative_to(other)): p.lstat().st_mtime_ns for p in [other, *other.rglob('*')]}
        result = oracle.review_normalized(self.source, other, self.base/'manifest.json', self.manifest['manifest_sha256'],
            self.base/'supplement.json', oracle.digest(self.supplement), self.base/'policy.json', oracle.digest(self.policy),
            receipt_path=path, receipt_sha256=pin)
        after = {str(p.relative_to(other)): p.lstat().st_mtime_ns for p in [other, *other.rglob('*')]}
        self.assertEqual(result['status'], 'FAIL', result)
        self.assertEqual(before, after)

    def test_receipt_projection_orders_unicode_and_includes_empty_directories(self):
        def d(mode):
            return {'mode': mode, 'uid': 1, 'gid': 2, 'xattrs': (), 'signature': (0,)*9}
        directories = {'空': d('0750'), '.': d('0700')}
        entries = {'é': {'kind':'symlink', 'target':'空', 'uid':1, 'gid':2, 'xattrs':(),
                         'signature':(0,)*8+(1,)}}
        projection = oracle._receipt_projection(directories, entries)
        self.assertEqual([item['path'] for item in projection], ['.', 'é', '空'])
        self.assertEqual(projection[-1]['kind'], 'directory')
        self.assertEqual(projection[1]['target'], '空')

    def test_receipt_canonical_producer_bounds_are_enforced(self):
        for value in ([-1], [1 << 63], [1.5], ['x' * 4097], [{1: 'bad'}]):
            with self.subTest(value_type=type(value[0]).__name__):
                with self.assertRaises(oracle.Invalid):
                    oracle._receipt_v1_digest(value)
        for constant, limit, value in (('RECEIPT_MAX_JSON_BYTES', 4, ['abc']),
                                       ('RECEIPT_MAX_ENTRIES', 1, [1, 2]),
                                       ('RECEIPT_MAX_NODES', 2, [1, 2]),
                                       ('RECEIPT_MAX_DEPTH', 1, [[1]])):
            with self.subTest(constant=constant), patch.object(oracle, constant, limit):
                with self.assertRaises(oracle.Invalid):
                    oracle._receipt_v1_digest(value)
        with patch.object(oracle, 'RECEIPT_MAX_ENTRIES', 0):
            with self.assertRaises(oracle.Invalid):
                oracle._receipt_projection({'.': {}}, {})
        self.assertEqual(oracle._receipt_v1_digest([{'path':'汉字','count':3}]),
                         oracle.digest([{'path':'汉字','count':3}]))

    def test_receipt_endpoint_reads_unicode_and_empty_excluded_container(self):
        # A source directory containing only an excluded boundary projects to
        # a real, empty candidate directory. The Unicode file is Git-tracked.
        (self.source/'console/node_modules').mkdir(parents=True)
        (self.candidate/'console').mkdir(mode=0o750)
        (self.candidate/'console').chmod(0o750)
        content = '小样本\n'.encode()
        (self.source/'汉字.txt').write_bytes(content)
        (self.candidate/'汉字.txt').write_bytes(content)
        (self.candidate/'汉字.txt').chmod(0o640)
        self.git('add', '汉字.txt')
        self.git('-c', 'user.name=fixture', '-c', 'user.email=fixture@example.invalid', 'commit', '-qm', 'unicode')
        self.head = self.git('rev-parse', 'HEAD').decode().strip()
        projection = self.manifest['directory_projection']
        projection['directories'].append({'path':'console', 'kind':'directory', 'mode':None, 'origin':'excluded_container'})
        projection['directories'].sort(key=lambda x: x['path'].encode('utf-8'))
        projection['excluded_directory_boundaries'].append({'path':'console/node_modules', 'kind':'directory',
                                                             'excluded_by':'console/node_modules/'})
        projection['excluded_directory_boundaries'].sort(key=lambda x: x['path'].encode('utf-8'))
        self.manifest['projection_sha256'] = oracle.digest(projection)
        self.manifest['head'] = self.head
        self.manifest['manifest_sha256'] = oracle.digest({k:v for k,v in self.manifest.items()
            if k not in ('manifest_sha256', 'created_at', 'release_qualifiable')})
        # The manifest's hash field itself is excluded from its digest.
        self.supplement['source_manifest_sha256'] = self.manifest['manifest_sha256']
        self.supplement['source_head'] = self.head
        self.supplement['directories'].append({'path':'console', 'origin':'excluded_container'})
        self.supplement['directories'].sort(key=lambda x: x['path'].encode('utf-8'))
        oid = hashlib.sha1(b'blob '+str(len(content)).encode()+b'\0'+content).hexdigest()
        self.supplement['entries'].append({'path':'汉字.txt','kind':'file','git_mode':'100644',
                                            'git_oid':oid,'size':len(content),'sha256':sha(content)})
        self.supplement['entries'].sort(key=lambda x: x['path'].encode('utf-8'))
        self.policy['source_manifest_sha256'] = self.manifest['manifest_sha256']
        self.policy['source_head'] = self.head
        self.policy['directories'].append({'path':'console','mode':'0750'})
        self.policy['directories'].sort(key=lambda x: x['path'].encode('utf-8'))
        self.policy['entries'].append({'path':'汉字.txt','kind':'file','mode':'0640'})
        self.policy['entries'].sort(key=lambda x: x['path'].encode('utf-8'))
        self.save()
        uid, gid = os.getuid(), os.getgid()
        extra = [{'path':'console','kind':'directory','mode':'0750','uid':uid,'gid':gid,'visible_xattrs':[]},
                 {'path':'汉字.txt','kind':'file','mode':'0640','size':len(content),'sha256':sha(content),
                  'uid':uid,'gid':gid,'nlink':1,'visible_xattrs':[]}]
        path, pin = self.save_receipt(self.receipt(extra))
        result = self.review(receipt_path=path, receipt_hash=pin)
        self.assertEqual(result['status'], 'OBSERVED_NOT_GATE', result)
        self.assertEqual(result['receipt_consistency']['status'], 'CONSISTENT_DRAFT')
        self.assertEqual(result['denominator']['directories'], 3)
        self.assertGreater(result['denominator']['symlink_target_bytes'], 0)

    def test_real_9p_to_ext4_observation_never_grants_gate(self):
        result = self.review()
        self.assertEqual(result['status'], 'OBSERVED_NOT_GATE', result)
        self.assertEqual((result['qualification'], result['product_gate_effect']), ('NOT_RUN','NONE'))
        self.assertEqual(result['source_permissions_preserved'], 'UNKNOWN')
        self.assertEqual(result['denominator']['entries'], 3)
        self.assertEqual(result['denominator']['directories'], 2)
        denominator = result['denominator']
        self.assertEqual(denominator['regular_file_bytes'], len(b'fixture-data\n') + len(b'#!/bin/sh\nexit 0\n'))
        self.assertEqual(denominator['symlink_target_bytes'], len(b'data/hello.txt'))
        self.assertEqual(denominator['bytes'], denominator['regular_file_bytes'] + denominator['symlink_target_bytes'])
        self.assertEqual(denominator['bytes_scope'], 'regular_file_bytes_plus_symlink_target_bytes')

    def test_external_hardlink_is_detected(self):
        target = self.candidate/'data/hello.txt'
        external = self.base/'external'
        os.link(target, external)
        self.assertEqual(target.stat().st_nlink, 2)
        result = self.review()
        self.assertEqual(result['status'], 'FAIL', result)
        self.assertIn('hardlink', result['reason'])

    def test_candidate_content_mode_extra_and_missing_are_rejected(self):
        file = self.candidate/'data/hello.txt'
        original = file.read_bytes()
        for mutate, restore in ((lambda: file.write_bytes(b'tampered\n'), lambda: file.write_bytes(original)),
                                (lambda: file.chmod(0o600), lambda: file.chmod(0o640)),
                                (lambda: (self.candidate/'extra').write_bytes(b'x'), lambda: (self.candidate/'extra').unlink()),
                                (file.unlink, lambda: file.write_bytes(original))):
            with self.subTest(mutate=mutate):
                mutate()
                self.assertEqual(self.review()['status'], 'FAIL')
                restore()
                file.chmod(0o640)

    def assert_named_acl_entry(self, path, attribute, uid):
        raw = os.getxattr(path, attribute)
        self.assertEqual(raw[:4], struct.pack('<I', 2))
        self.assertEqual((len(raw) - 4) % 8, 0)
        entries = list(struct.iter_unpack('<HHI', raw[4:]))
        self.assertIn((2, 5, uid), entries)

    def test_named_access_acl_same_mode_is_rejected(self):
        baseline = self.review()
        self.assertEqual((baseline['status'], baseline['qualification'], baseline['product_gate_effect']),
                         ('OBSERVED_NOT_GATE', 'NOT_RUN', 'NONE'), baseline)
        uid = os.getuid()
        payload = struct.pack('<I', 2) + b''.join(struct.pack('<HHI', tag, perm, owner) for tag,perm,owner in
            ((1,7,0xffffffff),(2,5,uid),(4,5,0xffffffff),(16,5,0xffffffff),(32,0,0xffffffff)))
        folder = self.candidate/'data'
        try:
            os.setxattr(folder, 'system.posix_acl_access', payload)
        except OSError as exc:
            if exc.errno in (errno.EOPNOTSUPP, errno.ENOTSUP):
                self.skipTest('fixture filesystem does not support POSIX ACL')
            raise
        self.assertEqual(stat.S_IMODE(folder.stat().st_mode), 0o750)
        self.assertIn('system.posix_acl_access', os.listxattr(folder))
        self.assert_named_acl_entry(folder, 'system.posix_acl_access', uid)
        result = self.review()
        self.assertEqual((result['status'], result['qualification'], result['product_gate_effect'], result['reason']),
                         ('FAIL', 'NOT_RUN', 'NONE', 'candidate directory policy differs'), result)

    def test_inherited_default_acl_is_rejected(self):
        baseline = self.review()
        self.assertEqual((baseline['status'], baseline['qualification'], baseline['product_gate_effect']),
                         ('OBSERVED_NOT_GATE', 'NOT_RUN', 'NONE'), baseline)
        uid = os.getuid()
        payload = struct.pack('<I', 2) + b''.join(struct.pack('<HHI', tag, perm, owner) for tag,perm,owner in
            ((1,7,0xffffffff),(2,5,uid),(4,5,0xffffffff),(16,5,0xffffffff),(32,0,0xffffffff)))
        folder = self.candidate/'data'
        try:
            os.setxattr(self.candidate, 'system.posix_acl_default', payload)
        except OSError as exc:
            if exc.errno in (errno.EOPNOTSUPP, errno.ENOTSUP):
                self.skipTest('fixture filesystem does not support POSIX ACL')
            raise
        self.assert_named_acl_entry(self.candidate, 'system.posix_acl_default', uid)
        (folder/'hello.txt').unlink()
        folder.rmdir()
        folder.mkdir(mode=0o700)
        folder.chmod(0o750)
        os.removexattr(self.candidate, 'system.posix_acl_default')
        (folder/'hello.txt').write_bytes(b'fixture-data\n')
        (folder/'hello.txt').chmod(0o640)
        self.assertEqual(stat.S_IMODE(folder.stat().st_mode), 0o750)
        self.assertIn('system.posix_acl_default', os.listxattr(folder))
        self.assertNotIn('system.posix_acl_default', os.listxattr(self.candidate))
        self.assert_named_acl_entry(folder, 'system.posix_acl_default', uid)
        result = self.review()
        self.assertEqual((result['status'], result['qualification'], result['product_gate_effect'], result['reason']),
                         ('FAIL', 'NOT_RUN', 'NONE', 'candidate directory policy differs'), result)

    def test_cannot_read_xattrs_is_inconclusive(self):
        with patch.object(oracle, '_acl_and_xattrs', side_effect=PermissionError('injected')):
            result = self.review()
        self.assertEqual(result['status'], 'INCONCLUSIVE')
        self.assertEqual((result['qualification'], result['product_gate_effect']), ('NOT_RUN','NONE'))

    def test_overall_deadline_expires_before_document_processing(self):
        with patch.object(oracle, 'MAX_SCAN_SECONDS', 0):
            result = self.review()
        self.assertEqual(result['status'], 'INCONCLUSIVE')
        self.assertIsNone(oracle._DEADLINE.get())

    def test_unconfirmed_root_descriptor_close_is_inconclusive(self):
        original_directory, original_close = oracle.absolute_directory, os.close
        held = []
        def open_and_capture(path):
            value = original_directory(path)
            if os.path.abspath(path) == str(self.candidate):
                held.append(value[1])
            return value
        def close_then_error(fd):
            if held and fd == held[0]:
                held.clear()
                original_close(fd)
                raise OSError('injected close failure')
            return original_close(fd)
        with patch.object(oracle, 'absolute_directory', side_effect=open_and_capture), \
             patch.object(oracle.os, 'close', side_effect=close_then_error):
            result = self.review()
        self.assertEqual(result['status'], 'INCONCLUSIVE', result)
        self.assertIn('closure', result['reason'])
        self.assertIsNone(oracle._DEADLINE.get())

    def test_policy_hash_binding_and_invalid_owner_are_rejected(self):
        self.assertEqual(self.review(policy_hash='0'*64)['status'], 'FAIL')
        self.policy['owner']['uid'] = (os.getuid()+1) % (2**32-2)
        self.save()
        self.assertEqual(self.review()['status'], 'FAIL')

    def test_untrusted_supplement_cannot_hide_real_source_bytes(self):
        self.supplement['entries'][0]['sha256'] = '0'*64
        self.save()
        result = self.review()
        self.assertEqual(result['status'], 'FAIL')

    def test_source_git_index_cannot_be_replaced_by_a_self_consistent_supplement(self):
        self.supplement['entries'][0]['git_oid'] = '1'*40
        self.save()
        result = self.review()
        self.assertEqual(result['status'], 'FAIL')
        self.assertIn('Git index', result['reason'])

    def test_symlink_bytes_are_bounded_before_graph_or_git(self):
        target = 'a' * 4097
        raw = target.encode()
        item = self.supplement['entries'][1]
        item.update(target=target, size=len(raw), sha256=sha(raw),
                    git_oid=hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest())
        self.save()
        with patch.object(oracle, 'parse_git_inventory') as git:
            result = self.review()
        self.assertEqual(result['status'], 'FAIL', result)
        self.assertIn('symlink', result['reason'])
        git.assert_not_called()

    def test_untracked_business_source_and_wrong_candidate_link_are_rejected(self):
        extra = self.source/'data/not-in-git'
        extra.write_text('synthetic\n')
        try:
            self.assertEqual(self.review()['status'], 'FAIL')
        finally:
            extra.unlink()
        link = self.candidate/'latest'
        link.unlink()
        link.symlink_to('../outside')
        self.assertEqual(self.review()['status'], 'FAIL')

    def test_excluded_container_with_untracked_excluded_file_is_not_forged_clean(self):
        prefixes = ['docs', 'docs/idea', 'docs/idea/ForgeFlow_ECP_完整开发规划']
        boundary = prefixes[-1]+'/evidence'
        (self.source/boundary).mkdir(parents=True)
        (self.source/boundary/'retained.json').write_text('{}')
        # The directory boundary is explicitly excluded, irrespective of suffix.
        (self.source/boundary/'inside.log').write_text('excluded boundary log')
        for path in prefixes:
            folder = self.candidate/path
            folder.mkdir(exist_ok=True)
            folder.chmod(0o750)
            self.manifest['directory_projection']['directories'].append(
                {'path':path,'kind':'directory','mode':None,'origin':'excluded_container'})
            self.supplement['directories'].append({'path':path,'origin':'excluded_container'})
            self.policy['directories'].append({'path':path,'mode':'0750'})
        self.manifest['directory_projection']['directories'].sort(key=lambda row:row['path'].encode())
        self.supplement['directories'].sort(key=lambda row:row['path'].encode())
        self.policy['directories'].sort(key=lambda row:row['path'].encode())
        self.manifest['directory_projection']['excluded_directory_boundaries'].append(
            {'path':boundary,'kind':'directory','excluded_by':'docs/idea/ForgeFlow_ECP_完整开发规划/evidence/'})
        self.manifest['directory_projection']['excluded_directory_boundaries'].sort(key=lambda row:row['path'].encode())
        self.manifest['projection_sha256'] = oracle.digest(self.manifest['directory_projection'])
        self.manifest['manifest_sha256'] = oracle.digest({k:v for k,v in self.manifest.items()
            if k not in ('manifest_sha256','created_at','release_qualifiable')})
        self.supplement['source_manifest_sha256'] = self.manifest['manifest_sha256']
        self.policy['source_manifest_sha256'] = self.manifest['manifest_sha256']
        self.save()
        valid = self.review()
        self.assertEqual(valid['status'], 'OBSERVED_NOT_GATE', valid)
        # A log adjacent to the boundary is now an untracked business input.
        outside=self.source/prefixes[-1]/'orphan.log'
        outside.write_text('untracked business sibling')
        invalid = self.review()
        self.assertEqual(invalid['status'], 'FAIL', invalid)
        self.assertIn('unexpected or duplicate file', invalid['reason'])
        outside.unlink()
        # Preserve the original origin-classification check: a *regular file*
        # with the registered cache-boundary name cannot make its parent an
        # exclusion-only container. No assumption about file extension is used.
        excluded_regular=self.source/prefixes[-1]/'__pycache__'
        excluded_regular.write_text('excluded regular sibling')
        self.assertIsNone(oracle.exclusion(prefixes[-1]+'/__pycache__'))
        invalid = self.review()
        self.assertEqual(invalid['status'], 'FAIL', invalid)
        self.assertIn('unexpected or duplicate file', invalid['reason'])

    def test_caller_path_cannot_replace_git(self):
        fake = self.base/'fake-bin'
        fake.mkdir()
        marker = self.base/'fake-git-executed'
        git = fake/'git'
        git.write_text('#!/bin/sh\nprintf touched > '+str(marker)+'\nexit 1\n')
        git.chmod(0o755)
        with patch.dict(os.environ, {'PATH':str(fake)}):
            result = self.review()
        self.assertEqual(result['status'], 'OBSERVED_NOT_GATE', result)
        self.assertFalse(marker.exists())

    def test_duplicate_and_unknown_json_fields_are_rejected(self):
        with (self.base/'policy.json').open('w') as out:
            out.write('{"status":"DRAFT","status":"DRAFT"}')
        self.assertEqual(self.review()['status'], 'FAIL')
        self.save()
        self.policy['unknown'] = 'field'
        self.save()
        self.assertEqual(self.review()['status'], 'FAIL')

    def test_empty_excluded_boundaries_are_list_not_null_or_false(self):
        git_dir = self.source.parent / (self.source.name + '-gitdir')
        (self.source/'.git').rename(git_dir)
        self.addCleanup(lambda: shutil.rmtree(git_dir))
        (self.source/'.git').write_text('gitdir: '+str(git_dir)+'\n')
        projection = self.manifest['directory_projection']
        def set_boundaries(value):
            projection['excluded_directory_boundaries'] = value
            self.manifest['projection_sha256'] = oracle.digest(projection)
            self.manifest['manifest_sha256'] = oracle.digest({k:v for k,v in self.manifest.items()
                if k not in ('manifest_sha256','created_at','release_qualifiable')})
            self.supplement['source_manifest_sha256'] = self.manifest['manifest_sha256']
            self.policy['source_manifest_sha256'] = self.manifest['manifest_sha256']
            self.save()
        set_boundaries([])
        positive = self.review()
        self.assertEqual(positive['status'], 'OBSERVED_NOT_GATE', positive)
        for value in (None, False, 0, {}):
            with self.subTest(value=value):
                set_boundaries(value)
                result = self.review()
                self.assertEqual(result['status'], 'FAIL', result)
                self.assertIn('boundary list', result['reason'])

    def test_individual_symlink_and_directory_graph_cycles_rejected(self):
        with self.assertRaises(oracle.Invalid):
            oracle.validate_link_graph({'loop':{'kind':'symlink','target':'.'}},{'.':{}})
        with self.assertRaises(oracle.Invalid):
            oracle.validate_link_graph({'a/link':{'kind':'symlink','target':'../b'},
                                        'b/link':{'kind':'symlink','target':'../a'}},
                                       {'.':{},'a':{},'b':{}})
        with self.assertRaises(oracle.Invalid):
            oracle.validate_link_graph({'loop':{'kind':'symlink','target':'../../outside'}},{'.':{}})
        oracle.validate_link_graph({'a/link':{'kind':'symlink','target':'../b/file'},
                                    'b/file':{'kind':'file'}},{'.':{},'a':{},'b':{}})

    def test_repeated_clean_observation_is_deterministic(self):
        one = self.review()
        two = self.review()
        self.assertEqual(one['status'], 'OBSERVED_NOT_GATE', one)
        self.assertEqual(one['candidate_inventory_projection_sha256'], two['candidate_inventory_projection_sha256'])


if __name__ == '__main__':
    unittest.main()
