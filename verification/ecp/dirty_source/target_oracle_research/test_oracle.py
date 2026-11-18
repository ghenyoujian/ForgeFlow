"""Fixed synthetic fixtures for the independent restricted dirty-source oracle.

All fixtures are new directories beneath an explicitly provided 0700 root.
No Git, subprocess, source repository, database, cleanup or network access.
"""
import base64
import copy
import hashlib
import json
import os
from pathlib import Path
import stat
import struct
import sys
import unittest
import zlib
from types import SimpleNamespace
from unittest.mock import patch

# Load exactly the adjacent research oracle without registering a generic
# module name or changing sys.path for other discovery participants.
import importlib.util
_spec = importlib.util.spec_from_file_location(
    '_forgeflow_dirty_target_oracle_research', Path(__file__).resolve().with_name('oracle.py'))
if _spec is None or _spec.loader is None:
    raise ImportError('cannot load adjacent dirty target oracle')
oracle = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(oracle)

ROOT_VALUE=os.environ.get('ECP_ORACLE_FIXTURES')
if not ROOT_VALUE or not os.path.isabs(ROOT_VALUE):
    raise RuntimeError('ECP_ORACLE_FIXTURES absolute private directory required')
ROOT=Path(ROOT_VALUE)


def oid(kind,data):
    obj=kind+b' '+str(len(data)).encode('ascii')+b'\0'+data
    return hashlib.sha1(obj).hexdigest(),zlib.compress(obj)


def row(path,kind,mode,data):
    return {'path_b64':base64.b64encode(path).decode('ascii'),'kind':kind,'mode':mode,
            'byte_count':len(data),'sha256':hashlib.sha256(data).hexdigest(),
            'computed_git_blob_oid':oid(b'blob',data)[0]}


def create_file(path,data):
    with path.open('xb') as stream:stream.write(data)


def create_fixture(root, fault=None):
    head={b'.gitignore':('file','100644',b'ignored.tmp\n'),
          b'a.txt':('file','100644',b'base\n'),
          b'dir/tool.sh':('file','100755',b'echo base\n'),
          b'link':('symlink','120000',b'a.txt')}
    index=dict(head);index[b'a.txt']=('file','100644',b'staged\n')
    index[b'staged-new.txt']=('file','100644',b'staged new\n')
    tracked=dict(index);tracked[b'a.txt']=('file','100644',b'working\n')
    tracked[b'link']=('symlink','120000',b'dir/tool.sh')
    untracked={b'ignored.tmp':('file','100644',b'ignored\n'),b'n\xff.bin':('file','100644',b'\x00\xffbinary')}
    objects={}
    def obj(kind,data):
        hexdigest,compressed=oid(kind,data);objects[hexdigest]=compressed;return hexdigest
    def trees(entries):
        children={}
        for path,(kind,mode,data) in entries.items():
            parts=path.split(b'/');node=children
            for part in parts[:-1]:node=node.setdefault(part,{})
            node[parts[-1]]=(mode.encode('ascii'),obj(b'blob',data))
        if fault=='empty_subtree':children[b'ghost']={}
        def encode(node):
            parts=[]
            for name,value in node.items():
                if isinstance(value,dict):mode=b'40000';child=encode(value);key=name+b'/'
                else:mode,child=value;key=name+b'\0'
                parts.append((key,mode+b' '+name+b'\0'+bytes.fromhex(child)))
            return obj(b'tree',b''.join(data for _key,data in sorted(parts)))
        return encode(children)
    tree=trees(head)
    commit=b'tree '+tree.encode('ascii')+b'\nauthor Fixture <f@example.invalid> 1 +0000\ncommitter Fixture <f@example.invalid> 1 +0000\n\nfixture\n'
    head_oid=obj(b'commit',commit)
    for entries in (index,tracked,untracked):
        for _path,(_kind,_mode,data) in entries.items():obj(b'blob',data)
    out=[]
    for path,(_kind,mode,data) in sorted(index.items()):
        objid=oid(b'blob',data)[0]
        flags=len(path)
        if fault=='index_flags' and path==b'a.txt':flags|=0x8000
        fixed=struct.pack('!10I20sH',0,0,0,0,0,0,int(mode,8),0,0,len(data),bytes.fromhex(objid),flags)
        encoded=fixed+path+b'\0';encoded+=b'\0'*((-len(encoded))%8);out.append(encoded)
    index_data=b'DIRC'+struct.pack('!II',3 if fault=='index_version' else 2,len(out))+b''.join(out)
    ext=b'TREE'+struct.pack('!I',6)+b'\0-1 0\n'
    index_extensions={
        'index_extension':b'TREE'+struct.pack('!I',0),
        'tree_invalid_root':ext,
        'tree_short_header':b'TRE',
        'tree_short_payload':b'TREE'+struct.pack('!I',7)+b'\0-1 0\n',
        'tree_size_overflow':b'TREE'+struct.pack('!I',0xffffffff)+b'\0-1 0\n',
        'tree_unknown_optional':b'XXXX'+struct.pack('!I',0),
        'tree_mandatory':b'link'+struct.pack('!I',0),
        'tree_sparse':b'sdir'+struct.pack('!I',0),
        'tree_duplicate':ext+ext,
        'tree_trailing':ext+b'\0',
        'tree_child_claim':b'TREE'+struct.pack('!I',6)+b'\0-1 1\n',
        'tree_valid_cache':b'TREE'+struct.pack('!I',25)+b'\0'+b'0 0\n'+bytes(20),
        'tree_not_root':b'TREE'+struct.pack('!I',7)+b'a\0-1 0\n',
        'tree_checksum':ext,
    }
    index_data+=index_extensions.get(fault,b'')
    index_data+=hashlib.sha1(index_data).digest()
    if fault in ('index_checksum','tree_checksum'):index_data=index_data[:-1]+bytes([index_data[-1]^1])
    def changes(left,right):
        result=[]
        for path in sorted(set(left)|set(right)):
            before,after=left.get(path),right.get(path)
            if before==after:continue
            state='ADDED' if before is None else 'DELETED' if after is None else 'MODIFIED'
            result.append({'path_b64':base64.b64encode(path).decode('ascii'),'change':state})
        return result
    manifest={'schema':'forgeflow.ecp-dirty-source-declaration.research.v1','qualification':'NOT_RUN',
      'product_gate_effect':'NONE','source_authentication':'UNVERIFIED','snapshot_atomicity':'UNKNOWN',
      'completeness_authority':'UNVERIFIED','head_commit_claim':head_oid,'git_object_format_claim':'sha1',
      'coverage_claims':{'head':True,'index':True,'worktree':True,'exclusions':False},
      'head':[row(p,*v) for p,v in sorted(head.items())],
      'index':[row(p,*v) for p,v in sorted(index.items())],
      'tracked_worktree':[row(p,*v) for p,v in sorted(tracked.items())],
      'untracked':[row(p,*v) for p,v in sorted(untracked.items())],
      'excluded':[],'staged_changes':changes(head,index),'unstaged_changes':changes(index,tracked),'unknown_worktree_modes':[],
      'input_bytes_counting_each_projection':sum(len(v[2]) for layer in (head,index,tracked,untracked) for v in layer.values())}
    blobs={hashlib.sha256(v[2]).hexdigest():v[2] for layer in (head,index,tracked,untracked) for v in layer.values()}
    digest=hashlib.sha256(json.dumps(manifest,sort_keys=True,ensure_ascii=True,separators=(',',':')).encode('ascii')).hexdigest()
    os.mkdir(root,0o700);git=root/'.git';git.mkdir(mode=0o700)
    objects_dir=git/'objects';objects_dir.mkdir(mode=0o700);(objects_dir/'info').mkdir(mode=0o700);(objects_dir/'pack').mkdir(mode=0o700)
    (git/'refs').mkdir(mode=0o700);(git/'refs'/'heads').mkdir(mode=0o700)
    ref=b'main'
    if fault=='head_path':ref=b'../elsewhere'
    if fault=='head_space':ref=b'a b'
    if fault=='head_hidden':ref=b'.hidden'
    if fault=='head_lock':ref=b'name.lock'
    if fault=='head_doubledot':ref=b'a..b'
    if fault=='head_atbrace':ref=b'a@{b'
    if fault=='head_backslash':ref=b'a\\b'
    create_file(git/'HEAD',b'ref: refs/heads/'+ref+b'\n')
    create_file(git/'refs'/'heads'/'main',(head_oid+'\n').encode('ascii'))
    create_file(git/'index',index_data)
    missing=oid(b'blob',head[b'a.txt'][2])[0]
    for hashname,compressed in objects.items():
        if fault=='missing_object' and hashname==missing:continue
        sub=objects_dir/hashname[:2];sub.mkdir(mode=0o700,exist_ok=True)
        if fault=='bad_object' and hashname==missing:compressed=b'bad-zlib'
        create_file(sub/hashname[2:],compressed)
    if fault=='pack':create_file(objects_dir/'pack'/'fixture.pack',b'pack-marker')
    if fault=='alternates':create_file(objects_dir/'info'/'alternates',b'/outside\n')
    root_bytes=os.fsencode(root)
    for path,(kind,mode,data) in sorted({**tracked,**untracked}.items()):
        if fault=='missing_worktree' and path==b'a.txt':continue
        if fault=='changed_worktree' and path==b'a.txt':data=b'wrong\n'
        if fault=='changed_symlink' and path==b'link':data=b'wrong'
        parts=path.split(b'/');parent=root_bytes
        for part in parts[:-1]:
            parent+=b'/'+part
            try:os.mkdir(parent,0o700)
            except FileExistsError:pass
        target=root_bytes+b'/'+path
        if kind=='symlink':os.symlink(data,target)
        else:
            fd=os.open(target,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
            try:
                remaining=memoryview(data)
                while remaining:
                    written=os.write(fd,remaining)
                    if written<=0:raise OSError('fixture short write')
                    remaining=remaining[written:]
                os.fchmod(fd,0o755 if mode=='100755' else 0o644)
            finally:os.close(fd)
    if fault=='extra_worktree':create_file(root/'unexpected.txt',b'unexpected')
    if fault=='extra_empty_dir':(root/'unused').mkdir(mode=0o700)
    return manifest,digest,blobs


class OracleTests(unittest.TestCase):
    def setUp(self):
        info=os.lstat(ROOT)
        if not stat.S_ISDIR(info.st_mode) or stat.S_IMODE(info.st_mode)!=0o700 or info.st_uid!=os.geteuid():
            raise RuntimeError('fixture root must be owned, private and real')
        self.case=ROOT/self._testMethodName
        os.mkdir(self.case,0o700)
        self.path=self.case/'target'
    def observe(self,fault=None,change=None):
        manifest,digest,blobs=create_fixture(self.path,fault)
        if change is not None:manifest,digest,blobs=change(manifest,digest,blobs)
        inputs={'fault':fault,'manifest':manifest,'manifest_sha256':digest,
                'blobs_base64':{key:base64.b64encode(value).decode('ascii') for key,value in sorted(blobs.items())}}
        with (self.case/'inputs.json').open('x',encoding='ascii') as stream:
            json.dump(inputs,stream,sort_keys=True,separators=(',',':'),ensure_ascii=True);stream.write('\n')
        fd=os.open(self.path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
        try:
            try:
                result=oracle.review(fd,manifest,digest,blobs)
            except Exception as exc:
                prior=getattr(exc,'oracle_primary_error',None)
                result={'raised_type':type(exc).__name__,'code':getattr(exc,'code',None),
                        'close_outcomes':getattr(exc,'close_outcomes',None),
                        'ledger_incomplete':getattr(exc,'oracle_ledger_incomplete',False),
                        'prior_type':None if prior is None else type(prior).__name__,
                        'prior_code':None if prior is None else getattr(prior,'code',None)}
                with (self.case/'observation.json').open('x',encoding='ascii') as stream:
                    json.dump(result,stream,sort_keys=True,separators=(',',':'));stream.write('\n')
                raise
            with (self.case/'observation.json').open('x',encoding='ascii') as stream:
                json.dump(result,stream,sort_keys=True,separators=(',',':'));stream.write('\n')
            return result
        finally:os.close(fd)
    def test_valid_restricted_fixture(self):
        result=self.observe();self.assertEqual(result['status'],'OBSERVED_RESEARCH_ONLY')
        self.assertEqual((result['head_rows'],result['index_rows'],result['worktree_rows'],result['untracked_rows']),(4,5,7,2))
        self.assertEqual(result['index_format'],'SHA1_V2_NO_EXTENSIONS')
        self.assertEqual(result['git_ignore_classification'],'NOT_MEASURED')
        self.assertEqual(result['qualification'],'NOT_RUN');self.assertEqual(result['product_gate_effect'],'NONE')
    def test_changed_worktree_rejected(self):
        with self.assertRaisesRegex(oracle.OracleError,'WORKTREE_MISMATCH'):self.observe('changed_worktree')
    def test_missing_worktree_rejected(self):
        with self.assertRaisesRegex(oracle.OracleError,'WORKTREE_MISMATCH'):self.observe('missing_worktree')
    def test_extra_worktree_rejected(self):
        with self.assertRaisesRegex(oracle.OracleError,'WORKTREE_MISMATCH'):self.observe('extra_worktree')
    def test_extra_empty_directory_rejected(self):
        with self.assertRaisesRegex(oracle.OracleError,'WORKTREE_DIRECTORY_MISMATCH'):self.observe('extra_empty_dir')
    def test_changed_symlink_rejected(self):
        with self.assertRaisesRegex(oracle.OracleError,'WORKTREE_MISMATCH'):self.observe('changed_symlink')
    def test_checksum_rejected(self):
        with self.assertRaisesRegex(oracle.OracleError,'INDEX_CHECKSUM'):self.observe('index_checksum')
    def test_index_v3_rejected(self):
        with self.assertRaisesRegex(oracle.OracleError,'INDEX_UNSUPPORTED'):self.observe('index_version')
    def test_index_flag_rejected(self):
        with self.assertRaisesRegex(oracle.OracleError,'INDEX_FLAGS_OR_MODE_UNSUPPORTED'):self.observe('index_flags')
    def test_index_extension_rejected(self):
        with self.assertRaisesRegex(oracle.OracleError,'INDEX_TREE_UNSUPPORTED'):self.observe('index_extension')
    def test_tree_invalid_root_observed(self):
        result=self.observe('tree_invalid_root')
        self.assertEqual(result['index_format'],'SHA1_V2_TREE_INVALID_ROOT_ONLY')
        self.assertEqual(result['index_rows'],5)
    def test_tree_short_header_rejected(self):
        with self.assertRaisesRegex(oracle.OracleError,'INDEX_EXTENSION_TRUNCATED'):self.observe('tree_short_header')
    def test_tree_short_payload_rejected(self):
        with self.assertRaisesRegex(oracle.OracleError,'INDEX_EXTENSION_TRUNCATED'):self.observe('tree_short_payload')
    def test_tree_size_overflow_rejected(self):
        with self.assertRaisesRegex(oracle.OracleError,'INDEX_EXTENSION_TRUNCATED'):self.observe('tree_size_overflow')
    def test_tree_unknown_optional_rejected(self):
        with self.assertRaisesRegex(oracle.OracleError,'INDEX_EXTENSION_UNSUPPORTED'):self.observe('tree_unknown_optional')
    def test_tree_required_extension_rejected(self):
        with self.assertRaisesRegex(oracle.OracleError,'INDEX_EXTENSION_UNSUPPORTED'):self.observe('tree_mandatory')
    def test_tree_sparse_extension_rejected(self):
        with self.assertRaisesRegex(oracle.OracleError,'INDEX_EXTENSION_UNSUPPORTED'):self.observe('tree_sparse')
    def test_tree_duplicate_rejected(self):
        with self.assertRaisesRegex(oracle.OracleError,'INDEX_EXTENSION_UNSUPPORTED'):self.observe('tree_duplicate')
    def test_tree_trailing_byte_rejected(self):
        with self.assertRaisesRegex(oracle.OracleError,'INDEX_EXTENSION_UNSUPPORTED'):self.observe('tree_trailing')
    def test_tree_child_claim_rejected(self):
        with self.assertRaisesRegex(oracle.OracleError,'INDEX_TREE_UNSUPPORTED'):self.observe('tree_child_claim')
    def test_tree_valid_cache_rejected(self):
        with self.assertRaisesRegex(oracle.OracleError,'INDEX_TREE_UNSUPPORTED'):self.observe('tree_valid_cache')
    def test_tree_nonroot_rejected(self):
        with self.assertRaisesRegex(oracle.OracleError,'INDEX_TREE_UNSUPPORTED'):self.observe('tree_not_root')
    def test_tree_checksum_rejected(self):
        with self.assertRaisesRegex(oracle.OracleError,'INDEX_CHECKSUM'):self.observe('tree_checksum')
    def test_packed_objects_rejected(self):
        with self.assertRaisesRegex(oracle.OracleError,'PACK_UNSUPPORTED'):self.observe('pack')
    def test_alternates_rejected(self):
        with self.assertRaisesRegex(oracle.OracleError,'ALTERNATES_UNSUPPORTED'):self.observe('alternates')
    def test_missing_object_inconclusive(self):
        with self.assertRaisesRegex(oracle.OracleError,'OBSERVATION_INCOMPLETE'):self.observe('missing_object')
    def test_bad_zlib_rejected(self):
        with self.assertRaisesRegex(oracle.OracleError,'OBJECT_COMPRESSION_INVALID_OR_LIMIT'):self.observe('bad_object')
    def test_empty_subtree_rejected(self):
        with self.assertRaisesRegex(oracle.OracleError,'EMPTY_SUBTREE_UNSUPPORTED'):self.observe('empty_subtree')
    def test_head_ref_traversal_rejected(self):
        with self.assertRaisesRegex(oracle.OracleError,'PATH_INVALID'):self.observe('head_path')
    def test_ref_space_rejected(self):
        with self.assertRaisesRegex(oracle.OracleError,'HEAD_REF_UNSUPPORTED'):self.observe('head_space')
    def test_ref_hidden_component_rejected(self):
        with self.assertRaisesRegex(oracle.OracleError,'HEAD_REF_UNSUPPORTED'):self.observe('head_hidden')
    def test_ref_lock_suffix_rejected(self):
        with self.assertRaisesRegex(oracle.OracleError,'HEAD_REF_UNSUPPORTED'):self.observe('head_lock')
    def test_ref_double_dot_rejected(self):
        with self.assertRaisesRegex(oracle.OracleError,'HEAD_REF_UNSUPPORTED'):self.observe('head_doubledot')
    def test_ref_at_brace_rejected(self):
        with self.assertRaisesRegex(oracle.OracleError,'HEAD_REF_UNSUPPORTED'):self.observe('head_atbrace')
    def test_ref_backslash_rejected(self):
        with self.assertRaisesRegex(oracle.OracleError,'HEAD_REF_UNSUPPORTED'):self.observe('head_backslash')
    def test_manifest_digest_rejected_before_scan(self):
        with self.assertRaisesRegex(oracle.OracleError,'MANIFEST_HASH_MISMATCH'):
            self.observe(change=lambda m,h,b:(m,'0'*64,b))
    def test_blob_payload_rejected_before_scan(self):
        def change(m,h,b):
            key=next(iter(b));bad=dict(b);bad[key]=b'wrong';return m,h,bad
        with self.assertRaisesRegex(oracle.OracleError,'BLOB_MISMATCH'):self.observe(change=change)
    def test_sha256_format_rejected(self):
        def change(m,h,b):
            m=dict(m);m['git_object_format_claim']='sha256'
            return m,hashlib.sha256(json.dumps(m,sort_keys=True,ensure_ascii=True,separators=(',',':')).encode()).hexdigest(),b
        with self.assertRaisesRegex(oracle.OracleError,'DECLARATION_UNSUPPORTED'):self.observe(change=change)
    def test_unapproved_exclusion_rejected(self):
        def change(m,h,b):
            m=dict(m);m['excluded']=[{'path_b64':'eA==','reason':'fixture'}]
            return m,hashlib.sha256(json.dumps(m,sort_keys=True,ensure_ascii=True,separators=(',',':')).encode()).hexdigest(),b
        with self.assertRaisesRegex(oracle.OracleError,'EXCLUSIONS_UNSUPPORTED'):self.observe(change=change)
    def test_forged_derived_changes_rejected(self):
        def change(m,h,b):
            m=dict(m);m['staged_changes']=[]
            return m,hashlib.sha256(json.dumps(m,sort_keys=True,ensure_ascii=True,separators=(',',':')).encode()).hexdigest(),b
        with self.assertRaisesRegex(oracle.OracleError,'DERIVED_CLAIMS_MISMATCH'):self.observe(change=change)

    def collision(self,label):
        def change(m,h,b):
            m=copy.deepcopy(m)
            source=next(row for row in m['head'] if base64.b64decode(row['path_b64'])==b'a.txt')
            for path in (b'a',b'a-foo',b'a/z'):
                extra=dict(source);extra['path_b64']=base64.b64encode(path).decode('ascii');m[label].append(extra)
            m[label].sort(key=lambda row:base64.b64decode(row['path_b64']))
            def changes(left,right):
                old={row['path_b64']:row for row in left};new={row['path_b64']:row for row in right}
                result=[]
                for key in sorted(set(old)|set(new),key=base64.b64decode):
                    a,c=old.get(key),new.get(key)
                    if a==c:continue
                    result.append({'path_b64':key,'change':'ADDED' if a is None else 'DELETED' if c is None else 'MODIFIED'})
                return result
            m['staged_changes']=changes(m['head'],m['index'])
            m['unstaged_changes']=changes(m['index'],m['tracked_worktree'])
            m['input_bytes_counting_each_projection']=sum(row['byte_count'] for projection in
                ('head','index','tracked_worktree','untracked') for row in m[projection])
            digest=hashlib.sha256(json.dumps(m,sort_keys=True,ensure_ascii=True,separators=(',',':')).encode('ascii')).hexdigest()
            return m,digest,b
        with self.assertRaisesRegex(oracle.OracleError,'PATH_COLLISION'):self.observe(change=change)
    def test_nonadjacent_head_prefix_collision(self):self.collision('head')
    def test_nonadjacent_index_prefix_collision(self):self.collision('index')
    def test_nonadjacent_worktree_prefix_collision(self):self.collision('untracked')

    def test_aggregate_path_budget_before_target_scan(self):
        def change(m,h,b):
            m=copy.deepcopy(m)
            source=next(row for row in m['head'] if base64.b64decode(row['path_b64'])==b'a.txt')
            for number in range(522):
                path=('k%04d/'%number).encode('ascii')+b'/'.join([b'x'*250]*16)
                extra=dict(source);extra['path_b64']=base64.b64encode(path).decode('ascii');m['untracked'].append(extra)
            m['untracked'].sort(key=lambda row:base64.b64decode(row['path_b64']))
            m['input_bytes_counting_each_projection']=sum(row['byte_count'] for label in
                ('head','index','tracked_worktree','untracked') for row in m[label])
            digest=hashlib.sha256(json.dumps(m,sort_keys=True,ensure_ascii=True,separators=(',',':')).encode('ascii')).hexdigest()
            return m,digest,b
        with self.assertRaisesRegex(oracle.OracleError,'TOTAL_PATH_BUDGET'):self.observe(change=change)

    def test_derived_directory_expansion_budget_before_scan(self):
        def change(m,h,b):
            m=copy.deepcopy(m)
            source=next(row for row in m['head'] if base64.b64decode(row['path_b64'])==b'a.txt')
            for number in range(70):
                path=('k%04d/'%number).encode('ascii')+b'/'.join([b'x'*250]*16)
                extra=dict(source);extra['path_b64']=base64.b64encode(path).decode('ascii');m['untracked'].append(extra)
            m['untracked'].sort(key=lambda row:base64.b64decode(row['path_b64']))
            m['input_bytes_counting_each_projection']=sum(row['byte_count'] for label in
                ('head','index','tracked_worktree','untracked') for row in m[label])
            digest=hashlib.sha256(json.dumps(m,sort_keys=True,ensure_ascii=True,separators=(',',':')).encode('ascii')).hexdigest()
            return m,digest,b
        with self.assertRaisesRegex(oracle.OracleError,'DERIVED_DIRECTORY_BUDGET'):self.observe(change=change)

    def fake_second_stat(self,name,code):
        original=os.stat;calls=[]
        def changed(path,*args,**kwargs):
            info=original(path,*args,**kwargs)
            if path==name and kwargs.get('dir_fd') is not None:
                calls.append(path)
                if len(calls)==2:
                    fields={key:getattr(info,key) for key in ('st_dev','st_ino','st_mode','st_nlink','st_size','st_mtime_ns','st_ctime_ns')}
                    fields['st_ino']+=1
                    return SimpleNamespace(**fields)
            return info
        with patch.object(oracle.os,'stat',side_effect=changed):
            with self.assertRaisesRegex(oracle.OracleError,code):self.observe()
        self.assertEqual(len(calls),2)
    def test_file_identity_change_between_stats_is_rejected(self):
        self.fake_second_stat(b'a.txt','FILE_IDENTITY_CHANGED')
    def test_directory_identity_change_between_stats_is_rejected(self):
        self.fake_second_stat(b'dir','DIRECTORY_IDENTITY_CHANGED')

    def test_close_failure_closes_next_fd_once_without_retry(self):
        self.observe();calls=[];body=oracle.OracleError('BODY_REJECTED')
        def close(fd):
            calls.append(fd)
            if fd==202:raise OSError('injected close uncertainty')
        def inner(_root,_manifest,_digest,_blobs,ledger):
            with oracle.OwnedFD(101,ledger,'OUTER'):
                with oracle.OwnedFD(202,ledger,'INNER'):raise body
        with patch.object(oracle,'_review_inner',side_effect=inner),patch.object(oracle.os,'close',side_effect=close):
            with self.assertRaisesRegex(oracle.OracleError,'FD_CLOSE_UNKNOWN') as caught:
                oracle.review(9,None,None,None)
        self.assertEqual(calls,[202,101]);self.assertIs(caught.exception.oracle_primary_error,body)
        self.assertEqual([row['state'] for row in caught.exception.close_outcomes],['UNKNOWN','CLOSED'])
        create_file(self.case/'manual_fault.json',json.dumps({'close_calls':calls,'outcomes':caught.exception.close_outcomes}).encode('ascii'))

    def test_body_rejection_with_close_failure_is_unknown(self):
        self.observe();calls=[];body=oracle.OracleError('DIRECTORY_CHANGED')
        def close(fd):calls.append(fd);raise OSError('injected close uncertainty')
        def inner(_root,_manifest,_digest,_blobs,ledger):
            with oracle.OwnedFD(101,ledger,'OUTER'):raise body
        with patch.object(oracle,'_review_inner',side_effect=inner),patch.object(oracle.os,'close',side_effect=close):
            with self.assertRaisesRegex(oracle.OracleError,'FD_CLOSE_UNKNOWN') as caught:
                oracle.review(9,None,None,None)
        self.assertEqual(calls,[101]);self.assertIs(caught.exception.oracle_primary_error,body)
        self.assertEqual(caught.exception.close_outcomes[0]['state'],'UNKNOWN')
        create_file(self.case/'manual_fault.json',json.dumps({'close_calls':calls,'outcomes':caught.exception.close_outcomes}).encode('ascii'))

    def test_interrupted_close_propagates_after_next_fd_close(self):
        self.observe();calls=[];interrupt=KeyboardInterrupt('injected interruption')
        def close(fd):
            calls.append(fd)
            if fd==202:raise interrupt
        def inner(_root,_manifest,_digest,_blobs,ledger):
            with oracle.OwnedFD(101,ledger,'OUTER'):
                with oracle.OwnedFD(202,ledger,'INNER'):pass
        with patch.object(oracle,'_review_inner',side_effect=inner),patch.object(oracle.os,'close',side_effect=close):
            with self.assertRaises(KeyboardInterrupt) as caught:oracle.review(9,None,None,None)
        self.assertIs(caught.exception,interrupt);self.assertEqual(calls,[202,101])
        self.assertEqual([item['state'] for item in caught.exception.oracle_close_outcomes],['UNKNOWN','CLOSED'])
        self.assertEqual(caught.exception.oracle_unregistered_fd_state,'UNKNOWN_ON_ASYNC_INTERRUPTION')
        create_file(self.case/'manual_fault.json',json.dumps({'close_calls':calls,'outcomes':caught.exception.oracle_close_outcomes}).encode('ascii'))

    def test_generic_close_failure_is_unknown_and_not_retried(self):
        self.observe();calls=[];ledger=oracle.CloseLedger()
        def close(fd):calls.append(fd);raise OSError('injected uncertainty')
        with patch.object(oracle.os,'close',side_effect=close):
            with self.assertRaisesRegex(oracle.OracleError,'FD_CLOSE_UNKNOWN'):
                with oracle.OwnedFD(101,ledger,'OUTER'):pass
        self.assertEqual(calls,[101]);self.assertEqual(ledger.events[0]['state'],'UNKNOWN')
        create_file(self.case/'manual_fault.json',json.dumps({'close_calls':calls,'outcomes':ledger.events}).encode('ascii'))

    def test_body_interrupt_survives_two_close_failures(self):
        self.observe();calls=[];body=KeyboardInterrupt('body interrupt')
        def close(fd):calls.append(fd);raise OSError('close failed')
        def inner(_root,_manifest,_digest,_blobs,ledger):
            with oracle.OwnedFD(101,ledger,'OUTER'):
                with oracle.OwnedFD(202,ledger,'INNER'):raise body
        with patch.object(oracle,'_review_inner',side_effect=inner),patch.object(oracle.os,'close',side_effect=close):
            with self.assertRaises(KeyboardInterrupt) as caught:oracle.review(9,None,None,None)
        self.assertIs(caught.exception,body);self.assertEqual(calls,[202,101])
        self.assertEqual([item['state'] for item in body.oracle_close_outcomes],['UNKNOWN','UNKNOWN'])
        create_file(self.case/'manual_fault.json',json.dumps({'close_calls':calls,'outcomes':body.oracle_close_outcomes}).encode('ascii'))

    def test_body_error_and_two_close_failures_preserve_primary(self):
        self.observe();calls=[];body=oracle.OracleError('BODY_REJECTED')
        def close(fd):calls.append(fd);raise OSError('close failed')
        def inner(_root,_manifest,_digest,_blobs,ledger):
            with oracle.OwnedFD(101,ledger,'OUTER'):
                with oracle.OwnedFD(202,ledger,'INNER'):raise body
        with patch.object(oracle,'_review_inner',side_effect=inner),patch.object(oracle.os,'close',side_effect=close):
            with self.assertRaisesRegex(oracle.OracleError,'FD_CLOSE_UNKNOWN') as caught:oracle.review(9,None,None,None)
        self.assertIs(caught.exception.oracle_primary_error,body);self.assertEqual(calls,[202,101])
        self.assertEqual([item['state'] for item in caught.exception.close_outcomes],['UNKNOWN','UNKNOWN'])
        create_file(self.case/'manual_fault.json',json.dumps({'close_calls':calls,'outcomes':caught.exception.close_outcomes}).encode('ascii'))

    def test_close_interrupt_precedes_body_oserror_and_later_close_failure(self):
        self.observe();calls=[];body=OSError('body');interrupt=KeyboardInterrupt('close interrupt')
        def close(fd):
            calls.append(fd)
            if fd==202:raise interrupt
            raise OSError('later close failure')
        def inner(_root,_manifest,_digest,_blobs,ledger):
            with oracle.OwnedFD(101,ledger,'OUTER'):
                with oracle.OwnedFD(202,ledger,'INNER'):raise body
        with patch.object(oracle,'_review_inner',side_effect=inner),patch.object(oracle.os,'close',side_effect=close):
            with self.assertRaises(KeyboardInterrupt) as caught:oracle.review(9,None,None,None)
        self.assertIs(caught.exception,interrupt);self.assertIs(interrupt.oracle_prior_error,body)
        self.assertEqual(calls,[202,101]);self.assertEqual([item['state'] for item in interrupt.oracle_close_outcomes],['UNKNOWN','UNKNOWN'])
        create_file(self.case/'manual_fault.json',json.dumps({'close_calls':calls,'outcomes':interrupt.oracle_close_outcomes}).encode('ascii'))

    def test_incomplete_close_ledger_cannot_observe_success(self):
        self.observe();calls=[]
        def inner(_root,_manifest,_digest,_blobs,ledger):
            with oracle.OwnedFD(101,ledger,'OUTER'):pass
            return {'status':'OBSERVED_RESEARCH_ONLY'}
        with patch.object(oracle,'MAX_CLOSE_EVENTS',0),patch.object(oracle,'_review_inner',side_effect=inner),\
             patch.object(oracle.os,'close',side_effect=lambda fd:calls.append(fd)):
            with self.assertRaisesRegex(oracle.OracleError,'FD_LEDGER_INCOMPLETE') as caught:oracle.review(9,None,None,None)
        self.assertEqual(calls,[101]);self.assertTrue(caught.exception.oracle_ledger_incomplete)
        create_file(self.case/'manual_fault.json',json.dumps({'close_calls':calls,'ledger_incomplete':True}).encode('ascii'))

    def controlled_open_failure(self,body,close_faults,expected_type,expected_code=None,expected_prior=None):
        """Exercise real open_dir control flow with synthetic FD numbers only."""
        self.observe();calls=[]
        before=SimpleNamespace(st_dev=1,st_ino=42,st_mode=stat.S_IFDIR|0o700,
             st_nlink=1,st_size=4096,st_mtime_ns=7,st_ctime_ns=8)
        altered=SimpleNamespace(**vars(before));altered.st_ino+=1
        def fstat(_fd):
            if body=='IDENTITY_MISMATCH':return altered
            raise body
        def close(fd):
            calls.append(fd)
            if fd in close_faults:raise close_faults[fd]
        def inner(_root,_manifest,_digest,_blobs,ledger):
            with oracle.OwnedFD(202,ledger,'OUTER'):
                oracle.open_dir(9,b'fixture',1,ledger,expected=before)
        with patch.object(oracle,'_review_inner',side_effect=inner),\
             patch.object(oracle.os,'stat',return_value=before) as outer_stat,\
             patch.object(oracle.os,'open',return_value=101) as opened,\
             patch.object(oracle.os,'fstat',side_effect=fstat) as opened_stat,\
             patch.object(oracle.os,'close',side_effect=close):
            with self.assertRaises(expected_type) as caught:oracle.review(9,None,None,None)
        self.assertEqual(outer_stat.call_count,1);self.assertEqual(opened.call_count,1)
        self.assertEqual(opened_stat.call_count,1);self.assertEqual(calls,[101,202])
        exc=caught.exception
        if expected_code is not None:self.assertEqual(getattr(exc,'code',None),expected_code)
        if expected_prior is not None:self.assertIs(getattr(exc,'oracle_primary_error',None),expected_prior)
        outcomes=getattr(exc,'close_outcomes',getattr(exc,'oracle_close_outcomes',()))
        self.assertEqual([item['state'] for item in outcomes],
                         ['UNKNOWN' if fd in close_faults else 'CLOSED' for fd in calls])
        create_file(self.case/'manual_fault.json',json.dumps({'close_calls':calls,'outcomes':outcomes,
            'raised_type':type(exc).__name__,'raised_code':getattr(exc,'code',None),
            'prior_type':type(getattr(exc,'oracle_primary_error',None)).__name__,
            'prior_code':getattr(getattr(exc,'oracle_primary_error',None),'code',None)}).encode('ascii'))
        return exc

    def test_acquired_dir_fstat_error_two_close_failures(self):
        body=OSError('fstat failed')
        self.controlled_open_failure(body,{101:OSError('inner close'),202:OSError('outer close')},
                                     oracle.OracleError,'FD_CLOSE_UNKNOWN',body)

    def test_acquired_dir_identity_mismatch_and_close_failure(self):
        exc=self.controlled_open_failure('IDENTITY_MISMATCH',{101:OSError('inner close')},
                                         oracle.OracleError,'FD_CLOSE_UNKNOWN')
        self.assertEqual(exc.oracle_primary_error.code,'DIRECTORY_CHANGED')

    def test_acquired_dir_fstat_interrupt_survives_close_failures(self):
        body=KeyboardInterrupt('fstat interrupt')
        exc=self.controlled_open_failure(body,{101:OSError('inner close'),202:OSError('outer close')},KeyboardInterrupt)
        self.assertIs(exc,body);self.assertEqual(exc.oracle_unregistered_fd_state,'UNKNOWN_ON_ASYNC_INTERRUPTION')

    def test_acquired_dir_close_interrupt_preserves_fstat_error(self):
        body=OSError('fstat failed');interrupt=KeyboardInterrupt('close interrupt')
        exc=self.controlled_open_failure(body,{101:interrupt,202:OSError('outer close')},KeyboardInterrupt)
        self.assertIs(exc,interrupt);self.assertIs(exc.oracle_prior_error,body)

    def test_small_fd_limit_rejected_before_target_observation(self):
        with patch.object(oracle.resource,'getrlimit',return_value=(1,1)):
            with self.assertRaisesRegex(oracle.OracleError,'FD_BUDGET'):self.observe()

    def test_missing_fd_inventory_is_rejected(self):
        with patch.object(oracle.os,'scandir',side_effect=OSError('injected inventory failure')):
            with self.assertRaisesRegex(oracle.OracleError,'FD_INVENTORY_UNAVAILABLE'):self.observe()

    def test_unexpected_directory_is_not_opened(self):
        original=os.open;unexpected=[]
        def guarded(path,*args,**kwargs):
            if path==b'unused':unexpected.append(path);raise AssertionError('unexpected directory open')
            return original(path,*args,**kwargs)
        with patch.object(oracle.os,'open',side_effect=guarded):
            with self.assertRaisesRegex(oracle.OracleError,'WORKTREE_DIRECTORY_MISMATCH'):self.observe('extra_empty_dir')
        self.assertEqual(unexpected,[])

    def test_bounded_readlink_rejects_filled_buffer(self):
        self.observe()
        class FakeReadlink:
            def __call__(self,*_args):return oracle.MAX_SYMLINK_BYTES+1
        with patch.object(oracle.ctypes,'CDLL',return_value=SimpleNamespace(readlinkat=FakeReadlink())):
            with self.assertRaisesRegex(oracle.OracleError,'SYMLINK_TARGET_LIMIT'):
                oracle._bounded_readlink(9,b'link')
        create_file(self.case/'manual_fault.json',b'{"readlink_returned":4096,"status":"REJECTED"}\n')

    def test_bounded_readlink_unavailable_is_rejected(self):
        self.observe()
        with patch.object(oracle.ctypes,'CDLL',return_value=SimpleNamespace()):
            with self.assertRaisesRegex(oracle.OracleError,'READLINKAT_UNAVAILABLE'):
                oracle._bounded_readlink(9,b'link')
        create_file(self.case/'manual_fault.json',b'{"readlinkat":"UNAVAILABLE","status":"REJECTED"}\n')

    def test_fixture_exclusive_create_preserves_existing_bytes(self):
        self.observe();path=self.path/'.git'/'HEAD';before=path.read_bytes()
        with self.assertRaises(FileExistsError):create_file(path,b'should-not-overwrite')
        self.assertEqual(path.read_bytes(),before)
        create_file(self.case/'manual_fault.json',b'{"existing_head":"UNCHANGED"}\n')

    def test_git_directory_symlink_is_never_opened(self):
        self.observe();os.symlink(b'target/.git',os.fsencode(self.case/'linked-git'))
        casefd=os.open(self.case,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
        try:
            with self.assertRaisesRegex(oracle.OracleError,'DIRECTORY_UNSUPPORTED'):
                oracle.open_dir(casefd,b'linked-git',os.fstat(casefd).st_dev,oracle.CloseLedger())
        finally:os.close(casefd)
        create_file(self.case/'manual_fault.json',b'{"gitdir_symlink":"REJECTED_BEFORE_OPEN"}\n')

if __name__=='__main__':unittest.main(verbosity=2)
