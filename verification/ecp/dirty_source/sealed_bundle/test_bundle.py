"""Synthetic sealed-bundle tests; no Git, database, source tree or subprocess."""
import base64
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import struct
import sys
import unittest
from unittest.mock import patch
import importlib.util

HERE=Path(__file__).parent

def load(name):
    spec=importlib.util.spec_from_file_location(name,HERE/(name+'.py'))
    value=importlib.util.module_from_spec(spec);spec.loader.exec_module(value);return value
writer=load('writer');reader=load('reader')

def hash_obj(kind,data,alg='sha1'):
    return hashlib.new(alg,kind+b' '+str(len(data)).encode()+b'\0'+data).hexdigest()

def fixture(alg='sha1'):
    base=b'baseline\n';staged=b'staged\n';work=b'worktree\n';unknown=b'ignored\x00bytes'
    link=b'a.txt'
    blobs={hashlib.sha256(d).hexdigest():d for d in (base,staged,work,unknown,link)}
    def row(path,mode,data,kind='file'):
        return {'path_b64':base64.b64encode(path).decode(),'kind':kind,'mode':mode,
                'byte_count':len(data),'sha256':hashlib.sha256(data).hexdigest(),
                'computed_git_blob_oid':hash_obj(b'blob',data,alg)}
    head=[row(b'a.txt','100644',base),row(b'link','120000',link,'symlink')]
    index=[row(b'a.txt','100644',staged),row(b'link','120000',link,'symlink')]
    tracked=[row(b'a.txt','100644',work),row(b'link','120000',link,'symlink')]
    untracked=[row(b'ignored.tmp',None,unknown)]
    tree=(b'100644 a.txt\0'+bytes.fromhex(hash_obj(b'blob',base,alg))+
          b'120000 link\0'+bytes.fromhex(hash_obj(b'blob',link,alg)))
    commit=(b'tree '+hash_obj(b'tree',tree,alg).encode()+b'\nauthor A <a@x> 1 +0000\n\nsynthetic\n')
    manifest={'schema':'forgeflow.ecp-dirty-source-declaration.research.v1',
      'qualification':'NOT_RUN','product_gate_effect':'NONE','source_authentication':'UNVERIFIED',
      'snapshot_atomicity':'UNKNOWN','completeness_authority':'UNVERIFIED',
      'head_commit_claim':hash_obj(b'commit',commit,alg),'git_object_format_claim':alg,
      'coverage_claims':{'head':True,'index':True,'worktree':True,'exclusions':False},
      'head':head,'index':index,'tracked_worktree':tracked,'untracked':untracked,'excluded':[],
      'staged_changes':[{'path_b64':base64.b64encode(b'a.txt').decode(),'change':'MODIFIED'}],
      'unstaged_changes':[{'path_b64':base64.b64encode(b'a.txt').decode(),'change':'MODIFIED'}],
      'unknown_worktree_modes':[base64.b64encode(b'ignored.tmp').decode()],
      'input_bytes_counting_each_projection':sum(row['byte_count'] for group in (head,index,tracked,untracked) for row in group)}
    return manifest,blobs,commit

def canon(m):return json.dumps(m,sort_keys=True,ensure_ascii=True,separators=(',',':'),allow_nan=False).encode('ascii')
def bundle(m,b,c):return writer.encode(canon(m),b,c)
def pin(data):return hashlib.sha256(data).hexdigest()
def sealed_bytes(data):
    fd=os.memfd_create('synthetic-test',os.MFD_ALLOW_SEALING|os.MFD_CLOEXEC)
    try:
        n=0
        while n<len(data):n+=os.write(fd,data[n:])
        fcntl.fcntl(fd,fcntl.F_ADD_SEALS,fcntl.F_SEAL_WRITE|fcntl.F_SEAL_GROW|fcntl.F_SEAL_SHRINK|fcntl.F_SEAL_SEAL)
        return fd
    except BaseException:
        os.close(fd);raise

def reseal(body):return body[:-32]+hashlib.sha256(body[:-32]).digest()

class SealedBundleTests(unittest.TestCase):
    def verify(self,m,b,c):
        raw=bundle(m,b,c);fd=writer.create(canon(m),b,c)
        try:return reader.read(fd,pin(raw))
        finally:os.close(fd)
    def reject_raw(self,raw,reason):
        fd=sealed_bytes(raw)
        try:
            with self.assertRaisesRegex(reader.Invalid,reason):reader.read(fd,pin(raw))
        finally:os.close(fd)
    def test_dense_json_is_rejected_before_json_decoder_allocation(self):
        raw=b'['+b'0,'*100000+b'0]'
        with patch.object(reader.json,'loads',side_effect=AssertionError('decoder must not run')) as decoder:
            with self.assertRaisesRegex(reader.Invalid,'JSON_COMPLEXITY'):reader.canonical_manifest(raw)
        decoder.assert_not_called()
    def test_lexical_array_exact_token_boundary(self):
        with patch.object(reader,'MAX_NODES',5):
            self.assertEqual(reader.canonical_manifest(b'[0,0,0,0]'),[0,0,0,0])
            with self.assertRaisesRegex(reader.Invalid,'JSON_COMPLEXITY'):reader.canonical_manifest(b'[0,0,0,0,0]')
    def test_lexical_object_keys_count_toward_budget(self):
        with patch.object(reader,'MAX_NODES',5):
            self.assertEqual(reader.canonical_manifest(b'{"a":1,"b":2}'),{'a':1,'b':2})
        with patch.object(reader,'MAX_NODES',4),patch.object(reader.json,'loads',side_effect=AssertionError('decoder must not run')) as decoder:
            with self.assertRaisesRegex(reader.Invalid,'JSON_COMPLEXITY'):reader.canonical_manifest(b'{"a":1,"b":2}')
        decoder.assert_not_called()
    def test_lexical_quotes_and_backslashes_do_not_inflate_structure(self):
        value=['quote " and slash \\ and [ { ] }'];raw=json.dumps(value,ensure_ascii=True,separators=(',',':')).encode('ascii')
        with patch.object(reader,'MAX_NODES',2):self.assertEqual(reader.canonical_manifest(raw),value)
    def test_lexical_depth_rejects_before_decoder(self):
        raw=b'['*17+b'0'+b']'*17
        with patch.object(reader.json,'loads',side_effect=AssertionError('decoder must not run')) as decoder:
            with self.assertRaisesRegex(reader.Invalid,'JSON_COMPLEXITY'):reader.canonical_manifest(raw)
        decoder.assert_not_called()
    def test_lexical_unterminated_input_fails_closed(self):
        with patch.object(reader.json,'loads',side_effect=AssertionError('decoder must not run')) as decoder:
            with self.assertRaisesRegex(reader.Invalid,'JSON_STRUCTURE'):reader.canonical_manifest(b'["unterminated')
        decoder.assert_not_called()
    def test_lexical_string_raw_bytes_exact_boundary(self):
        with patch.object(reader,'MAX_RAW_STRING',4):
            reader.lexical_preflight(b'"abcd"')
            with self.assertRaisesRegex(reader.Invalid,'JSON_STRING_RAW_LIMIT'):reader.lexical_preflight(b'"abcde"')
    def test_dense_object_keys_are_rejected_before_json_decoder(self):
        raw=b'{'+b','.join(('"k%d":0'%i).encode('ascii') for i in range(50000))+b'}'
        with patch.object(reader.json,'loads',side_effect=AssertionError('decoder must not run')) as decoder:
            with self.assertRaisesRegex(reader.Invalid,'JSON_COMPLEXITY'):reader.canonical_manifest(raw)
        decoder.assert_not_called()
    def test_escaped_unicode_and_delimiters_are_scanned_as_strings(self):
        value={'a': '[]{}",\\\u0000\U0001f600'}
        raw=json.dumps(value,ensure_ascii=True,sort_keys=True,separators=(',',':')).encode('ascii')
        with patch.object(reader,'MAX_NODES',3):self.assertEqual(reader.canonical_manifest(raw),value)
    def test_returned_mutable_values_do_not_mutate_sealed_bytes(self):
        m,b,c=fixture();raw=bundle(m,b,c);fd=writer.create(canon(m),b,c)
        try:
            first=reader.read(fd,pin(raw));first['manifest']['head_commit_claim']='modified';first['blobs'].clear()
            second=reader.read(fd,pin(raw))
            self.assertEqual((second['manifest'],second['blobs'],second['commit']),(m,b,c))
        finally:os.close(fd)
    def test_valid_roundtrip_and_claims_are_not_authenticated(self):
        m,b,c=fixture();out=self.verify(m,b,c)
        self.assertEqual((out['manifest'],out['blobs'],out['commit']),(m,b,c))
        self.assertEqual((out['status'],out['qualification'],out['product_gate_effect']),('OBSERVED_RESEARCH_ONLY','NOT_RUN','NONE'))
        self.assertEqual((out['source_authentication'],out['snapshot_atomicity'],out['directory_immutability']),('UNVERIFIED','UNKNOWN','NOT_MEASURED'))
    def test_sha256_object_format_is_self_consistent(self):
        m,b,c=fixture('sha256');out=self.verify(m,b,c)
        self.assertEqual(out['head_commit_claim'],m['head_commit_claim'])
        self.assertEqual(len(out['head_commit_claim']),64)
    def test_returned_fd_rejects_write_and_resize(self):
        m,b,c=fixture();raw=bundle(m,b,c);fd=writer.create(canon(m),b,c)
        try:
            for operation in (lambda:os.pwrite(fd,b'X',0),lambda:os.ftruncate(fd,len(raw)+1),lambda:os.ftruncate(fd,len(raw)-1)):
                with self.subTest(operation=operation),self.assertRaises(PermissionError):operation()
            self.assertEqual(reader.read(fd,pin(raw))['manifest'],m)
        finally:os.close(fd)
    def test_determinism_ignores_blob_dict_insertion_order(self):
        m,b,c=fixture();reverse=dict(reversed(list(b.items())))
        self.assertEqual(bundle(m,b,c),bundle(m,reverse,c))
    def test_unsealed_fd_is_rejected_before_decoding(self):
        m,b,c=fixture();fd=os.memfd_create('unsealed',os.MFD_ALLOW_SEALING|os.MFD_CLOEXEC)
        try:
            data=bundle(m,b,c);os.write(fd,data)
            with self.assertRaisesRegex(reader.Invalid,'SEALS_MISSING'):reader.read(fd,pin(data))
        finally:os.close(fd)
    def test_empty_row_denominator_is_rejected(self):
        m,b,c=fixture();m['head']=[];m['index']=[];m['tracked_worktree']=[];m['untracked']=[]
        m['staged_changes']=[];m['unstaged_changes']=[];m['unknown_worktree_modes']=[];m['input_bytes_counting_each_projection']=0
        empty_tree=hash_obj(b'tree',b'');c=b'tree '+empty_tree.encode()+b'\n\nempty';m['head_commit_claim']=hash_obj(b'commit',c)
        with self.assertRaisesRegex(reader.Invalid,'ZERO_ROWS'):self.verify(m,{},c)
    def test_wrong_expected_pin_is_rejected(self):
        m,b,c=fixture();data=bundle(m,b,c);fd=sealed_bytes(data)
        try:
            with self.assertRaisesRegex(reader.Invalid,'BUNDLE_PIN_MISMATCH'):reader.read(fd,'a'*64)
        finally:os.close(fd)
    def test_corrupt_trailer_and_truncation_are_rejected(self):
        m,b,c=fixture();raw=bundle(m,b,c)
        self.reject_raw(raw[:-1]+bytes([raw[-1]^1]),'TRAILER_MISMATCH')
        self.reject_raw(raw[:10],'BUNDLE_SIZE')
        self.reject_raw(reseal(raw[:-33]+raw[-32:]),'TRUNCATED|BUNDLE_TRAILING_OR_TRUNCATED|BLOB_ENCODING')
    def test_corrupt_magic_and_blob_bytes_are_rejected_even_with_new_trailer(self):
        m,b,c=fixture();raw=bundle(m,b,c)
        self.reject_raw(reseal(b'X'+raw[1:]),'HEADER_INVALID')
        off=20+len(canon(m))+36
        altered=raw[:off]+bytes([raw[off]^1])+raw[off+1:]
        self.reject_raw(reseal(altered),'BLOB_DIGEST')
    def test_missing_or_extra_blobs_are_rejected(self):
        m,b,c=fixture();missing=dict(b);missing.pop(next(iter(missing)))
        with self.assertRaisesRegex(reader.Invalid,'ROW_BLOB_MISMATCH'):self.verify(m,missing,c)
        extra=dict(b);data=b'extra';extra[hashlib.sha256(data).hexdigest()]=data
        with self.assertRaisesRegex(reader.Invalid,'BLOB_SET_MISMATCH'):self.verify(m,extra,c)
    def test_duplicate_sorted_blob_record_is_rejected(self):
        m,b,c=fixture();raw=bundle(m,b,c);manifest_len=len(canon(m));start=20+manifest_len
        n=struct.unpack_from('!I',raw,start+32)[0];end=start+36+n
        magic,ml,count,cl=struct.unpack_from('!8sIII',raw,0)
        changed=struct.pack('!8sIII',magic,ml,count+1,cl)+raw[20:end]+raw[start:end]+raw[end:]
        self.reject_raw(reseal(changed),'BLOB_ENCODING')
    def test_tight_resource_bounds_reject_before_create(self):
        m,b,c=fixture()
        with patch.object(writer,'MAX_MANIFEST',2),patch.object(writer.os,'memfd_create',side_effect=AssertionError('unexpected create')):
            with self.assertRaisesRegex(writer.BundleWriteError,'MANIFEST_LIMIT'):writer.create(b'123',{},b'x')
        raw=bundle(m,b,c);fd=sealed_bytes(raw)
        try:
            with patch.object(reader,'MAX_BUNDLE',len(raw)-1):
                with self.assertRaisesRegex(reader.Invalid,'BUNDLE_SIZE'):reader.read(fd,pin(raw))
        finally:os.close(fd)
    def test_short_writer_writes_complete_with_no_content_loss(self):
        m,b,c=fixture();raw=bundle(m,b,c);real_write=os.write
        def short(fd,buf):return real_write(fd,buf[:min(13,len(buf))])
        with patch.object(writer.os,'write',side_effect=short):fd=writer.create(canon(m),b,c)
        try:self.assertEqual(reader.read(fd,pin(raw))['manifest'],m)
        finally:os.close(fd)
    def test_raw_commit_and_head_tree_mismatch_rejected(self):
        m,b,c=fixture()
        with self.assertRaisesRegex(reader.Invalid,'COMMIT_OID_MISMATCH'):self.verify(m,b,c+b'x')
        bogus=b'tree '+b'0'*40+b'\n\nmsg';m['head_commit_claim']=hash_obj(b'commit',bogus)
        with self.assertRaisesRegex(reader.Invalid,'COMMIT_TREE_MISMATCH'):self.verify(m,b,bogus)
    def test_changed_blob_and_projection_claims_rejected(self):
        m,b,c=fixture();m['index'][0]['computed_git_blob_oid']='0'*40
        with self.assertRaisesRegex(reader.Invalid,'ROW_BLOB_MISMATCH'):self.verify(m,b,c)
        m,b,c=fixture();m['staged_changes']=[]
        with self.assertRaisesRegex(reader.Invalid,'CHANGE_MISMATCH'):self.verify(m,b,c)
    def test_manifest_order_unknown_fields_and_duplicate_keys_rejected(self):
        m,b,c=fixture();raw=json.dumps(m,ensure_ascii=True,indent=2).encode()
        fd=writer.create(raw,b,c)
        try:
            with self.assertRaisesRegex(reader.Invalid,'MANIFEST_NONCANONICAL'):reader.read(fd,pin(writer.encode(raw,b,c)))
        finally:os.close(fd)
        m['extra']=1
        with self.assertRaisesRegex(reader.Invalid,'DECLARATION_SCHEMA'):self.verify(m,b,c)
        raw=b'{"schema":1,"schema":2}'
        fd=writer.create(raw,{},b'x')
        try:
            with self.assertRaisesRegex(reader.Invalid,'JSON_DUPLICATE_KEY'):reader.read(fd,pin(writer.encode(raw,{},b'x')))
        finally:os.close(fd)
    def test_nonadjacent_path_prefix_rejected(self):
        m,b,c=fixture();b.pop(hashlib.sha256(b'ignored\x00bytes').hexdigest());raw=b'x';h=hashlib.sha256(raw).hexdigest();b[h]=raw
        def row(path):return {'path_b64':base64.b64encode(path).decode(),'kind':'file','mode':'100644','byte_count':1,'sha256':h,'computed_git_blob_oid':hash_obj(b'blob',raw)}
        m['untracked']=[row(b'bad'),row(b'bad-foo'),row(b'bad/z')];m['unknown_worktree_modes']=[]
        m['input_bytes_counting_each_projection']=sum(x['byte_count'] for k in ('head','index','tracked_worktree','untracked') for x in m[k])
        with self.assertRaisesRegex(reader.Invalid,'PATH_COLLISION'):self.verify(m,b,c)
    def test_writer_limits_and_bad_digest_precede_fd_creation(self):
        with patch.object(writer.os,'memfd_create',side_effect=AssertionError('unexpected create')):
            with self.assertRaisesRegex(writer.BundleWriteError,'MANIFEST_LIMIT'):writer.create(b'',{},b'x')
            with self.assertRaisesRegex(writer.BundleWriteError,'COMMIT_LIMIT'):writer.create(b'{}',{},b'')
            with self.assertRaisesRegex(writer.BundleWriteError,'BLOB_DIGEST'):writer.create(b'{}',{'a'*64:b'x'},b'x')
    def test_close_failure_does_not_retry_or_replace_original(self):
        m,b,c=fixture();calls=[];real_close=writer._close_fd
        def close_once(fd):calls.append(fd);real_close(fd);raise OSError('synthetic close error after close')
        with patch.object(writer.os,'write',side_effect=OSError('synthetic write error')),patch.object(writer,'_close_fd',side_effect=close_once):
            with self.assertRaisesRegex(OSError,'synthetic write error') as ctx:writer.create(canon(m),b,c)
        self.assertEqual(len(calls),1);self.assertEqual(ctx.exception.bundle_close_state,'UNKNOWN');self.assertEqual(ctx.exception.bundle_close_error_type,'OSError')
    def test_close_interruption_takes_precedence_over_ordinary_failure(self):
        m,b,c=fixture();calls=[];real_close=writer._close_fd
        def close_interrupt(fd):calls.append(fd);real_close(fd);raise KeyboardInterrupt('synthetic interruption')
        with patch.object(writer.os,'write',side_effect=OSError('synthetic write error')),patch.object(writer,'_close_fd',side_effect=close_interrupt):
            with self.assertRaises(KeyboardInterrupt) as ctx:writer.create(canon(m),b,c)
        self.assertEqual(len(calls),1);self.assertEqual(ctx.exception.bundle_close_state,'UNKNOWN');self.assertIsInstance(ctx.exception.bundle_prior_error,OSError)

if __name__=='__main__':unittest.main(verbosity=2)
