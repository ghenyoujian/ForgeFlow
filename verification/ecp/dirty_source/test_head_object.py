import base64
import hashlib
import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch

s = importlib.util.spec_from_file_location('head_object_research', Path(__file__).with_name('head_object.py'))
h = importlib.util.module_from_spec(s)
s.loader.exec_module(h)


def obj(algorithm, kind, raw):
    return hashlib.new(algorithm, kind + b' ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()


def row(path, raw, mode='100644', alg='sha1'):
    return {'path_b64': base64.b64encode(path).decode(),
            'kind': 'symlink' if mode == '120000' else 'file', 'mode': mode,
            'byte_count': len(raw), 'sha256': hashlib.sha256(raw).hexdigest(),
            'computed_git_blob_oid': obj(alg, b'blob', raw)}


def fixture(alg='sha1'):
    data = b'hello\n'
    r = row(b'a', data, alg=alg)
    body = b'100644 a\0' + bytes.fromhex(r['computed_git_blob_oid'])
    tree = obj(alg, b'tree', body)
    commit = b'tree ' + tree.encode() + b'\nauthor A <a@example.invalid> 1 +0000\ncommitter A <a@example.invalid> 1 +0000\n\nmessage\n'
    m = {'schema':'forgeflow.ecp-dirty-source-declaration.research.v1',
         'git_object_format_claim':alg, 'head_commit_claim':obj(alg,b'commit',commit), 'head':[r]}
    return m, {r['sha256']:data}, commit, tree, body


class HeadEvidenceTests(unittest.TestCase):
    def test_single_blob_links_to_commit_and_preserves_raw_objects(self):
        m,b,c,t,tree_body=fixture(); v=h.verify(m,b,c)['evidence']
        self.assertEqual((v['tree_oid'],v['commit_oid'],v['head_rows']),(t,m['head_commit_claim'],1))
        self.assertEqual(base64.b64decode(v['commit_bytes_base64']),c)
        self.assertEqual(base64.b64decode(v['trees_base64'][t]),tree_body)
        self.assertEqual((v['qualification'],v['product_gate_effect'],v['source_authentication']),('NOT_RUN','NONE','UNVERIFIED'))
    def test_empty_tree_known_git_oid(self):
        tree='4b825dc642cb6eb9a060e54bf8d69288fbee4904';c=b'tree '+tree.encode()+b'\n\nempty\n'
        m={'schema':'forgeflow.ecp-dirty-source-declaration.research.v1','git_object_format_claim':'sha1','head_commit_claim':obj('sha1',b'commit',c),'head':[]}
        self.assertEqual(h.verify(m,{},c)['evidence']['tree_oid'],tree)
    def test_sha256_git_object_format(self):
        m,b,c,t,_=fixture('sha256');self.assertEqual(h.verify(m,b,c)['evidence']['tree_oid'],t)
    def test_changed_commit_rejected(self):
        m,b,c,_,_=fixture()
        with self.assertRaisesRegex(h.HeadObjectError,'COMMIT_OID_MISMATCH'):h.verify(m,b,c+b'changed')
    def test_commit_matches_but_wrong_tree_rejected(self):
        m,b,c,_,_=fixture();c=c.replace(c.split(b'\n',1)[0],b'tree '+b'1'*40);m['head_commit_claim']=obj('sha1',b'commit',c)
        with self.assertRaisesRegex(h.HeadObjectError,'TREE_OID_MISMATCH'):h.verify(m,b,c)
    def test_changed_blob_bytes_rejected(self):
        m,b,c,_,_=fixture();key=next(iter(b));b[key]=b'wrong\n'
        with self.assertRaisesRegex(h.HeadObjectError,'BLOB_CONTENT_MISMATCH'):h.verify(m,b,c)
    def test_changed_blob_oid_rejected(self):
        m,b,c,_,_=fixture();m['head'][0]['computed_git_blob_oid']='0'*40
        with self.assertRaisesRegex(h.HeadObjectError,'BLOB_OID_MISMATCH'):h.verify(m,b,c)
    def test_symlink_target_and_mode_are_bound(self):
        m,b,c,_,_=fixture();r=row(b'a',b'target','120000');tree=obj('sha1',b'tree',b'120000 a\0'+bytes.fromhex(r['computed_git_blob_oid']));c=b'tree '+tree.encode()+b'\n\nlink\n';m['head']=[r];m['head_commit_claim']=obj('sha1',b'commit',c)
        self.assertEqual(h.verify(m,{r['sha256']:b'target'},c)['evidence']['tree_oid'],tree)
    def test_nested_tree_git_sorting_with_prefix(self):
        a=row(b'a/x',b'x');dot=row(b'a.',b'z');child=b'100644 x\0'+bytes.fromhex(a['computed_git_blob_oid']);childid=obj('sha1',b'tree',child)
        root=b'100644 a.\0'+bytes.fromhex(dot['computed_git_blob_oid'])+b'40000 a\0'+bytes.fromhex(childid);tree=obj('sha1',b'tree',root)
        c=b'tree '+tree.encode()+b'\n\nmessage\n';m={'schema':'forgeflow.ecp-dirty-source-declaration.research.v1','git_object_format_claim':'sha1','head_commit_claim':obj('sha1',b'commit',c),'head':[a,dot]}
        v=h.verify(m,{a['sha256']:b'x',dot['sha256']:b'z'},c)['evidence'];self.assertEqual(v['tree_oid'],tree);self.assertEqual(len(v['trees_base64']),2)
    def test_non_utf8_filename(self):
        m,b,c,_,_=fixture();r=row(b'\xff',b'hello\n');tree=obj('sha1',b'tree',b'100644 \xff\0'+bytes.fromhex(r['computed_git_blob_oid']));c=b'tree '+tree.encode()+b'\n\nnonutf8\n';m['head']=[r];m['head_commit_claim']=obj('sha1',b'commit',c)
        self.assertEqual(h.verify(m,b,c)['evidence']['tree_oid'],tree)
    def test_duplicate_path_rejected(self):
        m,b,c,_,_=fixture();m['head'].append(dict(m['head'][0]))
        with self.assertRaisesRegex(h.HeadObjectError,'DUPLICATE_PATH'):h.verify(m,b,c)
    def test_file_directory_collision_rejected_in_any_order(self):
        for reverse in (False,True):
            m,b,c,_,_=fixture();r=row(b'a/b',b'x');b[r['sha256']]=b'x';m['head'].append(r)
            if reverse:m['head'].reverse()
            with self.subTest(reverse=reverse),self.assertRaisesRegex(h.HeadObjectError,'PATH_COLLISION'):h.verify(m,b,c)
    def test_dotgit_and_parent_path_rejected(self):
        for path in (b'.git/config',b'x/../y',b'x//y'):
            m,b,c,_,_=fixture();m['head'][0]['path_b64']=base64.b64encode(path).decode()
            with self.subTest(path=path),self.assertRaisesRegex(h.HeadObjectError,'INVALID_PATH'):h.verify(m,b,c)
    def test_duplicate_tree_header_rejected(self):
        m,b,c,_,_=fixture();c=c.replace(b'\n\n',b'\ntree '+b'0'*40+b'\n\n');m['head_commit_claim']=obj('sha1',b'commit',c)
        with self.assertRaisesRegex(h.HeadObjectError,'INVALID_COMMIT_HEADER'):h.verify(m,b,c)
    def test_invalid_mode_and_bool_size_rejected(self):
        for field,value in (('mode','160000'),('byte_count',True)):
            m,b,c,_,_=fixture();m['head'][0][field]=value
            with self.subTest(field=field),self.assertRaisesRegex(h.HeadObjectError,'INVALID_HEAD_ROW'):h.verify(m,b,c)
    def test_commit_size_limit(self):
        m,b,c,_,_=fixture()
        with self.assertRaisesRegex(h.HeadObjectError,'INVALID_INPUT'):h.verify(m,b,b'x'*(h.MAX_COMMIT+1))
    def test_content_address_is_deterministic(self):
        m,b,c,_,_=fixture();self.assertEqual(h.verify(m,b,c),h.verify(m,b,c))
    def test_wrong_object_format_rejected(self):
        m,b,c,_,_=fixture();m['git_object_format_claim']='sha256'
        with self.assertRaisesRegex(h.HeadObjectError,'INVALID_COMMIT_CLAIM'):h.verify(m,b,c)
    def test_path_depth_limit_is_checked_before_trie_build(self):
        m,b,c,_,_=fixture();m['head'][0]['path_b64']=base64.b64encode(b'/'.join([b'd'] * 128 + [b'f'])).decode()
        with self.assertRaisesRegex(h.HeadObjectError,'PATH_DEPTH_LIMIT'):h.verify(m,b,c)
    def test_path_depth_exact_boundary_is_accepted(self):
        parts=[b'd'] * 127 + [b'f'];r=row(b'/'.join(parts),b'x')
        child=obj('sha1',b'tree',b'100644 f\0'+bytes.fromhex(r['computed_git_blob_oid']))
        for _ in parts[:-1]:
            child=obj('sha1',b'tree',b'40000 d\0'+bytes.fromhex(child))
        c=b'tree '+child.encode()+b'\n\nboundary\n'
        m={'schema':'forgeflow.ecp-dirty-source-declaration.research.v1','git_object_format_claim':'sha1','head_commit_claim':obj('sha1',b'commit',c),'head':[r]}
        v=h.verify(m,{r['sha256']:b'x'},c)['evidence']
        self.assertEqual(v['tree_oid'],child);self.assertEqual(len(v['trees_base64']),128)
    def test_total_path_bytes_limit_is_checked(self):
        m,b,c,_,_=fixture();r=row(b'bcd',b'x');b[r['sha256']]=b'x';m['head'].append(r)
        with patch.object(h,'MAX_TOTAL_PATH_BYTES',3,create=True),self.assertRaisesRegex(h.HeadObjectError,'TOTAL_PATH_BYTES_LIMIT'):h.verify(m,b,c)
    def test_total_path_bytes_exact_boundary_is_accepted(self):
        m,b,c,t,_=fixture()
        with patch.object(h,'MAX_TOTAL_PATH_BYTES',1,create=True):self.assertEqual(h.verify(m,b,c)['evidence']['tree_oid'],t)
    def test_trie_nodes_limit_is_checked_before_insert(self):
        m,b,c,_,_=fixture();r=row(b'b/c',b'x');b[r['sha256']]=b'x';m['head'].append(r)
        with patch.object(h,'MAX_TRIE_NODES',2,create=True),self.assertRaisesRegex(h.HeadObjectError,'TRIE_NODE_LIMIT'):h.verify(m,b,c)
    def test_trie_nodes_exact_boundary_is_accepted(self):
        r=row(b'd/f',b'x');child=obj('sha1',b'tree',b'100644 f\0'+bytes.fromhex(r['computed_git_blob_oid']))
        tree=obj('sha1',b'tree',b'40000 d\0'+bytes.fromhex(child));c=b'tree '+tree.encode()+b'\n\nnode boundary\n'
        m={'schema':'forgeflow.ecp-dirty-source-declaration.research.v1','git_object_format_claim':'sha1','head_commit_claim':obj('sha1',b'commit',c),'head':[r]}
        with patch.object(h,'MAX_TRIE_NODES',2,create=True):self.assertEqual(h.verify(m,{r['sha256']:b'x'},c)['evidence']['tree_oid'],tree)

if __name__ == '__main__': unittest.main(verbosity=2)
