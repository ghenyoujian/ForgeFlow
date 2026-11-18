import base64
import hashlib
import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location('dirty_model_research', Path(__file__).with_name('model.py'))
model = importlib.util.module_from_spec(spec)
spec.loader.exec_module(model)

H='a'*40
C={'head':True,'index':True,'worktree':True,'exclusions':True}
def file(data=b'a', mode='100644'): return ('file',mode,data)
def link(target=b'target'): return ('symlink','120000',target)
def make(**kwargs):
    args=dict(head_commit=H,head={b'a':file()},index={b'a':file()},tracked_worktree={b'a':file()},untracked={},excluded={},coverage_claims=C)
    args.update(kwargs)
    return model.create(**args)
def paths(rows): return [(base64.b64decode(x['path_b64']),x['change']) for x in rows]

class DirtyDeclarationTests(unittest.TestCase):
 def test_clean_is_deterministic_despite_input_order(self):
  x=make(untracked={b'z':file(b'z'),b'b':file(b'b')})
  y=make(untracked={b'b':file(b'b'),b'z':file(b'z')})
  self.assertEqual(x['manifest_sha256'],y['manifest_sha256']);self.assertEqual(x['blobs'],y['blobs'])
 def test_staged_and_unstaged_distinct(self):
  x=make(index={b'a':file(b'b')},tracked_worktree={b'a':file(b'c')})['manifest']
  self.assertEqual(paths(x['staged_changes']),[(b'a','MODIFIED')]);self.assertEqual(paths(x['unstaged_changes']),[(b'a','MODIFIED')])
  self.assertEqual([x[k][0]['sha256'] for k in ('head','index','tracked_worktree')],[hashlib.sha256(s).hexdigest() for s in (b'a',b'b',b'c')])
 def test_cancelling_changes_do_not_disappear(self):
  x=make(index={b'a':file(b'b')},tracked_worktree={b'a':file()})['manifest']
  self.assertEqual(paths(x['staged_changes']),[(b'a','MODIFIED')]);self.assertEqual(paths(x['unstaged_changes']),[(b'a','MODIFIED')])
 def test_staged_delete_same_path_untracked(self):
  x=make(index={},tracked_worktree={},untracked={b'a':file(b'new')})['manifest']
  self.assertEqual(paths(x['staged_changes']),[(b'a','DELETED')]);self.assertEqual(x['unstaged_changes'],[]);self.assertEqual(base64.b64decode(x['untracked'][0]['path_b64']),b'a')
 def test_unstaged_delete(self):
  self.assertEqual(paths(make(tracked_worktree={})['manifest']['unstaged_changes']),[(b'a','DELETED')])
 def test_rename_is_delete_plus_add_not_heuristic(self):
  x=make(index={b'b':file()},tracked_worktree={b'b':file()})['manifest']
  self.assertEqual(paths(x['staged_changes']),[(b'a','DELETED'),(b'b','ADDED')])
 def test_file_to_directory_transition(self):
  x=make(index={},tracked_worktree={},untracked={b'a/b':file()})['manifest']
  self.assertEqual(paths(x['staged_changes']),[(b'a','DELETED')]);self.assertEqual(len(x['untracked']),1)
 def test_symlink_is_opaque_and_mode_change_changes_digest(self):
  a=make(untracked={b'l':link(b'../outside')});b=make(untracked={b'l':link(b'../else')})
  self.assertNotEqual(a['manifest_sha256'],b['manifest_sha256']);self.assertIn(b'../outside',a['blobs'].values())
 def test_unknown_mode_is_explicit(self):
  x=make(tracked_worktree={b'a':file(mode=None)})['manifest']
  self.assertEqual(x['unknown_worktree_modes'],['YQ==']);self.assertEqual(paths(x['unstaged_changes']),[(b'a','INDETERMINATE_MODE')]);self.assertIsNone(x['tracked_worktree'][0]['mode'])
 def test_incomplete_projections_do_not_assert_absence(self):
  c={'head':False,'index':False,'worktree':False,'exclusions':False}
  x=make(head={b'old':file()},index={b'new':file()},tracked_worktree={},coverage_claims=c)['manifest']
  self.assertEqual(paths(x['staged_changes']),[(b'new','EXTRA_UNCONFIRMED'),(b'old','MISSING_UNCONFIRMED')])
  self.assertEqual(paths(x['unstaged_changes']),[(b'new','MISSING_UNCONFIRMED')])
 def test_raw_path_bytes_are_not_normalized(self):
  x=make(untracked={b'\xff':file()})['manifest'];self.assertEqual(base64.b64decode(x['untracked'][0]['path_b64']),b'\xff')
 def test_exclusions_affect_manifest_and_are_claims(self):
  x=make(excluded={b'cache': 'generated'});y=make(excluded={b'cache':'other'})
  self.assertNotEqual(x['manifest_sha256'],y['manifest_sha256']);self.assertEqual(x['manifest']['completeness_authority'],'UNVERIFIED')
 def test_exclusion_cannot_hide_tracked_path(self):
  with self.assertRaisesRegex(model.ModelError,'EXCLUSION_OVERLAP'):make(excluded={b'a':'ignored'})
 def test_excluded_ancestor_cannot_hide_deleted_head_or_index(self):
  cases=[dict(head={b'parent/child':file()},index={},tracked_worktree={}),
         dict(head={},index={b'parent/child':file()},tracked_worktree={}),
         dict(head={},index={},tracked_worktree={},untracked={b'parent/child':file()})]
  for case in cases:
   with self.subTest(case=case),self.assertRaisesRegex(model.ModelError,'FILE_DIRECTORY_COLLISION'):
    make(**case,excluded={b'parent':'generated'})
 def test_excluded_descendant_cannot_hide_deleted_head_or_index(self):
  cases=[dict(head={b'parent':file()},index={},tracked_worktree={}),
         dict(head={},index={b'parent':file()},tracked_worktree={}),
         dict(head={},index={},tracked_worktree={},untracked={b'parent':file()})]
  for case in cases:
   with self.subTest(case=case),self.assertRaisesRegex(model.ModelError,'FILE_DIRECTORY_COLLISION'):
    make(**case,excluded={b'parent/child':'generated'})
 def test_cross_projection_file_directory_conversions_with_unrelated_exclusion(self):
  cases=[(b'parent',b'parent/child'),(b'parent/child',b'parent')]
  for head_path,untracked_path in cases:
   with self.subTest(head=head_path):
    x=make(head={head_path:file()},index={},tracked_worktree={},untracked={untracked_path:file()},excluded={b'generated':'cache'})['manifest']
    self.assertEqual(paths(x['staged_changes']),[(head_path,'DELETED')])
    self.assertEqual(base64.b64decode(x['untracked'][0]['path_b64']),untracked_path)
 def test_invalid_paths_rejected(self):
  for p in (b'',b'/a',b'a//b',b'a/../b',b'.git/config',b'x/./a',b'a\0b'):
   with self.subTest(p=p),self.assertRaises(model.ModelError):make(untracked={p:file()})
 def test_prefix_conflicts_rejected(self):
  with self.assertRaisesRegex(model.ModelError,'FILE_DIRECTORY_COLLISION'):make(untracked={b'x':file(),b'x/y':file()})
  # A sibling between ancestor and descendant in byte sort order must not hide it.
  with self.assertRaisesRegex(model.ModelError,'FILE_DIRECTORY_COLLISION'):make(untracked={b'x':file(),b'x-':file(),b'x/y':file()})
 def test_symlink_target_must_be_materializable(self):
  for target in (b'', b'a\0b'):
   with self.subTest(target=target),self.assertRaisesRegex(model.ModelError,'INVALID_SYMLINK_TARGET'):
    make(untracked={b'l':link(target)})
 def test_untracked_cannot_be_indexed(self):
  with self.assertRaisesRegex(model.ModelError,'UNTRACKED_IS_INDEXED'):make(untracked={b'a':file()})
 def test_tracked_worktree_must_be_indexed(self):
  with self.assertRaisesRegex(model.ModelError,'WORKTREE_NOT_INDEXED'):make(tracked_worktree={b'b':file()})
 def test_sha256_git_object_format(self):
  x=make(head_commit='b'*64)['manifest']['head'][0]
  self.assertEqual(x['computed_git_blob_oid'],hashlib.sha256(b'blob 1\0a').hexdigest())
 def test_no_qualification_even_complete_claim(self):
  x=make()['manifest'];self.assertEqual((x['qualification'],x['product_gate_effect'],x['source_authentication']),('NOT_RUN','NONE','UNVERIFIED'))
 def test_invalid_claim_type_and_head_rejected(self):
  with self.assertRaises(model.ModelError):make(coverage_claims={'head':1})
  with self.assertRaises(model.ModelError):make(head_commit='not-a-commit')
 def test_blob_store_deduplicates_same_bytes(self):
  x=make(untracked={b'x':file(),b'y':file()});self.assertEqual(len(x['blobs']),1);self.assertEqual(next(iter(x['blobs'].values())),b'a')

if __name__=='__main__':unittest.main(verbosity=2)
