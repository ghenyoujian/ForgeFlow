"""Local byte-retention/codec fixtures only; no native session or model qualification."""
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('native_history',ROOT/'ops/native-context-history.py')
H=importlib.util.module_from_spec(spec);spec.loader.exec_module(H)


class NativeHistoryTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name)
        self.home=self.root/'executor-homes/project/attempt/managed';self.sessions=self.home/'sessions';self.sessions.mkdir(parents=True)
        journal=self.root/'attempts/attempt';journal.mkdir(parents=True)
        H.C.write_json(journal/'managed-native-config.json',{'home':str(self.home)})
        self.node=Path('/usr/bin/node').resolve()
        self.config={'data_root':str(self.root),'profile':{'program':str(self.node),'artifact_pins':[{'path':str(self.node),'sha256':hashlib.sha256(self.node.read_bytes()).hexdigest()}]}}
        self.text=json.dumps({'type':'session','version':4,'id':'session-a'})+'\n'+json.dumps({'type':'user/message','data':{'content':'Keep context-a memory 独立上下文'}})+'\n'+json.dumps({'type':'assistant/message','data':{'message':{'role':'assistant','content':'Remembered context-a'}}})+'\n'
    def tearDown(self):self.temp.cleanup()
    def collect(self):return H.collect(self.config,'project','attempt',{'session-a'})
    def test_original_messages_retained_and_credentials_excluded(self):
        (self.sessions/'session.v4.jsonl').write_text(self.text)
        (self.home/'.credentials.yaml').write_text('DO_NOT_CAPTURE_CREDENTIALS')
        result=self.collect();self.assertEqual(result[0]['content_utf8'],self.text)
        self.assertNotIn('DO_NOT_CAPTURE',json.dumps(result));self.assertEqual(result[0]['native_session_id'],'session-a')
    def test_actual_pinned_node_zstd_roundtrip(self):
        compressed=subprocess.run([str(self.node),'-e',"const fs=require('node:fs'),z=require('node:zlib');process.stdout.write(z.zstdCompressSync(fs.readFileSync(0)));"],input=self.text.encode(),capture_output=True,check=True).stdout
        (self.sessions/'session.v4.jsonl.zstd').write_bytes(compressed)
        result=self.collect();self.assertEqual(result[0]['content_utf8'],self.text)
        self.assertEqual(result[0]['source_file_sha256'],hashlib.sha256(compressed).hexdigest())
    def test_alias_and_foreign_session_refused(self):
        outside=self.root/'foreign.jsonl';outside.write_text(self.text)
        path=self.sessions/'session.v4.jsonl';path.symlink_to(outside)
        with self.assertRaises(H.C.Blocked):self.collect()
        path.unlink();path.write_text(self.text.replace('session-a','session-b'))
        with self.assertRaises(H.C.Blocked):self.collect()
    def test_decompression_expansion_is_bounded_and_missing_history_not_success(self):
        with self.assertRaises(H.C.Blocked):self.collect()
        header=self.sessions/"header-only.jsonl";header.write_text(json.dumps({"type":"session","id":"session-a","version":4})+"\n")
        with self.assertRaises(H.C.Blocked):self.collect()
        header.unlink()
        compressed=subprocess.run([str(self.node),'-e',"process.stdout.write(require('node:zlib').zstdCompressSync(Buffer.alloc(9*1024*1024,65)));"],capture_output=True,check=True).stdout
        (self.sessions/'session.v4.jsonl.zstd').write_bytes(compressed)
        with self.assertRaises(H.C.Blocked):self.collect()


if __name__=='__main__':unittest.main()
