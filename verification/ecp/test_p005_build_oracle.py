from __future__ import annotations
import hashlib,importlib.util,json,os,subprocess,tempfile,unittest
from pathlib import Path
spec=importlib.util.spec_from_file_location('p005_build_oracle',Path(__file__).with_name('p005_build_oracle.py'))
o=importlib.util.module_from_spec(spec);spec.loader.exec_module(o)

def digest(value):return hashlib.sha256(value).hexdigest()

class BuildOracleTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.root=Path(self.tmp.name)
        self.evidence=self.root/'evidence';self.evidence.mkdir()
        self.target=self.root/'target';self.run=self.target/'ecp-p005'/'run';(self.run/'target/debug').mkdir(parents=True)
        (self.run/'dist').mkdir();(self.run/'dist/index.html').write_bytes(b'fixture html')
        self.sha='a'*40;self.manifest='b'*64;self.inventory='c'*64
        self.tools={x:{'selected_path':'fixture-'+x} for x in ('cargo','rustc','node','npm')}
        self.quota={'status':'PASS','project_id':42,'hard_limit_bytes':1024}
        self.artifacts={}
        for name in ('forgeflow-server','forgeflow-worker','forgeflow-sandbox-guard','forgeflow'):
            data=('synthetic '+name).encode();(self.run/'target/debug'/name).write_bytes(data);self.artifacts[name]=digest(data)
        self.artifacts['frontend']={'index.html':digest(b'fixture html')}
        self.write('source-review.json',{'status':'OBSERVED_NOT_GATE','product_gate_effect':'NONE','source_sha':self.sha,
                                       'source_manifest_sha256':self.manifest,'candidate_inventory_sha256':self.inventory})
        self.workload={'source_sha':self.sha,'source_manifest_sha256':self.manifest,'candidate_inventory_sha256':self.inventory,
                       'run_dir':str(self.run),'artifacts':self.artifacts,'tool_identity':self.tools,'quota':self.quota}
        self.write('workload.json',self.workload)
        self.phases={}
        for name in o.PHASES:
            stdout=(b'running 2 tests\ntest result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s\n'
                    if name=='cargo_test' else ('synthetic '+name).encode())
            stderr=b'';(self.evidence/(name+'.stdout')).write_bytes(stdout);(self.evidence/(name+'.stderr')).write_bytes(stderr)
            p={'name':name,'command':o.COMMANDS[name],'source_sha':self.sha,'candidate_inventory_sha256':self.inventory,
               'exit_code':0,'logs_complete':True,'stdout_sha256':digest(stdout),'stderr_sha256':digest(stderr),
               'source_after':{'candidate_inventory_sha256':self.inventory},'tool_identity':self.tools,'quota_after':self.quota}
            self.phases[name]=p;self.write(name+'.json',p)
    def write(self,name,value): (self.evidence/name).write_text(json.dumps(value))
    def review(self):return o.review(self.evidence,self.sha,self.manifest,self.target)
    def reject(self):
        with self.assertRaises((o.Invalid,OSError,ValueError)):self.review()

    def test_fabricated_all_green_cannot_issue_gate(self):
        r=self.review();self.assertEqual(r['status'],'INCONCLUSIVE');self.assertEqual(r['product_gate_effect'],'NONE')

    def test_missing_stage_bad_command_and_source_are_rejected(self):
        p=self.evidence/'npm_ci.json';data=p.read_bytes();p.unlink();self.reject();p.write_bytes(data)
        self.phases['npm_ci']['command']=['true'];self.write('npm_ci.json',self.phases['npm_ci']);self.reject()
        self.phases['npm_ci']['command']=o.COMMANDS['npm_ci'];self.phases['npm_ci']['source_sha']='0'*40
        self.write('npm_ci.json',self.phases['npm_ci']);self.reject()

    def test_logs_tamper_and_skipped_or_zero_tests_are_rejected(self):
        path=self.evidence/'cargo_test.stdout';original=path.read_bytes();path.write_bytes(b'corrupt');self.reject()
        for value in (b'running 0 tests\ntest result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.0s\n',
                      b'running 2 tests\ntest result: ok. 1 passed; 0 failed; 1 ignored; 0 measured; 0 filtered out; finished in 0.0s\n'):
            path.write_bytes(value);self.phases['cargo_test']['stdout_sha256']=digest(value);self.write('cargo_test.json',self.phases['cargo_test']);self.reject()
        path.write_bytes(original)

    def test_tool_source_and_quota_drift_rejected(self):
        for field,value in [('tool_identity',{}),('source_after',{'candidate_inventory_sha256':'d'*64}),
                            ('quota_after',{'project_id':43,'hard_limit_bytes':1024})]:
            p=self.phases['cargo_build'];old=p[field];p[field]=value;self.write('cargo_build.json',p);self.reject();p[field]=old

    def test_artifact_tamper_symlink_and_root_escape_rejected(self):
        f=self.run/'target/debug/forgeflow';original=f.read_bytes();f.write_text('changed');self.reject();f.write_bytes(original)
        f.unlink();f.symlink_to('/etc/passwd');self.reject();f.unlink();f.write_bytes(original)
        self.workload['run_dir']=str(self.root);self.write('workload.json',self.workload);self.reject()

    def test_duplicate_json_and_evidence_symlink_rejected(self):
        p=self.evidence/'npm_ci.json';p.write_text('{"x":1,"x":2}');self.reject()
        p.unlink();p.symlink_to('/etc/passwd');self.reject()

if __name__=='__main__':unittest.main()
