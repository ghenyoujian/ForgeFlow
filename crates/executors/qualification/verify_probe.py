#!/usr/bin/env python3
"""Independent consumer of actual DSH author output; does not trust author assertions."""
import hashlib,importlib.util,json,subprocess,tempfile,sys
from pathlib import Path
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent
REPO=Path('/home/chenyoujian/.cache/forgeflow-dsh-managed-probe/repository')
def main():
    execution=json.loads((HERE/'probe-receipt.json').read_text())
    if execution['exit_code']!=0:raise RuntimeError('author process did not complete successfully')
    changes=subprocess.check_output(['git','-C',str(REPO),'status','--porcelain','--untracked-files=all'],text=True).splitlines()
    assert changes==['?? indexer.py'],changes
    artifact=REPO/'indexer.py'
    spec=importlib.util.spec_from_file_location('real_author_indexer',artifact)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    checks=[]
    with tempfile.TemporaryDirectory(prefix='forgeflow-independent-consumer-') as root:
        folder=Path(root); (folder/'nested').mkdir(); (folder/'.git').mkdir();(folder/'nested/.git').mkdir()
        records={'文件.txt':'Unicode 中文\n'.encode(),'nested/binary.bin':b'\x00\xff\x80','a.txt':b'a','empty':b''}
        for name,data in records.items():(folder/name).write_bytes(data)
        (folder/'.git/secret').write_bytes(b'excluded');(folder/'nested/.git/secret').write_bytes(b'excluded')
        (folder/'symlink-file').symlink_to(folder/'a.txt');(folder/'symlink-directory').symlink_to(folder/'nested',target_is_directory=True)
        expected=[{'path':name,'size':len(data),'sha256':hashlib.sha256(data).hexdigest()} for name,data in sorted(records.items())]
        result=module.index_files(str(folder));assert result==expected,(result,expected);checks.append('recursive_regular_files_unicode_binary_empty_sorted_sha256')
        cli=subprocess.run(['python3','-B',str(artifact),str(folder)],capture_output=True,check=True)
        assert json.loads(cli.stdout)==expected;assert '文件'.encode() in cli.stdout;checks.append('real_cli_consumer_json_utf8')
        checks.extend(['symlink_file_excluded','symlink_directory_not_followed','all_git_directories_excluded'])
    # Import reads a real artifact; cache emission is redirected by -B command invocation.
    receipt={'status':'PASS','independent_authority':'verify_probe.py','checks':checks,'candidate_path':str(artifact),'candidate_sha256':hashlib.sha256(artifact.read_bytes()).hexdigest(),'write_set':['indexer.py'],'diff_audit':changes,'integrated':False,'g2_end_to_end':'INCONCLUSIVE'}
    (HERE/'independent-consumer-receipt.json').write_text(json.dumps(receipt,indent=2)+'\n');print(json.dumps(receipt))
if __name__=='__main__':main()
