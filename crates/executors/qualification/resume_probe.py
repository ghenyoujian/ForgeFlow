#!/usr/bin/env python3
"""Resume the actual native Session without re-authoring; record lifecycle truth."""
import hashlib,json,os,signal,subprocess,time
from pathlib import Path
HERE=Path(__file__).resolve().parent
HOME=Path('/home/chenyoujian/.cache/forgeflow-dsh-managed-probe/home')
REPO=HOME.parent/'repository'
ENTRY='/home/chenyoujian/.local/share/dsh-wsl/source/apps/cli/lib/bin.js'
def digest(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
    rows=[json.loads(l) for l in (HERE/'probe.stdout.ndjson').read_text().splitlines()]
    session=next(v['sessionId'] for v in rows if v['type']=='session')
    env=os.environ.copy();env['DSH_HOME']=str(HOME)
    args=['/usr/bin/node',ENTRY,'--profile','headless','--json','--session-id',session,'-']
    wrong=subprocess.run(args,cwd=HOME.parent,env=env,input=b'Only report current file path; no tools.\n',capture_output=True,timeout=30)
    (HERE/'wrong-cwd.stdout.ndjson').write_bytes(wrong.stdout);(HERE/'wrong-cwd.stderr.log').write_bytes(wrong.stderr)
    (HERE/'wrong-cwd-receipt.json').write_text(json.dumps({'exit_code':wrong.returncode,'status':'PASS' if wrong.returncode!=0 else 'FAIL','session_id':session,'stdout_sha256':digest(HERE/'wrong-cwd.stdout.ndjson')},indent=2)+'\n')
    prompt='The already implemented indexer.py has been independently verified. Do not call any tools or make further edits. Respond with exactly one short sentence identifying indexer.py and finish this turn immediately.\n'
    (HERE/'resume-prompt.txt').write_text(prompt)
    started=time.time()
    with (HERE/'resume.stdout.ndjson').open('wb') as out,(HERE/'resume.stderr.log').open('wb') as err:
        p=subprocess.Popen(args,cwd=REPO,env=env,stdin=subprocess.PIPE,stdout=out,stderr=err,start_new_session=True)
        (HERE/'resume-live.json').write_text(json.dumps({'pid':p.pid,'session_id':session,'started_at':started}))
        cancelled=False
        try:p.communicate(prompt.encode(),timeout=360)
        except subprocess.TimeoutExpired:
            cancelled=True;os.killpg(p.pid,signal.SIGTERM)
            try:p.wait(timeout=10)
            except subprocess.TimeoutExpired:os.killpg(p.pid,signal.SIGKILL);p.wait()
    rows=[json.loads(l) for l in (HERE/'resume.stdout.ndjson').read_text().splitlines()]
    reasons=[v.get('reason',{}).get('kind') for v in rows if v.get('phase')=='turn_end']
    successful=p.returncode==0 and not cancelled and reasons==['completed'] and sum(v['type']=='final' for v in rows)==1
    receipt={'exit_code':p.returncode,'timeout_cancelled':cancelled,'elapsed_seconds':time.time()-started,'native_session_id':session,'turn_end_reasons':reasons,'status':'PASS' if successful else 'FAIL','verified_capability':'session_resume' if successful else None,'stdout_sha256':digest(HERE/'resume.stdout.ndjson'),'stderr_sha256':digest(HERE/'resume.stderr.log'),'candidate_sha256':digest(REPO/'indexer.py'),'g2_end_to_end':'INCONCLUSIVE'}
    (HERE/'resume-receipt.json').write_text(json.dumps(receipt,indent=2)+'\n');print(json.dumps(receipt))
if __name__=='__main__':main()
