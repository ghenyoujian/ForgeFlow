#!/usr/bin/env python3
"""Real, finite DSH protocol probe. Private credentials stay outside public evidence."""
import hashlib,json,os,re,signal,subprocess,time,yaml
from pathlib import Path

HERE=Path(__file__).resolve().parent
SOURCE=Path('/home/chenyoujian/.local/share/dsh-wsl/source')
PRIVATE=Path('/home/chenyoujian/.cache/forgeflow-dsh-managed-probe')
HOME=PRIVATE/'home'
REPO=PRIVATE/'repository'
class Loader(yaml.SafeLoader): pass
Loader.yaml_implicit_resolvers={key:[(tag,regexp) for tag,regexp in values if tag!='tag:yaml.org,2002:bool'] for key,values in yaml.SafeLoader.yaml_implicit_resolvers.items()}
Loader.add_implicit_resolver('tag:yaml.org,2002:bool',re.compile(r'^(?:true|false|True|False|TRUE|FALSE)$'),list('tTfF'))
Loader.add_constructor('tag:yaml.org,2002:js',lambda l,n:l.construct_scalar(n))
def digest(path):return hashlib.sha256(path.read_bytes()).hexdigest()
def run(args,**kwargs):return subprocess.run(args,check=True,**kwargs)

def prepare():
    PRIVATE.mkdir(mode=0o700,parents=True,exist_ok=True)
    HOME.mkdir(mode=0o700,exist_ok=True)
    REPO.mkdir(exist_ok=True)
    source_home=Path('/mnt/e/WSL/workspace/DSH/.dsh')
    rows=yaml.load((source_home/'profiles/web/cordis.patch.yml').read_text(),Loader=Loader)
    default=next(row for row in rows if row.get('id')=='agent-default-model')
    providers=next(row for row in rows if row.get('id')=='llm-pi-ai')['config']['providers']
    provider=default['config']['provider']
    selected=providers[provider]
    creds=yaml.safe_load((source_home/'.credentials.yaml').read_text())
    key_ref=selected['apiKeyEnv']
    if not creds.get('refs',{}).get(key_ref): raise RuntimeError('BLOCKED_EXECUTOR_ACCESS: selected credential reference unresolved')
    private_creds={'version':creds['version'],'refs':{key_ref:creds['refs'][key_ref]}}
    credential_path=HOME/'.credentials.yaml'
    credential_path.write_text(yaml.safe_dump(private_creds)); credential_path.chmod(0o600)
    selected['models']=[m for m in selected['models'] if m['id']==default['config']['model']]
    disabled=['session-title-llm','subagent','subagent-spawn-in-process','subagent-fork-in-process','tool-subagent-control','tool-subagent-list-agents','tool-subagent','tool-subagent-fork','workflow-ptc','tool-workflow','tool-goal','goal-round-driver','tool-plugin-manager']
    managed_rows=[default,{'id':'llm-pi-ai','config':{'providers':{provider:selected}}}]+[{'id':id,'disabled':True} for id in disabled]
    (HOME/'cordis.patch.yml').write_text(yaml.safe_dump(managed_rows,sort_keys=False))
    (HOME/'cordis.patch.yml').chmod(0o600)
    if not (REPO/'.git').exists():
        run(['git','init','-q',str(REPO)])
        (REPO/'README.md').write_text('Finite real DSH protocol qualification repository.\n')
        run(['git','-C',str(REPO),'-c','user.name=ForgeFlow Probe','-c','user.email=probe@localhost','add','README.md'])
        run(['git','-C',str(REPO),'-c','user.name=ForgeFlow Probe','-c','user.email=probe@localhost','commit','-qm','initial probe input'])
    pins=[]
    paths=[Path('/usr/bin/node'),SOURCE/'pnpm-lock.yaml',SOURCE/'package.json',SOURCE/'apps/cli/lib/bin.js']
    paths.extend(sorted(SOURCE.glob('apps/cli/lib/**/*.js')))
    paths.extend(sorted(SOURCE.glob('vendor/*/lib/**/*.js')))
    paths.extend(sorted(SOURCE.glob('packages/*/*/lib/**/*.js')))
    paths.extend(sorted(SOURCE.glob('packages/*/*/package.json')))
    for p in paths:
        if p.is_file(): pins.append({'path':str(p),'sha256':digest(p)})
    identity={'package_version':json.loads((SOURCE/'package.json').read_text())['version'],'source_commit':subprocess.check_output(['git','-C',str(SOURCE),'rev-parse','HEAD'],text=True).strip(),'source_is_dirty':bool(subprocess.check_output(['git','-C',str(SOURCE),'status','--porcelain'])),'program':'/usr/bin/node','entrypoint':str(SOURCE/'apps/cli/lib/bin.js'),'artifact_pins':pins,'pin_manifest_sha256':hashlib.sha256(json.dumps(pins,sort_keys=True).encode()).hexdigest(),'model_route':{'provider':provider,'model':default['config']['model'],'protocol':selected['api'],'reasoningEffort':default['config'].get('reasoningEffort')},'config_sha256':digest(HOME/'cordis.patch.yml'),'credential_refs_resolved':[key_ref],'credential_values_disclosed':False,'disabled_entries':disabled,'nested_spawn_control':'UNVERIFIED','model_budget_mode':'direct_observed','managed_home':str(HOME),'workspace_root':str(REPO),'base_sha':subprocess.check_output(['git','-C',str(REPO),'rev-parse','HEAD'],text=True).strip()}
    (HERE/'runtime-identity.json').write_text(json.dumps(identity,indent=2)+'\n')
    return identity

def probe():
    identity=prepare()
    prompt='''Implement a finite Python standard-library file indexer in exactly indexer.py.\nUnicode requirement: 文件索引。\nFunction index_files(root: str) returns a sorted list of dictionaries with path (relative POSIX string), size (bytes), and sha256 for every regular non-symlink file recursively; omit any .git directory and do not follow symlinks. CLI: python3 indexer.py ROOT writes the list as JSON with ensure_ascii=False. Do not write tests, do not commit, do not spawn agents, do not install packages, and do not touch any other path. Finish after this one file is implemented and report the file path.\n'''
    (HERE/'probe-prompt.txt').write_text(prompt)
    env=os.environ.copy(); env['DSH_HOME']=str(HOME)
    args=['/usr/bin/node',str(SOURCE/'apps/cli/lib/bin.js'),'--profile','headless','--json','-']
    start=time.time()
    with (HERE/'probe.stdout.ndjson').open('wb') as out,(HERE/'probe.stderr.log').open('wb') as err:
        process=subprocess.Popen(args,cwd=REPO,env=env,stdin=subprocess.PIPE,stdout=out,stderr=err,start_new_session=True)
        (HERE/'probe-live.json').write_text(json.dumps({'pid':process.pid,'started_at':start,'workspace':str(REPO)}))
        try: process.communicate(prompt.encode(),timeout=240); cancelled=False
        except subprocess.TimeoutExpired:
            os.killpg(process.pid,signal.SIGTERM)
            try:process.wait(timeout=10)
            except subprocess.TimeoutExpired:os.killpg(process.pid,signal.SIGKILL);process.wait()
            cancelled=True
    receipt={'elapsed_seconds':time.time()-start,'exit_code':process.returncode,'timeout_cancelled':cancelled,'stdout_sha256':digest(HERE/'probe.stdout.ndjson'),'stderr_sha256':digest(HERE/'probe.stderr.log'),'prompt_sha256':digest(HERE/'probe-prompt.txt'),'model_budget_mode':'direct_observed','business_completion':'UNVERIFIED','g2_end_to_end':'INCONCLUSIVE','program':identity['program'],'entrypoint':identity['entrypoint'],'workspace_root':str(REPO)}
    (HERE/'probe-receipt.json').write_text(json.dumps(receipt,indent=2)+'\n'); print(json.dumps(receipt))

if __name__=='__main__':probe()
