#!/usr/bin/env python3
"""Deterministic companion package; no npm install, DSH activation or model call."""
import argparse,hashlib,io,json,pathlib,tarfile,gzip
root=pathlib.Path(__file__).resolve().parents[1]
parser=argparse.ArgumentParser();parser.add_argument('--output',type=pathlib.Path,required=True);args=parser.parse_args()
plugin=root/'plugins/dsh-forgeflow-network'
names=['package.json','index.mjs','client.mjs','bin/forgeflow.mjs','templates/personal-site.workflow.js','README.md']
if any((plugin/name).is_symlink() for name in names):raise RuntimeError('Package sources must be regular files')
files={name:(plugin/name).read_bytes() for name in names}
files['plan.json']=(root/'project-packs/personal-website/plan.json').read_bytes()
manifest={name:hashlib.sha256(content).hexdigest() for name,content in files.items()}
files['package-manifest.json']=(json.dumps({'schema_version':'forgeflow.dsh-plugin-package.v1','files':manifest},indent=2)+'\n').encode()
args.output.parent.mkdir(parents=True,exist_ok=True)
with args.output.open('xb') as target:
 with gzip.GzipFile(fileobj=target,mode='wb',filename='',mtime=0) as compressed:
  with tarfile.open(fileobj=compressed,mode='w') as archive:
   for name,content in sorted(files.items()):
    info=tarfile.TarInfo('dsh-forgeflow-network/'+name);info.size=len(content);info.mode=0o755 if name.startswith('bin/') else 0o644;info.mtime=0;archive.addfile(info,io.BytesIO(content))
print(json.dumps({'package':str(args.output),'sha256':hashlib.sha256(args.output.read_bytes()).hexdigest(),'files':len(files),'model_calls':0}))
