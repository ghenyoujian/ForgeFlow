#!/usr/bin/env node
import { readFile, writeFile, mkdir, mkdtemp, rename, symlink, stat, access, rm } from 'node:fs/promises';
import { resolve, dirname, join, basename } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { createHash } from 'node:crypto';
import vm from 'node:vm';

const [command, ...argv] = process.argv.slice(2);
const options = {};
for (let i = 0; i < argv.length; i++) {
  if (!argv[i].startsWith('--')) throw new Error('Use --name value options');
  const name = argv[i].slice(2);
  if (name === 'offline') options[name] = true;
  else {if (!argv[i + 1] || argv[i + 1].startsWith('--')) throw new Error(`Missing --${name} value`); options[name] = argv[++i];}
}
const required = name => {if (!options[name]) throw new Error(`--${name} is required`); return options[name];};
const localRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const packaged = basename(dirname(fileURLToPath(import.meta.url))) === 'bin';
const files = {'package.json':'package.json', 'index.mjs':'index.mjs', 'client.mjs':'client.mjs', 'forgeflow.mjs':'bin/forgeflow.mjs', 'personal-site.workflow.js':'templates/personal-site.workflow.js', 'plan.json':'plan.json', 'README.md':'README.md'};
function baseUrl(value) {
  const url = new URL(value);
  if (url.username || url.password || url.search || url.hash || !['http:', 'https:'].includes(url.protocol)) throw new Error('Invalid service URL');
  if (url.protocol === 'http:' && !['localhost','127.0.0.1','[::1]'].includes(url.hostname)) throw new Error('Remote connections require HTTPS');
  return url.origin;
}
async function source(file, base) {
  if (packaged) {
    try {return await readFile(join(localRoot, files[file]));} catch (error) {if (error.code !== 'ENOENT') throw error;}
  }
  const response = await fetch(`${base}/api/v1/plugins/dsh-forgeflow-network/${file}`, {redirect:'error', signal:AbortSignal.timeout(10000)});
  if (!response.ok) throw new Error(`Cannot download ${file}: ${response.status}`);
  const bytes = Buffer.from(await response.arrayBuffer());
  if (bytes.length > 1024 * 1024) throw new Error('Plugin source exceeds limit');
  return bytes;
}
try {
  if (command === 'install') {
    const destination = resolve(required('directory'));
    const modules = resolve(required('dsh-node-modules'));
    const base = baseUrl(required('url'));
    const projectId = required('project'); const workspaceId = required('workspace');
    if (!/^[-a-zA-Z0-9_]{1,128}$/.test(projectId) || !/^[-a-zA-Z0-9_]{1,128}$/.test(workspaceId)) throw new Error('Invalid project/workspace id');
    const sdk = JSON.parse(await readFile(join(modules,'@deepseek-ai/dsh/package.json'),'utf8'));
    if (sdk.version !== '0.2.1-rc.5') throw new Error(`DSH ${sdk.version} has not been validated. This package supports 0.2.1-rc.5.`);
    try {await access(destination); throw new Error('Installation directory already exists; choose a new directory for a reversible install');} catch (error) {if (error.code !== 'ENOENT') throw error;}
    const payload = await Promise.all(Object.keys(files).map(async file => [file, await source(file, base)]));
    const manifest = Object.fromEntries(payload.map(([file, bytes]) => [files[file], createHash('sha256').update(bytes).digest('hex')]));
    await mkdir(dirname(destination), {recursive:true});
    const staging = await mkdtemp(join(dirname(destination),'.forgeflow-install-'));
    try {
      for (const [file, bytes] of payload) {const path=join(staging,files[file]);await mkdir(dirname(path),{recursive:true});await writeFile(path,bytes,{mode:0o600});}
      await symlink(modules,join(staging,'node_modules'),'dir');
      const config={url:base,projectId,workspaceId,...(options['token-file']?{tokenFile:resolve(options['token-file'])}:{})};
      await writeFile(join(staging,'connection.json'),JSON.stringify(config,null,2)+'\n',{mode:0o600});
      const patch=[{insert:[{id:'forgeflow-network',name:pathToFileURL(join(destination,'index.mjs')).href,config}]}];
      await writeFile(join(staging,'cordis.patch.json'),JSON.stringify(patch,null,2)+'\n',{mode:0o600});
      await writeFile(join(staging,'manifest.json'),JSON.stringify({package:'dsh-forgeflow-network',version:'0.1.0',dsh:sdk.version,files:manifest},null,2)+'\n',{mode:0o600});
      await rename(staging,destination);
    } catch (error) {await rm(staging,{recursive:true,force:true});throw error;}
    process.stdout.write(JSON.stringify({installed:destination,patch:join(destination,'cordis.patch.json'),activation:'Add --patch to your existing DSH startup. No DSH home or service was modified.',next:`node ${join(destination,'bin/forgeflow.mjs')} doctor --directory ${destination}`},null,2)+'\n');
  } else if (command === 'doctor') {
    const directory=resolve(options.directory||localRoot);
    const manifest=JSON.parse(await readFile(join(directory,'manifest.json'),'utf8'));
    for (const [file,digest] of Object.entries(manifest.files)) {
      if (!Object.values(files).includes(file)) throw new Error('Unexpected manifest file');
      const actual=createHash('sha256').update(await readFile(join(directory,file))).digest('hex');
      if (actual!==digest) throw new Error(`Installed source changed: ${file}`);
    }
    const plugin=await import(pathToFileURL(join(directory,'index.mjs')).href);
    const preview=await plugin.workflowPreview();
    new vm.Script(`(async () => {${preview.script}\n})`,{filename:'personal-site.workflow.js'});
    let directoryResult;
    if (!options.offline) {
      const config=JSON.parse(await readFile(join(directory,'connection.json'),'utf8'));
      const {ForgeFlowClient}=await import(pathToFileURL(join(directory,'client.mjs')).href);
      const agents=await new ForgeFlowClient(config).agents();directoryResult={reachable:true,registered_agents:agents.length};
    }
    process.stdout.write(JSON.stringify({status:'PASS',dsh:manifest.dsh,plugin:plugin.name,tools:6,workflow_sha256:preview.sha256,network:directoryResult||'NOT_CHECKED',model_calls:0},null,2)+'\n');
  } else if (command === 'workflow') {
    const directory=resolve(options.directory||localRoot);
    const plugin=await import(pathToFileURL(join(directory,'index.mjs')).href);
    const request=await plugin.workflowPreview();
    const target=resolve(required('output'));
    await writeFile(target,JSON.stringify({meta:request.meta,script:request.script,args:request.args},null,2)+'\n',{mode:0o600,flag:'wx'});
    process.stdout.write(JSON.stringify({prepared:target,workflow_sha256:request.sha256,execution:'NOT_STARTED',use:'Pass this JSON to the native DSH workflow tool. The default is a zero-agent preview.'},null,2)+'\n');
  } else {
    process.stdout.write('ForgeFlow DSH companion\ninstall --directory DIR --dsh-node-modules DIR --url URL --project ID --workspace ID [--token-file FILE]\ndoctor --directory DIR [--offline]\nworkflow --directory DIR --output FILE\n');
    if(command && !['help','--help'].includes(command)) process.exitCode=2;
  }
} catch (error) {
  // Never dump request headers, config, credentials or stack-local values.
  process.stderr.write(`ForgeFlow: ${error.message}\n`);process.exitCode=1;
}
