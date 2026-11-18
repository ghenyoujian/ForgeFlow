// Actual installed DSH SDK tool registration/dispatch + real PostgreSQL/HTTP.
// Agent handles below are fixtures, not model sessions or execution evidence.
import fs from 'node:fs/promises';
import path from 'node:path';
import assert from 'node:assert/strict';
import {randomUUID} from 'node:crypto';
import {pathToFileURL} from 'node:url';
import {spawnSync} from 'node:child_process';
import vm from 'node:vm';
import {createServer} from 'node:http';
const output=path.resolve(process.argv[2]);
const run=JSON.parse(await fs.readFile(path.join(output,'private.json'),'utf8'));
const modules='/mnt/e/WSL/workspace/DSH/node_modules';
const root=path.resolve(path.dirname(new URL(import.meta.url).pathname),'..');
const report={status:'RUNNING',actual_sdk:'0.2.1-rc.5',agent_handles:'synthetic',model_calls:0,checks:[],native_ptc_execution:'NOT_RUN'};
const verify=(name,passed)=>{report.checks.push({name,passed:!!passed});assert.ok(passed,name);};
async function api(user,route,body,method='POST'){
 const response=await fetch(run.base+'/api/v1'+route,{method:body===undefined?'GET':method,headers:{Authorization:`Bearer ${user.token}`,'X-ForgeFlow-Workspace':run.users[0].workspace,'Content-Type':'application/json','Idempotency-Key':randomUUID()},body:body===undefined?undefined:JSON.stringify(body)});
 const result=await response.json();assert.ok(response.ok,`${response.status} ${result.code||route}`);return result.data;
}
const contexts=[];
try{
 const [alice,bob]=run.users;const base=`/projects/${run.project}/agent-network`;
 const invitation=await api(alice,`/workspaces/${alice.workspace}/invitations`,{role:'EDITOR',email:bob.email});
 await api(bob,'/invitations/accept',{token:invitation.invite_token});
 const sdk=async name=>import(pathToFileURL(path.join(modules,'@deepseek-ai',name,'lib/index.js')).href);
 const {Context}=await sdk('cordis');const {default:SystemPrompt}=await sdk('dsh-system-prompt');
 const {default:Tools}=await sdk('dsh-tools');const {default:Agents}=await sdk('dsh-agent');const {createScope}=await sdk('dsh-scope');
 const entries=[];
 for(const [i,user] of [alice,bob].entries()){
  const connector=await api(user,base+'/integrations',{name:`DSH SDK fixture ${i}`});
  const tokenFile=path.join(output,`plugin-${i}.token`);await fs.writeFile(tokenFile,connector.token,{mode:0o600});
  const directory=path.join(output,`installed-plugin-${i}`);
  const install=spawnSync(process.execPath,[path.join(root,'plugins/dsh-forgeflow-network/bin/forgeflow.mjs'),'install','--directory',directory,'--dsh-node-modules',modules,'--url',run.base,'--workspace',alice.workspace,'--project',run.project,'--token-file',tokenFile],{encoding:'utf8',timeout:30000,env:{...process.env,HTTP_PROXY:'',HTTPS_PROXY:'',ALL_PROXY:'',NO_PROXY:'*'}});
  await fs.writeFile(path.join(output,`plugin-install-${i}.log`),install.stdout+install.stderr,{mode:0o600});verify(`installer ${i} uses the official installed SDK`,install.status===0);
  const doctor=spawnSync(process.execPath,[path.join(directory,'bin/forgeflow.mjs'),'doctor','--directory',directory],{encoding:'utf8',timeout:30000,env:{...process.env,HTTP_PROXY:'',HTTPS_PROXY:'',ALL_PROXY:'',NO_PROXY:'*'}});
  await fs.writeFile(path.join(output,`plugin-doctor-${i}.json`),doctor.stdout||doctor.stderr);verify(`doctor ${i} validates package and live scoped connection`,doctor.status===0&&JSON.parse(doctor.stdout).model_calls===0);
  const ctx=new Context();contexts.push(ctx);
  await ctx.plugin(SystemPrompt,{}).await();await ctx.plugin(Tools,{}).await();await ctx.plugin(Agents).await();
  // Mint the fixture through a declared SDK factory scope, as AgentLoop does.
  // Root contexts do not pass injected-service access into an Agent scope.
  const agent={id:randomUUID()};agent.session={id:agent.id};let scope;
  await ctx.plugin({name:'fixture-agent-scope',inject:['agents','tools'],apply(factory){scope=createScope(factory,agent);agent.ctx=scope.ctx;factory.agents.enter(agent,undefined);}}).await();
  const plugin=await import(pathToFileURL(path.join(directory,'index.mjs')).href);
  const config=JSON.parse(await fs.readFile(path.join(directory,'connection.json'),'utf8'));
  const fiber=ctx.plugin(plugin,config);await fiber.await();
  async function tool(name,args={}){
   const value=await agent.ctx.tools.execute({callId:randomUUID(),name,arguments:args,agent,signal:new AbortController().signal});
   assert.equal(value.isError,false,JSON.stringify(value.content));return JSON.parse(value.content[0].text);
  }
  const identity=await tool('forgeflow_identity');verify(`SDK agent ${i} is bound to its account`,identity.account_id===user.account_id&&identity.native_agent_id===agent.id);
  entries.push({ctx,agent,scope,fiber,tool,identity,directory,connector,config});
 }
 const [a,b]=entries;
 const late={id:randomUUID()};late.session={id:late.id};let lateScope,detachLate;
 await b.ctx.plugin({name:'fixture-later-agent',inject:['agents','tools'],apply(factory){lateScope=createScope(factory,late);late.ctx=lateScope.ctx;detachLate=factory.agents.enter(late,undefined);}}).await();
 await b.ctx.agents.announce(late,'startup');
 const lateCall=async(name,args={})=>late.ctx.tools.execute({callId:randomUUID(),name,arguments:args,agent:late,signal:new AbortController().signal});
 const lateResult=await lateCall('forgeflow_identity');verify('plugin installs tools for agents created after activation',!lateResult.isError);
 const lateIdentity=JSON.parse(lateResult.content[0].text);
 const directory=await a.tool('forgeflow_agents');verify('one user discovers the other user agent',directory.agents.some(agent=>agent.agent_id===b.identity.agent_id&&agent.account_id===bob.account_id));
 const message=await a.tool('forgeflow_send',{recipient_agent_id:b.identity.agent_id,client_message_id:'sdk-'+randomUUID(),text:'API 合同交接：请复核联系表单的错误响应。'});
 const inbox=await b.tool('forgeflow_inbox',{after:0});verify('real SDK tool delivers cross-user peer message',inbox.items.some(m=>m.message_id===message.message_id));
 const receipt=await b.tool('forgeflow_ack',{message_id:message.message_id});verify('real SDK tool acknowledges only its recipient identity',!!receipt.received_at&&receipt.recipient_agent_id===b.identity.agent_id);
 const renewed=await api(bob,base+'/integrations/'+b.connector.integration_id+'/sessions',{});
 await fs.writeFile(b.config.tokenFile,renewed.token,{mode:0o600});
 const renewedInbox=await b.tool('forgeflow_inbox',{after:0});verify('renewed file credential retains the existing SDK identity and inbox',renewedInbox.items.some(m=>m.message_id===message.message_id));
 const reply=await b.tool('forgeflow_send',{recipient_agent_id:a.identity.agent_id,client_message_id:'sdk-reply-'+randomUUID(),text:'已收到。先补充 422 与 429 的 UI 状态，不改变执行验收结论。',thread_id:message.thread_id,reply_to:message.message_id});
 const again=await a.tool('forgeflow_inbox',{after:0});verify('reply reaches original user with same thread',again.items.some(m=>m.message_id===reply.message_id&&m.thread_id===message.thread_id));
 const forLate=await a.tool('forgeflow_send',{recipient_agent_id:lateIdentity.agent_id,client_message_id:'sdk-late-'+randomUUID(),text:'仅供另一个独立上下文接收。'});
 await assert.rejects(()=>b.tool('forgeflow_ack',{message_id:forLate.message_id}));verify('one agent cannot acknowledge another agent in the same connector',true);
 const lateAck=await lateCall('forgeflow_ack',{message_id:forLate.message_id});verify('exact late recipient can acknowledge its message',!lateAck.isError);
 detachLate();await lateScope.dispose();
 const spoof=await a.agent.ctx.tools.execute({callId:randomUUID(),name:'forgeflow_send',arguments:{recipient_agent_id:b.identity.agent_id,client_message_id:'spoof-'+randomUUID(),text:'spoof',sender_agent_id:b.identity.agent_id},agent:a.agent,signal:new AbortController().signal});
 verify('model cannot forge a sender through open SDK parameters',spoof.isError || JSON.parse(spoof.content[0].text).sender_agent_id===a.identity.agent_id);
 const stolen=await a.agent.ctx.tools.execute({callId:randomUUID(),name:'forgeflow_identity',arguments:{},agent:b.agent,signal:new AbortController().signal});verify('tool dispatch rejects a caller from another Agent scope',stolen.isError);
 const preview=await a.tool('forgeflow_workflow_preview');let children=0;
 const value=await vm.runInNewContext(`(async()=>{${preview.script}\n})()`,{args:{execute:false},phase:()=>{},log:()=>{},agent:()=>{children++;throw new Error('Unexpected model call');}},{timeout:1000});
 verify('bundled workflow dry run covers all twelve tasks without child calls',value.tasks.length===12&&children===0&&value.agentsStarted===0);
 const workflowFile=path.join(output,'personal-site.request.json');
 const prepared=spawnSync(process.execPath,[path.join(a.directory,'bin/forgeflow.mjs'),'workflow','--directory',a.directory,'--output',workflowFile],{encoding:'utf8',timeout:10000});verify('CLI prepares a native workflow request with no execution',prepared.status===0&&JSON.parse(await fs.readFile(workflowFile,'utf8')).args.execute===false);
 const {ForgeFlowClient,privateToken}=await import(pathToFileURL(path.join(a.directory,'client.mjs')).href);
 const invalid=path.join(output,'unsafe-credential.token');await fs.writeFile(invalid,a.connector.token,{mode:0o644});
 await assert.rejects(()=>new ForgeFlowClient({...a.config,tokenFile:invalid}).agents(),/0600/);verify('unsafe credential permissions fail before network use',true);await fs.rm(invalid);
 const fifo=path.join(output,'credential.fifo');const made=spawnSync('mkfifo',['-m','600',fifo],{encoding:'utf8'});assert.equal(made.status,0);
 const fifoStart=Date.now();await assert.rejects(()=>privateToken(fifo),/regular file/);verify('FIFO credential is rejected without blocking for a writer',Date.now()-fifoStart<1000);await fs.rm(fifo);
 const oversized=path.join(output,'oversized.token');await fs.writeFile(oversized,'a'.repeat(8193),{mode:0o600});await assert.rejects(()=>privateToken(oversized),/0600|8192/);verify('oversized credential files fail before consumption',true);await fs.rm(oversized);
 // Transport-boundary fixture only. No real credential or business result is
 // supplied by this local adversarial HTTP server.
 let streamed=0;
 const boundary=createServer((req,res)=>{
  res.setHeader('Content-Type','application/json');
  const timer=setInterval(()=>{if(res.destroyed){clearInterval(timer);return;}streamed+=131072;res.write(Buffer.alloc(131072,97));if(streamed>8*1024*1024){clearInterval(timer);res.end();}},1);
  res.on('close',()=>clearInterval(timer));
 });
 await new Promise(resolve=>boundary.listen(0,'127.0.0.1',resolve));
 try {
  const bounded=new ForgeFlowClient({url:`http://127.0.0.1:${boundary.address().port}`,workspaceId:'transport-fixture',projectId:'transport-fixture',token:'a'.repeat(64)});
  await assert.rejects(()=>bounded.agents(),/4 MiB/);verify('streamed response is cancelled at the byte limit without buffering the full body',streamed<8*1024*1024);
 } finally {boundary.closeAllConnections();await new Promise(resolve=>boundary.close(resolve));}
 const home=path.join(output,'dsh-doctor-home');const profile=path.join(home,'profiles/headless');await fs.mkdir(profile,{recursive:true,mode:0o700});
 await fs.writeFile(path.join(home,'cordis.patch.yml'),'[]\n');await fs.writeFile(path.join(profile,'cordis.patch.yml'),'[]\n');
 await fs.writeFile(path.join(profile,'package.json'),JSON.stringify({name:'forgeflow-network-doctor',private:true,dependencies:{},dsh:{profile:{bundles:['@deepseek-ai/dsh-base','@deepseek-ai/dsh-headless']}}}));
 await fs.symlink(modules,path.join(profile,'node_modules'),'dir');
 const composition=spawnSync(process.execPath,[path.join(modules,'@deepseek-ai/dsh/lib/bin.js'),'--profile','headless','--patch',path.join(a.directory,'cordis.patch.json'),'--dump-config'],{cwd:output,encoding:'utf8',timeout:60000,env:{PATH:'/usr/bin:/bin',HOME:home,DSH_HOME:home,LANG:'C.UTF-8'}});
 await fs.writeFile(path.join(output,'dsh-composition.yaml'),composition.stdout,{mode:0o600});await fs.writeFile(path.join(output,'dsh-composition.stderr'),composition.stderr,{mode:0o600});
 verify('official DSH CLI accepts the additive companion patch',composition.status===0&&composition.stdout.includes('forgeflow-network'));
 verify('official DSH config dump contains no connector secret',!composition.stdout.includes(a.connector.token));
 // Run the actual official PTC process and workflow lifecycle, with a provider
 // that throws on any attempted child. No LLM service or credential is loaded.
 const native=new Context();contexts.push(native);const nativeRoot=path.join(output,'native-workflow');await fs.mkdir(nativeRoot,{recursive:true});
 const services=[['dsh-system-prompt',{}],['dsh-session',undefined],['dsh-session-projection',undefined],['dsh-fs-local',{cwd:nativeRoot}],['dsh-subprocess-local',undefined],['dsh-sandbox-local',{}],['dsh-sandbox-policy',{mode:'read-only',workspaceRoot:nativeRoot}],['dsh-working-directory',{defaultDirectory:nativeRoot}],['dsh-subagent',{}],['dsh-ptc-runtime-node',{}],['dsh-workflow-ptc',{provider:'deny-model',maxConcurrentAgents:32,maxTotalAgents:128}]];
 for(const[name,config]of services){const module=await sdk(name);await native.plugin(module.default,config).await();}
 let starts=0;native.subagents.registerProvider({name:'deny-model',capabilities:{},inheritsParentContext:false,async start(){starts++;throw new Error('Model execution forbidden in this acceptance');}});
 const session=native.sessions.create(randomUUID(),{meta:{cwd:nativeRoot}});const parent={id:session.id,session,ctx:native};const events=[];
 native.on('workflow/start',info=>events.push({kind:'start',run_id:info.id}));native.on('workflow/end',(info,result)=>events.push({kind:'end',run_id:info.id,...result}));
 const live=native.workflowEngine.start({...JSON.parse(await fs.readFile(workflowFile,'utf8')),parent,signal:AbortSignal.timeout(15000)});
 const nativeResult=await live.result;await live.dispose();
 await fs.writeFile(path.join(output,'native-workflow-report.json'),JSON.stringify({events,result:nativeResult,provider_calls:starts},null,2)+'\n');
 verify('official native PTC engine completes the twelve-task preview with zero children',nativeResult.stopReason==='completed'&&starts===0&&nativeResult.agentsStarted===0&&nativeResult.value.tasks.length===12);
 const canonical=(await (await fetch(run.base+'/api/v1/tutorials/personal-site')).json()).data;
 verify('native workflow and UI tutorial share identical task boundaries',JSON.stringify(nativeResult.value.tasks)===JSON.stringify(canonical.tasks.map(t=>({id:t.id,title:t.title,owner:t.role,dependencies:t.depends_on,write_set:t.write_set}))));
 report.native_ptc_execution={stopReason:nativeResult.stopReason,agentsStarted:nativeResult.agentsStarted,provider_calls:starts};
 const attempts=await api(alice,`/projects/${run.project}/attempts`);verify('communication and dry run create no execution attempts',attempts.length===0);
 for(const entry of entries)await entry.fiber.dispose();
 const removed=await a.agent.ctx.tools.execute({callId:randomUUID(),name:'forgeflow_identity',arguments:{},agent:a.agent,signal:new AbortController().signal});verify('unloading plugin removes scoped tools',removed.isError);
 report.status='PASS';
}catch(error){report.status='FAIL';report.error=error.message;throw error;}
finally{for(const ctx of contexts.reverse())await ctx.fiber.dispose();await fs.writeFile(path.join(output,'dsh-plugin-report.json'),JSON.stringify(report,null,2)+'\n');}
process.stdout.write(JSON.stringify({status:report.status,checks:report.checks.length,model_calls:0})+'\n');
