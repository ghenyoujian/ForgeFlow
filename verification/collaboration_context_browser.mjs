// Real browser and PostgreSQL/HTTP. Fault injection delays real responses;
// no fabricated business result and no model execution.
import fs from 'node:fs/promises';
import path from 'node:path';
import assert from 'node:assert/strict';
import {randomUUID,createHash} from 'node:crypto';
import {createRequire} from 'node:module';
const require=createRequire(import.meta.url);
const {chromium}=require('/home/chenyoujian/miniconda/lib/python3.13/site-packages/playwright/driver/package');
const output=path.resolve(process.argv[2]);
const before=process.argv.includes('--observe-before');
const tag=before?'context-before':'context-final';
const run=JSON.parse(await fs.readFile(path.join(output,'private.json'),'utf8'));
const report={status:'RUNNING',synthetic_accounts:true,model_calls:0,checks:[],page_errors:[],observations:[]};
const sha=bytes=>createHash('sha256').update(bytes).digest('hex');
report.runner_sha256=sha(await fs.readFile(new URL(import.meta.url)));
report.binary_sha256=sha(await fs.readFile(run.server));
report.frontend_sha256={'index.html':sha(await fs.readFile(path.join(output,'candidate-console/index.html')))};
for(const name of await fs.readdir(path.join(output,'candidate-console/assets')))report.frontend_sha256['assets/'+name]=sha(await fs.readFile(path.join(output,'candidate-console/assets',name)));
await fs.copyFile(new URL(import.meta.url),path.join(output,tag+'-runner.mjs'));
const verify=(name,passed)=>{report.checks.push({name,passed:!!passed});if(!passed&&!before)assert.ok(passed,name);};
async function api(user,workspace,route,body,method='POST') {
 const res=await fetch(run.base+'/api/v1'+route,{method:body===undefined?'GET':method,
  headers:{Accept:'application/json','Content-Type':'application/json',...(user?{Authorization:`Bearer ${user.token}`} : {}),...(workspace?{'X-ForgeFlow-Workspace':workspace}:{}),'Idempotency-Key':randomUUID()},body:body===undefined?undefined:JSON.stringify(body)});
 const value=await res.json();assert.ok(res.ok,`${res.status} ${value.code||route}`);return value.data;
}
const account=async name=>{
 const email=`${name.toLowerCase().replace(/[^a-z0-9]/g,'')}-${randomUUID()}@example.test`,password=`fixture-${randomUUID()}`;
 const value=await api(null,null,'/registrations',{email,password,display_name:name});
 return {token:value.token,password,email,id:value.account.account_id,workspace:value.account.workspace_id};
};
async function project(user,workspace,name) {
 const id=randomUUID();await api(user,workspace,'/projects',{project_id:id,name,root_path:'',authority_mode:'MANAGED',data_origin:'NATIVE',goal:'Context-boundary fixture',technology_stack:['React'],timezone:'Asia/Shanghai',paused:true,archived:false,revision:0});
 await api(user,workspace,`/projects/${id}/tutorial/personal-site`,{});
 const connector=await api(user,workspace,`/projects/${id}/agent-network/integrations`,{name:'Context connector'});
 const agent=await api(connector,workspace,`/projects/${id}/agent-network/agents`,{native_agent_id:'context-'+randomUUID(),name:'Context UI Agent'});
 return {id,name,agent};
}
const browser=await chromium.launch({executablePath:'/home/chenyoujian/.cache/ms-playwright/chromium-1247/chrome-linux64/chrome',headless:true,args:['--no-proxy-server']});
const contexts=[];
async function pageFor(user,workspace=user.workspace,mobile=false) {
 const context=await browser.newContext({viewport:mobile?{width:390,height:844}:{width:1440,height:1000},reducedMotion:'reduce',timezoneId:'Asia/Shanghai'});contexts.push(context);
 await context.addInitScript(config=>{
  if(sessionStorage.getItem('context-fixture-initialized'))return;
  sessionStorage.setItem('forgeflow.owner-token',config.token);sessionStorage.setItem('forgeflow.personal-account','1');
  sessionStorage.setItem('forgeflow.workspace',config.workspace);sessionStorage.setItem('forgeflow.workspace-role','OWNER');
  sessionStorage.setItem('forgeflow.auth-scope',config.scope);
  sessionStorage.setItem('context-fixture-initialized','1');
 },{token:user.token,workspace,scope:randomUUID()});
 // Only seed the first navigation. Subsequent reloads use the app's actual
 // rotated context, rather than overwriting it with fixture initial state.
 const page=await context.newPage();page.on('pageerror',e=>report.page_errors.push(e.message));
 await page.goto(run.base+'/workspaces');await page.getByRole('heading',{name:'工作区与成员',exact:true}).waitFor();
 return page;
}
let page;
try {
 const alice=await account('Context Alice'),bob=await account('Context Bob'),eve=await account('Context Eve');
 const second=await api(alice,null,'/workspaces',{name:'Context workspace B'});
 const a=await project(alice,alice.workspace,'Context project A');
 const a2=await project(alice,alice.workspace,'Context project A2');
 const b=await project(alice,second.workspace_id,'Context project B');
 const fixtures={alice,bob,eve,second,a,a2,b};await fs.writeFile(path.join(output,tag+'-private.json'),JSON.stringify(fixtures,null,2)+'\n',{mode:0o600});
 page=await pageFor(alice);
 const selectWorkspace=async id=>{
  await page.getByLabel('切换协作工作区').selectOption(id);
  await page.waitForFunction(id=>sessionStorage.getItem('forgeflow.workspace')===id,id);
  await page.waitForURL(url=>url.pathname==='/portfolio');
  await page.getByLabel('切换协作工作区').waitFor();
 };
 await page.goto(run.base+`/projects/${a.id}/flows/1?workbench=1`);
 await page.getByRole('button',{name:'重命名任务 brief',exact:true}).click();
 await page.getByRole('textbox',{name:'编辑标题 brief',exact:true}).fill('跨工作区保留的规划输入');await page.keyboard.press('Enter');
 await page.goto(run.base+`/projects/${a.id}/agent-network`);
 await page.getByLabel('发给',{exact:true}).selectOption(a.agent.agent_id);await page.getByLabel('消息',{exact:true}).fill('跨工作区保留的协作草稿');
 await selectWorkspace(second.workspace_id);await selectWorkspace(alice.workspace);
 await page.goto(run.base+`/projects/${a.id}/flows/1?workbench=1`);await page.getByRole('button',{name:'重命名任务 brief',exact:true}).waitFor();
 verify('unsaved planning edits survive a workspace round trip',await page.locator('.virtual-task-row[data-task-id="brief"] strong').innerText()==='跨工作区保留的规划输入');
 await page.goto(run.base+`/projects/${a.id}/agent-network`);await page.getByLabel('消息',{exact:true}).waitFor();
 await page.getByRole('option',{name:/Context UI Agent/}).waitFor({state:'attached'});
 verify('message content and recipient survive a workspace round trip',await page.getByLabel('消息',{exact:true}).inputValue()==='跨工作区保留的协作草稿'&&await page.getByLabel('发给',{exact:true}).inputValue()===a.agent.agent_id);
 await page.goto(run.base+`/projects/${a2.id}/agent-network`);await page.getByLabel('消息',{exact:true}).waitFor();
 verify('another project never inherits the first project message draft',await page.getByLabel('消息',{exact:true}).inputValue()==='');
 await page.goto(run.base+'/tutorial');await page.getByLabel('我已阅读并核对这一章').check();
 await page.getByRole('button',{name:'下一章',exact:true}).click();
 const chapterTitle=await page.locator('.lesson-content h2').innerText();
 verify('chapter navigation transfers keyboard focus to its heading',await page.locator('.lesson-content h2').evaluate(el=>document.activeElement===el));
 await selectWorkspace(second.workspace_id);await page.goto(run.base+'/tutorial');await page.getByLabel('我已阅读并核对这一章').waitFor();
 verify('tutorial retains the selected chapter across workspaces',await page.locator('.lesson-content h2').innerText()===chapterTitle);
 verify('tutorial reading confirmation follows the user across workspaces',/已手动确认 1 \/\s*\d+ 章/.test(await page.locator('.tutorial-progress small').innerText()));
 await selectWorkspace(alice.workspace);await page.goto(run.base+'/workspaces');await page.getByLabel('显示名称',{exact:true}).fill('点击当前工作区仍保留的资料输入');
 await page.locator('.workspace-list>button[aria-pressed="true"]').click();
 verify('selecting the current workspace keeps unsaved profile input',await page.getByLabel('显示名称',{exact:true}).inputValue()==='点击当前工作区仍保留的资料输入');
 // Delay an actual project-create response, then switch workspaces. The
 // following tutorial import must not be sent with the new workspace header.
 await page.goto(run.base+'/tutorial');
 const initialProjects=await api(alice,alice.workspace,'/projects');
 let release,saved;
 const gate=new Promise(resolve=>{release=resolve;}),accepted=new Promise(resolve=>{saved=resolve;});
 const createRoute='**/api/v1/projects';
 const hold=async route=>{
  if(route.request().method()!=='POST')return route.continue();
  const upstream=await route.fetch();assert.equal(upstream.status(),200);saved(route.request().postDataJSON().project_id);await gate;await route.fulfill({response:upstream});
 };
 await page.route(createRoute,hold);
 const followups=[];const observe=req=>{if(req.method()==='POST'&&req.url().endsWith('/tutorial/personal-site'))followups.push(req.headers()['x-forgeflow-workspace']);};page.on('request',observe);
 await page.getByRole('button',{name:'创建案例项目',exact:true}).click();const partialId=await accepted;
 await selectWorkspace(second.workspace_id);release();
 // Wait for the held real response to reach the previous page instance.
 await page.waitForResponse(res=>res.request().method()==='POST'&&res.url().endsWith('/api/v1/projects'));
 await page.waitForTimeout(300);
 await page.unroute(createRoute,hold);
 await page.goto(run.base+'/tutorial');await page.getByRole('heading',{name:'个人网站 · 从想法到协作交付',exact:true}).waitFor();
 page.off('request',observe);
 verify('late response never continues tutorial writes under the next workspace',followups.length===0);
 await selectWorkspace(alice.workspace);await page.goto(run.base+'/tutorial');
 const resume=page.getByRole('button',{name:before?'创建案例项目':'继续创建案例',exact:true});await resume.click();
 await page.getByRole('button',{name:'案例草案已创建',exact:true}).waitFor();
 const afterProjects=await api(alice,alice.workspace,'/projects');
 const installed=await api(alice,alice.workspace,`/projects/${partialId}/tasks`);
 verify('partial tutorial resumes the same project without creating duplicates',afterProjects.length===initialProjects.length+1&&installed.length===12);
 await page.goto(run.base+'/workspaces');await page.goto(run.base+'/tutorial');
 await page.getByRole('heading',{name:'个人网站 · 从想法到协作交付',exact:true}).waitFor();
 verify('returning to the tutorial keeps the confirmed case and planning entry',await page.getByRole('button',{name:'案例草案已创建',exact:true}).isVisible()&&await page.getByRole('button',{name:'打开规划草案',exact:true}).isVisible());
 if(!before) {
  // A missing cached role must not enable edits before /me verifies membership.
  let releaseIdentity,identityAccepted;
  const identityGate=new Promise(resolve=>{releaseIdentity=resolve;}),identityReady=new Promise(resolve=>{identityAccepted=resolve;});
  const identityRoute='**/api/v1/me';
  const holdIdentity=async route=>{const upstream=await route.fetch();identityAccepted();await identityGate;await route.fulfill({response:upstream});};
  await page.route(identityRoute,holdIdentity);await page.evaluate(()=>sessionStorage.removeItem('forgeflow.workspace-role'));
  await page.goto(run.base+`/projects/${a.id}/agent-network`);await identityReady;await page.getByLabel('消息',{exact:true}).waitFor();
  verify('unknown membership role stays read only until verified',await page.getByLabel('消息',{exact:true}).isDisabled());releaseIdentity();
  await page.waitForFunction(()=>sessionStorage.getItem('forgeflow.workspace-role')==='OWNER');await page.unroute(identityRoute,holdIdentity);
  verify('verified role restores editing without dropping the draft',await page.getByLabel('消息',{exact:true}).isEnabled()&&await page.getByLabel('消息',{exact:true}).inputValue()==='跨工作区保留的协作草稿');
  // Password changes are account-scoped. A workspace switch must not discard
  // the valid replacement credential. Hold real reads until it is applied so
  // rejected old-token reads exercise the stale-response guard as well.
  await page.goto(run.base+'/workspaces');await page.getByLabel('当前密码',{exact:true}).fill(alice.password);
  const changedPassword='context-changed-'+randomUUID();await page.getByLabel('新密码',{exact:true}).fill(changedPassword);
  let releasePassword,passwordAccepted,releaseReads;
  const passwordGate=new Promise(resolve=>{releasePassword=resolve;}),passwordReady=new Promise(resolve=>{passwordAccepted=resolve;}),readsGate=new Promise(resolve=>{releaseReads=resolve;});
  const passwordRoute='**/api/v1/account/password';
  const holdPassword=async route=>{const upstream=await route.fetch();assert.equal(upstream.status(),200);passwordAccepted();await passwordGate;await route.fulfill({response:upstream});};
  const holdReads=async route=>{if(route.request().method()!=='GET')return route.fallback();await readsGate;await route.continue().catch(()=>{});};
  await page.route(passwordRoute,holdPassword);await page.route('**/api/v1/**',holdReads);
  await page.getByRole('button',{name:'更新密码',exact:true}).click();await passwordReady;
  await page.getByLabel('切换协作工作区').selectOption(second.workspace_id);await page.waitForFunction(id=>sessionStorage.getItem('forgeflow.workspace')===id,second.workspace_id);
  releasePassword();await page.waitForFunction(token=>sessionStorage.getItem('forgeflow.owner-token')!==token,alice.token);
  alice.token=await page.evaluate(()=>sessionStorage.getItem('forgeflow.owner-token'));alice.password=changedPassword;
  releaseReads();await page.unroute('**/api/v1/**',holdReads);await page.unroute(passwordRoute,holdPassword);
  await page.getByLabel('切换协作工作区').waitFor();
  const signed=await api(alice,null,'/me');verify('workspace switch during password confirmation retains the new account credential',signed.account.account_id===alice.id&&await page.getByLabel('切换协作工作区').inputValue()===second.workspace_id);
  await selectWorkspace(alice.workspace);await page.goto(run.base+`/projects/${a.id}/agent-network`);await page.getByLabel('消息',{exact:true}).waitFor();
  verify('password renewal and workspace switching preserve the same private draft',await page.getByLabel('消息',{exact:true}).inputValue()==='跨工作区保留的协作草稿');
  // The second account can read the exact same project, which makes this a
  // privacy test rather than a test of inaccessible project routing.
  const invite=await api(alice,null,`/workspaces/${alice.workspace}/invitations`,{role:'EDITOR',email:bob.email});await api(bob,null,'/invitations/accept',{token:invite.invite_token});
  await page.goto(run.base+'/workspaces');await page.getByRole('button',{name:'退出账号',exact:true}).click();
  await page.getByLabel('邮箱',{exact:true}).fill(bob.email);await page.getByLabel('密码',{exact:true}).fill(bob.password);await page.getByRole('button',{name:'进入工作区',exact:true}).click();
  await page.getByLabel('切换协作工作区').waitFor();await selectWorkspace(alice.workspace);
  await page.goto(run.base+`/projects/${a.id}/flows/1?workbench=1`);await page.getByRole('button',{name:'重命名任务 brief',exact:true}).waitFor();
  verify('another authorized account cannot inherit a private planning draft',await page.locator('.virtual-task-row[data-task-id="brief"] strong').innerText()!=='跨工作区保留的规划输入');
  await page.goto(run.base+`/projects/${a.id}/agent-network`);await page.getByLabel('消息',{exact:true}).waitFor();
  verify('another authorized account cannot inherit a private message draft',await page.getByLabel('消息',{exact:true}).inputValue()==='');
  await page.goto(run.base+'/tutorial');await page.getByRole('button',{name:'创建案例项目',exact:true}).waitFor();
  verify('confirmed tutorial cases and reading progress stay with their account',await page.getByRole('button',{name:'创建案例项目',exact:true}).isVisible()&&/已手动确认 0 \/\s*\d+ 章/.test(await page.locator('.tutorial-progress small').innerText()));
  const phone=await pageFor(bob,bob.workspace,true);await phone.getByRole('button',{name:'打开主导航',exact:true}).click();
  const dialog=phone.getByRole('dialog',{name:'工作空间导航',exact:true});await dialog.waitFor();
  const focused=new Set();let contained=true;
  for(let index=0;index<35;index++) {
   const value=await phone.evaluate(()=>({tag:document.activeElement?.tagName,inside:!!document.activeElement?.closest('aside[role="dialog"]'),disabled:!!document.activeElement?.matches(':disabled')}));
   if(value.tag)focused.add(value.tag);contained&&=value.inside&&!value.disabled;await phone.keyboard.press('Tab');
  }
  verify('mobile keyboard navigation includes form controls and remains in the open menu',contained&&focused.has('SELECT')&&focused.has('INPUT'));
  await phone.keyboard.press('Escape');verify('closing the mobile menu restores focus to its trigger',await phone.getByRole('button',{name:'打开主导航',exact:true}).evaluate(el=>document.activeElement===el));
  await phone.screenshot({path:path.join(output,tag+'-mobile.png')});
 }
 // Last-membership removal is distinct from a viewer role. The user can still
 // manage their own account and create a replacement workspace.
 const invitation=await api(eve,null,`/workspaces/${eve.workspace}/invitations`,{role:'EDITOR',email:bob.email});
 await api(bob,null,'/invitations/accept',{token:invitation.invite_token});
 await api(eve,null,`/workspaces/${eve.workspace}/members/${bob.id}`,{role:'OWNER'},'PATCH');
 const empty=await pageFor(eve);
 await api(bob,null,`/workspaces/${eve.workspace}/members/${eve.id}`,{role:null},'PATCH');
 await empty.reload();await empty.getByRole('heading',{name:'工作区与成员',exact:true}).waitFor();
 await empty.locator('.account-workspace-switcher').waitFor();
 verify('last-membership removal clears the obsolete workspace and role',await empty.evaluate(()=>!sessionStorage.getItem('forgeflow.workspace')&&!sessionStorage.getItem('forgeflow.workspace-role')));
 verify('empty membership state offers truthful recovery instead of endless loading',await empty.getByText('还没有协作工作区',{exact:true}).isVisible());
 await empty.getByLabel('新工作区名称').fill('Context recovered workspace');await empty.getByRole('button',{name:'创建工作区',exact:true}).click();
 await empty.waitForFunction(()=>document.querySelector('[aria-label="切换协作工作区"]')?.selectedOptions[0]?.text==='Context recovered workspace');
 verify('account without memberships can create a new workspace',!!await empty.evaluate(()=>sessionStorage.getItem('forgeflow.workspace')));
 await empty.screenshot({path:path.join(output,tag+'-recovered-workspace.png')});
 verify('no browser JavaScript errors',report.page_errors.length===0);
 report.status=before?'OBSERVED_BASELINE':'PASS';
} catch(error) {
 report.status='FAIL';report.error=error.message;if(page)await page.screenshot({path:path.join(output,tag+'-failure.png')});throw error;
} finally {
 await browser.close();await fs.writeFile(path.join(output,tag+'-report.json'),JSON.stringify(report,null,2)+'\n');
}
process.stdout.write(JSON.stringify({status:report.status,checks:report.checks.length,failed:report.checks.filter(x=>!x.passed).map(x=>x.name),model_calls:0})+'\n');
