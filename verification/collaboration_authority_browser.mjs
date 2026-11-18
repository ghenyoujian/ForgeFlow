// Real rendered workspace exit/cancel/confirm. Responses are actual server
// responses; only their delivery is delayed. Registered agents are fixtures.
import fs from 'node:fs/promises';
import path from 'node:path';
import assert from 'node:assert/strict';
import {randomUUID,createHash} from 'node:crypto';
import {createRequire} from 'node:module';
const require=createRequire(import.meta.url);
const {chromium}=require('/home/chenyoujian/miniconda/lib/python3.13/site-packages/playwright/driver/package');
const output=path.resolve(process.argv[2]),before=process.argv.includes('--observe-before');
const tag=before?'authority-ui-before':'authority-ui-final';
const run=JSON.parse(await fs.readFile(path.join(output,'private.json'),'utf8'));
const fixture=JSON.parse(await fs.readFile(path.join(output,before?'authority-before-private.json':'authority-final-private.json'),'utf8'));
const {alice,bob,workspace,project}=fixture;
const report={status:'RUNNING',checks:[],page_errors:[],synthetic_accounts:true,model_calls:0};
const hash=bytes=>createHash('sha256').update(bytes).digest('hex');
report.runner_sha256=hash(await fs.readFile(new URL(import.meta.url)));report.binary_sha256=hash(await fs.readFile(run.server));
report.frontend_sha256={'index.html':hash(await fs.readFile(path.join(output,'candidate-console/index.html')))};
for(const name of await fs.readdir(path.join(output,'candidate-console/assets')))report.frontend_sha256['assets/'+name]=hash(await fs.readFile(path.join(output,'candidate-console/assets',name)));
await fs.copyFile(new URL(import.meta.url),path.join(output,tag+'-runner.mjs'));
const verify=(name,condition)=>{report.checks.push({name,passed:!!condition});if(!condition&&!before)assert.ok(condition,name);};
async function api(user,route,body,method='POST') {
 const response=await fetch(run.base+'/api/v1'+route,{method:body===undefined?'GET':method,headers:{Authorization:`Bearer ${user.token}`,'Content-Type':'application/json','X-ForgeFlow-Workspace':workspace,'Idempotency-Key':randomUUID()},body:body===undefined?undefined:JSON.stringify(body)});
 const result=await response.json();assert.equal(response.status,200,`${response.status} ${result.code||route}`);return result.data;
}
const browser=await chromium.launch({executablePath:'/home/chenyoujian/.cache/ms-playwright/chromium-1247/chrome-linux64/chrome',headless:true,args:['--no-proxy-server']});
const context=await browser.newContext({viewport:{width:1440,height:1000},reducedMotion:'reduce',timezoneId:'Asia/Shanghai'});
await context.addInitScript(value=>{
 if(sessionStorage.getItem('authority-fixture-initialized'))return;
 sessionStorage.setItem('authority-fixture-initialized','1');sessionStorage.setItem('forgeflow.owner-token',value.token);sessionStorage.setItem('forgeflow.personal-account','1');sessionStorage.setItem('forgeflow.workspace',value.workspace);sessionStorage.setItem('forgeflow.workspace-role','EDITOR');
},{token:bob.token,workspace});
const page=await context.newPage();page.on('pageerror',e=>report.page_errors.push(e.message));
const selfChanges=[];page.on('request',request=>{if(request.method()==='PATCH'&&request.url().endsWith(`/workspaces/${workspace}/members/${bob.account_id}`))selfChanges.push(request.postDataJSON());});
try {
 await page.goto(run.base+`/projects/${project}/agent-network`);await page.getByText('连接我的 DSH',{exact:true}).click();
 const issued=page.waitForResponse(res=>res.request().method()==='POST'&&res.url().endsWith('/agent-network/integrations'));
 await page.getByRole('button',{name:'生成项目连接凭证',exact:true}).click();const connector=(await (await issued).json()).data;
 await page.getByRole('dialog').waitFor();await page.getByRole('button',{name:'关闭检查器',exact:true}).click();
 const agent=await api(connector,`/projects/${project}/agent-network/agents`,{native_agent_id:'leave-fixture-'+randomUUID(),name:'Leave fixture Agent'});
 await fs.writeFile(path.join(output,tag+'-private.json'),JSON.stringify({connector,agent},null,2)+'\n',{mode:0o600});
 await page.goto(run.base+'/workspaces');await page.getByRole('button',{name:'退出此工作区',exact:true}).waitFor();await page.getByLabel('显示名称',{exact:true}).fill('取消退出后保留的资料输入');
 await page.getByRole('button',{name:'退出此工作区',exact:true}).click();
 const confirm=page.getByRole('group',{name:'确认退出工作区',exact:true});
 if(before) {
  await page.waitForTimeout(250);
  verify('workspace exit first displays its impact and an explicit confirmation',await confirm.isVisible());
  verify('opening an exit confirmation sends no membership mutation',selfChanges.length===0);
  report.status='OBSERVED_BASELINE';
 } else {
  await confirm.waitFor();verify('workspace exit first displays its impact and an explicit confirmation',await confirm.getByText('退出后将失去此工作区的项目访问，你的 DSH 连接也会停用。再次加入需要协作者邀请。',{exact:true}).isVisible());
  verify('opening an exit confirmation sends no membership mutation',selfChanges.length===0);
  verify('exit confirmation focuses the cancel action',await confirm.getByRole('button',{name:'取消退出',exact:true}).evaluate(el=>document.activeElement===el));
  const members=await api(alice,`/workspaces/${workspace}/members`);verify('membership remains active while confirming',members.some(m=>m.account_id===bob.account_id&&m.role==='EDITOR'));
  await page.screenshot({path:path.join(output,tag+'-confirmation.png')});
  await page.keyboard.press('Escape');await confirm.waitFor({state:'detached'});
  verify('Escape cancels and restores keyboard focus',await page.getByRole('button',{name:'退出此工作区',exact:true}).evaluate(el=>document.activeElement===el));
  verify('cancelling keeps other unsaved input',await page.getByLabel('显示名称',{exact:true}).inputValue()==='取消退出后保留的资料输入'&&selfChanges.length===0);
  await page.setViewportSize({width:390,height:844});await page.getByRole('button',{name:'退出此工作区',exact:true}).click();await confirm.waitFor();
  await confirm.scrollIntoViewIfNeeded();verify('mobile exit confirmation fits inside the viewport',await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth+1));
  await page.screenshot({path:path.join(output,tag+'-mobile.png')});await confirm.getByRole('button',{name:'取消退出',exact:true}).click();
  await page.setViewportSize({width:1440,height:1000});await page.getByRole('button',{name:'退出此工作区',exact:true}).click();await confirm.waitFor();
  let release,accepted;const gate=new Promise(resolve=>{release=resolve;}),committed=new Promise(resolve=>{accepted=resolve;});
  const route=`**/api/v1/workspaces/${workspace}/members/${bob.account_id}`;
  const hold=async intercepted=>{const upstream=await intercepted.fetch();assert.equal(upstream.status(),200);accepted();await gate;await intercepted.fulfill({response:upstream});};
  await page.route(route,hold);await confirm.getByRole('button',{name:'确认退出工作区',exact:true}).click();await committed;
  verify('confirmed exit shows pending state until the real response arrives',await confirm.getByRole('button',{name:'正在退出…',exact:true}).isDisabled()&&await confirm.getByRole('button',{name:'取消退出',exact:true}).isDisabled());
  verify('confirmed exit emits exactly one explicit null mutation',selfChanges.length===1&&Object.keys(selfChanges[0]).length===1&&selfChanges[0].role===null);
  release();await page.waitForFunction(id=>sessionStorage.getItem('forgeflow.workspace')===id,bob.workspace);await page.unroute(route,hold);
  verify('confirmed exit selects an accessible remaining workspace',await page.getByLabel('切换协作工作区').inputValue()===bob.workspace);
  const remaining=await api(alice,`/workspaces/${workspace}/members`);verify('server confirms removal before the completed state',!remaining.some(m=>m.account_id===bob.account_id));
  const old=await fetch(run.base+`/api/v1/projects/${project}/agent-network/agents`,{headers:{Authorization:`Bearer ${connector.token}`}});
  verify('exit invalidates the old DSH connector',old.status===403);
  const directory=await api(alice,`/projects/${project}/agent-network/agents`);verify('old agent remains registered but unavailable',directory.some(a=>a.agent_id===agent.agent_id&&!a.available));
  const invite=await api(alice,`/workspaces/${workspace}/invitations`,{role:'EDITOR',email:bob.email});await api(bob,'/invitations/accept',{token:invite.invite_token});
  const stillRevoked=await fetch(run.base+`/api/v1/projects/${project}/agent-network/agents`,{headers:{Authorization:`Bearer ${connector.token}`}});
  verify('being invited back never revives the old connector',stillRevoked.status===403);
  verify('no browser JavaScript errors',report.page_errors.length===0);report.status='PASS';
 }
} catch(error) {report.status='FAIL';report.error=error.message;await page.screenshot({path:path.join(output,tag+'-failure.png')});throw error;}
finally {await browser.close();await fs.writeFile(path.join(output,tag+'-report.json'),JSON.stringify(report,null,2)+'\n');}
process.stdout.write(JSON.stringify({status:report.status,checks:report.checks.length,failed:report.checks.filter(c=>!c.passed).map(c=>c.name),model_calls:0})+'\n');
