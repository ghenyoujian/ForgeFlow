// One actual UI journey. Root GO is enforced by the owning Python driver.
import fs from 'node:fs';
import { createRequire } from 'node:module';
const require = createRequire(import.meta.url);
const { chromium } = require('/home/chenyoujian/miniconda/lib/python3.13/site-packages/playwright/driver/package');
const input = JSON.parse(fs.readFileSync(process.argv[2], 'utf8'));
const result = { schema_version:'forgeflow.decision-browser-point.v1', status:'RUNNING', commands:[], pages:[], errors:[], model_calls:0 };
const write = (path,value) => fs.writeFileSync(path, JSON.stringify(value,null,2)+'\n', {flag:'wx',mode:0o600});
let browser;
process.on('SIGTERM',async()=>{if(browser)await browser.close();process.exit(143);});
try {
  browser = await chromium.launch({headless:true,executablePath:input.chrome,args:['--no-proxy-server']});
  const context = await browser.newContext({viewport:{width:1440,height:1000},timezoneId:'UTC'});
  await context.addInitScript(token=>sessionStorage.setItem('forgeflow.owner-token',token),input.owner_token);
  const page = await context.newPage();
  page.on('pageerror',e=>result.errors.push({kind:'pageerror',message:e.message}));
  const capture = async (predicate,action) => {
    const waiting=page.waitForResponse(r=>r.request().method()==='POST' && predicate(new URL(r.url()).pathname),{timeout:20000});
    await action(); const response=await waiting; const request=response.request();
    const row={path:new URL(request.url()).pathname,method:request.method(),body:request.postDataJSON(),idempotency_key:request.headers()['idempotency-key'],status:response.status(),response:await response.json()};
    result.commands.push(row);
    if (!response.ok()) throw new Error('UI command failed '+row.status+'/'+row.response.code);
    return row.response.data;
  };
  const visit = async p => {await page.goto(input.url+'/decisions?project='+encodeURIComponent(p),{waitUntil:'domcontentloaded'});await page.getByRole('heading',{name:'决策收件箱',exact:true}).waitFor();};
  const open = async (p,scope) => {
    await visit(p); await page.getByTestId('decision-create').click();
    await page.getByTestId('decision-create-scope').selectOption(scope);
    await page.getByTestId('decision-create-note').fill('实际决策闭环 '+p);
    const receipt=await capture(path=>path.endsWith('/decisions'),()=>page.getByTestId('decision-create-submit').click());
    await page.locator('.decision-detail').getByText(receipt.decision.decision_id,{exact:true}).waitFor();
    return receipt;
  };
  const action = async (name,submit,suffix,reason,revisit) => {
    await page.getByTestId({'确认事项':'decision-ack','安排复查':'decision-defer','预览恢复作用域':'decision-resolve'}[name]).click();
    await page.getByTestId('decision-action-reason').fill(reason);
    if (revisit) await page.getByTestId('decision-action-revisit').fill(revisit);
    const receipt=await capture(path=>path.endsWith('/'+suffix),()=>page.getByTestId('decision-action-submit').click());
    await page.locator('.decision-preview').waitFor({state:'hidden'});
    return receipt;
  };
  result.b_open=await open(input.b_project,input.b_scope);
  result.b_ack=await action('确认事项','确认并回读事项','acknowledgments','B确认但维持暂停');
  result.b_defer=await action('安排复查','确认延期','deferrals','B未来复查，维持策略不变',input.revisit_local);
  result.a_open=await open(input.a_project,input.a_scope);
  result.a_ack=await action('确认事项','确认并回读事项','acknowledgments','A确认当前暂停原因');
  result.a_resolve=await action('预览恢复作用域','确认恢复此作用域','resolutions','A只恢复已绑定项目策略');
  write(input.actions_path,result);
  const deadline=Date.now()+120000;
  while (!fs.existsSync(input.facts_path)) {if(Date.now()>deadline)throw new Error('actual Worker readback handshake timed out');await new Promise(r=>setTimeout(r,300));}
  const facts=JSON.parse(fs.readFileSync(input.facts_path,'utf8'));
  for(const [name,p,id,state] of [['desktop-a',input.a_project,result.a_open.decision.decision_id,'已解决'],['responsive-b',input.b_project,result.b_open.decision.decision_id,'已延期']]) {
    if(name==='responsive-b')await page.setViewportSize({width:390,height:844});
    await page.goto(input.url+'/decisions?project='+encodeURIComponent(p)+'&decision='+encodeURIComponent(id),{waitUntil:'domcontentloaded'});
    await page.locator('.decision-detail').getByText(id,{exact:true}).waitFor();
    await page.getByRole('button',{name:'刷新',exact:true}).click();
    await page.waitForFunction(({id,expected})=>{const e=document.querySelector('[data-testid=decision-detail]');return e?.dataset.decisionId===id && e.dataset.decisionState===expected;},{id,expected:name==='desktop-a'?'RESOLVED':'DEFERRED'});
    const authority=await page.getByTestId('decision-detail').evaluate(e=>({...e.dataset}));
    if(authority.policyPaused!==(name==='desktop-a'?'false':'true'))throw new Error('rendered authoritative policy pause mismatch');
    await page.screenshot({path:input.output+'/'+name+'.png',fullPage:true});
    const body=await page.locator('main').innerText();
    const dimensions=await page.evaluate(()=>({width:innerWidth,documentWidth:document.documentElement.scrollWidth}));
    if(dimensions.documentWidth>dimensions.width+1)throw new Error('responsive horizontal overflow');
    result.pages.push({name,project:p,decision_id:id,expected_authoritative_state:state,authority,body_text:body,dimensions});
  }
  await page.setViewportSize({width:1440,height:1000});
  await page.goto(input.url+'/runs/'+encodeURIComponent(facts.attempt_id)+'?project='+encodeURIComponent(facts.project_id),{waitUntil:'domcontentloaded'});
  await page.getByRole('heading',{name:'尝试工作台',exact:true}).waitFor();
  await page.getByRole('button',{name:'日志',exact:true}).click();
  await page.waitForFunction(pid=>document.querySelector('main')?.textContent.includes(String(pid)),facts.actual_author_pid,{timeout:15000});
  const liveBody=await page.locator('main').innerText();
  if(!liveBody.includes(facts.attempt_id) || !(liveBody.includes('RUNNING') || liveBody.includes('运行中')))throw new Error('actual run UI identity/state mismatch');
  result.actual_run_ui={project_id:facts.project_id,attempt_id:facts.attempt_id,actual_author_pid:facts.actual_author_pid,body_text:liveBody,cost:'UNKNOWN_NO_MODEL_USAGE_RECORD'};
  result.actual_worker_readback=facts;
  result.status=result.errors.length?'FAIL':'PASS_ACTUAL_DECISION_GUI_COMMANDS';
} catch(e) {result.status='FAIL';result.errors.push({kind:e.name,message:e.message});process.exitCode=1;}
finally {if(browser)await browser.close();result.browser_closed=true;write(input.report_path,result);}
