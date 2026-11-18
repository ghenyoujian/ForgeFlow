// One connected GUI journey. The Python owner enforces exact RootGO and deadlines.
import fs from 'node:fs';
import { createRequire } from 'node:module';
const require=createRequire(import.meta.url);
const {chromium}=require('/home/chenyoujian/miniconda/lib/python3.13/site-packages/playwright/driver/package');
const input=JSON.parse(fs.readFileSync(process.argv[2],'utf8'));
const result={schema_version:'forgeflow.interrupted-retry-browser.v1',status:'RUNNING',commands:[],pages:[],errors:[],models:0,DSH:0};
const put=(p,v)=>fs.writeFileSync(p,JSON.stringify(v,null,2)+'\n',{flag:'wx',mode:0o600});
const awaitFile=async p=>{const deadline=Date.now()+150000;while(!fs.existsSync(p)){if(Date.now()>deadline)throw new Error('owner handshake timed out');await new Promise(r=>setTimeout(r,200));}return JSON.parse(fs.readFileSync(p,'utf8'));};
let browser;
process.on('SIGTERM',async()=>{if(browser)await browser.close();process.exit(143);});
try {
 browser=await chromium.launch({headless:true,executablePath:input.chrome,args:['--no-proxy-server']});
 const context=await browser.newContext({viewport:{width:1440,height:1000},timezoneId:'UTC'});
 await context.addInitScript(t=>sessionStorage.setItem('forgeflow.owner-token',t),input.owner_token);
 const page=await context.newPage();page.on('pageerror',e=>result.errors.push({kind:'pageerror',message:e.message}));
 const visitRun=async id=>{await page.goto(input.url+'/runs/'+encodeURIComponent(id)+'?project='+encodeURIComponent(input.project_id),{waitUntil:'domcontentloaded'});await page.getByRole('heading',{name:'尝试工作台',exact:true}).waitFor();};
 const capture=async(suffix,action)=>{const responseWait=page.waitForResponse(r=>r.request().method()==='POST'&&new URL(r.url()).pathname.endsWith(suffix),{timeout:25000});await action();const response=await responseWait,request=response.request();const row={path:new URL(request.url()).pathname,method:'POST',body:request.postDataJSON(),idempotency_key:request.headers()['idempotency-key'],status:response.status(),response:await response.json()};result.commands.push(row);if(!response.ok())throw new Error('GUI command rejected '+row.status+'/'+row.response.code);return row.response.data;};
 await visitRun(input.old_attempt_id);
 const cancel=page.getByRole('button',{name:'请求停止当前尝试',exact:true});
 await page.getByLabel('操作原因',{exact:true}).fill('BC06用户中断旧版本，确认停止后由Owner重新规划');
 await cancel.waitFor();
 result.cancel=await capture('/cancel',()=>cancel.click());put(input.cancel_path,result);
 const retry=await awaitFile(input.retry_input_path);
 await page.goto(input.url+'/projects/'+encodeURIComponent(input.project_id)+'/tasks/'+encodeURIComponent(input.task_id),{waitUntil:'domcontentloaded'});
 await page.getByRole('button',{name:'重新准入并重试',exact:true}).waitFor();
 result.retry=await capture('/retry',()=>page.getByRole('button',{name:'重新准入并重试',exact:true}).click());
 await page.screenshot({path:input.output+'/owner-new-version-retry.png',fullPage:true});
 result.reviewed_revision=retry.task_revision;put(input.retry_path,result);
 const next=await awaitFile(input.integrate_input_path);result.new_attempt_id=next.attempt_id;
 await visitRun(next.attempt_id);
 const integrate=page.getByRole('button',{name:'验证并请求受控集成',exact:true});await integrate.waitFor();
 result.integrate=await capture('/verify-and-integrate',()=>integrate.click());put(input.integrate_path,result);
 const final=await awaitFile(input.final_input_path);
 for(const[id,state,name]of[[input.old_attempt_id,'CANCELLED','old-cancelled-history'],[next.attempt_id,'SUCCEEDED','new-successful-delivery']]){
  await visitRun(id);await page.getByRole('button',{name:'完整身份与结果',exact:true}).click();await page.waitForFunction(({id,state})=>document.querySelector('main')?.textContent.includes(id)&&document.querySelector('main')?.textContent.includes(state),{id,state},{timeout:20000});
  const body=await page.locator('main').innerText();await page.screenshot({path:input.output+'/'+name+'.png',fullPage:true});result.pages.push({attempt_id:id,expected_state:state,body_text:body});
 }
 result.final_authority=final;result.status=result.errors.length?'FAIL':'PASS_ACTUAL_INTERRUPT_RETRY_GUI';
}catch(e){result.status='FAIL';result.errors.push({kind:e.name,message:e.message});process.exitCode=1;}
finally{if(browser)await browser.close();result.browser_closed=true;put(input.report_path,result);}
