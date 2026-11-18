// One genuine Release GUI journey; Python owns exact-plan GO and actor cleanup.
import fs from 'node:fs';
import { createRequire } from 'node:module';
const require=createRequire(import.meta.url);
const {chromium}=require('/home/chenyoujian/miniconda/lib/python3.13/site-packages/playwright/driver/package');
const input=JSON.parse(fs.readFileSync(process.argv[2],'utf8'));
const result={schema_version:'forgeflow.release-browser-point.v1',status:'RUNNING',commands:[],pages:[],errors:[]};
const write=(p,v)=>fs.writeFileSync(p,JSON.stringify(v,null,2)+'\n',{flag:'wx',mode:0o600});
let browser;
process.on('SIGTERM',async()=>{if(browser)await browser.close();process.exit(143);});
try {
  browser=await chromium.launch({headless:true,executablePath:input.chrome,args:['--no-proxy-server']});
  const context=await browser.newContext({viewport:{width:1440,height:1000},acceptDownloads:true});
  await context.addInitScript(t=>sessionStorage.setItem('forgeflow.owner-token',t),input.owner_token);
  const page=await context.newPage();page.on('pageerror',e=>result.errors.push({kind:'pageerror',message:e.message}));
  const capture=async(suffix,action)=>{
    const pending=page.waitForResponse(r=>r.request().method()==='POST'&&new URL(r.url()).pathname.endsWith(suffix),{timeout:20000});await action();const response=await pending;const request=response.request();
    const row={path:new URL(request.url()).pathname,body:request.postDataJSON(),idempotency_key:request.headers()['idempotency-key'],status:response.status(),response:await response.json()};result.commands.push(row);
    if(!response.ok())throw new Error('GUI Release command failed '+row.status+'/'+row.response.code);return row.response.data;
  };
  const detailState=async state=>page.waitForFunction(state=>document.querySelector('[data-testid=release-detail]')?.dataset.releaseState===state,state);
  const action=async(name,suffix,reason)=>{
    await page.getByTestId('release-'+name).click();
    if(name==='candidate')await page.getByTestId('release-main-sha').fill(input.main_sha);
    if(reason)await page.getByTestId('release-action-reason').fill(reason);
    if(name==='reopen'){await page.getByTestId('release-phase-title').fill('真实后续阶段');await page.getByTestId('release-phase-goal').fill('保留既有接受版本，负责人继续安排任务前保持暂停。');}
    const receipt=await capture('/'+suffix,()=>page.getByTestId('release-action-submit').click());await page.getByTestId('release-action-submit').waitFor({state:'hidden'});return receipt;
  };
  await page.goto(input.url+'/projects/'+encodeURIComponent(input.project_id)+'/releases',{waitUntil:'domcontentloaded'});
  await page.getByTestId('release-create').click();await page.getByTestId('release-create-title').fill('真实验收版本交付');await page.getByTestId('release-milestone-'+input.milestone_id).check();
  await page.getByTestId('release-installation').fill('解包交付文件，在独立目录核对 manifest 与 artifacts 的 SHA256；source.tar 为固定主线的 Git archive。此受控项目按其已有验证环境复现，不承诺跨机执行器资格。');
  await page.getByTestId('release-not-proven').fill('100+生产并发\n跨机执行器运行资格');await page.getByTestId('release-risks').fill('后续阶段保持暂停，新增执行前由负责人重新核验环境和预算。');
  result.draft=await capture('/releases',()=>page.getByTestId('release-create-submit').click());await detailState('DRAFT');
  result.candidate=await action('candidate','candidates');await detailState('CANDIDATE');
  result.accepted=await action('accept','acceptances','仅接受已冻结里程碑范围与主线身份，保留未证明项。');await detailState('ACCEPTED');
  result.exported=await action('export','exports');
  const downloading=page.waitForEvent('download',{timeout:20000});await page.getByTestId('release-bundle-download').click();const download=await downloading;await download.saveAs(input.download_path);const error=await download.failure();if(error)throw new Error('actual bundle download failed '+error);
  result.download={suggested_filename:download.suggestedFilename(),actual_path:input.download_path};
  write(input.export_ready_path,result);
  const deadline=Date.now()+60000;while(!fs.existsSync(input.clean_verified_path)){if(Date.now()>deadline)throw new Error('independent real bundle verification handshake timed out');await new Promise(r=>setTimeout(r,250));}
  result.independent_verification=JSON.parse(fs.readFileSync(input.clean_verified_path,'utf8'));if(!result.independent_verification.passed)throw new Error('independent bundle hash verification did not pass');
  await page.screenshot({path:input.output+'/desktop-accepted.png',fullPage:true});result.pages.push({name:'desktop-accepted',authority:await page.getByTestId('release-detail').evaluate(e=>({...e.dataset})),body_text:await page.locator('main').innerText()});
  result.archived=await action('archive','archives','交付已接受、真实文件已导出并在独立目录核验；归档保留原历史。');
  await page.waitForFunction(()=>document.querySelector('[data-testid=release-detail]')?.dataset.projectArchived==='true');
  const archived=await page.getByTestId('release-detail').evaluate(e=>({...e.dataset}));if(archived.releaseState!=='ACCEPTED')throw new Error('archive discarded accepted Release history');result.archived_history_ui=archived;
  await page.reload({waitUntil:'domcontentloaded'});await detailState('ACCEPTED');
  result.reopened=await action('reopen','reopenings','按真实交付开新阶段，继承历史但保持暂停。');
  await page.waitForFunction(()=>{const e=document.querySelector('[data-testid=release-detail]');return e?.dataset.projectArchived==='false'&&e.dataset.projectPaused==='true';});
  await page.setViewportSize({width:390,height:844});await page.screenshot({path:input.output+'/responsive-reopened.png',fullPage:true});
  const dimensions=await page.evaluate(()=>({width:innerWidth,documentWidth:document.documentElement.scrollWidth}));if(dimensions.documentWidth>dimensions.width+1)throw new Error('Release responsive horizontal overflow');
  result.pages.push({name:'responsive-reopened',dimensions,authority:await page.getByTestId('release-detail').evaluate(e=>({...e.dataset})),body_text:await page.locator('main').innerText()});
  result.status=result.errors.length?'FAIL':'PASS_ACTUAL_RELEASE_GUI_CHAIN';
} catch(e){result.status='FAIL';result.errors.push({kind:e.name,message:e.message});process.exitCode=1;}
finally{if(browser)await browser.close();result.browser_closed=true;write(input.report_path,result);}
