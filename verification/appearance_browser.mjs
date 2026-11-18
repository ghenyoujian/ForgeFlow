// Real isolated-server rendering and interaction checks. No model execution.
import fs from 'node:fs';
import path from 'node:path';
import assert from 'node:assert/strict';
import {createRequire} from 'node:module';
const require=createRequire(import.meta.url);
const {chromium}=require('/home/chenyoujian/miniconda/lib/python3.13/site-packages/playwright/driver/package');
const output=path.resolve(process.argv[2]);
const run=JSON.parse(fs.readFileSync(path.join(output,'private.json'),'utf8'));
const user=run.users[0],project=run.appearance_project;
const report={status:'RUNNING',checks:[],screenshots:[],page_errors:[],synthetic_accounts:true,canonical_tasks:12,model_calls:0,production_changed:false};
const verify=(name,passed,detail)=>{report.checks.push({name,passed:!!passed,...(detail===undefined?{}:{detail})});assert.ok(passed,name);};
const browser=await chromium.launch({executablePath:'/home/chenyoujian/.cache/ms-playwright/chromium-1247/chrome-linux64/chrome',headless:true,args:['--no-proxy-server']});
let page;
async function makeContext({mobile=false,auth=true,skin='glass',mode='light',motion='reduce',storage=true,...options}={}) {
  const context=await browser.newContext({viewport:mobile?{width:390,height:844}:{width:1440,height:1000},isMobile:mobile,hasTouch:mobile,deviceScaleFactor:1,reducedMotion:motion,colorScheme:'light',timezoneId:'Asia/Shanghai',...options});
  if(storage)await context.addInitScript(({user,auth,skin,mode})=>{
    if(location.origin==='null')return;
    if(sessionStorage.getItem('appearance-fixture-booted'))return;
    if(auth){sessionStorage.setItem('forgeflow.owner-token',user.token);sessionStorage.setItem('forgeflow.personal-account','1');sessionStorage.setItem('forgeflow.workspace',user.workspace);sessionStorage.setItem('forgeflow.workspace-role','OWNER');}
    if(skin!==null)localStorage.setItem('forgeflow.ui-theme',skin);
    if(mode!==null)localStorage.setItem('forgeflow.color-mode',mode);
    sessionStorage.setItem('appearance-fixture-booted','1');
  },{user,auth,skin,mode});
  context.on('page',p=>p.on('pageerror',e=>report.page_errors.push(e.message)));
  return context;
}
const root=()=>page.locator('html');
async function settle(){await page.evaluate(async()=>{await document.fonts.ready;await new Promise(r=>requestAnimationFrame(()=>requestAnimationFrame(r)));});}
async function capture(name){await settle();const filename=`appearance-${name}.png`;await page.screenshot({path:path.join(output,filename),fullPage:false});report.screenshots.push(filename);}
async function navigate(route,selector){await page.goto(run.base+route);await page.locator(selector).first().waitFor();await settle();}
async function openPicker(){await page.getByRole('button',{name:'外观与主题',exact:true}).click();const dialog=page.getByRole('dialog',{name:'外观与主题',exact:true});await dialog.waitFor();return dialog;}
async function closePicker(){await page.keyboard.press('Escape');await page.locator('[data-appearance-dialog]').waitFor({state:'detached'});}
async function choose(skin,mode){const d=await openPicker();await d.getByLabel(skin==='glass'?'Glass 轻盈通透':'Studio 专业石墨',{exact:true}).check();await d.getByLabel(mode==='light'?'浅色':mode==='dark'?'深色':'跟随系统',{exact:true}).check();await closePicker();await settle();}
async function noOverflow(name){const v=await page.evaluate(()=>({width:innerWidth,document:document.documentElement.scrollWidth}));verify(name,v.document<=v.width+1,v);}
async function appearanceState(skin,mode){verify(`${skin}/${mode} root preference`,await root().getAttribute('data-ui-theme')===skin&&await root().getAttribute('data-theme')===mode);}
function contrast(a,b){const linear=v=>(v/=255)<=.04045?v/12.92:((v+.055)/1.055)**2.4;const luminance=v=>.2126*linear(v[0])+.7152*linear(v[1])+.0722*linear(v[2]);return(Math.max(luminance(a),luminance(b))+.05)/(Math.min(luminance(a),luminance(b))+.05);}
async function verifyPalette(name){const colors=await page.evaluate(()=>{const r=getComputedStyle(document.documentElement),ctx=document.createElement('canvas').getContext('2d');const resolve=name=>{const el=document.createElement('span');el.style.color=r.getPropertyValue(name);document.body.append(el);const value=getComputedStyle(el).color;el.remove();ctx.clearRect(0,0,1,1);ctx.fillStyle=value;ctx.fillRect(0,0,1,1);return Array.from(ctx.getImageData(0,0,1,1).data).slice(0,3);};return{panel:resolve('--panel'),muted:resolve('--muted'),text:resolve('--text'),control:resolve('--control-line')};});const normal=contrast(colors.text,colors.panel),muted=contrast(colors.muted,colors.panel),control=contrast(colors.control,colors.panel);verify(`${name} text and control palette contrast`,normal>=4.5&&muted>=4.5&&control>=3,{text:normal,muted,control});}
try {
  const context=await makeContext();page=await context.newPage();
  const writes=[];page.on('request',r=>{if(['POST','PATCH','DELETE','PUT'].includes(r.method())&&r.url().includes('/api/'))writes.push(new URL(r.url()).pathname);});
  for(const skin of ['glass','studio'])for(const mode of ['light','dark']) {
    await navigate(`/projects/${project}`,'.planning-summary-card');await choose(skin,mode);await appearanceState(skin,mode);await verifyPalette(`${skin}/${mode}`);await noOverflow(`${skin}/${mode} desktop overview has no page overflow`);await capture(`${skin}-${mode}-overview`);
    await navigate(`/projects/${project}/flows/1`,'.virtual-task-row');
    verify(`${skin}/${mode} all twelve canonical tasks remain visible`,await page.locator('.planning-match-count').innerText()==='12 / 12 张任务');
    const heights=await page.locator('.virtual-task-row').evaluateAll(rows=>rows.map(r=>r.getBoundingClientRect().height));verify(`${skin}/${mode} virtualized row geometry remains 60px`,heights.every(n=>Math.abs(n-60)<.5),heights);
    await noOverflow(`${skin}/${mode} desktop task table contains its scrolling`);await capture(`${skin}-${mode}-planning`);
    await page.getByRole('button',{name:'看板',exact:true}).click();await page.locator('.planning-kanban').waitFor();await noOverflow(`${skin}/${mode} kanban contains its scrolling`);
    if(skin==='studio'&&mode==='dark')await capture('studio-dark-kanban');
  }
  verify('appearance changes and navigation issue no mutation requests',writes.length===0,writes);
  await choose('glass','light');await page.reload();await page.locator('.planning-kanban').waitFor();await appearanceState('glass','light');verify('reload keeps the selected planning view',new URL(page.url()).searchParams.get('view')==='board');
  await page.getByRole('button',{name:'任务表',exact:true}).click();await page.getByRole('button',{name:'重命名任务 brief',exact:true}).click();await page.getByLabel('编辑标题 brief',{exact:true}).fill('保留我的个人网站设计草稿');await page.keyboard.press('Enter');
  await page.getByLabel('搜索全部规划任务').fill('brief');await page.waitForURL(url=>url.searchParams.get('q')==='brief');const beforeURL=page.url();await choose('studio','dark');verify('theme switch retains unsaved task title and filter',await page.locator('.virtual-task-row[data-task-id="brief"] strong').innerText()==='保留我的个人网站设计草稿'&&page.url()===beforeURL,{before:beforeURL,after:page.url()});
  await page.getByRole('button',{name:'查看任务 brief',exact:true}).click();await page.getByRole('dialog').waitFor();const inspectorURL=page.url();
  // The toolbar is correctly inert behind a task inspector; its content remains
  // open while the OS changes the system appearance.
  await page.keyboard.press('Escape');await page.getByRole('dialog').waitFor({state:'detached'});await choose('glass','system');await page.getByRole('button',{name:'查看任务 brief',exact:true}).click();await page.getByRole('dialog').waitFor();const selectedURL=page.url();
  await page.emulateMedia({colorScheme:'dark'});await page.waitForFunction(()=>document.documentElement.dataset.theme==='dark');verify('system appearance keeps the selected task inspector and draft',page.url()===selectedURL&&await page.getByRole('dialog').isVisible()&&inspectorURL.includes('task=brief'));await page.keyboard.press('Escape');await page.getByRole('dialog').waitFor({state:'detached'});
  await choose('glass','light');const dialog=await openPicker();await capture('glass-light-appearance');
  const glassRadio=dialog.getByLabel('Glass 轻盈通透',{exact:true});await glassRadio.focus();await page.keyboard.press('ArrowRight');verify('native arrow keys select the next visual theme',await dialog.getByLabel('Studio 专业石墨',{exact:true}).isChecked());
  for(let i=0;i<14;i++)await page.keyboard.press('Tab');verify('keyboard focus stays within the appearance dialog',await page.evaluate(()=>!!document.activeElement.closest('[data-appearance-dialog]')));
  await closePicker();verify('Escape returns focus to the appearance button',await page.getByRole('button',{name:'外观与主题',exact:true}).evaluate(e=>e===document.activeElement));
  await navigate(`/projects/${project}/agent-network`,'.network-compose');await page.getByLabel('消息',{exact:true}).fill('请保留这条尚未发送的协作消息。');await choose('studio','dark');verify('appearance preserves an unsent collaboration message',await page.getByLabel('消息',{exact:true}).inputValue()==='请保留这条尚未发送的协作消息。');await capture('studio-dark-network');
  const send=await page.getByRole('button',{name:'发送消息',exact:true}).boundingBox();verify('desktop composer stays above the status bar',send&&send.y+send.height<=page.viewportSize().height-30,send);
  await navigate('/workspaces','.member-row');await page.getByLabel('显示名称',{exact:true}).fill('尚未保存的个人名称');await choose('glass','light');verify('appearance preserves unsaved profile input',await page.getByLabel('显示名称',{exact:true}).inputValue()==='尚未保存的个人名称');await capture('glass-light-workspaces');
  await navigate(`/projects/${project}/teams`,'.capacity-tiers');await capture('glass-light-team');await noOverflow('team has no horizontal page overflow');
  await navigate(`/projects/${project}/schedule`,'.planning-studio');await capture('glass-light-schedule');await noOverflow('schedule has no horizontal page overflow');
  await navigate('/tutorial','.tutorial-hero');await capture('glass-light-tutorial');
  await openPicker();await page.getByRole('dialog').getByLabel('减少透明效果',{exact:true}).check();await closePicker();verify('reduced transparency removes navigation blur',await page.locator('.topbar').evaluate(e=>getComputedStyle(e).backdropFilter)==='none');
  verify('reduced motion removes appearance transitions',await page.locator('.appearance-trigger').evaluate(e=>getComputedStyle(e).transitionDuration.split(',').every(v=>parseFloat(v)===0)));
  const peer=await context.newPage();await peer.goto(run.base+'/tutorial');await peer.locator('.tutorial-hero').waitFor();await choose('studio','dark');await peer.waitForFunction(()=>document.documentElement.dataset.uiTheme==='studio'&&document.documentElement.dataset.theme==='dark');verify('preferences synchronize to another open tab',true);await peer.close();
  const d=await openPicker();await d.getByRole('button',{name:'使用原有样式',exact:true}).click();await closePicker();verify('classic appearance is available as a rollback',await root().getAttribute('data-ui-theme')==='classic');await choose('glass','light');
  await page.emulateMedia({contrast:'more'});await verifyPalette('increased contrast preference');await page.emulateMedia({contrast:'no-preference'});
  await page.emulateMedia({forcedColors:'active'});await openPicker();verify('forced colors preserve a visible selected theme outline',await page.locator('.appearance-theme-card.is-selected').evaluate(e=>getComputedStyle(e).outlineStyle==='solid'));await closePicker();await page.emulateMedia({forcedColors:'none'});
  await page.setViewportSize({width:720,height:500});await noOverflow('desktop content reflows at a 720px layout viewport');await openPicker();await noOverflow('appearance picker fits a short 720px viewport');await page.getByRole('button',{name:'使用原有样式',exact:true}).scrollIntoViewIfNeeded();verify('appearance footer remains reachable in a short viewport',await page.getByRole('button',{name:'使用原有样式',exact:true}).isVisible());await closePicker();
  verify('all appearance and draft retention checks made no server writes',writes.length===0,writes);await context.close();
  for(const skin of ['glass','studio'])for(const mode of ['light','dark']) {
    const mobile=await makeContext({mobile:true,skin,mode});page=await mobile.newPage();
    await navigate(`/projects/${project}/flows/1`,'.virtual-task-row');await noOverflow(`${skin}/${mode} phone task table has no page overflow`);await capture(`${skin}-${mode}-mobile-planning`);
    await openPicker();await noOverflow(`${skin}/${mode} phone appearance dialog fits`);await capture(`${skin}-${mode}-mobile-appearance`);const close=await page.getByRole('button',{name:'关闭检查器',exact:true}).boundingBox();verify(`${skin}/${mode} phone close control fits viewport with a 44px target`,close&&close.x>=0&&close.x+close.width<=390&&close.y>=0&&close.width>=44&&close.height>=44,close);await closePicker();
    await navigate('/tutorial','.tutorial-hero');await noOverflow(`${skin}/${mode} phone tutorial fits`);
    await navigate(`/projects/${project}/teams`,'.capacity-metrics');await noOverflow(`${skin}/${mode} phone team fits`);await page.locator('.capacity-adjustment>summary').click();await page.locator('.capacity-tiers').waitFor();await noOverflow(`${skin}/${mode} expanded phone capacity controls fit`);
    await navigate(`/projects/${project}/schedule`,'.planning-studio');await noOverflow(`${skin}/${mode} phone schedule fits`);
    await mobile.close();
  }
  const publicContext=await makeContext({auth:false});page=await publicContext.newPage();
  for(const skin of ['glass','studio'])for(const mode of ['light','dark']){await navigate('/','.login-workspace');await page.getByLabel('邮箱',{exact:true}).fill('我的登录输入@example.test');await choose(skin,mode);verify(`${skin}/${mode} login input survives appearance change`,await page.getByLabel('邮箱',{exact:true}).inputValue()==='我的登录输入@example.test');await capture(`${skin}-${mode}-welcome`);await noOverflow(`${skin}/${mode} welcome fits desktop`);}
  await page.setViewportSize({width:390,height:844});await choose('glass','light');await noOverflow('public welcome fits phone');const emailBox=await page.getByLabel('邮箱',{exact:true}).boundingBox();verify('phone welcome prioritizes the login form above decoration',emailBox&&emailBox.y>=0&&emailBox.y+emailBox.height<844,emailBox);verify('phone login uses a readable 16px input font',await page.getByLabel('邮箱',{exact:true}).evaluate(e=>parseFloat(getComputedStyle(e).fontSize))>=16);await capture('glass-light-mobile-welcome');await page.setViewportSize({width:320,height:740});await noOverflow('welcome fits a 320px phone');await openPicker();await noOverflow('appearance picker fits a 320px phone');await closePicker();await publicContext.close();
  const fresh=await makeContext({auth:false,storage:false,colorScheme:'dark'});page=await fresh.newPage();await navigate('/','.login-workspace');verify('new browser follows system dark with Glass default',await root().getAttribute('data-ui-theme')==='glass'&&await root().getAttribute('data-theme')==='dark');const freshPeer=await fresh.newPage();await freshPeer.goto(run.base+'/');await freshPeer.locator('.login-workspace').waitFor();await page.emulateMedia({colorScheme:'light'});await page.waitForFunction(()=>document.documentElement.dataset.theme==='light');verify('new browser continues following system changes',true);await freshPeer.getByRole('button',{name:'外观与主题',exact:true}).click();verify('system changes in another tab do not turn system mode into a fixed mode',await freshPeer.getByLabel('跟随系统',{exact:true}).isChecked());await freshPeer.close();await fresh.close();
  const invalid=await makeContext({auth:false,skin:'not-a-skin',mode:'bad-mode'});await invalid.addInitScript(()=>{if(location.origin!=='null')localStorage.setItem('forgeflow.theme','dark');});page=await invalid.newPage();await navigate('/','.login-workspace');verify('invalid preference falls back while respecting legacy dark mode',await root().getAttribute('data-ui-theme')==='glass'&&await root().getAttribute('data-theme')==='dark');await invalid.close();
  const accessibility=await makeContext({auth:false,motion:'no-preference'});page=await accessibility.newPage();await navigate('/','.login-workspace');await openPicker();const animation=await page.locator('[data-appearance-dialog] .drawer').evaluate(e=>({name:getComputedStyle(e).animationName,duration:parseFloat(getComputedStyle(e).animationDuration)}));verify('normal motion uses a short drawer entrance',animation.name==='inspector-appear'&&animation.duration>0&&animation.duration<=.3,animation);await closePicker();const cdp=await accessibility.newCDPSession(page);await cdp.send('Emulation.setEmulatedMedia',{features:[{name:'prefers-reduced-transparency',value:'reduce'},{name:'prefers-reduced-motion',value:'reduce'}]});await page.waitForFunction(()=>document.documentElement.dataset.transparency==='reduced');await openPicker();verify('OS reduced transparency overrides and explains the preference',await page.getByLabel('减少透明效果',{exact:true}).isChecked()&&await page.getByLabel('减少透明效果',{exact:true}).isDisabled()&&await page.getByText('系统已启用减少透明效果',{exact:true}).isVisible());verify('OS reduced transparency removes overlay blur',await page.locator('[data-appearance-dialog] .drawer-backdrop').evaluate(e=>getComputedStyle(e).backdropFilter)==='none');await closePicker();await accessibility.close();
  const unavailable=await makeContext({auth:false});page=await unavailable.newPage();await navigate('/','.login-workspace');await page.evaluate(()=>{const original=Storage.prototype.setItem;Storage.prototype.setItem=function(key,value){if(this===localStorage&&key.startsWith('forgeflow.'))throw new DOMException('Fixture storage full','QuotaExceededError');return original.call(this,key,value);};});await openPicker();await page.getByRole('dialog').getByLabel('Studio 专业石墨',{exact:true}).check();verify('storage failure applies appearance with honest feedback',await root().getAttribute('data-ui-theme')==='studio'&&await page.getByText('已应用，浏览器暂时无法保存偏好',{exact:true}).isVisible());await closePicker();await unavailable.close();
  verify('no uncaught JavaScript errors',report.page_errors.length===0,report.page_errors);report.status='PASS';
} catch(error){report.status='FAIL';report.error=String(error.stack||error);if(page&&!page.isClosed())await page.screenshot({path:path.join(output,'appearance-failure.png')}).catch(()=>{});throw error;}
finally{fs.writeFileSync(path.join(output,'appearance-report.json'),JSON.stringify(report,null,2)+'\n');await browser.close();console.log(JSON.stringify({status:report.status,checks:report.checks.length,screenshots:report.screenshots.length,page_errors:report.page_errors.length,model_calls:0}));}
