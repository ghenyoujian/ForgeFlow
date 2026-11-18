import {useEffect,useRef,useState} from 'react';
import {Link,useNavigate} from 'react-router-dom';
import {ArrowLeft,ArrowRight,Check,Play,BookOpen,Download,Workflow} from 'lucide-react';
import {api,useApi,getDraftScope,getWorkspace,getToken,isPersonalAccount,useWorkspaceWritable} from '../../app/api';
import {PageHeader,Panel,ErrorNotice} from '../../components';
interface Lesson {id:string;title:string;summary:string;steps:string[];check:string}
interface Guide {title:string;goal:string;lessons:Lesson[];roles:{id:string;name:string;include:string[]}[];tasks:{id:string;title:string;role:string;depends_on:string[];write_set:string[];outcome:string;acceptance:string}[]}
interface Reading {done:string[];lessonId:string}
interface CaseProject {id:string;timezone:string;ready:boolean}
function readProgress(key:string):Reading {
  try {
    const value=JSON.parse(sessionStorage.getItem(key)||'null');
    const done=Array.isArray(value)?value:value?.done;
    return {done:Array.isArray(done)?[...new Set(done.filter((id):id is string=>typeof id==='string'))]:[],lessonId:typeof value?.lessonId==='string'?value.lessonId:''};
  } catch {return {done:[],lessonId:''};}
}
function readCase(key:string):CaseProject|undefined {
  try {
    const value=JSON.parse(sessionStorage.getItem(key)||'null');
    if(value&&typeof value.id==='string'&&/^[a-f0-9-]{36}$/.test(value.id)&&typeof value.timezone==='string'&&typeof value.ready==='boolean')return value;
  } catch { /* Keep the guide readable even if an old local record is malformed. */ }
}
export function TutorialPage() {
  const guide=useApi<Guide>('/tutorials/personal-site');const navigate=useNavigate();
  const readingKey=`forgeflow.tutorial.${getDraftScope()}`;
  const caseKey=`forgeflow.tutorial-case.${getDraftScope()}.${getWorkspace()}`;
  const [reading,setReading]=useState<Reading>(()=>readProgress(readingKey));
  const [localWarning,setLocalWarning]=useState('');
  const [caseProject,setCaseProject]=useState<CaseProject|undefined>(()=>readCase(caseKey));
  const [busy,setBusy]=useState(false);const [error,setError]=useState<Error>();
  const creating=useRef(false);
  const lessonHeading=useRef<HTMLHeadingElement>(null);
  const previousLesson=useRef<string|undefined>(undefined);
  const [expanded,setExpanded]=useState('');
  const writable=useWorkspaceWritable();
  const lesson=guide.data?.lessons.find(l=>l.id===reading.lessonId)||guide.data?.lessons[0];
  const step=lesson&&guide.data?guide.data.lessons.indexOf(lesson):0;
  const done=reading.done.filter(id=>guide.data?.lessons.some(l=>l.id===id));
  const project=caseProject?.ready?caseProject.id:'';
  useEffect(()=>{
    if(lesson&&previousLesson.current&&previousLesson.current!==lesson.id)lessonHeading.current?.focus();
    previousLesson.current=lesson?.id;
  },[lesson?.id]);
  useEffect(()=>{
    try{sessionStorage.setItem(readingKey,JSON.stringify(reading));setLocalWarning('');}
    catch{setLocalWarning('浏览器暂时无法保存阅读位置；当前教程仍可阅读。');}
  },[readingKey,reading]);
  async function createCase() {
    if(creating.current||!writable)return;creating.current=true;setBusy(true);setError(undefined);
    const record=caseProject||{id:crypto.randomUUID(),timezone:Intl.DateTimeFormat().resolvedOptions().timeZone,ready:false};
    const id=record.id;
    try {
      // Keep the same project, timezone and request keys across reloads and
      // workspace changes, including a committed create with a lost response.
      try{sessionStorage.setItem(caseKey,JSON.stringify(record));}
      catch{throw new Error('浏览器无法保存案例恢复信息，请释放存储空间后重试。');}
      setCaseProject(record);
      await api.post('/projects',{project_id:id,name:'我的个人网站',root_path:'',authority_mode:'MANAGED',data_origin:'NATIVE',goal:'个人介绍、作品集与联系表单；适配手机、支持键盘与减少动画，经过独立验证后部署。',technology_stack:['React','TypeScript','HTTP API'],timezone:record.timezone,paused:true,archived:false,revision:0},{idempotencyKey:`tutorial-project-${id}`});
      await api.post(`/projects/${id}/tutorial/personal-site`,{},{idempotencyKey:`tutorial-plan-${id}`});
      const saved={...record,ready:true};sessionStorage.setItem(caseKey,JSON.stringify(saved));setCaseProject(saved);
    }catch(e){setError(e as Error);}finally{creating.current=false;setBusy(false);}
  }
  return <div className="tutorial-page collaboration-page">
    <PageHeader title="个人网站 · 从想法到协作交付" description="跟着一个可编辑的案例，学会规划、设计、编排自己的 Agent 团队。" actions={<Link className="button" to={getToken()?'/portfolio':'/'}>{getToken()?'返回项目':'注册 / 登录'}</Link>}/>
    <section className="tutorial-hero"><div><span className="eyebrow"><BookOpen size={14}/> FORGEFLOW 入门指南</span><h2>你的第一个网站，<br/>也是团队的第一次默契。</h2><p>把 UI、前端、后端、动效与部署拆成清晰的工作，让不同人的 Agent 通过同一项目协作。</p><div className="tutorial-hero-actions">{!getToken()?<Link className="button primary" to="/">注册并建立工作区 <ArrowRight size={16}/></Link>:isPersonalAccount()?<button className="primary" disabled={busy||!!project||!writable} onClick={()=>void createCase()}><Play size={15}/>{busy?'正在创建案例…':project?'案例草案已创建':caseProject?'继续创建案例':'创建案例项目'}</button>:<p>使用个人账号可创建独立案例；管理员仍可保留原有项目接入方式。</p>}{project&&<button onClick={()=>navigate(`/projects/${project}/flows?workbench=1`)}>打开规划草案 <ArrowRight size={15}/></button>}</div><small>12 个任务 · 6 个岗位 · 仅创建规划草案</small></div><div className="tutorial-map" aria-label="案例流程"><span>目标与 UI</span><i/><div><span>前端</span><span>API 与后端</span><span>动效</span></div><i/><span>验证 → 部署审批</span><p><Workflow size={15}/>每一步都有边界、依赖和验收标准</p></div></section>
    {localWarning&&<p role="status" className="panel-caption">{localWarning}</p>}
    {caseProject&&!caseProject.ready&&!busy&&<p className="panel-caption" role="status">上次的案例尚未完成，点击「继续创建案例」补齐规划草案。</p>}
    {isPersonalAccount()&&!writable&&<p className="panel-caption">{getWorkspace()?'当前工作区只读，请切换到可编辑的工作区创建案例。':'请先创建或加入工作区，再创建案例。'} <Link to="/workspaces">工作区与成员</Link></p>}
    {(guide.error||error)&&<ErrorNotice error={guide.error||error} onRetry={guide.reload}/>}
    {!guide.data&&!guide.error&&<p role="status">正在加载教程…</p>}
    {guide.data&&lesson&&<div className="tutorial-layout"><nav className="lesson-nav" aria-label="教程章节">{guide.data.lessons.map((l,i)=><button key={l.id} aria-current={i===step?'step':undefined} onClick={()=>setReading(current=>({...current,lessonId:l.id}))}><span>{done.includes(l.id)?<Check size={14}/>:String(i+1).padStart(2,'0')}</span><strong>{l.title}</strong></button>)}<div className="tutorial-progress"><progress value={done.length} max={guide.data.lessons.length} aria-label="已阅读章节"/><small>已手动确认 {done.length} / {guide.data.lessons.length} 章</small></div></nav>
      <article className="lesson-content" key={lesson.id}><span className="eyebrow">第 {step+1} 章 / {guide.data.lessons.length} 章</span><h2 ref={lessonHeading} tabIndex={-1}>{lesson.title}</h2><p className="lesson-summary">{lesson.summary}</p><ol className="lesson-steps">{lesson.steps.map((text,i)=><li key={i}>{text}</li>)}</ol><div className="lesson-check"><Check size={18}/><div><strong>完成这一章时，确认</strong><p>{lesson.check}</p></div></div>
      {lesson.id==='plugin'&&<div className="tutorial-code"><a className="button" download href="/api/v1/plugins/dsh-forgeflow-network/forgeflow.mjs"><Download size={15}/>下载安装器</a><p>安装目录使用一个新路径，参数中的项目与工作区标识可从「Agent 通讯」复制。</p><pre><code>{`node forgeflow.mjs install --directory /absolute/forgeflow-plugin \\\n  --dsh-node-modules /absolute/DSH/node_modules \\\n  --url ${location.origin} --workspace WORKSPACE_ID --project PROJECT_ID \\\n  --token-file /absolute/private-token-file\nnode /absolute/forgeflow-plugin/bin/forgeflow.mjs doctor \\\n  --directory /absolute/forgeflow-plugin`}</code></pre><p>然后把 <code>--patch /absolute/forgeflow-plugin/cordis.patch.json</code> 加到现有 DSH 启动参数。安装器不改变当前 DSH_HOME，也不自动重启服务。</p></div>}
      {lesson.id==='workflow'&&<div className="tutorial-code"><pre><code>{`node /absolute/forgeflow-plugin/bin/forgeflow.mjs workflow \\\n  --directory /absolute/forgeflow-plugin \\\n  --output /absolute/personal-site.request.json`}</code></pre><p>将请求文件里的 <code>meta</code>、<code>script</code> 和 <code>args</code> 传给 DSH 原生 <code>workflow</code> 工具。默认只运行零 Agent 预览。</p></div>}
      <label className="lesson-done"><input type="checkbox" checked={done.includes(lesson.id)} onChange={e=>{const checked=e.target.checked;setReading(current=>({...current,done:checked?[...new Set([...current.done,lesson.id])]:current.done.filter(id=>id!==lesson.id)}));}}/>我已阅读并核对这一章</label><footer className="lesson-controls"><button disabled={step===0} onClick={()=>setReading(current=>({...current,lessonId:guide.data!.lessons[step-1].id}))}><ArrowLeft size={15}/>上一章</button><button className="primary" disabled={step===guide.data.lessons.length-1} onClick={()=>setReading(current=>({...current,lessonId:guide.data!.lessons[step+1].id}))}>下一章<ArrowRight size={15}/></button></footer></article>
    </div>}
    {guide.data&&<Panel title="案例任务 · 点击查看边界与验收" className="tutorial-task-panel"><div className="tutorial-task-list">{guide.data.tasks.map(task=><div key={task.id}><button aria-expanded={expanded===task.id} onClick={()=>setExpanded(expanded===task.id?'':task.id)}><span>{guide.data?.roles.find(r=>r.id===task.role)?.name}</span><strong>{task.title}</strong><small>{task.depends_on.length?`${task.depends_on.length} 个前置任务`:'可先开始'}</small></button>{expanded===task.id&&<div className="tutorial-task-detail"><p>{task.outcome}</p><p><strong>验收：</strong>{task.acceptance}</p><p><strong>负责文件：</strong><code>{task.write_set.join('、')}</code></p><p><strong>前置：</strong>{task.depends_on.join('、')||'无'}</p></div>}</div>)}</div></Panel>}
  </div>;
}
