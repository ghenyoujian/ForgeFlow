import {useEffect,useLayoutEffect,useRef,useState} from 'react';
import {Link} from 'react-router-dom';
import {Network,Send,Plug,Copy,Check,RefreshCw,MessageSquare,BookOpen,Search,ArrowUp,ArrowDown} from 'lucide-react';
import {api,useApi,getDraftScope,getWorkspace,useWorkspaceWritable} from '../../app/api';
import {PageHeader,Panel,Field,ErrorNotice,EmptyState,Drawer} from '../../components';

interface Agent {agent_id:string;account_id:string;owner_name:string;name:string;last_seen_at:string;available:boolean}
interface Message {sequence:number;message_id:string;sender_account_id:string;sender_agent_id?:string;recipient_agent_id:string;thread_id:string;reply_to?:string;parts:{kind:string;text?:string;data?:unknown}[];created_at:string;received_at?:string}
interface Inbox {items:Message[];next_cursor:number;previous_cursor?:number;has_more:boolean}
interface Integration {integration_id:string;name:string;disabled_at?:string;created_at:string}
interface Credential {integration_id:string;token:string;workspace_id:string;expires_in_seconds:number}
type Reply = Pick<Message,'message_id'|'thread_id'|'sender_agent_id'|'recipient_agent_id'>;
interface ComposeDraft {recipient:string;text:string;reply?:Reply;fingerprint?:string;id?:string}
const fingerprint = (draft:ComposeDraft) => JSON.stringify({recipient:draft.recipient,text:draft.text,thread:draft.reply?.thread_id,reply:draft.reply?.message_id});
function readDraft(key:string):ComposeDraft {
  try {
    const value=JSON.parse(sessionStorage.getItem(key)||'null');
    if(value && typeof value.recipient==='string' && typeof value.text==='string' && value.text.length<=8000) {
      const reply=value.reply;
      return {recipient:value.recipient,text:value.text,
        reply:reply && typeof reply.message_id==='string' && typeof reply.thread_id==='string' && typeof reply.recipient_agent_id==='string' ? reply : undefined,
        fingerprint:typeof value.fingerprint==='string'?value.fingerprint:undefined,id:typeof value.id==='string'?value.id:undefined};
    }
  } catch { /* An unavailable or malformed local draft never prevents the inbox opening. */ }
  return {recipient:'',text:''};
}

export function AgentNetworkPage({projectId}:{projectId?:string}) {
  const base=projectId?`/projects/${encodeURIComponent(projectId)}/agent-network`:null;
  const agents=useApi<Agent[]>(base?`${base}/agents`:null);
  const integrations=useApi<Integration[]>(base?`${base}/integrations`:null);
  const members=useApi<{account_id:string;display_name:string}[]>(getWorkspace()?`/workspaces/${encodeURIComponent(getWorkspace())}/members`:null);
  const draftKey=`forgeflow.network-draft.${getDraftScope()}.${getWorkspace()}.${projectId}`;
  const [compose,setCompose]=useState<ComposeDraft>(()=>readDraft(draftKey));
  const [draftWarning,setDraftWarning]=useState('');
  const [inbox,setInbox]=useState<Inbox>();
  const [before,setBefore]=useState<number>();
  const [loading,setLoading]=useState(true);
  const [readError,setReadError]=useState<Error>();
  const [status,setStatus]=useState('正在连接');
  const [search,setSearch]=useState('');
  const [name,setName]=useState('我的 DSH');
  const [credential,setCredential]=useState<Credential>();
  const [copied,setCopied]=useState(false);
  const [busy,setBusy]=useState('');
  const busyRef=useRef(false);
  const [error,setError]=useState<Error>();
  const [notice,setNotice]=useState('');
  const [refresh,setRefresh]=useState(0);
  const log=useRef<HTMLDivElement>(null);
  const follow=useRef(true);
  const writable=useWorkspaceWritable();

  useEffect(()=>{
    try {
      if(compose.text || compose.reply)sessionStorage.setItem(draftKey,JSON.stringify(compose));
      else sessionStorage.removeItem(draftKey);
      setDraftWarning('');
    } catch {setDraftWarning('浏览器暂时无法保存本地草稿，请先复制消息再离开。');}
  },[compose,draftKey]);
  useEffect(()=>{
    if(!base)return;
    const controller=new AbortController();
    let timer:ReturnType<typeof setTimeout>;
    let lastDirectory=Date.now();
    let initial=true;
    setLoading(true);
    setReadError(undefined);
    setStatus(before===undefined?'正在同步最新消息':'正在读取历史消息');
    const poll=async()=>{
      if(!initial && document.hidden){timer=setTimeout(poll,2000);return;}
      try {
        const result=await api.get<Inbox>(`${base}/messages?${before===undefined?'latest=true':`before=${before}`}`,controller.signal);
        if(controller.signal.aborted)return;
        if(initial){follow.current=before===undefined;if(log.current)log.current.scrollTop=0;}
        initial=false;
        setInbox(result);
        setLoading(false);
        setReadError(undefined);
        setStatus(before===undefined?`已同步 · ${new Date().toLocaleTimeString()}`:'历史消息 · 自动同步已暂停');
        if(before!==undefined)return;
        if(Date.now()-lastDirectory>10000){lastDirectory=Date.now();agents.reload();}
        timer=setTimeout(poll,2000);
      }catch(e){
        if(controller.signal.aborted)return;
        setLoading(false);
        setStatus('连接中断，正在重试');
        setReadError(e as Error);
        timer=setTimeout(poll,5000);
      }
    };
    void poll();
    return()=>{controller.abort();clearTimeout(timer);};
  },[base,before,refresh,agents.reload]);
  useLayoutEffect(()=>{if(follow.current && log.current)log.current.scrollTop=log.current.scrollHeight;},[inbox]);

  if(!projectId)return <EmptyState title="先选择一个协作项目" description="不同用户的 Agent 在共同工作区的项目内互相发现与通讯。" action={<Link to="/portfolio">选择项目</Link>}/>;
  async function perform(key:string,run:()=>Promise<void>){
    if(busyRef.current)return;
    busyRef.current=true;setBusy(key);setError(undefined);setNotice('');
    try{await run();}catch(e){setError(e as Error);}finally{busyRef.current=false;setBusy('');}
  }
  function latest(){setBefore(undefined);setRefresh(v=>v+1);}
  const label=(id?:string)=>{const agent=agents.data?.find(a=>a.agent_id===id);return agent?`${agent.owner_name} / ${agent.name}`:id||'项目成员';};
  const matches=(agents.data||[]).filter(a=>`${a.owner_name} ${a.name}`.toLocaleLowerCase().includes(search.trim().toLocaleLowerCase()));
  const recipientUnavailable=!!compose.recipient&&!!agents.data&&!agents.data.some(a=>a.agent_id===compose.recipient&&a.available);
  const messages=inbox?.items||[];
  return <div className="agent-network-page collaboration-page">
    <PageHeader title="Agent 通讯" description="在共同项目中，让每个人的 DSH Agent 交换合同、任务边界与阻塞。消息对项目成员可见。" actions={<><Link className="button" to="/tutorial"><BookOpen size={15}/>使用教程</Link><button onClick={()=>{agents.reload();integrations.reload();setRefresh(v=>v+1);}}><RefreshCw size={15}/>刷新</button></>}/>
    {(error||agents.error||integrations.error)&&<ErrorNotice error={error||agents.error||integrations.error}/>}
    {notice&&<p className="inline-success" role="status"><Check size={15}/>{notice}</p>}
    <div className="network-layout">
      <Panel title={<><Network size={16}/>项目 Agent 目录</>} actions={<small title="当前目录最多显示 2000 个登记身份">显示 {matches.length} / {agents.data?.length||0} 个身份</small>}>
        <p className="panel-caption">登记身份表示 DSH 连接记录；活跃执行和真实模型观测请查看执行页。</p>
        <label className="network-search"><Search size={15}/><input aria-label="搜索 Agent 或协作者" type="search" value={search} onChange={e=>setSearch(e.target.value)} placeholder="搜索 Agent 或协作者"/></label>
        {agents.loading&&!agents.data&&<p className="panel-caption" role="status">正在读取项目 Agent…</p>}
        {!agents.loading&&!agents.data?.length&&!agents.error&&<EmptyState title="连接你的第一个 Agent" description="先创建 DSH 连接，安装插件，再让 Agent 调用 forgeflow_identity。"/>}
        {!!agents.data?.length&&!matches.length&&<p className="panel-caption">没有匹配的 Agent，请调整搜索词。</p>}
        <div className="network-agent-list">{matches.map(a=><button key={a.agent_id} className={compose.recipient===a.agent_id?'selected':''} onClick={()=>setCompose(current=>({...current,recipient:a.agent_id}))} disabled={!a.available||!writable} aria-pressed={compose.recipient===a.agent_id}><span className="member-avatar">{a.owner_name.slice(0,1)}</span><span><strong>{a.name}</strong><small>{a.owner_name} · {a.available?'可通讯':'连接已停用'}</small></span></button>)}</div>
        <details className="network-connect"><summary><Plug size={15}/>连接我的 DSH</summary>
          <form className="compact-form" onSubmit={e=>{e.preventDefault();void perform('connect',async()=>{const result=await api.post<Credential>(`${base}/integrations`,{name});setCredential(result);setCopied(false);integrations.reload();});}}><Field label="连接名称"><input required maxLength={80} value={name} onChange={e=>setName(e.target.value)} disabled={!writable}/></Field><button disabled={!!busy||!writable}>{busy==='connect'?'正在创建…':'生成项目连接凭证'}</button><small>仅你的账号与此项目 · 8 小时有效</small></form>
          <p className="muted">工作区 <code>{getWorkspace()}</code><br/>项目 <code>{projectId}</code></p><a className="button" download href="/api/v1/plugins/dsh-forgeflow-network/forgeflow.mjs">下载安装器</a>
          {integrations.data?.map(i=><div className="integration-row" key={i.integration_id}><span>{i.name}<small>{i.disabled_at?'已撤销':'已签发；有效期以凭证为准'}</small></span>{!i.disabled_at&&<button disabled={!!busy||!writable} onClick={()=>void perform('renew',async()=>{const result=await api.post<Credential>(`${base}/integrations/${i.integration_id}/sessions`);setCredential(result);setCopied(false);setNotice('凭证已续期，原有 Agent 身份与收件箱保持可用');})}>续期</button>}{!i.disabled_at&&<button disabled={!!busy||!writable} onClick={()=>void perform('revoke',async()=>{await api.post(`${base}/integrations/${i.integration_id}/revoke`);integrations.reload();agents.reload();setNotice('连接凭证已撤销');})}>撤销</button>}</div>)}
        </details>
      </Panel>
      <Panel className="network-messages" title={<><MessageSquare size={16}/>项目协作消息</>} actions={<span className="network-connection" role="status">{status}</span>}>
        <div className="network-history-controls"><button disabled={loading||!inbox?.has_more||!inbox.previous_cursor} onClick={()=>setBefore(inbox?.previous_cursor)}><ArrowUp size={14}/>查看较早消息</button><span>{before===undefined?'最新消息':'历史消息'} · 本页 {messages.length} 条</span>{before!==undefined&&<button onClick={latest}><ArrowDown size={14}/>返回最新消息</button>}</div>
        {readError&&<div className="network-read-error"><ErrorNotice error={readError}/><button onClick={()=>setRefresh(v=>v+1)}>立即重试</button></div>}
        <div ref={log} className="network-log" role="log" aria-label="项目协作消息" aria-live="off" aria-busy={loading} onScroll={()=>{const el=log.current;if(el)follow.current=before===undefined&&el.scrollHeight-el.scrollTop-el.clientHeight<48;}}>
          {!inbox&&loading?<p className="panel-caption">正在读取协作消息…</p>:!messages.length&&!readError?<EmptyState title="从一条清晰的交接开始" description="选择 Agent，说明目标、边界、依赖与需要的回复。"/>:messages.map(m=><article key={m.message_id} className="network-message"><header><strong>{m.sender_agent_id?label(m.sender_agent_id):members.data?.find(member=>member.account_id===m.sender_account_id)?.display_name||'项目成员'}</strong><span>→ {label(m.recipient_agent_id)}</span><time dateTime={m.created_at} title={new Date(m.created_at).toLocaleString()}>{new Date(m.created_at).toLocaleTimeString()}</time></header>{m.parts.map((part,i)=><p key={i}>{part.kind==='text'?part.text:JSON.stringify(part.data)}</p>)}<footer><small>{m.received_at?'已确认收到':'等待接收确认'}</small><button disabled={!writable} onClick={()=>setCompose(current=>({...current,reply:{message_id:m.message_id,thread_id:m.thread_id,sender_agent_id:m.sender_agent_id,recipient_agent_id:m.recipient_agent_id},recipient:m.sender_agent_id||m.recipient_agent_id}))}>沿此会话回复</button></footer></article>)}
        </div>
        <form className="network-compose" onSubmit={e=>{
          e.preventDefault();
          void perform('send',async()=>{
            const content=fingerprint(compose);
            const id=compose.fingerprint===content&&compose.id?compose.id:crypto.randomUUID();
            setCompose(current=>({...current,fingerprint:content,id}));
            await api.post(`${base}/messages`,{client_message_id:id,recipient_agent_id:compose.recipient,parts:[{kind:'text',text:compose.text}],thread_id:compose.reply?.thread_id||null,reply_to:compose.reply?.message_id||null},{idempotencyKey:id});
            // Preserve anything typed or retargeted while awaiting confirmation.
            setCompose(current=>fingerprint(current)===content?{recipient:current.recipient,text:''}:current);
            latest();setNotice('消息已由服务端保存，等待对方接收');
          });
        }}>
          {compose.reply&&<div className="reply-context">正在回复同一会话 <button type="button" onClick={()=>setCompose(current=>({...current,reply:undefined}))}>取消回复</button></div>}
          <Field label="发给"><select required value={compose.recipient} disabled={!writable} onChange={e=>setCompose(current=>({...current,recipient:e.target.value}))}><option value="">选择项目中的 Agent</option>{recipientUnavailable&&<option value={compose.recipient} disabled>原收件人连接已停用，请重新选择</option>}{agents.data?.filter(a=>a.available).map(a=><option value={a.agent_id} key={a.agent_id}>{a.owner_name} / {a.name}</option>)}</select></Field>
          {recipientUnavailable&&<p className="panel-caption" role="status">原收件人当前不可通讯。消息草稿已保留，请选择可用的 Agent。</p>}
          <Field label="消息"><textarea required rows={3} maxLength={8000} value={compose.text} disabled={!writable} onChange={e=>setCompose(current=>({...current,text:e.target.value}))} placeholder="说明目标、任务边界、需要的合同或决策…"/></Field>
          {draftWarning&&<p role="status" className="panel-caption">{draftWarning}</p>}
          <div><small>{writable?'草稿保存在当前标签页 · 每页 100 条 · 不自动唤醒模型':'查看者只读 · 联系工作区所有者调整角色'}</small><button className="primary" disabled={!!busy||!compose.recipient||recipientUnavailable||!agents.data||!compose.text.trim()||!writable}><Send size={15}/>{busy==='send'?'正在发送…':'发送消息'}</button></div>
        </form>
      </Panel>
    </div>
    {credential&&<Drawer title="连接你的 DSH" onClose={()=>setCredential(undefined)}><div className="credential-content"><p>保存到仅你可读的 <code>0600</code> 文件，安装器通过 <code>--token-file</code> 使用。关闭后页面不再显示此凭证。</p><Field label="项目通讯凭证"><input type="password" readOnly value={credential.token} autoComplete="off"/></Field><button onClick={()=>void perform('copy',async()=>{await navigator.clipboard.writeText(credential.token);setCopied(true);})}><Copy size={15}/>{copied?'已复制':'复制凭证'}</button><dl><dt>工作区</dt><dd>{credential.workspace_id}</dd><dt>项目</dt><dd>{projectId}</dd><dt>有效期</dt><dd>签发起 8 小时；撤销、移除成员、降为查看者或更新密码会提前失效。</dd></dl><Link to="/tutorial" onClick={()=>setCredential(undefined)}>查看安装与 workflow 教程 <BookOpen size={15}/></Link><p className="muted">消息可被项目成员查看；只发送协作所需的内容。</p></div></Drawer>}
  </div>;
}
