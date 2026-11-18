import {useEffect,useState,useRef} from 'react';
import {Link,useLocation,useNavigate} from 'react-router-dom';
import {Plus,Users,Link2,Check,LogOut,KeyRound} from 'lucide-react';
import {api,useApi,getWorkspace,setWorkspace,setToken,renewAccountSession} from '../../app/api';
import type {Account,Workspace} from '../../app/WorkspaceSwitcher';
import {PageHeader,Panel,Field,ErrorNotice,EmptyState} from '../../components';
import {AppearanceControls} from '../../app/AppearanceControls';
import {EcpMembers, type EcpMember} from './EcpMembers';
import {EcpInvitations, type EcpInvitation} from './EcpInvitations';
type Member=EcpMember;
type Invite=EcpInvitation;
const roleName=(role:string)=>role==='OWNER'?'所有者':role==='EDITOR'?'编辑者':'查看者';
export function WorkspacesPage() {
  const workspaces=useApi<Workspace[]>('/workspaces');
  const profile=useApi<Account>('/account');
  const workspace=workspaces.data?.find(w=>w.workspace_id===getWorkspace())||workspaces.data?.[0];
  const base=workspace?`/workspaces/${workspace.workspace_id}`:null;
  const members=useApi<Member[]>(base?`${base}/members`:null);
  const soleOwner=(member:Member)=>member.role==='OWNER'&&members.data?.filter(m=>m.role==='OWNER').length===1;
  const invitations=useApi<Invite[]>(base&&workspace?.role==='OWNER'?`${base}/invitations`:null);
  const createRequest=useRef({name:'',id:''});
  const [newName,setNewName]=useState('');const [name,setName]=useState('');
  const [inviteEmail,setInviteEmail]=useState('');const [inviteRole,setInviteRole]=useState('EDITOR');
  const [link,setLink]=useState('');const [copied,setCopied]=useState(false);
  const [oldPassword,setOldPassword]=useState('');const [newPassword,setNewPassword]=useState('');
  const [busy,setBusy]=useState('');const [error,setError]=useState<Error>();const [notice,setNotice]=useState('');
  const operation=useRef(false);const [leaveConfirm,setLeaveConfirm]=useState(false);
  const leaveButton=useRef<HTMLButtonElement>(null);const cancelLeave=useRef<HTMLButtonElement>(null);const wasLeaving=useRef(false);
  const [remove,setRemove]=useState('');const navigate=useNavigate();
  const nameBase=useRef<{account?:string;value?:string}>({});
  useEffect(()=>{if(leaveConfirm)cancelLeave.current?.focus();else if(wasLeaving.current)leaveButton.current?.focus();wasLeaving.current=leaveConfirm;},[leaveConfirm]);
  useEffect(()=>{const data=profile.data;if(!data)return;const previous=nameBase.current;setName(current=>previous.account!==data.account_id||current===previous.value?data.display_name:current);nameBase.current={account:data.account_id,value:data.display_name};},[profile.data?.account_id,profile.data?.display_name]);
  async function perform(key:string,run:()=>Promise<void>) {if(operation.current)return;operation.current=true;setBusy(key);setError(undefined);setNotice('');try{await run();}catch(e){setError(e as Error);}finally{operation.current=false;setBusy('');}}
  const switchTo=(w:Workspace)=>{setWorkspace(w.workspace_id,w.role);setLink('');setRemove('');};
  return <div className="collaboration-page">
    <PageHeader title="工作区与成员" description="个人账号连接多个独立工作区；在共同项目中，让每个人的 Agent 一起协作。" actions={<Link className="button" to="/tutorial">个人网站教程</Link>}/>
    {(error||workspaces.error||profile.error)&&<ErrorNotice error={error||workspaces.error||profile.error}/>}
    {notice&&<p className="inline-success" role="status"><Check size={16}/>{notice}</p>}
    <div className="workspace-settings-grid">
      <Panel title="你的工作区">
        <div className="workspace-list">{workspaces.data?.map(w=><button key={w.workspace_id} aria-pressed={workspace?.workspace_id===w.workspace_id} onClick={()=>switchTo(w)}><Users size={18}/><span><strong>{w.name}</strong><small>{roleName(w.role)}</small></span>{workspace?.workspace_id===w.workspace_id&&<Check size={16}/>}</button>)}</div>
        <form className="compact-form" onSubmit={e=>{e.preventDefault();void perform('create',async()=>{if(createRequest.current.name!==newName.trim())createRequest.current={name:newName.trim(),id:crypto.randomUUID()};const w=await api.post<Workspace>('/workspaces',{name:newName},{idempotencyKey:createRequest.current.id});createRequest.current={name:'',id:''};switchTo(w);setNewName('');workspaces.reload();setNotice('工作区已创建');});}}>
          <Field label="新工作区名称"><input required maxLength={80} value={newName} onChange={e=>setNewName(e.target.value)} placeholder="例如：个人创作 / 产品团队"/></Field>
          <button disabled={!!busy||!newName.trim()} className="primary"><Plus size={15}/>{busy==='create'?'正在创建…':'创建工作区'}</button>
        </form>
      </Panel>
      <Panel title={workspace?.name||(workspaces.loading?'正在读取工作区':'协作工作区')} actions={workspace?<span>{roleName(workspace.role)}</span>:undefined}>
        {!workspaces.loading&&!workspaces.error&&!workspace&&<EmptyState title="还没有协作工作区" description="创建你的工作区，或通过协作者的邀请链接加入。你的个人账号仍可使用。"/>}
        {members.error&&<ErrorNotice error={members.error}/>}
        <EcpMembers members={members.data || []} currentAccountId={profile.data?.account_id} owner={workspace?.role==='OWNER'} busy={!!busy} soleOwner={soleOwner} remove={remove} onRemove={setRemove} onCancel={()=>setRemove('')} onRoleChange={(member, role)=>void perform('role',async()=>{await api.patch(`${base}/members/${member.account_id}`,{role});members.reload();workspaces.reload();setNotice('成员角色已更新');})} onConfirmRemove={member=>void perform('remove',async()=>{await api.patch(`${base}/members/${member.account_id}`,{role:null});setRemove('');members.reload();workspaces.reload();setNotice('成员已移除');})}/>
        {workspace?.role==='OWNER'&&members.data?.filter(m=>m.role==='OWNER').length===1&&<p className="panel-caption">工作区须保留一位所有者。退出或更改自己的角色前，请先将另一位成员设为所有者。</p>}
        {workspace&&workspace.role!=='OWNER'&&<>
          {!leaveConfirm?<button ref={leaveButton} type="button" className="leave-workspace" disabled={!!busy} onClick={()=>setLeaveConfirm(true)}>退出此工作区</button>:<div className="member-confirm" role="group" aria-label="确认退出工作区" onKeyDown={event=>{if(event.key==='Escape'&&!busy){event.stopPropagation();setLeaveConfirm(false);}}}>
            <p>退出后将失去此工作区的项目访问，你的 DSH 连接也会停用。再次加入需要协作者邀请。</p>
            <button type="button" disabled={!!busy} onClick={()=>void perform('leave',async()=>{await api.patch(`${base}/members/${profile.data?.account_id}`,{role:null});const list=await api.get<Workspace[]>('/workspaces');setLeaveConfirm(false);if(list[0])switchTo(list[0]);else setWorkspace('');workspaces.reload();setNotice('已退出工作区');})}>{busy==='leave'?'正在退出…':'确认退出工作区'}</button>
            <button ref={cancelLeave} type="button" disabled={!!busy} onClick={()=>setLeaveConfirm(false)}>取消退出</button>
          </div>}
        </>}
        {workspace?.role==='OWNER'&&<form className="compact-form invite-form" onSubmit={e=>{e.preventDefault();void perform('invite',async()=>{const result=await api.post<{invite_path:string}>(`${base}/invitations`,{role:inviteRole,email:inviteEmail||null});setLink(location.origin+result.invite_path);setCopied(false);invitations.reload();});}}>
          <h3>邀请协作者</h3><Field label="指定邮箱（可选）"><input type="email" value={inviteEmail} onChange={e=>setInviteEmail(e.target.value)} placeholder="不填写时，持链接的人可加入"/></Field>
          <Field label="加入后的角色"><select value={inviteRole} onChange={e=>setInviteRole(e.target.value)}><option value="EDITOR">编辑者 · 规划与通讯</option><option value="VIEWER">查看者 · 只读访问</option></select></Field>
          <button disabled={!!busy}><Link2 size={15}/>{busy==='invite'?'正在生成…':'生成邀请链接'}</button><small>7 天有效 · 单次加入 · 通过你选择的渠道分享</small>
          {link&&<div className="copy-invite"><input readOnly aria-label="邀请链接" value={link}/><button type="button" onClick={()=>void perform('copy',async()=>{await navigator.clipboard.writeText(link);setCopied(true);})}>{copied?'已复制':'复制链接'}</button></div>}
        </form>}
        {workspace?.role==='OWNER'&&<EcpInvitations invitations={invitations.data || []} busy={!!busy} onRevoke={invitation=>void perform('revoke',async()=>{await api.post(`${base}/invitations/${invitation.invitation_id}/revoke`);invitations.reload();setNotice('邀请已撤销');})}/>}
      </Panel>
    </div>
    <div className="workspace-settings-grid">
      <Panel title="个人资料"><form className="compact-form" onSubmit={e=>{e.preventDefault();void perform('profile',async()=>{await api.patch('/account',{name});profile.reload();setNotice('个人资料已保存');});}}><Field label="显示名称"><input required maxLength={80} value={name} onChange={e=>setName(e.target.value)}/></Field><p className="muted">{profile.data?.email}</p><button disabled={!!busy}>保存名称</button></form><button className="leave-workspace" onClick={()=>void perform('logout',async()=>{await api.post('/logout');setToken('');navigate('/portfolio');})}><LogOut size={15}/>退出账号</button></Panel>
      <Panel title="更新密码"><form className="compact-form" onSubmit={e=>{e.preventDefault();void perform('password',async()=>{const result=await api.post<{token:string}>('/account/password',{current_password:oldPassword,new_password:newPassword});renewAccountSession(result.token);setOldPassword('');setNewPassword('');setNotice('密码已更新；其他登录与 DSH 连接凭证已失效，请重新签发');});}}><Field label="当前密码"><input type="password" required autoComplete="current-password" value={oldPassword} onChange={e=>setOldPassword(e.target.value)}/></Field><Field label="新密码"><input type="password" required minLength={12} autoComplete="new-password" value={newPassword} onChange={e=>setNewPassword(e.target.value)}/></Field><button disabled={!!busy}><KeyRound size={15}/>更新密码</button></form></Panel>
    </div>
    <Panel title="外观与主题" className="appearance-settings-panel"><AppearanceControls/></Panel>
  </div>;
}
export function InvitePage() {
  const location=useLocation();const navigate=useNavigate();
  const [token,setTokenValue]=useState(()=>location.hash.slice(1));
  const [busy,setBusy]=useState(false);const [error,setError]=useState<Error>();
  return <><PageHeader title="加入协作工作区" description="接受邀请后，你可以按分配的角色与工作区成员、Agent 共同开展项目。"/><Panel title="工作区邀请"><form className="compact-form" onSubmit={e=>{e.preventDefault();if(busy)return;setBusy(true);setError(undefined);void api.post<{workspace_id:string}>('/invitations/accept',{token}).then(async result=>{const list=await api.get<Workspace[]>('/workspaces');const w=list.find(w=>w.workspace_id===result.workspace_id);if(w)setWorkspace(w.workspace_id,w.role);navigate('/workspaces',{replace:true});}).catch(e=>setError(e as Error)).finally(()=>setBusy(false));}}><Field label="邀请凭证"><input required value={token} type="password" onChange={e=>setTokenValue(e.target.value)} autoComplete="off"/></Field><button className="primary" disabled={busy}>{busy?'正在加入…':'接受邀请并加入'}</button>{error&&<ErrorNotice error={error}/>}</form></Panel><EmptyState title="邀请不适用？" description="链接可能已失效、撤销，或仅供指定邮箱使用。请联系邀请者重新生成。" action={<Link to="/portfolio">返回我的项目</Link>}/></>;
}
