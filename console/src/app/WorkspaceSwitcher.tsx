import { useEffect } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { Users, BookOpen } from 'lucide-react';
import { api, getWorkspace, setWorkspace, useApi, setToken } from './api';
export interface Workspace {workspace_id:string; name:string; role:string}
export interface Account {account_id:string;display_name:string;email:string}
export function WorkspaceSwitcher({account,workspaces}:{account:Account;workspaces:Workspace[]}) {
  const navigate=useNavigate();
  const selected=workspaces.find(w=>w.workspace_id===getWorkspace())||workspaces[0];
  useEffect(()=>{
    if(selected && getWorkspace()!==selected.workspace_id) {if(getWorkspace())navigate('/portfolio');setWorkspace(selected.workspace_id,selected.role);}
    else if(selected && sessionStorage.getItem('forgeflow.workspace-role')!==selected.role) setWorkspace(selected.workspace_id,selected.role);
    else if(!selected && (getWorkspace()||sessionStorage.getItem('forgeflow.workspace-role'))) {navigate('/workspaces');setWorkspace('');}
  },[selected?.workspace_id,selected?.role]);
  return <div className="account-workspace-switcher">
    <label><Users size={15}/><select aria-label="切换协作工作区" value={selected?.workspace_id||''} disabled={!workspaces.length} onChange={event=>{
      const w=workspaces.find(w=>w.workspace_id===event.target.value);if(w){navigate('/portfolio');setWorkspace(w.workspace_id,w.role);}
    }}>{!workspaces.length&&<option value="">创建或加入工作区</option>}{workspaces.map(w=><option key={w.workspace_id} value={w.workspace_id}>{w.name}</option>)}</select></label>
    <div><Link to="/workspaces">{account.display_name} · 成员与设置</Link><Link to="/tutorial" aria-label="个人网站教程"><BookOpen size={15}/></Link></div>
    <span className="workspace-role">{!selected?'尚未加入工作区':selected.role==='VIEWER'?'查看者 · 只读':selected.role==='OWNER'?'工作区所有者':'编辑者'}</span>
  </div>;
}
export function AccountSettings() {
  const account=useApi<Account>('/account');
  const navigate=useNavigate();
  return <div className="account-summary"><span>{account.data?.display_name}</span><button onClick={async()=>{try{await api.post('/logout');}finally{setToken('');navigate('/portfolio');}}}>退出账号</button></div>;
}
