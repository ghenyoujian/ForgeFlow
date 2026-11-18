import { Users } from "lucide-react";

export type EcpMember = { account_id: string; display_name: string; role: string };
const roleName = (role: string) => role === "OWNER" ? "所有者" : role === "EDITOR" ? "编辑者" : "查看者";

export function EcpMembers({ members, currentAccountId, owner, busy, soleOwner, onRoleChange, onRemove, remove, onCancel, onConfirmRemove }: {
  members: EcpMember[];
  currentAccountId?: string;
  owner: boolean;
  busy: boolean;
  soleOwner: (member: EcpMember) => boolean;
  onRoleChange: (member: EcpMember, role: string) => void;
  onRemove: (accountId: string) => void;
  remove?: string;
  onCancel: () => void;
  onConfirmRemove: (member: EcpMember) => void;
}) {
  return <div className="member-list" aria-label="工作区成员">
    {members.map(member => <div className="member-row" key={member.account_id}>
      <span className="member-avatar"><Users size={14} /></span>
      <span><strong>{member.display_name}{member.account_id === currentAccountId ? "（你）" : ""}</strong><small>{roleName(member.role)}</small></span>
      {owner && <><select aria-label={`调整 ${member.display_name} 的角色`} title={soleOwner(member) ? "请先将另一位成员设为所有者" : undefined} value={member.role} disabled={busy || soleOwner(member)} onChange={event => onRoleChange(member, event.target.value)}><option value="OWNER">所有者</option><option value="EDITOR">编辑者</option><option value="VIEWER">查看者</option></select><button type="button" disabled={busy || soleOwner(member)} onClick={() => onRemove(member.account_id)}>移除</button></>}
      {remove === member.account_id && <div className="member-confirm" role="group" aria-label="确认移除成员"><p>移除后，该成员的项目访问和 DSH 连接会撤销。</p><button type="button" disabled={busy} onClick={() => onConfirmRemove(member)}>确认移除</button><button type="button" onClick={onCancel}>取消</button></div>}
    </div>)}
  </div>;
}
