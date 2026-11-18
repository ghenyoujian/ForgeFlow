import { Link2 } from "lucide-react";

export type EcpInvitation = { invitation_id: string; role: string; invited_email?: string; expires_at: string; accepted_by?: string; revoked_at?: string };
const roleName = (role: string) => role === "EDITOR" ? "编辑者" : "查看者";

export function EcpInvitations({ invitations, busy, onRevoke }: { invitations: EcpInvitation[]; busy: boolean; onRevoke: (invitation: EcpInvitation) => void }) {
  const active = invitations.filter(invitation => !invitation.revoked_at && !invitation.accepted_by);
  if (!active.length) return <p className="panel-caption"><Link2 size={14} />暂无未使用邀请；邀请接受或撤销后会保留为历史记录。</p>;
  return <details className="invitation-history"><summary>管理已生成的邀请（{active.length}）</summary>{active.map(invitation => <div key={invitation.invitation_id}><span>{invitation.invited_email || "链接邀请"} · {roleName(invitation.role)}<small>有效至 {new Date(invitation.expires_at).toLocaleString()}</small></span><button type="button" disabled={busy} onClick={() => onRevoke(invitation)}>撤销</button></div>)}</details>;
}
