import { MessageSquare, ShieldCheck } from "lucide-react";
import { Panel } from "../../components";
import { EcpConversation } from "./EcpConversation";

export function EcpHub({ conversationId, threadId }: { conversationId: string; threadId?: string }) {
  return <><Panel title={<><MessageSquare size={16} />协作中心</>}><p className="muted"><ShieldCheck size={13} /> ACK、processing、DONE 和验证状态分开显示；取消与 resume 只有服务端能力可用时才出现。</p></Panel><EcpConversation conversationId={conversationId} threadId={threadId || ""} /></>;
}
