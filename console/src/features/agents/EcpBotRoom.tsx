import { Bot, CircleHelp } from "lucide-react";
import { Link } from "react-router-dom";
import { Panel, StatusBadge } from "../../components";

export function EcpBotRoom() {
  return <div className="collaboration-page"><Panel title={<><Bot size={16} />Bot Room</>}><p>Bot 唤醒必须绑定已授权的消息、workspace 和 generation；任意自然语言不会自动获得写权限。</p><p><StatusBadge state="NOT_RUN" /> 双 Provider 原生联调尚未绑定当前授权执行器，保留为 NOT_RUN。</p><p className="muted"><CircleHelp size={14} /> 先在 <Link to="/executors/registry">Agent Registry</Link> 检查身份和 Profile，再进入 <Link to="/runs">执行大厅</Link>。</p></Panel></div>;
}
