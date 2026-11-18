import { Panel } from "../../components";

export function EcpInspector({ projectId, taskId }: { projectId: string; taskId?: string }) {
  return <Panel title="统一任务 Inspector"><p className="muted">项目 <code>{projectId}</code> · 当前任务 <code>{taskId || "未选择"}</code>。详情、revision 和尝试状态由 Flow 页面按当前服务端快照读取。</p></Panel>;
}
