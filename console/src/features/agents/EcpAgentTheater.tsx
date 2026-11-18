import { Activity } from "lucide-react";
import { Panel } from "../../components";
import type { PageProps } from "../../app/types";
import { RunsPage } from "../runs";

export function EcpAgentTheater(props: PageProps) {
  return <><Panel title={<><Activity size={16} />Agent 运行视图</>}><p className="muted">执行器在线、消息 ACK、尝试处理和验证完成分别计量；没有回执时不会显示为 DONE。</p></Panel><RunsPage {...props} /></>;
}
