import { CalendarDays } from "lucide-react";
import type { PageProps } from "../../app/types";
import { Panel } from "../../components";
import { TimelinePage } from "./index";

export function EcpGantt(props: PageProps) {
  return <><Panel title={<><CalendarDays size={16} />Gantt / 里程碑</>}><p className="muted">排程读取真实服务端 revision；拖动或接受里程碑前必须回读当前版本，冲突保持可见。</p></Panel><TimelinePage {...props} /></>;
}
