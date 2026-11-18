import { Link } from "react-router-dom";
import { GitBranch, ShieldCheck } from "lucide-react";
import { Panel } from "../../components";
import type { PageProps } from "../../app/types";
import { FlowPage } from "./index";

export function EcpDag(props: PageProps) {
  return <><Panel title={<><GitBranch size={16} />Flow DAG 与任务 Inspector</>}><p className="muted">DAG 数据来自当前项目 Flow revision；非法环、旧 revision 与执行资格仍由控制面检查。<Link to={`/projects/${encodeURIComponent(props.projectId || "")}/tasks`}>打开任务列表</Link> <ShieldCheck size={13} /></p></Panel><FlowPage {...props} /></>;
}
