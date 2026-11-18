import { ArrowRight, FileCheck2, Link2, MessageSquare, ShieldCheck } from "lucide-react";
import { Link } from "react-router-dom";
import { ProjectJourney } from "./ProjectJourney";

/**
 * Shared ECP project journey shell.  ProjectJourney remains the canonical
 * navigation implementation; this component adds explicit links for the
 * requirement-to-evidence and collaboration paths without inventing state.
 */
export function EcpJourney({ projectId }: { projectId: string }) {
  const base = `/projects/${encodeURIComponent(projectId)}`;
  return (
    <div className="ecp-journey-shell" data-project-id={projectId}>
      <div className="ecp-journey-context" aria-label="ECP 项目审阅路径">
        <span><ShieldCheck size={14} /> 授权项目范围</span>
        <Link to={`${base}/requirements`}><FileCheck2 size={14} />需求 → 任务</Link>
        <Link to={`${base}/evidence`}><Link2 size={14} />任务 → 证据</Link>
        <Link to={`${base}/agent-network`}><MessageSquare size={14} />消息与协作</Link>
        <ArrowRight size={13} aria-hidden="true" />
      </div>
      <ProjectJourney projectId={projectId} />
    </div>
  );
}
