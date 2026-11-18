import { Link } from "react-router-dom";
import { ArrowRight, CircleAlert, FileCheck2, ShieldCheck } from "lucide-react";
import { useApi } from "../../app/api";
import { ReleasesPage } from "../../app/ReleasesPage";

type ProjectIdentity = { project_id: string; name?: string; revision?: number; archived?: boolean; paused?: boolean };

/** Release manifest entry point; ReleasesPage remains the canonical manifest API consumer. */
export function EcpRelease({ projectId, releaseId }: { projectId?: string; releaseId?: string }) {
  const project = useApi<ProjectIdentity>(projectId ? `/projects/${encodeURIComponent(projectId)}` : null);
  const base = projectId ? `/projects/${encodeURIComponent(projectId)}` : "/portfolio";
  const identityMatches = !!project.data && project.data.project_id === projectId;
  return <>
    {projectId && <nav className="ecp-workbench-context" aria-label="项目发布工作台">
      <span><FileCheck2 size={14} /> {identityMatches ? project.data?.name || projectId : projectId}</span>
      <span className="ecp-workbench-revision">项目版本 {identityMatches ? project.data?.revision ?? "未知" : "读取中"}</span>
      <Link to={`${base}/evidence`}><ShieldCheck size={14} />证据收据<ArrowRight size={12} /></Link>
      <Link to="/recovery"><CircleAlert size={14} />维护与恢复<ArrowRight size={12} /></Link>
      {(project.data?.archived || project.data?.paused) && <span className="ecp-workbench-warning">{project.data.archived ? "项目已归档" : "项目暂停新增"}</span>}
    </nav>}
    <ReleasesPage projectId={projectId} releaseId={releaseId} />
  </>;
}
