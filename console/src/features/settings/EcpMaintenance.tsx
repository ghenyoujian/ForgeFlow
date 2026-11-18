import { Link } from "react-router-dom";
import { ArrowRight, Archive, ShieldCheck } from "lucide-react";
import { useApi } from "../../app/api";
import { RecoveryPage } from "../../app/UtilityPages";

type BackupReadiness = { ready?: boolean; scope_sha256?: string; projects?: unknown[]; blockers?: unknown[] };

/** Global maintenance entry point. RecoveryPage owns backup/restore commands. */
export function EcpMaintenance() {
  const readiness = useApi<BackupReadiness>("/backup-readiness");
  return <>
    <nav className="ecp-workbench-context" aria-label="发布与维护工作台">
      <span><Archive size={14} /> 发布与灾备</span>
      <Link to="/portfolio"><ShieldCheck size={14} />项目组合<ArrowRight size={12} /></Link>
      <span className={`ecp-workbench-readiness ${readiness.data?.ready === true ? "ready" : "unknown"}`}>
        备份条件：{readiness.data?.ready === true ? "已满足" : readiness.data?.ready === false ? "有阻塞" : "读取中"}
      </span>
      {readiness.data?.scope_sha256 && <code title="服务端备份范围摘要">范围 {readiness.data.scope_sha256.slice(0, 12)}…</code>}
    </nav>
    <RecoveryPage />
  </>;
}
