import { useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { RefreshCw, ShieldCheck, Users } from "lucide-react";
import { useApi, getWorkspace, setWorkspace } from "../../app/api";
import type { Workspace } from "../../app/WorkspaceSwitcher";
import {
  DataTable,
  Drawer,
  EmptyState,
  ErrorNotice,
  JsonView,
  PageHeader,
  Panel,
  QueryState,
  SourceStamp,
  StatusBadge,
} from "../../components";
import { EcpProfile } from "./EcpProfile";

type RecordValue = Record<string, unknown>;
type RegistrySnapshot = {
  agents?: RecordValue[];
  profiles?: RecordValue[];
  qualification?: string;
};

const object = (value: unknown): RecordValue =>
  value !== null && typeof value === "object" && !Array.isArray(value)
    ? (value as RecordValue)
    : {};
const list = (value: unknown): RecordValue[] =>
  Array.isArray(value) ? value.map(object) : [];
const text = (value: unknown) =>
  typeof value === "string" || typeof value === "number" ? String(value) : "—";
const id = (row: RecordValue, ...keys: string[]) =>
  text(keys.map(key => row[key]).find(value => value !== undefined && value !== null));

/**
 * Discovery-only Agent Registry/Profile view. A registry row is an immutable
 * identity snapshot; it does not imply that the executor is qualified to run.
 */
export function AgentRegistryPage() {
  const workspaces = useApi<Workspace[]>("/workspaces");
  const selectedWorkspace =
    workspaces.data?.find(workspace => workspace.workspace_id === getWorkspace()) ??
    workspaces.data?.[0];
  const workspaceId = selectedWorkspace?.workspace_id ?? "";
  const registry = useApi<RegistrySnapshot>(
    workspaceId ? `/workspaces/${encodeURIComponent(workspaceId)}/registry` : null,
  );
  const [selected, setSelected] = useState<RecordValue>();
  const agents = list(registry.data?.agents);
  const profiles = list(registry.data?.profiles);
  const registrations = useMemo(
    () => new Map(agents.map(agent => [text(agent.registration_id), agent])),
    [agents],
  );

  return (
    <div className="collaboration-page">
      <PageHeader
        title="Agent Registry / Profile"
        description="读取当前工作区的 Agent 身份和冻结执行器 Profile。登记声明与实际运行资格分离。"
        actions={
          <Link className="button" to="/executors">
            返回执行器探测
          </Link>
        }
      />
      {workspaces.error && <ErrorNotice error={workspaces.error} onRetry={workspaces.reload} />}
      {!workspaces.loading && !workspaces.error && !selectedWorkspace && (
        <EmptyState
          title="还没有可用工作区"
          description="先创建或加入协作工作区，再登记 Agent 身份。"
          action={<Link className="button" to="/workspaces">打开工作区与成员</Link>}
        />
      )}
      {selectedWorkspace && (
        <>
          <Panel title="工作区范围" actions={<button type="button" onClick={registry.reload} aria-label="刷新 Agent Registry"><RefreshCw size={15} /></button>}>
            <div className="panel-body">
              <label className="field">
                <span>读取工作区</span>
                <select
                  value={workspaceId}
                  onChange={event => {
                    const next = workspaces.data?.find(item => item.workspace_id === event.target.value);
                    if (next) setWorkspace(next.workspace_id, next.role);
                  }}
                >
                  {workspaces.data?.map(workspace => (
                    <option key={workspace.workspace_id} value={workspace.workspace_id}>
                      {workspace.name} · {workspace.role}
                    </option>
                  ))}
                </select>
                <small>读取需要有效成员身份；登记和 Profile 冻结仍由服务端 Owner 权限控制。</small>
              </label>
            </div>
          </Panel>
          <QueryState loading={registry.loading && !registry.data} error={registry.error} onRetry={registry.reload}>
            <div className="settings-grid">
              <Panel title={<><Users size={16} />Agent 登记 ({agents.length})</>}>
                <DataTable
                  rows={agents}
                  rowKey={row => id(row, "registration_id", "principal_id")}
                  onRowClick={setSelected}
                  empty={<EmptyState title="尚无 Agent 登记" description="登记是发现记录，不会单独授予项目或执行权限。" />}
                  columns={[
                    { key: "display_name", label: "名称", render: row => <><strong>{text(row.display_name)}</strong><small>{id(row, "registration_id")}</small></> },
                    { key: "principal_id", label: "Principal", render: row => id(row, "principal_id") },
                    { key: "executor_kinds", label: "执行器类型", render: row => Array.isArray(row.executor_kinds) ? row.executor_kinds.join("、") : "—" },
                    { key: "status", label: "登记状态", render: row => <StatusBadge state={text(row.status)} /> },
                  ]}
                />
              </Panel>
              <Panel title={<>冻结 Executor Profile ({profiles.length})</>}>
                <EcpProfile profiles={profiles} registrations={registrations} onSelect={setSelected} />
              </Panel>
            </div>
            <Panel title={<><ShieldCheck size={16} />资格边界</>}>
              <div className="panel-body">
                <p className="muted">当前 Registry 快照的资格语义：<StatusBadge state={text(registry.data?.qualification ?? "discovery_only")} />。Profile 的 provider、版本、能力和摘要用于准入比较；没有当前探测或尝试回执时，能力仍为 UNKNOWN / NOT_RUN。</p>
                <p className="muted">登记总数：{agents.length} · Profile 总数：{profiles.length} · 当前工作区：{workspaceId}</p>
              </div>
            </Panel>
            <SourceStamp source={registry.metadata.source} observedAt={registry.metadata.observed_at} />
          </QueryState>
        </>
      )}
      {selected && (
        <Drawer title={text(selected.display_name ?? selected.profile_id ?? selected.registration_id)} onClose={() => setSelected(undefined)}>
          <p className="muted">这是服务端 Registry 快照的详细记录。修改、撤销和执行准入走对应命令接口；此页只读。</p>
          <JsonView value={selected} />
        </Drawer>
      )}
    </div>
  );
}
