import { useState } from "react";
import { useSearchParams } from "react-router-dom";
import { Boxes, Cpu, Network, RefreshCw, ShieldCheck } from "lucide-react";
import { useApi, useCursorApi } from "./api";
import type { ProjectRef } from "./types";
import { DataTable, Drawer, EmptyState, Field, JsonView, Pagination, Panel, QueryState, SourceStamp, StatusBadge } from "../components";
import { CapsulePolicies } from "./CapsulePolicies";
import { NativeConfigurationEditor } from "./NativeConfigurationEditor";

type RecordValue = Record<string, unknown>;
const object = (value: unknown): RecordValue => value !== null && typeof value === "object" && !Array.isArray(value) ? value as RecordValue : {};
const list = (value: unknown): RecordValue[] => Array.isArray(value) ? value.map(object) : [];
const text = (value: unknown) => typeof value === "string" || typeof value === "number" ? String(value) : "—";
const rowId = (value: RecordValue) => text(value.id ?? value.route_id ?? value.model_route_id ?? value.scope_id ?? value.team_id ?? value.operation_id);

export function ExecutorSettings() {
  const [params, setParams] = useSearchParams();
  const projectId = params.has("catalog_project") ? params.get("catalog_project") || "" : localStorage.getItem("forgeflow.project") || "";
  const projects = useCursorApi<ProjectRef[]>("/projects", "executor_project_cursor");
  const executors = useApi<unknown>("/executors");
  const resources = useApi<unknown>("/resource-usage");
  const projectRoot = projectId ? `/projects/${encodeURIComponent(projectId)}` : null;
  const routes = useCursorApi<unknown>(projectRoot ? `${projectRoot}/documents/model_routes` : null, "model_cursor");
  const profiles = useCursorApi<unknown>(projectRoot ? `${projectRoot}/documents/resource_profiles` : null, "resource_profile_cursor");
  const teams = useCursorApi<unknown>(projectRoot ? `${projectRoot}/teams` : null, "executor_team_cursor");
  const operations = useCursorApi<unknown>(projectRoot ? `${projectRoot}/documents/operations` : null, "executor_operation_cursor");
  const [selected, setSelected] = useState<RecordValue>();
  const registered = list(executors.data).filter(row => !projectId || row.project_id === projectId);
  const policies = list(object(resources.data).policies).filter(row => !projectId || !row.project_id || row.project_id === projectId);
  const doctorOperations = list(operations.data).filter(row => row.kind === "EXECUTOR_DOCTOR");
  function chooseProject(value: string) {
    const next = new URLSearchParams(params);
    next.set("catalog_project", value);
    for (const key of ["model_cursor", "resource_profile_cursor", "executor_team_cursor", "executor_operation_cursor"]) next.delete(key);
    setSelected(undefined);
    setParams(next);
  }
  return <>
    <NativeConfigurationEditor key={`offline-${projectId || "no-project"}`} projectId={projectId || undefined} />
    <Panel title={<><Cpu size={16} />执行环境目录</>} actions={<a className="button" href="/executors">执行器探测</a>}>
      <div className="panel-body">
        <p className="muted">查看已登记的运行配置及其模型、资源和团队约束。选择项目仅切换查看范围；执行绑定由任务配置和服务端准入决定。</p>
        <QueryState loading={projects.loading && !projects.data} error={projects.error} onRetry={projects.reload}>
          <Field label="查看执行项目"><select value={projectId} onChange={event => chooseProject(event.target.value)}>
            <option value="">选择项目查看关联配置</option>
            {projects.data?.map(project => <option key={project.project_id ?? project.id} value={project.project_id ?? project.id}>{project.name} · {project.project_id ?? project.id}</option>)}
            {projectId && !projects.data?.some(project => (project.project_id ?? project.id) === projectId) && <option value={projectId}>{projectId} · 不在当前项目页</option>}
          </select></Field>
          <Pagination query={projects} count={projects.data?.length ?? 0} />
        </QueryState>
      </div>
      <QueryState loading={executors.loading && !executors.data} error={executors.error} onRetry={executors.reload}>
        <DataTable rows={registered} rowKey={row => `${text(row.project_id)}:${rowId(object(row.profile))}`} onRowClick={setSelected} empty={<EmptyState title="当前范围没有返回执行器登记" description="登记和探测资格各自读取；没有登记不代表可用。" />} columns={[
          { key: "name", label: "运行配置", render: row => <><strong>{text(object(row.profile).profile_name)}</strong><small>{rowId(object(row.profile))}</small></> },
          { key: "project_id", label: "项目" },
          { key: "model", label: "模型路由", render: row => text(object(row.profile).model_route_id) },
          { key: "qualification", label: "探测资格", render: row => <StatusBadge state={typeof row.qualification === "string" ? row.qualification : "INCONCLUSIVE"} /> },
          { key: "mode", label: "Agent 预设 / 工作模式", render: row => <>{text(object(row.profile).agent_preset)} / {text(object(row.profile).work_mode)}<small>未返回的能力保持未知</small></> },
        ]} />
      </QueryState>
      <SourceStamp source={executors.metadata.source} observedAt={executors.metadata.observed_at} />
    </Panel>
    <CapsulePolicies key={projectId || "no-project"} projectId={projectId || undefined}
      executorProfileIds={registered.map(row => object(row.profile).id).filter((value): value is string => typeof value === "string")}
      resourceProfileIds={list(profiles.data).map(row => row.id).filter((value): value is string => typeof value === "string")}
      modelRouteIds={list(routes.data).map(row => row.id).filter((value): value is string => typeof value === "string")} />
    <div className="settings-grid">
      <Panel title={<><Network size={16} />模型与资源配置</>}>
        {!projectRoot ? <EmptyState title="选择项目读取模型和资源绑定" /> : <>
          <div className="section-heading panel-body"><h3>模型路由</h3><button onClick={routes.reload} aria-label="刷新模型路由"><RefreshCw size={14} /></button></div>
          <QueryState loading={routes.loading && !routes.data} error={routes.error} onRetry={routes.reload}>
            <DataTable rows={list(routes.data)} rowKey={rowId} columns={[{ key: "id", label: "路由", render: row => rowId(row) }, { key: "binding", label: "登记内容", render: row => <details><summary>查看路由约束</summary><JsonView value={row} /></details> }]} />
            <Pagination query={routes} count={list(routes.data).length} />
          </QueryState>
          <SourceStamp source={routes.metadata.source} observedAt={routes.metadata.observed_at} />
          <div className="section-heading panel-body"><h3>资源 Profile</h3></div>
          <QueryState loading={profiles.loading && !profiles.data} error={profiles.error} onRetry={profiles.reload}>
            <DataTable rows={list(profiles.data)} rowKey={rowId} columns={[{ key: "id", label: "配置", render: row => rowId(row) }, { key: "constraints", label: "资源约束", render: row => <details><summary>查看已登记约束</summary><JsonView value={row} /></details> }]} />
            <Pagination query={profiles} count={list(profiles.data).length} />
          </QueryState>
          <SourceStamp source={profiles.metadata.source} observedAt={profiles.metadata.observed_at} />
        </>}
      </Panel>
      <Panel title={<><ShieldCheck size={16} />资源策略与团队</>}>
        <QueryState loading={resources.loading && !resources.data} error={resources.error} onRetry={resources.reload}>
          <DataTable rows={policies} rowKey={rowId} columns={[
            { key: "scope_id", label: "作用域" },
            { key: "ownership", label: "绑定", render: row => <>{row.worker_id ? `Worker ${text(row.worker_id)}` : row.team_id ? `团队 ${text(row.team_id)}` : row.project_id ? `项目 ${text(row.project_id)}` : "全局"}<small>父作用域 {text(row.parent_scope_id)}</small></> },
            { key: "limits", label: "预算", render: row => <details><summary>查看资源上限</summary><JsonView value={row.limits} /></details> },
            { key: "paused", label: "暂停新增", render: row => row.paused === true ? "是" : row.paused === false ? "否" : "未知" },
          ]} />
          <p className="source-stamp">跨项目策略分时读取；观察向量及完整返回值可在资源中心核对。</p>
        </QueryState>
        <SourceStamp source={resources.metadata.source} observedAt={resources.metadata.observed_at} />
        {projectRoot && <QueryState loading={teams.loading && !teams.data} error={teams.error} onRetry={teams.reload}>
          <div className="section-heading panel-body"><h3>项目团队</h3><a href={`/projects/${encodeURIComponent(projectId)}/teams`}>打开团队与队列</a></div>
          <DataTable rows={list(teams.data)} rowKey={rowId} columns={[{ key: "name", label: "团队" }, { key: "team_id", label: "身份" }, { key: "parent_team_id", label: "父团队", render: row => text(row.parent_team_id) }]} />
          <Pagination query={teams} count={list(teams.data).length} />
        </QueryState>}
      </Panel>
    </div>
    <Panel title={<><Boxes size={16} />能力与启动诊断</>}>
      <div className="panel-body"><p className="muted">上方离线工作台读取项目固定配置中的预设、配套插件与岗位绑定。插件登记、离线校验和真实协作资格分别记录；运行能力仍以探测与尝试回执为准。</p></div>
      {projectRoot && <QueryState loading={operations.loading && !operations.data} error={operations.error} onRetry={operations.reload}>
        <DataTable rows={doctorOperations} rowKey={rowId} empty={<EmptyState title="当前操作页没有执行器探测回执" description="不据此推断没有启动失败；尝试工作台保留各次真实尝试的原因和日志。" />} columns={[
          { key: "executor_profile_id", label: "运行配置" }, { key: "status", label: "操作", render: row => <StatusBadge state={text(row.status)} scope="operation" /> },
          { key: "report", label: "真实回执", render: row => <details><summary>查看探测结果</summary><JsonView value={row} /></details> },
        ]} />
        <Pagination query={operations} count={list(operations.data).length} />
      </QueryState>}
    </Panel>
    {selected && <Drawer title={text(object(selected.profile).profile_name)} onClose={() => setSelected(undefined)}>
      <StatusBadge state={typeof selected.qualification === "string" ? selected.qualification : "INCONCLUSIVE"} />
      <p className="muted">这里回读已登记配置。Profile 中的验证布尔值是登记声明；实际能力和启动结果仍以探测或尝试回执为准。</p>
      <JsonView value={selected} />
      <a className="button" href={`/runs?project=${encodeURIComponent(text(selected.project_id))}`}>查看该项目真实尝试</a>
    </Drawer>}
  </>;
}
