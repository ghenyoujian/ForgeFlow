import { useState } from "react";
import { Network, Users, Plus, Pause, Play } from "lucide-react";
import { api, useApi,useWorkspaceWritable } from "../../app/api";
import { UnknownMetric } from "../portfolio/metrics";
import { useCollection } from "../portfolio/collection";
import { useCommandIdentity } from "../portfolio/commands";
import { OwnerTerritories } from "./OwnerTerritories";
import { AgentTeamWorkspace } from "./AgentTeamWorkspace";
import { AgentCapacity } from "./AgentCapacity";
import { planningWorkbenchEnabled } from "../../app/feature-flags";
import { DeliveryTeams } from "./DeliveryTeams";
import type { PageProps } from "../../app/types";
import {
  PageHeader,
  Panel,
  EmptyState,
  ErrorNotice,
  StatusBadge,
  DataTable,
  JsonView,
  Field,
  Drawer,
} from "../../components";
import {
  rows,
  object,
  str,
  id,
  path,
  num,
  errorMessage,
  type Row,
} from "../portfolio/monitor";

export function TeamsPage({ projectId }: PageProps) {
  const isDeliveryProject = Boolean(projectId);
  const [workspaceView, setWorkspaceView] = useState(planningWorkbenchEnabled() ? "agent" : "delivery");
  const legacyData = workspaceView !== "agent";
  const commandIdentity = useCommandIdentity();
  const [creationId, setCreationId] = useState(() => crypto.randomUUID());
  const projectQuery = useApi<unknown>(
    projectId ? `/projects/${path(projectId)}` : null,
  );
  const writable = useWorkspaceWritable() && object(projectQuery.data).authority_mode === "MANAGED";
  const teamsQ = useApi<unknown>(
    projectId && legacyData ? `/projects/${path(projectId)}/teams` : null,
  );
  const tasksQ = useApi<unknown>(
    projectId && legacyData ? `/projects/${path(projectId)}/tasks` : null,
  );
  const resourcesQ = useApi<unknown>(legacyData ? "/resources" : null);
  const snapshotQuery = useApi<unknown>(
    projectId && legacyData ? `/projects/${path(projectId)}/snapshot` : null,
  );
  const queueQuery = useCollection<Row>(
    projectId && legacyData ? `/projects/${path(projectId)}/queue-entries` : null,
  );
  const [selected, setSelected] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string>();
  const [name, setName] = useState("");
  const [capacity, setCapacity] = useState("");
  const [selectedTask, setSelectedTask] = useState<Row>();
  const [queuePriority, setQueuePriority] = useState("");
  const selectedQueue = rows(queueQuery.data).find(
    (entry) => entry.task_id === selectedTask?.task_id,
  );
  const snapshot = object(snapshotQuery.data);
  const teams = rows(snapshot.teams ?? teamsQ.data);
  const tasks = rows(snapshot.tasks ?? tasksQ.data);
  const partialTopology =
    !Array.isArray(snapshot.teams) && Boolean(teamsQ.metadata.next_cursor);
  const partialTasks =
    !Array.isArray(snapshot.tasks) && Boolean(tasksQ.metadata.next_cursor);
  const current = teams.find((t) => id(t) === selected);
  const policies = rows(object(resourcesQ.data).policies ?? resourcesQ.data);
  const policy = policies.find((p) => p.team_id === selected);
  function effectiveCapacity(): number | undefined {
    if (!policy) return;
    let currentPolicy: Row | undefined = policy;
    let effective = Infinity;
    const seen = new Set<string>();
    while (currentPolicy) {
      const scopeId = str(currentPolicy.scope_id);
      if (seen.has(scopeId)) return;
      seen.add(scopeId);
      const limit = num(object(currentPolicy.limits).active_slot);
      if (limit === undefined) return;
      effective = Math.min(effective, limit);
      if (!currentPolicy.parent_scope_id) return effective;
      currentPolicy = policies.find(
        (p) => p.scope_id === currentPolicy?.parent_scope_id,
      );
    }
    return undefined;
  }
  const matchingAllocations = rows(
    object(snapshotQuery.data).allocations,
  ).filter(
    (a) =>
      a.scope_id === policy?.scope_id &&
      a.dimension === "active_slot" &&
      a.state !== "RELEASED",
  );
  const occupied =
    policy &&
    snapshotQuery.data !== undefined &&
    matchingAllocations.every((a) => num(a.amount) !== undefined)
      ? matchingAllocations.reduce((sum, a) => sum + Number(a.amount), 0)
      : undefined;
  function descendants(teamId: string, seen = new Set<string>()): Set<string> {
    if (seen.has(teamId)) return seen;
    seen.add(teamId);
    for (const child of teams.filter((t) => t.parent_team_id === teamId))
      descendants(id(child), seen);
    return seen;
  }
  const subtree = selected ? descendants(selected) : new Set<string>();
  const queue = selected
    ? tasks.filter((t) => subtree.has(str(t.team_id, "")))
    : tasks;
  function ancestors(t: Row): Row[] {
    const result: Row[] = [];
    const seen = new Set<string>();
    let cursor = t;
    while (cursor.parent_team_id) {
      const parent = teams.find((v) => id(v) === cursor.parent_team_id);
      if (!parent || seen.has(id(parent))) break;
      seen.add(id(parent));
      result.push(parent);
      cursor = parent;
    }
    return result;
  }
  function pauseReasons(team: Row): string[] {
    const lineage = [team, ...ancestors(team)];
    const reasons = lineage.filter((t) => t.paused).map((t) => str(t.name));
    if (object(projectQuery.data).paused) reasons.unshift("项目暂停");
    const teamIds = new Set(lineage.map(id));
    for (const policy of policies.filter(
      (p) => p.paused && teamIds.has(str(p.team_id)),
    ))
      reasons.push(`资源策略 ${str(policy.scope_id)}`);
    return reasons;
  }
  async function command(kind: "pause" | "capacity" | "create") {
    setBusy(true);
    setError(undefined);
    try {
      if (kind === "pause" && current) {
        const route = `/projects/${path(projectId ?? "")}/teams/${path(selected)}`;
        const body = {
          team: { ...current, paused: !current.paused },
          expected_revision: current.revision,
        };
        await api.patch(route, body, {
          ...commandIdentity(route, body),
          expectedRevision: num(current.revision),
        });
      }
      if (kind === "capacity" && policy) {
        const route = `/projects/${path(projectId ?? "")}/resources`;
        const body = {
          policy: {
            ...policy,
            limits: { ...object(policy.limits), active_slot: Number(capacity) },
          },
          expected_revision: policy.revision,
        };
        await api.post(route, body, commandIdentity(route, body));
      }
      if (kind === "create") {
        const route = `/projects/${path(projectId ?? "")}/teams`;
        const body = {
          project_id: projectId,
          team_id: creationId,
          name,
          parent_team_id: selected || null,
          paused: false,
          revision: 0,
        };
        await api.post(route, body, commandIdentity(route, body));
        setCreationId(crypto.randomUUID());
      }
      teamsQ.reload();
      resourcesQ.reload();
      snapshotQuery.reload();
      setName("");
    } catch (e) {
      setError(errorMessage(e));
    } finally {
      setBusy(false);
    }
  }
  async function updatePriority() {
    if (!selectedTask || !selectedQueue) return;
    setBusy(true);
    setError(undefined);
    try {
      const route = `/projects/${path(projectId ?? "")}/queue-entries/${path(str(selectedTask.task_id))}`;
      const body = {
        priority: Number(queuePriority),
        expected_revision: selectedQueue.revision,
      };
      await api.patch(route, body, {
        ...commandIdentity(route, body),
        expectedRevision: num(selectedQueue.revision),
      });
      queueQuery.reload();
    } catch (e) {
      setError(errorMessage(e));
    } finally {
      setBusy(false);
    }
  }
  function branch(
    parent: string | null,
    depth = 0,
    seen = new Set<string>(),
  ): React.ReactNode {
    return teams
      .filter((t) => (t.parent_team_id ?? null) === parent)
      .map((t) => {
        const key = id(t);
        if (seen.has(key)) return <p key={key}>团队循环：{key}</p>;
        const next = new Set(seen);
        next.add(key);
        const inherited = pauseReasons(t);
        return (
          <li key={key}>
            <button
              className={selected === key ? "tree-item selected" : "tree-item"}
              style={{ paddingLeft: 12 + depth * 16 }}
              onClick={() => setSelected(key)}
              aria-pressed={selected === key}
            >
              <span aria-hidden="true">{depth === 0 ? "◈" : "↳"}</span>{" "}
              {str(t.name)}{" "}
              <StatusBadge
                state={inherited.length ? "暂停新增" : "无已知暂停"}
              />
              <small>
                直属 {tasks.filter((k) => k.team_id === key).length} · 子树{" "}
                {
                  tasks.filter((k) => descendants(key).has(str(k.team_id, "")))
                    .length
                }
              </small>
            </button>
            {depth < 30 && <ul role="group">{branch(key, depth + 1, next)}</ul>}
          </li>
        );
      });
  }
  return (
    <>
      <PageHeader
        title="Agent Teams 与交付"
        description="完整任务目录、专业岗位、DSH 插件与预设、真实会话和受控集成。"
      />
      {projectId && planningWorkbenchEnabled() && <AgentCapacity key={projectId} projectId={projectId} />}
      {projectId && isDeliveryProject && <div className="delivery-tabs" aria-label="团队工作区">
        {planningWorkbenchEnabled() && <button type="button" aria-pressed={workspaceView === "agent"} onClick={() => setWorkspaceView("agent")}>岗位与任务</button>}
        <button type="button" aria-pressed={workspaceView === "delivery"} onClick={() => setWorkspaceView("delivery")}>交付工作区</button>
        <button type="button" aria-pressed={workspaceView === "governance"} onClick={() => setWorkspaceView("governance")}>团队治理与队列</button>
      </div>}
      {teamsQ.error && (
        <ErrorNotice error={teamsQ.error} onRetry={teamsQ.reload} />
      )}{" "}
      {!projectId ? (
        <EmptyState title="请选择项目" />
      ) : workspaceView === "agent" ? <AgentTeamWorkspace key={projectId} projectId={projectId} /> : isDeliveryProject && workspaceView === "delivery" ? (
        <DeliveryTeams key={projectId} projectId={projectId} />
      ) : (
        <div className="workspace-grid">
          <Panel
            title={
              <>
                <Network size={16} />
                责任树
              </>
            }
          >
            {(partialTopology || partialTasks) && (
              <p role="status">
                当前是分页加载的局部团队／任务记录，子树数字仅统计已加载范围；完整权威快照尚未取得。
              </p>
            )}
            {teamsQ.loading && !teamsQ.data ? (
              <p>读取团队…</p>
            ) : teamsQ.error && teamsQ.data === undefined ? (
              <p>团队来源不可读，请重试。</p>
            ) : teams.length ? (
              <ul className="team-tree" role="tree">
                {branch(null)}
              </ul>
            ) : (
              <EmptyState
                title="尚无团队"
                description="创建团队前先登记项目与合法写领域。"
              />
            )}
            <Field label="新团队名称">
              <input value={name} onChange={(e) => setName(e.target.value)} />
            </Field>
            <button
              disabled={busy || !name || !writable}
              onClick={() => void command("create")}
            >
              <Plus size={14} />
              创建{selected ? "子" : "根"}团队
            </button>
          </Panel>
          <Panel title={current ? str(current.name) : "选择团队查看队列"}>
            {current && (
              <>
                <div className="toolbar">
                  <button
                    disabled={busy || !writable}
                    title="修改团队暂停策略；子树继承全部祖先限制"
                    onClick={() => void command("pause")}
                  >
                    {current.paused ? <Play size={14} /> : <Pause size={14} />}{" "}
                    {current.paused ? "解除本团队暂停" : "暂停子树新增"}
                  </button>
                  <span className="muted">暂停不会伪造当前尝试的停止结果</span>
                </div>
                <dl>
                  <dt>稳定身份</dt>
                  <dd>{selected}</dd>
                  <dt>暂停来源</dt>
                  <dd>
                    {pauseReasons(current).join(" / ") ||
                      "无已知暂停；仍需联合检查祖先预算"}
                  </dd>
                  <dt>配置容量 / 祖先有效上限 / 保留占用</dt>
                  <dd>
                    {str(object(policy?.limits).active_slot, "—")} /{" "}
                    {effectiveCapacity() === undefined ? (
                      <UnknownMetric description="资源策略祖先链未完整返回，有效配置上限保持未知" />
                    ) : (
                      effectiveCapacity()
                    )}{" "}
                    /{" "}
                    {occupied === undefined ? (
                      <UnknownMetric description="实际保留占用需要权威快照；停止未确认与隔离分配仍计入" />
                    ) : (
                      occupied
                    )}
                  </dd>
                </dl>
                {policy && writable && (
                  <div className="toolbar">
                    <Field label="活动槽位配置">
                      <input
                        type="number"
                        min="0"
                        step="1"
                        value={capacity}
                        onChange={(e) => setCapacity(e.target.value)}
                      />
                    </Field>
                    <button
                      disabled={
                        busy ||
                        !capacity ||
                        !Number.isSafeInteger(Number(capacity)) ||
                        Number(capacity) < 0
                      }
                      onClick={() => void command("capacity")}
                    >
                      保存容量策略
                    </button>
                  </div>
                )}
                <JsonView value={current} />
              </>
            )}
            {error && <p role="alert">{error}</p>}
            {tasksQ.error && (
              <ErrorNotice error={tasksQ.error} onRetry={tasksQ.reload} />
            )}
            {tasksQ.error && tasksQ.data === undefined ? (
              <p className="muted">队列数据尚无法读取，没有可靠快照。</p>
            ) : tasksQ.loading && tasksQ.data === undefined ? (
              <p role="status">正在读取队列…</p>
            ) : (
              <>
                <DataTable<Row>
                  rows={queue}
                  rowKey={id}
                  onRowClick={(task) => {
                    setSelectedTask(task);
                    setQueuePriority(
                      str(
                        rows(queueQuery.data).find(
                          (entry) => entry.task_id === task.task_id,
                        )?.priority,
                        "",
                      ),
                    );
                  }}
                  empty="该子树没有任务"
                  columns={[
                    {
                      key: "title",
                      label: "任务",
                      render: (t) => (
                        <a
                          href={`/projects/${path(projectId)}/tasks/${path(id(t))}`}
                        >
                          {str(t.title)}
                        </a>
                      ),
                    },
                    { key: "team_id", label: "责任团队" },
                    {
                      key: "state",
                      label: "规划态",
                      render: (t) => <StatusBadge state={str(t.state)} />,
                    },
                    {
                      key: "priority",
                      label: "优先级",
                      render: (t) => {
                        const entry = rows(queueQuery.data).find(
                          (e) => e.task_id === t.task_id,
                        );
                        return entry ? str(entry.priority) : "—";
                      },
                    },
                    {
                      key: "queue_status",
                      label: "持久候选态",
                      render: (t) => {
                        const entry = rows(queueQuery.data).find(
                          (e) => e.task_id === t.task_id,
                        );
                        return entry ? (
                          <StatusBadge state={str(entry.status)} />
                        ) : queueQuery.data !== undefined ? (
                          "未入队"
                        ) : (
                          "队列来源未提供"
                        );
                      },
                    },
                    {
                      key: "blocking_reasons",
                      label: "准入阻塞",
                      render: (t) => str(t.blocking_reasons ?? t.blockers),
                    },
                  ]}
                />{" "}
              </>
            )}

            {queueQuery.error && (
              <ErrorNotice
                error={queueQuery.error}
                onRetry={queueQuery.reload}
              />
            )}
            <p className="muted">
              候选状态与优先级来自持久队列；任务数与队列数分别计量。本地排序不改变调度。
            </p>
          </Panel>
        </div>
      )}
      {projectId && (workspaceView === "governance" || !isDeliveryProject) && <OwnerTerritories key={projectId} projectId={projectId}
        project={projectQuery.data === undefined ? undefined : object(projectQuery.data)}
        projectReady={projectQuery.data !== undefined && !projectQuery.loading && !projectQuery.error}
        teams={teams} selectedTeamId={selected}
        teamsComplete={Array.isArray(snapshot.teams) ? !snapshotQuery.loading && !snapshotQuery.error
          : teamsQ.data !== undefined && !teamsQ.loading && !teamsQ.error && !teamsQ.metadata.next_cursor}
        onSaved={snapshotQuery.reload} />}
      {selectedTask && (
        <Drawer
          title={`${str(selectedTask.title)} · 持久队列`}
          onClose={() => setSelectedTask(undefined)}
        >
          <p>
            任务 {str(selectedTask.task_id)} · 团队 {str(selectedTask.team_id)}
          </p>
          {selectedQueue ? (
            <>
              <StatusBadge state={str(selectedQueue.status)} />
              <Field label="候选优先级">
                <input
                  type="number"
                  step="1"
                  min="-2147483648"
                  max="2147483647"
                  value={queuePriority}
                  onChange={(e) => setQueuePriority(e.target.value)}
                />
              </Field>
              <button
                disabled={
                  busy ||
                  !writable ||
                  !queuePriority ||
                  !Number.isInteger(Number(queuePriority)) ||
                  Number(queuePriority) < -2147483648 ||
                  Number(queuePriority) > 2147483647
                }
                onClick={() => void updatePriority()}
              >
                保存队列优先级
              </button>
              <JsonView value={selectedQueue} />
            </>
          ) : (
            <p className="muted">
              尚未返回该任务的合法候选队列项；请在任务详情完成准入与入队。
            </p>
          )}
          {error && <p role="alert">{error}</p>}
          <JsonView value={selectedTask} />
          <a
            href={`/projects/${path(projectId ?? "")}/tasks/${path(str(selectedTask.task_id))}`}
          >
            打开任务详情
          </a>
        </Drawer>
      )}
    </>
  );
}
