import { useState, useEffect } from "react";
import {
  Activity,
  RefreshCw,
  Terminal,
  Square,
  RotateCcw,
  Download,
  Server,
  SlidersHorizontal,
} from "lucide-react";
import { api, useApi, useCursorApi } from "../../app/api";
import { useCollection } from "../portfolio/collection";
import { useCommandIdentity } from "../portfolio/commands";
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
  Pagination,
  SourceStamp,
} from "../../components";
import {
  rows,
  object,
  str,
  id,
  path,
  date,
  num,
  errorMessage,
  activeStates,
  type Row,
} from "../portfolio/monitor";
import { useProjectEvents } from "./events";
import { useAttemptLogs } from "./logs";
import { NativeAgentPanel } from "./NativeAgentPanel";
import { IntegrationRecovery } from "./IntegrationRecovery";

export function RunsPage({ projectId }: PageProps) {
  const projectsQ = useCollection<Row>("/projects");
  const [scope, setScope] = useState(
    projectId ?? new URLSearchParams(location.search).get("project") ?? "",
  );
  const [state, setState] = useState(
    new URLSearchParams(location.search).get("state") ?? "",
  );
  const [all, setAll] = useState<Row[]>([]);
  const [globalError, setGlobalError] = useState<string>();
  const [globalBusy, setGlobalBusy] = useState(false);
  const q = useCursorApi<unknown>(
    scope ? `/projects/${path(scope)}/attempts` : null,
    "attempt_cursor",
  );
  const projects = rows(projectsQ.data);
  useEffect(() => {
    if (scope) return;
    let disposed = false;
    setGlobalBusy(true);
    setGlobalError(undefined);
    Promise.all(
      projects.map((p) =>
        api
          .collect<Row>(`/projects/${path(id(p))}/attempts`)
          .then((envelope) => envelope.data),
      ),
    )
      .then((data) => {
        if (!disposed) setAll(data.flat());
      })
      .catch((e) => {
        if (!disposed) setGlobalError(errorMessage(e));
      })
      .finally(() => {
        if (!disposed) setGlobalBusy(false);
      });
    return () => {
      disposed = true;
    };
  }, [scope, projectsQ.data]);
  const attempts = scope ? rows(q.data) : all;
  const filtered = state ? attempts.filter((a) => a.state === state) : attempts;
  function filter(key: string, value: string) {
    const url = new URL(location.href);
    if (value) url.searchParams.set(key, value);
    else url.searchParams.delete(key);
    history.replaceState(null, "", url);
    if (key === "project") setScope(value);
    else setState(value);
  }
  return (
    <>
      <PageHeader
        title="执行大厅"
        description="活动占用包含停止未确认和待恢复尝试。进程退出与业务集成分开判定。"
      />
      <Panel
        title={
          <>
            <Activity size={16} />
            真实尝试
          </>
        }
        actions={
          <div className="toolbar">
            <select
              aria-label="项目筛选"
              value={scope}
              onChange={(e) => filter("project", e.target.value)}
            >
              <option value="">全部项目</option>
              {projects.map((p) => (
                <option key={id(p)} value={id(p)}>
                  {str(p.name)}
                </option>
              ))}
            </select>
            <select
              aria-label="尝试状态筛选"
              value={state}
              onChange={(e) => filter("state", e.target.value)}
            >
              <option value="">全部状态</option>
              {[...activeStates, "SUCCEEDED", "FAILED", "CANCELLED"].map(
                (s) => (
                  <option key={s}>{s}</option>
                ),
              )}
            </select>
            <button
              onClick={() => {
                q.reload();
                projectsQ.reload();
              }}
            >
              刷新
            </button>
          </div>
        }
      >
        {(q.error ?? projectsQ.error) && (
          <ErrorNotice
            error={(q.error ?? projectsQ.error)!}
            onRetry={() => {
              q.reload();
              projectsQ.reload();
            }}
          />
        )}
        {globalError && (
          <p role="alert">组合读取不完整：{globalError}。保留上次成功快照。</p>
        )}
        {(q.loading || globalBusy) && !attempts.length ? (
          <p role="status">读取尝试…</p>
        ) : (
          <DataTable<Row>
            rows={filtered}
            rowKey={id}
            empty={
              attempts.length
                ? "当前过滤无匹配尝试"
                : "本次查询没有可展示的尝试；接口不可用时不推断没有运行"
            }
            columns={[
              {
                key: "attempt_id",
                label: "尝试 / 任务",
                render: (a) => (
                  <a
                    href={`/runs/${path(id(a))}?project=${path(str(a.project_id, ""))}`}
                  >
                    {id(a)}
                    <small>{str(a.task_id)}</small>
                  </a>
                ),
              },
              { key: "project_id", label: "项目" },
              { key: "worker_id", label: "Worker / 执行器" },
              {
                key: "state",
                label: "阶段",
                render: (a) => (
                  <StatusBadge
                    state={str(a.state)}
                    scope={
                      object(a.result).kind === "STRUCTURED_ARTIFACT"
                        ? undefined
                        : "attempt"
                    }
                  />
                ),
              },
              {
                key: "created_at",
                label: "获租时间",
                render: (a) => date(a.created_at),
              },
              {
                key: "terminal_at",
                label: "终态时间",
                render: (a) => date(a.terminal_at),
              },
              { key: "generation", label: "租约代次", numeric: true },
            ]}
          />
        )}
        {scope && <Pagination query={q} count={attempts.length} />}
        <p className="muted">
          显示 {filtered.length} / {attempts.length} 个已返回尝试；活动{" "}
          {attempts.filter((a) => activeStates.has(str(a.state))).length}
          。全项目查询逐项目读取，观察时刻不合并为一个瞬时快照。
        </p>
      </Panel>
    </>
  );
}

export function AttemptPage({ attemptId }: PageProps) {
  const commandIdentity = useCommandIdentity();
  const routeProject = new URLSearchParams(location.search).get("project");
  const q = useApi<unknown>(
    attemptId
      ? `/attempts/${path(attemptId)}${routeProject ? `?project_id=${path(routeProject)}` : ""}`
      : null,
  );
  const attempt = object(q.data);
  const verifiedProjectId =
    typeof attempt.project_id === "string" && attempt.project_id
      ? attempt.project_id
      : undefined;
  const [verifiedScope, setVerifiedScope] = useState<{
    attemptId: string;
    projectId: string;
    routeProject: string | null;
  }>();
  useEffect(() => {
    if (attemptId && verifiedProjectId)
      setVerifiedScope((previous) =>
        previous?.attemptId === attemptId && previous.projectId === verifiedProjectId && previous.routeProject === routeProject
          ? previous
          : { attemptId, projectId: verifiedProjectId, routeProject },
      );
  }, [attemptId, verifiedProjectId, routeProject]);
  // Keep the read subscription stable while a resync invalidates the attempt
  // cache. URL scope selects an authenticated read; commands use the returned
  // attempt's authoritative project identity below.
  const projectId =
    verifiedProjectId ??
    (verifiedScope && verifiedScope.attemptId === attemptId && verifiedScope.routeProject === routeProject
      ? verifiedScope.projectId
      : undefined) ??
    routeProject ?? undefined;
  const stream = useProjectEvents(projectId);
  const taskQuery = useApi<unknown>(
    projectId && typeof attempt.task_id === "string"
      ? `/projects/${path(projectId)}/tasks/${path(attempt.task_id)}`
      : null,
  );
  const task = object(taskQuery.data);
  const events = stream.events.filter(
    (e) =>
      e.object_id === attemptId || object(e.payload).attempt_id === attemptId,
  );
  const [tab, setTab] = useState("events");
  const [reason, setReason] = useState("");
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState<string>();
  const logs = useAttemptLogs(attemptId, tab === "logs");
  const [operationId, setOperationId] = useState<string>();
  const operationQuery = useApi<unknown>(
    operationId ? `/operations/${path(operationId)}` : null,
  );
  const operation = object(operationQuery.data);
  const eventRevision = Math.max(
    0,
    ...events.map((e) => num(e.object_revision) ?? 0),
  );
  useEffect(() => {
    if (eventRevision > (num(attempt.revision) ?? 0)) q.reload();
  }, [eventRevision, attempt.revision, q.reload]);
  useEffect(() => {
    if (!operationId || ["SUCCEEDED", "FAILED"].includes(str(operation.status)))
      return;
    const interval = setInterval(operationQuery.reload, 2000);
    return () => clearInterval(interval);
  }, [operationId, operation.status, operationQuery.reload]);
  useEffect(() => {
    if (["SUCCEEDED", "FAILED"].includes(str(operation.status))) q.reload();
  }, [operation.status, q.reload]);
  async function verify(integrate = false) {
    setBusy(true);
    setMessage(undefined);
    try {
      const route = `/attempts/${path(attemptId ?? "")}/${integrate ? "verify-and-integrate" : "verify"}`;
      const body = { project_id: attempt.project_id };
      const result = object(
        await api.post(
          route,
          body,
          commandIdentity(route, {
            ...body,
            attempt_revision: attempt.revision,
          }),
        ),
      );
      const operationId = str(result.operation_id, "");
      if (operationId) setOperationId(operationId);
      setMessage(
        `服务端接受操作：${str(result)}。操作接受不等于验证或集成成功。`,
      );
    } catch (e) {
      setMessage(errorMessage(e));
    } finally {
      setBusy(false);
    }
  }
  async function command(kind: "cancel" | "retry") {
    setBusy(true);
    setMessage(undefined);
    try {
      const route =
        kind === "cancel"
          ? `/attempts/${path(attemptId ?? "")}/cancel`
          : `/tasks/${path(str(attempt.task_id, ""))}/retry`;
      const body =
        kind === "cancel"
          ? {
              project_id: attempt.project_id,
              reason,
              expected_revision: attempt.revision,
            }
          : {
              project_id: attempt.project_id,
              expected_revision: task.revision,
            };
      const response = await api.post(route, body, {
        ...commandIdentity(route, body),
        expectedRevision: num(
          kind === "cancel" ? attempt.revision : task.revision,
        ),
      });
      setMessage(`服务器回执：${str(response)}。以重新读取的尝试状态为准。`);
      q.reload();
    } catch (e) {
      setMessage(errorMessage(e));
    } finally {
      setBusy(false);
    }
  }
  function download() {
    const blob = new Blob([logs.text], { type: "text/plain;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `${attemptId}.log`;
    a.click();
    URL.revokeObjectURL(url);
  }
  return (
    <>
      <PageHeader
        title="尝试工作台"
        description={attemptId ?? "未选择尝试"}
        actions={
          <button onClick={q.reload}>
            <RefreshCw size={14} />
            重新读取
          </button>
        }
      />
      {q.error && <ErrorNotice error={q.error} onRetry={q.reload} />}{" "}
      {!attemptId ? (
        <EmptyState title="请选择尝试" />
      ) : (
        <>
          <Panel
            title={
              <>
                <Terminal size={16} />
                执行身份与控制
              </>
            }
          >
            <dl>
              <dt>当前阶段</dt>
              <dd>
                <StatusBadge
                  state={str(attempt.state)}
                  scope={
                    object(attempt.result).kind === "STRUCTURED_ARTIFACT"
                      ? undefined
                      : "attempt"
                  }
                />
              </dd>
              <dt>任务 → 尝试 → 租约</dt>
              <dd>
                {str(attempt.task_id)} → {attemptId} → {str(attempt.lease_id)}
              </dd>
              <dt>Worker / 代次 / 操作</dt>
              <dd>
                {str(attempt.worker_id)} / {str(attempt.generation)} /{" "}
                {str(attempt.operation_id)}
              </dd>
              <dt>基线 SHA</dt>
              <dd>
                <code>{str(attempt.base_sha)}</code>
              </dd>
              <dt>模型 token / 费用 / 工具计数</dt>
              <dd>
                {str(object(attempt.result).token_usage, "执行器未提供")} /{" "}
                {str(object(attempt.result).cost, "执行器未提供")} /{" "}
                {str(object(attempt.result).tool_count, "执行器未提供")}
              </dd>
            </dl>
            <Field label="操作原因">
              <input
                value={reason}
                onChange={(e) => setReason(e.target.value)}
              />
            </Field>
            <div className="toolbar">
              <button
                disabled={
                  busy || !reason || !activeStates.has(str(attempt.state))
                }
                onClick={() => void command("cancel")}
              >
                <Square size={14} />
                请求停止当前尝试
              </button>
              <button
                disabled={busy || attempt.state !== "VERIFYING"}
                onClick={() => void verify()}
              >
                发起已定义独立验证
              </button>
              <button
                disabled={
                  busy ||
                  !["VERIFYING", "REVIEW_READY"].includes(str(attempt.state))
                }
                onClick={() => void verify(true)}
              >
                验证并请求受控集成
              </button>
              <button
                disabled={
                  busy ||
                  !["FAILED", "CANCELLED"].includes(str(attempt.state)) ||
                  taskQuery.data === undefined ||
                  task.task_revision !== attempt.task_revision
                }
                title="基于当前任务版本授权重试；重新获租后才创建新尝试，保留旧租约与失败证据"
                onClick={() => void command("retry")}
              >
                <RotateCcw size={14} />
                重试并重新入队
              </button>
            </div>
            {message && <p role="status">{message}</p>}
            {operationId && (
              <>
                <p role="status">
                  操作 {operationId} · {str(operation.status, "读取中")}
                  ；业务完成以尝试、收据和可达 SHA 为准。
                </p>
                {operationQuery.error && (
                  <ErrorNotice
                    error={operationQuery.error}
                    onRetry={operationQuery.reload}
                  />
                )}
                <JsonView value={operationQuery.data} />
              </>
            )}
            <p className="muted">
              停止只有收到可信进程终止证据才成为 CANCELLED。作者取消后，未知模型用量与原资源占用仍可能保留，请继续查看原生协作的未结清占用；COMMIT_IN_PROGRESS 需要核对提交结果。原生 Source 任务的新尝试从 Native 面板 START/RETRY 重新准入。
            </p>
          </Panel>
          <IntegrationRecovery
            projectId={projectId}
            attemptId={attemptId}
            attempt={attempt}
            onRecovered={q.reload}
          />
          <NativeAgentPanel
            projectId={projectId}
            attemptId={attemptId}
            attemptState={typeof attempt.state === "string" ? attempt.state : undefined}
            onAuthorClosed={q.reload}
          />
          <Panel
            title="运行过程"
            actions={
              <div className="view-tabs">
                {[
                  ["events", "结构化事件"],
                  ["logs", "日志"],
                  ["identity", "完整身份与结果"],
                ].map(([value, label]) => (
                  <button
                    key={value}
                    aria-pressed={tab === value}
                    onClick={() => setTab(value)}
                  >
                    {label}
                  </button>
                ))}
              </div>
            }
          >
            {stream.notice && <p className="muted" role="status">{stream.notice}</p>}
            {stream.cacheNotice && <p className="muted" role="status">{stream.cacheNotice}</p>}
            {tab === "events" ? (
              <>
                <p role="status">
                  {stream.connected ? "事件已连接" : "事件连接中断，保留快照"} ·
                  游标 {stream.cursor} · 最后观察 {date(stream.observedAt)}
                </p>
                {stream.error && <p role="alert">{stream.error}</p>}
                <div
                  className="attempt-events-scroll"
                  role="region"
                  aria-label={`当前尝试的结构化事件，共 ${events.length} 条，可使用方向键和翻页键滚动`}
                  tabIndex={0}
                >
                <DataTable<Row>
                  rows={events}
                  rowKey={(e) => str(e.event_id)}
                  empty="尚无该尝试的已持久化事件"
                  columns={[
                    { key: "project_seq", label: "序号", numeric: true },
                    {
                      key: "occurred_at",
                      label: "UTC+8 时间",
                      render: (e) => date(e.occurred_at),
                    },
                    { key: "kind", label: "事件" },
                    {
                      key: "payload",
                      label: "事实",
                      render: (e) => <JsonView value={e.payload} />,
                    },
                  ]}
                />
                </div>
                <p className="muted">
                  按显示缓存预算保留最近事件，完整原文保留在服务端；最多
                  1,000 条 / 256 KiB，游标持久化于本会话。重新连接从服务器游标继续。
                </p>
              </>
            ) : tab === "logs" ? (
              <>
                {logs.error && (
                  <ErrorNotice error={logs.error} onRetry={logs.reload} />
                )}
                <div className="toolbar">
                  <button onClick={logs.reload}>读取日志</button>
                  <button disabled={!logs.text} onClick={download}>
                    <Download size={14} />
                    下载已读取日志
                  </button>
                </div>
                <p className="muted">
                  服务器字节偏移 {logs.offset} · 显示最近 256 KiB ·
                  离开日志标签停止读取
                </p>
                <pre className="log-view">
                  {logs.text || (logs.loading ? "读取日志…" : "尚无已读取日志")}
                </pre>
              </>
            ) : (
              <JsonView value={attempt} />
            )}
          </Panel>
        </>
      )}
    </>
  );
}

export function ResourcePage() {
  const q = useApi<unknown>("/resource-usage");
  if (!q.data) return <><PageHeader title="资源与预算" description="按观察时刻读取跨项目资源账本。" />{q.error ? <ErrorNotice error={q.error} onRetry={q.reload} /> : <p role="status">正在读取资源与机器观测…</p>}</>;
  const resource = object(q.data);
  const policies = rows(resource.policies);
  const allocations = [...rows(resource.allocations), ...rows(resource.native_allocations)];
  const measures = rows(resource.usage).map(limit => ({ ...limit, used: limit.allocated,
    remaining: num(limit.allocated) === undefined || num(limit.hard_limit) === undefined ? undefined : Number(limit.hard_limit) - Number(limit.allocated), observed_at:q.metadata.observed_at }));
  const memory = object(resource.host_memory);
  const gib = (value: unknown) => num(value) === undefined ? "未知" : `${(Number(value)/1073741824).toFixed(2)} GiB`;
  return <><PageHeader title="资源与预算" description="全部项目共享一次数据库观察；停止待确认与隔离分配继续占用。主机物理内存单独采样。" />
    {q.error && <ErrorNotice error={q.error} onRetry={q.reload} />}
    <Panel title="容量与保留占用" actions={<button disabled={q.loading} onClick={q.reload}><RefreshCw size={14} />{q.loading ? "正在读取…" : "重新采样"}</button>}>
      <p>主机可用内存 {gib(memory.available_bytes)} / 总内存 {gib(memory.total_bytes)} · {str(memory.source)} · {date(memory.observed_at)}</p>
      <DataTable<Row> rows={measures} rowKey={r => `${str(r.scope_id)}:${str(r.dimension)}`} empty={q.loading ? "正在读取权威资源账本…" : "尚未登记资源范围"} columns={[{key:"scope_id",label:"作用域"},{key:"dimension",label:"资源维度"},{key:"hard_limit",label:"配置上限",numeric:true},{key:"used",label:"保留占用",numeric:true},{key:"remaining",label:"配置余额",numeric:true}]} />
      <p className="muted">使用量来自资源账本，包含根尝试和 Native 子会话的保留占用。各范围余额分别计算；实际准入联合检查全部祖先。</p>
      <SourceStamp source={q.metadata.source} observedAt={q.metadata.observed_at} />
    </Panel>
    <Panel title="Worker 心跳登记"><DataTable<Row> rows={rows(resource.workers)} rowKey={r => str(r.worker_id)} empty="尚未登记 Worker 心跳；不能据此推断可执行容量。" columns={[{key:"worker_id",label:"Worker"},{key:"heartbeat_at",label:"最后心跳",render:r=>date(r.heartbeat_at)},{key:"reported_active_attempts",label:"自报活动尝试",numeric:true}]} /></Panel>
    <Panel title="资源策略"><DataTable<Row> rows={policies} rowKey={p=>str(p.scope_id)} columns={[{key:"scope_id",label:"作用域"},{key:"project_id",label:"项目"},{key:"parent_scope_id",label:"祖先"},{key:"paused",label:"新增准入",render:p=>p.paused?"暂停":"开放"}]} /><details><summary>完整配置资源向量</summary><JsonView value={policies} /></details></Panel>
    <Panel title="保留分配明细"><DataTable<Row> rows={allocations} rowKey={a=>str(a.resource_allocation_id??a.allocation_id)} empty={q.loading?"读取中…":"本次观察没有保留分配。"} columns={[{key:"attempt_id",label:"尝试",render:a=><a href={`/runs/${path(str(a.attempt_id))}?project=${path(str(a.project_id))}`}>{str(a.attempt_id)}</a>},{key:"scope_id",label:"作用域"},{key:"dimension",label:"维度"},{key:"amount",label:"数量",numeric:true},{key:"state",label:"保留状态",render:a=><StatusBadge state={str(a.state)} />}]} /><SourceStamp source={q.metadata.source} observedAt={q.metadata.observed_at} /></Panel>
  </>;
}

export function ExecutorsPage() {
  const q = useApi<unknown>("/executors");
  const [result, setResult] = useState<string>();
  const [busy, setBusy] = useState("");
  async function probe(executor: Row) {
    setBusy(id(executor));
    try {
      setResult(
        str(
          await api.post(
            `/executors/${path(id(executor))}/probe`,
            { project_id: executor.project_id },
            { expectedRevision: num(executor.revision) },
          ),
        ),
      );
      q.reload();
    } catch (e) {
      setResult(errorMessage(e));
    } finally {
      setBusy("");
    }
  }
  return (
    <>
      <PageHeader
        title="执行器与通道"
        description="只有真实版本和能力探测支持可用状态。未探测不显示可用。"
      />
      {q.error && <ErrorNotice error={q.error} onRetry={q.reload} />}
      <Panel
        title={
          <>
            <Server size={16} />
            执行器登记
          </>
        }
      >
        <DataTable<Row>
          rows={rows(q.data).map((r) => ({ ...r, ...object(r.profile) }))}
          rowKey={(e) => `${str(e.project_id)}:${id(e)}`}
          empty="本次查询未返回执行器登记；接口失败时保留未知"
          columns={[
            { key: "profile_name", label: "名称" },
            { key: "project_id", label: "项目" },
            { key: "model_route_id", label: "模型路由" },
            { key: "protocol", label: "协议", render: () => "Headless" },
            { key: "version", label: "版本" },
            {
              key: "capabilities",
              label: "已探测能力",
              render: (e) => <JsonView value={e.capabilities ?? "未探测"} />,
            },
            {
              key: "observed_at",
              label: "探测时间",
              render: (e) => date(e.observed_at),
            },
            {
              key: "actions",
              label: "操作",
              render: (e) => (
                <button disabled={!!busy} onClick={() => void probe(e)}>
                  {busy === id(e) ? "探测中…" : "重新探测"}
                </button>
              ),
            },
          ]}
        />
        {result && <p role="status">{result}</p>}
      </Panel>
    </>
  );
}
