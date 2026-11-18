import { useEffect, useId, useMemo, useState, type CSSProperties } from "react";
import { Bot, ChevronRight, Cpu, GitBranch, Layers, LockKeyhole, RefreshCw, Search, Users } from "lucide-react";
import { api, useApi } from "../../app/api";
import { useCommandIdentity } from "../portfolio/commands";
import { EmptyState, ErrorNotice, Panel, StatusBadge } from "../../components";
import { activeStates, date, errorMessage, num, object, path, rows, str, type Row } from "../portfolio/monitor";
import "./native-agent.css";

const dimensions = [
  ["active_slot", "活动槽位"],
  ["coding_slot", "编码槽位"],
  ["cpu_units", "CPU 单位"],
  ["memory_bytes", "内存"],
  ["build_permit", "构建许可"],
  ["gpu_permit", "GPU 许可"],
  ["provider_inflight", "模型并行"],
] as const;
const usageFields = [
  ["inputTokens", "输入"], ["outputTokens", "输出"],
  ["cacheReadTokens", "缓存读取"], ["cacheWriteTokens", "缓存写入"],
  ["reasoningTokens", "推理"], ["totalTokens", "总量"],
] as const;
const capabilityNames: Record<string, string> = {
  workflow: "Workflow", agent_teams: "Agent Teams", subagent: "Subagent",
  one_shot_subagent: "单次子 Agent", fork_subagent: "分叉子 Agent",
  planning: "规划", todo: "任务清单", goal_tracking: "目标跟踪",
  skills: "Skills", session_query: "会话查询", checkpoint: "检查点",
  context_compaction: "上下文压缩",
};
const sourceNames: Record<string, string> = {
  startup: "启动", resume: "恢复", clear: "清空上下文", compact: "压缩上下文",
};
const purposeNames: Record<string, string> = {
  conversation: "对话", compaction: "上下文压缩", "session-title": "会话标题",
};
const executorNames: Record<string, string> = {
  DSH_MANAGED: "DSH · 受管执行", DSH_HEADLESS: "DSH · Headless",
  CLAUDE_CODE_LEAF: "Claude Code · 单叶执行", CONTROLLED_LIGHTWEIGHT: "受控轻量执行器",
};
const observedCode = (value: unknown) => typeof value === "string" && /^[A-Z][A-Z0-9_]{0,127}$/.test(value) ? value : undefined;
const observedSession = (value: unknown) => typeof value === "string" && /^[A-Za-z0-9][A-Za-z0-9._:@-]{0,255}$/.test(value) ? value : undefined;
const observedDigest = (value: unknown) => typeof value === "string" && /^[a-f0-9]{64}$/.test(value) ? value : undefined;
const observedArtifact = (value: unknown) => typeof value === "string" && value.trim().length > 0 && value.length <= 512 && !/[\x00-\x1f\x7f]/.test(value) && !/^(?:[/\\]|[A-Za-z]:|[A-Za-z][A-Za-z0-9+.-]*:\/\/)/.test(value) ? value : undefined;
const count = (value: unknown) => {
  const n = num(value);
  return n === undefined ? "—" : n.toLocaleString("zh-CN");
};

function AuthorCustody({ projectId, attemptId, attemptState, onClosed }: { projectId: string; attemptId: string; attemptState?: string; onClosed: () => void }) {
  const status = useApi<Row>(`/attempts/${path(attemptId)}/author-custody?project_id=${encodeURIComponent(projectId)}`);
  const commandIdentity = useCommandIdentity();
  const [reason, setReason] = useState("停止已确认的作者，保留全部未知模型用量与原资源占用");
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState("");
  const current = object(status.data);
  const pending = current.custody_pending === true;
  const eligible = current.project_id === projectId && current.attempt_id === attemptId
    && current.author_close_eligible === true && typeof current.trusted_stop_observation_event_id === "string";
  useEffect(() => {
    if (!["STOPPING", "RECOVERY_REQUIRED"].includes(attemptState ?? "") && !pending) return;
    const timer = setInterval(status.reload, 5000);
    return () => clearInterval(timer);
  }, [attemptState, pending, status.reload]);
  async function closeAuthor() {
    if (!eligible || busy || !reason.trim()) return;
    setBusy(true);
    try {
      const route = `/attempts/${path(attemptId)}/close-author-retain-custody`;
      const body = { project_id: projectId, attempt_id: attemptId, expected_revision: current.revision,
        observation_event_id: current.trusted_stop_observation_event_id, reason };
      await api.post(route, body, commandIdentity(route, body));
      setMessage("作者已取消。未知模型请求、原资源占用和失败证据继续保留；新尝试须从 Native 面板重新准入。");
      status.reload();
      onClosed();
    } catch (error) { setMessage(errorMessage(error)); }
    finally { setBusy(false); }
  }
  return <section className="native-section" aria-label="作者停止与未结清占用">
    <h3><LockKeyhole size={15} />作者与未结清占用</h3>
    {status.error && <ErrorNotice error={status.error} onRetry={status.reload} />}
    {pending && <p role="status" className="native-note">模型用量或资源占用尚未结清：保留 {count(current.pending_native_model_request_count)} 个模型请求与 {count(current.held_allocation_count)} 条分配。作者 CANCELLED 不表示这些占用已释放。</p>}
    {["STOPPING", "RECOVERY_REQUIRED"].includes(str(current.state, attemptState ?? "")) && <>
      <p className="native-note">{eligible ? "原 Worker 的完整物理停止证明已登记，可仅关闭作者并保留未知占用。" : "等待可信物理停止观察或恢复前置条件；尝试仍保持停止待确认。"}</p>
      <label>关闭作者的原因<input value={reason} onChange={event => setReason(event.target.value)} /></label>
      <button type="button" disabled={!eligible || busy || !reason.trim()} onClick={() => void closeAuthor()}>关闭作者并保留未知占用</button>
    </>}
    {typeof current.retained_author_closure_operation_id === "string" && <p className="native-note">作者关闭回执：{current.retained_author_closure_operation_id}。本回执不结算模型用量、不释放资源。</p>}
    {message && <p role="status">{message}</p>}
  </section>;
}
function amount(value: unknown, dimension: string) {
  const n = num(value);
  if (n === undefined) return "—";
  if (dimension === "memory_bytes" && n >= 1048576)
    return `${(n / 1048576).toLocaleString("zh-CN", { maximumFractionDigits: 1 })} MiB`;
  return `${count(n)}${dimension === "memory_bytes" ? " B" : ""}`;
}
interface LineageRow { lifecycle: Row; depth: number; anomaly?: string }

/** The allocation identity distinguishes cold resumes of the same native session. */
function lineageOrder(lifecycles: Row[]): LineageRow[] {
  const byId = new Map(lifecycles.map(row => [str(row.allocation_id, ""), row]));
  const children = new Map<string, Row[]>();
  const roots: Row[] = [];
  for (const row of lifecycles) {
    const parent = str(row.parent_allocation_id, "");
    if (!parent || !byId.has(parent)) roots.push(row);
    else {
      const siblings = children.get(parent) ?? [];
      siblings.push(row);
      children.set(parent, siblings);
    }
  }
  const ordered: LineageRow[] = [];
  const visited = new Set<string>();
  const walk = (root: Row, anomaly?: string) => {
    const pending: LineageRow[] = [{ lifecycle: root, depth: 0, anomaly }];
    while (pending.length) {
      const entry = pending.pop()!;
      const key = str(entry.lifecycle.allocation_id, "");
      if (visited.has(key)) continue;
      visited.add(key);
      ordered.push(entry);
      const descendants = children.get(key) ?? [];
      for (let i = descendants.length - 1; i >= 0; i--)
        pending.push({ lifecycle: descendants[i], depth: entry.depth + 1, anomaly });
    }
  };
  for (const root of roots)
    walk(root, root.parent_allocation_id ? "快照缺少父级生命周期" : undefined);
  for (const row of lifecycles)
    if (!visited.has(str(row.allocation_id, ""))) walk(row, "父级关系异常，请核对生命周期证据");
  return ordered;
}

function ResourceScopes({ lifecycle, allocations, limits, available }: {
  lifecycle: Row; allocations: Row[]; limits: Row[]; available: boolean;
}) {
  const scopes = [...new Set(allocations.map(row => str(row.scope_id, "")))].filter(Boolean);
  return (
    <section className="native-section" aria-label="七维资源分配">
      <h3><Cpu size={15} />资源作用域</h3>
      <p className="native-note">
        {lifecycle.borrowed_parent_reservation === true
          ? "根会话借用该尝试原有分配，以下份额不再次累加。"
          : "子 Agent 使用独立分配；各祖先作用域分别核算。"}
      </p>
      {!available ? <p className="native-note">当前快照未提供该资源账本。</p>
        : !scopes.length ? <p className="native-note">该生命周期没有已登记的资源分配行。</p>
          : <div className="native-scopes">{scopes.map((scope, scopeIndex) => {
            const scopeRows = allocations.filter(row => row.scope_id === scope);
            const retainedAmount = (dimension: string) => scopeRows
              .filter(row => row.dimension === dimension && row.state !== "RELEASED")
              .reduce((sum, row) => sum + (num(row.amount) ?? 0), 0);
            return <details className="native-scope" key={`${str(lifecycle.allocation_id)}:${scope}`} open={scopeIndex === 0}>
              <summary>
                <span className="native-scope-name"><Layers size={13} /><strong title={scope}>{scope}</strong></span>
                <span className="native-scope-amounts">保留活动 {count(retainedAmount("active_slot"))} · 内存 {amount(retainedAmount("memory_bytes"), "memory_bytes")}</span>
                <ChevronRight size={13} aria-hidden="true" />
              </summary>
              <div className="native-table-scroll">
                <table>
                  <caption className="sr-only">{scope} 的会话份额与权威作用域容量</caption>
                  <thead><tr><th scope="col">维度</th><th scope="col">会话保留</th><th scope="col">Scope 已分配</th><th scope="col">Scope 上限</th></tr></thead>
                  <tbody>{dimensions.map(([dimension, label]) => {
                    const matching = scopeRows.filter(row => row.dimension === dimension);
                    const retained = matching.filter(row => row.state !== "RELEASED")
                      .reduce((sum, row) => sum + (num(row.amount) ?? 0), 0);
                    const released = matching.filter(row => row.state === "RELEASED")
                      .reduce((sum, row) => sum + (num(row.amount) ?? 0), 0);
                    const limit = limits.find(row => row.scope_id === scope && row.dimension === dimension);
                    return <tr key={dimension}>
                      <th scope="row">{label}</th>
                      <td title={`${retained} ${dimension}`}>
                        {amount(retained, dimension)}
                        {released > 0 && <small title={`${released} ${dimension}`}>已释放 {amount(released, dimension)}</small>}
                      </td>
                      <td title={limit ? `${str(limit.allocated)} ${dimension}` : undefined}>{amount(limit?.allocated, dimension)}</td>
                      <td title={limit ? `${str(limit.hard_limit)} ${dimension}` : undefined}>{amount(limit?.hard_limit, dimension)}</td>
                    </tr>;
                  })}</tbody>
                </table>
              </div>
              <p className="native-note">保留包含隔离占位；0 表示该维度没有未释放的分配行。</p>
            </details>;
          })}</div>}
    </section>
  );
}

function ModelRequests({ requests, selectedAllocation, available }: {
  requests: Row[]; selectedAllocation: string; available: boolean;
}) {
  const [scope, setScope] = useState<"selected" | "all">("selected");
  const [page, setPage] = useState(0);
  const showAll = scope === "all" || !selectedAllocation;
  const scoped = showAll ? requests : requests.filter(row => row.allocation_id === selectedAllocation);
  const pages = Math.max(1, Math.ceil(scoped.length / 20));
  const currentPage = Math.min(page, pages - 1);
  useEffect(() => setPage(0), [scope, selectedAllocation]);
  const pageRows = scoped.slice(currentPage * 20, (currentPage + 1) * 20);
  return <section className="native-section native-models" aria-label="实际模型请求与用量">
    <div className="native-section-heading">
      <h3><Bot size={15} />模型请求与实际用量</h3>
      <div className="view-tabs">
        <button type="button" disabled={!selectedAllocation} aria-pressed={!showAll} onClick={() => setScope("selected")}>当前 Agent</button>
        <button type="button" aria-pressed={showAll} onClick={() => setScope("all")}>本次尝试全部</button>
      </div>
    </div>
    <p className="native-note">Token 按原始结算字段展示。缺失显示 —；不将未知费用换算为零。</p>
    {!available ? <p className="native-note">当前快照未提供模型请求账本。</p>
      : !scoped.length ? <p className="native-note">当前范围没有已登记的模型请求。</p>
        : <>
          <div className="native-table-scroll">
            <table>
              <caption className="sr-only">真实模型请求、路由、Token 和结算状态</caption>
              <thead><tr><th scope="col">请求 / 路由</th><th scope="col">状态与结算</th>
                {usageFields.map(([key, label]) => <th scope="col" className="numeric" key={key}>{label}</th>)}
                <th scope="col">费用</th></tr></thead>
              <tbody>{pageRows.map(row => <tr key={str(row.request_id)}>
                <td><code>{str(row.request_id)}</code>
                  <small>{str(row.provider)} / {str(row.model)}</small>
                  <small>{purposeNames[str(row.purpose)] ?? str(row.purpose)} · 输出上限 {count(row.max_output_tokens)}</small>
                  {showAll && <small>会话 {str(row.native_session_id)}</small>}
                </td>
                <td><span className="native-pill">{str(row.status)}</span>
                  <small>{row.usage_complete === true ? "用量已完整结算" : "用量未完整结算"}</small>
                  <small>{date(row.settled_at ?? row.admitted_at)}</small>
                </td>
                {usageFields.map(([key]) => <td className="numeric" key={key}>{count(object(row.usage)[key])}</td>)}
                <td><span className="native-pill">{str(row.cost_status, "UNKNOWN")}</span><small>费用未知</small></td>
              </tr>)}</tbody>
            </table>
          </div>
          <div className="native-pagination">
            <span>{scoped.length} 条实际请求 · {currentPage + 1} / {pages} 页</span>
            <button type="button" disabled={currentPage === 0} onClick={() => setPage(currentPage - 1)}>上一页</button>
            <button type="button" disabled={currentPage + 1 >= pages} onClick={() => setPage(currentPage + 1)}>下一页</button>
          </div>
        </>}
  </section>;
}

export function NativeAgentPanel({ projectId, attemptId, attemptState, onAuthorClosed }: {
  projectId?: string; attemptId?: string; attemptState?: string; onAuthorClosed?: () => void;
}) {
  const q = useApi<unknown>(projectId ? `/projects/${path(projectId)}/snapshot` : null);
  const capsuleQ = useApi<unknown>(projectId && attemptId ? `/projects/${path(projectId)}/capsules/${path(attemptId)}` : null);
  const searchId = useId();
  const [search, setSearch] = useState("");
  const [stateFilter, setStateFilter] = useState("");
  const [selected, setSelected] = useState("");
  const [visibleCount, setVisibleCount] = useState(100);
  const [autoRefresh, setAutoRefresh] = useState(true);
  const snapshot = object(q.data);
  const snapshotMatches = object(snapshot.project).project_id === projectId;
  const sameAttempt = (row: Row) => row.attempt_id === attemptId && row.project_id === projectId;
  const lifecycles = useMemo(() => rows(object(q.data).native_child_lifecycles).filter(
    row => row.attempt_id === attemptId && row.project_id === projectId,
  ), [q.data, attemptId, projectId]);
  const ordered = useMemo(() => lineageOrder(lifecycles), [lifecycles]);
  const modelRequests = rows(snapshot.native_model_requests).filter(sameAttempt);
  const lifecycleAvailable = Array.isArray(snapshot.native_child_lifecycles);
  const modelsAvailable = Array.isArray(snapshot.native_model_requests);
  const unreleased = lifecycles.filter(row => row.state !== "RELEASED");
  const pendingRequests = modelRequests.filter(row => row.status !== "SETTLED");
  const needsRefresh = activeStates.has(attemptState ?? "") || unreleased.length > 0 || pendingRequests.length > 0;
  useEffect(() => {
    setSearch(""); setStateFilter(""); setSelected(""); setVisibleCount(100);
  }, [projectId, attemptId]);
  useEffect(() => {
    if (lifecycles.some(row => row.allocation_id === selected)) return;
    setSelected(str((lifecycles.find(row => row.state !== "RELEASED") ?? lifecycles[0])?.allocation_id, ""));
  }, [lifecycles, selected]);
  useEffect(() => setVisibleCount(100), [search, stateFilter]);
  useEffect(() => {
    if (!projectId || !autoRefresh || !needsRefresh) return;
    const refresh = () => { if (document.visibilityState === "visible") q.reload(); };
    const timer = setInterval(refresh, 5000);
    document.addEventListener("visibilitychange", refresh);
    return () => { clearInterval(timer); document.removeEventListener("visibilitychange", refresh); };
  }, [projectId, autoRefresh, needsRefresh, q.reload]);
  const matched = new Set(lifecycles.filter(row =>
    (!stateFilter || row.state === stateFilter)
    && [row.native_session_id, row.allocation_id, row.parent_session_id, row.provider, row.model]
      .some(value => str(value, "").toLocaleLowerCase().includes(search.trim().toLocaleLowerCase())),
  ).map(row => str(row.allocation_id, "")));
  const shown = new Set(matched);
  const byId = new Map(lifecycles.map(row => [str(row.allocation_id, ""), row]));
  for (const allocation of matched) {
    const seen = new Set<string>([allocation]);
    let parent = str(byId.get(allocation)?.parent_allocation_id, "");
    while (parent && byId.has(parent) && !seen.has(parent) && !shown.has(parent)) {
      seen.add(parent); shown.add(parent);
      parent = str(byId.get(parent)?.parent_allocation_id, "");
    }
  }
  const filtered = ordered.filter(entry => shown.has(str(entry.lifecycle.allocation_id, "")));
  const selectedLifecycle = byId.get(selected);
  const selectedEntry = ordered.find(entry => entry.lifecycle.allocation_id === selected);
  const nativeProfile = snapshotMatches ? rows(snapshot.attempt_native_profiles).find(row => row.attempt_id === attemptId) : undefined;
  const attempt = snapshotMatches ? rows(snapshot.attempts).find(sameAttempt) : undefined;
  const result = object(attempt?.result);
  const outcome = object(result.outcome);
  const resultEvidence = object(result.evidence);
  // Project only bounded public scalars. Never stringify arbitrary result data:
  // evidence also contains private worktree/journal/launch details.
  const executorKind = observedCode(nativeProfile?.executor_kind ?? resultEvidence.executor_kind);
  const executorName = executorKind && Object.hasOwn(executorNames, executorKind) ? executorNames[executorKind] : "UNKNOWN · 执行器身份尚未提供";
  const rootSession = observedSession(outcome.upstream_session_id);
  const completionReason = observedCode(outcome.completion_reason);
  const transcriptCompleteness = observedCode(outcome.transcript_completeness);
  const exitCode = typeof outcome.exit_code === "number" && Number.isSafeInteger(outcome.exit_code) && outcome.exit_code >= -2147483648 && outcome.exit_code <= 2147483647 ? outcome.exit_code : undefined;
  const rawEventDigest = typeof outcome.raw_event_digest === "string" && /^[a-f0-9]{64}$/.test(outcome.raw_event_digest) ? outcome.raw_event_digest : undefined;
  const capsuleView = object(capsuleQ.data);
  const capsuleScopeMatches = capsuleView.project_id === projectId && capsuleView.attempt_id === attemptId;
  const capsule = object(capsuleView.capsule);
  const capsuleEnvelope = object(capsule.envelope_ref);
  const capsuleBound = capsuleScopeMatches && capsuleView.binding_status === "BOUND_IDENTITY_CHECKED"
    && capsule.capsule_id === `capsule:${attemptId}` && capsuleEnvelope.project_id === projectId && capsuleEnvelope.attempt_id === attemptId;
  const capsuleUnbound = capsuleScopeMatches && capsuleView.binding_status === "UNBOUND" && capsuleView.capsule === null;
  const capsuleQualification = object(capsule.qualification_ref);
  const policy = object(nativeProfile?.native_child_policy);
  const capabilities = Array.isArray(nativeProfile?.capabilities)
    ? nativeProfile.capabilities.filter((capability): capability is string => typeof capability === "string")
    : undefined;
  const isBorrowed = selectedLifecycle?.borrowed_parent_reservation === true;
  const allocationCollection = isBorrowed ? snapshot.allocations : snapshot.native_child_allocations;
  const selectedAllocations = rows(allocationCollection).filter(row =>
    sameAttempt(row) && (isBorrowed || row.allocation_id === selected),
  );
  return <Panel className="native-agent-panel" title={<><Users size={16} />原生 Agent 协作</>}
    actions={<div className="native-panel-actions">
      <label className="native-refresh-toggle"><input type="checkbox" checked={autoRefresh} onChange={event => setAutoRefresh(event.target.checked)} />自动更新</label>
      <button type="button" disabled={!projectId || q.loading || capsuleQ.loading} onClick={() => { q.reload(); capsuleQ.reload(); }}><RefreshCw size={13} />刷新快照</button>
    </div>}>
    {q.error && <ErrorNotice error={q.error} onRetry={q.reload} />}
    {!projectId || !attemptId ? <EmptyState title="等待尝试身份" description="读取项目与尝试后展示对应的原生协作记录。" />
      : q.loading && q.data === undefined ? <p className="native-loading" role="status">读取原生 Agent 权威快照…</p>
        : q.data === undefined ? <EmptyState title="尚未取得权威快照" description="请重新读取；接口错误时无法判断是否存在原生 Agent。" />
          : !snapshotMatches ? <EmptyState title="快照项目身份不匹配" description="当前观察未用于展示会话、模型或资源事实，请重新读取此项目。" />
          : <>
            <AuthorCustody projectId={projectId} attemptId={attemptId} attemptState={attemptState} onClosed={() => { q.reload(); onAuthorClosed?.(); }} />
            <div className="native-snapshot-meta" role="status">
              <span><LockKeyhole size={12} />{str(snapshot.source, "来源未提供")} · 版本 {str(snapshot.revision)}</span>
              <span>观察 {date(snapshot.as_of)}{q.loading ? " · 正在更新" : q.error ? " · 保留上次成功快照" : ""}</span>
            </div>
            <section className="native-root-observation" aria-label="原生 root 结果观察">
              <div className="native-section-heading"><h3><Bot size={15} />{executorName}</h3><span className="native-pill">{attempt ? str(attempt.state) : "尝试身份未提供"}</span></div>
              <dl className="native-identity">
                <dt>ForgeFlow 尝试 / 任务修订</dt><dd><code>{str(attempt?.attempt_id)}</code> / {count(attempt?.task_revision)}</dd>
                <dt>Worker / 租约代次</dt><dd>{str(attempt?.worker_id)} / {count(attempt?.generation)}</dd>
                <dt>原生根会话</dt><dd><code>{rootSession ?? "UNKNOWN · 结果尚未提供可展示的原生会话身份"}</code></dd>
                <dt>执行结果 / 进程退出</dt><dd>{completionReason ?? "尚未返回可展示的执行结果"} / {count(exitCode)}</dd>
                <dt>物理退出确认</dt><dd>{resultEvidence.process_exit_confirmed === true ? "已登记真实进程退出确认" : resultEvidence.process_exit_confirmed === false ? "尚未确认退出" : "未提供"}</dd>
                <dt>原始流完整性</dt><dd>{transcriptCompleteness ?? "UNKNOWN · 尚未提供完整性观察"}</dd>
                {rawEventDigest && <><dt>原始事件 SHA256</dt><dd><code>{rawEventDigest}</code></dd></>}
              </dl>
              <p className="native-note">会话身份来自该尝试的实际执行结果；结果未返回时保持 UNKNOWN。根会话结果不证明 Native Team、子 Agent 或 Workflow 已运行，业务验收仍以尝试和独立验证记录为准。</p>
              <a href={`/runs/${path(attemptId)}?project=${path(projectId)}`}>打开该尝试的事件、日志与验证</a>
            </section>
            <section className="native-root-observation" aria-label="Capsule 绑定身份">
              <div className="native-section-heading"><h3><Layers size={15} />Capsule 身份</h3><span className="native-pill">{capsuleUnbound ? "UNBOUND" : capsuleBound ? "BOUND_IDENTITY_CHECKED" : "UNKNOWN"}</span></div>
              {capsuleQ.error && <ErrorNotice error={capsuleQ.error} onRetry={capsuleQ.reload} />}
              {capsuleQ.loading && !capsuleQ.data ? <p className="native-note" role="status">正在读取原始 Capsule 绑定…</p>
                : capsuleUnbound ? <p className="native-note">此尝试没有登记 Capsule 绑定。历史尝试保留 UNBOUND，不补造资格或重新封存；既有尝试、资源与验收记录继续独立展示。</p>
                  : capsuleBound ? <>
                    <dl className="native-identity">
                      <dt>Capsule ID</dt><dd><code>{`capsule:${attemptId}`}</code></dd>
                      <dt>驱动 / 执行种类</dt><dd>{typeof capsule.driver_id === "string" && ["DSH", "CLAUDE_CODE"].includes(capsule.driver_id) ? capsule.driver_id : "UNKNOWN"} / {observedCode(capsule.execution_kind) ?? "UNKNOWN"}</dd>
                      <dt>写策略 / 租约代次</dt><dd>{observedCode(capsule.team_write_policy) ?? "UNKNOWN"} / {count(capsuleEnvelope.generation)}</dd>
                      <dt>原始信封 SHA256</dt><dd><code>{observedDigest(capsuleEnvelope.sha256) ?? "UNKNOWN"}</code></dd>
                      <dt>冻结执行器 CAS SHA256</dt><dd><code>{observedDigest(capsule.executor_profile_sha256) ?? "UNKNOWN"}</code></dd>
                      <dt>资格原件 Artifact ID</dt><dd><code>{observedArtifact(capsuleQualification.artifact_id) ?? "UNKNOWN"}</code></dd>
                      <dt>资格原件 SHA256</dt><dd><code>{observedDigest(capsuleQualification.sha256) ?? "UNKNOWN"}</code></dd>
                      <dt>已登记根会话 / 尚占用生命周期</dt><dd>{observedSession(capsuleView.native_root_session_id) ?? "UNKNOWN"} / {count(capsuleView.occupied_native_lifecycles)}</dd>
                    </dl>
                    <p className="native-note">已核对原始绑定身份；此读取没有重新评估运行资格，也不授予租约或写权限。尚占用生命周期包含隔离占位，不能视为正在运行的 Agent。</p>
                  </> : !capsuleQ.error && <p className="native-note">尚未取得匹配本项目、此尝试的公开绑定身份，不能推断已绑定或未绑定。</p>}
            </section>
            <div className="native-metrics">
              <div><span>生命周期记录</span><strong>{lifecycleAvailable ? count(lifecycles.length) : "—"}</strong><small>包含恢复与上下文重建历史</small></div>
              <div><span>尚未释放</span><strong>{lifecycleAvailable ? count(unreleased.length) : "—"}</strong><small>借用根分配与子分配分别核算</small></div>
              <div><span>隔离 / 已撤权</span><strong>{lifecycleAvailable ? `${count(lifecycles.filter(row => row.state === "QUARANTINED").length)} / ${count(lifecycles.filter(row => row.revoked === true).length)}` : "—"}</strong><small>撤权不直接认定资源已释放</small></div>
              <div><span>模型请求 / 未完整结算</span><strong>{modelsAvailable ? `${count(modelRequests.length)} / ${count(pendingRequests.length)}` : "—"}</strong><small>费用状态按实际记录展示</small></div>
            </div>
            <details className="native-profile">
              <summary><Layers size={14} /><span>冻结工作模式</span><code>{str(nativeProfile?.mode_id, "未提供模式身份")}</code></summary>
              {nativeProfile ? <>
                <dl><dt>执行器</dt><dd>{str(nativeProfile.executor_profile_id)} · {str(nativeProfile.executor_kind)}</dd>
                  <dt>资源 / 模型档案</dt><dd>{str(nativeProfile.resource_profile_id)} / {str(nativeProfile.model_route_id)}</dd>
                  <dt>Preset SHA256</dt><dd><code>{str(nativeProfile.preset_sha256, "冻结记录未提供摘要")}</code></dd>
                  <dt>子 Agent 政策</dt><dd>{policy.enabled === true ? "允许按冻结限额准入" : policy.enabled === false ? "冻结政策禁止子 Agent" : "冻结记录未提供"}</dd>
                </dl>
                {Object.keys(policy).length > 0 && <div className="native-policy-limits">
                  <span>同时活动 {count(policy.max_live_agents)}</span><span>生命周期 {count(policy.max_lifecycles)}</span>
                  <span>委派深度 {count(policy.max_delegation_depth)}</span><span>模型并行 {count(policy.model_inflight_limit)}</span>
                </div>}
                {policy.child_resources !== undefined && policy.child_resources !== null && <div className="native-policy-limits" aria-label="每个子 Agent 的冻结资源预算">
                  <span>子 Agent 冻结预算</span>
                  {dimensions.map(([dimension, label]) => <span key={dimension}>{label} {amount(object(policy.child_resources)[dimension], dimension)}</span>)}
                </div>}
                <div className="native-capabilities" aria-label="冻结配置中的插件能力">
                  {capabilities === undefined ? <p className="native-note">冻结记录未提供 Workflow、Agent Teams 或 Subagent 等插件能力清单。</p>
                    : !capabilities.length ? <p className="native-note">冻结能力清单为空。</p>
                      : capabilities.map(capability => <span className="native-pill" key={capability}>{capabilityNames[capability] ?? capability}</span>)}
                </div>
                <p className="native-note">此处展示准入时冻结的配置；实际启用与执行资格需对应运行证据。</p>
              </> : <p className="native-note">当前服务未提供该尝试的冻结模式投影。</p>}
            </details>
            {!lifecycleAvailable ? <EmptyState title="当前服务未提供原生生命周期账本" description="尝试运行与原生子 Agent 是不同记录，不能由尝试状态推断子 Agent 已启动。" />
              : !lifecycles.length ? <EmptyState title="该尝试暂无原生 Agent 生命周期记录" description="尚无可展示的实际父子会话与资源分配。模型请求记录仍按权威快照显示。" />
                : <div className="native-workspace">
                  <section className="native-lineage" aria-label="原生 Agent 父子层级">
                    <div className="native-lineage-heading"><h3><GitBranch size={15} />会话层级</h3><small>{matched.size} 个匹配</small></div>
                    <div className="native-filters">
                      <label className="native-search" htmlFor={searchId}><Search size={13} /><input id={searchId} type="search" value={search} placeholder="搜索会话、模型或分配 ID" aria-label="搜索原生 Agent" onChange={event => setSearch(event.target.value)} /></label>
                      <select aria-label="生命周期状态筛选" value={stateFilter} onChange={event => setStateFilter(event.target.value)}>
                        <option value="">全部状态</option><option value="HELD">占用中</option><option value="QUARANTINED">隔离占位</option><option value="RELEASED">已释放</option>
                      </select>
                    </div>
                    <p className="native-note">筛选保留匹配会话的父级上下文；按真实 allocation 身份区分恢复历史。</p>
                    {!filtered.length ? <p className="native-filter-empty">当前筛选没有匹配会话。</p>
                      : <ol className="native-tree">{filtered.slice(0, visibleCount).map(({ lifecycle: row, depth, anomaly }) => {
                        const key = str(row.allocation_id, "");
                        return <li key={key} className={matched.has(key) ? undefined : "native-context-row"}>
                          <button type="button" className="native-tree-row" aria-pressed={selected === key} onClick={() => setSelected(key)}
                            style={{ "--native-depth": Math.min(depth, 5) } as CSSProperties}>
                            <span className="native-tree-symbol" aria-hidden="true">{depth > 0 ? <GitBranch size={14} /> : <Bot size={16} />}</span>
                            <span className="native-tree-copy"><strong>{str(row.native_session_id)}</strong>
                              <small>{row.borrowed_parent_reservation === true ? "根会话 · 借用尝试分配" : "子 Agent"} · 第 {count(row.lifecycle_number)} 次生命周期 · {sourceNames[str(row.source)] ?? str(row.source)}</small>
                              <span className="native-tree-state"><StatusBadge state={str(row.state)} />{row.revoked === true && <span className="native-pill">已撤权</span>}{anomaly && <span className="native-pill" title={anomaly}>层级待核对</span>}</span>
                            </span><ChevronRight size={13} aria-hidden="true" />
                          </button>
                        </li>;
                      })}</ol>}
                    {filtered.length > visibleCount && <button className="native-load-more" type="button" onClick={() => setVisibleCount(previous => previous + 100)}>继续显示 {Math.min(100, filtered.length - visibleCount)} 条 · 共 {filtered.length} 条</button>}
                  </section>
                  <section className="native-agent-detail" aria-label="选中 Agent 详情">
                    {selectedLifecycle ? <>
                      <header className="native-detail-heading"><div><span className="native-eyebrow">NATIVE SESSION</span><h3>{str(selectedLifecycle.native_session_id)}</h3></div><StatusBadge state={str(selectedLifecycle.state)} /></header>
                      {selectedEntry?.anomaly && <p className="native-note" role="status">{selectedEntry.anomaly}</p>}
                      <dl className="native-identity">
                        <dt>分配身份</dt><dd><code>{selected}</code></dd>
                        <dt>父会话 / 根会话</dt><dd>{str(selectedLifecycle.parent_session_id, "根会话，无父级")} / {str(selectedLifecycle.root_session_id)}</dd>
                        <dt>模型路由 / 输出上限</dt><dd>{str(selectedLifecycle.provider)} / {str(selectedLifecycle.model)} · {count(selectedLifecycle.max_output_tokens)}</dd>
                        <dt>Worker / 租约代次 / 委派深度</dt><dd>{str(selectedLifecycle.worker_id)} / {str(selectedLifecycle.generation)} / {count(selectedLifecycle.delegation_depth)}</dd>
                        <dt>撤权 / 会话关闭 / 进程停止</dt><dd>{selectedLifecycle.revoked === true ? "已撤权" : selectedLifecycle.revoked === false ? "未撤权" : "未提供"} / {date(selectedLifecycle.disposed_at)} / {date(selectedLifecycle.process_stopped_at)}</dd>
                        <dt>获分配 / 释放</dt><dd>{date(selectedLifecycle.acquired_at)} / {date(selectedLifecycle.released_at)}</dd>
                        {!!selectedLifecycle.release_reason && <><dt>释放原因</dt><dd>{str(selectedLifecycle.release_reason)}</dd></>}
                      </dl>
                      <ResourceScopes lifecycle={selectedLifecycle} allocations={selectedAllocations} limits={rows(snapshot.resource_limits)} available={Array.isArray(allocationCollection)} />
                    </> : <p className="native-note">选择会话查看冻结路由与分配。</p>}
                  </section>
                </div>}
            <ModelRequests requests={modelRequests} selectedAllocation={selected} available={modelsAvailable} />
            <p className="native-panel-footnote">停止协作请进入尝试页请求停止。撤权、模型结算与实际进程停止分别留痕；会话观察不授予新的控制权。{autoRefresh && needsRefresh ? " 活动期间每 5 秒读取快照，隐藏页面暂停定时读取。" : ""}</p>
          </>}
  </Panel>;
}
