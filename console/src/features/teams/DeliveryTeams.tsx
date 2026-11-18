import { useEffect, useId, useMemo, useState } from "react";
import { ArrowUpRight, Bot, CheckCircle2, ChevronRight, GitBranch, Layers, ListChecks, RefreshCw, Search, ShieldCheck, Users } from "lucide-react";
import { api, ApiError, useApi } from "../../app/api";
import { Drawer, EmptyState, ErrorNotice, JsonView, StatusBadge } from "../../components";
import { useCollection } from "../portfolio/collection";
import { useCommandIdentity } from "../portfolio/commands";
import { activeStates, date, id, num, object, path, rows, str, type Row } from "../portfolio/monitor";
import { NativeAgentPanel } from "../runs/NativeAgentPanel";
import "./delivery-teams.css";

const capabilities: Record<string, string> = {
  workflow: "Workflow", agent_teams: "Agent Teams", subagent: "Subagent",
  one_shot_subagent: "单次子 Agent", fork_subagent: "分叉子 Agent",
  planning: "规划", skills: "Skills", checkpoint: "检查点",
  goal_tracking: "目标跟踪", context_compaction: "上下文压缩", todo: "任务清单",
};
const count = (value: number | undefined) => value === undefined ? "—" : value.toLocaleString("zh-CN");
const strings = (value: unknown): string[] => Array.isArray(value)
  ? value.map(item => typeof item === "string" ? item : str(object(item).code ?? object(item).message ?? item)).filter(Boolean) : [];
const cardId = (row: Row) => str(row.task_id ?? row.card_id, "");
function payload(value: unknown): { value: Row; error?: Error } {
  const row = object(value);
  if (typeof row.content === "string") {
    try { return { value: object(JSON.parse(row.content)) }; }
    catch { return { value: {}, error: new Error("登记来源不是有效 JSON，无法读取交付事实。") }; }
  }
  return { value: Object.keys(object(row.value)).length ? object(row.value) : row };
}
function blockers(row: Row): string[] {
  return [...new Set([
    ...strings(row.admission_blockers), ...strings(row.blocking_reasons), ...strings(row.blockers),
    ...strings(object(row.metadata).admission_blockers),
  ])];
}
function CardMetric({ icon, label, value, note }: {
  icon: React.ReactNode; label: string; value: string; note: string;
}) {
  return <div className="delivery-metric"><span className="delivery-metric-icon">{icon}</span>
    <span className="delivery-metric-label">{label}</span><strong className="delivery-metric-value">{value}</strong>
    <span className="delivery-metric-note">{note}</span></div>;
}
function PathList({ title, paths }: { title: string; paths: unknown }) {
  const values = strings(paths);
  return <section><h4>{title} · {values.length}</h4>{values.length
    ? <ul className="delivery-contract-list">{values.map((value, index) => <li key={`${index}-${value}`}><code>{value}</code></li>)}</ul>
    : <p className="delivery-note">未登记</p>}</section>;
}

export function DeliveryTeams({ projectId }: { projectId: string }) {
  const root = `/projects/${path(projectId)}`;
  const snapshotQ = useApi<unknown>(`${root}/snapshot`);
  const flowQ = useApi<unknown>(`${root}/flows/latest`);
  const cardsQ = useCollection<Row>(`${root}/documents/planning_cards`);
  const catalogsQ = useCollection<Row>(`${root}/documents/planning_catalogs`);
  const settingsQ = useApi<unknown>(`${root}/documents/delivery_settings/default`);
  const settings = object(settingsQ.data);
  const contextsQ = useCollection<Row>(settings.context_count ? `${root}/documents/agent_contexts` : null);
  const catalogRows = catalogsQ.data?.map(row => payload(row).value) ?? [];
  const catalogId = str(settings.planning_catalog_id, "") || (catalogRows.length === 1 ? str(catalogRows[0].catalog_id ?? catalogRows[0].id, "") : "");
  const selectedCatalog = catalogRows.find(row => (row.catalog_id ?? row.id) === catalogId);
  const sourceRefs = object(settings.source_refs ?? object(selectedCatalog).source_refs);
  const rosterId = str(sourceRefs.roster, "");
  const capabilitiesId = str(sourceRefs.capabilities, "");
  const sourceUrl = (value: unknown) => typeof value === "string" && value ? `${root}/sources/${path(value)}` : null;
  const rosterQ = useApi<unknown>(sourceUrl(sourceRefs.roster));
  const catalogSourceQ = useApi<unknown>(sourceUrl(sourceRefs.catalog));
  const deliveryQ = useApi<unknown>(sourceUrl(sourceRefs.delivery));
  const capabilitiesQ = useApi<unknown>(sourceUrl(sourceRefs.capabilities));
  const profilesQ = useCollection<Row>(`${root}/documents/executor_profiles`);
  const queueQ = useCollection<Row>(`${root}/queue-entries`);
  const commandIdentity = useCommandIdentity();
  const searchId = useId();
  const [tab, setTab] = useState("overview");
  const [search, setSearch] = useState("");
  const [owner, setOwner] = useState("");
  const [cardState, setCardState] = useState("");
  const [page, setPage] = useState(0);
  const [selectedCard, setSelectedCard] = useState<Row>();
  const [selectedAttempt, setSelectedAttempt] = useState("");
  const [showNative, setShowNative] = useState(false);
  const [autoRefresh, setAutoRefresh] = useState(true);
  const [busy, setBusy] = useState(false);
  const [commandError, setCommandError] = useState<Error>();
  const [commandReceipt, setCommandReceipt] = useState<Row>();
  const snapshot = object(snapshotQ.data);
  const project = object(snapshot.project);
  const flow = object(flowQ.data);
  const deliveryResult = useMemo(() => payload(deliveryQ.data), [deliveryQ.data]);
  const rosterResult = useMemo(() => payload(rosterQ.data), [rosterQ.data]);
  const catalogResult = useMemo(() => payload(catalogSourceQ.data), [catalogSourceQ.data]);
  const capabilitiesResult = useMemo(() => payload(capabilitiesQ.data), [capabilitiesQ.data]);
  const delivery = deliveryResult.value;
  const nativePanelUrl = settings.native_panel_enabled === true ? `/api/v1/projects/${path(projectId)}/native-panel/open` : null;
  const registeredCatalog = catalogsQ.data?.map(row => payload(row).value).find(row => (row.catalog_id ?? row.id) === catalogId);
  const catalog = registeredCatalog ?? catalogResult.value;
  const typedCards = useMemo<Row[] | undefined>(() => cardsQ.data?.filter(row => row.catalog_id === catalogId).map(row => ({
    ...object(object(row.metadata).source_card), ...object(row.metadata), ...object(row.task), task_id: row.task_id ?? object(row.task).task_id,
    metadata: row.metadata, spec: row.spec, catalog_id: row.catalog_id, catalog_revision: row.revision,
    admission_blockers: row.admission_blockers ?? object(row.metadata).admission_blockers,
    unbound_input_paths: row.unbound_input_paths,
  })), [cardsQ.data, catalogId]);
  const sourceCards = useMemo(() => rows(catalogResult.value.cards), [catalogResult.value]);
  const allCards = typedCards?.length ? typedCards : sourceCards;
  const catalogAvailable = cardsQ.data !== undefined || Array.isArray(catalogResult.value.cards);
  const typedRegisteredCount = cardsQ.data === undefined ? undefined : typedCards?.length ?? 0;
  const roleSource = [rosterResult.value.roles, rosterResult.value.positions, rosterResult.value.roster, catalog.roles, catalog.roster].find(Array.isArray);
  const roles = rows(roleSource);
  const rolesAvailable = roleSource !== undefined && !rosterResult.error;
  const teams = rows(snapshot.teams);
  const attempts = rows(snapshot.attempts);
  const native = rows(snapshot.native_child_lifecycles);
  const requests = rows(snapshot.native_model_requests);
  const nativeAvailable = Array.isArray(snapshot.native_child_lifecycles);
  const running = attempts.filter(row => row.state === "RUNNING");
  const nativeHeld = native.filter(row => row.state === "HELD" && row.revoked !== true);
  const unknownRequests = requests.filter(row => row.status === "QUARANTINED" || row.usage_complete !== true && row.status !== "ADMITTED");
  const committed = flow.state === "COMMITTED";
  const flowTasks = rows(flow.tasks);
  const tasksById = useMemo(() => new Map(flowTasks.map(row => [cardId(row), row])), [flowQ.data]);
  const canonicalTasksById = useMemo(() => new Map(rows(snapshot.tasks).map(row => [cardId(row), row])), [snapshotQ.data]);
  const queuedById = useMemo(() => new Map((queueQ.data ?? []).map(row => [str(row.task_id), row])), [queueQ.data]);
  const executable = committed ? flowTasks.filter(row => Object.keys(object(row.envelope)).length > 0) : [];
  const currentCardIds = new Set(allCards.map(cardId));
  const catalogCommitted = committed ? flowTasks.filter(row => currentCardIds.has(cardId(row))) : [];
  const succeededCards = new Set(attempts.filter(row => row.state === "SUCCEEDED" && currentCardIds.has(str(row.task_id)))
    .map(row => str(row.task_id)));
  const filtered = useMemo(() => allCards.filter(row => {
    const canonical = tasksById.get(cardId(row));
    const state = canonical?.state ?? row.state ?? "NEEDS_REVIEW";
    return (!owner || row.owner_id === owner || row.owner === owner)
      && (!cardState || state === cardState)
      && (!search || [cardId(row), row.title, row.business_outcome, row.owner_id, row.parent_task]
        .some(value => str(value, "").toLocaleLowerCase().includes(search.trim().toLocaleLowerCase())));
  }), [allCards, tasksById, owner, cardState, search]);
  const pageSize = 40;
  const pageCount = Math.max(1, Math.ceil(filtered.length / pageSize));
  const currentPage = Math.min(page, pageCount - 1);
  const active = attempts.some(row => activeStates.has(str(row.state))) || requests.some(row => row.status === "ADMITTED");
  const selectedExecution = attempts.find(row => row.attempt_id === selectedAttempt)
    ?? running[0] ?? [...attempts].reverse()[0];
  const selectedCardDetailQ = useApi<unknown>(selectedCard?.catalog_id ? `${root}/documents/planning_cards/${path(cardId(selectedCard))}` : null);
  const selectedDetail = object(selectedCardDetailQ.data);
  const selectedDisplay: Row | undefined = selectedCard ? {
    ...selectedCard, ...object(object(selectedDetail.metadata).source_card), ...object(selectedDetail.metadata), ...object(selectedDetail.task),
    spec: selectedDetail.spec ?? selectedCard.spec, metadata: selectedDetail.metadata ?? selectedCard.metadata,
    admission_blockers: selectedDetail.admission_blockers ?? selectedCard.admission_blockers,
  } : undefined;
  const selectedCanonical = selectedCard && tasksById.has(cardId(selectedCard))
    ? canonicalTasksById.get(cardId(selectedCard)) ?? tasksById.get(cardId(selectedCard)) : undefined;
  const selectedQueue = selectedCard ? queuedById.get(cardId(selectedCard)) : undefined;
  const sourceErrors = [settingsQ.error, rosterQ.error, catalogSourceQ.error, deliveryQ.error, capabilitiesQ.error]
    .filter(error => error && (!(error instanceof ApiError) || error.status !== 404));
  const parseErrors = [rosterResult.error, catalogResult.error, deliveryResult.error, capabilitiesResult.error].filter(Boolean);
  const currentIds = executable.map(row => cardId(row));
  useEffect(() => { setPage(0); }, [search, owner, cardState, projectId]);
  useEffect(() => {
    if (!autoRefresh) return;
    const refresh = () => { if (document.visibilityState === "visible") { snapshotQ.reload(); deliveryQ.reload(); if (active) queueQ.reload(); } };
    const timer = window.setInterval(refresh, active ? 5000 : 15000);
    return () => window.clearInterval(timer);
  }, [autoRefresh, active, snapshotQ.reload, deliveryQ.reload, queueQ.reload]);
  function refresh() {
    [snapshotQ, flowQ, cardsQ, catalogsQ, settingsQ, rosterQ, catalogSourceQ, deliveryQ, capabilitiesQ, profilesQ, queueQ, contextsQ].forEach(query => query.reload());
  }
  async function preview() {
    if (!selectedCanonical) return;
    setBusy(true); setCommandError(undefined); setCommandReceipt(undefined);
    try {
      const route = `${root}/tasks/${path(cardId(selectedCanonical))}/admission-checks`;
      setCommandReceipt(object(await api.post<unknown>(route, {}, commandIdentity(route, {}))));
    } catch (error) { setCommandError(error instanceof Error ? error : new Error(String(error))); }
    finally { setBusy(false); }
  }

  return <div className="delivery-workspace">
    <header className="delivery-hero"><div className="delivery-hero-copy">
      <span className="delivery-eyebrow">WORKFLOW · AGENT TEAMS</span>
      <h2>{str(project.name, "项目交付工作区")}</h2>
      <p>完整规划、专业岗位与真实执行在同一条交付链上。</p>
      <div className="delivery-hero-meta"><span>目标 · {count(num(settings.expected_positions ?? catalog.position_count))} 岗位 / {count(num(settings.expected_card_count ?? catalog.card_count))} 卡</span>
        <span>指定模型 · {str(settings.model_display, "以项目配置为准")}</span><span>运行模型 ID · {str(delivery.model_id ?? object(delivery.model).model_id, "等待绑定")}</span></div>
    </div><div className="delivery-hero-links">{nativePanelUrl && <a href={nativePanelUrl} className="button primary">在 DSH 操作面板中开发 <ArrowUpRight size={14} /></a>}
      <a href={`/projects/${path(projectId)}/flows`} className="button">检查 Flow <ArrowUpRight size={14} /></a>
      <a href={`/projects/${path(projectId)}/runs`} className="button primary">查看真实执行 <ArrowUpRight size={14} /></a></div></header>
    <div className="delivery-topbar"><span className="delivery-source">{str(snapshot.source, "等待权威快照")} · 事件版本 {str(snapshot.revision, "—")} · {snapshot.as_of ? date(snapshot.as_of) : "尚未观察"}</span>
      <div className="delivery-toolbar"><label><input type="checkbox" checked={autoRefresh} onChange={event => setAutoRefresh(event.target.checked)} />自动更新</label>
        <button type="button" className="delivery-refresh" disabled={snapshotQ.loading} onClick={refresh}><RefreshCw size={14} />刷新全部</button></div></div>
    {snapshotQ.error && <ErrorNotice error={snapshotQ.error} onRetry={snapshotQ.reload} />}
    {[cardsQ.error, catalogsQ.error, flowQ.error, contextsQ.error, ...sourceErrors, ...parseErrors].map((error, index) => error && <ErrorNotice key={index} error={error} />)}
    <div className="delivery-metric-grid">
      <CardMetric icon={<ListChecks size={18} />} label="完整任务登记" value={`${count(typedRegisteredCount)} / ${count(num(settings.expected_card_count ?? catalog.card_count))}`} note={cardsQ.loading ? "正在遍历完整分页" : "按已登记 planning_cards 计数"} />
      <CardMetric icon={<Users size={18} />} label="专业岗位" value={count(rolesAvailable ? roles.length : undefined)} note="规划身份；实际会话单独计量" />
      <CardMetric icon={<Bot size={18} />} label="正在执行 / Native 占用" value={`${count(snapshotQ.data ? running.length : undefined)} / ${count(nativeAvailable ? nativeHeld.length : undefined)}`} note="实际 RUNNING 尝试 / 未撤权 HELD 生命周期" />
      <CardMetric icon={<CheckCircle2 size={18} />} label="本目录验收完成" value={count(catalogAvailable && snapshotQ.data ? succeededCards.size : undefined)} note="仅计匹配目录卡 ID 的 SUCCEEDED 尝试" />
    </div>
    {Boolean(settings.context_count) && <section className="delivery-card" aria-label="独立 Agent 上下文">
      <div className="delivery-card-heading"><h3><Layers size={16} />独立 Agent 上下文</h3><span className="delivery-tag">活跃上限 {count(num(settings.active_limit))}</span></div>
      <p>已持久化 {count(contextsQ.data?.length)} 个独立上下文。启用档位：1 / 4 / 10 / 32 / 64；空闲上下文保存输入和历史，按需激活。</p>
      <p className="delivery-note">当前 RUNNING 尝试 {count(snapshotQ.data ? running.length : undefined)}；物理进程与模型结果以执行证据为准。</p>
    </section>}
    <div className="delivery-tabs" role="tablist" aria-label="交付工作区视图">
      {[["overview", "交付链路"], ["catalog", "全量任务卡"], ["roles", "岗位名册"], ["capabilities", "DSH 插件与预设"]].map(([key, label]) =>
        <button key={key} type="button" role="tab" aria-selected={tab === key} onClick={() => setTab(key)}>{label}</button>)}
    </div>
    {tab === "overview" && <div className="delivery-panels">
      <section className="delivery-card"><div className="delivery-card-heading"><h3><GitBranch size={16} />实际交付链</h3>
        <span className="delivery-tag">{flowQ.data ? `R${str(flow.flow_revision)} · ${str(flow.state)}` : "Flow 尚未读取"}</span></div>
        <ol className="delivery-pipeline">{[
          ["全量登记", typedRegisteredCount], ["当前 Flow 覆盖", flowQ.data && catalogAvailable ? catalogCommitted.length : undefined],
          ["配置已绑定", flowQ.data ? executable.length : undefined], ["持久候选", queueQ.data?.filter(row => row.status === "QUEUED").length],
          ["实际执行", snapshotQ.data ? running.length : undefined], ["验收完成", catalogAvailable && snapshotQ.data ? succeededCards.size : undefined],
        ].map(([label, value]) => <li className="delivery-pipeline-step" key={String(label)}><strong className="delivery-pipeline-value">{count(typeof value === "number" ? value : undefined)}</strong>
          <span className="delivery-pipeline-label">{label}</span></li>)}</ol>
        <p className="delivery-note">当前 Flow 覆盖与完整目录分别计算。执行配置、入队、模型回复和 main 集成都有独立记录。</p>
        <div className="delivery-phase-grid"><div className="delivery-phase"><span className="delivery-eyebrow">DELIVERY WINDOW</span><strong>{str(settings.delivery_window_label, "项目交付时间")}</strong>
          <p>{delivery.started_at ? `开始 ${date(delivery.started_at)}` : "开工时间尚未登记"}</p><p>{delivery.deadline_at ? `截止 ${date(delivery.deadline_at)}` : "截止时间尚未登记"}</p></div>
          <div className="delivery-phase"><span className="delivery-eyebrow">LIVE ADMISSION</span><strong>{str(delivery.state ?? delivery.status, "等待工作流状态")}</strong>
            <p>资源准入按本机预算；模型并行 {count(Array.isArray(snapshot.native_model_requests) ? requests.filter(row => row.status === "ADMITTED").length : undefined)}</p>
            <p>未知结算 / 隔离请求 {count(Array.isArray(snapshot.native_model_requests) ? unknownRequests.length : undefined)}</p></div></div>
        {blockers(delivery).length > 0 && <div className="delivery-blocked"><h4>下一步解阻</h4><ul>{blockers(delivery).map(reason => <li key={reason}>{reason}</li>)}</ul></div>}
        <p className="delivery-note">{nativePanelUrl ? "开发启动、暂停与重新规划通过原生 DSH 操作面板执行。" : "任务批准、资源准入和执行结果通过当前项目的规范流程登记。"}</p>
      </section>
      <section className="delivery-card"><div className="delivery-card-heading"><h3><Users size={16} />专业团队</h3><span>{count(Array.isArray(snapshot.teams) ? teams.length : undefined)} 个已登记团队</span></div>
        {!teams.length ? <EmptyState title="等待团队记录" /> : <div className="delivery-role-grid">{teams.map(team => {
          const teamId = id(team); const teamRoles = roles.filter(role => role.team_id === teamId);
          const cards = allCards.filter(card => card.team_id === teamId);
          const executions = running.filter(attempt => (attempt.team_id ?? canonicalTasksById.get(str(attempt.task_id))?.team_id) === teamId);
          return <div className="delivery-role" key={teamId}><div className="delivery-role-heading"><h4>{str(team.name)}</h4><StatusBadge state={team.paused === true ? "PAUSED" : "已登记"} /></div>
            <code className="delivery-role-id">{teamId}</code><div className="delivery-role-details"><span>岗位 {rolesAvailable ? count(teamRoles.length) : "—"}</span>
              <span>目录卡 {catalogAvailable ? count(cards.length) : "—"}</span><span>执行 {snapshotQ.data ? count(executions.length) : "—"}</span></div></div>;
        })}</div>}
      </section>
      <section className="delivery-card delivery-lineage"><div className="delivery-card-heading"><h3><Bot size={16} />真实 Agent 会话</h3>
        <button type="button" disabled={!attempts.length} onClick={() => setShowNative(value => !value)}>{showNative ? "收起层级与资源" : "展开层级与资源"}<ChevronRight size={14} /></button></div>
        {attempts.length ? <div className="delivery-toolbar"><label>选择尝试 <select aria-label="选择真实执行尝试" value={str(selectedExecution?.attempt_id, "")} onChange={event => setSelectedAttempt(event.target.value)}>
          {attempts.map(attempt => <option key={str(attempt.attempt_id)} value={str(attempt.attempt_id)}>{str(attempt.task_id)} · {str(attempt.state)} · {str(attempt.attempt_id)}</option>)}</select></label>
          <span>根会话、子 Agent 与孙 Agent 从冻结生命周期读取。</span></div> : <p className="delivery-note">当前快照没有尝试记录。</p>}
        {showNative && selectedExecution && <NativeAgentPanel projectId={projectId} attemptId={str(selectedExecution.attempt_id)} attemptState={str(selectedExecution.state)} />}
      </section>
    </div>}
    {tab === "catalog" && <section className="delivery-card"><div className="delivery-card-heading"><h3><ListChecks size={16} />全量任务卡目录</h3>
      <span>{count(filtered.length)} / {count(allCards.length)} · {typedCards?.length ? "正式登记目录" : "来源目录"}</span></div>
      <div className="delivery-filters"><label className="delivery-search" htmlFor={searchId}><Search size={15} /><input id={searchId} type="search" placeholder="搜索卡号、功能、Owner 或父任务" value={search} onChange={event => setSearch(event.target.value)} /></label>
        <select aria-label="任务 Owner" value={owner} onChange={event => setOwner(event.target.value)}><option value="">所有 Owner</option>
          {[...new Set(allCards.map(row => str(row.owner_id ?? row.owner, "")))].filter(Boolean).sort().map(value => <option key={value} value={value}>{value}</option>)}</select>
        <select aria-label="任务规划状态" value={cardState} onChange={event => setCardState(event.target.value)}><option value="">所有规划状态</option>
          {[...new Set(allCards.map(row => str(tasksById.get(cardId(row))?.state ?? row.state ?? "NEEDS_REVIEW")))].sort().map(value => <option key={value} value={value}>{value}</option>)}</select></div>
      {cardsQ.loading && !cardsQ.data && <p role="status" className="delivery-note">正在读取完整目录分页，统计将在完整读取后更新…</p>}
      {!allCards.length ? <EmptyState title={catalogAvailable ? "当前没有已登记卡" : "目录尚未读取"} description="完整目录登记后，可逐卡查看需求、依赖、所有权和阻塞原因。" />
        : <div className="delivery-table-wrap"><table className="delivery-catalog-table"><caption className="sr-only">完整任务卡及其实际 Flow 绑定状态</caption>
          <thead><tr><th>任务 / 功能</th><th>责任与阶段</th><th>规划 / 执行绑定</th><th>解阻项</th><th><span className="sr-only">详情</span></th></tr></thead>
          <tbody>{filtered.slice(currentPage * pageSize, (currentPage + 1) * pageSize).map(row => {
            const task = tasksById.get(cardId(row)); const reasons = blockers(row); const queue = queuedById.get(cardId(row));
            return <tr key={cardId(row)}><td><button type="button" className="delivery-link" onClick={() => { setSelectedCard(row); setCommandReceipt(undefined); setCommandError(undefined); }}>
              <strong>{str(row.title ?? row.business_outcome, cardId(row))}</strong><code>{cardId(row)}</code></button></td>
              <td><span>{str(row.owner_id ?? row.owner)} · {str(row.team_id)}</span><small>{str(row.parent_task ?? row.parent_task_id, "父任务未登记")} · 阶段 {str(row.phase, "—")}</small></td>
              <td><StatusBadge state={str(task?.state ?? row.state, "NEEDS_REVIEW")} /><small>{task && committed ? `当前 R${str(flow.flow_revision)}` : "等待进入当前提交 Flow"}</small>
                <small>{task?.envelope ? "配置已绑定" : "执行配置待绑定"}{queue ? ` · ${str(queue.status)}` : ""}</small></td>
              <td>{reasons.length ? <span title={reasons.join("\n")}>{reasons.length} 项 · {reasons[0]}</span> : <span>目录未提供阻塞项</span>}</td>
              <td><button type="button" aria-label={`打开 ${cardId(row)} 详情`} onClick={() => setSelectedCard(row)}><ChevronRight size={15} /></button></td></tr>;
          })}</tbody></table></div>}
      <div className="delivery-pagination"><span>第 {currentPage + 1} / {pageCount} 页 · 每页 {pageSize} 卡</span><button type="button" disabled={currentPage === 0} onClick={() => setPage(currentPage - 1)}>上一页</button>
        <button type="button" disabled={currentPage + 1 >= pageCount} onClick={() => setPage(currentPage + 1)}>下一页</button></div>
      <p className="delivery-note">历史完成记录保留在卡片来源中。目录登记不改变运行状态；当前版本与验收结果按真实 ID 对齐。</p>
    </section>}
    {tab === "roles" && <section className="delivery-card"><div className="delivery-card-heading"><h3><Users size={16} />专业岗位与配套预设</h3><span>{count(rolesAvailable ? roles.length : undefined)} 个实际登记岗位</span></div>
      {!roles.length ? <EmptyState title="岗位名册尚未登记" description={`等待 ${rosterId} 的实际名册；不会从团队数推算 Agent 数。`} />
        : <div className="delivery-role-grid">{roles.map((role, index) => <article className="delivery-role" key={str(role.role_id ?? role.position_id ?? role.agent_id ?? role.id, String(index))}>
          <div className="delivery-role-heading"><h4>{str(role.name ?? role.title ?? role.position ?? role.role, "岗位")}</h4><span className="delivery-tag">{str(role.state, "规划岗位")}</span></div>
          <code className="delivery-role-id">{str(role.role_id ?? role.position_id ?? role.agent_id ?? role.id)}</code><p>{str(role.responsibility ?? role.purpose ?? role.outcome, "职责未提供")}</p>
          <div className="delivery-role-details"><span>项目 Owner {str(role.owner_id ?? role.owner)}</span><span>{str(role.team_id)}</span></div>
          <dl><dt>Agent 预设</dt><dd>{str(role.agent_preset_id ?? role.preset_id ?? role.preset)}</dd><dt>执行器</dt><dd>{str(role.executor_profile_id ?? role.execution_profile)}</dd>
            <dt>Workflow</dt><dd>{str(role.workflow_id ?? role.workflow)}</dd><dt>父岗位</dt><dd>{str(role.parent_role_id ?? role.parent_agent_id, "根岗位 / 未登记父级")}</dd></dl>
          {strings(role.required_plugins ?? role.plugins).length > 0 && <div className="delivery-capability-tags">{strings(role.required_plugins ?? role.plugins).map(plugin => <span className="delivery-tag" key={plugin}>{capabilities[plugin] ?? plugin}</span>)}</div>}
        </article>)}</div>}
      <p className="delivery-note">岗位负责人与执行会话分别记录。下发和启动以当前提交 Flow、Worker 绑定及真实资源准入为准。</p>
    </section>}
    {tab === "capabilities" && <section className="delivery-card"><div className="delivery-card-heading"><h3><Layers size={16} />DSH 插件、Agent 预设与工作流</h3><span>{str(capabilitiesResult.value.state ?? capabilitiesResult.value.status, "资格尚未提供")}</span></div>
      {capabilitiesQ.data === undefined && <p className="delivery-note">等待实际插件审计来源 {capabilitiesId}。已登记执行器仍可读取；登记不自动授予运行资格。</p>}
      <div className="delivery-capability-grid">{(profilesQ.data ?? []).map(profile => {
        const mode = object(profile.native_mode); const auditProfiles = rows(capabilitiesResult.value.profiles ?? capabilitiesResult.value.presets);
        const audit = auditProfiles.find(row => (row.executor_profile_id ?? row.id ?? row.profile_id) === profile.id);
        const actualFrozen = rows(snapshot.attempt_native_profiles).filter(row => row.executor_profile_id === profile.id);
        const declared = strings(audit?.capabilities ?? profile.capabilities);
        const frozen = [...new Set(actualFrozen.flatMap(row => strings(row.capabilities)))];
        return <article className="delivery-capability" key={str(profile.id)}><div className="delivery-role-heading"><h4>{str(profile.id)}</h4><ShieldCheck size={16} /></div>
          <dl><dt>执行类型</dt><dd>{str(profile.kind)}</dd><dt>模式</dt><dd>{str(mode.mode_id, "无 Native 模式")}</dd><dt>模型路由</dt><dd>{str(profile.model_route_id, "无模型路由")}</dd>
            <dt>产物固定身份</dt><dd>{Array.isArray(profile.artifact_pins) ? `${profile.artifact_pins.length.toLocaleString("zh-CN")} 个实际 hash` : "当前 Profile 未提供"}</dd>
            <dt>实际资格</dt><dd>{str(audit?.qualification ?? audit?.status, "审计未绑定此 Profile")}</dd><dt>Preset SHA256</dt><dd><code>{str(audit?.preset_sha256 ?? actualFrozen[0]?.preset_sha256)}</code></dd></dl>
          <div className="delivery-capability-tags">{declared.map(value => <span className="delivery-tag" key={value}>{capabilities[value] ?? value}</span>)}</div>
          {frozen.length > 0 && <p className="delivery-note">实际尝试冻结能力：{frozen.map(value => capabilities[value] ?? value).join("、")}</p>}
          {!!audit?.qualified_scope && <p className="delivery-note">资格范围：{str(audit.qualified_scope)}</p>}
        </article>;
      })}</div>
      {profilesQ.error && <ErrorNotice error={profilesQ.error} onRetry={profilesQ.reload} />}
      {rows(capabilitiesResult.value.plugins).length > 0 && <div className="delivery-table-wrap"><table className="delivery-catalog-table"><thead><tr><th>插件</th><th>实际安装身份</th><th>状态</th><th>资格范围</th></tr></thead>
        <tbody>{rows(capabilitiesResult.value.plugins).map((plugin, index) => <tr key={str(plugin.id ?? plugin.name, String(index))}><td>{str(plugin.name ?? plugin.id)}</td><td><code>{str(plugin.sha256 ?? plugin.version)}</code></td>
          <td>{str(plugin.status ?? plugin.qualification)}</td><td>{str(plugin.qualified_scope ?? plugin.scope)}</td></tr>)}</tbody></table></div>}
      <p className="delivery-note">Capability 清单、安装摘要、准入冻结和真实执行资格分别展示。Workflow 与 Agent Teams 是否生效需要对应尝试证据。</p>
    </section>}
    {selectedCard && selectedDisplay && <Drawer title={str(selectedDisplay.title ?? selectedDisplay.business_outcome, cardId(selectedCard))} onClose={() => !busy && setSelectedCard(undefined)}>
      <p className="delivery-identity"><code>{cardId(selectedCard)}</code> · Owner {str(selectedCard.owner_id ?? selectedCard.owner)}</p>
      <div className="delivery-toolbar"><StatusBadge state={str(selectedCanonical?.state ?? selectedCard.state, "NEEDS_REVIEW")} />
        {selectedCanonical && <a href={`/projects/${path(projectId)}/tasks/${path(cardId(selectedCard))}`}>打开权威任务详情 <ArrowUpRight size={13} /></a>}</div>
      <div className="delivery-drawer-grid"><dl><dt>正式目录</dt><dd>{str(selectedCard.catalog_id, "来源目录尚未登记")}</dd><dt>当前 Flow</dt><dd>{selectedCanonical && committed ? `R${str(flow.flow_revision)}` : "尚未纳入当前提交版本"}</dd>
        <dt>规划修订</dt><dd>{str(selectedCanonical?.task_revision ?? selectedCard.task_revision)}</dd><dt>执行 Profile</dt><dd>{str(object(object(selectedCanonical?.envelope).executor).profile_id ?? object(selectedCard.spec).execution_profile)}</dd>
        <dt>队列</dt><dd>{str(selectedQueue?.status, "未入队 / 尚未读取")}</dd></dl></div>
      {selectedCardDetailQ.error && <ErrorNotice error={selectedCardDetailQ.error} onRetry={selectedCardDetailQ.reload} />}
      {selectedCardDetailQ.loading && <p className="delivery-note" role="status">正在读取完整卡片合同与验收声明…</p>}
      {blockers(selectedDisplay).length > 0 && <div className="delivery-blocked"><h4>目录解阻清单</h4><ul>{blockers(selectedDisplay).map(reason => <li key={reason}>{reason}</li>)}</ul></div>}
      <div className="delivery-toolbar"><button type="button" disabled={!selectedCanonical || busy} onClick={() => void preview()}><ShieldCheck size={14} />实际准入预检查</button>
        {nativePanelUrl && <a href={nativePanelUrl} className="button primary">在 DSH 操作面板中开发 <ArrowUpRight size={14} /></a>}</div>
      <p className="delivery-note">此处读取规划与准入事实；开发动作由原生 DSH 面板中的授权 Bridge 发起。</p>
      {commandError && <ErrorNotice error={commandError} />}
      {commandReceipt && <section className="delivery-card"><h4>服务端原始回执</h4><JsonView value={commandReceipt} /><p className="delivery-note">入队回执只证明候选登记；实际执行与验收继续按权威事件读取。</p></section>}
      <PathList title="需求映射" paths={selectedDisplay.requirement_ids} /><PathList title="精确读集合" paths={selectedDisplay.read_set} />
      <PathList title="精确写集合" paths={selectedDisplay.write_set} /><PathList title="正式依赖" paths={selectedDisplay.dependencies ?? selectedDisplay.predecessor_cards} />
      <details><summary>输入、合同与独立验收声明</summary><JsonView value={{ inputs: object(selectedDisplay.spec).inputs ?? selectedDisplay.inputs,
        contracts: { produces: object(selectedDisplay.spec).produces ?? selectedDisplay.contract_produces, consumes: object(selectedDisplay.spec).consumes ?? selectedDisplay.contract_requires },
        verification_plan: object(selectedDisplay.spec).verification_plan, definition_of_done: selectedDisplay.definition_of_done,
        catalog_metadata: selectedDisplay.metadata, current_executable_task_ids: currentIds }} /></details>
    </Drawer>}
  </div>;
}
