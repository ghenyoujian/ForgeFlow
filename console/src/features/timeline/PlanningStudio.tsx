import { useEffect, useMemo, useRef, useState } from "react";
import { ArrowRight, CalendarRange, ChartNoAxesCombined, Clock3, Filter, Play, Plus, RefreshCw, SlidersHorizontal, Trash2 } from "lucide-react";
import { api, ApiError, useApi } from "../../app/api";
import { DataTable, EmptyState, ErrorNotice, Field, Panel, SourceStamp } from "../../components";
import { object, num, path, rows, str, type Row } from "../portfolio/monitor";
import { EffortEstimate, weightedEffort, type PlanningInputs } from "./EffortEstimate";
import { useCollection } from "../portfolio/collection";
import { instant } from "./schedule";
import "./planning.css";

type WindowDraft = { id: string; start: string; end: string };
type ForecastRow = { task_id: string; owner_id: string; team_id: string; planned_start: string; planned_end: string; duration_hours: number; duration_source: string; critical_dependency_path: boolean; dependency_slack_hours: number; resource_or_calendar_wait_hours: number; scope_ids: string[] };
type Scenario = { forecast: { algorithm: string; rows: ForecastRow[]; blocked: { task_id: string; code: string; detail: string }[]; dependency_lower_bound_hours: number | null; complete: boolean; assumptions: string[] }; input_revision: number; planning_input_digest?: string; input_changed_since_request?: boolean; as_of: string; source: string; execution_rights_granted: false; worker_placement: string };
const dimensions = [["active_slot", "活动通道"], ["coding_slot", "编码通道"], ["cpu_units", "CPU 单位"], ["memory_bytes", "内存 GiB"], ["build_permit", "构建许可"], ["gpu_permit", "GPU 许可"], ["provider_inflight", "模型请求"]] as const;
const sources: Record<string, string> = { REVIEWED_TASK_ESTIMATE: "复核时长", CURRENT_PLAN_INTERVAL: "现有计划区间", USER_SCENARIO_OVERRIDE: "本次假设", UNKNOWN: "未知" };
const findings: Record<string, string> = { DURATION_UNKNOWN: "缺少排程时长", PREDECESSOR_UNSCHEDULED: "前置未排入", MISSING_PREDECESSOR: "前置不在范围", RESOURCE_SCOPE_UNQUALIFIED: "资源或责任绑定待核验", NO_FEASIBLE_WINDOW: "窗口或容量不足" };
function utc(value: string) { return value ? new Date(`${value}Z`).toISOString() : ""; }
function time(value: string) { const n = instant(value); return n === undefined ? "未知" : new Date(n).toISOString().slice(0, 16).replace("T", " "); }
function fmt(value: number | undefined | null) { return value == null || !Number.isFinite(value) ? "未知" : value.toLocaleString("zh-CN", { maximumFractionDigits: 2 }); }
function millis(value: string) { const n = Date.parse(`${value}Z`); return Number.isFinite(n) ? n : undefined; }

function limitedTaskChoices(tasks: Row[], query: string, selected: string) {
  const needle = query.trim().toLocaleLowerCase();
  const matches = tasks.filter(task => !needle || `${str(task.task_id)} ${str(task.title)}`.toLocaleLowerCase().includes(needle)).slice(0, 50);
  const picked = tasks.find(task => str(task.task_id) === selected);
  if (picked && !matches.includes(picked)) { matches.unshift(picked); if (matches.length > 50) matches.pop(); }
  return matches;
}

export function PlanningStudio({ projectId, writable = true, selectedTaskId, onTaskSelect, onAdopt }: { projectId: string; writable?: boolean; selectedTaskId?: string; onTaskSelect?: (taskId: string) => void; onAdopt?: (rows: { task_id: string; planned_start: string; planned_end: string }[]) => void }) {
  const inputsQ = useApi<PlanningInputs>(`/projects/${path(projectId)}/planning-inputs`);
  const attemptsQ = useCollection<Row>(`/projects/${path(projectId)}/attempts`);
  const inputs = inputsQ.error ? undefined : inputsQ.data;
  const [start, setStart] = useState(() => new Date().toISOString().slice(0, 16));
  const [end, setEnd] = useState(() => new Date(Date.now() + 7 * 86400000).toISOString().slice(0, 16));
  const [windows, setWindows] = useState<WindowDraft[]>([]);
  const [worker, setWorker] = useState("");
  const [capacityScope, setCapacityScope] = useState("");
  const [capacityTier, setCapacityTier] = useState(32);
  const [capacityOverrides, setCapacityOverrides] = useState<Record<string, number>>({});
  const [comparison, setComparison] = useState<Scenario>();
  const [overrideTask, setOverrideTask] = useState("");
  const [overrideQuery, setOverrideQuery] = useState('');
  const [estimateQuery, setEstimateQuery] = useState('');
  const [overrideHours, setOverrideHours] = useState("");
  const [overrides, setOverrides] = useState<Record<string, number>>({});
  const [scenario, setScenario] = useState<Scenario>();
  const [scenarioError, setScenarioError] = useState<unknown>();
  const [busy, setBusy] = useState(false);
  const [conflict, setConflict] = useState(false);
  const [query, setQuery] = useState("");
  const [owner, setOwner] = useState("");
  const [team, setTeam] = useState("");
  const [kind, setKind] = useState("all");
  const [page, setPage] = useState(0);
  const [blockedPage, setBlockedPage] = useState(0);
  const [capacityPage, setCapacityPage] = useState(0);
  const [localSelected, setLocalSelected] = useState("");
  const selected = selectedTaskId ?? localSelected;
  const setSelected = onTaskSelect ?? setLocalSelected;
  const [runIdentity, setRunIdentity] = useState({ form: "", digest: "", project: "" });
  const projectRef = useRef(projectId); projectRef.current = projectId;
  useEffect(() => { setScenario(undefined); setScenarioError(undefined); setConflict(false); setWorker(""); setOverrides({}); setOverrideTask(""); setLocalSelected(""); setPage(0); setOwner(""); setTeam(""); setQuery(""); }, [projectId]);
  const fingerprint = JSON.stringify([start, end, windows.map(w => [w.start, w.end]), worker, overrides, capacityOverrides]);
  const inputIdentity = inputs?.planning_input_digest ?? String(inputs?.revision ?? "");
  const visibleScenario = runIdentity.project === projectId ? scenario : undefined;
  const stale = !!visibleScenario && (runIdentity.digest !== inputIdentity || runIdentity.form !== fingerprint || !!inputsQ.error || inputsQ.loading);
  const validation = useMemo(() => {
    const errors: string[] = [], a = millis(start), b = millis(end);
    if (a === undefined || b === undefined || b <= a) errors.push("请选择有效开始与结束时间，结束须晚于开始。");
    else if (b - a > 366 * 86400000) errors.push("单次预览时间范围不能超过 366 天。");
    const sorted = windows.map(w => ({ start: millis(w.start), end: millis(w.end) })).sort((x, y) => (x.start ?? 0) - (y.start ?? 0));
    sorted.forEach((w, i) => {
      if (w.start === undefined || w.end === undefined || w.end <= w.start) errors.push(`工作窗口 ${i + 1} 需要有效正时长。`);
      else if (a !== undefined && b !== undefined && (w.start < a || w.end > b)) errors.push(`工作窗口 ${i + 1} 超出预览范围。`);
      if (i && w.start !== undefined && sorted[i - 1].end !== undefined && w.start < sorted[i - 1].end!) errors.push("工作窗口不能重叠。");
    });
    return [...new Set(errors)];
  }, [start, end, windows]);
  const tasks = inputs?.tasks ?? [];
  const taskMap = useMemo(() => new Map((inputs?.tasks ?? []).map(task => [str(task.task_id), task])), [inputs]);
  const maps = useMemo(() => {
    const estimates = new Map<string, Row>(), schedules = new Map<string, Row>();
    for (const doc of inputs?.documents ?? []) {
      const id = str(doc.value.task_id), old = doc.collection === "task_estimates" ? estimates.get(id) : schedules.get(id);
      if (doc.collection === "task_estimates" && taskMap.get(id)?.task_revision === doc.value.task_revision && (!old || Number(old.estimate_version) < Number(doc.value.estimate_version))) estimates.set(id, doc.value);
      if (doc.collection === "schedules" && (!old || Number(old.baseline_version) < Number(doc.value.baseline_version))) schedules.set(id, doc.value);
    }
    const effort = new Map<string, { hours?: number; historical: boolean }>();
    for (const [id] of taskMap) { const estimate = estimates.get(id); const hours = weightedEffort(object(estimate?.effort ?? schedules.get(id)?.effort_estimate)); effort.set(id, { hours, historical: !estimate && hours !== undefined }); }
    const allocation = new Map((inputs?.resource_limits ?? []).map(limit => [`${limit.scope_id}:${limit.dimension}`, limit]));
    return { estimates, effort, allocation };
  }, [inputs, taskMap]);
  const elapsed = useMemo(() => {
    const result = new Map<string, { hours: number; unknown: number; count: number; open: number }>();
    const observed = instant(attemptsQ.metadata.observed_at);
    for (const attempt of rows(attemptsQ.data)) {
      const id = str(attempt.task_id); if (taskMap.get(id)?.task_revision !== attempt.task_revision) continue;
      const value = result.get(id) ?? { hours: 0, unknown: 0, count: 0, open: 0 };
      const a = instant(attempt.created_at), b = instant(attempt.terminal_at) ?? observed;
      value.count++; if (attempt.terminal_at == null) value.open++;
      if (a === undefined || b === undefined || b < a) value.unknown++; else value.hours += (b - a) / 3600000;
      result.set(id, value);
    }
    return result;
  }, [attemptsQ.data, attemptsQ.metadata.observed_at, taskMap]);
  const policies = inputs?.resource_policies ?? [];
  const overrideChoices = useMemo(() => limitedTaskChoices(tasks, overrideQuery, overrideTask), [tasks, overrideQuery, overrideTask]);
  const estimateChoices = useMemo(() => limitedTaskChoices(tasks, estimateQuery, selected), [tasks, estimateQuery, selected]);
  const selectedTask = taskMap.get(selected);
  const allRows = visibleScenario?.forecast.rows ?? [], blocked = visibleScenario?.forecast.blocked ?? [];
  const capacityPolicies = policies.filter(p => !p.worker_id || p.scope_id === worker);
  const safeCapacityPage = Math.min(capacityPage, Math.max(0, Math.ceil(capacityPolicies.length / 8) - 1));
  const resourceDemand = useMemo(() => {
    const result = new Map<string, Map<string, { demand: number; unknown: number }>>();
    for (const row of allRows) {
      const request = object(taskMap.get(row.task_id)?.resource_request);
      for (const scope of row.scope_ids) {
        const values = result.get(scope) ?? new Map<string, { demand: number; unknown: number }>();
        for (const [dimension] of dimensions) {
          const value = values.get(dimension) ?? { demand: 0, unknown: 0 }, count = num(request[dimension]);
          if (count === undefined) value.unknown++; else value.demand += count * row.duration_hours / (dimension === "memory_bytes" ? 1073741824 : 1);
          values.set(dimension, value);
        }
        result.set(scope, values);
      }
    }
    return result;
  }, [visibleScenario, taskMap]);
  const filtered = allRows.filter(row => (!owner || row.owner_id === owner) && (!team || row.team_id === team) && (kind !== "critical" || row.critical_dependency_path) && (kind !== "delayed" || row.resource_or_calendar_wait_hours > 0)
    && (!query || `${row.task_id} ${str(taskMap.get(row.task_id)?.title, "")} ${row.owner_id} ${row.team_id}`.toLowerCase().includes(query.toLowerCase())));
  const safeBlockedPage = Math.min(blockedPage, Math.max(0, Math.ceil(blocked.length / 50) - 1));
  const safePage = Math.min(page, Math.max(0, Math.ceil(filtered.length / 50) - 1));
  useEffect(() => setPage(0), [query, owner, team, kind]);
  const workload = useMemo(() => {
    const completed = new Set(inputs?.completed_task_ids), pending = [...taskMap.keys()].filter(id => !completed.has(id));
    let effort = 0, known = 0, historical = 0;
    for (const id of pending) { const e = maps.effort.get(id); if (e?.hours !== undefined) { effort += e.hours; known++; if (e.historical) historical++; } }
    return { effort, known, historical, unknown: pending.length - known, total: pending.length, activeHours: allRows.reduce((sum, row) => sum + row.duration_hours, 0) };
  }, [inputs, maps, visibleScenario]);
  const available = validation.length ? undefined : (windows.length ? windows.reduce((sum, w) => sum + (millis(w.end)! - millis(w.start)!) / 3600000, 0) : (millis(end)! - millis(start)!) / 3600000);
  async function run() {
    if (!inputs || validation.length || busy) return;
    const requestProject = projectId, requestForm = fingerprint, requestDigest = inputIdentity;
    setBusy(true); setScenarioError(undefined); setConflict(false);
    try {
      const result = await api.post<Scenario>(`/projects/${path(projectId)}/planning-scenarios`, { input_revision: inputs.revision,
        ...(inputs.planning_input_digest ? { planning_input_digest: inputs.planning_input_digest } : {}), start_at: utc(start), end_at: utc(end),
        availability: windows.map(w => ({ start_at: utc(w.start), end_at: utc(w.end) })), ...(worker ? { worker_scope_id: worker } : {}), duration_overrides: overrides, capacity_overrides: capacityOverrides });
      if (projectRef.current !== requestProject) return;
      setScenario(result); setBlockedPage(0); setRunIdentity({ form: requestForm, digest: requestDigest, project: requestProject });
    } catch (error) { if (projectRef.current !== requestProject) return; setScenarioError(error); if (error instanceof ApiError && error.status === 409) setConflict(true); }
    finally { setBusy(false); }
  }
  function refresh() { inputsQ.reload(); attemptsQ.reload(); setConflict(false); }
  function addOverride() { const hours = Number(overrideHours); if (overrideTask && overrideHours.trim() && Number.isFinite(hours) && hours > 0 && hours <= 1_000_000) { setOverrides(prior => ({ ...prior, [overrideTask]: hours })); setOverrideTask(""); setOverrideHours(""); } }
  return <section className="planning-studio" aria-label="容量与工作量规划">
    <header className="planning-intro"><div><span className="planning-eyebrow">排程预览</span><h2><ChartNoAxesCombined size={21} strokeWidth={1.6} /><span>容量与工作量规划</span></h2><p>先复核工作量，再比较依赖、工作窗口与资源约束下的安排。</p></div><button disabled={inputsQ.loading || busy} onClick={refresh}><RefreshCw size={15} /> 更新规划输入</button></header>
    {inputsQ.error && <ErrorNotice error={inputsQ.error} onRetry={inputsQ.reload} />}
    {inputsQ.loading && <p className="planning-status" role="status">正在读取项目、任务、责任与资源的一致快照…</p>}
    {!inputs && !inputsQ.loading && !inputsQ.error && <EmptyState title="尚无规划输入" description="需要权威任务与资源快照后才能计算预览。" />}
    {inputs && <>
      <div className="planning-metrics">
        <div><span>待交付工作量 · 全部任务</span><strong>{workload.known ? fmt(workload.effort) : "未知"}<small>{workload.known ? "小时" : ""}</small></strong><p>{workload.known} / {workload.total} 项有估计 · {workload.unknown} 项未知{workload.historical ? ` · ${workload.historical} 项历史来源` : ""}</p></div>
        <div><span>窗口内预测占用时长</span><strong>{visibleScenario ? fmt(workload.activeHours) : "未计算"}<small>{visibleScenario ? "任务小时" : ""}</small></strong><p>累计全部预览行 · 并行任务分别计入{stale ? " · 结果待刷新" : ""}</p></div>
        <div><span>预览覆盖</span><strong>{visibleScenario ? `${allRows.length} / ${workload.total}` : "未计算"}</strong><p>{visibleScenario ? `${new Set(blocked.map(b => b.task_id)).size} 项阻塞 · ${visibleScenario.forecast.complete ? "输入范围已排入" : "仅部分排入"}` : "完整任务范围；筛选不改变汇总分母"}</p></div>
        <div><span>{visibleScenario?.forecast.complete ? "依赖时长下界" : "已知子图依赖时长下界"}</span><strong>{visibleScenario ? fmt(visibleScenario.forecast.dependency_lower_bound_hours) : "未计算"}<small>{visibleScenario?.forecast.dependency_lower_bound_hours != null ? "小时" : ""}</small></strong><p>缺失时长不计入；不包含资源与日历等待</p></div>
      </div>
      <div className="planning-setup">
        <Panel title={<><CalendarRange size={16} /> 预览范围与工作窗口</>} className="planning-form-panel"><form onSubmit={event => { event.preventDefault(); void run(); }}>
          <div className="form-grid"><Field label="开始（UTC）"><input type="datetime-local" value={start} onChange={e => setStart(e.target.value)} required /></Field><Field label="结束（UTC）"><input type="datetime-local" value={end} onChange={e => setEnd(e.target.value)} required /></Field><Field label="Worker 资源范围"><select value={worker} onChange={e => setWorker(e.target.value)}><option value="">未选择 · Worker 放置尚未核验</option>{policies.filter(p => typeof p.worker_id === "string" && p.worker_id).map(p => <option key={str(p.scope_id)} value={str(p.scope_id)}>{str(p.worker_id)} · {str(p.scope_id)}{p.paused ? " · 已暂停" : ""}</option>)}</select></Field></div>
          <p className="muted planning-help">所有时间均为 UTC。留空工作窗口时，整个范围连续可用；增加窗口可表达班次与休息。每项任务须完整放入单个窗口。</p>
          {windows.map((w, i) => <div className="planning-window" key={w.id}><Field label={`窗口 ${i + 1} 开始（UTC）`}><input type="datetime-local" value={w.start} onChange={e => setWindows(prior => prior.map(v => v.id === w.id ? { ...v, start: e.target.value } : v))} required /></Field><Field label={`窗口 ${i + 1} 结束（UTC）`}><input type="datetime-local" value={w.end} onChange={e => setWindows(prior => prior.map(v => v.id === w.id ? { ...v, end: e.target.value } : v))} required /></Field><button type="button" aria-label={`删除工作窗口 ${i + 1}`} onClick={() => setWindows(prior => prior.filter(v => v.id !== w.id))}><Trash2 size={15} /></button></div>)}
          <div className="planning-form-actions"><button type="button" disabled={windows.length >= 256} onClick={() => setWindows(prior => [...prior, { id: crypto.randomUUID(), start, end }])}><Plus size={14} /> 添加工作窗口</button><button className="primary" disabled={busy || inputsQ.loading || !!inputsQ.error || validation.length > 0 || conflict}><Play size={14} /> {busy ? "计算中…" : "计算排程预览"}</button></div>{validation.map(e => <p role="alert" key={e}>{e}</p>)}
        </form></Panel>
        <Panel title={<><SlidersHorizontal size={16} /> 时长假设</>} className="planning-form-panel"><p className="muted planning-help">搜索全部任务，列表显示前 50 个匹配项。假设仅用于本次预览。</p><div className="form-grid"><Field label="查找任务"><input aria-label="搜索时长假设任务" placeholder="输入任务名称或编号" value={overrideQuery} onChange={event => setOverrideQuery(event.target.value)} /></Field><Field label="任务"><select value={overrideTask} onChange={e => setOverrideTask(e.target.value)}><option value="">选择任务</option>{overrideChoices.map(t => <option key={str(t.task_id)} value={str(t.task_id)}>{str(t.title)} · {str(t.task_id)}</option>)}</select></Field><Field label="假设占用时长（小时）"><input type="number" min="0.001" max="1000000" step="any" value={overrideHours} onChange={e => setOverrideHours(e.target.value)} /></Field></div><button disabled={!overrideTask || !overrideHours.trim() || !(Number(overrideHours) > 0) || Number(overrideHours) > 1_000_000} onClick={addOverride}><Plus size={14} /> 应用时长假设</button><ul className="planning-overrides">{Object.entries(overrides).map(([id, hours]) => <li key={id}><span>{str(taskMap.get(id)?.title, id)}<small>{fmt(hours)} 小时 · {id}</small></span><button aria-label={`移除 ${id} 时长假设`} onClick={() => setOverrides(prior => { const next = { ...prior }; delete next[id]; return next; })}><Trash2 size={14} /></button></li>)}</ul>{!Object.keys(overrides).length && <p className="planning-quiet">当前使用权威输入中的时长来源。</p>}</Panel>
      </div>
      {!!scenarioError && <ErrorNotice error={scenarioError} onRetry={conflict ? refresh : () => void run()} />}
      {conflict && <p className="planning-status" role="status">输入版本已变化。刷新权威输入后重新计算；本次未写入排程。</p>}
      {stale && <div className="planning-status" role="status"><RefreshCw size={15} /> 预览输入或表单已变化。下方保留旧结果供查阅，请重新计算后用于安排。</div>}
      <Panel title="容量情景比较"><div className="toolbar"><select aria-label="情景容量范围" value={capacityScope} onChange={e => setCapacityScope(e.target.value)}><option value="">选择资源范围</option>{policies.map(p => <option key={str(p.scope_id)} value={str(p.scope_id)}>{str(p.scope_id)}</option>)}</select><select aria-label="情景活动档位" value={capacityTier} onChange={e => setCapacityTier(Number(e.target.value))}>{[1,4,10,32,64].map(n => <option key={n} value={n}>{n} 个活动槽位</option>)}</select><button disabled={!capacityScope} onClick={() => setCapacityOverrides(prior => ({ ...prior, [capacityScope]: capacityTier }))}>加入只读假设</button><button disabled={!Object.keys(capacityOverrides).length} onClick={() => setCapacityOverrides({})}>清除容量假设</button><button disabled={!visibleScenario || stale} onClick={() => setComparison(visibleScenario)}>保留当前预览作对照</button></div>{Object.entries(capacityOverrides).map(([scope, n]) => <p key={scope}>{scope}：假设 {n} 个活动槽位</p>)}{comparison && <p>对照预览：排入 {comparison.forecast.rows.length} 张，阻塞 {comparison.forecast.blocked.length} 项。当前预览：排入 {allRows.length} 张，阻塞 {blocked.length} 项。</p>}<p className="muted">假设只用于预测；实际内存、Worker 和供应商约束仍参与计算。</p></Panel>
      <details className="planning-resource-details"><summary>资源窗口负载与计算依据</summary><Panel title={<><Clock3 size={16} /> 资源窗口负载</>}><p className="muted planning-help">容量与已占量来自下方注明的输入观察时刻。已持有与隔离占用在整个预测窗口保留；预览可能读取更新占用，请同时查看结果来源时间。预测量累计全部预览行，未排入任务的需求未计入。</p><div className="planning-capacity">{capacityPolicies.slice(safeCapacityPage * 8, (safeCapacityPage + 1) * 8).map(policy => <article key={str(policy.scope_id)}><div className="planning-scope-heading"><strong>{str(policy.scope_id)}</strong><span>{policy.paused ? "已暂停" : policy.worker_id ? `Worker ${str(policy.worker_id)}` : policy.team_id ? `团队 ${str(policy.team_id)}` : policy.project_id ? "项目范围" : "全局范围"}</span></div><table><caption className="sr-only">{str(policy.scope_id)} 窗口容量</caption><thead><tr><th>维度</th><th>已占 / 上限</th><th>预测 × 小时</th><th>可用 × 小时</th></tr></thead><tbody>{dimensions.map(([dimension, label]) => {
        const held = num(maps.allocation.get(`${policy.scope_id}:${dimension}`)?.allocated), limit = num(object(policy.limits)[dimension]), unit = dimension === "memory_bytes" ? 1073741824 : 1;
        const { demand, unknown } = resourceDemand.get(str(policy.scope_id))?.get(dimension) ?? { demand: 0, unknown: 0 };
        const headroom = held === undefined || limit === undefined || available === undefined ? undefined : (policy.paused ? 0 : Math.max(0, limit - held) / unit * available);
        return <tr key={dimension}><th>{label}</th><td>{fmt(held === undefined ? undefined : held / unit)} / {fmt(limit === undefined ? undefined : limit / unit)}</td><td>{visibleScenario ? `${fmt(demand)}${unknown ? ` + ${unknown} 项未知` : ""}` : "未计算"}</td><td>{fmt(headroom)}</td></tr>;
      })}</tbody></table><p className="muted">汇总余量不能代替每一时刻的资源准入检查。</p></article>)}</div>{!policies.length && <EmptyState title="尚无资源政策" description="缺少层级资源约束时，预览保留阻塞原因。" />}{capacityPolicies.length > 8 && <div className="planning-pagination"><span>{capacityPolicies.length} 个政策范围 · 每页最多 8 个</span><button disabled={safeCapacityPage === 0} onClick={() => setCapacityPage(safeCapacityPage - 1)}>上一页资源</button><span>{safeCapacityPage + 1} / {Math.ceil(capacityPolicies.length / 8)}</span><button disabled={(safeCapacityPage + 1) * 8 >= capacityPolicies.length} onClick={() => setCapacityPage(safeCapacityPage + 1)}>下一页资源</button></div>}<SourceStamp source={inputs.source} observedAt={inputs.as_of} /></Panel></details>
      {onAdopt && visibleScenario && <div className="planning-draft-bar"><span>已排入 {allRows.length} 张任务 · {blocked.length} 项阻塞</span><button className="primary" disabled={!writable || stale || busy || !allRows.length || !!blocked.length} onClick={() => onAdopt(allRows)}>将预览作为日期草稿</button><small className="muted">先核对日期影响，再通过原有排程接口保存。</small></div>}
      <Panel title={<><Filter size={16} /> 预览任务</>} actions={<span className="planning-result-count">{filtered.length} / {allRows.length} 行</span>}><div className="planning-filters"><input aria-label="搜索预览任务" placeholder="搜索任务、Owner 或团队" value={query} onChange={e => setQuery(e.target.value)} /><select aria-label="筛选 Owner" value={owner} onChange={e => setOwner(e.target.value)}><option value="">全部 Owner</option>{[...new Set(tasks.map(t => str(t.owner_id)))].sort().map(id => <option key={id}>{id}</option>)}</select><select aria-label="筛选团队" value={team} onChange={e => setTeam(e.target.value)}><option value="">全部团队</option>{[...new Set(tasks.map(t => str(t.team_id)))].sort().map(id => <option key={id} value={id}>{str(inputs.teams.find(t => t.team_id === id)?.name, id)}</option>)}</select><select aria-label="筛选关键与延迟" value={kind} onChange={e => setKind(e.target.value)}><option value="all">全部路径</option><option value="critical">依赖关键路径</option><option value="delayed">资源或日历等待</option></select></div>
        <DataTable<ForecastRow> rows={filtered.slice(safePage * 50, (safePage + 1) * 50)} rowKey={r => r.task_id} onRowClick={r => setSelected(r.task_id)} empty={visibleScenario ? "当前筛选没有已排入任务；阻塞项见下方" : "设置时间窗口后计算预览"} columns={[
          { key: "task", label: "任务 / 责任", render: r => <span className="planning-task-title">{str(taskMap.get(r.task_id)?.title, r.task_id)}<small>{r.task_id} · {r.owner_id} · {r.team_id}</small></span> },
          { key: "effort", label: "工作量小时", render: r => <span>{fmt(maps.effort.get(r.task_id)?.hours)}{maps.effort.get(r.task_id)?.historical && <small>历史 Schedule</small>}</span> },
          { key: "duration", label: "占用时长 / 来源", render: r => <span>{fmt(r.duration_hours)} 小时<small>{sources[r.duration_source] ?? r.duration_source}</small></span> },
          { key: "elapsed", label: "实际准入耗时", render: r => { const e = elapsed.get(r.task_id); return <span>{attemptsQ.error || attemptsQ.loading ? "未知" : e ? `${fmt(e.unknown ? undefined : e.hours)} 小时` : "无尝试"}<small>{e?.open ? `${e.open} 项进行中 · 截至观察时间` : "包含等待与验证；非运行工时"}</small></span>; } },
          { key: "dates", label: "预测安排（UTC）", render: r => <span>{time(r.planned_start)}<small><ArrowRight size={11} /> {time(r.planned_end)}</small></span> },
          { key: "critical", label: "依赖路径", render: r => r.critical_dependency_path ? "关键路径" : `余量 ${fmt(r.dependency_slack_hours)} 小时` },
          { key: "wait", label: "资源 / 日历等待", render: r => `${fmt(r.resource_or_calendar_wait_hours)} 小时` },
        ]} />{!!allRows.length && <div className="planning-pagination"><span>每页最多 50 行 · 全部行参与汇总</span><button disabled={safePage === 0} onClick={() => setPage(safePage - 1)}>上一页</button><span>{safePage + 1} / {Math.max(1, Math.ceil(filtered.length / 50))}</span><button disabled={(safePage + 1) * 50 >= filtered.length} onClick={() => setPage(safePage + 1)}>下一页</button></div>}
        {attemptsQ.error && <ErrorNotice error={attemptsQ.error} onRetry={attemptsQ.reload} />}<p className="muted planning-help">真实运行耗时需要进程开始与结束证据，当前尝试接口未提供该边界，保持未知。准入耗时来自创建至终态或观察时刻，多次尝试分别累计。</p>
        {visibleScenario && <><SourceStamp source={visibleScenario.source} observedAt={visibleScenario.as_of} /><p className="planning-footnote">输入版本 {visibleScenario.input_revision} · {visibleScenario.worker_placement === "EXPLICIT_SCOPE" ? "显式 Worker 范围预览" : "Worker 放置尚未核验"} · 预览不授予执行权，不写入计划或完成状态。{visibleScenario.input_changed_since_request ? " 运行输入在请求后有变化，使用服务端最新占用快照。" : ""}</p></>}
      </Panel>
      {!!blocked.length && <Panel title="尚未排入的任务"><DataTable rows={blocked.slice(safeBlockedPage * 50, (safeBlockedPage + 1) * 50)} rowKey={r => `${r.task_id}:${r.code}:${r.detail}`} onRowClick={r => setSelected(r.task_id)} columns={[{ key: "task_id", label: "任务", render: r => <span>{str(taskMap.get(r.task_id)?.title, r.task_id)}<small>{r.task_id}</small></span> }, { key: "code", label: "原因", render: r => findings[r.code] ?? r.code }, { key: "detail", label: "权威检查详情" }]} /><div className="planning-pagination"><span>{blocked.length} 项检查结果 · 每页最多 50 行</span><button disabled={safeBlockedPage === 0} onClick={() => setBlockedPage(safeBlockedPage - 1)}>上一页阻塞项</button><span>{safeBlockedPage + 1} / {Math.max(1, Math.ceil(blocked.length / 50))}</span><button disabled={(safeBlockedPage + 1) * 50 >= blocked.length} onClick={() => setBlockedPage(safeBlockedPage + 1)}>下一页阻塞项</button></div></Panel>}
      <Panel title="复核任务工作量" actions={<div className="planning-estimate-picker"><input aria-label="搜索工作量任务" placeholder="搜索任务名称或编号" value={estimateQuery} onChange={event => setEstimateQuery(event.target.value)} /><select aria-label="选择工作量任务" value={selected} onChange={e => setSelected(e.target.value)}><option value="">选择任务</option>{estimateChoices.map(t => <option key={str(t.task_id)} value={str(t.task_id)}>{str(t.title)} · {str(t.task_id)}</option>)}</select></div>}>{selectedTask ? <EffortEstimate task={selectedTask} projectId={projectId} writable={writable && inputs.project.authority_mode === "MANAGED"} planningInputs={inputs} onSaved={inputsQ.reload} /> : <p className="planning-help muted">选择任意任务，或点击预览与阻塞行。没有计划日期也可以保存估计。</p>}<p className="planning-footnote">{tasks.length - maps.estimates.size} 项没有当前任务修订的独立估计；旧修订估计不参与当前估计。</p></Panel>
      {visibleScenario && <details className="planning-assumptions"><summary>算法与假设 · {visibleScenario.forecast.algorithm}</summary><ul>{visibleScenario.forecast.assumptions.map(a => <li key={a}>{a}</li>)}</ul></details>}<SourceStamp source={inputs.source} observedAt={inputs.as_of} />
    </>}
  </section>;
}
