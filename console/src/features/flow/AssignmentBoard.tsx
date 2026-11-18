import { useEffect, useMemo, useRef, useState } from 'react';
import { ArrowRight, Check, ChevronLeft, ChevronRight, ClipboardCheck, Filter, GitBranch, LockKeyhole, Search, ShieldCheck, Users, X } from 'lucide-react';
import type { CompileContext, FlowRevision, TaskCard } from './types';
import './assignment.css';

export interface AssignmentTeam {
  project_id: string; team_id: string; parent_team_id: string | null;
  name: string; paused: boolean; revision: number;
}
export interface AssignmentTaskChange {
  task_id: string; expected_task_revision: number; owner_id: string; team_id: string;
}
/** Review intent only. The parent owns CAS, new revisions and server compilation. */
export interface AssignmentChangeSet {
  project_id: string; base_flow_revision: number; base_revision: number;
  context_source_revision: string; task_changes: AssignmentTaskChange[];
}
export interface AssignmentFinding {
  code: string; task_ids: string[]; message: string;
  severity: 'BLOCKING' | 'WARNING';
}
export interface AssignmentPreview {
  changeSet: AssignmentChangeSet; findings: AssignmentFinding[];
  affectedDependents: string[];
}
export interface AssignmentBoardProps {
  flow: FlowRevision; context?: CompileContext; historicalContext?: CompileContext;
  teams?: AssignmentTeam[]; teamsComplete?: boolean;
  activeTaskIds?: readonly string[]; activeTasksComplete?: boolean;
  readOnly?: boolean; busy?: boolean;
  /** Return true only after an authoritative save receipt. Throw to preserve the candidate on failure. */
  onSave?: (changes: AssignmentChangeSet) => Promise<boolean | void>;
  onPreview?: (preview: AssignmentPreview) => void;
  onSelectTask?: (taskId: string) => void;
}

const planningLabels: Record<TaskCard['state'], string> = {
  PLANNED: '已规划', NEEDS_REVIEW: '待复核', READY_FOR_ADMISSION: '可预检查准入',
  DEFERRED: '已延后', REMOVED_FROM_PLAN: '已移出计划',
};
const contains = (scope: string, path: string) => scope.endsWith('/') ? path.startsWith(scope) : scope === path;
const overlaps = (a: string, b: string) => contains(a, b) || contains(b, a);
const safePath = (path: string) => !!path && !/^[\/]|[\\\0:]/.test(path)
  && !path.replace(/\/$/, '').split('/').some(part => !part || part === '.' || part === '..');

/** Advisory review mirrors public path semantics; the server remains the final check authority. */
export function previewAssignments(
  flow: FlowRevision, context: CompileContext, changes: AssignmentTaskChange[],
  teams: AssignmentTeam[], activeTaskIds: readonly string[],
): AssignmentPreview {
  const changesById = new Map(changes.map(change => [change.task_id, change]));
  const tasks = new Map(flow.tasks.map(task => [task.task_id, task]));
  const owners = new Map(context.owners.map(owner => [owner.owner_id, owner]));
  const teamMap = new Map(teams.filter(team => team.project_id === flow.project_id).map(team => [team.team_id, team]));
  const active = new Set(activeTaskIds);
  const findings: AssignmentFinding[] = [];
  const add = (code: string, task_ids: string[], message: string, severity: AssignmentFinding['severity'] = 'BLOCKING') => findings.push({ code, task_ids, message, severity });
  for (const change of changes) {
    const task = tasks.get(change.task_id);
    if (!task || task.task_revision !== change.expected_task_revision) { add('TASK_REVISION_CHANGED', [change.task_id], '任务定义版本已变化，请重新读取并预览。'); continue; }
    if (active.has(task.task_id)) add('ACTIVE_ATTEMPT', [task.task_id], '任务有活动尝试；先处理执行权与占用，再建立新定义。');
    if (task.state === 'REMOVED_FROM_PLAN') add('TASK_REMOVED', [task.task_id], '任务已移出计划，需先通过任务编辑恢复规划范围。');
    const owner = owners.get(change.owner_id);
    if (!owner) { add('OWNER_UNREGISTERED', [task.task_id], '目标 Owner 未登记在当前权威上下文。'); continue; }
    if (context.owners.filter(value => value.owner_id === change.owner_id).length !== 1) add('DUPLICATE_OWNER_ID', [task.task_id], '目标 Owner 存在重复登记，无法确认唯一责任。');
    if (!owner.root_team_id) add('OWNER_ROOT_UNBOUND', [task.task_id], '目标 Owner 未绑定根团队。');
    const lineage = new Set<string>();
    let cursor: string | null = change.team_id;
    while (cursor) {
      if (lineage.has(cursor)) { add('TEAM_LINEAGE_CYCLE', [task.task_id], '执行团队祖先链存在循环。'); break; }
      lineage.add(cursor);
      const team = teamMap.get(cursor);
      if (!team) { add('TEAM_NOT_REGISTERED', [task.task_id], '执行团队或祖先不在该项目的完整团队集合中。'); break; }
      if (team.paused) add('TEAM_PAUSED', [task.task_id], `团队 ${team.name || team.team_id} 已暂停新准入。`, 'WARNING');
      cursor = team.parent_team_id;
    }
    if (owner.root_team_id && !lineage.has(owner.root_team_id)) add('OWNER_TEAM_SCOPE', [task.task_id], '执行团队必须属于所选 Owner 根团队的子树。');
    for (const path of task.write_set) {
      const resolved = context.resolved_paths[path] ?? path;
      const allowed = [path, resolved].every(value => safePath(value)
        && owner.include.some(scope => contains(scope, value))
        && !owner.exclude.some(scope => overlaps(scope, value)));
      if (!allowed) add('OWNER_TERRITORY', [task.task_id], `写路径 ${path}${resolved !== path ? ` → ${resolved}` : ''} 超出目标 Owner 领地或命中排除项。`);
      if (context.owners.filter(value => value.include.some(scope => contains(scope, resolved))
        && !value.exclude.some(scope => overlaps(scope, resolved))).length > 1) {
        add('OWNER_TERRITORY_AMBIGUOUS', [task.task_id], `写路径 ${resolved} 同时由多个根 Owner 覆盖。`);
      }
    }
    const spec = context.task_specs[task.task_id];
    if (!spec) add('MISSING_TASK_SPEC', [task.task_id], '当前上下文缺少任务语义合同，需由父页面保留历史 TaskSpec 后再检查。');
    for (const dependency of task.dependencies) {
      if (!tasks.has(dependency)) add('DEPENDENCY_NOT_IN_FLOW', [task.task_id], `前置 ${dependency} 不在当前 Flow；需核验显式跨项目合同。`);
      if (!spec?.dependency_refs.some(ref => ref.task_id === dependency)) add('DEPENDENCY_BINDING_MISSING', [task.task_id], `前置 ${dependency} 缺少依赖语义绑定。`);
    }
  }
  const precedes = (source: string, target: string) => {
    const seen = new Set<string>(); const pending = [...(tasks.get(target)?.dependencies ?? [])];
    while (pending.length) { const id = pending.pop()!; if (id === source) return true; if (seen.has(id)) continue; seen.add(id); pending.push(...(tasks.get(id)?.dependencies ?? [])); }
    return false;
  };
  for (const change of changes) if (precedes(change.task_id, change.task_id)) add('DEPENDENCY_CYCLE', [change.task_id], '变化任务的前置链存在依赖循环，必须先修复正式依赖。');
  // Sort the exact/resolved write scopes so unrelated paths never require pair comparisons.
  const writers = flow.tasks.flatMap(task => task.write_set.map(path => ({ id: task.task_id, path: context.resolved_paths[path] ?? path })))
    .sort((a, b) => a.path < b.path ? -1 : a.path > b.path ? 1 : a.id.localeCompare(b.id));
  const reviewedPairs = new Set<string>();
  for (let i = 0; i < writers.length; i++) {
    const a = writers[i];
    for (let j = i + 1; j < writers.length; j++) {
      const b = writers[j];
      if (!b.path.startsWith(a.path.replace(/\/$/, ''))) break;
      if (a.id === b.id || (!changesById.has(a.id) && !changesById.has(b.id)) || !overlaps(a.path, b.path)) continue;
      const pair = [a.id, b.id].sort().join('\0');
      if (reviewedPairs.has(pair)) continue;
      reviewedPairs.add(pair);
      if (!precedes(a.id, b.id) && !precedes(b.id, a.id)) add('WRITE_SCOPE_CONFLICT', [a.id, b.id], `任务写集合 ${a.path} / ${b.path} 重叠，缺少明确依赖顺序。`);
    }
  }
  const successors = new Map<string, string[]>();
  for (const task of flow.tasks) for (const dependency of task.dependencies) successors.set(dependency, [...(successors.get(dependency) ?? []), task.task_id]);
  const affected = new Set<string>(); const pending = [...changesById.keys()];
  while (pending.length) for (const id of successors.get(pending.pop()!) ?? []) if (!affected.has(id)) { affected.add(id); pending.push(id); }
  for (const id of changesById.keys()) affected.delete(id);
  return { changeSet: { project_id: flow.project_id, base_flow_revision: flow.flow_revision, base_revision: flow.revision,
    context_source_revision: context.source_revision, task_changes: changes }, findings, affectedDependents: [...affected] };
}

function resourceSummary(task: TaskCard) {
  const r = task.resource_request;
  return [`${r.active_slot} 活动`, r.coding_slot && `${r.coding_slot} 编码`, r.cpu_units && `${r.cpu_units} CPU`,
    r.memory_bytes && `${Math.ceil(r.memory_bytes / 1048576)} MiB`, r.build_permit && `${r.build_permit} 构建`,
    r.gpu_permit && `${r.gpu_permit} GPU`, r.provider_inflight && `${r.provider_inflight} 模型`].filter(Boolean).join(' · ');
}

export function AssignmentBoard({ flow, context, historicalContext, teams = [], teamsComplete = false,
  activeTaskIds = [], activeTasksComplete = false, readOnly = false, busy = false,
  onSave, onPreview, onSelectTask }: AssignmentBoardProps) {
  const [search, setSearch] = useState(''); const [ownerFilter, setOwnerFilter] = useState('');
  const [teamFilter, setTeamFilter] = useState(''); const [stateFilter, setStateFilter] = useState('');
  const [resourceFilter, setResourceFilter] = useState(''); const [dependencyFilter, setDependencyFilter] = useState('');
  const [selected, setSelected] = useState<Set<string>>(new Set()); const [page, setPage] = useState(0);
  const [targetOwner, setTargetOwner] = useState(''); const [targetTeam, setTargetTeam] = useState('');
  const [preview, setPreview] = useState<AssignmentPreview>(); const [reviewed, setReviewed] = useState(false);
  const [saving, setSaving] = useState(false); const [error, setError] = useState<string>();
  const [receipt, setReceipt] = useState(false); const selectAllRef = useRef<HTMLInputElement>(null);
  const previewSource = useRef(''); const savingRef = useRef(false);
  const activeIds = useMemo(() => new Set(activeTaskIds), [activeTaskIds]);
  const localBusy = busy || saving;
  const sourceIdentity = useMemo(() => JSON.stringify([flow, context, historicalContext, teams, teamsComplete, [...activeTaskIds].sort(), activeTasksComplete]), [flow, context, historicalContext, teams, teamsComplete, activeTaskIds, activeTasksComplete]);
  const stalePreview = !!preview && previewSource.current !== sourceIdentity;
  const projectTeams = teams.filter(team => team.project_id === flow.project_id);
  const ownerIds = Array.from(new Set([...flow.tasks.map(task => task.owner_id), ...(context?.owners.map(owner => owner.owner_id) ?? [])])).sort();
  const teamIds = Array.from(new Set([...flow.tasks.map(task => task.team_id), ...projectTeams.map(team => team.team_id)])).sort();
  const teamName = (id: string) => projectTeams.find(team => team.team_id === id)?.name || id;
  const filtered = useMemo(() => {
    const needle = search.trim().toLocaleLowerCase();
    return flow.tasks.filter(task => (!needle || [task.task_id, task.title, task.owner_id, task.team_id, ...task.requirement_ids, ...task.write_set].join(' ').toLocaleLowerCase().includes(needle))
      && (!ownerFilter || task.owner_id === ownerFilter) && (!teamFilter || task.team_id === teamFilter)
      && (!stateFilter || task.state === stateFilter)
      && (!resourceFilter || task.resource_request[resourceFilter as keyof TaskCard['resource_request']] > 0)
      && (!dependencyFilter || (dependencyFilter === 'with' ? task.dependencies.length > 0 : task.dependencies.length === 0)));
  }, [flow.tasks, search, ownerFilter, teamFilter, stateFilter, resourceFilter, dependencyFilter]);
  const eligible = filtered.filter(task => !activeIds.has(task.task_id) && task.state !== 'REMOVED_FROM_PLAN');
  const selectedTasks = flow.tasks.filter(task => selected.has(task.task_id));
  const selectedVisible = eligible.filter(task => selected.has(task.task_id)).length;
  const selectedOutsideFilter = selectedTasks.length - filtered.filter(task => selected.has(task.task_id)).length;
  const allVisibleSelected = !!eligible.length && selectedVisible === eligible.length;
  const pageCount = Math.max(1, Math.ceil(filtered.length / 50)); const safePage = Math.min(page, pageCount - 1);
  const visibleTasks = filtered.slice(safePage * 50, (safePage + 1) * 50);
  const hasFilters = !!(search || ownerFilter || teamFilter || stateFilter || resourceFilter || dependencyFilter);
  const blockingCount = preview?.findings.filter(finding => finding.severity === 'BLOCKING').length ?? 0;
  const sourceReady = !!context && !!historicalContext && teamsComplete && activeTasksComplete;
  useEffect(() => { setPage(0); }, [search, ownerFilter, teamFilter, stateFilter, resourceFilter, dependencyFilter]);
  useEffect(() => { if (selectAllRef.current) selectAllRef.current.indeterminate = selectedVisible > 0 && !allVisibleSelected; }, [selectedVisible, allVisibleSelected]);
  useEffect(() => { setSelected(new Set()); setPreview(undefined); setReviewed(false); setError(undefined); setReceipt(false); }, [flow.project_id, flow.flow_revision]);
  function invalidate() { setPreview(undefined); setReviewed(false); setError(undefined); setReceipt(false); }
  function toggle(id: string) { invalidate(); setSelected(previous => { const next = new Set(previous); if (next.has(id)) next.delete(id); else next.add(id); return next; }); }
  function buildPreview() {
    if (!context || !historicalContext) return;
    const changes = selectedTasks.filter(task => (targetOwner && targetOwner !== task.owner_id) || (targetTeam && targetTeam !== task.team_id))
      .map(task => ({ task_id: task.task_id, expected_task_revision: task.task_revision, owner_id: targetOwner || task.owner_id, team_id: targetTeam || task.team_id }));
    const value = previewAssignments(flow, { ...context, task_specs: historicalContext.task_specs }, changes, teams, activeTaskIds);
    if (!teamsComplete) value.findings.push({ code: 'TEAM_COVERAGE_UNKNOWN', task_ids: changes.map(change => change.task_id), message: '完整团队权威尚未加载，无法确认执行团队归属。', severity: 'BLOCKING' });
    if (!activeTasksComplete) value.findings.push({ code: 'ATTEMPT_COVERAGE_UNKNOWN', task_ids: changes.map(change => change.task_id), message: '活动尝试事实不完整，保存前必须重新核验。', severity: 'BLOCKING' });
    previewSource.current = sourceIdentity; setPreview(value); setReviewed(false); setError(undefined); setReceipt(false); onPreview?.(value);
  }
  async function save() {
    if (savingRef.current || !preview || stalePreview || blockingCount || !reviewed || !sourceReady || !onSave || readOnly || localBusy || !preview.changeSet.task_changes.length) return;
    savingRef.current = true; setSaving(true); setError(undefined);
    try { const saved = await onSave(preview.changeSet); if (saved === true) { setReceipt(true); setPreview(undefined); setSelected(new Set()); setReviewed(false); } }
    catch (cause) { setError(cause instanceof Error ? cause.message : String(cause)); }
    finally { savingRef.current = false; setSaving(false); }
  }
  return <section className="assignment-board" aria-label="任务责任与批量分工">
    <div className="assignment-heading"><div><div className="assignment-eyebrow"><Users size={14} />责任与执行</div><h2>让每张任务都有明确归属</h2><p>唯一代码 Owner 承担交付责任，执行团队在其授权子树内实施。</p></div><div className="assignment-source"><span>Flow R{flow.flow_revision} · {flow.state}</span><span>{flow.tasks.length} 张任务 · 完整 Flow 范围</span></div></div>
    <div className="assignment-summary"><div><strong>{new Set(flow.tasks.map(task => task.owner_id).filter(Boolean)).size}</strong><span>任务涉及 Owner</span></div><div><strong>{new Set(flow.tasks.map(task => task.team_id).filter(Boolean)).size}</strong><span>任务涉及执行团队</span></div><div><strong>{activeTasksComplete ? flow.tasks.filter(task => activeIds.has(task.task_id)).length : '—'}</strong><span>活动尝试锁定任务</span></div><div><strong>{selectedTasks.length}</strong><span>待分工选择</span></div></div>
    {flow.state === 'COMMITTED' || flow.state === 'SUPERSEDED' ? <p className="assignment-notice"><GitBranch size={16} />保存会建立新草案和新任务定义版本，保留当前审定版本与历史尝试。</p> : null}
    {!sourceReady && <p className="assignment-notice"><ShieldCheck size={16} />权威核验待完成：{[!context && '当前上下文', !historicalContext && '历史任务合同', !teamsComplete && '完整团队集合', !activeTasksComplete && '活动尝试集合'].filter(Boolean).join('、')}。可筛选查看，保存暂不可用。</p>}
    <div className="assignment-filters"><label className="assignment-search"><Search size={16} /><input aria-label="搜索 Flow 内任务" placeholder="搜索任务、Owner、需求或写路径" value={search} onChange={event => setSearch(event.target.value)} /></label><label><span>代码 Owner</span><select value={ownerFilter} onChange={event => setOwnerFilter(event.target.value)}><option value="">全部 Owner</option>{ownerIds.map(id => <option key={id} value={id}>{id || '未分配'}</option>)}</select></label><label><span>执行团队</span><select value={teamFilter} onChange={event => setTeamFilter(event.target.value)}><option value="">全部团队</option>{teamIds.map(id => <option key={id} value={id}>{teamName(id) || '未分配'}</option>)}</select></label><label><span>规划状态</span><select value={stateFilter} onChange={event => setStateFilter(event.target.value)}><option value="">全部状态</option>{Object.entries(planningLabels).map(([id, label]) => <option key={id} value={id}>{label}</option>)}</select></label><label><span>资源需求</span><select value={resourceFilter} onChange={event => setResourceFilter(event.target.value)}><option value="">全部资源</option>{[['active_slot', '活动槽'], ['coding_slot', '编码槽'], ['cpu_units', 'CPU'], ['memory_bytes', '内存'], ['build_permit', '构建许可'], ['gpu_permit', 'GPU'], ['provider_inflight', '模型在途']].map(([id, label]) => <option key={id} value={id}>{label}需求 &gt; 0</option>)}</select></label><label><span>依赖关系</span><select value={dependencyFilter} onChange={event => setDependencyFilter(event.target.value)}><option value="">全部任务</option><option value="with">有前置依赖</option><option value="without">无前置依赖</option></select></label></div>
    <div className="assignment-table-meta"><span><Filter size={14} />匹配 {filtered.length} / {flow.tasks.length} · 每页最多 50 张</span>{hasFilters && <button onClick={() => { setSearch(''); setOwnerFilter(''); setTeamFilter(''); setStateFilter(''); setResourceFilter(''); setDependencyFilter(''); }}><X size={14} />清除筛选</button>}<span>筛选后保留跨页选择{selectedOutsideFilter > 0 ? ` · ${selectedOutsideFilter} 张在当前筛选外` : ''}</span></div>
    <div className="assignment-table-scroll"><table className="assignment-table"><thead><tr><th><input ref={selectAllRef} type="checkbox" aria-label="选择全部筛选匹配任务，包含其他页" checked={allVisibleSelected} disabled={readOnly || localBusy || !eligible.length} onChange={() => { invalidate(); setSelected(previous => { const next = new Set(previous); for (const task of eligible) if (allVisibleSelected) next.delete(task.task_id); else next.add(task.task_id); return next; }); }} /></th><th>有限任务 / 定义版本</th><th>代码 Owner</th><th>执行团队</th><th>规划状态</th><th>资源需求</th><th>前置 / 写集合</th></tr></thead><tbody>{visibleTasks.map(task => <tr key={task.task_id} data-selected={selected.has(task.task_id) || undefined}><td><input type="checkbox" aria-label={`选择任务 ${task.title || task.task_id}`} checked={selected.has(task.task_id)} disabled={readOnly || localBusy || activeIds.has(task.task_id) || task.state === 'REMOVED_FROM_PLAN'} onChange={() => toggle(task.task_id)} /></td><td><button className="assignment-task-link" disabled={!onSelectTask} onClick={() => onSelectTask?.(task.task_id)}>{task.title || '未命名任务'}</button><div className="assignment-task-id"><code>{task.task_id}</code><span>v{task.task_revision}</span>{activeIds.has(task.task_id) && <span title="活动尝试锁定"><LockKeyhole size={12} />执行中锁定</span>}</div></td><td>{task.owner_id || '未分配'}</td><td>{teamName(task.team_id) || '未分配'}</td><td><span className="assignment-state">{planningLabels[task.state]}</span></td><td className="assignment-resources">{resourceSummary(task)}</td><td><span>{task.dependencies.length} 前置 · {task.write_set.length} 写路径</span><details><summary>查看范围</summary><p>前置：{task.dependencies.join('、') || '无'}</p><p>写路径：{task.write_set.join('、') || '只读任务'}</p></details></td></tr>)}</tbody></table>{!filtered.length && <div className="assignment-empty"><Search size={22} /><strong>{flow.tasks.length ? '没有匹配的任务' : '当前 Flow 尚无任务'}</strong><span>{flow.tasks.length ? '调整筛选条件，已有选择仍然保留。' : '先建立有限任务，再明确责任和执行团队。'}</span></div>}</div>
    <div className="assignment-pagination"><span>{filtered.length ? `${safePage * 50 + 1}–${Math.min((safePage + 1) * 50, filtered.length)}` : '0'} / {filtered.length}</span><button aria-label="上一页分工任务" disabled={!safePage} onClick={() => setPage(safePage - 1)}><ChevronLeft size={16} /></button><span>第 {safePage + 1} / {pageCount} 页</span><button aria-label="下一页分工任务" disabled={safePage + 1 >= pageCount} onClick={() => setPage(safePage + 1)}><ChevronRight size={16} /></button></div>
    <div className="assignment-edit"><div><h3><Users size={16} />批量调整责任</h3><p>只改变明确选择的字段；空选项保留各任务原值。</p></div><label><span>目标代码 Owner</span><select value={targetOwner} disabled={readOnly || localBusy || !context} onChange={event => { setTargetOwner(event.target.value); invalidate(); }}><option value="">保留原 Owner</option>{context?.owners.map((owner, index) => <option key={`${owner.owner_id}:${index}`} value={owner.owner_id}>{owner.owner_id} · 根团队 {owner.root_team_id || '未绑定'}</option>)}</select></label><label><span>目标执行团队</span><select value={targetTeam} disabled={readOnly || localBusy || !teamsComplete} onChange={event => { setTargetTeam(event.target.value); invalidate(); }}><option value="">保留原执行团队</option>{projectTeams.map(team => <option key={team.team_id} value={team.team_id}>{team.name || team.team_id}{team.paused ? ' · 已暂停' : ''}</option>)}</select></label><button className="primary" disabled={readOnly || localBusy || !selectedTasks.length || (!targetOwner && !targetTeam) || !context || !historicalContext} onClick={buildPreview}><ClipboardCheck size={16} />预览 {selectedTasks.length} 张任务</button>{selectedTasks.length > 0 && <button disabled={localBusy} onClick={() => { setSelected(new Set()); invalidate(); }}>清空选择</button>}</div>
    {preview && <div className="assignment-review" aria-label="分工变更预览"><div className="assignment-review-heading"><div><h3><ClipboardCheck size={17} />审阅变更</h3><p>{preview.changeSet.task_changes.length} 张定义变化 · {preview.affectedDependents.length} 张后继需重新核验 · {blockingCount} 项本地阻塞</p></div><button disabled={localBusy} aria-label="关闭分工预览" onClick={invalidate}><X size={16} /></button></div>
      <p className="assignment-notice"><GitBranch size={16} />变化任务提升 task_revision，清除旧执行信封与输入身份，重新编译、检查及审定。原尝试与证据继续绑定原版本。</p>
      {stalePreview && <p className="assignment-notice" role="alert">源 Flow、Owner、团队或活动尝试已变化。重新预览当前权威后才能保存。</p>}
      <div className="assignment-diff-list">{preview.changeSet.task_changes.slice(0, 100).map(change => { const task = flow.tasks.find(value => value.task_id === change.task_id); return <div className="assignment-diff" key={change.task_id}><div><strong>{task?.title || change.task_id}</strong><span><code>{change.task_id}</code> · v{change.expected_task_revision} <ArrowRight size={12} /> v{change.expected_task_revision + 1}</span></div><div><span>Owner</span><span>{task?.owner_id} <ArrowRight size={13} /> {change.owner_id}</span></div><div><span>执行团队</span><span>{teamName(task?.team_id ?? '')} <ArrowRight size={13} /> {teamName(change.team_id)}</span></div></div>; })}</div>
      {preview.changeSet.task_changes.length > 100 && <p className="assignment-muted">仅展示前 100 张变化；原子保存范围为全部 {preview.changeSet.task_changes.length} 张。展开完整意图可审阅全部。</p>}
      {!preview.changeSet.task_changes.length && <p className="assignment-notice">目标与原分工相同，没有需要保存的语义变化。</p>}
      {preview.findings.length > 0 ? <div className="assignment-findings"><h4>范围与依赖复核</h4>{preview.findings.slice(0, 100).map((finding, index) => <div key={`${finding.code}:${index}`}><span className="assignment-state">{finding.severity === 'BLOCKING' ? '阻塞' : '提醒'}</span><div><strong>{finding.message}</strong><span><code>{finding.code}</code> · {finding.task_ids.join('、')}</span></div></div>)}{preview.findings.length > 100 && <p>展示前 100 项，完整意图包含全部 {preview.findings.length} 项。</p>}</div> : <p className="assignment-notice"><ShieldCheck size={16} />本地未发现分工冲突。完整合同、输入、资源与准入资格仍由服务端重新检查。</p>}
      {preview.affectedDependents.length > 0 && <details><summary>受影响的 {preview.affectedDependents.length} 张后继任务</summary><p className="assignment-break">{preview.affectedDependents.join('、')}</p><p className="assignment-muted">后继数量表示复核范围，不表示可立即释放的执行产能。</p></details>}
      <details><summary>完整变更意图与本地发现</summary><pre>{JSON.stringify(preview, null, 2)}</pre></details>
      <label className="assignment-ack"><input type="checkbox" checked={reviewed} disabled={localBusy || stalePreview || blockingCount > 0} onChange={event => setReviewed(event.target.checked)} /><span>已审阅 Owner 领地、团队归属与依赖影响，并确认重新封存变化任务。</span></label>
      <div className="assignment-save"><span>以 Flow R{preview.changeSet.base_flow_revision} / revision {preview.changeSet.base_revision} 为比较基线</span><button className="primary" disabled={readOnly || localBusy || !onSave || !sourceReady || stalePreview || !!blockingCount || !reviewed || !preview.changeSet.task_changes.length} onClick={() => void save()}><Check size={16} />{localBusy ? '正在保存…' : '保存为新草案'}</button></div>
    </div>}
    {error && <p className="assignment-notice" role="alert">保存未完成：{error}。候选已保留，刷新权威后重新预览；失败不会更新任务分工。</p>}
    {receipt && <p className="assignment-notice" role="status"><Check size={16} />服务端已返回保存回执。新草案仍需重新检查、配置执行并审定。</p>}
  </section>;
}
