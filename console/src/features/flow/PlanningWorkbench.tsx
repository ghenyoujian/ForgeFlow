import { useId, useMemo, useRef, useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import { GitBranch, List, Columns3, Pencil, Bookmark, Search, SlidersHorizontal, X, ChevronRight, Check } from 'lucide-react';
import { EmptyState, StatusBadge } from '../../components';
import { VirtualTaskTable } from '../../components/VirtualTaskTable';
import { getAuthScope } from '../../app/api';
import { DagEditor, type GraphDependency } from './DagEditor';
import type { TaskCard } from './types';
import './planning-workbench.css';
type View = 'table' | 'board' | 'graph';
const labels = { PLANNED: '已规划', NEEDS_REVIEW: '待复核', READY_FOR_ADMISSION: '可预检查', DEFERRED: '已延期', REMOVED_FROM_PLAN: '已移出计划' };
const taskModule = (task: TaskCard) => task.write_set[0]?.split('/').slice(0, -1).slice(0, 2).join('/') || '根目录 / 只读';

function InlineTitle({ task, disabled, onPatch }: { task: TaskCard; disabled: boolean; onPatch: (task: TaskCard) => void }) {
  const [editing, setEditing] = useState(false);
  const cancelled = useRef(false);
  if (!editing) return <div className="planning-task-title"><strong title={task.title}>{task.title}</strong>{!disabled && <button className="task-rename" aria-label={`重命名任务 ${task.task_id}`} title="重命名" onClick={event => { event.stopPropagation(); cancelled.current = false; setEditing(true); }}><Pencil size={13} /></button>}</div>;
  function finish(value: string) {
    setEditing(false);
    const title = value.trim();
    if (!cancelled.current && title && title !== task.title) onPatch({ ...task, title });
  }
  return <input className="planning-title-input" aria-label={`编辑标题 ${task.task_id}`} defaultValue={task.title} autoFocus disabled={disabled} onClick={event => event.stopPropagation()} onFocus={event => event.currentTarget.select()} onBlur={event => finish(event.target.value)} onKeyDown={event => {
    event.stopPropagation();
    if (event.key === 'Escape' || event.key === 'Enter') {
      event.preventDefault();
      const row = event.currentTarget.closest<HTMLTableRowElement>('tr');
      if (event.key === 'Escape') { cancelled.current = true; setEditing(false); } else event.currentTarget.blur();
      requestAnimationFrame(() => row?.focus({ preventScroll: true }));
    }
  }} />;
}

export function PlanningWorkbench({ projectId, tasks, dependencies, selectedId, readOnly, busy, execution, executionAvailable, onSelect, onPatch, onConnect, onDeleteDependency }: {
  projectId: string; tasks: TaskCard[]; dependencies: GraphDependency[]; selectedId?: string;
  readOnly: boolean; busy: boolean; execution: Map<string, { state: string }[]>; executionAvailable: boolean;
  onSelect: (id: string) => void; onPatch: (task: TaskCard) => void;
  onConnect: (source: string, target: string) => void; onDeleteDependency: (id: string) => void;
}) {
  const [params, setParams] = useSearchParams();
  const rawView = params.get('view'); const view: View = rawView === 'graph' || rawView === 'board' ? rawView : 'table';
  const search = params.get('q') ?? '', owner = params.get('owner') ?? '', module = params.get('module') ?? '';
  const [filtersOpen, setFiltersOpen] = useState(!!(owner || module));
  const filtersId = useId();
  const [boardLimit, setBoardLimit] = useState(40);
  const tableScroll = useRef(0);
  const [viewName, setViewName] = useState('');
  const storage = `forgeflow.views.${getAuthScope()}.${projectId}`;
  const [saved, setSaved] = useState<{ name: string; query: string }[]>(() => { try { return JSON.parse(localStorage.getItem(storage) ?? '[]'); } catch { return []; } });
  const [notice, setNotice] = useState('');
  function change(key: string, value: string) { const next = new URLSearchParams(window.location.search); if (value) next.set(key, value); else next.delete(key); setParams(next, { replace: true }); }
  function clearFilters() { const next = new URLSearchParams(window.location.search); ['q', 'owner', 'module'].forEach(key => next.delete(key)); setParams(next, { replace: true }); }
  const filtered = useMemo(() => {
    const needle = search.trim().toLocaleLowerCase();
    return tasks.filter(task => (!needle || `${task.task_id} ${task.title}`.toLocaleLowerCase().includes(needle)) && (!owner || task.owner_id === owner) && (!module || taskModule(task) === module));
  }, [tasks, search, owner, module]);
  const graphTasks = useMemo(() => tasks.map(task => ({ id: task.task_id, title: task.title, owner: task.owner_id, state: task.state, packageId: taskModule(task), executionState: execution.get(task.task_id)?.[0]?.state, executionAvailable })), [tasks, execution, executionAvailable]);
  const graphScopeIds = useMemo(() => filtered.map(task => task.task_id), [filtered]);
  const groups = useMemo(() => [...new Set(tasks.map(taskModule))].sort(), [tasks]);
  const owners = useMemo(() => [...new Set(tasks.map(task => task.owner_id))].sort(), [tasks]);
  const filterCount = Number(!!owner) + Number(!!module);
  return <div className="planning-workbench" role="region" aria-label="统一规划工作台">
    <div className="planning-view-toolbar"><div className="tabs" aria-label="规划视图">{([['table', List, '任务表'], ['board', Columns3, '看板'], ['graph', GitBranch, '依赖图']] as const).map(([value, Icon, label]) => <button key={value} className={view === value ? 'active' : ''} aria-pressed={view === value} onClick={() => change('view', value)}><Icon size={15} />{label}</button>)}</div><a className="button" href="#assignment-workspace" onClick={event => { const target = document.getElementById("assignment-workspace"); if (target instanceof HTMLDetailsElement) { event.preventDefault(); target.open = true; target.scrollIntoView({ behavior: matchMedia("(prefers-reduced-motion: reduce)").matches ? "instant" : "smooth", block: "start" }); target.querySelector("summary")?.focus({ preventScroll: true }); } }}>批量分工<ChevronRight size={14} /></a></div>
    <div className="planning-search-row"><div className="planning-search"><Search size={16} aria-hidden="true" /><input aria-label="搜索全部规划任务" placeholder="搜索任务…" value={search} onChange={event => change('q', event.target.value)} onKeyDown={event => { if (event.key === 'Escape' && search) { event.stopPropagation(); change('q', ''); } }} />{search && <button aria-label="清除任务搜索" onClick={() => change('q', '')}><X size={14} /></button>}</div>
      <button aria-expanded={filtersOpen} aria-controls={filtersId} className={filterCount ? 'filter-active' : ''} onClick={() => setFiltersOpen(open => !open)}><SlidersHorizontal size={15} />筛选{filterCount > 0 && <span className="control-count">{filterCount}</span>}</button>
      <span className="planning-match-count" role="status">{filtered.length.toLocaleString()}<span> / {tasks.length.toLocaleString()} 张任务</span></span>
      <details className="planning-view-options"><summary><Bookmark size={15} />管理视图</summary><div className="planning-saved-views"><label>打开已保存视图<select aria-label="已保存管理视图" defaultValue="" onChange={event => { const value = saved.find(v => v.name === event.target.value); if (value) { const next = new URLSearchParams(value.query); const task = new URLSearchParams(window.location.search).get('task'); if (task) next.set('task', task); setParams(next, { replace: true }); } event.target.value = ''; }}><option value="">选择视图…</option>{saved.map(v => <option key={v.name}>{v.name}</option>)}</select></label><label>保存当前筛选<input aria-label="管理视图名称" placeholder="给视图起个名字" maxLength={40} value={viewName} onChange={event => setViewName(event.target.value)} /></label><button disabled={!viewName.trim()} onClick={() => { const nextParams = new URLSearchParams(window.location.search); nextParams.delete('task'); const next = [...saved.filter(v => v.name !== viewName.trim()), { name: viewName.trim(), query: nextParams.toString() }].slice(-20); try { localStorage.setItem(storage, JSON.stringify(next)); setSaved(next); setViewName(''); setNotice('视图已保存，下次可以直接打开。'); } catch { setNotice('浏览器未能保存，请收藏当前链接。'); } }}><Check size={14} />保存视图</button>{notice && <span role="status">{notice}</span>}</div></details>
    </div>
    <div className="planning-filter-panel" id={filtersId} hidden={!filtersOpen}><label>责任人<select aria-label="规划责任人" value={owner} onChange={event => change('owner', event.target.value)}><option value="">全部责任人</option>{owners.map(id => <option key={id}>{id}</option>)}</select></label><label>目录模块<select aria-label="目录模块" value={module} onChange={event => change('module', event.target.value)}><option value="">全部模块</option>{groups.map(id => <option key={id}>{id}</option>)}</select></label></div>
    {(search || owner || module) && <div className="planning-filter-chips">{owner && <button onClick={() => change('owner', '')} aria-label="移除责任人筛选">{owner}<X size={12} /></button>}{module && <button onClick={() => change('module', '')} aria-label="移除模块筛选">{module}<X size={12} /></button>}<button className="quiet-button" onClick={clearFilters}>清除全部筛选</button></div>}
    <div className="planning-view-content" key={view}>
      {view === 'table' && <VirtualTaskTable initialScrollTop={tableScroll.current} onScrollPositionChange={value => { tableScroll.current = value; }} tasks={filtered} selectedId={selectedId} onSelect={onSelect} group={taskModule} renderTitle={task => <InlineTitle task={task} disabled={readOnly || busy} onPatch={onPatch} />} renderActions={task => <button className="task-open" aria-label={`查看任务 ${task.task_id}`} onClick={() => onSelect(task.task_id)}><ChevronRight size={16} /></button>} />}
      {view === 'board' && (filtered.length ? <div className="planning-kanban">{Object.entries(labels).map(([state, label]) => { const cards = filtered.filter(t => t.state === state); return <section key={state} aria-label={label}><header><StatusBadge state={state} /><span>{cards.length}</span></header>{cards.slice(0, boardLimit).map(task => <button className="planning-kanban-card" key={task.task_id} aria-pressed={selectedId === task.task_id} onClick={() => onSelect(task.task_id)}><strong>{task.title}</strong><small>{task.owner_id} · {taskModule(task)}</small><span>{task.dependencies.length} 项前置 · {!executionAvailable ? '执行观察暂不可用' : execution.get(task.task_id)?.[0]?.state ?? '尚未开始执行'}</span><code>{task.task_id}</code></button>)}{!cards.length && <p className="kanban-empty">暂无任务</p>}{cards.length > boardLimit && <button onClick={() => setBoardLimit(n => n + 40)}>再显示 40 张 · 剩余 {cards.length - boardLimit}</button>}</section>; })}</div> : <EmptyState title="没有找到匹配任务" description="试试更短的关键词，或清除筛选。" action={<button onClick={clearFilters}>清除筛选</button>} />)}
      {view === 'graph' && <DagEditor scopeIds={graphScopeIds} onExpandBoundary={clearFilters} tasks={graphTasks} dependencies={dependencies} selectedId={selectedId} readOnly={readOnly} busy={busy} onSelect={onSelect} onConnect={onConnect} onDeleteDependency={onDeleteDependency} />}
    </div>
  </div>;
}
