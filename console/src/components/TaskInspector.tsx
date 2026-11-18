import { useEffect, useId, useState, type ReactNode } from 'react';
import { Link } from 'react-router-dom';
import { ArrowUpRight, CircleCheck, GitBranch, Activity, FileText } from 'lucide-react';
import { Drawer, ErrorNotice, JsonView, SourceStamp, StatusBadge } from './index';
import { useApi } from '../app/api';
import { pathId, useCompleteApi, type CompileContext, type Requirement, type TaskCard, type TaskSpec } from '../features/flow/types';
export type InspectorAttempt = { project_id: string; task_id: string; task_revision: number; attempt_id: string; state: string; worker_id: string; generation: number; created_at: string };
const explanations: Record<TaskCard['state'], string> = {
  PLANNED: '确认任务结果、责任人与前置依赖，再检查规划版本。',
  NEEDS_REVIEW: '任务定义或输入有变化，请根据检查报告补齐后重新复核。',
  READY_FOR_ADMISSION: '可以进行准入预检查。实际运行仍以服务端确认结果为准。',
  DEFERRED: '任务已延期，可核对需求安排与后续排程。',
  REMOVED_FROM_PLAN: '任务已移出当前计划，历史记录仍可追溯。',
};
const tabs = [['details', '任务详情', FileText], ['relations', '来源与依赖', GitBranch], ['execution', '执行与验收', Activity]] as const;
type Tab = typeof tabs[number][0];
export function TaskInspector({ task, spec, onClose, onSelectTask, actions }: {
  task: TaskCard; spec?: TaskSpec; onClose: () => void; onSelectTask?: (id: string) => void; actions?: ReactNode;
}) {
  const root = `/projects/${pathId(task.project_id)}`;
  const [tab, setTab] = useState<Tab>('details');
  const id = useId();
  useEffect(() => setTab('details'), [task.task_id]);
  const execution = useApi<{ attempts: InspectorAttempt[]; as_of: string; source: string }>(`${root}/assignment-context`);
  const context = useApi<CompileContext>(!spec ? `/flows/${pathId(`${task.project_id}:${task.flow_revision}`)}/context` : null);
  const requirements = useCompleteApi<Requirement>(`${root}/requirements`);
  const definition = spec ?? context.data?.task_specs[task.task_id];
  const history = execution.data?.attempts.filter(a => a.task_id === task.task_id) ?? [];
  const current = history.filter(a => a.task_revision === task.task_revision).sort((a, b) => b.created_at.localeCompare(a.created_at));
  const mapped = requirements.data?.filter(r => task.requirement_ids.includes(r.requirement_id)) ?? [];
  return <Drawer animateClose title={task.title} onClose={onClose}>
    <div className="task-inspector-content">
      <div className="task-inspector-context"><StatusBadge state={task.state} /><code>{task.task_id}</code></div>
      <div className="inspector-tabs" role="tablist" aria-label="任务详情分区">{tabs.map(([value, label, Icon], index) => <button key={value} id={`${id}-${value}-tab`} role="tab" aria-selected={tab === value} aria-controls={`${id}-${value}`} tabIndex={tab === value ? 0 : -1} onClick={() => setTab(value)} onKeyDown={event => {
        if (!['ArrowRight', 'ArrowLeft', 'Home', 'End'].includes(event.key)) return;
        event.preventDefault();
        const next = event.key === 'Home' ? 0 : event.key === 'End' ? tabs.length - 1 : (index + (event.key === 'ArrowRight' ? 1 : -1) + tabs.length) % tabs.length;
        setTab(tabs[next][0]); document.getElementById(`${id}-${tabs[next][0]}-tab`)?.focus();
      }}><Icon size={14} />{label}</button>)}</div>
      <div id={`${id}-details`} role="tabpanel" aria-labelledby={`${id}-details-tab`} hidden={tab !== 'details'} className="inspector-tab-content">
        <section className="inspector-next-step"><CircleCheck size={18} /><div><strong>下一步</strong><p>{explanations[task.state]}</p></div></section>
        <section className="task-inspector-section"><h3>交付结果</h3><p className="inspector-outcome">{definition?.outcome || task.title}</p><dl className="detail-grid"><dt>责任人</dt><dd>{task.owner_id}</dd><dt>执行团队</dt><dd><Link to={`${root}/teams`}>{task.team_id}<ArrowUpRight size={12} /></Link></dd><dt>规划版本</dt><dd>R{task.flow_revision} · 任务修订 {task.task_revision}</dd></dl></section>
        <section className="inspector-execution-summary"><div><strong>实际执行</strong><p>{!execution.data ? execution.error ? '执行观察暂不可用' : '正在读取…' : current.length ? `${current.length} 次已登记尝试` : '此任务修订尚无已登记尝试。'}</p></div><button onClick={() => setTab('execution')}>查看记录<ArrowUpRight size={13} /></button></section>
      </div>
      <div id={`${id}-relations`} role="tabpanel" aria-labelledby={`${id}-relations-tab`} hidden={tab !== 'relations'} className="inspector-tab-content">
        <section className="task-inspector-section"><h3>前置依赖 <span className="muted">{task.dependencies.length}</span></h3>{task.dependencies.length ? <div className="selection-list">{task.dependencies.map(dependency => <button key={dependency} onClick={() => onSelectTask?.(dependency)} disabled={!onSelectTask}><GitBranch size={13} />{dependency}<ArrowUpRight size={12} /></button>)}</div> : <p>没有登记前置任务。</p>}<Link className="inspector-text-link" to={`${root}/flows/${task.flow_revision}?view=graph&task=${pathId(task.task_id)}`}>在依赖图中查看<ArrowUpRight size={13} /></Link></section>
        <section className="task-inspector-section"><h3>关联需求 <span className="muted">{task.requirement_ids.length}</span></h3>{requirements.error && <ErrorNotice error={requirements.error} onRetry={requirements.reload} />}{!requirements.data && task.requirement_ids.length > 0 && <p role="status">正在读取需求原文…</p>}{mapped.map(requirement => <article className="inspector-requirement" key={requirement.requirement_id}><strong>{requirement.title}</strong><p>{requirement.acceptance.join('；')}</p><Link to={`${root}/requirements?requirement=${pathId(requirement.requirement_id)}`}>查看需求原文<ArrowUpRight size={12} /></Link></article>)}{!task.requirement_ids.length && <p>尚未关联需求，可在编辑任务时补充。</p>}</section>
      </div>
      <div id={`${id}-execution`} role="tabpanel" aria-labelledby={`${id}-execution-tab`} hidden={tab !== 'execution'} className="inspector-tab-content">
        <section className="task-inspector-section"><h3>实际执行</h3>{execution.error && <ErrorNotice error={execution.error} onRetry={execution.reload} />}{!execution.data ? <p role="status">正在读取执行观察…</p> : !current.length ? <p>此任务修订尚无已登记尝试。</p> : current.map(attempt => <Link className="inspector-attempt" key={attempt.attempt_id} to={`/runs/${pathId(attempt.attempt_id)}?project=${pathId(task.project_id)}`}><StatusBadge state={attempt.state} /><span>{attempt.worker_id} · 代次 {attempt.generation}<small>{attempt.attempt_id}</small></span><ArrowUpRight size={14} /></Link>)}{history.length > current.length && <p className="muted">其他任务修订另有 {history.length - current.length} 次历史尝试。</p>}<SourceStamp source={execution.data?.source} observedAt={execution.data?.as_of} /></section>
        <section className="task-inspector-section"><h3>验收与恢复</h3><p>{definition?.verification_plan || '验证计划待补充'}</p><p>{definition?.rollback_plan || '回滚方案待补充'}</p><Link className="inspector-text-link" to={`${root}/evidence?task=${pathId(task.task_id)}`}>查看验收证据<ArrowUpRight size={13} /></Link></section>
      </div>
      <details className="inspector-technical"><summary>技术记录与完整数据</summary>{context.error && <ErrorNotice error={context.error} onRetry={context.reload} />}<JsonView value={{ task, spec: definition }} /></details>
      {actions && <div className="task-inspector-actions">{actions}</div>}
    </div>
  </Drawer>;
}
