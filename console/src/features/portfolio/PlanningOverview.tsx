import { Link } from 'react-router-dom';
import { ArrowUpRight, ArrowRight, Target, AlertCircle, CalendarDays, RefreshCw } from 'lucide-react';
import { useApi } from '../../app/api';
import { EmptyState, ErrorNotice, Panel, SourceStamp, StatusBadge } from '../../components';
import { pathId } from '../flow/types';
export type PlanningOverviewData = {
  project: { project_id: string; authority_mode: string; archived: boolean; goal: string; paused: boolean };
  flow?: { flow_revision: number; revision: number; state: string };
  statistics: { task_count: number; dependency_count: number; needs_review: number; requirements: number; covered: number; uncovered: number; deferred: number; gaps: { requirement_id: string; title: string }[] };
  capacity: { persistent_contexts: number; active_attempts: number; recovery_attempts: number; observed_native_sessions: number; context_design_capacity: number };
  policies: { scope_id: string; team_id?: string; worker_id?: string; revision: number; paused: boolean; limits: Record<string, number>; usage: Record<string, number> }[];
  milestones: Record<string, unknown>[]; milestone_count: number;
  decisions: { decision_id: string; note: string; state: string }[];
};
export function PlanningOverview({ projectId }: { projectId: string }) {
  const root = `/projects/${pathId(projectId)}`;
  const query = useApi<PlanningOverviewData>(`${root}/planning-overview`);
  const data = query.data;
  if (query.error && !data) return <ErrorNotice error={query.error} onRetry={query.reload} />;
  if (!data) return <p role="status">正在汇总目标、覆盖和容量…</p>;
  const { statistics: stats, capacity } = data;
  const blockers = [
    ...(data.project.paused ? [{ title: '项目暂停新增准入', reason: '当前已启动尝试继续按执行协议处理。', action: '核对项目与团队', to: `${root}/teams` }] : []),
    ...(stats.uncovered ? [{ title: `${stats.uncovered} 条需求缺少任务覆盖`, reason: '映射到任务或登记明确延期理由。', action: '补齐需求映射', to: `${root}/requirements` }] : []),
    ...(stats.needs_review ? [{ title: `${stats.needs_review} 张任务待复核`, reason: '检查任务定义、输入及依赖，并形成新草案。', action: '检查规划', to: `${root}/flows` }] : []),
    ...(capacity.recovery_attempts ? [{ title: `${capacity.recovery_attempts} 次尝试等待停止或恢复确认`, reason: '服务端确认停止与释放后才会释放占用。', action: '处理执行阻塞', to: `/runs?project=${pathId(projectId)}` }] : []),
    ...data.policies.filter(p => p.paused).map(p => ({ title: `资源范围 ${p.scope_id} 暂停新增`, reason: '核对该范围与祖先约束，再调整准入政策。', action: '查看资源限制', to: `${root}/teams` })),
  ];
  return <section aria-label="项目规划总览">
    <div className="overview-goal"><div><span className="overview-eyebrow"><Target size={14} />交付目标 · {data.flow ? `规划 R${data.flow.flow_revision}` : '等待规划'}</span><h2>{data.project.goal || '明确项目目标，开始安排交付'}</h2><p>从下一步开始，让目标、任务和执行保持关联。</p></div><div className="overview-goal-actions"><Link className="button primary" to={`${root}/flows`}>{stats.task_count ? '继续规划' : '开始规划'}<ArrowRight size={15} /></Link><Link className="button" to={`${root}/schedule`}><CalendarDays size={15} />查看排程</Link><button aria-label="刷新总览" aria-busy={query.refreshing} title="刷新总览" onClick={query.reload} disabled={query.refreshing}><RefreshCw size={15} /></button></div></div>
    {query.error && <ErrorNotice error={query.error} onRetry={query.reload} />}
    <div className="planning-summary-grid">
      <Link className="planning-summary-card summary-card-link" to={`${root}/flows`}><span>规划任务<ArrowUpRight size={14} /></span><strong>{stats.task_count.toLocaleString()}</strong><span>{stats.needs_review} 张待复核 · {stats.dependency_count.toLocaleString()} 项依赖</span></Link>
      <Link className="planning-summary-card summary-card-link" to={`${root}/requirements`}><span>需求映射覆盖<ArrowUpRight size={14} /></span><strong>{stats.covered} <small>/ {stats.requirements}</small></strong>{stats.requirements > 0 && <div className="coverage-track" role="progressbar" aria-label="需求映射覆盖进度" aria-valuemin={0} aria-valuemax={stats.requirements} aria-valuenow={stats.covered}><span style={{ width: `${Math.min(100, stats.covered / stats.requirements * 100)}%` }} /></div>}<span>缺口 {stats.uncovered} 条 · 明确延期 {stats.deferred} 条</span></Link>
      <Link className="planning-summary-card summary-card-link" to={`${root}/teams`}><span>活动尝试 / 持久上下文<ArrowUpRight size={14} /></span><strong>{capacity.active_attempts} <small>/ {capacity.persistent_contexts}</small></strong><span>Native 会话登记观测 {capacity.observed_native_sessions} 个 · 含历史</span></Link>
    </div>
    <div className="planning-overview-grid"><Panel title={<><AlertCircle size={16} />需要处理</>}>
      {blockers.length ? blockers.map((blocker, i) => <article className="planning-action-row" key={i}><div><strong>{blocker.title}</strong><small>{blocker.reason}</small></div><Link to={blocker.to} className="button">{blocker.action}<ArrowUpRight size={14} /></Link></article>) : <EmptyState title="此摘要未发现规划阻塞" description="任务准入与交付验收仍以对应服务端检查为准。" />}
      {data.decisions.map(decision => <article className="planning-action-row" key={decision.decision_id}><div><StatusBadge state={decision.state} /><p>{decision.note}</p></div><Link to={`/decisions?project=${pathId(projectId)}`}>处理决策</Link></article>)}
    </Panel><Panel title={<><CalendarDays size={16} />里程碑与覆盖缺口</>}>
      {data.milestones.length ? data.milestones.map((m, i) => <Link className="planning-action-row" to={`${root}/schedule`} key={i}><span>{String(m.title ?? m.name ?? m.milestone_id ?? '里程碑')}<small>{String(m.due_at ?? m.target_date ?? m.target_at ?? m.deadline ?? '日期待安排')}</small></span><ArrowUpRight size={14} /></Link>) : <p className="muted">尚未登记里程碑。<Link to={`/calendar?project=${pathId(projectId)}`}>安排交付目标</Link></p>}
      {data.milestone_count > data.milestones.length && <Link to={`/calendar?project=${pathId(projectId)}`}>查看全部 {data.milestone_count} 个里程碑</Link>}
      {stats.gaps.map(gap => <Link className="planning-action-row" key={gap.requirement_id} to={`${root}/requirements?requirement=${pathId(gap.requirement_id)}`}><span>{gap.title}<small>缺少任务映射</small></span><ArrowUpRight size={14} /></Link>)}
      {stats.uncovered > stats.gaps.length && <Link to={`${root}/requirements`}>查看全部 {stats.uncovered} 条缺口</Link>}
    </Panel></div><SourceStamp source={query.metadata.source} observedAt={query.metadata.observed_at} />
  </section>;
}
