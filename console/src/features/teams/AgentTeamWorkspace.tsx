import { useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import { useApi, useCursorApi } from '../../app/api';
import { DataTable, EmptyState, ErrorNotice, Panel, Pagination, StatusBadge } from '../../components';
import { TaskInspector, type InspectorAttempt } from '../../components/TaskInspector';
import { pathId, useCompleteApi, type TaskCard } from '../flow/types';
type Context = { context_id: string; position_id: string; model_route_id: string; history_refs: unknown[] };
type Role = { position_id: string; owner_id: string; owner_team_id: string; teammate_name: string };
export function AgentTeamWorkspace({ projectId }: { projectId: string }) {
  const root = `/projects/${pathId(projectId)}`;
  const [params, setParams] = useSearchParams(); const team = params.get('team') ?? '';
  const [page, setPage] = useState(0);
  const contexts = useCompleteApi<Context>(`${root}/documents/agent_contexts`);
  const execution = useApi<{ teams: { team_id: string; name: string; paused: boolean }[]; attempts: InspectorAttempt[] }>(`${root}/assignment-context`);
  const tasks = useCursorApi<TaskCard[]>(`${root}/tasks?limit=50${team ? `&team=${pathId(team)}` : ''}`, 'team_task_cursor');
  const settings = useApi<{ source_refs?: { roster?: string } }>(`${root}/documents/delivery_settings/default`);
  const roster = useApi<{ content?: string }>(settings.data?.source_refs?.roster ? `${root}/sources/${pathId(settings.data.source_refs.roster)}` : null);
  let roles: Role[] = []; let rosterError: Error | undefined;
  if (roster.data?.content) try { const parsed = JSON.parse(roster.data.content); roles = parsed.roster ?? parsed.positions ?? parsed.roles ?? []; if (!Array.isArray(roles)) throw new Error('岗位名册需要结构化列表'); } catch (cause) { rosterError = cause instanceof Error ? cause : new Error(String(cause)); }
  const selectedId = params.get('task');
  const selected = useApi<TaskCard>(selectedId ? `${root}/tasks/${pathId(selectedId)}` : null);
  const selectTask = (id: string) => setParams(prior => { const next = new URLSearchParams(prior); next.set('task', id); return next; }, { replace: true });
  return <>
    {[contexts.error, execution.error, tasks.error, roster.error, rosterError, selected.error].map((error, i) => error && <ErrorNotice key={i} error={error} />)}
    <Panel title="团队当前任务与等待原因" actions={<select aria-label="团队任务范围" value={team} onChange={event => setParams(prior => { const next = new URLSearchParams(prior); if (event.target.value) next.set('team', event.target.value); else next.delete('team'); next.delete('team_task_cursor'); return next; }, { replace: true })}><option value="">全部团队</option>{execution.data?.teams.map(t => <option key={t.team_id} value={t.team_id}>{t.name}</option>)}</select>}>
      <p className="muted">全部匹配 {tasks.metadata.total_count ?? '读取中'} 张任务；真实执行仅关联相同任务修订。</p>
      <DataTable selectedKey={selectedId ?? undefined} rows={tasks.data ?? []} rowKey={task => task.task_id} onRowClick={task => selectTask(task.task_id)} columns={[
        { key: 'title', label: '任务 / 团队', render: t => <span>{t.title}<small>{t.team_id} · {t.task_id}</small></span> },
        { key: 'state', label: '规划', render: t => <StatusBadge state={t.state} /> },
        { key: 'execution', label: '实际执行 / 下一步', render: t => { const attempts = execution.data?.attempts.filter(a => a.task_id === t.task_id && a.task_revision === t.task_revision).sort((a, b) => b.created_at.localeCompare(a.created_at)); return attempts?.length ? <StatusBadge state={attempts[0].state} /> : <span>{t.state === 'NEEDS_REVIEW' ? '先复核任务定义与输入' : t.state === 'DEFERRED' ? '已延期，核对需求安排' : '尚无尝试，查看准入检查'}</span>; } },
      ]} /><Pagination query={tasks} count={tasks.data?.length ?? 0} />
    </Panel>
    <details className="team-context-details"><summary><span>岗位与独立上下文</span><small>{contexts.data ? `${contexts.data.length} 个已登记 · 查看模型路由与交接历史` : '正在读取…'}</small></summary>
    <Panel title="独立上下文与岗位交接"><DataTable rows={(contexts.data ?? []).slice(page * 32, (page + 1) * 32)} rowKey={c => c.context_id} empty={<EmptyState title="尚未登记独立上下文" description="通过项目配置登记岗位与独立输入后，这里会关联显示；不会从团队数推算 Agent 数。" />} columns={[
      { key: 'position_id', label: '岗位 / 责任', render: c => { const role = roles.find(r => r.position_id === c.position_id); return <span>{role?.teammate_name ?? c.position_id}<small>{role ? `${role.owner_id} · ${role.owner_team_id}` : '名册责任尚未绑定'}</small></span>; } },
      { key: 'context_id', label: '独立上下文', render: c => <code>{c.context_id}</code> },
      { key: 'model_route_id', label: '模型路由' },
      { key: 'history', label: '交接历史', render: c => `${c.history_refs.length} 条不可变引用` },
    ]} /><div className="toolbar"><button disabled={!page} onClick={() => setPage(n => n - 1)}>上一页上下文</button><span>{page + 1} / {Math.max(1, Math.ceil((contexts.data?.length ?? 0) / 32))}</span><button disabled={(page + 1) * 32 >= (contexts.data?.length ?? 0)} onClick={() => setPage(n => n + 1)}>下一页上下文</button></div></Panel>
    </details>
    {selected.data && <TaskInspector task={selected.data} onSelectTask={selectTask} onClose={() => setParams(prior => { const next = new URLSearchParams(prior); next.delete('task'); return next; }, { replace: true })} />}
  </>;
}
