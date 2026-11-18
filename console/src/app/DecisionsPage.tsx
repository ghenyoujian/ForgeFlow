import { useEffect, useRef, useState, type KeyboardEvent } from 'react';
import { useSearchParams } from 'react-router-dom';
import { Check, Clock3, Inbox, Pause, Play, Plus, RefreshCw, Search } from 'lucide-react';
import { api, ApiError, items, useApi, useCursorApi } from './api';
import type { ProjectRef } from './types';
import { EmptyState, ErrorNotice, Field, JsonView, PageHeader, Pagination, Panel, QueryState, SourceStamp } from '../components';
import { useCompleteApi } from '../features/flow/types';
import './decisions.css';

type State = 'OPEN' | 'ACKNOWLEDGED' | 'DEFERRED' | 'RESOLVED';
type Vector = Record<string, number>;
interface Policy { scope_id: string; project_id: string | null; team_id: string | null; worker_id: string | null; parent_scope_id: string | null; paused: boolean; revision: number; limits: Vector }
interface Decision {
  schema_version: string; decision_id: string; project_id: string; cause: 'PAUSED_RESOURCE_POLICY'; state: State;
  policy: Policy; blocked_tasks: { task_id: string; task_revision: number; queue_revision: number }[];
  note: string; created_by: string; created_at: string; updated_at: string; revision: number;
  acknowledged_by: string | null; acknowledged_at: string | null; resolved_by: string | null; resolved_at: string | null;
  revisit_at: string | null; resolution_reason: string | null;
}
interface Receipt { decision: Decision; policy: Policy; created: boolean; policy_changed: boolean }
interface Snapshot { project: { project_id: string }; allocations: { scope_id: string; dimension: string; amount: number; state: string }[] }
type Action = 'ack' | 'defer' | 'resolve';
interface Preview { action: Action; decision: Decision; policy: Policy }
const states: Record<State, string> = { OPEN: '待确认', ACKNOWLEDGED: '已确认', DEFERRED: '已延期', RESOLVED: '已解决' };
const dimensions: Record<string, string> = { active_slot: '活动会话', coding_slot: '代码会话', cpu_units: 'CPU 单位', memory_bytes: '内存字节', build_permit: '构建许可', gpu_permit: 'GPU 许可', provider_inflight: '模型在途' };
const path = (value: string) => encodeURIComponent(value);
const time = (value?: string | null) => value ? new Date(value).toLocaleString() : '未记录';

function DecisionState({ state }: { state: State }) {
  const Icon = state === 'RESOLVED' ? Check : state === 'DEFERRED' ? Clock3 : state === 'ACKNOWLEDGED' ? Check : Inbox;
  return <span className="decision-state"><Icon size={13} />{states[state] ?? state}</span>;
}

export function DecisionsPage() {
  const [parameters, setParameters] = useSearchParams();
  const project = parameters.get('project') ?? localStorage.getItem('forgeflow.project') ?? '';
  const selectedId = parameters.get('decision') ?? '';
  const catalog = useCompleteApi<ProjectRef>('/projects');
  const root = project ? `/projects/${path(project)}` : null;
  const query = useCursorApi<Decision[]>(root ? `${root}/decisions` : null, 'decision_cursor');
  const detail = useApi<Decision>(root && selectedId ? `${root}/decisions/${path(selectedId)}` : null);
  const policies = useApi<Policy[]>(root ? `${root}/resources` : null);
  const snapshot = useApi<Snapshot>(root ? `${root}/snapshot` : null);
  const projectQuery = useApi<{ project_id: string; authority_mode: string; archived: boolean }>(root);
  const [status, setStatus] = useState<State | ''>('');
  const [search, setSearch] = useState('');
  const [creating, setCreating] = useState(false);
  const [scope, setScope] = useState('');
  const [note, setNote] = useState('');
  const [preview, setPreview] = useState<Preview>();
  const [reason, setReason] = useState('');
  const [revisit, setRevisit] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<Error>();
  const [notice, setNotice] = useState('');
  const keys = useRef(new Map<string, string>());
  const inFlight = useRef(false);
  const currentScope = useRef({ project, selectedId });
  currentScope.current = { project, selectedId };
  const detailHeading = useRef<HTMLSpanElement>(null);
  const rows = items(query.data);
  const visible = rows.filter(row => (!status || row.state === status) && (!search || `${row.decision_id} ${row.policy.scope_id} ${row.note}`.toLowerCase().includes(search.toLowerCase())));
  const decision = detail.data?.project_id === project && detail.data?.decision_id === selectedId ? detail.data : undefined;
  const currentPolicy = decision ? items(policies.data).find(policy => policy.project_id === project && policy.scope_id === decision.policy.scope_id) : undefined;
  const writable = projectQuery.data?.project_id === project && projectQuery.data.authority_mode === 'MANAGED' && !projectQuery.data.archived;
  const resourceReady = !policies.loading && !policies.error && Array.isArray(policies.data);
  const detailReady = !!decision && !detail.loading && !detail.error;
  const eligible = resourceReady ? items(policies.data).filter(policy => policy.project_id === project && policy.paused) : [];
  const createPolicy = eligible.find(policy => policy.scope_id === scope);
  const sourceStable = !!currentPolicy && currentPolicy.paused && currentPolicy.revision === decision?.policy.revision;

  useEffect(() => { setPreview(undefined); setCreating(false); setScope(''); setNote(''); setReason(''); setRevisit(''); setError(undefined); setNotice(''); }, [project]);
  useEffect(() => { setPreview(undefined); setReason(''); setRevisit(''); }, [selectedId]);
  useEffect(() => { if (selectedId) detailHeading.current?.focus(); }, [selectedId]);
  useEffect(() => {
    const refresh = (event: Event) => {
      const value = (event as CustomEvent<{ projectId?: string; kind?: string }>).detail;
      if (value?.projectId !== project || !/^(decision\.|resource\.)/.test(value.kind ?? '')) return;
      query.reload(); detail.reload(); policies.reload(); snapshot.reload();
    };
    window.addEventListener('forgeflow-event', refresh);
    return () => window.removeEventListener('forgeflow-event', refresh);
  }, [project, query.reload, detail.reload, policies.reload, snapshot.reload]);

  function selectProject(value: string) {
    const next = new URLSearchParams(parameters);
    if (value) next.set('project', value); else next.delete('project');
    next.delete('decision'); next.delete('decision_cursor'); setParameters(next);
  }
  function selectDecision(id: string) { const next = new URLSearchParams(parameters); next.set('project', project); next.set('decision', id); setParameters(next); }
  function refresh() { query.reload(); detail.reload(); policies.reload(); snapshot.reload(); projectQuery.reload(); }
  function reloadForReview() { setPreview(undefined); setError(undefined); setNotice('已请求最新权威记录，请核对后重新预览。'); refresh(); }
  function listKey(event: KeyboardEvent<HTMLButtonElement>, index: number) {
    if (!['ArrowDown', 'ArrowUp', 'Home', 'End'].includes(event.key)) return;
    event.preventDefault();
    const next = event.key === 'Home' ? 0 : event.key === 'End' ? visible.length - 1 : Math.max(0, Math.min(visible.length - 1, index + (event.key === 'ArrowDown' ? 1 : -1)));
    const buttons = event.currentTarget.closest('.decision-list')?.querySelectorAll<HTMLButtonElement>('.decision-item');
    buttons?.[next]?.focus();
  }
  async function beginAction(action: Action) {
    if (!decision || !root || !writable || !detailReady || busy || inFlight.current) return;
    inFlight.current = true; setBusy(true); setPreview(undefined); setError(undefined); setNotice('');
    try {
      const fresh = await api.get<Policy[]>(`${root}/resources`);
      const target = fresh.find(policy => policy.project_id === project && policy.scope_id === decision.policy.scope_id);
      if (!target) throw new Error('目标策略已不可读取，请刷新权威记录。');
      if (action === 'resolve' && (!target.paused || target.revision !== decision.policy.revision)) throw new Error('策略已变化，此事项不能恢复该作用域。请刷新并按当前暂停版本建立新事项。');
      if (currentScope.current.project !== project || currentScope.current.selectedId !== decision.decision_id) return;
      setPreview({ action, decision, policy: target }); setReason(''); setRevisit('');
    } catch (cause) { setError(cause instanceof Error ? cause : new Error(String(cause))); }
    finally { inFlight.current = false; setBusy(false); }
  }
  async function send(commandPath: string, body: Record<string, unknown>, operation: string) {
    if (inFlight.current || !root || !writable) return;
    const message = typeof body.note === 'string' ? body.note : typeof body.reason === 'string' ? body.reason : '';
    if (!message.trim() || message.includes('\0') || new TextEncoder().encode(message).length > 4096) { setError(new Error('说明须为非空文本，不含空字符，UTF-8 长度不超过 4096 字节。')); return; }
    const identity = JSON.stringify([commandPath, body]);
    let key = keys.current.get(identity);
    if (!key) { key = crypto.randomUUID(); keys.current.set(identity, key); }
    inFlight.current = true; setBusy(true); setError(undefined); setNotice('');
    let accepted = false;
    try {
      const receipt = await api.post<Receipt>(commandPath, body, { idempotencyKey: key });
      accepted = true;
      if (receipt.decision.project_id !== project) throw new Error('回执项目身份不匹配，尚未把结果标记为完成。');
      const actual = await api.get<Decision>(`${root}/decisions/${path(receipt.decision.decision_id)}`);
      if (actual.project_id !== project || actual.decision_id !== receipt.decision.decision_id) throw new Error('权威回读身份不匹配。');
      keys.current.delete(identity);
      if (currentScope.current.project !== project) return;
      setPreview(undefined); setCreating(false); selectDecision(actual.decision_id);
      setNotice(`${operation}已由服务端处理，当前权威状态：${states[actual.state]}。`);
      refresh();
    } catch (cause) {
      if (currentScope.current.project !== project) return;
      setError(cause instanceof Error ? cause : new Error(String(cause)));
      if (accepted) setNotice('命令已返回回执，但权威回读未完成。保留原请求身份，可重试同一请求或刷新记录。');
    } finally { inFlight.current = false; setBusy(false); }
  }
  function submitAction() {
    if (!preview || !root || !reason.trim()) return;
    const target = `${root}/decisions/${path(preview.decision.decision_id)}`;
    const base = { expected_revision: preview.decision.revision };
    if (preview.action === 'ack') void send(`${target}/acknowledgments`, { ...base, note: reason.trim() }, '确认');
    else if (preview.action === 'resolve') void send(`${target}/resolutions`, { ...base, expected_policy_revision: preview.policy.revision, reason: reason.trim() }, '恢复作用域');
    else {
      const date = new Date(revisit);
      if (!revisit || !Number.isFinite(date.getTime()) || date.getTime() <= Date.now() || date.getTime() > Date.now() + 365 * 86400000) { setError(new Error('填写未来一年内的真实复查时间。')); return; }
      void send(`${target}/deferrals`, { ...base, revisit_at: date.toISOString(), reason: reason.trim() }, '延期');
    }
  }
  const conflict = error instanceof ApiError && (error.status === 409 || /STALE|CONFLICT/.test(error.code));
  const allocationsReady = snapshot.data?.project.project_id === project && Array.isArray(snapshot.data.allocations) && !snapshot.loading && !snapshot.error;

  return <>
    <PageHeader title="决策收件箱" description="从真实暂停策略建立事项，明确责任、复查时间和恢复范围。" actions={<><button disabled={busy} onClick={refresh}><RefreshCw size={16} />刷新</button><button data-testid="decision-create" disabled={!root || !writable || !resourceReady || busy} onClick={() => { setCreating(value => !value); setPreview(undefined); setError(undefined); }}><Plus size={16} />建立事项</button></>} />
    <div className="decision-toolbar">
      <Field label="项目"><select data-testid="decision-project" aria-label="决策项目" value={project} disabled={busy} onChange={event => selectProject(event.target.value)}><option value="">选择项目</option>{catalog.data?.map(item => <option key={item.project_id ?? item.id} value={item.project_id ?? item.id}>{item.name}</option>)}{project && !catalog.data?.some(item => (item.project_id ?? item.id) === project) && <option value={project}>{project}</option>}</select></Field>
      <Field label="事项状态"><select value={status} onChange={event => setStatus(event.target.value as State | '')}><option value="">全部状态</option>{Object.entries(states).map(([value, label]) => <option key={value} value={value}>{label}</option>)}</select></Field>
      <div className="decision-search"><Field label="检索当前页"><div className="toolbar"><Search size={16} /><input aria-label="检索决策" value={search} onChange={event => setSearch(event.target.value)} placeholder="事项、作用域或说明" /></div></Field></div>
    </div>
    {catalog.error && <ErrorNotice error={catalog.error} onRetry={catalog.reload} />}
    {projectQuery.error && <ErrorNotice error={projectQuery.error} onRetry={projectQuery.reload} />}
    {policies.error && <ErrorNotice error={policies.error} onRetry={policies.reload} />}
    {error && <ErrorNotice error={error} />}{conflict && <div className="notice">权威版本或状态已变化，动作没有被虚拟标记为成功。<button disabled={busy} onClick={reloadForReview}>读取最新记录并重新预览</button></div>}
    {notice && <p className="notice" role="status">{notice}</p>}
    {!root ? <Panel><EmptyState title="选择项目查看决策" description="项目筛选复用工作区当前项目，不授予新的操作权限。" /></Panel> : <>
      <SourceStamp source={query.metadata.source} observedAt={query.metadata.observed_at} />
      {!writable && projectQuery.data && <p className="notice">当前项目为只读观察或已归档，事项与证据可查阅。</p>}
      {creating && <Panel title="从真实暂停策略建立事项"><div className="decision-content"><QueryState loading={policies.loading} error={policies.error} onRetry={policies.reload}>
        {eligible.length ? <form onSubmit={event => { event.preventDefault(); if (createPolicy && note.trim()) void send(`${root}/decisions`, { scope_id: createPolicy.scope_id, expected_policy_revision: createPolicy.revision, note: note.trim() }, '建立事项'); }}>
          <Field label="该项目的暂停策略"><select data-testid="decision-create-scope" required value={scope} disabled={busy} onChange={event => setScope(event.target.value)}><option value="">选择真实作用域</option>{eligible.map(policy => <option value={policy.scope_id} key={policy.scope_id}>{policy.scope_id} · 版本 {policy.revision}</option>)}</select></Field>
          <Field label="建立原因"><textarea data-testid="decision-create-note" required rows={3} value={note} disabled={busy} onChange={event => setNote(event.target.value)} placeholder="记录需要负责人决定的具体问题" /></Field>
          {createPolicy && <p className="notice">仅关联作用域 <code>{createPolicy.scope_id}</code> 的暂停版本 {createPolicy.revision}。队列受阻证据由服务端读取；同一原因会聚合到已有事项。</p>}
          <div className="toolbar"><button data-testid="decision-create-submit" className="primary" disabled={busy || !createPolicy || !note.trim()}>{busy ? '正在提交…' : '建立并回读事项'}</button><button type="button" disabled={busy} onClick={() => setCreating(false)}>取消</button></div>
        </form> : <EmptyState title="该项目当前没有暂停策略" description="只有真实已暂停的资源作用域可以建立此类事项。" />}
      </QueryState></div></Panel>}
      <div className="decision-workspace">
        <Panel title={`事项 · 当前页 ${visible.length}/${rows.length}`}><div className="decision-content"><QueryState loading={query.loading && !query.data} error={query.error} onRetry={query.reload}>
          {visible.length ? <div className="decision-list" aria-label="决策事项列表">{visible.map((item, index) => <button data-testid={`decision-item-${item.decision_id}`} className="decision-item" key={item.decision_id} aria-current={selectedId === item.decision_id ? 'true' : undefined} disabled={busy} onKeyDown={event => listKey(event, index)} onClick={() => selectDecision(item.decision_id)}>
            <span className="decision-item-header"><Pause size={16} /><DecisionState state={item.state} /></span><span className="decision-item-title">{item.note || '暂停策略待决事项'}</span><code>{item.policy.scope_id}</code><span className="decision-item-meta">{item.blocked_tasks.length} 张创建时受阻任务 · {time(item.updated_at)}</span>
          </button>)}</div> : <EmptyState title={rows.length ? '当前页没有匹配事项' : '当前页没有决策事项'} description={rows.length ? '调整筛选；筛选不代表完整历史集合。' : '从该项目的真实暂停策略建立事项，原始原因和处理过程会保留。'} />}
          <Pagination query={query} count={rows.length} />
        </QueryState></div></Panel>
        <div className="decision-detail" data-testid="decision-detail" data-decision-id={decision?.decision_id} data-decision-revision={decision?.revision} data-decision-state={decision?.state} data-policy-revision={currentPolicy?.revision} data-policy-paused={currentPolicy?.paused}><Panel title={<span ref={detailHeading} tabIndex={-1}>事项详情</span>}><div className="decision-content"><QueryState loading={detail.loading && !decision} error={detail.error} onRetry={detail.reload}>
          {!decision ? <EmptyState title="选择一项决策" description="查看来源、当前策略、预算占用和实际处理记录。" /> : <>
            <div className="toolbar"><DecisionState state={decision.state} /><code>{decision.decision_id}</code><span className="muted">事项版本 {decision.revision}</span></div>
            <p>{decision.note}</p><dl className="decision-facts"><dt>受影响作用域</dt><dd><code>{decision.policy.scope_id}</code></dd><dt>原因</dt><dd>资源策略暂停</dd><dt>创建来源</dt><dd>{decision.created_by} · {time(decision.created_at)}</dd><dt>团队 / Worker</dt><dd>{decision.policy.team_id ?? '未绑定团队'} / {decision.policy.worker_id ?? '未绑定 Worker'}</dd><dt>策略版本</dt><dd>创建时 {decision.policy.revision} · 当前 {currentPolicy?.revision ?? '未读取'}</dd><dt>当前策略</dt><dd>{currentPolicy ? currentPolicy.paused ? '暂停新增' : '已开启新增' : '尚未读取当前策略'}</dd><dt>复查时间</dt><dd>{time(decision.revisit_at)}</dd></dl>
            {currentPolicy && <div className="decision-budgets">{Object.entries(currentPolicy.limits).map(([dimension, limit]) => {
              const allocations = snapshot.data?.allocations.filter(allocation => allocation.scope_id === currentPolicy.scope_id && allocation.dimension === dimension && allocation.state !== 'RELEASED');
              const held = allocationsReady && allocations?.every(allocation => Number.isFinite(allocation.amount)) ? allocations.reduce((sum, allocation) => sum + allocation.amount, 0) : undefined;
              return <div className="decision-budget" key={dimension}><small>{dimensions[dimension] ?? dimension} · 余额</small><strong>{held === undefined ? '未读取' : limit - held}</strong><small>容量 {limit} · 占用 {held ?? '未读取'}</small></div>;
            })}</div>}
            <SourceStamp source={snapshot.metadata.source} observedAt={snapshot.metadata.observed_at} />{snapshot.error && <ErrorNotice error={snapshot.error} onRetry={snapshot.reload} />}
            <details><summary>创建时的队列阻塞证据 · {decision.blocked_tasks.length} 张任务</summary>{decision.blocked_tasks.length ? <ul>{decision.blocked_tasks.map(task => <li key={task.task_id}><a href={`/projects/${path(project)}/tasks/${path(task.task_id)}`}>{task.task_id}</a> · 定义 {task.task_revision} · 队列版本 {task.queue_revision}</li>)}</ul> : <p className="muted">创建时未观察到关联队列受阻任务。</p>}</details>
            <ul className="decision-history"><li>建立事项<small>{decision.created_by} · {time(decision.created_at)}</small></li>{decision.acknowledged_at && <li>确认责任<small>{decision.acknowledged_by} · {time(decision.acknowledged_at)}</small></li>}{decision.revisit_at && <li>延期复查<small>{time(decision.revisit_at)}</small></li>}{decision.resolved_at && <li>恢复已绑定作用域<small>{decision.resolved_by} · {time(decision.resolved_at)} · {decision.resolution_reason}</small></li>}</ul>
            <div className="decision-actions">{decision.state === 'OPEN' && <button data-testid="decision-ack" disabled={!writable || !detailReady || busy} onClick={() => void beginAction('ack')}><Check size={16} />确认事项</button>}{['OPEN', 'ACKNOWLEDGED'].includes(decision.state) && <button data-testid="decision-defer" disabled={!writable || !detailReady || busy} onClick={() => void beginAction('defer')}><Clock3 size={16} />安排复查</button>}{decision.state === 'ACKNOWLEDGED' && <button data-testid="decision-resolve" className="primary" disabled={!writable || !detailReady || !resourceReady || !sourceStable || busy} onClick={() => void beginAction('resolve')}><Play size={16} />预览恢复作用域</button>}</div>
            {decision.state === 'ACKNOWLEDGED' && resourceReady && !sourceStable && <p className="notice">策略已改变或已开启。此事项不能恢复另一个策略版本，先读取最新记录。</p>}
            {decision.state === 'DEFERRED' && <p className="notice">延期记录保留真实复查时间；尚未恢复策略。</p>}
            {preview && preview.decision.decision_id === decision.decision_id && <form data-testid="decision-preview" className="decision-preview" onSubmit={event => { event.preventDefault(); submitAction(); }}>
              <h3>{preview.action === 'resolve' ? '恢复动作预览' : preview.action === 'ack' ? '确认事项预览' : '延期复查预览'}</h3>
              <dl className="decision-facts"><dt>作用域</dt><dd><code>{preview.policy.scope_id}</code></dd><dt>绑定版本</dt><dd>事项 {preview.decision.revision} · 策略 {preview.policy.revision}</dd><dt>实际效果</dt><dd>{preview.action === 'resolve' ? '仅把该暂停策略开启；容量和已有占用保留原值。' : preview.action === 'ack' ? '登记负责人确认；策略继续暂停。' : '记录延期与复查时间；策略继续暂停。'}</dd></dl>
              <Field label={preview.action === 'ack' ? '确认说明' : '处理依据'}><textarea data-testid="decision-action-reason" required rows={3} value={reason} disabled={busy} onChange={event => setReason(event.target.value)} /></Field>
              {preview.action === 'defer' && <Field label="实际复查时间" hint="使用当前设备时区填写，提交时转换为 UTC。"><input data-testid="decision-action-revisit" type="datetime-local" required value={revisit} disabled={busy} onChange={event => setRevisit(event.target.value)} /></Field>}
              <div className="toolbar"><button data-testid="decision-action-submit" className="primary" disabled={busy || !reason.trim() || (preview.action === 'defer' && !revisit)}>{busy ? '正在提交并回读…' : preview.action === 'resolve' ? '确认恢复此作用域' : preview.action === 'ack' ? '确认并回读事项' : '确认延期'}</button><button type="button" disabled={busy} onClick={() => setPreview(undefined)}>取消</button></div>
            </form>}
            <details><summary>完整权威记录</summary><JsonView value={decision} /></details>
          </>}
        </QueryState></div></Panel></div>
      </div>
    </>}
  </>;
}
