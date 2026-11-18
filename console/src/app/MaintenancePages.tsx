import { useEffect, useRef, useState } from 'react';
import { Link, useSearchParams } from 'react-router-dom';
import { Archive, ArrowUpRight, Download, FolderOpen, Layers3, RefreshCw, Search, ShieldCheck } from 'lucide-react';
import { api, ApiError, apiUrl, getToken, useApi, useCursorApi } from './api';
import { EmptyState, ErrorNotice, Field, JsonView, PageHeader, Pagination, Panel, QueryState, SourceStamp, StatusBadge } from '../components';
import { useCollection } from '../features/portfolio/collection';
import { IntegrationRecovery } from '../features/runs/IntegrationRecovery';
import type { Row } from '../features/portfolio/monitor';
import './maintenance.css';

const path = encodeURIComponent;
const time = (value?: string | null) => value && Number.isFinite(new Date(value).getTime()) ? new Date(value).toLocaleString() : '时间未知';
const count = (value: unknown): number | undefined => typeof value === 'number' && Number.isSafeInteger(value) && value >= 0 ? value : undefined;
const quantity = (value: unknown) => count(value)?.toLocaleString('zh-CN') ?? '未知';
const bytes = (value?: number) => {
  if (count(value) === undefined) return '大小未知';
  if (value === 0) return '0 B';
  const units = ['B', 'KiB', 'MiB', 'GiB', 'TiB', 'PiB'];
  const index = Math.min(Math.floor(Math.log(value!) / Math.log(1024)), units.length - 1);
  return `${(value! / 1024 ** index).toLocaleString('zh-CN', { maximumFractionDigits: index === 0 ? 0 : 1 })} ${units[index]}`;
};
const errorOf = (cause: unknown) => cause instanceof Error ? cause : new Error(String(cause));
const reasonNames: Record<string, string> = {
  RECOVERY_REQUIRED: '执行结果待核对', STOP_UNCONFIRMED: '还未确认停止', MODEL_CUSTODY_PENDING: '模型用量未结清',
  INTEGRATION_UNRESOLVED: '主线集成待核对', TERMINAL_CUSTODY_RETAINED: '作者结束后仍有占用', WORKER_HEARTBEAT_STALE: '近期没有 Worker 心跳',
};
interface RecoveryItem extends Row {
  project_id: string; project_name: string; task_id: string; attempt_id: string; state: string;
  worker_id: string; revision: number; generation: number; reasons: string[];
  last_worker_heartbeat_at: string | null; process_status: string;
  pending_native_model_request_count: number; pending_gateway_model_request_count: number; held_allocation_count: number;
  lease_expires_at: string | null; lease_revoked_at: string | null; merge_intents: Row[];
}

interface MaintenanceIssue {
  key: string; title: string; amount?: number; unit: string; explanation: string;
  next: string; to: string; action: string;
}

function IssueCards({ issues }: { issues: MaintenanceIssue[] }) {
  return <div className="maintenance-issues">{issues.map(issue => <article key={issue.key} className="maintenance-issue" data-maintenance-issue={issue.key}>
    <div className="maintenance-issue-heading"><h4>{issue.title}</h4><span className="maintenance-issue-count">{quantity(issue.amount)}<small>{issue.unit}</small></span></div>
    <p>{issue.explanation}</p><p className="maintenance-next-step"><strong>下一步</strong>{issue.next}</p>
    <Link to={issue.to}>{issue.action}<ArrowUpRight size={14} aria-hidden="true" /></Link>
  </article>)}</div>;
}

function recoveryIssues(item: RecoveryItem): MaintenanceIssue[] {
  const attempt = `/runs/${path(item.attempt_id)}?project=${path(item.project_id)}`;
  return item.reasons.map(reason => {
    const base = { key: reason, title: reasonNames[reason] ?? '还有一项记录待核对', unit: '项', to: attempt, action: '查看这次尝试', next: '打开原尝试，核对保留的执行记录与证据。' };
    if (reason === 'MODEL_CUSTODY_PENDING') {
      const native = count(item.pending_native_model_request_count);
      const gateway = count(item.pending_gateway_model_request_count);
      const primary = native !== undefined && native > 0 ? { amount: native, unit: '个原生请求' } : gateway !== undefined && gateway > 0 ? { amount: gateway, unit: '个网关请求' } : { amount: undefined, unit: '个未结清请求' };
      return { ...base, ...primary, explanation: `原生模型请求 ${quantity(native)} 个，网关模型请求 ${quantity(gateway)} 个。它们是不同记录口径，不代表同时运行的模型数。`, next: '先核对原请求与用量回执；取消作者也不会清除未知用量。' };
    }
    if (reason === 'TERMINAL_CUSTODY_RETAINED') return { ...base, amount: count(item.held_allocation_count), unit: '条分配记录', explanation: '作者尝试已经结束，相关资源仍被保留。一项资源可能在多个范围登记，记录数不能当作活动 Agent 数。', next: '核对可信停止证明和原分配记录，等待原流程确认可释放的范围。', to: '/resources', action: '查看全工作区资源' };
    if (reason === 'INTEGRATION_UNRESOLVED') return { ...base, amount: item.merge_intents.length, unit: '条集成意图', explanation: '候选或主线提交仍需要核对，当前作者状态不能代替实际 Git 集成结果。', next: '核对原候选和已经持久化的提交决定，再按现有集成恢复流程处理。', to: `/projects/${path(item.project_id)}/integration`, action: '查看项目集成记录' };
    if (reason === 'STOP_UNCONFIRMED') return { ...base, amount: 1, explanation: '停止请求尚未获得完整确认，当前不能认定进程已经退出。', next: '核对原执行器留下的停止观察，保留尚未确认的占用。' };
    if (reason === 'WORKER_HEARTBEAT_STALE') return { ...base, amount: 1, unit: '个执行节点', explanation: `最近一次心跳：${time(item.last_worker_heartbeat_at)}。超过 120 秒未收到观察，并不能据此判断进程已停止。`, next: '先查看执行器状态和原尝试记录；这里不会启动执行器或恢复自启动。', to: '/executors', action: '查看执行器状态' };
    return { ...base, amount: 1, explanation: reason === 'RECOVERY_REQUIRED' ? '这次执行的结果尚未完成核对，任务没有因此获得新的完成或集成记录。' : '服务端保留了一项尚未解释的条件，详情中提供原始原因。' };
  });
}

const custodyReasons: Record<string, string> = {
  AUTHOR_STOP_OBSERVATION_MISSING: '尚未登记原执行器的可信停止观察。',
  PROCESS_EXIT_UNCONFIRMED: '完整停止证明仍未满足原流程要求。',
  MERGE_EFFECT_UNCONFIRMED: '需要先核对已有集成决定及其结果。',
  LEASE_STALE: '原写入租约和权限撤销仍需核对。',
  NO_UNKNOWN_NATIVE_CUSTODY: '当前没有符合该作者关闭流程的未知原生模型占用。',
  AUTHOR_CLOSE_STATE_INVALID: '当前作者状态不允许按此流程关闭。',
};

function CustodyFacts({ value, item }: { value: Row; item: RecoveryItem }) {
  if (value.project_id !== item.project_id || value.attempt_id !== item.attempt_id) return <ErrorNotice error={new Error('恢复详情与所选尝试不一致，请刷新实际记录。')} />;
  const observation = typeof value.trusted_stop_observation_event_id === 'string' && value.trusted_stop_observation_event_id.length > 0;
  const blocked = typeof value.blocked_code === 'string' ? value.blocked_code : '';
  return <div className="maintenance-custody">
    <div className="maintenance-facts"><div><span>原生模型请求未结清</span><strong>{quantity(value.pending_native_model_request_count)}<small> 个</small></strong></div><div><span>资源分配仍被保留</span><strong>{quantity(value.held_allocation_count)}<small> 条记录</small></strong></div><div><span>可信停止观察</span><strong>{observation ? '已登记' : value.trusted_stop_observation_event_id === null ? '尚未登记' : '未提供'}</strong></div></div>
    <div className="maintenance-guidance"><h4>当前可以做什么</h4><p>{value.author_close_eligible === true ? '服务端已允许进入作者关闭审阅。请在原尝试中核对适用范围，未知用量仍会保留。' : custodyReasons[blocked] ?? '关闭作者的前置条件尚未确认满足，请核对原尝试和诊断记录。'}</p><Link to={`/runs/${path(item.attempt_id)}?project=${path(item.project_id)}`}>核对完整尝试与停止证据<ArrowUpRight size={14} /></Link></div>
    <details className="maintenance-diagnostics"><summary>高级诊断：身份、停止条件与原始回执</summary><JsonView value={value} /></details>
  </div>;
}

export function RecoveryPage() {
  const [parameters, setParameters] = useSearchParams();
  const project = parameters.get('project') ?? '';
  const [selected, select] = useState<RecoveryItem>();
  const projects = useCollection<{ project_id: string; name: string }>('/projects');
  const query = useCursorApi<RecoveryItem[]>(`/recovery-items${project ? `?project_id=${path(project)}` : ''}`, 'recovery_cursor');
  const attempt = useApi<Row>(selected && selected.merge_intents.length > 0 ? `/attempts/${path(selected.attempt_id)}?project_id=${path(selected.project_id)}` : null);
  const custody = useApi<Row>(selected ? `/attempts/${path(selected.attempt_id)}/author-custody?project_id=${path(selected.project_id)}` : null);
  useEffect(() => { select(undefined); }, [project]);
  const reload = () => { query.reload(); attempt.reload(); custody.reload(); };
  return <div className="maintenance-recovery">
    <PageHeader title="恢复与异常" description="先了解什么还没有确认，再沿原记录核对执行、用量、占用和主线集成。" actions={<button onClick={reload}><RefreshCw size={15} />刷新实际记录</button>} />
    <Panel title="需要核对的尝试" className="maintenance-panel">
      <div className="panel-body maintenance-recovery-intro"><Field label="查看范围"><select value={project} onChange={event => { const next = new URLSearchParams(parameters); event.target.value ? next.set('project', event.target.value) : next.delete('project'); next.delete('recovery_cursor'); setParameters(next); }}><option value="">所有项目</option>{(projects.data ?? []).map(item => <option key={item.project_id} value={item.project_id}>{item.name}</option>)}</select></Field>
        <p>“已取消”描述作者尝试的状态。未知模型用量和资源占用有各自的确认条件，作者结束后仍可能留在这里。</p>
        {projects.error && <ErrorNotice error={projects.error} onRetry={projects.reload} />}
      </div>
      <QueryState loading={query.loading} error={query.error} onRetry={query.reload}>
        {query.data?.length === 0 ? <EmptyState title="当前范围没有待恢复记录" description="可以回到项目查看交付情况；历史失败与审计记录仍然保留。" action={<Link to={project ? `/projects/${path(project)}` : '/portfolio'}>查看项目交付</Link>} /> : <div className="table-wrap maintenance-recovery-table"><table><thead><tr><th>项目与任务</th><th>作者尝试状态</th><th>为什么需要核对</th><th>未结清模型请求</th><th>资源占用</th><th>下一步</th></tr></thead><tbody>{(query.data ?? []).map(item => <tr key={item.attempt_id}><td><strong>{item.project_name || '项目名称未提供'}</strong><code className="maintenance-task-id" title={item.task_id}>{item.task_id}</code></td><td><StatusBadge state={item.state} scope="attempt" /></td><td><div className="maintenance-reason-tags">{item.reasons.map(reason => <span key={reason}>{reasonNames[reason] ?? '还有条件待核对'}</span>)}</div></td><td><span className="maintenance-count-line">原生 <strong>{quantity(item.pending_native_model_request_count)}</strong></span><span className="maintenance-count-line">网关 <strong>{quantity(item.pending_gateway_model_request_count)}</strong></span></td><td><strong>{quantity(item.held_allocation_count)}</strong><small className="maintenance-table-caption">条分配记录</small></td><td><button onClick={() => select(item)} aria-label={`查看恢复 ${item.task_id}`}><Search size={14} />查看原因与入口</button></td></tr>)}</tbody></table></div>}
      </QueryState>
      <Pagination query={query} count={query.data?.length ?? 0} /><SourceStamp source={query.metadata.source} observedAt={query.metadata.observed_at} />
    </Panel>
    {selected && <>
      <Panel title={`${selected.project_name || '所选项目'} · 恢复核对`} className="maintenance-panel" actions={<button onClick={() => select(undefined)}>收起详情</button>}>
        <div className="panel-body">
          <p className="maintenance-detail-lead">当前进程状态仍未知。最近心跳为 {time(selected.last_worker_heartbeat_at)}，心跳和租约记录都不能单独证明进程已经退出。</p>
          <IssueCards issues={recoveryIssues(selected)} />
          <details className="maintenance-diagnostics"><summary>查看尝试身份与租约记录</summary><dl className="maintenance-record"><div><dt>任务</dt><dd>{selected.task_id}</dd></div><div><dt>尝试</dt><dd>{selected.attempt_id}</dd></div><div><dt>Worker</dt><dd>{selected.worker_id}</dd></div><div><dt>租约到期</dt><dd>{time(selected.lease_expires_at)}</dd></div><div><dt>租约撤销</dt><dd>{time(selected.lease_revoked_at)}</dd></div></dl></details>
          <p className="maintenance-policy-note">这里只提供原记录和现有处理入口。不会启动执行器、恢复自启动，或清除尚未确认的占用。</p>
        </div>
        <QueryState loading={custody.loading} error={custody.error} onRetry={custody.reload}>{custody.data && <CustodyFacts value={custody.data} item={selected} />}</QueryState>
        <SourceStamp source={custody.metadata.source} observedAt={custody.metadata.observed_at} />
      </Panel>
      {selected.merge_intents.length > 0 && <QueryState loading={attempt.loading} error={attempt.error} onRetry={attempt.reload}>{attempt.data && <IntegrationRecovery projectId={selected.project_id} attemptId={selected.attempt_id} attempt={attempt.data} onRecovered={reload} />}</QueryState>}
    </>}
  </div>;
}

interface Readiness { ready: boolean; scope_sha256: string; backup_root: string; projects: { project_id: string; name: string; paused: boolean; revision: number }[]; unsettled_attempts: Row[]; custody: Record<string, number>; blockers: { code: string; kind?: string; count?: number; project_id?: string }[] }
interface BackupJob { backup_id: string; status: string; phase: string; created_at: string; updated_at: string; reason: string; archive_bytes?: number; archive_sha256?: string; archive_warning?: string; download_available: boolean; error?: { code: string; message: string }; progress?: Row; verification?: Row }
const phases: Record<string, string> = { ACCEPTED: '请求已留档', CHECKING_CUSTODY: '核对未结清占用', PAUSING_DISPATCH: '暂停新增派发', READING_INVENTORY: '读取文件与 Git 清单', EXPORTING_DATABASE: '导出 PostgreSQL', COPYING_DATA: '复制持久数据', COPYING_REPOSITORIES: '复制外部仓库', CHECKING_QUIESCENCE: '复核静止窗口', SEALING_MANIFEST: '封存清单', SNAPSHOT_VERIFIED: '快照已核对', ARCHIVING: '压缩归档', VERIFYING_ARCHIVE: '逐文件校验归档', SEALED: '归档已封存', INTERRUPTED: '中断待核对' };
const phaseDescriptions: Record<string, string> = {
  ACCEPTED: '请求已经留档，实际备份结果仍待后台作业确认。',
  CHECKING_CUSTODY: '正在确认所有项目的尝试、模型用量和占用都符合备份条件。',
  PAUSING_DISPATCH: '正在按审阅范围暂停新增派发，现有尝试不会被这里强制取消。',
  READING_INVENTORY: '正在登记要保留的文件与仓库身份。',
  EXPORTING_DATABASE: '正在导出项目、任务、历史与权威记录。',
  COPYING_DATA: '正在复制日志、证据和其他持久文件。',
  COPYING_REPOSITORIES: '正在保留需要单独复制的受管仓库。',
  CHECKING_QUIESCENCE: '正在复核备份期间是否发生了会影响一致性的写入。',
  SEALING_MANIFEST: '正在记录完整文件清单和摘要。',
  SNAPSHOT_VERIFIED: '快照检查已经完成，归档尚未封存。',
  ARCHIVING: '正在生成压缩文件，完成前还不能下载。',
  VERIFYING_ARCHIVE: '正在逐项核对实际归档，检查通过后才提供下载。',
  SEALED: '实际归档已经完成校验并封存，可以下载和查看隔离恢复条件。',
  INTERRUPTED: '原作业未完成确认，部分材料继续保留，不会自动重跑或作为成功备份下载。',
};

function backupIssues(data: Readiness): MaintenanceIssue[] {
  const issues: MaintenanceIssue[] = [];
  const attempts = data.unsettled_attempts;
  const first = attempts[0];
  if (attempts.length > 0 || data.blockers.some(blocker => blocker.code === 'UNSETTLED_ATTEMPTS')) {
    const exactAttempt = typeof first?.attempt_id === 'string' && typeof first?.project_id === 'string';
    issues.push({ key: 'unsettled_attempts', title: '尝试还没有结束确认', amount: attempts.length, unit: '次尝试', explanation: '这些尝试还没有形成终态。备份需要一个没有未结算执行写入的窗口。', next: '查看原尝试，等待完成或按原停止流程核对；这里不会代为取消。', to: exactAttempt ? `/runs/${path(first.attempt_id as string)}?project=${path(first.project_id as string)}` : '/runs', action: exactAttempt ? '查看原尝试' : '查看执行大厅' });
  }
  const kinds: Record<string, Omit<MaintenanceIssue, 'key' | 'amount'>> = {
    pending_native_model_requests: { title: '原生模型请求未结清', unit: '个请求', explanation: '缺少完整结算的请求继续保留，作者取消或进程退出都不会把未知用量改成零。', next: '到恢复台沿原尝试核对用量和可信停止记录。', to: '/recovery', action: '核对模型请求' },
    pending_gateway_model_requests: { title: '网关模型请求未结清', unit: '个请求', explanation: '模型网关仍保留未结清记录，此数量是网关记录口径，不代表正在请求的模型数。', next: '到恢复台查找原尝试，核对请求与结算证据。', to: '/recovery', action: '核对网关用量' },
    held_resource_allocations: { title: '资源分配记录仍被保留', unit: '条记录', explanation: '同一项资源可能在多个范围登记。这是尚未释放的分配记录数，不能当作运行中的 Agent 数。', next: '先核对相关尝试的停止与未结清用量，再查看资源记录。', to: '/resources', action: '查看全工作区资源' },
    held_native_allocations: { title: '子级资源分配仍被保留', unit: '条记录', explanation: '子级执行产生的资源分配尚未释放，结束作者不会跳过它们的核对。', next: '从恢复台沿原尝试核对其子级和占用记录。', to: '/recovery', action: '查看恢复事项' },
    held_native_lifecycles: { title: '会话占用记录仍未结清', unit: '条记录', explanation: '这些会话记录尚未释放。记录数不能说明有多少进程仍在运行，可信停止观察与用量仍需分别核对。', next: '从恢复台打开原尝试，核对保留的会话和停止证据。', to: '/recovery', action: '核对会话记录' },
    unresolved_merge_intents: { title: '主线集成还有未决记录', unit: '条集成意图', explanation: '已有候选或提交决定的结果尚待核对，需要保留原集成身份。', next: '从恢复事项进入对应项目，核对原候选、主线与提交决定。', to: '/recovery', action: '查看集成恢复事项' },
  };
  for (const [kind, explanation] of Object.entries(kinds)) {
    const blocker = data.blockers.find(item => item.code === 'CUSTODY_PENDING' && item.kind === kind);
    const amount = count(data.custody[kind]) ?? count(blocker?.count);
    if (blocker || (amount !== undefined && amount > 0)) issues.push({ key: kind, amount, ...explanation });
  }
  const unavailable = data.blockers.filter(blocker => blocker.code === 'REPOSITORY_UNAVAILABLE');
  if (unavailable.length) issues.push({ key: 'repositories', title: '项目仓库目录不可用', amount: unavailable.length, unit: '个项目', explanation: '当前服务无法确认这些项目登记的仓库目录可用，不能为它们生成完整备份。', next: '查看下方项目登记，确认原目录或挂载，再返回这里刷新检查。', to: '/portfolio', action: '查看项目目录' });
  const other = data.blockers.filter(blocker => !['UNSETTLED_ATTEMPTS', 'REPOSITORY_UNAVAILABLE'].includes(blocker.code) && !(blocker.code === 'CUSTODY_PENDING' && blocker.kind && kinds[blocker.kind]));
  if (other.length) issues.push({ key: 'other_conditions', title: '还有备份条件需要核对', amount: other.length, unit: '项', explanation: '服务端保留了尚不能明确解释的条件，当前仍不能创建一致备份。', next: '查看高级诊断中的原始原因，核对后重新读取；不会跳过此条件。', to: '/recovery', action: '查看现有恢复记录' });
  return issues;
}

function ReadinessExplanation({ data }: { data: Readiness }) {
  const issues = backupIssues(data);
  const unavailable = data.blockers.filter(blocker => blocker.code === 'REPOSITORY_UNAVAILABLE');
  const names = new Map(data.projects.map(project => [project.project_id, project.name]));
  return <div className="maintenance-readiness" data-testid="maintenance-readiness-explanation">
    <div className="maintenance-readiness-heading"><ShieldCheck size={20} /><div><h3>{data.ready ? '当前备份条件已满足，等待审阅范围' : '完整备份暂时不能创建'}</h3><p>{data.ready ? '可以继续核对全部项目范围、填写原因并确认。提交前服务端仍会再次检查。' : '先核对下面的事实，处理后刷新检查。项目筛选不会隐藏或跳过这些备份条件。'}</p></div></div>
    {!data.ready && <IssueCards issues={issues} />}
    {unavailable.length > 0 && <div className="maintenance-project-problems"><h4>需要核对登记目录的项目</h4><ul>{unavailable.map((blocker, index) => <li key={`${blocker.project_id ?? 'unknown'}:${index}`}>{blocker.project_id ? <Link to={`/projects/${path(blocker.project_id)}`}><FolderOpen size={15} /><span>{names.get(blocker.project_id) || '名称未提供的项目'}</span><ArrowUpRight size={13} /></Link> : <span>该条记录未提供项目身份，请查看高级诊断。</span>}</li>)}</ul></div>}
    {data.unsettled_attempts.length > 0 && <details className="maintenance-diagnostics"><summary>查看尚未结束确认的尝试（{data.unsettled_attempts.length} 次）</summary><ul className="maintenance-attempt-links">{data.unsettled_attempts.slice(0, 12).map((item, index) => <li key={typeof item.attempt_id === 'string' ? item.attempt_id : index}>{typeof item.project_id === 'string' && typeof item.attempt_id === 'string' ? <Link to={`/runs/${path(item.attempt_id)}?project=${path(item.project_id)}`}><span>{names.get(item.project_id) || '名称未提供的项目'}</span><StatusBadge state={typeof item.state === 'string' ? item.state : undefined} scope="attempt" /><ArrowUpRight size={13} /></Link> : '尝试身份未完整提供，请查看原始记录。'}</li>)}</ul>{data.unsettled_attempts.length > 12 && <p>这里只列出前 12 次尝试，其余可到项目执行大厅核对。</p>}</details>}
    <details className="maintenance-diagnostics"><summary>高级诊断：完整备份检查回执</summary><p>以下保留接口原始字段、范围摘要与实际数量；未知占用继续保留。</p><JsonView value={data} /></details>
  </div>;
}

function RestoreFacts({ value }: { value: Row }) {
  const verification = value.verification && typeof value.verification === 'object' && !Array.isArray(value.verification) ? value.verification as Row : {};
  const projects = Array.isArray(verification.projects) ? verification.projects.length : undefined;
  return <section className="maintenance-restore-preview" aria-label="隔离恢复条件">
    <h4>先准备隔离环境，再按恢复流程核对</h4><p>{value.restore_executed === false && value.production_overwritten === false ? '本次只查看封存归档和恢复条件，没有执行恢复或覆盖生产。' : '接口未完整提供恢复执行标记，请先核对高级诊断。'}</p>
    <p>{verification.status === 'VERIFIED' ? '当前归档与原封存验证回执匹配。' : '验证回执的状态尚未明确，请核对高级诊断。'}</p>
    <div className="maintenance-facts"><div><span>快照项目</span><strong>{quantity(projects)}<small> 个</small></strong></div><div><span>归档文件</span><strong>{quantity(verification.file_count)}<small> 个</small></strong></div><div><span>解包后内容</span><strong>{bytes(typeof verification.unpacked_bytes === 'number' ? verification.unpacked_bytes : undefined)}</strong></div></div>
    <ol><li>下载备份，保留文件大小与完整摘要。</li><li>准备一个新的隔离目录与显式空数据库，按部署恢复流程还原。</li><li>先核对仓库路径、Git、证据和访问凭证；派发继续保持暂停，执行器不在此处启动。</li></ol>
    {count(verification.symlink_count) !== undefined && <p className="maintenance-policy-note">快照含 {quantity(verification.symlink_count)} 条符号链接，恢复时需核对其目标是否适合新环境。</p>}
    <details className="maintenance-diagnostics"><summary>高级诊断：封存摘要与恢复预览回执</summary><JsonView value={value} /></details>
  </section>;
}
interface SaveFile { createWritable(): Promise<{ write(value: Uint8Array): Promise<void>; close(): Promise<void>; abort(): Promise<void> }> }
type Picker = (options: { suggestedName: string; types: { description: string; accept: Record<string, string[]> }[] }) => Promise<SaveFile>;

export function BackupsPanel({ projectId }: { projectId?: string }) {
  const catalog = useCursorApi<BackupJob[]>('/backups', 'backup_cursor');
  const readiness = useApi<Readiness>('/backup-readiness');
  const [selected, select] = useState('');
  const detail = useApi<BackupJob>(selected ? `/backups/${path(selected)}` : null);
  const [reviewing, review] = useState(false);
  const [reason, setReason] = useState('');
  const [acknowledged, acknowledge] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<Error>();
  const [message, setMessage] = useState('');
  const [showPreview, preview] = useState(false);
  const restore = useApi<Row>(selected && showPreview ? `/backups/${path(selected)}/restore-preview` : null);
  const command = useRef<{ fingerprint: string; key: string } | undefined>(undefined);
  const inFlight = useRef(false);
  const running = detail.data?.status === 'ACCEPTED' || detail.data?.status === 'RUNNING';
  useEffect(() => { if (!running) return; const timer = setInterval(() => { if (document.visibilityState === 'visible') detail.reload(); }, 2000); return () => clearInterval(timer); }, [running, detail.reload]);
  useEffect(() => { if (detail.data && !running) catalog.reload(); }, [selected, detail.data?.status, running, catalog.reload]);
  useEffect(() => { preview(false); setMessage(''); }, [selected]);
  async function create() {
    if (!readiness.data?.ready || !acknowledged || !reason.trim() || inFlight.current) return;
    const body = { reason: reason.trim(), pause_new_dispatch: true, expected_scope_sha256: readiness.data.scope_sha256 };
    const fingerprint = JSON.stringify(body);
    const key = command.current?.fingerprint === fingerprint ? command.current.key : crypto.randomUUID();
    command.current = { fingerprint, key };
    inFlight.current = true; setBusy(true); setError(undefined);
    try {
      const job = await api.post<BackupJob>('/backups', body, { idempotencyKey: key });
      select(job.backup_id); catalog.reload(); detail.reload(); review(false); acknowledge(false); command.current = undefined;
      setMessage('备份请求已登记。作业将按审阅范围暂停新增派发，实际结果以下方回执为准。');
    } catch (cause) { setError(errorOf(cause)); readiness.reload(); }
    finally { inFlight.current = false; setBusy(false); }
  }
  async function download() {
    const job = detail.data;
    if (!job?.download_available || job.status !== 'SUCCEEDED' || !job.archive_sha256 || job.archive_bytes === undefined || inFlight.current) return;
    inFlight.current = true; setBusy(true); setError(undefined); setMessage('');
    let output: Awaited<ReturnType<SaveFile['createWritable']>> | undefined;
    try {
      const filename = `forgeflow-backup-${job.backup_id.slice(0, 16)}.tar.gz`;
      const picker = (window as unknown as { showSaveFilePicker?: Picker }).showSaveFilePicker;
      if (picker) output = await (await picker({ suggestedName: filename, types: [{ description: 'ForgeFlow 备份', accept: { 'application/gzip': ['.gz'] } }] })).createWritable();
      else if (job.archive_bytes > 128 * 1024 * 1024) throw new Error('此浏览器不支持大文件流式保存。请在支持文件保存的 Chromium 浏览器下载该备份。');
      const response = await fetch(apiUrl(`/backups/${path(job.backup_id)}/archive`), { credentials: 'omit', headers: { Authorization: `Bearer ${getToken()}` } });
      if (!response.ok) throw new ApiError(response.status, await response.json().catch(() => ({ code: 'DOWNLOAD_FAILED', message: `下载失败 (${response.status})` })));
      if (response.headers.get('etag') !== `"${job.archive_sha256}"` || Number(response.headers.get('content-length')) !== job.archive_bytes) throw new Error('下载响应与封存的摘要或字节数不匹配。');
      if (output) {
        if (!response.body) throw new Error('浏览器没有提供下载数据流。');
        let received = 0; const reader = response.body.getReader();
        try { for (;;) { const chunk = await reader.read(); if (chunk.done) break; received += chunk.value.byteLength; if (received > job.archive_bytes) throw new Error('下载数据超出封存大小。'); await output.write(chunk.value); } }
        finally { reader.releaseLock(); }
        if (received !== job.archive_bytes) throw new Error('下载提前结束，文件没有完整保存。');
        await output.close(); output = undefined;
        setMessage(`备份已流式保存，服务端摘要已核对，接收 ${bytes(received)}。`);
      } else {
        const data = await response.arrayBuffer();
        const digest = Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256', data)), value => value.toString(16).padStart(2, '0')).join('');
        if (digest !== job.archive_sha256 || data.byteLength !== job.archive_bytes) throw new Error('实际下载摘要与封存备份不匹配，文件未交付。');
        const url = URL.createObjectURL(new Blob([data], { type: 'application/gzip' })); const link = document.createElement('a'); link.href = url; link.download = filename; link.click(); setTimeout(() => URL.revokeObjectURL(url), 1000);
        setMessage('备份下载已提交浏览器；实际字节数和 SHA256 已核对。');
      }
    } catch (cause) { if ((cause as { name?: string })?.name !== 'AbortError') setError(errorOf(cause)); }
    finally { if (output) await output.abort().catch(() => {}); inFlight.current = false; setBusy(false); }
  }
  const reload = () => { catalog.reload(); readiness.reload(); detail.reload(); restore.reload(); };
  return <Panel title="备份与 Release" className="maintenance-panel" actions={<button onClick={reload} disabled={busy}><RefreshCw size={14} />刷新检查与记录</button>}>
    <div className="panel-body">
      <div className="maintenance-scope-banner"><Layers3 size={21} /><div><strong>这份备份覆盖工作区的全部项目</strong><p>包含数据库、持久文件与受管 Git 仓库。当前项目选择和目录筛选都不会缩小备份范围；新增派发将在备份流程中暂停，结束后由负责人另行审阅。</p></div></div>
      <div className="toolbar"><button disabled={busy || running} onClick={() => { review(value => !value); readiness.reload(); }}><Archive size={15} />检查并创建备份</button><Link className="button" to={projectId ? `/projects/${path(projectId)}/releases` : '/portfolio'}><Download size={15} />{projectId ? '打开项目 Release' : '选择项目查看 Release'}</Link></div>
      {error && <ErrorNotice error={error} />}{message && <p role="status">{message}</p>}
      <QueryState loading={readiness.loading} error={readiness.error} onRetry={readiness.reload}>{readiness.data && <ReadinessExplanation data={readiness.data} />}</QueryState>
      {reviewing && <QueryState loading={readiness.loading} error={readiness.error} onRetry={readiness.reload}><section className="maintenance-review" aria-label="全部项目备份范围审阅"><h3>审阅全部 {readiness.data?.projects.length ?? '未知'} 个项目</h3>
        <p>其中 {readiness.data?.projects.filter(item => !item.paused).length ?? '未知'} 个项目将在流程中暂停新增派发。不会取消尝试、强制释放占用或启动执行器。</p>
        <ul className="maintenance-scope-projects">{readiness.data?.projects.map(item => <li key={item.project_id}><span>{item.name || '项目名称未提供'}</span><small>{item.paused ? '已暂停新增' : '将暂停新增'}</small></li>)}</ul>
        <Field label="备份原因"><input value={reason} onChange={event => setReason(event.target.value)} maxLength={2000} disabled={busy} placeholder="例如：更新前保留完整工作区" /></Field>
        <label className="maintenance-acknowledgement"><input type="checkbox" checked={acknowledged} onChange={event => acknowledge(event.target.checked)} disabled={busy} /><span>我已审阅全部项目范围，备份结束后继续保持暂停。</span></label>
        {!readiness.data?.ready && <p className="maintenance-policy-note">上方条件尚未满足，填写原因或勾选确认都不会允许跳过这些条件。</p>}
        <div className="toolbar"><button className="primary" disabled={busy || !readiness.data?.ready || !acknowledged || !reason.trim()} onClick={() => void create()}>确认范围并创建备份</button><button disabled={busy} onClick={() => review(false)}>收起审阅</button></div>
        <SourceStamp source={readiness.metadata.source} observedAt={readiness.metadata.observed_at} />
      </section></QueryState>}
      {!reviewing && <SourceStamp source={readiness.metadata.source} observedAt={readiness.metadata.observed_at} />}
    </div>
    <QueryState loading={catalog.loading} error={catalog.error} onRetry={catalog.reload}>
      {catalog.data?.length === 0 ? <EmptyState title="当前页没有备份记录" description="只有完成静止检查、数据库导出和完整归档校验后，备份才会提供下载。" /> : <div className="table-wrap maintenance-backup-table"><table><thead><tr><th>创建时间与原因</th><th>实际状态</th><th>归档大小</th><th>下一步</th></tr></thead><tbody>{(catalog.data ?? []).map(job => <tr key={job.backup_id}><td>{time(job.created_at)}<div className="muted">{job.reason}</div></td><td><StatusBadge state={job.status} scope="operation" /><div className="maintenance-table-caption">{phases[job.phase] ?? '阶段待核对'}</div></td><td>{bytes(job.archive_bytes)}</td><td><button onClick={() => select(job.backup_id)}>查看进度与文件</button></td></tr>)}</tbody></table></div>}
    </QueryState>
    <Pagination query={catalog} count={catalog.data?.length ?? 0} /><SourceStamp source={catalog.metadata.source} observedAt={catalog.metadata.observed_at} />
    {selected && <div className="panel-body maintenance-backup-detail"><QueryState loading={detail.loading && !detail.data} error={detail.error} onRetry={detail.reload}>{detail.data && <>
      <h3>备份进度与文件</h3><p className="maintenance-job-stage"><StatusBadge state={detail.data.status} scope="operation" /> {phases[detail.data.phase] ?? '阶段待核对'}</p>
      {detail.loading && <p className="maintenance-policy-note" role="status">正在读取最新状态，以下是最近一次回执。</p>}
      <p className="maintenance-detail-lead">{detail.data.status === 'FAILED' ? '这次备份没有完成封存流程，当前不提供下载。部分材料和失败记录仍然保留。' : detail.data.status === 'RECOVERY_REQUIRED' ? phaseDescriptions.INTERRUPTED : phaseDescriptions[detail.data.phase] ?? '该阶段尚未提供可解释的进度，请核对高级诊断。'}</p>
      {detail.data.error && <div className="maintenance-guidance"><h4>先核对失败原因，再重新检查备份范围</h4><p>高级诊断保留了原始失败回执。处理原因后刷新条件，原失败记录不会被覆盖。</p><button onClick={() => { readiness.reload(); review(true); }}>重新检查全部项目范围</button></div>}
      {detail.data.archive_warning && <p className="maintenance-policy-note" role="alert">原归档文件当前不可用或与封存记录不一致，暂时不能下载；原回执仍保留。</p>}
      <dl className="maintenance-record"><div><dt>归档大小</dt><dd>{bytes(detail.data.archive_bytes)}</dd></div><div><dt>最近回执</dt><dd>{time(detail.data.updated_at)}</dd></div></dl>
      <div className="toolbar"><button disabled={busy || !detail.data.download_available || detail.data.status !== 'SUCCEEDED'} onClick={() => void download()}><Download size={15} />下载实际备份</button><button disabled={busy || !detail.data.download_available} onClick={() => preview(value => !value)}><ShieldCheck size={15} />只读恢复预览</button></div>
      <details className="maintenance-diagnostics"><summary>文件详情：实际字节与完整 SHA256 摘要</summary><dl className="maintenance-record"><div><dt>备份身份</dt><dd><code>{detail.data.backup_id}</code></dd></div><div><dt>实际字节</dt><dd>{count(detail.data.archive_bytes) === undefined ? '未知' : `${quantity(detail.data.archive_bytes)} B`}</dd></div><div><dt>SHA256</dt><dd><code>{detail.data.archive_sha256 ?? '尚未封存'}</code></dd></div></dl></details>
      {(detail.data.progress || detail.data.error || detail.data.archive_warning) && <details className="maintenance-diagnostics"><summary>高级诊断：备份阶段与原始失败回执</summary><JsonView value={{ phase: detail.data.phase, progress: detail.data.progress, error: detail.data.error, archive_warning: detail.data.archive_warning }} /></details>}
      <SourceStamp source={detail.metadata.source} observedAt={detail.metadata.observed_at} />
      {showPreview && <QueryState loading={restore.loading} error={restore.error} onRetry={restore.reload}>{restore.data && <RestoreFacts value={restore.data} />}</QueryState>}
    </>}</QueryState></div>}
  </Panel>;
}
