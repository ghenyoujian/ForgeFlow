import { useState } from 'react';
import { Link } from 'react-router-dom';
import { Layers3, Gauge, ArrowRight, Check, Info } from 'lucide-react';
import { useApi,isPersonalAccount } from '../../app/api';
import { ErrorNotice, Field, Panel, SourceStamp } from '../../components';
import { pathId, useCommand, type ResourceVector } from '../flow/types';
import type { PlanningOverviewData } from '../portfolio/PlanningOverview';
type Policy = { scope_id: string; project_id: string | null; parent_scope_id: string | null; team_id: string | null; worker_id: string | null; limits: ResourceVector; paused: boolean; revision: number };
const tiers = [[1, '专注'], [4, '小组'], [10, '并行'], [32, '标准'], [64, '高并发']] as const;
const gib = (value?: number) => value == null ? '未知' : `${(value / 1073741824).toFixed(2)} GiB`;
export function AgentCapacity({ projectId }: { projectId: string }) {
  const root = `/projects/${pathId(projectId)}`;
  const query = useApi<PlanningOverviewData>(`${root}/planning-overview`);
  const machine = useApi<{ host_memory?: { total_bytes?: number; available_bytes?: number; source: string; observed_at: string }; workers: { worker_id: string; heartbeat_at: string; reported_active_attempts: number }[] }>('/resource-usage');
  const policiesQ = useApi<Policy[]>(`${root}/resources`);
  const [expanded, setExpanded] = useState(() => !matchMedia('(max-width: 768px)').matches);
  const [scope, setScope] = useState(''); const [tierChoice, setTier] = useState<number>();
  const [review, setReview] = useState<{ policy: Policy; tier: number }>();
  const [receipt, setReceipt] = useState('');
  const command = useCommand(); const data = query.data;
  const policies = policiesQ.data?.filter(policy => policy.project_id === projectId && !policy.worker_id) ?? [];
  const policy = policies.find(policy => policy.scope_id === scope) ?? policies.find(policy => !policy.team_id);
  const tier = tierChoice ?? policy?.limits.active_slot ?? 32;
  const usage = data?.policies.find(candidate => candidate.scope_id === policy?.scope_id)?.usage;
  const stale = !review || JSON.stringify(review.policy) !== JSON.stringify(policy) || review.tier !== tier;
  const writable = !isPersonalAccount() && data?.project.authority_mode === 'MANAGED' && !data.project.archived;
  async function save() {
    if (!review || stale) return;
    const saved = await command.run(`${root}/resources`, { policy: { ...review.policy, limits: { ...review.policy.limits, active_slot: review.tier } }, expected_revision: review.policy.revision });
    if (saved) { setReceipt(`服务端已确认 ${review.tier} 档容量。`); setReview(undefined); policiesQ.reload(); query.reload(); }
  }
  return <Panel className="agent-capacity-panel" title={<><Layers3 size={16} />岗位、上下文与活动容量</>}>
    {[query.error, policiesQ.error, machine.error, command.error].map((error, index) => error && <ErrorNotice key={index} error={error} />)}
    {!data ? <p role="status">正在读取团队容量…</p> : <>
      <div className="capacity-metrics"><article><span>持久独立上下文</span><strong>{data.capacity.persistent_contexts}</strong><small>设计容量至少 128</small></article><article><span>活动尝试</span><strong>{data.capacity.active_attempts}</strong><small>停止待确认仍占用资源</small></article><article><span>Native 会话登记观测</span><strong>{data.capacity.observed_native_sessions}</strong><small>包含历史会话，单独计量</small></article></div>
      <details className="capacity-adjustment" open={expanded} onToggle={event => setExpanded(event.currentTarget.open)}><summary><span>调整活动容量</span><small>{policy ? `当前 ${policy.limits.active_slot} 档` : '读取中…'}</small></summary><div className="capacity-controls"><div className="capacity-scope"><Field label="调整资源范围"><select value={policy?.scope_id ?? ''} onChange={event => { setScope(event.target.value); setTier(undefined); setReview(undefined); setReceipt(''); }}>{!policies.length && <option value="">尚未登记资源范围</option>}{policies.map(policy => <option key={policy.scope_id} value={policy.scope_id}>{policy.team_id ?? '整个项目'} · 当前 {policy.limits.active_slot} 档</option>)}</select></Field><p className="muted">{policy ? `当前上限 ${policy.limits.active_slot} · 已占 ${usage?.active_slot ?? '未知'}` : '正在读取可调整范围'}</p></div>
        <div className="capacity-tier-picker"><span>选择活动容量</span><div className="capacity-tiers" aria-label="活动容量档位">{tiers.map(([value, label]) => <button key={value} aria-label={`${value}`} aria-pressed={tier === value} disabled={command.busy} onClick={() => { setTier(value); setReview(undefined); setReceipt(''); }}><strong>{value}</strong><small>{label}</small>{tier === value && <Check size={12} />}</button>)}</div><p className="muted">32 为默认档位；空闲上下文继续保留。</p></div>
      </div>
      <div className="capacity-machine-summary"><Gauge size={15} /><span>主机可用内存 <strong>{gib(machine.data?.host_memory?.available_bytes)}</strong> · Worker 心跳登记 {machine.data ? machine.data.workers.length : '读取中'} 个</span><a href="#capacity-resource-details" onClick={event => { const detail = document.getElementById('capacity-resource-details'); if (detail instanceof HTMLDetailsElement) { event.preventDefault(); detail.open = !detail.open; } }}>资源详情</a></div>
      {review && <div className="capacity-review" role="status"><div><strong>容量影响预览：{review.policy.limits.active_slot}<ArrowRight size={15} />{review.tier}</strong><p>{review.tier < review.policy.limits.active_slot ? `降低新增准入预算，已有尝试继续按原流程完成或停止。${(usage?.active_slot ?? 0) > tier ? '当前占用高于新档位，释放确认后才恢复新增。' : ''}` : '调整所选范围预算，实际准入继续核验内存、Worker 与供应商约束。'}</p></div>{stale && <p role="alert">资源设置已有变化，请重新预览。</p>}</div>}
      <div className="capacity-submit"><span><Info size={14} />调整容量不会启动模型</span>{review && !stale ? <button className="primary" aria-busy={command.busy} disabled={!writable || command.busy} onClick={() => void save()}><Check size={14} />{command.busy ? '正在保存…' : '确认容量设置'}</button> : <button className="primary" disabled={!policy || tier === policy.limits.active_slot || !writable || command.busy || query.loading || policiesQ.loading} onClick={() => policy && setReview({ policy: structuredClone(policy), tier })}>预览切档影响<ArrowRight size={14} /></button>}</div>
      {receipt && <p className="inline-success" role="status"><Check size={15} />{receipt}</p>}
      <details id="capacity-resource-details" className="capacity-resource-details"><summary>实际资源与准入限制</summary><p>主机总内存 {gib(machine.data?.host_memory?.total_bytes)} · 可用 {gib(machine.data?.host_memory?.available_bytes)} · {machine.data?.host_memory?.source ?? '尚未取得观测'}</p><p className="muted">{machine.data?.workers.length ? machine.data.workers.map(worker => `${worker.worker_id}（${worker.heartbeat_at}）`).join(' · ') : '当前没有 Worker 心跳可以支持实际执行资格。'}供应商外部配额与 Worker 执行资格仍由真实准入检查确认。</p><div className="table-wrap"><table><thead><tr><th>约束范围</th><th>活动已占 / 上限</th><th>内存已占 / 上限</th><th>模型请求已占 / 上限</th></tr></thead><tbody>{data.policies.map(candidate => <tr key={candidate.scope_id}><td>{candidate.worker_id ? `Worker ${candidate.worker_id}` : candidate.team_id ?? candidate.scope_id}{candidate.paused && ' · 暂停新增'}</td><td>{candidate.usage.active_slot ?? '未知'} / {candidate.limits.active_slot}</td><td>{gib(candidate.usage.memory_bytes)} / {gib(candidate.limits.memory_bytes)}</td><td>{candidate.usage.provider_inflight ?? '未知'} / {candidate.limits.provider_inflight}</td></tr>)}</tbody></table></div><p className="muted">祖先范围及资源账本约束继续生效；不会静默减少计划预算或提前释放占用。</p><Link className="inspector-text-link" to="/resources">查看全部机器与资源观测<ArrowRight size={13} /></Link><SourceStamp source={query.metadata.source} observedAt={query.metadata.observed_at} /></details></details>
    </>}
  </Panel>;
}
