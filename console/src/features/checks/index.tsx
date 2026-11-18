import { useState } from 'react';
import { Download, Filter, RefreshCw, ShieldCheck } from 'lucide-react';
import { api, items, useApi, useCursorApi } from '../../app/api';
import type { PageProps } from '../../app/types';
import { DataTable, Drawer, EmptyState, ErrorNotice, JsonView, PageHeader, Panel, QueryState, SourceStamp, StatusBadge, Pagination } from '../../components';
import { flowPath, pathId, useCommand, useCompleteApi, type CheckReport, type Finding, type FlowRevision } from '../flow/types';

export function ChecksPage({ projectId }: PageProps) {
  const projects = useCompleteApi<{ project_id: string; name: string; authority_mode: string }>('/projects');
  const [scope, setScope] = useState(projectId ?? new URLSearchParams(window.location.search).get('project') ?? '');
  const effectiveProject = projectId ?? scope;
  const reports = useCursorApi<(CheckReport & { revision?: number })[]>(effectiveProject ? `/projects/${pathId(effectiveProject)}/findings` : null, 'finding_cursor');
  const latestQuery = useApi<FlowRevision | null>(effectiveProject ? `/projects/${pathId(effectiveProject)}/flows/latest` : null);
  const [severity, setSeverity] = useState('');
  const [rule, setRule] = useState('');
  const [selected, setSelected] = useState<Finding>();
  const command = useCommand();
  const latest = latestQuery.data ?? undefined;
  const allFindings = items(reports.data).flatMap(report => (report.findings ?? []).map(finding => ({ ...finding, stale: !!latest && report.input_digest !== latest.input_digest, report_input_digest: report.input_digest })));
  const findings = allFindings.filter(finding => (!severity || finding.severity === severity) && (!rule || `${finding.rule_id} ${finding.subject_ref} ${finding.suggested_action}`.toLowerCase().includes(rule.toLowerCase())));
  async function rerun() { if (!latest) return; const result = await command.run<CheckReport>(`${flowPath(latest)}/checks`, {}); if (result) reports.reload(); }
  function exportFindings() {
    const blob = new Blob([JSON.stringify({ project_id: effectiveProject, observed_at: reports.metadata.observed_at, source: reports.metadata.source, filters: { severity, rule }, reports: reports.data }, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob); const link = document.createElement('a'); link.href = url; link.download = `forgeflow-checks-${effectiveProject}.json`; link.click(); URL.revokeObjectURL(url);
  }
  return <><PageHeader title="检查中心" description="沿规则、输入版本和受影响任务定位根因，保留失败与过期报告。" actions={<><button disabled={!reports.data} onClick={exportFindings}><Download size={16} />导出报告</button><button className="primary" disabled={!latest || command.busy || items(projects.data).find(project => project.project_id === effectiveProject)?.authority_mode !== 'MANAGED'} onClick={rerun}><RefreshCw size={16} />{command.busy ? '正在重新检查…' : `重查${latest ? ` R${latest.flow_revision}` : ''}`}</button></>} />
    <div className="toolbar"><Filter size={16} /><select aria-label="项目检查范围" value={effectiveProject} disabled={!!projectId} onChange={event => { setScope(event.target.value); setSelected(undefined); const search = new URLSearchParams(window.location.search); search.set('project', event.target.value); window.history.replaceState(null, '', `${window.location.pathname}?${search}`); }}><option value="">选择项目</option>{items(projects.data).map(project => <option value={project.project_id} key={project.project_id}>{project.name}</option>)}</select><select aria-label="问题严重度" value={severity} onChange={event => setSeverity(event.target.value)}><option value="">全部严重度</option><option value="BLOCKING">阻断</option><option value="WARNING">警告</option><option value="INFO">信息</option></select><input aria-label="查找规则与对象" placeholder="规则、对象、修复动作" value={rule} onChange={event => setRule(event.target.value)} /><span className="muted">本页报告 {findings.length} / {allFindings.length} 个问题</span></div>
    <SourceStamp source={reports.metadata.source} observedAt={reports.metadata.observed_at} />{command.error && <ErrorNotice error={command.error} />}{projects.error && <ErrorNotice error={projects.error} onRetry={projects.reload} />}
    {!effectiveProject ? <EmptyState title="选择项目查看真实检查" description="每份报告绑定规划输入，不以全局空列表宣告项目通过。" /> : <QueryState loading={reports.loading && !reports.data} error={reports.error} onRetry={reports.reload}><Panel title={<span><ShieldCheck size={16} />依赖与合同检查</span>}><DataTable rows={findings} rowKey={finding => `${finding.finding_id}:${finding.source_revision}`} onRowClick={setSelected} columns={[{ key: 'severity', label: '严重度', render: finding => <StatusBadge state={finding.severity} /> }, { key: 'rule_id', label: '规则' }, { key: 'subject_ref', label: '对象', render: finding => String(finding.subject_ref ?? '未提供') }, { key: 'blocked_tasks', label: '受影响卡', numeric: true, render: finding => finding.blocked_tasks?.length ?? 0 }, { key: 'suggested_action', label: '修复建议' }, { key: 'stale', label: '输入有效性', render: finding => finding.stale ? <StatusBadge state="报告已过期" /> : <span>当前记录</span> }]} empty={<EmptyState title={items(reports.data).length ? allFindings.length ? '本页筛选没有匹配问题' : '本页报告未记录问题' : '当前页没有检查报告'} description={items(reports.data).length ? '结构检查结果不代表产品 Gate 已通过。' : '在 Flow 工作台建立版本，然后运行完整检查。'} />} /><Pagination query={reports} count={items(reports.data).length} /></Panel></QueryState>}
    {selected && <Drawer title={`${selected.rule_id} · ${selected.severity}`} onClose={() => setSelected(undefined)}><StatusBadge state={selected.severity} /><dl className="detail-grid"><dt>问题身份</dt><dd>{selected.finding_id}</dd><dt>对象</dt><dd>{String(selected.subject_ref ?? '')}</dd><dt>输入版本</dt><dd>{selected.source_revision ?? '未提供'}</dd><dt>观察时间</dt><dd>{selected.observed_at ?? '未提供'}</dd><dt>修复动作</dt><dd>{selected.suggested_action ?? '服务端未提供'}</dd></dl><h3>受影响任务</h3><div className="selection-list">{selected.blocked_tasks?.map(task => <a key={task} href={`/projects/${pathId(effectiveProject)}/tasks/${pathId(task)}`}>{task}</a>)}</div><h3>原始证据引用</h3><JsonView value={selected.evidence_refs ?? []} /><a className="button" href={`/projects/${pathId(effectiveProject)}/flows`}>定位到 Flow 修复</a><details><summary>完整问题记录</summary><JsonView value={selected} /></details></Drawer>}
  </>;
}
