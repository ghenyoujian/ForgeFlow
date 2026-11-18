import { useEffect, useRef, useState, type FormEvent } from 'react';
import { useNavigate } from 'react-router-dom';
import { ArrowUpRight, FileText, Plus, RefreshCw, Sparkles, Upload } from 'lucide-react';
import { ApiError, apiUrl, getToken, items, useApi, useCursorApi } from '../../app/api';
import type { PageProps } from '../../app/types';
import { DataTable, Drawer, EmptyState, ErrorNotice, Field, JsonView, PageHeader, Panel, QueryState, SourceStamp, StatusBadge, Pagination } from '../../components';
import { flowPath, lines, pathId, useCommand, useCompleteApi, type CompileContext, type FlowRevision, type Requirement } from '../flow/types';

type Source = { source_id?: string; id?: string; name?: string; format?: string; content?: string; raw_sha256?: string; source_document?: string; revision?: number; [key: string]: unknown };
type ArtifactRef = { artifact_id: string; sha256: string };
type PlanningEvidence = { receipt_id: string; project_id: string; attempt_id: string; generation: number; kind: string; total: number; failed: number; skipped: number; artifact?: ArtifactRef; [key: string]: unknown };
type PlanningLogPage = { attempt_id: string; offset: number; bytes: number; next_offset: number; text: string };
type Operation = { operation_id: string; project_id?: string; kind?: string; revision?: number; state?: string; status?: string; result?: { flow?: FlowRevision; planning_attempt_id?: string; generation_method?: string; validation?: unknown }; error?: unknown; execution?: { project_id?: string; task_id?: string; attempt_id?: string; generation?: number; phase?: string; source?: string }; [key: string]: unknown };
function record(value: unknown): Record<string, unknown> { return value && typeof value === 'object' && !Array.isArray(value) ? value as Record<string, unknown> : {}; }
function artifactRef(value: unknown): ArtifactRef | undefined {
  const ref = record(value);
  return typeof ref.artifact_id === 'string' && ref.artifact_id.length > 0 && typeof ref.sha256 === 'string' && /^[a-f0-9]{64}$/i.test(ref.sha256) ? { artifact_id: ref.artifact_id, sha256: ref.sha256 } : undefined;
}
function PlanningArtifact({ artifact, projectId }: { artifact: ArtifactRef; projectId: string }) {
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState<string>();
  const [error, setError] = useState<Error>();
  const controller = useRef<AbortController | null>(null);
  useEffect(() => () => controller.current?.abort(), []);
  async function download() {
    const request = new AbortController(); controller.current = request;
    setBusy(true); setError(undefined); setMessage(undefined);
    try {
      const token = getToken();
      const response = await fetch(apiUrl(`/artifacts/${pathId(artifact.artifact_id)}/content?project_id=${pathId(projectId)}`), { credentials: 'omit', headers: token ? { Authorization: `Bearer ${token}` } : {}, signal: request.signal });
      if (!response.ok) {
        const body = await response.json().catch(() => ({}));
        throw new ApiError(response.status, { message: `原始产物读取失败 (${response.status})`, ...record(body) });
      }
      const bytes = await response.arrayBuffer();
      const digest = Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256', bytes))).map(value => value.toString(16).padStart(2, '0')).join('');
      if (digest !== artifact.sha256.toLowerCase()) throw new Error('产物 SHA-256 与服务端引用不一致，已拒绝下载。');
      if (request.signal.aborted) return;
      const url = URL.createObjectURL(new Blob([bytes], { type: 'application/octet-stream' }));
      const link = document.createElement('a'); link.href = url; link.download = artifact.artifact_id; link.click(); URL.revokeObjectURL(url);
      setMessage(`已核对 SHA-256 并下载 ${bytes.byteLength} 字节。`);
    } catch (cause) { if (!request.signal.aborted) setError(cause instanceof Error ? cause : new Error(String(cause))); }
    finally { if (!request.signal.aborted) setBusy(false); }
  }
  return <><dl className="detail-grid"><dt>产物身份</dt><dd><code>{artifact.artifact_id}</code></dd><dt>SHA-256</dt><dd><code>{artifact.sha256}</code></dd></dl><button type="button" disabled={busy} onClick={() => void download()}>{busy ? '正在读取并核对…' : '下载原始产物'}</button>{error && <ErrorNotice error={error} />}{message && <p role="status">{message}</p>}</>;
}
function PlanningEvidenceDrawer({ projectId, attemptId, generation, onClose }: { projectId: string; attemptId: string; generation?: number; onClose: () => void }) {
  const evidence = useCompleteApi<PlanningEvidence>(`/projects/${pathId(projectId)}/evidence`);
  const receipts = evidence.data?.filter(receipt => receipt.project_id === projectId && receipt.attempt_id === attemptId && (generation === undefined || receipt.generation === generation));
  const [readLogs, setReadLogs] = useState(false);
  const [offsets, setOffsets] = useState([0]);
  const [segment, setSegment] = useState(0);
  const offset = offsets[segment];
  const logs = useApi<PlanningLogPage>(readLogs ? `/attempts/${pathId(attemptId)}/logs?offset=${offset}&limit_bytes=65536` : null);
  const page = logs.data;
  const validLogPage = page && page.attempt_id === attemptId && page.offset === offset && Number.isSafeInteger(page.bytes) && page.bytes >= 0 && page.bytes <= 65536 && page.next_offset === offset + page.bytes && typeof page.text === 'string';
  function nextSegment() {
    if (!validLogPage || !page) return;
    setOffsets(values => [...values.slice(0, segment + 1), page.next_offset]); setSegment(value => value + 1);
  }
  return <Drawer title="规划日志与验证证据" onClose={onClose}><p className="muted">按本次尝试身份读取服务端记录；下载产物时核对引用的 SHA-256。</p><dl className="detail-grid"><dt>尝试</dt><dd><code>{attemptId}</code></dd>{generation !== undefined && <><dt>Generation</dt><dd>{generation}</dd></>}</dl>
    <h3>原始尝试日志</h3><button type="button" disabled={logs.loading} onClick={() => readLogs ? logs.reload() : setReadLogs(true)}>{logs.loading ? '正在读取日志…' : readLogs ? '重新读取本段日志' : '读取规划日志'}</button>
    {readLogs && <QueryState loading={logs.loading && !page} error={logs.error} onRetry={logs.reload}>{page && !validLogPage ? <p role="alert" className="notice">日志身份或字节偏移不匹配，未显示该响应。</p> : validLogPage && page ? <><p className="muted">本段 {page.bytes} 字节 · 服务端偏移 {page.offset}–{page.next_offset}</p><pre className="log-panel" tabIndex={0} aria-label="当前范围的原始规划日志">{page.text || '当前范围没有日志字节。'}</pre><div className="toolbar"><button type="button" disabled={logs.loading || segment === 0} onClick={() => setSegment(value => value - 1)}>上一段</button><button type="button" disabled={logs.loading || page.bytes < 65536} onClick={nextSegment}>下一段</button></div></> : <p className="muted">服务端未返回日志内容。</p>}</QueryState>}
    <h3>本次尝试的验证收据</h3><QueryState loading={evidence.loading && !evidence.data} error={evidence.error} onRetry={evidence.reload}>{receipts?.length ? receipts.map(receipt => <details key={receipt.receipt_id}><summary tabIndex={0}>{receipt.kind} · {receipt.receipt_id}</summary><dl className="detail-grid"><dt>输入</dt><dd>{receipt.total}</dd><dt>失败 / 跳过</dt><dd>{receipt.failed} / {receipt.skipped}</dd></dl>{artifactRef(receipt.artifact) ? <PlanningArtifact artifact={artifactRef(receipt.artifact)!} projectId={projectId} /> : <p className="muted">此收据未提供完整的原始产物引用。</p>}<details><summary tabIndex={0}>原始验证收据</summary><JsonView value={receipt} /></details></details>) : evidence.data ? <p className="muted">服务端完整收据集合中没有与本次尝试匹配的已登记验证收据。</p> : <p className="muted">验证收据尚未读取。</p>}</QueryState><SourceStamp source={evidence.metadata.source} observedAt={evidence.metadata.observed_at} />
  </Drawer>;
}
function PlanningOperationPanel({ operationId, projectId, data, loading, error, reload, observedAt }: { operationId: string; projectId: string; data?: Operation; loading: boolean; error?: Error; reload: () => void; observedAt?: string }) {
  const [evidenceOpen, setEvidenceOpen] = useState(false);
  const identityMatches = !!data && data.operation_id === operationId && data.project_id === projectId && data.kind === 'DSH_FLOW_GENERATION';
  const state = identityMatches ? data.state ?? data.status : undefined;
  const failure = record(data?.error);
  const execution = identityMatches && data.execution?.project_id === projectId ? data.execution : undefined;
  const failureDetails = record(failure.details);
  const primaryFailure = record(failureDetails.primary);
  const rawOutput = identityMatches ? artifactRef(primaryFailure.output_artifact) ?? artifactRef(failureDetails.output_artifact) ?? artifactRef(record(data?.result).planning_output) : undefined;
  const failureCode = typeof failure.code === 'string' ? failure.code : undefined;
  const failureMessage = typeof failure.message === 'string' ? failure.message : typeof data?.error === 'string' ? data.error : '服务端未提供失败原因。';
  return <Panel title={<span>规划操作 <span aria-live="polite" aria-atomic="true"><StatusBadge state={state === 'SUCCEEDED' ? '草案已生成' : state === 'ACCEPTED' ? '规划请求已接收' : state ?? (loading ? '正在读取' : '状态未提供')} /></span></span>} actions={<button type="button" disabled={loading} onClick={reload}><RefreshCw size={14} aria-hidden="true" />{loading ? '正在读取…' : '读取状态'}</button>}>
    <div className="panel-body">{error && data && <ErrorNotice error={error} onRetry={reload} />}<QueryState loading={loading && !data} error={data ? undefined : error} onRetry={reload}>{!data ? <p className="muted">服务端未返回此规划操作。</p> : !identityMatches ? <p role="alert" className="notice">{data.project_id && data.project_id !== projectId ? '规划操作属于其他项目，请使用该项目的历史入口。' : '服务端未提供匹配的规划操作身份，证据入口暂不可用。'}</p> : <>
      {state === 'FAILED' && <div className="notice" role="alert" aria-label="规划失败原因"><strong className="break-word">{failureCode ?? '失败原因未提供'}</strong><p className="break-word">{failureMessage}</p><p>{failureCode === 'MODEL_DRAFT_INVALID' ? '模型输出未通过草案合同校验。服务端未返回可审阅的生成草案。' : '规划操作未完成。请按此操作的实际记录核对原因。'}</p>{typeof failure.remediation === 'string' && <p className="break-word">{failure.remediation}</p>}</div>}
      <dl className="detail-grid"><dt>操作</dt><dd><code>{operationId}</code></dd><dt>项目</dt><dd><code>{projectId}</code></dd>{data.revision !== undefined && <><dt>操作版本</dt><dd>{data.revision}</dd></>}{execution?.task_id && <><dt>规划任务</dt><dd><code>{execution.task_id}</code></dd></>}{execution?.attempt_id && <><dt>尝试</dt><dd><code>{execution.attempt_id}</code></dd></>}{execution?.generation !== undefined && <><dt>Generation</dt><dd>{execution.generation}</dd></>}{execution?.phase && <><dt>尝试状态</dt><dd><StatusBadge state={execution.phase} /></dd></>}</dl>
      {rawOutput ? <details><summary tabIndex={0}>原始规划产物</summary><PlanningArtifact artifact={rawOutput} projectId={projectId} /></details> : state === 'FAILED' && <p className="muted">此操作响应未提供原始模型输出的产物引用。日志与验证收据按实际尝试身份读取。</p>}
      {execution?.attempt_id ? <div className="toolbar"><a href={`/runs/${pathId(execution.attempt_id)}?project=${pathId(projectId)}`}>查看规划尝试 <ArrowUpRight size={14} aria-hidden="true" /></a><button type="button" onClick={() => setEvidenceOpen(true)}>读取日志与验证证据</button></div> : <p className="muted">服务端尚未提供规划尝试身份。</p>}
      {state === 'SUCCEEDED' && data.result?.flow && <a className="button" href={`/projects/${pathId(projectId)}/flows/${data.result.flow.flow_revision}`}>审阅生成的 R{data.result.flow.flow_revision}</a>}
      <SourceStamp source={execution?.source} observedAt={observedAt} />
    </>}</QueryState></div>
    {evidenceOpen && identityMatches && execution?.attempt_id && <PlanningEvidenceDrawer key={execution.attempt_id} projectId={projectId} attemptId={execution.attempt_id} generation={execution.generation} onClose={() => setEvidenceOpen(false)} />}
  </Panel>;
}
export function RequirementsPage(props: PageProps) { return <RequirementsWorkspace key={props.projectId} {...props} />; }
function RequirementsWorkspace({ projectId }: PageProps) {
  const navigate = useNavigate();
  const requirements = useCursorApi<Requirement[]>(projectId ? `/projects/${pathId(projectId)}/requirements` : null, 'requirement_cursor');
  const sourcesQuery = useCursorApi<Source[]>(projectId ? `/projects/${pathId(projectId)}/sources` : null, 'source_cursor');
  const latestQuery = useApi<FlowRevision | null>(projectId ? `/projects/${pathId(projectId)}/flows/latest` : null);
  const latest = latestQuery.data ?? undefined;
  const fullContext = useApi<CompileContext>(latest ? `${flowPath(latest)}/context/current` : null);
  const project = useApi<{ authority_mode: string; archived: boolean }>(projectId ? `/projects/${pathId(projectId)}` : null);
  const [sourceId, setSourceId] = useState<string>();
  const [sourceLinePage, setSourceLinePage] = useState(0);
  const [selected, setSelected] = useState<Requirement>();
  const requestedRequirement = new URLSearchParams(window.location.search).get('requirement');
  useEffect(() => {
    if (!requestedRequirement) return;
    const loaded = requirements.data?.find(r => r.requirement_id === requestedRequirement);
    if (loaded) { setSelected(loaded); setSourceId(loaded.source_anchor.split('#')[0]); }
    else { const record = fullContext.data?.requirements.find(r => r.requirement_id === requestedRequirement); if (record) setSourceId(record.source_document); }
  }, [requestedRequirement, requirements.data, fullContext.data]);
  const [importing, setImporting] = useState(false);
  const [creating, setCreating] = useState(false);
  const [generating, setGenerating] = useState(false);
  const [generationOwner, setGenerationOwner] = useState('');
  const [generationTeam, setGenerationTeam] = useState('');
  const [generationExecutor, setGenerationExecutor] = useState('');
  const [generationVerifier, setGenerationVerifier] = useState('');
  const [generationResource, setGenerationResource] = useState('');
  const [generationRequestLimit, setGenerationRequestLimit] = useState('8');
  const [preparationError, setPreparationError] = useState<Error>();
  const [editingRequirement, setEditingRequirement] = useState<Requirement>();
  const [name, setName] = useState('');
  const [format, setFormat] = useState('MARKDOWN');
  const [content, setContent] = useState('');
  const [instruction, setInstruction] = useState('');
  const [fileError, setFileError] = useState<Error>();
  const [operationId, setOperationId] = useState<string | undefined>(new URLSearchParams(window.location.search).get('operation') ?? undefined);
  const discoveryRoot = generating && projectId ? `/projects/${pathId(projectId)}` : null;
  const allSources = useCompleteApi<Source>(discoveryRoot ? `${discoveryRoot}/sources` : null);
  const owners = useCompleteApi<{ owner_id: string }>(discoveryRoot ? `${discoveryRoot}/owners` : null);
  const teams = useCompleteApi<{ team_id: string; name: string }>(discoveryRoot ? `${discoveryRoot}/teams` : null);
  const executors = useCompleteApi<{ id: string; protocol?: string }>(discoveryRoot ? `${discoveryRoot}/documents/executor_profiles` : null);
  const verifiers = useCompleteApi<{ plan_id: string }>(discoveryRoot ? `${discoveryRoot}/documents/verification_plans` : null);
  const resources = useCompleteApi<{ id: string }>(discoveryRoot ? `${discoveryRoot}/documents/resource_profiles` : null);
  const command = useCommand();
  const operation = useApi<Operation>(operationId ? `/operations/${pathId(operationId)}` : null);
  const operationState = operation.data?.state ?? operation.data?.status;
  useEffect(() => {
    if (!operationId || (operation.data?.project_id && operation.data.project_id !== projectId) || ['SUCCEEDED', 'FAILED', 'CANCELLED', 'BLOCKED', 'COMPLETED'].includes(operationState ?? '')) return;
    const timer = window.setInterval(operation.reload, 2500); return () => window.clearInterval(timer);
  }, [operationId, operationState, operation.reload, operation.data?.project_id, projectId]);
  useEffect(() => { setSourceId(undefined); setSelected(undefined); setGenerating(false); setOperationId(new URLSearchParams(window.location.search).get('operation') ?? undefined); }, [projectId]);
  const sources = items(sourcesQuery.data);
  useEffect(() => { if (!sourceId && sources.length) setSourceId(sources[0].source_id ?? sources[0].id ?? sources[0].source_document); }, [sourceId, sourcesQuery.data]);
  const sourceDetail = useApi<Source>(sourceId && projectId ? `/projects/${pathId(projectId)}/sources/${pathId(sourceId)}` : null);
  const source = sourceDetail.data ?? sources.find(item => (item.source_id ?? item.id ?? item.source_document) === sourceId) ?? (!sourceId ? sources[0] : undefined);
  const sourceIdentity = source?.source_id ?? source?.id ?? source?.source_document;
  const sourceLines = source?.content?.split(/\r?\n/) ?? [];
  useEffect(() => { const line = selected?.source_anchor.startsWith(`${sourceIdentity}#`) ? selected.source_anchor.match(/:L(\d+)$/)?.[1] : undefined; setSourceLinePage(line ? Math.floor((Number(line) - 1) / 200) : 0); }, [sourceIdentity, selected?.source_anchor]);
  const reqs = items(requirements.data);
  const covered = (id: string) => latest?.tasks.filter(task => task.requirement_ids.includes(id)) ?? [];
  const uncovered = reqs.filter(requirement => !requirement.deferred_reason && covered(requirement.requirement_id).length === 0);
  const globalGaps = fullContext.data?.requirements.filter(requirement => !requirement.deferred_reason && covered(requirement.requirement_id).length === 0);
  const noFlow = latestQuery.error instanceof ApiError && latestQuery.error.code === 'FLOW_NOT_FOUND';
  const writable = project.data?.authority_mode === 'MANAGED' && !project.data.archived;
  function selectRequirement(requirement: Requirement) { setSelected(requirement); const source = requirement.source_anchor.split('#'); if (source.length > 1) setSourceId(source[0]); }
  async function readFile(file?: File) {
    if (!file) return;
    setFileError(undefined);
    if (file.size > 4 * 1024 * 1024) { setFileError(new Error('单次文件上限为 4 MiB。请拆分为多个明确来源，必要内容不会被截断。')); return; }
    if (!/\.(md|markdown|txt|json)$/i.test(file.name)) { setFileError(new Error('当前支持 Markdown、纯文本和 JSON。')); return; }
    try { setName(file.name); setFormat(/\.json$/i.test(file.name) ? 'JSON' : 'MARKDOWN'); setContent(await file.text()); }
    catch (cause) { setFileError(cause instanceof Error ? cause : new Error(String(cause))); }
  }
  async function importSource(event: FormEvent) {
    event.preventDefault(); if (!projectId) return;
    const result = await command.run(`/projects/${pathId(projectId)}/source-imports`, { name, format, content });
    if (result) { requirements.reload(); sourcesQuery.reload(); fullContext.reload(); latestQuery.reload(); setImporting(false); }
  }
  async function generate(event: FormEvent) {
    event.preventDefault();
    if (!projectId || !allSources.data) return;
    const sourceIds = allSources.data.map(source => source.source_id ?? source.id ?? source.source_document).filter((id): id is string => !!id);
    if (sourceIds.length !== allSources.data.length || !sourceIds.length) { setPreparationError(new Error('来源身份不完整；重新读取真实来源后才能生成。')); return; }
    const requestLimit = Number(generationRequestLimit);
    if (!/^[1-8]$/.test(generationRequestLimit) || !Number.isSafeInteger(requestLimit)) { setPreparationError(new Error('本次规划调用上限需为 1–8 的整数。')); return; }
    setPreparationError(undefined);
    const result = await command.run<Operation>(`/projects/${pathId(projectId)}/flow-generations`, { source_ids: sourceIds, instruction, owner_id: generationOwner, team_id: generationTeam, executor_profile_id: generationExecutor, verification_plan_id: generationVerifier, resource_profile_id: generationResource, max_model_requests: requestLimit });
    if (result?.operation_id) { setOperationId(result.operation_id); setGenerating(false); const params = new URLSearchParams(window.location.search); params.set('operation', result.operation_id); navigate(`${window.location.pathname}?${params}`, { replace: true }); latestQuery.reload(); }
  }
  return <><PageHeader title="需求与设计" description="原文、验收和任务映射一起审阅；缺口保持在交付分母中。" actions={<><button disabled={!writable || command.busy} onClick={() => setImporting(true)}><Upload size={16} />导入来源</button><button disabled={!writable || command.busy} onClick={() => setCreating(true)}><Plus size={16} />人工需求</button><button className="primary" disabled={!writable || !sourceIdentity || command.busy} onClick={() => setGenerating(true)}><Sparkles size={16} />{command.busy ? '正在提交…' : '生成 Flow 草案'}</button></>} />
    {!projectId ? <EmptyState title="选择项目开始规划" /> : <><SourceStamp source={requirements.metadata.source} observedAt={requirements.metadata.observed_at} />{command.error && <ErrorNotice error={command.error} />}{project.error && <ErrorNotice error={project.error} onRetry={project.reload} />}
      {latestQuery.error && !noFlow && <ErrorNotice error={latestQuery.error} onRetry={latestQuery.reload} />}
      {fullContext.error && <ErrorNotice error={fullContext.error} onRetry={fullContext.reload} />}
      {operationId && <PlanningOperationPanel key={`${projectId}:${operationId}`} operationId={operationId} projectId={projectId} data={operation.data} loading={operation.loading} error={operation.error} reload={operation.reload} observedAt={operation.metadata.observed_at} />}
      <div className="notice">{fullContext.data ? `当前完整需求范围：${fullContext.data.requirements.length} 条需求，${globalGaps?.length ?? 0} 条尚未映射到 R${latest?.flow_revision}。下方表格按页读取。` : '完整覆盖分母尚未读取。当前页结果不能证明全项目覆盖完整。'}</div>
      <div className="toolbar"><span>{reqs.length} 条当前页需求</span><span className="muted">{uncovered.length} 条本页尚无覆盖 · {reqs.filter(item => item.deferred_reason).length} 条明确延期 · 当前 Flow {latest ? `R${latest.flow_revision}` : '未建立'}</span><button aria-label="刷新需求" onClick={() => { requirements.reload(); sourcesQuery.reload(); latestQuery.reload(); }}><RefreshCw size={16} /></button></div>
      <div className="workbench-grid requirements-workbench"><Panel title={<span><FileText size={16} />原始来源</span>}><QueryState loading={sourcesQuery.loading && !sourcesQuery.data} error={sourcesQuery.error} onRetry={sourcesQuery.reload}>{sources.length ? <><Field label="来源"><select value={sourceIdentity ?? ''} onChange={event => setSourceId(event.target.value)}>{sourceId && !sources.some(item => (item.source_id ?? item.id ?? item.source_document) === sourceId) && <option value={sourceId}>{source?.name ?? sourceId} · 原文锚点</option>}{sources.map((item, index) => <option key={String(item.source_id ?? item.id ?? item.source_document ?? index)} value={String(item.source_id ?? item.id ?? item.source_document ?? '')}>{item.name ?? item.source_document ?? item.source_id ?? item.id}</option>)}</select></Field><Pagination query={sourcesQuery} count={sources.length} />{sourceDetail.error && <ErrorNotice error={sourceDetail.error} onRetry={sourceDetail.reload} />}<div className="source-document">{source?.content ? sourceLines.slice(sourceLinePage * 200, (sourceLinePage + 1) * 200).map((line, localIndex) => { const index = sourceLinePage * 200 + localIndex; const linked = reqs.find(requirement => requirement.source_anchor.startsWith(`${sourceIdentity}#`) && requirement.source_anchor.endsWith(`:L${index + 1}`)); return <button type="button" key={index} className={`source-line ${linked ? 'linked' : ''} ${selected?.requirement_id === linked?.requirement_id && linked ? 'selected' : ''}`} aria-label={`原文第 ${index + 1} 行${linked ? `，需求 ${linked.title}` : ''}`} onClick={() => linked && selectRequirement(linked)} disabled={!linked}><span aria-hidden="true">{index + 1}</span>{line || ' '}</button>; }) : sourceDetail.loading ? '正在读取原文…' : '服务端未提供原文内容。'}</div><div className="toolbar"><button disabled={sourceLinePage === 0} onClick={() => setSourceLinePage(value => value - 1)}>原文上一页</button><span>{source?.content !== undefined ? `${Math.min(sourceLinePage * 200 + 1, sourceLines.length)}–${Math.min((sourceLinePage + 1) * 200, sourceLines.length)} / ${sourceLines.length} 行` : '原文尚未读取'}</span><button disabled={(sourceLinePage + 1) * 200 >= sourceLines.length} onClick={() => setSourceLinePage(value => value + 1)}>原文下一页</button></div><p className="muted">原始 SHA256</p><code className="break-word">{source?.raw_sha256 ?? '服务端未提供'}</code></> : <EmptyState title="还没有原始来源" description="导入文档保留原文与 hash，然后核对解析结果。" />}</QueryState></Panel>
      <Panel title="需求 → 任务映射"><QueryState loading={requirements.loading && !requirements.data} error={requirements.error} onRetry={requirements.reload}><DataTable rows={reqs} rowKey={requirement => requirement.requirement_id} onRowClick={selectRequirement} columns={[{ key: 'title', label: '需求与验收', render: requirement => <span>{requirement.title}<small className="muted">{requirement.source_anchor}</small></span> }, { key: 'priority', label: '优先级', numeric: true }, { key: 'weight', label: '权重', numeric: true }, { key: 'coverage', label: '覆盖任务', render: requirement => covered(requirement.requirement_id).length ? covered(requirement.requirement_id).map(task => <a key={task.task_id} href={`/projects/${pathId(projectId)}/flows/${latest?.flow_revision}?task=${pathId(task.task_id)}`}>{task.title}</a>) : requirement.deferred_reason ? <span title={requirement.deferred_reason}>明确延期</span> : <StatusBadge state="BLOCKED" /> }]} empty={<EmptyState title="还没有结构化需求" description="导入后核对原文锚点，或录入人工需求。" />} /><Pagination query={requirements} count={reqs.length} /></QueryState></Panel>
      <Panel title="覆盖缺口"><p className="muted">需求覆盖只表示任务映射；产品交付需要验收证据。</p>{uncovered.length ? <div className="selection-list">{uncovered.map(requirement => <button key={requirement.requirement_id} onClick={() => setSelected(requirement)}><span>{requirement.title}<small>{requirement.requirement_id}</small></span><ArrowUpRight size={14} /></button>)}</div> : <p>{reqs.length ? requirements.hasNext || requirements.hasPrevious ? '本页需求均有任务映射或明确延期；其他页面尚未在此显示。' : '本页需求均有任务映射或明确延期理由。' : '导入需求后计算覆盖缺口。'}</p>}<Field label="规划指导"><textarea rows={4} value={instruction} onChange={event => setInstruction(event.target.value)} placeholder="范围、技术约束、有限退出条件与里程碑" /></Field><p className="muted">生成依赖真实执行器与持久操作。人工录入保持可用；不会被计作自动生成已验收。</p></Panel></div>
    </>}
    {selected && !editingRequirement && <Drawer title={selected.title} onClose={() => setSelected(undefined)}><button disabled={!writable || command.busy} onClick={() => setEditingRequirement(selected)}>编辑需求与延期理由</button><dl className="detail-grid"><dt>身份</dt><dd>{selected.requirement_id}</dd><dt>原文锚点</dt><dd>{selected.source_anchor}</dd><dt>业务结果</dt><dd>{selected.outcome}</dd><dt>范围</dt><dd>{selected.scope}</dd><dt>验收</dt><dd>{selected.acceptance.join('\n')}</dd><dt>延期理由</dt><dd>{selected.deferred_reason ?? '未延期'}</dd></dl><h3>覆盖任务</h3>{covered(selected.requirement_id).map(task => <a className="button" key={task.task_id} href={`/projects/${pathId(projectId!)}/flows/${latest?.flow_revision}?task=${pathId(task.task_id)}`}>{task.title}</a>)}<details><summary>原始需求记录</summary><JsonView value={selected} /></details></Drawer>}
    {importing && <Drawer title="导入真实需求来源" onClose={() => !command.busy && setImporting(false)}><form onSubmit={importSource} onDragOver={event => event.preventDefault()} onDrop={event => { event.preventDefault(); void readFile(event.dataTransfer.files[0]); }}><Field label="选择文件或拖放到此处"><input type="file" accept=".md,.markdown,.txt,.json" onChange={event => void readFile(event.target.files?.[0])} /></Field><Field label="来源名称"><input required value={name} onChange={event => setName(event.target.value)} /></Field><Field label="内容格式"><select value={format} onChange={event => setFormat(event.target.value)}><option value="MARKDOWN">Markdown / 纯文本</option><option value="JSON">结构化 JSON</option></select></Field><Field label="完整原文" hint="解析由后端执行；失败保留当前内容与具体错误。"><textarea rows={18} required value={content} onChange={event => setContent(event.target.value)} spellCheck={false} /></Field>{fileError && <ErrorNotice error={fileError} />}{command.error && <ErrorNotice error={command.error} />}<button className="primary" disabled={command.busy}><Upload size={16} />{command.busy ? '正在保存与解析…' : '导入并解析'}</button></form></Drawer>}
    {creating && projectId && <Drawer title="新增人工需求" onClose={() => !command.busy && setCreating(false)}><RequirementForm projectId={projectId} busy={command.busy} error={command.error} onSave={async requirement => { const saved = await command.run<Requirement>(`/projects/${pathId(projectId)}/requirements`, requirement); if (saved) { requirements.reload(); fullContext.reload(); setCreating(false); } }} /></Drawer>}
    {generating && projectId && <Drawer title="真实 DSH 规划配置" onClose={() => !command.busy && setGenerating(false)}><form onSubmit={generate}>
      <p>一次规划使用完整登记来源，并创建受预算约束的只读 DSH 尝试。执行器运行、独立验证和草案产出分别留证。</p>
      {[allSources, owners, teams, executors, verifiers, resources].some(query => query.loading) && <p role="status">正在完整读取规划来源与已登记配置…</p>}
      {[allSources, owners, teams, executors, verifiers, resources].map((query, index) => query.error && <ErrorNotice key={index} error={query.error} onRetry={query.reload} />)}
      <p className="muted">完整来源 {allSources.data?.length ?? '未读完'} 份；不会截断来源或只提交当前页面。</p>
      <Field label="根 Owner"><select required value={generationOwner} onChange={event => setGenerationOwner(event.target.value)}><option value="">选择已登记领地</option>{owners.data?.map(owner => <option value={owner.owner_id} key={owner.owner_id}>{owner.owner_id}</option>)}</select></Field>
      <Field label="预算团队"><select required value={generationTeam} onChange={event => setGenerationTeam(event.target.value)}><option value="">选择执行团队</option>{teams.data?.map(team => <option value={team.team_id} key={team.team_id}>{team.name} · {team.team_id}</option>)}</select></Field>
      <Field label="DSH 执行器 Profile"><select required value={generationExecutor} onChange={event => setGenerationExecutor(event.target.value)}><option value="">选择真实已探测执行器</option>{executors.data?.map(profile => <option value={profile.id} key={profile.id}>{profile.id}</option>)}</select></Field>
      <Field label="独立规划验证模板"><select required value={generationVerifier} onChange={event => setGenerationVerifier(event.target.value)}><option value="">选择已登记独立验证</option>{verifiers.data?.map(plan => <option value={plan.plan_id} key={plan.plan_id}>{plan.plan_id}</option>)}</select></Field>
      <Field label="资源 Profile"><select required value={generationResource} onChange={event => setGenerationResource(event.target.value)}><option value="">选择资源配置</option>{resources.data?.map(profile => <option value={profile.id} key={profile.id}>{profile.id}</option>)}</select></Field>
      <Field label="本次规划调用上限"><input type="number" required min={1} max={8} step={1} value={generationRequestLimit} onChange={event => setGenerationRequestLimit(event.target.value)} /><span className="muted">每次模型请求计数，执行阶段的预算单独设置。</span></Field><Field label="规划指导"><textarea rows={5} value={instruction} onChange={event => setInstruction(event.target.value)} /></Field>
      {preparationError && <ErrorNotice error={preparationError} />}{command.error && <ErrorNotice error={command.error} />}
      <div className="toolbar"><a href={`/projects/${pathId(projectId)}/teams`}>登记责任与团队</a><a href="/executors">查看执行器能力</a></div>
      <button className="primary" disabled={command.busy || !allSources.data || [allSources, owners, teams, executors, verifiers, resources].some(query => query.loading || query.error)}>{command.busy ? '正在创建真实规划操作…' : '提交真实规划操作'}</button>
    </form></Drawer>}
    {editingRequirement && projectId && <Drawer title="编辑需求" onClose={() => !command.busy && setEditingRequirement(undefined)}><RequirementForm projectId={projectId} initial={editingRequirement} busy={command.busy} error={command.error} onSave={async requirement => { const saved = await command.run<Requirement>(`/projects/${pathId(projectId)}/requirements/${pathId(requirement.requirement_id)}`, { requirement }, editingRequirement.revision, 'PATCH'); if (saved) { requirements.reload(); fullContext.reload(); setSelected(saved); setEditingRequirement(undefined); } }} /></Drawer>}
  </>;
}

function RequirementForm({ projectId, initial, busy, error, onSave }: { projectId: string; initial?: Requirement; busy: boolean; error?: Error; onSave: (requirement: Requirement) => void }) {
  const [draft, setDraft] = useState<Requirement>(initial ?? { project_id: projectId, requirement_id: crypto.randomUUID(), title: '', source_anchor: '', outcome: '', scope: '', acceptance: [], priority: 0, weight: 1, deferred_reason: null, revision: 1 });
  return <form onSubmit={event => { event.preventDefault(); onSave({ ...draft, acceptance: lines(draft.acceptance.join('\n')) }); }}><Field label="需求标题"><input required value={draft.title} onChange={event => setDraft({ ...draft, title: event.target.value })} /></Field><Field label="原文锚点"><input required value={draft.source_anchor} onChange={event => setDraft({ ...draft, source_anchor: event.target.value })} /></Field><Field label="业务结果"><textarea required value={draft.outcome} onChange={event => setDraft({ ...draft, outcome: event.target.value })} /></Field><Field label="范围"><textarea required value={draft.scope} onChange={event => setDraft({ ...draft, scope: event.target.value })} /></Field><Field label="验收条件 · 每行一条"><textarea required rows={5} value={draft.acceptance.join('\n')} onChange={event => setDraft({ ...draft, acceptance: event.target.value.split(/\r?\n/) })} /></Field><div className="form-grid"><Field label="优先级"><input type="number" step={1} value={draft.priority} onChange={event => setDraft({ ...draft, priority: Number(event.target.value) })} /></Field><Field label="批准权重"><input type="number" min={1} step={1} value={draft.weight} onChange={event => setDraft({ ...draft, weight: Number(event.target.value) })} /></Field></div><Field label="明确延期理由（可选）"><textarea value={draft.deferred_reason ?? ''} onChange={event => setDraft({ ...draft, deferred_reason: event.target.value || null })} /></Field>{error && <ErrorNotice error={error} />}<button className="primary" disabled={busy}>{busy ? '正在保存…' : '创建需求'}</button></form>;
}
