import { useEffect, useLayoutEffect, useMemo, useState } from 'react';
import { useLocation, useNavigate, useSearchParams } from 'react-router-dom';
import { Check, Copy, FilePlus2, GitBranch, List, Play, RefreshCw, Search, Workflow } from 'lucide-react';
import { api, ApiError, getDraftScope, items, useApi, useCursorApi,useWorkspaceWritable } from '../../app/api';
import type { PageProps } from '../../app/types';
import { DataTable, Drawer, EmptyState, ErrorNotice, Field, JsonView, PageHeader, Panel, QueryState, SourceStamp, StatusBadge, Pagination } from '../../components';
import { DagEditor } from './DagEditor';
import { TaskForm } from './TaskForm';
import { AssignmentBoard, previewAssignments, type AssignmentTeam, type AssignmentChangeSet } from './AssignmentBoard';
import { flowPath, newTask, parseStrictJson, pathId, useCommand, useCompleteApi, type CheckReport, type CompileContext, type FlowRevision, type Requirement, type TaskCard, type TaskSpec } from './types';
import './task-inspector.css';
import { planningWorkbenchEnabled } from '../../app/feature-flags';
import { PlanningWorkbench } from './PlanningWorkbench';
import { TaskInspector } from '../../components/TaskInspector';

const taskColumns = [
  { key: 'task_id', label: '卡号', render: (task: TaskCard) => <code>{task.task_id}</code> },
  { key: 'title', label: '有限交付结果' }, { key: 'owner_id', label: '根 Owner' }, { key: 'team_id', label: '执行团队' },
  { key: 'state', label: '规划状态', render: (task: TaskCard) => <StatusBadge state={task.state} /> },
  { key: 'dependencies', label: '前置', numeric: true, render: (task: TaskCard) => task.dependencies.length },
  { key: 'write_set', label: '精确写路径', numeric: true, render: (task: TaskCard) => task.write_set.length },
];

type TemplateFlowReference = Pick<FlowRevision, 'project_id' | 'flow_revision' | 'revision' | 'input_digest'>;
type FlowAttempt = {
  project_id: string; task_id: string; task_revision: number; attempt_id: string;
  state: string; worker_id: string; generation: number; created_at: string;
  terminal_at?: string | null;
};
const planningExplanations: Record<TaskCard['state'], string> = {
  PLANNED: '已列入计划，尚未达到准入条件。',
  NEEDS_REVIEW: '任务定义或输入需要复核，审阅前不能启动。',
  READY_FOR_ADMISSION: '规划已符合候选条件；实际执行仍需准入、有效租约和资源。',
  DEFERRED: '此任务修订已延期，当前不会作为执行候选。',
  REMOVED_FROM_PLAN: '此任务修订已移出计划，历史记录继续保留。',
};
function CopyTechnicalId({ label, value, compact = false }: { label: string; value: string; compact?: boolean }) {
  const [message, setMessage] = useState('');
  useEffect(() => setMessage(''), [value]);
  async function copy() {
    try { await navigator.clipboard.writeText(value); setMessage('已复制'); }
    catch { setMessage('未能复制，请展开技术身份手动选择编号'); }
  }
  return <div className={compact ? 'task-inspector-copy compact' : 'task-inspector-copy'}>
    {!compact && <code title={value}>{value}</code>}
    <button type="button" onClick={() => void copy()} aria-label={`复制${label}`} title={value}><Copy size={13} />{compact ? `复制${label}` : '复制'}</button>
    {message && <span role="status">{message}</span>}
  </div>;
}

type LocalPlanningDraft = { project_id: string; base_flow_revision: number; base_revision: number; source_revision: string; changes: Record<string, { task: TaskCard; spec?: TaskSpec }> };
export function FlowPage(props: PageProps) { return <FlowWorkspace key={`${props.projectId}:${props.flowId ?? 'latest'}`} {...props} />; }
function FlowWorkspace({ projectId, flowId, taskId }: PageProps) {
  const nextWorkbench = planningWorkbenchEnabled();
  const [assignmentMounted, setAssignmentMounted] = useState(!nextWorkbench);
  const [draft, setDraft] = useState<LocalPlanningDraft>();
  const [draftRestored, setDraftRestored] = useState(false);
  const [draftNotice, setDraftNotice] = useState('');
  const navigate = useNavigate();
  const location = useLocation();
  const linkedTask = taskId ?? new URLSearchParams(location.search).get('task');
  useEffect(() => { if (linkedTask) { setSelectedTask(linkedTask); setInspectorOpen(true); } else setInspectorOpen(false); }, [linkedTask]);
  const flowsQuery = useCursorApi<FlowRevision[]>(projectId ? `/projects/${pathId(projectId)}/flows?view=summary` : null, 'flow_cursor');
  const flows = items(flowsQuery.data);
  const [revisionId, setRevisionId] = useState<string>();
  const [view, setView] = useState<'graph' | 'table'>('graph');
  const [taskPage, setTaskPage] = useState(0);
  const [selectedTask, setSelectedTask] = useState<string | undefined>(taskId ?? new URLSearchParams(window.location.search).get('task') ?? undefined);
  const [inspectorOpen, setInspectorOpen] = useState(!!(taskId ?? new URLSearchParams(window.location.search).get('task')));
  const [editing, setEditing] = useState<TaskCard>();
  const [configuring, setConfiguring] = useState<TaskCard>();
  const [templateOperationId, setTemplateOperationId] = useState<string | undefined>(new URLSearchParams(window.location.search).get('template_operation') ?? undefined);
  const [showJson, setShowJson] = useState(false);
  const [jsonDraft, setJsonDraft] = useState('');
  const [jsonError, setJsonError] = useState<Error>();
  const [preparationError, setPreparationError] = useState<Error>();
  const [checkReport, setCheckReport] = useState<CheckReport>();
  const [checkPage, setCheckPage] = useState(0);
  useEffect(() => setCheckPage(0), [checkReport]);
  const [checkOrigin, setCheckOrigin] = useState<{ kind: 'stored' | 'unsaved'; projectId: string; flowRevision: number; revision: number }>();
  const command = useCommand();
  const templateOperation = useApi<{ operation_id: string; project_id: string; status: string; error?: unknown; result?: { flow?: FlowRevision; flow_ref?: TemplateFlowReference } }>(templateOperationId ? `/operations/${pathId(templateOperationId)}?view=summary` : null);
  useEffect(() => {
    if (!templateOperationId || ['SUCCEEDED', 'FAILED', 'CANCELLED', 'BLOCKED'].includes(templateOperation.data?.status ?? '')) return;
    const timer = window.setInterval(templateOperation.reload, 2000); return () => window.clearInterval(timer);
  }, [templateOperationId, templateOperation.data?.status, templateOperation.reload]);
  useEffect(() => {
    if (templateOperation.data && templateOperation.data.project_id !== projectId) { setPreparationError(new Error('执行配置操作属于其他项目；请使用对应项目的历史入口。')); return; }
    if (templateOperation.data?.status === 'SUCCEEDED') {
      const result = templateOperation.data.result?.flow_ref ?? templateOperation.data.result?.flow;
      if (result && result.project_id === projectId) { chooseRevision(`${result.project_id}:${result.flow_revision}`); flowQuery.reload(); contextQuery.reload(); currentContextQuery.reload(); latestQuery.reload(); }
      else { setPreparationError(new Error('执行配置结果缺少匹配的项目与 Flow 版本引用。')); }
    }
  }, [templateOperation.data, projectId]);
  useEffect(() => { setRevisionId(undefined); setSelectedTask(taskId ?? new URLSearchParams(window.location.search).get('task') ?? undefined); setEditing(undefined); setCheckReport(undefined); setTaskPage(0); }, [projectId, flowId, taskId]);
  const latestQuery = useApi<FlowRevision | null>(projectId ? `/projects/${pathId(projectId)}/flows/latest?view=summary` : null);
  const latest = latestQuery.data ?? undefined;
  const noFlow = latestQuery.error instanceof ApiError && latestQuery.error.code === 'FLOW_NOT_FOUND';
  const rawRevisionId = revisionId ?? flowId ?? (latest ? `${latest.project_id}:${latest.flow_revision}` : undefined);
  const requested = rawRevisionId && projectId && !rawRevisionId.includes(':') ? `${projectId}:${rawRevisionId}` : rawRevisionId;
  const endpoint = requested ? (requested.includes(':') ? `/flows/${pathId(requested)}` : projectId ? `/flows/${pathId(`${projectId}:${requested}`)}` : null) : null;
  const flowQuery = useApi<FlowRevision>(endpoint);
  const contextQuery = useApi<CompileContext>(endpoint ? `${endpoint}/context` : null);
  const currentContextQuery = useApi<CompileContext>(endpoint ? `${endpoint}/context/current?view=summary` : null);
  const projectQuery = useApi<{ authority_mode: string; archived: boolean }>(projectId ? `/projects/${pathId(projectId)}` : null);
  const assignmentSnapshot = useApi<{ teams: AssignmentTeam[]; attempts: FlowAttempt[]; project: { project_id: string }; revision: number; as_of: string; source: string }>(projectId ? `/projects/${pathId(projectId)}/assignment-context` : null);
  const assignmentCoverage = !!assignmentSnapshot.data && !assignmentSnapshot.error && !assignmentSnapshot.loading && assignmentSnapshot.data.project?.project_id === projectId && Array.isArray(assignmentSnapshot.data.teams) && Array.isArray(assignmentSnapshot.data.attempts);
  const terminalStates = new Set(['SUCCEEDED', 'FAILED', 'CANCELLED']);
  const assignmentActiveIds = useMemo(() => assignmentCoverage ? assignmentSnapshot.data!.attempts.filter(a => !['SUCCEEDED', 'FAILED', 'CANCELLED'].includes(a.state)).map(a => a.task_id) : [], [assignmentCoverage, assignmentSnapshot.data]);
  const assignmentContext = useMemo(() => currentContextQuery.data ? { ...currentContextQuery.data, task_specs: contextQuery.data?.task_specs ?? {} } : undefined, [currentContextQuery.data, contextQuery.data]);
  const baseFlow = flowQuery.data;
  const draftStorageKey = baseFlow ? `forgeflow.planning-draft.${getDraftScope()}.${projectId}.${baseFlow.flow_revision}` : undefined;
  useLayoutEffect(() => {
    if (!nextWorkbench || !draftStorageKey || draftRestored) return;
    try {
      const raw = sessionStorage.getItem(draftStorageKey);
      if (raw) {
        const saved = JSON.parse(raw) as LocalPlanningDraft;
        if (saved.project_id === projectId && saved.base_flow_revision === baseFlow?.flow_revision && saved.changes && typeof saved.changes === 'object') { setDraft(saved); setDraftNotice('已恢复此浏览器保存的未提交草稿。'); }
      }
    } catch { setDraftNotice('未能读取本地草稿；当前服务端版本仍可浏览。'); }
    setDraftRestored(true);
  }, [nextWorkbench, draftStorageKey, draftRestored, projectId, baseFlow?.flow_revision]);
  useLayoutEffect(() => {
    if (!nextWorkbench || !draftRestored || !draftStorageKey) return;
    try { if (draft) sessionStorage.setItem(draftStorageKey, JSON.stringify(draft)); else sessionStorage.removeItem(draftStorageKey); }
    catch { setDraftNotice('浏览器存储空间不足；草稿仍在当前页面，请及时保存。'); }
  }, [draft, draftStorageKey, draftRestored, nextWorkbench]);
  const flow = useMemo(() => {
    if (!baseFlow || !draft) return baseFlow;
    const ids = new Set(baseFlow.tasks.map(task => task.task_id));
    return { ...baseFlow, tasks: [...baseFlow.tasks.map(task => draft.changes[task.task_id]?.task ?? task), ...Object.values(draft.changes).filter(change => !ids.has(change.task.task_id)).map(change => change.task)] };
  }, [baseFlow, draft]);
  const workingSpecs = useMemo(() => ({ ...contextQuery.data?.task_specs, ...Object.fromEntries(Object.entries(draft?.changes ?? {}).filter(([, change]) => change.spec).map(([id, change]) => [id, change.spec!])) }), [contextQuery.data?.task_specs, draft]);
  const draftStale = !!draft && (draft.base_flow_revision !== baseFlow?.flow_revision || draft.base_revision !== baseFlow?.revision || draft.source_revision !== currentContextQuery.data?.source_revision);
  const readOnly = !useWorkspaceWritable() || projectQuery.data?.authority_mode !== 'MANAGED' || projectQuery.data?.archived === true;
  const tasks = flow?.tasks ?? [];
  const selected = tasks.find(task => task.task_id === selectedTask);
  const executionAvailable = flow?.project_id === projectId && assignmentCoverage;
  const attemptsByTask = useMemo(() => {
    const currentTasks = new Map(tasks.map(task => [task.task_id, task]));
    const grouped = new Map<string, FlowAttempt[]>();
    if (!executionAvailable) return grouped;
    for (const attempt of assignmentSnapshot.data!.attempts) {
      const task = currentTasks.get(attempt.task_id);
      if (attempt.project_id !== projectId || !task || attempt.task_revision !== task.task_revision) continue;
      const history = grouped.get(task.task_id) ?? [];
      history.push(attempt); grouped.set(task.task_id, history);
    }
    for (const history of grouped.values()) history.sort((a, b) => b.created_at.localeCompare(a.created_at) || b.attempt_id.localeCompare(a.attempt_id));
    return grouped;
  }, [tasks, projectId, assignmentSnapshot.data, executionAvailable]);
  const selectedAttempts = selected ? attemptsByTask.get(selected.task_id) ?? [] : [];
  const historicalAttemptCount = selected && executionAvailable ? assignmentSnapshot.data!.attempts.filter(attempt => attempt.project_id === projectId && attempt.task_id === selected.task_id && attempt.task_revision !== selected.task_revision).length : 0;
  const executionColumns = [...taskColumns, {
    key: 'execution', label: '最近真实尝试', render: (task: TaskCard) => {
      const attempts = attemptsByTask.get(task.task_id) ?? [];
      return !executionAvailable ? <span className="muted">执行快照未取得</span> : !attempts.length ? <span className="muted">本任务修订尚无尝试</span> : <><StatusBadge state={attempts[0].state} /><small>{attempts.length} 次 · 任务修订 {task.task_revision}</small></>;
    },
  }];
  const currentSpec = selected ? workingSpecs[selected.task_id] : undefined;
  const parentQuery = useApi<FlowRevision>(flow?.parent_revision ? `/flows/${pathId(`${flow.project_id}:${flow.parent_revision}`)}` : null);
  const parent = parentQuery.data;
  const editorRequirements: Requirement[] = (currentContextQuery.data?.requirements ?? []).map(requirement => ({ project_id: projectId ?? '', requirement_id: requirement.requirement_id, title: requirement.acceptance, source_anchor: `${requirement.source_document}#${requirement.anchor}`, outcome: requirement.acceptance, scope: '', acceptance: [requirement.acceptance], priority: requirement.priority, weight: 0, deferred_reason: requirement.deferred_reason, revision: 0 }));
  const previousTasks = new Map(parent?.tasks.map(task => [task.task_id, task]));
  const currentTaskIds = new Set(tasks.map(task => task.task_id));
  const changes = parent ? {
    added: tasks.filter(task => !previousTasks.has(task.task_id)),
    removed: parent.tasks.filter(task => !currentTaskIds.has(task.task_id)),
    changed: tasks.filter(task => { const previous = previousTasks.get(task.task_id); return previous && (previous.input_digest !== task.input_digest || previous.title !== task.title || previous.owner_id !== task.owner_id || previous.team_id !== task.team_id || JSON.stringify(previous.dependencies) !== JSON.stringify(task.dependencies)); }),
  } : undefined;
  const edges = useMemo(() => tasks.flatMap(task => task.dependencies.map(source => ({ id: `${task.task_id}:${source}`, source, target: task.task_id, kind: workingSpecs[task.task_id]?.dependency_refs.find(ref => ref.task_id === source)?.kind ?? '语义未加载' }))), [tasks, workingSpecs]);
  const pendingConfig = !!templateOperationId && (!templateOperation.data || templateOperation.data.status === 'ACCEPTED');
  const canEdit = !!flow && !!contextQuery.data && !contextQuery.error && !!currentContextQuery.data && !currentContextQuery.error && !readOnly && !command.busy && !pendingConfig;

  function reload() { assignmentSnapshot.reload(); flowQuery.reload(); flowsQuery.reload(); latestQuery.reload(); contextQuery.reload(); currentContextQuery.reload(); }
  useEffect(() => {
    let timer: number | undefined;
    const schedule = () => { if (timer === undefined) timer = window.setTimeout(() => { timer = undefined; assignmentSnapshot.reload(); }, 750); };
    const refresh = (event: Event) => {
      const detail = (event as CustomEvent<{ projectId: string; kind?: string }>).detail;
      if (detail?.projectId === projectId && /^attempt\.(admitted|starting|running|transitioned|execution_returned|stopped|cancel_requested|lease_expired|never_dispatched)$/.test(detail.kind ?? '')) schedule();
    };
    const resync = (event: Event) => { if ((event as CustomEvent<{ projectId: string }>).detail?.projectId === projectId) schedule(); };
    window.addEventListener('forgeflow-event', refresh); window.addEventListener('forgeflow-resync', resync);
    return () => { window.removeEventListener('forgeflow-event', refresh); window.removeEventListener('forgeflow-resync', resync); if (timer !== undefined) window.clearTimeout(timer); };
  }, [projectId, assignmentSnapshot.reload]);
  useEffect(() => {
    let timer: number | undefined;
    const refresh = (event: Event) => {
      const detail = (event as CustomEvent<{ projectId: string; kind?: string; payload?: { collection?: string } }>).detail;
      if (detail?.projectId !== projectId || !detail.kind || !/^(source\.|requirement\.|flow\.|owner\.|contract\.|input\.|document\.updated)/.test(detail.kind) || timer !== undefined) return;
      if (detail.kind === 'document.updated' && !['flow_contexts', 'sources', 'owners', 'input_snapshots', 'contract_versions'].includes(detail.payload?.collection ?? '')) return;
      timer = window.setTimeout(() => { timer = undefined; contextQuery.reload(); currentContextQuery.reload(); flowQuery.reload(); }, 300);
    };
    window.addEventListener('forgeflow-event', refresh); return () => { window.removeEventListener('forgeflow-event', refresh); if (timer !== undefined) window.clearTimeout(timer); };
  }, [projectId, contextQuery.reload, currentContextQuery.reload, flowQuery.reload]);
  async function readLatest() {
    if (!projectId) return null;
    try { const value = await api.get<FlowRevision | null>(`/projects/${pathId(projectId)}/flows/latest?view=summary`); setPreparationError(undefined); return value; }
    catch (cause) { if (cause instanceof ApiError && cause.code === 'FLOW_NOT_FOUND') return null; throw cause; }
  }
  function selectTask(id: string) { setSelectedTask(id); setInspectorOpen(true); const parameters = new URLSearchParams(window.location.search); parameters.set('task', id); navigate(`${window.location.pathname}?${parameters}`, { replace: true }); }
  function clearTaskSelection() { setInspectorOpen(false); const parameters = new URLSearchParams(window.location.search); parameters.delete('task'); navigate(`${window.location.pathname}${parameters.size ? `?${parameters}` : ''}`, { replace: true }); }
  function chooseRevision(id: string) { setRevisionId(id); setCheckReport(undefined); setSelectedTask(undefined); if (projectId) navigate(`/projects/${pathId(projectId)}/flows/${id.slice(id.lastIndexOf(':') + 1)}`, { replace: true }); }
  async function prepareTasks(nextTasks: TaskCard[], nextSpecs = contextQuery.data?.task_specs, reseal = false) {
    if (!flow || !currentContextQuery.data || !nextSpecs) return;
    const { requirements, requirement_semantic_digests, owners, current_inputs, resolved_paths, contracts, source_revision, observed_at } = currentContextQuery.data;
    const context: CompileContext = { requirements, requirement_semantic_digests, owners, task_specs: nextSpecs, current_inputs, resolved_paths, contracts, source_revision, observed_at };
    let currentLatest: FlowRevision | null;
    try { currentLatest = await readLatest(); } catch (cause) { setPreparationError(cause instanceof Error ? cause : new Error(String(cause))); return; }
    const nextRevision = Math.max(flow.flow_revision, currentLatest?.flow_revision ?? 0) + 1;
    const baseTasksById = new Map(baseFlow?.tasks.map(task => [task.task_id, task]));
    const nextFlow: FlowRevision = {
      ...flow, flow_revision: nextRevision, parent_revision: flow.flow_revision,
      state: 'DRAFT', approved_by: null, revision: 1,
      tasks: nextTasks.map<TaskCard>(task => {
        const previous = baseTasksById.get(task.task_id);
        const changed = !previous || reseal || JSON.stringify(previous) !== JSON.stringify(task)
          || JSON.stringify(contextQuery.data?.task_specs[task.task_id]) !== JSON.stringify(nextSpecs[task.task_id]);
        return {
          ...task, flow_revision: nextRevision,
          task_revision: task.task_revision + (previous && changed ? 1 : 0),
          state: changed ? 'NEEDS_REVIEW' : task.state,
          envelope: changed ? null : task.envelope,
        };
      }),
    };
    return { flow: nextFlow, context };
  }
  async function previewTasks(nextTasks: TaskCard[], nextSpecs = contextQuery.data?.task_specs, reseal = false) {
    const proposal = await prepareTasks(nextTasks, nextSpecs, reseal);
    if (!proposal) return;
    setCheckReport(undefined); setCheckOrigin(undefined);
    const report = await command.run<CheckReport>(`/projects/${pathId(proposal.flow.project_id)}/flow-checks`, proposal);
    if (!report) return;
    setCheckReport(report);
    setCheckOrigin({ kind: 'unsaved', projectId: proposal.flow.project_id, flowRevision: proposal.flow.flow_revision, revision: proposal.flow.revision });
    return { proposal, report };
  }
  async function saveTasks(nextTasks: TaskCard[], nextSpecs = contextQuery.data?.task_specs, reseal = false, parentGuard?: { flow_revision: number; revision: number; source_revision: string }) {
    const checked = await previewTasks(nextTasks, nextSpecs, reseal);
    if (!checked) return;
    // Invalid edges cannot be stored. Keep the proposal and its actual compiler
    // locations visible; other incomplete draft semantics remain saveable.
    if (checked.report.findings?.some(finding => ['DEPENDENCY_CYCLE', 'DANGLING_DEPENDENCY'].includes(finding.rule_id))) return;
    const saved = await command.run<FlowRevision>(`/projects/${pathId(checked.proposal.flow.project_id)}/flow-revisions`, { ...checked.proposal, ...(parentGuard ? { parent_guard: parentGuard } : {}) });
    if (saved) { chooseRevision(`${saved.project_id}:${saved.flow_revision}`); setEditing(undefined); setShowJson(false); flowsQuery.reload(); latestQuery.reload(); assignmentSnapshot.reload(); }
    return saved;
  }
  async function saveAssignment(changes: AssignmentChangeSet) {
    if (!flow || !contextQuery.data || !currentContextQuery.data || !canEdit || changes.project_id !== projectId || changes.base_flow_revision !== flow.flow_revision || changes.base_revision !== flow.revision) throw new Error("分工预览的 Flow 已变化，请重新加载并预览。");
    const [base, current, snapshot] = await Promise.all([api.get<FlowRevision>(flowPath(flow)), api.get<CompileContext>(`${flowPath(flow)}/context/current`), api.get<{ project: { project_id: string }; teams: AssignmentTeam[]; attempts: { task_id: string; state: string }[] }>(`/projects/${pathId(flow.project_id)}/assignment-context`)]);
    if (base.revision !== changes.base_revision || current.source_revision !== changes.context_source_revision || JSON.stringify(current.owners) !== JSON.stringify(currentContextQuery.data.owners) || JSON.stringify(current.current_inputs) !== JSON.stringify(currentContextQuery.data.current_inputs) || snapshot.project?.project_id !== flow.project_id || !Array.isArray(snapshot.teams) || !Array.isArray(snapshot.attempts)) throw new Error("权威来源已变化，请重新加载并预览。");
    const preview = previewAssignments(base, { ...current, task_specs: contextQuery.data.task_specs }, changes.task_changes, snapshot.teams, snapshot.attempts.filter(a => !terminalStates.has(a.state)).map(a => a.task_id));
    const blocked = preview.findings.filter(f => f.severity === "BLOCKING");
    if (blocked.length) throw new Error(blocked.map(f => f.message).join("；"));
    const updates = new Map(changes.task_changes.map(change => [change.task_id, change]));
    if (updates.size !== changes.task_changes.length || !updates.size) throw new Error("分工变更必须包含不重复的有效任务。");
    const saved = await saveTasks(tasks.map(task => { const change = updates.get(task.task_id); return change ? { ...task, owner_id: change.owner_id, team_id: change.team_id } : task; }), contextQuery.data.task_specs, false, { flow_revision: changes.base_flow_revision, revision: changes.base_revision, source_revision: changes.context_source_revision });
    return !!saved;
  }
  function stageTasks(nextTasks: TaskCard[], nextSpecs = workingSpecs) {
    if (!baseFlow || !currentContextQuery.data) return;
    const original = new Map(baseFlow.tasks.map(task => [task.task_id, task]));
    const changes = Object.fromEntries(nextTasks.filter(task => (original.get(task.task_id) !== task && JSON.stringify(original.get(task.task_id)) !== JSON.stringify(task)) || (contextQuery.data?.task_specs[task.task_id] !== nextSpecs[task.task_id] && JSON.stringify(contextQuery.data?.task_specs[task.task_id]) !== JSON.stringify(nextSpecs[task.task_id]))).map(task => [task.task_id, { task, spec: nextSpecs[task.task_id] }]));
    setDraft({ project_id: baseFlow.project_id, base_flow_revision: draft?.base_flow_revision ?? baseFlow.flow_revision, base_revision: draft?.base_revision ?? baseFlow.revision, source_revision: draft?.source_revision ?? currentContextQuery.data.source_revision, changes });
    setCheckReport(undefined); setCheckOrigin(undefined); setDraftNotice('修改已暂存。集中预览后保存新草案。');
  }
  async function saveTask(task: TaskCard, spec: TaskSpec) {
    const updated = tasks.some(item => item.task_id === task.task_id) ? tasks.map(item => item.task_id === task.task_id ? task : item) : [...tasks, task];
    if (nextWorkbench) { stageTasks(updated, { ...workingSpecs, [task.task_id]: spec }); setEditing(undefined); }
    else await saveTasks(updated, { ...workingSpecs, [task.task_id]: spec });
  }
  async function saveDraft() {
    if (!draft || draftStale || readOnly) return;
    const saved = await saveTasks(tasks, workingSpecs, false, { flow_revision: draft.base_flow_revision, revision: draft.base_revision, source_revision: draft.source_revision });
    if (saved) { if (draftStorageKey) sessionStorage.removeItem(draftStorageKey); setDraft(undefined); setDraftNotice(`服务端已保存草案 R${saved.flow_revision}。`); }
  }
  async function seedExecution(body: { executor_profile_id: string; resource_profile_id: string; verification_plan_id: string; prompt: string; session_purpose: string; max_model_requests: number }) {
    if (!flow || !configuring) return;
    const result = await command.run<{ operation_id: string }>(`${flowPath(flow)}/tasks/${pathId(configuring.task_id)}/execution-templates`, body, flow.revision);
    if (result?.operation_id) { setTemplateOperationId(result.operation_id); setConfiguring(undefined); setSelectedTask(undefined); const params = new URLSearchParams(window.location.search); params.set('template_operation', result.operation_id); navigate(`${window.location.pathname}?${params}`, { replace: true }); }
  }
  async function addEdge(source: string, target: string) {
    if (!contextQuery.data || !contextQuery.data.task_specs[target] || source === target || tasks.find(task => task.task_id === target)?.dependencies.includes(source)) return;
    const spec = workingSpecs[target];
    const apply = nextWorkbench ? stageTasks : saveTasks;
    await apply(tasks.map(task => task.task_id === target ? { ...task, dependencies: [...task.dependencies, source] } : task), { ...workingSpecs, [target]: { ...spec, dependency_refs: [...spec.dependency_refs, { task_id: source, project_id: flow!.project_id, kind: 'integrated', binding_id: `${source}:integrated` }] } });
  }
  async function deleteEdge(id: string) {
    const edge = edges.find(item => item.id === id); if (!edge || !contextQuery.data) return;
    const spec = workingSpecs[edge.target];
    const apply = nextWorkbench ? stageTasks : saveTasks;
    await apply(tasks.map(task => task.task_id === edge.target ? { ...task, dependencies: task.dependencies.filter(dependency => dependency !== edge.source) } : task), spec ? { ...workingSpecs, [edge.target]: { ...spec, dependency_refs: spec.dependency_refs.filter(ref => ref.task_id !== edge.source) } } : contextQuery.data.task_specs);
  }
  const storedCheckPassed = !!flow && checkReport?.passed === true && checkOrigin?.kind === 'stored'
    && checkOrigin.projectId === flow.project_id && checkOrigin.flowRevision === flow.flow_revision && checkOrigin.revision === flow.revision;
  async function check() { if (!flow) return; setCheckReport(undefined); setCheckOrigin(undefined); const report = await command.run<CheckReport>(`${flowPath(flow)}/checks`, {}); if (report) { setCheckReport(report); setCheckOrigin({ kind: 'stored', projectId: flow.project_id, flowRevision: flow.flow_revision, revision: flow.revision }); flowQuery.reload(); } }
  async function commit() { if (!flow || !storedCheckPassed) return; const receipt = await command.run<FlowRevision>(`${flowPath(flow)}/commit`, {}, flow.revision); if (receipt) { reload(); setCheckReport(undefined); setCheckOrigin(undefined); } }
  async function createDraft() {
    if (!projectId) return;
    let currentLatest: FlowRevision | null;
    try { currentLatest = await readLatest(); } catch (cause) { setPreparationError(cause instanceof Error ? cause : new Error(String(cause))); return; }
    const nextRevision = (currentLatest?.flow_revision ?? 0) + 1;
    const saved = await command.run<FlowRevision>(`/projects/${pathId(projectId)}/flow-revisions`, { flow: { project_id: projectId, flow_revision: nextRevision, parent_revision: latest?.flow_revision ?? null, state: 'DRAFT', tasks: [], input_digest: '', approved_by: null, revision: 1 }, context: { requirements: [], requirement_semantic_digests: {}, owners: [], task_specs: {}, current_inputs: {}, resolved_paths: {}, contracts: [], source_revision: '', observed_at: '' } });
    if (saved) { chooseRevision(`${saved.project_id}:${saved.flow_revision}`); flowsQuery.reload(); latestQuery.reload(); }
  }
  function renderCheckReport(compact = false) {
    if (!checkReport) return null;
    return <Panel title={<span>{checkOrigin?.kind === 'unsaved' ? '未保存更改检查' : '已保存版本检查'} <StatusBadge state={checkReport.passed ? 'PASS' : 'BLOCKED'} /></span>}>
      <p className="muted">{checkOrigin?.kind === 'unsaved' ? '此次预览没有保存任务或依赖。保存草案后，仍须检查已保存版本才能审定。' : '报告绑定已保存版本；通过结构检查不等于业务验收。'} 输入身份：{checkReport.input_digest || '服务端未提供'}。</p>
      {checkReport.findings?.length ? compact ? <div role="list" style={{ display: 'grid', gap: 12, minWidth: 0 }}>
        {checkReport.findings.slice(checkPage * 50, (checkPage + 1) * 50).map(finding => <article role="listitem" className="notice" key={finding.finding_id} style={{ minWidth: 0, overflowWrap: 'anywhere' }}>
          <StatusBadge state={finding.severity} /> <code style={{ overflowWrap: 'anywhere' }}>{finding.rule_id}</code>
          <dl style={{ display: 'grid', gridTemplateColumns: 'minmax(0, 1fr)', gap: 6, marginBottom: 0 }}>
            <dt>对象</dt><dd style={{ margin: 0 }}>{typeof finding.subject_ref === 'string' ? finding.subject_ref : JSON.stringify(finding.subject_ref ?? '')}</dd>
            <dt>受阻任务</dt><dd style={{ margin: 0 }}>{finding.blocked_tasks?.join(' · ') || '未提供'}</dd>
            <dt>{finding.rule_id === 'DEPENDENCY_CYCLE' ? '闭环路径' : '定位依据'}</dt>
            <dd style={{ margin: 0 }}>{finding.evidence_refs?.map(ref => typeof ref === 'string' ? ref : JSON.stringify(ref)).join(finding.rule_id === 'DEPENDENCY_CYCLE' ? ' → ' : ' · ') || '未提供'}</dd>
            <dt>修复建议</dt><dd style={{ margin: 0 }}>{finding.suggested_action || '未提供'}</dd>
          </dl>
        </article>)}
      </div> : <DataTable rows={checkReport.findings.slice(checkPage * 50, (checkPage + 1) * 50)} rowKey={finding => finding.finding_id} columns={[
        { key: 'severity', label: '严重度', render: finding => <StatusBadge state={finding.severity} /> },
        { key: 'rule_id', label: '规则' }, { key: 'subject_ref', label: '对象', render: finding => String(finding.subject_ref ?? '') },
        { key: 'blocked_tasks', label: '受阻任务', render: finding => finding.blocked_tasks?.join(' · ') ?? '' },
        { key: 'evidence_refs', label: '定位依据', render: finding => JSON.stringify(finding.evidence_refs ?? []) },
        { key: 'suggested_action', label: '修复动作' },
      ]} onRowClick={finding => { if (finding.blocked_tasks?.[0]) selectTask(finding.blocked_tasks[0]); }} /> : <p>服务端报告未发现阻塞项。</p>}
      {!!checkReport.findings?.length && <div className="toolbar"><button disabled={!checkPage} onClick={() => setCheckPage(page => page - 1)}>上一页检查项</button><span>全部 {checkReport.findings.length} 项 · 第 {checkPage + 1} 页</span><button disabled={(checkPage + 1) * 50 >= checkReport.findings.length} onClick={() => setCheckPage(page => page + 1)}>下一页检查项</button></div>}
      {checkReport.impact !== undefined && (() => { const impact = checkReport.impact as { changed_task_ids: string[]; affected_task_ids: string[]; active_attempts: unknown[]; resource_findings: unknown[] }; return <div className="notice"><strong>变更与影响</strong><p>{impact.changed_task_ids.length} 张直接变更 · {impact.affected_task_ids.length} 张依赖影响 · {impact.active_attempts.length} 次活动尝试 · {impact.resource_findings.length} 项资源超限</p><details><summary>影响对象与资源详情</summary><JsonView value={impact} /></details></div>; })()}
      <details><summary>完整报告与来源</summary><JsonView value={checkReport} /></details>
    </Panel>;
  }
  if (!projectId) return <><PageHeader title="Flow 工作台" description="需求、责任和依赖形成可检查的规划版本。" /><EmptyState title="选择项目" description="从项目工作台进入 Flow，保持项目权威与稳定身份。" /></>;
  return <>
    <PageHeader title={nextWorkbench ? "规划工作台" : "Flow 工作台"} description={nextWorkbench ? "安排任务、明确分工，再检查并保存计划。" : "审阅有限结果与依赖。每次语义改动保留历史，提交版本后才允许准入。"} actions={<><button onClick={reload} aria-label="刷新 Flow"><RefreshCw size={16} /></button><button disabled={!canEdit} onClick={() => setEditing(newTask(projectId, flow!.flow_revision + 1))}><FilePlus2 size={16} />新增任务</button><button className="primary" hidden={nextWorkbench && !!draft} disabled={!flow || readOnly || command.busy || pendingConfig || !!draft} onClick={check}><Check size={16} />{command.busy ? '正在处理…' : '检查版本'}</button></>} />
    {nextWorkbench && (draftNotice || draft) && <div className="planning-draft-bar" role="status"><span>{draftStale ? '服务端版本已变化。草稿输入已保留，请核对后再保存。' : draftNotice}<small className="muted">{draft ? ` · ${Object.keys(draft.changes).length} 张任务待保存` : ''}</small></span>{draft && <><button disabled={command.busy || draftStale || readOnly} onClick={() => void previewTasks(tasks, workingSpecs)}>预览全部影响</button><button className="primary" disabled={command.busy || draftStale || readOnly || !Object.keys(draft.changes).length} onClick={() => void saveDraft()}>{command.busy ? '正在保存…' : '保存新草案'}</button>{draftStale && <button onClick={() => { if (baseFlow && currentContextQuery.data) setDraft({ ...draft, base_flow_revision: baseFlow.flow_revision, base_revision: baseFlow.revision, source_revision: currentContextQuery.data.source_revision }); setDraftNotice('草稿已基于最新版本恢复，请重新检查全部影响。'); }}>保留输入并重新预览</button>}<button disabled={command.busy} onClick={() => { setDraft(undefined); setDraftNotice('已放弃未保存更改。'); }}>放弃更改</button></>}</div>}
    {assignmentSnapshot.error && <ErrorNotice error={assignmentSnapshot.error} onRetry={assignmentSnapshot.reload} />}
    {command.error && <ErrorNotice error={command.error} />}
    {preparationError && <ErrorNotice error={preparationError} />}
    {latestQuery.error && !noFlow && <ErrorNotice error={latestQuery.error} onRetry={latestQuery.reload} />}
    {projectQuery.error && <ErrorNotice error={projectQuery.error} onRetry={projectQuery.reload} />}
    <QueryState retainContent={!!flowsQuery.data} loading={flowsQuery.loading && !flowsQuery.data} error={flowsQuery.error} onRetry={flowsQuery.reload}>
      {!flows.length && !flowsQuery.hasNext && !flow && (latestQuery.data === null || noFlow) ? <Panel><EmptyState title="还没有 Flow 版本" description="导入需求并启动真实规划，或创建人工草案。人工编辑不计作自动生成验收。" action={<div className="toolbar"><a className="button" href={`/projects/${pathId(projectId)}/requirements`}>导入需求</a><button disabled={readOnly || command.busy} onClick={createDraft}>创建空草案</button></div>} /></Panel> : <>
        <div className="toolbar flow-version-bar"><Workflow size={17} /><label>规划版本 <select aria-label="规划版本" value={requested ?? ''} onChange={event => chooseRevision(event.target.value)}>{flow && !flows.some(item => item.flow_revision === flow.flow_revision) && <option value={`${flow.project_id}:${flow.flow_revision}`}>R{flow.flow_revision} · {flow.state === 'DRAFT' ? '草案' : flow.state === 'COMMITTED' ? '已提交' : flow.state} · 当前版本</option>}{flows.map(item => <option value={`${item.project_id}:${item.flow_revision}`} key={item.flow_revision}>R{item.flow_revision} · {item.state === 'DRAFT' ? '草案' : item.state === 'COMMITTED' ? '已提交' : item.state}</option>)}</select></label>{flow && <StatusBadge state={flow.state} />}<span className="muted">{tasks.length} 张任务 · 父版本 {flow?.parent_revision ?? '无'}</span><div className="tabs" hidden={nextWorkbench}><button className={view === 'graph' ? 'active' : ''} onClick={() => setView('graph')}><GitBranch size={16} />依赖图</button><button className={view === 'table' ? 'active' : ''} onClick={() => setView('table')}><List size={16} />任务表</button></div><button hidden={nextWorkbench} disabled={!canEdit} onClick={() => { setJsonDraft(JSON.stringify(tasks, null, 2)); setShowJson(true); }}>批量 JSON 编辑</button>{flow && flow.state !== 'COMMITTED' && flow.state !== 'SUPERSEDED' && (!nextWorkbench || storedCheckPassed) && <button disabled={readOnly || command.busy || pendingConfig || !storedCheckPassed || !!draft} onClick={commit}><Play size={16} />审定并提交 R{flow.flow_revision}</button>}</div>
        {(flowsQuery.hasNext || flows.length > 1) && <details className="flow-history"><summary>浏览历史版本</summary><Pagination query={flowsQuery} count={flows.length} /></details>}
        {contextQuery.error && <ErrorNotice error={contextQuery.error} onRetry={contextQuery.reload} />}{currentContextQuery.error && <ErrorNotice error={currentContextQuery.error} onRetry={currentContextQuery.reload} />}
        {flow?.state === 'COMMITTED' && <div className="notice">当前版本已提交。编辑操作创建新的子版本，历史输入和尝试保持可追溯。</div>}
        <QueryState retainContent={!!flow} loading={flowQuery.loading && !flow} error={flowQuery.error} onRetry={flowQuery.reload}><Panel title={nextWorkbench ? undefined : "任务与依赖"}>{tasks.length ? nextWorkbench ? <PlanningWorkbench projectId={projectId} tasks={tasks} dependencies={edges} selectedId={selectedTask} readOnly={!canEdit} busy={command.busy} execution={attemptsByTask} executionAvailable={executionAvailable} onSelect={selectTask} onPatch={task => stageTasks(tasks.map(old => old.task_id === task.task_id ? task : old))} onConnect={addEdge} onDeleteDependency={deleteEdge} /> : view === 'graph' ? <DagEditor tasks={tasks.map(task => ({ id: task.task_id, title: task.title, owner: task.owner_id, state: task.state, executionState: attemptsByTask.get(task.task_id)?.[0]?.state, executionAvailable }))} dependencies={edges} selectedId={selectedTask} readOnly={!canEdit} busy={command.busy} onSelect={selectTask} onConnect={addEdge} onDeleteDependency={deleteEdge} /> : <><DataTable columns={executionColumns} rows={tasks.slice(taskPage * 100, (taskPage + 1) * 100)} rowKey={task => task.task_id} onRowClick={task => selectTask(task.task_id)} /><div className="toolbar"><button disabled={taskPage === 0} onClick={() => setTaskPage(value => value - 1)}>上一页任务</button><span>完整 Flow 内第 {taskPage + 1} 页 · 全部 {tasks.length} 张卡</span><button disabled={(taskPage + 1) * 100 >= tasks.length} onClick={() => setTaskPage(value => value + 1)}>下一页任务</button></div></> : <EmptyState title="草案还没有任务" description="添加任务并明确输入、责任、合同和验证，再运行完整检查。" />}</Panel></QueryState>
      </>}
    </QueryState>
    {templateOperationId && (!templateOperation.data || templateOperation.data.project_id === projectId) && <Panel title={<span>执行配置操作 <StatusBadge state={templateOperation.data?.status === 'SUCCEEDED' ? '执行配置已保存' : templateOperation.data?.status === 'ACCEPTED' ? '配置请求已接收' : templateOperation.data?.status} /></span>}><code>{templateOperationId}</code>{templateOperation.error && <ErrorNotice error={templateOperation.error} onRetry={templateOperation.reload} />}<JsonView value={templateOperation.data} /></Panel>}
    {changes && <Panel title={`相较父版本 R${parent?.flow_revision}`}><details><summary>新增 {changes.added.length} · 移除 {changes.removed.length} · 修改 {changes.changed.length} 张卡</summary><JsonView value={Object.fromEntries(Object.entries(changes).map(([kind, cards]) => [kind, cards.map(task => ({ task_id: task.task_id, title: task.title, owner_id: task.owner_id, task_revision: task.task_revision, input_digest: task.input_digest }))]))} /></details></Panel>}
    <details className="flow-observation-details"><summary>数据来源与执行观察</summary>
    <SourceStamp source={flowQuery.metadata.source ?? flowsQuery.metadata.source} observedAt={flowQuery.metadata.observed_at ?? flowsQuery.metadata.observed_at} />
    <p className="muted" aria-label="Flow 执行观察来源">执行观察：{executionAvailable ? `${assignmentSnapshot.data!.source} · 项目游标 ${assignmentSnapshot.data!.revision} · ${assignmentSnapshot.data!.as_of}` : '尚未取得同项目权威快照'}。图与表共用任务 ID 和任务修订；最近尝试状态独立于规划状态。</p>
    </details>
    {nextWorkbench && <details className="notice"><summary>高级批量检查与编辑</summary><button disabled={!canEdit} onClick={() => { setJsonDraft(JSON.stringify(tasks, null, 2)); setShowJson(true); }}>打开任务 JSON 编辑器</button></details>}
    <details id="assignment-workspace" className="assignment-disclosure" open={!nextWorkbench || undefined} onToggle={event => { if (event.currentTarget.open) setAssignmentMounted(true); }}><summary><span>批量分工</span><small>选择任务 → 调整责任 → 预览影响</small></summary>
    {assignmentMounted && flow && <AssignmentBoard flow={flow} context={assignmentContext} historicalContext={contextQuery.data} teams={assignmentSnapshot.data?.teams ?? []} teamsComplete={assignmentCoverage} activeTaskIds={assignmentActiveIds} activeTasksComplete={assignmentCoverage} readOnly={!canEdit} busy={command.busy} onSave={draft ? undefined : saveAssignment} onPreview={preview => { const changes = new Map(preview.changeSet.task_changes.map(change => [change.task_id, change])); void previewTasks(tasks.map(task => { const change = changes.get(task.task_id); return change ? { ...task, owner_id: change.owner_id, team_id: change.team_id } : task; }), workingSpecs); }} onSelectTask={selectTask} />}
    </details>
    {flow && <details className="notice"><summary>输入身份或合同格式升级后的重新封存</summary><p>建立新草案并提升所有任务定义版本，重新核验当前来源。服务端拒绝覆盖活动尝试；重新封存不会授权运行或继承验收结果。</p><button disabled={!canEdit} onClick={() => saveTasks(tasks, contextQuery.data?.task_specs, true)}>重新封存任务定义</button></details>}
    {renderCheckReport()}
    {selected && inspectorOpen && !editing && !configuring && <TaskInspector task={selected} spec={currentSpec} onClose={clearTaskSelection} onSelectTask={selectTask} actions={<><button className="primary" disabled={!canEdit} onClick={() => setEditing(selected)}>编辑任务</button><button disabled={!canEdit || flow?.state === 'COMMITTED' || flow?.state === 'SUPERSEDED'} onClick={() => setConfiguring(selected)}>配置执行</button></>} />}
    {editing && <Drawer title={tasks.some(task => task.task_id === editing.task_id) ? '编辑任务 · 新草案版本' : '新增有限任务'} onClose={() => !command.busy && setEditing(undefined)}><p className="muted">保存前会检查未保存更改；环与缺失前置保留本地草案并显示定位。</p>{checkOrigin?.kind === 'unsaved' && renderCheckReport(true)}<TaskForm key={editing.task_id} task={editing} spec={workingSpecs[editing.task_id]} tasks={tasks} requirements={editorRequirements} requirementDigests={currentContextQuery.data?.requirement_semantic_digests ?? {}} busy={command.busy} error={command.error} onSave={saveTask} onCancel={() => setEditing(undefined)} /></Drawer>}
    {configuring && flow && <Drawer title="绑定执行器与独立验证" onClose={() => !command.busy && setConfiguring(undefined)}><ExecutionSetupForm task={configuring} spec={contextQuery.data?.task_specs[configuring.task_id]} busy={command.busy} error={command.error} onSave={seedExecution} /></Drawer>}
    {showJson && <Drawer title="批量任务编辑" onClose={() => !command.busy && setShowJson(false)}><p>提交完整任务数组建立新版本。任务语义合同保持原绑定；新增任务随后通过表单补齐。</p>{checkOrigin?.kind === 'unsaved' && renderCheckReport(true)}<Field label="TaskCard JSON 数组"><textarea rows={25} value={jsonDraft} onChange={event => setJsonDraft(event.target.value)} spellCheck={false} /></Field>{jsonError && <ErrorNotice error={jsonError} />}<button disabled={command.busy} onClick={() => { try { const value: unknown = parseStrictJson(jsonDraft); if (!Array.isArray(value)) throw new Error('必须为任务数组'); setJsonError(undefined); void previewTasks(value as TaskCard[]); } catch (cause) { setJsonError(cause instanceof Error ? cause : new Error(String(cause))); } }}>检查未保存更改</button><button className="primary" disabled={command.busy} onClick={() => { try { const value: unknown = parseStrictJson(jsonDraft); if (!Array.isArray(value)) throw new Error('必须为任务数组'); setJsonError(undefined); if (nextWorkbench) { stageTasks(value as TaskCard[], workingSpecs); setShowJson(false); } else void saveTasks(value as TaskCard[]); } catch (cause) { setJsonError(cause instanceof Error ? cause : new Error(String(cause))); } }}>保存新草案版本</button></Drawer>}
  </>;
}

export function TasksPage(props: PageProps) { return <TaskListWorkspace key={props.projectId} {...props} />; }
function TaskListWorkspace({ projectId, taskId }: PageProps) {
  const [params, setParams] = useSearchParams(); const navigate = useNavigate();
  const [search, setSearch] = useState(params.get('task_q') ?? '');
  const [debounced, setDebounced] = useState(search);
  useEffect(() => { const timer = setTimeout(() => setDebounced(search.trim()), 220); return () => clearTimeout(timer); }, [search]);
  const owner = params.get('owner') ?? '', state = params.get('state') ?? '', sort = params.get('sort') ?? 'task_id';
  const root = projectId ? `/projects/${pathId(projectId)}` : undefined;
  const filters = new URLSearchParams({ limit: '100', sort });
  if (debounced) filters.set('q', debounced); if (owner) filters.set('owner', owner); if (state) filters.set('state', state);
  const query = useCursorApi<TaskCard[]>(root ? `${root}/tasks?${filters}` : null, 'task_cursor');
  const selectedId = params.get('task') ?? taskId;
  const detail = useApi<TaskCard>(selectedId && root ? `${root}/tasks/${pathId(selectedId)}` : null);
  const project = useApi<{ authority_mode: string; archived: boolean }>(root ?? null);
  const owners = useApi<{ owner_id: string }[]>(root ? `${root}/owners` : null);
  const command = useCommand(); const [actionResult, setActionResult] = useState<unknown>();
  const tasks = items(query.data); const selected = detail.data ?? tasks.find(t => t.task_id === selectedId);
  const writable = project.data?.authority_mode === 'MANAGED' && !project.data.archived;
  function change(key: string, value: string) { setParams(prior => { const next = new URLSearchParams(prior); if (value) next.set(key, value); else next.delete(key); next.delete('task_cursor'); return next; }, { replace: true }); }
  function select(id: string) { setActionResult(undefined); setParams(prior => { const next = new URLSearchParams(prior); next.set('task', id); return next; }, { replace: true }); }
  function close() { const next = new URLSearchParams(params); next.delete('task'); navigate(`${root}/tasks${next.size ? `?${next}` : ''}`, { replace: true }); }
  async function action(path: string, body: unknown, revision?: number) { const result = await command.run<unknown>(path, body, revision); if (result) { setActionResult(result); query.reload(); detail.reload(); } }
  return <><PageHeader title="任务" description="在全部项目任务中搜索、筛选和排序；规划、执行和验收分别追溯。" actions={root && <a className="button primary" href={`${root}/flows`}>打开规划工作台</a>} />
    {!root ? <EmptyState title="选择项目查看任务" /> : <><SourceStamp source={query.metadata.source} observedAt={query.metadata.observed_at} />
      <div className="toolbar"><Search size={16} /><input aria-label="搜索全部项目任务" placeholder="搜索全部卡号或交付结果" value={search} onChange={event => { setSearch(event.target.value); change('task_q', event.target.value); }} />
        <select aria-label="任务 Owner" value={owner} onChange={event => change('owner', event.target.value)}><option value="">全部 Owner</option>{owners.data?.map(o => <option key={o.owner_id}>{o.owner_id}</option>)}</select>
        <select aria-label="任务规划状态" value={state} onChange={event => change('state', event.target.value)}><option value="">全部规划状态</option>{Object.keys(planningExplanations).map(value => <option key={value}>{value}</option>)}</select>
        <select aria-label="任务排序" value={sort} onChange={event => change('sort', event.target.value)}><option value="task_id">按编号</option><option value="title">按标题</option><option value="owner_id">按 Owner</option><option value="state">按规划状态</option></select>
        <span className="muted">当前页 {tasks.length} · 全部匹配 {query.metadata.total_count ?? '计算中'} 张</span><button onClick={query.reload}><RefreshCw size={16} />{query.refreshing ? '正在更新…' : '刷新'}</button></div>
      <QueryState retainContent={!!query.data} loading={query.loading && !query.data} error={query.error} onRetry={query.firstPage}><Panel><DataTable selectedKey={selectedId} columns={taskColumns} rows={tasks} rowKey={task => task.task_id} onRowClick={task => select(task.task_id)} empty={<EmptyState title="没有匹配任务" description="调整搜索或筛选范围。" />} /><Pagination query={query} count={tasks.length} /></Panel></QueryState>
      {detail.error && <ErrorNotice error={detail.error} onRetry={detail.reload} />}</>}
    {selected && <TaskInspector task={selected} onClose={close} onSelectTask={select} actions={<><button disabled={!writable || command.busy} onClick={() => action(`/projects/${pathId(selected.project_id)}/tasks/${pathId(selected.task_id)}/admission-checks`, {})}>预检查准入</button><button disabled={!writable || command.busy} onClick={() => action('/queue-entries', { project_id: selected.project_id, task_id: selected.task_id, priority: 0, lease_seconds: 30, worker_id: '', worker_scope_id: '', scope_ids: [] }, selected.revision)}>合法入队</button><a className="button" href={`/projects/${pathId(selected.project_id)}/flows/${selected.flow_revision}?task=${pathId(selected.task_id)}`}>编辑规划</a>{command.error && <ErrorNotice error={command.error} />}{actionResult !== undefined && <details open><summary>服务端动作回执</summary><JsonView value={actionResult} /></details>}</>} />}
  </>;
}

function ExecutionSetupForm({ task, spec, busy, error, onSave }: {
  task: TaskCard; spec?: TaskSpec; busy: boolean; error?: Error;
  onSave: (value: { executor_profile_id: string; resource_profile_id: string; verification_plan_id: string; prompt: string; session_purpose: string; max_model_requests: number }) => void;
}) {
  const root = `/projects/${pathId(task.project_id)}/documents`;
  const profiles = useCompleteApi<{ id: string }>(`${root}/executor_profiles`);
  const resources = useCompleteApi<{ id: string }>(`${root}/resource_profiles`);
  const verifiers = useCompleteApi<{ plan_id: string }>(`${root}/verification_plans`);
  const [executor, setExecutor] = useState(spec?.execution_profile ?? '');
  const [resource, setResource] = useState('');
  const [verifier, setVerifier] = useState(spec?.verification_plan ?? '');
  const [prompt, setPrompt] = useState(spec?.outcome ?? task.title);
  const [purpose, setPurpose] = useState(task.write_set.length ? 'EXECUTION' : 'REVIEW');
  const [requests, setRequests] = useState(8);
  const ready = profiles.data && resources.data && verifiers.data;
  return <form onSubmit={event => { event.preventDefault(); onSave({ executor_profile_id: executor, resource_profile_id: resource, verification_plan_id: verifier, prompt, session_purpose: purpose, max_model_requests: requests }); }}>
    <p>服务端从真实输入、Git 基线和已登记独立验证生成执行配置。此动作不签发尝试、工作树或租约；配置完成后重新检查并审定 Flow。</p>
    {[profiles, resources, verifiers].map((query, index) => query.error && <ErrorNotice key={index} error={query.error} onRetry={query.reload} />)}
    <Field label="执行器 Profile"><select required value={executor} onChange={event => setExecutor(event.target.value)}><option value="">选择已登记 DSH 执行器</option>{profiles.data?.map(profile => <option value={profile.id} key={profile.id}>{profile.id}</option>)}</select></Field>
    <Field label="资源 Profile"><select required value={resource} onChange={event => setResource(event.target.value)}><option value="">选择资源配置</option>{resources.data?.map(profile => <option value={profile.id} key={profile.id}>{profile.id}</option>)}</select></Field>
    <Field label="独立验证模板"><select required value={verifier} onChange={event => setVerifier(event.target.value)}><option value="">选择登记的验证计划</option>{verifiers.data?.map(plan => <option value={plan.plan_id} key={plan.plan_id}>{plan.plan_id}</option>)}</select></Field>
    <Field label="会话用途"><select value={purpose} onChange={event => setPurpose(event.target.value)}><option value="EXECUTION">代码执行与受控集成</option><option value="REVIEW">只读审查与结构化产物</option></select></Field>
    <Field label="模型请求预算声明" hint="实际强制范围以执行器与网关资格为准。"><input type="number" min={1} max={1000} step={1} required value={requests} onChange={event => setRequests(Number(event.target.value))} /></Field>
    <Field label="有限任务指令"><textarea rows={8} required value={prompt} onChange={event => setPrompt(event.target.value)} /></Field>
    <details><summary>回读将绑定的输入与写集合</summary><JsonView value={{ task_id: task.task_id, task_revision: task.task_revision, read_set: task.read_set, write_set: task.write_set, inputs: spec?.inputs, mandatory_paths: spec?.mandatory_paths }} /></details>
    {error && <ErrorNotice error={error} />}
    <button className="primary" disabled={busy || !ready || [profiles, resources, verifiers].some(query => query.loading || query.error)}>{busy ? '正在创建配置操作…' : '生成真实执行配置'}</button>
  </form>;
}
