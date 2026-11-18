import { useEffect, useRef, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Archive, Check, Download, FileCheck2, GitBranch, Plus, RefreshCw, RotateCcw } from 'lucide-react';
import { api, ApiError, getToken, items, useApi, useCursorApi } from './api';
import { EmptyState, ErrorNotice, Field, JsonView, PageHeader, Pagination, Panel, QueryState, SourceStamp } from '../components';
import { useCompleteApi } from '../features/flow/types';
import './releases.css';

type ReleaseState = 'DRAFT' | 'CANDIDATE' | 'ACCEPTED';
interface MilestoneRef { milestone_id: string; milestone_revision: number; baseline_version: number }
interface EvidenceRef { task_id?: string; task_revision?: number; integrated_sha?: string; integrated_log_sha256?: string; verification_plan_id?: string; verification_plan_hash?: string; source_tree_oid?: string; environment?: unknown; [key: string]: unknown }
interface Acceptance extends MilestoneRef { project_id: string; status: string; accepted_at?: string; accepted_by?: string; conditions?: { requirement_refs?: { requirement_id: string; revision: number }[]; task_refs?: Record<string, unknown>[]; required_gate_ids?: string[] }; evidence_refs?: EvidenceRef[]; [key: string]: unknown }
interface Milestone { project_id: string; milestone_id: string; revision: number; baseline_version: number; title: string }
interface Manifest {
  main_sha: string; main_tree_oid: string; milestone_acceptances: Acceptance[];
  files: { artifact_id: string; sha256: string; bytes: number }[];
  installation: string; not_proven: string[]; risk_dispositions: string[];
  scope: string; production_gate_claim: string; export_scope: string; [key: string]: unknown;
}
interface Release {
  release_id: string; project_id: string; phase_id: string; revision: number; title: string; state: ReleaseState;
  milestone_refs: MilestoneRef[]; installation: string; not_proven: string[]; risk_dispositions: string[];
  created_by: string; created_at: string; updated_at: string; candidate_by: string | null; candidate_at: string | null;
  accepted_by: string | null; accepted_at: string | null; acceptance_note: string | null;
  manifest: Manifest | null; manifest_sha256: string | null;
}
interface Phase { phase_id: string; project_id: string; ordinal: number; previous_release_id: string | null; title: string; goal: string; baseline_main_sha: string; created_by: string; created_at: string; revision: number }
interface Project { project_id: string; authority_mode: string; archived: boolean; paused: boolean; revision: number; goal: string }
interface ExportReceipt { schema_version: string; export_id: string; project_id: string; release_id: string; manifest_sha256: string; artifact: { artifact_id: string; sha256: string }; bytes: number; bundle: { artifact_id: string; sha256: string }; bundle_bytes: number; source_archive_sha256: string; exported_by: string; exported_at: string; revision: number }
interface Outcome { release: Release; project: Project; phase: Phase; export: ExportReceipt | null; accepted: boolean }
type Action = 'candidate' | 'accept' | 'export' | 'archive' | 'reopen';
interface Preview { action: Action; release: Release; project: Project }
const path = (value: string) => encodeURIComponent(value);
const time = (value?: string | null) => value ? new Date(value).toLocaleString() : '未记录';
const lines = (value: string) => value.split(/\r?\n/).map(line => line.trim()).filter(Boolean);
const labels: Record<ReleaseState, string> = { DRAFT: '草案', CANDIDATE: '候选', ACCEPTED: '已接受' };
const actionNames: Record<Action, string> = { candidate: '形成候选', accept: '接受候选', export: '导出交付包', archive: '归档项目', reopen: '重开新阶段' };
const unwrap = <T,>(rows: (T | { value: T })[] | undefined): T[] => (rows ?? []).map(row => row && typeof row === 'object' && 'value' in row ? (row as { value: T }).value : row as T);

export function ReleasesPage({ projectId, releaseId }: { projectId?: string; releaseId?: string }) {
  const navigate = useNavigate();
  const root = projectId ? `/projects/${path(projectId)}` : null;
  const catalog = useCursorApi<Release[]>(root ? `${root}/releases` : null, 'release_cursor');
  const detail = useApi<Release>(root && releaseId ? `${root}/releases/${path(releaseId)}` : null);
  const project = useApi<Project>(root);
  const phases = useCompleteApi<Phase>(root ? `${root}/phases` : null);
  const milestones = useCompleteApi<Milestone>(root ? `${root}/milestones` : null);
  const acceptances = useCompleteApi<Acceptance | { value: Acceptance }>(root ? `${root}/documents/milestone_acceptances` : null);
  const exports = useCompleteApi<ExportReceipt>(root && releaseId ? `${root}/releases/${path(releaseId)}/exports` : null);
  const [search, setSearch] = useState('');
  const [state, setState] = useState<ReleaseState | ''>('');
  const [creating, setCreating] = useState(false);
  const [title, setTitle] = useState('');
  const [installation, setInstallation] = useState('');
  const [notProven, setNotProven] = useState('');
  const [risks, setRisks] = useState('');
  const [chosen, setChosen] = useState<string[]>([]);
  const [preview, setPreview] = useState<Preview>();
  const [mainSha, setMainSha] = useState('');
  const [reason, setReason] = useState('');
  const [phaseTitle, setPhaseTitle] = useState('');
  const [phaseGoal, setPhaseGoal] = useState('');
  const [error, setError] = useState<Error>();
  const [notice, setNotice] = useState('');
  const [busy, setBusy] = useState(false);
  const [downloaded, setDownloaded] = useState<{ releaseId: string; sha256: string; bytes: number; kind: 'manifest' | 'bundle' }>();
  const keys = useRef(new Map<string, string>());
  const running = useRef(false);
  const current = useRef({ projectId, releaseId }); current.current = { projectId, releaseId };
  const release = detail.data?.project_id === projectId && detail.data?.release_id === releaseId ? detail.data : undefined;
  const currentProject = project.data;
  const managed = !!currentProject && currentProject.project_id === projectId && currentProject.authority_mode === 'MANAGED';
  const liveProject = managed && !project.data?.archived && !project.loading && !project.error;
  const readyDetail = !!release && !detail.loading && !detail.error;
  const phase = release ? phases.data?.find(item => item.phase_id === release.phase_id && item.project_id === projectId) : undefined;
  const latestPhase = phases.data?.filter(item => item.project_id === projectId).sort((a, b) => b.ordinal - a.ordinal)[0];
  const judgments = unwrap<Acceptance>(acceptances.data);
  const eligible = !milestones.loading && !milestones.error && !acceptances.loading && !acceptances.error ? milestones.data?.filter(item => judgments.some(judgment => judgment.project_id === projectId && judgment.milestone_id === item.milestone_id && judgment.milestone_revision === item.revision && judgment.baseline_version === item.baseline_version && judgment.status === 'ACCEPTED')) ?? [] : [];
  const exportRows = (exports.data ?? []).filter(item => item.project_id === projectId && item.release_id === releaseId);
  const matchingExport = release ? exportRows.find(item => item.manifest_sha256 === release.manifest_sha256) : undefined;
  const rows = items(catalog.data).filter(item => (!state || item.state === state) && (!search || `${item.title} ${item.release_id} ${item.phase_id}`.toLowerCase().includes(search.toLowerCase())));

  useEffect(() => { setCreating(false); setChosen([]); setPreview(undefined); setDownloaded(undefined); setError(undefined); setNotice(''); }, [projectId]);
  useEffect(() => { setPreview(undefined); setDownloaded(undefined); }, [releaseId]);
  useEffect(() => {
    const refresh = (event: Event) => {
      const value = (event as CustomEvent<{ projectId?: string; kind?: string }>).detail;
      if (value?.projectId !== projectId || !/^(release\.|phase\.|project\.|milestone\.)/.test(value.kind ?? '')) return;
      catalog.reload(); detail.reload(); project.reload(); phases.reload(); exports.reload();
    };
    window.addEventListener('forgeflow-event', refresh); return () => window.removeEventListener('forgeflow-event', refresh);
  }, [projectId, catalog.reload, detail.reload, project.reload, phases.reload, exports.reload]);
  function reload() { catalog.reload(); detail.reload(); project.reload(); phases.reload(); milestones.reload(); acceptances.reload(); exports.reload(); }
  function reviewLatest() { setPreview(undefined); setError(undefined); setNotice('正在回读最新权威版本，请核对后重新预览。'); reload(); }
  function select(id: string) { if (root) navigate(`${root}/releases/${path(id)}`); }
  async function command(commandPath: string, body: Record<string, unknown>, label: string) {
    if (running.current || !root || !managed) return;
    const identity = JSON.stringify([commandPath, body]);
    let key = keys.current.get(identity); if (!key) { key = crypto.randomUUID(); keys.current.set(identity, key); }
    running.current = true; setBusy(true); setError(undefined); setNotice('');
    let accepted = false;
    try {
      const receipt = await api.post<Outcome>(commandPath, body, { idempotencyKey: key }); accepted = true;
      if (receipt.release.project_id !== projectId || receipt.project.project_id !== projectId) throw new Error('回执项目身份不匹配。');
      const [actual, actualProject] = await Promise.all([api.get<Release>(`${root}/releases/${path(receipt.release.release_id)}`), api.get<Project>(root)]);
      if (actual.project_id !== projectId || actual.release_id !== receipt.release.release_id || actualProject.project_id !== projectId) throw new Error('Release 或项目权威回读身份不匹配。');
      keys.current.delete(identity);
      if (current.current.projectId !== projectId) return;
      setPreview(undefined); setCreating(false); select(actual.release_id);
      setNotice(`${label}已由服务端处理。当前 Release：${labels[actual.state]}；项目${actualProject.archived ? '已归档' : actualProject.paused ? '保持暂停' : '未暂停'}。`);
      reload();
    } catch (cause) {
      if (current.current.projectId !== projectId) return;
      setError(cause instanceof Error ? cause : new Error(String(cause)));
      if (accepted) setNotice('服务端已返回回执，但权威回读未完成。保留同一请求身份，可重试或刷新记录。');
    } finally { running.current = false; setBusy(false); }
  }
  function createDraft() {
    if (!root || !project.data || !title.trim() || !installation.trim() || !chosen.length) return;
    const refs = eligible.filter(item => chosen.includes(item.milestone_id)).map(item => ({ milestone_id: item.milestone_id, milestone_revision: item.revision, baseline_version: item.baseline_version }));
    if (refs.length !== chosen.length) { setError(new Error('所选里程碑验收或版本已变化，请重新读取并选择。')); return; }
    void command(`${root}/releases`, { expected_project_revision: project.data.revision, title: title.trim(), milestone_refs: refs, installation: installation.trim(), not_proven: lines(notProven), risk_dispositions: lines(risks) }, '建立草案');
  }
  function begin(action: Action) {
    if (!release || !project.data || !readyDetail || busy) return;
    setPreview({ action, release, project: project.data }); setReason(''); setPhaseTitle(''); setPhaseGoal('');
    setMainSha(phase?.baseline_main_sha ?? ''); setError(undefined); setNotice('');
  }
  function submit() {
    if (!preview || !root) return;
    const target = `${root}/releases/${path(preview.release.release_id)}`;
    const base = { expected_revision: preview.release.revision };
    if (preview.action === 'candidate') {
      if (!/^[a-f0-9]{40}$/.test(mainSha.trim())) { setError(new Error('填写真实当前主线的完整 40 位 Git SHA。')); return; }
      void command(`${target}/candidates`, { ...base, expected_main_sha: mainSha.trim() }, actionNames.candidate);
    } else if (preview.action === 'accept') {
      if (!preview.release.manifest_sha256 || !reason.trim()) return;
      void command(`${target}/acceptances`, { ...base, expected_manifest_sha256: preview.release.manifest_sha256, note: reason.trim() }, actionNames.accept);
    } else if (preview.action === 'export') void command(`${target}/exports`, base, actionNames.export);
    else if (preview.action === 'archive') {
      if (!reason.trim()) return;
      void command(`${target}/archives`, { ...base, expected_project_revision: preview.project.revision, reason: reason.trim() }, actionNames.archive);
    } else {
      if (!reason.trim() || !phaseTitle.trim() || !phaseGoal.trim()) return;
      void command(`${target}/reopenings`, { ...base, expected_project_revision: preview.project.revision, title: phaseTitle.trim(), goal: phaseGoal.trim(), reason: reason.trim() }, actionNames.reopen);
    }
  }
  async function download(kind: 'manifest' | 'bundle' = 'manifest') {
    if (!release || !root || !release.manifest_sha256 || busy || running.current) return;
    const expectedSha = kind === 'bundle' ? matchingExport?.bundle?.sha256 : release.manifest_sha256;
    const expectedBytes = kind === 'bundle' ? matchingExport?.bundle_bytes : matchingExport?.bytes;
    if (!expectedSha || (kind === 'bundle' && !Number.isSafeInteger(expectedBytes))) return;
    running.current = true; setBusy(true); setError(undefined); setDownloaded(undefined);
    try {
      const response = await fetch(`/api/v1${root}/releases/${path(release.release_id)}/${kind}`, { credentials: 'omit', headers: { Authorization: `Bearer ${getToken()}` } });
      if (!response.ok) { const body = await response.json().catch(() => ({ code: 'DOWNLOAD_FAILED', message: `下载失败 (${response.status})` })); throw new ApiError(response.status, body); }
      const bytes = await response.arrayBuffer();
      const digest = Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256', bytes)), value => value.toString(16).padStart(2, '0')).join('');
      if (digest !== expectedSha || (expectedBytes !== undefined && expectedBytes !== bytes.byteLength)) throw new Error('下载字节与服务端登记的 SHA256 或字节数不匹配，未提交下载文件。');
      const url = URL.createObjectURL(new Blob([bytes], { type: kind === 'bundle' ? 'application/x-tar' : 'application/json' }));
      const link = document.createElement('a'); link.href = url; link.download = `${release.release_id}.${kind === 'bundle' ? 'bundle.tar' : 'manifest.json'}`; link.click(); window.setTimeout(() => URL.revokeObjectURL(url), 1000);
      if (current.current.projectId === projectId && current.current.releaseId === release.release_id) setDownloaded({ releaseId: release.release_id, sha256: digest, bytes: bytes.byteLength, kind });
    } catch (cause) { setError(cause instanceof Error ? cause : new Error(String(cause))); }
    finally { running.current = false; setBusy(false); }
  }
  const conflict = error instanceof ApiError && (error.status === 409 || /STALE|CONFLICT/.test(error.code));
  const manifest = release?.manifest;
  const evidence = manifest?.milestone_acceptances.flatMap(judgment => judgment.evidence_refs ?? []) ?? [];

  return <>
    <PageHeader title="项目 Release" description="审阅已集成交付与独立里程碑验收，保留清单、下载和阶段历史。" actions={<><button disabled={busy} onClick={reload}><RefreshCw size={16} />刷新</button><button data-testid="release-create" disabled={!liveProject || busy} onClick={() => { setCreating(value => !value); setPreview(undefined); }}><Plus size={16} />建立草案</button></>} />
    {!root ? <Panel><EmptyState title="选择项目查看 Release" /></Panel> : <>
      <div className="release-toolbar"><Field label="状态"><select value={state} onChange={event => setState(event.target.value as ReleaseState | '')}><option value="">全部状态</option>{Object.entries(labels).map(([value, label]) => <option value={value} key={value}>{label}</option>)}</select></Field><div className="release-search"><Field label="检索当前页"><input value={search} onChange={event => setSearch(event.target.value)} placeholder="Release 名称、身份或阶段" /></Field></div><span className="muted">项目{project.data?.archived ? '已归档' : project.data?.paused ? '暂停新增' : project.data ? '未暂停' : '状态未读取'}</span></div>
      <SourceStamp source={catalog.metadata.source} observedAt={catalog.metadata.observed_at} />
      {error && <ErrorNotice error={error} />}{conflict && <div className="notice">版本、验收或主线已变化，请核对真实来源。<button disabled={busy} onClick={reviewLatest}>读取最新版本并重新预览</button></div>}{notice && <p role="status" className="notice">{notice}</p>}
      {project.error && <ErrorNotice error={project.error} onRetry={project.reload} />}
      {creating && <Panel title="建立真实交付草案"><div className="release-content"><QueryState loading={milestones.loading || acceptances.loading} error={milestones.error ?? acceptances.error} onRetry={() => { milestones.reload(); acceptances.reload(); }}>
        <form onSubmit={event => { event.preventDefault(); createDraft(); }}><Field label="Release 名称"><input data-testid="release-create-title" required value={title} disabled={busy} onChange={event => setTitle(event.target.value)} /></Field>
          <div className="release-selection" data-testid="release-milestones">{eligible.length ? eligible.map(item => <label key={item.milestone_id}><input type="checkbox" data-testid={`release-milestone-${item.milestone_id}`} checked={chosen.includes(item.milestone_id)} disabled={busy} onChange={event => setChosen(event.target.checked ? [...chosen, item.milestone_id] : chosen.filter(id => id !== item.milestone_id))} /><span>{item.title}<small>{item.milestone_id} · 当前定义 {item.revision} · 已验收基线 {item.baseline_version}</small></span></label>) : <EmptyState title="尚无与当前版本匹配的里程碑验收" description="先在日程与里程碑页面接受真实基线，再选择该范围。" action={<a href={`/calendar?project=${path(projectId ?? '')}`}>打开里程碑验收</a>} />}</div>
          <Field label="安装与复现说明"><textarea data-testid="release-installation" required rows={4} value={installation} disabled={busy} onChange={event => setInstallation(event.target.value)} /></Field>
          <Field label="未证明项 · 每行一项"><textarea data-testid="release-not-proven" rows={3} value={notProven} disabled={busy} onChange={event => setNotProven(event.target.value)} /></Field><Field label="风险处理 · 每行一项"><textarea data-testid="release-risks" rows={3} value={risks} disabled={busy} onChange={event => setRisks(event.target.value)} /></Field>
          <p className="notice">仅绑定所选里程碑的实际定义、基线和验收来源。候选清单由服务端从真实主线与产物生成。</p><div className="toolbar"><button data-testid="release-create-submit" className="primary" disabled={busy || !liveProject || !title.trim() || !installation.trim() || !chosen.length}>建立并回读草案</button><button type="button" disabled={busy} onClick={() => setCreating(false)}>取消</button></div>
        </form></QueryState></div></Panel>}
      <div className="release-layout"><Panel title={`Release · 当前页 ${rows.length}`}><div className="release-content"><QueryState loading={catalog.loading && !catalog.data} error={catalog.error} onRetry={catalog.reload}>
        {rows.length ? <div className="release-list">{rows.map(item => <button className="release-item" data-testid={`release-item-${item.release_id}`} key={item.release_id} aria-current={item.release_id === releaseId ? 'true' : undefined} disabled={busy} onClick={() => select(item.release_id)}><span className="release-item-header"><FileCheck2 size={16} /><span className="release-state">{labels[item.state]}</span></span><strong>{item.title}</strong><code>{item.release_id}</code><small className="muted">{item.milestone_refs.length} 个里程碑 · {time(item.updated_at)}</small></button>)}</div> : <EmptyState title={items(catalog.data).length ? '当前页没有匹配 Release' : '当前页还没有 Release'} description="选择实际已验收里程碑，建立第一份交付草案。" />}<Pagination query={catalog} count={items(catalog.data).length} />
      </QueryState></div></Panel>
      <div className="release-detail" data-testid="release-detail" data-release-id={release?.release_id} data-release-revision={release?.revision} data-release-state={release?.state} data-project-revision={project.data?.revision} data-project-archived={project.data?.archived} data-project-paused={project.data?.paused} data-phase-id={latestPhase?.phase_id}>
        <Panel title={release?.title ?? 'Release 详情'}><div className="release-content"><QueryState loading={detail.loading && !release} error={detail.error} onRetry={detail.reload}>
          {!release ? <EmptyState title="选择一份 Release" description="查看实际清单、接受记录和阶段历史。" /> : <>
            <div className="toolbar"><span className="release-state">{labels[release.state]}</span><code>{release.release_id}</code><span className="muted">定义版本 {release.revision}</span></div>
            <dl className="release-facts"><dt>所属阶段</dt><dd>{phase?.title ?? release.phase_id}</dd><dt>创建来源</dt><dd>{release.created_by} · {time(release.created_at)}</dd><dt>候选形成</dt><dd>{release.candidate_by ?? '未记录'} · {time(release.candidate_at)}</dd><dt>实际接受</dt><dd>{release.accepted_by ?? '尚未接受'} · {time(release.accepted_at)}</dd><dt>清单 SHA256</dt><dd><code>{release.manifest_sha256 ?? '尚未生成'}</code></dd><dt>已集成主线</dt><dd><code>{manifest?.main_sha ?? '候选尚未生成'}</code></dd><dt>主线树身份</dt><dd><code>{manifest?.main_tree_oid ?? '未生成'}</code></dd></dl>
            <div className="release-actions">{release.state === 'DRAFT' && <button data-testid="release-candidate" disabled={!liveProject || !readyDetail || busy} onClick={() => begin('candidate')}><GitBranch size={16} />预览候选</button>}{release.state === 'CANDIDATE' && <button data-testid="release-accept" className="primary" disabled={!liveProject || !readyDetail || busy} onClick={() => begin('accept')}><Check size={16} />预览接受</button>}{release.state === 'ACCEPTED' && <><button data-testid="release-export" disabled={!managed || !readyDetail || busy} onClick={() => begin('export')}><Archive size={16} />实际导出交付包</button><button data-testid="release-download" disabled={!readyDetail || !release.manifest_sha256 || busy} onClick={() => void download()}><Download size={16} />下载并核对清单</button><button data-testid="release-bundle-download" className="primary" disabled={!readyDetail || !matchingExport?.bundle?.sha256 || !Number.isSafeInteger(matchingExport?.bundle_bytes) || exports.loading || !!exports.error || busy} onClick={() => void download('bundle')}><Download size={16} />下载真实交付包</button>{!project.data?.archived ? <button data-testid="release-archive" disabled={!liveProject || !readyDetail || !matchingExport?.bundle?.sha256 || exports.loading || !!exports.error || busy} onClick={() => begin('archive')}><Archive size={16} />预览归档</button> : <button data-testid="release-reopen" disabled={!managed || !readyDetail || project.loading || !!project.error || busy} onClick={() => begin('reopen')}><RotateCcw size={16} />重开新阶段</button>}</>}</div>
            {preview && preview.release.release_id === release.release_id && <form className="release-preview" data-testid="release-preview" onSubmit={event => { event.preventDefault(); submit(); }}><h3>{actionNames[preview.action]}预览</h3><dl className="release-facts"><dt>绑定身份</dt><dd>{preview.release.release_id} · Release {preview.release.revision} · 项目 {preview.project.revision}</dd><dt>实际效果</dt><dd>{preview.action === 'candidate' ? '从当前主线、已接受里程碑及实际产物生成冻结候选清单。' : preview.action === 'accept' ? '按清单 SHA256 重新核验主线、里程碑和独立证据，记录负责人接受。' : preview.action === 'export' ? '生成并登记真实交付包：冻结清单、绑定产物、Git 源码归档和安装说明。' : preview.action === 'archive' ? '服务端确认项目已静止后归档，原 Release 与证据保留。' : '建立新的项目阶段与目标，保留历史 Release，新阶段保持暂停。'}</dd></dl>
              {preview.action === 'candidate' && <Field label="当前主线完整 SHA" hint="阶段基线仅用于核对，服务端会重新读取当前 Git 主线。"><input data-testid="release-main-sha" required value={mainSha} disabled={busy} onChange={event => setMainSha(event.target.value)} /></Field>}
              {preview.action === 'accept' && <p className="notice">将接受清单 <code>{preview.release.manifest_sha256}</code>，范围为所选里程碑。</p>}
              {['accept', 'archive', 'reopen'].includes(preview.action) && <Field label="处理依据"><textarea data-testid="release-action-reason" required rows={3} value={reason} disabled={busy} onChange={event => setReason(event.target.value)} /></Field>}
              {preview.action === 'reopen' && <><Field label="新阶段名称"><input data-testid="release-phase-title" required value={phaseTitle} disabled={busy} onChange={event => setPhaseTitle(event.target.value)} /></Field><Field label="新阶段目标"><textarea data-testid="release-phase-goal" required rows={3} value={phaseGoal} disabled={busy} onChange={event => setPhaseGoal(event.target.value)} /></Field></>}
              <div className="toolbar"><button data-testid="release-action-submit" className="primary" disabled={busy || (['accept', 'archive', 'reopen'].includes(preview.action) && !reason.trim()) || (preview.action === 'reopen' && (!phaseTitle.trim() || !phaseGoal.trim()))}>{busy ? '正在提交并回读…' : `确认${actionNames[preview.action]}`}</button><button type="button" disabled={busy} onClick={() => setPreview(undefined)}>取消</button></div>
            </form>}
            <h3>导出与下载</h3>{exports.error && <ErrorNotice error={exports.error} onRetry={exports.reload} />}<p data-testid="release-export-state">{matchingExport ? `已登记实际导出 ${matchingExport.export_id} · ${matchingExport.bytes} 字节` : exports.loading ? '正在读取导出记录…' : '未观察到与这份清单匹配的导出记录'}</p>{matchingExport && <dl className="release-facts"><dt>导出产物</dt><dd><code>{matchingExport.artifact.artifact_id}</code></dd><dt>产物 SHA256</dt><dd><code>{matchingExport.artifact.sha256}</code></dd><dt>交付包产物</dt><dd><code>{matchingExport.bundle?.artifact_id ?? '未登记'}</code></dd><dt>交付包 SHA256</dt><dd><code>{matchingExport.bundle?.sha256 ?? '未登记'}</code></dd><dt>交付包字节</dt><dd>{Number.isSafeInteger(matchingExport.bundle_bytes) ? matchingExport.bundle_bytes : '未精确读取'}</dd><dt>源码归档 SHA256</dt><dd><code>{matchingExport.source_archive_sha256 ?? '未登记'}</code></dd><dt>导出来源</dt><dd>{matchingExport.exported_by} · {time(matchingExport.exported_at)}</dd></dl>}{downloaded?.releaseId === release.release_id && <p role="status" data-testid="release-download-state">已核对并发起{downloaded.kind === 'bundle' ? '交付包' : '清单'}下载：{downloaded.bytes} 字节 · SHA256 {downloaded.sha256}</p>}
            <p className="muted">接受状态、服务端导出和本次下载各自记录。交付包包含冻结清单、绑定产物、实际 Git 源码归档和安装说明。</p>
            <h3>安装与复现</h3><p style={{ whiteSpace: 'pre-wrap', overflowWrap: 'anywhere' }}>{release.installation || '未提供安装说明'}</p>
            <h3>未证明项与风险处理</h3>{release.not_proven.length ? <ul>{release.not_proven.map((item, index) => <li key={index}>{item}</li>)}</ul> : <p className="muted">未登记未证明项，所选范围以实际清单为准。</p>}{release.risk_dispositions.length ? <ul>{release.risk_dispositions.map((item, index) => <li key={index}>{item}</li>)}</ul> : <p className="muted">未登记额外风险处理。</p>}
            {manifest && <><h3>绑定需求与独立验收</h3>{manifest.milestone_acceptances.map(judgment => <details key={`${judgment.milestone_id}:${judgment.baseline_version}`}><summary>{judgment.milestone_id} · 基线 {judgment.baseline_version} · {judgment.status}</summary><p>{judgment.accepted_by ?? '来源未提供'} · {time(judgment.accepted_at)}</p><ul>{judgment.conditions?.requirement_refs?.map(ref => <li key={ref.requirement_id}>{ref.requirement_id} · 定义 {ref.revision}</li>)}</ul><JsonView value={judgment} /></details>)}
              <h3>集成、环境与日志身份</h3><ul className="release-artifacts">{evidence.map((ref, index) => <li key={index}><strong>{ref.task_id ?? '证据来源未提供任务 ID'}</strong><dl className="release-facts"><dt>已集成 SHA</dt><dd><code>{ref.integrated_sha ?? '未提供'}</code></dd><dt>独立验证计划</dt><dd>{ref.verification_plan_id ?? '未提供'}<br /><code>{ref.verification_plan_hash ?? '未提供计划摘要'}</code></dd><dt>日志 SHA256</dt><dd><code>{ref.integrated_log_sha256 ?? '未提供'}</code></dd><dt>环境记录</dt><dd>{ref.environment === undefined ? '此证据引用未提供环境字段，请核对完整独立验收记录。' : <JsonView value={ref.environment} />}</dd></dl></li>)}</ul>
              <h3>实际候选产物</h3><ul className="release-artifacts">{manifest.files.map(file => <li key={file.artifact_id}><code>{file.artifact_id}</code><p><code>{file.sha256}</code></p><span>{Number.isSafeInteger(file.bytes) ? `${file.bytes} 字节` : '字节数超出精确显示范围'}</span></li>)}</ul><details><summary>完整冻结清单与范围声明</summary><JsonView value={manifest} /></details>
            </>}
            <details><summary>完整 Release 记录</summary><JsonView value={release} /></details>
          </>}
        </QueryState></div></Panel>
        <Panel title="项目阶段历史"><div className="release-content"><QueryState loading={phases.loading} error={phases.error} onRetry={phases.reload}>{phases.data?.length ? <ul className="release-phase-history" data-testid="release-phases">{phases.data.filter(item => item.project_id === projectId).sort((a, b) => b.ordinal - a.ordinal).map(item => <li key={item.phase_id}><strong>阶段 {item.ordinal} · {item.title}</strong><p>{item.goal}</p><code>{item.baseline_main_sha}</code><small className="muted"> {item.created_by} · {time(item.created_at)}</small>{item.previous_release_id && <p><a href={`${root}/releases/${path(item.previous_release_id)}`}>查看上一阶段 Release {item.previous_release_id}</a></p>}</li>)}</ul> : <EmptyState title="尚未建立阶段记录" description="首份实际草案由服务端绑定阶段；重开时新增阶段，历史保持可读取。" />}</QueryState></div></Panel>
      </div></div>
    </>}
  </>;
}
