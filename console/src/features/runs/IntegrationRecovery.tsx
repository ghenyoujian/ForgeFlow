import { useEffect, useRef, useState } from "react";
import { ClipboardCheck, GitMerge, RefreshCw, RotateCcw } from "lucide-react";
import { api, ApiError, useApi } from "../../app/api";
import { ErrorNotice, Field, JsonView, Panel, SourceStamp, StatusBadge } from "../../components";
import { useCollection } from "../portfolio/collection";
import { useCommandIdentity } from "../portfolio/commands";
import { object, path, str, type Row } from "../portfolio/monitor";

interface RecoveryRequest {
  project_id: string;
  intent_id: string;
  expected_intent_revision: number;
  reason: string;
}
interface RecoveryPreview {
  body: RecoveryRequest;
  intent: Row;
  fingerprint: string;
}
interface ReplayPreview {
  operationId: string;
  body: RecoveryRequest;
  idempotencyKey: string;
}
const recoverableIntents = new Set(["COMMIT_DECIDED", "REF_UPDATED", "RECOVERY_REQUIRED"]);
const recoverableAttempts = new Set(["MERGING", "RECOVERY_REQUIRED"]);
const terminalOperations = new Set(["SUCCEEDED", "RECOVERY_REQUIRED", "FAILED", "CANCELLED"]);
const positiveRevision = (value: unknown) => typeof value === "number" && Number.isSafeInteger(value) && value > 0;
const nonblank = (value: unknown): value is string => typeof value === "string" && value.trim().length > 0;
const uuid = (value: unknown): value is string => typeof value === "string"
  && /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(value);

function retainedAuthorization(operation: Row, projectId: string, attemptId: string): ReplayPreview | undefined {
  const request = object(operation.request);
  const before = object(operation.intent_before);
  const key = object(operation.authorization_identity).idempotency_key;
  if (operation.kind !== "INTEGRATION_RECOVERY" || operation.status !== "ACCEPTED"
    || operation.project_id !== projectId || operation.attempt_id !== attemptId
    || request.project_id !== projectId || request.attempt_id !== attemptId
    || request.operation_id !== operation.operation_id
    || request.intent_id !== operation.intent_id || before.intent_id !== operation.intent_id
    || before.project_id !== projectId || before.attempt_id !== attemptId
    || object(before.receipt).commit_decided !== true || !nonblank(before.integrated_sha)
    || !uuid(request.intent_id) || !positiveRevision(request.expected_intent_revision)
    || !nonblank(request.reason) || new TextEncoder().encode(request.reason).length > 2000
    || !nonblank(key) || !nonblank(operation.operation_id)) return;
  return {
    operationId: operation.operation_id,
    idempotencyKey: key,
    body: { project_id: projectId, intent_id: request.intent_id,
      expected_intent_revision: request.expected_intent_revision as number, reason: request.reason },
  };
}

/** Resume one reviewed durable decision. Authoring and original verification stay separate. */
export function IntegrationRecovery({ projectId, attemptId, attempt, onRecovered }: {
  projectId?: string; attemptId?: string; attempt: Row; onRecovered: () => void;
}) {
  const scope = `${projectId ?? ""}:${attemptId ?? ""}`;
  const scopeRef = useRef(scope); scopeRef.current = scope;
  const [selectedId, setSelectedId] = useState("");
  const [reason, setReason] = useState("");
  const [preview, setPreview] = useState<RecoveryPreview>();
  const [replayPreview, setReplayPreview] = useState<ReplayPreview>();
  const [operationId, setOperationId] = useState("");
  const [accepted, setAccepted] = useState<Row>();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<Error>();
  const [message, setMessage] = useState("");
  const inFlight = useRef(false);
  const completed = useRef(new Set<string>());
  const commandIdentity = useCommandIdentity();
  const projectRoot = projectId && attemptId ? `/projects/${path(projectId)}` : null;
  const historyQ = useCollection<Row>(projectRoot ? `${projectRoot}/operations` : null);
  const recoveryHistory = (historyQ.data ?? []).filter(row => row.kind === "INTEGRATION_RECOVERY"
    && row.project_id === projectId && row.attempt_id === attemptId);
  const newRecoveryStage = recoverableAttempts.has(str(attempt.state, ""));
  const relevant = newRecoveryStage || !!operationId
    || recoveryHistory.length > 0 || !!historyQ.error;
  const root = newRecoveryStage ? projectRoot : null;
  // Both handlers currently return the complete stored array, with next_cursor=null.
  // The collection hook also traverses a future cursor response instead of trusting one page.
  const intentsQ = useCollection<Row>(root ? `${root}/integration-queue` : null);
  const projectQ = useApi<unknown>(root);
  const operationQ = useApi<unknown>(operationId ? `/operations/${path(operationId)}` : null);
  const rawOperation = operationQ.data === undefined ? accepted : object(operationQ.data);
  const operation = rawOperation && rawOperation.operation_id === operationId
    && rawOperation.project_id === projectId && rawOperation.attempt_id === attemptId
    && rawOperation.kind === "INTEGRATION_RECOVERY" ? rawOperation : undefined;
  const operationMismatch = operationQ.data !== undefined && !operation;
  const operationStatus = str(operation?.status, "");
  const intentsComplete = intentsQ.data !== undefined && !intentsQ.loading && !intentsQ.error;
  const historyComplete = historyQ.data !== undefined && !historyQ.loading && !historyQ.error;
  const projectComplete = projectQ.data !== undefined && !projectQ.loading && !projectQ.error;
  const intents = (intentsQ.data ?? []).filter(row => row.project_id === projectId && row.attempt_id === attemptId);
  const selected = intents.find(row => row.intent_id === selectedId);
  const verification = object(object(selected?.receipt).verification);
  const reasonBytes = new TextEncoder().encode(reason).length;
  const validReason = !!reason.trim() && reasonBytes <= 2000;
  const body: RecoveryRequest | undefined = projectId && selected && positiveRevision(selected.revision)
    && typeof selected.intent_id === "string" ? {
      project_id: projectId, intent_id: selected.intent_id,
      expected_intent_revision: selected.revision as number, reason,
    } : undefined;
  const fingerprint = JSON.stringify([scope, body, selected, attempt.state, attempt.generation,
    object(projectQ.data).authority_mode]);
  const pendingExisting = recoveryHistory.filter(row => row.intent_id === selectedId && row.status === "ACCEPTED");
  const eligibility = !projectComplete ? "项目权威尚未完整读取。"
    : object(projectQ.data).authority_mode !== "MANAGED" ? "恢复需要受管项目，由服务端核验 Owner 授权。"
      : !intentsComplete || !historyComplete ? "集成意图或恢复操作记录尚未完整读取。"
        : !selected ? selectedId ? "原选择未出现在当前完整主线列表中；请核对原操作，或明确选择其他意图。" : "先明确选择本尝试的真实集成意图。"
          : attempt.project_id !== projectId || attempt.attempt_id !== attemptId ? "当前尝试身份尚未确认与页面作用域一致。"
            : !recoverableAttempts.has(str(attempt.state, "")) ? "当前尝试阶段不允许发起新的集成恢复。"
            : !recoverableIntents.has(str(selected.state, "")) ? "该意图尚无可继续的提交决定，或已结束。"
              : object(selected.receipt).commit_decided !== true ? "原收据没有已持久化的 commit_decided=true。"
                : !nonblank(selected.integrated_sha) ? "原意图未提供实际已决定的集成 SHA。"
                  : !uuid(selected.intent_id) || !positiveRevision(selected.revision) ? "意图身份或版本未提供有效值。"
                    : !positiveRevision(selected.generation) || !positiveRevision(attempt.generation) || selected.generation !== attempt.generation ? "意图与当前尝试的租约代次未确认一致。"
                      : pendingExisting.length ? "该意图已有已接收的恢复授权；查看原操作并使用其原请求身份重放。"
                        : "";
  const canPreview = !eligibility && validReason && !!body && !busy;
  const stalePreview = !!preview && preview.fingerprint !== fingerprint;
  function reload() { intentsQ.reload(); historyQ.reload(); projectQ.reload(); }

  useEffect(() => {
    setSelectedId(""); setReason(""); setPreview(undefined); setReplayPreview(undefined);
    setOperationId(""); setAccepted(undefined); setError(undefined); setMessage(""); setBusy(false);
    completed.current.clear();
  }, [scope]);
  useEffect(() => {
    if (!operationId || !operation || terminalOperations.has(operationStatus)) return;
    const timer = setInterval(() => { if (document.visibilityState === "visible") operationQ.reload(); }, 2000);
    return () => clearInterval(timer);
  }, [operationId, operationStatus, !!operation, operationQ.reload]);
  useEffect(() => {
    if (!operation || operationStatus !== "SUCCEEDED" || completed.current.has(operationId)) return;
    completed.current.add(operationId);
    intentsQ.reload(); historyQ.reload(); onRecovered();
  }, [operationId, operationStatus, operation, intentsQ.reload, historyQ.reload, onRecovered]);

  async function submit(request: RecoveryRequest, idempotencyKey: string) {
    if (!projectId || !attemptId || inFlight.current) return;
    const submittedScope = scope;
    inFlight.current = true; setBusy(true); setError(undefined); setMessage("");
    try {
      const result = object(await api.post(`/attempts/${path(attemptId)}/integration-recovery`, request, { idempotencyKey }));
      if (scopeRef.current !== submittedScope) return;
      if (!nonblank(result.operation_id) || result.kind !== "INTEGRATION_RECOVERY"
        || result.project_id !== projectId || result.attempt_id !== attemptId || result.intent_id !== request.intent_id
        || object(result.request).expected_intent_revision !== request.expected_intent_revision
        || object(result.request).reason !== request.reason)
        throw new Error("恢复回执未确认完整操作身份；保留原请求，请刷新操作记录核对。");
      setOperationId(result.operation_id); setAccepted(result); setReplayPreview(undefined);
      setMessage(`操作 ${result.operation_id} 已返回 ${str(result.status)}；以持久操作结果和重新读取的尝试为准。`);
      reload();
    } catch (cause) {
      if (scopeRef.current !== submittedScope) return;
      const next = cause instanceof Error ? cause : new Error(String(cause));
      setError(next);
      setMessage(cause instanceof ApiError && cause.status === 409
        ? "版本或恢复授权发生冲突。原因与原预览已保留；刷新记录后重新核对，已有授权使用原操作重放。"
        : "恢复请求失败或回执未确认。输入已保留；刷新已有操作后核对实际结果。");
      reload();
    } finally {
      inFlight.current = false;
      if (scopeRef.current === submittedScope) setBusy(false);
    }
  }

  function prepareReplay() {
    if (!newRecoveryStage || !operation || !projectId || !attemptId || busy || !historyComplete || !intentsComplete) return;
    const original = retainedAuthorization(operation, projectId, attemptId);
    setReplayPreview(original);
    if (!original) setError(new Error("原授权请求、持久提交决定或重放身份不完整，无法构造重放；保留现有记录。"));
    else setError(undefined);
  }

  if (!projectId || !attemptId || !relevant) return null;
  return <Panel title={<span><GitMerge size={16} />{newRecoveryStage ? "已有提交决定的恢复" : "集成恢复记录"}</span>}
    actions={<button type="button" disabled={busy} onClick={reload}><RefreshCw size={14} />刷新恢复记录</button>}>
    <div className="panel-body">
      <p className="muted">{newRecoveryStage
        ? "恢复沿已持久化的 Git 提交决定继续，保留原验证历史。这里读取 refs/heads/main 的完整未完成意图，Owner 权限由服务端裁决。"
        : "此面板仅查看该尝试的已登记恢复历史。明确选择操作后查看持久结果与原授权内容。"}</p>
      {historyQ.error && <ErrorNotice error={historyQ.error} onRetry={historyQ.reload} />}
      {historyQ.loading && <p role="status">正在完整读取恢复历史…</p>}
      <div className="toolbar"><a href={`/projects/${path(projectId)}/evidence`}>查看原验证记录（按尝试 {attemptId} 核对）</a><a href={`/projects/${path(projectId)}/integration`}>查看集成记录</a></div>
      {newRecoveryStage && <>
      {intentsQ.error && <ErrorNotice error={intentsQ.error} onRetry={intentsQ.reload} />}
      {projectQ.error && <ErrorNotice error={projectQ.error} onRetry={projectQ.reload} />}
      {(intentsQ.loading || projectQ.loading) && <p role="status">正在完整读取意图与项目权威…</p>}
      {intentsComplete && !intents.length && <p className="notice">当前主线列表没有该尝试的未完成集成意图；已结束意图可从原恢复操作和证据页核对。</p>}
      <Field label="选择本尝试的集成意图">
        <select style={{ width: "100%" }} value={selectedId} disabled={busy || !intentsComplete} onChange={event => {
          setSelectedId(event.target.value); setPreview(undefined); setReplayPreview(undefined); setError(undefined);
        }}>
          <option value="">请选择真实意图，不自动绑定</option>
          {selectedId && !selected && <option value={selectedId}>{selectedId} · 当前列表未返回</option>}
          {intents.map(row => <option value={str(row.intent_id, "")} key={str(row.intent_id)}>{str(row.intent_id)} · {str(row.state)} · r{str(row.revision)}</option>)}
        </select>
      </Field>
      {selected && <dl className="detail-grid">
        <dt>意图阶段 / 版本</dt><dd><StatusBadge state={str(selected.state)} /> / r{str(selected.revision)}</dd>
        <dt>持久提交决定</dt><dd>{object(selected.receipt).commit_decided === true ? "已持久化" : "未确认"}</dd>
        <dt>候选 SHA</dt><dd><code>{str(selected.candidate_sha)}</code></dd>
        <dt>预期主线 SHA</dt><dd><code>{str(selected.expected_sha)}</code></dd>
        <dt>已决定集成 SHA</dt><dd><code>{str(selected.integrated_sha)}</code></dd>
        <dt>目标引用 / 代次</dt><dd>{str(selected.target_ref)} / {str(selected.generation)}</dd>
        <dt>原验证者 / 用例</dt><dd>{str(verification.verifier_id)} · 总数 {str(verification.total)} / 失败 {str(verification.failed)} / 跳过 {str(verification.skipped)}</dd>
        <dt>原验证摘要</dt><dd><code>{str(object(selected.receipt).verification_receipt_hash)}</code></dd>
      </dl>}
      <Field label="集成恢复原因" hint={`${reasonBytes} / 2000 UTF-8 字节；保存冲突时保留输入。`}>
        <textarea value={reason} maxLength={2000} disabled={busy} rows={3} onChange={event => { setReason(event.target.value); setReplayPreview(undefined); }} />
      </Field>
      {eligibility && <p className="notice" role="status">{eligibility}</p>}
      {!!reason.trim() && !validReason && <p role="alert">原因超过 2000 UTF-8 字节，请缩短后重新预览。</p>}
      <button type="button" disabled={!canPreview} onClick={() => body && selected && setPreview({ body, intent: selected, fingerprint })}><ClipboardCheck size={14} />预览恢复请求</button>
      {preview && <details open>
        <summary>已审阅意图 {preview.body.intent_id} · r{preview.body.expected_intent_revision}</summary>
        <JsonView value={{ candidate_sha: preview.intent.candidate_sha, integrated_sha: preview.intent.integrated_sha,
          target_ref: preview.intent.target_ref, commit_decided: object(preview.intent.receipt).commit_decided,
          request: preview.body }} />
        {stalePreview && <p className="notice" role="alert">意图、尝试或输入已变化。原请求保留供核对，重新预览后才能发起新的恢复。</p>}
        <button type="button" className="primary" disabled={!canPreview || stalePreview} onClick={() => {
          if (!canPreview || stalePreview) return;
          const route = `/attempts/${path(attemptId)}/integration-recovery`;
          void submit(preview.body, commandIdentity(route, preview.body).idempotencyKey);
        }}><RotateCcw size={14} />{busy ? "正在请求恢复…" : "发起已审阅的集成恢复"}</button>
      </details>}
      </>}
      {recoveryHistory.length > 0 && <Field label="查看已登记恢复操作">
        <select style={{ width: "100%" }} value={operationId} disabled={busy || !historyComplete} onChange={event => {
          const chosen = recoveryHistory.find(row => row.operation_id === event.target.value);
          setOperationId(event.target.value); setAccepted(chosen); setReplayPreview(undefined); setError(undefined);
        }}>
          <option value="">请选择原恢复操作</option>
          {operationId && !recoveryHistory.some(row => row.operation_id === operationId) && <option value={operationId}>{operationId} · 回执等待刷新</option>}
          {recoveryHistory.map(row => <option key={str(row.operation_id)} value={str(row.operation_id, "")}>{str(row.operation_id)} · {str(row.status)} · 意图 {str(row.intent_id)}</option>)}
        </select>
      </Field>}
      {operationId && <section aria-label="集成恢复操作结果">
        <h3 className="break-word">恢复操作 {operationId}</h3>
        {operationQ.error && <ErrorNotice error={operationQ.error} onRetry={operationQ.reload} />}
        {operationMismatch && <p className="notice" role="alert">操作回读身份不匹配，结果保持未知；不会绑定其他恢复意图。</p>}
        {operation ? <>
          <p role="status"><StatusBadge state={operationStatus} scope="operation" />{operationStatus === "ACCEPTED" ? " · 请求已接收，尚未证明恢复完成。" : operationStatus === "SUCCEEDED" ? " · 服务端恢复操作已完成，尝试与分配正在重新读取。" : operationStatus === "RECOVERY_REQUIRED" ? " · 仍需恢复，核对本次真实错误。" : " · 以持久操作结果为准。"}</p>
          <dl className="detail-grid"><dt>绑定意图 / 授权版本</dt><dd>{str(operation.intent_id)} / r{str(operation.authorized_intent_revision)}</dd>
            <dt>原授权人</dt><dd>{str(operation.actor_id)}</dd>
            <dt>原候选 SHA</dt><dd><code>{str(object(operation.intent_before).candidate_sha)}</code></dd>
            <dt>目标引用</dt><dd>{str(object(operation.intent_before).target_ref)}</dd>
            <dt>原验证摘要</dt><dd><code>{str(object(object(operation.intent_before).receipt).verification_receipt_hash)}</code></dd>
            <dt>当前结果</dt><dd>{str(object(object(operation.result).integration).state, "尚无完成结果")}</dd>
            <dt>最终集成 SHA</dt><dd><code>{str(object(object(operation.result).integration).integrated_sha, "尚无完成结果")}</code></dd>
          </dl>
          {operation.error !== undefined && operation.error !== null && <ErrorNotice error={str(operation.error)} />}
          <details><summary>原恢复请求</summary><JsonView value={operation.request} /></details>
          {newRecoveryStage && operationStatus === "ACCEPTED" && <button type="button" disabled={busy || !historyComplete || !intentsComplete || !!operationQ.error} onClick={prepareReplay}><ClipboardCheck size={14} />预览原授权重放</button>}
          {newRecoveryStage && replayPreview && <details open><summary>重放原操作 {replayPreview.operationId}</summary>
            <p className="muted">保留原意图、原因、版本与请求身份，由服务端核验原 Owner 授权。</p>
            <JsonView value={replayPreview.body} />
            <button type="button" disabled={busy || operationId !== replayPreview.operationId || operationStatus !== "ACCEPTED" || !historyComplete || !intentsComplete || !!operationQ.error} onClick={() => void submit(replayPreview.body, replayPreview.idempotencyKey)}><RotateCcw size={14} />重放原恢复请求</button>
          </details>}
        </> : <p className="muted" role="status">等待真实操作回读；当前没有可确认的恢复结果。</p>}
        <button type="button" disabled={operationQ.loading} onClick={operationQ.reload}><RefreshCw size={14} />重新读取操作结果</button>
      </section>}
      {error && <ErrorNotice error={error} />}
      {message && <p role="status" className="notice">{message}</p>}
    </div>
    <SourceStamp source={newRecoveryStage ? intentsQ.metadata.source : historyQ.metadata.source}
      observedAt={newRecoveryStage ? intentsQ.metadata.observed_at : historyQ.metadata.observed_at} />
  </Panel>;
}
