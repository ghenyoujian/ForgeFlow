import { useEffect, useId, useRef, useState, type FormEvent } from "react";
import { Layers, RefreshCw, ShieldCheck } from "lucide-react";
import { api } from "./api";
import { DataTable, EmptyState, ErrorNotice, Field, Panel, QueryState, SourceStamp } from "../components";
import { useCollection } from "../features/portfolio/collection";
import { useCommandIdentity } from "../features/portfolio/commands";

type ArtifactReference = { artifact_id: string; sha256: string };
type CapsulePolicy = {
  schema_version: "forgeflow.capsule-policy.v1";
  executor_profile_id: string;
  resource_profile_id: string;
  model_route_id: string;
  mode: "CLAUDE_LEAF" | "DSH_HEADLESS";
  team_write_policy: "READ_ONLY" | "AGGREGATE_WRITE_SCOPE";
  qualification_ref: ArtifactReference;
};
type CapsuleEnvironment = {
  schema_version: string;
  executor_profile_sha256: string;
  resource_profile_sha256: string;
  model_route_sha256: string;
  control_build_sha256: string;
  operating_system: string;
  architecture: string;
  kernel_release: string;
};
type PolicyRecord = { policy: CapsulePolicy; registered_at: string; revision: number; environment: CapsuleEnvironment };
type ContextResult = { environment: CapsuleEnvironment; qualification: string; authorization_granted: boolean };
type Props = { projectId?: string; executorProfileIds?: string[]; resourceProfileIds?: string[]; modelRouteIds?: string[] };
const boundedText = (value: unknown) => typeof value === "string" && value.length <= 512 && !/[\x00-\x1f\x7f]/.test(value) ? value : "—";
const digest = (value: unknown) => typeof value === "string" && /^[a-f0-9]{64}$/.test(value) ? value : "未提供有效 SHA256";
const referenceId = (value: string) => value.trim().length > 0 && value.length <= 512 && !/[\x00-\x1f\x7f]/.test(value) && !/^(?:[/\\]|[A-Za-z]:|[A-Za-z][A-Za-z0-9+.-]*:\/\/)/.test(value);
const identities = (values: string[]) => [...new Set(values)].filter(value => value.length > 0 && value.length <= 512);

export function CapsulePolicies({ projectId, executorProfileIds = [], resourceProfileIds = [], modelRouteIds = [] }: Props) {
  const root = projectId ? `/projects/${encodeURIComponent(projectId)}` : undefined;
  const policies = useCollection<PolicyRecord>(root ? `${root}/capsule-policies?limit=100` : null);
  const commandIdentity = useCommandIdentity();
  const fieldId = useId();
  const [executor, setExecutor] = useState("");
  const [resource, setResource] = useState("");
  const [route, setRoute] = useState("");
  const [mode, setMode] = useState<CapsulePolicy["mode"]>("CLAUDE_LEAF");
  const [writePolicy, setWritePolicy] = useState<CapsulePolicy["team_write_policy"]>("READ_ONLY");
  const [artifactId, setArtifactId] = useState("");
  const [artifactSha, setArtifactSha] = useState("");
  const [busy, setBusy] = useState<"context" | "register">();
  const [error, setError] = useState<Error>();
  const [context, setContext] = useState<{ identity: string; result: ContextResult }>();
  const [receipt, setReceipt] = useState<PolicyRecord>();
  const request = useRef<AbortController | undefined>(undefined);
  const inFlight = useRef(false);
  useEffect(() => () => request.current?.abort(), []);
  const ids = { executor_profile_id: executor.trim(), resource_profile_id: resource.trim(), model_route_id: route.trim() };
  const currentIdentity = JSON.stringify([projectId, ids]);
  const idsValid = Object.values(ids).every(value => value.length > 0 && value.length <= 512 && !/[\x00-\x1f\x7f]/.test(value));
  const qualificationValid = referenceId(artifactId.trim()) && /^[a-f0-9]{64}$/.test(artifactSha);
  const existing = policies.data?.some(record => record.policy?.executor_profile_id === ids.executor_profile_id) ?? false;
  const currentContext = context?.identity === currentIdentity ? context.result : undefined;

  async function readContext() {
    if (!root || !idsValid || inFlight.current) return;
    inFlight.current = true; setBusy("context"); setError(undefined); setContext(undefined);
    const controller = new AbortController(); request.current = controller;
    try {
      const result = await api.get<ContextResult>(`${root}/capsule-context?${new URLSearchParams(ids)}`, controller.signal);
      if (!controller.signal.aborted) setContext({ identity: currentIdentity, result });
    } catch (cause) { if (!controller.signal.aborted) setError(cause instanceof Error ? cause : new Error("环境指纹读取失败")); }
    finally { inFlight.current = false; if (!controller.signal.aborted) setBusy(undefined); }
  }
  async function register(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!root || !idsValid || !qualificationValid || inFlight.current || existing) return;
    inFlight.current = true; setBusy("register"); setError(undefined); setReceipt(undefined);
    const controller = new AbortController(); request.current = controller;
    const body: CapsulePolicy = { schema_version: "forgeflow.capsule-policy.v1", ...ids, mode, team_write_policy: writePolicy, qualification_ref: { artifact_id: artifactId.trim(), sha256: artifactSha } };
    const endpoint = `${root}/capsule-policies`;
    try {
      const result = await api.post<PolicyRecord>(endpoint, body, { ...commandIdentity(endpoint, body), signal: controller.signal });
      if (!controller.signal.aborted) { setReceipt(result); policies.reload(); }
    } catch (cause) { if (!controller.signal.aborted) setError(cause instanceof Error ? cause : new Error("Capsule 策略登记失败")); }
    finally { inFlight.current = false; if (!controller.signal.aborted) setBusy(undefined); }
  }

  return <Panel title={<><Layers size={16} />Capsule 策略</>} actions={<button type="button" disabled={!root || policies.loading} onClick={policies.reload}><RefreshCw size={14} />刷新策略</button>}>
    {!root ? <EmptyState title="选择项目读取 Capsule 策略" description="策略与资格原件均按项目隔离。" /> : <>
      <div className="panel-body"><p className="muted">Capsule 复用既有尝试、冻结执行配置和租约。这里只登记经服务端核验的单叶资格策略；登记不会创建尝试、启动进程或修改 DSH 自启动。</p></div>
      <QueryState loading={policies.loading && !policies.data} error={policies.error} onRetry={policies.reload}>
        <DataTable<PolicyRecord> rows={policies.data ?? []} rowKey={record => record.policy.executor_profile_id} empty={<EmptyState title="此项目尚无已登记 Capsule 策略" description="既有尝试保持 UNBOUND；没有策略不代表已有运行资格。" />} columns={[
          { key: "executor", label: "执行配置 / 单叶模式", render: record => <><code>{boundedText(record.policy.executor_profile_id)}</code><small>{boundedText(record.policy.mode)}</small></> },
          { key: "bindings", label: "资源 / 模型路由", render: record => <>{boundedText(record.policy.resource_profile_id)}<small>{boundedText(record.policy.model_route_id)}</small></> },
          { key: "write_policy", label: "写策略", render: record => boundedText(record.policy.team_write_policy) },
          { key: "qualification", label: "已核验资格引用", render: record => <><code>{boundedText(record.policy.qualification_ref?.artifact_id)}</code><small style={{ overflowWrap: "anywhere" }}>{digest(record.policy.qualification_ref?.sha256)}</small></> },
          { key: "registered_at", label: "登记时间", render: record => boundedText(record.registered_at) },
        ]} />
      </QueryState>
      <SourceStamp source={policies.metadata.source} observedAt={policies.metadata.observed_at} />
      <div className="panel-body">
        <h3><ShieldCheck size={15} />登记不可变单叶策略</h3>
        <p className="muted">需要已注册的 REAL_MODEL 资格原件及真实独立验证、Git 集成封存。Doctor 发现、手填 VERIFIED 或模型文本不能替代。当前不接受 Team、Workflow 或逐成员独立写隔离声明。</p>
        <form onSubmit={event => void register(event)}>
          <fieldset disabled={!!busy} style={{ border: 0, padding: 0, margin: 0, minWidth: 0 }}>
          <div className="settings-grid">
            <Field label="执行器 Profile ID" hint="可从当前已加载目录选择，或输入同项目的确切已登记 ID。"><input required maxLength={512} list={`${fieldId}-executors`} value={executor} onChange={event => { setExecutor(event.target.value); setReceipt(undefined); }} /><datalist id={`${fieldId}-executors`}>{identities(executorProfileIds).map(id => <option key={id} value={id} />)}</datalist></Field>
            <Field label="资源 Profile ID"><input required maxLength={512} list={`${fieldId}-resources`} value={resource} onChange={event => { setResource(event.target.value); setReceipt(undefined); }} /><datalist id={`${fieldId}-resources`}>{identities(resourceProfileIds).map(id => <option key={id} value={id} />)}</datalist></Field>
            <Field label="模型路由 ID"><input required maxLength={512} list={`${fieldId}-routes`} value={route} onChange={event => { setRoute(event.target.value); setReceipt(undefined); }} /><datalist id={`${fieldId}-routes`}>{identities(modelRouteIds).map(id => <option key={id} value={id} />)}</datalist></Field>
            <Field label="执行模式"><select value={mode} onChange={event => { setMode(event.target.value as CapsulePolicy["mode"]); setReceipt(undefined); }}><option value="CLAUDE_LEAF">Claude Code · 单叶</option><option value="DSH_HEADLESS">DSH · Headless 单叶（仅登记）</option></select></Field>
            <Field label="写入策略"><select value={writePolicy} onChange={event => { setWritePolicy(event.target.value as CapsulePolicy["team_write_policy"]); setReceipt(undefined); }}><option value="READ_ONLY">READ_ONLY · 任务无写权限</option><option value="AGGREGATE_WRITE_SCOPE">AGGREGATE_WRITE_SCOPE · 外层精确写集合</option></select></Field>
          </div>
          <button type="button" disabled={!idsValid || !!busy} onClick={() => void readContext()}>{busy === "context" ? "正在读取环境指纹…" : "读取只读环境指纹"}</button>
          {currentContext && <section aria-label="Capsule 资格环境指纹" className="notice"><p>资格状态：{boundedText(currentContext.qualification)}。环境读取不登记资格，也不授予执行权。</p><dl className="detail-grid">
            <dt>执行器 CAS SHA256</dt><dd style={{ overflowWrap: "anywhere" }}><code>{digest(currentContext.environment?.executor_profile_sha256)}</code></dd>
            <dt>资源配置 SHA256</dt><dd style={{ overflowWrap: "anywhere" }}><code>{digest(currentContext.environment?.resource_profile_sha256)}</code></dd>
            <dt>模型路由 SHA256</dt><dd style={{ overflowWrap: "anywhere" }}><code>{digest(currentContext.environment?.model_route_sha256)}</code></dd>
            <dt>Core SHA256</dt><dd style={{ overflowWrap: "anywhere" }}><code>{digest(currentContext.environment?.control_build_sha256)}</code></dd>
            <dt>系统 / 架构 / 内核</dt><dd>{boundedText(currentContext.environment?.operating_system)} / {boundedText(currentContext.environment?.architecture)} / {boundedText(currentContext.environment?.kernel_release)}</dd>
          </dl></section>}
          <div className="settings-grid">
            <Field label="资格原件 Artifact ID" hint="输入已注册的逻辑 Artifact ID；不能填写本机绝对路径。"><input required maxLength={512} value={artifactId} onChange={event => { setArtifactId(event.target.value); setReceipt(undefined); }} />{artifactId && !referenceId(artifactId.trim()) && <span role="alert">需要有效逻辑 Artifact ID，不能使用绝对路径或控制字符。</span>}</Field>
            <Field label="资格原件 SHA256" hint="64 位小写十六进制；服务端会核验已注册原件的实际字节。"><input required minLength={64} maxLength={64} pattern="[a-f0-9]{64}" spellCheck={false} value={artifactSha} onChange={event => { setArtifactSha(event.target.value); setReceipt(undefined); }} /></Field>
          </div>
          {existing && <p className="notice">该执行器 Profile 已登记不可变策略。调整资格或配置需要新的 Profile ID。</p>}
          {error && <ErrorNotice error={error} />}
          {receipt && <p role="status" className="notice">服务端已登记策略：{boundedText(receipt.policy?.executor_profile_id)}，登记时间 {boundedText(receipt.registered_at)}。没有创建尝试或启动进程。</p>}
          <button className="primary" type="submit" disabled={!idsValid || !qualificationValid || !!busy || existing}>{busy === "register" ? "正在核验资格原件…" : "核验并登记单叶策略"}</button>
          </fieldset>
        </form>
      </div>
    </>}
  </Panel>;
}
