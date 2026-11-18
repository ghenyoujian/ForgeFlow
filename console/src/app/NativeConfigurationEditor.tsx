import { useEffect, useMemo, useRef, useState } from "react";
import { Copy, FilePlus2, Layers, RefreshCw, Save, Search, ShieldCheck } from "lucide-react";
import { api } from "./api";
import { EmptyState, ErrorNotice, Field, Panel, StatusBadge } from "../components";
import "./native-configuration-editor.css";

type Preset = { id: string; name: string; description: string; persona_prefix: string; clone_from: string };
type Plugin = { entry_id: string; enabled: boolean; config: Record<string, boolean | number | string> };
type Binding = { position_id: string; preset_id: string };
type Spec = { base_executor_profile_id: string; presets: Preset[]; plugins: Plugin[]; role_bindings: Binding[]; max_active_attempts_per_worker?: number };
type Context = { project_id: string; schema_version: string; base_config_sha256: string; spec: Spec; model: string; required_plugins: string[]; offline_only: boolean; runtime_actions_available: boolean; runtime_invoked: boolean; execution_rights_granted: boolean };
type Draft = { project_id: string; draft_id: string; revision: number; status: "DRAFT" | "PREVIEWED" | "PUBLISHED"; base_config_sha256: string; spec_sha256: string; spec: Spec; published_executor_profile_id?: string; activation?: { config_sha256?: string } };
type Tab = "presets" | "plugins" | "roles" | "changes" | "versions";
type Difference = { id: string; field: string; message: string };
const identifier = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;
const sha256 = /^[a-f0-9]{64}$/;
const encoder = new TextEncoder();
const byteLength = (value: string) => encoder.encode(value).byteLength;
const clone = <T,>(value: T): T => structuredClone(value);
const object = (value: unknown): Record<string, unknown> => value && typeof value === "object" && !Array.isArray(value) ? value as Record<string, unknown> : {};
const stable = (value: unknown): string => Array.isArray(value) ? `[${value.map(stable).join(",")}]` : value && typeof value === "object" ? `{${Object.keys(value).sort().map(key => `${JSON.stringify(key)}:${stable((value as Record<string, unknown>)[key])}`).join(",")}}` : JSON.stringify(value) ?? "null";
const newId = () => `native-edit-${crypto.randomUUID()}`;
const message = (error: unknown) => error instanceof Error ? error : new Error("执行配置读取失败，请重新读取权威来源。");

function checkedSpec(value: unknown): Spec {
  const row = object(value);
  const allowed = ["base_executor_profile_id", "presets", "plugins", "role_bindings", "max_active_attempts_per_worker"];
  if (Object.keys(row).some(key => !allowed.includes(key)) || typeof row.base_executor_profile_id !== "string" || !identifier.test(row.base_executor_profile_id)
    || !Array.isArray(row.presets) || !row.presets.length || row.presets.length > 1024 || !Array.isArray(row.plugins) || !Array.isArray(row.role_bindings)) throw new Error("服务端配置结构不符合已审定的编辑合同，未使用替代配置。");
  for (const preset of row.presets) {
    const item = object(preset);
    if (Object.keys(item).sort().join(",") !== "clone_from,description,id,name,persona_prefix" || ["id", "name", "description", "persona_prefix", "clone_from"].some(key => typeof item[key] !== "string")) throw new Error("预设字段不完整，未将读取失败显示为空预设。");
  }
  for (const plugin of row.plugins) {
    const item = object(plugin);
    if (Object.keys(item).sort().join(",") !== "config,enabled,entry_id" || typeof item.entry_id !== "string" || typeof item.enabled !== "boolean" || !item.config || Array.isArray(item.config) || typeof item.config !== "object" || Object.values(item.config).some(v => !["boolean", "number", "string"].includes(typeof v))) throw new Error("插件配置结构不支持安全表单编辑。");
  }
  for (const binding of row.role_bindings) {
    const item = object(binding);
    if (Object.keys(item).sort().join(",") !== "position_id,preset_id" || typeof item.position_id !== "string" || typeof item.preset_id !== "string") throw new Error("岗位绑定结构不完整，不能推算岗位或自动补齐。");
  }
  return clone(row as unknown as Spec);
}
function checkedContext(value: unknown, project: string, profile?: string): Context {
  const row = object(value);
  if (row.project_id !== project || row.schema_version !== "forgeflow.native-configuration-context.v1" || typeof row.model !== "string" || typeof row.base_config_sha256 !== "string" || !sha256.test(row.base_config_sha256)
    || row.offline_only !== true || row.runtime_actions_available !== false || row.runtime_invoked !== false || row.execution_rights_granted !== false
    || !Array.isArray(row.required_plugins) || row.required_plugins.some(v => typeof v !== "string")) throw new Error("离线配置来源或项目身份不匹配，未装载编辑内容。");
  const spec = checkedSpec(row.spec);
  if (profile && spec.base_executor_profile_id !== profile) throw new Error("历史版本的配置基底与服务端返回不一致，未套用当前运行基底。");
  return { ...row, spec } as unknown as Context;
}
function checkedDraft(value: unknown, project: string): Draft {
  const row = object(value);
  if (row.project_id !== project || typeof row.draft_id !== "string" || !identifier.test(row.draft_id) || !Number.isSafeInteger(row.revision) || Number(row.revision) < 1
    || !["DRAFT", "PREVIEWED", "PUBLISHED"].includes(String(row.status)) || typeof row.base_config_sha256 !== "string" || !sha256.test(row.base_config_sha256)) throw new Error("草案项目、身份或版本无效，未打开其他项目内容。");
  return { ...row, spec: checkedSpec(row.spec) } as unknown as Draft;
}
function issues(spec: Spec, context: Context): string[] {
  const errors: string[] = [];
  const baseline = context.spec;
  const templates = new Map(baseline.presets.map(p => [p.id, p]));
  const ids = new Set<string>();
  for (const p of spec.presets) {
    if (!identifier.test(p.id) || ids.has(p.id) || !templates.has(p.clone_from)) errors.push(`预设 ${p.id}：ID 或原始模板无效。`);
    ids.add(p.id);
    if (templates.has(p.id) && p.clone_from !== p.id) errors.push(`原预设 ${p.id} 不能更换组合模板。`);
    for (const [field, label, maximum] of [["name", "名称", 256], ["description", "说明", 4096], ["persona_prefix", "Persona", 32768]] as const)
      if (byteLength(p[field]) > maximum || field !== "description" && !p[field].trim()) errors.push(`预设 ${p.id} 的${label}需满足非空及 ${maximum} 字节限制（说明可为空）。`);
  }
  if (spec.presets.length > 1024 || baseline.presets.some(p => !ids.has(p.id))) errors.push("原有预设必须保留，预设总量不能超过 1,024。");
  const plugins = new Map(spec.plugins.map(p => [p.entry_id, p]));
  if (context.required_plugins.some(id => !plugins.has(id))) errors.push("配置缺少必需插件，不能补造或忽略该来源问题。");
  if (plugins.size !== baseline.plugins.length || spec.plugins.length !== baseline.plugins.length) errors.push("可编辑插件集合必须与基底一致。");
  for (const original of baseline.plugins) {
    const p = plugins.get(original.entry_id);
    if (!p || stable(Object.keys(p.config).sort()) !== stable(Object.keys(original.config).sort())) { errors.push(`插件 ${original.entry_id} 的参数集合发生变化。`); continue; }
    if (context.required_plugins.includes(p.entry_id) && !p.enabled) errors.push(`必需插件 ${p.entry_id} 不能停用。`);
    for (const [key, value] of Object.entries(p.config)) {
      if (typeof value !== typeof original.config[key] || typeof value === "number" && (!Number.isInteger(value) || value < 1 || value > 1000000)) errors.push(`插件 ${p.entry_id} · ${key} 的类型或整数范围无效。`);
      if (key === "maxDepth" && value !== 2) errors.push(`插件 ${p.entry_id} 的委派深度必须为 2。`);
    }
  }
  const positions = new Set(baseline.role_bindings.map(r => r.position_id));
  const seen = new Set<string>(), bound = new Set<string>();
  for (const r of spec.role_bindings) {
    if (!positions.has(r.position_id) || seen.has(r.position_id) || bound.has(r.preset_id) || !ids.has(r.preset_id)) errors.push(`岗位 ${r.position_id} 需唯一绑定一个存在且未被其他岗位使用的预设。`);
    seen.add(r.position_id); bound.add(r.preset_id);
  }
  if (seen.size !== positions.size) errors.push("必须保留基底中的完整岗位集合。");
  if (spec.max_active_attempts_per_worker !== undefined && (!Object.hasOwn(baseline, "max_active_attempts_per_worker") || !Number.isInteger(spec.max_active_attempts_per_worker) || spec.max_active_attempts_per_worker < 1 || spec.max_active_attempts_per_worker > 64)) errors.push("当前基底不支持该容量字段，或容量不在 1–64 范围内。");
  if (byteLength(stable(spec)) > 4 * 1024 * 1024) errors.push("完整草案超过服务端 4 MiB 上限。");
  return errors;
}
function differences(spec: Spec, baseline: Spec): Difference[] {
  const result: Difference[] = [];
  const before = new Map(baseline.presets.map(p => [p.id, p]));
  for (const p of spec.presets) {
    const old = before.get(p.id);
    if (!old) result.push({ id: p.id, field: "预设", message: `新增“${p.name}”，继承模板 ${p.clone_from}` });
    else for (const [field, label] of [["name", "名称"], ["description", "说明"], ["persona_prefix", "Persona"]] as const)
      if (old[field] !== p[field]) result.push({ id: p.id, field: label, message: field === "name" ? `“${old.name}” → “${p.name}”` : `更新内容：${byteLength(old[field])} → ${byteLength(p[field])} 字节` });
  }
  const oldPlugins = new Map(baseline.plugins.map(p => [p.entry_id, p]));
  for (const p of spec.plugins) {
    const old = oldPlugins.get(p.entry_id); if (!old) continue;
    if (old.enabled !== p.enabled) result.push({ id: p.entry_id, field: "启用状态", message: p.enabled ? "改为启用" : "改为停用" });
    for (const [key, value] of Object.entries(p.config)) if (value !== old.config[key]) result.push({ id: p.entry_id, field: key, message: `${String(old.config[key])} → ${String(value)}` });
  }
  const oldRoles = new Map(baseline.role_bindings.map(r => [r.position_id, r.preset_id]));
  for (const r of spec.role_bindings) if (oldRoles.get(r.position_id) !== r.preset_id) result.push({ id: r.position_id, field: "岗位预设", message: `${oldRoles.get(r.position_id)} → ${r.preset_id}` });
  if (spec.max_active_attempts_per_worker !== baseline.max_active_attempts_per_worker) result.push({ id: spec.base_executor_profile_id, field: "每 Worker 根任务容量", message: `${baseline.max_active_attempts_per_worker ?? "保持原值"} → ${spec.max_active_attempts_per_worker ?? "保持原值"}` });
  return result;
}
function Pager({ page, count, size, onChange }: { page: number; count: number; size: number; onChange: (page: number) => void }) {
  const pages = Math.max(1, Math.ceil(count / size));
  return <div className="configuration-pagination"><span>第 {Math.min(page + 1, pages)} / {pages} 页 · {count} 项</span><button type="button" disabled={page === 0} onClick={() => onChange(page - 1)}>上一页</button><button type="button" disabled={page + 1 >= pages} onClick={() => onChange(page + 1)}>下一页</button></div>;
}

export function NativeConfigurationEditor({ projectId }: { projectId?: string }) {
  return projectId ? <Editor key={projectId} projectId={projectId} /> : <Panel title="执行预设与插件"><EmptyState title="选择项目编辑执行配置" description="草案、预设和岗位绑定均从该项目的已审定基底读取。" /></Panel>;
}
function Editor({ projectId }: { projectId: string }) {
  const root = `/projects/${encodeURIComponent(projectId)}/execution-configuration`;
  const [context, setContext] = useState<Context>();
  const [currentBase, setCurrentBase] = useState<{ id: string; sha: string }>();
  const [spec, setSpec] = useState<Spec>();
  const [versions, setVersions] = useState<Draft[]>();
  const [saved, setSaved] = useState<Draft>();
  const [draftId, setDraftId] = useState("");
  const [origin, setOrigin] = useState("");
  const [history, setHistory] = useState(false);
  const [tab, setTab] = useState<Tab>("presets");
  const [selected, setSelected] = useState("");
  const [search, setSearch] = useState("");
  const [page, setPage] = useState(0);
  const [cloneId, setCloneId] = useState("");
  const [cloneName, setCloneName] = useState("");
  const [role, setRole] = useState("");
  const [roleSearch, setRoleSearch] = useState("");
  const [rolePage, setRolePage] = useState(0);
  const [busy, setBusy] = useState("");
  const [error, setError] = useState<Error>();
  const [versionError, setVersionError] = useState<Error>();
  const [notice, setNotice] = useState("");
  const [validation, setValidation] = useState<string>();
  const life = useRef<AbortController | undefined>(undefined);
  const pending = useRef<{ signature: string; key: string } | undefined>(undefined);
  const dirtyRef = useRef(false);
  const inFlight = useRef(false);
  const rolePicker = useRef<HTMLElement | null>(null);
  const signature = useMemo(() => spec ? stable(spec) : "", [spec]);
  const dirty = !!spec && signature !== origin;
  dirtyRef.current = dirty || !!cloneId || !!cloneName;
  const readOnly = history || saved?.status === "PUBLISHED" || !!busy;
  const errors = useMemo(() => spec && context ? issues(spec, context) : [], [spec, context]);
  const changes = useMemo(() => spec && context ? differences(spec, context.spec) : [], [spec, context]);
  const currentValidation = !!context && validation === `${context.base_config_sha256}:${signature}`;
  const preset = spec?.presets.find(p => p.id === selected);
  const template = context?.spec.presets.find(p => p.id === preset?.clone_from);
  const rows = useMemo(() => {
    if (!spec) return [];
    const query = search.trim().toLocaleLowerCase();
    if (tab === "presets") return spec.presets.filter(p => !query || `${p.id} ${p.name} ${p.description}`.toLocaleLowerCase().includes(query));
    if (tab === "plugins") return spec.plugins.filter(p => !query || p.entry_id.toLocaleLowerCase().includes(query));
    if (tab === "roles") return spec.role_bindings.filter(r => !query || `${r.position_id} ${r.preset_id} ${spec.presets.find(p => p.id === r.preset_id)?.name ?? ""}`.toLocaleLowerCase().includes(query));
    return [];
  }, [spec, search, tab]);
  const activePage = Math.min(page, Math.max(0, Math.ceil(rows.length / 12) - 1));
  const roleChoices = useMemo(() => spec?.presets.filter(p => !roleSearch || `${p.name} ${p.id}`.toLocaleLowerCase().includes(roleSearch.trim().toLocaleLowerCase())) ?? [], [spec, roleSearch]);
  const choicePage = Math.min(rolePage, Math.max(0, Math.ceil(roleChoices.length / 10) - 1));
  function mayDiscard() { return !dirtyRef.current || window.confirm("当前执行配置有未保存内容。离开会放弃这些本地更改，是否继续？"); }
  function update(change: (value: Spec) => void) {
    if (readOnly) return;
    setSpec(previous => { if (!previous) return previous; const next = clone(previous); change(next); return next; });
    setValidation(undefined); setNotice("");
  }
  function install(ctx: Context, value: Spec, draft?: Draft, asHistory = false, copied = false) {
    setContext(ctx); setSpec(clone(value)); setSaved(draft); setDraftId(draft?.draft_id ?? newId()); setOrigin(copied ? "" : stable(value));
    setHistory(asHistory); setTab("presets"); setSelected(value.presets[0]?.id ?? ""); setValidation(undefined); setCloneId(""); setCloneName(""); setRole(""); setSearch(""); setPage(0); pending.current = undefined;
  }
  async function readContext(signal: AbortSignal, profile?: string) {
    return checkedContext(await api.get<unknown>(`${root}${profile ? `?executor_profile_id=${encodeURIComponent(profile)}` : ""}`, signal), projectId, profile);
  }
  async function readVersions(signal: AbortSignal) {
    const value = await api.get<unknown>(`${root}/drafts`, signal);
    if (!Array.isArray(value)) throw new Error("版本接口未返回实际列表，不能将读取失败视为空历史。");
    return value.map(row => checkedDraft(row, projectId));
  }
  async function loadCurrent(ask = true) {
    if (busy || ask && !mayDiscard()) return;
    const controller = life.current; if (!controller) return;
    setBusy("LOAD"); setError(undefined); setVersionError(undefined); setNotice(""); setContext(undefined); setSpec(undefined); setSaved(undefined); setVersions(undefined);
    const [ctx, drafts] = await Promise.allSettled([readContext(controller.signal), readVersions(controller.signal)]);
    if (controller.signal.aborted) return;
    if (ctx.status === "fulfilled") { install(ctx.value, ctx.value.spec); setCurrentBase({ id: ctx.value.spec.base_executor_profile_id, sha: ctx.value.base_config_sha256 }); }
    else setError(message(ctx.reason));
    if (drafts.status === "fulfilled") setVersions(drafts.value); else setVersionError(message(drafts.reason));
    setBusy("");
  }
  async function refreshVersions() {
    if (busy || !life.current) return;
    setBusy("VERSIONS"); setVersionError(undefined);
    try { const result = await readVersions(life.current.signal); if (!life.current.signal.aborted) setVersions(result); }
    catch (failure) { if (!life.current.signal.aborted) { setVersions(undefined); setVersionError(message(failure)); } }
    finally { if (!life.current.signal.aborted) setBusy(""); }
  }
  async function openVersion(version: Draft, copyAsNew = false) {
    if (busy || !mayDiscard() || !life.current) return;
    setBusy("OPEN"); setError(undefined); setNotice("");
    try {
      const ctx = await readContext(life.current.signal, version.spec.base_executor_profile_id);
      if (life.current.signal.aborted) return;
      const value = clone(version.spec);
      const droppedCapacity = !Object.hasOwn(ctx.spec, "max_active_attempts_per_worker") && Object.hasOwn(value, "max_active_attempts_per_worker");
      if (copyAsNew && droppedCapacity) delete value.max_active_attempts_per_worker;
      install(ctx, value, copyAsNew ? undefined : version, !copyAsNew, copyAsNew);
      setNotice(copyAsNew ? `已复制为新草案，基底 ${ctx.spec.base_executor_profile_id}。原版本保持不变。${droppedCapacity ? "当前基底不支持容量字段，未将该字段带入新草案。" : ""}` : "历史内容只读。继续编辑符合当前源身份的草案，或复制为新草案。");
    } catch (failure) { if (!life.current.signal.aborted) setError(message(failure)); }
    finally { if (!life.current.signal.aborted) setBusy(""); }
  }
  async function saveOrValidate(action: "SAVE" | "VALIDATE") {
    if (!context || !spec || readOnly || errors.length || !life.current || inFlight.current) return;
    inFlight.current = true;
    setBusy(action); setError(undefined); setNotice("");
    const source = { base_config_sha256: context.base_config_sha256, spec };
    try {
      if (action === "VALIDATE") {
        setValidation(undefined);
        const result = await api.post<{ valid: boolean; native_resolution: string; runtime_invoked: boolean; execution_rights_granted: boolean }>(`${root}/validations`, source, { signal: life.current.signal });
        if (life.current.signal.aborted) return;
        if (result.valid !== true || result.native_resolution !== "NOT_RUN" || result.runtime_invoked !== false || result.execution_rights_granted !== false) throw new Error("离线校验没有返回预期边界，未显示校验成功。");
        setValidation(`${context.base_config_sha256}:${signature}`); setNotice("服务端离线结构校验通过。原生组合解析、运行资格、发布及激活均未执行。");
      } else {
        const body = { draft_id: draftId, expected_revision: saved?.revision ?? null, ...source };
        const fingerprint = stable(body);
        if (pending.current?.signature !== fingerprint) pending.current = { signature: fingerprint, key: crypto.randomUUID() };
        const result = checkedDraft(await api.post<unknown>(`${root}/drafts`, body, { idempotencyKey: pending.current.key, signal: life.current.signal }), projectId);
        if (life.current.signal.aborted) return;
        if (result.draft_id !== draftId || result.status !== "DRAFT" || stable(result.spec) !== signature) throw new Error("保存回执与本次草案身份或内容不匹配，未标记已保存。");
        setSaved(result); setSpec(clone(result.spec)); setOrigin(stable(result.spec)); setVersions(previous => previous ? [...previous.filter(v => v.draft_id !== result.draft_id), result] : undefined); pending.current = undefined;
        setNotice(`草案已保存：R${result.revision}。保存不发布配置，也不启动 Agent。`);
      }
    } catch (failure) { if (!life.current.signal.aborted) { setError(message(failure)); setValidation(undefined); } }
    finally { inFlight.current = false; if (!life.current.signal.aborted) setBusy(""); }
  }
  useEffect(() => {
    const controller = new AbortController(); life.current = controller; void loadCurrent(false);
    return () => controller.abort();
  }, []);
  useEffect(() => {
    const unload = (event: BeforeUnloadEvent) => { if (dirtyRef.current) { event.preventDefault(); event.returnValue = ""; } };
    const click = (event: MouseEvent) => {
      const target = event.target instanceof Element ? event.target.closest<HTMLAnchorElement>("a[href]") : null;
      if (!dirtyRef.current || !target || target.origin !== window.location.origin || target.href === window.location.href || target.target === "_blank" || target.hasAttribute("download")) return;
      if (!mayDiscard()) { event.preventDefault(); event.stopImmediatePropagation(); } else dirtyRef.current = false;
    };
    const projectChange = (event: Event) => {
      const target = event.target;
      if (!(target instanceof HTMLSelectElement) || !dirtyRef.current) return;
      const label = document.getElementById(target.getAttribute("aria-labelledby") ?? "")?.textContent;
      if (label !== "查看执行项目") return;
      if (!mayDiscard()) { target.value = projectId; event.preventDefault(); event.stopImmediatePropagation(); } else dirtyRef.current = false;
    };
    window.addEventListener("beforeunload", unload); document.addEventListener("click", click, true); document.addEventListener("change", projectChange, true);
    return () => { window.removeEventListener("beforeunload", unload); document.removeEventListener("click", click, true); document.removeEventListener("change", projectChange, true); };
  }, [projectId]);
  useEffect(() => { setPage(0); setSearch(""); }, [tab]);
  useEffect(() => { if (role) rolePicker.current?.scrollIntoView({ block: "nearest", behavior: "auto" }); }, [role]);
  const versionPages = versions ? Math.max(1, Math.ceil(versions.length / 10)) : 1;
  const versionPage = Math.min(page, versionPages - 1);

  return <Panel className="native-configuration-editor" title={<><Layers size={16} />执行预设与插件</>} actions={<button type="button" disabled={!!busy} onClick={() => void loadCurrent()}><RefreshCw size={14} />读取当前基底</button>}>
    <div className="configuration-intro"><p>在主工作台编辑预设、配套插件和岗位绑定。此处只读取、离线校验及保存草案，DSH 保持停用。</p><span className="configuration-pill">离线编辑</span></div>
    {error && <ErrorNotice error={error} />}
    {busy === "LOAD" && <p role="status" className="configuration-note">正在读取实际配置与版本记录…</p>}
    {!context || !spec ? !busy && <EmptyState title="尚未取得可编辑配置" description="该项目须有已审定的执行基底。读取失败时不会自动生成空预设或替代岗位。" /> : <>
      <div className="configuration-baselines"><div><span>当前默认配置 · 读取快照</span><code>{currentBase?.id ?? "尚未读取"}</code>{currentBase && currentBase.sha !== context.base_config_sha256 && <small>源身份已变化，请重新读取当前默认配置核对。</small>}</div><div><span>{history ? "正在查看的历史基底" : "本草案编辑基底"}</span><code>{context.spec.base_executor_profile_id}</code></div><div><span>当前内容</span><strong>{history ? saved?.status === "PUBLISHED" ? "已发布历史 · 只读" : "已保存草案 · 只读查看" : saved ? `草案 R${saved.revision}${dirty ? " · 有未保存更改" : " · 已保存"}` : "尚未保存的新草案"}</strong></div></div>
      <p className="configuration-note">默认配置用于未来绑定；已准入尝试继续保留各自的冻结配置。</p>
      <div className="configuration-actions"><button type="button" disabled={readOnly || !!errors.length || !!saved && !dirty} onClick={() => void saveOrValidate("SAVE")}><Save size={14} />{busy === "SAVE" ? "正在保存…" : "保存草案"}</button><button type="button" disabled={readOnly || !!errors.length} onClick={() => void saveOrValidate("VALIDATE")}><ShieldCheck size={14} />{busy === "VALIDATE" ? "正在离线校验…" : "服务器离线校验"}</button><button type="button" disabled={!!busy} onClick={() => void loadCurrent()}><FilePlus2 size={14} />从当前基底新建</button>{saved && <button type="button" disabled={!!busy} onClick={() => void openVersion(saved, true)}><Copy size={14} />复制为新草案</button>}{history && saved?.status !== "PUBLISHED" && saved?.base_config_sha256 === context.base_config_sha256 && <button type="button" disabled={!!busy} onClick={() => { setHistory(false); setValidation(undefined); setNotice("正在编辑已保存草案；保存将核对原修订号。"); }}>继续编辑此草案</button>}</div>
      {notice && <p role="status" className="configuration-notice">{notice}</p>}
      {currentValidation && <p className="configuration-validation" role="status">离线校验通过 · Native resolution: NOT_RUN · 未发布 / 未激活 / 未启动</p>}
      {errors.length > 0 && <div className="configuration-errors" role="alert"><strong>保存前需修正 {errors.length} 项</strong><ul>{errors.slice(0, 8).map((error, index) => <li key={index}>{error}</li>)}</ul>{errors.length > 8 && <p>其余问题会在修正后继续显示。</p>}</div>}
      <div className="configuration-tabs" role="tablist" aria-label="执行配置编辑区域">{([["presets", `预设 ${spec.presets.length}`], ["plugins", `配套插件 ${spec.plugins.length}`], ["roles", `岗位绑定 ${spec.role_bindings.length}`], ["changes", `本地变更 ${changes.length}`], ["versions", `版本记录 ${versions?.length ?? "—"}`]] as [Tab, string][]).map(([id, label]) => <button type="button" key={id} role="tab" aria-selected={tab === id} onClick={() => setTab(id)}>{label}</button>)}</div>
      {["presets", "plugins", "roles"].includes(tab) && <div className="configuration-search"><Search size={15} /><input aria-label="搜索当前配置区域" placeholder={tab === "presets" ? "搜索预设名称、说明或 ID" : tab === "plugins" ? "搜索可编辑插件" : "搜索岗位、预设名称或 ID"} value={search} onChange={event => { setSearch(event.target.value); setPage(0); }} /><span>{rows.length} 项匹配</span></div>}
      {tab === "presets" && <div className="configuration-preset-workspace"><section className="configuration-picker" aria-label="预设列表">{(rows as Preset[]).slice(activePage * 12, (activePage + 1) * 12).map(p => <button type="button" key={p.id} aria-pressed={selected === p.id} onClick={() => setSelected(p.id)}><strong>{p.name}</strong><code>{p.id}</code></button>)}{!rows.length && <p className="configuration-note">当前搜索没有匹配预设。</p>}<Pager page={activePage} count={rows.length} size={12} onChange={setPage} /></section><section className="configuration-preset-form" aria-label="预设编辑表单">{preset && <><header><h3>{preset.name || "未命名预设"}</h3><code>{preset.id}</code></header><fieldset disabled={readOnly}><Field label="预设名称" hint={`${byteLength(preset.name)} / 256 字节`}><input value={preset.name} maxLength={256} onChange={event => update(next => { next.presets.find(p => p.id === preset.id)!.name = event.target.value; })} /></Field><Field label="预设说明" hint={`${byteLength(preset.description)} / 4,096 字节`}><textarea rows={3} maxLength={4096} value={preset.description} onChange={event => update(next => { next.presets.find(p => p.id === preset.id)!.description = event.target.value; })} /></Field><Field label="Persona 指令" hint={`${byteLength(preset.persona_prefix)} / 32,768 字节；只修改该预设的受审前缀。`}><textarea rows={8} maxLength={32768} value={preset.persona_prefix} onChange={event => update(next => { next.presets.find(p => p.id === preset.id)!.persona_prefix = event.target.value; })} /></Field></fieldset><details className="configuration-clone"><summary>克隆当前预设为新 ID</summary><p>继承当前已编辑的说明与 Persona，组合模板继续沿用基底中的 <code>{template?.id ?? "模板未提供"}</code>。原预设与组合模板保持不变。</p><fieldset disabled={readOnly}><Field label="新预设 ID"><input value={cloneId} maxLength={128} onChange={event => setCloneId(event.target.value)} /></Field><Field label="新预设名称"><input value={cloneName} maxLength={256} onChange={event => setCloneName(event.target.value)} /></Field><button type="button" disabled={!template || !identifier.test(cloneId) || !cloneName.trim() || byteLength(cloneName) > 256 || spec.presets.some(p => p.id === cloneId) || spec.presets.length >= 1024} onClick={() => { if (!template || !preset) return; update(next => next.presets.push({ ...clone(preset), id: cloneId, name: cloneName, clone_from: template.id })); setSelected(cloneId); setCloneId(""); setCloneName(""); }}>添加克隆预设到草案</button></fieldset></details>{!context.spec.presets.some(p => p.id === preset.id) && <button type="button" disabled={readOnly || spec.role_bindings.some(r => r.preset_id === preset.id)} onClick={() => { update(next => { next.presets = next.presets.filter(p => p.id !== preset.id); }); setSelected(context.spec.presets[0].id); }}>移除此草案新增预设</button>}</>}</section></div>}
      {tab === "plugins" && <section className="configuration-plugins" aria-label="配套插件参数"><p className="configuration-note">这是所选项目基底中可编辑的配套插件集合，不是 DSH 宿主的完整插件库存。模型、沙箱和 ForgeFlow 桥不在编辑范围。</p>{(rows as Plugin[]).slice(activePage * 12, (activePage + 1) * 12).map(plugin => <article key={plugin.entry_id} className="configuration-plugin"><header><label><input type="checkbox" checked={plugin.enabled} disabled={readOnly || context.required_plugins.includes(plugin.entry_id)} onChange={event => update(next => { next.plugins.find(p => p.entry_id === plugin.entry_id)!.enabled = event.target.checked; })} /><code>{plugin.entry_id}</code></label>{context.required_plugins.includes(plugin.entry_id) && <span className="configuration-pill">必需 · 保持启用</span>}</header><fieldset disabled={readOnly}>{Object.entries(plugin.config).map(([key, value]) => <Field key={key} label={`${plugin.entry_id} · ${key}`} hint={key === "maxDepth" ? "委派深度固定为 2，不提升子代权限。" : undefined}>{typeof value === "boolean" ? <input type="checkbox" checked={value} disabled={key === "maxDepth"} onChange={event => update(next => { next.plugins.find(p => p.entry_id === plugin.entry_id)!.config[key] = event.target.checked; })} /> : typeof value === "number" ? <input type="number" min={1} max={1000000} step={1} value={value} disabled={key === "maxDepth"} onChange={event => update(next => { next.plugins.find(p => p.entry_id === plugin.entry_id)!.config[key] = Number(event.target.value); })} /> : key === "backgroundMode" ? <select value={value} onChange={event => update(next => { next.plugins.find(p => p.entry_id === plugin.entry_id)!.config[key] = event.target.value; })}>{[...new Set(["foreground", "background", "auto", "disabled", "enabled", String(context.spec.plugins.find(p => p.entry_id === plugin.entry_id)?.config[key] ?? value)])].map(option => <option value={option} key={option}>{option}</option>)}</select> : <input value={value} readOnly />}</Field>)}</fieldset>{!Object.keys(plugin.config).length && <p className="configuration-note">此插件没有开放给编辑器的参数。</p>}</article>)}<Pager page={activePage} count={rows.length} size={12} onChange={setPage} /></section>}
      {tab === "roles" && <section className="configuration-roles" aria-label="岗位预设绑定"><p className="configuration-note">完整岗位集合来自所选基底。每个岗位与预设均保持唯一；更换前可先克隆独立预设。岗位数量不代表活动 Agent 数。</p>{(rows as Binding[]).slice(activePage * 12, (activePage + 1) * 12).map(binding => <div className="configuration-role" key={binding.position_id}><div><code>{binding.position_id}</code><strong>{spec.presets.find(p => p.id === binding.preset_id)?.name ?? "绑定预设未找到"}</strong><small>{binding.preset_id}</small></div><button type="button" disabled={readOnly} onClick={() => { setRole(binding.position_id); setRoleSearch(""); setRolePage(0); }}>更换预设</button></div>)}<Pager page={activePage} count={rows.length} size={12} onChange={setPage} />{role && <section ref={rolePicker} className="configuration-role-picker" aria-label="为岗位选择预设"><header><h3>岗位 {role}</h3><button type="button" onClick={() => setRole("")}>关闭选择</button></header><Field label="搜索岗位可用预设"><input value={roleSearch} onChange={event => { setRoleSearch(event.target.value); setRolePage(0); }} /></Field>{roleChoices.slice(choicePage * 10, (choicePage + 1) * 10).map(p => { const used = spec.role_bindings.find(r => r.position_id !== role && r.preset_id === p.id); return <button type="button" key={p.id} disabled={readOnly || !!used} onClick={() => { update(next => { if (!next.role_bindings.some(r => r.position_id !== role && r.preset_id === p.id)) next.role_bindings.find(r => r.position_id === role)!.preset_id = p.id; }); setRole(""); }}><strong>{p.name}</strong><code>{p.id}</code>{used && <small>已绑定岗位 {used.position_id}</small>}</button>; })}<Pager page={choicePage} count={roleChoices.length} size={10} onChange={setRolePage} /></section>}</section>}
      {tab === "changes" && <section className="configuration-changes" aria-label="本地字段变更摘要"><h3>与所选基底比较 · 本地计算</h3><p className="configuration-note">下列摘要按稳定 ID 和字段解释差异，不是服务器原生组合预览，也不证明运行资格。</p>{!changes.length ? <p>尚无相对基底的字段变更。</p> : <ul>{changes.map((change, index) => <li key={`${change.id}:${change.field}:${index}`}><strong>{change.field}</strong><code>{change.id}</code><span>{change.message}</span></li>)}</ul>}{Object.hasOwn(context.spec, "max_active_attempts_per_worker") && <Field label="每 Worker 根任务容量" hint="仅当前基底实际开放此字段时可编辑；配置容量不等于活动 Agent 数。"><input type="number" min={1} max={64} step={1} value={spec.max_active_attempts_per_worker ?? ""} disabled={readOnly} onChange={event => update(next => { if (event.target.value === "") delete next.max_active_attempts_per_worker; else next.max_active_attempts_per_worker = Number(event.target.value); })} /></Field>}</section>}
    </>}
    {(tab === "versions" || !context) && <section className="configuration-versions" aria-label="配置版本记录"><header><h3>草案与已发布历史</h3><button type="button" disabled={!!busy} onClick={() => void refreshVersions()}>刷新版本记录</button></header>{versionError && <ErrorNotice error={versionError} onRetry={() => void refreshVersions()} />}{versions === undefined ? <p className="configuration-note">尚未取得完整版本列表，不能判断是否没有历史。</p> : !versions.length ? <p className="configuration-note">当前项目没有已登记的配置草案或已发布版本。</p> : <>{[...versions].reverse().slice(versionPage * 10, (versionPage + 1) * 10).map(version => <article key={version.draft_id}><div><StatusBadge state={version.status} /><strong>R{version.revision} · {version.spec.presets.length} 个预设</strong><code>{version.draft_id}</code><small>基底 {version.spec.base_executor_profile_id}</small>{version.published_executor_profile_id && <small>已发布为 {version.published_executor_profile_id}</small>}</div><div className="configuration-version-actions"><button type="button" disabled={!!busy} onClick={() => void openVersion(version)}>只读打开</button><button type="button" disabled={!!busy} onClick={() => void openVersion(version, true)}>复制为新草案</button></div></article>)}<Pager page={versionPage} count={versions.length} size={10} onChange={setPage} /></>}</section>}
    <div className="configuration-runtime-note"><strong>运行操作保持关闭</strong><p>发布前需要原生组合解析与适用的真实资格。未来可在恢复授权后的原生操作面板完成预览、发布及激活；此离线编辑器不调用这些操作，也不恢复 DSH 自启动。</p></div>
    {context && <details className="configuration-diagnostics"><summary>来源与版本诊断</summary><dl><dt>项目</dt><dd>{projectId}</dd><dt>当前编辑源 SHA256</dt><dd><code>{context.base_config_sha256}</code></dd><dt>草案身份</dt><dd><code>{draftId}</code></dd><dt>已保存草案源 SHA256</dt><dd><code>{saved?.base_config_sha256 ?? "尚未保存"}</code></dd><dt>原生解析</dt><dd>NOT_RUN</dd><dt>模型</dt><dd>{context.model}</dd></dl></details>}
  </Panel>;
}
