import { useEffect, useState } from "react";
import { ArrowRight, ClipboardCheck, FolderKey, Plus, RefreshCw, Save, Undo2 } from "lucide-react";
import { api, ApiError } from "../../app/api";
import { EmptyState, ErrorNotice, Field, Panel } from "../../components";
import { useCollection } from "../portfolio/collection";
import { useCommandIdentity } from "../portfolio/commands";
import { num, path, str, type Row } from "../portfolio/monitor";
import "./owner-territories.css";

interface Territory {
  owner_id: string; root_team_id: string | null; include: string[]; exclude: string[]; revision: number;
}
interface Draft {
  ownerId: string; rootTeamId: string; includeText: string; excludeText: string; base: Territory | null;
}
function territory(value: Row | undefined): Territory | undefined {
  if (!value || typeof value.owner_id !== "string" || !value.owner_id
    || !Number.isSafeInteger(value.revision) || Number(value.revision) < 1
    || (value.root_team_id !== undefined && value.root_team_id !== null && typeof value.root_team_id !== "string")
    || ![value.include, value.exclude].every(list => Array.isArray(list)
      && list.every(entry => typeof entry === "string" && !/[\r\n]/.test(entry)))) return;
  return { owner_id: value.owner_id, root_team_id: typeof value.root_team_id === "string" ? value.root_team_id : null,
    include: value.include as string[], exclude: value.exclude as string[], revision: Number(value.revision) };
}
const lines = (value: string) => value.split("\n").filter(line => line !== "");
// Match the server's relative-path checks without trimming filenames or expanding globs.
const safePath = (value: string) => !value.startsWith("/") && !/[\\\0:]/.test(value)
  && !value.replace(/\/+$/, "").split("/").some(part => !part || part === "." || part === "..");
const meaning = (value: Pick<Territory, "owner_id" | "root_team_id" | "include" | "exclude">) =>
  JSON.stringify([value.owner_id, value.root_team_id, value.include, value.exclude]);
function fromTerritory(value: Territory): Draft {
  return { ownerId: value.owner_id, rootTeamId: value.root_team_id ?? "", includeText: value.include.join("\n"),
    excludeText: value.exclude.join("\n"), base: value };
}

export function OwnerTerritories({ projectId, project, projectReady, teams, teamsComplete, selectedTeamId, onSaved }: {
  projectId: string; project?: Row; projectReady: boolean; teams: Row[]; teamsComplete: boolean;
  selectedTeamId?: string; onSaved: () => void;
}) {
  const query = useCollection<Row>(`/projects/${path(projectId)}/owners`);
  const commandIdentity = useCommandIdentity();
  const [selected, setSelected] = useState("");
  const [draft, setDraft] = useState<Draft>();
  const [creating, setCreating] = useState(false);
  const [preview, setPreview] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>();
  const [conflict, setConflict] = useState(false);
  const [message, setMessage] = useState("");
  const owners = query.data ?? [];
  const actualTeams = teams.filter(team => team.project_id === projectId && typeof team.team_id === "string");
  const availableTeams = actualTeams.filter(team => !owners.some(owner => owner.owner_id === team.team_id));
  const current = owners.find(owner => owner.owner_id === (creating ? draft?.ownerId : selected));
  const latest = territory(current);
  const writable = projectReady && project?.authority_mode === "MANAGED" && project.archived === false;
  const loaded = query.data !== undefined && !query.loading && !query.error && teamsComplete;
  const value = draft ? { owner_id: draft.ownerId, root_team_id: draft.rootTeamId || null,
    include: lines(draft.includeText), exclude: lines(draft.excludeText) } : undefined;
  const invalidPaths = value ? [...value.include, ...value.exclude].filter(entry => !safePath(entry)) : [];
  const valid = Boolean(value?.owner_id && value.include.length && !invalidPaths.length
    && actualTeams.some(team => team.team_id === value.root_team_id)
    && (!creating || availableTeams.some(team => team.team_id === value.owner_id)));
  const changed = Boolean(value && (!draft?.base || meaning(value) !== meaning(draft.base)));
  const stale = Boolean(draft && (creating ? owners.some(owner => owner.owner_id === draft.ownerId)
    : !latest || latest.revision !== draft.base?.revision));
  const body = value && draft ? { id: draft.ownerId, expected_revision: draft.base?.revision ?? null, value } : undefined;
  const fingerprint = body ? JSON.stringify(body) : "";
  const canPreview = loaded && writable && valid && changed && !busy && !stale && !conflict;

  function choose(ownerId: string) {
    setSelected(ownerId); setCreating(false); setPreview(""); setError(undefined); setConflict(false); setMessage("");
    const record = territory(owners.find(owner => owner.owner_id === ownerId));
    setDraft(record ? fromTerritory(record) : undefined);
  }
  useEffect(() => {
    if (!selected && !creating && query.data?.length) choose(str(query.data[0].owner_id, ""));
    else if (selected && !creating && !draft && latest) setDraft(fromTerritory(latest));
  }, [query.data, selected, creating, draft]);

  function create() {
    const team = availableTeams.find(team => team.team_id === selectedTeamId) ?? availableTeams[0];
    if (!team) return;
    const teamId = String(team.team_id);
    setCreating(true); setSelected(""); setDraft({ ownerId: teamId, rootTeamId: teamId,
      includeText: "", excludeText: "", base: null });
    setPreview(""); setError(undefined); setConflict(false); setMessage("");
  }
  function adoptLatest() {
    if (!draft || !latest) return;
    setDraft({ ...draft, base: latest }); setCreating(false); setSelected(latest.owner_id);
    setPreview(""); setError(undefined); setConflict(false);
    setMessage(`已读取 r${latest.revision} 并保留表单输入，请重新预览变化。`);
  }
  async function save() {
    if (!canPreview || !body || preview !== fingerprint) return;
    setBusy(true); setError(undefined); setMessage("");
    try {
      const route = `/projects/${path(projectId)}/owners`;
      const receipt = territory(await api.post<Row>(route, body, {
        ...commandIdentity(route, body), expectedRevision: draft?.base?.revision,
      }));
      if (!receipt || receipt.revision !== (draft?.base?.revision ?? 0) + 1 || meaning(receipt) !== meaning(body.value))
        throw new ApiError(200, { code: "INVALID_OWNER_RECEIPT", message: "保存响应未能确认领地及版本，请重载权威记录；本地草案已保留。" });
      setDraft(fromTerritory(receipt)); setSelected(receipt.owner_id); setCreating(false); setPreview("");
      setMessage(`Owner 领地 r${receipt.revision} 已保存。相关 Flow 需重新检查与审定；已冻结尝试仍使用原权限。`);
      query.reload(); onSaved();
    } catch (failure) {
      setError(failure);
      if (failure instanceof ApiError && (failure.status === 409 || failure.code === "REVISION_CONFLICT")) setConflict(true);
    } finally { setBusy(false); }
  }
  const rootName = (teamId: string | null | undefined) => actualTeams.find(team => team.team_id === teamId)?.name ?? teamId ?? "未绑定";
  return <Panel title={<><FolderKey size={16} /> Owner 代码领地</>} className="owner-territories"
    actions={<button disabled={!loaded || !writable || busy || !availableTeams.length || changed} onClick={create}>
      <Plus size={14} /> 登记 Owner</button>}>
    <p className="muted owner-intro">把代码责任绑定到实际团队，再安排任务分工。领地先应用排除规则，再匹配精确文件或以 / 结尾的目录前缀。</p>
    {query.loading && <p role="status">正在完整读取 Owner 领地…</p>}
    {query.error && <ErrorNotice error={query.error} onRetry={query.reload} />}
    {!teamsComplete && <p role="status">团队清单尚未完整读取，领地操作暂不可用。</p>}
    {!writable && <p className="muted">{!projectReady ? "项目权限尚未确认。" : project?.archived ? "项目已归档，领地只读。" : "当前项目为只读观察模式。"}</p>}
    {!actualTeams.length && teamsComplete && <p className="owner-note">先在责任树创建真实团队，再将其登记为代码 Owner。</p>}
    {query.data !== undefined && !owners.length && !creating && <EmptyState title="尚无 Owner 领地"
      description="选择已有团队登记稳定 Owner 身份，并明确允许与排除的仓库路径。" />}
    {(owners.length > 0 || creating) && <div className="owner-layout">
      <aside className="owner-context">
        <Field label={creating ? "新 Owner · 已有团队身份" : "已登记 Owner"}>
          {creating ? <select value={draft?.ownerId ?? ""} disabled={!loaded || !writable || busy} onChange={event => {
            setDraft(prior => prior && { ...prior, ownerId: event.target.value, rootTeamId: event.target.value });
          }}>{availableTeams.map(team => <option key={String(team.team_id)} value={String(team.team_id)}>{str(team.name)} · {str(team.team_id)}</option>)}</select>
          : <select value={selected} disabled={busy || changed || query.loading} onChange={event => choose(event.target.value)}>
            {owners.map((owner, index) => <option key={`${str(owner.owner_id)}:${index}`} value={str(owner.owner_id, "")}>{str(owner.owner_id)}</option>)}
          </select>}
        </Field>
        <dl><dt>稳定 Owner 身份</dt><dd>{draft?.ownerId || selected || "未知"}</dd>
          <dt>读取版本</dt><dd>{creating ? "首次登记 · 不覆盖现有记录" : num(current?.revision) === undefined ? "未知" : `r${current?.revision}`}</dd>
          <dt>当前根团队</dt><dd>{creating ? "待保存" : str(rootName(latest?.root_team_id))}</dd></dl>
        {changed && <p className="muted">有未保存的修改。恢复或取消后可切换 Owner。</p>}
        {!draft && current && <p role="alert">该领地的版本或路径格式无法确认，禁止覆盖。请重载或检查权威记录。</p>}
        <button disabled={busy || query.loading} onClick={query.reload}><RefreshCw size={14} /> 重载权威记录</button>
      </aside>
      {draft && <div className="owner-editor">
        <Field label="Owner 根团队"><select value={draft.rootTeamId} disabled={!loaded || !writable || busy}
          onChange={event => setDraft({ ...draft, rootTeamId: event.target.value })}>
          <option value="">选择实际团队</option>
          {draft.rootTeamId && !actualTeams.some(team => team.team_id === draft.rootTeamId)
            && <option value={draft.rootTeamId}>未确认的团队 · {draft.rootTeamId}</option>}
          {actualTeams.map(team => <option key={String(team.team_id)} value={String(team.team_id)}>{str(team.name)} · {str(team.team_id)}</option>)}
        </select></Field>
        <div className="owner-paths"><Field label="允许路径 · 每行一个"><textarea value={draft.includeText} spellCheck={false}
          disabled={!loaded || !writable || busy} placeholder={"crates/engine/\ninclude/engine.h"}
          onChange={event => setDraft({ ...draft, includeText: event.target.value })} /></Field>
          <Field label="排除路径 · 每行一个，可留空"><textarea value={draft.excludeText} spellCheck={false}
            disabled={!loaded || !writable || busy} placeholder="crates/engine/generated/"
            onChange={event => setDraft({ ...draft, excludeText: event.target.value })} /></Field></div>
        <p className="muted owner-path-hint">空行忽略，其余字符原样保存；不自动裁剪空格或展开 * 通配符。排除规则不能用来绕过不同 Owner 的允许路径重叠检查。</p>
        {invalidPaths.length > 0 && <p role="alert">路径须为仓库相对路径，不能包含绝对路径、反斜杠、冒号、空片段或 . / ..：{invalidPaths.map(entry => JSON.stringify(entry)).join("、")}</p>}
        {(stale || conflict) && <div className="owner-note" role="alert"><p>权威领地版本已变化或保存发生冲突。本地草案已保留；重载后采用最新版本，再复核与预览。</p>
          <button disabled={busy || !loaded || !latest || latest.revision === draft.base?.revision} onClick={adoptLatest}>
            <RefreshCw size={14} /> 采用最新 r{latest?.revision ?? "未知"} · 保留输入</button></div>}
        {preview === fingerprint && body && <section className="owner-preview" aria-label="Owner 领地变化预览">
          <h3><ClipboardCheck size={15} /> 保存前复核 <span>{creating ? "首次登记" : `基于 r${draft.base?.revision}`}</span></h3>
          <div className="owner-root-change"><span>{creating ? "未登记" : str(rootName(draft.base?.root_team_id))}</span><ArrowRight size={14} /><strong>{str(rootName(value?.root_team_id))}</strong></div>
          <div className="owner-diff">{(["include", "exclude"] as const).map(kind => <div key={kind}>
            <h4>{kind === "include" ? "允许路径" : "排除路径"}</h4>
            <p className="muted">原记录</p><pre>{draft.base?.[kind].join("\n") || "（无）"}</pre>
            <p className="muted">保存后</p><pre>{value?.[kind].join("\n") || "（无）"}</pre>
          </div>)}</div>
          <p className="muted">此预览只展示修改意图；保存时服务端将检查领地冲突与版本，成功回执才代表已生效。</p>
        </section>}
        <div className="owner-actions"><button disabled={!canPreview} onClick={() => setPreview(fingerprint)}><ClipboardCheck size={14} /> 预览变化</button>
          <button className="primary" disabled={!canPreview || preview !== fingerprint} onClick={() => void save()}><Save size={14} /> {busy ? "保存中…" : creating ? "登记领地" : "保存领地"}</button>
          <button disabled={busy} onClick={() => {
            if (creating) { setCreating(false); setDraft(undefined); setSelected(""); setPreview(""); setError(undefined); setConflict(false); }
            else choose(selected);
          }}><Undo2 size={14} /> {creating ? "取消登记" : "恢复已保存值"}</button></div>
      </div>}
    </div>}
    {!!error && <ErrorNotice error={error} />}
    {message && <p className="owner-message" role="status">{message}</p>}
  </Panel>;
}
