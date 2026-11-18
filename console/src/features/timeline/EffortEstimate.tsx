import { useEffect, useState } from "react";
import { Calculator, RefreshCw, Save } from "lucide-react";
import { api, ApiError, useApi } from "../../app/api";
import { ErrorNotice, Field } from "../../components";
import { object, str, path, num } from "../portfolio/monitor";
import { useCommandIdentity } from "../portfolio/commands";
import type { Row } from "../portfolio/monitor";
import "./effort.css";

export interface PlanningInputs {
  project: Row; tasks: Row[]; teams: Row[];
  documents: { collection: string; value: Row }[];
  resource_policies: Row[]; resource_limits: Row[]; completed_task_ids: string[];
  revision: number; planning_input_digest?: string; as_of: string; source: string;
}
export function currentEstimate(inputs: PlanningInputs | undefined, task: Row): Row | undefined {
  return inputs?.documents.filter(doc => doc.collection === "task_estimates"
    && doc.value.task_id === task.task_id && doc.value.task_revision === task.task_revision)
    .map(doc => doc.value).sort((a, b) => Number(b.estimate_version) - Number(a.estimate_version))[0];
}
export function historicalEffort(inputs: PlanningInputs | undefined, task: Row): Row {
  const schedule = inputs?.documents.filter(doc => doc.collection === "schedules" && doc.value.task_id === task.task_id)
    .map(doc => doc.value).sort((a, b) => Number(b.baseline_version) - Number(a.baseline_version))[0];
  return object(schedule?.effort_estimate ?? task.effort_estimate);
}
export function weightedEffort(effort: Row): number | undefined {
  const a = num(effort.optimistic_hours), b = num(effort.likely_hours), c = num(effort.pessimistic_hours);
  return a !== undefined && b !== undefined && c !== undefined && a >= 0 && a <= b && b <= c
    ? (a + 4 * b + c) / 6 : undefined;
}
export function EffortEstimate({ task, projectId, writable, onSaved, planningInputs }: {
  task: Row; projectId: string; writable: boolean; onSaved: () => void; planningInputs?: PlanningInputs;
}) {
  const query = useApi<PlanningInputs>(planningInputs ? null : `/projects/${path(projectId)}/planning-inputs`);
  const inputs = planningInputs ?? query.data;
  const authoritativeTask = inputs?.tasks.find(value => value.task_id === task.task_id);
  const estimate = currentEstimate(inputs, authoritativeTask ?? task);
  const historical = historicalEffort(inputs, task);
  const stored = estimate ? object(estimate.effort) : historical;
  const commandIdentity = useCommandIdentity();
  const [hours, setHours] = useState(["", "", ""]);
  const [duration, setDuration] = useState("");
  const [rationale, setRationale] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>();
  const [conflict, setConflict] = useState(false);
  const [message, setMessage] = useState("");
  useEffect(() => {
    setHours([stored.optimistic_hours, stored.likely_hours, stored.pessimistic_hours]
      .map(value => typeof value === "number" ? String(value) : ""));
    setDuration(typeof estimate?.duration_hours === "number" ? String(estimate.duration_hours) : "");
    setRationale(str(stored.rationale, ""));
  }, [projectId, task.task_id, authoritativeTask?.task_revision, estimate?.estimate_id]);
  useEffect(() => { setError(undefined); setMessage(""); setConflict(false); }, [projectId, task.task_id]);
  const values = hours.map(Number);
  const valid = hours.every(value => value.trim() !== "")
    && values.every(value => Number.isFinite(value) && value >= 0 && value <= 1_000_000)
    && values[0] <= values[1] && values[1] <= values[2];
  const durationValid = !duration.trim() || (Number.isFinite(Number(duration)) && Number(duration) > 0 && Number(duration) <= 1_000_000);
  const weighted = valid ? (values[0] + 4 * values[1] + values[2]) / 6 : undefined;
  function refresh() { setConflict(false); setError(undefined); query.reload(); onSaved(); }
  async function save() {
    if (!authoritativeTask || !valid || !durationValid || conflict) return;
    setBusy(true); setError(undefined); setMessage("");
    try {
      const version = Number(estimate?.estimate_version ?? 0) + 1;
      const route = `/projects/${path(projectId)}/task-estimates`;
      const body = {
        project_id: projectId, estimate_id: `${str(task.task_id)}:r${authoritativeTask.task_revision}:e${version}`,
        task_id: task.task_id, task_revision: authoritativeTask.task_revision, estimate_version: version,
        effort: { optimistic_hours: values[0], likely_hours: values[1], pessimistic_hours: values[2],
          rationale: rationale.trim(), source: "USER_REVIEWED_THREE_POINT" },
        duration_hours: duration.trim() ? Number(duration) : null, revision: 0,
      };
      await api.post(route, body, commandIdentity(route, body));
      setMessage(`工作量版本 e${version} 已保存 · 任务修订 r${authoritativeTask.task_revision}`);
      query.reload(); onSaved();
    } catch (failure) {
      setError(failure);
      if (failure instanceof ApiError && (failure.status === 409 || failure.code === "CONTEXT_STALE")) setConflict(true);
    } finally { setBusy(false); }
  }
  return <section className="effort-estimate" aria-label="任务工作量评估">
    <div className="effort-heading"><h3><Calculator size={16} /> 工作量评估</h3>
      <span className="effort-version">{estimate ? `r${estimate.task_revision} · e${estimate.estimate_version}` : "尚无当前修订估计"}</span></div>
    <p className="muted">工作量可在安排日期前保存。人工工作小时、排程占用时长与真实执行耗时分别记录。</p>
    {!estimate && weightedEffort(historical) !== undefined && <p className="effort-note">表单读取了历史 Schedule 工作量，仅供复核。保存后才会创建当前任务修订的独立估计版本。</p>}
    {query.error && <ErrorNotice error={query.error} onRetry={query.reload} />}
    {query.loading && <p role="status">正在读取当前任务修订与估计版本…</p>}
    <div className="form-grid">
      {["乐观工作量（小时）", "通常工作量（小时）", "悲观工作量（小时）"].map((label, index) =>
        <Field label={label} key={label}><input type="number" min="0" max="1000000" step="0.25"
          value={hours[index]} disabled={!writable || busy}
          onChange={event => setHours(prior => prior.map((value, at) => at === index ? event.target.value : value))} /></Field>)}
      <Field label="排程占用时长（小时，可留空）"><input type="number" min="0.001" max="1000000" step="any"
        value={duration} disabled={!writable || busy} placeholder="独立评估，不从工作量自动换算"
        onChange={event => setDuration(event.target.value)} /></Field>
      <Field label="估计依据"><textarea value={rationale} disabled={!writable || busy}
        onChange={event => setRationale(event.target.value)} placeholder="实现范围、依赖、复用条件、排程时长依据与不确定性" /></Field>
    </div>
    <div className="effort-summary"><strong>{weighted === undefined ? "工作量未知" : `${weighted.toFixed(2)} 小时`}</strong>
      <span>{weighted === undefined ? "填写并复核三点估计" : `三点加权工作量 · 区间 ${values[0]}–${values[2]} 小时`}</span></div>
    <p className="muted">三点加权值是估计摘要；未经历史样本校准，不表示完成概率。时长留空时，预览可使用已保存的计划区间，并标明来源。</p>
    {hours.some(Boolean) && !valid && <p role="alert">需要有效小时数，且乐观 ≤ 通常 ≤ 悲观。</p>}
    {!durationValid && <p role="alert">排程时长须大于 0 且不超过 1,000,000 小时，或留空。</p>}
    <button className="button" disabled={!writable || busy || !valid || !durationValid || !rationale.trim() || !authoritativeTask || !!query.error || query.loading || conflict} onClick={() => void save()}>
      <Save size={14} /> {busy ? "保存中…" : "保存工作量版本"}</button>
    {!!error && <ErrorNotice error={error} />}
    {conflict && <div className="effort-note"><p>任务修订或估计版本已变化。重新读取后复核输入，再保存新版本。</p>
      <button onClick={refresh}><RefreshCw size={14} /> 重新读取版本</button></div>}
    {message && <p role="status">{message}</p>}
  </section>;
}
