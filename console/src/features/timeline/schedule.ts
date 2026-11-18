import { rows, object, str, type Row } from "../portfolio/monitor";
export type Segment = {
  start: number;
  finish: number;
  kind: "baseline" | "plan" | "actual" | "wait";
  source: string;
  attemptId?: string;
};
export function instant(value: unknown): number | undefined {
  if (typeof value !== "string") return undefined;
  const parts =
    /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2})(?::(\d{2})(?:\.\d{1,9})?)?(Z|[+-]\d{2}:\d{2})$/.exec(
      value,
    );
  if (!parts) return undefined;
  const year = Number(parts[1]),
    month = Number(parts[2]),
    day = Number(parts[3]);
  const leap = year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0);
  const days = [31, leap ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
  if (
    month < 1 ||
    month > 12 ||
    day < 1 ||
    day > days[month - 1] ||
    Number(parts[4]) > 23 ||
    Number(parts[5]) > 59 ||
    Number(parts[6] ?? 0) > 59
  )
    return undefined;
  const time = Date.parse(value);
  return Number.isFinite(time) ? time : undefined;
}
export function segments(task: Row): Segment[] {
  const values: Segment[] = [];
  function add(
    start: unknown,
    finish: unknown,
    kind: Segment["kind"],
    source: string,
    attemptId?: string,
  ) {
    const a = instant(start),
      b = instant(finish);
    if (a !== undefined && b !== undefined && b >= a)
      values.push({ start: a, finish: b, kind, source, attemptId });
  }
  add(
    task.baseline_start,
    task.baseline_finish,
    "baseline",
    "ScheduleBaseline",
  );
  add(task.planned_start, task.planned_finish, "plan", "ScheduleRevision");
  for (const attempt of rows(task.attempts)) {
    add(
      attempt.started_at,
      attempt.finished_at ?? attempt.terminal_at,
      "actual",
      str(attempt.source, "运行事件"),
      str(attempt.attempt_id, ""),
    );
  }
  for (const wait of rows(task.wait_intervals))
    add(wait.start, wait.finish, "wait", str(wait.reason, "资源等待"));
  return values;
}
export function scheduleRows(value: unknown): Row[] {
  if (Array.isArray(value)) {
    const documents = rows(value).map((r) => ({ ...r, ...object(r.value) }));
    const byTask = new Map<string, Row[]>();
    for (const r of documents) {
      if (typeof r.task_id !== "string") continue;
      const versions = byTask.get(r.task_id) ?? [];
      versions.push(r);
      byTask.set(r.task_id, versions);
    }
    return [...byTask.values()].map((versions) => {
      versions.sort(
        (a, b) => Number(a.baseline_version) - Number(b.baseline_version),
      );
      const baseline = versions[0],
        latest = versions[versions.length - 1];
      return {
        ...latest,
        baseline_start: baseline.planned_start,
        baseline_finish: baseline.planned_end,
        planned_finish: latest.planned_end,
      };
    });
  }
  const schedule = object(value);
  return rows(schedule.tasks ?? schedule.entries ?? value);
}
export function validateDates(
  tasks: Row[],
  drafts: Record<string, { start: string; finish: string }>,
): string[] {
  const errors: string[] = [];
  const byId = new Map(tasks.map((t) => [str(t.task_id), t]));
  for (const [taskId, draft] of Object.entries(drafts)) {
    const start = instant(draft.start),
      finish = instant(draft.finish);
    if (start === undefined || finish === undefined) {
      errors.push(`${taskId}：时间必须含明确 UTC 偏移或 Z`);
      continue;
    }
    if (finish < start) errors.push(`${taskId}：完成时间早于开始时间`);
    const task = byId.get(taskId);
    for (const predecessorId of Array.isArray(task?.dependencies)
      ? task.dependencies
      : []) {
      const predecessor = byId.get(str(predecessorId));
      const predecessorFinish = instant(
        drafts[str(predecessorId)]?.finish ?? predecessor?.planned_finish,
      );
      if (predecessorFinish === undefined)
        errors.push(
          `${taskId}：前置 ${str(predecessorId)} 完成估计未知，服务端需检查`,
        );
      else if (predecessorFinish > start)
        errors.push(`${taskId}：开始早于前置 ${str(predecessorId)} 计划完成`);
    }
  }
  for (const task of tasks) {
    const taskId = str(task.task_id);
    if (drafts[taskId]) continue;
    const start = instant(task.planned_start);
    if (start === undefined) continue;
    for (const predecessorId of Array.isArray(task.dependencies)
      ? task.dependencies
      : []) {
      const changed = drafts[str(predecessorId)];
      if (!changed) continue;
      const finish = instant(changed.finish);
      if (finish !== undefined && finish > start) {
        errors.push(
          `${taskId}：新方案使前置 ${str(predecessorId)} 完成晚于已保存的后继开始，请同时调整后继方案`,
        );
      }
    }
  }
  return errors;
}

/** Keep every intermediate write compatible with the still-persisted dates. */
export function scheduleWriteOrder(
  tasks: Row[],
  drafts: Record<string, { start: string; finish: string }>,
): string[] {
  const ids = Object.keys(drafts);
  const requested = new Set(ids);
  const byId = new Map(tasks.map((task) => [str(task.task_id), task]));
  const edges = new Map(ids.map((taskId) => [taskId, new Set<string>()]));
  const indegree = new Map(ids.map((taskId) => [taskId, 0]));
  function edge(from: string, to: string) {
    if (!edges.get(from)?.has(to)) {
      edges.get(from)?.add(to);
      indegree.set(to, (indegree.get(to) ?? 0) + 1);
    }
  }
  for (const task of tasks) {
    const taskId = str(task.task_id);
    for (const dependency of Array.isArray(task.dependencies)
      ? task.dependencies
      : []) {
      const predecessorId = str(dependency);
      const predecessor = byId.get(predecessorId);
      const oldFinish = instant(
        predecessor?.planned_finish ?? predecessor?.planned_end,
      );
      const oldStart = instant(task.planned_start);
      if (requested.has(taskId)) {
        const start = instant(drafts[taskId].start);
        if (start === undefined) throw new Error(`${taskId}：无效日期`);
        if (oldFinish === undefined || start < oldFinish) {
          if (requested.has(predecessorId)) edge(predecessorId, taskId);
          else throw new Error(`${taskId}：前置日期未知或不相容`);
        }
      }
      if (requested.has(predecessorId)) {
        const finish = instant(drafts[predecessorId].finish);
        if (finish === undefined) throw new Error(`${predecessorId}：无效日期`);
        if (oldStart !== undefined && finish > oldStart) {
          if (requested.has(taskId)) edge(taskId, predecessorId);
          else throw new Error(`${predecessorId}：需要同时调整后继 ${taskId}`);
        }
      }
    }
  }
  const ready = ids.filter((taskId) => indegree.get(taskId) === 0).sort();
  const result: string[] = [];
  while (ready.length) {
    const taskId = ready.shift()!;
    result.push(taskId);
    for (const next of edges.get(taskId) ?? []) {
      const count = (indegree.get(next) ?? 0) - 1;
      indegree.set(next, count);
      if (count === 0) {
        ready.push(next);
        ready.sort();
      }
    }
  }
  if (result.length !== ids.length)
    throw new Error("现有日期需要原子排程方案调整；未尝试写入冲突版本");
  return result;
}
