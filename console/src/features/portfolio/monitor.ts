export type Row = Record<string, unknown>;
export function rows(value: unknown): Row[] {
  if (Array.isArray(value))
    return value.filter((r): r is Row => !!r && typeof r === "object");
  if (value && typeof value === "object") {
    const r = value as Row;
    for (const key of [
      "items",
      "projects",
      "teams",
      "tasks",
      "attempts",
      "gates",
      "receipts",
      "milestones",
      "entries",
      "events",
    ])
      if (Array.isArray(r[key])) return rows(r[key]);
  }
  return [];
}
export function object(value: unknown): Row {
  return value && typeof value === "object" && !Array.isArray(value)
    ? (value as Row)
    : {};
}
export function str(value: unknown, fallback = "未提供"): string {
  return value === undefined || value === null || value === ""
    ? fallback
    : typeof value === "string"
      ? value
      : JSON.stringify(value);
}
export function id(r: Row): string {
  return str(
    r.id ??
      r.receipt_id ??
      r.intent_id ??
      r.attempt_id ??
      r.task_id ??
      r.team_id ??
      r.milestone_id ??
      r.project_id,
    "",
  );
}
export function num(value: unknown): number | undefined {
  return typeof value === "number" && Number.isFinite(value)
    ? value
    : undefined;
}
export function date(value: unknown, zone = "Asia/Shanghai"): string {
  if (typeof value !== "string" || !Number.isFinite(Date.parse(value)))
    return str(value);
  return new Intl.DateTimeFormat("zh-CN", {
    timeZone: zone,
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  }).format(new Date(value));
}
export function ratio(value: unknown): string {
  const r = object(value);
  const numerator = num(r.numerator ?? r.completed ?? r.passed);
  const denominator = num(r.denominator ?? r.total ?? r.required);
  return numerator === undefined || denominator === undefined
    ? "口径未提供"
    : `${numerator} / ${denominator}${denominator === 0 ? " · 无验收对象" : ""}`;
}
export function path(value: string): string {
  return encodeURIComponent(value);
}
export const activeStates = new Set([
  "LEASED",
  "STARTING",
  "RUNNING",
  "VERIFYING",
  "REVIEW_READY",
  "MERGE_QUEUED",
  "MERGING",
  "STOPPING",
  "RECOVERY_REQUIRED",
]);
export function errorMessage(e: unknown): string {
  return e instanceof Error ? e.message : str(e);
}
