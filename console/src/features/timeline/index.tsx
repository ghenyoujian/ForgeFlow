import { useState, useEffect, useLayoutEffect, useRef } from "react";
import { useSearchParams } from "react-router-dom";
import { TaskInspector } from "../../components/TaskInspector";
import type { TaskCard } from "../flow/types";
import type { PlanningInputs } from "./EffortEstimate";
import { planningWorkbenchEnabled } from "../../app/feature-flags";
import { PlanningStudio } from "./PlanningStudio";
import {
  CalendarDays,
  Clock3,
  Save,
  GitBranch,
  ChevronLeft,
  ChevronRight,
  Diamond,
} from "lucide-react";
import { useWorkspaceWritable, api, ApiError, getAuthScope, useApi } from "../../app/api";
import type { ControlEvent } from "../../app/events";
import { TableScrollHint, UnknownMetric } from "../portfolio/metrics";
import { useCollection } from "../portfolio/collection";
import { useCommandIdentity } from "../portfolio/commands";
import type { PageProps } from "../../app/types";
import {
  PageHeader,
  Panel,
  EmptyState,
  ErrorNotice,
  StatusBadge,
  DataTable,
  JsonView,
  Field,
  SourceStamp,
  Pagination,
} from "../../components";
import {
  rows,
  object,
  str,
  id,
  path,
  date,
  num,
  errorMessage,
  type Row,
} from "../portfolio/monitor";
import {
  scheduleRows,
  segments,
  instant,
  validateDates,
  scheduleWriteOrder,
} from "./schedule";

export function TimelinePage(props: PageProps) { return <TimelineWorkspace key={props.projectId} {...props} />; }
function TimelineWorkspace({ projectId }: PageProps) {
  const [params, setParams] = useSearchParams();
  const inspectorId = params.get('task');
  const inspectorTask = useApi<TaskCard>(projectId && inspectorId ? `/projects/${path(projectId)}/tasks/${path(inspectorId)}` : null);
  function inspectTask(id: string) { setSelected(id); setParams(prior => { const next = new URLSearchParams(prior); next.set('task', id); return next; }, { replace: true }); }
  function closeInspector() { setParams(prior => { const next = new URLSearchParams(prior); next.delete('task'); return next; }, { replace: true }); }
  const projectQuery = useApi<unknown>(
    projectId ? `/projects/${path(projectId)}` : null,
  );
  const writable = useWorkspaceWritable() && object(projectQuery.data).authority_mode === "MANAGED";
  const newPlanning = planningWorkbenchEnabled();
  const sharedInputs = useApi<PlanningInputs>(projectId && newPlanning ? `/projects/${path(projectId)}/planning-inputs` : null);
  const legacySchedules = useCollection<Row>(
    projectId && !newPlanning ? `/projects/${path(projectId)}/schedule` : null,
  );
  const milestoneQuery = useCollection<Row>(
    projectId ? `/projects/${path(projectId)}/milestones` : null,
  );
  const legacyTasks = useCollection<Row>(
    projectId && !newPlanning ? `/projects/${path(projectId)}/tasks` : null,
  );
  const q = newPlanning ? { ...sharedInputs, data: sharedInputs.data?.documents.filter(doc => doc.collection === "schedules").map(doc => doc.value) } : legacySchedules;
  const taskQuery = newPlanning ? { ...sharedInputs, data: sharedInputs.data?.tasks } : legacyTasks;
  const commandIdentity = useCommandIdentity();
  const schedule = object(q.data);
  const savedSchedules = scheduleRows(q.data);
  const schedulesByTask = new Map(savedSchedules.map(schedule => [schedule.task_id, schedule]));
  const tasks = rows(taskQuery.data).map((task) => ({
    ...task,
    ...(schedulesByTask.get(task.task_id) ?? {}),
  }));
  const zone = str(
    object(projectQuery.data).timezone ?? schedule.timezone,
    "Asia/Shanghai",
  );
  const [selected, setSelected] = useState(() => {
    const explicit = new URLSearchParams(location.search).get("task");
    if (explicit) return explicit;
    try { return JSON.parse(sessionStorage.getItem(`forgeflow.schedule-draft.${getAuthScope()}.${projectId}`) ?? '{}').selected ?? ''; } catch { return ''; }
  });
  useEffect(() => { if (inspectorId) setSelected(inspectorId); }, [inspectorId]);
  const draftStorage = `forgeflow.schedule-draft.${getAuthScope()}.${projectId}`;
  const [restoredDraft] = useState<{ drafts: Record<string,{start:string;finish:string}>; basis: Record<string,number> }>(() => {
    try { return JSON.parse(sessionStorage.getItem(draftStorage) ?? '{"drafts":{},"basis":{}}'); } catch { return { drafts:{},basis:{} }; }
  });
  const [drafts, setDrafts] = useState(restoredDraft.drafts);
  const [draftBasis, setDraftBasis] = useState(restoredDraft.basis);
  const savePending = useRef(false);
  useLayoutEffect(() => { try { sessionStorage.setItem(draftStorage, JSON.stringify({ drafts, basis: draftBasis, selected })); } catch { setMessage('浏览器空间不足；日期草稿仍保留在当前页面，请及时保存。'); } }, [drafts, draftBasis, draftStorage, selected]);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState<string>();
  const [zoom, setZoom] = useState<"hour" | "day" | "week">("hour");
  const [offset, setOffset] = useState(0);
  const allSegments = tasks.flatMap(segments);
  const timestamps = allSegments.flatMap((s) => [s.start, s.finish]);
  const earliest = timestamps.length ? Math.min(...timestamps) : undefined;
  const latest = timestamps.length ? Math.max(...timestamps) : undefined;
  const [chartElement, setChartElement] = useState<HTMLDivElement | null>(null);
  const [width, setWidth] = useState(960);
  const [scrollTop, setScrollTop] = useState(0);
  useEffect(() => {
    if (!chartElement) return;
    const update = () =>
      setWidth(Math.max(960, Math.floor(chartElement.clientWidth)));
    update();
    const observer = new ResizeObserver(update);
    observer.observe(chartElement);
    return () => observer.disconnect();
  }, [chartElement]);
  const firstVisibleRow = Math.max(0, Math.floor((scrollTop - 40) / 58) - 4);
  const visibleTasks = tasks.slice(firstVisibleRow, firstVisibleRow + 18);
  const [tablePage, setTablePage] = useState(0);
  const tableRows = tasks.slice(tablePage * 50, tablePage * 50 + 50);
  useEffect(() => {
    setTablePage(0);
    setScrollTop(0);
  }, [projectId]);
  useEffect(() => {
    if (tablePage > 0 && tablePage * 50 >= tasks.length)
      setTablePage(Math.max(0, Math.ceil(tasks.length / 50) - 1));
  }, [tablePage, tasks.length]);
  const labelWidth = 240;
  const chartWidth = width - labelWidth;
  const tick =
    zoom === "hour" ? 3600000 : zoom === "day" ? 86400000 : 7 * 86400000;
  const beginning =
    earliest === undefined
      ? undefined
      : Math.floor(earliest / tick) * tick + offset * tick;
  const span = tick * 8;
  const x = (time: number) =>
    labelWidth + ((time - (beginning ?? 0)) / span) * chartWidth;
  const current = tasks.find((t) => str(t.task_id) === selected);
  const errors = validateDates(tasks, drafts);
  const tasksById = new Map(tasks.map(task => [task.task_id, task]));
  const staleDateDrafts = Object.keys(drafts).filter(taskId => draftBasis[taskId] !== undefined && draftBasis[taskId] !== Number(tasksById.get(taskId)?.baseline_version ?? 0));
  const hasDraftChanges = Object.entries(drafts).some(([taskId, d]) => {
    const task = tasksById.get(taskId);
    return (
      instant(d.start) !== instant(task?.planned_start) ||
      instant(d.finish) !== instant(task?.planned_finish)
    );
  });
  function update(field: "start" | "finish", value: string) {
    if (!current) return;
    setDraftBasis(basis => ({ ...basis, [selected]: basis[selected] ?? Number(current.baseline_version ?? 0) }));
    setDrafts(previous => {
      const prior = previous[selected] ?? {
        start: str(current.planned_start, ""),
        finish: str(current.planned_finish, ""),
      };
      return { ...previous, [selected]: { ...prior, [field]: value } };
    });
  }
  function adoptForecast(forecast: {task_id:string;planned_start:string;planned_end:string}[]) {
    setDraftBasis(Object.fromEntries(forecast.map(row => [row.task_id, Number(tasksById.get(row.task_id)?.baseline_version ?? 0)])));
    setDrafts(Object.fromEntries(forecast.map(row => [row.task_id, {start:row.planned_start,finish:row.planned_end}])));
  }
  async function save(baseline = false) {
    if (savePending.current || (!baseline && staleDateDrafts.length)) return;
    savePending.current = true;
    setBusy(true);
    setMessage(undefined);
    const proposal = baseline
      ? Object.fromEntries(
          tasks
            .filter(
              (t) =>
                instant(t.planned_start) !== undefined &&
                instant(t.planned_finish) !== undefined,
            )
            .map((t) => [
              str(t.task_id),
              { start: str(t.planned_start), finish: str(t.planned_finish) },
            ]),
        )
      : drafts;
    const pending = new Map(Object.entries(proposal));
    const workingTasks = tasks.map((task) => ({ ...task }));
    const workingById = new Map(workingTasks.map(task => [str(task.task_id), task]));
    const results: string[] = [];
    const succeeded = new Set<string>();
    try {
      const writeOrder = scheduleWriteOrder(workingTasks, Object.fromEntries(pending));
      for (const taskId of writeOrder) {
        const draft = pending.get(taskId)!;
        const task = workingById.get(taskId);
        const version = Number((baseline ? undefined : draftBasis[taskId]) ?? task?.baseline_version ?? 0) + 1;
        setMessage(`正在保存 ${succeeded.size + 1} / ${writeOrder.length} 张日期草稿，等待服务端确认…`);
        const scheduleId = `${taskId}:v${version}`;
        const route = `/projects/${path(projectId ?? "")}/schedule`;
        const body = {
          id: scheduleId,
          value: {
            project_id: projectId,
            schedule_id: scheduleId,
            task_id: taskId,
            baseline_version: version,
            planned_start: new Date(draft.start).toISOString(),
            planned_end: new Date(draft.finish).toISOString(),
            dependencies: task?.dependencies ?? [],
            revision: 0,
            ...(task?.effort_estimate ? { effort_estimate: task.effort_estimate } : {}),
          },
        };
        try {
          await api.post(route, body, commandIdentity(route, body));
          results.push(`${taskId}：服务端保存 v${version}`);
          succeeded.add(taskId);
        } catch (e) {
          results.push(`${taskId}：${errorMessage(e)}`);
          throw e;
        }
        pending.delete(taskId);
        if (task) {
          task.planned_start = body.value.planned_start;
          task.planned_finish = body.value.planned_end;
        }
      }
    } catch (e) {
      results.push(`方案未全部保存：${errorMessage(e)}`);
    } finally {
      setMessage(`${succeeded.size} 张已由服务端确认；${pending.size} 张仍保留。\n${results.slice(-10).join("\n")}`);
      setDrafts((prior) =>
        baseline
          ? prior
          : Object.fromEntries(
              Object.entries(prior).filter(([key]) => !succeeded.has(key)),
            ),
      );
      setDraftBasis(prior => Object.fromEntries(Object.entries(prior).filter(([id]) => !succeeded.has(id))));
      q.reload();
      setBusy(false); savePending.current = false;
    }
  }
  return (
    <>
      <PageHeader
        title="计划与基线"
        description={`基线、计划和运行事件共用任务身份 · ${zone}。计划编辑不改变尝试状态。`}
        actions={
          <button
            disabled={
              busy ||
              !writable ||
              hasDraftChanges ||
              !tasks.some(
                (t) =>
                  instant(t.planned_start) !== undefined &&
                  instant(t.planned_finish) !== undefined,
              )
            }
            title={
              hasDraftChanges
                ? "请先保存日期方案，再为当前已保存计划建立基线"
                : "逐任务追加不可变基线版本，原始基线保留"
            }
            onClick={() => void save(true)}
          >
            <Save size={15} />
            保存基线
          </button>
        }
      />
      {staleDateDrafts.length > 0 && <div className="planning-draft-bar" role="status"><span>{staleDateDrafts.length} 张服务端日程版本已变化，日期草稿已保留。</span><button disabled={busy || taskQuery.loading} onClick={() => setDraftBasis(Object.fromEntries(Object.keys(drafts).map(id => [id, Number(tasksById.get(id)?.baseline_version ?? 0)])))}>基于最新版本重新预览日期</button></div>}
      {inspectorTask.data && <TaskInspector task={inspectorTask.data} onClose={closeInspector} onSelectTask={inspectTask} />}
      {inspectorTask.error && <ErrorNotice error={inspectorTask.error} onRetry={inspectorTask.reload} />}
      {projectId && <PlanningStudio projectId={projectId} writable={writable} selectedTaskId={current ? str(current.task_id) : selected} onTaskSelect={inspectTask} onAdopt={adoptForecast} />}
      {q.error && <ErrorNotice error={q.error} onRetry={q.reload} />}
      {taskQuery.error && (
        <ErrorNotice error={taskQuery.error} onRetry={taskQuery.reload} />
      )}{" "}
      {!projectId ? (
        <EmptyState title="请选择项目" />
      ) : (
        <>
          <Panel
            title={
              <>
                <GitBranch size={16} />
                任务时间轴
              </>
            }
            actions={
              <div className="toolbar">
                <button
                  aria-label="前移时间轴"
                  onClick={() => setOffset(offset - 1)}
                >
                  <ChevronLeft size={16} />
                </button>
                <button onClick={() => setOffset(0)}>基线范围</button>
                <button
                  aria-label="后移时间轴"
                  onClick={() => setOffset(offset + 1)}
                >
                  <ChevronRight size={16} />
                </button>
                <select
                  aria-label="时间轴缩放"
                  value={zoom}
                  onChange={(e) => setZoom(e.target.value as typeof zoom)}
                >
                  <option value="hour">小时</option>
                  <option value="day">日</option>
                  <option value="week">周</option>
                </select>
              </div>
            }
          >
            {q.loading && !q.data ? (
              <p>读取排程…</p>
            ) : !tasks.length ? (
              <EmptyState
                title="尚未形成排程"
                description="服务端需要保存任务日期与基线。缺少估计保持未知。"
              />
            ) : beginning === undefined ? (
              <EmptyState
                title="任务日期尚未估计"
                description="任务已存在；未知工期不绘成零长度条。请从下方表单设置有明确时区的计划。"
              />
            ) : (
              <div
                className="table-wrap"
                ref={setChartElement}
                onScroll={(event) =>
                  setScrollTop(event.currentTarget.scrollTop)
                }
                style={{ maxHeight: 480, overflow: "auto" }}
              >
                <svg
                  role="img"
                  aria-label="任务甘特图：灰色基线，浅灰计划，黑色实际，纹理等待"
                  viewBox={`0 0 ${width} ${56 + tasks.length * 58}`}
                  width={width}
                  height={56 + tasks.length * 58}
                  style={{
                    minWidth: width,
                    width,
                    height: 56 + tasks.length * 58,
                    display: "block",
                  }}
                >
                  <defs>
                    <pattern
                      id="schedule-wait"
                      width="6"
                      height="6"
                      patternUnits="userSpaceOnUse"
                    >
                      <path d="M0 6L6 0" stroke="var(--control-line)" />
                    </pattern>
                  </defs>
                  <rect
                    width={width}
                    height={56 + tasks.length * 58}
                    fill="var(--panel)"
                  />
                  {Array.from({ length: 9 }, (_, i) => {
                    const time = beginning + (span * i) / 8;
                    return (
                      <g key={i}>
                        <line
                          x1={x(time)}
                          x2={x(time)}
                          y1={30}
                          y2={56 + tasks.length * 58}
                          stroke="var(--line)"
                        />
                        <text
                          x={x(time) + 4}
                          y={20}
                          fontSize="11"
                          fill="var(--text)"
                        >
                          {new Intl.DateTimeFormat("zh-CN", {
                            timeZone: zone,
                            month: "2-digit",
                            day: "2-digit",
                            hour: zoom === "hour" ? "2-digit" : undefined,
                          }).format(new Date(time))}
                        </text>
                      </g>
                    );
                  })}
                  {rows(milestoneQuery.data).map((milestone) => {
                    const time = instant(milestone.due_at);
                    if (
                      time === undefined ||
                      x(time) < labelWidth ||
                      x(time) > width
                    )
                      return null;
                    return (
                      <a
                        key={str(milestone.milestone_id)}
                        href={`/calendar?project=${path(projectId)}&milestone=${path(str(milestone.milestone_id))}`}
                      >
                        <g>
                          <line
                            x1={x(time)}
                            x2={x(time)}
                            y1={30}
                            y2={56 + tasks.length * 58}
                            stroke="var(--text)"
                            strokeDasharray="3 4"
                            opacity={0.25}
                          />
                          <path
                            d={`M${x(time)} 26 l5 5 -5 5 -5 -5 Z`}
                            fill="var(--panel)"
                            stroke="var(--text)"
                          />
                          <title>
                            {str(milestone.title)} ·{" "}
                            {date(milestone.due_at, zone)} ·
                            验收裁决由业务Gate判定
                          </title>
                        </g>
                      </a>
                    );
                  })}
                  {visibleTasks.map((task, offset) => {
                    const i = firstVisibleRow + offset;
                    const taskId = str(task.task_id);
                    const y = 40 + i * 58;
                    return (
                      <g key={taskId}>
                        <rect
                          x={0}
                          y={y}
                          width={width}
                          height={58}
                          fill={
                            selected === taskId
                              ? "var(--panel2)"
                              : "transparent"
                          }
                        />
                        <line
                          x1={0}
                          x2={width}
                          y1={y + 58}
                          y2={y + 58}
                          stroke="var(--line)"
                        />
                        <a
                          href={`/projects/${path(projectId)}/tasks/${path(taskId)}`}
                        >
                          <text
                            x={12}
                            y={y + 22}
                            fontSize="12"
                            fill="var(--text)"
                          >
                            {str(task.title, taskId).slice(0, 25)}
                          </text>
                        </a>
                        <text
                          x={12}
                          y={y + 40}
                          fontSize="11"
                          fill="var(--muted)"
                        >
                          {taskId} · {str(task.owner_id).slice(0, 12)}
                        </text>
                        {segments(task).map((segment, j) => {
                          const a = Math.max(labelWidth, x(segment.start));
                          const b = Math.min(width, x(segment.finish));
                          if (b < a) return null;
                          const sy =
                            y +
                            (segment.kind === "baseline"
                              ? 46
                              : segment.kind === "plan"
                                ? 12
                                : 28);
                          return (
                            <g
                              key={`${segment.kind}-${j}`}
                              tabIndex={0}
                              role="button"
                              aria-label={`${taskId} ${segment.kind} ${date(new Date(segment.start).toISOString(), zone)} 到 ${date(new Date(segment.finish).toISOString(), zone)} ${segment.source}`}
                              onClick={() => setSelected(taskId)}
                              onKeyDown={(e) => {
                                if (e.key === "Enter" || e.key === " ") {
                                  e.preventDefault();
                                  setSelected(taskId);
                                }
                              }}
                            >
                              <rect
                                x={a}
                                y={sy}
                                width={Math.max(2, b - a)}
                                height={segment.kind === "baseline" ? 3 : 12}
                                rx={segment.kind === "baseline" ? 0 : 3}
                                fill={
                                  segment.kind === "actual"
                                    ? "var(--text)"
                                    : segment.kind === "wait"
                                      ? "url(#schedule-wait)"
                                      : "var(--control-line)"
                                }
                              />
                              <title>
                                {segment.kind} · {segment.source} ·{" "}
                                {date(
                                  new Date(segment.start).toISOString(),
                                  zone,
                                )}{" "}
                                →{" "}
                                {date(
                                  new Date(segment.finish).toISOString(),
                                  zone,
                                )}
                                {segment.attemptId
                                  ? ` · ${segment.attemptId}`
                                  : ""}
                              </title>
                            </g>
                          );
                        })}
                      </g>
                    );
                  })}
                </svg>
              </div>
            )}
            {tasks.length > 18 && (
              <p className="muted">
                时间轴当前绘制第 {firstVisibleRow + 1}–
                {Math.min(tasks.length, firstVisibleRow + 18)} / {tasks.length}{" "}
                行；其余任务通过滚动读取，计划检查覆盖完整集合。
              </p>
            )}
            <TableScrollHint />
            <div className="toolbar muted">
              <span>━ 基线</span>
              <span>▱ 当前计划</span>
              <span>▰ 实际事件</span>
              <span>▨ 等待</span>
              <span>未知估计不绘条；失败与重试保留全部实际段</span>
            </div>
            <SourceStamp
              source={q.metadata.source}
              observedAt={q.metadata.observed_at}
            />
          </Panel>
          <Panel
            title={
              <>
                <Clock3 size={16} />
                日期方案
              </>
            }
          >
            <DataTable<Row>
              rows={tableRows}
              rowKey={(t) => str(t.task_id)}
              onRowClick={(t) => inspectTask(str(t.task_id))}
              empty="排程任务尚未返回"
              columns={[
                { key: "task_id", label: "稳定任务 ID" },
                { key: "title", label: "任务" },
                {
                  key: "planned_start",
                  label: "当前计划开始",
                  render: (t) => date(t.planned_start, zone),
                },
                {
                  key: "planned_finish",
                  label: "当前计划完成",
                  render: (t) => date(t.planned_finish, zone),
                },
                {
                  key: "effort_estimate",
                  label: "工作量估计",
                  render: (t) => {
                    const estimate = object(t.effort_estimate);
                    const likely = num(estimate.likely_hours);
                    return likely === undefined ? "待估计" : `${likely} 小时 · ${estimate.optimistic_hours}–${estimate.pessimistic_hours}`;
                  },
                },
              ]}
            />
            {tasks.length > 50 && (
              <Pagination
                query={{
                  page: tablePage + 1,
                  loading: taskQuery.loading,
                  hasNext: (tablePage + 1) * 50 < tasks.length,
                  hasPrevious: tablePage > 0,
                  nextPage: () => setTablePage((page) => page + 1),
                  previousPage: () =>
                    setTablePage((page) => Math.max(0, page - 1)),
                  firstPage: () => setTablePage(0),
                }}
                count={tableRows.length}
              />
            )}
            {current && (
              <div className="form-grid">
                <Field label="计划开始（ISO 8601 + 时区）">
                  <input
                    value={
                      drafts[selected]?.start ?? str(current.planned_start, "")
                    }
                    onChange={(e) => update("start", e.target.value)}
                    placeholder="2026-10-09T09:00:00+08:00"
                  />
                </Field>
                <Field label="计划完成（ISO 8601 + 时区）">
                  <input
                    value={
                      drafts[selected]?.finish ??
                      str(current.planned_finish, "")
                    }
                    onChange={(e) => update("finish", e.target.value)}
                    placeholder="2026-10-09T18:00:00+08:00"
                  />
                </Field>
              </div>
            )}
            {errors.map((e) => (
              <p role="alert" key={e}>
                {e}
              </p>
            ))}
            {Object.keys(drafts).length > 0 && (
              <>
                <button disabled={busy} onClick={() => { setDrafts({}); setDraftBasis({}); }}>放弃日期草稿</button><p>{Object.keys(drafts).length} 张任务的日期将形成新版本。以下预览前 50 项；全部草稿参与依赖校验。</p>
                <DataTable rows={Object.entries(drafts).slice(0, 50).map(([task_id, dates]) => ({ task_id, ...dates }))} rowKey={row => row.task_id} columns={[{ key: 'task_id', label: '任务' }, { key: 'start', label: '新计划开始' }, { key: 'finish', label: '新计划完成' }]} />
                <details><summary>高级日期草稿检查</summary><JsonView value={drafts} /></details>
                <button
                  className="primary"
                  disabled={busy || errors.length > 0 || !writable || staleDateDrafts.length > 0 || taskQuery.loading}
                  title="服务端校验任务依赖并追加不可变日期版本"
                  onClick={() => void save()}
                >
                  <Save size={15} />
                  保存排程版本
                </button>
              </>
            )}
            {message && <p role="status">{message}</p>}
            <p className="muted">
              日期修改会核对任务依赖；资源及工作窗口约束可在容量预览中复核。
            </p>
          </Panel>
        </>
      )}
    </>
  );
}

export function CalendarPage({ projectId }: PageProps) {
  const commandIdentity = useCommandIdentity();
  const acceptanceIdentity = useCommandIdentity();
  const [creationId, setCreationId] = useState(() => crypto.randomUUID());
  const [requirementIds, setRequirementIds] = useState("");
  const [workPackages, setWorkPackages] = useState("");
  const [editing, setEditing] = useState<Row>();
  const [changeReason, setChangeReason] = useState("");
  const [scope, setScope] = useState(
    new URLSearchParams(location.search).get("project") ?? projectId ?? "",
  );
  const projectsQ = useCollection<Row>("/projects");
  const writable = useWorkspaceWritable() && rows(projectsQ.data).some(
    (project) => id(project) === scope && project.authority_mode === "MANAGED",
  ) && !projectsQ.error && !projectsQ.loading;
  const q = useCollection<Row>(
    scope ? `/projects/${path(scope)}/milestones` : null,
  );
  const scheduleQuery = useCollection<Row>(
    scope ? `/projects/${path(scope)}/schedule` : null,
  );
  const taskQuery = useCollection<Row>(
    scope ? `/projects/${path(scope)}/tasks` : null,
  );
  const requirementQuery = useCollection<Row>(
    scope ? `/projects/${path(scope)}/requirements` : null,
  );
  const acceptanceQuery = useCollection<Row>(
    scope ? `/projects/${path(scope)}/documents/milestone_acceptances` : null,
  );
  const zone = str(
    rows(projectsQ.data).find((project) => id(project) === scope)?.timezone,
    "Asia/Shanghai",
  );
  const calendarTasks = scheduleRows(scheduleQuery.data).map((schedule) => ({
    ...rows(taskQuery.data).find((task) => task.task_id === schedule.task_id),
    ...schedule,
  }));
  const historyQuery = useCollection<Row>(
    scope ? `/projects/${path(scope)}/documents/milestone_baselines` : null,
  );
  const [title, setTitle] = useState("");
  const [due, setDue] = useState("");
  const [conditions, setConditions] = useState("");
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState<string>();
  const [accepting, setAccepting] = useState<string>();
  const acceptingRef = useRef(false);
  const [acceptanceError, setAcceptanceError] = useState<Error>();
  const [acceptanceReceipt, setAcceptanceReceipt] = useState<unknown>();
  const [acceptanceHistory, setAcceptanceHistory] = useState<Row[]>();
  const acceptanceRows = rows(acceptanceQuery.data).map((r) => ({ ...r, ...object(r.value) }));
  const basisUnknown = q.loading || !!q.error || taskQuery.loading || !!taskQuery.error ||
    requirementQuery.loading || !!requirementQuery.error || acceptanceQuery.loading ||
    !!acceptanceQuery.error || !q.data || !taskQuery.data || !requirementQuery.data || !acceptanceQuery.data;
  function acceptanceFor(m: Row) {
    if (basisUnknown) return { label: "验收状态未知", reason: "验收记录及当前任务、需求版本尚未完整读取", receipt: undefined as Row | undefined };
    const historical = acceptanceRows.filter((r) => r.project_id === scope && r.milestone_id === m.milestone_id);
    const current = historical.find((r) => r.baseline_version === m.baseline_version && r.milestone_revision === m.revision);
    if (!current) return { label: historical.length ? "需重新验收" : "待验收", reason: historical.length ? "历史回执不属于当前基线和里程碑版本" : "尚无服务端接受回执", receipt: undefined };
    if (current.status !== "ACCEPTED" || instant(current.accepted_at) === undefined)
      return { label: "验收状态未知", reason: "服务端记录未提供有效接受状态和时间", receipt: undefined };
    const conditions = object(current.conditions);
    const taskRefs = rows(conditions.task_refs);
    const requirementRefs = rows(conditions.requirement_refs);
    const requiredTasks = Array.isArray(m.required_work_packages) ? m.required_work_packages : [];
    const requiredRequirements = Array.isArray(m.requirement_ids) ? m.requirement_ids : [];
    const requiredPlans = Array.isArray(m.required_gate_ids) ? m.required_gate_ids : [];
    const taskMatches = taskRefs.length === requiredTasks.length && requiredTasks.every((taskId) => {
      const ref = taskRefs.find((r) => r.task_id === taskId);
      const task = rows(taskQuery.data).find((r) => r.task_id === taskId && r.project_id === scope);
      const planId = object(task?.envelope).verification_plan_id;
      return ref && task && ref.task_revision === task.task_revision &&
        typeof ref.input_digest === "string" && ref.input_digest === task.input_digest &&
        typeof ref.verification_plan_id === "string" && requiredPlans.includes(ref.verification_plan_id) &&
        (!planId || planId === ref.verification_plan_id);
    });
    const requirementMatches = requirementRefs.length === requiredRequirements.length && requiredRequirements.every((requirementId) => {
      const ref = requirementRefs.find((r) => r.requirement_id === requirementId);
      const requirement = rows(requirementQuery.data).find((r) => r.requirement_id === requirementId && r.project_id === scope);
      return ref && requirement && ref.revision === requirement.revision;
    });
    if (!taskMatches || !requirementMatches)
      return { label: "需重新验收", reason: "任务、输入、验证计划或需求版本已变化；历史回执保留", receipt: undefined };
    return { label: "已接受", reason: "服务端回执与当前基线、里程碑和任务、需求版本匹配", receipt: current };
  }
  function reloadAcceptanceBasis() {
    q.reload();
    taskQuery.reload();
    requirementQuery.reload();
    acceptanceQuery.reload();
  }
  useEffect(() => {
    setAcceptanceError(undefined);
    setAcceptanceReceipt(undefined);
    setAcceptanceHistory(undefined);
    setEditing(undefined);
    setCreationId(crypto.randomUUID());
    setTitle("");
    setDue("");
    setConditions("");
    setRequirementIds("");
    setWorkPackages("");
    setChangeReason("");
  }, [scope]);
  useEffect(() => {
    let timer: ReturnType<typeof setTimeout> | undefined;
    const changed = (event: Event) => {
      const detail = (event as CustomEvent<ControlEvent>).detail;
      if (detail?.projectId !== scope) return;
      const collection = object(detail.payload).collection;
      if (!/^(task\.|flow\.|requirements?\.|merge\.|milestone\.)/.test(detail.kind) &&
        !(detail.kind === "document.updated" && ["milestones", "milestone_acceptances"].includes(str(collection)))) return;
      if (timer !== undefined) return;
      timer = setTimeout(() => { timer = undefined; reloadAcceptanceBasis(); }, 300);
    };
    window.addEventListener("forgeflow-event", changed);
    return () => { window.removeEventListener("forgeflow-event", changed); if (timer !== undefined) clearTimeout(timer); };
  }, [scope, q.reload, taskQuery.reload, requirementQuery.reload, acceptanceQuery.reload]);
  async function accept(m: Row) {
    if (acceptingRef.current || busy || !writable || basisUnknown || !scope) return;
    if (!Number.isSafeInteger(m.revision) || !Number.isSafeInteger(m.baseline_version)) return;
    acceptingRef.current = true;
    setAccepting(str(m.milestone_id));
    setAcceptanceError(undefined);
    setAcceptanceReceipt(undefined);
    try {
      const route = `/projects/${path(scope)}/milestones/${path(str(m.milestone_id))}/accept`;
      const body = { expected_revision: m.revision, baseline_version: m.baseline_version };
      const result = await api.post(route, body, acceptanceIdentity(route, body));
      setAcceptanceReceipt(result);
      reloadAcceptanceBasis();
    } catch (e) {
      setAcceptanceError(e instanceof Error ? e : new Error(errorMessage(e)));
    } finally {
      acceptingRef.current = false;
      setAccepting(undefined);
    }
  }
  async function create() {
    if (!writable || acceptingRef.current) return;
    setBusy(true);
    setMessage(undefined);
    try {
      const route = `/projects/${path(scope)}/milestones`;
      const body = {
        id: editing ? str(editing.milestone_id) : creationId,
        expected_revision: editing?.revision,
        value: {
          project_id: scope,
          milestone_id: editing ? str(editing.milestone_id) : creationId,
          title,
          due_at: new Date(due).toISOString(),
          baseline_version: editing ? Number(editing.baseline_version) + 1 : 1,
          change_reason: editing ? changeReason : undefined,
          requirement_ids: requirementIds.split("\n").filter(Boolean),
          required_work_packages: workPackages.split("\n").filter(Boolean),
          required_gate_ids: conditions.split("\n").filter(Boolean),
          revision: 0,
        },
      };
      const result = await api.post(route, body, commandIdentity(route, body));
      setCreationId(crypto.randomUUID());
      setEditing(undefined);
      setChangeReason("");
      setTitle("");
      setDue("");
      setConditions("");
      setRequirementIds("");
      setWorkPackages("");
      setMessage(`里程碑事务回执：${str(result)}`);
      q.reload();
      historyQuery.reload();
      acceptanceQuery.reload();
    } catch (e) {
      setMessage(errorMessage(e));
    } finally {
      setBusy(false);
    }
  }
  return (
    <>
      <PageHeader
        title="日程与里程碑"
        description={`同一计划权威，${zone}。业务条件未验收时，截止已到也不会自动成为完成。`}
      />
      <Panel
        title={
          <>
            <CalendarDays size={16} />
            交付条件
          </>
        }
        actions={
          <select
            aria-label="项目范围"
            value={scope}
            disabled={busy || !!accepting}
            onChange={(e) => setScope(e.target.value)}
          >
            <option value="">全部项目</option>
            {rows(projectsQ.data).map((p) => (
              <option key={id(p)} value={id(p)}>
                {str(p.name)}
              </option>
            ))}
          </select>
        }
      >
        {scope && <PlanningStudio projectId={scope} writable={writable} />}
      {q.error && <ErrorNotice error={q.error} onRetry={q.reload} />}
        {acceptanceQuery.error && <ErrorNotice error={acceptanceQuery.error} onRetry={acceptanceQuery.reload} />}
        {taskQuery.error && <ErrorNotice error={taskQuery.error} onRetry={taskQuery.reload} />}
        {requirementQuery.error && <ErrorNotice error={requirementQuery.error} onRetry={requirementQuery.reload} />}
        <div className="toolbar"><button disabled={!scope || !!accepting} onClick={reloadAcceptanceBasis}>刷新验收依据</button>
          <span className="muted">仅当前基线和版本匹配的服务端回执显示已接受；计划日期不会自动验收。</span></div>
        <DataTable<Row>
          rows={rows(q.data).map((r) => ({ ...r, ...object(r.value) }))}
          rowKey={id}
          onRowClick={(m) => {
            setEditing(m);
            setTitle(str(m.title, ""));
            setDue(str(m.due_at, ""));
            setConditions(
              (Array.isArray(m.required_gate_ids) ? m.required_gate_ids : [])
                .map((v) => str(v))
                .join("\n"),
            );
            setRequirementIds(
              (Array.isArray(m.requirement_ids) ? m.requirement_ids : [])
                .map((v) => str(v))
                .join("\n"),
            );
            setWorkPackages(
              (Array.isArray(m.required_work_packages)
                ? m.required_work_packages
                : []
              )
                .map((v) => str(v))
                .join("\n"),
            );
            setChangeReason("");
          }}
          empty="当前没有可展示的里程碑；请先选择项目，来源失败时保留未知"
          columns={[
            {
              key: "title",
              label: "里程碑",
              render: (m) => (
                <>
                  <Diamond size={13} />
                  {str(m.title)}
                </>
              ),
            },
            { key: "project_id", label: "项目" },
            {
              key: "due_at",
              label: "目标时刻",
              render: (m) => date(m.due_at, zone),
            },
            {
              key: "baseline_version",
              label: "当前计划版本",
            },
            {
              key: "original_due_at",
              label: "原始目标",
              render: (m) => {
                const histories = rows(historyQuery.data)
                  .filter((h) => h.milestone_id === m.milestone_id)
                  .sort(
                    (a, b) =>
                      Number(a.baseline_version) - Number(b.baseline_version),
                  );
                return histories[0]?.baseline_version === 1 ? (
                  date(histories[0].due_at, zone)
                ) : (
                  <UnknownMetric description="原始 v1 基线尚未返回；不把当前日期冒充原始目标" />
                );
              },
            },
            {
              key: "required_gate_ids",
              label: "验证计划 ID",
              render: (m) => <JsonView value={m.required_gate_ids} />,
            },
            { key: "required_work_packages", label: "任务/工作单元 ID", render: (m) => <JsonView value={m.required_work_packages} /> },
            {
              key: "status",
              label: "验收",
              render: (m) => <span title={acceptanceFor(m).reason}><StatusBadge state={acceptanceFor(m).label} /><small>{acceptanceFor(m).reason}</small></span>,
            },
            {
              key: "accepted_at",
              label: "实际接受",
              render: (m) => acceptanceFor(m).receipt ? date(acceptanceFor(m).receipt?.accepted_at, zone) : "—",
            },
            {
              key: "acceptance_action", label: "验收操作",
              render: (m) => <div className="toolbar" onClick={(e) => e.stopPropagation()}>
                <button type="button" disabled={!writable || busy || !!accepting || basisUnknown || !!acceptanceFor(m).receipt ||
                  !Number.isSafeInteger(m.revision) || !Number.isSafeInteger(m.baseline_version)}
                  title={!writable ? "当前项目不允许写入" : acceptanceFor(m).reason}
                  onClick={(e) => { e.stopPropagation(); void accept(m); }}>
                  {accepting === m.milestone_id ? "正在验收…" : "接受当前基线"}
                </button>
                <button type="button" disabled={acceptanceQuery.loading || !!acceptanceQuery.error ||
                  !acceptanceRows.some((r) => r.project_id === scope && r.milestone_id === m.milestone_id)}
                  onClick={(e) => { e.stopPropagation(); setAcceptanceHistory(acceptanceRows.filter((r) => r.project_id === scope && r.milestone_id === m.milestone_id)); }}>
                  查看验收记录
                </button>
              </div>,
            },
          ]}
        />
        <SourceStamp
          source={q.metadata.source}
          observedAt={q.metadata.observed_at}
        />
        <SourceStamp source={acceptanceQuery.metadata.source} observedAt={acceptanceQuery.metadata.observed_at} />
        {acceptanceError && <><ErrorNotice error={acceptanceError} />
          {acceptanceError instanceof ApiError && acceptanceError.details !== undefined && <JsonView value={acceptanceError.details} />}</>}
        {acceptanceReceipt !== undefined && <Panel title="服务端验收回执"><JsonView value={acceptanceReceipt} />
          <a href={`/projects/${path(scope)}/evidence`}>打开项目证据索引，核对回执中的 evidence_refs</a></Panel>}
        {acceptanceHistory && <Panel title="保留的验收记录" actions={<button onClick={() => setAcceptanceHistory(undefined)}>收起记录</button>}>
          <p className="muted">历史记录保留原始基线与版本，不代表当前版本已接受。</p>
          {acceptanceHistory.map((receipt) => <details key={`${str(receipt.milestone_id)}:${str(receipt.baseline_version)}`}>
            <summary>基线 v{str(receipt.baseline_version)} · 里程碑 revision {str(receipt.milestone_revision)} · {date(receipt.accepted_at, zone)}</summary>
            <JsonView value={receipt} /></details>)}</Panel>}
      </Panel>
      <Panel
        title={
          <>
            <Clock3 size={16} />
            当前任务日程
          </>
        }
      >
        {scheduleQuery.error && (
          <ErrorNotice
            error={scheduleQuery.error}
            onRetry={scheduleQuery.reload}
          />
        )}
        <DataTable<Row>
          rows={calendarTasks}
          rowKey={(task) => str(task.task_id)}
          empty="当前范围尚未保存任务日期；不从执行态推断计划日期"
          columns={[
            {
              key: "task_id",
              label: "任务",
              render: (task) => (
                <a
                  href={`/projects/${path(scope)}/schedule?task=${path(str(task.task_id))}`}
                >
                  {str(task.title, str(task.task_id))}
                  <small>{str(task.task_id)}</small>
                </a>
              ),
            },
            {
              key: "planned_start",
              label: "当前计划开始",
              render: (task) => date(task.planned_start, zone),
            },
            {
              key: "planned_finish",
              label: "当前计划完成",
              render: (task) => date(task.planned_finish, zone),
            },
            {
              key: "baseline_start",
              label: "原始基线开始",
              render: (task) => date(task.baseline_start, zone),
            },
            {
              key: "state",
              label: "规划态",
              render: (task) => <StatusBadge state={str(task.state)} />,
            },
          ]}
        />
        <SourceStamp
          source={scheduleQuery.metadata.source}
          observedAt={scheduleQuery.metadata.observed_at}
        />
        <p className="muted">
          日期来自与甘特相同的 Schedule 版本及任务 ID；日程视图不另存任务日期。
        </p>
      </Panel>
      <Panel
        title={editing ? "编辑里程碑计划" : "创建里程碑"}
        actions={
          editing ? (
            <button
              onClick={() => {
                setEditing(undefined);
                setTitle("");
                setDue("");
                setConditions("");
                setRequirementIds("");
                setWorkPackages("");
              }}
            >
              新建里程碑
            </button>
          ) : undefined
        }
      >
        <form
          onSubmit={(e) => {
            e.preventDefault();
            void create();
          }}
          className="form-grid"
        >
          <Field label="标题">
            <input
              required
              value={title}
              onChange={(e) => setTitle(e.target.value)}
            />
          </Field>
          <Field label="目标时刻（包含时区）">
            <input
              required
              value={due}
              onChange={(e) => setDue(e.target.value)}
              placeholder="2026-10-10T18:00:00+08:00"
            />
          </Field>
          <Field label="验证计划 ID（每行一项）">
            <textarea
              required
              value={conditions}
              onChange={(e) => setConditions(e.target.value)}
            />
          </Field>
          <Field label="需求 ID（每行一项）">
            <textarea
              value={requirementIds}
              onChange={(e) => setRequirementIds(e.target.value)}
            />
          </Field>
          <Field label="任务/工作单元 ID（每行一项）">
            <textarea
              value={workPackages}
              onChange={(e) => setWorkPackages(e.target.value)}
            />
          </Field>
          {editing && (
            <Field label="日期／条件变更原因">
              <textarea
                required
                value={changeReason}
                onChange={(e) => setChangeReason(e.target.value)}
              />
            </Field>
          )}
          <button
            className="primary"
            disabled={
              busy ||
              !!accepting ||
              !writable ||
              !scope ||
              instant(due) === undefined ||
              (!!editing && !changeReason)
            }
          >
            {editing ? "保存里程碑新版本" : "创建里程碑"}
          </button>
        </form>
        {message && <p role="status">{message}</p>}
        <p className="muted">
          请选择项目后创建。未启用的周月视图与人工窗口容量计算保持明确边界。
        </p>
      </Panel>
    </>
  );
}
