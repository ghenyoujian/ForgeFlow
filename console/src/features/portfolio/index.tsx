import { useState } from "react";
import { Layers, FolderPlus, FolderOpen, Fingerprint } from "lucide-react";
import { api, useApi, useCursorApi,isPersonalAccount,workspaceWritable } from "../../app/api";
import { UnknownMetric, ProgressMetric, TableScrollHint } from "./metrics";
import { useCommandIdentity } from "./commands";
import { PlanningOverview } from "./PlanningOverview";
import { planningWorkbenchEnabled } from "../../app/feature-flags";
import { DeliveryOverview } from "./DeliveryOverview";
import "./delivery-overview.css";
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
  Drawer,
} from "../../components";
import {
  rows,
  object,
  str,
  id,
  ratio,
  date,
  path,
  errorMessage,
  type Row,
} from "./monitor";

export function PortfolioPage() {
  const query = useCursorApi<unknown>("/portfolio", "portfolio_cursor");
  const [selected, setSelected] = useState<Row>();
  const [risk, setRisk] = useState(false);
  const projects = rows(query.data).map((r) => ({
    ...r,
    ...object(r.project),
  }));
  const filtered = risk
    ? projects.filter(
        (p) =>
          rows(p.blockers).length > 0 ||
          ["FAIL", "BLOCKED", "INCONCLUSIVE"].includes(
            str(p.gate_status ?? p.qualification, ""),
          ),
      )
    : projects;
  return (
    <>
      <PageHeader
        title="项目组合"
        description="任务集成、需求交付与必需 Gate 分别计量；观察项目与受管项目保留各自来源。"
        actions={
          <a className="button primary" href="/projects/new">
            <FolderPlus size={15} />
            接入项目
          </a>
        }
      />
      {query.error && (
        <ErrorNotice error={query.error} onRetry={query.reload} />
      )}
      <Panel
        title={
          <>
            <Layers size={16} />
            项目交付总览
          </>
        }
        actions={
          <label>
            <input
              type="checkbox"
              checked={risk}
              onChange={(e) => setRisk(e.target.checked)}
            />
            只看交付风险
          </label>
        }
      >
        {query.loading && !query.data ? (
          <p role="status">正在读取项目组合…</p>
        ) : query.error && query.data === undefined ? (
          <p className="muted">项目组合尚未可读取，当前没有可靠快照。</p>
        ) : projects.length === 0 ? (
          <EmptyState
            title="尚未接入项目"
            description="组合数据来自控制服务。接入真实目录后才会形成项目事实。"
            action={<a href="/projects/new">接入项目</a>}
          />
        ) : (
          <DataTable<Row>
            rows={filtered}
            rowKey={id}
            onRowClick={setSelected}
            empty="当前筛选没有匹配项目"
            columns={[
              {
                key: "name",
                label: "项目 / 阶段",
                render: (p) => (
                  <a href={`/projects/${path(id(p))}`}>
                    {str(p.name)}
                    <small>{str(p.phase ?? p.stage, "")}</small>
                  </a>
                ),
              },
              {
                key: "authority_mode",
                label: "权威 / 来源",
                render: (p) => (
                  <>
                    <StatusBadge state={str(p.authority_mode)} />
                    <small>{str(p.data_origin ?? p.source)}</small>
                  </>
                ),
              },
              {
                key: "task_progress",
                label: "已完成卡 / 当前批准 Flow",
                render: (p) => {
                  const progress = object(p.task_progress);
                  const recognized = progress.scope === "current_approved_flow" && typeof progress.flow_revision === "number" && Number.isSafeInteger(progress.flow_revision) && progress.flow_revision > 0 && typeof progress.numerator === "number" && Number.isSafeInteger(progress.numerator) && progress.numerator >= 0 && typeof progress.denominator === "number" && Number.isSafeInteger(progress.denominator) && progress.denominator >= progress.numerator;
                  return recognized ? <><ProgressMetric value={progress} description="仅当前批准 Flow 的任务交付；不代表原始完整计划，成功尝试次数不直接计为完成卡" /><small className="portfolio-flow-scope">Flow {String(progress.flow_revision)} · 当前批准范围</small></> : <UnknownMetric description="服务未提供可识别的当前批准 Flow 范围，不能推导原始完整计划的交付比例" />;
                },
              },
              {
                key: "requirement_progress",
                label: "需求交付 / 批准权重",
                render: (p) => (
                  <ProgressMetric
                    value={p.requirement_progress}
                    description="需求交付需批准权重、验收映射与未覆盖需求；服务尚未提供该口径"
                  />
                ),
              },
              {
                key: "gate_progress",
                label: "必需 Gate",
                render: (p) =>
                  p.gate_progress || p.gates ? (
                    <JsonView value={p.gate_progress ?? p.gates} />
                  ) : (
                    <UnknownMetric description="服务尚未提供必需 Gate 集合和裁决分布，证据收据数量不等于 Gate 通过数量" />
                  ),
              },
              {
                key: "active_attempts",
                label: "活动占用",
                render: (p) => str(p.active_attempts),
              },
              {
                key: "succeeded_attempts",
                label: "成功尝试 / 返回卡数",
                render: (p) =>
                  `${str(p.succeeded_attempts)} 次 / ${str(p.task_count)} 张（分别计量）`,
              },
              {
                key: "blockers",
                label: "阻塞",
                render: (p) =>
                  p.blockers || p.primary_blocker ? (
                    str(p.blockers ?? p.primary_blocker)
                  ) : (
                    <UnknownMetric description="服务尚未提供交付阻塞根因；缺失数据不能解释为没有阻塞" />
                  ),
              },
              {
                key: "milestone",
                label: "下一里程碑",
                render: (p) =>
                  p.next_milestone ? (
                    str(p.next_milestone)
                  ) : (
                    <UnknownMetric description="组合摘要尚未提供下一里程碑；可在项目日程中查看原始里程碑" />
                  ),
              },
              {
                key: "observed_at",
                label: "观察时间",
                render: (p) =>
                  date(
                    p.observed_at ?? p.updated_at ?? query.metadata.observed_at,
                  ),
              },
            ]}
          />
        )}
        <Pagination query={query} count={projects.length} />
        <TableScrollHint />
        <p className="muted">
          当前页显示 {filtered.length} / {projects.length}{" "}
          个返回项目。未返回的验收口径保留未知。
        </p>
        <SourceStamp
          source={query.metadata.source}
          observedAt={query.metadata.observed_at}
        />
      </Panel>
      {selected && (
        <Drawer
          title={`${str(selected.name)} · 统计口径`}
          onClose={() => setSelected(undefined)}
        >
          <dl>
            <dt>已返回任务卡</dt>
            <dd>{str(selected.task_count)}</dd>
            <dt>成功尝试次数</dt>
            <dd>
              {str(selected.succeeded_attempts)}
              ；重试与只读尝试分别保留，不推导集成比例。
            </dd>
            <dt>活动占用</dt>
            <dd>{str(selected.active_attempts)}</dd>
            <dt>验收资格</dt>
            <dd>
              <StatusBadge
                state={str(selected.qualification, "INCONCLUSIVE")}
              />
            </dd>
          </dl>
          <p className="muted">
            需求权重、Gate
            分母或当前规划范围缺失时保持未知。显示筛选不改变验收分母。
          </p>
          <JsonView value={selected} />
          <SourceStamp
            source={query.metadata.source}
            observedAt={query.metadata.observed_at}
          />
          <a href={`/projects/${path(id(selected))}`}>打开项目工作台</a>
        </Drawer>
      )}
    </>
  );
}

export function ProjectPage({ projectId }: PageProps) {
  const q = useApi<unknown>(projectId ? `/projects/${path(projectId)}` : null);
  const p = object(q.data);
  return (
    <>
      <PageHeader
        title={str(p.name, "项目工作台")}
        description={str(p.goal, "目标尚未提供")}
      />
      {q.error && <ErrorNotice error={q.error} onRetry={q.reload} />}
      {!projectId ? (
        <EmptyState title="请选择项目" />
      ) : q.loading && !q.data ? (
        <p>读取项目…</p>
      ) : (
        <>
          {planningWorkbenchEnabled() ? <PlanningOverview key={projectId} projectId={projectId} /> : <DeliveryOverview key={projectId} projectId={projectId} />}
          <Panel
            title={
              <>
                <FolderOpen size={16} />
                项目身份与范围
              </>
            }
          >
            <dl>
              <dt>稳定 ID</dt>
              <dd>{projectId}</dd>
              <dt>权威模式</dt>
              <dd>
                <StatusBadge state={str(p.authority_mode)} />
              </dd>
              <dt>任务准入</dt>
              <dd>
                <StatusBadge state={p.paused === true ? "暂停新增" : p.paused === false ? "开放" : "未提供"} />
              </dd>
              <dt>根目录</dt>
              <dd>{str(p.root_path)}</dd>
              <dt>时区</dt>
              <dd>{str(p.timezone, "Asia/Shanghai")}</dd>
            </dl>
            <nav className="toolbar">
              {[
                ["tasks", "任务"],
                ["teams", "团队与队列"],
                ["schedule", "计划与基线"],
                ["evidence", "Gate 与证据"],
                ["integration", "集成队列"],
              ].map(([slug, label]) => (
                <a key={slug} href={`/projects/${path(projectId)}/${slug}`}>
                  {label}
                </a>
              ))}
            </nav>
          </Panel>
          <Panel
            title={
              <>
                <Fingerprint size={16} />
                源记录
              </>
            }
          >
            <details>
              <summary className="section-body">查看原始项目记录</summary>
              <JsonView value={p} />
            </details>
          </Panel>
        </>
      )}
    </>
  );
}

export function ProjectNewPage() {
  const personal=isPersonalAccount();
  const commandIdentity = useCommandIdentity();
  const [creationId] = useState(() => crypto.randomUUID());
  const [name, setName] = useState("");
  const [root, setRoot] = useState("");
  const [goal, setGoal] = useState("");
  const [authority, setAuthority] = useState("MANAGED");
  const [probe, setProbe] = useState<unknown>();
  const [error, setError] = useState<string>();
  const [busy, setBusy] = useState(false);
  async function inspect() {
    setBusy(true);
    setError(undefined);
    try {
      setProbe(await api.post("/project-probes", { root_path: root }));
    } catch (e) {
      setError(errorMessage(e));
    } finally {
      setBusy(false);
    }
  }
  async function create() {
    setBusy(true);
    setError(undefined);
    try {
      const body = {
        project_id: creationId,
        name,
        root_path: root,
        goal,
        authority_mode: authority,
        data_origin: "NATIVE",
        technology_stack: [],
        timezone: "Asia/Shanghai",
        paused: false,
        archived: false,
        revision: 0,
      };
      const result = object(
        await api.post("/projects", body, commandIdentity("/projects", body)),
      );
      if (id(result)) location.assign(`/projects/${path(id(result))}`);
      else setError("服务未返回项目身份，请重新查询项目，勿重复创建。");
    } catch (e) {
      setError(errorMessage(e));
    } finally {
      setBusy(false);
    }
  }
  return (
    <>
      <PageHeader
        title={personal?"创建项目":"接入真实项目"}
        description={personal?"为当前工作区建立独立项目仓库，再开始规划与协作。":"创建由服务端验证目录和控制权。预探测能力不足时保留错误，接入不等于已经获准执行。"}
      />
      <Panel title="目录与目标">
        <form
          onSubmit={(e) => {
            e.preventDefault();
            void create();
          }}
        >
          <Field label="项目名称">
            <input
              required
              value={name}
              onChange={(e) => setName(e.target.value)}
            />
          </Field>
          {!personal&&<Field label="真实根目录">
            <input
              required
              value={root}
              onChange={(e) => {
                setRoot(e.target.value);
                setProbe(undefined);
              }}
            />
          </Field>}
          <Field label="项目目标">
            <textarea
              required
              value={goal}
              onChange={(e) => setGoal(e.target.value)}
            />
          </Field>
          {!personal&&<Field label="权威模式">
            <select
              value={authority}
              onChange={(e) => setAuthority(e.target.value)}
            >
              <option value="MANAGED">受管项目</option>
              <option value="OBSERVED_READ_ONLY">只读观察</option>
            </select>
          </Field>}
          <div className="toolbar">
            {!personal&&<button
              type="button"
              disabled
              title="项目预探测接口尚未启用；创建时服务端仍核验目录"
              onClick={() => void inspect()}
            >
              预探测尚未启用
            </button>}
            <button className="primary" disabled={busy||!workspaceWritable()}>
              创建项目
            </button>
          </div>
        </form>
        {error && <p role="alert">{error}</p>}
        {probe !== undefined && <JsonView value={probe} />}
      </Panel>
    </>
  );
}
