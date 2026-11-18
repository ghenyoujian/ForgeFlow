import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { Activity, ArrowUpRight, CircleHelp, PauseCircle, RefreshCw } from "lucide-react";
import { ErrorNotice, Panel, SourceStamp } from "../../components";
import type { ControlEvent, ControlResync } from "../../app/events";
import { useCollection } from "./collection";
import { object, path, type Row } from "./monitor";
import "./delivery-overview.css";

const reasons: Record<string, { title: string; detail: string; integration?: boolean }> = {
  MODEL_CUSTODY_PENDING: { title: "核对尚未结清的模型请求", detail: "用量或请求结局仍待确认，需在恢复台查看原始记录。" },
  STOP_UNCONFIRMED: { title: "核对停止证明", detail: "尚未确认执行进程已停止，相关占用继续保留。" },
  INTEGRATION_UNRESOLVED: { title: "核对未完成的集成", detail: "Git 与数据库的集成记录仍需对账。", integration: true },
  TERMINAL_CUSTODY_RETAINED: { title: "核对终态后的残留占用", detail: "尝试已结束，部分资源或子任务占用仍未结清。" },
  WORKER_HEARTBEAT_STALE: { title: "核对失联 Worker", detail: "近期未收到心跳；是否仍有进程运行需要进一步核对。" },
  RECOVERY_REQUIRED: { title: "核对待恢复尝试", detail: "先查看尝试详情和可信停止记录，再决定后续处理。" },
};

function count(value: unknown): number | undefined {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 0 ? value : undefined;
}

function expired(observedAt: string | undefined, now: number) {
  return !!observedAt && Number.isFinite(Date.parse(observedAt)) && now - Date.parse(observedAt) > 120_000;
}

/** Read-only project summary. Each collection retains its own observation time. */
export function DeliveryOverview({ projectId }: { projectId: string }) {
  const portfolio = useCollection<Row>("/portfolio");
  const recovery = useCollection<Row>(`/recovery-items?project_id=${path(projectId)}`);
  const [now, setNow] = useState(Date.now);
  const reload = () => { portfolio.reload(); recovery.reload(); setNow(Date.now()); };

  useEffect(() => {
    const timer = setInterval(() => setNow(Date.now()), 30_000);
    return () => clearInterval(timer);
  }, []);

  useEffect(() => {
    let timer: ReturnType<typeof setTimeout> | undefined;
    const changed = (event: Event) => {
      const detail = (event as CustomEvent<ControlEvent | ControlResync>).detail;
      if (detail?.projectId !== projectId) return;
      if ("kind" in detail && /heartbeat|stdout|stderr|token_delta|^tool\./.test(detail.kind)) return;
      if (timer !== undefined) return;
      timer = setTimeout(() => { timer = undefined; portfolio.reload(); recovery.reload(); }, 1000);
    };
    window.addEventListener("forgeflow-event", changed);
    window.addEventListener("forgeflow-resync", changed);
    return () => {
      window.removeEventListener("forgeflow-event", changed);
      window.removeEventListener("forgeflow-resync", changed);
      if (timer !== undefined) clearTimeout(timer);
    };
  }, [projectId, portfolio.reload, recovery.reload]);

  const portfolioOld = expired(portfolio.metadata.observed_at, now);
  const recoveryOld = expired(recovery.metadata.observed_at, now);
  const portfolioReady = portfolio.data !== undefined && !portfolio.loading && !portfolio.error && !portfolioOld;
  const matches = portfolio.data?.filter(item => object(item.project).project_id === projectId) ?? [];
  const summary = portfolioReady && matches.length === 1 ? matches[0] : undefined;
  const project = object(summary?.project);
  const progress = object(summary?.task_progress);
  const completed = count(progress.numerator);
  const total = count(progress.denominator);
  const revision = count(progress.flow_revision);
  const flowKnown = progress.scope === "current_approved_flow" && completed !== undefined && total !== undefined && completed <= total && revision !== undefined && revision > 0;
  const active = count(summary?.active_attempts);
  const recoveryValid = recovery.data !== undefined && recovery.data.every(item => item.project_id === projectId && typeof item.attempt_id === "string" && item.attempt_id.length > 0 && Array.isArray(item.reasons) && item.reasons.every(reason => typeof reason === "string")) && new Set(recovery.data.map(item => item.attempt_id)).size === recovery.data.length;
  const recoveryReady = recovery.data !== undefined && recoveryValid && !recovery.loading && !recovery.error && !recoveryOld;
  const reasonCounts = new Map<string, number>();
  if (recoveryReady) for (const item of recovery.data ?? []) {
    for (const reason of new Set(item.reasons as string[])) reasonCounts.set(reason, (reasonCounts.get(reason) ?? 0) + 1);
  }
  const orderedReasons = [...reasonCounts.entries()].sort(([left], [right]) => {
    const order = Object.keys(reasons);
    const position = (code: string) => order.includes(code) ? order.indexOf(code) : order.length;
    return position(left) - position(right) || left.localeCompare(right);
  });
  const base = `/projects/${path(projectId)}`;
  const recoveryLink = `/recovery?project=${path(projectId)}`;
  const loading = portfolio.loading || recovery.loading;
  const pendingLabel = (query: typeof portfolio, old: boolean) => query.loading ? "读取中" : old ? "待刷新" : "未核对";

  return <Panel title="交付摘要" className="delivery-overview" actions={<button onClick={reload} disabled={loading} aria-label="刷新项目交付事实"><RefreshCw size={14} aria-hidden="true" />{loading ? "正在更新" : "刷新事实"}</button>}>
    <div className="delivery-body">
      <div className="delivery-state" aria-live="polite">
        <span className="delivery-state-label">{project.authority_mode === "OBSERVED_READ_ONLY" ? <><CircleHelp size={15} aria-hidden="true" />只读观察，无执行授权</> : project.paused === true ? <><PauseCircle size={15} aria-hidden="true" />新增派发已暂停</> : project.paused === false ? <><Activity size={15} aria-hidden="true" />新增派发未暂停</> : "派发状态未核对"}</span>
        {project.archived === true && <span>项目已归档</span>}
        <span className="delivery-observation-label">{loading ? "更新期间暂不展示旧计数" : portfolioOld || recoveryOld ? "部分观察已超过 2 分钟，请刷新" : "按来源分时观察"}</span>
      </div>

      {portfolio.error && <ErrorNotice error={portfolio.error} onRetry={portfolio.reload} />}
      {portfolioReady && matches.length !== 1 && <p className="delivery-notice" role="status">{matches.length === 0 ? "本次组合数据未返回当前项目的交付摘要。" : "组合数据返回了重复项目摘要，暂不用于交付统计。"}<Link to={`${base}/flows`}>查看项目 Flow</Link></p>}

      <div className="delivery-metrics">
        <div className="delivery-flow-metric">
          <span className="delivery-metric-label">当前批准 Flow · 已完成卡</span>
          <strong className="delivery-metric-value">{flowKnown ? <>{completed}<span> / {total}</span></> : portfolio.loading ? "读取中" : "口径未核对"}</strong>
          <span className="delivery-metric-caption">{flowKnown ? `Flow ${revision} · 仅此批准范围` : "需要服务端提供批准范围及对应完成记录"}</span>
          {flowKnown && total! > 0 && <div className="delivery-progress" role="progressbar" aria-label={`Flow ${revision} 已完成卡`} aria-valuemin={0} aria-valuemax={total} aria-valuenow={completed} aria-valuetext={`${completed} / ${total} 张，仅当前批准 Flow`}><span style={{ width: `${completed! / total! * 100}%` }} /></div>}
          {flowKnown && total === 0 && <span className="delivery-metric-caption">此批准范围没有任务卡，不计算完成百分比。</span>}
        </div>
        <div>
          <span className="delivery-metric-label">未结束尝试 / 活动占用</span>
          <strong className="delivery-metric-value">{active ?? pendingLabel(portfolio, portfolioOld)}</strong>
          <span className="delivery-metric-caption">含停止中、待恢复尝试；不表示 Agent 在线。</span>
        </div>
        <div>
          <span className="delivery-metric-label">本次返回的恢复事项</span>
          <strong className="delivery-metric-value">{recoveryReady ? recovery.data!.length === 0 ? "未返回事项" : `${recovery.data!.length} 项` : pendingLabel(recovery, recoveryOld)}</strong>
          <Link className="delivery-metric-link" to={recoveryLink}>到恢复台核对<ArrowUpRight size={13} aria-hidden="true" /></Link>
        </div>
      </div>

      <div className="delivery-scope-note">
        <CircleHelp size={16} aria-hidden="true" />
        <div><strong>原始完整计划的总进度：尚未提供可核验汇总</strong><p>当前 Flow 的分母仅代表该批准范围。成功尝试次数、已登记卡数不能换算为原始总计划的交付比例。</p>
          <p>需求交付：{!summary ? "尚未核对" : summary.requirement_progress == null ? "口径未提供" : "请查看需求验收记录"} · 必需 Gate：{!summary ? "尚未核对" : summary.gate_progress == null ? "口径未提供" : "请查看 Gate 裁决记录"}</p>
          {summary && <p className="delivery-raw-counts">已登记卡 {count(summary.task_count) ?? "未提供"} 张 · 成功尝试 {count(summary.succeeded_attempts) ?? "未提供"} 次；两者分别计量。</p>}
        </div>
      </div>

      <div className="delivery-next">
        <div className="delivery-section-heading"><h3>下一步</h3><span>查看事实后再决定操作</span></div>
        {recovery.error && <ErrorNotice error={recovery.error} onRetry={recovery.reload} />}
        {recovery.data !== undefined && !recoveryValid && !recovery.error && <p className="delivery-notice" role="alert">恢复事项的项目或原因字段未通过核对，暂不汇总。</p>}
        <ul className="delivery-actions">
          {orderedReasons.slice(0, 3).map(([code, amount]) => <li key={code}>
            <div><strong>{reasons[code]?.title ?? "核对其他恢复原因"}<span className="delivery-reason-count">涉及 {amount} 次尝试</span></strong><p>{reasons[code]?.detail ?? `服务端原因：${code}`}</p></div>
            <Link to={reasons[code]?.integration ? `${base}/integration` : recoveryLink}>{reasons[code]?.integration ? "查看集成" : "查看事项"}<ArrowUpRight size={14} aria-hidden="true" /></Link>
          </li>)}
          {!recoveryReady && <li><div><strong>先核对恢复事项</strong><p>{recovery.loading ? "正在读取本项目的恢复记录。" : recoveryOld ? "上次恢复观察已过期，请刷新后判断。" : "当前没有可用于判断的恢复观察，不能推断是否有阻塞。"}</p></div><Link to={recoveryLink}>打开恢复台<ArrowUpRight size={14} aria-hidden="true" /></Link></li>}
          {recoveryReady && recovery.data!.length === 0 && <li><div><strong>继续核对执行与验收条件</strong><p>本次完整遍历未返回恢复事项；任务依赖、预算和验收 Gate 仍需分别核对。</p></div><Link to={`${base}/teams`}>查看队列<ArrowUpRight size={14} aria-hidden="true" /></Link></li>}
          {project.paused === true && <li><div><strong>新增派发保持暂停</strong><p>先核对已有尝试与队列；本页只提供查看入口。</p></div><Link to={`${base}/teams`}>查看团队与队列<ArrowUpRight size={14} aria-hidden="true" /></Link></li>}
          <li><div><strong>{flowKnown ? `核对 Flow ${revision} 的交付与验收` : "核对批准范围与验收映射"}</strong><p>从任务与证据记录确认下一张可交付卡。</p></div><Link to={flowKnown ? `${base}/flows/${revision}` : `${base}/flows`}>打开 Flow<ArrowUpRight size={14} aria-hidden="true" /></Link></li>
        </ul>
        {orderedReasons.length > 3 && <Link className="delivery-more" to={recoveryLink}>查看全部 {orderedReasons.length} 类恢复原因<ArrowUpRight size={13} aria-hidden="true" /></Link>}
        {active !== undefined && active > 0 && <Link className="delivery-more" to={`/runs?project=${path(projectId)}`}>查看 {active} 个未结束尝试的实际状态<ArrowUpRight size={13} aria-hidden="true" /></Link>}
      </div>

      <div className="delivery-sources">
        <div><span>本次交付摘要观察{portfolio.error && portfolio.data !== undefined ? " · 更新失败，计数已隐藏" : portfolioOld ? " · 观察已过期" : ""}</span><SourceStamp source={portfolio.metadata.source} observedAt={portfolio.metadata.observed_at} /></div>
        <div><span>本次恢复事项观察{recovery.error && recovery.data !== undefined ? " · 更新失败，计数已隐藏" : recoveryOld ? " · 观察已过期" : ""}</span><SourceStamp source={recovery.metadata.source} observedAt={recovery.metadata.observed_at} /></div>
        <p>两类记录分别观察；未提供跨页快照版本时，读取期间的变化也可能影响结果。恢复计数仅对应本次返回事项，不代表全部交付阻塞。</p>
      </div>
    </div>
  </Panel>;
}
