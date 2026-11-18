import {
  useEffect,
  useId,
  useRef,
  useState,
  Children,
  cloneElement,
  isValidElement,
  type ReactElement,
  type ReactNode,
} from "react";
import {
  X,
  Diamond,
  AlertCircle,
  ChevronLeft,
  ChevronRight,
} from "lucide-react";
import { ApiError, type CursorApiControls } from "../app/api";
const drawerStack: HTMLElement[] = [];
let drawerScrollLocks = 0;
let bodyOverflowBeforeDrawers = "";
const inertSiblings = new WeakMap<HTMLElement, { count: number; prior: boolean }>();
export function PageHeader({
  title,
  description,
  actions,
}: {
  title: string;
  description?: string;
  actions?: ReactNode;
}) {
  return (
    <header className="page-header">
      <div>
        <h1>{title}</h1>
        {description && <p>{description}</p>}
      </div>
      {actions && <div className="page-actions">{actions}</div>}
    </header>
  );
}
export function Panel({
  title,
  actions,
  children,
  className = "",
}: {
  title?: ReactNode;
  actions?: ReactNode;
  children: ReactNode;
  className?: string;
}) {
  return (
    <section className={`panel ${className}`}>
      {(title || actions) && (
        <div className="panel-header">
          <h2>{title}</h2>
          <div className="panel-actions">{actions}</div>
        </div>
      )}
      {children}
    </section>
  );
}
export function EmptyState({
  title,
  description,
  action,
}: {
  title: string;
  description?: string;
  action?: ReactNode;
}) {
  return (
    <div className="empty-state">
      <Diamond size={30} strokeWidth={1} />
      <h3>{title}</h3>
      {description && <p>{description}</p>}
      {action}
    </div>
  );
}
export function ErrorNotice({
  error,
  onRetry,
}: {
  error: unknown;
  onRetry?: () => void;
}) {
  const e = error instanceof Error ? error : new Error(String(error));
  return (
    <div className="error-notice" role="alert">
      <AlertCircle size={20} />
      <div>
        <strong>{e instanceof ApiError && e.status === 409 ? "内容已变化，请核对后重试" : "暂时无法完成请求"}</strong>
        <p>{e.message}</p>
        {e instanceof ApiError && e.remediation && <p>{e.remediation}</p>}
        {e instanceof ApiError && <details><summary>技术详情</summary><code>{e.code}</code>{e.requestId && <p>请求 ID：{e.requestId}</p>}</details>}
      </div>
      {onRetry && <button onClick={onRetry}>重新请求</button>}
    </div>
  );
}
const stateNames: Record<string, [string, string, string]> = {
  LEASED: ["已获租", "○", "blue"],
  STARTING: ["启动中", "◉", "blue"],
  RUNNING: ["运行中", "●", "blue"],
  VERIFYING: ["验证中", "◎", "blue"],
  REVIEW_READY: ["待审阅", "◇", "amber"],
  MERGE_QUEUED: ["待集成", "○", "amber"],
  MERGING: ["集成中", "◎", "blue"],
  STOPPING: ["停止待确认", "□", "amber"],
  RECOVERY_REQUIRED: ["待恢复", "□", "red"],
  SUCCEEDED: ["已完成", "✓", "green"],
  FAILED: ["失败", "×", "red"],
  CANCELLED: ["已取消", "—", "muted"],
  PASS: ["通过", "✓", "green"],
  FAIL: ["未通过", "×", "red"],
  BLOCKED: ["受阻", "◆", "amber"],
  NOT_RUN: ["未运行", "○", "muted"],
  INCONCLUSIVE: ["未证明", "◇", "amber"],
  VERIFIER_INVALID: ["验证器无效", "×", "red"],
  COMMITTED: ["已提交", "✓", "blue"],
  DRAFT: ["草案", "○", "muted"],
  CHECKING: ["检查中", "◎", "blue"],
  PLANNED: ["已规划", "○", "muted"],
  NEEDS_REVIEW: ["需审阅", "◇", "amber"],
  READY_FOR_ADMISSION: ["规划就绪", "◇", "blue"],
  DEFERRED: ["已延期", "○", "muted"],
  REMOVED_FROM_PLAN: ["已移出规划", "—", "muted"],
  REVIEW_REQUIRED: ["待审版本", "◇", "amber"],
  SUPERSEDED: ["历史版本", "—", "muted"],
  RESERVED: ["已预留", "□", "blue"],
  HELD: ["占用中", "●", "blue"],
  QUARANTINED: ["隔离占位", "□", "red"],
  RELEASED: ["已释放", "✓", "muted"],
  PREPARED: ["已准备", "○", "muted"],
  COMMIT_DECIDED: ["提交决定已持久化", "□", "blue"],
  ABORTED: ["已终止", "—", "muted"],
  ACTIVE: ["活动", "●", "blue"],
  PAUSED: ["暂停新增", "□", "amber"],
  FROZEN: ["已冻结", "✓", "green"],
  MANAGED: ["受管", "●", "blue"],
  OBSERVED_READ_ONLY: ["只读观察", "○", "muted"],
};
export function StatusBadge({
  state,
  scope,
}: {
  state?: string | null;
  scope?: "attempt" | "operation";
}) {
  const [baseLabel, symbol, tone] = stateNames[state || ""] || [
    state || "尚无尝试",
    "○",
    "muted",
  ];
  const label =
    state === "SUCCEEDED"
      ? scope === "attempt"
        ? "已集成"
        : scope === "operation"
          ? "操作完成"
          : baseLabel
      : baseLabel;
  return (
    <span className={`status-badge ${tone}`} title={state || undefined}>
      <span aria-hidden="true">{symbol}</span>
      {label}
    </span>
  );
}
export interface TableColumn<T> {
  key: string;
  label: ReactNode;
  render?: (row: T) => ReactNode;
  numeric?: boolean;
}
export function DataTable<T>({
  columns,
  rows,
  rowKey,
  onRowClick,
  empty,
  selectedKey,
}: {
  columns: TableColumn<T>[];
  rows: T[];
  rowKey: (row: T) => string;
  onRowClick?: (row: T) => void;
  empty?: ReactNode;
  selectedKey?: string;
}) {
  const [activeKey, setActiveKey] = useState(selectedKey);
  useEffect(() => { if (selectedKey !== undefined) setActiveKey(selectedKey); }, [selectedKey]);
  const refs = useRef<(HTMLTableRowElement | null)[]>([]);
  return (
    <div className="table-wrap">
      <table>
        <thead>
          <tr>
            {columns.map((c) => (
              <th
                key={c.key}
                className={c.numeric ? "numeric" : ""}
                scope="col"
              >
                {c.label}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rows.map((row, i) => (
            <tr
              ref={(n) => {
                refs.current[i] = n;
              }}
              key={rowKey(row)}
              tabIndex={onRowClick ? 0 : undefined}
              className={onRowClick ? "interactive-row" : ""}
              aria-selected={onRowClick ? activeKey === rowKey(row) : undefined}
              onClick={() => { if (onRowClick) { setActiveKey(rowKey(row)); onRowClick(row); } }}
              onKeyDown={(e) => {
                if (e.target !== e.currentTarget) return;
                if (e.key === "Enter" && onRowClick) {
                  e.preventDefault();
                  setActiveKey(rowKey(row));
                  onRowClick(row);
                }
                if (
                  (e.key === "ArrowDown" || e.key === "ArrowUp") &&
                  onRowClick
                ) {
                  e.preventDefault();
                  refs.current[
                    Math.max(
                      0,
                      Math.min(
                        rows.length - 1,
                        i + (e.key === "ArrowDown" ? 1 : -1),
                      ),
                    )
                  ]?.focus();
                }
              }}
            >
              {columns.map((c) => (
                <td key={c.key} className={c.numeric ? "numeric" : ""}>
                  {c.render
                    ? c.render(row)
                    : String((row as Record<string, unknown>)[c.key] ?? "—")}
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
      {rows.length === 0 && (empty || <EmptyState title="暂无记录" />)}
    </div>
  );
}
export function Drawer({
  title,
  onClose,
  children,
  animateClose = false,
}: {
  title: string;
  onClose: () => void;
  children: ReactNode;
  animateClose?: boolean;
}) {
  const ref = useRef<HTMLDivElement>(null);
  const [leaving, setLeaving] = useState(false);
  const leavingRef = useRef(false);
  const closeTimer = useRef<ReturnType<typeof setTimeout>>(undefined);
  const [width, setWidth] = useState(() => {
    const saved = localStorage.getItem("forgeflow.inspector.width");
    const value = saved === null || saved.trim() === "" ? 560 : Number(saved);
    return Number.isFinite(value) ? Math.max(320, Math.min(960, value)) : 560;
  });
  function resize(next: number) {
    setWidth(next);
    localStorage.setItem("forgeflow.inspector.width", String(next));
  }
  const id = useId();
  const close = useRef(onClose);
  close.current = onClose;
  function requestClose() {
    if (leavingRef.current) return;
    if (!animateClose || matchMedia('(prefers-reduced-motion: reduce)').matches) { close.current(); return; }
    leavingRef.current = true;
    setLeaving(true);
    closeTimer.current = setTimeout(() => close.current(), 160);
  }
  const dismiss = useRef(requestClose);
  dismiss.current = requestClose;
  useEffect(() => {
    const prior = document.activeElement as HTMLElement | null;
    if (drawerScrollLocks++ === 0) { bodyOverflowBeforeDrawers = document.body.style.overflow; document.body.style.overflow = "hidden"; }
    const el = ref.current;
    const blocked: HTMLElement[] = [];
    if (el) drawerStack.push(el);
    let branch = el?.parentElement;
    while (branch?.parentElement) {
      for (const sibling of branch.parentElement.children) {
        if (!(sibling instanceof HTMLElement) || sibling === branch || ['SCRIPT', 'STYLE', 'LINK'].includes(sibling.tagName)) continue;
        const entry = inertSiblings.get(sibling) ?? { count: 0, prior: sibling.inert };
        entry.count++; inertSiblings.set(sibling, entry); sibling.inert = true; blocked.push(sibling);
      }
      branch = branch.parentElement;
      if (branch === document.body) break;
    }
    el?.querySelector<HTMLElement>('button,input,a,[tabindex="0"]')?.focus({ preventScroll: true });
    const handler = (e: KeyboardEvent) => {
      if (drawerStack.at(-1) !== el) return;
      if (e.key === "Escape") {
        e.preventDefault();
        dismiss.current();
      }
      if (e.key === "Tab" && el) {
        const nodes = Array.from(
          el.querySelectorAll<HTMLElement>(
            'button:not(:disabled),a[href],input:not(:disabled),select:not(:disabled),textarea:not(:disabled),[tabindex="0"]',
          ),
        ).filter((node) => node.getClientRects().length > 0);
        const first = nodes[0],
          last = nodes[nodes.length - 1];
        if (e.shiftKey && document.activeElement === first) {
          e.preventDefault();
          last?.focus();
        } else if (!e.shiftKey && document.activeElement === last) {
          e.preventDefault();
          first?.focus();
        }
      }
    };
    document.addEventListener("keydown", handler);
    return () => {
      document.removeEventListener("keydown", handler);
      if (el) { const index = drawerStack.indexOf(el); if (index >= 0) drawerStack.splice(index, 1); }
      for (const sibling of blocked) {
        const entry = inertSiblings.get(sibling);
        if (entry && --entry.count === 0) { sibling.inert = entry.prior; inertSiblings.delete(sibling); }
      }
      clearTimeout(closeTimer.current);
      if (--drawerScrollLocks === 0) document.body.style.overflow = bodyOverflowBeforeDrawers;
      if (prior?.isConnected && !prior.closest('[inert]')) prior.focus({ preventScroll: true });
    };
  }, []);
  return (
    <div className="drawer-backdrop" data-closing={leaving || undefined} onClick={requestClose}>
      <div
        ref={ref}
        className="drawer"
        style={{ width }}
        role="dialog"
        aria-modal="true"
        aria-labelledby={id}
        onClick={(e) => e.stopPropagation()}
      >
        <header>
          <h2 id={id} style={{ minWidth: 0, overflowWrap: "anywhere", lineHeight: 1.5 }}>{title}</h2>
          <button type="button" aria-label="关闭检查器" title="关闭 · Esc" onClick={requestClose} style={{ flexShrink: 0 }}>
            <X size={18} />
          </button>
        </header>
        <div className="drawer-body">{children}</div>
        <details className="drawer-options"><summary>显示设置</summary><div className="drawer-size" style={{ flexWrap: "wrap" }}>
          <label htmlFor={`${id}-width`}>检查器宽度</label>
          <input
            id={`${id}-width`}
            type="range"
            min={320}
            max={960}
            step={8}
            value={width}
            aria-valuetext={`${width} 像素`}
            style={{ flex: "1 1 80px", maxWidth: 180 }}
            onChange={(event) => resize(Number(event.target.value))}
          />
          <span>{width}px</span>
          <button type="button" disabled={width >= 960} onClick={() => resize(Math.min(960, Math.max(720, width + 160)))} aria-label="扩大检查器">扩大</button>
          <button
            type="button"
            onClick={() => resize(560)}
          >
            恢复默认
          </button>
        </div></details>
      </div>
    </div>
  );
}
export function Field({
  label,
  children,
  hint,
}: {
  label: string;
  children: ReactNode;
  hint?: string;
}) {
  const id = useId();
  const content = Children.map(children, (child) => {
    if (
      !isValidElement(child) ||
      typeof child.type !== "string" ||
      !["input", "select", "textarea"].includes(child.type)
    )
      return child;
    const control = child as ReactElement<Record<string, unknown>>;
    return cloneElement(control, {
      "aria-labelledby": control.props["aria-labelledby"] || `${id}-label`,
      "aria-describedby":
        [control.props["aria-describedby"], hint ? `${id}-hint` : undefined]
          .filter(Boolean)
          .join(" ") || undefined,
    });
  });
  return (
    <label className="field">
      <span id={`${id}-label`}>{label}</span>
      {content}
      {hint && <small id={`${id}-hint`}>{hint}</small>}
    </label>
  );
}
export function JsonView({ value }: { value: unknown }) {
  return <pre className="json-view">{JSON.stringify(value, null, 2)}</pre>;
}
export function QueryState({
  loading,
  error,
  empty,
  onRetry,
  children,
  retainContent = false,
}: {
  loading: boolean;
  error?: unknown;
  empty?: boolean;
  onRetry?: () => void;
  children: ReactNode;
  retainContent?: boolean;
}) {
  if (loading && !retainContent)
    return (
      <div className="loading-state" role="status" aria-live="polite">
        <div className="skeleton" />
        <div className="skeleton" />
        <div className="skeleton short" />
        <span>正在读取服务端记录…</span>
      </div>
    );
  if (error && !retainContent) return <ErrorNotice error={error} onRetry={onRetry} />;
  if (empty)
    return (
      <EmptyState
        title="暂无记录"
        description="当前作用域没有匹配的服务端记录。"
      />
    );
  return <>{error && <><ErrorNotice error={error} onRetry={onRetry} /><p className="muted" role="status">更新未完成，当前保留最后一次成功观察的内容。</p></>}{children}</>;
}
export function SourceStamp({
  source,
  observedAt,
}: {
  source?: string;
  observedAt?: string;
}) {
  return (
    <div className="source-stamp">
      来源：{source || "服务端未提供"} · 观察时间：
      {observedAt
        ? new Date(observedAt).toLocaleString("zh-CN", {
            timeZone: "Asia/Shanghai",
            hour12: false,
          })
        : "服务端未提供"}{" "}
      · Asia/Shanghai
    </div>
  );
}
export function Pagination({
  query,
  count = 0,
}: {
  query: CursorApiControls;
  count?: number;
}) {
  return (
    <div className="pagination">
      <span>
        {query.loading ? (
          "正在读取当前页…"
        ) : query.error ? (
          "当前页未取得最新结果"
        ) : (
          <>
            当前页{query.page ? ` ${query.page}` : ""} · 本页 {count} 条
            {query.hasNext ? " · 还有更多记录" : ""}
          </>
        )}
      </span>
      <div>
        <button
          onClick={query.firstPage}
          disabled={query.loading || query.page === 1}
        >
          回到首页
        </button>
        <button
          onClick={query.previousPage}
          disabled={query.loading || !query.hasPrevious}
        >
          <ChevronLeft size={14} />
          上一页
        </button>
        <button
          onClick={query.nextPage}
          disabled={query.loading || !query.hasNext}
        >
          下一页
          <ChevronRight size={14} />
        </button>
      </div>
    </div>
  );
}
