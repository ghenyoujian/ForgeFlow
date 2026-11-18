import { useLayoutEffect, useRef, useState, type ReactNode } from 'react';
import type { TaskCard } from '../features/flow/types';

/** Fixed-height rows bound DOM cost; keyboard navigation addresses the full set. */
export function VirtualTaskTable({ tasks, selectedId, onSelect, renderActions, renderTitle, group, initialScrollTop = 0, onScrollPositionChange }: {
  initialScrollTop?: number; onScrollPositionChange?: (value: number) => void;
  tasks: TaskCard[]; selectedId?: string; onSelect: (id: string) => void;
  renderActions?: (task: TaskCard) => ReactNode; renderTitle?: (task: TaskCard) => ReactNode; group?: (task: TaskCard) => string;
}) {
  const viewport = useRef<HTMLDivElement>(null);
  const [top, setTop] = useState(initialScrollTop);
  useLayoutEffect(() => { if (viewport.current) viewport.current.scrollTop = initialScrollTop; }, []);
  const height = 60, windowSize = 18, overscan = 5;
  const start = Math.min(Math.max(0, tasks.length - windowSize), Math.max(0, Math.floor(top / height) - overscan));
  const end = Math.min(tasks.length, start + windowSize + overscan * 2);
  function focus(index: number) {
    const next = Math.max(0, Math.min(tasks.length - 1, index));
    viewport.current?.scrollTo({ top: Math.max(0, next * height - 120) });
    setTop(Math.max(0, next * height - 120));
    requestAnimationFrame(() => viewport.current?.querySelector<HTMLElement>(`[data-task-index="${next}"]`)?.focus());
  }
  return <div className="virtual-task-viewport" ref={viewport} onScroll={event => { setTop(event.currentTarget.scrollTop); onScrollPositionChange?.(event.currentTarget.scrollTop); }}>
    <table aria-label="规划任务表" aria-rowcount={tasks.length + 1}>
      <thead><tr><th>任务</th><th>责任与状态</th>{renderActions && <th><span className="sr-only">任务操作</span></th>}</tr></thead>
      <tbody>
        {start > 0 && <tr aria-hidden="true"><td colSpan={3} style={{ height: start * height, padding: 0 }} /></tr>}
        {tasks.slice(start, end).map((task, i) => <tr key={task.task_id} data-task-index={start + i} data-task-id={task.task_id} aria-rowindex={start + i + 2}
          aria-selected={task.task_id === selectedId} className="virtual-task-row" tabIndex={0}
          onClick={() => onSelect(task.task_id)} onKeyDown={event => {
            if (event.target !== event.currentTarget) return;
            if (event.key === 'Enter' || event.key === ' ') { event.preventDefault(); onSelect(task.task_id); }
            if (['ArrowDown', 'ArrowUp', 'Home', 'End'].includes(event.key)) {
              event.preventDefault(); focus(event.key === 'Home' ? 0 : event.key === 'End' ? tasks.length - 1 : start + i + (event.key === 'ArrowDown' ? 1 : -1));
            }
          }}>
          <td>{renderTitle ? renderTitle(task) : <strong title={task.title}>{task.title}</strong>}<small>{group?.(task)} · {task.task_id}</small></td>
          <td><span title={`责任人 ${task.owner_id} · 团队 ${task.team_id}`}>{task.owner_id}{task.team_id !== task.owner_id && ` · ${task.team_id}`}</span><small>{({ PLANNED: '已规划', NEEDS_REVIEW: '待复核', READY_FOR_ADMISSION: '可预检查准入', DEFERRED: '已延期', REMOVED_FROM_PLAN: '已移出计划' })[task.state]}</small></td>
          {renderActions && <td onClick={e => e.stopPropagation()}>{renderActions(task)}</td>}
        </tr>)}
        {end < tasks.length && <tr aria-hidden="true"><td colSpan={3} style={{ height: (tasks.length - end) * height, padding: 0 }} /></tr>}
      </tbody>
    </table>
    {!tasks.length && <p className="empty-state">没有匹配任务</p>}
  </div>;
}
