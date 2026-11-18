import { useEffect, useLayoutEffect, useMemo, useRef, useState } from 'react';
import { Background, Controls, MarkerType, Position, ReactFlow, type Connection, type Edge, type Node, type ReactFlowInstance, useNodesState } from '@xyflow/react';
import ELK, { type ELK as LayoutEngine } from 'elkjs/lib/elk-api';
import LayoutWorker from 'elkjs/lib/elk-worker.min.js?worker';
import { StatusBadge } from '../../components';
import '@xyflow/react/dist/style.css';

export type GraphTask = { id: string; title: string; owner: string; state: string; packageId?: string; executionState?: string; executionAvailable?: boolean };
export type GraphDependency = { id: string; source: string; target: string; kind: string };
type Props = {
  tasks: GraphTask[];
  scopeIds?: string[];
  onExpandBoundary?: () => void;
  dependencies: GraphDependency[];
  selectedId?: string;
  readOnly: boolean;
  busy: boolean;
  onSelect: (id: string) => void;
  onConnect: (source: string, target: string) => void;
  onDeleteDependency: (id: string) => void;
};


export function DagEditor({ tasks, scopeIds, onExpandBoundary, dependencies, selectedId, readOnly, busy, onSelect, onConnect, onDeleteDependency }: Props) {
  const [query, setQuery] = useState('');
  const [owner, setOwner] = useState('');
  const [slice, setSlice] = useState('all');
  const [exceptionsOnly, setExceptionsOnly] = useState(false);
  const [selectedEdge, setSelectedEdge] = useState<string>();
  const [layoutError, setLayoutError] = useState<string>();
  const [layoutBusy, setLayoutBusy] = useState(false);
  const [module, setModule] = useState('');
  const [nodes, setNodes, onNodesChange] = useNodesState<Node>([]);
  const flowRef = useRef<ReactFlowInstance<Node, Edge> | undefined>(undefined);
  const scopeSet = useMemo(() => scopeIds ? new Set(scopeIds) : undefined, [scopeIds]);
  const matching = useMemo(() => {
    const linked = new Set<string>(selectedId ? [selectedId] : []);
    if (slice !== 'all' && selectedId) {
      const adjacency = new Map<string, string[]>();
      for (const edge of dependencies) {
        const from = slice === 'upstream' ? edge.target : edge.source;
        const to = slice === 'upstream' ? edge.source : edge.target;
        const adjacent = adjacency.get(from); if (adjacent) adjacent.push(to); else adjacency.set(from, [to]);
      }
      const queue = [selectedId];
      for (let index = 0; index < queue.length; index++) for (const next of adjacency.get(queue[index]) ?? []) {
        if (!linked.has(next)) { linked.add(next); queue.push(next); }
      }
    }
    return tasks.filter(task => (!scopeSet || scopeSet.has(task.id)) && (!owner || task.owner === owner) && (!module || task.packageId === module) && (!query || `${task.id} ${task.title}`.toLowerCase().includes(query.toLowerCase())) && (!exceptionsOnly || ['FAILED', 'STOPPING', 'RECOVERY_REQUIRED'].includes(task.executionState ?? '')) && (slice === 'all' || !selectedId || linked.has(task.id)));
  }, [tasks, dependencies, owner, query, slice, selectedId, exceptionsOnly, module, scopeSet]);
  const visible = useMemo(() => {
    const limited = matching.slice(0, 200);
    const selected = tasks.find(task => task.id === selectedId);
    if (selected && !limited.some(task => task.id === selectedId)) { if (limited.length < 200) limited.push(selected); else limited[limited.length - 1] = selected; }
    return limited;
  }, [matching, selectedId, tasks]);
  const visibleIds = useMemo(() => new Set(visible.map(task => task.id)), [visible]);
  const boundary = useMemo(() => {
    const groups = new Map<string, { id: string; owner: string; ids: Set<string> }>();
    const aliases = new Map<string, string>();
    const taskMap = new Map(tasks.map(task => [task.id, task]));
    let prefix = '@view-boundary:';
    while (tasks.some(task => task.id.startsWith(prefix))) prefix = `@${prefix}`;
    for (const edge of dependencies) {
      const outside = visibleIds.has(edge.source) && !visibleIds.has(edge.target) ? edge.target : visibleIds.has(edge.target) && !visibleIds.has(edge.source) ? edge.source : undefined;
      if (!outside) continue;
      const groupOwner = taskMap.get(outside)?.owner ?? '外部引用';
      const ownerId = JSON.stringify([prefix, groupOwner]);
      const capped = !groups.has(ownerId) && groups.size >= 64;
      const id = capped ? JSON.stringify([prefix, 'overflow', 0]) : ownerId;
      const group = groups.get(id) ?? { id, owner: capped ? '其他 Owner 范围' : groupOwner, ids: new Set<string>() };
      group.ids.add(outside); groups.set(id, group); aliases.set(outside, id);
    }
    return { groups, aliases };
  }, [dependencies, visibleIds, tasks]);
  const graphRelations = useMemo(() => {
    const groups = new Map<string, { id: string; source: string; target: string; kind: string; originals: GraphDependency[] }>();
    for (const edge of dependencies) {
      if (!visibleIds.has(edge.source) && !visibleIds.has(edge.target)) continue;
      const source = boundary.aliases.get(edge.source) ?? edge.source;
      const target = boundary.aliases.get(edge.target) ?? edge.target;
      const id = source === edge.source && target === edge.target ? edge.id : JSON.stringify(['view', source, target, edge.kind]);
      const group = groups.get(id) ?? { id, source, target, kind: edge.kind, originals: [] };
      group.originals.push(edge); groups.set(id, group);
    }
    return Array.from(groups.values());
  }, [dependencies, visibleIds, boundary]);
  const graphEdges = useMemo<Edge[]>(() => graphRelations.map(edge => ({
    id: edge.id, source: edge.source, target: edge.target, label: `${edge.kind}${edge.originals.length > 1 ? ` · ${edge.originals.length} 条` : ''}`,
    markerEnd: { type: MarkerType.ArrowClosed, color: 'var(--control-line, #8f8f8f)' }, selected: edge.id === selectedEdge,
    animated: edge.id === selectedEdge && !window.matchMedia('(prefers-reduced-motion: reduce)').matches,
    style: { stroke: edge.id === selectedEdge ? 'var(--text, #202A35)' : 'var(--control-line, #8f8f8f)' },
  })), [graphRelations, selectedEdge]);

  const draftNodes = useMemo<Node[]>(() => {
    const graphTasks: GraphTask[] = [...visible, ...Array.from(boundary.groups.values()).map(group => ({ id: group.id, title: `${group.ids.size} 张范围外任务`, owner: group.owner, state: 'BOUNDARY' }))];
    const draftNodes: Node[] = graphTasks.map((task, index) => ({
      id: task.id, position: { x: (index % 4) * 250, y: Math.floor(index / 4) * 125 },
      sourcePosition: Position.Right, targetPosition: Position.Left,
      data: { label: <div><code style={{ display: 'block', fontSize: 11, opacity: 0.85, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }} title={task.id}>{boundary.groups.has(task.id) ? '范围边界' : task.id}</code><strong style={{ display: '-webkit-box', WebkitLineClamp: 2, WebkitBoxOrient: 'vertical', overflow: 'hidden', fontWeight: 550, margin: '5px 0', fontSize: 13 }}>{task.title}</strong><span style={{ display: 'block', fontSize: 11, opacity: 0.7, marginBottom: 5, whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>{task.owner}</span><StatusBadge state={task.state} />{!boundary.groups.has(task.id) && <div style={{ marginTop: 7, fontSize: 10 }}>{task.executionState ? <span>最近尝试 <StatusBadge state={task.executionState} /></span> : <span className="muted">{task.executionAvailable ? '此修订尚无尝试' : '执行观察未取得'}</span>}</div>}</div> },
      selected: task.id === selectedId, connectable: !boundary.groups.has(task.id) && !readOnly && !busy,
      style: { width: 225, whiteSpace: 'pre-line', textAlign: 'left', padding: 12, fontSize: 12, lineHeight: 1.5, background: boundary.groups.has(task.id) ? 'var(--panel2, #EDF1F5)' : 'var(--panel, white)', color: 'var(--text, #202A35)', border: `1px ${boundary.groups.has(task.id) ? 'dashed' : 'solid'} ${task.id === selectedId ? 'var(--text, #202A35)' : 'var(--control-line, #8f8f8f)'}`, borderRadius: 10, boxShadow: task.id === selectedId ? '0 8px 24px #00000012' : undefined },
      ariaLabel: `${task.id}，${task.title}，${task.owner}，规划 ${task.state}${task.executionState ? `，最近尝试 ${task.executionState}` : ''}`,
    }));
    return draftNodes;
  }, [visible, boundary, selectedId, readOnly, busy]);

  useLayoutEffect(() => {
    setNodes(current => {
      const previous = new Map(current.map(node => [node.id, node]));
      return draftNodes.map(node => ({ ...previous.get(node.id), ...node, position: previous.get(node.id)?.position ?? node.position }));
    });
  }, [draftNodes, setNodes]);
  // Labels, execution observations and selection do not change geometry. Keep
  // the layout request alive while these arrive, and preserve manual positions.
  const layoutShape = JSON.stringify({ ids: draftNodes.map(node => node.id), links: [...new Set(graphRelations.map(edge => JSON.stringify([edge.source, edge.target])))].sort() });
  const topology = useMemo(() => {
    const shape = JSON.parse(layoutShape) as { ids: string[]; links: string[] };
    return { ids: shape.ids, edges: shape.links.map((link, index) => { const [source, target] = JSON.parse(link) as [string, string]; return { id: `layout-${index}`, sources: [source], targets: [target] }; }) };
  }, [layoutShape]);
  useEffect(() => {
    let active = true;
    setLayoutError(undefined);
    if (!topology.ids.length) { setLayoutBusy(false); return; }
    let layout: LayoutEngine | undefined;
    setLayoutBusy(true);
    try {
      layout = new ELK({ workerFactory: () => new LayoutWorker() });
      void layout.layout({ id: 'root', layoutOptions: { 'elk.algorithm': 'layered', 'elk.direction': 'RIGHT', 'elk.spacing.nodeNode': '36', 'elk.layered.spacing.nodeNodeBetweenLayers': '75' }, children: topology.ids.map(id => ({ id, width: 225, height: 170 })), edges: topology.edges }).then(result => {
        if (!active) return;
        const positions = new Map((result.children ?? []).map(node => [node.id, node]));
        setNodes(current => current.map(node => ({ ...node, position: { x: positions.get(node.id)?.x ?? node.position.x, y: positions.get(node.id)?.y ?? node.position.y } })));
        setLayoutBusy(false);
        requestAnimationFrame(() => requestAnimationFrame(() => {
          if (active) void flowRef.current?.fitView({ padding: 0.18, maxZoom: 1, duration: window.matchMedia('(prefers-reduced-motion: reduce)').matches ? 0 : 220 });
        }));
      }).catch(error => { if (active) { setLayoutBusy(false); setLayoutError(error instanceof Error ? error.message : String(error)); } });
    } catch (error) { setLayoutBusy(false); setLayoutError(error instanceof Error ? error.message : String(error)); }
    return () => { active = false; layout?.terminateWorker(); };
  }, [topology, setNodes]);

  function connect(connection: Connection) {
    if (connection.source && connection.target && !readOnly && !busy) onConnect(connection.source, connection.target);
  }
  return <div>
    <div className="toolbar dag-scope-toolbar">
      {!scopeIds && <><input aria-label="搜索图中任务" placeholder="搜索卡号或结果" value={query} onChange={event => setQuery(event.target.value)} />
      <select aria-label="Owner 范围" value={owner} onChange={event => setOwner(event.target.value)}><option value="">全部 Owner</option>{Array.from(new Set(tasks.map(task => task.owner))).map(value => <option key={value}>{value}</option>)}</select>
      <select aria-label="模块范围" value={module} onChange={event => setModule(event.target.value)}><option value="">全部模块</option>{[...new Set(tasks.map(task => task.packageId).filter((id): id is string => !!id))].map(id => <option key={id}>{id}</option>)}</select></>}
      <select aria-label="依赖范围" value={slice} onChange={event => setSlice(event.target.value)}><option value="all">全部依赖</option><option value="upstream">选中任务的前置</option><option value="downstream">选中任务的后续</option></select>
      <label><input type="checkbox" checked={exceptionsOnly} onChange={event => setExceptionsOnly(event.target.checked)} />仅看执行异常</label>
      <span>{visible.length} / {tasks.length} 张卡 · {boundary.aliases.size} 张边界任务</span>{(query || owner || module || slice !== 'all' || exceptionsOnly) && <button onClick={() => { setQuery(''); setOwner(''); setModule(''); setSlice('all'); setExceptionsOnly(false); }}>重置图范围</button>}
    </div>
    {matching.length > 200 && <p className="dag-hint">图中显示前 200 张匹配任务及范围外依赖。缩小筛选可查看具体任务；完整检查始终使用全部任务。</p>}
    {layoutError && <p role="alert">自动布局失败，已保留可操作图：{layoutError}</p>}
    <div className="dag-canvas"><ReactFlow nodes={nodes} edges={graphEdges} onInit={instance => { flowRef.current = instance; }} onNodesChange={onNodesChange} onNodeClick={(_, node) => { const group = boundary.groups.get(node.id); if (group) { onExpandBoundary?.(); setQuery(''); setOwner(group.owner === '其他 Owner 范围' ? '' : group.owner); setSlice('all'); return; } onSelect(node.id); }} onEdgeClick={(_, edge) => setSelectedEdge(edge.id)} onConnect={connect} nodesConnectable={!readOnly && !busy} edgesFocusable nodesFocusable deleteKeyCode={null} fitView fitViewOptions={{ padding: 0.18, maxZoom: 1 }} minZoom={0.15} maxZoom={2} aria-label="任务依赖图"><Background /><Controls /></ReactFlow>{layoutBusy && <div role="status" className="dag-layout-status"><span className="activity-spinner" />正在后台布局，可继续操作</div>}</div>
    <details className="dag-help"><summary>如何查看和调整依赖</summary><p>箭头从前置任务指向后续任务。虚线节点表示范围外依赖，点击可展开。拖动连线修改依赖，保存草案后由服务端确认；移动任务仅调整当前布局。</p></details>
    {selectedEdge && <div className="selection-list">{graphRelations.find(edge => edge.id === selectedEdge)?.originals.slice(0, 100).map(edge => <div className="toolbar" key={edge.id}><span>{edge.source} → {edge.target} · {edge.kind}</span><button onClick={() => { setQuery(edge.source); setOwner(''); setSlice('all'); onSelect(edge.source); }}>定位前置</button><button disabled={readOnly || busy} onClick={() => onDeleteDependency(edge.id)}>移除依赖</button></div>)}<small>聚合关系展示前 100 条真实引用；任务检查器保留完整依赖。删除只提交指定真实关系。</small></div>}
  </div>;
}
