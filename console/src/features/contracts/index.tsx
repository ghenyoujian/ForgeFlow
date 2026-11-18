import { useState, type FormEvent } from 'react';
import { FilePlus2, LockKeyhole, RefreshCw, ScrollText } from 'lucide-react';
import { useApi, useCursorApi, items } from '../../app/api';
import type { PageProps } from '../../app/types';
import { DataTable, Drawer, EmptyState, ErrorNotice, Field, JsonView, PageHeader, Panel, Pagination, QueryState, SourceStamp, StatusBadge } from '../../components';
import { lines, parseStrictJson, pathId, useCommand, useCompleteApi } from '../flow/types';

interface ContractVersion {
  project_id: string; contract_id: string; version: number; spec_sha256: string;
  source_sha256: string; producer_task_id: string; required_consumers: string[];
  passing_consumers: string[]; independent_receipt_id: string | null;
  integration_receipt_id: string | null; frozen: boolean; revision: number; schema: unknown;
}
interface Receipt { receipt_id: string; attempt_id: string; kind: string; total: number; failed: number; skipped: number; candidate_sha?: string; integrated_sha?: string; verifier_id: string }
interface Registration { contract_id: string; version: number; schema: unknown; producer_task_id: string; source_sha256: string; required_consumers: string[] }

export function ContractsPage({ projectId }: PageProps) {
  const path = projectId ? `/projects/${pathId(projectId)}/contract-versions` : null;
  const query = useCursorApi<ContractVersion[]>(path, 'contract_cursor');
  const project = useApi<{ authority_mode: string; archived: boolean }>(projectId ? `/projects/${pathId(projectId)}` : null);
  const [selected, setSelected] = useState<ContractVersion>();
  const [editing, setEditing] = useState<{ base?: ContractVersion }>();
  const [freezing, setFreezing] = useState<ContractVersion>();
  const definitions = useCompleteApi<ContractVersion>(editing ? path : null);
  const receipts = useCompleteApi<Receipt>(freezing && projectId ? `/projects/${pathId(projectId)}/evidence` : null);
  const command = useCommand();
  const versions = items(query.data);
  const writable = project.data?.authority_mode === 'MANAGED' && !project.data.archived;
  async function save(value: Registration) {
    if (!path) return;
    const result = await command.run<ContractVersion>(path, value);
    if (result) { query.reload(); setEditing(undefined); setSelected(result); }
  }
  async function freeze(contract: ContractVersion, producerReceipt: string, consumerReceipts: string[]) {
    if (!projectId) return;
    const result = await command.run<ContractVersion>(`/contracts/${pathId(contract.contract_id)}/freeze-requests`, {
      project_id: projectId, version: contract.version, producer_receipt_id: producerReceipt, consumer_receipt_ids: consumerReceipts,
    }, contract.revision);
    if (result) { query.reload(); setFreezing(undefined); setSelected(result); }
  }
  return <>
    <PageHeader title="合同中心" description="生产者、消费者与独立证据绑定同一版本。冻结由权威服务重新核验。" actions={<>
      <button onClick={query.reload} aria-label="刷新合同"><RefreshCw size={16} /></button>
      <button className="primary" disabled={!projectId || !writable || command.busy} onClick={() => setEditing({})}><FilePlus2 size={16} />登记合同版本</button>
    </>} />
    <SourceStamp source={query.metadata.source} observedAt={query.metadata.observed_at} />
    {command.error && <ErrorNotice error={command.error} />}
    {!projectId ? <EmptyState title="选择项目查看合同" /> : <QueryState loading={query.loading && !query.data} error={query.error} onRetry={query.reload}>
      <Panel title={<span><ScrollText size={16} />版本与消费者矩阵</span>}>
        <DataTable rows={versions} rowKey={contract => `${contract.contract_id}:${contract.version}`} onRowClick={setSelected} columns={[
          { key: 'contract_id', label: '合同' }, { key: 'version', label: '版本', numeric: true },
          { key: 'frozen', label: '冻结状态', render: contract => <StatusBadge state={contract.frozen ? 'FROZEN' : 'DRAFT'} /> },
          { key: 'producer_task_id', label: '生产者' },
          { key: 'required_consumers', label: '消费者验证', render: contract => `${contract.passing_consumers.length} / ${contract.required_consumers.length}` },
          { key: 'independent_receipt_id', label: '独立收据', render: contract => contract.independent_receipt_id ? '已关联' : '缺失' },
        ]} empty={<EmptyState title="本页没有合同版本" description="登记类型化版本与来源身份。冻结需要真实消费者验证、独立收据与已集成生产者。" />} />
        <Pagination query={query} count={versions.length} />
      </Panel>
    </QueryState>}
    {selected && !editing && !freezing && <Drawer title={`${selected.contract_id} · v${selected.version}`} onClose={() => setSelected(undefined)}>
      <div className="toolbar"><StatusBadge state={selected.frozen ? 'FROZEN' : 'DRAFT'} />
        <button disabled={!writable || command.busy} onClick={() => setEditing({ base: selected })}>建立下一版本</button>
        <button disabled={!writable || selected.frozen || command.busy} onClick={() => setFreezing(selected)}><LockKeyhole size={16} />请求冻结</button>
      </div>
      <dl className="detail-grid"><dt>规范 hash</dt><dd><code>{selected.spec_sha256}</code></dd><dt>来源 hash</dt><dd><code>{selected.source_sha256}</code></dd><dt>生产者</dt><dd>{selected.producer_task_id}</dd><dt>独立收据</dt><dd>{selected.independent_receipt_id ?? '缺失'}</dd><dt>集成收据</dt><dd>{selected.integration_receipt_id ?? '缺失'}</dd></dl>
      {!selected.frozen && <p className="muted">草案来源 hash 是待核验声明；只有冻结收据证明消费者兼容与生产者集成。</p>}
      <h3>消费者兼容矩阵</h3>
      <DataTable rows={selected.required_consumers.map(id => ({ id, passed: selected.passing_consumers.includes(id) }))} rowKey={row => row.id} columns={[{ key: 'id', label: '消费者' }, { key: 'passed', label: '当前版本验证', render: row => <StatusBadge state={row.passed ? 'PASS' : 'NOT_RUN'} /> }]} empty={<p>没有登记消费者，不能把空矩阵计作兼容验证。</p>} />
      <h3>版本规范</h3><JsonView value={selected.schema} />
      <details><summary>完整合同身份</summary><JsonView value={selected} /></details>
    </Drawer>}
    {editing && <Drawer title={editing.base ? '建立合同下一版本' : '登记公共合同版本'} onClose={() => !command.busy && setEditing(undefined)}>
      <QueryState loading={definitions.loading} error={definitions.error} onRetry={definitions.reload}>
        <ContractForm base={editing.base} versions={definitions.data ?? []} busy={command.busy} error={command.error} onSave={save} />
      </QueryState>
    </Drawer>}
    {freezing && <Drawer title={`冻结 ${freezing.contract_id} · v${freezing.version}`} onClose={() => !command.busy && setFreezing(undefined)}>
      <QueryState loading={receipts.loading} error={receipts.error} onRetry={receipts.reload}>
        <FreezeForm contract={freezing} receipts={receipts.data ?? []} busy={command.busy} error={command.error} onSave={(producer, consumers) => freeze(freezing, producer, consumers)} />
      </QueryState>
    </Drawer>}
  </>;
}

function ContractForm({ base, versions, busy, error, onSave }: { base?: ContractVersion; versions: ContractVersion[]; busy: boolean; error?: Error; onSave: (value: Registration) => void }) {
  const [id, setId] = useState(base?.contract_id ?? '');
  const [schema, setSchema] = useState(base ? JSON.stringify(base.schema, null, 2) : '');
  const [sourceHash, setSourceHash] = useState(base?.source_sha256 ?? '');
  const [producer, setProducer] = useState(base?.producer_task_id ?? '');
  const [consumers, setConsumers] = useState(base?.required_consumers.join('\n') ?? '');
  const [validation, setValidation] = useState<Error>();
  const nextVersion = Math.max(0, ...versions.filter(version => version.contract_id === id).map(version => version.version)) + 1;
  function submit(event: FormEvent) {
    event.preventDefault();
    try {
      const value: unknown = parseStrictJson(schema);
      if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('规范必须为 JSON 对象。');
      if (!/^[0-9a-f]{64}$/i.test(sourceHash)) throw new Error('输入真实来源的 64 位 SHA256，冻结时重新核验。');
      setValidation(undefined); onSave({ contract_id: id.trim(), version: nextVersion, schema: value, source_sha256: sourceHash, producer_task_id: producer.trim(), required_consumers: lines(consumers) });
    } catch (cause) { setValidation(cause instanceof Error ? cause : new Error(String(cause))); }
  }
  return <form onSubmit={submit}>
    <div className="notice">v{nextVersion} · 下一版本基于完整版本列表计算，不继承消费者 PASS 或冻结资格。</div>
    <Field label="合同稳定 ID"><input required value={id} disabled={!!base} onChange={event => setId(event.target.value)} /></Field>
    <Field label="规范 JSON"><textarea rows={14} required spellCheck={false} value={schema} onChange={event => setSchema(event.target.value)} /></Field>
    <Field label="来源 SHA256"><input required value={sourceHash} onChange={event => setSourceHash(event.target.value)} /></Field>
    <Field label="生产者任务 ID"><input required value={producer} onChange={event => setProducer(event.target.value)} /></Field>
    <Field label="必需消费者 ID · 每行一个"><textarea rows={4} value={consumers} onChange={event => setConsumers(event.target.value)} /></Field>
    {validation && <ErrorNotice error={validation} />}{error && <ErrorNotice error={error} />}
    <button className="primary" disabled={busy}>{busy ? '正在登记…' : `保存 v${nextVersion}`}</button>
  </form>;
}

function FreezeForm({ contract, receipts, busy, error, onSave }: { contract: ContractVersion; receipts: Receipt[]; busy: boolean; error?: Error; onSave: (producer: string, consumers: string[]) => void }) {
  const [producer, setProducer] = useState('');
  const [consumers, setConsumers] = useState<string[]>([]);
  return <form onSubmit={event => { event.preventDefault(); onSave(producer, consumers); }}>
    <p>版本 v{contract.version} 的生产者与消费者收据必须绑定规范 hash、真实候选、独立验证与可达集成提交。服务端拒绝不匹配、零用例或过期证据。</p>
    <Field label="生产者证据收据"><select required value={producer} onChange={event => setProducer(event.target.value)}><option value="">选择真实持久收据</option>{receipts.map(receipt => <option key={receipt.receipt_id} value={receipt.receipt_id}>{receipt.receipt_id} · {receipt.kind} · {receipt.total} 用例</option>)}</select></Field>
    <h3>消费者证据收据</h3>
    <div className="selection-list">{receipts.map(receipt => <label key={receipt.receipt_id}><input type="checkbox" checked={consumers.includes(receipt.receipt_id)} onChange={event => setConsumers(event.target.checked ? [...consumers, receipt.receipt_id] : consumers.filter(id => id !== receipt.receipt_id))} />{receipt.receipt_id} · {receipt.kind} · 失败 {receipt.failed} / {receipt.total}</label>)}</div>
    {!receipts.length && <EmptyState title="尚无真实验证收据" description="先运行生产与消费验证并完成受控集成，随后绑定收据。" />}
    {error && <ErrorNotice error={error} />}
    <button className="primary" disabled={busy || !producer || (contract.required_consumers.length > 0 && !consumers.length)}>{busy ? '正在核验冻结资格…' : '核验并提交冻结请求'}</button>
  </form>;
}
