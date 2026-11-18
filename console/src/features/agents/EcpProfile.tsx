import { Bot, CircleHelp } from "lucide-react";
import { DataTable, EmptyState, StatusBadge } from "../../components";

type RecordValue = Record<string, unknown>;
const text = (value: unknown) => typeof value === "string" || typeof value === "number" ? String(value) : "—";
const id = (row: RecordValue, ...keys: string[]) => text(keys.map(key => row[key]).find(value => value !== undefined && value !== null));
const digest = (value: unknown) => { const valueText = text(value); return valueText === "—" ? valueText : `${valueText.slice(0, 12)}…`; };
const capabilityState = (value: unknown) => {
  if (value === true) return "SUPPORTED";
  if (value === false) return "UNSUPPORTED";
  if (typeof value === "string") return value.toUpperCase();
  if (value && typeof value === "object" && !Array.isArray(value)) {
    const row = value as RecordValue;
    return text(row.status ?? row.evidence_status ?? row.support_status).toUpperCase();
  }
  return "UNKNOWN";
};
const capabilities = (row: RecordValue) => {
  const value = row.capabilities;
  if (!value || typeof value !== "object" || Array.isArray(value)) return [] as Array<[string, string]>;
  return Object.entries(value as Record<string, unknown>).map(([name, state]) => [name, capabilityState(state)] as [string, string]);
};

export function EcpProfile({ profiles, registrations, onSelect }: { profiles: RecordValue[]; registrations: Map<string, RecordValue>; onSelect: (row: RecordValue) => void }) {
  return <DataTable
    rows={profiles}
    rowKey={row => id(row, "profile_id")}
    onRowClick={onSelect}
    empty={<EmptyState title="尚无冻结 Profile" description="Profile 身份包含版本和摘要；运行资格需要单独探测与证据。" />}
    columns={[
      { key: "profile_id", label: <><Bot size={14} /> Profile</>, render: row => <><strong>{id(row, "profile_id")}</strong><small>{text(row.provider)} · {text(row.profile_version)}</small></> },
      { key: "registration_id", label: "Agent 登记", render: row => registrations.has(text(row.registration_id)) ? text(row.registration_id) : <span title="关联登记未返回">{text(row.registration_id)} <CircleHelp size={13} /></span> },
      { key: "support_status", label: "声明支持", render: row => <StatusBadge state={text(row.support_status)} /> },
      { key: "evidence_status", label: "证据状态", render: row => <StatusBadge state={text(row.evidence_status)} /> },
      { key: "capabilities", label: "能力矩阵", render: row => {
        const entries = capabilities(row);
        return entries.length ? <ul className="compact-list">{entries.map(([name, state]) => <li key={name}><span>{name}</span> <StatusBadge state={state} /></li>)}</ul> : <span className="muted">UNKNOWN · 未返回能力清单</span>;
      } },
      { key: "binary_digest", label: "二进制摘要", render: row => digest(row.binary_digest) },
    ]}
  />;
}
