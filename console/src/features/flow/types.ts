import { useRef, useState } from 'react';
import { api, useSharedApi } from '../../app/api';

export interface ResourceVector { active_slot: number; coding_slot: number; cpu_units: number; memory_bytes: number; build_permit: number; gpu_permit: number; provider_inflight: number }
export interface TaskCard {
  project_id: string; task_id: string; task_revision: number; flow_revision: number;
  title: string; owner_id: string; team_id: string; requirement_ids: string[];
  read_set: string[]; write_set: string[]; dependencies: string[];
  state: 'PLANNED' | 'NEEDS_REVIEW' | 'READY_FOR_ADMISSION' | 'DEFERRED' | 'REMOVED_FROM_PLAN';
  input_digest: string; resource_request: ResourceVector; envelope: Record<string, unknown> | null; revision: number;
}
export interface FlowRevision {
  project_id: string; flow_revision: number; parent_revision: number | null;
  state: 'DRAFT' | 'CHECKING' | 'REVIEW_REQUIRED' | 'COMMITTED' | 'SUPERSEDED';
  tasks: TaskCard[]; input_digest: string; approved_by: string | null; revision: number;
}
export interface Requirement { project_id: string; requirement_id: string; title: string; source_anchor: string; outcome: string; scope: string; acceptance: string[]; priority: number; weight: number; deferred_reason: string | null; revision: number }
export interface Finding { finding_id: string; rule_id: string; severity: string; subject_ref?: string | Record<string, unknown>; task_id?: string; message?: string; evidence_refs?: unknown[]; blocked_tasks?: string[]; suggested_action?: string; source_revision?: number | string; observed_at?: string; [key: string]: unknown }
export interface CheckReport { findings?: Finding[]; valid?: boolean; passed?: boolean; input_digest?: string; flow_revision?: number; observed_at?: string; [key: string]: unknown }
export interface ContractBinding { contract_id: string; version: number; spec_sha256: string }
export interface DependencySpec { task_id: string; project_id: string; kind: 'integrated' | 'artifact' | 'contract_frozen' | 'gate_pass'; binding_id: string }
export interface TaskSpec {
  outcome: string; requirement_digest_refs: Record<string, string>; design_anchors: string[]; inputs: { path: string; sha256: string; producer_task_id: string | null }[];
  mandatory_paths: string[]; dependency_refs: DependencySpec[]; contract_produces: ContractBinding[]; contract_consumes: ContractBinding[];
  execution_profile: string; verification_plan: string; verification_case_count: number; rollback_plan: string;
  known_unknowns: string[]; not_proven: string[]; isolated_contract_probe: boolean;
}
export interface CompileContext {
  requirements: { requirement_id: string; source_document: string; anchor: string; acceptance: string; priority: number; deferred_reason: string | null }[];
  requirement_semantic_digests: Record<string, string>;
  owners: { owner_id: string; root_team_id?: string | null; include: string[]; exclude: string[] }[]; task_specs: Record<string, TaskSpec>;
  current_inputs: Record<string, string>; resolved_paths: Record<string, string>; contracts: unknown[];
  source_revision: string; observed_at: string;
}
export function newTaskSpec(): TaskSpec { return { outcome: '', requirement_digest_refs: {}, design_anchors: [], inputs: [], mandatory_paths: [], dependency_refs: [], contract_produces: [], contract_consumes: [], execution_profile: '', verification_plan: '', verification_case_count: 0, rollback_plan: '', known_unknowns: [], not_proven: [], isolated_contract_probe: false }; }
export const pathId = (value: string) => encodeURIComponent(value);
export const flowPath = (flow: FlowRevision) => `/flows/${pathId(`${flow.project_id}:${flow.flow_revision}`)}`;
export const lines = (value: string) => value.split(/\r?\n/).map(line => line.trim()).filter(Boolean);
export const unique = (values: string[]) => Array.from(new Set(values));
/** Preserve ambiguity failures before browser JSON parsing can discard duplicate keys. */
export function parseStrictJson<T = unknown>(source: string): T {
  const parsed: T = JSON.parse(source);
  const tokens = source.match(/"(?:\\[\s\S]|[^"\\])*"|[{}\[\]:,]|-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?|true|false|null/g) ?? [];
  let index = 0;
  function value() {
    const token = tokens[index++];
    if (token === '{') {
      const keys = new Set<string>();
      if (tokens[index] === '}') { index++; return; }
      while (index < tokens.length) {
        const key: string = JSON.parse(tokens[index++]);
        if (keys.has(key)) throw new Error(`JSON 对象包含重复键：${key}。修复原文后再提交。`);
        keys.add(key); index++; value();
        if (tokens[index++] === '}') return;
      }
    } else if (token === '[') {
      if (tokens[index] === ']') { index++; return; }
      while (index < tokens.length) { value(); if (tokens[index++] === ']') return; }
    }
  }
  value(); return parsed;
}
export function newTask(projectId: string, flowRevision: number): TaskCard {
  return { project_id: projectId, task_id: crypto.randomUUID(), task_revision: 1, flow_revision: flowRevision, title: '', owner_id: '', team_id: '', requirement_ids: [], read_set: [], write_set: [], dependencies: [], state: 'PLANNED', input_digest: '', resource_request: { active_slot: 1, coding_slot: 0, cpu_units: 0, memory_bytes: 0, build_permit: 0, gpu_permit: 0, provider_inflight: 0 }, envelope: null, revision: 0 };
}
export function useCommand() {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<Error>();
  const [receipt, setReceipt] = useState<unknown>();
  const pending = useRef<{ identity: string; key: string } | undefined>(undefined);
  const inFlight = useRef(false);
  async function run<T>(path: string, body: unknown, revision?: number, method: 'POST' | 'PATCH' = 'POST'): Promise<T | undefined> {
    if (inFlight.current) return undefined;
    const identity = JSON.stringify([method, path, body, revision]);
    if (pending.current?.identity !== identity) pending.current = { identity, key: crypto.randomUUID() };
    inFlight.current = true; setBusy(true); setError(undefined); setReceipt(undefined);
    try {
      const data = await (method === 'PATCH' ? api.patch<T> : api.post<T>)(path, body, { expectedRevision: revision, idempotencyKey: pending.current.key });
      setReceipt(data); pending.current = undefined; return data;
    } catch (cause) { setError(cause instanceof Error ? cause : new Error(String(cause))); return undefined; }
    finally { inFlight.current = false; setBusy(false); }
  }
  return { busy, error, receipt, run, clearError: () => setError(undefined) };
}
/** Complete immutable picker inputs; api.collect refuses partial or drifting reads. */
export function useCompleteApi<T>(path: string | null) { return useSharedApi<T[]>(path, true); }
