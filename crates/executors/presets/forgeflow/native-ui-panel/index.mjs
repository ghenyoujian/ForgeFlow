/** Authenticated native DSH operation panel; development authority stays in ForgeFlow. */
import { readFileSync, statSync, lstatSync, writeFileSync, renameSync } from 'node:fs';
import { isAbsolute, dirname, join } from 'node:path';
import { createHash, randomUUID } from 'node:crypto';
import { fileURLToPath } from 'node:url';

export const name = 'forgeflow-native-operation-panel';
export const inject = ['connection', 'forgeflowNativeUiReadOnly', 'forgeflowNativeUiGuard'];
const ACTIONS = new Set(['PREPARE', 'START', 'PAUSE', 'REPLAN', 'RETRY', 'CANCEL']);
const SAFE_ID = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;
const TASK_ID = /^[A-Za-z0-9][A-Za-z0-9._-]{0,511}$/;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const SHA = /^[0-9a-f]{64}$/;
const digest = raw => createHash('sha256').update(raw).digest('hex');
const pick = (value, keys) => Object.fromEntries(keys.filter(key => value?.[key] !== undefined).map(key => [key, value[key]]));
const RESOURCE_KEYS = ['active_slot', 'coding_slot', 'cpu_units', 'memory_bytes', 'build_permit', 'gpu_permit', 'provider_inflight'];
function canonicalJson(value) {
  if (Array.isArray(value)) return '[' + value.map(canonicalJson).join(',') + ']';
  if (value && typeof value === 'object') {
    return '{' + Object.keys(value).filter(key => value[key] !== undefined)
      .sort((a, b) => Buffer.compare(Buffer.from(a), Buffer.from(b)))
      .map(key => JSON.stringify(key) + ':' + canonicalJson(value[key])).join(',') + '}';
  }
  if (typeof value === 'number' && (!Number.isFinite(value) || (Number.isInteger(value) && !Number.isSafeInteger(value)))) {
    throw Object.assign(new Error('Logical blueprint number is outside exact JSON range'), { code: 'BLUEPRINT_NUMBER_NOT_EXACT', status: 409 });
  }
  return JSON.stringify(value);
}
function logicalPath(path) {
  return typeof path === 'string' && path.length > 0 && path.length <= 4096 &&
    !isAbsolute(path) && !/^[A-Za-z]:/.test(path) && !path.includes('\\') && !path.includes('\0') &&
    !path.split('/').includes('..') && !/^[A-Za-z][A-Za-z0-9+.-]*:\/\//.test(path);
}
function requireLogicalPaths(paths) {
  if (!Array.isArray(paths) || paths.some(path => !logicalPath(path))) {
    throw Object.assign(new Error('Blueprint requires relative logical paths'), { code: 'BLUEPRINT_LOGICAL_PATHS_REQUIRED', status: 409 });
  }
  return paths;
}
function logicalSource(value) {
  if (typeof value === 'string') {
    // Negative cases may name a host-specific escape path. Keep the denial
    // scenario as a logical location, with original bytes bound by provenance.
    return value.replace(/(?:\/(?:home|mnt|tmp|run|root)\/|[A-Za-z]:[\\/])[^\s`"'<>()[\]{};,，。]*/g, '[OUTSIDE_PROJECT_ROOT]');
  }
  if (Array.isArray(value)) return value.map(logicalSource);
  if (!value || typeof value !== 'object') return value;
  return Object.fromEntries(Object.entries(value).filter(([key]) =>
    !/^(authorization|api_key|apiKey|password|token|credentials|environment|worktree|root_path|legacy|status|state|runtime_pid|pid|envelope|input_digest|producer_input_digest|producer_task_revision|lease_granted|lease_id|attempt_id|integration|evidence|freeze|frozen|qualification|qualified)$/i.test(key) &&
    !/^(runtime_|historical_|previous_|attempt_|lease_|integration_|evidence_|freeze_|frozen_)/i.test(key) &&
    !/(_status|_receipt_id|_evidence_id|_lease_id|_attempt_id|_sha256)$/.test(key))
    .map(([key, item]) => [key, logicalSource(item)]));
}
function logicalCard(row) {
  const task = row.task ?? {};
  const spec = row.spec ?? {};
  const source = row.metadata?.source_card;
  if (!source || typeof source !== 'object' || Array.isArray(source)) {
    throw Object.assign(new Error('Original logical source card is unavailable'), { code: 'BLUEPRINT_ORIGINAL_SOURCE_CARD_REQUIRED', status: 409 });
  }
  const originalHash = row.metadata?.source_card_sha256;
  if (typeof originalHash !== 'string' || !/^[0-9a-f]{64}$/.test(originalHash)) {
    throw Object.assign(new Error('Original card hash provenance is unavailable'), { code: 'BLUEPRINT_ORIGINAL_HASH_PROVENANCE_REQUIRED', status: 409 });
  }
  const sourceCard = logicalSource(source);
  const inputRefs = [ ...(spec.inputs ?? []).map(input => pick(input, ['path', 'producer_task_id'])),
    ...(spec.producer_inputs ?? []).map(input => pick(input, ['path', 'producer_task_id'])) ];
  requireLogicalPaths(task.read_set);
  requireLogicalPaths(task.write_set);
  requireLogicalPaths(spec.mandatory_paths);
  requireLogicalPaths(inputRefs.map(input => input.path));
  return { ...pick(task, ['task_id', 'title', 'owner_id', 'team_id', 'requirement_ids', 'read_set', 'write_set', 'dependencies']),
    role_id: row.metadata?.role_id, resource_request: pick(task.resource_request, RESOURCE_KEYS),
    spec: { ...pick(spec, ['outcome', 'mandatory_paths', 'rollback_plan', 'known_unknowns', 'not_proven']),
      design_anchors: (spec.design_anchors ?? []).filter(anchor => typeof anchor === 'string' && !/^forgeflow:/i.test(anchor)),
      input_refs: inputRefs, dependency_refs: (spec.dependency_refs ?? []).map(ref => pick(ref, ['task_id', 'kind'])),
      contract_produces: (spec.contract_produces ?? []).map(contract => contract.contract_id),
      contract_consumes: (spec.contract_consumes ?? []).map(contract => contract.contract_id) },
    execution_profile_ref: 'default', resource_profile_ref: 'default', model_route_ref: 'default',
    ...pick(row.metadata, ['parent_task']), phase: String(row.metadata?.phase ?? source.phase ?? ''), source_card: sourceCard,
    source_card_sha256: digest(canonicalJson(sourceCard)),
    source_original_card_sha256: originalHash };
}
function cardSummary(row) {
  const blockers = row.admission_blockers ?? row.metadata?.admission_blockers ?? [];
  const paths = row.unbound_input_paths ?? [];
  const counts = {};
  for (const blocker of blockers) {
    const code = typeof blocker === 'string' ? blocker.split(':', 1)[0] : blocker.code ?? 'UNCLASSIFIED';
    counts[code] = (counts[code] ?? 0) + 1;
  }
  return { ...pick(row, ['task_id', 'revision']),
    admission_blockers: blockers.slice(0, 4), admission_blocker_count: blockers.length,
    admission_blocker_counts: counts, unbound_input_paths: paths.slice(0, 4), unbound_input_path_count: paths.length,
    admission_blocker_source: 'INITIAL_REGISTERED_PLANNING_SNAPSHOT',
    task: { ...pick(row.task, ['project_id', 'task_id', 'title', 'owner_id', 'team_id', 'state', 'revision',
      'flow_revision', 'task_revision', 'input_digest', 'dependencies', 'requirement_ids']),
      write_set: (row.task?.write_set ?? []).slice(0, 4), write_set_count: row.task?.write_set?.length ?? 0,
      read_set_count: row.task?.read_set?.length ?? 0 },
    metadata: pick(row.metadata, ['card_id', 'parent_task', 'role_id', 'phase', 'source_card_sha256',
      'source_requirement_ids', 'dependency_binding_state', 'deadline_days', 'deadline_scope',
      'resource_demand_status', 'verification_binding']),
    list_projection: 'SUMMARY_EXACT_DAG_REQUIREMENTS_IDENTITIES_FULL_DETAILS_ON_SELECTION',
    spec: pick(row.spec, ['task_id', 'priority', 'weight', 'execution_profile', 'verification_plan',
      'verification_case_count', 'requirement_ids', 'acceptance_profile']) };
}
function profileSummary(row) {
  const headless = row.headless_profile;
  const patch = row.native_mode?.preset_patch;
  const rolePath = typeof patch === 'string' && isAbsolute(patch) ? join(dirname(patch), 'agent-roles.json') : null;
  const rolePin = rolePath ? (row.artifact_pins ?? []).find(pin => pin.path === rolePath) : null;
  return { ...pick(row, ['id', 'name', 'kind', 'revision', 'capabilities', 'qualified', 'qualification',
    'qualification_status', 'qualification_metadata', 'approved_effects', 'command_effects', 'native_mode', 'plugin_audit',
    'program', 'prefix_args', 'profile_name', 'model_route_id', 'resume_verified', 'gateway_coverage_verified']),
    pin_count: Array.isArray(row.artifact_pins) ? row.artifact_pins.length : 0,
    pins_sha256: digest(JSON.stringify(row.artifact_pins ?? [])),
    role_catalog_pin: rolePin ? pick(rolePin, ['path', 'sha256']) : null,
    ...(headless ? { headless_profile: { ...pick(headless, ['id', 'program', 'prefix_args', 'model_route_id', 'profile_name',
      'doctor_sha256', 'doctor_receipt_id', 'qualified', 'qualification', 'capabilities']),
      pin_count: Array.isArray(headless.pins) ? headless.pins.length : Object.keys(headless.pins ?? {}).length,
      pins_sha256: digest(JSON.stringify(headless.pins ?? [])) } } : {}) };
}
function catalogSummary(row) {
  return { ...pick(row, ['catalog_id', 'id', 'project_id', 'revision', 'card_count', 'manifest_sha256',
    'alignment_sha256', 'content_sha256', 'source_manifest_sha256', 'source', 'deadline_days', 'created_at',
    'cards_sha256', 'edge_count', 'role_count', 'parent_count', 'covered_requirement_count', 'requirement_count',
    'execution_ready_cards', 'planning_only', 'source_revision', 'observed_at', 'blocker_counts', 'uncovered_requirement_ids']),
    metadata: pick(row.metadata, ['card_count', 'dag_edge_count', 'planned_agent_positions', 'delivery_days',
      'minimum_concurrent_agents', 'deadline_days', 'deadline_scope', 'plan_sha256', 'historical_done_cards']) };
}

function privateBytes(path) {
  if (!isAbsolute(path ?? '') || lstatSync(path).isSymbolicLink() ||
      !statSync(path).isFile() || (statSync(path).mode & 0o077)) throw new Error('Private native panel configuration is unavailable');
  return readFileSync(path);
}
function jsonResponse(value, status = 200) {
  return new Response(JSON.stringify(value), { status, headers: { 'content-type': 'application/json', 'cache-control': 'no-store' } });
}
function safe(value) {
  if (Array.isArray(value)) return value.map(safe);
  if (!value || typeof value !== 'object') return value;
  return Object.fromEntries(Object.entries(value).filter(([key]) =>
    !/^(authorization|api_key|apiKey|owner_password|owner_token|panel_secret|password|token|credentials|environment)$/i.test(key)).map(([key, item]) => [key, safe(item)]));
}

export function apply(ctx, config) {
  if (config?.schema_version !== 'forgeflow.native-ui-panel.v1') throw new Error('Native operation panel configuration is absent');
  const host = JSON.parse(privateBytes(config.private_config_path));
  if (host.schema_version !== 'forgeflow.native-ui-host.v1' || !Array.isArray(host.projects) ||
      !Number.isInteger(host.refresh_interval_ms) || host.refresh_interval_ms < 1000 || host.refresh_interval_ms > 60000) {
    throw new Error('Native operation panel host configuration is invalid');
  }
  const blueprintTimeouts = { preview: host.blueprint_preview_timeout_ms ?? 600000,
    import: host.blueprint_import_timeout_ms ?? 600000 };
  if (Object.values(blueprintTimeouts).some(value => !Number.isSafeInteger(value) || value < 45000 || value > 900000)) {
    throw new Error('Native blueprint response deadlines must be between 45 seconds and 15 minutes');
  }
  const origin = new URL(host.control_api_url);
  if (origin.protocol !== 'http:' || !['127.0.0.1', 'localhost', '[::1]'].includes(origin.hostname) ||
      origin.username || origin.password || origin.search || origin.hash || origin.pathname.replace(/\/$/, '') !== '/api/v1') {
    throw new Error('Native operation panel requires the exact private loopback control API');
  }
  const ownerRecord = JSON.parse(privateBytes(host.owner_runtime_env_path));
  const owner = ownerRecord[host.owner_token_key ?? 'FORGEFLOW_SERVICE_TOKEN'];
  const panel = privateBytes(host.panel_secret_file).toString().trim();
  if (typeof owner !== 'string' || owner.length < 16 || panel.length < 24 || panel.length > 4096 ||
      !/^[\x21-\x7e]+$/.test(panel)) throw new Error('Native operation panel credentials are unavailable');
  const projects = new Map();
  for (const item of host.projects) {
    if (!SAFE_ID.test(item.project_id ?? '') || projects.has(item.project_id) || !isAbsolute(item.delivery_config_path ?? '')) {
      throw new Error('Native operation panel project map is invalid');
    }
    projects.set(item.project_id, Object.freeze({ ...item }));
  }
  const lifetime = new AbortController();
  ctx.effect(() => () => lifetime.abort(), 'forgeflow-native-panel: lifetime');
  const catalogCache = new Map();
  const observationCache = new Map();
  const profileCache = new Map();
  const nativeReadPending = new Map();
  async function nativeRegistryRead(name, operation) {
    let pending = nativeReadPending.get(name);
    if (!pending) {
      pending = Promise.resolve().then(operation).finally(() => nativeReadPending.delete(name));
      nativeReadPending.set(name, pending);
    }
    let timer;
    try {
      return await Promise.race([pending, new Promise((_, reject) => {
        timer = setTimeout(() => reject(Object.assign(new Error('Native registry read exceeded its deadline'),
          { code: 'NATIVE_REGISTRY_READ_TIMEOUT', status: 504 })), 10000);
      })]);
    } finally { clearTimeout(timer); }
  }
  ctx.inject(['webServer', 'appReady'], ready => {
    ready.effect(() => ready.appReady.onReady(() => {
      const path = host.authenticated_url_path ?? join(dirname(config.private_config_path), 'native-ui-bootstrap.json');
      if (!isAbsolute(path) || statSync(dirname(path)).mode & 0o077) throw new Error('Native UI bootstrap directory must be private');
      const temporary = path + '.tmp-' + randomUUID();
      const port = ready.webServer.port;
      const url = ready.connection.authenticatedUrl(`http://127.0.0.1:${port}/`);
      writeFileSync(temporary, JSON.stringify({ schema_version: 'forgeflow.native-ui-bootstrap.v1',
        url, port, created_at: new Date().toISOString(), source: 'ACTUAL_NATIVE_CONNECTION_AUTHENTICATED_URL' }) + '\n',
        { flag: 'wx', mode: 0o600 });
      renameSync(temporary, path);
      // The tokenized URL remains in the private file, never the public panel.
      process.stderr.write('FORGEFLOW_NATIVE_PANEL_READY ' + JSON.stringify({ bootstrap_path: path, port }) + '\n');
    }), 'forgeflow-native-panel: private native authentication handoff');
  });

  function boundedPublicText(value, limit = 512) {
    if (typeof value !== 'string') return undefined;
    let text = value.replace(/[\u0000-\u001f\u007f]/g, ' ');
    for (const secret of [owner, panel]) text = text.split(secret).join('[PRIVATE_SECRET]');
    return text.replace(/\bBearer\s+\S+/gi, '[PRIVATE_SECRET]')
      .replace(/\bsk[-_][A-Za-z0-9_-]{16,}/g, '[PRIVATE_SECRET]')
      .replace(/\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/g, '[PRIVATE_SECRET]')
      .replace(/https?:\/\/[^\s`"'<>()[\]{};,，。]*/gi, '[SERVICE_LOCATION]')
      .replace(/file:\/\/[^\s`"'<>()[\]{};,，。]*/gi, '[PRIVATE_LOCATION]')
      .replace(/(?:\/(?:home|mnt|tmp|run|root|etc)\/|[A-Za-z]:[\\/])[^\s`"'<>()[\]{};,，。]*/g, '[PRIVATE_LOCATION]')
      .replace(/(?<![\p{L}\p{N}_])\/[^\s`"'<>()[\]{};,，。]*/gu, '[PRIVATE_LOCATION]')
      .trim().slice(0, limit);
  }
  function coreFailure(value, status) {
    const source = value?.error && typeof value.error === 'object' ? value.error : value;
    const code = typeof source?.code === 'string' && /^[A-Z][A-Z0-9_]{0,95}$/.test(source.code) ? source.code : 'CONTROL_REJECTED';
    const failure = { code };
    if (code.startsWith('BLUEPRINT_') && status >= 400 && status < 500) {
      const message = boundedPublicText(source?.message);
      if (message) failure.message = message;
      const raw = source?.details;
      const details = {};
      if (typeof raw?.field === 'string' && /^(blueprint|mapping|expected_authority)(\.[A-Za-z0-9_]+)*$/.test(raw.field)) {
        details.field = raw.field.slice(0, 128);
      }
      const subject = boundedPublicText(raw?.subject, 512);
      if (subject) details.subject = subject;
      if (typeof raw?.reason === 'string' && /^[A-Z][A-Z0-9_]{0,95}$/.test(raw.reason)) details.reason = raw.reason;
      if (Object.keys(details).length) failure.details = details;
    }
    return failure;
  }
  function blueprintFailure(error, kind, fallback) {
    const requestId = UUID.test(error.request_id ?? '') ? error.request_id : undefined;
    if (error.transport_failure) {
      const timeout = error.code === 'CONTROL_RESPONSE_TIMEOUT';
      return { code: kind + (timeout ? '_TIMEOUT' : '_TRANSPORT_UNAVAILABLE'),
        message: timeout ? 'The full blueprint response exceeded its deadline. The canonical result is not yet confirmed; retry the unchanged request with the same request ID.' :
          'The canonical blueprint response was interrupted. Confirm the result or retry the unchanged request with the same request ID.',
        outcome: 'UNKNOWN_COMMIT_OR_PENDING', retry_same_request_id: true,
        ...(requestId ? { request_id: requestId } : {}) };
    }
    return { ...(error.public_failure ?? {}),
      code: typeof error.public_failure?.code === 'string' ? error.public_failure.code :
        typeof error.code === 'string' ? error.code : kind + '_UNAVAILABLE',
      message: error.public_failure?.message ?? fallback,
      ...(requestId ? { request_id: requestId } : {}) };
  }
  async function api(path, method = 'GET', body, requestId, signal, timeoutMs = 45000) {
    const headers = { authorization: `Bearer ${owner}`, 'X-ForgeFlow-Native-Panel-Key': panel };
    if (body !== undefined) headers['content-type'] = 'application/json';
    if (requestId) headers['Idempotency-Key'] = requestId;
    const deadline = AbortSignal.timeout(timeoutMs);
    let response;
    let raw;
    try {
      response = await fetch(origin.href.replace(/\/$/, '') + path, { method, headers,
        body: body === undefined ? undefined : JSON.stringify(body), redirect: 'error',
        signal: AbortSignal.any([lifetime.signal, ...(signal ? [signal] : []), deadline]) });
      raw = await response.text();
    } catch {
      throw Object.assign(new Error('Canonical response could not be confirmed'), {
        status: deadline.aborted ? 504 : 503,
        code: deadline.aborted ? 'CONTROL_RESPONSE_TIMEOUT' : 'CONTROL_TRANSPORT_UNAVAILABLE',
        transport_failure: true, request_id: requestId });
    }
    if (Buffer.byteLength(raw) > 16 * 1024 * 1024) throw Object.assign(new Error('Control API response exceeds the panel read limit'), {
      status: 502, code: 'CONTROL_RESPONSE_TOO_LARGE', transport_failure: true, request_id: requestId });
    let value;
    try { value = JSON.parse(raw); } catch { throw Object.assign(new Error('Control API returned an invalid response'), {
      status: 502, code: 'CONTROL_RESPONSE_INVALID', transport_failure: true, request_id: requestId }); }
    if (!response.ok) {
      const failure = coreFailure(value, response.status);
      throw Object.assign(new Error('Control API rejected the operation'), { status: response.status,
        code: failure.code, public_failure: failure, request_id: requestId });
    }
    return value;
  }
  const data = value => value?.data ?? value;
  async function all(path, signal) {
    const result = [];
    let cursor;
    for (let page = 0; page < 100; page++) {
      const value = await api(path + `?limit=500${cursor ? '&cursor=' + encodeURIComponent(cursor) : ''}`, 'GET', undefined, undefined, signal);
      const rows = data(value);
      if (Array.isArray(rows)) result.push(...rows);
      else if (Array.isArray(rows?.items)) result.push(...rows.items);
      else if (Array.isArray(value?.items)) result.push(...value.items);
      else throw new Error('Control API list response is invalid');
      cursor = value.next_cursor ?? rows?.next_cursor;
      if (!cursor) return result;
    }
    throw new Error('Control API list exceeded its bounded pagination');
  }
  async function blueprintSource(projectId, catalogId, signal) {
    const path = '/projects/' + encodeURIComponent(projectId) + '/native-panel/blueprint-source';
    let source;
    let identity;
    let cursor;
    const cards = [];
    const ids = new Set();
    for (let page = 0; page < 100; page++) {
      const value = await api(path + '?limit=100&catalog_id=' + encodeURIComponent(catalogId) +
        (cursor ? '&cursor=' + encodeURIComponent(cursor) : ''), 'GET', undefined, undefined, signal);
      const current = data(value);
      if (!current || !current.catalog || !Array.isArray(current.cards) ||
          !Array.isArray(current.requirements) || !Array.isArray(current.teams) || !Array.isArray(current.owner_territories)) {
        throw Object.assign(new Error('Canonical blueprint source is unavailable'), { code: 'BLUEPRINT_SOURCE_INVALID', status: 502 });
      }
      const currentIdentity = canonicalJson(pick(current.catalog, ['catalog_id', 'revision', 'cards_sha256', 'source_revision']));
      if (identity !== undefined && identity !== currentIdentity) {
        throw Object.assign(new Error('Blueprint source changed during pagination'), { code: 'BLUEPRINT_SOURCE_REVISION_CHANGED', status: 409 });
      }
      identity = currentIdentity;
      source ??= current;
      for (const card of current.cards) {
        const id = card.task?.task_id;
        if (typeof id !== 'string' || ids.has(id)) {
          throw Object.assign(new Error('Blueprint source task pagination is invalid'), { code: 'BLUEPRINT_SOURCE_TASK_IDENTITIES_INVALID', status: 409 });
        }
        ids.add(id);
        cards.push(card);
      }
      cursor = value.next_cursor ?? current.next_cursor;
      if (!cursor) return { ...source, cards };
    }
    throw Object.assign(new Error('Blueprint source exceeds bounded pagination'), { code: 'BLUEPRINT_SOURCE_TOO_LARGE', status: 413 });
  }
  function selected(url) {
    const id = url.searchParams.get('project_id') ?? host.default_project_id ?? projects.keys().next().value;
    if (id && !projects.has(id)) throw Object.assign(new Error('Project is outside the reviewed native panel map'), { status: 404 });
    return id;
  }
  async function readState(url, signal) {
    const projectId = selected(url);
    const view = url.searchParams.get('view') ?? 'overview';
    const readCatalogCards = ['catalog', 'dag', 'agents', 'presets', 'reuse'].includes(view);
    const errors = [];
    const capture = async (label, operation, fallback) => {
      try { return await operation(); }
      catch (error) { errors.push({ source: label, code: error.code ?? 'READ_UNAVAILABLE', status: error.status ?? null }); return fallback; }
    };
    const projectRows = await capture('projects', () => all('/projects', signal), []);
    const state = { schema_version: 'forgeflow.native-panel-state.v1', refresh_interval_ms: host.refresh_interval_ms,
      projects: projectRows.filter(row => projects.has(row.project_id)), selected_project_id: projectId ?? null,
      project: null, snapshot: null, planning_cards: [], selected_card: null, catalog: null, roster: { roles: [] },
      flow: null, delivery: null, scheduling: null, executor_profiles: [], observations: [], action_receipts: [], errors,
      agent_presets: null, native_plugin_inventory: null,
      capabilities: { entry_source: 'DSH_NATIVE_PANEL', development_entry: 'CANONICAL_TYPED_PANEL_ACTIONS',
        model: null, model_route: null, model_calls_in_ui_host: false,
        native_stock_authoring: false, native_stock_authoring_reason: 'ActualReadOnlyUnsupported: use the ForgeFlow operation panel',
        readonly_native_persistence: true, actual_concurrency_source: 'CANONICAL_NATIVE_SESSION_FACTS_ONLY',
        actions: [...ACTIONS], native_plugins: ['presets', 'workflow', 'skills', 'plugins', 'teams'] } };
    if (view === 'presets') state.agent_presets = await capture('agent_presets', () => nativeRegistryRead('agent_presets', async () => {
      const registry = ctx.get('agentPresets');
      if (!registry) throw new Error('Native preset registry is unavailable');
      return await registry.list();
    }), []);
    if (view === 'presets') state.native_plugin_inventory = await capture('native_plugin_inventory', () => nativeRegistryRead('native_plugin_inventory', async () => {
      const inventory = ctx.get('pluginInventory');
      if (!inventory) throw new Error('Native plugin inventory is unavailable');
      return await inventory.list();
    }), null);
    if (!projectId) return state;
    const p = '/projects/' + encodeURIComponent(projectId);
    const entry = projects.get(projectId);
    let retainedCandidatePolicy;
    const reviewedConfiguration = async () => {
      const raw = privateBytes(entry.delivery_config_path);
      const file = JSON.parse(raw);
      let verificationRecovery = null;
      let retainedCandidateReview = null;
      const reuse = file.candidate_reuse_policy;
      if (reuse) {
        retainedCandidateReview = { ...pick(reuse, ['enabled', 'mode', 'source_attempt_id', 'target_task_id',
          'review_task_id', 'expected_cases', 'max_once', 'model_calls', 'old_attempt_preserved',
          'verification_plan_id', 'verification_plan_sha256']), execution_rights_granted: false };
        if (reuse.enabled === true) {
          const unavailable = () => Object.assign(new Error('Reviewed retained candidate provenance is unavailable'), {
            code: 'RETAINED_CANDIDATE_PROVENANCE_UNAVAILABLE' });
          if (reuse.mode !== 'RETAINED_NATIVE_CANDIDATE_REVIEW' || reuse.max_once !== 1 ||
              reuse.model_calls !== 0 || reuse.expected_cases !== 8 || reuse.old_attempt_preserved !== true ||
              !SHA.test(reuse.source_provenance?.sha256 ?? '') || !SHA.test(reuse.verification_plan_sha256 ?? '')) throw unavailable();
          const proofRaw = privateBytes(reuse.source_provenance.path);
          if (digest(proofRaw) !== reuse.source_provenance.sha256) throw unavailable();
          const source = JSON.parse(proofRaw);
          if (source.schema_version !== 'forgeflow.retained-native-candidate-source.v1' ||
              source.project_id !== projectId || source.attempt_id !== reuse.source_attempt_id ||
              source.task_id !== reuse.target_task_id || !source.candidate ||
              !/^[0-9a-f]{40}(?:[0-9a-f]{24})?$/.test(source.candidate.candidate_sha ?? '')) throw unavailable();
          Object.assign(retainedCandidateReview, { candidate_sha: source.candidate.candidate_sha,
            source_provenance_sha256: reuse.source_provenance.sha256,
            source_task_id: source.task_id, source_generation: source.generation,
            source_task_revision: source.task_revision, source_role_id: source.native_root_binding?.position_id,
            base_sha: source.candidate.base_sha });
          // Policy review is not authorization or inherited source completion.
          retainedCandidatePolicy = reuse;
        }
      }
      const recovery = file.verification_recovery_policy;
      if (recovery) {
        verificationRecovery = { ...pick(recovery, ['enabled', 'attempt_id', 'generation', 'task_revision',
          'prior_operation_id', 'original_plan_sha256', 'repair_id', 'repair_revision', 'repair_sha256',
          'expected_case_count', 'max_once', 'repair_kind']), execution_rights_granted: false };
        if (recovery.enabled === true) {
          const unavailable = () => Object.assign(new Error('Reviewed verification recovery assets are unavailable'), {
            code: 'VERIFICATION_RECOVERY_ASSET_BINDING_UNAVAILABLE' });
          if (recovery.max_once !== 1 || !SHA.test(recovery.runtime_manifest_sha256 ?? '') ||
              !SHA.test(recovery.preflight_proof?.sha256 ?? '')) throw unavailable();
          const runtimeRaw = privateBytes(recovery.runtime_manifest_path);
          const preflightRaw = privateBytes(recovery.preflight_proof.path);
          if (digest(runtimeRaw) !== recovery.runtime_manifest_sha256 ||
              digest(preflightRaw) !== recovery.preflight_proof.sha256) throw unavailable();
          const runtime = JSON.parse(runtimeRaw);
          if (runtime.schema_version !== 'forgeflow.verifier-python-runtime.v1' || !Array.isArray(runtime.files) ||
              !SHA.test(runtime.interpreter?.sha256 ?? '') || !Number.isSafeInteger(runtime.file_count) ||
              runtime.file_count !== runtime.files.length || runtime.files.some(member =>
                !Number.isSafeInteger(member.bytes) || member.bytes < 0 || member.bytes > 8 * 1024 * 1024) ||
              !Number.isSafeInteger(runtime.total_bytes) || runtime.total_bytes > 128 * 1024 * 1024 ||
              runtime.total_bytes !== runtime.files.reduce((sum, member) => sum + member.bytes, 0)) throw unavailable();
          verificationRecovery.runtime = { manifest_sha256: recovery.runtime_manifest_sha256,
            file_count: runtime.file_count, total_bytes: runtime.total_bytes,
            interpreter_sha256: runtime.interpreter.sha256 };
        }
      }
      const resources = (file.resource_policy_updates ?? []).map(update =>
        pick(update.policy, ['scope_id', 'project_id', 'team_id', 'limits', 'paused']));
      let modelConfiguration = { id: file.expected_provider_model_id ?? null,
        model_route_id: file.model_route_id ?? null, user_model: file.user_model ?? null,
        reasoning_effort: null, max_output_tokens: null, source: 'APPROVED_DELIVERY_CONFIG',
        upstream_honors_requested_policy: 'REQUIRES_ACTUAL_MATCHING_REQUEST_EVIDENCE' };
      try {
        const policyBytes = readFileSync(join(dirname(fileURLToPath(import.meta.url)), '..', 'provider-policy.json'));
        const policy = JSON.parse(policyBytes);
        if (policy.model === file.expected_provider_model_id) modelConfiguration = { ...modelConfiguration,
          reasoning_effort: policy.effort ?? null, max_output_tokens: policy.max_output_tokens ?? null,
          provider_policy_id: policy.id, provider_policy_sha256: digest(policyBytes),
          source: 'APPROVED_CONFIG_AND_FROZEN_PROVIDER_POLICY' };
      } catch { /* Missing policy defaults remain unknown; no values are invented. */ }
      return { schema_version: 'forgeflow.native-project-configuration.v1',
        source: { project_id: projectId, config_sha256: digest(raw), alignment_sha256: file.alignment_sha256 },
        target: { ...pick(file.acceptance, ['cards', 'positions', 'days', 'minimum_real_concurrent_agents', 'all_required_terminal']),
          deadline_at: file.deadline_at ?? null },
        model_policy: { user_model: file.user_model ?? null, model_route_id: file.model_route_id ?? null,
          provider_model_id: file.expected_provider_model_id ?? null, request_budget_per_task: file.model_budget_per_task ?? null,
          model_fallback: false, edit_authority: 'FUTURE_REVIEWED_FROZEN_PROFILE_REQUIRED' },
        model_configuration: modelConfiguration,
        execution_policy: { ...pick(file, ['desired_active_agents', 'max_active_agents', 'prepare_batch_size', 'lease_seconds']),
          concurrency_mode: file.max_active_agents === 0 ? 'DYNAMIC_RESOURCE_ADMISSION' : 'CONFIGURED_FINITE_GUARD',
          effective_capacity_source: 'CANONICAL_RESOURCE_LIMITS_AND_ACTUAL_ALLOCATIONS' },
        resources, role_allocations: { planned_positions: null, teams: [] },
        verification_recovery: verificationRecovery,
        retained_candidate_review: retainedCandidateReview,
        edit_capabilities: { reviewed_delivery_draft_save: true, reviewed_delivery_apply: true,
          quota_changes: 'EXISTING_TYPED_RESOURCE_POLICY_CAS_NOT_EXPOSED_HERE',
          reason: 'Native configuration drafts publish new immutable executor versions; current attempts keep their admitted profile' },
        blueprint_export: { available: true, endpoint: '/api/forgeflow-panel/blueprint', execution_rights_granted: false } };
    };
    const readProfiles = async () => {
      const delivery = JSON.parse(privateBytes(entry.delivery_config_path));
      const ids = [...new Set(delivery.executor_profile_ids ??
        (delivery.executor_profile_id ? [delivery.executor_profile_id] : []))];
      if (!ids.length) {
        // Generic projects without an approved ID map can still inspect a
        // bounded page; a 500-profile full-pin list is never requested.
        const value = data(await api(p + '/documents/executor_profiles?limit=2', 'GET', undefined, undefined, signal));
        return (Array.isArray(value) ? value : value?.items ?? []).map(profileSummary);
      }
      const result = [];
      for (const id of ids) {
        if (!SAFE_ID.test(id)) throw new Error('Approved executor profile ID is invalid');
        const key = projectId + ':' + id;
        let cached = profileCache.get(key);
        if (!cached || Date.now() - cached.time > (host.profile_cache_ms ?? 60000)) {
          const value = data(await api(p + '/documents/executor_profiles/' + encodeURIComponent(id),
            'GET', undefined, undefined, signal));
          cached = { time: Date.now(), value: profileSummary(value) };
          profileCache.set(key, cached);
        }
        result.push(cached.value);
      }
      return result;
    };
    const readDelivery = async () => {
      const file = JSON.parse(privateBytes(entry.delivery_config_path));
      const value = { schema_version: file.schema_version, project_id: file.project_id,
        model_route: file.model_route_id ?? file.model_route ?? file.native_model_route,
        model: file.user_model ?? file.model ?? file.native_model,
        expected_provider_model_id: file.expected_provider_model_id,
        desired_active_agents: file.desired_active_agents, max_active_agents: file.max_active_agents,
        deadline: file.deadline ?? file.deadline_at, acceptance: file.acceptance, concurrency: file.concurrency };
      if (entry.delivery_status_path) await capture('delivery_status', async () => {
        Object.assign(value, safe(JSON.parse(privateBytes(entry.delivery_status_path))));
      }, undefined);
      // The reviewed configuration owns the future execution default. Historical
      // status observations must not replace its current preset/roster identity.
      value.executor_profile_id = file.executor_profile_id ?? null;
      return value;
    };
    const responses = await Promise.all([
      capture('snapshot', async () => data(await api(p + '/snapshot', 'GET', undefined, undefined, signal)), null),
      capture('planning_catalogs', () => all(p + '/documents/planning_catalogs', signal), []),
      capture('executor_profiles', readProfiles, []),
      capture('native_panel_actions', () => all(p + '/native-panel/actions', signal), []),
      capture('delivery', readDelivery, null),
      capture('configuration', reviewedConfiguration, null),
      capture('scheduling', async () => data(await api(p + '/native-panel/scheduling', 'GET', undefined, undefined, signal)), null),
    ]);
    [state.snapshot, state.catalog, state.executor_profiles, state.action_receipts, state.delivery, state.configuration, state.scheduling] = responses;
    state.model_configuration = state.configuration?.model_configuration ?? null;
    state.execution_policy = state.configuration?.execution_policy ?? null;
    state.capabilities.model = state.delivery?.model ?? null;
    state.capabilities.model_route = state.delivery?.model_route ?? null;
    if (retainedCandidatePolicy && state.configuration?.retained_candidate_review) {
      const review = state.configuration.retained_candidate_review;
      const id = retainedCandidatePolicy.review_task_id;
      if (TASK_ID.test(id ?? '')) {
        try {
          const task = data(await api(p + '/tasks/' + encodeURIComponent(id), 'GET', undefined, undefined, signal));
          if (task.task_id === id && task.task_revision === retainedCandidatePolicy.expected_review_task_revision) {
            if (task.resource_request) review.resource_request = pick(task.resource_request, RESOURCE_KEYS);
            if (Array.isArray(task.write_set) && (!task.envelope || Array.isArray(task.envelope.write_set))) {
              review.read_only = task.write_set.length === 0 && (!task.envelope || task.envelope.write_set.length === 0);
            }
            if (task.envelope) {
              if (Number.isSafeInteger(task.envelope.max_model_requests)) {
                review.model_budget = { max_model_requests: task.envelope.max_model_requests };
              }
              if (typeof task.envelope.deadline_at === 'string') review.deadline_at = task.envelope.deadline_at;
            }
          }
        } catch (error) {
          // A not-yet-prepared task has unknown runtime facts. A partial or
          // absent attempt list cannot prove that a review has not started.
          if (error.status !== 404) errors.push({ source: 'retained_review_task', code: error.code ?? 'READ_UNAVAILABLE', status: error.status ?? null });
        }
      }
      const attempts = (Array.isArray(state.snapshot?.attempts) ? state.snapshot.attempts : [])
        .filter(attempt => attempt.task_id === id && attempt.task_revision === retainedCandidatePolicy.expected_review_task_revision);
      if (attempts.length === 1) {
        review.review_attempt_id = attempts[0].attempt_id;
        review.review_attempt_state = attempts[0].state;
      }
    }
    state.project = state.snapshot?.project ?? projectRows.find(row => row.project_id === projectId) ?? null;
    const sourceCatalog = state.catalog.at(-1) ?? null;
    state.catalog = sourceCatalog ? catalogSummary(sourceCatalog) : null;
    state.catalog_task_ids = Array.isArray(sourceCatalog?.task_ids) ? sourceCatalog.task_ids : [];
    state.retained_native_candidate_acceptances = await capture('native_candidate_acceptances', async () =>
      data(await api(p + '/native-panel/candidate-acceptances', 'GET', undefined, undefined, signal)), []);
    // Lifecycle rows contain allocation facts, not Workflow/Team event traces.
    // Render only actual bounded observation events returned by the control API.
    if (view === 'workflow' || view === 'agents') state.observations = await capture('native_observations', async () => {
      const previous = observationCache.get(projectId) ?? { cursor: 0, rows: [] };
      let cursor = previous.cursor;
      const rows = [...previous.rows];
      for (let page = 0; page < 20; page++) {
        const response = await api(p + '/native-panel/observations?limit=500&cursor=' + cursor, 'GET', undefined, undefined, signal);
        const value = data(response);
        rows.push(...(Array.isArray(value) ? value : value?.items ?? []));
        const after = response.cursor_after ?? value?.cursor_after;
        if (!Number.isSafeInteger(after) || after < cursor) throw new Error('Native observation cursor is invalid');
        cursor = after;
        if (!response.next_cursor) break;
      }
      const bound = rows.slice(-(host.observation_rows_limit ?? 10000));
      observationCache.set(projectId, { cursor, rows: bound });
      state.observation_cursor = cursor;
      state.observation_history_scope = 'Bounded actual PG events; complete original evidence remains in the control service';
      return bound;
    }, []);
    const defaultProfileId = state.delivery?.executor_profile_id;
    if (defaultProfileId || entry.role_catalog_path) await capture('role_catalog', async () => {
      const profile = defaultProfileId ? state.executor_profiles.find(row => row.id === defaultProfileId) : null;
      const pin = profile?.role_catalog_pin;
      if (defaultProfileId && (!pin || !isAbsolute(pin.path ?? '') || !SHA.test(pin.sha256 ?? ''))) {
        throw Object.assign(new Error('Current execution version has no verified role catalog'), { code: 'ROLE_CATALOG_PIN_UNAVAILABLE' });
      }
      const rolePath = pin?.path ?? entry.role_catalog_path;
      if (lstatSync(rolePath).isSymbolicLink() || !statSync(rolePath).isFile()) {
        throw Object.assign(new Error('Current role catalog is unavailable'), { code: 'ROLE_CATALOG_UNAVAILABLE' });
      }
      const raw = readFileSync(rolePath);
      if (pin && digest(raw) !== pin.sha256) {
        throw Object.assign(new Error('Current execution role catalog identity changed'), { code: 'ROLE_CATALOG_PIN_CHANGED' });
      }
      const value = JSON.parse(raw);
      state.roster = { roles: (value.roster ?? []).map(row => ({ ...row,
        agent_id: row.agent_id ?? row.position_id, role_id: row.role_id ?? row.position_id,
        position: row.position ?? row.specialty, team_id: row.team_id ?? row.owner_team_id,
        parent_agent_id: row.parent_agent_id ?? row.organizational_parent_position_id })),
        teams: value.teams ?? [], planned_positions: value.positions,
        source: defaultProfileId ? 'CURRENT_REVIEWED_EXECUTOR_PROFILE' : 'CONFIGURED_HOST_ROLE_CATALOG',
        executor_profile_id: defaultProfileId ?? null, sha256: digest(raw) };
      if (state.configuration) {
        const groups = new Map();
        for (const role of state.roster.roles) {
          const key = role.owner_team_id ?? role.team_id;
          const group = groups.get(key) ?? { owner_team_id: key, owner_id: role.owner_id, position_count: 0, position_ids: [] };
          group.position_count++;
          group.position_ids.push(role.position_id ?? role.agent_id);
          groups.set(key, group);
        }
        state.configuration.role_allocations = { planned_positions: state.roster.roles.length, teams: [...groups.values()] };
      }
    }, undefined);
    state.flow = await capture('flow', async () => data(await api(p + '/flows/latest', 'GET', undefined, undefined, signal)), null);
    state.catalog_revision = state.catalog ? `${state.catalog.catalog_id ?? state.catalog.id}:${state.catalog.revision}:${state.catalog.cards_sha256 ?? ''}` : null;
    let cache = catalogCache.get(projectId);
    if (readCatalogCards && (!cache || cache.catalog_revision !== state.catalog_revision ||
        Date.now() - cache.time > (host.catalog_cache_ms ?? 60000))) {
      const cards = await capture('planning_cards', () => all(p + '/documents/planning_cards', signal), null);
      if (cards !== null) {
        cache = { time: Date.now(), catalog_revision: state.catalog_revision,
          cards: cards.map(cardSummary) };
        catalogCache.set(projectId, cache);
      } else if (cache?.catalog_revision !== state.catalog_revision) {
        cache = null;
      }
      // A failed refresh must never publish [] with a fresh TTL. Preserve the
      // last complete snapshot and keep its expired timestamp for the next retry.
    }
    state.catalog_unchanged = Boolean(cache) && cache.catalog_revision === state.catalog_revision && state.catalog_revision !== null &&
      url.searchParams.get('catalog_revision') === state.catalog_revision;
    state.catalog_snapshot_source = 'INITIAL_REGISTERED_PLANNING_AND_SEPARATE_CURRENT_CANONICAL_TASK_FACTS';
    state.canonical_task_bindings = (state.snapshot?.tasks ?? []).map(task => ({
      ...pick(task, ['task_id', 'task_revision', 'flow_revision', 'revision', 'state', 'input_digest']),
      frozen_execution_envelope_present: task.envelope !== null && task.envelope !== undefined,
      envelope_identity: pick(task.envelope, ['executor_profile_id', 'resource_profile_id', 'model_route_id', 'input_digest']),
      source: 'CURRENT_POSTGRESQL_TASK_AUTHORITY', planning_blockers_are_historical: true }));
    if (state.catalog_unchanged) delete state.planning_cards;
    else state.planning_cards = cache?.cards ?? [];
    state.catalog_cards_loaded = Boolean(cache) && cache.catalog_revision === state.catalog_revision;
    const taskId = url.searchParams.get('task_id');
    if (taskId) {
      if (!TASK_ID.test(taskId)) throw Object.assign(new Error('Task ID is invalid'), { status: 400 });
      state.selected_card = await capture('selected_card', async () => data(await api(p + '/documents/planning_cards/' + encodeURIComponent(taskId), 'GET', undefined, undefined, signal)), null);
    }
    return safe(state);
  }

  ctx.connection.fetch.register({ path: '/api/forgeflow-panel/state', methods: ['GET'], requestBody: 'buffered',
    fetch: async request => {
      try { return jsonResponse(await readState(new URL(request.url), request.signal)); }
      catch (error) { return jsonResponse({ error: { code: error.code ?? 'PANEL_READ_UNAVAILABLE', message: 'Native panel state is unavailable' } }, error.status ?? 503); }
    } });
  ctx.connection.fetch.register({ path: '/api/forgeflow-panel/import-targets', methods: ['GET'], requestBody: 'buffered',
    fetch: async request => {
      try {
        const rows = await all('/projects', request.signal);
        return jsonResponse({ schema_version: 'forgeflow.native-import-targets.v1',
          source: 'ACTUAL_OWNER_VISIBLE_CONTROL_PROJECTS',
          projects: rows.map(row => ({ ...pick(row, ['project_id', 'name', 'revision', 'authority_mode',
            'data_origin', 'timezone', 'paused', 'archived']),
            native_prepare_start_configured: projects.has(row.project_id) })),
          development_execution_approval_automatic: false });
      } catch (error) {
        return jsonResponse({ error: { code: error.code ?? 'IMPORT_TARGETS_UNAVAILABLE',
          message: 'Owner-visible blueprint import targets are unavailable' } }, error.status ?? 503);
      }
    } });
  ctx.connection.fetch.register({ path: '/api/forgeflow-panel/import-context', methods: ['GET'], requestBody: 'buffered',
    fetch: async request => {
      try {
        const projectId = new URL(request.url).searchParams.get('project_id');
        if (!SAFE_ID.test(projectId ?? '')) return jsonResponse({ error: { code: 'IMPORT_TARGET_REQUIRED' } }, 400);
        const result = await api('/projects/' + encodeURIComponent(projectId) + '/native-panel/blueprint-import-context',
          'GET', undefined, undefined, request.signal);
        return jsonResponse(safe(result));
      } catch (error) {
        return jsonResponse({ error: { code: error.code ?? 'IMPORT_CONTEXT_UNAVAILABLE',
          message: 'Canonical target authority and import bindings are unavailable' } }, error.status ?? 503);
      }
    } });
  ctx.connection.fetch.register({ path: '/api/forgeflow-panel/blueprint-preview', methods: ['POST'], requestBody: 'buffered',
    fetch: async request => {
      try {
        const raw = await request.text();
        if (Buffer.byteLength(raw) > 128 * 1024 * 1024) return jsonResponse({ error: { code: 'BLUEPRINT_PREVIEW_TOO_LARGE' } }, 413);
        const body = JSON.parse(raw);
        if (!SAFE_ID.test(body.target_project_id ?? '') || !UUID.test(body.request_id ?? '') ||
            !body.blueprint || body.blueprint.schema_version !== 'forgeflow.native-project-blueprint.v2' ||
            !body.mapping || !body.expected_authority ||
            Object.keys(body).some(key => !['target_project_id', 'request_id', 'blueprint', 'mapping', 'expected_authority'].includes(key))) {
          return jsonResponse({ error: { code: 'BLUEPRINT_PREVIEW_INVALID' } }, 400);
        }
        const result = await api('/projects/' + encodeURIComponent(body.target_project_id) + '/native-panel/blueprint-previews',
          'POST', pick(body, ['blueprint', 'mapping', 'expected_authority']), body.request_id, request.signal, blueprintTimeouts.preview);
        return jsonResponse(safe(result));
      } catch (error) {
        return jsonResponse({ error: blueprintFailure(error, 'BLUEPRINT_PREVIEW',
          'Canonical blueprint preview was not accepted') }, error.status ?? 503);
      }
    } });
  ctx.connection.fetch.register({ path: '/api/forgeflow-panel/blueprint-import', methods: ['POST'], requestBody: 'buffered',
    fetch: async request => {
      try {
        const raw = await request.text();
        if (Buffer.byteLength(raw) > 16384) return jsonResponse({ error: { code: 'BLUEPRINT_IMPORT_TOO_LARGE' } }, 413);
        const body = JSON.parse(raw);
        if (!SAFE_ID.test(body.target_project_id ?? '') || !SAFE_ID.test(body.preview_id ?? '') ||
            !UUID.test(body.request_id ?? '') || !SHA.test(body.review_sha256 ?? '') ||
            !Number.isSafeInteger(body.expected_revision) || body.expected_revision < 1 ||
            Object.keys(body).some(key => !['target_project_id', 'request_id', 'preview_id', 'expected_revision', 'review_sha256'].includes(key))) {
          return jsonResponse({ error: { code: 'BLUEPRINT_IMPORT_INVALID' } }, 400);
        }
        const result = await api('/projects/' + encodeURIComponent(body.target_project_id) + '/native-panel/blueprint-reviews/' +
          encodeURIComponent(body.preview_id) + '/import', 'POST', pick(body, ['expected_revision', 'review_sha256']),
          body.request_id, request.signal, blueprintTimeouts.import);
        catalogCache.delete(body.target_project_id);
        return jsonResponse(safe(result));
      } catch (error) {
        return jsonResponse({ error: blueprintFailure(error, 'BLUEPRINT_IMPORT',
          'Canonical reviewed planning import was not accepted') }, error.status ?? 503);
      }
    } });
  ctx.connection.fetch.register({ path: '/api/forgeflow-panel/command', methods: ['POST'], requestBody: 'buffered',
    fetch: async request => {
      try {
        const raw = await request.text();
        if (Buffer.byteLength(raw) > 16384) return jsonResponse({ error: { code: 'PANEL_COMMAND_TOO_LARGE' } }, 413);
        const body = JSON.parse(raw);
        if (!ACTIONS.has(body.action) || !projects.has(body.project_id) || !UUID.test(body.request_id ?? '') ||
            (body.attempt_id !== undefined && !SAFE_ID.test(body.attempt_id)) ||
            (body.reason !== undefined && (typeof body.reason !== 'string' || body.reason.length > 2000)) ||
            Object.keys(body).some(key => !['project_id', 'action', 'request_id', 'attempt_id', 'reason'].includes(key))) {
          return jsonResponse({ error: { code: 'PANEL_COMMAND_INVALID' } }, 400);
        }
        const entry = projects.get(body.project_id);
        const configBytes = privateBytes(entry.delivery_config_path);
        const delivery = JSON.parse(configBytes);
        const alignment = entry.alignment_sha256 ?? delivery.alignment_sha256;
        if (!SHA.test(alignment ?? '') || delivery.project_id !== body.project_id) {
          return jsonResponse({ error: { code: 'PANEL_REVIEWED_CONFIG_REQUIRED' } }, 409);
        }
        const command = { action: body.action, config_sha256: digest(configBytes), alignment_sha256: alignment,
          ...(body.attempt_id ? { attempt_id: body.attempt_id } : {}), ...(body.reason ? { reason: body.reason } : {}) };
        const receipt = await api('/projects/' + encodeURIComponent(body.project_id) + '/native-panel/actions',
          'POST', command, body.request_id, request.signal);
        catalogCache.delete(body.project_id);
        for (const key of profileCache.keys()) if (key.startsWith(body.project_id + ':')) profileCache.delete(key);
        return jsonResponse(safe(receipt), 202);
      } catch (error) {
        return jsonResponse({ error: { code: error.code ?? 'PANEL_COMMAND_UNAVAILABLE', message: 'Canonical native panel command was not accepted' } }, error.status ?? 503);
      }
    } });
  for (const section of ['configuration', 'configuration-drafts']) {
    ctx.connection.fetch.register({ path: '/api/forgeflow-panel/' + section, methods: section === 'configuration' ? ['GET'] : ['GET', 'POST'], requestBody: 'buffered',
      fetch: async request => {
        try {
          if (request.method === 'GET') {
            const projectId = selected(new URL(request.url));
            if (!projectId) return jsonResponse({ error: { code: 'NATIVE_CONFIGURATION_PROJECT_REQUIRED' } }, 400);
            return jsonResponse(safe(await api('/projects/' + encodeURIComponent(projectId) + '/native-panel/configuration' +
              (section === 'configuration-drafts' ? '/drafts' : ''), 'GET', undefined, undefined, request.signal, 180000)));
          }
          const raw = await request.text();
          if (Buffer.byteLength(raw) > 4 * 1024 * 1024) return jsonResponse({ error: { code: 'NATIVE_CONFIGURATION_TOO_LARGE' } }, 413);
          const body = JSON.parse(raw);
          if (!projects.has(body.project_id) || !UUID.test(body.request_id ?? '') || !SAFE_ID.test(body.draft_id ?? '') ||
              !['SAVE', 'PREVIEW', 'PUBLISH', 'ACTIVATE'].includes(body.action) ||
              Object.keys(body).some(key => !['project_id', 'request_id', 'action', 'draft_id', 'expected_revision', 'base_config_sha256', 'spec', 'review_sha256'].includes(key))) {
            return jsonResponse({ error: { code: 'NATIVE_CONFIGURATION_INVALID' } }, 400);
          }
          const payload = body.action === 'SAVE'
            ? pick(body, ['draft_id', 'expected_revision', 'base_config_sha256', 'spec'])
            : pick(body, ['expected_revision', 'review_sha256']);
          const path = '/projects/' + encodeURIComponent(body.project_id) + '/native-panel/configuration/drafts' +
            (body.action === 'SAVE' ? '' : '/' + encodeURIComponent(body.draft_id) + '/' + body.action.toLowerCase());
          const result = await api(path, 'POST', payload, body.request_id, request.signal, 240000);
          return jsonResponse(safe(result));
        } catch (error) {
          return jsonResponse({ error: blueprintFailure(error, 'NATIVE_CONFIGURATION', 'Native configuration operation was not accepted') }, error.status ?? 503);
        }
      } });
  }
  ctx.connection.fetch.register({ path: '/api/forgeflow-panel/blueprint', methods: ['GET'], requestBody: 'buffered',
    fetch: async request => {
      try {
        const url = new URL(request.url);
        // Export always uses the complete logical catalog, irrespective of a
        // caller's incremental dashboard cursor.
        url.searchParams.delete('catalog_revision');
        const state = await readState(url, request.signal);
        if (!state.project || !state.configuration || state.errors.some(row =>
          ['planning_cards', 'role_catalog', 'configuration'].includes(row.source))) {
          return jsonResponse({ error: { code: 'BLUEPRINT_SOURCE_UNAVAILABLE', message: 'Refresh the approved project configuration before exporting' } }, 409);
        }
        const configuration = state.configuration;
        const source = await blueprintSource(state.selected_project_id,
          state.catalog?.catalog_id ?? state.catalog?.id ?? '', request.signal);
        const catalog = source.catalog;
        const cards = source.cards.map(logicalCard);
        const roles = state.roster.roles.map(role => ({
          role_id: role.position_id ?? role.agent_id, owner_id: role.owner_id,
          team_id: role.owner_team_id ?? role.team_id,
          parent_role_id: role.organizational_parent_position_id ?? role.parent_agent_id ?? null,
          preset_id: role.preset_id }));
        const roleIds = new Set(roles.map(role => role.role_id));
        if (cards.some(card => !roleIds.has(card.role_id))) {
          return jsonResponse({ error: { code: 'BLUEPRINT_SOURCE_ROLE_BINDING_REQUIRED' } }, 409);
        }
        const edgeCount = cards.reduce((sum, card) => sum + (card.dependencies?.length ?? 0), 0);
        if (cards.length !== catalog.card_count || edgeCount !== catalog.edge_count || roles.length !== catalog.role_count) {
          return jsonResponse({ error: { code: 'BLUEPRINT_CATALOG_COUNTS_MISMATCH', counts: {
            expected_tasks: catalog.card_count ?? null, actual_tasks: cards.length,
            expected_edges: catalog.edge_count ?? null, actual_edges: edgeCount,
            expected_roles: catalog.role_count ?? null, actual_roles: roles.length },
            catalog_revision: catalog.revision } }, 409);
        }
        const requirements = source.requirements.map(row => pick(row, ['requirement_id', 'title', 'source_anchor',
          'outcome', 'scope', 'acceptance', 'priority', 'weight']));
        const sourceRequirementDigests = Object.fromEntries(source.requirements.map(row => [row.requirement_id,
          digest(JSON.stringify(['forgeflow.requirement.semantic.v1', row.project_id ?? state.selected_project_id,
            row.requirement_id, row.source_anchor, row.outcome, row.scope, row.acceptance, row.priority,
            row.weight, row.deferred_reason ?? null]))]));
        const ownerTerritories = source.owner_territories.map(owner => ({
          ...pick(owner, ['owner_id', 'root_team_id']),
          include: requireLogicalPaths(owner.include), exclude: requireLogicalPaths(owner.exclude) }));
        const teams = source.teams.map(team => pick(team, ['team_id', 'parent_team_id', 'name']));
        const samePlanningSnapshot = state.catalog?.catalog_id === catalog.catalog_id &&
          state.catalog?.revision === catalog.revision && state.catalog?.cards_sha256 === catalog.cards_sha256;
        const initialBlockers = catalog.blocker_counts ?? (samePlanningSnapshot ? state.catalog?.blocker_counts : null);
        const blueprint = { schema_version: 'forgeflow.native-project-blueprint.v2',
          blueprint_id: 'bp-' + digest(canonicalJson([state.selected_project_id, catalog.catalog_id,
            catalog.revision, catalog.cards_sha256, configuration.source.config_sha256])).slice(0, 32),
          title: state.project.name, exported_at: new Date().toISOString(),
          source: { project_id: state.selected_project_id, catalog_id: catalog.catalog_id,
            catalog_revision: catalog.revision, source_revision: catalog.source_revision,
            catalog_sha256: catalog.cards_sha256 },
          requirements, teams, owner_territories: ownerTerritories, roles, cards,
          parents: (catalog.parents ?? []).map(logicalSource),
          metadata: { project_template: { name: state.project.name, target: configuration.target },
            model_policy: configuration.model_policy, model_configuration: configuration.model_configuration,
            execution_policy: configuration.execution_policy,
            resource_targets: configuration.resources.map(policy => pick(policy, ['scope_id', 'project_id', 'team_id', 'limits'])),
            role_allocations: configuration.role_allocations,
            role_capabilities: state.roster.roles.map(role => ({ role_id: role.position_id ?? role.agent_id,
              ...pick(role, ['role', 'specialty', 'generic_preset_id', 'max_descendant_depth', 'allows_subagents', 'allows_grandchildren']) })),
            source_requirement_semantic_digests: sourceRequirementDigests,
            source_requirement_digest_algorithm: 'forgeflow.requirement.semantic.v1',
            source_card_digest_algorithm: 'SHA256_CANONICAL_UTF8_JSON_LEXICOGRAPHIC_KEYS',
            source_provenance_is_target_authority: false,
            source_host_path_literals: 'Replaced by [OUTSIDE_PROJECT_ROOT]; original source hashes remain provenance only',
            logical_read_path_count: cards.reduce((sum, card) => sum + card.read_set.length, 0),
            logical_write_path_count: cards.reduce((sum, card) => sum + card.write_set.length, 0),
            dag: { node_count: cards.length, edge_count: edgeCount, representation: 'Exact card.dependencies' },
            initial_planning_blocker_counts: initialBlockers ? Object.fromEntries(Object.entries(initialBlockers).reduce((counts, [name, count]) => {
              const code = name.split(':', 1)[0]; counts.set(code, (counts.get(code) ?? 0) + count); return counts;
            }, new Map())) : null,
            initial_planning_blockers_are_execution_status: false,
            target_binding_status: 'REQUIRES_ACTUAL_CANONICAL_TARGET_PREVIEW',
            reuse_scope: 'Explicit target mappings and canonical review/import required; imported planning remains NEEDS_REVIEW' },
          execution_rights_granted: false, runtime_bindings_exported: false };
        // The canonical serializer also rejects imprecise integer provenance.
        canonicalJson(blueprint);
        return new Response(JSON.stringify(blueprint, null, 2) + '\n', { status: 200,
          headers: { 'content-type': 'application/json', 'cache-control': 'no-store',
            'content-disposition': `attachment; filename="${state.selected_project_id}-workflow-blueprint.json"` } });
      } catch (error) {
        return jsonResponse({ error: { code: error.code ?? 'BLUEPRINT_EXPORT_UNAVAILABLE', message: 'Approved project blueprint export is unavailable' } }, error.status ?? 503);
      }
    } });
}
