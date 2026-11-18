/** Additive Cordis bridge. A controller must admit each native lifecycle before it runs. */
import { createConnection } from 'node:net';
import { createHash, randomUUID } from 'node:crypto';
import { AsyncLocalStorage } from 'node:async_hooks';

const modelGrantKey = Symbol.for('forgeflow.nativeModelGrantContext.v1');
const modelTransportKey = Symbol.for('forgeflow.nativeModelTransportConfig.v1');
const modelGrants = globalThis[modelGrantKey] ??= new AsyncLocalStorage();

export const name = 'forgeflow-managed-children';
export const inject = ['agents', 'llm'];

/** Inspect the real root scope before granting its first execution/model rights. */
export function assertRootRuntimeAvailable(ctx, agent, config) {
  // Fresh readonly children retain their narrower inherited capabilities.
  if (agent.session.header.parentSession) return;
  const requiredServices = ['tools', 'fs', 'sandbox', 'shell', 'ptcRuntime',
    'workflowEngine', 'agentTeams', 'forgeflowTeamBinding'];
  const requiredTools = ['read', 'bash', 'workflow', 'spawn_teammate', 'send_message',
    'list_agents', 'wait_agent', 'interrupt_agent', 'team_task_create', 'team_task_list',
    'team_task_get', 'team_task_update'];
  if (config.exact_write_binding?.write_set.length) requiredTools.push('write', 'edit');
  const missingServices = requiredServices.filter(service => !ctx.get(service));
  const tools = ctx.get('tools');
  const availableTools = typeof tools?.schemas === 'function'
    ? tools.schemas(agent).map(tool => tool.name).sort() : [];
  const missingTools = requiredTools.filter(tool =>
    typeof tools?.get !== 'function' || !tools.get(tool, agent) || !availableTools.includes(tool));
  const report = { schema_version: 'forgeflow.native-runtime-preflight.v1',
    attempt_id: config.attempt_id, native_session_id: agent.id,
    scope: 'ACTUAL_ROOT_AGENT_BEFORE_ADMISSION', model_calls: 0,
    available_tools: availableTools, required_tools: requiredTools,
    missing_services: missingServices, missing_tools: missingTools,
    status: missingServices.length || missingTools.length ? 'FAIL' : 'PASS' };
  // This diagnostic contains registry names only; no prompts, arguments or credentials.
  process.stderr.write('FORGEFLOW_RUNTIME_PREFLIGHT ' + JSON.stringify(report) + '\n');
  if (report.status === 'FAIL') {
    throw new Error(`Native runtime preflight failed: missing services [${missingServices.join(', ')}]; tools [${missingTools.join(', ')}]`);
  }
  return report;
}

export function apply(ctx, config) {
  const required = ['socket_path', 'project_id', 'task_id', 'attempt_id', 'generation'];
  if (required.some(key => config?.[key] === undefined)) throw new Error('Managed bridge identity is incomplete');
  const base = Object.fromEntries(required.filter(key => key !== 'socket_path').map(key => [key, config[key]]));
  if (config.model_relay) {
    const relay = config.model_relay;
    const hasProviderPolicy = relay.provider_policy_id !== undefined || relay.provider_policy_path !== undefined;
    if (relay.schema_version !== 'forgeflow.model-uds.v1' || relay.socket_path !== '/tmp/forgeflow/model.sock' ||
        relay.sdk_origin !== 'http://forgeflow-model.invalid' ||
        !Number.isSafeInteger(relay.max_request_bytes) || relay.max_request_bytes < 1 || relay.max_request_bytes > 8388608 ||
        !Number.isSafeInteger(relay.response_idle_timeout_ms) || relay.response_idle_timeout_ms < 1 || relay.response_idle_timeout_ms > 1800000 ||
        hasProviderPolicy && (relay.provider_policy_id !== 'glm-5.3-max.v1' ||
          relay.provider_policy_path !== '/tmp/forgeflow/provider-policy.json')) {
      throw new Error('Managed model transport configuration is invalid');
    }
    const frozen = Object.freeze({ schema_version: relay.schema_version, socket_path: relay.socket_path,
      sdk_origin: relay.sdk_origin, max_request_bytes: relay.max_request_bytes, response_idle_timeout_ms: relay.response_idle_timeout_ms,
      ...hasProviderPolicy ? { provider_policy_id: relay.provider_policy_id, provider_policy_path: relay.provider_policy_path } : {} });
    if (globalThis[modelTransportKey] && JSON.stringify(globalThis[modelTransportKey]) !== JSON.stringify(frozen)) {
      throw new Error('Managed model transport configuration changed');
    }
    globalThis[modelTransportKey] ??= frozen;
  }
  const live = new Map();
  const releases = new Map();
  const pending = new Set();
  const admissions = new Map();
  const modelStreams = new Set();
  // Lifecycle and model grants retain their independent awaited path. Native
  // observation bursts must not occupy every Worker socket while a Team is
  // creating its children. A single ordered tail also preserves each session's
  // publication order without manufacturing a receipt or dropping an event.
  let observationTail = Promise.resolve();
  let closing = false;
  let stopping;
  let firstClosing;

  const exact = config.exact_write_binding;
  if (exact !== undefined && (exact?.schema_version !== 'forgeflow.exact-leaf-write.v1' ||
      typeof exact.workspace_root !== 'string' || !exact.workspace_root.startsWith('/') ||
      !Array.isArray(exact.write_set) || exact.write_set.some(path => typeof path !== 'string' ||
        !path || path.startsWith('/') || path.includes('\\') || path.split('/').some(part => !part || part === '.' || part === '..')) ||
      Object.keys(exact).some(key => !['schema_version', 'workspace_root', 'write_set'].includes(key)))) {
    throw new Error('Managed exact-write binding is invalid');
  }
  ctx.provide('forgeflowExactWriteBinding', Object.freeze({ schema_version: 'forgeflow.exact-leaf-write.v1',
    workspace_root: exact?.workspace_root ?? null, write_set: Object.freeze([...(exact?.write_set ?? [])]),
    canWrite: () => {
      if (closing) return false;
      const agent = ctx.agents.currentInitiator();
      const entry = agent && live.get(agent.id);
      return !!(entry && entry.agent === agent && entry.grant && !closing);
    } }));

  async function rpc(operation, fields = {}) {
    // Identity is generated once per logical operation, never per connection.
    // A lost reply may follow a committed PostgreSQL mutation; retry those exact
    // bytes so the canonical controller can return its durable original reply.
    const rpcId = randomUUID();
    const request = JSON.stringify({ ...fields, ...base,
      schema_version: 'forgeflow.dsh-bridge.v2', rpc_id: rpcId, operation }) + '\n';
    if (Buffer.byteLength(request) > 65536) throw new Error('Managed controller request exceeds limit');
    const exchange = () => new Promise((resolve, reject) => {
      const socket = createConnection(config.socket_path);
      socket.setEncoding('utf8');
      let bytes = '';
      socket.setTimeout(config.rpc_timeout_ms ?? 3000, () => socket.destroy(new Error('Managed controller timeout')));
      socket.on('error', error => reject(Object.assign(error, { managedTransport: true })));
      socket.on('connect', () => socket.end(request));
      socket.on('data', chunk => {
        bytes += chunk.toString();
        if (Buffer.byteLength(bytes) > 65536) socket.destroy(new Error('Managed controller response exceeds limit'));
      });
      socket.on('end', () => {
        try {
          if (!bytes) throw Object.assign(new Error('Managed controller closed without a reply'), { managedTransport: true });
          const response = JSON.parse(bytes);
          if (response.ok !== true) {
            const code = typeof response.code === 'string' && /^[A-Z0-9_]{1,80}$/.test(response.code)
              ? response.code : 'INVALID_RESPONSE';
            throw Object.assign(new Error(`Managed controller rejected ${operation}: ${code}`), {
              managedCode: code,
              managedTransport: ['NATIVE_CONTROLLER_TIMEOUT', 'NATIVE_CONTROLLER_TRANSPORT'].includes(code),
            });
          }
          if (response.generation !== base.generation) throw new Error('Managed controller returned a stale generation');
          resolve(response);
        } catch (error) { reject(error); }
      });
    });
    for (let attempt = 0; attempt < 2; attempt++) {
      try { return await exchange(); }
      catch (error) {
        if (!error?.managedTransport || attempt === 1) {
          throw Object.assign(error, { managedOperation: operation, managedRpcId: rpcId });
        }
      }
    }
  }
  function track(job) {
    pending.add(job);
    job.finally(() => pending.delete(job)).catch(() => {});
    return job;
  }
  function observe(event, value) {
    const job = observationTail.then(() => rpc('observe', { event, value }));
    // Keep the queue drainable after a failed original operation. The original
    // promise remains rejected and failClosed retains its first failure.
    observationTail = job.catch(() => {});
    track(job).catch(failClosed);
    return job;
  }
  function beginClosing(reason, error) {
    closing = true;
    if (firstClosing) return;
    firstClosing = { schema_version: 'forgeflow.managed-bridge-close.v1', ...base, reason,
      operation: error?.managedOperation ?? null, rpc_id: error?.managedRpcId ?? null,
      response_code: error?.managedCode ?? null,
      error_kind: !error ? null : error.managedCode === 'NATIVE_CONTROLLER_TIMEOUT' || error.message?.includes('Managed controller timeout') ? 'controller_timeout' :
        error.managedTransport ? 'transport_error' : 'controller_or_protocol_rejection' };
    // Native logger sinks may be absent in --json mode. Preserve the first
    // cause directly, without requests, credentials or provider response bodies.
    process.stderr.write('FORGEFLOW_MANAGED_BRIDGE_CLOSE ' + JSON.stringify(firstClosing) + '\n');
  }
  function failClosed(error) {
    beginClosing('controller_failure', error);
    if (!stopping) stopping = stopAll('controller_unavailable');
    ctx.logger.warn(`ForgeFlow managed bridge closed admission: ${error instanceof Error ? error.message : 'controller failure'}`);
    stopping.catch(() => {}); // Preserve failure; never fake a successful cancel acknowledgment.
  }
  async function drainAdmissions(entries) {
    await Promise.allSettled(entries.map(entry => entry.finished.promise));
    // A creation hook rejected after a successful grant is paired with a real
    // agent/disposed event by the native registry. Keep that listener installed
    // until its actual callback and canonical release complete.
    await Promise.all(entries.filter(entry => entry.grant && entry.closedDuringAdmission)
      .map(entry => entry.disposed.promise));
    await Promise.all([...releases.values()]);
  }
  async function stopAll(reason) {
    beginClosing(reason === 'controller_revoke' ? 'controller_revoke' : 'controller_failure');
    const entering = [...admissions.values()];
    const agents = [...new Set([...live.values(), ...entering].map(value => value.agent))];
    for (const agent of agents) agent.cancel({ kind: 'hook', reason: `forgeflow:${reason}` });
    await drainAdmissions(entering);
    // Whole-agent idle is a quiescence observation, never disposal or business completion.
    await Promise.all(agents.map(agent => agent.whenIdle()));
    await Promise.all([...modelStreams]);
    await Promise.all([...releases.values()]);
    await rpc('cancel_ack', { reason, active_model_requests: modelStreams.size,
      sessions: [...live.values()].map(({ agent }) => ({ native_session_id: agent.id, status: agent.status })) });
  }

  // Cordis unloads sibling effects concurrently. A composite owns these exact
  // listener disposers so teardown drains pending admissions before unhooking
  // the real disposal callback. No modeled disposal edge is manufactured.
  ctx.effect(function* () {
  yield ctx.on('agent/created', async ({ agent, source, signal }) => {
    const previousRelease = releases.get(agent.id);
    if (previousRelease) await previousRelease;
    if (closing) throw new Error('Managed child admission is closed');
    const entry = { agent, grant: null, finished: Promise.withResolvers(), disposed: Promise.withResolvers(),
      disposedObserved: false, closedDuringAdmission: false, earlyObservations: [] };
    admissions.set(agent.id, entry);
    const header = agent.session.header;
    try {
      // The additive Team binding service uses the native, already-durable
      // provisioning record. It selects a registered preset before the first
      // turn; it cannot allocate resources or alter the parent's write set.
      // Calling it here makes this boundary independent of plugin load order.
      entry.binding = await ctx.get('forgeflowTeamBinding')?.bindAgent(agent);
      assertRootRuntimeAvailable(ctx, agent, config);
      signal?.throwIfAborted();
      if (closing) throw new Error('Managed child admission is closed');
      entry.grant = await rpc('admit', {
        native_session_id: agent.id, parent_session_id: header.parentSession ?? null,
        source, delegation_depth: header.delegationDepth ?? 0, origin: header.origin ?? null,
        agent_options: { provider: agent.options.provider ?? null, model: agent.options.model ?? null,
          preset_id: ctx.get('agentPresets')?.composedPreset(agent.ctx) ?? null,
          ...entry.binding ? Object.fromEntries(['position_id', 'owner_team_id', 'native_team_id', 'team_name']
            .map(key => [key, entry.binding[key]])) : {} },
      });
      // A committed grant must be visible to the actual disposal callback even
      // when cancellation won the race while its reply was in transit.
      live.set(agent.id, entry);
      for (const [event, value] of entry.earlyObservations) {
        if (event === 'agent-preset/selected' && entry.binding?.preset_id === value.preset_id) {
          value.position_id = entry.binding.position_id;
        }
        observe(event, value);
      }
      entry.earlyObservations.length = 0;
      if (entry.disposedObserved) releaseDisposed(entry);
      signal?.throwIfAborted();
      if (closing) {
        entry.closedDuringAdmission = true;
        throw new Error('Managed lifecycle was cancelled during admission');
      }
    } finally {
      if (admissions.get(agent.id) === entry) admissions.delete(agent.id);
      entry.finished.resolve();
    }
  });
  yield ctx.on('agent/request', async ({ agent }, next) => {
    const proposed = await next();
    const entry = live.get(agent.id);
    if (!entry || closing) throw new Error('Native request has no active managed allocation');
    // Route and cap replacements use DSH's logged request-config extension point.
    return { ...proposed, provider: entry.grant.provider, model: entry.grant.model, maxTokens: entry.grant.max_output_tokens };
  });
  yield ctx.on('llm/stream', (options, next) => {
    const initiator = ctx.agents.currentInitiator();
    return (async function* () {
      const entry = initiator && live.get(initiator.id);
      if (!entry || closing) throw new Error('Unattributed native model egress is denied');
      const settled = Promise.withResolvers();
      modelStreams.add(settled.promise);
      const requestId = randomUUID();
      let admitted;
      try { admitted = await rpc('model_request', {
        native_session_id: initiator.id, allocation_id: entry.grant.allocation_id,
        request_id: requestId, provider: options.provider, model: options.model,
        max_output_tokens: options.maxTokens ?? null, purpose: options.purpose ?? 'conversation',
      }); } catch (error) {
        modelStreams.delete(settled.promise);
        settled.resolve();
        throw error;
      }
      let usage = null;
      let finish = 'abandoned';
      // ALS covers provider iterator work only. The consumer of yielded native
      // chunks (including ordinary tools) runs outside this model authority.
      const transportGrant = { ...base, native_session_id: initiator.id,
        allocation_id: entry.grant.allocation_id, request_id: requestId,
        request_grant_id: admitted.request_grant_id, provider: entry.grant.provider,
        model: entry.grant.model, max_output_tokens: options.maxTokens ?? entry.grant.max_output_tokens,
        live: true, dispatch_started: false };
      let iterator;
      let exhausted = false;
      try {
        if (closing) throw new Error('Model request cancelled before native dispatch');
        const iterable = modelGrants.run(transportGrant, () => next());
        iterator = modelGrants.run(transportGrant, () => iterable[Symbol.asyncIterator]());
        for (;;) {
          const result = await modelGrants.run(transportGrant, () => iterator.next());
          if (result.done) { exhausted = true; break; }
          const chunk = result.value;
          if (chunk.type === 'usage') usage = chunk.usage;
          if (chunk.type === 'finish') finish = chunk.reason.kind;
          yield chunk;
        }
      } catch (error) {
        finish = error?.name === 'AbortError' ? 'aborted' : 'error';
        throw error;
      } finally {
        try {
          try {
            if (iterator && !exhausted && typeof iterator.return === 'function') {
              await modelGrants.run(transportGrant, () => iterator.return());
            }
          } finally {
            let transportError;
            if (transportGrant.transportComplete) {
              let completionTimer;
              try {
                await Promise.race([transportGrant.transportComplete, new Promise((_, reject) => {
                  completionTimer = setTimeout(() => {
                    const error = new Error('Managed model transport completion timed out');
                    transportGrant.cancelTransport?.(error);
                    reject(error);
                  }, config.model_relay.response_idle_timeout_ms);
                })]);
              }
              catch (error) {
                transportError = error;
                finish = error?.name === 'AbortError' ? 'aborted' : 'error';
              }
              finally { clearTimeout(completionTimer); }
            }
            transportGrant.live = false;
            await rpc('model_settle', { native_session_id: initiator.id,
              allocation_id: entry.grant.allocation_id, request_grant_id: admitted.request_grant_id,
              request_id: requestId, usage, usage_complete: usage !== null &&
                !['abandoned', 'aborted', 'error'].includes(finish), finish_reason: finish });
            if (transportError) throw transportError;
          }
        } finally {
          modelStreams.delete(settled.promise);
          settled.resolve();
        }
      }
    })();
  });
  function releaseDisposed(entry) {
    if (!entry.disposedObserved || !entry.grant || entry.release) return;
    if (live.get(entry.agent.id) === entry) live.delete(entry.agent.id);
    const release = entry.release = track(rpc('release', { native_session_id: entry.agent.id,
      allocation_id: entry.grant.allocation_id, reason: 'native_disposed' }));
    releases.set(entry.agent.id, release);
    release.then(() => { if (releases.get(entry.agent.id) === release) releases.delete(entry.agent.id); }, failClosed);
  }
  yield ctx.on('agent/disposed', ({ agent }) => {
    const entry = live.get(agent.id) ?? admissions.get(agent.id);
    if (!entry || entry.agent !== agent) return; // A stale same-id instance cannot dispose its replacement.
    entry.disposedObserved = true;
    entry.disposed.resolve();
    releaseDisposed(entry);
  });
  yield ctx.on('agent/status', ({ agent, status }) => {
    const entry = live.get(agent.id) ?? admissions.get(agent.id);
    if (!entry || entry.agent !== agent) return;
    const value = { native_session_id: agent.id, status };
    if (!entry.grant) entry.earlyObservations.push(['agent/status', value]);
    else observe('agent/status', value);
  });
  yield ctx.on('session/event', (session, event) => {
    const entry = live.get(session.id) ?? admissions.get(session.id);
    if (!entry || entry.agent.session !== session) return;
    if (!['assistant/message', 'assistant/attempt', 'turn/end', 'tool/call', 'agent-preset/selected', 'team/member',
          'team/task', 'team/message/queued', 'team/message/delivered', 'tool-workflow/run-start', 'tool-workflow/agent-start',
          'tool-workflow/agent-end', 'tool-workflow/run-end'].includes(event.type)) return;
    const data = {};
    for (const key of ['usage', 'runId', 'childId', 'stopReason', 'outcome']) {
      if (event.data[key] !== undefined) data[key] = event.data[key];
    }
    if (event.type === 'tool/call') {
      data.callId = event.data.callId;
      data.name = event.data.name;
    }
    if (event.type === 'agent-preset/selected') {
      data.preset_id = event.data.agentPreset;
      if (entry.binding?.preset_id === data.preset_id) data.position_id = entry.binding.position_id;
    }
    if (event.type === 'team/member') {
      data.teamId = event.data.teamId;
      const member = event.data.member;
      data.member = Object.fromEntries(['id', 'name', 'provider', 'context', 'phase'].map(key => [key, member[key]]));
      const binding = ctx.get('forgeflowTeamBinding')?.factFor(member.id);
      if (binding) {
        data.member.position_id = binding.position_id;
        data.member.preset_id = binding.preset_id;
      }
    }
    if (event.type === 'team/task') {
      data.teamId = event.data.teamId;
      const task = event.data.task;
      data.task = { id: task.id, revision: task.revision, status: task.status,
        blockedByCount: task.blockedBy.length, writeScopesCount: task.writeScopes.length,
        ...task.ownerId !== undefined ? { ownerId: task.ownerId } : {} };
    }
    if (event.type === 'team/message/queued') {
      data.teamId = event.data.teamId;
      data.messageId = event.data.message.id;
      data.targetId = event.data.message.targetId;
      data.senderId = event.data.message.senderId;
    }
    if (event.type === 'team/message/delivered') {
      for (const key of ['teamId', 'messageId', 'targetId']) data[key] = event.data[key];
    }
    if (event.type === 'tool-workflow/run-start') data.name = event.data.name;
    if (event.type === 'tool-workflow/agent-start' || event.type === 'tool-workflow/agent-end') {
      data.memberSeq = event.data.seq;
      if (event.data.label !== undefined) data.label = event.data.label;
      if (event.data.phase !== undefined) data.phase = event.data.phase;
    }
    if (event.data.reason) data.reason = { kind: event.data.reason.kind };
    if (event.type === 'assistant/message') {
      const output = event.data.message.content.filter(block => block.type === 'text').map(block => block.text).join('');
      data.assistant_text_sha256 = createHash('sha256').update(output).digest('hex');
      data.interrupted = event.data.interrupted === true;
    }
    const value = { native_session_id: session.id, seq: event.seq, ...data };
    // Native preset selection can be durable inside the creation hook before
    // its canonical admission reply. Preserve that real event, but do not send
    // it as an attributed lifecycle until its actual grant has committed.
    if (!entry.grant) entry.earlyObservations.push([event.type, value]);
    else observe(event.type, value);
  });
  // These notifications are observation only: never treated as controller grants.
  for (const event of ['subagent/start', 'subagent/end', 'workflow/start', 'workflow/phase', 'workflow/end', 'workflow/agent-start', 'workflow/agent-end']) {
    yield ctx.on(event, (info, child) => {
      const value = {};
      for (const key of ['id', 'runId', 'provider', 'local', 'stopReason', 'parentSessionId']) {
        if (info?.[key] !== undefined) value[key] = info[key];
      }
      if (event.startsWith('workflow/')) {
        value.runId = info.id;
        if (info.meta?.name !== undefined) value.name = info.meta.name;
      }
      if (event === 'workflow/phase') value.phase = child;
      if (child) for (const key of ['childId', 'outcome', 'label', 'phase', 'stopReason']) {
        if (child[key] !== undefined) value[key] = child[key];
      }
      if (child?.seq !== undefined) value.memberSeq = child.seq;
      observe(event, value);
    });
  }
  yield ctx.effect(() => {
    let checking = false;
    const timer = setInterval(() => {
      if (closing || checking) return;
      checking = true;
      track(rpc('poll').then(response => {
        if (response.revoked && !stopping) stopping = stopAll('controller_revoke');
      }).catch(failClosed).finally(() => { checking = false; }));
    }, config.poll_interval_ms ?? 1000);
    return async () => {
      clearInterval(timer);
      beginClosing('context_dispose');
      await drainAdmissions([...admissions.values()]);
      if (stopping) await stopping;
      await Promise.allSettled([...pending]);
    };
  });
  }, 'forgeflow managed lifecycle and ordered shutdown');
}
