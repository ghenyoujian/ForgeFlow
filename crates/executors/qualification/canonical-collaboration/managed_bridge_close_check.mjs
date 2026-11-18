/** One zero-model deterministic admission/context-unload race.
 * Real pinned Cordis and AgentRegistry lifecycle; controller is an explicit
 * local transport fixture, not canonical PostgreSQL or production evidence.
 */
import assert from 'node:assert/strict';
import { createServer } from 'node:net';
import { mkdtemp, readFile, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createHash, randomUUID } from 'node:crypto';
import { Context } from '/home/chenyoujian/.local/share/dsh-wsl/source/vendor/cordis/lib/index.js';
import AgentRegistry from '/home/chenyoujian/.local/share/dsh-wsl/source/packages/core/agent/lib/index.js';
import { apply } from '../../presets/forgeflow/managed-bridge.mjs';

const ready = Promise.withResolvers(), closedCause = Promise.withResolvers(), released = Promise.withResolvers();
const root = await mkdtemp(join(tmpdir(), 'ff-native-close-'));
const socketPath = join(root, 'controller.sock'), calls = [], order = [];
let admitSocket;
const respond = (socket, value) => socket.end(JSON.stringify({ ok: true, generation: 1, ...value }) + '\n');
const server = createServer({ allowHalfOpen: true }, socket => {
  let raw = '';
  socket.on('data', chunk => { raw += chunk; });
  socket.on('end', () => {
    const request = JSON.parse(raw); calls.push(request); order.push(request.operation);
    if (request.operation === 'admit') { admitSocket = socket; ready.resolve(); }
    else { respond(socket, { revoked: false }); if (request.operation === 'release') released.resolve(request); }
  });
});
await new Promise(resolve => server.listen(socketPath, resolve));
const stderrWrite = process.stderr.write.bind(process.stderr);
const diagnostics = [];
process.stderr.write = (chunk, ...args) => {
  const text = String(chunk);
  if (text.startsWith('FORGEFLOW_MANAGED_BRIDGE_CLOSE ')) {
    const value = JSON.parse(text.slice('FORGEFLOW_MANAGED_BRIDGE_CLOSE '.length));
    diagnostics.push(value); closedCause.resolve(value);
  }
  return stderrWrite(chunk, ...args);
};
const ctx = new Context();
await ctx.plugin(AgentRegistry);
const bridge = await ctx.plugin(pluginCtx => apply(pluginCtx, {
  socket_path: socketPath, project_id: 'fixture-project', task_id: 'fixture-task',
  attempt_id: 'fixture-attempt', generation: 1, rpc_timeout_ms: 1000, poll_interval_ms: 100000,
}));
let cancelled = 0, disposedEvents = 0;
const agent = { id: 'fixture-native', options: {}, session: { id: 'fixture-native', header: {} },
  status: 'idle', cancel() { cancelled++; }, whenIdle() { return Promise.resolve(); } };
ctx.on('agent/disposed', ({ agent: actual }) => {
  if (actual === agent) { disposedEvents++; order.push('actual_registry_disposal'); }
});
const detach = ctx.agents.enter(agent, undefined);
let creationError;
const creation = ctx.agents.announce(agent, 'startup').catch(error => {
  creationError = error; detach(); // Actual native registry rollback capability emits disposal.
});
let cleanupFinished = false;
const deadline = setTimeout(() => { console.error('deterministic race did not close'); process.exit(1); }, 5000);
try {
  await ready.promise;
  const cleanup = bridge.dispose().then(() => { cleanupFinished = true; });
  const cause = await closedCause.promise;
  assert.equal(cause.reason, 'context_dispose');
  assert.equal(cleanupFinished, false, 'unload must join the pending admission');
  assert.equal(calls.filter(call => call.operation === 'release').length, 0, 'no invented disposal before grant');
  respond(admitSocket, { allocation_id: randomUUID(), provider: 'fixture', model: 'fixture', max_output_tokens: 32 });
  await creation;
  const release = await released.promise;
  await cleanup;
  assert.match(creationError.message, /cancelled during admission/);
  assert.equal(disposedEvents, 1);
  assert.equal(ctx.agents.get(agent.id), undefined);
  assert.equal(release.reason, 'native_disposed');
  assert.equal(release.native_session_id, agent.id);
  assert.equal(order.indexOf('actual_registry_disposal') < order.indexOf('release'), true);
  assert.equal(calls.filter(call => call.operation === 'admit').length, 1);
  assert.equal(calls.filter(call => call.operation === 'release').length, 1);
  assert.equal(calls.filter(call => call.operation.startsWith('model_')).length, 0);
  assert.equal(diagnostics.length, 1);
  for (const call of calls) {
    assert.match(call.rpc_id, /^[0-9a-f-]{36}$/);
    assert.equal(call.schema_version, 'forgeflow.dsh-bridge.v2');
    assert.equal(call.attempt_id, 'fixture-attempt');
  }
  const report = { schema_version: 'forgeflow.native-admission-close-regression.v1', status: 'PASS_ZERO_MODEL_RACE',
    scope: 'Actual Cordis ordered teardown and AgentRegistry disposal, deterministic local transport fixture; no PostgreSQL, Worker or provider workload',
    checks: 15, actual_model_requests: 0, admission_calls: 1, release_calls: 1,
    actual_registry_disposal_events: disposedEvents, teardown_joined_pending_admission: true,
    first_closing_cause: diagnostics[0], event_order: order,
    source_sha256: createHash('sha256').update(await readFile(new URL('../../presets/forgeflow/managed-bridge.mjs', import.meta.url))).digest('hex'),
    driver_sha256: createHash('sha256').update(await readFile(new URL(import.meta.url))).digest('hex'),
    not_proven: ['Initial actual-run closing trigger', 'Canonical PostgreSQL release', 'Unknown-model release', 'Real native parent artifact closure', 'Production100'] };
  const target = process.argv[2];
  if (target) await writeFile(target, JSON.stringify(report, null, 2) + '\n', { flag: 'wx' });
  console.log(JSON.stringify(report));
} finally {
  clearTimeout(deadline);
  process.stderr.write = stderrWrite;
  await ctx.fiber.dispose();
  await new Promise(resolve => server.close(resolve));
}
