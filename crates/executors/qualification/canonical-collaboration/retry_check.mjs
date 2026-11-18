/** Actual UDS transport checks only; these do not qualify PostgreSQL or native DSH. */
import { createServer } from 'node:net';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import assert from 'node:assert/strict';
import { apply } from '../../presets/forgeflow/managed-bridge.mjs';

const directory = await mkdtemp(join(tmpdir(), 'ff-rpc-'));
const socketPath = join(directory, 'controller.sock');
const received = [];
const handlers = new Map();
let scenario = 'lost-reply';
const server = createServer({ allowHalfOpen: true }, socket => {
  let bytes = '';
  socket.on('data', chunk => { bytes += chunk.toString(); });
  socket.on('end', () => {
    received.push(bytes);
    if (scenario === 'lost-reply' && received.length === 1) return socket.end();
    if (scenario === 'rejection') return socket.end(JSON.stringify({ ok: false, generation: 1, code: 'CAPACITY_EXHAUSTED' }));
    socket.end(JSON.stringify({ ok: true, generation: scenario === 'stale' ? 2 : 1,
      allocation_id: 'transport-check-only', provider: 'transport-check-only', model: 'transport-check-only', max_output_tokens: 1 }));
  });
});
await new Promise(resolve => server.listen(socketPath, resolve));
apply({ on: (event, hook) => handlers.set(event, hook), effect: () => {}, logger: { warn() {} } },
  { socket_path: socketPath, project_id: 'p', task_id: 't', attempt_id: 'a', generation: 1, rpc_timeout_ms: 100 });
const created = handlers.get('agent/created');
const agent = id => ({ id, options: {}, session: { header: {} } });
try {
  await created({ agent: agent('first'), source: 'startup' });
  assert.equal(received.length, 2);
  assert.equal(received[0], received[1]);
  const first = JSON.parse(received[0]);
  assert.equal(first.schema_version, 'forgeflow.dsh-bridge.v2');
  assert.match(first.rpc_id, /^[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$/);
  scenario = 'success';
  await created({ agent: agent('second'), source: 'startup' });
  assert.notEqual(JSON.parse(received[2]).rpc_id, first.rpc_id);
  scenario = 'rejection';
  const beforeRejection = received.length;
  await assert.rejects(created({ agent: agent('third'), source: 'startup' }), /CAPACITY_EXHAUSTED/);
  assert.equal(received.length, beforeRejection + 1);
  scenario = 'stale';
  const beforeStale = received.length;
  await assert.rejects(created({ agent: agent('fourth'), source: 'startup' }), /stale generation/);
  assert.equal(received.length, beforeStale + 1);
  console.log(JSON.stringify({ scope: 'ACTUAL_UDS_TRANSPORT_ONLY', status: 'PASS', assertions: 8,
    logical_calls: 4, socket_exchanges: received.length, lost_reply_reuses_exact_request: true,
    postgres_native_qualification: 'UNPROVEN' }));
} finally {
  await new Promise(resolve => server.close(resolve));
  await rm(directory, { recursive: true, force: true });
}
