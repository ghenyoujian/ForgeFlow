import test from 'node:test';
import assert from 'node:assert/strict';
import { apply } from '../crates/executors/presets/forgeflow/team-binding.mjs';

const roles = Array.from({ length: 128 }, (_, i) => ({ position_id: `agent-${i}`, teammate_name: `member-${i}`,
  preset_id: `preset-${i}`, owner_id: 'owner', owner_team_id: 'team' }));
function fixture(bindings = roles) {
  const handlers = new Map(), services = new Map(), selected = [];
  const ctx = { on: (event, callback) => handlers.set(event, callback), provide: (name, service) => services.set(name, service),
    sessionProjections: { stateOf: (session, name) => name === 'turnBoundary' ? { lastTurn: 0, openTurnStartSeq: null }
      : name === 'agentPreset' ? session.savedPreset : {} }, sessions: { flush: async () => {} },
    agentPresets: { resolve: async () => ({ broken: false }), composedPreset: context => context.preset,
      select: async (agent, preset) => { selected.push(preset); agent.ctx.preset = preset; },
      mount: async (context, preset) => { context.preset = preset; } } };
  apply(ctx, { schema_version: 'forgeflow.dsh-team-binding.v1', require_fresh_for_role_change: true,
    bindings, default_root_position_id: 'agent-0' });
  return { handlers, services, selected };
}
test('128 arbitrary project positions bind the declared native member before execution', async () => {
  const f = fixture();
  f.handlers.get('session/event')({ id: 'lead-session' }, { type: 'team/member', data: { version: 2, teamId: 'lead-session',
    member: { id: 'child-session', name: 'member-127' } } });
  const agent = { id: 'child-session', session: { header: { parentSession: 'lead-session' } }, ctx: { preset: 'forgeflow-implementer-v1' } };
  await f.handlers.get('agent/created')({ agent });
  assert.deepEqual(f.selected, ['preset-127']);
  assert.equal(f.services.get('forgeflowTeamBinding').factFor(agent.id).position_id, 'agent-127');
});
test('duplicate declarations and unknown native teammates fail closed', () => {
  assert.throws(() => fixture([...roles, roles[0]]), /duplicate/);
  const f = fixture();
  assert.throws(() => f.handlers.get('session/event')({ id: 'lead' }, { type: 'team/member',
    data: { version: 2, teamId: 'lead', member: { id: 'child', name: 'undeclared' } } }), /Unknown project/);
});
test('native member cannot change its parent or borrow another role', async () => {
  const f = fixture();
  f.handlers.get('session/event')({ id: 'lead' }, { type: 'team/member', data: { version: 2, teamId: 'lead', member: { id: 'child', name: 'member-1' } } });
  const agent = { id: 'child', session: { header: { parentSession: 'other-lead' } }, ctx: { preset: 'forgeflow-implementer-v1' } };
  await assert.rejects(f.handlers.get('agent/created')({ agent }), /wrong direct parent/);
  assert.equal(f.selected.length, 0);
});
test('cold resume restores the exact persisted preset without selecting a new role', async () => {
  const f = fixture();
  const agent = { id: 'restored', session: { header: {}, savedPreset: 'preset-2' }, ctx: { preset: 'forgeflow-lead-v1' } };
  await f.handlers.get('agent/created')({ agent });
  assert.equal(agent.ctx.preset, 'preset-2');
  assert.equal(f.selected.length, 0);
});
