/** Bind actual native Team identities to their declared preset before queued work starts. */
export const name = 'forgeflow-team-binding';
export const inject = ['agents', 'agentPresets', 'sessionProjections', 'sessions'];

export function apply(ctx, config) {
  if (config?.schema_version !== 'forgeflow.dsh-team-binding.v1' ||
      config.require_fresh_for_role_change !== true || !Array.isArray(config.bindings)) {
    throw new Error('ForgeFlow Team binding requires the frozen v1 roster');
  }
  const byName = new Map();
  const byPosition = new Map();
  const byPreset = new Map();
  for (const row of config.bindings) {
    if (!/^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/.test(row?.position_id ?? '') ||
        !/^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/.test(row.teammate_name ?? '') ||
        !/^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/.test(row.preset_id ?? '') ||
        !/^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/.test(row.owner_team_id ?? '') ||
        byName.has(row.teammate_name) || byPosition.has(row.position_id) || byPreset.has(row.preset_id)) {
      throw new Error('ForgeFlow Team binding has an invalid or duplicate declared position');
    }
    const frozen = Object.freeze({ ...row });
    byName.set(row.teammate_name, frozen);
    byPosition.set(row.position_id, frozen);
    byPreset.set(row.preset_id, frozen);
  }
  const root = config.default_root_position_id === null ? null : byPosition.get(config.default_root_position_id);
  if (config.default_root_position_id !== null && !root) throw new Error('Declared root position is absent');
  const members = new Map();
  const facts = new Map();
  const operations = new WeakMap();

  function memberFact(session, event) {
    if (event.type !== 'team/member') return;
    const data = event.data;
    const member = data?.member;
    if (data?.version !== 2 || typeof member?.id !== 'string' || typeof member.name !== 'string') return;
    const position = byName.get(member.name);
    if (!position) {
      throw new Error('Unknown project teammate position');
    }
    if (typeof session?.id !== 'string' || data.teamId !== session.id) {
      throw new Error('Native Team member has inconsistent Lead identity');
    }
    const old = members.get(member.id);
    if (old && (old.position.preset_id !== position.preset_id || old.parent_session_id !== session.id)) {
      throw new Error('Native Team member changed its declared position');
    }
    members.set(member.id, { position, parent_session_id: session.id, native_team_id: data.teamId });
  }

  function restoreTeamMembers(agent) {
    const state = ctx.sessionProjections.stateOf(agent.session, 'agentTeam');
    if (state?.failure) throw new Error('Cannot bind a failed native Team projection');
    for (const member of state?.members ?? []) {
      memberFact(agent.session, { type: 'team/member', data: { version: 2, teamId: agent.id, member } });
    }
  }

  async function performBinding(agent) {
    restoreTeamMembers(agent);
    const header = agent.session.header;
    const recordedPreset = ctx.sessionProjections.stateOf(agent.session, 'agentPreset');
    const currentPreset = ctx.agentPresets.composedPreset(agent.ctx);
    const member = members.get(agent.id);
    let position = member?.position ?? byPreset.get(recordedPreset) ?? byPreset.get(currentPreset);
    if (member && header.parentSession !== member.parent_session_id) {
      throw new Error('Declared native teammate has the wrong direct parent');
    }
    const boundary = ctx.sessionProjections.stateOf(agent.session, 'turnBoundary');
    // A historical generic session keeps its actual composition. A new lead
    // chooses the exact position while the official blank-session window is open.
    if (!position && !header.parentSession && currentPreset === 'forgeflow-lead-v1' &&
        boundary?.lastTurn === 0 && boundary.openTurnStartSeq === null) position = root;
    if (!position) return undefined;
    const preset = await ctx.agentPresets.resolve(position.preset_id);
    if (preset.broken) throw new Error(`Declared position preset failed activation: ${position.preset_id}`);
    if (recordedPreset === position.preset_id) {
      // Reconstruct precisely the persisted selection for cold resume. This is
      // not a new selection and does not bypass the official blank-session lock.
      if (currentPreset !== position.preset_id) await ctx.agentPresets.mount(agent.ctx, position.preset_id);
    } else {
      // select() itself rejects inherited/completed turns. A different role
      // needs a fresh teammate; do not relabel a fork or bypass the selection lock.
      await ctx.agentPresets.select(agent, position.preset_id);
      await ctx.sessions.flush(agent.session);
    }
    if (ctx.agentPresets.composedPreset(agent.ctx) !== position.preset_id) {
      throw new Error('Native Agent did not retain its selected role preset');
    }
    const result = Object.freeze({ position_id: position.position_id, preset_id: position.preset_id,
      team_name: position.teammate_name, owner_team_id: position.owner_team_id,
      native_team_id: member?.native_team_id ?? null, native_session_id: agent.id,
      parent_session_id: header.parentSession ?? null });
    facts.set(agent.id, result);
    return result;
  }

  function bindAgent(agent) {
    let operation = operations.get(agent);
    if (!operation) {
      operation = performBinding(agent);
      operations.set(agent, operation);
    }
    return operation;
  }

  // The bridge also awaits bindAgent() before admission, making binding order
  // independent of sibling plugin initialization or creation listener order.
  ctx.provide('forgeflowTeamBinding', Object.freeze({ bindAgent, factFor: id => facts.get(id) }));
  ctx.on('session/event', memberFact);
  ctx.on('agent/created', async ({ agent }) => { await bindAgent(agent); });
  ctx.on('agent/disposed', ({ agent }) => { facts.delete(agent.id); });
}
