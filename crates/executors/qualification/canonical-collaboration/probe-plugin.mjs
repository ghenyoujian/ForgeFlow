/** Qualification only: deterministically exercises actual installed native collaboration services. */
import { defineTool } from '/home/chenyoujian/.local/share/dsh-wsl/source/packages/core/tools/lib/index.js';

export const name = 'forgeflow-collaboration-qualification';
export const inject = ['tools', 'subagents', 'workflowEngine', 'agentTeams', 'agents'];

export function apply(ctx) {
  ctx.tools.register(defineTool({
    name: 'forgeflow_native_wait',
    description: 'Wait for the finite cancellation qualification; does not read or write files.',
    parameters: {},
    output: { schema: { type: 'string' }, render: (_args, value) => [{ type: 'text', text: value }] },
    async execute(_args, exec) {
      await new Promise((resolve, reject) => {
        const abort = () => { clearTimeout(timer); reject(new Error('Finite wait cancelled')); };
        const timer = setTimeout(() => { exec.signal.removeEventListener('abort', abort); resolve(); }, 20000);
        exec.signal.addEventListener('abort', abort, { once: true });
        if (exec.signal.aborted) abort();
      });
      return 'CANCEL_DELAY_DONE';
    },
  }));
  ctx.tools.register(defineTool({
    name: 'forgeflow_collaboration_probe',
    description: 'Run the explicitly requested finite ForgeFlow collaboration qualification. Does not edit files.',
    parameters: { mode: { type: 'string', required: true, enum: ['finite', 'cancel'] } },
    output: { schema: { type: 'string' }, render: (_args, value) => [{ type: 'text', text: value }] },
    async execute(args, exec) {
      const parent = exec.agent;
      if (!parent) throw new Error('Probe requires a native parent Agent');
      if (args.mode === 'cancel') {
        const workflow = ctx.workflowEngine.start({
          parent, signal: exec.signal, meta: { name: 'forgeflow-cancel-native-workflow', description: 'Finite cancellation qualification' },
          script: 'const value = await agent("Perform only this finite delay: call forgeflow_native_wait with empty arguments exactly once. Do not edit files, do not delegate. After the delay reply CANCEL_DELAY_DONE.", {label:"cancel-child"}); return value;',
          maxTotalAgents: 1,
        });
        try { return JSON.stringify(await workflow.result); }
        finally { await workflow.dispose(); }
      }
      const child = await ctx.subagents.start('spawn', { parent, signal: exec.signal,
        label: 'finite-one-shot', prompt: [{ type: 'text', text: 'Reply exactly ONE_SHOT_RECEIPT. Do not call any tools, edit files, or delegate.' }] });
      let oneShot;
      try { oneShot = await child.result; } finally { await child.dispose(); }
      const workflow = ctx.workflowEngine.start({ parent, signal: exec.signal,
        meta: { name: 'forgeflow-finite-native-workflow', description: 'Finite native workflow receipt' }, maxTotalAgents: 1,
        script: 'const result = await agent("Reply exactly WORKFLOW_RECEIPT. Do not call tools, edit files, or delegate.", {label:"workflow-child"}); return {receipt:result};' });
      let workflowResult;
      try { workflowResult = await workflow.result; } finally { await workflow.dispose(); }
      const teammate = await ctx.agentTeams.spawnTeammate(parent, {
        name: 'finite-verifier', description: 'Finite read-only receipt verifier',
        prompt: [{ type: 'text', text: 'Reply exactly TEAM_RECEIPT. Do not call tools, send messages, edit files, or delegate. This is the entire finite assignment.' }],
        context: 'fresh', provider: 'spawn', signal: exec.signal,
      });
      const teamAgent = ctx.agents.get(teammate.member.id);
      if (teamAgent) await teamAgent.whenIdle();
      // Drain the first residency, then recover the actual durable child through
      // its native Team mailbox rather than creating another session.
      await ctx.subagents.drainContinuableChildren(parent, [teammate.member.id]);
      const recovery = await ctx.agentTeams.sendMessage(parent, {
        target: 'finite-verifier', signal: exec.signal,
        content: [{ type: 'text', text: 'Reply exactly TEAM_RESUME_RECEIPT. Do not call tools, send messages, edit files, or delegate. This is a finite recovery check.' }],
      });
      const resumed = ctx.agents.get(teammate.member.id);
      if (resumed) await resumed.whenIdle();
      const roster = ctx.agentTeams.listMembers(parent).map(({ id, name, role, status }) => ({ id, name, role, status }));
      return JSON.stringify({
        scope: 'actual_native_services_with_canonical_postgresql_grants',
        one_shot: oneShot, workflow: workflowResult, roster, recovery,
      });
    },
  }));
}
