/** Qualification only: real stock tools before the first model step, then reject it. */
import { readFileSync, readlinkSync } from 'node:fs';
import { randomUUID } from 'node:crypto';
export const name = 'forgeflow-native-tool-egress-point';
export const inject = ['tools', 'agents', 'ptcRuntime', 'llm'];
export function* apply(ctx, config) {
  if (config?.host !== '127.0.0.1' || !Number.isInteger(config.port) || config.port < 1024 || config.port > 65535) throw new Error('Owned loopback listener identity required');
  let executed = false;
  yield ctx.on('llm/stream', () => {
    process.stdout.write(JSON.stringify({ type: 'forgeflow_native_tool_model_denial', code: 'G07_ZERO_MODEL_GUARD' }) + '\n');
    throw Object.assign(new Error('G07 tool-only point never dispatches a model'), { code: 'G07_ZERO_MODEL_GUARD' });
  }, { global: true, prepend: true });
  yield ctx.on('agent/pre-step', async ({ agent, signal }) => {
    if (executed) return { kind: 'reject' };
    executed = true;
    const base = { agent, signal };
    const bashCommand = `printf 'G07_BASH_NS='; readlink /proc/self/ns/net; printf 'G07_BASH_CGROUP='; cat /proc/self/cgroup; if bash -c 'exec 3<>/dev/tcp/127.0.0.1/${config.port}' ; then printf 'G07_TCP_UNEXPECTED_ALLOWED\\n'; exit 7; else printf 'G07_BASH_TCP_DENIED\\n'; fi`;
    const bash = await ctx.tools.execute({ ...base, callId: randomUUID(), name: 'bash', arguments: { command: bashCommand, description: 'Check owned loopback listener from actual stock Bash', timeoutMs: 3000, run_in_background: false } });
    const ptcCode = `const net = await import('node:net'); const fs = await import('node:fs'); const network_namespace = fs.readlinkSync('/proc/self/ns/net'); const cgroup = fs.readFileSync('/proc/self/cgroup','utf8'); const tcp = await new Promise(resolve => { const s=net.createConnection({host:'127.0.0.1',port:${config.port}}); s.setTimeout(2000,()=>{s.destroy();resolve({allowed:false,code:'TIMEOUT'});}); s.once('connect',()=>{s.destroy();resolve({allowed:true});});s.once('error',e=>resolve({allowed:false,code:e.code}));}); let ambient_fetch; const ctl=new AbortController();const timer=setTimeout(()=>ctl.abort(),2000);try {await fetch('http://127.0.0.1:${config.port}/', {signal:ctl.signal});ambient_fetch={allowed:true};}catch(e){ambient_fetch={allowed:false,error:e.name,code:e.cause?.code??null};}finally{clearTimeout(timer);} return {network_namespace,cgroup,tcp,ambient_fetch};`;
    const ptc = await ctx.tools.execute({ ...base, callId: randomUUID(), name: 'run_code', arguments: { code: ptcCode, description: 'Check raw TCP and ambient fetch in stock Node PTC tool', timeoutMs: 5000 } });
    let outsideGrant;
    try { await fetch('http://forgeflow-model.invalid/v1/messages', { method: 'POST', body: JSON.stringify({ model: 'glm-5.3', max_tokens: 1, stream: true, messages: [] }) }); outsideGrant = { allowed: true }; }
    catch (error) { outsideGrant = { allowed: false, code: error.code ?? null, error: error.name }; }
    process.stdout.write(JSON.stringify({ type: 'forgeflow_native_tool_proof', schema_version: 'forgeflow.native-tool-egress-point.v1', agent_id: agent.id, network_namespace: readlinkSync('/proc/self/ns/net'), cgroup: readFileSync('/proc/self/cgroup','utf8'), tools: { bash, ptc }, outside_grant_fetch: outsideGrant, model_step_rejected: true, tools_mode: 'both', scope: 'qualification_only_actual_stock_tool_entries' }) + '\n');
    return { kind: 'reject' };
  });
}
