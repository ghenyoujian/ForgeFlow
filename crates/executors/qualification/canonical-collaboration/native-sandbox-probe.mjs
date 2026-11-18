/** Necessary zero-model native PTC probe; launch under the same strong Worker wrapper. */
import { readFileSync } from 'node:fs';
import { dirname, resolve, join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { createRequire } from 'node:module';
import { createHash } from 'node:crypto';

const [configPath, providerPath, workspace] = process.argv.slice(2);
if (!configPath || !providerPath || !workspace) throw new Error('config, provider and workspace required');
const config = JSON.parse(readFileSync(configPath, 'utf8'));
const require = createRequire(config.module_anchor);
const { Context } = await import(pathToFileURL(require.resolve('@deepseek-ai/cordis')).href);
const nativeRoot = resolve(dirname(config.module_anchor), '../../../..');
const load = async path => (await import(pathToFileURL(join(nativeRoot, path, 'lib/index.js')).href)).default;
const provider = await import(pathToFileURL(providerPath).href);
const baseline = join(workspace, 'baseline.txt');
const baselineBefore = createHash('sha256').update(readFileSync(baseline)).digest('hex');
const context = new Context();
try {
  await context.plugin(await load('packages/core/session'));
  await context.plugin(await load('packages/fs/fs-local'));
  await context.plugin(await load('packages/subprocess/subprocess-local'));
  await context.plugin(provider, config);
  await context.plugin(await load('packages/session/session-projection'));
  await context.plugin(await load('packages/sandbox/sandbox-policy'), { mode: 'workspace-write', workspaceRoot: workspace });
  await context.plugin(await load('packages/ptc-runtime/ptc-runtime-node'), { graceMs: 250, timeoutMs: 20000, maxOutputBytes: 1048576 });
  const program = `
    const fs = await import('node:fs/promises');
    const cp = await import('node:child_process');
    const root = ${JSON.stringify(workspace)};
    const baseline = root + '/baseline.txt';
    const temporary = '/tmp/forgeflow-native-combined-' + process.pid;
    const checks = [];
    const check = (name, condition, facts) => checks.push({name, passed: !!condition, ...(facts === undefined ? {} : {facts})});
    await fs.mkdir(temporary);
    const a = temporary + '/a', b = temporary + '/b', link = temporary + '/link';
    await fs.writeFile(a, 'permitted'); await fs.truncate(a, 3); await fs.rename(a, b);
    await fs.symlink(b, link);
    check('legal_temporary_write_truncate_rename_symlink', await fs.readFile(link, 'utf8') === 'per');
    check('legal_workspace_read', (await fs.readFile(baseline, 'utf8')).length > 0);
    const denied = async (name, action) => {
      try { await action(); check(name, false, {unexpected_effect: true}); }
      catch (error) { check(name, ['EACCES','EPERM','EROFS'].includes(error.code), {code: error.code}); }
    };
    await denied('outside_exact_write_set_write', () => fs.writeFile(baseline, 'FORBIDDEN'));
    await denied('outside_exact_write_set_truncate', () => fs.truncate(baseline, 0));
    await denied('outside_exact_write_set_rename', () => fs.rename(baseline, root + '/forbidden-rename'));
    await denied('outside_exact_write_set_symlink', () => fs.symlink(b, root + '/forbidden-symlink'));
    const escape = temporary + '/escape'; await fs.symlink(baseline, escape);
    await denied('symlink_to_readonly_workspace_write', () => fs.writeFile(escape, 'FORBIDDEN'));
    const inherited = cp.spawnSync(${JSON.stringify(config.ioctl_guard)}, ['--check-ioctl'], {encoding:'utf8',timeout:2000});
    check('ioctl_denied_in_actual_ptc_descendant', inherited.status === 0, {status: inherited.status, stderr: inherited.stderr});
    await fs.rm(temporary, {recursive:true});
    return {checks, actual_model_requests:0};
  `;
  const result = await context.ptcRuntime.run(context.ptcRuntime.resolve({ program, bindings: [], cwd: workspace }));
  const baselineAfter = createHash('sha256').update(readFileSync(baseline)).digest('hex');
  const checks = result.value?.checks ?? [];
  const passed = result.error === undefined && checks.length === 8 && checks.every(value => value.passed) && baselineBefore === baselineAfter;
  console.log(JSON.stringify({schema_version:'forgeflow.native-combined-sandbox-probe.v1', status:passed?'PASS':'FAIL',
    actual_model_requests:0, native_runtime:'ACTUAL_INSTALLED_NODE_PTC', result, baseline_before_sha256:baselineBefore,
    baseline_after_sha256:baselineAfter, scope:'Native filesystem and ioctl surface under unchanged outer Worker namespace/exact mounts; no native collaboration or production gate'}));
  process.exitCode = passed ? 0 : 1;
} finally {
  await context.fiber.dispose();
}
