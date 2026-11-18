/** Native Node confinement intersects with the exact outer Worker boundary. */
import { createHash } from 'node:crypto';
import { readFileSync, statSync } from 'node:fs';
import { isAbsolute } from 'node:path';
import { createRequire } from 'node:module';
import { pathToFileURL } from 'node:url';
import { spawnSync } from 'node:child_process';

export const name = 'forgeflow-native-landlock-seccomp';
function digest(path) { return createHash('sha256').update(readFileSync(path)).digest('hex'); }

export async function apply(ctx, config) {
  const fields = ['module_anchor', 'module_anchor_sha256', 'launcher', 'launcher_sha256',
    'ioctl_guard', 'ioctl_guard_sha256', 'probe_timeout_ms'];
  if (!config || Object.keys(config).some(key => !fields.includes(key)) ||
      !['module_anchor', 'launcher', 'ioctl_guard'].every(key => typeof config[key] === 'string' && isAbsolute(config[key])) ||
      !['module_anchor_sha256', 'launcher_sha256', 'ioctl_guard_sha256'].every(key => /^[0-9a-f]{64}$/.test(config[key])) ||
      !Number.isSafeInteger(config.probe_timeout_ms) || config.probe_timeout_ms < 1 || config.probe_timeout_ms > 5000) {
    throw new Error('ForgeFlow native sandbox requires pinned inputs and a bounded probe');
  }
  if (digest(config.module_anchor) !== config.module_anchor_sha256) throw new Error('Native sandbox SDK anchor changed');
  const require = createRequire(config.module_anchor);
  const { SandboxProvider, SandboxUnavailableError, canonicalPath } =
    await import(pathToFileURL(require.resolve('@deepseek-ai/dsh-sandbox')).href);
  const { grantArgs, LAUNCHER_FAILURE_EXIT, LAUNCHER_BIN } =
    await import(pathToFileURL(require.resolve('@deepseek-ai/node-addon-system/landlock-run')).href);
  class PinnedLandlockSandbox extends SandboxProvider {
    constructor(scope) { super(scope); this.probed = false; }
    async confine(argv, policy, signal) {
      signal?.throwIfAborted();
      if (!['read-only', 'workspace-write'].includes(policy?.mode) || !Array.isArray(argv) || !argv.length) {
        throw new Error('Native sandbox requires an explicit confined mode and exact argv');
      }
      for (const name of ['launcher', 'ioctl_guard']) {
        const metadata = statSync(config[name]);
        if (!metadata.isFile() || !(metadata.mode & 0o111) || metadata.mode & 0o222 || digest(config[name]) !== config[name + '_sha256']) {
          throw new SandboxUnavailableError(policy.mode, 'immutable native confinement executable changed');
        }
      }
      if (!this.probed) {
        const result = spawnSync(config.launcher, ['--probe'], { timeout: config.probe_timeout_ms,
          encoding: 'utf8', maxBuffer: 4096, stdio: ['ignore', 'pipe', 'pipe'] });
        if (result.status !== 0 || !['landlock: fully enforced', 'landlock: partially enforced (older ABI)'].includes(result.stdout.trim())) {
          throw new SandboxUnavailableError(policy.mode, 'official Landlock enforcement was not observed');
        }
        const guard = spawnSync(config.ioctl_guard, ['--probe'], { timeout: config.probe_timeout_ms,
          encoding: 'utf8', maxBuffer: 4096, stdio: ['ignore', 'pipe', 'pipe'] });
        let proof;
        try { proof = JSON.parse(guard.stdout); } catch { /* Exact positive probe required below. */ }
        if (guard.status !== 0 || proof?.schema_version !== 'forgeflow.native-ioctl-guard.v1' ||
            proof.landlock_abi < 3 || proof.ioctl_after_errno !== 1 || proof.child_exec_ioctl_denied !== true || proof.allowed_fionbio !== true) {
          throw new SandboxUnavailableError(policy.mode, 'Landlock ABI3 and inherited seccomp ioctl denial were not observed');
        }
        this.probed = true;
      }
      const readWrite = ['/dev/null'];
      if (policy.mode === 'workspace-write') readWrite.push('/tmp', canonicalPath(policy.workspaceRoot));
      // Inherited rules intersect: this native policy cannot widen Worker rights.
      return { argv: [config.ioctl_guard, '--', config.launcher, ...grantArgs({ readOnly: ['/'], readWrite }), '--', ...argv],
        enforcement: 'full', denialSignatures: ['permission denied'],
        runnerFailureRules: [{ allowedExitCodes: [LAUNCHER_FAILURE_EXIT], fatalSignatures: [`${LAUNCHER_BIN}: `, 'forgeflow-ioctl-deny: '],
          informationalLines: [`${LAUNCHER_BIN}: partial enforcement (older Landlock ABI)`] }] };
    }
  }
  await ctx.plugin(PinnedLandlockSandbox);
}
