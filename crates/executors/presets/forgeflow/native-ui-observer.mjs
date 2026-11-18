/** Actual read-only persistence provider and native UI author guards. */
import { createRequire } from 'node:module';
import { pathToFileURL } from 'node:url';
import { isAbsolute } from 'node:path';
import { join } from 'node:path';
import { readdirSync, chmodSync, statSync, lstatSync, readFileSync, writeFileSync, renameSync } from 'node:fs';
import { randomUUID } from 'node:crypto';

export const name = 'forgeflow-native-ui-observer';

function unsupported(operation) {
  const error = new Error(`ActualReadOnlyUnsupported: native ${operation} is owned by the canonical ForgeFlow operation panel`);
  error.code = 'FORGEFLOW_NATIVE_UI_READ_ONLY';
  return error;
}

export async function apply(ctx, config) {
  if (config?.schema_version !== 'forgeflow.native-ui-observer.v1') throw new Error('Native UI observer configuration is missing');
  if (config.kind === 'read-only-config-editor') {
    if (!isAbsolute(config.module_anchor ?? '')) throw new Error('Frozen native UI module anchor is invalid');
    const require = createRequire(config.module_anchor);
    const { default: Editor, ConfigEditor } = await import(pathToFileURL(require.resolve('@deepseek-ai/dsh-config-editor')).href);
    const Base = ConfigEditor ?? Editor;
    if (typeof Base !== 'function') throw new Error('Installed native configuration reader is unavailable');
    ctx.inject(['loader', 'profileContext'], scoped => {
      class ReadOnlyEditor extends Base {
        async edit(entry, change) {
          // Welcome acknowledgement is a private UI preference, not an
          // executable profile capability. Persist it separately; never reopen
          // the sealed profile or permit model/tool/preset changes.
          if (entry.options.id !== 'ui-settings-general' ||
              entry.options.name !== '@deepseek-ai/dsh-client-ui-settings-general' ||
              !this.entries().includes(entry)) throw unsupported('active profile mutation');
          const inherited = this.configuration().find(row => row.entry === entry)?.inherited ?? {};
          const next = change(structuredClone(entry.options.config ?? {}), structuredClone(inherited));
          if (!next || typeof next !== 'object' || Array.isArray(next) ||
              Object.keys(next).some(key => key !== 'welcomeNoticeVersion') ||
              typeof next.welcomeNoticeVersion !== 'string' || !/^\d{4}-\d{2}-\d{2}\.\d{1,8}$/.test(next.welcomeNoticeVersion) ||
              !isAbsolute(config.ui_preferences_path ?? '')) throw unsupported('non-UI preference mutation');
          const path = config.ui_preferences_path;
          let stored = { schema_version: 'forgeflow.native-ui-preferences.v1', preferences: {} };
          try { stored = JSON.parse(readFileSync(path)); } catch (error) { if (error.code !== 'ENOENT') throw error; }
          if (stored.schema_version !== 'forgeflow.native-ui-preferences.v1') throw unsupported('invalid UI preferences');
          const value = { ...stored, preferences: { ...stored.preferences, 'ui-settings-general': next } };
          const temporary = path + '.tmp-' + randomUUID();
          writeFileSync(temporary, JSON.stringify(value) + '\n', { flag: 'wx', mode: 0o600 });
          renameSync(temporary, path);
          // Entry.update is the supported native live update; Include is not
          // rewritten, and all profile capability bytes remain frozen.
          await entry.update({ config: next });
        }
      }
      new ReadOnlyEditor(scoped);
    });
    return;
  }
  if (config.kind === 'read-only-persistence') {
    if (!isAbsolute(config.module_anchor ?? '') || !isAbsolute(config.root ?? '') ||
        !['zstd', 'none'].includes(config.compression)) throw new Error('Frozen native UI snapshot configuration is invalid');
    const require = createRequire(config.module_anchor);
    const { default: JsonlPersistence } = await import(pathToFileURL(require.resolve('@deepseek-ai/dsh-session-persistence-jsonl')).href);
    class ReadOnlyPersistence extends JsonlPersistence {
      create() { return Promise.reject(unsupported('session creation')); }
      open(id, access, options) {
        if (access !== 'read') return Promise.reject(unsupported('session write-open or resume'));
        return super.open(id, access, options);
      }
    }
    // The original JSONL row is replaced, so this is the one real persistence
    // service. Actual native read/stat/list methods remain the upstream backend.
    const backend = new ReadOnlyPersistence(ctx, { root: config.root, compression: config.compression });
    ctx.provide('forgeflowNativeUiReadOnly', Object.freeze({ schema_version: config.schema_version,
      root: config.root, session_writes: false, agent_activation: false, model_requests: false,
      persistence_identity: String(backend.identity) }));
    return;
  }
  if (config.kind !== 'guards') throw new Error('Unsupported native UI observer provider kind');
  // Both events are supported native extension points, also used by the
  // managed bridge. No Agent or provider stream may escape into this UI host.
  ctx.on('agent/created', async () => { throw unsupported('Agent activation'); });
  ctx.on('llm/stream', () => { throw unsupported('model request'); });
  ctx.inject(['appReady'], ready => {
    ready.effect(() => ready.appReady.onReady(() => {
      const home = process.env.DSH_HOME;
      if (!isAbsolute(home ?? '')) throw new Error('Native UI runtime home is not explicit');
      const profile = join(home, 'profiles', 'web');
      if (!statSync(profile).isDirectory() || lstatSync(profile).isSymbolicLink()) {
        throw new Error('Native UI active profile directory is invalid');
      }
      // The supported CLI generates cordis.yml before application readiness.
      // Freeze its active profile only after that real boot output is complete.
      for (const entry of readdirSync(profile, { withFileTypes: true })) {
        if (entry.isFile()) chmodSync(join(profile, entry.name), 0o400);
      }
      chmodSync(profile, 0o500);
    }), 'forgeflow-native-ui: seal actual ready profile');
  });
  ctx.provide('forgeflowNativeUiGuard', Object.freeze({ schema_version: config.schema_version,
    agent_activation: false, model_requests: false, author_permission_source: 'CANONICAL_WORKER_ONLY' }));
}
