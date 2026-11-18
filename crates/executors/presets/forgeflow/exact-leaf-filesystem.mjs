/** Native FS compatibility for immutable Worker file mounts; never widens a directory. */
import { createHash } from 'node:crypto';
import { constants, openSync, closeSync, fstatSync, lstatSync, realpathSync,
  readSync, writeSync, ftruncateSync, fsyncSync, readFileSync } from 'node:fs';
import { dirname, isAbsolute, resolve, relative, sep } from 'node:path';
import { createRequire } from 'node:module';
import { pathToFileURL } from 'node:url';

export const name = 'forgeflow-exact-leaf-filesystem';
export const inject = ['sandboxPolicy', 'forgeflowExactWriteBinding'];

export async function apply(ctx, config) {
  const allowed = ['module_anchor', 'module_anchor_sha256', 'max_write_bytes'];
  const maximum = config?.max_write_bytes ?? 16777216;
  if (!config || Object.keys(config).some(key => !allowed.includes(key)) ||
      !isAbsolute(config.module_anchor ?? '') || !/^[a-f0-9]{64}$/.test(config.module_anchor_sha256 ?? '') ||
      !Number.isSafeInteger(maximum) || maximum < 1 || maximum > 67108864 ||
      createHash('sha256').update(readFileSync(config.module_anchor)).digest('hex') !== config.module_anchor_sha256) {
    throw new Error('Exact-leaf filesystem requires a pinned native FS module and a finite byte bound');
  }
  const require = createRequire(config.module_anchor);
  const { FsError } = await import(pathToFileURL(require.resolve('@deepseek-ai/dsh-fs')).href);
  const { SandboxedFileSystem } = await import(pathToFileURL(config.module_anchor).href);
  if (typeof SandboxedFileSystem !== 'function') throw new Error('Pinned native sandbox FS provider is unavailable');
  const binding = ctx.get('forgeflowExactWriteBinding');
  if (binding?.schema_version !== 'forgeflow.exact-leaf-write.v1' || !Array.isArray(binding.write_set) ||
      typeof binding.canWrite !== 'function') throw new Error('Exact-leaf filesystem has no immutable Worker binding');
  const denied = () => new FsError('File mutation is outside the active exact Worker write set', 'FS_SANDBOX_DENIED');
  const version = info => `${info.dev}:${info.ino}:${info.size}:${info.mtimeNs}:${info.ctimeNs}`;
  const normalize = text => text.replaceAll('\r\n', '\n');
  const decode = bytes => {
    if (bytes.includes(0)) throw new FsError('Cannot edit binary content', 'FS_NOT_TEXT');
    try { return new TextDecoder('utf-8', { fatal: true }).decode(bytes); }
    catch { throw new FsError('Cannot edit invalid UTF-8 content', 'FS_NOT_TEXT'); }
  };

  class ExactLeafFileSystem extends SandboxedFileSystem {
    static inject = ['sandboxPolicy', 'forgeflowExactWriteBinding'];
    constructor(scope) {
      super(scope, { cwd: process.cwd(), diffBasisMaxBytes: 10485760 });
      this.exactLocks = new Map();
    }
    async withExactLock(key, operation) {
      const previous = this.exactLocks.get(key) ?? Promise.resolve();
      const result = previous.then(operation, operation);
      const tail = result.then(() => {}, () => {});
      this.exactLocks.set(key, tail);
      try { return await result; }
      finally { if (this.exactLocks.get(key) === tail) this.exactLocks.delete(key); }
    }
    checkedExactPath(target, policy, signal) {
      signal?.throwIfAborted();
      const effective = policy ?? this.ctx.sandboxPolicy.resolve();
      if (process.platform !== 'linux' || !['workspace-write', 'danger-full-access'].includes(effective?.mode) ||
          !binding.canWrite() || typeof binding.workspace_root !== 'string') throw denied();
      const root = binding.workspace_root;
      const path = this.processPath(target);
      const display = isAbsolute(target.displayPath) ? resolve(target.displayPath) : resolve(root, target.displayPath);
      const suffix = relative(root, path);
      if (!isAbsolute(root) || resolve(root) !== root || realpathSync(root) !== root ||
          !suffix || suffix === '..' || suffix.startsWith(`..${sep}`) || isAbsolute(suffix) ||
          display !== path || !binding.write_set.includes(suffix)) throw denied();
      if (effective.mode === 'workspace-write') {
        if (typeof effective.workspaceRoot !== 'string' || !isAbsolute(effective.workspaceRoot)) throw denied();
        const policyRoot = realpathSync(resolve(effective.workspaceRoot));
        const policySuffix = relative(policyRoot, path);
        if (policySuffix === '..' || policySuffix.startsWith(`..${sep}`) || isAbsolute(policySuffix)) throw denied();
      }
      // Require the exact lexical path as well as its canonical identity. The
      // opened descriptor below rejects final-link swaps; read-only outer mount
      // parents also prevent author code from renaming any ancestor or sibling.
      let cursor = path;
      for (;;) {
        const info = lstatSync(cursor);
        if (info.isSymbolicLink() || (cursor !== path && !info.isDirectory())) throw denied();
        if (cursor === root) break;
        cursor = dirname(cursor);
      }
      if (realpathSync(path) !== path) throw denied();
      return path;
    }
    mutate(target, expected, signal, policy, transform) {
      let descriptor;
      try {
        const path = this.checkedExactPath(target, policy, signal);
        // No O_CREAT/O_TRUNC, temporary file, rename, chmod, link or parent mkdir.
        // Worker preparation must already have mounted this regular leaf.
        descriptor = openSync(path, constants.O_RDWR | constants.O_NOFOLLOW);
        const initial = fstatSync(descriptor, { bigint: true });
        const named = lstatSync(path, { bigint: true });
        if (!initial.isFile() || initial.nlink !== 1n || named.isSymbolicLink() ||
            named.dev !== initial.dev || named.ino !== initial.ino) throw denied();
        if (expected?.kind === 'createIfAbsent') {
          throw new FsError('Read the existing mounted leaf before overwriting it', 'FS_NOT_OBSERVED');
        }
        const expectedVersion = expected?.kind === 'replaceIfVersion' ? expected.version : expected?.version;
        if (expectedVersion !== undefined && expectedVersion !== version(initial)) {
          throw new FsError('File changed since it was read', 'FS_STALE_VERSION');
        }
        if (initial.size > BigInt(maximum)) throw new FsError('Existing file exceeds the exact-write byte bound', 'FS_TOO_LARGE');
        const beforeBytes = Buffer.alloc(Number(initial.size));
        let read = 0;
        while (read < beforeBytes.length) {
          const count = readSync(descriptor, beforeBytes, read, beforeBytes.length - read, read);
          if (!count) throw new FsError('File changed during the guarded read', 'FS_STALE_VERSION');
          read += count;
        }
        if (version(fstatSync(descriptor, { bigint: true })) !== version(initial)) {
          throw new FsError('File changed during the guarded read', 'FS_STALE_VERSION');
        }
        const change = transform(beforeBytes);
        const bytes = Buffer.from(change.storage, 'utf8');
        if (bytes.length > maximum) throw new FsError('New file exceeds the exact-write byte bound', 'FS_TOO_LARGE');
        signal?.throwIfAborted();
        if (!binding.canWrite()) throw denied();
        const store = data => {
          let written = 0;
          while (written < data.length) {
            const count = writeSync(descriptor, data, written, data.length - written, written);
            if (!count) throw new Error('Exact-leaf write made no progress');
            written += count;
          }
          ftruncateSync(descriptor, data.length);
          fsyncSync(descriptor);
        };
        try { store(bytes); }
        catch (error) {
          // A handled I/O fault restores the bounded preimage on the SAME
          // descriptor. Process kill can interrupt an in-place write; no atomic
          // publication is claimed, and independent candidate review stays required.
          try { store(beforeBytes); }
          catch { throw new FsError('In-place write and preimage restoration failed; candidate is incomplete', 'FS_IO_ERROR', { cause: error }); }
          throw error;
        }
        return { version: version(fstatSync(descriptor, { bigint: true })), ...change.result };
      } catch (error) {
        if (error instanceof FsError) throw error;
        if (error?.name === 'AbortError') throw new FsError('File mutation aborted', 'FS_ABORTED');
        if (['EACCES', 'EPERM', 'EROFS', 'ELOOP', 'ENOENT'].includes(error?.code)) throw denied();
        throw new FsError('Exact-leaf mutation failed', 'FS_IO_ERROR', { cause: error });
      } finally { if (descriptor !== undefined) closeSync(descriptor); }
    }
    async writeText(target, content, expected, signal, policy) {
      return this.withExactLock(target.targetKey, () => this.mutate(target, expected, signal, policy, beforeBytes => {
        let before = null;
        if (beforeBytes.length < 10485760 && Buffer.byteLength(content) < 10485760) {
          try { before = normalize(decode(beforeBytes)); } catch { /* Native optional diff basis may be absent. */ }
        }
        return { storage: content, result: { operation: 'update', before, after: normalize(content) } };
      }));
    }
    async editText(target, edit, expected, signal, policy) {
      return this.withExactLock(target.targetKey, () => this.mutate(target, expected, signal, policy, beforeBytes => {
        const raw = decode(beforeBytes);
        const before = normalize(raw), old = normalize(edit.oldString), replacement = normalize(edit.newString);
        if (!old) throw new FsError('Edit search text must not be empty', 'FS_EDIT_NOT_FOUND');
        const parts = before.split(old), count = parts.length - 1;
        if (!count) throw new FsError('Edit search text was not found', 'FS_EDIT_NOT_FOUND');
        if (count > 1 && !edit.replaceAll) throw new FsError('Edit search text is ambiguous', 'FS_AMBIGUOUS_EDIT');
        const after = edit.replaceAll ? parts.join(replacement) : before.replace(old, () => replacement);
        const sample = raw.slice(0, 4096), crlf = sample.split('\r\n').length - 1;
        const lf = sample.split('\n').length - 1 - crlf;
        return { storage: crlf > lf ? after.replaceAll('\n', '\r\n') : after, result: { before, after } };
      }));
    }
  }
  await ctx.plugin(ExactLeafFileSystem);
}
