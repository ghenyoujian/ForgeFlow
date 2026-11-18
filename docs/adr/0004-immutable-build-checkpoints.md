# Build inputs and running artifact identity

A00 runs Cargo through `python3 team/build_checkpoint.py` in one coordinated build
slot. Each invocation must name actual work. Use `--check --check-packages
forgeflow-store` for a compile check, `--targeted-test
forgeflow-store:native_configuration` for an impacted integration test, or
`--postgres-target forgeflow-store:authority --database-env /private/runtime.json`
for an impacted ignored PostgreSQL test. Tests build only their own Cargo targets;
they no longer prepend a full workspace binary build. `--build-bins
forgeflow-worker` explicitly packages one binary; `--build` explicitly packages all
four deployment binaries. `--test` remains available for a deliberate broader
suite. Invalid operation combinations are rejected before checkpoint creation.

The helper inventories workspace manifests, lock, crate sources and tests,
migrations, contracts and `.cargo` settings; copies them to native Linux storage;
and checks the original and copied inventories before Cargo. Generated
qualification, target, node_modules and Git directories are pruned before traversal.
A changed inventory refuses the build. The compiler reads a stable Linux source
path under the shared build lock, synchronized to the frozen checkpoint; unchanged
files retain mtimes, so a new checkpoint path does not force a dependency rebuild.
Snapshot and compiler-source hashes are checked after every Cargo command,
including failing test and check commands.

Both the workspace Cargo configuration and helper use the same Linux target cache
(`/home/chenyoujian/.cache/forgeflow-control-target`) with two jobs. Development and
test profiles disable debug information and incremental compilation, and strip
debug information from linked output. This trades some edit/rebuild CPU time for
less persistent disk use; line-level debugger information requires a separately
reviewed explicit profile override. It does not change release optimization policy.

The rebuildable target has a **2 GiB before/after-invocation budget**, measured in
allocated filesystem bytes with hardlinks counted once within that tree. It is not
a limit on transient compilation peaks. If the target exceeds this budget, the
helper checks process working directories, executables, open descriptors, mapped
files and other Cargo/Rust compiler processes, and acquires Cargo target locks.
Active references, unreadable same-user processes, symbolic links or busy Cargo
locks prevent retirement. An over-budget protected cache blocks a new build;
post-build protection is reported without altering the original Cargo result.
Only rebuildable target files are removed, keeping Cargo lock inodes in place.
Receipts record before/after allocated bytes and the actual difference. No source,
pinned deployment, database, receipt or test log is treated as build cache.

Successful explicitly requested binaries are copied out of the mutable target and
made read-only. An existing checkpoint binary can be reused by hardlink only after
verifying its recorded SHA256, actual content, read-only mode and independence from
the mutable target. The target itself is never hardlinked into a checkpoint.
Otherwise a new independent copy is frozen and checked against the original hash.
Servers and Workers run from these frozen paths, not mutable target output.

After successful or failed Cargo work, the helper calls the referenced-aware
checkpoint maintenance routine in the same process while holding the build lock.
It retains the latest three live checkpoint payloads, active/referenced payloads
and the stable compiler source. Older unreferenced source/binary payloads are
archived using the storage maintenance archive; their original receipt and command
logs stay in place. Failure to establish references prevents retirement and is
reported separately. Maintenance never upgrades build qualification or hides the
original command failure. See `docs/STORAGE_MAINTENANCE.zh-CN.md` for restore and
retention procedures.

The receipt records source identity, each input digest, exact commands, exit codes,
logs, output digests, pin reuse and maintenance results. Frozen copies are an
operational convention, not a security boundary against the same operating-system
user; recheck hashes before loading. This receipt covers Rust compilation inputs
only. It excludes frontend builds, deployment qualification, credentials and
mutable native DSH qualification artifacts, which have separate identities and
evidence. Build success grants no Gate. Test failures and unexecuted PostgreSQL
checks remain explicit.

Refreshing an existing control server requires authoritative checks for open
attempts, retained resource allocations and unresolved merge decisions. Record the
actual loaded executable through `/proc/PID/exe`, since replacing a target binary
does not replace a running process. Request graceful shutdown, poll that same PID
until it is absent, and start the pinned replacement. Restore prior dispatch pause
settings only through revisioned authoritative commands. Concurrently changed
revisions require review; never overwrite them with an old snapshot.
