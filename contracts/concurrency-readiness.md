# Persistent Agent contexts and bounded activation

`forgeflow.context-campaign.v1` describes independent persistent contexts and a
finite activation campaign; it is not an execution grant. PostgreSQL remains the
sole authority for attempts, leases, native lifecycles, model requests and resources.

The default pool has128contexts. Context population is independent of the hard
active limit, selected from **1/4/10/32/64**, default32. Supported lower tiers run
in order, then bounded batches cover every context exactly once. There is no
requirement to run128Agents simultaneously or keep them alive for an hour.

`documents/agent_contexts` uses `forgeflow.agent-context.v1`: project_id,
context_id, position_id, model_route_id, immutable input_manifest_ref/prompt_ref,
and append-only history_refs. Every reference binds an existing artifact from
that exact project by SHA256. Identity/base changes, history truncation, foreign
artifacts and runtime/grant fields are rejected. Existing revision CAS applies.
These descriptors are data only; dormant contexts do not acquire leases, slots,
processes or model grants. Context contents are materialized only for activation.
Logical context replay creates a newly admitted native session; it does not claim
unsupported reuse of a prior native session ID or bypass a new approved task.

Preparation binds each context to a distinct roster position, input artifact,
manifest, prompt and task read set. Dedicated project/global/team active_slot
policies cap actual admissions at the selected limit; Worker capacity and native
workflow limits are configured separately from roster size. Native child pools
are disabled for this root-Agent campaign. Every task reserves finite CPU,
memory, process and provider capacity; selecting64does not waive hardware checks.

The manifest binds a fresh ff_concurrency_* database, private data root, actual
listening Core PID/start/boot/executable and exact binaries/configurations. Main
8787, DSH3080, provider17891 and remote control origins are refused. No production
credentials or database are implicitly selected. Commands use authenticated
canonical APIs, stable idempotency keys and expected revisions. Preparation
creates a non-executable typed planning catalog and approved finite Flow while
paused; it does not queue or call models.

Shared Worker profile_ref/managed_dsh_ref pins expand into the existing immutable
WorkerConfig. Inline plus reference, changed hashes, noncanonical paths and
unbounded JSON are refused. Runtime/SDK dependencies and profile bytes are shared;
128contexts do not imply128runtime installations or128resident Workers.

Live roots require a RUNNING attempt, exact durable launch receipt, distinct
alive PID/start/boot identities and matching cgroup membership/inode/CPU/memory/
PID readbacks. A qualified activation additionally requires a root native
lifecycle and a dispatched conversation request with successful trusted transport,
nonzero bytes and settled nonzero usage. Positions, allocations, grants and
ADMITTED requests alone never count. Completed short tasks can count as historical
activations; the tool reports them separately from currently alive processes.
Public snapshots expose bounded transport metadata, never bodies or credentials.

Each batch records physical observations, model results, context coverage and
peak active processes. Same native session IDs across independent contexts,
failed/recovery attempts, unknown usage, over-allocation, stale quota evidence,
request budget excess or state-query P95 above500ms block/fail execution.
API timing and browser rendering timing remain separate measurements.

After each batch: pause dispatch, cancel unfinished attempts through the original
API and confirm authoritative drain before activating another batch. Unknown
usage and unconfirmed resources remain held. No SQL cleanup or direct author kill.
Append a checkpoint of original authority metadata to each used context; preserve
its base inputs and earlier history. `agent-context.py` exports exact pinned input
and history data without activating any process or granting execution.

Provider billing reconciliation requires exact settled request population,
provider request IDs, finite nonnegative observed USD and original source digest.
It never changes custody or awards G20. Preflight and context activation results
do not award the historical100+simultaneous G20; that is outside the revised user
scope. Actual artifact verification, Git integration and native same-session
resume qualification remain separately evidenced.

Before actual activation, `concurrency-environment.py delegate` reopens only the paused/drained dedicated database on an installed, pinned Core using a fresh private systemd service and the existing verifier launcher. It never enables autostart. The emitted environment/campaign pins bind the new PID and binary; original receipts remain. Preflight requires actual verifier supervisor membership, empty owned cgroup interior and CPU/memory/pids controllers; a raw preparation Core cannot pass that check. Fleet up additionally verifies canonical Worker registration via the existing authenticated read-only dispatch stream, rather than counting a PID as readiness.

After drain, native context checkpoints also retain original DSH session JSONL (plain or zstd), selected only from the exact Worker-prepared managed home and authority root session IDs. The frozen Node binary performs bounded zstd decoding. Foreign IDs, aliases, absent/corrupt history and size overflow fail closed; configuration/credential files are excluded. Chunked immutable history preserves original message/tool events for logical replay, rather than replacing conversation memory with usage metadata. Codec/byte fixtures prove retention logic only; actual model-backed capture and native restore remain unqualified.
