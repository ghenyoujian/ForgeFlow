# Standalone worker

For a required `forgeflow.physical-limits.v1` policy, admission freezes the root
plus the maximum concurrent native-child pool across all seven resource dimensions
in `bindings.physical_resources`. The Worker verifies its canonical hashes and
checked CPU conversion. Children borrow the already-held pool; disposal does not
shrink its static physical limits. Profiles without this policy retain explicit
`UNVERIFIED` physical status.

The dedicated user service uses `Delegate=cpu memory pids` and
`DelegateSubgroup=supervisor`. Its launcher discovers `ControlGroup`; the Worker
checks its own `/proc/self/cgroup`, UID and cgroup v2 mount before writing only
inside that private service. Each attempt/generation receives a new leaf with
finite `cpu.max`, `memory.max`, `pids.max`, zero `memory.swap.max` and group OOM.
The actual values are read back and the boot, mount, inode, reservation hash and
limits are durably bound into launch-authority v3. A preopened CLOEXEC
`cgroup.procs` FD attaches the child before exec. Required profiles also require
the frozen namespace/Landlock sandbox; authors cannot access writable host
cgroupfs or retain the attachment FD. Errors deny launch, without weaker fallback.

After real attachment and durable launch receipt, `sandbox.json` records physical
confirmation scoped to the **Worker author and inherited native descendants**.
This does not claim CPU or memory enforcement for API verification processes,
remote provider execution, GPU allocation or production DSH throughput. Stop
requires the original process fingerprint/group checks, child wait/reap and an
authenticated `cgroup.kill` followed by `populated 0`. `cgroup-fence.json`,
`cgroup-membership.json` and `cgroup-stop.json` retain raw limits and counters.
Restart rejects changed boot, inode, limits or uncertain population rather than
signalling an unrelated tree. A previously recorded positive same-boot stop can
remain completed after systemd removes the now-empty private leaf; only exact
ENOENT with the bound closure proof is accepted.

`forgeflow-worker --physical-resource-probe /private/probe.json` invokes that same
`supervise_physical` runtime with one pinned trusted finite helper. It requires
neither a Worker token nor API configuration, registers no Worker and starts no
models. Its `runtime-report.json` describes actual launch/stop, limit readback,
membership and raw counters; CPU throttling, fork denial and OOM are judged by
the separate bounded collector. This local proof does not qualify real DSH or
business admission.

`forgeflow-worker --config /absolute/worker.json` uses `FORGEFLOW_WORKER_TOKEN` for
bearer authentication. The token stays in the control client; supervised children
receive a cleared environment, approved PATH/LANG, dedicated HOME/DSH_HOME and only
explicit secret references. Secret bindings identify private regular files, never
inline secrets. API credentials and PostgreSQL credentials are not inherited.

Configuration fields are `control_url`, `worker_id`, `project_id`, `data_root`,
`profile` (the frozen `HeadlessProfile`), `model_route_id`, `secret_files` (reference
ID to `{env_name,path}`), `poll_seconds` (default 2), `max_log_bytes` (default 256MiB
per stdout/stderr stream), `max_active_attempts` (default 4, maximum 128), and
`controlled_workload_programs` (default empty map of executable to SHA256).
`strict_resource_handoff` defaults to false; `managed_dsh` defaults to absent.
`cgroup_delegation` is optional private deployment metadata with
`{unit_name,root_path}`, discovered from the actual dedicated user service. It is
mandatory whenever the frozen resource profile requires `physical_limits`.
The declared profile home is preserved exactly; changing it invalidates pinned
model/profile configuration. A durable project/profile marker prevents another
project from reusing the same mutable namespace. Registration declares the fixed
project and exact approved executor profile IDs; admission and scheduler selection
use these associations. Native launches compare the complete profile against the
immutable attempt binding snapshot, not just its display ID.

The single-node deployment shares `data_root` with the server. Artifacts served
by the control API are immutable, project-scoped and digest checked. Every attempt
uses a distinct branch/worktree from an explicitly managed **bare** repository;
`ExecutionEnvelope.workspace_root` identifies that repository. Input hashes are
verified before launching. Mandatory context files, including all manifest entries,
are checked against real worktree bytes; traversal and context symlinks are rejected.
Canonical `artifact_inputs` represent immutable source documents separately: their
project-scoped artifacts are downloaded, digest checked and stored in the private
context-artifact directory. Logical source names do not claim workspace files.

The worker independently registers, claims bounded concurrent attempts, renews
leases, polls cancellation and persists events/results. A lease watchdog continues
running while HTTP requests are delayed. Shutdown signals request child/group
termination and wait for settlement. Each uncertain attempt retains its local
capacity slot and the authoritative server allocation remains quarantined.
Completed author processes retain their slots and exact leases through verification
and integration; only canonical terminal state plus confirmed local quiescence
releases local capacity. Native results awaiting callback acknowledgement retry
after control-plane reconnect without launching another process.

Worker presence runs on a separate five-second heartbeat task, including during
startup reconciliation and shutdown drain. Its snapshot conservatively includes
unsettled durable attempts. A failed or more than fifteen-second-old presence
acknowledgement suspends new admission. Admission permits at most four claims per
poll and one in-flight claim; at most four settlement/retry jobs run concurrently,
with a rotating attempt cursor so failed low-ID reports cannot starve later ones.
An in-flight claim received during shutdown is durably settled without launch.
An identity-bound terminal result ACK plus a completed local stop journal frees
the predecessor's local slot immediately and wakes a normal claim, without
waiting for the next poll. The ACK is fsynced before this notification. Claim
remains the sole start delivery; the replacement envelope returned by handoff
does not bypass claim-before-effect, duplicate journals or the launch fence.
Task completion and observed terminal settlement also wake bounded maintenance
and refill immediately. Independent input files each retain file fsync and atomic
rename while writing concurrently with private Git preparation. After all file
writes in a batch settle, one fsync per parent directory makes their published
entries durable. Successful entries still complete this checkpoint if another
file fails; all file writes and directory checkpoints drain before any author can
launch or preparation failure is reported.
Fresh attempts freeze their envelope, execution UUID and result-delivery policy
in one `attempt-preparation.json` checkpoint with a schema and payload SHA256.
Create-new publication chooses one immutable authority even under duplicate
delivery. Its file and directory are fsynced before preparing or acknowledging
anything. `envelope.json`, `execution-id.json` and
`result-delivery-policy.json` are compatibility views of that authority; they
are validated on use, and missing views are reconstructed before restart
reconciliation. Existing changed view bytes, a changed envelope, a corrupt digest
or a replaced/symlinked authority are rejected and retained. Journals predating
the bundle keep their original formats and identities. The bundle grants no
process launch rights and is never counted as a live author or launch receipt.
The worktree record and STARTING outbox record retain their independent file
fsyncs, performed concurrently with one shared journal-directory checkpoint
before the final launch-control check.
One scoped `/workers/WORKER_ID/dispatch-events` stream watches committed terminal
and handoff facts for the registered project. Scoped cursor IDs bind project,
worker and original PostgreSQL event sequence. A terminal fact must match the
complete immutable attempt tuple and a completed actual local stop before the
worker fsyncs `controller-terminal.json` and wakes normal claim. The receipt
records its real current receive time; replay never rewrites that first observation.
Handoff wakes grant no release or launch rights. Late log replay runs independently
of this terminal notification, including the HTTP maintenance fallback. When
the stream disconnects, only post-author attempts receive a bounded four-job
250ms fallback; a healthy stream avoids per-attempt rapid polling. Preparation
carries its already-verified bundle result through input persistence, avoiding
two redundant bundle reads/restorations while retaining all input hash, private
Git, executable pin and final lease checks.
Live log/RUNNING event append retains file and directory fsync on the blocking
IO pool, so simultaneous author notifications do not occupy Tokio's dispatch and
renewal threads. Each controlled attempt still verifies the complete executable
SHA256; that independent read now overlaps immutable artifacts and private Git
preparation. Native Headless preparation retains all profile pins on the blocking
pool. No mutable controller state or executable verification result is cached.
Initial control, frozen binding validation, input downloads, private Git and
executable verification now prepare concurrently; every branch drains before a
failed preparation is acknowledged. A validated preparation bundle carries its
execution UUID only within that invocation, removing a duplicate compatibility
read. The final launch control remains fresh. `preparation-timing.json` records
monotonic phase times after the physical launch notification, adding no durable
checkpoint to the launch path.

Each admitted or restored generation has an independent five-second lease keeper.
It covers slow native event projection, final parsing, result replay, missing ACKs
and post-ACK controller verification/integration. Retention starts when the result
is durable, before publication; an ACK does not release its lease or capacity.
HTTP delays never extend the last observed lease deadline. Expiry, revocation,
the attempt deadline and shutdown interrupt renewal independently, and final
launch control refreshes the local fence before supervision starts. Restarted
journals restore lease observation concurrently before serial recovery publication.
The embedding `execute` entrypoint retains its signal ownership through settlement.

Per-attempt records are under `data_root/attempts/ATTEMPT_ID/`:

- `envelope.json`, `worktree.json`, prompt and context input;
- `execution-id.json` (distinct UUID), `launch.lock`, fsynced launch intent/receipt;
- `stdout.ndjson`, `stderr.log`, optional full `final.json`;
- `stop.json`, durable event outbox files and `result.json`.

The receipt records boot ID, PID, PGID, Linux process start ticks, attempt/operation
markers, the independently allocated execution UUID, command arguments and
environment **key names**, without secret values. Normalized native events retain
source, local receive sequence, stable receive time, completeness and an exact
local raw artifact reference; replay cannot rewrite these observations.
Raw logs are streamed into private files with fixed read buffers and bounded
notification queues. Notifications reference persisted offsets; overflows are
explicit and clients replay from the files. Native NDJSON projections are published
while execution runs; full finals remain on disk, including finals larger than the parser memory buffer
which are spooled and validated through a streaming JSON reader. Disk or parser-budget failures
stop execution and prevent complete-evidence claims.

Normal, failed and reconciled terminal results carry the complete existing
`launch-receipt.json` under `evidence.launch_receipt`, bound to their execution UUID
and immutable attempt identity. The same evidence can back `StopReceipt.evidence`;
its `execution_id` matches the receipt. Missing launch files leave this field absent.
Changed generation, worker, operation, execution UUID or process/intent boot identity
rejects the attachment. This preserves positive launch lineage when RUNNING event
publication was lost, without treating an unused reservation as a launched process.

Event append is local and durable before transport. Replay sends at most sixteen
events per batch, checking the two-second batch budget between requests. Issued
requests await the existing ten-second HTTP bound; four shared telemetry slots
prevent duplicate retry storms from starving independent control and renewal.
Delayed or lost acknowledgements
retain the original event IDs and bytes. Live projection processes at most sixteen
native records per poll and resumes unread records even after stdout reaches EOF.
The scheduled supervisor rechecks current authority before entering the runtime.

A successful process exit cannot mark a task successful. Native Headless must
also have the required native session, completed turn and complete final evidence.
All committed, staged, unstaged, ignored/untracked and renamed paths are audited by
the Git owner before submission. The result is execution evidence; successful
execution can enter `VERIFYING`. Independent verification and integration are
separate control-plane decisions.

# Strict terminal handoff

With `strict_resource_handoff: true`, negative terminal callbacks use
`POST /api/v1/attempts/ATTEMPT_ID/handoff-result` with the same `WorkerResult`
body and original event ID. A refused handoff, including an unavailable successor,
retains the durable callback, lease and local capacity. It cannot fall back to the
ordinary result endpoint. Passed execution still uses `execution-result` and
enters independent verification before controller finalization.

The attempt's `result-delivery-policy.json` freezes this choice before launch or
preparation failure. Changing worker configuration cannot change a retry's
transaction. Existing journals without that file retain their previous endpoint;
their result bytes and IDs are preserved.
`result-ack.json` retains the controller response and exact callback event ID.
A separate post-author-stop callback uses its own ACK file and cannot acknowledge
a different pending result. Failure, wrong identities and unconfirmed local stop
never free local capacity. These dispatch changes require actual launch receipts
to qualify the strict two-second successor grace; reservation and ACK alone do
not prove launch latency.

# Managed native DSH

`managed_dsh` opts into the pinned ForgeFlow composition and canonical child RPC:

```json
{
  "mode_id": "forgeflow-collaboration-v2",
  "mode_manifest": "/approved/mode.json",
  "preset_patch": "/approved/cordis.patch.yml",
  "bridge_plugin": "/approved/managed-bridge.mjs",
  "selected_model_config": "/approved/selected-model.json",
  "credentials": "/approved/.credentials.yaml",
  "doctor": "/approved/managed-doctor.json",
  "rpc_timeout_ms": 2000
}
```

Every referenced file, the native executable/entrypoint, and the native package
version must belong to the frozen `profile.artifact_pins`. The registered executor
has the original flat `HeadlessProfile` fields plus `kind: "DSH_MANAGED"` and
`native_mode` equal to this exact configuration. Legacy native registrations keep
their original shape. Managed mode requires the frozen strong sandbox; the mode
manifest uses `forgeflow.dsh-mode.v2` and bridge protocol
`forgeflow.dsh-bridge.v2`.

The selected model file is a JSON array with exactly two distinct rows,
`agent-default-model` and `llm-pi-ai`. The worker copies only these rows and the
pinned credential file into a fresh attempt home. It adds the approved native
profile package, then invokes the existing native CLI with the supported preset
and bridge `--patch` arguments before `--json -`. Personal configuration is never
modified or imported into the attempt home.

`managed_dsh.model_relay` selects the strict model transport:

```json
{
  "schema_version": "forgeflow.model-uds.v1",
  "transport_loader": "/approved/model-transport.mjs",
  "sdk_origin": "http://forgeflow-model.invalid",
  "max_request_bytes": 8388608,
  "response_idle_timeout_ms": 30000
}
```

This option is included in the exact frozen executor registration. It requires
the frozen sandbox's `network_allowed: false`, the pinned Node preloader, no
child secret references, and a pinned credentials JSON document containing only
`{"version":1,"refs":{"FORGEFLOW_MODEL_RELAY_DUMMY":"forgeflow-relay-no-provider-secret"}}`.
The approved selected route must explicitly name one Anthropic Messages model.
Worker derives a fresh single-provider native configuration with that model,
the synthetic origin, SSE transport and dummy credential. The actual provider
key remains in the server gateway. Provider credential files and their parent
directories cannot be exposed as sandbox readonly mounts.

Node imports the readonly loader before the unchanged native CLI. The bridge's
live canonical model grant supplies the request context. The stock provider SDK
continues to form Anthropic requests and parse response/usage events; its fetch
transport crosses `/tmp/forgeflow/model.sock`. Bash, PTC, web tools and descendants
share the isolated network namespace. Ambient IP connections have no permitted
route; the only external model path is the exact private relay socket and fixed
authenticated gateway endpoint. The synthetic URL is never resolved or used as
an external destination. Native model HTTP headers cannot forward credentials,
another URL, or the Worker's authentication token.

The UDS request is a big-endian four-byte JSON metadata length (maximum64KiB),
that metadata, then exactly the declared body bytes (maximum8MiB). Metadata binds
project/task/attempt/generation, native session/allocation, request/grant UUIDs,
provider/model/output cap and the SHA256 of the raw Anthropic JSON. Only streaming
`POST /v1/messages` at the synthetic origin is accepted. The Worker posts those
same body bytes to `/api/v1/attempts/ATTEMPT_ID/native-model?project_id=PROJECT`.
The server independently hashes them and atomically consumes the existing native
grant before any upstream connection. It reuses the already charged native
request rather than making a second budget admission. Replay never reconnects.

Response metadata records the actual status and allowlisted protocol/rate headers.
Four-byte lengths precede raw chunks up to64KiB; a zero length means complete
HTTP transport. Premature EOF, idle expiry and native cancellation close the
upstream response and remain conservative. Sixteen bounded connection tasks
provide streaming backpressure. The relay listener and tasks are closed and
joined after author supervision settles and before whole-attempt stop publication;
`model-relay-stop.json` records transport facts and never attests provider stop.
Canonical gateway observations protect model settlement independently of native
usage reports. The independent authority retains interrupted or uncertain model
work even after the author process stops.

Omitting `model_relay` preserves the historical direct-observed profile's JSON
shape and behavior. That legacy mode remains unqualified for complete model
egress coverage. Implementing strict transport does not manufacture a coverage
receipt: exact native SDK, ordinary tool denial and canonical grant/stream evidence
must qualify the selected profile before it claims `gateway_enforced`.

The immutable doctor receipt has schema `forgeflow.managed-doctor.v1`,
`mode_id`, `executor_profile_id`, `native_profile`, `bridge_schema_version`,
`exit_code: 0`, a 64-character `composition_sha256`, `runtime_package` (an absolute
pinned package JSON path), `runtime_version` equal to that package's version, and
`artifact_sha256` mapping canonical paths to every frozen artifact digest except
the doctor file itself. This receipt must come from the actual matching native
configuration resolution; file pins or a fabricated receipt do not qualify a
managed workload.

Each attempt has a private 0700 RPC directory and 0600 Unix socket. Its complete
host pathname must fit 100 bytes, so use a short data root. The sandbox mounts only
that socket inode at `/tmp/forgeflow/controller.sock` and exact immutable mode
files at fixed aliases in a separate readonly mount. Neither the socket parent nor
the worker journal is exposed. Native profile scratch, sessions and storages are
private to the attempt; package/model/credential/patch choices remain readonly.

The relay accepts one RPCv2 line per connection, at most 64KiB per request/reply,
sixteen concurrent exchanges, and a configured 1ms–5s total exchange deadline.
Every request carries an exact project/task/attempt/generation identity and a
UUID `rpc_id`. Transport retries reuse it and the original request; changed
payloads with the same ID are rejected. The bearer token remains in the worker
control client. Canonical `/native-controller` issues every allocation and model
grant; the relay never grants locally or falls back to a qualification ledger.
Native `root_release`, revocation and process-stop RPC operations are forbidden.

After independent supervisor stop, the worker closes native access and delivers
the original bound launch receipt and stop evidence through its result callback.
Canonical stop closure releases only the proven root lifecycle; unknown native
streams and child reservations remain retained or quarantined. Restart never
rebinds or adopts a journal's old socket, and PID absence alone cannot release
allocation. Real canonical collaboration, complete model egress coverage,
financial accounting and large-scale native qualification still require their
separate actual evidence.

# Controlled capacity workload

The controlled workload is explicitly distinct from DSH qualification. Set the
executor profile to `controlled-lightweight.v1`, include an approved `command`
(program and argument array), use `max_model_requests: 0`, and omit
`REQUEST_APPROVED_MODEL`. The absolute executable must match its configured SHA256.
No shell string is constructed. The frozen registered controlled executor must
match `{id,kind:"CONTROLLED_LIGHTWEIGHT",approved_programs}`; its exact allowlist
map is compared with worker configuration before launching. Results carry `real_dsh: false`,
`executor_kind: CONTROLLED_LIGHTWEIGHT` and
`transcript_completeness: CONTROLLED_LIGHTWEIGHT_STDIO_NOT_DSH`.
Passing these workloads proves supervised control behavior; it does not prove
model-provider capacity or real DSH sessions.

# Recovery and limitations

On restart, receipts are reconciled against the current kernel boot and process
fingerprint. A matched prior process group is stopped because this adapter does
not adopt a live native runtime. Missing receipts, uncertain process identities
and escaped live descendants remain quarantined. Missing receipts never justify
relaunch. Repeated delivery replays existing records and cannot change the
immutable envelope. Never unlink launch locks or reuse an old attempt worktree to
force a retry: acquire a new attempt through authoritative admission.

Process groups and linked worktrees implement a **local trusted execution**
profile. They do not provide a hostile-code container or cgroup CPU/memory fence.
Escaped descendants retain quarantine until explicitly reconciled. Multi-host
artifact/log transfer is not implemented; the current deployment uses shared
single-node storage. Native sessions require the pinned DSH home to be retained.
Platform native resume/adoption is explicitly unsupported for fresh attempt
worktrees; qualified upstream `--session-id` support is separate. A configuration
snapshot and executable checksum alone do not prove gateway
coverage; that requires the executor's separate qualified coverage receipt.
