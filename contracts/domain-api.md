# Canonical public contract v0.1 candidate

Rust authority: `crates/domain/src/model.rs`, `execution.rs`, `commands.rs`. ExecutionEnvelope is verbatim design §13.3 with schema version `forgeflow.execution.v1`; no duplicate envelope or alias fields. IDs are strings; ordinary domain states serialize uppercase; ModelBudgetMode serializes snake_case. Times in envelopes are RFC3339 strings; persisted domain dates are UTC chrono values.

`forgeflow-store::Store`: `connect(&str)`, `migrate()`, `pool()`. PostgreSQL is authority. HTTP handlers use `execute_command(CommandIdentity,CatalogCommand) -> CommandResult` for catalog writes, `admit`, `cancel` for execution commands. Generic documents cannot alter Attempt, Lease, Gate, allocation, or grant FROZEN contracts.

Typed queries: list_projects, get_project(project), list_requirements(project), list_teams(project), list_tasks(project), get_task(project,task), list_flows(project), get_flow(project,flow_revision), list_attempts(project), get_attempt(project,attempt), resource_policies(project), list_evidence(project), events(project,after,limit), list_documents(project,collection), get_document(project,collection,id). All methods async return Store Result.

CatalogCommand: CreateProject, UpdateProject{project,expected_revision}, CreateRequirement, UpdateRequirement{requirement,expected_revision}, CreateTeam, PutFlow{flow,expected_revision,context:Option<Value>}, PutResourcePolicy{policy,expected_revision}, PutDocument{project_id,collection,id,expected_revision,value}. Catalog identity actor_id and idempotency_key map atomically to stable operation_id. Revision None means create only. Committed flows immutable; semantic task edits require a new task_revision. Context is persisted atomically with the flow. Generic collections currently sources, contracts, contract_versions, schedules, milestones, findings, artifacts, flow_contexts, operations.

AdmissionRequest fields in commands.rs are the frozen input preflight. The Store fills operation/attempt/lease IDs, generation, worker ID, issued/expires timestamps in the envelope. Caller envelopes must include immutable resolved configuration and a task deadline. AdmissionReceipt includes the authoritative envelope; only that envelope may be dispatched. Resource requests always count active_slot >= 1, ancestor resource policies and owner pause apply, unknown remaining process allocations remain occupied. No normal transition may mark SUCCEEDED; merge confirmation or read-only evidence closure owns success.

TransitionRequest requires expected_state, worker_id and generation. `AttemptState::can_transition` is the ordinary table from §11.2. Cancellation and unknown-result recovery are explicit domain commands (§11.3/13.7), so they can revoke from phases outside ordinary transitions. STARTING blocks duplicate starts. STOPPING and RECOVERY_REQUIRED retain resources until stop evidence. Cancellation after COMMIT_DECIDED reports COMMIT_IN_PROGRESS; after success reports ALREADY_COMMITTED.

Worker endpoints use WorkerRegisterRequest, WorkerHeartbeatRequest, WorkerEvent and WorkerResult. Lease heartbeat is a separate HeartbeatRequest. claim returns an optional authoritative ExecutionEnvelope and records STARTING before delivering it. Replaying a start is safe only when the Worker durable supervisor uses operation_id. Exit zero is not accepted as success.

Integration: prepare_merge(MergeIntent), decide_merge(project,intent,expected_revision), confirm_merge(project,intent,integrated_sha,receipt), get_merge_intent(project,intent), pending_merges(project,target_ref). Unresolved intent uniqueness is enforced per project/ref. EvidenceReceipt includes detailed scope in details and must bind task revision/base SHA/source/environment/test denominator/oracle. Receipt/intent identity cannot be overwritten.

Qualification: interfaces are implementation contracts, not evidence of passed G1/G2 or production capacity. All acceptance gates remain INCONCLUSIVE until actual tests prove their required scope.

## Implemented additions and authority rules

The actual source types remain canonical when reviewing this candidate. Catalog commands additionally include `ImportRequirements`, `UpdateTeam`, `CommitFlow`, `EnqueueTask`, `ChangeQueuePriority`, `PutArtifact`, and `RegisterInputSnapshots` (exact fields in commands.rs). `CommitFlow` receives stable IDs/revision/approval, then loads and freezes current authority in one idempotent transaction; the API does not recompute a different retry request after a successful commit. Generic queue writes are restricted to internal scheduler identity. Execution profiles, model routes, resource profiles, and verification plans are append-only by ID.

ResourcePolicy includes optional `worker_id`. Worker scopes are global machine scopes (`project_id` and `team_id` null); project/team scopes never carry worker_id. Admission requires explicit global, project, worker, and every team ancestor scope. Lowering limits permits draining existing allocations; new positive reservations cannot increase an exhausted dimension. All scopes use the same transaction lock order. Model permits still ADMITTED or QUARANTINED prevent resource release until request reconciliation.

Admission requires the exact owner-approved task envelope, authoritative repository root equal to Project.root_path, live registered worker, and registered immutable executor/resource/route/verification profile snapshots. The verification plan must bind task revision/input hash and author/consumer/independent commands. `attempt_bindings(project,attempt)` returns the immutable resolved executor_profile, resource_profile, model_route and verification_plan objects for Worker comparison. This is supplemental snapshot data; the ExecutionEnvelope remains §13.3 verbatim.

New admissions store the complete executor profile once in `frozen_executor_profiles`,
keyed by `(project_id, sha256)`. The hash covers UTF-8 compact JSON
`["forgeflow.frozen-executor-profile.v1", recursively-key-sorted-profile]`, with
array order preserved and the already excluded document `revision` still excluded.
`attempts.executor_profile_sha256` is an immutable same-project foreign key;
referenced attempts omit only `execution_bindings.executor_profile` on disk.
Object UPDATE/DELETE/TRUNCATE, reference rebinding and simultaneous inline/reference
representations are rejected. Object insertion, exact conflict verification and
Attempt admission commit in the same transaction. There is no automatic GC.

The Store resolver verifies the complete content hash and admitted executor ID,
then restores the original full JSON shape. Worker profile equality and retained
source binding hashes therefore keep their existing inputs. Missing or corrupt
objects fail closed; mutable/current profile documents never serve as a fallback.
Legacy inline attempts remain readable without backfill or resealing. Public
snapshots project only the existing public metadata, once per shared object;
private executor configuration is not included. A Core rollback must retain a
reader that supports these references; the Worker API and ExecutionEnvelope have
no new fields.

Task input and Flow approval use versioned algorithms in planner. The task input digest excludes Flow revision and derived prompt bytes. Flow approval includes static rendered execution-template identity. Dynamic operation/lease/attempt/generation/worker/issued/expires/trace/request identities are excluded from the static template digest. Equivalent active tasks can appear in a newer approved Flow only after exact task/source/input/territory/dependency/contract/template checks; the original Attempt still resolves its original `task_revisions`/Flow context. Changing an active contract requires explicit stop/finish, and omitted cards are removed from the current plan while history remains. Older committed Flow lifecycle becomes SUPERSEDED; its approved content/context cannot be overwritten. Historical digests are not silently resealed.

New merge intent lifecycle is PREPARED → COMMIT_DECIDED → REF_UPDATED → FINALIZED, with separate durable events. `mark_ref_updated` proves actual target-ref reachability and independent receipt identity; `finalize_merge` closes Attempt and allocations. `confirm_merge` remains a compatibility wrapper around those two transactions. Legacy COMMITTED records decode as historical final records, and are never rewritten. Irreversible stage markers survive RECOVERY_REQUIRED; recovery cannot reapply a ref CAS once REF_UPDATED was recorded. `abort_merge` is only valid before COMMIT_DECIDED.

A trusted Worker execution-result callback in STOPPING or RECOVERY_REQUIRED must still validate exact Attempt/lease/worker/generation and required frozen physical stop evidence. If an irreversible merge decision exists (including a retained `receipt.commit_decided` marker on a RECOVERY_REQUIRED intent), the callback records the author-stop result and event once, leaves the Attempt RECOVERY_REQUIRED without a terminal timestamp, and preserves root/native resource custody and lease state for Owner merge recovery. Author termination cannot cancel this decision or substitute for merge finalization. Exact event replay does not change revision or release resources; conflicting event reuse remains rejected.

Code evidence details contain a full VerificationReceipt; read-only STRUCTURED_ARTIFACT details contain ArtifactVerificationReceipt, with no synthetic Git fields. Both bind registered plan, exact argv, source/input identity, real artifact bytes and the trusted runner's durable `verification-receipt.json`; the denominator equals registered exact cases. The code ArtifactRef points to raw log; the read-only ArtifactRef points to the produced structured artifact. Raw logs remain confined to the frozen artifact prefix and their operation directory. `complete_read_only` requires reviewed read-only purpose and bound artifact receipt. Contract freezing additionally requires producer final integration/source identity and each exact required consumer receipt; it writes relational consumer records.

ContextManifest artifact content is described by `context-manifest.schema.json`: repository files and optional controlled artifact_inputs, each with pinned hash. Logical artifacts do not fabricate files in a project worktree.

Schedule documents are append-only proposals by schedule_id and baseline_version; predecessor and latest successor dates must remain compatible with the task DAG. The schedule_baselines collection is derived immutable history. Milestone changes increment baseline_version, preserve milestone_baselines, and a changed due_at requires change_reason. Planned dates are serialized UTC independently of Attempt runtime facts. Decision records are persisted scoped proposals; no generic document grants execution or Gate authority.

`paginated_catalog(project,collection,after,limit)` returns `Page<Value>` with max500 and next_cursor. Project scope is mandatory except the project list. Full `snapshot(project)` is an explicitly requested REPEATABLE READ authority audit snapshot with revision/as_of, attempts/leases/allocations/limits; it is not a dashboard pagination shortcut.

## Validation scope

An actual PostgreSQL16 run of `cargo test -p forgeflow-store --test authority -- --ignored --nocapture` proved the initial atomic admission/fencing/quarantine scenario (12 duplicate submissions, 5 competing tasks under capacity2, claim replay, cancellation retention, stop/release idempotence and forced expiry). Later profile/source/merge/replan hardening and a second active replan test require another scope-matched run. Migrations0001 remains checksum frozen; new changes append0002–0006. These facts do not prove G2, six business chains, 128 channels, process isolation, production model concurrency, or failure recovery beyond the specific tested scenarios.
# Request capacity

`POST /api/v1/projects/{project}/flow-revisions` accepts JSON bodies up to 32 MiB,
including the Flow and its compile context. Larger requests return HTTP 413.
Other JSON routes retain the default 2 MiB limit. This capacity increase preserves
authentication, revision checks, dependency validation and resource admission.

Worker dispatch observations are committed read models, never execution envelopes. The scoped fact tuple and local completed process must both match before a Worker durably acknowledges an observed terminal state and refills its local capacity. Event replay and cursor messages only wake processing; Store claim remains the sole transition into STARTING, and durable launch authority remains mandatory.

## Native model dispatch once

`forgeflow_store::native_model_dispatch::NativeModelDispatchRequest` contains
`project_id`, `attempt_id`, `generation:i64`, `worker_id`, `native_session_id`,
`allocation_id`, `request_id`, `request_grant_id`, `route_id`, `provider`, `model`,
`max_output_tokens:u64`, and lowercase 64-character `body_sha256`.
`Store::consume_native_dispatch(request)` is a trusted Gateway operation before
any upstream DNS/socket/HTTP operation. The server supplies authenticated Worker
identity and hashes the exact forwarded body bytes. It validates the current
lease/fence, claimed active parent, unpaused project/team, complete held native
ancestry, immutable Attempt envelope/route, and exact existing ADMITTED grant.

The transaction sets `native_model_requests.dispatched_at` and
`dispatch_body_sha256` once and emits `native_model.dispatched`. It never inserts
another request or `model_request_permit`, changes admission counters, or changes
the original idempotency request JSON. Its receipt includes the validated request
fields, lease/operation identity, committed UTC dispatch time, and immutable
`execution_bindings.model_route` snapshot. Gateway routing uses trusted server
configuration and secrets; a caller-supplied upstream URL has no authority.

Any second consumption, including identical replay after a disconnect, is denied
with `NATIVE_DISPATCH_ALREADY_CONSUMED`. A crash between consumption and connect
retains the admitted request as uncertain and cannot authorize another connect.
Existing native settlement retains its original request/grant identity. Native
admission accepts the existing `gateway_enforced` mode subject to the frozen
envelope's required coverage receipt; `direct_observed` remains weaker legacy
accounting. This interface alone proves neither coverage nor financial usage.

`Store::record_native_transport_observation(NativeModelTransportObservation)` is
trusted server cleanup after the upstream stream was dropped/drained. Its fields
are the original project/attempt/generation/Worker/native session/allocation/
request/grant identities, `body_sha256`, `outcome`, `upstream_status:Option<u16>`,
`received_bytes:u64`, optional `usage:Value`, and `usage_complete:bool` (default
false). Only `RESPONSE_BODY_COMPLETED` with actual EOF/provider completion or
`RESPONSE_INTERRUPTED` for uncertainty is accepted. Cleanup can arrive after
lease revocation, but must match the exact consumed request and body hash.
Observations are immutable; exact replay does not emit another event.

The nullable `dispatch_transport_settlement` is independent of native bridge
settlement. A dispatched grant cannot accept `model_settle` until this trusted
closure exists (`NATIVE_TRANSPORT_PENDING`). Interruptions use existing
QUARANTINED custody and revoke the native lifecycle, preserving allocations.
Complete transport alone never releases budget. For dispatched grants, settlement
uses proxy-observed canonical numeric usage (`inputTokens`, `outputTokens`, optional
cache/reasoning/total counters) and its trusted completeness flag instead of native
caller usage claims. Missing usage remains unknown and conservatively quarantined;
provider/SDK JSON spelling differences are not treated as identical provenance.
No new Attempt/native/model states or envelope fields are introduced.

## Required physical resource reservation (v1)

An immutable `resource_profiles` document may contain `physical_limits` with typed
`PhysicalLimitsPolicy`: `schema_version="forgeflow.physical-limits.v1"`,
`required=true`, positive `cpu_units_per_cpu <= i64::MAX`, `period_us` in
1000..1000000, `pids_max` in 1..65536, `swap_max_bytes=0`, and
`memory_oom_group=true`. Presence requires this exact policy; null, false, malformed,
or unknown fields fail closed. Absence preserves legacy separately charged native
children and grants no physical enforcement qualification.

Admission freezes `execution_bindings.physical_resources: PhysicalResourceBinding`
with schema `forgeflow.physical-reservation.v1`, accounting mode
`UPFRONT_NATIVE_POOL`, `resource_profile_id`, `root_resources`,
`native_child_resources`, `max_concurrent_children`, `reserved_resources`,
`physical_limits`, `cpu_quota_us`, `memory_max_bytes`,
`physical_limits_sha256`, and `reservation_sha256`. For an enabled frozen
native policy, concurrent children are `max_live_agents-1` (the root counts as an
Agent); otherwise they are zero. The complete seven-dimensional reservation is
`root_resources + max_concurrent_children * native_child_resources`, with checked
multiplication/addition and every resulting dimension at most `i64::MAX`.
Each distinct global/project/Owner-root/team ancestor/Worker scope reserves that
same vector in the original admission transaction; replicated ancestor rows are
never summed to infer additional capacity. A root must have positive CPU and
memory. CPU quota is exactly `reserved.cpu_units * period_us / cpu_units_per_cpu`:
checked product, exact divisibility, quota 1000..i64::MAX. Memory max is the
positive reserved memory bytes. Zero-child physical policies use the same mode.

Public domain helpers are `ResourceVector::checked_pool`,
`PhysicalLimitsPolicy::{validate,hash_payload,digest}`, and
`PhysicalResourceBinding::{new,validate,hash_payload,digest,verify}`.
`new(profile_id,root,child,count,policy)` derives the reservation and hashes;
`verify` recomputes all arithmetic, limits, and hashes. Policy SHA256 uses compact
typed-struct JSON in definition field order. Reservation SHA256 uses compact JSON
from the typed binding converted to `serde_json::Value` (lexicographic object keys)
with `reservation_sha256` removed. Consumers use these helpers rather than their
own serialization assumptions. Worker compares the binding to the frozen profile
and native policy, enforces an attempt-owned delegated cgroup leaf containing the
root and all native descendants, and rejects missing enforcement/weak sandbox or
writable cgroup filesystem when required. Launch rights do not derive from mutable
current Task data. The policy's presence alone does not prove OS enforcement.

New physical native admissions return `resource_accounting="UPFRONT_NATIVE_POOL"`,
`physical_reservation_sha256`, and the exact borrowed root/child vector. Children
borrow within the immutable held pool while existing lineage, depth, lifecycle,
model request and live-Agent guards remain in force. All non-RELEASED child
lifecycles retain a loan, including disposed but unsettled/quarantined children.
No `native_child_allocations` rows or second ancestor charges are created for these
loans. Child disposal never shrinks the parent pool. The existing
`borrowed_parent_reservation` column stays root-only; a child disposal cannot replace
trusted parent process stop. Cancellation, expiry, unknown children, outstanding
model calls or verifiers retain the entire pool until original stop/settlement
requirements permit the parent release. Legacy policies retain their old child
allocation/release path. Existing profiles/attempts/history are not backfilled.

`crates/store/tests/physical_resources.rs` contains one live PostgreSQL target for
complete-vector capacity, atomic failure, admission/native replay and fencing,
loan limits, retained capacity through child disposal and unsettled model requests,
parent stop gating and exactly-once release. It uses authority fixtures without OS
launches or upstream model calls. Its results do not establish actual cgroup
fencing, real DSH/native Agent qualification, financial budgets, or 100-Agent scale.

Required physical parent stop additionally validates trusted Worker
`evidence.physical_fence` (`forgeflow.cgroup-fence.v1`) against the frozen pool SHA,
profile-derived limits, project/Attempt/generation, execution and launch
intent/process boot identity. Fence SHA is recomputed from compact JSON with
`identity_sha256` removed. `evidence.physical_stop` (`forgeflow.cgroup-stop.v1`) must
match identity SHA, boot and leaf inode, contain explicit `populated=false` and
`process_exit_confirmed=true`, and retain raw snapshot `cgroup.events` with exactly
one `populated 0` line plus empty `cgroup.procs`. Missing/read-failed/contradictory
proof denies stop/release. When RUNNING was durably recorded, the original launch
receipt must match. WorkerResult outcome execution ID must also match. Durable
matching positive stop remains acceptable after empty cgroup/unit deletion; the
Store does not reinterpret filesystem ENOENT as a new positive stop proof.
A journal-confirmed never-launched closure uses `never_launched=true`, the original
bound `launch_intent`, no launch receipt, and the same positive empty physical
fence proof; recorded RUNNING forbids that branch. It does not qualify enforced
execution. Canonical never-dispatched cancellation remains its separate no-effect
proof. These facts trust the registered Worker's scoped kernel observations;
PostgreSQL does not independently prove remote hardware. The single PG fixture
labels its positive physical-stop DTO synthetic/trusted, with no actual OS launch,
and rejects missing proof, bad hash/generation/execution/limits, populated state,
and nonempty raw process membership without releasing any capacity.

Only successful validation of this required frozen whole-attempt physical stop
allows the stop transaction to record `process_stopped_at` on every non-released
native lifecycle with the exact Attempt, generation and Worker identity. This
closes orphan children whose native disposal callback was lost during a crash.
A child then requires its own native disposal or this validated whole-pool stop;
the borrowed root always requires trusted process stop. Closure proceeds from
children to ancestors only after every descendant has released and no associated
model request remains `ADMITTED` or `QUARANTINED`. Unknown/incomplete model usage
still retains capacity even when the physical group is empty. No caller boolean,
field presence, PID absence or legacy parent-only stop grants descendant closure.
Legacy profiles retain their independent native disposal requirement. The same
predicate applies to explicit stop receipts and both WorkerResult paths; rejected
transactions roll back all lifecycle and resource mutations.

For a required physical profile, a trusted `VERIFIER_PROCESS_ROOT` operation
must additionally freeze `physical_grant: PhysicalVerificationContext`
(`forgeflow.physical-verification.v1`). It binds the canonical parent Attempt,
generation, operation, registration ID, canonical verifier root, frozen plan ID
and hash, original reservation SHA and limits, and the complete ordered command
manifest. Each command has a distinct execution UUID and synthetic
`process_attempt_id` so recovery cannot sweep the original author or another role.
Registration requires `VERIFYING` or `REVIEW_READY`, a valid current lease,
the original immutable WorkerResult's matching positive whole-author stop on the
same local boot, closed native/model effects, and every selected resource scope's
unchanged complete reserved vector. It creates no additional resource allocation.
Any unclosed verifier root blocks another root from borrowing the pool. An
idempotent registration replay does not grant permission to launch again.

The runner executes roles sequentially under that original pool's CPU, memory,
swap, pids and group-OOM limits. A trusted `VERIFIER_PROCESS_SETTLED` fact carries
`physical_evidence`, the complete original command closure array. The Store
compares it with the durable context/command journals and exact frozen grant,
including launch authority, execution identity, fence hash, boot, limits and raw
empty cgroup stop. A failed business command may close physical custody when its
actual stop is known; it does not pass its business oracle. A missing mapping,
lock, fence or stop is not an unused command. Only an explicit closed sequencer
seal can acknowledge manifest entries with no launch effects. Bound positive
empty stops with no process receipt are accepted solely for
`cancelled_before_launch` or `spawn_failed:`; they retain their complete launch
authority/fence and are classified as stopped, not as unused grants.

Registration, settlement, merge preparation/decision and final resource release
use the same authority transaction locks and closure guard. Settling a verifier
returns only custody; the canonical pool remains held until final task completion
or confirmed cancellation. Startup recovery may close the registered sequencer
only after the exclusive server instance lock is acquired and before new HTTP or
scheduler activity. Legacy profiles without a physical grant retain their existing
process-stop path and gain no physical enforcement qualification. The PG fixture
also exercises authority DTOs and explicitly sealed unused manifests without
starting a verifier, cgroup or model; actual kernel enforcement is a separate proof.

### Logical event retention

Migration0011 marks a contiguous expired prefix with `archived_at`; it never deletes original events, changes payloads, resets project sequences, or removes history from backup and paginated history queries. The hot SSE window retains the latest event for every project. Database time and a recent-event sequence barrier determine eligibility, with at most1000 events per archive transaction. This is a logical PostgreSQL archive, not external cold storage or a disk reclamation operation.

`event_replay_window` reads the project head, oldest hot event and replay batch in one repeatable-read snapshot. A future or expired initial cursor requires a snapshot; a live subscriber crossing the archive frontier receives `stream_error` with `SNAPSHOT_REQUIRED` and closes without advancing its cursor. Server policy defaults to30days hot retention and an hourly bounded batch; validated private environment overrides configure the interval and retention. Business authority, outbox delivery and immutable full history remain independent of the hot replay window.

### Persistent Agent context data (2026-11-06)

Owner document commands accept `agent_contexts` with `forgeflow.agent-context.v1`. Immutable project/context/position/route/base references and append-only same-project artifact history use existing document revision CAS. These descriptors grant no execution state, lease or process authority. Pool population is independent of active-slot policies (tiers1/4/10/32/64, default32). See [context campaign contract](concurrency-readiness.md). `delivery_settings` contains optional project presentation metadata only.


### Agent-team planning workbench read models (2026-11-06)

- `GET /projects/{project}/planning-overview` returns `{project,flow,statistics,capacity,policies,milestones,milestone_count,decisions,revision,as_of,source,execution_rights_granted:false}` in the read envelope. Statistics describe the latest planning Flow, including a draft; task count and dependency count exclude `REMOVED_FROM_PLAN`. Coverage counts distinct requirement mappings, deferred requirements and uncovered nondeferred requirements separately. Gaps and milestone lists are bounded to 12; totals always come from SQL over the complete scope. Capacity separates persistent descriptors, nonterminal canonical attempts and distinct registered `(attempt_id,native_session_id)` lifecycle observations (including history). This is not a count of live model processes or accepted product results.
- `GET /projects/{project}/assignment-context` returns complete same-project teams and public attempt identity/state/timestamps under one MVCC observation. Private envelopes, execution bindings, prompts and result bodies are omitted.
- `GET /projects/{project}/tasks` accepts `q`, `owner`, `team`, `state`, `sort`, `order`, `cursor`, `limit`. Search is literal title/ID matching; sorts are `task_id/title/owner_id/team_id/state` with a stable task-ID tie-break in C collation. `order=asc|desc`; limit is clamped to 1..500. The envelope adds `total_count` computed in the same read-only repeatable-read transaction. Returned cursors bind project, filter and project event revision. Filter mismatch is `422 INVALID_CURSOR`; version drift is `409 SNAPSHOT_CHANGED`; restart at the first page. Cursor contents are opaque client input, never authority.
- Flow list and latest-Flow reads accept `view=summary`, omitting the full task array. Latest uses a single descending indexed query. `GET /flows/{flow}/context/current?view=summary` supplies current requirement, ownership, input and contract metadata with `task_specs:{}`; consumers retain the separately frozen TaskSpecs. Default full responses remain compatible.
- `GET /resource-usage` now uses a fixed set of collection queries in one repeatable-read transaction, with `version_vector` and `observation_vector`. `data.allocations` includes unreleased allocations and explicitly declares `allocation_scope:"unreleased"`; full historical allocation records remain in project snapshots. `GET /resources` retains its array shape and returns unique policies (global policy appears once).
- The read-only draft compiler preview adds `impact:{changed_task_ids,removed_task_ids,affected_task_ids,active_attempts,resource_findings,execution_rights_granted:false}`. Impact traversal includes old and proposed dependency edges. Resource findings compare single-task requests to applicable global/project/team ancestor limits; they do not claim Worker placement or peak feasibility. Final writes continue through existing Flow draft/approval commands and parent/context guards.
- Planning scenarios accept optional `capacity_overrides:{scope_id:active_tier}`. Every scope must exist and every tier is 1/4/10/32/64. Overrides affect forecasting only and are echoed in the result. No policy, lease, attempt, process, completion record or model request is created by a forecast.

Migration 0013 adds task filter and Native observation indexes only. No new execution state is introduced. Browser event resynchronization reads the lightweight authoritative event cursor and invalidates scoped read caches; it does not require downloading a full execution snapshot.

`/resource-usage` also returns `data.native_allocations` (unreleased Native charge rows), `data.workers` (public heartbeat identity/time and self-reported attempt count), and `data.host_memory:{total_bytes,available_bytes,source,observed_at}`. Host memory is separately sampled from `/proc/meminfo`; unsupported/failed observations stay null. Resource UI uses authoritative `usage.allocated`, which includes root and Native charges, rather than summing only root allocations. `/portfolio` now uses set-based aggregation with its original response shape and distinct current-approved-Flow delivery scope.
