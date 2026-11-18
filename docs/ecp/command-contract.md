# ECP command contract v1

This document freezes the Phase 0 boundary for writes. It does not claim that
all fields are implemented by the current control plane.

## Observed producer / consumer boundary (source 9661a79)

The original v1 schemas remain byte-for-byte unchanged. New
`command_context.v2.schema.json` and `error.v2.schema.json` are **draft target
contracts**, not wire-compatible replacements for existing HTTP, 0014 network
DTOs or v1 schemas. Both v2 envelopes require `schema_version: 2`; no current
route negotiates, emits or validates them. Existing
consumers must continue to use their current contracts until a versioned adapter
is implemented and independently tested. The following mapping is an inventory,
not a claim that the target context is currently constructed or enforced. These
consumer observations are bound to historical source `9661a79`; source or
dependency changes require fresh evidence before applying them to another HEAD:

| Target field | Existing source or gap |
| --- | --- |
| `principal_id` | HTTP `identity()` derives `actor_id` from authenticated `Principal`; account actors and the ECP `human:<account_id>` principal have distinct identifiers. Resolve the principal from authoritative membership; never copy an untrusted sender field. |
| `workspace_id`, `project_id` | Workspace middleware derives scope from the authenticated session and workspace selection; individual route/body supplies project scope, revalidated by Store. No general context mapping exists. |
| `idempotency_key` | Catalog HTTP accepts 1–200 bytes when `HeaderValue::to_str` succeeds; ECP messaging requires 16–128 bytes and equality with its request ID. The draft requires 16–128 JSON string characters. Preserve existing legacy keys; do not silently truncate, pad or claim the bounds are identical. |
| `expected_revision` | Existing commands carry operation-specific `u64` revisions in typed bodies; the draft tagged `kind`/string `value` has no general conversion or create-if-absent encoding in the current API. Unsupported mappings remain unresolved. |
| `request_digest` | Catalog replay stores and compares the full serialized command JSON by actor/operation/key; network messages separately hash the serialized `NetworkMessageInput`. Neither is a general wire-provided ECP digest. |
| `operation_id` | Catalog Store allocates an ID for a new result and persists it with the replay record; it is not generally an incoming HTTP field. |
| `trace_id` | Legacy network messages create a stored trace ID; no uniform propagation for all Catalog commands is established. |
| `schema_version`, `capability_grant_id`, `authorization_epoch` | There is no universal `CommandIdentity` binding to these target fields; their presence in a schema does not prove authorization. |

`Store::execute_command` invokes account-catalog authorization before replay,
then obtains its replay lock, compares the saved request, applies the command,
and saves the result in one transaction. This observation is specific to that
entry point; it does not establish universal capability enforcement across all
commands. The legacy network path uses `(sender_account_id, project_id,
client_message_id)` and its own request hash. A mismatched request returns
`IDEMPOTENCY_CONFLICT` on both paths; neither establishes a global exactly-once
guarantee for external effects.

Existing `ApiError` serializes `DomainError` as `code`, `message`, `object_id`,
`request_id`, `retryable`, `remediation` and `details`. The browser's `ApiError`
reads `code`, `message`, `request_id`, `object_id`, `remediation` and `details`.
The draft error schema instead requires `operation_id` and excludes those extra
legacy fields, so the two are not directly compatible. Preserve the legacy
shape on existing routes; add an explicitly versioned adapter only after its
operation ID, retryability and redaction semantics have authoritative sources.
Do not map a request ID to an operation ID or infer a current revision from an
error message.

For v2 draft context epochs and error revisions, a JSON integer is permitted
only through 2^53−1; a canonical decimal string can represent the complete
nonnegative PostgreSQL signed-bigint range through 9223372036854775807. Reject
negative, non-decimal, noncanonical or overflowing strings. These schema checks
do not add runtime parsing, authorization or compatibility to existing routes.
Existing v1 inputs are not implicitly upgraded; a future adapter must explicitly
reject values outside v2 bounds and prove consumer compatibility. The
`expected_revision.value` sentinel and overflow behavior remain unresolved until
each tagged kind and its existing consumer are mapped explicitly.

The target requires each protected write to derive its principal from
authentication and bind operation identity, workspace scope, expected revision,
idempotency key, request digest and trace identity. Its required transaction
rechecks authorization, serializes idempotency, checks the aggregate revision,
and persists the modification, event/outbox and replay result. Existing routes
only implement subsets of this target, as identified below.

`control/crates/domain/src/commands.rs::CommandIdentity` and
`control/crates/store/src/catalog.rs::Store::execute_command` are the current
implementation anchors. The existing `0014_workspaces_agent_network.sql`
network message path remains a compatibility surface; it is not evidence that
ECP Principal, CapabilityGrant, Conversation, Delivery, Outbox or resume
semantics are complete.

A replay with the same operation and request digest may return the durable
result after current authorization succeeds. The same idempotency key with a
different digest is `IDEMPOTENCY_CONFLICT`. A revoked principal cannot use an
old replay key to recover a sensitive response. Missing database, missing
principal/lease, a zero test denominator, or a non-disposable database changes
the verification result to `BLOCKED` or `NOT_RUN`; it never becomes PASS.

## Operation-specific revision and error inventory (source 4e86166)

The following is a source inspection of commit
`4e8616664fcbb6721d70770b075d267cfd2c73a0`, not an end-to-end
qualification. The earlier `9661a79` observations above remain tied to that
snapshot. This inventory neither admits the draft schemas nor changes any wire
format, and it must be rechecked when its cited consumers change.

| Entry point | Observed revision behavior | Source evidence and limits |
| --- | --- | --- |
| Catalog `PutDocument` | Its `expected_revision` is `Option<u64>`. At the revision check, `None` matches an absent document; `Some(n)` matches only an existing row whose revision equals `n`. A mismatch returns `REVISION_CONFLICT`. Other collection-specific validations can reject the command before or after this check; this is not a promise that every absent-document request succeeds. | `crates/domain/src/commands.rs::CatalogCommand::PutDocument`; `crates/store/src/catalog.rs::put_document`, including its locked `documents` lookup and comparison. This says nothing about how to encode the draft `create_if_absent.value`. |
| Catalog `UpdateProject` | A mandatory `u64` is compared with the locked project's revision. An unequal value returns `REVISION_CONFLICT`; a missing project fails the lookup. Other authorization and update checks still apply. | `crates/domain/src/commands.rs::CatalogCommand::UpdateProject`; `crates/store/src/catalog.rs::apply_catalog`; `crates/store/src/lib.rs::project_lock`. |
| Workspace membership change | The HTTP field is `Option<i64>` with a serde default, so a missing or null field reaches the Store as `None`. For an existing active member, `Some(n)` must be positive and equal to its current revision; `None` skips that equality condition. An invalid current revision is `CORRUPT_AUTHORITY`; an invalid or stale supplied revision is `REVISION_CONFLICT`. The SQL update includes a revision predicate only for `Some`. This `None` does **not** mean create-if-absent. | `crates/api/src/workspaces.rs::MemberChange` and `change_member`; `crates/store/src/ecp_membership.rs::require_expected_revision`; `crates/store/src/workspaces.rs::change_workspace_member`. Role, owner, last-owner and row-state checks remain separate. |
| Capability-grant revocation | The HTTP body requires an `i64` expected revision. After the owner and grant lookups, a mismatch with the locked grant row returns `REVISION_CONFLICT`; success increments that grant revision. | `crates/api/src/ecp_identity.rs::RevokeGrant` and `revoke_grant`; `crates/store/src/ecp_identity.rs::revoke_capability_grant`. This does not define a conversion for every object-revision kind. |
| Lease generation | The `attempt_control` check compares its supplied generation to the attempt generation, lease generation and fence epoch alongside worker, revocation, expiry, deadline and dispatch conditions. | `crates/store/src/lifecycle.rs::Store::attempt_control`, at the `valid` predicate. It is a fencing check with additional conditions, not proof that generation is interchangeable with an object revision. |

The `kind`/string `value` in the draft is not consumed by these routes. In
particular, the `create_if_absent` value/sentinel, mappings from absent legacy
membership revisions, generation-to-kind conversion and the allowed numeric
range for each operation remain **UNRESOLVED**. Do not assign them a common
meaning or silently narrow a `u64` to a database `i64`. No inference here
establishes that a target adapter or its authorization exists.

For errors, the following table applies specifically when a
`forgeflow_store::StoreError` is converted by
`crates/api/src/lib.rs::ApiError::from`; handlers that construct `ApiError`
directly or fail in an extractor may have different behavior.

| Input to this conversion | Observed HTTP status and output code | Source evidence |
| --- | --- | --- |
| Domain code `FORBIDDEN`, `NOT_FOUND`, `SESSION_REVOKED` | 403, 404, 401 respectively; the original domain error is retained. | `crates/api/src/lib.rs::ApiError::from`, ordered domain branches. |
| Domain code `SNAPSHOT_CHANGED`, or containing `CONFLICT`, `STALE`, `CAPACITY`, `UNSATISFIED` or `ESCALATION` | 409 with the original domain error. Other domain codes reach 422, after the earlier exact-code branches. | Same conversion; therefore `REVISION_CONFLICT` and `IDEMPOTENCY_CONFLICT` take this branch, without implying the same cause or safe retry policy. |
| Database SQLSTATE `23503`, `23505`, `23514` | 422 `REFERENCE_NOT_FOUND`, 409 `OBJECT_EXISTS`, 422 `VALIDATION_ERROR`, respectively. Other database errors become 503 `AUTHORITY_UNAVAILABLE`. | Same conversion, database branch. |
| Stored JSON decoding error; migration error | 422 `CONTRACT_INVALID`; 503 `SCHEMA_UNAVAILABLE`, respectively. | Same conversion, JSON and migration branches. |

`crates/domain/src/lib.rs::DomainError::new` initializes `retryable` to false,
optional IDs and remediation to `None`, and details to JSON null; this is a
constructor default, not proof that every subsequently constructed or mutated
error has these values. `ApiError::into_response` serializes the `DomainError`,
and `console/src/app/api.ts::ApiError` reads legacy code, message, request ID,
object ID, remediation and details. These facts do not establish a v2 error
adapter: neither `request_id` nor `object_id` establishes an operation ID, a current
revision cannot be recovered reliably from the message, and a details reference
or retry policy cannot be invented from HTTP status. The authorization and
redaction rules for exposing a current revision or details remain **UNRESOLVED**.

## Phase 1 identity extension

Migration `0015_ecp_principals_capabilities.sql` introduces immutable `principals`,
`capability_grants`, `workspace_security_events` and
`workspace_security_outbox`. Existing accounts, connectors and network agents
are mapped to principal IDs; the 0014 network API remains compatible.

A child grant must be a subset of its parent action, project, write-set,
executor-set and numeric budget. Each grant captures the principal's current
authorization epoch. Membership changes increment the membership and principal
revision/epoch in the same transaction and append an outbox-backed security
event. Grant revocation requires the expected grant revision and is also
transactional. The HTTP handlers expose these facts under the workspace
principal and capability-grant routes; the handlers do not upgrade the ECP
Gate state by themselves.
