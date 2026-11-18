# Capsule Store/API v1

Capsule is optional immutable metadata inside the existing admitted
`attempts.execution_bindings.capsule`. It adds no execution state, lease,
resource ledger, process launcher or copy of an envelope/profile. Existing
Attempts and executor profiles without an explicit policy remain `UNBOUND`.
Read/check results never grant authorization, settle costs or mark an Attempt
successful. `BOUND_IDENTITY_CHECKED` checks the stored identity, not current
lease validity or a fresh runtime qualification.

All routes below require the existing Owner identity; Worker credentials are
rejected. All responses use the normal `/api/v1` JSON envelope. Lists support
`cursor` and `limit` (1–200); cursors are exclusive stable IDs.

| Method and path | Behavior |
| --- | --- |
| `GET /projects/{project}/capsules` | Paginated Attempt/Capsule summaries, including truthful historical `UNBOUND`; no raw envelope, credentials, commands or runtime paths. A present list binding is `BOUND_UNCHECKED` until detail validation. |
| `GET /projects/{project}/capsules/{attempt}` | Resolve same-project original envelope and frozen profile CAS, validate Capsule identity/digest/driver, return canonical Attempt state and existing native-root/occupied-lifecycle observations. |
| `POST /projects/{project}/capsule-checks` | Body `{"binding": CapsuleBinding}` must exactly match the admitted binding. Cross-project, changed generation/profile/digest/qualification fail. This is an integrity check, with `authorization_granted:false`; it cannot launch or authorize writes. |
| `GET /projects/{project}/capsule-context` | Query `executor_profile_id`, `resource_profile_id`, `model_route_id`; return the required environment fingerprint with `qualification:NOT_EVALUATED`. No policy, event or Attempt is created. |
| `GET /projects/{project}/capsule-policies` | Paginated immutable prepared policies. |
| `POST /projects/{project}/capsule-policies` | Validate registered qualification originals and prepare an immutable policy; requires `Idempotency-Key`. Same key/payload replays; changed payload conflicts. No Attempt or dispatch is created. |

Policy request (all fields required; unknown fields rejected):

```json
{
  "schema_version": "forgeflow.capsule-policy.v1",
  "executor_profile_id": "reviewed-executor-version",
  "resource_profile_id": "reviewed-resource-version",
  "model_route_id": "reviewed-model-route-version",
  "mode": "CLAUDE_LEAF",
  "team_write_policy": "AGGREGATE_WRITE_SCOPE",
  "qualification_ref": {"artifact_id": "registered-probe-id", "sha256": "<64 lowercase hex>"}
}
```

Only `CLAUDE_LEAF` and `DSH_HEADLESS` are implemented here. Team/Workflow modes
and `DISJOINT_ATTESTED` are rejected, even if caller metadata says VERIFIED.
This implementation does not start DSH or change the user's disabled services
and autostart. `READ_ONLY` additionally requires the original envelope to carry
no write paths/effect; it never silently downgrades a writing task.

The policy is separate from the frozen executor profile to avoid a circular
profile/probe digest. It is stored once in existing `documents.capsule_policies`,
keyed by executor profile ID. Generic `PutDocument` is forbidden for that
collection. Changing qualification/configuration requires a new profile ID;
existing policies and Capsule bindings are not resealed or overwritten.

The qualification original must be an existing same-project ArtifactRef whose
registered file bytes match SHA256. It must deserialize as strict
`DriverProbeResult`, bind exact driver/mode and the **CAS** profile digest, use
`REAL_MODEL` evidence, and contain VERIFIED checks with original evidence for:
`EXECUTABLE_IDENTITY`, `VERSION_HELP`, `START_HEADLESS`, `STRUCTURED_EVENTS`,
`PROCESS_CANCEL`, `TRANSCRIPT_REPLAY`, `VERIFIED_WRITE_ISOLATION`, `BUSINESS_E2E`.
Resume additionally requires `SESSION_RESUME`; GatewayEnforced additionally
requires `MODEL_EGRESS_ENFORCED`. Missing/unknown/partial checks fail closed.
NoModel fixtures and offline Doctor discovery are not runtime qualification.

`BUSINESS_E2E` must reference a registered strict seal:

```json
{
  "schema_version": "forgeflow.capsule-business-seal.v1",
  "project_id": "same-project",
  "attempt_id": "existing-native-leaf-attempt",
  "generation": 1,
  "integrated_sha": "<actual integrated commit SHA>"
}
```

The seal must resolve to existing same-project canonical `SUCCEEDED` authority,
the exact generation and driver, matching frozen executor profile bytes, and a
finalized/committed MergeIntent with that integrated SHA. A caller-written
VERIFIED field, executor final or process exit 0 is insufficient. This readback
checks the existing canonical acceptance chain; it does not rerun its oracle or
promote a missing Gate. Qualification artifact authors remain responsible for
the exact workload and evidence scope of their claims.

`environment_ref` must contain precisely the `CapsuleEnvironment` returned by
`capsule-context`: schema `forgeflow.capsule-environment.v1`, CAS executor hash,
canonical JSON resource-profile and model-route hashes, current Core executable
SHA256, operating system, architecture and kernel release. Profile pins must
match the original `artifact_pins_ref` JSON array, and the current executable
must match both the probe and a frozen artifact pin. Every command/check
evidence reference is resolved and byte-checked. Artifacts are bounded at 1 MiB
each and the checked evidence set at 8 MiB. File checks perform no commands or
network requests. Full profile, environment and probe originals are not copied
into Attempt bindings.

Existing `claude_doctor` uses its historical typed-profile SHA rather than the
CAS domain-separated digest. Those receipts remain valid discovery evidence
but **do not match** this Capsule admission contract. They are rejected rather
than silently rehashed, reclassified or treated as current qualification.

Ordinary admission revalidates an explicit policy against actual originals and
current environment before inserting its Capsule alongside the original
Attempt/Lease/resource reservations/Outbox in that same transaction. Failure
rolls back. Absence of a policy preserves legacy admission behavior and bytes.
The Worker still uses its existing frozen-profile/lease/pins/sandbox launch
path; Capsule GET/check is not a substitute for that action-time validation.

Scoped verification: `forgeflow-store --test capsules
capsule_metadata_cannot_manufacture_qualification_or_authority -- --ignored
--exact` uses an isolated PostgreSQL schema and no native/model process. It
checks forged qualification rejection, changed artifact bytes, unsupported
modes, generic-write bypass, historical readback, project/generation/profile
binding, public secret projection and pagination. Its terminal bound fixture
tests storage only and grants no execution qualification. API shape test:
`capsule_policy_and_checks_reject_replacement_authority_fields`. Actual managed
Team/Workflow qualification and current-build real-model positive qualification
remain NOT_RUN unless separately evidenced; these tests cannot earn them.
