# Native configuration editor contract

The ForgeFlow Console can edit and validate reviewed project execution
configuration while the DSH Host remains stopped. The DSH operation panel retains
its separate native preview/publication/activation route. Both editors use the
same typed draft authority. The model remains GLM5.3 Max (`glm-5.3`). Published
profiles, admitted task envelopes and original task-card acceptance stay distinct.

## API and authority

All paths below start with
`/api/v1/projects/{project}/native-panel/configuration`.

| Method and suffix | Request | Result |
|---|---|---|
| `GET` (base path) | No body | Current configuration SHA, editable spec, required plugins |
| `GET /drafts` | No body | Canonical drafts and published versions |
| `POST /drafts` | `draft_id`, `expected_revision` (null on creation), `base_config_sha256`, `spec` | `DRAFT` and new revision |
| `POST /drafts/{id}/preview` | `expected_revision` | `PREVIEWED`, actual native composition review and its SHA |
| `POST /drafts/{id}/publish` | `expected_revision`, `review_sha256` | `PUBLISHED`, immutable executor-profile ID |
| `POST /drafts/{id}/activate` | `expected_revision`, `review_sha256` | `PUBLISHED`, new revision, activation receipt and pending Worker policies |

Every native-panel route in the table above requires Owner authentication and exactly one
`x-forgeflow-native-panel-key` header from
the configured native panel. Mutations also require `Idempotency-Key`. Browser
requests carry a stable request UUID; the authenticated panel supplies the private
server-side credentials. Workers cannot issue these editing commands.

The protected document collection is `native_configuration_drafts`. Generic
`PutDocument` writes are rejected. Only the typed `native-configuration-service`
command can update it. Exact retries replay the recorded command before checking
whether later configuration changes made its original source stale. Reusing an
idempotency key for different request fields is rejected.

## Owner offline editing in the main Console

These separate paths start with
`/api/v1/projects/{project}/execution-configuration`.

| Method and suffix | Request | Result |
|---|---|---|
| `GET` (base path) | Optional query `executor_profile_id` | Source-backed editable context, current configuration SHA and required plugins |
| `GET /drafts` | No body | The existing `native_configuration_drafts` versions for this project |
| `POST /drafts` | The same `SaveRequest`: `draft_id`, `expected_revision`, `base_config_sha256`, `spec` | The same canonical `DRAFT`, revision and operation receipt |
| `POST /validations` | `base_config_sha256`, `spec` | `valid:true`, `native_resolution:NOT_RUN`, `runtime_invoked:false`, `execution_rights_granted:false` |

All four paths require normal Owner authentication and reject Worker principals
before reading private configurations. They require no panel key, and never
expose that key to the browser. Save retains the original actor/project
idempotency scope, source SHA, optimistic revision checks and typed
`NativeConfigurationCommand::Save`. Exact retries replay the existing receipt
before checking subsequently changed source files. Published versions remain
immutable; copying one requires a new draft ID. No second document collection or
draft state machine is created. Validation is read-only with respect to the
canonical database: it creates no draft, event, review, publication or grant.

Context, validation and a new save still resolve the original reviewed project
map and executor-profile allowlist, and verify the configured helper's SHA256.
Selecting an historical `executor_profile_id` only selects that approved base;
the helper loads its pinned preset patch and role roster and reconstructs the
context. The caller cannot replace that context with an arbitrary draft spec.
The base resource profile continues to follow the approved Worker/profile
mapping. The response envelope records `source:"postgres+pinned files"` for
context and validation. Context additionally reports `offline_only:true`,
`runtime_actions_available:false`, `runtime_invoked:false` and
`execution_rights_granted:false`.

The Owner helper boundary permits only `context` and `validate`. These modes
read approved files and validate local data; they do not invoke DSH, composition
resolution, a model, a Worker, a native session, or an autostart command. There
are no Owner offline preview/publish/activate/start routes. Those existing
native-panel actions retain Owner-plus-panel-key authentication and their
original native review requirements. Successful offline helper requests remove
their UUID-specific private input/output temporary files. Failed requests retain
their originals and diagnostics; existing panel preview/publish/activate
evidence retention is unchanged. Offline helper operations have a 30-second
deadline; the original panel deadline remains unchanged.

The editable field set comes from the actual pinned helper version. In
particular, an older four-field helper context is returned without inventing
`max_active_attempts_per_worker`; a client must not inject a newer optional field
that the selected helper cannot validate. A successful offline validation proves
only the local specification constraints. Native resolution and runtime
collaboration remain NOT_RUN, and no original-card completion credit follows.

## Editable specification

The spec has four required fields: `base_executor_profile_id`, `presets`,
`plugins`, and `role_bindings`, and one optional field,
`max_active_attempts_per_worker`. No other fields are accepted. Its complete
serialized size is bounded to 4 MiB.
The base profile must belong to the project's reviewed profile allowlist.

`max_active_attempts_per_worker` is an integer from 1 through 64; booleans,
floating-point values, strings and null are rejected. New editor contexts expose
the current capacity from the private configurations of the applicable Worker
templates (up to two); their delivery-list values must agree. If the historical
pair has different capacities, the new uniform default is the lower value.
Existing four-field drafts retain their original spec and hash: omission keeps
each template's existing capacity. Setting the field applies the reviewed value
to both the new delivery Worker entries and their private Worker configurations
on activation. For example, two Workers set to 12 provide a configured capacity
of 24 independent root tasks; this does not establish 24 live Agents or grant
resource admission. Global, project, team, Worker, model, build, GPU and integration
policies remain in force.

Preset entries contain `id`, `name`, `description`, `persona_prefix`, and
`clone_from`. Existing definitions retain their own composition template; new
presets clone a reviewed existing template. Original presets cannot be removed.
The maximum is 1,024 presets. Names, descriptions and persona prefixes have UTF-8
byte limits of 256, 4,096 and 32,768 respectively.

Plugin entries contain `entry_id`, `enabled`, and `config`. The existing plugin
set and editable key set are preserved. The editor exposes reviewed parameter
changes and optional-plugin toggles; installing arbitrary new packages requires
a separately reviewed composition. Workflow, Agent Teams, spawn/fork subagents
and their required tools cannot be disabled. Delegation depth remains two. This
editor cannot change the model route, filesystem sandbox or ForgeFlow bridge.

Each original position must appear exactly once and select an existing preset;
position bindings cannot share a preset. The SplatForge configuration therefore
retains all 58 positions. A preset count is not an active-Agent count.

## Review, activation and execution

Saving checks the current delivery-configuration SHA and canonical revision.
Editing a nonpublished draft returns it to `DRAFT`; a published version is
immutable. Preview materializes a separate pinned profile and resolves it with
the actual supported DSH `--dump-config` command. Preview starts no model and
keeps active profiles unchanged. Publish registers exactly that reviewed profile.

Activation requires native scheduling to be paused with no pending START. It
updates the future default and relevant future binding templates, creates private
Worker configurations, and stages resource policies. It neither rewrites existing
attempts nor registers a Worker or grants execution. The draft remains
`PUBLISHED`; activation is recorded separately.

Each future Worker receives an independent scoped credential and private 0600
environment file. A locked credential update preserves existing grants and binds
the new token to exactly its Worker and project. Core reads the private scoped
credential file during authentication; malformed or insecure files fail closed.
The direct Owner credential remains the repair entry point. Tokens never appear
in public reports or the browser.

A separate real native START launches the Workers. Their actual registration
precedes application of the staged resource policies and task admission. Service
`active`, configured capacity and declared roles alone prove no native session,
model request or completed card.

The configuration file and database receipt are separate commits. Interrupted
activation retains the exact previous configuration and private receipt. A retry
checks their identities and repairs staged-policy/credential preparation
idempotently; stale or conflicting state is rejected rather than overwritten.
Original failure evidence remains available.

## UI identity and evidence

New Draft reloads current authoritative context. The position roster uses the
current delivery profile's pinned `agent-roles.json`, verifies its SHA, and reports
a section error if it is missing or altered. It never silently substitutes the
old host roster. Profile summaries are cached by project and profile identity.

The DSH UI host catalog and project execution presets are displayed separately.
The observed host retains 66 presets and 256 plugin entries; the edited project
has 63 presets, including the added production-delivery lead, with 58 unique
position bindings. Host registration and successful composition resolution do not
qualify runtime collaboration.

The scoped evidence is
[`splatforge-native-configuration-r1/report.json`](../evidence/customer-projects/splatforge-native-configuration-r1/report.json).
It records actual Save → Preview → Publish → Activate → reopen → New Draft,
rendered current-profile role bindings, and subsequent real Worker registration.
It grants zero original-card completion credit. Actual 20+ Agent concurrency,
full business acceptance, all 2,884 original cards and the original 14-day target
require their own evidence.
