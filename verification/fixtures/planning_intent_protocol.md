# Compact planning intent and independent raw oracle

This is source-ready protocol work. The oracle's 48 standalone contract tests use
constructed inputs and one retained negative artifact. They prove neither a new
model result nor a product Gate. No DSH session, API server, Worker, database,
Cargo build, or npm build is launched by these tests.

## Versions and unchanged legacy path

| Identity | Value |
| --- | --- |
| Model intent schema | `forgeflow.planning-intent.v1` |
| Prelaunch authority schema | `forgeflow.planning-authority.v1` |
| New independent oracle ID | `a10-source-bound-planning-intent.v2` |
| Original full DraftBundle oracle ID | `a10-source-bound-flow-draft.v1` |
| Original oracle file | `verification/fixtures/planning_verifier.py` |
| Original oracle SHA256 | `4dfc290d511472a4de5fbee9aad4a2a0f94e8b536daf0a2eb498783ce2f7c4fc` |

Only a newly registered template with the new oracle ID opts into the compact
prompt. Existing full DraftBundle templates keep their original grammar and
oracle. The new oracle accepts only the compact schema, so a full DraftBundle
returned to the new template fails its raw checks. Existing strict full proposal
parsing remains available on the legacy path. Old verifier/profile pins and
historical failed artifacts are preserved.

## Model-authored meaning

The native terminal event contains a string `text`. That string must be one
complete JSON object with exactly two keys:

```json
{
  "schema_version": "forgeflow.planning-intent.v1",
  "tasks": [
    {
      "task_id": "T1",
      "title": "A finite task",
      "requirement_ids": ["an exact original requirement ID"],
      "outcome": "A concrete result preserving original acceptance",
      "read_set": [],
      "write_set": [],
      "dependencies": [],
      "resource_request": {
        "active_slot": 1,
        "coding_slot": 0,
        "cpu_units": 0,
        "memory_bytes": 0,
        "build_permit": 0,
        "gpu_permit": 0,
        "provider_inflight": 0
      },
      "verification_case_count": 2,
      "rollback_plan": "Preserve failures and revert exact changes"
    }
  ]
}
```

The example describes the schema; it is never substituted for model output.
Required task fields are the eleven fields shown. Optional fields are arrays
`contract_produces`, `contract_consumes`, `producer_inputs`, `known_unknowns`, and
`not_proven`; omitting any optional array means an empty array. Unknown fields,
duplicate JSON keys at any depth, invalid UTF-8/Unicode scalars, nonfinite
numbers, incomplete JSON, trailing prose, and protocol-version mismatch fail.

Task IDs are unique short ASCII identifiers matching `[A-Za-z0-9_-]{1,48}`.
Proposal IDs are namespaced by the controller as
`TASK-{project_id}-r{flow_revision}-{task_id}`. The existing platform limit is
10,000 finite tasks, with a 32 MiB native artifact bound. There is no 16-task,
8 KiB, or title/outcome fixture limit. Deep DAGs and hierarchical project/team
planning remain possible; a new plan's selected Owner/team still comes from its
original request and approved ancestor authority.

Each task maps at least one exact original requirement ID. Every original
requirement must be covered unless the original immutable source already has an
explicit nonempty deferred reason. The model cannot rewrite acceptance, scope,
priority, source anchors, or the requirement denominator by providing duplicate
source facts. Full original source meaning and semantic references stay bound
to the request and prelaunch authority, independently of the concise outcome.

Dependencies are exact objects `{task_id, kind, binding_id}`. Kinds are
`integrated`, `artifact`, `contract_frozen`, and `gate_pass`. IDs reference other
proposal tasks, bindings are nonempty, predecessor IDs cannot repeat, and the
whole graph must be finite and acyclic. The oracle uses iterative traversal so
10,000-task dependency chains do not depend on Python recursion depth.

Read/write paths are normalized project-relative paths; `..`, `.`, empty path
components, absolute paths, backslashes, NUL, and colons fail. Every proposed
write lies inside the exact originally selected write scope and the single
original Owner territory, including excludes and resolved symlink targets.
Known reads resolve only to the immutable `current_inputs` snapshot. The
controller automatically binds the original source input to every task.

Resources contain exactly the seven canonical unsigned 64-bit integer
dimensions. Boolean, negative, fractional, or overflowing values fail.
`active_slot` is positive; tasks with writes also need a positive `coding_slot`.
Every dimension is at most the minimum **approved limits** of the captured
global/project/team ancestor scopes. These checks do not use transient free
capacity, including the planning attempt's own provider reservation. Provider
zero is valid for a task with no declared model access; there is no blanket
positive-provider requirement or new claim of model authority for future tasks.
Actual admission still checks current usage, the selected Worker, and all
applicable scopes. Worker placement remains explicitly unverified by this
snapshot. `verification_case_count` is a positive u64 planned denominator, and
does not claim that any of those cases executed.

Contracts have exactly `{contract_id, version, spec_sha256}` and match registered
snapshot pins. Each immutable contract version has one producer. Public
consumption requires the snapshot's frozen state, all required passing
consumers, and independent/integration receipts. This protocol authorizes no
isolated contract probe.

Unknown future bytes use an explicit `producer_inputs` object:

```json
{
  "path": "a/project-relative/output",
  "producer_task_id": "the exact proposal producer ID",
  "dependency_binding_id": "the exact integrated edge binding",
  "contract": {"contract_id": "registered-id", "version": 1, "spec_sha256": "the exact registered 64-character hash"}
}
```

The producer declares the path in its write set and the exact produced contract.
The consumer declares the read, exact consumed contract, and matching integrated
dependency. A future reference cannot override the immutable source input.
Optional `producer_task_revision` and `producer_input_digest` can be omitted or
null. A supplied revision must equal the proposed producer revision (1), and a
supplied semantic digest must be a wellformed SHA256. The mandatory existing
strict seal compares that digest against the controller-materialized canonical
producer task identity **before** a draft becomes ready; a wellformed wrong
digest fails there and is never rebound. This raw oracle does not duplicate the
full canonical task digest implementation or declare that check passed.
`inputs`, a future byte `sha256`, and other invented authority/hash fields are
forbidden. Exact registered contract hashes and already-known input pins are
checked against immutable original facts now.

## Prelaunch binding

Before launching the actual model, the controller writes a DraftRequest, a full
original source artifact, and a versioned authority artifact. Each verifier
command binds their exact paths and hashes in the immutable VerificationPlan's
`bound_inputs`. The command also pins:

| Environment variable | Immutable meaning |
| --- | --- |
| `FORGEFLOW_DRAFT_REQUEST_PATH` / `FORGEFLOW_DRAFT_REQUEST_SHA256` | Original requested project/version, Owner/team, write scope, executor/verification profile, source projections |
| `FORGEFLOW_PLANNING_SOURCE_PATH` / `FORGEFLOW_PLANNING_SOURCE_SHA256` | Complete original source documents and domain requirement rows |
| `FORGEFLOW_PLANNING_AUTHORITY_PATH` / `FORGEFLOW_PLANNING_AUTHORITY_SHA256` | Original authority facts, known inputs, contracts, limits |
| `FORGEFLOW_PLANNING_TASK_ID` | Original planning task identity |
| `FORGEFLOW_PLANNING_INPUT_HASH` | Original canonical planning TaskCard/TaskSpec input identity |
| `FORGEFLOW_PLANNING_CONTEXT_SHA256` | Original context manifest hash |
| `FORGEFLOW_PLANNING_PROMPT_SHA256` | Original prompt artifact hash |

The authority root has exactly `schema_version`, `proposal_schema_version`,
`max_tasks`, `source_input`, `current_inputs`, `requirement_semantic_digests`,
`owners`, `resolved_paths`, `contracts`, and `resources`.
`resources` has exactly `scope`, `scopes` (canonical ResourcePolicy snapshots),
and `effective_limits`. Its scope label is
`GLOBAL_PROJECT_TEAM_CAPS_ONLY_WORKER_PLACEMENT_UNVERIFIED`.

The oracle itself re-hashes those three files, verifies the source raw hash
against the request and source input/current-input references, independently
compares the original domain requirement rows to their request projections, and
recomputes documented `forgeflow.requirement.semantic.v1` source meaning pins.
It checks task/plan/source operation identities, planning task revision,
input/context/prompt identities, and the exact raw native final artifact hash.
The evidence runner additionally enforces the original plan digest, bound
inputs, expected case names/kinds, executable pin, and immutable ArtifactBinding.
Neither oracle expectations nor input pins are created from the result after
launch. Current authoritative source/input/Owner/contract/resource snapshot
drift is checked by the API before sealing and again after raw verification
before persistence; this file-only oracle cannot claim a live store audit.

The model cannot emit project/revision, Owner/team, execution state/approval,
leases/envelopes, profiles, requirement digests, known input hashes, or a
Flow/context wrapper. Controller normalization fills those fields after raw
validation and then runs the existing strict proposal/seal/compiler checks.
Intertask write serialization, resolved producer semantic digests, and final
compiler checks retain their existing downstream enforcement. No raw event or
model text is repaired, completed, or replaced.

## Reports and source evidence

The new oracle is standalone Python with no API/planner imports. It emits the
existing exact report schema `{binding, oracle_id, cases}`. The binding is the
unmodified original ArtifactBinding; each case has exactly `name`, `kind`, and
`outcome`. Register the exact `CASES` list from
`planning_intent_verifier.py` under a fresh immutable profile/version. There are
25 planned raw-oracle assertions across author (3), consumer (5), and independent
(17): six positive and nineteen negative. Any invalid original artifact fails
all its assertions; successful mutation rejection cannot qualify a failed
positive result.

Run the standalone contract suite with:

```sh
python3 -B verification/fixtures/planning_intent_cases.py evidence/enterprise-ux/planning-intent-oracle-r1/self-test-results.json
```

The tests cover nonzero complete structured reports, real subprocess execution
of all three oracle roles, exact byte pins, source meaning, scope, Owner excludes,
symlink escape, contracts, future edges, all resource dimensions, zero-model
tasks, invalid JSON/duplicates/EOF, and the original 10,000-task scale. The
retained actual 3,197-byte failed model text is independently decoded and stays
invalid; the original artifact bytes stay unchanged. Source proof hashes and
limitations are in `evidence/enterprise-ux/planning-intent-oracle-r1/source-proof.json`.
These self-tests use no ModelMock and assert no runtime or product qualification.
