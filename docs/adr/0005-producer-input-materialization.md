# Producer inputs and immutable execution recipes

A consumer can be approved before its producer has created a required file. Unknown
bytes have no SHA256. They are represented as an explicit producer input binding,
separately from known immutable input bindings; strings such as `planned`, zero
digests, and hashes of descriptions never represent future file contents.

Native planning output is an unapproved typed proposal. It may omit redundant
producer revision and semantic digest pins, or set them to null. The backend
resolves these pins in DAG order after binding unchanged authoritative source
and requirement meaning. Any supplied exact pin must match; mismatches and cycles
are refused. Only the resulting canonical draft stores mandatory exact pins, and
its source-resolution receipt remains visible before approval. This stage creates
no execution authority and never computes a hash for unknown producer bytes.

Binding a producer execution template can advance its draft task identity. A
consumer template bind with stale pins fails with an explicit old/new diff.
`reseal_producer_inputs: true` authorizes that reviewed draft edit and records the
diff in the binding result; ordinary binding never silently changes provided
pins. Committed Flows cannot be resealed. This completes preparation before the
producer runs and does not introduce a postapproval replan.

The approved binding names an exact project-local producer task revision and
semantic input digest, required output path, integrated dependency binding and
contract ID, version and specification SHA256. The producer must be a declared
predecessor with authority over that path and must produce the exact contract that
the consumer consumes. A public consumer still requires a frozen contract. A
candidate compatibility probe retains the existing isolated probe policy and
does not acquire a product Gate by reading the candidate.

The consumer's semantic task identity and approved static execution template stay
immutable. A versioned recipe is derived from that task identity, its specification,
the static template identity and the exact approved context manifest bytes. A
manifest used for approval includes every known immutable input and declares every
required path, while producer input paths are unresolved. That incomplete manifest
is never dispatched to a Worker.

Admission accepts only the approved template from the caller. After dependency
verification, the authority resolves the recipe using registered records for the
exact successful producer attempt: its independent verification receipt, its final
integration receipt, the integrated SHA reachable from the approved target ref,
and the exact registered contract schema. Candidate existence, a file in the old
base, executor claims, or a successful process exit cannot resolve an input.

The concrete execution manifest hashes the actual required Git blobs at the
verified integrated SHA. All known inputs must still match their approved hashes
at that same base; advancing the base cannot authorize drift in existing inputs.
Multiple producers require a common verified execution tree containing their exact
verified outputs. Unsupported combinations are blocked rather than resolved by
an arbitrary HEAD selection.

Only the execution envelope's base SHA and concrete context manifest reference
are materialized. Owner, territory, resources, semantic input digest, requirement
and contract meanings, executor configuration, prompt and verification plan are
unchanged. The Attempt records the immutable recipe, producer evidence and
integration identities, selected base and hashes of the materialized manifest and
each produced file. The Worker receives a complete ordinary execution manifest
and validates the artifact and worktree bytes through the existing protocol.

Retries and crash replay use the same authoritative admission identity. A changed
producer revision, contract schema, required path, known input or static template
requires a new reviewed task definition; materialization is not replanning and
does not rewrite a committed Flow or historical Attempt.

Qualification requires a real API-created two-task DAG approved before the
producer output exists, followed by actual Worker execution, independent producer
verification and integration, consumer materialization and independent consumer
verification. Unit tests exercise binding and refusal rules, but grant no business
Gate. Failed, missing and unsupported evidence remains explicit.

The current Git evidence `source_hash` is a tree object identity, 40 hexadecimal
characters for SHA1 repositories or 64 for SHA256 repositories. The existing
public-contract `source_sha256` freeze check requires 64 characters. This mismatch
is an existing limitation for SHA1 public-contract freezing and is not bypassed
by materialization. The controlled two-task qualification therefore uses an
explicit candidate compatibility probe and makes no public freeze, native DSH or
production capacity claim.
