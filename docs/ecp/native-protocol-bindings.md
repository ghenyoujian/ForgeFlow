# ECP native protocol bindings

This document freezes the adapter boundary for DSH and Claude without asserting
that either provider is currently qualified for every mode. The machine-readable
contract is `contracts/ecp/native_adapter.schema.json`.

Each adapter is selected by an immutable executor profile. The profile records
the provider and version, executable digest, adapter digest, configuration
digest, model route, and the evidence references that established those values.
Changing any of these values creates a new profile; an attempt never follows a
mutable profile pointer.

The adapter surface is deliberately small: `prepare`, `start`, `observe`,
`send`, `cancel`, `inspect`, `resume`, `collect_artifacts`, and `dispose`.
`prepare` and every side-effecting method receive the frozen execution envelope
and an idempotency key. A provider response is not considered a durable result
until the platform has persisted the raw response, its identity, and a receipt.

Capability support and evidence are separate fields. `SUPPORTED` without a
current evidence reference is invalid. A real model run is required to verify
native Team, Workflow, child supervision, and business end-to-end behavior;
offline discovery can only establish identity and protocol metadata. Historical
receipts remain useful context but never qualify the current source snapshot.

Native events are observed data. The adapter persists the original event bytes,
the provider sequence when present, the platform stream sequence, and a
content digest. Unknown events are retained and quarantined according to the
contract; they cannot silently authorize a write, cancel, resume, or release.

The platform owns principal authorization, capability attenuation, workspace
scope, budget reservation, write-set checks, generation checks, and final
receipt state. Native runtimes may own their internal Team or Workflow
lifecycle, but observations do not grant platform control handles. If a
provider lacks a stable resume or member-cancel API, the corresponding
capability stays `UNSUPPORTED` or `UNKNOWN` and the UI must expose a new
attempt rather than calling it a resume.

The current implementation has DSH managed/headless and Claude leaf building
blocks in `crates/executors` and `crates/worker`. This contract is a boundary
for the remaining Phase 5 integration work; it is not a Gate 5 result.
