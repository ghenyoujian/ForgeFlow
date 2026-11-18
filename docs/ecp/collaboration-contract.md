# ECP Phase 4 collaboration contract

Assignments, proposals, reviews, decisions and escalations are durable
collaboration facts. They do not grant file, project, executor or model access.
Every write is scoped to a workspace, carries an expected revision and an
idempotency key, and must be authorized again by the control plane before an
external effect is admitted.

A child assignment must remain a subset of its parent capability's actions,
projects, write set, executor set and numeric budget. A proposal records the
exact base revision, payload digest and write set. A decision names the exact
proposal revision and outcome. Older revisions are rejected instead of being
silently rebased. Message ACKs and reviews never make a task complete.

The migration includes an append-only collaboration outbox. A runtime
implementation must add the outbox fact in the same transaction as the
assignment/proposal/decision mutation and preserve failures for independent
verification. The schema and migration are ahead-of-gate scaffolding until
producer, consumer, authorization and fault-oracle tests run on one source
snapshot.
