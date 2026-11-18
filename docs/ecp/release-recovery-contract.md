# ECP release and recovery contract

A release candidate binds one source SHA to the source, binary, schema,
executor-profile and evidence manifests. A candidate row is a qualification
record; it cannot itself authorize publication. Approval requires an
independent verifier and a real authorized Principal.

A backup is valid only after dispatch is paused, unsettled attempts are zero,
PostgreSQL and artifact inventories are hashed at the same quiescent point, and
RPO/RTO are measured. Restore targets are fresh directories and empty databases.
Old sessions, leases, worker credentials and gateway permits are revoked or
quarantined; old lease identities never regain authority.

Upgrade rehearsals retain the N-1 candidate, record rollback evidence and keep
all NOT_RUN/BLOCKED/INCONCLUSIVE results visible. These tables and schemas do
not qualify a product Gate until an actual workload and independent oracle bind
the evidence to the same candidate.
