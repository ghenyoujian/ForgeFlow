# ECP Phase 6 resource and cost contract

The existing `resource_limits`, `resource_allocations`, `leases`, gateway budget
and native model request tables remain the current control-plane authority. The
Phase 6 tables are additive evidence and settlement boundaries until a runtime
adapter binds them to a task, attempt, lease generation and source snapshot.

`ecp_resource_profiles.logical_limits` describes scheduler/accounting quotas.
`physical_limits` describes OS/cgroup or worker enforcement facts. A logical
reservation never proves physical enforcement. The profile records an explicit
`enforcement_status` so an unknown host capability cannot be displayed as a
hard limit.

A budget reservation is idempotent by workspace, key and dimension. Reserved
capacity remains held until a durable settlement or release. A provider reply
with missing or partial usage creates `UNKNOWN`, `PARTIAL`, or `QUARANTINED`
ledger state; it never silently becomes zero cost and never releases capacity
without an explicit authority decision.

Lease revocation records the requested generation, reason and source identity.
An observed revocation is not a physical stop proof. A stop proof must be
produced by the existing worker/physical-custody contracts and independently
verified before releasing physical resources.

No table in this migration upgrades a Phase 6 Gate. Real resource, cost, fault,
capacity and 72-hour evidence must share one source SHA, environment identity,
profile digest, workload denominator and independent oracle.
