# Sustained channel proof and resource handoff

The binding user Gate requires 128 controlled lightweight allocated channels for a verified 3,600-second interval. The allocated channel count is the sum of valid, stopping and quarantined allocations. Author subprocess count, valid lease count, model requests and configured pool capacity are separate measurements. Unused slots and in-memory futures do not count as allocated channels.

A periodic count of 128 is insufficient evidence of continuous occupancy. The verifier must retain acquisition/release records, persistent event positions and transaction grouping to reconstruct changes between observations. Database wall-clock timestamps inside a transaction do not alone identify the moment at which its changes became authoritative.

Separate completion/release and subsequent admission transactions necessarily permit a visible interval with fewer allocations. This is a concrete engineering gap for the strict saturated mixed-fault Gate, even when refill latency meets the separate P95 <= 2-second requirement. The measurement threshold is not relaxed to hide this gap.

The proposed corrective mechanism is a bounded, authoritative atomic resource handoff: after confirmed cleanup and all required verifier settlements, a terminal transition and one independently legal replacement admission may commit together. It must preserve the ordinary admission checks, exact immutable inputs, fresh attempt and generation, complete resource vector, ancestor/worker limits, fairness policy, idempotency and evidence. Unknown cleanup must remain quarantined. External process/Git/model effects stay outside the transaction. Transaction-grouped release/acquisition evidence must prove the resulting count.

This mechanism is a pending implementation and verification obligation. A short real Worker smoke precedes expensive sustained runs; injected scenarios without an implemented actual path remain INCONCLUSIVE. A steady workload with no terminal handoff cannot be used to claim that the required mixed completion, failure, stop, timeout and recovery scenarios passed.
