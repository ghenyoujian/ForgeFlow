# ECP conversation and delivery contract

Migration `0017_ecp_conversations_delivery.sql` is an additive Phase 3 schema.
It separates conversations, threads, messages, per-recipient deliveries,
attempts, receipts, inbox checkpoints, outbox facts and dead letters. Existing
`0014 agent_messages` remains a compatibility surface until a producer and
consumer migration is admitted.

A message sequence is scoped to one conversation. The producer must lock the
conversation aggregate while allocating `next_sequence`, validate active
participant membership and authorization, check the sender/request idempotency
key, then commit the message, delivery rows and outbox facts in one PostgreSQL
transaction. Network sending happens only after that commit.

`ACKED` means the recipient durably accepted a delivery receipt. It does not
mean a model understood the message or that a task completed. An external
side-effect request whose receipt cannot be determined becomes
`UNCONFIRMED`; it must not be blindly retried. A cursor can advance only across
a contiguous durable prefix, and a gap or retention boundary requires an
explicit resync result.

The schemas are design contracts and the migration is a storage scaffold.
Static contract checks and migration syntax do not produce ECP-G3 or any
product Gate. Real qualification requires producer/consumer tests, duplicate
and reorder faults, cursor recovery, revocation, PostgreSQL restart, a durable
outbox oracle and source/profile identity bound to the evidence.
