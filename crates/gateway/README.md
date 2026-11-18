# Anthropic Messages gateway

This gateway forwards exactly `POST /v1/messages` to a frozen upstream URL.
It preserves response status, streaming bytes, request identity, rate headers and
Retry-After. It does not retry model requests, follow redirects, change models or
translate protocols. Provider usage is measured from bounded SSE records; missing
usage remains unknown and no hard token/cost cap is claimed.

`PgRequestAuthority` issues an opaque scoped token from an admitted canonical
envelope. Only its digest is persisted. Before any upstream connection, one
PostgreSQL transaction checks current lease, generation, worker and task revision,
route/model, attempt count and inflight limits, project/global inflight, and
project/global/route rolling request windows using database time. The transaction
creates a unique request permit, charges the count and reserves inflight capacity.
It uses the control plane's global advisory lock followed by project locking.
An independent issuer secret stays in a private server file. HMAC-SHA256 binds
the token to the frozen project, attempt, lease, generation, route and model.
Issuance retries and server restart replay the same token while keeping the
existing counters; a changed issuer or frozen scope fails closed.

Completed response bodies release inflight once. A connection error, broken stream
or client disconnect does not prove upstream model work stopped: its permit becomes
QUARANTINED and conservatively retains inflight. Trusted recovery can settle it with
`RECOVERY_CONFIRMED_REQUEST_CLOSED`. Revocation and lease expiration deny new calls
and never silently release existing reservations. Interrupted persistence retains
the last durable reservation for recovery. Atomic admission/settlement events and
`provider_requests` feed the authority's UI projections.

The server must configure a concrete PostgreSQL authority, an owner-only upstream
secret file, a frozen route/model and limits. Worker gets the attempt-scoped gateway
token. A whole DSH profile can claim `gateway_enforced` only after an independent
egress audit proves all relevant main, auxiliary and plugin model requests use the
gateway. The presence of this proxy alone does not qualify that profile.

`tests/postgres_budget.rs` runs actual database transactions in a disposable schema.
Set `DATABASE_URL` or `FORGEFLOW_TEST_DATABASE_URL`; absence fails the qualification.
Fixtures are synthetic authority inputs, and tests do not claim a real-model or G2
qualification. Unit tests also exercise a real local streaming HTTP upstream and
prove budget denial occurs before an upstream connection.
