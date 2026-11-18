# DSH Headless adapter

`prepare_headless` consumes the canonical `forgeflow.execution.v1` envelope,
verifies runtime pins and frozen profile/model route, validates the UTF-8 prompt
digest, and returns an argument array plus stdin bytes. Worker owns environment
isolation, process groups, deadline, cancellation, durable raw logs and events.
The local `dsh.sh` wrapper resets the cwd and personal home, so qualification
uses the actual built CLI through the pinned absolute Node executable.

`HeadlessStream` retains unknown JSON fields and exact raw lines. A successful
execution requires a native session, one final, `turn_end.reason.kind=completed`,
exit zero and persisted final evidence. It does not establish business acceptance.
For a large final, Worker validates and persists the complete JSON while streaming,
then calls `observe_spooled_final`; the final text must never inherit intermediate
event truncation. Cancellation requires independently confirmed process evidence.

`doctor` verifies artifact identity and returns platform, cwd, managed home,
protocol and conservative capability facts. Credential/model resolution and
process-descendant cancellation need their own probes. Resume is enabled only
after a real same-profile/cwd probe.

The `qualification` directory contains actual local runtime hashes, native stdout,
receipts and reproducible scripts. The first author run was cancelled at its
deadline; it produced `final` and exit zero without a completed `turn_end`.
The bounded genuine resume completed, and missing-session/wrong-cwd requests were
rejected. An independent consumer verified the actual candidate file. These facts
qualify local protocol behavior, with G2 remaining INCONCLUSIVE until the managed
admission/Worker/verification/integration chain is separately proved.

The current local profile is `direct_observed`. Hard model-budget coverage,
all nested spawn entry points, descendant cancellation and production real-session
capacity remain UNVERIFIED. Runtime, plugins, config, route or sandbox changes
invalidate the corresponding qualification.

Strict managed model transport uses the stock Node CLI with a pinned
`--import /tmp/forgeflow/model-transport.mjs` loader. The loader installs the
SDK's global fetch seam before CLI imports. Only the synthetic Anthropic endpoint
`http://forgeflow-model.invalid/v1/messages` may use the private
`/tmp/forgeflow/model.sock`, and only while the managed bridge runs provider
iterator creation/next/return under one live canonical model grant. Ordinary
tools execute outside that AsyncLocalStorage context. Direct IP networking is
disabled by the outer Worker; the native home contains a dummy SDK credential,
while the trusted API resolves the actual approved provider secret.
The installed SDK's exact `?beta=true` spelling is accepted on that same messages
path and normalized to the fixed relay route; other URLs and queries are denied.
Installed stock pi-ai adds its thinking budget to the answer token ceiling.
The transport requires that SDK ceiling to cover the canonical total response
grant, then lowers actual wire `max_tokens` to that grant. Explicit enabled
thinking is bounded to leave 1024 answer tokens; grants of at most 1024 tokens
omit explicit thinking. Supported adaptive thinking is retained. No request cap
is raised, and prompts, tools, provider keys and SSE parsing are preserved. Body
length and SHA bind the exact forwarded bytes after this budget projection.

The full-duplex UDS protocol is `forgeflow.model-uds.v1`: a four-byte big-endian
metadata length, bounded JSON identities/body SHA/header allowlist, then exact
request bytes; the response starts with framed HTTP status/headers followed by
bounded raw response frames and an explicit zero-length terminal frame. The
existing SDK parses the unchanged SSE stream and emits normal usage events.
Before settlement, the bridge awaits a per-grant transport completion promise.
Only the explicit zero frame resolves it, after the API has durably recorded
upstream closure. An SDK `message_stop` event cannot replace that proof.
Cancellation destroys the socket and drops upstream work. Missing terminal
frames or incomplete usage remain unknown; no transport retry spends the same
grant. The API consumes the already admitted native grant before external
connection, and the existing bridge remains the sole model settlement path.
Source checks or zero-model wire fixtures do not establish G07 or production
coverage. Legacy profiles without this loader retain their prior qualification.
