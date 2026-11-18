# ECP UI and browser contract v1

This contract defines what the React workbench may claim before a browser E2E
suite is connected. Static component rendering and a successful HTTP response
are not browser qualification.

## Context isolation

- `sessionStorage.forgeflow.auth-scope` identifies the current authenticated
  context. `setWorkspace` rotates it when the workspace changes.
- Every query/cache key must include authentication scope, workspace, project
  and the relevant server revision. A late response from another scope is
  discarded with `REQUEST_CONTEXT_CHANGED`.
- Workspace changes clear the selected project and cancel old subscriptions.
  A personal account cannot reuse a workspace-scoped write capability.
- Draft scope is deliberately separate from query scope; drafts must never be
  treated as server authority or permission evidence.

## Commands and truthful states

The API client sends the current token, `X-ForgeFlow-Workspace`, CSRF token,
`Idempotency-Key`, and `If-Match` when a command has an expected revision. A
command response means `accepted` only after the server returns durable JSON.
The UI must distinguish:

`accepted` → `received` → `processing` → `verified/completed`.

A network connection, an online indicator, an SSE event, or a delivery ACK does
not imply read, processing, task completion, verification, Git integration, or
physical process termination. Unsupported native actions are hidden or shown as
`UNSUPPORTED`/`UNKNOWN`; they must not become green success states.

## SSE cursor and resync

The project event cursor is an opaque string in the form `<project_id>:<seq>`.
The client sends it as both `after` and `Last-Event-ID`, validates that the event
project, sequence, object identity and cursor agree, and accepts only the next
contiguous sequence. Duplicate events are ignored; a gap is never silently
skipped.

HTTP `409 SNAPSHOT_REQUIRED`, a detected gap, an invalid frame, or an expired
cursor triggers a PostgreSQL snapshot read followed by a fresh cursor. Snapshot
resync invalidates cache and emits an observation event; it never submits a
mutation. Workspace/auth changes abort the old reader and prevent its responses
from overwriting the new context.

## Browser evidence minimum

Each journey records URL, workspace/project, request/response metadata, database
assertions, SSE cursor transitions, browser trace, screenshot, final status and
refresh/reload result. Component mocks are allowed only for component tests.
Release evidence must use the real API and database and must report separate
fractions for normal, rejected, revoked, stale-revision, disconnect/resync and
unsupported-capability cases.

The initial ECP browser suite should cover workspace switch isolation, invite and
revocation, principal/capability inspection, message send/ACK/receipt, stale
revision conflict, SSE reconnect and snapshot resync, task decision, evidence
readback, and a truthful unsupported native action. The suite remains `NOT_RUN`
until a real browser runner and independent oracle are bound.
