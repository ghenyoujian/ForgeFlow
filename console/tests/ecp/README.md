# ECP browser contract fixtures

This directory is the Phase 0/7 fixture namespace. Playwright is installed as a
development dependency, but journeys are opt-in and require a real server and
disposable PostgreSQL database before they can emit evidence.

Required fixture context:

```ts
interface EcpBrowserContext {
  sourceSha: string;
  workspaceId: string;
  projectId?: string;
  principalId: string;
  authScope: string;
  evidenceRoot: string;
}
```

Every write must capture `Idempotency-Key`, `If-Match`, workspace header, response
code, durable readback and the resulting revision. Every SSE assertion must
capture the cursor before connect, `Last-Event-ID`, received event IDs, gap or
resync decision, snapshot cursor, and the cursor after reload.

A fixture cannot mark a journey PASS when the server returns `NOT_RUN`,
`BLOCKED`, `INCONCLUSIVE`, `UNKNOWN`, `UNSUPPORTED`, or when a browser mock was
the only producer. The runner must preserve failures and skipped cases and use a
non-zero denominator.

The first real journey is `shell.spec.ts`. Run it only against a disposable
deployment:

```bash
ECP_BROWSER_RUN=1 \
ECP_BROWSER_BASE_URL=http://127.0.0.1:8080 \
ECP_BROWSER_TOKEN="$TOKEN" WORKSPACE="$WORKSPACE" PRINCIPAL="$PRINCIPAL" \
SOURCE_SHA="$SOURCE_SHA" npx playwright test --config playwright.config.ts
```

Without `ECP_BROWSER_RUN=1` the config matches no journey and cannot launch a
browser or create qualification evidence.

The current real-browser skeleton also includes:

- `identity.spec.ts`: authenticated workspace membership, selector scope, and reload isolation.
- `enterprise.spec.ts`: Registry/Profile qualification boundary plus a durable collaboration message sent through the real UI and read back from the API.
- `performance.spec.ts`: real Registry route navigation timing against `ECP_BROWSER_NAVIGATION_BUDGET_MS` (default `5000` ms).

These specs call `requireRealBrowser` before any journey action. Missing
`ECP_BROWSER_BASE_URL`, `ECP_BROWSER_TOKEN`, or a source-bound `SOURCE_SHA` is
reported as `NOT_RUN`/`BLOCKED`; no request interception, browser mock, or
fixture server is used. They are not Gate evidence until an independent run
captures the complete denominator and receipt.
