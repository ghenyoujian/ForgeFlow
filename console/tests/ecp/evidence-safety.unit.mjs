// Standalone collector test, not a product E2E or qualification Gate.
// Run from console with: node --experimental-strip-types tests/ecp/evidence-safety.unit.mjs
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import http from "node:http";
import { mkdtemp, readFile, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { createRequire } from "node:module";
import { evidenceUrl, recordResponse, serializeJourney } from "./helpers.ts";

const require = createRequire(import.meta.url);
const { chromium } = require("@playwright/test");
const secrets = ["fixture-query-secret", "fixture-fragment-secret", "fixture-cookie-secret",
  "fixture-location-secret", "fixture-extra-secret", "fixture-idempotency-secret"];
const server = http.createServer((request, response) => {
  if (request.url.startsWith("/abort")) {
    request.socket.destroy();
    return;
  }
  response.writeHead(request.url.startsWith("/error") ? 503 : 200, {
    "CoNtEnT-TyPe": "text/html; charset=utf-8",
    "SeT-CoOkIe": "session=fixture-cookie-secret; Path=/; HttpOnly",
    "LoCaTiOn": "/later?token=fixture-location-secret",
    "X-Unapproved": "fixture-extra-secret",
    "ReTrY-AfTeR": "5",
  });
  response.end("collector fixture");
});
await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
let browser;
try {
  const args = ["--no-proxy-server"];
  if (process.env.ECP_BROWSER_NO_SANDBOX === "1") args.push("--no-sandbox");
  browser = await chromium.launch({
    headless: true,
    ...(process.env.ECP_BROWSER_EXECUTABLE ? { executablePath: process.env.ECP_BROWSER_EXECUTABLE } : {}),
    args,
  });
  const context = await browser.newContext({ extraHTTPHeaders: {
    "Idempotency-Key": "fixture-idempotency-secret",
    "If-Match": '"7"',
    "X-ForgeFlow-Workspace": "fixture-workspace",
  }});
  const page = await context.newPage();
  const base = `http://127.0.0.1:${server.address().port}`;
  const journey = { requests: [] };
  const response = await page.goto(`${base}/ok?token=fixture-query-secret#fixture-fragment-secret`);
  assert(response);
  const raw = await response.allHeaders();
  assert(raw["set-cookie"].includes("fixture-cookie-secret"));
  assert(raw.location.includes("fixture-location-secret"));
  await recordResponse(journey, response.request(), response);
  assert.equal(evidenceUrl(page.url()), `${base}/ok`);
  assert.equal(evidenceUrl("http://fixture-user:fixture-password@example.test/a?x=secret#secret"), "http://example.test/a");
  assert.equal(evidenceUrl("not a URL"), "[invalid-url]");
  assert.equal(evidenceUrl("data:text/plain,secret"), "[unsupported-url]");
  const normal = journey.requests[0];
  assert.equal(normal.method, "GET");
  assert.equal(normal.url, `${base}/ok`);
  assert.equal(normal.status, 200);
  assert.equal(normal.workspace, "fixture-workspace");
  assert.equal(normal.ifMatch, '"7"');
  assert.equal(normal.idempotencyKey, `sha256:${createHash("sha256").update("fixture-idempotency-secret").digest("hex")}`);
  assert.deepEqual(normal.responseHeaders, { "content-type": "text/html", "retry-after": "5" });
  assert.equal(normal.responseHeadersStatus, "AVAILABLE");

  const failure = await page.goto(`${base}/error?token=fixture-query-secret`);
  assert(failure);
  await recordResponse(journey, failure.request(), failure);
  assert.equal(journey.requests[1].status, 503);
  assert.equal(journey.requests[1].responseHeaders["retry-after"], "5");

  const failedRequest = page.waitForEvent("requestfailed", { timeout: 5000 });
  await page.goto(`${base}/abort?token=fixture-query-secret`).then(
    () => { throw new Error("connection abort was unexpectedly successful"); },
    () => {},
  );
  await recordResponse(journey, await failedRequest, null);
  assert.equal(journey.requests[2].status, 0);
  assert.equal(journey.requests[2].responseHeadersStatus, "NO_RESPONSE");
  assert.deepEqual(journey.requests[2].responseHeaders, {});

  // Simulate header retrieval failure separately; its real HTTP status is retained.
  await recordResponse(journey, response.request(), {
    status: () => 502,
    allHeaders: async () => { throw new Error("fixture-extra-secret"); },
  });
  assert.equal(journey.requests[3].status, 502);
  assert.equal(journey.requests[3].responseHeadersStatus, "UNAVAILABLE");
  assert.deepEqual(journey.requests[3].responseHeaders, {});
  // Exercise the same serializer called by the public fixture sink, with a
  // URL directly assigned by a spec and an explicit failure state.
  journey.url = `${base}/direct?token=fixture-query-secret#fixture-fragment-secret`;
  journey.status = "FAIL";
  journey.reason = "synthetic connection failure";
  const evidence = await mkdtemp(path.join(os.tmpdir(), "ecp-collector-fixture-"));
  const output = path.join(evidence, "journey.json");
  await writeFile(output, serializeJourney(journey), "utf8");
  const artifact = await readFile(output, "utf8");
  const stored = JSON.parse(artifact);
  assert.equal(stored.url, `${base}/direct`);
  assert.equal(stored.status, "FAIL");
  assert.equal(stored.reason, "synthetic connection failure");
  assert.equal(stored.requests.length, 4);
  assert.deepEqual(stored.requests.map((item) => item.status), [200, 503, 0, 502]);
  for (const secret of secrets) assert(!artifact.includes(secret), `leaked fixture value: ${secret}`);
  console.log(JSON.stringify({ status: "OBSERVED_NOT_GATE", real_browser: true,
    scope: "synthetic HTTP fixture and evidence collector only", records: journey.requests.length,
    expected_statuses: [200, 503, 0, 502], failed_assertions: 0 }));
} finally {
  if (browser) await browser.close();
  await new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
}
