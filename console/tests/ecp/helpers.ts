import { createHash } from "node:crypto";
import type { APIResponse, Page, Request, Response } from "@playwright/test";
import type { EcpBrowserContext, EcpJourney } from "./fixtures";

export function requireRealBrowser(ecp: EcpBrowserContext): void {
  if (!process.env.ECP_BROWSER_BASE_URL || !process.env.ECP_BROWSER_TOKEN) {
    throw new Error("NOT_RUN: ECP_BROWSER_BASE_URL and ECP_BROWSER_TOKEN must target a real deployment");
  }
  if (!/^[0-9a-f]{40,64}$/i.test(ecp.sourceSha)) {
    throw new Error("BLOCKED: browser evidence must be bound to a source snapshot SHA");
  }
}

// Evidence stores the route, never credentials, query parameters or fragments.
export function evidenceUrl(raw: string): string {
  try {
    const url = new URL(raw);
    return url.protocol === "http:" || url.protocol === "https:"
      ? `${url.origin}${url.pathname}`
      : "[unsupported-url]";
  } catch {
    return "[invalid-url]";
  }
}

// The fixture is the common journey.json sink, including specs that assign a
// page URL directly instead of using reloadAndAssert.
export function serializeJourney(journey: EcpJourney): string {
  const safe = { ...journey, ...(journey.url === undefined ? {} : { url: evidenceUrl(journey.url) }) };
  return JSON.stringify(safe, null, 2) + "\n";
}

export function requestMetadata(request: Request): Record<string, unknown> {
  const headers = request.headers();
  const key = headers["idempotency-key"];
  return {
    method: request.method(),
    url: evidenceUrl(request.url()),
    // Preserve correlation without writing a caller-controlled key to evidence.
    idempotencyKey: key ? `sha256:${createHash("sha256").update(key).digest("hex")}` : null,
    ifMatch: headers["if-match"] ?? null,
    workspace: headers["x-forgeflow-workspace"] ?? null,
    startedAt: request.timing().startTime,
  };
}

// Explicit allowlist: Location, Set-Cookie and unknown response headers never
// enter the artifact. MIME parameters are discarded rather than copied.
function evidenceHeaders(headers: Record<string, string>): Record<string, string> {
  const result: Record<string, string> = {};
  const allowedTypes = new Set(["application/json", "application/octet-stream", "text/event-stream", "text/html", "text/plain"]);
  for (const [name, raw] of Object.entries(headers)) {
    const key = name.toLowerCase();
    if (key === "content-type") {
      const type = raw.split(";", 1)[0].trim().toLowerCase();
      result[key] = allowedTypes.has(type) ? type : "[other]";
    } else if ((key === "content-length" || key === "retry-after") && /^[0-9]{1,12}$/.test(raw)) {
      result[key] = raw;
    }
  }
  return result;
}

export async function recordResponse(
  journey: EcpJourney,
  request: Request,
  response: Response | null,
): Promise<void> {
  let responseHeaders: Record<string, string> = {};
  let responseHeadersStatus = response ? "AVAILABLE" : "NO_RESPONSE";
  if (response) {
    try {
      responseHeaders = evidenceHeaders(await response.allHeaders());
    } catch {
      // Preserve the observed HTTP status even if header retrieval fails.
      responseHeadersStatus = "UNAVAILABLE";
    }
  }
  journey.requests.push({
    ...requestMetadata(request),
    status: response?.status() ?? 0,
    responseHeaders,
    responseHeadersStatus,
  });
}

export async function durableReadback<T>(response: APIResponse): Promise<T> {
  const status = response.status();
  const body = await response.json().catch(() => undefined);
  if (!response.ok()) throw new Error(`HTTP_${status}: durable readback failed`);
  if (!body || typeof body !== "object" || !("data" in body)) {
    throw new Error("INVALID_RESPONSE: command did not return a data envelope");
  }
  return (body as { data: T }).data;
}

export function captureSseCursor(journey: EcpJourney, phase: string, cursor: string, extra = {}): void {
  journey.sse.push({ phase, cursor, capturedAt: new Date().toISOString(), ...extra });
}

export async function reloadAndAssert(page: Page, journey: EcpJourney, selector: string): Promise<void> {
  const before = page.url();
  await page.reload({ waitUntil: "domcontentloaded" });
  await page.locator(selector).waitFor({ state: "visible" });
  journey.url = evidenceUrl(page.url());
  if (before !== page.url()) throw new Error("RELOAD_CONTEXT_CHANGED");
}
