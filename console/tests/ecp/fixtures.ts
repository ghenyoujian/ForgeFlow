import { test as base, type APIRequestContext, type Page } from "@playwright/test";
import { mkdir, writeFile } from "node:fs/promises";
import { dirname } from "node:path";
import { serializeJourney } from "./helpers";

export interface EcpBrowserContext {
  sourceSha: string;
  workspaceId: string;
  projectId?: string;
  principalId: string;
  authScope: string;
  evidenceRoot: string;
}

export interface EcpJourney {
  name: string;
  startedAt: string;
  url?: string;
  requests: Array<Record<string, unknown>>;
  databaseAssertions: Array<Record<string, unknown>>;
  sse: Array<Record<string, unknown>>;
  status: "PASS" | "FAIL" | "NOT_RUN" | "BLOCKED" | "INCONCLUSIVE";
  reason?: string;
}

type Fixtures = {
  ecp: EcpBrowserContext;
  journey: EcpJourney;
  api: APIRequestContext;
};

function required(name: string): string {
  const value = process.env[name];
  if (!value) throw new Error(`ECP_BROWSER_${name} is required for a real browser journey`);
  return value;
}

export const test = base.extend<Fixtures>({
  ecp: async ({}, use) => {
    const evidenceRoot = process.env.ECP_BROWSER_EVIDENCE_ROOT ?? "test-results/ecp";
    await use({
      sourceSha: required("SOURCE_SHA"),
      workspaceId: required("WORKSPACE"),
      projectId: process.env.PROJECT,
      principalId: required("PRINCIPAL"),
      authScope: process.env.AUTH_SCOPE ?? "browser-session",
      evidenceRoot,
    });
  },
  journey: async ({}, use, info) => {
    const journey: EcpJourney = {
      name: info.title,
      startedAt: new Date().toISOString(),
      requests: [],
      databaseAssertions: [],
      sse: [],
      status: "NOT_RUN",
    };
    await use(journey);
    if (info.status !== "passed") {
      journey.status = info.status === "skipped" ? "NOT_RUN" : "FAIL";
      journey.reason = info.error?.message ?? `Browser journey ended as ${info.status}`;
    }
    const output = info.outputPath("journey.json");
    await mkdir(dirname(output), { recursive: true });
    await writeFile(output, serializeJourney(journey), "utf8");
  },
  api: async ({ playwright }, use, info) => {
    const token = process.env.ECP_BROWSER_TOKEN;
    if (!token) {
      await use(await playwright.request.newContext());
      return;
    }
    const context = await playwright.request.newContext({
      baseURL: process.env.ECP_BROWSER_BASE_URL,
      extraHTTPHeaders: {
        Authorization: `Bearer ${token}`,
        Accept: "application/json",
        ...(process.env.WORKSPACE ? { "X-ForgeFlow-Workspace": process.env.WORKSPACE } : {}),
      },
    });
    await use(context);
    await context.dispose();
    void info;
  },
});

export { expect } from "@playwright/test";
export type { Page };
