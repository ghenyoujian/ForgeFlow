import { test, expect } from "./fixtures";
import { durableReadback, requireRealBrowser } from "./helpers";

test("real project event cursor and SSE identity are contiguous", async ({ api, ecp, journey }) => {
  requireRealBrowser(ecp);
  const projectId = crypto.randomUUID();
  const projectResponse = await api.post("/api/v1/projects", {
    data: {
      project_id: projectId,
      name: "Browser SSE journey",
      root_path: "",
      authority_mode: "MANAGED",
      data_origin: "NATIVE",
      goal: "ECP SSE cursor evidence",
      technology_stack: [],
      timezone: "UTC",
      paused: false,
      archived: false,
      revision: 0,
    },
    headers: { "Idempotency-Key": `browser-project-${crypto.randomUUID()}` },
  });
  expect(projectResponse.ok()).toBeTruthy();
  await durableReadback(projectResponse);

  const cursorPath = `/api/v1/projects/${encodeURIComponent(projectId)}/event-cursor`;
  const beforeResponse = await api.get(cursorPath);
  const before = await durableReadback<{ project_id: string; cursor: number }>(beforeResponse);
  expect(before.project_id).toBe(projectId);
  expect(Number.isSafeInteger(before.cursor)).toBe(true);
  journey.sse.push({ phase: "before-connect", cursor: `${projectId}:${before.cursor}` });

  const requirementId = `browser-requirement-${crypto.randomUUID()}`;
  const requirementResponse = await api.post(`/api/v1/projects/${encodeURIComponent(projectId)}/requirements`, {
    data: {
      project_id: projectId,
      requirement_id: requirementId,
      title: "SSE cursor requirement",
      source_anchor: "browser#sse",
      outcome: "cursor evidence",
      scope: "browser",
      acceptance: ["event is durable"],
      priority: 0,
      weight: 1,
      deferred_reason: null,
      revision: 1,
    },
    headers: { "Idempotency-Key": `browser-requirement-${crypto.randomUUID()}` },
  });
  expect(requirementResponse.ok()).toBeTruthy();
  await durableReadback(requirementResponse);

  const token = process.env.ECP_BROWSER_TOKEN;
  if (!token) throw new Error("BLOCKED: ECP_BROWSER_TOKEN is required");
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 5_000);
  let text = "";
  try {
    const response = await fetch(`${process.env.ECP_BROWSER_BASE_URL}${cursorPath.replace("event-cursor", `events?after=${before.cursor}`)}`, {
      headers: {
        Accept: "text/event-stream",
        Authorization: `Bearer ${token}`,
        "X-ForgeFlow-Workspace": ecp.workspaceId,
        "Last-Event-ID": `${projectId}:${before.cursor}`,
      },
      signal: controller.signal,
    });
    expect(response.ok).toBeTruthy();
    expect(response.headers.get("content-type") || "").toContain("text/event-stream");
    const reader = response.body?.getReader();
    if (!reader) throw new Error("SSE_EMPTY_BODY");
    const decoder = new TextDecoder();
    while (!text.includes("\n\n")) {
      const chunk = await reader.read();
      if (chunk.done) break;
      text += decoder.decode(chunk.value, { stream: true });
      if (text.length > 1024 * 1024) throw new Error("SSE_FRAME_TOO_LARGE");
    }
    await reader.cancel();
  } finally {
    clearTimeout(timeout);
  }
  const id = text.match(/^id:\s*(.+)$/m)?.[1]?.trim();
  const payload = text.match(/^data:\s*(.+)$/m)?.[1]?.trim();
  expect(id).toBeTruthy();
  expect(id?.startsWith(`${projectId}:`)).toBe(true);
  expect(payload).toBeTruthy();
  const sequence = Number(id?.split(":").pop());
  expect(Number.isSafeInteger(sequence)).toBe(true);
  expect(sequence).toBeGreaterThan(before.cursor);
  const event = JSON.parse(payload!);
  expect(event.project_id).toBe(projectId);
  expect(Number(event.project_seq)).toBe(sequence);
  journey.sse.push({ phase: "event-received", cursor: id, sequence, eventKind: event.kind });
  journey.databaseAssertions.push({ kind: "event-cursor-contiguous", projectId, before: before.cursor, after: sequence, requirementId });
  journey.status = "PASS";
});
