import { test, expect } from "./fixtures";
import { durableReadback, requireRealBrowser } from "./helpers";

test("real conversation send is durable and idempotent after refresh", async ({ api, ecp, journey }) => {
  requireRealBrowser(ecp);
  const conversationId = `browser-conversation-${crypto.randomUUID()}`;
  const threadId = `browser-thread-${crypto.randomUUID()}`;
  const conversationKey = `browser-conversation-${crypto.randomUUID()}`;
  const messageKey = `browser-message-${crypto.randomUUID()}`;
  const base = `/api/v1/workspaces/${encodeURIComponent(ecp.workspaceId)}`;
  const record = async (name: string, response: { status: () => number; url: () => string }) => {
    journey.requests.push({ name, url: response.url(), status: response.status(), capturedAt: new Date().toISOString() });
    if (response.status() >= 400) throw new Error(`${name} returned HTTP ${response.status()}`);
  };

  const conversationResponse = await api.post(`${base}/conversations`, {
    data: { conversation_id: conversationId, project_id: null, participant_principal_ids: [ecp.principalId], request_key: conversationKey },
    headers: { "Idempotency-Key": conversationKey },
  });
  await record("conversation-create", conversationResponse);
  await durableReadback(conversationResponse);

  const threadResponseKey = `browser-thread-${crypto.randomUUID()}`;
  const threadResponse = await api.post(`/api/v1/conversations/${conversationId}/threads`, {
    data: { thread_id: threadId, task_id: null, request_key: threadResponseKey },
    headers: { "Idempotency-Key": threadResponseKey },
  });
  await record("thread-create", threadResponse);
  await durableReadback(threadResponse);

  const message = {
    thread_id: threadId,
    message_kind: "chat.message",
    client_request_id: messageKey,
    payload: { text: "browser durable message" },
    correlation_id: null,
    causation_id: null,
    expires_at: null,
  };
  const firstResponse = await api.post(`/api/v1/conversations/${conversationId}/messages`, {
    data: message,
    headers: { "Idempotency-Key": messageKey },
  });
  await record("message-first", firstResponse);
  const first = await durableReadback<{ message_id: string; sequence: number; replayed?: boolean }>(firstResponse);

  const replayResponse = await api.post(`/api/v1/conversations/${conversationId}/messages`, {
    data: message,
    headers: { "Idempotency-Key": messageKey },
  });
  await record("message-replay", replayResponse);
  const replay = await durableReadback<{ message_id: string; sequence: number; replayed?: boolean }>(replayResponse);
  expect(replay.replayed).toBe(true);
  expect(replay.message_id).toBe(first.message_id);
  expect(replay.sequence).toBe(first.sequence);

  const readResponse = await api.get(`/api/v1/conversations/${conversationId}/messages?after=0&limit=10`);
  await record("message-refresh-readback", readResponse);
  const read = await durableReadback<{ items: Array<{ message_id: string; sequence: number }>; next_cursor?: number }>(readResponse);
  expect(read.items.some(item => item.message_id === first.message_id && item.sequence === first.sequence)).toBe(true);
  journey.databaseAssertions.push({ kind: "durable-message-readback", conversationId, messageId: first.message_id, sequence: first.sequence });
  journey.status = "PASS";
});
