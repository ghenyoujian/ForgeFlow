import { test, expect } from "./fixtures";
import { durableReadback, recordResponse, requireRealBrowser } from "./helpers";

test("real registry and collaboration hub preserve durable identity", async ({ page, api, ecp, journey }) => {
  requireRealBrowser(ecp);
  const token = process.env.ECP_BROWSER_TOKEN;
  if (!token) throw new Error("BLOCKED: ECP_BROWSER_TOKEN is required");
  page.on("response", response => { void recordResponse(journey, response.request(), response); });
  await page.addInitScript(({ token: browserToken, workspace }) => {
    sessionStorage.setItem("forgeflow.owner-token", browserToken);
    sessionStorage.setItem("forgeflow.workspace", workspace);
  }, { token, workspace: ecp.workspaceId });

  await page.goto("/executors/registry", { waitUntil: "domcontentloaded" });
  journey.url = page.url();
  await expect(page.locator("#main-content")).toBeVisible();
  await expect(page.getByRole("heading", { name: "Agent Registry / Profile" })).toBeVisible();
  await expect(page.getByText(/登记声明与实际运行资格分离/)).toBeVisible();
  await expect(page.getByText(/discovery[_-]only|UNKNOWN|NOT_RUN/)).toBeVisible();

  const conversationId = `browser-enterprise-${crypto.randomUUID()}`;
  const threadId = `browser-enterprise-thread-${crypto.randomUUID()}`;
  const conversationKey = `browser-enterprise-conversation-${crypto.randomUUID()}`;
  const conversationResponse = await api.post(`/api/v1/workspaces/${encodeURIComponent(ecp.workspaceId)}/conversations`, {
    data: { conversation_id: conversationId, project_id: null, participant_principal_ids: [ecp.principalId], request_key: conversationKey },
    headers: { "Idempotency-Key": conversationKey },
  });
  await durableReadback(conversationResponse);
  const threadResponseKey = `browser-enterprise-thread-${crypto.randomUUID()}`;
  const threadResponse = await api.post(`/api/v1/conversations/${encodeURIComponent(conversationId)}/threads`, {
    data: { thread_id: threadId, task_id: null, request_key: threadResponseKey },
    headers: { "Idempotency-Key": threadResponseKey },
  });
  await durableReadback(threadResponse);
  await page.goto(`/conversations/${encodeURIComponent(conversationId)}?thread=${encodeURIComponent(threadId)}`, { waitUntil: "domcontentloaded" });
  await expect(page.getByRole("region", { name: "ECP 协作会话" })).toBeVisible();
  const message = `enterprise browser message ${crypto.randomUUID()}`;
  await page.getByRole("textbox", { name: "协作消息" }).fill(message);
  await page.getByRole("button", { name: "发送消息" }).click();
  await expect(page.getByText("消息已提交；ACK 和 Task 状态保持独立。", { exact: true })).toBeVisible();
  const messagesResponse = await api.get(`/api/v1/conversations/${encodeURIComponent(conversationId)}/messages?after=0&limit=50`);
  const messages = await durableReadback<{ items: Array<{ payload?: { text?: string }; sender_principal_id: string }> }>(messagesResponse);
  const sent = messages.items.find(item => item.payload?.text === message);
  expect(sent?.sender_principal_id).toBe(ecp.principalId);
  journey.databaseAssertions.push({ kind: "conversation-message-readback", conversationId, threadId, principalId: ecp.principalId, message });
  journey.status = "PASS";
});
