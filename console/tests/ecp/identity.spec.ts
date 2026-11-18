import { test, expect } from "./fixtures";
import { durableReadback, recordResponse, requireRealBrowser, reloadAndAssert } from "./helpers";

test("real workspace identity remains scoped after reload", async ({ page, api, ecp, journey }) => {
  requireRealBrowser(ecp);
  const token = process.env.ECP_BROWSER_TOKEN;
  if (!token) throw new Error("BLOCKED: ECP_BROWSER_TOKEN is required");
  page.on("response", response => { void recordResponse(journey, response.request(), response); });
  await page.addInitScript(({ token: browserToken, workspace }) => {
    sessionStorage.setItem("forgeflow.owner-token", browserToken);
    sessionStorage.setItem("forgeflow.workspace", workspace);
  }, { token, workspace: ecp.workspaceId });

  const workspacesResponse = await api.get("/api/v1/workspaces");
  const workspaces = await durableReadback<Array<{ workspace_id: string; role?: string }>>(workspacesResponse);
  const current = workspaces.find(workspace => workspace.workspace_id === ecp.workspaceId);
  if (!current) throw new Error("BLOCKED: WORKSPACE is not visible to the authenticated principal");
  journey.databaseAssertions.push({ kind: "workspace-membership-readback", workspaceId: current.workspace_id, role: current.role ?? null });

  await page.goto("/workspaces", { waitUntil: "domcontentloaded" });
  journey.url = page.url();
  await expect(page.locator("#main-content")).toBeVisible();
  await expect(page.getByRole("heading", { name: "工作区与成员" })).toBeVisible();
  const selector = page.getByRole("combobox", { name: "切换协作工作区" });
  await expect(selector).toHaveValue(ecp.workspaceId);
  await reloadAndAssert(page, journey, "#main-content");
  await expect(page.getByRole("combobox", { name: "切换协作工作区" })).toHaveValue(ecp.workspaceId);
  journey.status = "PASS";
});
