import { test, expect } from "./fixtures";
import { durableReadback, recordResponse, requireRealBrowser, reloadAndAssert } from "./helpers";

test("authenticated workspace shell survives a real reload", async ({ page, api, ecp, journey }) => {
  requireRealBrowser(ecp);
  const token = process.env.ECP_BROWSER_TOKEN;
  if (!token) throw new Error("BLOCKED: ECP_BROWSER_TOKEN is required");
  if (!ecp.projectId) throw new Error("BLOCKED: PROJECT must identify a persisted readback fixture");
  const identity = await durableReadback<{ actor_id: string; role: string; account?: { account_id: string } }>(
    await api.get("/api/v1/me"),
  );
  // This journey is a personal workspace session. Bind the declared principal
  // to the authenticated account and authoritative workspace membership; a
  // nonempty caller-provided PRINCIPAL is not evidence of that association.
  expect(identity.role).toBe("account");
  expect(identity.account?.account_id).toBeTruthy();
  expect(identity.actor_id).toBe(`account:${identity.account?.account_id}`);
  const workspaces = await durableReadback<Array<{ workspace_id: string }>>(await api.get("/api/v1/workspaces"));
  expect(workspaces.some(workspace => workspace.workspace_id === ecp.workspaceId)).toBeTruthy();
  const principals = await durableReadback<Array<{ principal_id: string; account_id: string | null; kind: string; status: string }>>(
    await api.get(`/api/v1/workspaces/${encodeURIComponent(ecp.workspaceId)}/principals`),
  );
  const principal = principals.filter(item => item.principal_id === ecp.principalId);
  expect(principal).toHaveLength(1);
  expect(principal[0]).toMatchObject({ kind: "HUMAN", status: "ACTIVE", account_id: identity.account?.account_id });
  const project = await durableReadback<{ project_id: string; name: string; revision: number }>(
    await api.get(`/api/v1/projects/${encodeURIComponent(ecp.projectId)}`),
  );
  expect(project.project_id).toBe(ecp.projectId);
  expect(project.name).toBeTruthy();
  journey.databaseAssertions.push({ kind: "api-authority-readback", actorId: identity.actor_id,
    principalId: principal[0].principal_id, workspaceId: ecp.workspaceId,
    projectId: project.project_id, revision: project.revision });
  page.on("response", response => {
    void recordResponse(journey, response.request(), response);
  });
  // Set the initial session once on this origin. An init script would silently
  // restore lost credentials on every reload and invalidate the persistence check.
  await page.goto("/healthz", { waitUntil: "domcontentloaded" });
  await page.evaluate(({ token, workspace, personal }) => {
    sessionStorage.setItem("forgeflow.owner-token", token);
    if (workspace) sessionStorage.setItem("forgeflow.workspace", workspace);
    if (personal) sessionStorage.setItem("forgeflow.personal-account", "1");
  }, { token, workspace: ecp.workspaceId, personal: identity.role === "account" });
  const sessionMatches = () => page.evaluate(({ token, workspace }) =>
    sessionStorage.getItem("forgeflow.owner-token") === token &&
    sessionStorage.getItem("forgeflow.workspace") === workspace &&
    sessionStorage.getItem("forgeflow.personal-account") === "1",
  { token, workspace: ecp.workspaceId });
  const identityRead = page.waitForResponse(response => new URL(response.url()).pathname === "/api/v1/me");
  const portfolioRead = page.waitForResponse(response => new URL(response.url()).pathname === "/api/v1/portfolio");
  await page.goto("/portfolio", { waitUntil: "domcontentloaded" });
  journey.url = page.url();
  const browserIdentity = await identityRead;
  expect(browserIdentity.ok()).toBeTruthy();
  expect((await browserIdentity.json()).data.actor_id).toBe(identity.actor_id);
  const portfolio = await portfolioRead;
  expect(portfolio.ok()).toBeTruthy();
  expect(portfolio.request().headers()["x-forgeflow-workspace"]).toBe(ecp.workspaceId);
  const portfolioRows = (await portfolio.json()).data as Array<{ project: { project_id: string } }>;
  expect(portfolioRows.filter(row => row.project.project_id === project.project_id)).toHaveLength(1);
  await expect(page.locator("#main-content")).toBeVisible();
  await expect(page.getByRole("heading", { name: "项目组合", exact: true })).toBeVisible();
  const projectLink = page.locator("#main-content").getByRole("link", { name: project.name, exact: true })
    .and(page.locator(`a[href="/projects/${encodeURIComponent(project.project_id)}"]`));
  await expect(projectLink).toBeVisible();
  expect(await sessionMatches()).toBe(true);
  const identityReload = page.waitForResponse(response => new URL(response.url()).pathname === "/api/v1/me");
  const portfolioReload = page.waitForResponse(response => new URL(response.url()).pathname === "/api/v1/portfolio");
  await reloadAndAssert(page, journey, "#main-content");
  const reloadedIdentity = await identityReload;
  expect(reloadedIdentity.ok()).toBeTruthy();
  expect((await reloadedIdentity.json()).data.actor_id).toBe(identity.actor_id);
  const reloadedPortfolio = await portfolioReload;
  expect(reloadedPortfolio.ok()).toBeTruthy();
  expect(reloadedPortfolio.request().headers()["x-forgeflow-workspace"]).toBe(ecp.workspaceId);
  const reloadedRows = (await reloadedPortfolio.json()).data as Array<{ project: { project_id: string } }>;
  expect(reloadedRows.filter(row => row.project.project_id === project.project_id)).toHaveLength(1);
  await expect(projectLink).toBeVisible();
  expect(await sessionMatches()).toBe(true);
  const readback = await durableReadback<{ project_id: string; revision: number }>(
    await api.get(`/api/v1/projects/${encodeURIComponent(ecp.projectId)}`),
  );
  expect(readback.project_id).toBe(project.project_id);
  expect(readback.revision).toBe(project.revision);
  journey.status = "PASS";
});
