import { test, expect } from "./fixtures";
import { recordResponse, requireRealBrowser } from "./helpers";

test("real browser navigation stays within the declared ECP shell budget", async ({ page, ecp, journey }) => {
  requireRealBrowser(ecp);
  const token = process.env.ECP_BROWSER_TOKEN;
  if (!token) throw new Error("BLOCKED: ECP_BROWSER_TOKEN is required");
  const budgetMs = Number(process.env.ECP_BROWSER_NAVIGATION_BUDGET_MS ?? "5000");
  if (!Number.isFinite(budgetMs) || budgetMs <= 0) throw new Error("BLOCKED: ECP_BROWSER_NAVIGATION_BUDGET_MS must be positive");
  page.on("response", response => { void recordResponse(journey, response.request(), response); });
  await page.addInitScript(({ token: browserToken, workspace }) => {
    sessionStorage.setItem("forgeflow.owner-token", browserToken);
    sessionStorage.setItem("forgeflow.workspace", workspace);
  }, { token, workspace: ecp.workspaceId });

  const started = performance.now();
  await page.goto("/executors/registry", { waitUntil: "domcontentloaded" });
  await expect(page.locator("#main-content")).toBeVisible();
  await expect(page.getByRole("heading", { name: "Agent Registry / Profile" })).toBeVisible();
  const elapsedMs = performance.now() - started;
  journey.databaseAssertions.push({ kind: "browser-navigation-budget", route: "/executors/registry", elapsedMs, budgetMs });
  expect(elapsedMs, `navigation exceeded ECP_BROWSER_NAVIGATION_BUDGET_MS=${budgetMs}`).toBeLessThanOrEqual(budgetMs);
  journey.status = "PASS";
});
