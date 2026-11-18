import { defineConfig, devices } from "@playwright/test";

/**
 * ECP browser runs are opt-in.  The config never starts a fake API or fixture
 * server: set ECP_BROWSER_BASE_URL to a real control deployment and provide
 * ECP_BROWSER_TOKEN/WORKSPACE when running a journey.
 */
export default defineConfig({
  testDir: "./tests/ecp",
  // Do not launch a browser in a developer checkout by accident.  A journey
  // is discoverable only when a real deployment and source-bound credentials
  // are explicitly supplied.
  testMatch: process.env.ECP_BROWSER_RUN === "1" && process.env.ECP_BROWSER_BASE_URL
    ? "**/*.spec.ts"
    : "**/*.never.ts",
  timeout: 30_000,
  expect: { timeout: 5_000 },
  fullyParallel: false,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 1 : 0,
  reporter: [["list"], ["json", { outputFile: process.env.ECP_BROWSER_REPORT ?? "test-results/ecp.json" }]],
  use: {
    baseURL: process.env.ECP_BROWSER_BASE_URL,
    ...devices["Desktop Chrome"],
    launchOptions: process.env.ECP_BROWSER_EXECUTABLE
      ? { executablePath: process.env.ECP_BROWSER_EXECUTABLE }
      : undefined,
    trace: "retain-on-failure",
    screenshot: "only-on-failure",
    // Keep the runner usable in minimal CI images without an ffmpeg download;
    // screenshots and traces remain available for the evidence receipt.
    video: "off",
    storageState: process.env.ECP_BROWSER_STORAGE_STATE,
  },
  webServer: process.env.ECP_BROWSER_BASE_URL
    ? undefined
    : undefined,
});
