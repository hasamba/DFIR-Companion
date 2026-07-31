import { defineConfig, devices } from "@playwright/test";

// The E2E suite talks to a server started by tests/e2e/server-entry.ts, which is the ONLY supported
// way to boot the app under test: it asserts the cases root is a temp directory before it listens,
// so a misconfigured run cannot write into a real case directory. See tests/e2e/isolation.ts for
// why that is a hard precondition rather than a convention.
//
// testMatch is *.spec.ts, not *.test.ts, because vitest.config.ts includes tests/**/*.test.ts — a
// Playwright spec named .test.ts would be collected by `npm test` and fail there. The helper unit
// tests under tests/e2e/ ARE named .test.ts, deliberately, so that vitest does run them.
export default defineConfig({
  testDir: "tests/e2e",
  testMatch: "**/*.spec.ts",
  fullyParallel: true,
  forbidOnly: !!process.env.CI,
  // One retry, not the conventional two. A retry still marks the test "flaky" in the report, so a
  // genuine intermittent product bug stays visible instead of being laundered into a green check.
  retries: process.env.CI ? 1 : 0,
  reporter: process.env.CI ? [["html"], ["list"]] : [["list"]],
  use: {
    baseURL: "http://127.0.0.1:4788",
    trace: "on-first-retry",
    screenshot: "only-on-failure",
  },
  projects: [{ name: "chromium", use: { ...devices["Desktop Chrome"] } }],
  webServer: {
    command: "npx tsx tests/e2e/server-entry.ts",
    // GET /cases is the readiness probe: it is a real route that only answers once the case store
    // is wired, so a 200 means the app is genuinely usable rather than merely bound to the port.
    url: "http://127.0.0.1:4788/cases",
    reuseExistingServer: false,
    timeout: 60_000,
    stdout: "pipe",
    stderr: "pipe",
  },
});
