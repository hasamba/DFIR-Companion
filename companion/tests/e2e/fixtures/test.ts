import { test as base } from "@playwright/test";
import { seedDemoCase } from "./api.js";

/** Case ids must be letters, numbers, dots, dashes or underscores (POST /cases validates this). */
function caseIdFor(workerIndex: number, testId: string): string {
  return `e2e-demo-${workerIndex}-${testId.replace(/[^\w.-]/g, "").slice(0, 12)}`;
}

/**
 * `demoCase` yields the id of a freshly seeded, fully populated case.
 *
 * Each worker gets its own case id so parallel specs never contend for the same case directory.
 *
 * Navigate with `/dashboard?caseId=${demoCase}` — NOT `/?caseId=`. GET / answers 302 -> /dashboard
 * and drops the query string, so the bare form silently loads with no case selected.
 */
export const test = base.extend<{ demoCase: string }>({
  demoCase: async ({ baseURL }, use, testInfo) => {
    const caseId = caseIdFor(testInfo.workerIndex, testInfo.testId);
    await seedDemoCase(baseURL ?? "http://127.0.0.1:4788", caseId);
    await use(caseId);
  },
});

export { expect } from "@playwright/test";
