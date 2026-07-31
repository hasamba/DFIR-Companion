import { test as base } from "@playwright/test";
import { seedDemoCase } from "./api.js";

// Per-worker counter. Combined with workerIndex and retry it is unique for the whole run, which
// matters because the server is fresh per run but NOT per test: a case id derived from the stable
// testId collides on retry, and POST /cases/seed-demo then answers 409 ("case is open — close it
// before force-seeding") because the previous attempt's dashboard already connected to it.
let seq = 0;

/** Case ids must be letters, numbers, dots, dashes or underscores (POST /cases validates this). */
function nextCaseId(workerIndex: number, retry: number): string {
  seq += 1;
  return `e2e-demo-w${workerIndex}-r${retry}-n${seq}`;
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
    const caseId = nextCaseId(testInfo.workerIndex, testInfo.retry);
    await seedDemoCase(baseURL ?? "http://127.0.0.1:4788", caseId);
    await use(caseId);
  },
});

export { expect } from "@playwright/test";
