import { test as base } from "@playwright/test";
import { seedDemoCase } from "./api.js";

/**
 * A case id unique to this test ATTEMPT.
 *
 * Was a per-worker counter, which was wrong in a way that only showed up once a spec started
 * DELETING cases: Playwright reuses worker processes across spec files, and the module — counter
 * and all — is loaded fresh per file, so two files could both produce e2e-demo-w0-r0-n1. Two tests
 * then shared one case. While every test only read, that mostly looked like nothing; as soon as
 * caseLifecycle.spec.ts deleted its case, the other test failed with "case not found". Seeding is
 * force:true, so a collision also silently RESET a case out from under a running test.
 *
 * testId is unique per test and stable across a run; retry disambiguates attempts of the same
 * test, which is what the counter was originally added to fix. Together they need no shared state.
 */
function caseIdFor(testId: string, workerIndex: number, retry: number): string {
  // NOT truncated. Playwright's testId is <fileHash>-<indexWithinFile>, so cutting it to a fixed
  // prefix keeps the file hash and drops the part that distinguishes tests — every test in a file
  // then shares one case id, which is strictly worse than the counter this replaced.
  const safe = testId.replace(/[^\w.-]/g, "");
  return `e2e-demo-w${workerIndex}-r${retry}-${safe}`;
}

export const test = base.extend<{ demoCase: string }>({
  demoCase: async ({ baseURL }, use, testInfo) => {
    const caseId = caseIdFor(testInfo.testId, testInfo.workerIndex, testInfo.retry);
    await seedDemoCase(baseURL ?? "http://127.0.0.1:4788", caseId);
    await use(caseId);
  },
});

export { expect } from "@playwright/test";
