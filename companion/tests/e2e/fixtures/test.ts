import { test as base, type TestInfo } from "@playwright/test";
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
 *
 * EXPORTED because a spec that builds its own case id needs the same three inputs, and a private
 * copy is what went wrong before: caseCreate.spec.ts grew a hand-rolled version that dropped
 * workerIndex and retry AND truncated testId, so its creating test answered 409 on every CI retry.
 * One helper, one set of traps.
 */
export function caseIdFor(prefix: string, testInfo: TestInfo): string {
  // NOT truncated. Playwright's testId is <fileHash>-<indexWithinFile>, so cutting it to a fixed
  // prefix keeps the file hash and drops the part that distinguishes tests — every test in a file
  // then shares one case id, which is strictly worse than the counter this replaced.
  //
  // isValidCaseId (src/storage/caseStore.ts) caps a case id at 80 characters, and the untruncated
  // form runs about 60 with a short prefix, so keep prefixes short rather than trimming testId.
  const safe = testInfo.testId.replace(/[^\w.-]/g, "");
  return `${prefix}-w${testInfo.workerIndex}-r${testInfo.retry}-${safe}`;
}

export const test = base.extend<{ demoCase: string }>({
  demoCase: async ({ baseURL }, use, testInfo) => {
    const caseId = caseIdFor("e2e-demo", testInfo);
    await seedDemoCase(baseURL ?? "http://127.0.0.1:4788", caseId);
    await use(caseId);
  },
});

export { expect } from "@playwright/test";
