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

/**
 * Whether the dashboard's cross-case capture warning (#caseMismatchBanner) may take up space.
 *
 * Every spec shares one e2e server, and the warning's inputs are global on purpose: GET
 * /captures/recent reports the newest capture across all cases, and every capture and import is
 * broadcast to every open dashboard. So a capture or import made by one test raised the warning in
 * whatever dashboard another test had open — a full-width row that moves the page, wraps at phone
 * width, and enters an axe scan — depending purely on suite order (#2923).
 *
 * "suppressed" (the default) hides the element with a constructed stylesheet in every page of the
 * test's browser context. That is presentation only: the dashboard still receives the events, runs
 * its timers and toggles the element's `hidden` attribute; the server state is still shared. It just
 * cannot change the layout or the accessibility tree of a spec that is not about it. A constructed
 * sheet, as in revealSections(), because the dashboard's CSP blocks an injected <style>.
 *
 * A spec ABOUT the warning opts back in with `test.use({ crossCaseBanner: "live" })`.
 */
export type CrossCaseBanner = "suppressed" | "live";

export const test = base.extend<{ demoCase: string; crossCaseBanner: CrossCaseBanner }>({
  crossCaseBanner: ["suppressed", { option: true }],
  context: async ({ context, crossCaseBanner }, use) => {
    if (crossCaseBanner === "suppressed") {
      await context.addInitScript(() => {
        const sheet = new CSSStyleSheet();
        sheet.replaceSync("#caseMismatchBanner { display: none !important; }");
        document.adoptedStyleSheets = [...document.adoptedStyleSheets, sheet];
      });
    }
    await use(context);
  },
  demoCase: async ({ baseURL }, use, testInfo) => {
    const caseId = caseIdFor("e2e-demo", testInfo);
    await seedDemoCase(baseURL ?? "http://127.0.0.1:4788", caseId);
    await use(caseId);
  },
});

export { expect } from "@playwright/test";
