import { writeFileSync } from "node:fs";
import { join } from "node:path";
import AxeBuilder from "@axe-core/playwright";
import { test, expect } from "../fixtures/test.js";

// Runs axe over the dashboard's real surfaces and records a violation count per scope and per rule.
// The counts are compared against scripts/a11y-ledger.json by scripts/check-a11y.mjs, in the same
// shape as the file-size and import-cycle ledgers: a number may fall freely, and raising one takes
// --init and a justification. Seeding the ledger at today's REAL counts is what lets the gate start
// working immediately instead of waiting for a clean sweep.
//
// SCOPES ARE NOT "THE FOUR VIEWS". The dashboard is one long scrolling page of ~49 sections; the
// triage/deep-dive/hunt-prep/report "views" are cockpit workspace shortcuts that show and hide
// sections, not separate pages. Scanning them as if they were four routes would have scanned the
// same DOM four times and reported a fourfold count.
//
// Everything runs in ONE test on purpose: the scans share a single results file, and parallel
// workers writing it would race.

const OUT = join(import.meta.dirname, "..", "..", "..", "a11y-results.json");

test("axe scan: dashboard surfaces", async ({ page, demoCase }) => {
  // Generous: this is one test doing every scan, and axe on a 25k-line DOM is not fast.
  test.setTimeout(180_000);

  /** scope -> rule id -> number of offending nodes */
  const results: Record<string, Record<string, number>> = {};

  const scan = async (scope: string): Promise<void> => {
    const run = await new AxeBuilder({ page })
      .withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa"])
      .analyze();
    const perRule: Record<string, number> = {};
    for (const v of run.violations) perRule[v.id] = (perRule[v.id] ?? 0) + v.nodes.length;
    results[scope] = perRule;
  };

  // 1. The empty dashboard, before any case is connected.
  await page.goto("/dashboard");
  await scan("dashboard-empty");

  // 2. With a fully populated case, which is what an investigator actually looks at.
  await page.goto(`/dashboard?caseId=${encodeURIComponent(demoCase)}`);
  await expect(page.locator("#swimlaneTableAlt tbody tr").first()).toBeAttached({ timeout: 30_000 });
  await scan("dashboard-case");

  // 3. Representative dialogs. Modals are the surface this issue changed most, so they are scanned
  //    open — a closed modal is display:none and axe skips it entirely, which would have let the
  //    dialog work land with no scan coverage at all.
  for (const overlayId of ["enrichOverlay", "anonOverlay", "settingsOverlay"]) {
    await page.evaluate((id) => document.getElementById(id)?.classList.add("open"), overlayId);
    await scan(`modal-${overlayId}`);
    await page.evaluate((id) => document.getElementById(id)?.classList.remove("open"), overlayId);
  }

  writeFileSync(OUT, `${JSON.stringify(results, null, 2)}\n`);

  // No pass/fail assertion on the counts here on purpose: the gate is the ledger comparison in
  // scripts/check-a11y.mjs, so a pre-existing violation does not fail the run while a NEW one does.
  // This only guards the scan itself — an empty result set means the scan silently did nothing.
  expect(Object.keys(results)).toHaveLength(5);
});
