import { test, expect } from "../fixtures/test.js";
import type { Page } from "@playwright/test";
import { revealSections } from "../fixtures/sections.js";

// seedDemoCase writes findings f001-f007 (12 in total including the extras), so these assert on
// known ids. "more than zero findings" would still pass if every row rendered empty.

async function openCase(page: Page, caseId: string): Promise<void> {
  await page.goto(`/dashboard?caseId=${encodeURIComponent(caseId)}`);
  await expect(page.locator("#sec-findings .finding").first()).toBeAttached({ timeout: 30_000 });
  // #sec-findings is display:none under the default view; without this these specs assert against
  // DOM the user cannot see.
  await revealSections(page, "sec-findings");
  await expect(page.locator("#sec-findings .finding").first()).toBeVisible();
}

test("lists the seeded findings by id", async ({ page, demoCase }) => {
  await openCase(page, demoCase);

  const findings = page.locator("#sec-findings .finding");
  expect(await findings.count()).toBeGreaterThan(0);

  // f001 is the initial-access finding in the seeded scenario.
  await expect(page.locator("#sec-findings .finding[data-fid='f001']")).toHaveCount(1);

  // Every finding must carry its id — it is what the ticket-export and jump-to-evidence actions
  // key off, so a finding without one renders fine and is inert.
  expect(await page.locator("#sec-findings .finding:not([data-fid])").count()).toBe(0);
});

test("findings carry readable text, not empty placeholders", async ({ page, demoCase }) => {
  await openCase(page, demoCase);
  const first = page.locator("#sec-findings .finding[data-fid='f001']");
  const text = (await first.innerText()).trim();
  // A row that renders but says nothing is the failure a row count cannot see.
  expect(text.length).toBeGreaterThan(20);
});

test("filtering applies to findings as well as events", async ({ page, demoCase }) => {
  await openCase(page, demoCase);
  const findings = page.locator("#sec-findings .finding");
  const before = await findings.count();
  expect(before).toBeGreaterThan(1);

  await page.locator("#main").click({ position: { x: 5, y: 5 } });
  await page.keyboard.press("/");
  await page.locator("#globalSearch").fill("zzz-no-such-finding-zzz");

  // The filter bar says "Filter events, findings, IOCs…" — so findings must actually respond to it.
  await expect.poll(async () => findings.count(), { timeout: 15_000 }).toBe(0);
});
