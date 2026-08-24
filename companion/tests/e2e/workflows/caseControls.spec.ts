import { mkdirSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";
import { test, expect, caseIdFor } from "../fixtures/test.js";
import type { Page } from "@playwright/test";
import { revealSections } from "../fixtures/sections.js";

// Covers: US-224, US-226, US-227, US-230, US-262
// US-233 (NSRL) lives in threatData.spec.ts: the real allow-list flow mutates the GLOBAL NSRL
// set, which races the fresh-install contract asserted there — so both run in one serial block
// in that file instead of split across two parallel ones. An earlier version here clicked Apply
// with no dataset and claimed the story on the zero-match report, which was a partial claim.
// (feature-user-stories.csv) — the case-level controls: the lifecycle menu, the regulatory
// notification clocks, the disk-space banner, the remembered import-severity preference, the NSRL
// apply button's honest refusal, and an incident type seeding a new case from the dialog.

async function openCase(page: Page, caseId: string): Promise<void> {
  await page.goto(`/dashboard?caseId=${encodeURIComponent(caseId)}`);
  await page.waitForLoadState("networkidle");
}

test("US-224: the lifecycle menu closes and reopens the case, and the button reflects the state", async ({
  page,
  demoCase,
}) => {
  await openCase(page, demoCase);

  const btn = page.locator("#lifecycleBtn");
  await expect(btn, "the lifecycle control appears once a case is connected").toBeVisible();

  // Closing pops a native confirm ("archive it now?") — decline it; archiving is caseLifecycle
  // route territory, this story is the state controls.
  page.on("dialog", (dialog) => void dialog.dismiss());

  await btn.click();
  const menu = page.locator("#lifecycleMenu");
  await expect(menu).toBeVisible();
  const closeBtn = page.locator("#closeBtn");
  await expect(closeBtn, "an open case offers Close").toBeVisible();
  await closeBtn.click();

  // The state change is server truth, and the button repaints to the closed (padlock) style.
  await expect
    .poll(
      async () => {
        const res = await page.request.get(`/cases`);
        const cases = (await res.json()) as Array<{ caseId: string; status?: string }>;
        return cases.find((c) => c.caseId === demoCase)?.status ?? "";
      },
      { timeout: 15_000 },
    )
    .toBe("closed");
  await expect(btn).toHaveClass(/\blc-closed\b/);

  // A closed case swaps Close for Reopen — the affordance the analyst needs next.
  await btn.click();
  const reopenBtn = page.locator("#reopenBtn");
  await expect(reopenBtn).toBeVisible();
  await expect(closeBtn).toBeHidden();
  await reopenBtn.click();

  await expect
    .poll(
      async () => {
        const res = await page.request.get(`/cases`);
        const cases = (await res.json()) as Array<{ caseId: string; status?: string }>;
        return cases.find((c) => c.caseId === demoCase)?.status ?? "";
      },
      { timeout: 15_000 },
    )
    .toBe("open");
  await expect(btn).not.toHaveClass(/\blc-closed\b/);
});

test("US-226: the compliance panel derives obligations, and the discovery date persists", async ({
  page,
  demoCase,
}) => {
  await openCase(page, demoCase);
  await revealSections(page, "sec-compliance");

  // The seeded case carries CONFIRMED findings with mapped techniques, so the panel must derive
  // real obligations — an empty panel on this case means the derivation lost its input.
  const results = await page.request.get(`/cases/${demoCase}/compliance`);
  expect(results.status(), await results.text()).toBe(200);
  const body = (await results.json()) as { results: unknown[] };
  expect(body.results.length, "confirmed seeded findings must map to obligations").toBeGreaterThan(0);
  await expect(page.locator("#compliancePanel")).not.toContainText(/^—$/);

  // The clocks all start from the discovery date the analyst sets. Setting it must persist on the
  // case — a date that only lives in this tab restarts every deadline for the next analyst.
  await page.locator("#complianceDiscovered").fill("2026-05-14");
  // The input saves on change; blur it to fire.
  await page.locator("#compliancePanel").click();

  await expect
    .poll(
      async () => {
        const res = await page.request.get(`/cases/${demoCase}/compliance`);
        const d = (await res.json()) as { discoveredAt?: string | null };
        return d.discoveredAt ?? "";
      },
      { timeout: 15_000 },
    )
    .toContain("2026-05-14");
  // With a date set, the hint explains what the clocks now mean rather than sitting blank.
  await expect(page.locator("#complianceDiscoveredHint")).not.toHaveText("");
});

test("US-227: a low-disk report raises the warning banner, and dismiss clears it", async ({
  page,
  demoCase,
}) => {
  // The banner renders whatever GET /disk-stats reports. The real route (covered by US-007
  // elsewhere) answers "none" on a healthy machine, so the scarce state is provoked by answering
  // the poll with a danger-level report — this tests the BANNER, which is what the story names,
  // not the disk arithmetic.
  await page.route("**/disk-stats", (route) =>
    route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({
        level: "danger",
        totalBytes: 100e9,
        freeBytes: 4e9,
        usedPct: 96,
        perCase: [],
      }),
    }),
  );
  await openCase(page, demoCase);

  const banner = page.locator("#diskWarnBanner");
  await expect(banner, "a danger-level report must raise the banner").toBeVisible({ timeout: 15_000 });
  await expect(banner).toHaveClass(/dw-danger/);
  // The text carries the numbers the analyst acts on — free space and the archive advice.
  await expect(page.locator("#diskWarnText")).toContainText(/96(\.0)?%/);
  await expect(page.locator("#diskWarnText")).toContainText(/archiv/i);

  await page.locator("#diskWarnDismiss").click();
  await expect(banner, "dismiss must hide the banner for the session").toBeHidden();
});

test("US-230: 'remember' on the severity floor skips the dialog for the next import", async ({
  page,
  demoCase,
}, testInfo) => {
  await openCase(page, demoCase);

  const writeEvidence = (name: string): string => {
    const path = testInfo.outputPath(name);
    mkdirSync(dirname(path), { recursive: true });
    writeFileSync(
      path,
      JSON.stringify({
        time: "2026-06-05T10:00:00Z",
        hostname: "SEVPREF-HOST",
        level: "Warning",
        module: "Filescan",
        message: `severity preference probe ${name}`,
        file: `C:\\Temp\\${name}`,
        reason_1: "YARA rule SUSP_PS1",
      }),
      "utf8",
    );
    return path;
  };

  // First import: the dialog appears; the analyst picks a floor and checks "remember".
  const chooser1 = page.waitForEvent("filechooser", { timeout: 15_000 });
  await page.locator("#importBtn").click();
  await (await chooser1).setFiles(writeEvidence("sevpref-one.jsonl"));

  const dialog = page.locator("#importSevOverlay");
  await expect(dialog).toHaveClass(/\bopen\b/);
  await dialog.locator("#importSevSelect").selectOption("info");
  await dialog.locator("#importSevRemember").check();
  await dialog.locator("#importSevOk").click();
  await expect(dialog).not.toHaveClass(/\bopen\b/);

  await expect
    .poll(
      async () => {
        const res = await page.request.get(`/cases/${demoCase}/import-meta`);
        const meta = (await res.json()) as { lastImportFile?: string };
        return meta.lastImportFile ?? "";
      },
      { timeout: 20_000 },
    )
    .toContain("sevpref-one");

  // Second import: the remembered choice must apply silently — the dialog staying closed IS the
  // feature. The import completing proves the silence was "remembered", not "stuck".
  const chooser2 = page.waitForEvent("filechooser", { timeout: 15_000 });
  await page.locator("#importBtn").click();
  await (await chooser2).setFiles(writeEvidence("sevpref-two.jsonl"));

  await expect(dialog, "the remembered preference must skip the dialog").not.toHaveClass(/\bopen\b/);
  await expect
    .poll(
      async () => {
        const res = await page.request.get(`/cases/${demoCase}/import-meta`);
        const meta = (await res.json()) as { lastImportFile?: string };
        return meta.lastImportFile ?? "";
      },
      { timeout: 20_000 },
    )
    .toContain("sevpref-two");
  await expect(dialog).not.toHaveClass(/\bopen\b/);

  // The remembered value is mirrored into Settings → General, where it can be changed or cleared.
  await page.locator("#settingsBtn").click();
  await expect(page.locator("#settingsOverlay")).toHaveClass(/\bopen\b/);
  await expect(page.locator("#importSevDefault")).toHaveValue("info");
});

test("US-262: picking an incident type in the dialog seeds the new case's questions and plan", async ({
  page,
}, testInfo) => {
  const caseId = caseIdFor("e2e-itype", testInfo);
  await page.goto("/dashboard");
  await page.waitForLoadState("networkidle");

  await page.locator("#newCaseBtn").click();
  const dialog = page.locator("#newCaseOverlay");
  await expect(dialog).toHaveClass(/\bopen\b/);
  await expect(dialog.locator("#ncCaseId")).not.toHaveValue("");

  await dialog.locator("#ncCaseId").fill(caseId);
  await dialog.locator("#ncName").fill("E2E incident-type seeded case");
  await dialog.locator("#ncInvestigator").fill("e2e");
  await dialog.locator("#ncTemplate").selectOption("type:ransomware");
  // Picking a type explains itself before the analyst commits.
  await expect(dialog.locator("#ncTemplateDesc")).toBeVisible();
  await expect(dialog.locator("#ncTemplateDesc")).toContainText(/ransomware/i);
  await dialog.locator("#ncCreate").click();
  await expect(dialog).not.toHaveClass(/\bopen\b/);

  // The seeding is the story: tailored initial questions land on the case, and the
  // ransomware collection plan exists — neither happens for a blank case.
  const state = await page.request.get(`/cases/${caseId}/state`);
  expect(state.status(), await state.text()).toBe(200);
  const parsed = (await state.json()) as { keyQuestions?: unknown[] };
  expect((parsed.keyQuestions ?? []).length, "the incident type must seed key questions").toBeGreaterThan(0);

  const plan = await page.request.get(`/cases/${caseId}/collection-plan`);
  const planBody = (await plan.json()) as { typeId?: string; plan?: { steps?: unknown[] } };
  expect(planBody.typeId).toBe("ransomware");
  expect((planBody.plan?.steps ?? []).length).toBeGreaterThan(0);
});
