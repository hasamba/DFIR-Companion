import { test, expect } from "../fixtures/test.js";
import { revealSections } from "../fixtures/sections.js";

// Covers: US-352
// feature-user-stories.csv had no host-scope-and-clearance entry before this PR (#553) — it is a
// brand-new feature: GET/POST /cases/:id/host-scope, #sec-host-scope on the dashboard. US-352 was
// added to the CSV alongside this spec to describe it.
//
// The ledger is DERIVED, never persisted except for analyst decisions (src/analysis/hostScope.ts):
// a host escalates from evidence alone (unknown → suspected → confirmed), and only a signed
// decision reaches cleared/out-of-scope. These tests assert the derived board for the seeded demo
// case, the decision round trip (with and without a required reason), and that the dashboard panel
// actually renders the ledger rather than just fetching it.

test("host-scope: the demo case derives a non-empty host-scope ledger from its evidence", async ({
  page,
  demoCase,
}) => {
  await page.goto(`/dashboard?caseId=${encodeURIComponent(demoCase)}`);

  const res = await page.request.get(`/cases/${demoCase}/host-scope`);
  expect(res.status(), await res.text()).toBe(200);
  const body = (await res.json()) as {
    hosts: Array<{ name: string; presence: string; derivedStatus: string; effectiveStatus: string }>;
    counts: Record<string, number>;
    referencedNeverCollected: number;
    fleet: unknown;
    nearDuplicates: unknown[];
  };

  // The seeded incident touches DC01, FS01, WEB01 and WKSTN-JSMITH — a 200 with an empty hosts
  // array would mean the aggregation never ran, not that the case is clean.
  expect(body.hosts.length).toBeGreaterThan(0);
  const names = body.hosts.map((h) => h.name.toLowerCase());
  expect(names).toContain("wkstn-jsmith");

  // Nothing has been decided yet, so no host may show an analyst-only status: derivation may only
  // reach unknown/suspected/confirmed.
  for (const host of body.hosts) {
    expect(["unknown", "suspected", "confirmed"]).toContain(host.effectiveStatus);
    expect(host.effectiveStatus).toBe(host.derivedStatus);
  }

  const total = Object.values(body.counts).reduce((sum, n) => sum + n, 0);
  expect(total).toBe(body.hosts.length);
  expect(Array.isArray(body.nearDuplicates)).toBe(true);
});

test("host-scope: clearing a host requires a reason, and the decision persists", async ({ page, demoCase }) => {
  await page.goto(`/dashboard?caseId=${encodeURIComponent(demoCase)}`);

  const empty = await page.request.post(`/cases/${demoCase}/host-scope/ws-e2e-042`, {
    data: { to: "cleared", reason: "" },
  });
  expect(empty.status()).toBe(400);

  const bogus = await page.request.post(`/cases/${demoCase}/host-scope/ws-e2e-042`, {
    data: { to: "definitely-fine", reason: "x" },
  });
  expect(bogus.status()).toBe(400);

  const cleared = await page.request.post(`/cases/${demoCase}/host-scope/ws-e2e-042`, {
    data: { to: "cleared", reason: "Reimaged before the incident window; no artifacts collected" },
  });
  expect(cleared.status(), await cleared.text()).toBe(200);
  const ledger = (await cleared.json()) as {
    hosts: Array<{ name: string; effectiveStatus: string; decision?: { reason: string } }>;
  };
  const row = ledger.hosts.find((h) => h.name.toLowerCase() === "ws-e2e-042");
  expect(row?.effectiveStatus).toBe("cleared");
  expect(row?.decision?.reason).toContain("Reimaged");

  // A decision is append-only, so a fresh GET must reflect the same clearance rather than only the
  // in-memory response from the POST that recorded it.
  const refetch = await page.request.get(`/cases/${demoCase}/host-scope`);
  const refetched = (await refetch.json()) as { hosts: Array<{ name: string; effectiveStatus: string }> };
  const refetchedRow = refetched.hosts.find((h) => h.name.toLowerCase() === "ws-e2e-042");
  expect(refetchedRow?.effectiveStatus).toBe("cleared");
});

test("host-scope: the dashboard panel renders the board, gap list and host table — not an empty shell", async ({
  page,
  demoCase,
}) => {
  await page.goto(`/dashboard?caseId=${encodeURIComponent(demoCase)}`);
  await revealSections(page, "sec-host-scope");

  const panel = page.locator("#hostScopeBody");
  // The panel starts as the literal placeholder "—"; a passing test must see it replaced.
  await expect(panel.locator(".hs-board")).toBeVisible();
  await expect(panel).not.toHaveText("—");

  // Stat tiles: "All hosts" plus one per status, each carrying a real count control.
  const allTile = panel.locator('[data-hs-filter="all"]');
  await expect(allTile).toBeVisible();
  const allCount = Number((await allTile.locator(".hs-stat-n").innerText()).replace(/,/g, ""));
  expect(allCount).toBeGreaterThan(0);

  // The host table has at least one real row, with a host name in a <code> cell — not a
  // "No hosts match this filter" empty state.
  await expect(panel.locator(".hs-table tbody tr").first()).toBeVisible();
  await expect(panel.locator(".hs-empty")).toHaveCount(0);
  await expect(panel.locator("h4")).toContainText(["Scope gaps", "Hosts"]);
});

test("host-scope: clicking Clear… prompts for a reason and records the decision through the UI", async ({
  page,
  demoCase,
}) => {
  await page.goto(`/dashboard?caseId=${encodeURIComponent(demoCase)}`);
  await revealSections(page, "sec-host-scope");

  const panel = page.locator("#hostScopeBody");
  await expect(panel.locator(".hs-table tbody tr").first()).toBeVisible();

  const row = panel.locator('tr[data-host="wkstn-jsmith"]');
  await expect(row).toHaveCount(1);
  const clearButton = row.locator('[data-hs-action="cleared"]');

  page.once("dialog", (dialog) => {
    expect(dialog.type()).toBe("prompt");
    void dialog.accept("Verified clean by IR team on-site, 2026-05-20");
  });
  await clearButton.click();

  // The panel repaints from the server's response, so the badge should flip without a reload.
  await expect(row.locator(".hs-badge")).toHaveText("Cleared");

  const res = await page.request.get(`/cases/${demoCase}/host-scope`);
  const ledger = (await res.json()) as {
    hosts: Array<{ name: string; effectiveStatus: string; decision?: { reason: string } }>;
  };
  const wkstn = ledger.hosts.find((h) => h.name.toLowerCase() === "wkstn-jsmith");
  expect(wkstn?.effectiveStatus).toBe("cleared");
  expect(wkstn?.decision?.reason).toContain("Verified clean");
});

test("host-scope: an unknown case derives an empty ledger rather than erroring", async ({ page }) => {
  await page.goto("/dashboard");
  const res = await page.request.get("/cases/no-such-case-e2e-hs/host-scope");
  // Ledger derivation does not require the case to exist yet (loadHostScopeLedger reads whatever
  // state/timeline/decisions are present, defaulting to empty) — so this must not 404 or 500.
  expect(res.status(), await res.text()).toBe(200);
  const body = (await res.json()) as { hosts: unknown[] };
  expect(body.hosts).toEqual([]);
});
