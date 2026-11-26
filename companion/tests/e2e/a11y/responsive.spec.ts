import type { Page } from "@playwright/test";
import { test, expect } from "../fixtures/test.js";
import { waitForCaseRendered } from "../fixtures/sections.js";
import { seedDemoCase } from "../fixtures/api.js";

// Covers: NO USER STORY EXISTS.
// feature-user-stories.csv has no accessibility stories — only US-216 and US-220 mention it,
// incidentally, about single controls. The a11y suite is gated by scripts/a11y-ledger.json
// instead. Mapping these to feature ids would misrepresent both.
//

// Task 10 added the media queries; this proves they take effect. A media query nobody exercises is
// one that can silently stop matching — a renamed variable or a later rule with higher specificity
// costs nothing at build time and everything to the user who needs it.
//
// Emulation is applied with page.emulateMedia()/setViewportSize() rather than test.use(). A
// describe-level test.use({ reducedMotion }) did NOT reach the page here: matchMedia reported false
// inside the test while the CSS was plainly correct in a standalone browser. The forced-colors
// test was passing for the same reason — vacuously, with no emulation applied at all. Each test
// below now asserts the emulation took hold before asserting anything about the page, so this
// cannot silently regress into a test that proves nothing.

/** How far the page scrolls sideways, plus the first few elements past the right edge. */
async function measureOverflow(page: Page): Promise<{ amount: number; culprits: string[] }> {
  return page.evaluate(() => {
    const doc = document.documentElement;
    const amount = doc.scrollWidth - doc.clientWidth;
    if (amount <= 1) return { amount, culprits: [] as string[] };
    // Name what actually escapes, so the failure is actionable instead of a bare number. The page
    // has ~18,000 elements, so a capped scan never reached the offenders (#2457). Report only the
    // outermost escape, and skip anything inside a box that scrolls or clips it — that content
    // does not widen the page.
    const clipped = (el: Element): boolean => {
      for (let p = el.parentElement; p && p !== document.body; p = p.parentElement) {
        if (getComputedStyle(p).overflowX !== "visible") return true;
      }
      return false;
    };
    const culprits: string[] = [];
    for (const el of document.querySelectorAll("body *")) {
      const r = el.getBoundingClientRect();
      if (r.width === 0 || r.right <= doc.clientWidth + 1) continue;
      const parent = el.parentElement;
      if (parent && parent !== document.body && parent.getBoundingClientRect().right > doc.clientWidth + 1)
        continue;
      if (clipped(el)) continue;
      const section = el.closest("section")?.id || "-";
      culprits.push(
        `${section}: ${el.tagName}#${el.id || "-"}.${el.className || "-"} right=${Math.round(r.right)}`,
      );
      if (culprits.length >= 5) break;
    }
    return { amount, culprits };
  });
}

test("reduced motion: no element keeps a perceptible transition or animation", async ({ page }) => {
  await page.emulateMedia({ reducedMotion: "reduce" });
  await page.goto("/dashboard");

  expect(
    await page.evaluate(() => matchMedia("(prefers-reduced-motion: reduce)").matches),
    "prefers-reduced-motion emulation did not apply — the rest of this test would prove nothing",
  ).toBe(true);

  const moving = await page.evaluate(() => {
    const offenders: string[] = [];
    const seconds = (value: string): number[] =>
      value.split(",").map((v) => {
        const n = parseFloat(v);
        return Number.isNaN(n) ? 0 : n * (v.trim().endsWith("ms") ? 0.001 : 1);
      });
    for (const el of [...document.querySelectorAll("*")].slice(0, 1500)) {
      const cs = getComputedStyle(el);
      const worst = Math.max(...seconds(cs.transitionDuration), ...seconds(cs.animationDuration));
      // The reduce block clamps everything to 0.01ms. Anything still measurable in tens of
      // milliseconds escaped it.
      if (worst > 0.05) offenders.push(`${el.tagName}.${el.className || "(none)"}: ${worst}s`);
    }
    return offenders.slice(0, 5);
  });

  expect(moving, `still animating under prefers-reduced-motion: ${moving.join("; ")}`).toEqual([]);
});

test("forced colors: content stays legible in high contrast", async ({ page, demoCase }) => {
  await page.emulateMedia({ forcedColors: "active" });
  await page.goto(`/dashboard?caseId=${encodeURIComponent(demoCase)}`);

  expect(
    await page.evaluate(() => matchMedia("(forced-colors: active)").matches),
    "forced-colors emulation did not apply — the rest of this test would prove nothing",
  ).toBe(true);

  await expect(page.locator("#main")).toBeVisible();
  // A common forced-colors failure is text disappearing because a hard-coded colour survives while
  // its background is replaced. Assert real content is rendered, not just that the page loaded.
  await expect(page.locator("#caseId")).toHaveValue(demoCase);
  await expect(page.locator("header")).toBeVisible();
});

test("narrow screen: the page does not scroll sideways at 380px", async ({ page, demoCase }) => {
  await page.setViewportSize({ width: 380, height: 800 });
  await page.goto(`/dashboard?caseId=${encodeURIComponent(demoCase)}`);

  expect(await page.evaluate(() => window.innerWidth)).toBe(380);

  // Measure only once the case content has actually rendered. Measuring at load reported no
  // overflow purely because the wide content had not arrived yet — a green result that proved
  // nothing, which is worse than the red one it replaced. The signal is the forensic timeline, which
  // renders in every view: the swimlane this used to wait on is hidden in the default Now view and,
  // since #2854, not loaded until shown.
  await waitForCaseRendered(page, demoCase);
  await page.waitForLoadState("networkidle");

  const overflow = await measureOverflow(page);

  // A page that scrolls sideways on a narrow display is unusable one-handed in the field. One pixel
  // of slack absorbs sub-pixel rounding; beyond that is a real layout escape.
  expect(
    overflow.amount,
    `horizontal overflow of ${overflow.amount}px. Widest offenders: ${overflow.culprits.join(" | ")}`,
  ).toBeLessThanOrEqual(1);
});

// #2919: the cross-case warning ("screenshots are arriving for case X") carries the other case's
// full id in its Switch button, and as one unwrapped row it pushed the page 45px sideways at phone
// width. It only appeared when some other test had posted a capture in the last two minutes, so the
// per-view test below failed by suite order. Raised here on purpose, through the real path: a
// capture for a second case, then the dashboard's own check-on-connect.
test("narrow screen: the cross-case capture warning wraps at 375px", async ({ page, demoCase, baseURL }) => {
  const otherCase = `${demoCase}-other`;
  await seedDemoCase(baseURL ?? "http://127.0.0.1:4788", otherCase);
  const posted = await page.request.post("/captures", {
    data: {
      caseId: otherCase,
      timestamp: "2026-05-16T09:00:00.000Z",
      url: "https://console.example.com/alerts/8821",
      tabTitle: "Alert 8821",
      triggerType: "click",
      imageBase64:
        "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==",
    },
  });
  expect(posted.ok(), await posted.text()).toBe(true);

  await page.setViewportSize({ width: 375, height: 900 });
  await page.goto(`/dashboard?caseId=${encodeURIComponent(demoCase)}`);
  await waitForCaseRendered(page, demoCase);
  await expect(page.locator("#caseMismatchBanner")).toBeVisible({ timeout: 15_000 });

  const overflow = await measureOverflow(page);
  expect(
    overflow.amount,
    `horizontal overflow of ${overflow.amount}px. Widest offenders: ${overflow.culprits.join(" | ")}`,
  ).toBeLessThanOrEqual(1);
});

test("narrow screen: the skip link still works at 380px", async ({ page }) => {
  await page.setViewportSize({ width: 380, height: 800 });
  await page.goto("/dashboard");
  await page.keyboard.press("Tab");
  await expect(page.locator(".skip-link")).toBeFocused();
  await page.keyboard.press("Enter");
  await expect(page.locator("#main")).toBeFocused();
});

// #2457: the 380px test above only ever measured the default layout. Every built-in view except Now
// scrolled sideways at phone AND tablet width (931px wide), because the IOCs header could not wrap
// and the single page column grew to its width. Each view shows a different mix of sections, so
// each one is measured, through the real view menu.
const NARROW_VIEWS = ["analyst", "lead", "executive", "triage", "report", "deep-dive", "hunt-prep"];

for (const width of [375, 768]) {
  test(`narrow screen: no built-in view scrolls sideways at ${width}px`, async ({ page, demoCase }) => {
    // Seven view switches, each waiting for the network to settle — and since #2854 the Analyst
    // switch is what loads the ~25 heavy panels the default view skipped. ~18s alone, past the 30s
    // default when the suite runs in parallel.
    test.setTimeout(90_000);
    await page.setViewportSize({ width, height: 900 });
    await page.goto(`/dashboard?caseId=${encodeURIComponent(demoCase)}`);
    expect(await page.evaluate(() => window.innerWidth)).toBe(width);
    await waitForCaseRendered(page, demoCase);
    await page.waitForLoadState("networkidle");

    const failures: string[] = [];
    for (const view of NARROW_VIEWS) {
      await page.locator("#dashViewBtn").click();
      const menu = page.locator("#dashViewMenu");
      await expect(menu).toBeVisible();
      await menu.locator(`.dv-item[data-view="${view}"]`).click();
      await expect(menu).toBeHidden();
      // Hidden heavy panels load when a view shows them (#2854). The swimlane is one of them and
      // Analyst shows it, so its labels appearing proves the view menu started the deferred loads.
      // It does not prove every other deferred panel has painted; networkidle below is what waits
      // for their requests to settle before the measurement.
      if (view === "analyst") {
        await expect(page.locator("#swimlaneLabels .swimlane-label").first()).toBeAttached({
          timeout: 30_000,
        });
      }
      await page.waitForLoadState("networkidle");
      const overflow = await measureOverflow(page);
      if (overflow.amount > 1) {
        failures.push(`${view}: ${overflow.amount}px (${overflow.culprits.join(" | ")})`);
      }
    }

    expect(failures, `views that scroll sideways at ${width}px:\n${failures.join("\n")}`).toEqual([]);
  });
}
