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
      // Content that is not rendered still has a box: Chrome lays out a CLOSED <details>'s body, so
      // the IOCs "Mark source" menu reported right=459 at 375px while widening nothing. Listed as an
      // offender, it hid the real one (#2923). checkVisibility() is false for that skipped content.
      if (!el.checkVisibility()) continue;
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

/** Seed a second case beside the test's own, to receive the "foreign" captures. */
async function seedOtherCase(demoCase: string, baseURL: string | undefined): Promise<string> {
  const otherCase = `${demoCase}-other`;
  await seedDemoCase(baseURL ?? "http://127.0.0.1:4788", otherCase);
  return otherCase;
}

/** Post a screenshot capture for the other case, so this page's case gets the warning. */
async function postForeignCapture(page: Page, otherCase: string): Promise<void> {
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
}

test.describe("cross-case capture warning", () => {
  // The one place the warning is wanted: every other spec runs with it suppressed (#2923, see
  // crossCaseBanner in fixtures/test.ts).
  test.use({ crossCaseBanner: "live" });

  // #2919: the cross-case warning ("screenshots are arriving for case X") carries the other case's
  // full id in its Switch button, and as one unwrapped row it pushed the page 45px sideways at phone
  // width. It only appeared when some other test had posted a capture in the last two minutes, so the
  // per-view test below failed by suite order. Raised here on purpose, through the real path: a
  // capture for a second case, then the dashboard's own check-on-connect.
  test("narrow screen: the cross-case capture warning wraps at 375px", async ({
    page,
    demoCase,
    baseURL,
  }) => {
    const otherCase = await seedOtherCase(demoCase, baseURL);
    await postForeignCapture(page, otherCase);

    await page.setViewportSize({ width: 375, height: 900 });
    await page.goto(`/dashboard?caseId=${encodeURIComponent(demoCase)}`);
    await waitForCaseRendered(page, demoCase);
    await expect(page.locator("#caseMismatchBanner")).toBeVisible({ timeout: 15_000 });
    // /captures/recent and the capture broadcast are global, so a parallel test's capture can put a
    // different case id in the warning (it did, in this file's own run). Post again while the page is
    // open until the live broadcast puts THIS test's case back, and measure that warning.
    await expect(async () => {
      await postForeignCapture(page, otherCase);
      await expect(page.locator("#caseMismatchSwitch")).toHaveText(`Switch to ${otherCase}`, {
        timeout: 2_000,
      });
    }).toPass({ timeout: 20_000 });

    const overflow = await measureOverflow(page);
    expect(
      overflow.amount,
      `horizontal overflow of ${overflow.amount}px. Widest offenders: ${overflow.culprits.join(" | ")}`,
    ).toBeLessThanOrEqual(1);
  });
});

// #2923: the default suppression has to actually take hold, or specs are coupled again with nothing
// to say so. The dashboard still raises the warning (its `hidden` flag clears); it just takes no space.
test("other specs: the cross-case warning is raised but takes no space by default", async ({
  page,
  demoCase,
  baseURL,
}) => {
  await postForeignCapture(page, await seedOtherCase(demoCase, baseURL));
  await page.goto(`/dashboard?caseId=${encodeURIComponent(demoCase)}`);
  await waitForCaseRendered(page, demoCase);
  await expect
    .poll(() => page.locator("#caseMismatchBanner").evaluate((el) => (el as HTMLElement).hidden), {
      timeout: 15_000,
    })
    .toBe(false);
  await expect(page.locator("#caseMismatchBanner")).toBeHidden();
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

// #2923: in one #2919 run the IOCs filter menus were named as escaping the viewport at 375px in the
// triage, report, deep-dive and hunt-prep views. Measured: they do not. The named one was the "Mark
// source" menu inside a CLOSED <details>, which has a layout box but no rendering, and was listed
// only because the cross-case warning had already widened the page. The per-view test above measures
// the menus closed; this one opens each through its real control, which is the interaction a phone
// user actually has, and checks the open menu stays on screen.
test("narrow screen: the IOC filter menus open inside the viewport at 375px", async ({ page, demoCase }) => {
  test.setTimeout(90_000);
  await page.setViewportSize({ width: 375, height: 900 });
  await page.goto(`/dashboard?caseId=${encodeURIComponent(demoCase)}`);
  await waitForCaseRendered(page, demoCase);
  await page.waitForLoadState("networkidle");

  /** [control that opens the menu, the menu] */
  const menus: [string, string][] = [
    ["#iocTypeFilterBtn", "#iocTypeFilterMenu"],
    ["#iocExcludeBtn", "#iocExcludeMenu"],
    [
      "#sec-iocs details.trusted-source-mark > summary",
      "#sec-iocs details.trusted-source-mark .src-filter-menu",
    ],
  ];
  const failures: string[] = [];
  for (const view of ["triage", "report", "deep-dive", "hunt-prep"]) {
    await page.locator("#dashViewBtn").click();
    const viewMenu = page.locator("#dashViewMenu");
    await expect(viewMenu).toBeVisible();
    await viewMenu.locator(`.dv-item[data-view="${view}"]`).click();
    await expect(viewMenu).toBeHidden();
    await page.waitForLoadState("networkidle");
    await expect(page.locator("#sec-iocs")).toBeVisible();

    for (const [control, menuSel] of menus) {
      const opener = page.locator(control);
      // The Types control appears only once the case has IOCs of more than one kind; the demo case
      // has them, so a missing control is a failure, not a skip.
      await expect(opener, `${view}: ${control} not shown`).toBeVisible();
      await opener.click();
      const menu = page.locator(menuSel);
      await expect(menu).toBeVisible();
      const box = await menu.evaluate((el) => {
        const r = el.getBoundingClientRect();
        return { left: r.left, right: r.right, vw: document.documentElement.clientWidth };
      });
      const overflow = await measureOverflow(page);
      if (box.left < -1 || box.right > box.vw + 1 || overflow.amount > 1) {
        failures.push(
          `${view} ${menuSel}: ${Math.round(box.left)}..${Math.round(box.right)} of ${box.vw}, page overflow ${overflow.amount}px (${overflow.culprits.join(" | ")})`,
        );
      }
      await opener.click(); // the same control closes it
      await expect(menu).toBeHidden();
    }
  }
  expect(failures, `IOC menus past the edge at 375px:\n${failures.join("\n")}`).toEqual([]);
});
