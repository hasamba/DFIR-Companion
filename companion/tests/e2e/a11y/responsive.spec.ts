import { test, expect } from "../fixtures/test.js";

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
  // nothing, which is worse than the red one it replaced.
  await expect(page.locator("#swimlaneTableAlt tbody tr").first()).toBeAttached({ timeout: 30_000 });
  await page.waitForLoadState("networkidle");

  const overflow = await page.evaluate(() => {
    const doc = document.documentElement;
    const amount = doc.scrollWidth - doc.clientWidth;
    if (amount <= 1) return { amount, culprits: [] as string[] };
    // Name what actually escapes, so the failure is actionable instead of a bare number.
    const culprits: string[] = [];
    for (const el of [...document.querySelectorAll("body *")].slice(0, 4000)) {
      const r = el.getBoundingClientRect();
      if (r.width > 0 && r.right > doc.clientWidth + 1) {
        culprits.push(`${el.tagName}#${el.id || "-"}.${el.className || "-"} right=${Math.round(r.right)}`);
      }
      if (culprits.length >= 5) break;
    }
    return { amount, culprits };
  });

  // A page that scrolls sideways on a narrow display is unusable one-handed in the field. One pixel
  // of slack absorbs sub-pixel rounding; beyond that is a real layout escape.
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
