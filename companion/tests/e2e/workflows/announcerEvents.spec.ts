import { mkdirSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";
import { test, expect } from "../fixtures/test.js";

// Covers: US-240
// (feature-user-stories.csv) — job, import and AI events reaching assistive technology.
//
// a11y/announce.spec.ts deliberately does NOT claim this story: it writes to #status by hand and
// proves the bridge underneath, because nothing in it triggers a real event. This spec closes that
// distance — a REAL import runs, and the announcements are captured as they happen.
//
// Captured with a MutationObserver installed BEFORE the import, because live regions are
// overwritten by the next announcement: asserting toHaveText() after the fact races whatever the
// dashboard says next (the same race that once made an import assertion report "the import never
// happened" against a clean 202 — see analystJourney.spec.ts). Observing records every text that
// ever passed through, which is exactly what a screen reader would have spoken.

test("US-240: a real import's progress reaches the live regions as spoken announcements", async ({
  page,
  demoCase,
}, testInfo) => {
  await page.goto(`/dashboard?caseId=${encodeURIComponent(demoCase)}`);
  await page.waitForLoadState("networkidle");

  // The recorder: every text that passes through either region, in order.
  await page.evaluate(() => {
    const w = window as unknown as { __e2eAnnounced: string[] };
    w.__e2eAnnounced = [];
    for (const id of ["a11y-live-polite", "a11y-live-assertive"]) {
      const el = document.getElementById(id);
      if (!el) continue;
      new MutationObserver(() => {
        const text = (el.textContent ?? "").trim();
        if (text) w.__e2eAnnounced.push(text);
      }).observe(el, { childList: true, characterData: true, subtree: true });
    }
  });

  const evidencePath = testInfo.outputPath("announce-probe.jsonl");
  mkdirSync(dirname(evidencePath), { recursive: true });
  writeFileSync(
    evidencePath,
    JSON.stringify({
      time: "2026-06-06T09:00:00Z",
      hostname: "ANNOUNCE-HOST",
      level: "Alert",
      module: "ProcessCheck",
      message: "announcer probe process",
      process_name: "announce-probe.exe",
      reason_1: "YARA rule Powerkatz_DLL",
    }),
    "utf8",
  );

  const chooser = page.waitForEvent("filechooser", { timeout: 15_000 });
  await page.locator("#importBtn").click();
  await (await chooser).setFiles(evidencePath);

  const sevDialog = page.locator("#importSevOverlay");
  await expect(sevDialog).toHaveClass(/\bopen\b/);
  await sevDialog.locator("#importSevSelect").selectOption("info");
  await sevDialog.locator("#importSevOk").click();

  // The import's COMPLETION must have been spoken, not merely painted. The tense is the
  // assertion: progress says "importing 1/1: …" and completion says "imported thor — analyzing",
  // so matching a bare /import/i would pass on the progress line while the completion never
  // reached assistive technology — the story is the completion event.
  await expect
    .poll(
      async () => page.evaluate(() => (window as unknown as { __e2eAnnounced: string[] }).__e2eAnnounced),
      { timeout: 30_000 },
    )
    .toEqual(expect.arrayContaining([expect.stringMatching(/\bimported\b.*thor/i)]));

  // Second named event: AI-synthesis-COMPLETE, triggered by the real toolbar button. Same tense
  // rule: the click writes "synthesizing…" immediately, and only completion writes
  // "synthesized: N findings, M techniques" — a bare /synth/i would pass on the start
  // announcement with the completion still pending, which is exactly not the story.
  // (The third named event — import FAILURE — is not provokable through this harness's UI: every
  // text file falls back to the log importer and is accepted, so there is no in-browser action
  // that fails an import. That gap is the harness's, and it is stated rather than papered over.)
  await page.locator("#synthesize").click();
  await expect
    .poll(
      async () => page.evaluate(() => (window as unknown as { __e2eAnnounced: string[] }).__e2eAnnounced),
      { timeout: 60_000 },
    )
    .toEqual(expect.arrayContaining([expect.stringMatching(/synthesized: \d+ findings/i)]));
});
