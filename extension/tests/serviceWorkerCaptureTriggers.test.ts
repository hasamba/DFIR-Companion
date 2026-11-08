// Capture-trigger wiring in the service worker (#2255). Asserted against source, like
// serviceWorkerMessages.test.ts: serviceWorker.ts registers its listeners at import time, so it
// cannot be imported here. The gate's behaviour itself is unit-tested in captureGate.test.ts.
import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";

const sw = readFileSync(resolve(__dirname, "../src/serviceWorker.ts"), "utf-8");
const manifest = JSON.parse(readFileSync(resolve(__dirname, "../manifest.json"), "utf-8")) as {
  permissions: string[];
};

function captureNowBody(): string {
  const body = /async function captureActiveTabNow\([\s\S]*?\n\}/.exec(sw)?.[0];
  expect(body, "captureActiveTabNow not found in serviceWorker.ts").toBeDefined();
  return body as string;
}

describe("service-worker capture triggers", () => {
  it("routes every capture through the single-flight gate", () => {
    expect(sw).toMatch(/captureThroughGate\(\s*captureGate,\s*automatic,/);
  });

  it("uploads outside the gate, so a slow companion cannot drop screenshots", () => {
    const body = captureNowBody();
    expect(body).not.toContain("controller.capture");
    expect(body).not.toContain("readCaseCredential");
    expect(sw).toMatch(/async function uploadSnapshot\([\s\S]*?controller\.capture\(/);
  });

  it("takes the navigation shot when the page has loaded, not when it is committed", () => {
    expect(sw).not.toContain("onCommitted.addListener");
    expect(sw).toMatch(/onCompleted\.addListener\([\s\S]{0,200}captureSafely\("navigation"\)/);
    // onCompleted is part of the existing webNavigation permission — no new permission is needed.
    expect(manifest.permissions).toContain("webNavigation");
  });

  it("skips a rate-limited screenshot without recording a blocked capture", () => {
    const body = captureNowBody();
    const rateLimit = /if \(isCaptureRateLimitError\(e\)\) \{[\s\S]*?\}/.exec(body)?.[0];
    expect(rateLimit).toBeDefined();
    expect(rateLimit).not.toContain("recordBlockedCapture");
    expect(rateLimit).not.toContain("setBadge");
  });

  it("records a blocked capture for inaccessible pages only when the analyst asked for it", () => {
    const blocked = captureNowBody().match(/automatic \? \{ ok: false, error \} : recordBlockedCapture/g) ?? [];
    expect(blocked.length).toBe(2);
  });
});

describe("service-worker capture toggle and timer (#2257)", () => {
  it("refuses to start from the shortcut without a case or site access", () => {
    const toggle = /async function toggleCapture\(\)[\s\S]*?\n\}/.exec(sw)?.[0];
    expect(toggle, "toggleCapture not found in serviceWorker.ts").toBeDefined();
    const guard = toggle?.indexOf("startCaptureBlockReason(settings, hasAccess)") ?? -1;
    // #2398: the check and the write are one step on the settings writer.
    const rec = toggle?.indexOf("return blocked ? undefined : { running: true }") ?? -1;
    expect(guard).toBeGreaterThan(-1);
    expect(guard).toBeLessThan(rec);
    expect(toggle).toContain("settingsWriter.transact(");
  });

  it("never schedules the timer under the browser's 30 s alarm floor", () => {
    expect(sw).toMatch(/periodInMinutes: clampIntervalSeconds\(settings\.intervalSeconds\) \/ 60/);
  });
});

// #2398: every settings write goes through the one writer in the service worker, and the timer,
// icon and badge follow the stored value rather than a best-effort message.
describe("service-worker settings ownership (#2398)", () => {
  const pages = ["popup.ts", "options.ts"].map((name) => readFileSync(resolve(__dirname, `../src/${name}`), "utf-8"));

  it("no page writes the settings key to storage itself", () => {
    for (const page of pages) expect(page).not.toMatch(/storage\.local\.set\(\{\s*settings/);
  });

  it("the worker never writes the whole settings object outside the writer", () => {
    expect(sw).not.toMatch(/storage\.local\.set\(\{\s*settings/);
  });

  it("refuses settings changes that do not come from an extension page", () => {
    const handler = /if \(msg\?\.kind === "update_settings"\) \{[\s\S]*?\n {2}\}/.exec(sw)?.[0];
    expect(handler, "update_settings handler not found").toBeDefined();
    expect(handler).toContain("isExtensionPageSender(sender.url");
  });

  it("a case list asked before an edit to the case, URL or token cannot repaint or clear (#2398 review)", () => {
    const popup = pages[0];
    const persistField = /async function persistField\([\s\S]*?\n\}/.exec(popup)?.[0];
    expect(persistField).toContain("invalidateCaseList()");
    const clear = /async function clearVanishedCase\([\s\S]*?\n\}/.exec(popup)?.[0];
    expect(clear).toMatch(/caseId, companionUrl: checked\.companionUrl, serviceToken: checked\.serviceToken/);
  });

  it("reschedules the timer from the storage change, not only from a message", () => {
    expect(sw).toMatch(/storage\.onChanged\.addListener\([\s\S]{0,400}settingsChangeNeedsReconcile\(changes\[SETTINGS_KEY\]\)/);
  });
});
