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
    expect(sw).toMatch(/captureGate\.run\(\s*automatic,/);
  });

  it("takes the navigation shot when the page has loaded, not when it is committed", () => {
    expect(sw).not.toContain("onCommitted.addListener");
    expect(sw).toMatch(/onCompleted\.addListener\([\s\S]{0,200}captureActiveTab\("navigation"\)/);
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
