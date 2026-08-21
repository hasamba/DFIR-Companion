// Every message handler that keeps the channel open (returns true) must answer it on BOTH arms.
//
// `void somePromise.then(sendResponse); return true;` answers only the happy path: a rejection —
// QuotaExceededError from the offline capture queue, storage.local.set failing — leaves the port
// open until the browser kills it, so the popup's `await runtime.sendMessage(...)` rejects with
// "message port closed", the status element never updates, and the analyst's action is lost with
// zero feedback plus an unhandled rejection in both contexts.
//
// Asserted against source, like firefox.test.ts: serviceWorker.ts registers its listeners at
// import time, so it cannot be imported here without standing up the whole extension environment.
import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";

const sw = readFileSync(resolve(__dirname, "../src/serviceWorker.ts"), "utf-8");

describe("service-worker message handlers", () => {
  it("never pass sendResponse to .then() without a rejection arm", () => {
    // `.then(sendResponse)` with a closing paren right after is the one-armed form; the fixed
    // form is `.then(sendResponse, <handler>)`. Any regression to the former reintroduces the
    // dead-port failure described above.
    expect(sw).not.toMatch(/\.then\(sendResponse\)/);
  });

  it("answer the protocol's failure shape when capture_once or push_artifact reject", () => {
    // Both handlers promise a `{ ok, error? }` result; the rejection arm must speak the same
    // protocol rather than answering with a bare error or nothing.
    const rejectionArms = sw.match(/sendResponse\(\{ ok: false, error: /g) ?? [];
    expect(rejectionArms.length).toBeGreaterThanOrEqual(2);
  });

  it("answer activate_site with false when activation rejects, matching its boolean protocol", () => {
    const activate = /if \(msg\?\.kind === "activate_site"\) \{[\s\S]*?\n {2}\}/.exec(sw)?.[0];
    expect(activate, "activate_site handler not found in serviceWorker.ts").toBeDefined();
    expect(activate).toContain("() => sendResponse(false)");
  });
});
