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

// Codex review of #2135: the cached case password must not survive a change of companion server,
// whichever page (popup or options) saved the new URL.
describe("service-worker case-password binding", () => {
  it("clears the cached case password when the stored companion URL changes", () => {
    expect(sw).toMatch(
      /storage\.onChanged\.addListener\([\s\S]{0,200}forgetCredentialOnServerChange\(sessionArea\(\), changes\)/,
    );
  });

  it("reads the credential for the configured companion, not by case id alone", () => {
    const reads = sw.match(/readCaseCredential\(sessionArea\(\),[^)]*\)/g) ?? [];
    expect(reads.length).toBeGreaterThan(0);
    for (const call of reads) expect(call).toContain("settings.companionUrl");
  });
});
