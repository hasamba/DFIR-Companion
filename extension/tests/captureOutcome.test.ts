import { describe, it, expect } from "vitest";
import { describeCaptureOutcome } from "../src/captureOutcome.js";
import { lockedQueueMessage, lockedQueuedMessage } from "../src/casePasswordSession.js";
import type { DroppedCapture } from "../src/types.js";

const AMBER = "#d18616";
const BLUE = "#2d6cdf";
const RED = "#cc3333";

function dropped(caseId: string, status: number): DroppedCapture {
  return {
    payload: { caseId, timestamp: "t", url: "u", tabTitle: "t", triggerType: "timer", imageBase64: "AAAA" },
    status,
  };
}

describe("describeCaptureOutcome", () => {
  // #2185: a drained capture for ANOTHER case hit that case's password lock.
  it("shows the amber count and names the locked case when a queued capture is waiting for its password", () => {
    const out = describeCaptureOutcome({ online: true, queued: 3, lockedQueuedCaseId: "case-a" }, true);
    expect(out.badgeText).toBe("3");
    expect(out.badgeColor).toBe(AMBER);
    expect(out.diag).toBe(lockedQueuedMessage(3, "case-a"));
    expect(out.diag).toContain('Case "case-a" is locked');
    // The CURRENT case's password was accepted — never forget it, and the capture was saved.
    expect(out.forgetCredential).toBe(false);
    expect(out.ok).toBe(true);
    expect(out.error).toBeUndefined();
  });

  it("keeps the current-capture locked behaviour: forget a rejected password, report blocked", () => {
    const out = describeCaptureOutcome({ online: true, queued: 2, locked: true }, true);
    expect(out.diag).toBe(`${lockedQueueMessage(2)} (the password was not accepted)`);
    expect(out.badgeText).toBe("2");
    expect(out.badgeColor).toBe(AMBER);
    expect(out.forgetCredential).toBe(true);
    expect(out.ok).toBe(false);
    expect(out.error).toBe(out.diag);
  });

  it("does not ask to forget a password that was never sent", () => {
    const out = describeCaptureOutcome({ online: true, queued: 1, locked: true }, false);
    expect(out.diag).toBe(lockedQueueMessage(1));
    expect(out.forgetCredential).toBe(false);
    expect(out.ok).toBe(false);
  });

  it("ranks a locked current capture above a locked queued case", () => {
    const out = describeCaptureOutcome({ online: true, queued: 2, locked: true, lockedQueuedCaseId: "case-a" }, false);
    expect(out.diag).toBe(lockedQueueMessage(2));
    expect(out.badgeText).toBe("2");
    expect(out.ok).toBe(false);
  });

  it("reports a rejected capture with its message and an amber '!'", () => {
    const out = describeCaptureOutcome({ online: true, queued: 0, rejected: 423, rejectedMessage: "case closed" }, false);
    expect(out.diag).toBe("rejected (HTTP 423) — case closed");
    expect(out.badgeText).toBe("!");
    expect(out.badgeColor).toBe(AMBER);
    expect(out.ok).toBe(false);
    expect(out.error).toBe(out.diag);
    expect(out.forgetCredential).toBe(false);
  });

  it("reports a rejected capture without a message as a missing case", () => {
    const out = describeCaptureOutcome({ online: true, queued: 0, rejected: 404 }, false);
    expect(out.diag).toBe("rejected (HTTP 404) — case missing? create/select it in the dashboard");
  });

  it("reports discarded queued captures with an amber '!' and keeps the capture ok", () => {
    const out = describeCaptureOutcome(
      { online: true, queued: 0, dropped: [dropped("x", 404), dropped("y", 423)] },
      false,
    );
    expect(out.diag).toBe("ok (online=true, queued=0) · 2 queued capture(s) discarded — case gone/closed (HTTP 404, 423)");
    expect(out.badgeText).toBe("!");
    expect(out.badgeColor).toBe(AMBER);
    expect(out.ok).toBe(true);
  });

  it("keeps the '!' badge when discarded and locked-queued captures coexist, and states both", () => {
    const out = describeCaptureOutcome(
      { online: true, queued: 1, lockedQueuedCaseId: "case-a", dropped: [dropped("x", 404)] },
      false,
    );
    expect(out.badgeText).toBe("!");
    expect(out.badgeColor).toBe(AMBER);
    expect(out.diag).toContain(lockedQueuedMessage(1, "case-a"));
    expect(out.diag).toContain("1 queued capture(s) discarded");
    expect(out.ok).toBe(true);
  });

  it("shows the normal blue queued count when online", () => {
    const out = describeCaptureOutcome({ online: true, queued: 4 }, false);
    expect(out.diag).toBe("ok (online=true, queued=4)");
    expect(out.badgeText).toBe("4");
    expect(out.badgeColor).toBe(BLUE);
    expect(out.ok).toBe(true);
  });

  it("clears the badge when online with nothing queued", () => {
    expect(describeCaptureOutcome({ online: true, queued: 0 }, false).badgeText).toBe("");
  });

  it("shows 'off' in red when offline", () => {
    const out = describeCaptureOutcome({ online: false, queued: 2 }, false);
    expect(out.diag).toBe("offline — capture queued for retry (queued=2)");
    expect(out.badgeText).toBe("off");
    expect(out.badgeColor).toBe(RED);
    expect(out.ok).toBe(true);
  });
});
