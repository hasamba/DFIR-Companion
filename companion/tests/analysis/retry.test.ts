import { describe, expect, it } from "vitest";
import { isRetryableError } from "../../src/analysis/ai/retry.js";
import { SendStopped } from "../../src/analysis/ai/sendStop.js";
import { WatsonAiOff, WatsonCaseFrozen } from "../../src/analysis/ai/watson/roundContext.js";

// A stop raised right before a send is a wall: a retry would redo masking and Presidio, and could
// send after the stop.
describe("a stop right before the send is never retried", () => {
  it("covers AI off, a closed case and any other SendStopped", () => {
    expect(isRetryableError(new WatsonAiOff())).toBe(false);
    expect(isRetryableError(new WatsonCaseFrozen())).toBe(false);
    expect(isRetryableError(new SendStopped("cancelled"))).toBe(false);
    expect(isRetryableError(new Error("blip"))).toBe(true);
  });
});
