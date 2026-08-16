// EVERY caller of synthesize() must report a gate as a hold, not a crash.
//
// This suite exists because the first attempt at that fix covered ONE of five call sites and looked
// finished: `pipeline.synthesize()` throws HostMergeDecisionRequired, and each caller catches it in
// its own way — the manual /synthesize route, /second-opinion, /deep-pass, the debounced live
// synthesis, and the post-import background re-synthesis. Four kept painting a red "AI: error" over
// a question, including the Re-synthesize button an analyst presses when they notice analysis is
// stuck. Unit tests that drove one path could not see the other four.
//
// So the first test here is a SOURCE gate rather than a behavioural one. It is deliberately not a
// substitute for the behavioural tests below and elsewhere (hostDuplicateGateStatus.test.ts,
// hostDuplicateGateWiring.test.ts, synthesizeGateRoute.test.ts) — it is the check that fails when a
// SIXTH call site is added and its author does not know this rule exists.
import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { PresidioApprovalRequired } from "../../src/analysis/presidio.js";
import { HostMergeDecisionRequired } from "../../src/analysis/hostDuplicateGate.js";
import { isAnalystDecisionGate } from "../../src/routes/presidioApproval.js";

const read = (path: string) => readFileSync(new URL(`../../src/${path}`, import.meta.url), "utf8");

/** Files whose catch blocks can see a rejection from pipeline.synthesize(). */
const SYNTHESIS_CALLERS = ["routes/aiSynthesis.ts", "routes/deepPass.ts", "composition/captureAnalysis.ts"];

describe("isAnalystDecisionGate", () => {
  it("recognises both gates", () => {
    expect(isAnalystDecisionGate(new HostMergeDecisionRequired([]))).toBe(true);
    expect(isAnalystDecisionGate(new PresidioApprovalRequired([]))).toBe(true);
  });

  // The predicate deciding "is this a gate" must never answer yes for an ordinary failure, or a
  // real crash would be reported as a hold and silently cancelled instead of surfaced.
  it("does not mistake an ordinary failure, or a lookalike message, for a gate", () => {
    expect(isAnalystDecisionGate(new Error("model returned 500"))).toBe(false);
    expect(isAnalystDecisionGate(new Error("1 possible duplicate host awaiting a merge decision"))).toBe(
      false,
    );
    expect(isAnalystDecisionGate(undefined)).toBe(false);
    expect(isAnalystDecisionGate(null)).toBe(false);
    expect(isAnalystDecisionGate("host_merge_decision_required")).toBe(false);
  });
});

describe("every synthesis caller consults the shared gate predicate", () => {
  it.each(SYNTHESIS_CALLERS)("%s asks isAnalystDecisionGate", (file) => {
    expect(
      read(file),
      `${file} catches a synthesize() rejection but never asks whether it is a gate — a held run ` +
        `there reports as "AI: error" and a failed job`,
    ).toContain("isAnalystDecisionGate");
  });

  // Scoped to HostMergeDecisionRequired on purpose. `err instanceof HostMergeDecisionRequired` in a
  // catch block is exactly what the first version of this fix wrote, and writing it again is how a
  // sixth call site gets its own subtly different answer.
  //
  // PresidioApprovalRequired is NOT prohibited here, because two routes legitimately test for it:
  // second-opinion/apply and apply-all use it to choose between delegating to sendPipelineError and
  // producing their own 404/409/500 from the message. That is a ROUTING decision, not a status one,
  // and neither route calls synthesize(), so neither can see the merge gate.
  it.each(SYNTHESIS_CALLERS)("%s does not branch on the merge gate class directly", (file) => {
    expect(
      read(file),
      `${file} should ask isAnalystDecisionGate rather than test the class itself`,
    ).not.toMatch(/instanceof\s+HostMergeDecisionRequired/);
  });

  it("keeps the gate classes named in exactly one place", () => {
    const owner = read("routes/presidioApproval.ts");
    expect(owner).toMatch(/instanceof PresidioApprovalRequired/);
    expect(owner).toMatch(/instanceof HostMergeDecisionRequired/);
  });
});

// The deep-pass route builds its own ai_status sender with a hardcoded status union. It compiled
// before this change only because "blocked" did not exist; a union that omits it can express the
// hold only as an error.
describe("deep-pass local ai_status helper", () => {
  it("can express a blocked status", () => {
    expect(read("routes/deepPass.ts")).toMatch(/"analyzing" \| "idle" \| "error" \| "blocked"/);
  });
});
