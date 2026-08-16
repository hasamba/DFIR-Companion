import { describe, it, expect, vi } from "vitest";
import type { Response } from "express";
import { withRetry } from "../../src/analysis/ai/retry.js";
import { sendPipelineError } from "../../src/routes/presidioApproval.js";
import { HostMergeDecisionRequired } from "../../src/analysis/hostDuplicateGate.js";

const PAIRS = [{ canonical: "win11.windomain.local", other: "win11", reason: "shortname-fqdn" as const }];

function fakeRes(): Response & { statusCode?: number; payload?: unknown } {
  const res = {
    statusCode: undefined as number | undefined,
    payload: undefined as unknown,
    status(code: number) {
      res.statusCode = code;
      return res;
    },
    json(body: unknown) {
      res.payload = body;
      return res;
    },
  };
  return res as unknown as Response & { statusCode?: number; payload?: unknown };
}

describe("HostMergeDecisionRequired wiring", () => {
  it("is not retried — it surfaces on the first throw", async () => {
    const fn = vi.fn(async () => {
      throw new HostMergeDecisionRequired(PAIRS);
    });
    await expect(withRetry(fn, 3, 1)).rejects.toBeInstanceOf(HostMergeDecisionRequired);
    expect(fn).toHaveBeenCalledTimes(1);
  });

  it("maps to 409 with the pairs in the body", () => {
    const res = fakeRes();
    sendPipelineError(res, new HostMergeDecisionRequired(PAIRS));
    expect(res.statusCode).toBe(409);
    expect(res.payload).toEqual({ error: "host_merge_decision_required", pairs: PAIRS });
  });

  // "blocked", NOT "error". The gate is a question waiting on the analyst, and painting it red as a
  // crash told them the AI had broken when it was only holding — the reason nobody went looking for
  // a merge button. Both gates in this helper report the same way for the same reason.
  it("broadcasts ai_status blocked when a context is supplied", () => {
    const onAiStatus = vi.fn();
    sendPipelineError(fakeRes(), new HostMergeDecisionRequired(PAIRS), { caseId: "c1", onAiStatus });
    expect(onAiStatus).toHaveBeenCalledWith("c1", expect.objectContaining({ status: "blocked" }));
  });

  it("carries the pair count in the detail so the pill can say what is held", () => {
    const onAiStatus = vi.fn();
    sendPipelineError(fakeRes(), new HostMergeDecisionRequired(PAIRS), { caseId: "c1", onAiStatus });
    expect(onAiStatus.mock.calls[0][1].detail).toContain("duplicate host");
  });

  it("still maps an unrelated error to 500", () => {
    const res = fakeRes();
    sendPipelineError(res, new Error("boom"));
    expect(res.statusCode).toBe(500);
  });
});
