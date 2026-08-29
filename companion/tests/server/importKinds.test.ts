import { readFile } from "node:fs/promises";
import { describe, it, expect, beforeEach, afterEach } from "vitest";
import type { Response } from "express";
import {
  PARSE_PROGRESS_KINDS,
  hasParseProgress,
  rejectIfAiImportOverBudget,
} from "../../src/routes/importKinds.js";
import { resetLimiters } from "../../src/http/rateLimiter.js";

// DUP2-4: the streaming-import kind predicate used to be five copied literals across the twin
// /import + /import-file registrations and the resume handler — and missing only the resume copy
// produced a job that was cancellable on first run but silently uncancellable after a restart
// resumed it. These tests pin the shared helper AND that both files actually route through it.
describe("importKinds — the streaming-import kind predicate", () => {
  it("marks exactly the streaming kinds as parse-progress capable", () => {
    expect([...PARSE_PROGRESS_KINDS].sort()).toEqual(["evtxxml", "syslog"]);
    expect(hasParseProgress("evtxxml")).toBe(true);
    expect(hasParseProgress("syslog")).toBe(true);
    expect(hasParseProgress("csv")).toBe(false);
    expect(hasParseProgress("log")).toBe(false);
    expect(hasParseProgress("plaso")).toBe(false);
  });

  it("rejects non-string kinds, so the resume handler can pass job.parameters?.kind raw", () => {
    expect(hasParseProgress(undefined)).toBe(false);
    expect(hasParseProgress(null)).toBe(false);
    expect(hasParseProgress(42)).toBe(false);
    expect(hasParseProgress({})).toBe(false);
  });

  // The kind-driven cancellable component must be the SAME expression in the registrations and
  // the resume predicate (the registrations additionally OR in aiDependent, which the resume
  // predicate intentionally lacks). With the helper consolidated, lockstep regresses only if a
  // literal creeps back in — so assert both files delegate and neither re-inlines the kind list.
  it("keeps import.ts and importRecovery.ts on the shared predicate, with no inline kind literals", async () => {
    for (const file of ["import.ts", "importRecovery.ts"]) {
      const src = await readFile(new URL(`../../src/routes/${file}`, import.meta.url), "utf8");
      expect(src, `${file} should use hasParseProgress`).toContain("hasParseProgress(");
      expect(src, `${file} re-inlines the streaming-kind literal`).not.toMatch(
        /kind\s*===\s*"(?:evtxxml|syslog)"/,
      );
    }
  });
});

// A CSV/log import is a direct LLM call, so it must be metered against the per-case AI budget even
// though /import + /import-file ride the generous deterministic-import limiter. Without this a
// caller could blow the 20/min AI cap by submitting CSV bodies to /import at 300/min.
describe("rejectIfAiImportOverBudget — the AI-cost gate for CSV/log imports", () => {
  beforeEach(() => resetLimiters());
  afterEach(() => resetLimiters());

  const mockRes = (): { res: Response; codes: number[] } => {
    const codes: number[] = [];
    const res = {
      status(code: number) {
        codes.push(code);
        return this;
      },
      json() {
        return this;
      },
    } as unknown as Response;
    return { res, codes };
  };

  it("never meters a deterministic kind, however fast it is called", () => {
    for (let i = 0; i < 100; i++) {
      const { res, codes } = mockRes();
      expect(rejectIfAiImportOverBudget("velociraptor", "case-a", res)).toBe(false);
      expect(codes).toEqual([]);
    }
  });

  it("caps CSV imports at the AI budget (20/min) and 429s past it", () => {
    let rejected = 0;
    let last429 = false;
    for (let i = 0; i < 25; i++) {
      const { res, codes } = mockRes();
      const stop = rejectIfAiImportOverBudget("csv", "case-b", res);
      if (stop) {
        rejected++;
        last429 = codes.includes(429);
      }
    }
    expect(rejected).toBeGreaterThan(0); // the 21st+ CSV import is throttled
    expect(last429).toBe(true);
  });

  it("meters per case — one case's CSV flood does not throttle another", () => {
    for (let i = 0; i < 25; i++) rejectIfAiImportOverBudget("csv", "busy", mockRes().res);
    const { res } = mockRes();
    expect(rejectIfAiImportOverBudget("csv", "quiet", res)).toBe(false);
  });
});
