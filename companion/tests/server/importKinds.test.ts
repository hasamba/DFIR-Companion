import { readFile } from "node:fs/promises";
import { describe, it, expect } from "vitest";
import { PARSE_PROGRESS_KINDS, hasParseProgress } from "../../src/routes/importKinds.js";

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
