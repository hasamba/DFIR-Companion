import { describe, it, expect } from "vitest";
import {
  NEVER_SNAPSHOT_STATE_FILES,
  SNAPSHOT_STATE_FILES,
} from "../../src/analysis/investigationStateFiles.js";

describe("SNAPSHOT_STATE_FILES", () => {
  it("includes the host scope decision log so clearances travel with the case", () => {
    expect(SNAPSHOT_STATE_FILES).toContain("host-scope.json");
  });

  it("includes the evidence-attestation ledger so signed attestations travel with the case (#1111)", () => {
    expect(SNAPSHOT_STATE_FILES).toContain("evidence-attestations.json");
  });

  it("never snapshots the analysis-run ledger, so a restore cannot rewind the audit chain (#2143)", () => {
    expect(SNAPSHOT_STATE_FILES.some((name) => name.startsWith("analysis-runs"))).toBe(false);
  });

  it("never snapshots watson-history.jsonl or hunt-fingerprints.json", () => {
    for (const f of NEVER_SNAPSHOT_STATE_FILES) expect(SNAPSHOT_STATE_FILES).not.toContain(f);
  });

  it("lists every file exactly once", () => {
    expect(new Set(SNAPSHOT_STATE_FILES).size).toBe(SNAPSHOT_STATE_FILES.length);
  });
});
