import { describe, it, expect } from "vitest";
import { createImportDebugRecorder } from "../../src/analysis/importDebug.js";
import { safeColumnName } from "../../src/analysis/importShape.js";
import { KNOWN_COLUMN_NAME_LIST } from "../../src/analysis/importShapeColumns.js";
import { createCodeTally, createFieldTally, MAX_FIELD_SOURCES } from "../../src/analysis/parseDebugTally.js";
import { VrDebugTally } from "../../src/analysis/rowDecisionDebug.js";
import { pickTime } from "../../src/analysis/veloRowTime.js";

// #1736 review: a source key is input-controlled (Velociraptor's fallback time scan reports any
// time-NAMED column), so a local tally must reduce it to the allowlist at insertion and hold a
// bounded number of keys — never one map entry per distinct column name in the file.

const ROWS = 100_000;
const rawKey = (i: number): string => `Time_zq${String(i).padStart(5, "0")}`;

describe("import debug tallies are bounded at insertion", () => {
  it("collapses 100,000 distinct time-like keys into one <unlisted> entry", () => {
    const fields = createFieldTally();
    for (let i = 1; i <= ROWS; i++) fields.add("timestamp", rawKey(i));
    expect(fields.size("timestamp")).toBeLessThanOrEqual(MAX_FIELD_SOURCES);
    expect(fields.size("timestamp")).toBe(1);

    const debug = createImportDebugRecorder();
    fields.flush(debug);
    const summary = debug.summary();
    expect(summary.fields.timestamp).toEqual({ "<unlisted>": ROWS });
    expect(summary.truncated).toBe(false);
    const json = JSON.stringify(summary);
    expect(json).not.toContain("Time_zq");
  });

  it("bounds the Velociraptor fallback time scan end to end", () => {
    const debug = createImportDebugRecorder();
    const vr = new VrDebugTally(debug);
    const ev = { timestamp: "2024-01-02T03:04:05Z" } as never;
    for (let i = 1; i <= ROWS; i++) {
      vr.beginRow();
      const t = pickTime({ [rawKey(i)]: "2024-01-02T03:04:05Z" });
      vr.endRow("generic", [t ? ev : null]);
    }
    vr.flush();
    const summary = debug.summary();
    expect(summary.fields.timestamp).toEqual({ "<unlisted>": ROWS });
    expect(JSON.stringify(summary)).not.toContain("Time_zq");
  });

  it("caps allowlisted names per target and reports the overflow", () => {
    const names = KNOWN_COLUMN_NAME_LIST.filter((n) => safeColumnName(n) === n).slice(0, 40);
    expect(names.length).toBe(40);
    const fields = createFieldTally();
    for (let i = 0; i < ROWS; i++) fields.add("timestamp", names[i % names.length]);
    for (let i = 1; i <= 1000; i++) fields.add("timestamp", rawKey(i));
    expect(fields.size("timestamp")).toBe(MAX_FIELD_SOURCES);

    const debug = createImportDebugRecorder();
    fields.flush(debug);
    const summary = debug.summary();
    const bySource = summary.fields.timestamp;
    expect(Object.keys(bySource)).toHaveLength(MAX_FIELD_SOURCES);
    expect(Object.values(bySource).reduce((a, b) => a + b, 0)).toBe(ROWS + 1000);
    const named = Object.keys(bySource).filter((k) => k !== "<unlisted>");
    expect(named).toHaveLength(MAX_FIELD_SOURCES - 1);
    const overflow = ROWS - named.reduce((a, k) => a + bySource[k], 0);
    expect(bySource["<unlisted>"]).toBe(overflow + 1000);
    expect(summary.observations.field_sources_truncated).toBe(overflow);
    expect(JSON.stringify(summary)).not.toContain("Time_zq");
  });

  it("holds a code tally to the recorder's code cap", () => {
    const codes = createCodeTally();
    for (let i = 0; i < 1000; i++) codes.add(`code_${i}`);
    const seen = new Map<string, number>();
    codes.flush((c, n) => seen.set(c, n));
    expect(seen.size).toBe(32);
    expect([...seen.values()].reduce((a, b) => a + b, 0)).toBe(1000);
    expect(seen.get("other")).toBe(1000 - 31);
  });
});
