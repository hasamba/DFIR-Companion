import { describe, it, expect } from "vitest";
import {
  computeLatestForRowId,
  highValueClause,
  latestClause,
  matchHighValueLabel,
  parseHighValueLabels,
  type LatestRowFacts,
} from "../../src/analysis/sqliteRowStateLatest.js";
import { MAX_HIGH_VALUE_LABELS, MAX_FIELD_LEN } from "../../src/analysis/canonicalSqliteRowState.js";

describe("parseHighValueLabels", () => {
  it("returns an empty list for undefined or an all-empty var", () => {
    expect(parseHighValueLabels(undefined)).toEqual([]);
    expect(parseHighValueLabels("")).toEqual([]);
    expect(parseHighValueLabels(",, ,")).toEqual([]);
  });

  it("trims, lowercases, and drops empty items", () => {
    expect(parseHighValueLabels(" History , Messages ,,cookies")).toEqual([
      "history",
      "messages",
      "cookies",
    ]);
  });

  it("caps the list at MAX_HIGH_VALUE_LABELS", () => {
    const many = Array.from({ length: MAX_HIGH_VALUE_LABELS + 10 }, (_, i) => `label${i}`).join(",");
    expect(parseHighValueLabels(many)).toHaveLength(MAX_HIGH_VALUE_LABELS);
  });

  it("clips an individual label to MAX_FIELD_LEN", () => {
    const long = "a".repeat(MAX_FIELD_LEN + 50);
    expect(parseHighValueLabels(long)[0]).toHaveLength(MAX_FIELD_LEN);
  });
});

describe("matchHighValueLabel", () => {
  it("matches case-insensitively and returns the FIRST configured match", () => {
    expect(matchHighValueLabel("iOS_Messages_History.db", "filename", ["messages", "history"])).toBe(
      "messages",
    );
  });

  it("never matches when the table name is unavailable", () => {
    expect(matchHighValueLabel("messages", "unavailable", ["messages"])).toBeUndefined();
  });

  it("never matches an empty table name", () => {
    expect(matchHighValueLabel("", "filename", ["messages"])).toBeUndefined();
  });

  it("strips brackets from the returned label (forgery guard)", () => {
    expect(matchHighValueLabel("data[oops]export", "filename", ["[oops]"])).toBe("oops");
  });
});

describe("highValueClause", () => {
  it("is empty for no label", () => {
    expect(highValueClause(undefined)).toBe("");
  });

  it("names the label", () => {
    expect(highValueClause("messages")).toContain('"messages"');
  });
});

describe("computeLatestForRowId", () => {
  function fact(overrides: Partial<LatestRowFacts>): LatestRowFacts {
    return { versionNumber: 0, columnsDigest: "d", operation: "Added", ...overrides };
  }

  it("ignores rows with no rowId entirely", () => {
    const rows = [fact({}), fact({})];
    expect(computeLatestForRowId(rows)).toEqual([]);
  });

  it("handles multiple independent rowId groups in one report", () => {
    const rows = [
      fact({ rowId: "1", versionNumber: 1 }),
      fact({ rowId: "1", versionNumber: 2 }),
      fact({ rowId: "2", versionNumber: 5 }),
    ];
    const results = computeLatestForRowId(rows);
    expect(results).toHaveLength(2);
    expect(results.find((r) => r.index === 1)).toMatchObject({ ambiguous: false, multiMember: true });
    expect(results.find((r) => r.index === 2)).toMatchObject({ ambiguous: false, multiMember: false });
  });

  it("excludes Carved candidates from winning but keeps them counted toward multiMember", () => {
    const rows = [
      fact({ rowId: "1", versionNumber: 1, operation: "Added" }),
      fact({ rowId: "1", versionNumber: 9, operation: "Carved" }),
    ];
    const results = computeLatestForRowId(rows);
    expect(results).toEqual([{ index: 0, ambiguous: false, multiMember: true }]);
  });

  it("produces no result when every member of a group is Carved", () => {
    const rows = [
      fact({ rowId: "1", versionNumber: 1, operation: "Carved" }),
      fact({ rowId: "1", versionNumber: 2, operation: "Carved" }),
    ];
    expect(computeLatestForRowId(rows)).toEqual([]);
  });
});

describe("latestClause", () => {
  it("is empty for a singleton, non-ambiguous winner", () => {
    expect(latestClause("1", "Added", false, false)).toBe("");
  });

  it("uses deletion wording for a Deleted multi-member winner", () => {
    expect(latestClause("1", "Deleted", false, true)).toContain("its own deletion");
    expect(latestClause("1", "Deleted", false, true)).not.toContain("no current row exists");
  });

  it("uses generic wording for a non-Deleted multi-member winner", () => {
    expect(latestClause("1", "Updated", false, true)).toContain("the highest recorded version");
  });

  it("uses ambiguity wording regardless of multiMember", () => {
    expect(latestClause("1", "Added", true, true)).toContain("cannot be determined");
  });
});
