import { describe, expect, it } from "vitest";
import {
  describeFindingTagDiffs,
  diffFindingTags,
  MAX_TAG_DIFF_LINES,
} from "../../src/analysis/findingTagDiff.js";
import type { Finding } from "../../src/analysis/stateTypes.js";

// #1684 — a re-synthesis dropped T1048.003 from f8 and T1570 from f9 and nothing recorded it.

const finding = (id: string, mitreTechniques: string[]): Finding => ({
  id,
  severity: "High",
  title: id,
  description: "",
  relatedIocs: [],
  mitreTechniques,
  sourceScreenshots: [],
  firstSeen: "2026-06-01T10:00:00.000Z",
  lastUpdated: "2026-06-01T10:00:00.000Z",
  status: "open",
});

describe("finding tag diff across a re-synthesis (#1684)", () => {
  it("reports the added and removed techniques of a kept finding", () => {
    const diffs = diffFindingTags(
      [finding("f8", ["T1567", "T1048.003", "T1041"])],
      [finding("f8", ["T1567", "T1041", "T1119"])],
    );
    expect(diffs).toEqual([{ findingId: "f8", added: ["T1119"], removed: ["T1048.003"] }]);
    expect(describeFindingTagDiffs(diffs)).toEqual([
      "finding f8 ATT&CK tags changed on re-synthesis — added T1119; removed T1048.003",
    ]);
  });

  it("reports nothing for an unchanged finding, whatever the tag order", () => {
    expect(diffFindingTags([finding("f1", ["T1", "T2"])], [finding("f1", ["T2", "T1"])])).toEqual([]);
  });

  it("ignores findings that are new or gone — only kept ids are compared", () => {
    expect(diffFindingTags([finding("gone", ["T1"])], [finding("new", ["T2"])])).toEqual([]);
  });

  it("bounds the lines and says how many it left out", () => {
    const n = MAX_TAG_DIFF_LINES + 3;
    const before = Array.from({ length: n }, (_, i) => finding(`f${i}`, ["T1"]));
    const after = Array.from({ length: n }, (_, i) => finding(`f${i}`, ["T2"]));
    const lines = describeFindingTagDiffs(diffFindingTags(before, after));
    expect(lines).toHaveLength(MAX_TAG_DIFF_LINES + 1);
    expect(lines[MAX_TAG_DIFF_LINES]).toBe("3 more finding(s) had ATT&CK tag changes on re-synthesis");
  });
});
