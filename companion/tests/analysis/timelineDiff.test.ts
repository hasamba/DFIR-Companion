import { describe, it, expect } from "vitest";
import { diffTimeline, isEmptyTimelineDiff } from "../../src/analysis/timelineDiff.js";
import type { ForensicEvent, Severity } from "../../src/analysis/stateTypes.js";

function e(timestamp: string, description: string, severity: Severity = "Medium", id = description): ForensicEvent {
  return {
    id,
    timestamp,
    description,
    severity,
    mitreTechniques: [],
    relatedFindingIds: [],
    sourceScreenshots: [],
  };
}

describe("diffTimeline", () => {
  it("detects events added by an import (by time+description, ignoring fresh ids)", () => {
    const before = [e("2026-01-01T00:00:00Z", "powershell -enc", "High", "old1")];
    const after = [
      e("2026-01-01T00:00:00Z", "powershell -enc", "High", "new-prefix-id"),
      e("2026-01-01T01:00:00Z", "ransomware note dropped", "Critical", "t2e1"),
    ];
    const d = diffTimeline(before, after);
    expect(d.added).toEqual([{ timestamp: "2026-01-01T01:00:00Z", description: "ransomware note dropped", severity: "Critical" }]);
    expect(d.removed).toEqual([]);
  });

  it("treats a re-import of the same events as no change", () => {
    const set = [e("2026-01-01T00:00:00Z", "logon 4624", "Low"), e("2026-01-01T00:05:00Z", "service install", "Medium")];
    // same content, brand-new ids (a re-import assigns a fresh idPrefix)
    const reimport = [e("2026-01-01T00:00:00Z", "logon 4624", "Low", "x1"), e("2026-01-01T00:05:00Z", "service install", "Medium", "x2")];
    expect(isEmptyTimelineDiff(diffTimeline(set, reimport))).toBe(true);
  });

  it("reports events absorbed by correlation as removed", () => {
    const before = [e("2026-01-01T00:00:00Z", "file written: a.exe", "Medium")];
    const after = [e("2026-01-01T00:00:00Z", "malware dropped: a.exe (sha256 ...)", "Critical")];
    const d = diffTimeline(before, after);
    expect(d.added.map(x => x.description)).toEqual(["malware dropped: a.exe (sha256 ...)"]);
    expect(d.removed.map(x => x.description)).toEqual(["file written: a.exe"]);
  });

  it("matches descriptions case-insensitively and ignores whitespace differences", () => {
    const before = [e("2026-01-01T00:00:00Z", "Mimikatz  Execution")];
    const after = [e("2026-01-01T00:00:00Z", "mimikatz execution")];
    expect(isEmptyTimelineDiff(diffTimeline(before, after))).toBe(true);
  });

  it("treats the first import on an empty case as all-added", () => {
    const after = [e("2026-01-01T00:00:00Z", "a"), e("2026-01-01T00:01:00Z", "b")];
    const d = diffTimeline([], after);
    expect(d.added).toHaveLength(2);
    expect(d.removed).toHaveLength(0);
  });

  it("returns an empty diff for identical timelines", () => {
    const set = [e("2026-01-01T00:00:00Z", "a", "High"), e("2026-01-01T00:01:00Z", "b", "Low")];
    expect(isEmptyTimelineDiff(diffTimeline(set, set))).toBe(true);
  });
});
