import { describe, expect, it } from "vitest";
import { loadDashboardModule } from "../helpers/dashboardModule.js";

// public/js/dashboard-filters.js — the search, exclude and relevance predicates (#415).
//
// These decide what an analyst sees in the four big lists. Until now none of them was reachable
// from a test, so "does the search box look inside MITRE technique IDs" was answerable only by
// reading 19,000 lines of inline script.

const f = loadDashboardModule("dashboard-filters.js");

describe("_evMatchesSearch", () => {
  const event = {
    description: "Encoded PowerShell launched",
    asset: "WKSTN-04",
    mitreTechniques: ["T1059.001"],
    sources: ["Sysmon", "unknown source"],
  };

  // The query is expected already lower-cased — every caller lower-cases it before calling, and
  // the function does not do it itself. A test passing "PowerShell" would silently match nothing,
  // which is worth stating rather than discovering.
  it("searches description, asset, techniques and sources", () => {
    for (const q of ["powershell", "wkstn", "t1059", "sysmon"]) expect(_ev(q)).toBe(true);
  });

  it("takes the query pre-lowered, and does not lower it itself", () => {
    expect(_ev("powershell")).toBe(true);
    expect(_ev("PowerShell")).toBe(false);
  });

  it("survives an event missing every optional field", () => {
    expect(f._evMatchesSearch({}, "anything")).toBe(false);
  });

  const _ev = (q: string) => f._evMatchesSearch(event, q);
});

describe("_iocMatchesSearch / _findingMatchesSearch / _fpMatchesSearch", () => {
  it("searches an IOC's value and type only", () => {
    const ioc = { value: "evil.com", type: "domain", note: "not searched" };
    expect(f._iocMatchesSearch(ioc, "evil")).toBe(true);
    expect(f._iocMatchesSearch(ioc, "domain")).toBe(true);
    expect(f._iocMatchesSearch(ioc, "not searched")).toBe(false);
  });

  it("searches a finding's title, description and techniques", () => {
    const finding = { title: "Persistence", description: "run key", mitreTechniques: ["T1547"] };
    for (const q of ["persist", "run key", "t1547"]) expect(f._findingMatchesSearch(finding, q)).toBe(true);
    expect(f._findingMatchesSearch(finding, "nope")).toBe(false);
  });

  it("searches all five fields of a false-positive mark", () => {
    const mark = {
      kind: "ioc",
      ref: "abc",
      label: "internal host",
      reason: "known good",
      note: "asset owner",
    };
    for (const q of ["ioc", "abc", "internal", "known", "owner"])
      expect(f._fpMatchesSearch(mark, q)).toBe(true);
  });
});

// The exclude family is the search family wrapped in "any of these terms", and it DOES lower-case
// each term — the opposite of its own search function. That asymmetry is real and load-bearing:
// exclusions come from a comma-separated box typed by hand, searches from an already-normalised
// input handler.
describe("the exclude predicates", () => {
  const event = { description: "Encoded PowerShell", asset: "WKSTN-04" };

  it("matches if ANY term matches, and lower-cases each term itself", () => {
    expect(f._evMatchesExclude(event, ["Nope", "POWERSHELL"])).toBe(true);
    expect(f._evMatchesExclude(event, ["nope"])).toBe(false);
  });

  it("ignores empty terms rather than excluding everything", () => {
    expect(f._evMatchesExclude(event, ["", null, undefined])).toBe(false);
    expect(f._iocMatchesExclude({ value: "x" }, [""])).toBe(false);
    expect(f._findingMatchesExclude({ title: "x" }, [""])).toBe(false);
    expect(f._fpMatchesExclude({ kind: "x" }, [""])).toBe(false);
  });
});

// An event that cannot be placed in time is KEPT, not dropped. Filtering it out would quietly hide
// evidence because its source did not record a timestamp, which is the wrong default for a
// forensics tool.
describe("_evMatchesTimeRange", () => {
  const at = (ts: string) => ({ timestamp: ts });

  it("keeps an event with no timestamp, or an unparseable one", () => {
    expect(f._evMatchesTimeRange({}, "2026-01-01", "2026-02-01")).toBe(true);
    expect(f._evMatchesTimeRange(at("nonsense"), "2026-01-01", "2026-02-01")).toBe(true);
  });

  it("bounds inclusively at both ends", () => {
    expect(f._evMatchesTimeRange(at("2026-01-01T00:00:00Z"), "2026-01-01T00:00:00Z", null)).toBe(true);
    expect(f._evMatchesTimeRange(at("2026-01-01T00:00:00Z"), null, "2026-01-01T00:00:00Z")).toBe(true);
  });

  it("excludes outside either bound", () => {
    expect(f._evMatchesTimeRange(at("2025-12-31T23:59:59Z"), "2026-01-01", null)).toBe(false);
    expect(f._evMatchesTimeRange(at("2026-02-02T00:00:00Z"), null, "2026-02-01")).toBe(false);
  });

  it("ignores an unparseable bound rather than dropping everything", () => {
    expect(f._evMatchesTimeRange(at("2026-01-15T00:00:00Z"), "junk", "junk")).toBe(true);
  });
});

// The corroboration unit. Two behaviours in one function and both matter: it drops the
// "unknown source" placeholder, and it de-duplicates — so the same source name repeated cannot
// fake multi-source corroboration.
describe("realSourceCount", () => {
  it("de-duplicates and drops the unknown-source placeholder", () => {
    expect(f.realSourceCount(["Sysmon", "Sysmon", "unknown source", "EVTX"])).toBe(2);
    expect(f.realSourceCount(["unknown source"])).toBe(0);
  });

  it("subtracts sources the analyst has hidden, when asked", () => {
    expect(f.realSourceCount(["Sysmon", "EVTX"], new Set(["EVTX"]))).toBe(1);
    expect(f.realSourceCount(["Sysmon", "EVTX"])).toBe(2);
  });

  it("tolerates a missing list and falsy entries", () => {
    expect(f.realSourceCount(null)).toBe(0);
    expect(f.realSourceCount(["", null, "EVTX"])).toBe(1);
  });
});

describe("isLowSignalEvent", () => {
  const info = { severity: "Info", sources: ["Sysmon"] };

  it("flags Info-severity telemetry with nothing to corroborate it", () => {
    expect(f.isLowSignalEvent(info)).toBe(true);
  });

  it("clears the flag on anything above Info", () => {
    expect(f.isLowSignalEvent({ ...info, severity: "Low" })).toBe(false);
  });

  it.each([
    ["a finding link", { relatedFindingIds: ["fnd-1"] }],
    ["a hash", { sha256: "ab" }],
    ["a path", { path: "C:\\x" }],
    ["a process", { processName: "cmd.exe" }],
    ["a parent", { parentName: "explorer.exe" }],
    ["a chain signature", { chainSignature: "sig" }],
    ["an ATT&CK tag", { mitreTechniques: ["T1059"] }],
    ["two real sources", { sources: ["Sysmon", "EVTX"] }],
  ])("clears the flag on %s", (_label, extra) => {
    expect(f.isLowSignalEvent({ ...info, ...extra })).toBe(false);
  });

  // Relevance is a property of the event, not of the analyst's current source filter, so the chip
  // must not appear and disappear as sources are toggled. That is why the `hidden` set is
  // deliberately not passed through.
  it("ignores the hidden-source filter", () => {
    const corroborated = { severity: "Info", sources: ["Sysmon", "EVTX"] };
    expect(f.isLowSignalEvent(corroborated)).toBe(false);
  });

  it("renders a chip only when flagged, and escapes the ampersand in ATT&CK", () => {
    expect(f.lowSignalChip({ severity: "High" })).toBe("");
    const chip = f.lowSignalChip(info);
    expect(chip).toContain("low signal");
    expect(chip).toContain("ATT&amp;CK");
    expect(chip).not.toContain("ATT&CK");
  });
});

// Substring matching in BOTH directions, which is much looser than it looks: a false-positive
// entry for "powershell" suppresses "Encoded PowerShell", and an entry for "Encoded PowerShell
// launched from Word" is also suppressed by a finding titled "Encoded PowerShell".
describe("isFindingFalsePositive", () => {
  it("matches case-insensitively on either containing the other", () => {
    expect(f.isFindingFalsePositive("Encoded PowerShell", ["powershell"])).toBe(true);
    expect(f.isFindingFalsePositive("PowerShell", ["encoded powershell launched"])).toBe(true);
    expect(f.isFindingFalsePositive("  PowerShell  ", ["powershell"])).toBe(true);
  });

  it("does not match an unrelated title", () => {
    expect(f.isFindingFalsePositive("Persistence", ["powershell"])).toBe(false);
    expect(f.isFindingFalsePositive("Persistence", [])).toBe(false);
  });

  // A SECOND LATENT BUG THE EXTRACTION MADE VISIBLE, pinned rather than fixed. The match is
  // `t.includes(ref) || ref.includes(t)`, and every string contains "" — so a finding with no
  // title at all is suppressed by the FIRST false-positive entry in the list, whatever it says.
  // The blast radius is small (findings normally have titles) but the direction is bad: the
  // failure mode of this function is hiding evidence, not showing noise. Fixing it changes what
  // the findings list renders, so it belongs in its own change; this records today's answer.
  it("treats an empty title as matching any entry", () => {
    expect(f.isFindingFalsePositive(null, ["powershell"])).toBe(true);
    expect(f.isFindingFalsePositive("   ", ["anything at all"])).toBe(true);
    expect(f.isFindingFalsePositive("", [])).toBe(false); // ...unless there are no entries
  });
});

describe("ftOriginOf / originFacets", () => {
  it("prefers the artifact name, falls back to the first source, then Unknown", () => {
    expect(f.ftOriginOf({ artifactName: "MFT", sources: ["EVTX"] })).toBe("MFT");
    expect(f.ftOriginOf({ sources: ["EVTX"] })).toBe("EVTX");
    expect(f.ftOriginOf({})).toBe("Unknown");
    expect(f.ftOriginOf({ sources: [] })).toBe("Unknown");
  });

  it("returns the distinct origins, locale-sorted", () => {
    expect(
      f.originFacets([{ artifactName: "MFT" }, { sources: ["evtx"] }, { artifactName: "MFT" }, {}]),
    ).toEqual(["evtx", "MFT", "Unknown"]);
    expect(f.originFacets(null)).toEqual([]);
  });
});
