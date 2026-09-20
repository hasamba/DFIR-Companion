// #1444: the two IOC-provenance routes fire after every import and used to index the WHOLE
// super-timeline in one array. They stream it now through incremental builders that only remember
// rows naming a known IOC. This file pins that the builders, fed in arbitrary batches, produce
// exactly what the whole-array functions produce — and that they retain nothing for rows no IOC
// names, which is the memory bound the fix rests on.
import { describe, it, expect } from "vitest";
import {
  createIocSeverityRankIndex,
  deriveIocProvenance,
  deriveIocSeverityRank,
} from "../../src/analysis/iocProvenance.js";
import {
  buildIocProvenanceChains,
  createIocProvenanceChainBuilder,
} from "../../src/analysis/iocProvenanceChain.js";
import type { Finding, ForensicEvent, IOC } from "../../src/analysis/stateTypes.js";

function ev(p: Partial<ForensicEvent> & { id: string; severity: ForensicEvent["severity"] }): ForensicEvent {
  return {
    timestamp: "2026-06-01T00:00:00Z",
    description: "",
    mitreTechniques: [],
    relatedFindingIds: [],
    sourceScreenshots: [],
    ...p,
  };
}
const ioc = (p: Partial<IOC> & { id: string; type: IOC["type"]; value: string }): IOC => ({
  firstSeen: "t",
  ...p,
});
function finding(p: Partial<Finding> & { id: string }): Finding {
  return {
    severity: "Medium",
    title: "f",
    description: "",
    relatedIocs: [],
    sourceScreenshots: [],
    mitreTechniques: [],
    firstSeen: "t",
    lastUpdated: "t",
    status: "open",
    ...p,
  };
}

const IOCS = [
  ioc({ id: "i-ip", type: "ip", value: "10.9.8.7" }),
  ioc({ id: "i-sha", type: "hash", value: "AB".repeat(32) }),
  ioc({ id: "i-path", type: "file", value: "C:\\Temp\\drop.ps1" }),
  ioc({ id: "i-auth", type: "domain", value: "evil.example", extractedFrom: ["e-auth", "e-missing"] }),
  ioc({ id: "i-none", type: "domain", value: "quiet.example" }),
];
const FINDINGS = [finding({ id: "f1", relatedIocs: ["i-ip"] })];

const events: ForensicEvent[] = [
  ev({ id: "e1", severity: "High", description: "connect to 10.9.8.7 from ws-01", dstIp: "10.9.8.7" }),
  ev({ id: "e2", severity: "Info", description: "seen 10.9.8.7 again", timestamp: "2026-06-02T00:00:00Z" }),
  ev({ id: "e3", severity: "Medium", sha256: "ab".repeat(32), description: "hash row" }),
  ev({ id: "e4", severity: "Low", path: "c:\\temp\\drop.ps1", description: "wrote the dropper" }),
  ev({ id: "e-auth", severity: "Info", description: "an authoritative link with no value in the text" }),
  ev({ id: "e5", severity: "Info", description: "evil.example resolved", timestamp: "2026-06-03T00:00:00Z" }),
  ...Array.from({ length: 40 }, (_, i) =>
    ev({
      id: `noise-${i}`,
      severity: "Info",
      description: `file observed f${i}.dll`,
      path: `C:\\Windows\\f${i}.dll`,
    }),
  ),
];

function chunks<T>(list: readonly T[], size: number): T[][] {
  const out: T[][] = [];
  for (let i = 0; i < list.length; i += size) out.push(list.slice(i, i + size));
  return out;
}

describe("createIocSeverityRankIndex (#1444)", () => {
  it("fed in batches of 3, equals the whole-array derivation", () => {
    const index = createIocSeverityRankIndex(IOCS);
    for (const batch of chunks(events, 3)) index.add(batch);
    expect(index.finish()).toEqual(deriveIocSeverityRank(IOCS, events));
    expect(deriveIocProvenance(IOCS, events)).toEqual({
      "i-ip": "detection",
      "i-sha": "detection",
      "i-path": "detection",
      "i-auth": "telemetry",
      "i-none": "telemetry",
    });
  });

  it("tracks only IOC values — 40 noise rows leave nothing behind", () => {
    const index = createIocSeverityRankIndex(IOCS);
    index.add(events);
    expect(index.trackedKeys()).toBe(4); // i-ip, i-sha, i-path, i-auth seen; i-none never
  });

  it("with no IOCs it reads nothing at all", () => {
    const index = createIocSeverityRankIndex([]);
    index.add(events);
    expect(index.finish()).toEqual({});
    expect(index.trackedKeys()).toBe(0);
  });
});

describe("createIocProvenanceChainBuilder (#1444)", () => {
  it("fed in batches of 5, equals the whole-array build — authoritative links, structured and token matches alike", () => {
    const builder = createIocProvenanceChainBuilder(IOCS, FINDINGS);
    for (const batch of chunks(events, 5)) builder.add(batch);
    const streamed = builder.finish();
    const whole = buildIocProvenanceChains(IOCS, events, FINDINGS);
    expect(streamed).toEqual(whole);
    expect(whole["i-ip"].extraction.map((e) => e.eventId)).toEqual(["e1", "e2"]);
    expect(whole["i-auth"].extractionAuthoritative).toBe(true);
    expect(whole["i-auth"].extraction.map((e) => e.eventId)).toEqual(["e-auth"]);
    expect(whole["i-auth"].extraction[0].valueHidden).toBe(true);
    expect(whole["i-none"].extraction).toEqual([]);
  });

  it("retains only rows an IOC names — the noise rows are never held", () => {
    const builder = createIocProvenanceChainBuilder(IOCS, FINDINGS);
    builder.add(events);
    // e1, e2 (ip), e3 (sha), e4 (path), e-auth (authoritative id), e5 (domain token)
    expect(builder.retainedEvents()).toBe(6);
  });
});
