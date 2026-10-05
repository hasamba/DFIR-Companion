import { describe, it, expect } from "vitest";
import { backfillScriptC2Findings } from "../../src/analysis/scriptBlockC2Findings.js";
import {
  AUTO_FINDING_ID_PREFIX,
  SCRIPT_C2_FINDING_ID_PREFIX,
  isDeterministicFindingId,
} from "../../src/analysis/responseSchema.js";
import type { Finding, ForensicEvent, InvestigationState } from "../../src/analysis/stateTypes.js";

// Hostnames are example.com-shaped; addresses are RFC 5737 documentation ranges.
const ISSUE_BLOCK = "$server='x.example.com'; $port=443; $uri='/submit.php'; $watermark=123456";
const QUALIFIED_BLOCK =
  "@{domains=@('cdn.example.com');IPs=@('198.51.100.7');port=443;sleep=62760;jitter=37;" +
  "watermark=1357776117;actualConnections='127.0.0.1 only';beaconIncluded=$false}";

function ev(p: Partial<ForensicEvent>): ForensicEvent {
  return {
    id: p.id ?? "e1",
    timestamp: p.timestamp ?? "2026-09-22T08:33:05Z",
    description: p.description ?? "Script block logged (EID 4104)",
    severity: p.severity ?? "High",
    asset: p.asset ?? "ws01.example.com",
    message: p.message ?? ISSUE_BLOCK,
    mitreTechniques: [],
    relatedFindingIds: p.relatedFindingIds ?? [],
    sourceScreenshots: [],
    ...p,
  };
}

function finding(p: Partial<Finding>): Finding {
  return {
    id: p.id ?? "f13",
    severity: "High",
    confidence: 70,
    title: p.title ?? "Possible Command & Control: beacon",
    description: p.description ?? "A beacon was seen.",
    relatedIocs: [],
    mitreTechniques: ["T1071.001"],
    sourceScreenshots: [],
    firstSeen: "2026-09-22T08:00:00Z",
    lastUpdated: "2026-09-22T09:00:00Z",
    status: "open",
    ...p,
  };
}

function state(events: ForensicEvent[], findings: Finding[] = []): InvestigationState {
  return {
    caseId: "INC-TEST",
    findings,
    forensicTimeline: events,
    iocs: [],
    timeline: [],
    mitreTechniques: [],
    keyQuestions: [],
    nextSteps: [],
    openThreads: [],
    uncertainties: [],
    updatedAt: "2026-09-22T09:00:00Z",
  } as unknown as InvestigationState;
}

const ts = "2026-09-22T10:00:00Z";
const all = (s: InvestigationState) => new Set(s.forensicTimeline.map((e) => e.id));
const minted = (s: InvestigationState) =>
  s.findings.filter((f) => f.id.startsWith(SCRIPT_C2_FINDING_ID_PREFIX));

describe("backfillScriptC2Findings", () => {
  it("mints one Medium finding that names all four of the issue's values", () => {
    const s = state([ev({ id: "2e71", relatedFindingIds: ["f13"] })], [finding({})]);
    const next = backfillScriptC2Findings(s, all(s), ts);
    const out = minted(next);
    expect(out).toHaveLength(1);
    const f = out[0];
    expect(f.id).toBe(`${SCRIPT_C2_FINDING_ID_PREFIX}2e71`);
    expect(f.severity).toBe("Medium");
    expect(f.mitreTechniques).toEqual([]);
    expect(f.title).toContain("ws01.example.com");
    for (const v of ["x.example.com", "443", "/submit.php", "123456"]) expect(f.description).toContain(v);
    expect(f.description).toMatch(/not a proven connection/i);
    expect(next.forensicTimeline[0].relatedFindingIds).toContain(f.id);
  });

  it("repeats the script's own qualifiers", () => {
    const s = state([ev({ message: QUALIFIED_BLOCK })]);
    const f = minted(backfillScriptC2Findings(s, all(s), ts))[0];
    expect(f.description).toContain("actualConnections='127.0.0.1 only'");
    expect(f.description).toContain("beaconIncluded=$false");
  });

  it("mints nothing for a port alone", () => {
    const s = state([ev({ message: "$port=443" })]);
    expect(backfillScriptC2Findings(s, all(s), ts)).toBe(s);
  });

  it("mints nothing for the collector's own script block", () => {
    const s = state([ev({ origin: "collector" })]);
    expect(backfillScriptC2Findings(s, all(s), ts)).toBe(s);
  });

  it("mints nothing for a row outside the synthesis scope", () => {
    const s = state([ev({})]);
    expect(backfillScriptC2Findings(s, new Set(), ts)).toBe(s);
  });

  it("mints nothing when a linked finding already names every infrastructure value", () => {
    const covered = finding({ id: "f2", description: "Beacon to X.EXAMPLE.COM over 443." });
    const s = state([ev({ relatedFindingIds: ["f2"] })], [covered]);
    expect(backfillScriptC2Findings(s, all(s), ts)).toBe(s);
  });

  it("counts a High row's f-auto finding that names the server as coverage", () => {
    const auto = finding({ id: `${AUTO_FINDING_ID_PREFIX}e1`, description: "Row e1: server x.example.com" });
    const s = state([ev({ relatedFindingIds: [auto.id] })], [auto]);
    expect(minted(backfillScriptC2Findings(s, all(s), ts))).toHaveLength(0);
  });

  it("still mints when a linked finding names only some of the values", () => {
    const partial = finding({ id: "f2", description: "cdn.example.com seen" });
    const s = state([ev({ message: QUALIFIED_BLOCK, relatedFindingIds: ["f2"] })], [partial]);
    expect(minted(backfillScriptC2Findings(s, all(s), ts))).toHaveLength(1);
  });

  it("does not count an address that only contains the value as coverage", () => {
    const near = finding({ id: "f2", description: "ax.example.com.evil.example" });
    const s = state([ev({ relatedFindingIds: ["f2"] })], [near]);
    expect(minted(backfillScriptC2Findings(s, all(s), ts))).toHaveLength(1);
  });

  it("collapses several views of one block on one host and day into one finding", () => {
    const s = state([ev({ id: "b" }), ev({ id: "a" }), ev({ id: "c", asset: "ws02.example.com" })]);
    const next = backfillScriptC2Findings(s, all(s), ts);
    expect(
      minted(next)
        .map((f) => f.id)
        .sort(),
    ).toEqual([`${SCRIPT_C2_FINDING_ID_PREFIX}a`, `${SCRIPT_C2_FINDING_ID_PREFIX}c`]);
    expect(next.forensicTimeline.find((e) => e.id === "b")!.relatedFindingIds).toContain(
      `${SCRIPT_C2_FINDING_ID_PREFIX}a`,
    );
  });

  it("is idempotent: a second run mints nothing new", () => {
    const s = state([ev({})]);
    const once = backfillScriptC2Findings(s, all(s), ts);
    const twice = backfillScriptC2Findings(once, all(once), ts);
    expect(twice.findings).toHaveLength(once.findings.length);
    expect(twice).toBe(once);
  });

  it("does not mutate its input", () => {
    const s = state([ev({})]);
    const snapshot = JSON.stringify(s);
    backfillScriptC2Findings(s, all(s), ts);
    expect(JSON.stringify(s)).toBe(snapshot);
  });

  it("reserves the prefix so the model cannot mint it", () => {
    expect(isDeterministicFindingId(`${SCRIPT_C2_FINDING_ID_PREFIX}x`)).toBe(true);
  });
});
