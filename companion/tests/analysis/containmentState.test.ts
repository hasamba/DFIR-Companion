import { describe, it, expect } from "vitest";
import { emptyState, type Finding, type ForensicEvent } from "../../src/analysis/stateTypes.js";
import {
  CONTAINMENT_TOKEN_BUDGET,
  buildContainmentState,
  findingFingerprint,
} from "../../src/analysis/ai/jev/containmentState.js";

// What the containment check sends to Jev (#1925): the finding plus the forensic-timeline events it
// cites, and nothing else — masked, with attacker text marked as data, and a budget whose
// truncation is disclosed.

const ev = (id: string, description: string, timestamp = "2026-01-01T00:00:00Z"): ForensicEvent => ({
  id,
  timestamp,
  description,
  severity: "High",
  mitreTechniques: [],
  relatedFindingIds: [],
  sourceScreenshots: [],
});

const finding = (over: Partial<Finding> = {}): Finding => ({
  id: "f1",
  severity: "High",
  title: "Credential theft on DC01",
  description: "mimikatz ran on DC01",
  relatedIocs: [],
  sourceScreenshots: [],
  mitreTechniques: ["T1003"],
  relatedEventIds: ["e1", "e2"],
  firstSeen: "2026-01-01T00:00:00Z",
  lastUpdated: "2026-01-01T00:00:00Z",
  status: "open",
  ...over,
});

const state = (events: ForensicEvent[], eventAliases?: Record<string, string>) => ({
  ...emptyState("c1"),
  forensicTimeline: events,
  ...(eventAliases ? { eventAliases } : {}),
});

const id = (t: string) => t;

describe("buildContainmentState", () => {
  it("sends only the events the finding cites", () => {
    const s = state([
      ev("e1", "mimikatz sekurlsa"),
      ev("e2", "lsass read"),
      ev("e3", "uncited chrome update"),
    ]);
    const { state: jev, coverage } = buildContainmentState(finding(), s, id);
    const text = JSON.stringify(jev);
    expect(text).toContain("mimikatz sekurlsa");
    expect(text).toContain("lsass read");
    expect(text).not.toContain("uncited chrome update");
    expect(coverage).toEqual({ cited: 2, sent: 2, notInTimeline: 0, truncated: false });
  });

  it("resolves a cited id that correlation folded into another event", () => {
    const s = state([ev("e9", "folded copy lives on")], { e1: "e9" });
    const { state: jev, coverage } = buildContainmentState(finding({ relatedEventIds: ["e1"] }), s, id);
    expect(JSON.stringify(jev)).toContain("folded copy lives on");
    expect(coverage).toEqual({ cited: 1, sent: 1, notInTimeline: 0, truncated: false });
  });

  it("sends a folded pair once", () => {
    const s = state([ev("e9", "one event")], { e1: "e9" });
    const { coverage } = buildContainmentState(finding({ relatedEventIds: ["e1", "e9"] }), s, id);
    expect(coverage.sent).toBe(1);
  });

  it("counts cited ids that are not in the forensic timeline", () => {
    const s = state([ev("e1", "present")]);
    const { coverage } = buildContainmentState(finding({ relatedEventIds: ["e1", "gone", "gone2"] }), s, id);
    expect(coverage).toEqual({ cited: 3, sent: 1, notInTimeline: 2, truncated: false });
  });

  it("masks the finding text and every event", () => {
    const mask = (t: string) => t.split("DC01").join("ANON_HOST_1");
    const s = state([ev("e1", "logon to DC01"), ev("e2", "DC01 lsass")]);
    const text = JSON.stringify(buildContainmentState(finding(), s, mask).state);
    expect(text).not.toContain("DC01");
    expect(text).toContain("ANON_HOST_1");
  });

  it("marks the text as attacker-influenced data, and says the evidence is a snapshot", () => {
    const { state: jev } = buildContainmentState(finding(), state([ev("e1", "x")]), id);
    expect(jev.note).toMatch(/ATTACKER-INFLUENCED/);
    expect(jev.note).toMatch(/untrusted data/);
    expect(jev.note).toMatch(/end of the collected evidence/);
  });

  it("truncates to the budget and says so", () => {
    const big = Array.from({ length: 60 }, (_, i) => ev(`b${i}`, `row ${i} ` + "x".repeat(1900)));
    const f = finding({ relatedEventIds: big.map((e) => e.id) });
    const { state: jev, coverage } = buildContainmentState(f, state(big), id);
    expect(coverage.truncated).toBe(true);
    expect(coverage.cited).toBe(60);
    expect(coverage.sent).toBeLessThan(60);
    expect(coverage.sent).toBe(Object.keys(jev.events).length);
    expect(JSON.stringify(jev).length / 4).toBeLessThanOrEqual(CONTAINMENT_TOKEN_BUDGET);
  });

  it("handles a finding that cites nothing", () => {
    const { coverage } = buildContainmentState(finding({ relatedEventIds: undefined }), state([]), id);
    expect(coverage).toEqual({ cited: 0, sent: 0, notInTimeline: 0, truncated: false });
  });
});

describe("findingFingerprint", () => {
  it("ignores a reworded title but changes with the cited evidence or techniques", () => {
    const base = findingFingerprint(finding());
    expect(findingFingerprint(finding({ title: "Reworded" }))).toBe(base);
    expect(findingFingerprint(finding({ relatedEventIds: ["e2", "e1"] }))).toBe(base);
    expect(findingFingerprint(finding({ relatedEventIds: ["e1"] }))).not.toBe(base);
    expect(findingFingerprint(finding({ mitreTechniques: ["T1003", "T1078"] }))).not.toBe(base);
    expect(findingFingerprint(finding({ id: "f2" }))).not.toBe(base);
  });
});
