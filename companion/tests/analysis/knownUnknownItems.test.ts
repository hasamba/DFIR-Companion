import { describe, it, expect } from "vitest";
import {
  buildKnownUnknownItems,
  uncoveredCoreTactics,
  tacticCollectDirectives,
  renderKnownUnknowns,
} from "../../src/analysis/knownUnknowns.js";
import { derivePlaybookTasks } from "../../src/analysis/playbook.js";
import {
  emptyState,
  type Finding,
  type ForensicEvent,
  type InvestigationState,
} from "../../src/analysis/stateTypes.js";

function finding(id: string, severity: Finding["severity"], mitreTechniques: string[]): Finding {
  return {
    id,
    severity,
    title: id,
    description: "",
    relatedIocs: [],
    sourceScreenshots: [],
    mitreTechniques,
    firstSeen: "2026-01-01T00:00:00Z",
    lastUpdated: "2026-01-01T00:00:00Z",
    status: "open",
  };
}
function ev(id: string, ts: string, asset: string): ForensicEvent {
  return {
    id,
    timestamp: ts,
    description: "",
    severity: "High",
    mitreTechniques: [],
    relatedFindingIds: [],
    sourceScreenshots: [],
    asset,
  };
}
// A serious case: only Impact (T1486) covered; hosts WEB01 (earliest) + DC01 present.
function seriousState(): InvestigationState {
  const s = emptyState("c");
  s.findings = [finding("f1", "Critical", ["T1486"])];
  s.forensicTimeline = [
    ev("e1", "2026-05-20T08:00:00Z", "WEB01"),
    ev("e2", "2026-05-20T09:00:00Z", "DC01"),
    ev("e3", "2026-05-20T10:00:00Z", "DC01"),
  ];
  return s;
}

describe("uncoveredCoreTactics", () => {
  it("returns [] for a low-signal case (no Critical/High finding)", () => {
    const s = emptyState("c");
    s.findings = [finding("f1", "Info", [])];
    expect(uncoveredCoreTactics(s)).toEqual([]);
  });
  it("lists core phases with no covering finding (Impact covered → excluded)", () => {
    const tactics = uncoveredCoreTactics(seriousState());
    expect(tactics).toContain("Initial Access");
    expect(tactics).toContain("Lateral Movement");
    expect(tactics).not.toContain("Impact");
  });
});

describe("tacticCollectDirectives", () => {
  it("builds a host+artifact directive for an uncovered tactic", () => {
    const s = seriousState();
    const dirs = tacticCollectDirectives("Lateral Movement", s, s.forensicTimeline, ["DC01", "WEB01"]);
    expect(dirs.length).toBeGreaterThan(0);
    expect(dirs[0].artifact).toBe("Windows.EventLogs.Evtx");
    expect(dirs[0].logSource).toMatch(/4624/);
    expect(dirs.every((d) => !!d.host)).toBe(true);
  });
  it("points Initial Access at the earliest-active asset", () => {
    const s = seriousState();
    const dirs = tacticCollectDirectives("Initial Access", s, s.forensicTimeline, ["DC01"]);
    expect(dirs.some((d) => d.host === "WEB01")).toBe(true); // WEB01 is the earliest-dated asset
  });
});

describe("buildKnownUnknownItems", () => {
  it("emits an uncovered_tactic item per missing phase, each with a collect directive", () => {
    const items = buildKnownUnknownItems(seriousState(), seriousState().forensicTimeline);
    const uncovered = items.filter((i) => i.kind === "uncovered_tactic");
    expect(uncovered.length).toBeGreaterThan(0);
    for (const i of uncovered) {
      expect(i.tactic).toBeTruthy();
      expect(i.collect.length).toBeGreaterThan(0); // #9: each carries a where-to-collect directive
      expect(i.collect[0].host).toBeTruthy();
    }
  });

  it("emits a silence_gap item with a window and NO collect (links to Timeline Gaps panel)", () => {
    const start = Date.parse("2026-05-20T00:00:00Z");
    const events = [
      ev("e0", new Date(start).toISOString(), "H"),
      ev("e1", new Date(start + 3 * 3600_000).toISOString(), "H"),
      ev("e2", new Date(start + 3 * 3600_000 + 5000).toISOString(), "H"),
    ];
    const items = buildKnownUnknownItems(emptyState("c"), events, {
      gapOptions: { minGapMinutes: 30, densityFactor: 0 },
    });
    const gap = items.find((i) => i.kind === "silence_gap");
    expect(gap).toBeDefined();
    expect(gap!.window?.complete).toBe(true);
    expect(gap!.collect).toEqual([]);
  });

  it("renderKnownUnknowns over the items reproduces the prompt block text", () => {
    const items = buildKnownUnknownItems(seriousState(), seriousState().forensicTimeline);
    const block = renderKnownUnknowns(items, 10);
    expect(block.startsWith("KNOWN UNKNOWNS / OPEN GAPS")).toBe(true);
    expect(block).toContain("No finding yet explains these ATT&CK phases");
  });
});

describe("derivePlaybookTasks — uncovered-tactic seeds (#9)", () => {
  it("seeds a known_unknown task per uncovered phase with a stable ku:<tactic> key", () => {
    const seeds = derivePlaybookTasks(seriousState());
    const ku = seeds.filter((t) => t.source === "known_unknown");
    expect(ku.length).toBeGreaterThan(0);
    expect(ku.every((t) => t.sourceKey.startsWith("ku:"))).toBe(true);
    expect(ku.some((t) => t.sourceKey === "ku:lateral-movement")).toBe(true);
    expect(ku[0].title).toMatch(/unexplained phase/i);
    expect(ku[0].description).toMatch(/collect/i);
  });
  it("emits no known_unknown seeds for a low-signal case", () => {
    const s = emptyState("c");
    s.findings = [finding("f1", "Info", [])];
    expect(derivePlaybookTasks(s).some((t) => t.source === "known_unknown")).toBe(false);
  });
});

// #230: a step of a playbook the case otherwise follows, that nothing evidenced. Sharper than an
// uncovered tactic — it names the specific stage the chain implies, and carries the same directive.
describe("buildKnownUnknownItems — unobserved playbook steps (#230)", () => {
  const contiMatch = (missing: string[]) => ({
    name: "Conti",
    description: "",
    reference: "https://example.invalid/conti",
    score: 80,
    matchedCount: 4,
    exactCount: 4,
    outOfOrderCount: 0,
    missingCount: missing.length,
    scope: "host" as const,
    host: "WKSTN01",
    steps: [
      {
        step: { technique: "T1566.001", name: "Spearphish" },
        status: "matched" as const,
        tactic: "Initial Access" as const,
      },
      ...missing.map((t) => ({
        step: { technique: t, name: `step ${t}` },
        status: "missing" as const,
        tactic: "Credential Access" as const,
      })),
    ],
  });

  it("emits one item per missing step, naming the playbook, the score and both readings", () => {
    const items = buildKnownUnknownItems(seriousState(), seriousState().forensicTimeline, {
      playbookMatch: contiMatch(["T1003.001"]),
    });
    const pb = items.filter((i) => i.kind === "playbook_step");
    expect(pb).toHaveLength(1);
    expect(pb[0].technique).toEqual({ id: "T1003.001", name: "step T1003.001" });
    expect(pb[0].playbook).toEqual({ name: "Conti", score: 80, reference: "https://example.invalid/conti" });
    expect(pb[0].label).toContain("Conti");
    expect(pb[0].label).toContain("WKSTN01"); // the scope the match was found at
    expect(pb[0].label).toMatch(/did not happen, or the evidence for it was not collected/i);
    // Same deterministic "collect X from host Y" directive an uncovered tactic gets.
    expect(pb[0].collect.length).toBeGreaterThan(0);
  });

  it("caps the number of missing steps reported", () => {
    const items = buildKnownUnknownItems(seriousState(), seriousState().forensicTimeline, {
      playbookMatch: contiMatch(["T1003.001", "T1003.002", "T1552", "T1555", "T1110"]),
      maxPlaybookSteps: 2,
    });
    expect(items.filter((i) => i.kind === "playbook_step")).toHaveLength(2);
  });

  it("emits nothing when no playbook matched", () => {
    const items = buildKnownUnknownItems(seriousState(), seriousState().forensicTimeline, {});
    expect(items.some((i) => i.kind === "playbook_step")).toBe(false);
  });

  it("carries the step into the synthesis prompt block, so the model sees the same gap", () => {
    const items = buildKnownUnknownItems(seriousState(), seriousState().forensicTimeline, {
      playbookMatch: contiMatch(["T1003.001"]),
    });
    expect(renderKnownUnknowns(items)).toContain("T1003.001");
  });
});
