import { describe, it, expect } from "vitest";
import {
  buildKnownUnknownItems,
  uncoveredCoreTactics,
  tacticCollectDirectives,
  renderKnownUnknowns,
} from "../../src/analysis/knownUnknowns.js";
import { derivePlaybookTasks } from "../../src/analysis/playbook.js";
import { buildHostAliasIndex } from "../../src/analysis/hostAlias.js";
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
// A same-binary-on-two-hosts hash, shared by every host-alias fixture below (evidenceGraph's
// lateral_move (hash) rule just needs it non-empty and shared across ≥2 hosts).
const ALIAS_FIXTURE_HASH = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
// Minimal forensic-event factory for fixtures that need fields ev() doesn't take (sha256, sources,
// description) — same "state only what this test cares about" shape used in evidenceGraph.test.ts.
function partialEvent(p: Partial<ForensicEvent> & { id: string }): ForensicEvent {
  return {
    timestamp: "2026-05-20T08:00:00Z",
    description: "",
    severity: "High",
    mitreTechniques: [],
    relatedFindingIds: [],
    sourceScreenshots: [],
    ...p,
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

// A duplicate-host case: the same machine appears as both a short name and an FQDN. Three of
// targetHostsForTactic's four branches (Initial Access/earliestAsset, Lateral Movement/lateralHosts,
// Command and Control/connectiveHosts) read RAW host names, so without an alias index a merged host
// shows up as TWO separate collection targets. The optional trailing `aliasIndex` param resolves and
// dedupes them onto one, at the single point where targetHostsForTactic returns.
describe("tacticCollectDirectives — host alias resolution", () => {
  const HASH = ALIAS_FIXTURE_HASH;

  it("Lateral Movement: without an index a merged host is still two targets (today's behavior)", () => {
    const s = emptyState("c");
    s.forensicTimeline = [
      partialEvent({ id: "e1", asset: "WIN11", sha256: HASH, severity: "Critical" }),
      partialEvent({ id: "e2", asset: "WIN11.windomain.local", sha256: HASH, severity: "High" }),
    ];
    const dirs = tacticCollectDirectives("Lateral Movement", s, s.forensicTimeline, []);
    expect(dirs.map((d) => d.host)).toEqual(["WIN11", "WIN11.windomain.local"]);
  });

  it("Lateral Movement: with an index, the same merged host yields ONE collection target", () => {
    const s = emptyState("c");
    s.forensicTimeline = [
      partialEvent({ id: "e1", asset: "WIN11", sha256: HASH, severity: "Critical" }),
      partialEvent({ id: "e2", asset: "WIN11.windomain.local", sha256: HASH, severity: "High" }),
    ];
    const aliasIndex = buildHostAliasIndex([], { win11: "win11.windomain.local" });
    const dirs = tacticCollectDirectives("Lateral Movement", s, s.forensicTimeline, [], aliasIndex);
    expect(dirs).toHaveLength(1);
    expect(dirs[0].host).toBe("win11.windomain.local");
  });

  it("Command and Control: with an index, the same merged host yields ONE collection target", () => {
    const s = emptyState("c");
    s.iocs = [{ id: "i1", type: "domain", value: "evil-c2.example", firstSeen: "" }];
    s.forensicTimeline = [
      partialEvent({ id: "e1", asset: "WIN11", description: "beacon to evil-c2.example", sources: ["Zeek"] }),
      partialEvent({
        id: "e2",
        asset: "WIN11.windomain.local",
        description: "beacon to evil-c2.example",
        sources: ["Zeek"],
      }),
    ];
    const withoutIndex = tacticCollectDirectives("Command and Control", s, s.forensicTimeline, []);
    expect(withoutIndex.map((d) => d.host)).toEqual(["WIN11", "WIN11.windomain.local"]); // today: split in two

    const aliasIndex = buildHostAliasIndex([], { win11: "win11.windomain.local" });
    const withIndex = tacticCollectDirectives("Command and Control", s, s.forensicTimeline, [], aliasIndex);
    expect(withIndex).toHaveLength(1);
    expect(withIndex[0].host).toBe("win11.windomain.local");
  });

  it("resolves+dedupes BEFORE the MAX_HOSTS_PER_TACTIC cap, so collapsing a duplicate doesn't lose a distinct host", () => {
    const s = emptyState("c");
    // Two connective IOCs. "primary-c2" ranks first (2 tools beat 1) so its hosts land at raw
    // positions 0/1 — the merged host. "secondary-c2" ranks second, contributing two MORE distinct
    // hosts at raw positions 2/3. MAX_HOSTS_PER_TACTIC is 3: resolving the duplicate away BEFORE
    // slicing leaves room for all 3 distinct hosts; slicing the raw 4 down to 3 first (capturing
    // both spellings of the same host) then resolving would collapse to only 2, silently dropping
    // FILESVR01 — the case the task description warns about ("the more useful one" gets dropped).
    s.iocs = [
      { id: "i1", type: "domain", value: "primary-c2.example", firstSeen: "" },
      { id: "i2", type: "domain", value: "secondary-c2.example", firstSeen: "" },
    ];
    s.forensicTimeline = [
      partialEvent({
        id: "e1",
        asset: "WIN11",
        description: "beacon to primary-c2.example",
        sources: ["Zeek"],
      }),
      partialEvent({
        id: "e2",
        asset: "WIN11.windomain.local",
        description: "beacon to primary-c2.example",
        sources: ["Sysmon"],
      }),
      partialEvent({
        id: "e3",
        asset: "DC01",
        description: "beacon to secondary-c2.example",
        sources: ["Zeek"],
      }),
      partialEvent({
        id: "e4",
        asset: "FILESVR01",
        description: "beacon to secondary-c2.example",
        sources: ["Zeek"],
      }),
    ];
    const aliasIndex = buildHostAliasIndex([], { win11: "win11.windomain.local" });
    const dirs = tacticCollectDirectives("Command and Control", s, s.forensicTimeline, [], aliasIndex);
    expect(dirs.map((d) => d.host)).toEqual(["win11.windomain.local", "dc01", "filesvr01"]);
  });

  it("with no alias index, host names pass through completely untouched — no implicit lowercasing/merging", () => {
    const s = emptyState("c");
    s.forensicTimeline = [
      partialEvent({ id: "e1", asset: "WIN11", sha256: HASH, severity: "Critical" }),
      // Deliberately mixed-case: if resolution ran even without an index (e.g. through an
      // accidentally-constructed empty one), canonicalHostName would lowercase this and the two
      // spellings would incorrectly merge.
      partialEvent({ id: "e2", asset: "Win11.WinDomain.Local", sha256: HASH, severity: "High" }),
    ];
    const dirs = tacticCollectDirectives("Lateral Movement", s, s.forensicTimeline, []);
    expect(dirs.map((d) => d.host)).toEqual(["WIN11", "Win11.WinDomain.Local"]);
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

  it("threads opts.aliasIndex down into each uncovered tactic's collect directive", () => {
    const s = emptyState("c");
    s.findings = [finding("f1", "Critical", ["T1486"])]; // Impact covered; Lateral Movement stays uncovered
    s.forensicTimeline = [
      partialEvent({ id: "e1", asset: "WIN11", sha256: ALIAS_FIXTURE_HASH, severity: "Critical" }),
      partialEvent({
        id: "e2",
        asset: "WIN11.windomain.local",
        sha256: ALIAS_FIXTURE_HASH,
        severity: "High",
      }),
    ];
    const aliasIndex = buildHostAliasIndex([], { win11: "win11.windomain.local" });
    const items = buildKnownUnknownItems(s, s.forensicTimeline, { aliasIndex });
    const lat = items.find((i) => i.kind === "uncovered_tactic" && i.tactic === "Lateral Movement");
    expect(lat).toBeDefined();
    expect(lat!.collect.map((d) => d.host)).toEqual(["win11.windomain.local"]); // one target, not two
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
  it("threads opts.aliasIndex down into the known_unknown task's collect directive", () => {
    const s = emptyState("c");
    s.findings = [finding("f1", "Critical", ["T1486"])]; // Impact covered; Lateral Movement stays uncovered
    s.forensicTimeline = [
      partialEvent({ id: "e1", asset: "WIN11", sha256: ALIAS_FIXTURE_HASH, severity: "Critical" }),
      partialEvent({
        id: "e2",
        asset: "WIN11.windomain.local",
        sha256: ALIAS_FIXTURE_HASH,
        severity: "High",
      }),
    ];

    const withoutIndex = derivePlaybookTasks(s);
    const latWithout = withoutIndex.find((t) => t.sourceKey === "ku:lateral-movement")!;
    expect(latWithout.description.match(/windomain\.local/gi) ?? []).toHaveLength(1); // FQDN spelling
    expect(latWithout.description).toContain("WIN11 "); // short-name spelling, still separate

    const aliasIndex = buildHostAliasIndex([], { win11: "win11.windomain.local" });
    const withIndex = derivePlaybookTasks(s, { aliasIndex });
    const latWith = withIndex.find((t) => t.sourceKey === "ku:lateral-movement")!;
    // Merged: the resolved host appears exactly once, not once per spelling.
    expect(latWith.description.match(/win11\.windomain\.local/gi) ?? []).toHaveLength(1);
    expect(latWith.description).not.toMatch(/WIN11 /); // the bare short-name line is gone
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
