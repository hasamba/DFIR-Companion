import { describe, it, expect } from "vitest";
import {
  openCollectTargets,
  collectSatisfiedBy,
  detectSatisfiedCollections,
  buildSatisfiedCollectionsBlock,
  stampCollectDirectives,
  highestImportSeq,
  type OpenCollectTarget,
} from "../../src/analysis/collectSatisfaction.js";
import { emptyState, type ForensicEvent } from "../../src/analysis/stateTypes.js";

function ev(p: Partial<ForensicEvent>): ForensicEvent {
  return {
    id: p.id ?? "e1",
    timestamp: "2026-01-01T00:00:00Z",
    description: p.description ?? "",
    severity: p.severity ?? "Info",
    mitreTechniques: [],
    relatedFindingIds: [],
    sourceScreenshots: [],
    ...p,
  };
}

describe("openCollectTargets", () => {
  it("collects actionable targets from nextSteps and unknown questions, de-duped", () => {
    const s = emptyState("c1");
    s.nextSteps = [
      {
        id: "n1",
        priority: "high",
        action: "pull",
        rationale: "",
        pointer: "",
        collect: { host: "DC01", logSource: "Security.evtx 4624" },
      },
      { id: "n2", priority: "low", action: "sandbox", rationale: "", pointer: "" }, // no collect → skipped
    ];
    s.keyQuestions = [
      {
        id: "q1",
        question: "lateral?",
        status: "unknown",
        answer: "",
        pointer: "",
        collect: { host: "DC01", logSource: "Security.evtx 4624" },
      }, // dup of n1's target
      {
        id: "q2",
        question: "exfil?",
        status: "partial",
        answer: "",
        pointer: "",
        collect: { host: "WEB01", logSource: "web proxy logs" },
      },
      {
        id: "q3",
        question: "answered",
        status: "answered",
        answer: "x",
        pointer: "",
        collect: { host: "H", logSource: "y" },
      }, // answered → skipped
    ];
    const targets = openCollectTargets(s);
    const keys = targets.map((t) => t.key);
    expect(keys).toContain("dc01|security.evtx 4624");
    expect(keys).toContain("web01|web proxy logs");
    // n1 and q1 share a target key → de-duped to one
    expect(keys.filter((k) => k === "dc01|security.evtx 4624")).toHaveLength(1);
    expect(targets.length).toBe(2);
  });

  it("carries the directive's issue stamp onto the target", () => {
    const s = emptyState("c1");
    s.nextSteps = [
      {
        id: "n1",
        priority: "high",
        action: "pull",
        rationale: "",
        pointer: "",
        collect: { host: "DC01", logSource: "Security.evtx 4624", issuedAfterImportSeq: 4 },
      },
    ];
    expect(openCollectTargets(s)[0].issuedAfterImportSeq).toBe(4);
  });
});

describe("collectSatisfiedBy", () => {
  const target: OpenCollectTarget = {
    key: "dc01|security.evtx 4624",
    host: "DC01",
    source: "Security.evtx 4624",
    from: "question",
    refId: "q1",
    summary: "collect Security.evtx 4624 from DC01",
    issuedAfterImportSeq: 0,
  };

  it("matches an event on the host whose source/description carries a source token", () => {
    const hits = collectSatisfiedBy(target, [
      ev({
        id: "1e1",
        asset: "DC01",
        description: "4624 logon type 3",
        sources: ["Windows.EventLogs.Security"],
      }),
      ev({ id: "1e2", asset: "WEB01", description: "4624 logon" }), // wrong host
    ]);
    expect(hits).toEqual(["1e1"]);
  });

  it("does not match a same-host event with an unrelated source (no token overlap)", () => {
    const hits = collectSatisfiedBy(target, [
      ev({ id: "1e1", asset: "DC01", description: "a sysmon network connection", sources: ["Sysmon"] }),
    ]);
    expect(hits).toEqual([]);
  });

  it("matches on host alone when the source names nothing specific", () => {
    const t2: OpenCollectTarget = { ...target, source: "logs", key: "dc01|logs" };
    const hits = collectSatisfiedBy(t2, [ev({ id: "1e1", asset: "DC01", description: "anything" })]);
    expect(hits).toEqual(["1e1"]);
  });

  // A case on 2026-09-14: a "baseline the WMI consumer on win-x" directive was marked
  // satisfied by the two Sigma hits that had prompted it — imported weeks before the directive existed —
  // and the next synthesis narrated those same hits as a completed "golden-image comparison". Only
  // evidence imported AFTER the directive was issued may satisfy it.
  it("ignores evidence that was already in the case when the directive was issued", () => {
    const wmi: OpenCollectTarget = {
      key: "win-x|wmi event consumer baseline",
      host: "win-x",
      source: "WMI event consumer baseline",
      from: "nextStep",
      refId: "n9",
      summary: "collect WMI event consumer baseline from win-x",
      issuedAfterImportSeq: 10, // the case had imports 1..10 when the model asked for this
    };
    const preExisting = [
      ev({ id: "2e926", asset: "WIN-X", description: "Sigma: Permanent WMI Event Consumer" }),
      ev({ id: "2e137", asset: "WIN-X", description: "Sigma: WMI Persistence" }),
      ev({ id: "10e3", asset: "WIN-X", description: "WMI subscription listing" }), // same import as the stamp
    ];
    expect(collectSatisfiedBy(wmi, preExisting)).toEqual([]);

    const later = ev({ id: "11e1", asset: "WIN-X", description: "WMI consumer baseline dump" });
    expect(collectSatisfiedBy(wmi, [...preExisting, later])).toEqual(["11e1"]);
  });

  it("never satisfies a directive that carries no issue stamp (its age is unknown)", () => {
    const { issuedAfterImportSeq: _omit, ...unstamped } = target;
    const hits = collectSatisfiedBy(unstamped, [
      ev({ id: "1e1", asset: "DC01", description: "4624 logon", sources: ["Windows.EventLogs.Security"] }),
    ]);
    expect(hits).toEqual([]);
  });

  it("does not count an event whose id carries no import sequence", () => {
    const hits = collectSatisfiedBy(target, [
      ev({ id: "manual-7", asset: "DC01", description: "4624 logon", sources: ["Windows.EventLogs.Security"] }),
    ]);
    expect(hits).toEqual([]);
  });
});

describe("highestImportSeq", () => {
  it("is the largest import prefix across the timeline, 0 when nothing is sequenced", () => {
    expect(highestImportSeq([ev({ id: "2e926" }), ev({ id: "10e3" }), ev({ id: "manual-1" })])).toBe(10);
    expect(highestImportSeq([])).toBe(0);
    expect(highestImportSeq([ev({ id: "e1" })])).toBe(0);
  });
});

describe("stampCollectDirectives", () => {
  const prev = () => {
    const s = emptyState("c1");
    s.forensicTimeline = [ev({ id: "3e1" }), ev({ id: "7e2" })]; // imports 1..7 are in the case
    return s;
  };

  it("stamps a NEW directive with the case's current import high-water mark", () => {
    const next = emptyState("c1");
    next.nextSteps = [
      { id: "n1", priority: "high", action: "a", rationale: "", pointer: "", collect: { host: "H1", logSource: "x" } },
    ];
    next.keyQuestions = [
      { id: "q1", question: "?", status: "unknown", answer: "", pointer: "", collect: { host: "H2", artifact: "y" } },
    ];
    const out = stampCollectDirectives(next, prev());
    expect(out.nextSteps[0].collect?.issuedAfterImportSeq).toBe(7);
    expect(out.keyQuestions[0].collect?.issuedAfterImportSeq).toBe(7);
  });

  it("carries the ORIGINAL stamp forward when the model re-emits the same target", () => {
    const p = prev();
    p.nextSteps = [
      {
        id: "n1",
        priority: "high",
        action: "a",
        rationale: "",
        pointer: "",
        collect: { host: "H1", logSource: "x", issuedAfterImportSeq: 3 },
      },
    ];
    const next = emptyState("c1");
    next.nextSteps = [
      // same host+source, different id and wording — the model re-issued it
      { id: "n4", priority: "medium", action: "pull x again", rationale: "", pointer: "", collect: { host: "h1", logSource: "X" } },
    ];
    const out = stampCollectDirectives(next, p);
    expect(out.nextSteps[0].collect?.issuedAfterImportSeq).toBe(3);
  });

  it("leaves non-collect steps and unanchored directives alone, and does not mutate its input", () => {
    const next = emptyState("c1");
    const steps = [
      { id: "n1", priority: "low" as const, action: "sandbox", rationale: "", pointer: "" },
      { id: "n2", priority: "low" as const, action: "collect somewhere", rationale: "", pointer: "", collect: { logSource: "x" } },
    ];
    next.nextSteps = steps;
    const out = stampCollectDirectives(next, prev());
    expect(out.nextSteps[0]).toEqual(steps[0]);
    expect(out.nextSteps[1].collect).toEqual({ logSource: "x" });
    expect(steps[1].collect).toEqual({ logSource: "x" });
  });
});

describe("detectSatisfiedCollections + block", () => {
  it("flags a previously-recommended collection now present in the events", () => {
    const s = emptyState("c1");
    s.keyQuestions = [
      {
        id: "q_lateral_movement",
        question: "Was there lateral movement?",
        status: "unknown",
        answer: "",
        pointer: "",
        collect: { host: "DC01", logSource: "Security.evtx 4624", issuedAfterImportSeq: 1 },
      },
    ];
    const events = [
      ev({
        id: "2e42",
        asset: "DC01",
        description: "Security 4624 type-3 logon from WS07",
        sources: ["Windows.EventLogs.Security"],
      }),
    ];
    const satisfied = detectSatisfiedCollections(s, events);
    expect(satisfied).toHaveLength(1);
    expect(satisfied[0].target.refId).toBe("q_lateral_movement");
    expect(satisfied[0].matchedEventIds).toEqual(["2e42"]);

    const block = buildSatisfiedCollectionsBlock(satisfied);
    expect(block).toContain("SATISFIED COLLECTIONS");
    expect(block).toContain("do NOT re-recommend");
    expect(block).toContain("Was there lateral movement?");
    expect(block).toContain("2e42");
  });

  it("returns '' block when nothing is satisfied", () => {
    expect(buildSatisfiedCollectionsBlock([])).toBe("");
  });
});
