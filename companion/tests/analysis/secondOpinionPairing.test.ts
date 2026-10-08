import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, it, expect } from "vitest";
import { emptyState, type Finding, type InvestigationState } from "../../src/analysis/stateTypes.js";
import {
  applyAcceptedSecondOpinion,
  buildSecondOpinion,
  buildSecondOpinionDeltas,
  setDeltaStatus,
} from "../../src/analysis/secondOpinion.js";
import {
  containment,
  jaccard,
  overlappingFinding,
  pairByOverlap,
} from "../../src/analysis/secondOpinionTargets.js";

// #1682 — the second opinion paired findings by title-derived key only. Two models that titled the
// same activity differently produced an A-only AND a B-only delta, and "accept B" then added a
// duplicate finding instead of changing A's severity.

function finding(over: Partial<Finding> & Pick<Finding, "id" | "title" | "severity">): Finding {
  return {
    confidence: 80,
    description: `${over.title} description`,
    relatedIocs: [],
    sourceScreenshots: [],
    mitreTechniques: [],
    firstSeen: "2026-06-01T00:00:00.000Z",
    lastUpdated: "2026-06-01T00:00:00.000Z",
    status: "open",
    ...over,
  };
}

const stateWith = (findings: Finding[]): InvestigationState => ({ ...emptyState("c1"), findings });

interface FixtureFinding {
  id: string;
  title: string;
  severity: Finding["severity"];
  mitreTechniques: string[];
  relatedEventIds: string[];
}
const fixture = JSON.parse(
  readFileSync(
    fileURLToPath(new URL("../fixtures/second-opinion/overlap-run.json", import.meta.url)),
    "utf8",
  ),
) as { a: FixtureFinding[]; b: FixtureFinding[] };
const toFinding = (f: FixtureFinding): Finding =>
  finding({ ...f, relatedEventIds: f.relatedEventIds.length ? f.relatedEventIds : undefined });

describe("jaccard", () => {
  it("is |A∩B| / |A∪B| and 0 when either side cites nothing", () => {
    expect(jaccard(["e1", "e2"], ["e2", "e3"])).toBeCloseTo(1 / 3);
    expect(jaccard(["e1"], ["e1"])).toBe(1);
    expect(jaccard([], ["e1"])).toBe(0);
    expect(jaccard(undefined, undefined)).toBe(0);
  });
});

const ids = (prefix: string, n: number): string[] => Array.from({ length: n }, (_, i) => `${prefix}${i}`);

describe("containment — a short B list inside a long A list (#2046)", () => {
  const long = ids("e", 100);
  const shortInside = long.slice(0, 8);

  it("is the share of the smaller set inside the larger", () => {
    expect(containment(shortInside, long)).toBe(1);
    expect(containment(long, shortInside)).toBe(1);
    expect(containment(["e0", "x1", "x2", "x3"], long)).toBe(0.25);
    expect(containment([], long)).toBe(0);
    expect(containment(undefined, long)).toBe(0);
  });

  it("pairs B (8 events) with A (100 events that include them) although Jaccard is 0.08", () => {
    const as = [
      finding({ id: "a0", title: "PsExec lateral movement", severity: "Critical", relatedEventIds: long }),
    ];
    const bs = [
      finding({
        id: "b0",
        title: "Remote service execution",
        severity: "Critical",
        relatedEventIds: shortInside,
      }),
    ];
    expect(jaccard(long, shortInside)).toBeLessThan(0.1);
    expect(pairByOverlap(as, bs)).toEqual([[0, 0]]);
  });

  it("breaks containment ties by Jaccard, so the tightest A finding wins", () => {
    const as = [
      finding({ id: "a0", title: "Broad", severity: "High", relatedEventIds: long }),
      finding({ id: "a1", title: "Tight", severity: "High", relatedEventIds: ids("e", 10) }),
    ];
    const bs = [finding({ id: "b0", title: "Short", severity: "High", relatedEventIds: shortInside })];
    expect(pairByOverlap(as, bs)).toEqual([[1, 0]]);
  });

  it("does not pair when most of B sits outside A (low containment)", () => {
    const as = [finding({ id: "a0", title: "A", severity: "High", relatedEventIds: long })];
    const bs = [
      finding({
        id: "b0",
        title: "B",
        severity: "High",
        relatedEventIds: ["e0", "e1", "x1", "x2", "x3", "x4", "x5", "x6"],
      }),
    ];
    expect(pairByOverlap(as, bs)).toEqual([]);
    expect(overlappingFinding(as, bs[0])).toBeUndefined();
  });

  it("folds an accepted b_only into the long A finding instead of adding a duplicate", () => {
    const a = stateWith([
      finding({ id: "f1", title: "PsExec lateral movement", severity: "High", relatedEventIds: long }),
    ]);
    const bf = finding({
      id: "g1",
      title: "Remote service execution",
      severity: "Critical",
      relatedEventIds: shortInside,
    });
    const so = {
      generatedAt: "t",
      modelA: "A",
      modelB: "B",
      referee: "",
      summary: "",
      agreementCount: 0,
      deltas: [
        {
          id: "b_only:g1",
          kind: "b_only" as const,
          title: bf.title,
          bSeverity: bf.severity,
          finding: bf,
          rationale: "",
          recommendation: "accept_b" as const,
          status: "accepted" as const,
        },
      ],
    };
    const next = applyAcceptedSecondOpinion(a, so);
    expect(next.findings).toHaveLength(1);
    expect(next.findings[0].severity).toBe("Critical");
  });

  it("folds a 1-event B finding that sits inside A (the issue's f4/f20 rows)", () => {
    const as = [finding({ id: "a0", title: "A", severity: "High", relatedEventIds: ids("e", 5) })];
    const bs = [finding({ id: "b0", title: "B", severity: "High", relatedEventIds: ["e2"] })];
    expect(pairByOverlap(as, bs)).toEqual([[0, 0]]);
  });
});

describe("pairByOverlap — global greedy 1:1 (#1682)", () => {
  it("takes the strongest pair first, so a weaker claim cannot steal a finding", () => {
    // B0 overlaps A1 at 0.75 but B1 overlaps A1 at 1.0. A per-B loop in order would give A1 to B0
    // and strand B1. Global greedy gives A1 to B1.
    const as = [
      finding({
        id: "a0",
        title: "Kit staged",
        severity: "High",
        relatedEventIds: ["1", "2", "3", "4", "5", "6", "7", "8", "9", "10"],
      }),
      finding({
        id: "a1",
        title: "DLL side-loading",
        severity: "High",
        relatedEventIds: ["1", "2", "3", "4", "5", "6"],
      }),
    ];
    const bs = [
      finding({
        id: "b0",
        title: "Kit",
        severity: "High",
        relatedEventIds: ["1", "2", "3", "4", "5", "6", "7", "8"],
      }),
      finding({
        id: "b1",
        title: "Side-load",
        severity: "High",
        relatedEventIds: ["1", "2", "3", "4", "5", "6"],
      }),
    ];
    const pairs = pairByOverlap(as, bs);
    expect(pairs).toContainEqual([1, 1]);
    expect(pairs).toContainEqual([0, 0]); // 8/10 = 0.8
    expect(pairs).toHaveLength(2);
  });

  it("never pairs below the threshold, and never pairs findings with no cited events", () => {
    const as = [finding({ id: "a0", title: "X one", severity: "High", relatedEventIds: ["1", "2", "3"] })];
    const bs = [
      finding({ id: "b0", title: "Y two", severity: "High", relatedEventIds: ["1", "4", "5"] }),
      finding({ id: "b1", title: "Z three", severity: "High" }),
    ];
    expect(pairByOverlap(as, bs)).toEqual([]);
  });

  it("pairs near-identical titles after normalization, even with no cited events", () => {
    const as = [finding({ id: "a0", title: "Quick Assist executed.", severity: "Low" })];
    const bs = [finding({ id: "b0", title: "quick-assist  executed", severity: "Low" })];
    expect(pairByOverlap(as, bs)).toEqual([[0, 0]]);
  });
});

describe("buildSecondOpinionDeltas — pairs by cited events (#1682)", () => {
  const a = stateWith(fixture.a.map(toFinding));
  const b = stateWith(fixture.b.map(toFinding));
  const deltas = buildSecondOpinionDeltas(a, b);
  const findingDeltas = deltas.filter(
    (d) => d.kind === "a_only" || d.kind === "b_only" || d.kind === "severity",
  );
  const oneSided = findingDeltas.filter((d) => d.kind !== "severity");

  it("turns at least 15 of the lab run's one-sided pairs into agreements or severity deltas", () => {
    const so = buildSecondOpinion({ a, b, modelA: "A", modelB: "B", now: () => "t" });
    const severity = findingDeltas.filter((d) => d.kind === "severity").length;
    expect(so.agreementCount + severity).toBeGreaterThanOrEqual(15);
    // Before #1682 every one of these 37 findings was a one-sided delta.
    expect(oneSided.length).toBeLessThanOrEqual(37 - 2 * 15);
  });

  it("never emits an A-only and a B-only delta for the same finding id pair it matched", () => {
    const aOnlyIds = new Set(deltas.filter((d) => d.kind === "a_only").map((d) => d.finding?.id));
    const bOnlyIds = deltas.filter((d) => d.kind === "b_only").map((d) => d.finding?.id);
    // In this run B re-used A's finding ids, so an id on both sides is the same finding split in two.
    // Since #2046 containment pairs the kit and the one-event PowerShell write too, so no id is
    // split any more. B's zero-event finding has nothing to pair on.
    const split = bOnlyIds.filter((id) => aOnlyIds.has(id));
    expect(split).toEqual([]);
  });

  it("does not strand B's DLL side-loading finding behind the emulation-kit finding", () => {
    const dll = deltas.find((d) => d.finding?.id === "f2");
    expect(dll).toBeUndefined(); // same severity on both sides → agreement, no delta at all
    expect(deltas.some((d) => d.kind === "b_only" && d.finding?.id === "f2")).toBe(false);
  });

  it("makes a paired disagreement a severity delta on A's finding", () => {
    const py = deltas.find((d) => d.finding?.id === "f3");
    expect(py?.kind).toBe("severity");
    expect(py?.aSeverity).toBe("High");
    expect(py?.bSeverity).toBe("Medium");
    expect(py?.finding?.title).toMatch(/^Python-based loader and backdoor staging \(slv\.py/);
    expect(py?.bFinding?.title).toBe("Python-based loader and backdoor staging emulating Sliver C2");
  });

  it("keeps a genuinely new B finding (no overlap with any A finding) as b_only", () => {
    const chainsaw = deltas.find((d) => d.finding?.id === "f-auto-8e12");
    expect(chainsaw?.kind).toBe("b_only");
  });

  it("accepting B on a paired finding lowers A's severity and adds no finding", () => {
    const so = buildSecondOpinion({ a, b, modelA: "A", modelB: "B", now: () => "t" });
    const py = so.deltas.find((d) => d.finding?.id === "f3");
    const next = applyAcceptedSecondOpinion(a, setDeltaStatus(so, py!.id, "accepted"));
    expect(next.findings).toHaveLength(a.findings.length);
    expect(next.findings.find((f) => f.id === "f3")?.severity).toBe("Medium");
  });
});

describe("applyAcceptedSecondOpinion — duplicate guard on an accepted b_only (#1682)", () => {
  const a = stateWith([
    finding({
      id: "f3",
      title: "Python loader (slv.py, wo14.py) emulating Sliver",
      severity: "High",
      relatedEventIds: ["e1", "e2", "e3", "e4"],
    }),
  ]);
  const bDup = finding({
    id: "g3",
    title: "Backdoor staging for C2",
    severity: "Medium",
    relatedEventIds: ["e1", "e2", "e3"],
  });
  const bNew = finding({
    id: "g9",
    title: "Cobalt Strike beacon",
    severity: "High",
    relatedEventIds: ["e70"],
  });
  const record = (f: Finding) => ({
    generatedAt: "t",
    modelA: "A",
    modelB: "B",
    referee: "",
    summary: "",
    agreementCount: 0,
    deltas: [
      {
        id: `b_only:${f.id}`,
        kind: "b_only" as const,
        title: f.title,
        bSeverity: f.severity,
        finding: f,
        rationale: "",
        recommendation: "accept_b" as const,
        status: "accepted" as const,
      },
    ],
  });

  it("turns an overlapping B-only into a severity change on the existing finding", () => {
    const next = applyAcceptedSecondOpinion(a, record(bDup));
    expect(next.findings).toHaveLength(1);
    expect(next.findings[0].id).toBe("f3");
    expect(next.findings[0].severity).toBe("Medium");
    // Idempotent: a second pass changes nothing more.
    expect(applyAcceptedSecondOpinion(next, record(bDup))).toEqual(next);
  });

  it("still adds a B-only finding that overlaps nothing", () => {
    const next = applyAcceptedSecondOpinion(a, record(bNew));
    expect(next.findings).toHaveLength(2);
    expect(next.findings[1].title).toBe("Cobalt Strike beacon");
  });

  it("adds B's finding when the only overlapping finding was dismissed", () => {
    const dismissed = stateWith([{ ...a.findings[0], status: "dismissed" }]);
    const next = applyAcceptedSecondOpinion(dismissed, record(bDup));
    expect(next.findings).toHaveLength(2);
    expect(next.findings[0].severity).toBe("High");
  });
});
