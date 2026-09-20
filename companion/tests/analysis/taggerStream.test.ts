// #1444: "Run tagger", its preview and the analysis-run replay used to pull the WHOLE super-timeline
// into one array before matching. They feed a TaggerAccumulator batch by batch now. This file pins
// that the accumulator equals runTagger over the same rows, that the scope feeder unions forensic
// and super exactly as selectScopedEvents did, and that the preview sample is the first N matches.
import { describe, it, expect } from "vitest";
import { compileRuleset } from "../../src/analysis/taggerRules.js";
import {
  createTaggerAccumulator,
  feedTaggerScope,
  runTagger,
  selectScopedEvents,
} from "../../src/analysis/tagger.js";
import type { ForensicEvent } from "../../src/analysis/stateTypes.js";

function ev(p: Partial<ForensicEvent> & { id: string }): ForensicEvent {
  return {
    timestamp: "2026-06-01T00:00:00Z",
    description: "d",
    severity: "Info",
    mitreTechniques: [],
    relatedFindingIds: [],
    sourceScreenshots: [],
    ...p,
  };
}

const RULESET = compileRuleset({
  svc: {
    any: [{ field: "message", contains: "7045" }],
    tags: ["win-service", "persistence"],
    mitre: ["T1543"],
    severity: "Medium",
  },
  cred: {
    any: [{ field: "message", contains: "lsass" }],
    tags: ["cred-access"],
    mitre: ["T1003"],
    severity: "High",
  },
});

const forensic = [
  ev({ id: "f1", message: "service 7045 installed" }),
  ev({ id: "shared", message: "dump lsass (forensic copy)" }),
  ev({ id: "f3", message: "quiet" }),
];
const superRows = [
  ev({ id: "s1", message: "7045 and lsass together" }),
  ev({ id: "shared", message: "dump lsass (super copy)" }),
  ev({ id: "s3", message: "nothing" }),
  ev({ id: "s4", message: "another lsass touch" }),
  ev({ id: "s5", message: "7045 again" }),
];

async function* batches(rows: ForensicEvent[], size: number): AsyncGenerator<ForensicEvent[]> {
  for (let i = 0; i < rows.length; i += size) yield rows.slice(i, i + size);
}

// perRule is exact (rule order is the ruleset's, ids are in row order). perEvent lists the same
// results, but a batched run lists them in row order rather than rule-then-row order — an order
// no consumer reads (they key it by eventId), so it is compared as a set here.
const byId = (r: { perEvent: { eventId: string }[] }) =>
  [...r.perEvent].sort((a, b) => a.eventId.localeCompare(b.eventId));
function expectSameResult(
  actual: ReturnType<typeof runTagger>,
  expected: ReturnType<typeof runTagger>,
): void {
  expect(actual.perRule).toEqual(expected.perRule);
  expect(actual.totalMatched).toBe(expected.totalMatched);
  expect(byId(actual)).toEqual(byId(expected));
}

describe("createTaggerAccumulator (#1444)", () => {
  it("fed in batches of 2, equals runTagger over the same rows — per rule and per event", () => {
    const all = [...forensic, ...superRows.filter((e) => e.id !== "shared")];
    const acc = createTaggerAccumulator(RULESET);
    for (let i = 0; i < all.length; i += 2) acc.add(all.slice(i, i + 2));
    expectSameResult(acc.finish(), runTagger(all, RULESET));
  });

  it("keeps only the first N matched events as the preview sample, in match order", () => {
    const acc = createTaggerAccumulator(RULESET, 2);
    acc.add(forensic);
    acc.add(superRows.filter((e) => e.id !== "shared"));
    expect(acc.sample().map((e) => e.id)).toEqual(["f1", "shared"]);
    expect(acc.finish().totalMatched).toBe(5);
  });

  it("with no sample requested, holds no events at all", () => {
    const acc = createTaggerAccumulator(RULESET);
    acc.add([...forensic, ...superRows]);
    expect(acc.sample()).toEqual([]);
  });
});

describe("feedTaggerScope (#1444)", () => {
  for (const scope of ["both", "forensic", "super"] as const) {
    it(`scope=${scope}: the streamed result equals runTagger(selectScopedEvents(...))`, async () => {
      const acc = createTaggerAccumulator(RULESET);
      await feedTaggerScope(acc, scope, forensic, batches(superRows, 2));
      const expected = runTagger(selectScopedEvents(scope, forensic, superRows), RULESET);
      expectSameResult(acc.finish(), expected);
    });
  }

  it("scope=both: the forensic copy of a shared id wins and the super copy is never counted", async () => {
    const acc = createTaggerAccumulator(RULESET, 10);
    await feedTaggerScope(acc, "both", forensic, batches(superRows, 2));
    const r = acc.finish();
    expect(r.perRule.find((x) => x.id === "cred")!.eventIds).toEqual(["shared", "s1", "s4"]);
    expect(acc.sample().find((e) => e.id === "shared")!.message).toContain("forensic copy");
  });

  it("without a super-timeline store, scope=both and scope=super read the forensic side only as before", async () => {
    const both = createTaggerAccumulator(RULESET);
    await feedTaggerScope(both, "both", forensic, null);
    expect(both.finish()).toEqual(runTagger(forensic, RULESET));
    const sup = createTaggerAccumulator(RULESET);
    await feedTaggerScope(sup, "super", forensic, null);
    expect(sup.finish().totalMatched).toBe(0);
  });
});
