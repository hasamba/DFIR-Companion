import { describe, it, expect } from "vitest";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { compileRuleset, type CompiledRuleset } from "../../src/analysis/taggerRules.js";
import { createTaggerAccumulator, runTagger, runTaggerYielding } from "../../src/analysis/tagger.js";
import { TaggerStore } from "../../src/analysis/taggerStore.js";
import type { ForensicEvent } from "../../src/analysis/stateTypes.js";
import { fixtureTimeline } from "./fixtures/mergeLoadFixture.js";
import { loopLag } from "./helpers/loopLag.js";

// #2716: the settle's auto-tagger evaluated every bundled rule against every row an import added in
// one synchronous call — minutes on a large import. runTaggerYielding walks the same rules over the
// same rows in the same rule-major order, so its result is identical in every list and order
// (perEvent included, which a row-sliced run would reorder), and it lets timers run.

async function bundledRules(): Promise<CompiledRuleset> {
  const dir = await mkdtemp(join(tmpdir(), "dfir-tagger-yield-"));
  try {
    return await new TaggerStore(join(dir, "user.yaml")).load(); // the bundled data/tags.yaml
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
}

const OVERLAP = compileRuleset({
  a: {
    any: [{ field: "description", contains: "Temp" }],
    tags: ["t1", "shared"],
    mitre: ["T1"],
    severity: "Low",
  },
  b: {
    any: [{ field: "description", contains: "drop" }],
    tags: ["shared", "t2"],
    mitre: ["T2"],
    severity: "High",
  },
  c: { any: [{ field: "description", contains: "never-present" }], tags: ["none"], mitre: [] },
});

function quiet(n: number): ForensicEvent[] {
  return Array.from({ length: n }, (_, i) => ({
    id: `q${i}`,
    timestamp: "2026-06-01T00:00:00Z",
    description: "nothing of note",
    severity: "Info",
    mitreTechniques: [],
    relatedFindingIds: [],
    sourceScreenshots: [],
  }));
}

describe("runTaggerYielding gives runTagger's exact result (#2716)", () => {
  it("with the bundled rules over a mixed timeline, every order included", async () => {
    const rules = await bundledRules();
    const events = fixtureTimeline(900);
    const expected = runTagger(events, rules);
    expect(expected.totalMatched).toBeGreaterThan(0);
    expect(await runTaggerYielding(events, rules)).toEqual(expected);
  });

  it("with overlapping rules, a rule that matches nothing, and a duplicated id", async () => {
    const events = fixtureTimeline(120);
    const withDup = [...events, { ...events[2], description: "second copy in Temp drop" }];
    expect(await runTaggerYielding(withDup, OVERLAP)).toEqual(runTagger(withDup, OVERLAP));
  });

  it("over rows no rule matches", async () => {
    const rules = await bundledRules();
    const events = quiet(500);
    const result = await runTaggerYielding(events, rules);
    expect(result).toEqual(runTagger(events, rules));
    expect(result.totalMatched).toBe(0);
  });

  it("addYielding keeps the preview sample add keeps", async () => {
    const events = fixtureTimeline(300);
    const a = createTaggerAccumulator(OVERLAP, 7);
    a.add(events);
    const b = createTaggerAccumulator(OVERLAP, 7);
    await b.addYielding(events);
    expect(b.sample()).toEqual(a.sample());
    expect(b.finish()).toEqual(a.finish());
  });
});

describe("runTaggerYielding lets the event loop run (#2716)", () => {
  it("a timer keeps firing while the bundled rules run over a large import", async () => {
    const rules = await bundledRules();
    const events = fixtureTimeline(12_000);
    const sync = await loopLag(async () => {
      runTagger(events, rules);
    });
    const yielding = await loopLag(() => runTaggerYielding(events, rules));
    expect(sync.ticks).toBeLessThanOrEqual(1);
    expect(yielding.ticks).toBeGreaterThanOrEqual(5);
    // A slice is ~25 ms; the gap allows for a slow CI box, and stays well under the one-block run.
    expect(yielding.maxGapMs).toBeLessThan(Math.max(250, sync.maxGapMs * 0.5));
  });
});
