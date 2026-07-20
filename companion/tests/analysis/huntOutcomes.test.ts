import { describe, it, expect } from "vitest";
import {
  normalizeVql,
  vqlFingerprint,
  recordDeploy,
  fillOutcome,
  deployedFingerprints,
  renderPriorHuntsBlock,
  buildHuntingProfile,
  classifyPivotType,
  buildPivotProductivity,
  renderHuntProductivityBlock,
  HUNT_OUTCOME_MAX_DEFAULT,
  type HuntOutcome,
} from "../../src/analysis/huntOutcomes.js";

const T0 = "2026-06-21T10:00:00.000Z";
const T1 = "2026-06-21T11:00:00.000Z";
const T2 = "2026-06-21T12:00:00.000Z";

describe("normalizeVql / vqlFingerprint", () => {
  it("collapses whitespace so formatting differences fingerprint identically", () => {
    expect(normalizeVql("  SELECT  *\n  FROM   pslist() ")).toBe("SELECT * FROM pslist()");
    expect(vqlFingerprint("SELECT * FROM pslist()")).toBe(vqlFingerprint("SELECT  *\nFROM pslist()"));
  });

  it("distinguishes genuinely different queries", () => {
    expect(vqlFingerprint("SELECT * FROM pslist()")).not.toBe(vqlFingerprint("SELECT * FROM netstat()"));
  });

  it("is case-sensitive (VQL artifact names are)", () => {
    expect(vqlFingerprint("Artifact.Foo()")).not.toBe(vqlFingerprint("artifact.foo()"));
  });

  it("returns '' for empty/whitespace input", () => {
    expect(vqlFingerprint("")).toBe("");
    expect(vqlFingerprint("   \n ")).toBe("");
  });

  it("is stable across calls", () => {
    expect(vqlFingerprint("SELECT 1")).toBe(vqlFingerprint("SELECT 1"));
  });
});

describe("recordDeploy", () => {
  it("records a suggested fleet hunt with fingerprint + preview, status deployed", () => {
    const out = recordDeploy([], {
      source: "fleet",
      title: "Hunt for ASPX webshells",
      vql: "SELECT * FROM glob(globs='C:/inetpub/**/*.aspx')",
      mitreTechniques: ["T1505.003"],
      huntId: "H.123",
      deployedAt: T0,
    });
    expect(out).toHaveLength(1);
    expect(out[0]).toMatchObject({
      id: "H.123",
      huntId: "H.123",
      source: "fleet",
      title: "Hunt for ASPX webshells",
      status: "deployed",
      mitreTechniques: ["T1505.003"],
      deployedAt: T0,
    });
    expect(out[0].vqlFingerprint).toBe(vqlFingerprint("SELECT * FROM glob(globs='C:/inetpub/**/*.aspx')"));
    expect(out[0].vqlPreview).toContain("glob");
  });

  it("carries relatedHypothesisId when the hunt was deployed to test a hypothesis (#14 deferred)", () => {
    const linked = recordDeploy([], { source: "fleet", title: "test h2", vql: "SELECT 1", huntId: "H.h", deployedAt: T0, relatedHypothesisId: "hyp-2" });
    expect(linked[0].relatedHypothesisId).toBe("hyp-2");
    const unlinked = recordDeploy([], { source: "fleet", title: "generic", vql: "SELECT 1", huntId: "H.g", deployedAt: T0 });
    expect(unlinked[0].relatedHypothesisId).toBeUndefined();
  });

  it("records a bundle with no VQL fingerprint, id from huntId", () => {
    const out = recordDeploy([], { source: "bundle", title: "Fast Triage", huntId: "H.999", deployedAt: T0 });
    expect(out[0].vqlFingerprint).toBe("");
    expect(out[0].vqlPreview).toBe("");
    expect(out[0].id).toBe("H.999");
  });

  it("falls back to fingerprint:deployedAt id when no huntId (collection-mode)", () => {
    const out = recordDeploy([], { source: "playbook", title: "Collect on host", vql: "SELECT * FROM info()", deployedAt: T0 });
    expect(out[0].huntId).toBeUndefined();
    expect(out[0].id).toBe(`${vqlFingerprint("SELECT * FROM info()")}:${T0}`);
  });

  it("prepends newest-first", () => {
    let out = recordDeploy([], { source: "fleet", title: "first", vql: "SELECT 1", huntId: "H.1", deployedAt: T0 });
    out = recordDeploy(out, { source: "fleet", title: "second", vql: "SELECT 2", huntId: "H.2", deployedAt: T1 });
    expect(out.map((o) => o.title)).toEqual(["second", "first"]);
  });

  it("upserts by id (re-deploying the same huntId replaces, never duplicates)", () => {
    let out = recordDeploy([], { source: "fleet", title: "v1", vql: "SELECT 1", huntId: "H.1", deployedAt: T0 });
    out = recordDeploy(out, { source: "fleet", title: "v2", vql: "SELECT 2", huntId: "H.1", deployedAt: T1 });
    expect(out).toHaveLength(1);
    expect(out[0].title).toBe("v2");
  });

  it("caps history to max (newest kept)", () => {
    let out: HuntOutcome[] = [];
    for (let i = 0; i < 5; i++) {
      out = recordDeploy(out, { source: "fleet", title: `h${i}`, vql: `SELECT ${i}`, huntId: `H.${i}`, deployedAt: T0 }, 3);
    }
    expect(out).toHaveLength(3);
    expect(out.map((o) => o.title)).toEqual(["h4", "h3", "h2"]);
  });

  it("does not mutate the input array", () => {
    const input: HuntOutcome[] = [];
    const out = recordDeploy(input, { source: "fleet", title: "x", vql: "SELECT 1", huntId: "H.1", deployedAt: T0 });
    expect(input).toHaveLength(0);
    expect(out).toHaveLength(1);
  });

  it("defaults to HUNT_OUTCOME_MAX_DEFAULT when max is invalid", () => {
    const out = recordDeploy([], { source: "fleet", title: "x", vql: "SELECT 1", huntId: "H.1", deployedAt: T0 }, 0);
    // sanity: a single entry survives; cap fell back to the default (no throw / no drop)
    expect(out).toHaveLength(1);
    expect(HUNT_OUTCOME_MAX_DEFAULT).toBeGreaterThan(0);
  });
});

describe("fillOutcome", () => {
  const deployed = recordDeploy([], { source: "fleet", title: "webshell hunt", vql: "SELECT 1", huntId: "H.1", deployedAt: T0 });

  it("marks collected + computes foundEvidence/summary from the delta", () => {
    const out = fillOutcome(deployed, "H.1", { resultRows: 10, addedEvents: 12, addedIocs: 3, collectedAt: T1 });
    expect(out[0]).toMatchObject({
      status: "collected",
      foundEvidence: true,
      resultRows: 10,
      addedEvents: 12,
      addedIocs: 3,
      resultSummary: "10 results, +12 new events, +3 new IOCs",
      collectedAt: T1,
    });
  });

  it("leads the summary with the rows the hunt RETURNED, then the new-to-case delta", () => {
    // The reported case: 10 rows returned but only 1 new after dedup — must not read as a bare "+1 event".
    const out = fillOutcome(deployed, "H.1", { resultRows: 10, addedEvents: 1, addedIocs: 0, collectedAt: T1 });
    expect(out[0].resultSummary).toBe("10 results, +1 new event");
    expect(out[0].foundEvidence).toBe(true);
  });

  it("a hunt that returns rows is a HIT even when nothing is new to the case (all already known)", () => {
    const out = fillOutcome(deployed, "H.1", { resultRows: 8, addedEvents: 0, addedIocs: 0, collectedAt: T1 });
    expect(out[0].foundEvidence).toBe(true);
    expect(out[0].resultSummary).toBe("8 results");
  });

  it("records a miss as 'no results' when the hunt returned nothing", () => {
    const out = fillOutcome(deployed, "H.1", { resultRows: 0, addedEvents: 0, addedIocs: 0, collectedAt: T1 });
    expect(out[0].foundEvidence).toBe(false);
    expect(out[0].resultSummary).toBe("no results");
  });

  it("singularizes counts of one", () => {
    const out = fillOutcome(deployed, "H.1", { resultRows: 1, addedEvents: 1, addedIocs: 1, collectedAt: T1 });
    expect(out[0].resultSummary).toBe("1 result, +1 new event, +1 new IOC");
  });

  it("is a no-op for a blank or unmatched huntId", () => {
    expect(fillOutcome(deployed, "", { addedEvents: 5, addedIocs: 0, collectedAt: T1 })[0].status).toBe("deployed");
    expect(fillOutcome(deployed, "H.nope", { addedEvents: 5, addedIocs: 0, collectedAt: T1 })[0].status).toBe("deployed");
  });

  it("clamps negative/garbage counts to zero", () => {
    const out = fillOutcome(deployed, "H.1", { resultRows: 0, addedEvents: -3, addedIocs: 0, collectedAt: T1 });
    expect(out[0].addedEvents).toBe(0);
    expect(out[0].foundEvidence).toBe(false);
  });

  it("accumulates new-event deltas but keeps resultRows as the max snapshot across re-collects", () => {
    let out = fillOutcome(deployed, "H.1", { resultRows: 10, addedEvents: 5, addedIocs: 0, collectedAt: T1 });
    out = fillOutcome(out, "H.1", { resultRows: 12, addedEvents: 3, addedIocs: 1, collectedAt: T2 });   // 2 stragglers arrived
    expect(out[0]).toMatchObject({ resultRows: 12, addedEvents: 8, addedIocs: 1, foundEvidence: true, collectedAt: T2 });
    expect(out[0].resultSummary).toBe("12 results, +8 new events, +1 new IOC");
  });

  it("never downgrades a hit when a re-collect adds nothing (dedup → 0 delta)", () => {
    let out = fillOutcome(deployed, "H.1", { resultRows: 10, addedEvents: 5, addedIocs: 0, collectedAt: T1 }); // hit
    out = fillOutcome(out, "H.1", { resultRows: 10, addedEvents: 0, addedIocs: 0, collectedAt: T2 });          // re-pull, nothing new
    expect(out[0].foundEvidence).toBe(true);
    expect(out[0].addedEvents).toBe(5);
    expect(out[0].resultRows).toBe(10);
    expect(out[0].resultSummary).toBe("10 results, +5 new events");
  });

  it("recovers a prior false miss once results finally collect", () => {
    let out = fillOutcome(deployed, "H.1", { resultRows: 0, addedEvents: 0, addedIocs: 0, collectedAt: T1 }); // collected too early
    expect(out[0].foundEvidence).toBe(false);
    out = fillOutcome(out, "H.1", { resultRows: 4, addedEvents: 4, addedIocs: 0, collectedAt: T2 });          // re-collect after rows arrive
    expect(out[0]).toMatchObject({ foundEvidence: true, resultRows: 4, addedEvents: 4 });
  });
});

describe("deployedFingerprints", () => {
  it("collects non-empty fingerprints and skips bundles", () => {
    let out = recordDeploy([], { source: "fleet", title: "a", vql: "SELECT 1", huntId: "H.1", deployedAt: T0 });
    out = recordDeploy(out, { source: "bundle", title: "triage", huntId: "H.2", deployedAt: T1 });
    const fps = deployedFingerprints(out);
    expect(fps.has(vqlFingerprint("SELECT 1"))).toBe(true);
    expect(fps.size).toBe(1); // the bundle contributed no fingerprint
  });

  it("excludes a hunt regardless of outcome (ran-and-found-nothing is still excluded)", () => {
    let out = recordDeploy([], { source: "fleet", title: "a", vql: "SELECT 1", huntId: "H.1", deployedAt: T0 });
    out = fillOutcome(out, "H.1", { addedEvents: 0, addedIocs: 0, collectedAt: T1 });
    expect(deployedFingerprints(out).has(vqlFingerprint("SELECT 1"))).toBe(true);
  });
});

describe("renderPriorHuntsBlock", () => {
  it("is empty when there are no outcomes", () => {
    expect(renderPriorHuntsBlock([])).toBe("");
  });

  it("renders collected hits, misses, and pending deploys, ending in a blank line", () => {
    let out = recordDeploy([], { source: "fleet", title: "webshell", vql: "SELECT 1", huntId: "H.1", deployedAt: T0, mitreTechniques: ["T1505.003"] });
    out = recordDeploy(out, { source: "fleet", title: "lolbin", vql: "SELECT 2", huntId: "H.2", deployedAt: T1 });
    out = recordDeploy(out, { source: "fleet", title: "persistence", vql: "SELECT 3", huntId: "H.3", deployedAt: T2 });
    out = fillOutcome(out, "H.1", { resultRows: 10, addedEvents: 12, addedIocs: 3, collectedAt: T2 });
    out = fillOutcome(out, "H.2", { resultRows: 0, addedEvents: 0, addedIocs: 0, collectedAt: T2 });
    const block = renderPriorHuntsBlock(out);
    expect(block).toContain("PRIOR HUNTS");
    expect(block).toContain('"webshell" — 10 results, +12 new events, +3 new IOCs  (T1505.003)');
    expect(block).toContain('"lolbin" — no results');
    expect(block).toContain('"persistence" — results not yet collected');
    expect(block.endsWith("\n\n")).toBe(true);
  });

  it("respects the limit", () => {
    let out: HuntOutcome[] = [];
    for (let i = 0; i < 5; i++) out = recordDeploy(out, { source: "fleet", title: `h${i}`, vql: `SELECT ${i}`, huntId: `H.${i}`, deployedAt: T0 });
    const block = renderPriorHuntsBlock(out, 2);
    expect(block).toContain("h4");
    expect(block).toContain("h3");
    expect(block).not.toContain("h2");
  });
});

describe("buildHuntingProfile", () => {
  it("tallies hit / missed / pending", () => {
    let out = recordDeploy([], { source: "fleet", title: "a", vql: "SELECT 1", huntId: "H.1", deployedAt: T0 });
    out = recordDeploy(out, { source: "fleet", title: "b", vql: "SELECT 2", huntId: "H.2", deployedAt: T1 });
    out = recordDeploy(out, { source: "fleet", title: "c", vql: "SELECT 3", huntId: "H.3", deployedAt: T2 });
    out = fillOutcome(out, "H.1", { addedEvents: 5, addedIocs: 0, collectedAt: T2 }); // hit
    out = fillOutcome(out, "H.2", { addedEvents: 0, addedIocs: 0, collectedAt: T2 }); // miss
    const profile = buildHuntingProfile(out);
    expect(profile).toMatchObject({ total: 3, hit: 1, missed: 1, pending: 1 });
    expect(profile.hunts).toHaveLength(3);
  });

  it("handles an empty case", () => {
    expect(buildHuntingProfile([])).toEqual({ total: 0, hit: 0, missed: 0, pending: 0, hunts: [], pivotProductivity: [] });
  });
});

describe("classifyPivotType", () => {
  const outcome = (vql: string, title = ""): HuntOutcome =>
    recordDeploy([], { source: "fleet", title: title || vql, vql, huntId: "H.x", deployedAt: T0 })[0];

  it("classifies hash pivots", () => {
    expect(classifyPivotType(outcome("SELECT * FROM hash(path=Path) WHERE MD5 = '...'"))).toBe("hash");
  });

  it("classifies process pivots", () => {
    expect(classifyPivotType(outcome("SELECT * FROM pslist() WHERE CommandLine =~ 'evil'"))).toBe("process");
  });

  it("classifies path/filesystem pivots", () => {
    expect(classifyPivotType(outcome("SELECT FullPath FROM glob(globs='C:/inetpub/**/*.aspx')"))).toBe("path");
  });

  it("classifies network pivots", () => {
    expect(classifyPivotType(outcome("SELECT * FROM netstat() WHERE Raddr = '1.2.3.4'"))).toBe("network");
  });

  it("classifies registry pivots", () => {
    expect(classifyPivotType(outcome("SELECT * FROM glob(globs='HKLM\\\\Software\\\\Run\\\\*')", "registry run keys"))).toBe("registry");
  });

  it("falls back to other when nothing matches", () => {
    expect(classifyPivotType(outcome("SELECT * FROM info()"))).toBe("other");
  });

  it("falls back to the title for a bundle with no VQL", () => {
    const bundle = recordDeploy([], { source: "bundle", title: "Fast Triage pslist sweep", huntId: "H.b", deployedAt: T0 })[0];
    expect(classifyPivotType(bundle)).toBe("process");
  });
});

describe("buildPivotProductivity", () => {
  it("returns [] for no outcomes", () => {
    expect(buildPivotProductivity([])).toEqual([]);
  });

  it("tallies hit/missed/pending per pivot class and ranks by hit-rate", () => {
    let out = recordDeploy([], { source: "fleet", title: "hash a", vql: "SELECT * FROM hash(path=Path)", huntId: "H.1", deployedAt: T0 });
    out = recordDeploy(out, { source: "fleet", title: "hash b", vql: "SELECT * FROM hash(path=Path)", huntId: "H.2", deployedAt: T0 });
    out = recordDeploy(out, { source: "fleet", title: "ps a", vql: "SELECT * FROM pslist()", huntId: "H.3", deployedAt: T0 });
    out = recordDeploy(out, { source: "fleet", title: "ps b", vql: "SELECT * FROM pslist()", huntId: "H.4", deployedAt: T0 });
    out = fillOutcome(out, "H.1", { addedEvents: 3, addedIocs: 0, collectedAt: T1 });   // hash: hit
    out = fillOutcome(out, "H.2", { addedEvents: 2, addedIocs: 0, collectedAt: T1 });   // hash: hit
    out = fillOutcome(out, "H.3", { addedEvents: 0, addedIocs: 0, collectedAt: T1 });   // process: miss
    // H.4 (process) stays pending

    const stats = buildPivotProductivity(out);
    expect(stats[0]).toMatchObject({ type: "hash", total: 2, hit: 2, missed: 0, pending: 0 });
    expect(stats[1]).toMatchObject({ type: "process", total: 2, hit: 0, missed: 1, pending: 1 });
  });

  it("only includes pivot classes that have at least one outcome", () => {
    const out = recordDeploy([], { source: "fleet", title: "hash a", vql: "SELECT * FROM hash(path=Path)", huntId: "H.1", deployedAt: T0 });
    const stats = buildPivotProductivity(out);
    expect(stats).toHaveLength(1);
    expect(stats[0].type).toBe("hash");
  });
});

describe("renderHuntProductivityBlock", () => {
  it("is empty when there is no collected history", () => {
    expect(renderHuntProductivityBlock([])).toBe("");
    const pendingOnly = recordDeploy([], { source: "fleet", title: "a", vql: "SELECT * FROM pslist()", huntId: "H.1", deployedAt: T0 });
    expect(renderHuntProductivityBlock(pendingOnly)).toBe("");
  });

  it("renders hit-rate per pivot class, most productive first, ending in a blank line", () => {
    let out = recordDeploy([], { source: "fleet", title: "hash a", vql: "SELECT * FROM hash(path=Path)", huntId: "H.1", deployedAt: T0 });
    out = recordDeploy(out, { source: "fleet", title: "ps a", vql: "SELECT * FROM pslist()", huntId: "H.2", deployedAt: T0 });
    out = fillOutcome(out, "H.1", { addedEvents: 3, addedIocs: 0, collectedAt: T1 });   // hash: hit
    out = fillOutcome(out, "H.2", { addedEvents: 0, addedIocs: 0, collectedAt: T1 });   // process: miss

    const block = renderHuntProductivityBlock(out);
    expect(block).toContain("HUNT PRODUCTIVITY BY PIVOT CLASS");
    expect(block).toContain("hash: 1/1 hunts found evidence (100%)");
    expect(block).toContain("process: 0/1 hunts found evidence (0%)");
    expect(block.indexOf("hash:")).toBeLessThan(block.indexOf("process:"));   // more productive class listed first
    expect(block.endsWith("\n\n")).toBe(true);
  });
});
