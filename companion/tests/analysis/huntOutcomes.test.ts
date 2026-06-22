import { describe, it, expect } from "vitest";
import {
  normalizeVql,
  vqlFingerprint,
  recordDeploy,
  fillOutcome,
  deployedFingerprints,
  renderPriorHuntsBlock,
  buildHuntingProfile,
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
    const out = fillOutcome(deployed, "H.1", { addedEvents: 12, addedIocs: 3, collectedAt: T1 });
    expect(out[0]).toMatchObject({
      status: "collected",
      foundEvidence: true,
      addedEvents: 12,
      addedIocs: 3,
      resultSummary: "+12 events, +3 IOCs",
      collectedAt: T1,
    });
  });

  it("records a miss as 'no new evidence'", () => {
    const out = fillOutcome(deployed, "H.1", { addedEvents: 0, addedIocs: 0, collectedAt: T1 });
    expect(out[0].foundEvidence).toBe(false);
    expect(out[0].resultSummary).toBe("no new evidence");
  });

  it("singularizes counts of one", () => {
    const out = fillOutcome(deployed, "H.1", { addedEvents: 1, addedIocs: 1, collectedAt: T1 });
    expect(out[0].resultSummary).toBe("+1 event, +1 IOC");
  });

  it("is a no-op for a blank or unmatched huntId", () => {
    expect(fillOutcome(deployed, "", { addedEvents: 5, addedIocs: 0, collectedAt: T1 })[0].status).toBe("deployed");
    expect(fillOutcome(deployed, "H.nope", { addedEvents: 5, addedIocs: 0, collectedAt: T1 })[0].status).toBe("deployed");
  });

  it("clamps negative/garbage counts to zero", () => {
    const out = fillOutcome(deployed, "H.1", { addedEvents: -3, addedIocs: 0, collectedAt: T1 });
    expect(out[0].addedEvents).toBe(0);
    expect(out[0].foundEvidence).toBe(false);
  });

  it("accumulates counts across re-collects (stragglers add up)", () => {
    let out = fillOutcome(deployed, "H.1", { addedEvents: 5, addedIocs: 0, collectedAt: T1 });
    out = fillOutcome(out, "H.1", { addedEvents: 3, addedIocs: 1, collectedAt: T2 });
    expect(out[0]).toMatchObject({ addedEvents: 8, addedIocs: 1, foundEvidence: true, collectedAt: T2 });
    expect(out[0].resultSummary).toBe("+8 events, +1 IOC");
  });

  it("never downgrades a hit when a re-collect adds nothing (dedup → 0 delta)", () => {
    let out = fillOutcome(deployed, "H.1", { addedEvents: 5, addedIocs: 0, collectedAt: T1 }); // hit
    out = fillOutcome(out, "H.1", { addedEvents: 0, addedIocs: 0, collectedAt: T2 });           // re-pull, nothing new
    expect(out[0].foundEvidence).toBe(true);
    expect(out[0].addedEvents).toBe(5);
    expect(out[0].resultSummary).toBe("+5 events");
  });

  it("recovers a prior false 'no evidence' once results finally collect", () => {
    let out = fillOutcome(deployed, "H.1", { addedEvents: 0, addedIocs: 0, collectedAt: T1 }); // collected too early
    expect(out[0].foundEvidence).toBe(false);
    out = fillOutcome(out, "H.1", { addedEvents: 4, addedIocs: 0, collectedAt: T2 });           // re-collect after rows arrive
    expect(out[0]).toMatchObject({ foundEvidence: true, addedEvents: 4 });
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
    out = fillOutcome(out, "H.1", { addedEvents: 12, addedIocs: 3, collectedAt: T2 });
    out = fillOutcome(out, "H.2", { addedEvents: 0, addedIocs: 0, collectedAt: T2 });
    const block = renderPriorHuntsBlock(out);
    expect(block).toContain("PRIOR HUNTS");
    expect(block).toContain('"webshell" — +12 events, +3 IOCs  (T1505.003)');
    expect(block).toContain('"lolbin" — no new evidence');
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
    expect(buildHuntingProfile([])).toEqual({ total: 0, hit: 0, missed: 0, pending: 0, hunts: [] });
  });
});
