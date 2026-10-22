import { readFile } from "node:fs/promises";
import { describe, expect, it } from "vitest";
import { computeSigmaCoverage, inventoryCounts } from "../../src/analysis/sigmaCoverage.js";
import {
  SIGMA_LOG_SOURCES,
  SIGMA_ORIGIN_CLOUDTRAIL,
  SIGMA_ORIGIN_ENTRA,
  SIGMA_ORIGIN_WEB,
} from "../../src/analysis/sigmaLogSources.js";
import { COMBINED_LOG_SOURCE } from "../../src/analysis/combinedLogImport.js";
import type { SigmaInventoryEntry } from "../../src/analysis/sigmaRuleSet.js";

// Per-case Sigma coverage (#2217): which ingested origins the import-time Sigma engine grades, and
// with how many rules. Derived on read from the super-timeline origin counts + the active rule set.

const rule = (source: string | undefined, outcome: SigmaInventoryEntry["outcome"], n = 1) =>
  Array.from({ length: n }, (_, i) => ({
    path: `rules/${source ?? "x"}/${outcome}-${i}.yml`,
    id: `${source ?? "x"}-${outcome}-${i}`,
    title: "t",
    outcome,
    ...(source ? { source } : {}),
  })) as SigmaInventoryEntry[];

const inventory: SigmaInventoryEntry[] = [
  ...rule("aws-cloudtrail", "loaded", 3),
  ...rule("aws-cloudtrail", "disabled", 1),
  ...rule("aws-cloudtrail", "status", 2),
  ...rule("azure-signinlogs", "loaded", 2),
  ...rule("azure-auditlogs", "refused", 1),
  ...rule("web-server", "disabled", 2),
  ...rule("web-proxy", "refused", 1),
  ...rule(undefined, "no-source", 5),
];

describe("inventoryCounts", () => {
  it("groups the inventory by source and outcome", () => {
    const c = inventoryCounts(inventory);
    expect(c["aws-cloudtrail"]).toEqual({ loaded: 3, disabled: 1, status: 2 });
    expect(c.other).toEqual({ "no-source": 5 });
  });
});

describe("computeSigmaCoverage", () => {
  it("marks a graded origin with loaded rules as covered, with its counts", () => {
    const cov = computeSigmaCoverage([{ origin: SIGMA_ORIGIN_CLOUDTRAIL, events: 40 }], inventory, true);
    expect(cov).toMatchObject({ enabled: true, graded: 1, total: 1 });
    expect(cov.rows[0]).toMatchObject({ origin: "AWS CloudTrail", events: 40, state: "covered" });
    expect(cov.rows[0].sigmaSources).toEqual([
      { id: "aws-cloudtrail", label: "AWS CloudTrail", loaded: 3, disabled: 1, refused: 0, status: 2 },
    ]);
  });

  it("marks an origin no Sigma source grades as not-graded", () => {
    const cov = computeSigmaCoverage([{ origin: "Windows.EventLogs.Evtx", events: 900 }], inventory, true);
    expect(cov.rows[0]).toMatchObject({ state: "not-graded", sigmaSources: [] });
    expect(cov.graded).toBe(0);
  });

  it("marks a graded origin whose every rule is disabled or refused as no-loaded-rules", () => {
    const cov = computeSigmaCoverage([{ origin: SIGMA_ORIGIN_WEB, events: 7 }], inventory, true);
    expect(cov.rows[0].state).toBe("no-loaded-rules");
    expect(cov.rows[0].sigmaSources.map((s) => s.id)).toEqual(["web-server", "web-proxy"]);
    expect(cov.graded).toBe(0);
  });

  it("marks every row sigma-off when Sigma grading is switched off", () => {
    const cov = computeSigmaCoverage(
      [
        { origin: SIGMA_ORIGIN_CLOUDTRAIL, events: 1 },
        { origin: "Microsoft 365", events: 2 },
      ],
      inventory,
      false,
    );
    expect(cov.enabled).toBe(false);
    expect(cov.rows.map((r) => r.state)).toEqual(["sigma-off", "sigma-off"]);
    expect(cov.graded).toBe(0);
  });

  it("covers Entra ID when one of its two sources has loaded rules, and says SP sign-ins are not graded", () => {
    const cov = computeSigmaCoverage([{ origin: SIGMA_ORIGIN_ENTRA, events: 5 }], inventory, true);
    expect(cov.rows[0].state).toBe("covered");
    expect(cov.rows[0].sigmaSources.map((s) => s.id)).toEqual(["azure-signinlogs", "azure-auditlogs"]);
    expect(cov.rows[0].caveat).toMatch(/service-principal/);
  });

  it("says the web pack is chosen per import", () => {
    const cov = computeSigmaCoverage([{ origin: SIGMA_ORIGIN_WEB, events: 1 }], inventory, true);
    expect(cov.rows[0].caveat).toMatch(/per import/);
  });

  it("keeps an Unknown origin and orders rows by event count, then name", () => {
    const cov = computeSigmaCoverage(
      [
        { origin: "Unknown", events: 3 },
        { origin: "b", events: 10 },
        { origin: "a", events: 10 },
      ],
      [],
      true,
    );
    expect(cov.rows.map((r) => r.origin)).toEqual(["a", "b", "Unknown"]);
    expect(cov.total).toBe(3);
  });

  it("does not mutate its inputs", () => {
    const counts = [
      { origin: "b", events: 1 },
      { origin: "a", events: 2 },
    ];
    const copy = JSON.parse(JSON.stringify(counts));
    computeSigmaCoverage(counts, inventory, true);
    expect(counts).toEqual(copy);
  });
});

describe("Sigma log source origins", () => {
  it("names at least one super-timeline origin for every source", () => {
    for (const def of SIGMA_LOG_SOURCES) expect(def.origins.length).toBeGreaterThan(0);
  });

  // The origin labels are the importers' own `sources` literals. A rename there must fail here,
  // or the coverage card would call a graded source "not graded".
  it("matches the labels the Sigma-graded importers stamp", async () => {
    expect(SIGMA_ORIGIN_WEB).toBe(COMBINED_LOG_SOURCE);
    const src = (f: string) => readFile(new URL(`../../src/analysis/${f}`, import.meta.url), "utf8");
    expect(await src("awsImport.ts")).toContain(`sources: [${JSON.stringify(SIGMA_ORIGIN_CLOUDTRAIL)}]`);
    expect(await src("m365Import.ts")).toContain(`sources: [${JSON.stringify(SIGMA_ORIGIN_ENTRA)}]`);
    expect(await src("entraAuditImport.ts")).toContain(`sources: [${JSON.stringify(SIGMA_ORIGIN_ENTRA)}]`);
  });
});
