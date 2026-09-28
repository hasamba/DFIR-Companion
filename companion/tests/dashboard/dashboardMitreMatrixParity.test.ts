import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import {
  aggregateCell,
  buildAttackMatrix,
  MATRIX_PLATFORMS,
  PLATFORM_GROUPS,
  type MatrixHit,
} from "../../src/analysis/attackMatrix.js";
import {
  coerceAttackMatrix,
  EMPTY_ATTACK_MATRIX,
  loadAttackMatrix,
} from "../../src/analysis/attackMatrixData.js";
import { techniqueNamesFor } from "../../src/analysis/attackTechniqueNames.js";
import { withEventTechniques } from "../../src/analysis/eventTechniques.js";
import { applyFalsePositive, type FalsePositiveMarker } from "../../src/analysis/falsePositive.js";
import { emptyState, type InvestigationState, type Severity } from "../../src/analysis/stateTypes.js";
import { buildMatrixHits } from "../../src/reports/attackMatrixHits.js";
import type { FiltersApi, MitreMatrixApi } from "./dashboardApi.js";
import { DASHBOARD_HELPER_FILES, loadDashboardModule } from "../helpers/dashboardModule.js";

// The ATT&CK matrix layout is written twice (#1764): analysis/attackMatrix.ts on the server and
// its mirror in public/js/dashboard-mitre-matrix.js, which re-derives the matrix in the browser on
// every render so a false-positive mark takes effect with no reload. The hit builder is written
// twice too (reports/attackMatrixHits.ts). This suite runs the server's REAL functions and the
// client's REAL functions over the same inputs — the real bundled catalogue — and demands equal
// output. A re-implementation in the test would pin the test author's reading of the rule.

// The module publishes DfirMitreMatrix from its initializer, so the suite calls it — with a page
// that has none of the panel's markup, which is also the "controls missing" path.
const stubDocument = { getElementById: () => null, addEventListener: () => {} };
function matrix(): MitreMatrixApi {
  const g = loadDashboardModule<{ initMitreMatrix(): void; DfirMitreMatrix?: MitreMatrixApi }>(
    "dashboard-mitre-matrix.js",
    ["dashboard-escape.js"],
    { document: stubDocument },
  );
  g.initMitreMatrix();
  if (!g.DfirMitreMatrix) throw new Error("initMitreMatrix() did not publish DfirMitreMatrix");
  return g.DfirMitreMatrix;
}
const client = matrix();

function filters(): FiltersApi {
  return loadDashboardModule<{ DfirFilters: FiltersApi }>(
    "dashboard-filters.js",
    DASHBOARD_HELPER_FILES.filter((f) => f !== "dashboard-filters.js"),
  ).DfirFilters;
}

const CATALOGUE = loadAttackMatrix();
// JSON text, not toEqual alone: it also pins key order and that no key is present-but-undefined.
const same = (a: unknown, b: unknown) => expect(JSON.stringify(a)).toBe(JSON.stringify(b));

const hit = (id: string, worst: Severity, extra: Partial<MatrixHit> = {}): MatrixHit => ({
  id,
  worst,
  findingIds: [],
  eventIds: [],
  ...extra,
});

// Three hit sets: the shapes the layout rules name, nothing at all, and a dense spread.
const SEVS: Severity[] = ["Critical", "High", "Medium", "Low", "Info"];
const FIXTURES: Array<[string, MatrixHit[]]> = [
  [
    "every layout rule at once",
    [
      hit("T1078", "High", { findingIds: ["f1"], eventIds: ["e1"] }), // four tactics
      hit("T1059.001", "Critical", { eventIds: ["e2", "e3"] }), // child hit, parent not
      hit("T1003", "Low", { findingIds: ["f2"] }), // parent and child both hit
      hit("T1003.001", "High", { findingIds: ["f2", "f3"] }),
      hit("T1583", "Info", { analystAccepted: true }), // PRE, analyst-accepted
      hit("T1543.003", "Medium", { eventIds: ["e4"] }), // Windows-only child
      hit("T1548.001", "Medium", { eventIds: ["e5"] }), // Linux/macOS child
      hit("T9999", "High", { findingIds: ["f4"] }), // unknown to the catalogue
      hit(" t1105 ", "Low", { eventIds: ["e6"] }), // untidy id
      hit("T1105", "Critical", { eventIds: ["e7"] }), // duplicate: merges
    ],
  ],
  ["no hits", []],
  [
    "every 17th technique, all severities",
    CATALOGUE.techniques
      .filter((_, i) => i % 17 === 0)
      .map((t, i) =>
        hit(t.id, SEVS[i % SEVS.length], { findingIds: [`f${i}`], eventIds: [`e${i}`, `e${i + 1}`] }),
      ),
  ],
];

describe("the real catalogue under test", () => {
  it("is the bundled one, not an empty fallback", () => {
    expect(CATALOGUE.techniques.length).toBeGreaterThan(600);
    expect(CATALOGUE.tactics.length).toBe(15);
  });

  it("coerces on the client exactly as the server loader does", () => {
    const raw = JSON.parse(readFileSync(new URL("../../data/attack-matrix.json", import.meta.url), "utf8"));
    const server = coerceAttackMatrix(raw);
    same(client.coerceCatalogue(raw), {
      attackVersion: server.attackVersion,
      tactics: server.tactics,
      techniques: server.techniques,
    });
  });

  it("uses the server's platform groups", () => {
    same(client.PLATFORM_GROUPS, PLATFORM_GROUPS);
    same(client.MATRIX_PLATFORMS, MATRIX_PLATFORMS);
  });
});

describe("the client layout deep-equals buildAttackMatrix", () => {
  const combos = FIXTURES.flatMap(([label, hits]) =>
    MATRIX_PLATFORMS.flatMap((platform) =>
      [false, true].map((hitsOnly) => [label, platform, hitsOnly, hits] as const),
    ),
  );

  it.each(combos)("%s — platform %s, hitsOnly %s", (_label, platform, hitsOnly, hits) => {
    const opts = { platform, hitsOnly };
    const server = buildAttackMatrix(CATALOGUE, hits, opts);
    const mirror = client.buildAttackMatrix(CATALOGUE, hits, opts);
    expect(mirror).toEqual(server);
    same(mirror, server);
  });

  it("agrees on every cell's aggregate (parent + children)", () => {
    const hits = FIXTURES[0][1];
    const server = buildAttackMatrix(CATALOGUE, hits, { platform: "all", hitsOnly: true });
    const mirror = client.buildAttackMatrix(CATALOGUE, hits, {
      platform: "all",
      hitsOnly: true,
    }) as typeof server;
    const cells = (m: typeof server) => m.columns.flatMap((c) => c.cells);
    same(
      cells(mirror).map((c) => client.aggregateCell(c)),
      cells(server).map((c) => aggregateCell(c)),
    );
    // Not vacuous: the parent-plus-child case is really there, merged.
    const t1003 = cells(server).find((c) => c.id === "T1003");
    expect(t1003 && aggregateCell(t1003)).toMatchObject({ worst: "High", findingIds: ["f2", "f3"] });
  });

  it("agrees with an empty catalogue: every hit goes to Unmapped", () => {
    const hits = FIXTURES[0][1];
    const opts = { platform: "windows" as const, hitsOnly: false };
    const server = buildAttackMatrix(EMPTY_ATTACK_MATRIX, hits, opts);
    same(client.buildAttackMatrix(EMPTY_ATTACK_MATRIX, hits, opts), server);
    expect(server.catalogueAvailable).toBe(false);
    expect(server.unmapped.map((h) => h.id)).toContain("T1078");
  });
});

// ── The hit builder: client buildMatrixHits(rows, notFp, ft) vs the server's over filtered state ──
function event(id: string, timestamp: string, severity: Severity, techniques: string[]) {
  return {
    id,
    timestamp,
    description: id,
    severity,
    mitreTechniques: techniques,
    relatedFindingIds: [],
    sourceScreenshots: [],
  };
}
function finding(id: string, title: string, severity: Severity, techniques: string[]) {
  return {
    id,
    severity,
    title,
    description: "",
    relatedIocs: [],
    mitreTechniques: techniques,
    sourceScreenshots: [],
    firstSeen: "",
    lastUpdated: "",
    status: "open" as const,
  };
}

// f-benign is the only support T1071 has, and a marker confirms it benign. T1583 is analyst-accepted
// with no support. T1059 is carried by events out of time order, one of them twice, one undated.
function caseState(): InvestigationState {
  return {
    ...emptyState("c1"),
    findings: [
      finding("f-open", "Encoded PowerShell", "Medium", ["T1059"]),
      finding("f-benign", "beaconing", "Critical", ["T1071"]),
    ],
    forensicTimeline: [
      event("e3", "2026-05-20T11:00:00Z", "Low", ["T1059"]),
      event("e1", "2026-05-20T09:00:00Z", "High", ["T1059", "t1059"]),
      event("e2", "2026-05-20T09:00:00Z", "Info", ["T1059"]),
      event("e0", "not a date", "Low", ["T1059"]),
      event("e4", "2026-05-20T10:00:00Z", "Medium", ["T1490"]),
    ],
    mitreTechniques: [
      { id: "T1059", name: "Command and Scripting Interpreter", findingIds: ["f-open"] },
      { id: "T1071", name: "Application Layer Protocol", findingIds: ["f-benign"] },
      { id: "T1583", name: "Acquire Infrastructure", findingIds: [], analystAccepted: true },
    ],
  };
}
const MARKERS: FalsePositiveMarker[] = [
  {
    id: "finding:beaconing",
    kind: "finding",
    ref: "beaconing",
    reason: "authorized-test",
    markedAt: "2026-05-21T00:00:00Z",
    markedBy: "analyst",
    note: "",
  },
];

function clientHits(state: InvestigationState, fpTitles: string[]) {
  const f = filters();
  const notFp = state.findings.filter((x) => !f.isFindingFalsePositive(x.title, fpTitles));
  const names = techniqueNamesFor(state.mitreTechniques, state.forensicTimeline);
  const rows = f.deriveMitreRows(notFp, state.forensicTimeline, state.mitreTechniques, names);
  return client.buildMatrixHits(rows, notFp, state.forensicTimeline) as Array<MatrixHit & { name: string }>;
}

describe("the client hit builder follows the MatrixHit contract", () => {
  it("equals the server's hits over the same filtered state", () => {
    const server = buildMatrixHits(withEventTechniques(applyFalsePositive(caseState(), MARKERS)));
    same(clientHits(caseState(), ["beaconing"]), server);
  });

  it("drops a technique whose only support was a confirmed false positive", () => {
    const hits = clientHits(caseState(), ["beaconing"]);
    expect(hits.map((h) => h.id)).not.toContain("T1071");
    expect(clientHits(caseState(), []).map((h) => h.id)).toContain("T1071"); // and keeps it unmarked
  });

  it("colors an analyst-accepted technique with no support Info, and says so", () => {
    const t1583 = clientHits(caseState(), ["beaconing"]).find((h) => h.id === "T1583");
    expect(t1583).toMatchObject({ worst: "Info", analystAccepted: true, findingIds: [], eventIds: [] });
  });

  it("takes the worst severity over findings and events, as the layer export does", () => {
    const t1059 = clientHits(caseState(), ["beaconing"]).find((h) => h.id === "T1059");
    expect(t1059?.worst).toBe("High"); // e1 High beats f-open Medium
  });

  it("orders events oldest first, then by id, de-duplicated, undated last", () => {
    const t1059 = clientHits(caseState(), ["beaconing"]).find((h) => h.id === "T1059");
    expect(t1059?.eventIds).toEqual(["e1", "e2", "e3", "e0"]);
  });

  it("appends an event-only technique with the server's name", () => {
    const t1490 = clientHits(caseState(), ["beaconing"]).find((h) => h.id === "T1490");
    expect(t1490).toMatchObject({ name: "Inhibit System Recovery", worst: "Medium", eventIds: ["e4"] });
  });
});
