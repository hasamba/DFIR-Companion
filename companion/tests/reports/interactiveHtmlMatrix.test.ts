import { describe, it, expect, afterEach } from "vitest";
import { runInNewContext } from "node:vm";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { renderInteractiveHtmlReport } from "../../src/reports/interactiveHtml.js";
import { buildMatrixEmbed, modelKey, type MatrixEmbed } from "../../src/reports/interactiveHtmlMatrix.js";
import { MATRIX_SCRIPT } from "../../src/reports/interactiveHtmlMatrixScript.js";
import { buildMatrixHits } from "../../src/reports/attackMatrixHits.js";
import { buildAttackLayer } from "../../src/reports/attackLayer.js";
import {
  aggregateCell,
  buildAttackMatrix,
  MATRIX_PLATFORMS,
  type MatrixCell,
} from "../../src/analysis/attackMatrix.js";
import {
  loadAttackMatrix,
  resetAttackMatrixCacheForTests,
  EMPTY_ATTACK_MATRIX,
} from "../../src/analysis/attackMatrixData.js";
import { withEventTechniques } from "../../src/analysis/eventTechniques.js";
import {
  emptyState,
  type Finding,
  type ForensicEvent,
  type InvestigationState,
} from "../../src/analysis/stateTypes.js";
import { CaseStore } from "../../src/storage/caseStore.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { ReportWriter } from "../../src/reports/reportWriter.js";
import { FalsePositiveStore } from "../../src/analysis/falsePositive.js";
import { createApp } from "../../src/server.js";

// The interactive report's ATT&CK Matrix section (#1764).
//
// The report embeds ten server-built models in a compact form and the inline renderer expands
// them. The first block runs that renderer's own expandModel() in a VM and pins it to deep-equal
// buildAttackMatrix() for every platform × Hits-only choice, so the report can never lay out a
// matrix the dashboard would not.

const HOSTILE = "<img src=x onerror=alert(1)>";

function finding(over: Partial<Finding>): Finding {
  return {
    id: "f1",
    severity: "High",
    title: "A finding",
    description: "d",
    relatedIocs: [],
    sourceScreenshots: [],
    mitreTechniques: [],
    firstSeen: "t0",
    lastUpdated: "t1",
    status: "open",
    ...over,
  };
}

function event(over: Partial<ForensicEvent>): ForensicEvent {
  return {
    id: "e1",
    timestamp: "2026-05-20T09:00:00Z",
    description: "ev",
    severity: "Medium",
    mitreTechniques: [],
    relatedFindingIds: [],
    sourceScreenshots: [],
    ...over,
  };
}

function caseState(): InvestigationState {
  const state = emptyState("c1");
  state.findings.push(
    finding({ id: "f1", title: "Encoded PowerShell", severity: "Critical", mitreTechniques: ["T1059.001"] }),
    finding({ id: "f2", title: "Valid account logon", severity: "Low", mitreTechniques: ["T1078"] }),
  );
  state.mitreTechniques.push(
    { id: "T1059.001", name: "PowerShell", findingIds: ["f1"] },
    { id: "T1078", name: "Valid Accounts", findingIds: ["f2"] },
    { id: "T9999", name: "Unknown technique", findingIds: [], analystAccepted: true },
  );
  state.forensicTimeline.push(
    event({ id: "e1", severity: "High", mitreTechniques: ["T1059.001", "T1105"] }),
    event({ id: "e2", severity: "Low", mitreTechniques: ["T1548.002"] }),
  );
  return withEventTechniques(state);
}

// Run the renderer in a VM with no DOM: it publishes its pure helpers and returns before drawing.
function rendererFor(embed: MatrixEmbed): {
  expandModel: (key: string) => unknown;
  aggregate: (cell: MatrixCell) => unknown;
} {
  const window: Record<string, unknown> = { __DFIR_MATRIX__: JSON.parse(JSON.stringify(embed)) };
  runInNewContext(MATRIX_SCRIPT, { window, document: { getElementById: () => null } });
  return window.DfirReportMatrix as never;
}

const plain = <T>(v: T): T => JSON.parse(JSON.stringify(v));

function matrixBlob(html: string): MatrixEmbed {
  const m = html.match(/window\.__DFIR_MATRIX__ = (\{.*?\});\nwindow\.__DFIR_CASE__/s);
  if (!m) throw new Error("no embedded matrix blob found");
  return JSON.parse(m[1]);
}

function layerIds(state: InvestigationState): string[] {
  return buildAttackLayer(state)
    .techniques.filter((t) => t.score !== undefined)
    .map((t) => t.techniqueID)
    .sort();
}

afterEach(() => resetAttackMatrixCacheForTests());

describe("the embedded models — one source of layout truth", () => {
  it("expandModel() deep-equals buildAttackMatrix() for all ten platform × Hits-only models", () => {
    const state = caseState();
    const catalogue = loadAttackMatrix();
    const renderer = rendererFor(buildMatrixEmbed(state, catalogue));
    const hits = buildMatrixHits(state);
    for (const platform of MATRIX_PLATFORMS) {
      for (const hitsOnly of [false, true]) {
        const expected = buildAttackMatrix(catalogue, hits, { platform, hitsOnly });
        expect(plain(renderer.expandModel(modelKey(platform, hitsOnly)))).toEqual(plain(expected));
      }
    }
  });

  it("the renderer's parent aggregation matches aggregateCell()", () => {
    const state = caseState();
    const catalogue = loadAttackMatrix();
    const renderer = rendererFor(buildMatrixEmbed(state, catalogue));
    const model = buildAttackMatrix(catalogue, buildMatrixHits(state), {
      platform: "windows",
      hitsOnly: true,
    });
    const cells = model.columns.flatMap((c) => c.cells);
    expect(cells.length).toBeGreaterThan(0);
    for (const cell of cells) {
      const got = plain(renderer.aggregate(cell)) as Record<string, unknown> | null;
      const want = aggregateCell(cell);
      expect(got && { ...got, analystAccepted: got.analystAccepted || undefined }).toEqual(
        want ? plain({ ...want, analystAccepted: want.analystAccepted || undefined }) : null,
      );
    }
  });

  it("with no catalogue, every hit lands in Unmapped and the blob says so", () => {
    const embed = buildMatrixEmbed(caseState(), EMPTY_ATTACK_MATRIX);
    expect(embed.catalogueAvailable).toBe(false);
    expect(embed.models[modelKey("windows", false)].columns).toEqual([]);
    expect(embed.models[modelKey("windows", false)].unmapped.sort()).toEqual(
      ["T1059.001", "T1078", "T1105", "T1548.002", "T9999"].sort(),
    );
  });
});

describe("renderInteractiveHtmlReport — ATT&CK Matrix section", () => {
  it("places the section after the findings and before the timeline, with the version stamp source", () => {
    const html = renderInteractiveHtmlReport(caseState());
    const findings = html.indexOf("<h2>Findings</h2>");
    const matrix = html.indexOf('<h2 id="attack-matrix">ATT&amp;CK Matrix</h2>');
    const timeline = html.indexOf("<h2>Forensic Timeline</h2>");
    expect(findings).toBeGreaterThan(-1);
    expect(matrix).toBeGreaterThan(findings);
    expect(timeline).toBeGreaterThan(matrix);
    expect(html).toContain('id="atm-platform"');
    expect(html).toContain('id="atm-hits"');
    expect(html).toContain("ATT&CK Enterprise v");
    // The renderer explains its numbers: a key line, and hover text on counts and badges.
    expect(html).toContain(
      "Cell number = findings + events · letter = worst severity · column number = techniques seen",
    );
    expect(html).toContain('title: "Techniques seen in this tactic"');
    expect(html).toContain("title: badgeTitle(cell, agg)");
    expect(html).toContain('<button type="button" id="atm-expand">Expand all</button>');
    expect(html).toContain('<button type="button" id="atm-collapse">Collapse all</button>');
    expect(matrixBlob(html).attackVersion).toBe(loadAttackMatrix().attackVersion);
  });

  it("highlights exactly the attack-layer export's ids", () => {
    const state = caseState();
    const blob = matrixBlob(renderInteractiveHtmlReport(state));
    // T9999 is an analyst-accepted row with no finding or event: the List shows it, the layer
    // (which reads findings and events only) cannot. Every other id must match the layer exactly.
    expect(
      Object.keys(blob.hits)
        .filter((id) => id !== "T9999")
        .sort(),
    ).toEqual(layerIds(state));
    expect(blob.hits.T9999).toMatchObject({ worst: "Info", analystAccepted: true });
    expect(blob.models[modelKey("windows", false)].unmapped).toEqual(["T9999"]);
  });

  it("gives finding cards and timeline rows the anchors the popover links to", () => {
    const html = renderInteractiveHtmlReport(caseState());
    expect(html).toContain('id: "finding-" + f.id');
    expect(html).toContain('id: "event-" + ev.id');
    expect(html).toContain('"#" + prefix + encodeURIComponent(id)');
  });

  it("never emits a hostile technique name or finding title as markup", () => {
    const state = caseState();
    state.findings.push(finding({ id: "f9", title: HOSTILE, mitreTechniques: ["T8888"] }));
    state.mitreTechniques.push({ id: "T8888", name: HOSTILE, findingIds: ["f9"] });
    const html = renderInteractiveHtmlReport(withEventTechniques(state));
    expect(html).not.toContain(HOSTILE);
    expect(html).not.toContain("<img");
    // It is still there as data, for the renderer to put in a text node.
    expect(matrixBlob(html).names.T8888).toBe(HOSTILE);
  });

  it("an embedded `</script>` cannot close the data element", () => {
    const state = caseState();
    const payload = "</script><script>alert(1)</script>";
    state.findings.push(finding({ id: "f8", title: payload, mitreTechniques: ["T7777"] }));
    state.mitreTechniques.push({ id: "T7777", name: payload, findingIds: ["f8"] });
    const html = renderInteractiveHtmlReport(withEventTechniques(state));
    expect(html.match(/<script\b/gi) ?? []).toHaveLength(2);
    expect(html).not.toContain(payload);
    expect(matrixBlob(html).names.T7777).toBe(payload);
  });

  it("adds a bounded amount to the file for a realistic case", () => {
    const state = caseState();
    const html = renderInteractiveHtmlReport(state);
    const bytes = Buffer.byteLength(JSON.stringify(matrixBlob(html)), "utf8");
    // ~80 KB for the 19.1 catalogue; ten uncompacted models would be ~370 KB.
    expect(bytes).toBeLessThan(150 * 1024);
  });
});

// Criterion 12: the report's highlighted set equals GET /cases/:id/attack-layer.json, through the
// real filtered state — so a confirmed false positive drops out of both.
describe("route parity with the attack-layer export", () => {
  it("the report and the layer highlight the same ids after a finding is marked false positive", async () => {
    const root = await mkdtemp(join(tmpdir(), "dfir-attack-matrix-report-"));
    const cases = new CaseStore(root);
    await cases.createCase({ caseId: "c1", name: "Matrix Case", investigator: "A", aiProvider: null });
    const stateStore = new StateStore(cases);
    const state = emptyState("c1");
    state.findings.push(
      finding({
        id: "f1",
        title: "Encoded PowerShell",
        severity: "Critical",
        mitreTechniques: ["T1059.001"],
      }),
      finding({ id: "f2", title: "Pentest scan", severity: "High", mitreTechniques: ["T1046"] }),
    );
    state.mitreTechniques.push(
      { id: "T1059.001", name: "PowerShell", findingIds: ["f1"] },
      { id: "T1046", name: "Network Service Discovery", findingIds: ["f2"] },
    );
    state.forensicTimeline.push(event({ id: "e1", severity: "High", mitreTechniques: ["T1105"] }));
    await stateStore.save(state);
    const falsePositives = new FalsePositiveStore(cases);
    await falsePositives.save("c1", [
      {
        id: "finding:Pentest scan",
        kind: "finding",
        ref: "Pentest scan",
        reason: "authorized-test",
        note: "",
        markedAt: "2026-05-20T00:00:00Z",
        markedBy: "analyst",
      },
    ]);
    const app = createApp(cases, {
      stateStore,
      reportWriter: new ReportWriter(cases, stateStore, { falsePositives }),
    });

    const layer = await request(app).get("/cases/c1/attack-layer.json");
    const report = await request(app).get("/cases/c1/report/interactive");
    expect(layer.status).toBe(200);
    expect(report.status).toBe(200);
    const layerSet = (layer.body.techniques as Array<{ techniqueID: string; score?: number }>)
      .filter((t) => t.score !== undefined)
      .map((t) => t.techniqueID)
      .sort();
    expect(layerSet).toEqual(["T1059.001", "T1105"]);
    expect(Object.keys(matrixBlob(report.text).hits).sort()).toEqual(layerSet);
  });
});
