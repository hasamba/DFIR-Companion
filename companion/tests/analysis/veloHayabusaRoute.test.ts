import { describe, it, expect } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { buildRuntimePipeline } from "../../src/server.js";
import { CaseStore } from "../../src/storage/caseStore.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { emptyState } from "../../src/analysis/stateTypes.js";
import { createImportDebugRecorder } from "../../src/analysis/importDebug.js";
import { looksLikeHayabusaNamedExport } from "../../src/analysis/hayabusaImport.js";
import { detectImportKind } from "../../src/analysis/importDetect.js";

// #1756 — the pull paths' importer seam. The server tests prove each entry point; these pin the
// shared rule and the option carry-over the pull paths depend on.

const ART = "Windows.Hayabusa.Rules";
const LABEL = `0003_velo-hunt_H.HAYA_${ART}.json`;

function row(title: string, level: string, recordId: number): Record<string, unknown> {
  return {
    Timestamp: `2026-09-20T19:29:${String(recordId % 60).padStart(2, "0")}.000Z`,
    Computer: "WS-01",
    Channel: "Microsoft-Windows-Sysmon/Operational",
    EID: "1",
    Level: level,
    Title: title,
    RecordID: String(recordId),
    Details: `Cmdline: helper.exe /c echo ${recordId} ¦ Proc: C:\\Users\\Public\\Sim\\helper${recordId}.exe`,
    _Source: "Windows.Sigma.Base",
  };
}

const ROWS = [row("Rule A", "high", 1101), row("Rule B", "high", 1102), row("Rule C", "med", 1103)];
const MAP = JSON.stringify({ [ART]: ROWS });

async function setup() {
  const root = await mkdtemp(join(tmpdir(), "dfir-velohaya-unit-"));
  const store = new CaseStore(root);
  const stateStore = new StateStore(store);
  await stateStore.save(emptyState("c1"));
  const pipeline = buildRuntimePipeline({
    provider: undefined,
    synthesisProvider: undefined,
    stateStore,
    store,
    imageLoader: async () => ({ base64: "AAAA", mimeType: "image/webp" }),
  });
  return { pipeline, stateStore };
}

const base = { label: LABEL, idPrefix: "7", importedAt: "2026-09-28T00:00:00.000Z" };

describe("looksLikeHayabusaNamedExport (#1756)", () => {
  it("needs the name AND a Hayabusa body", () => {
    expect(looksLikeHayabusaNamedExport(LABEL, MAP)).toBe(true);
    expect(looksLikeHayabusaNamedExport("velo-hunt_H.X_Windows.Sigma.Base.json", MAP)).toBe(false);
    expect(looksLikeHayabusaNamedExport(LABEL, JSON.stringify({ [ART]: [{ OSPath: "C:\\x" }] }))).toBe(false);
  });

  it("ignores leading whitespace, as auto-detect always has", () => {
    const padded = `\n\n   ${MAP}`;
    expect(looksLikeHayabusaNamedExport(LABEL, padded)).toBe(true);
    expect(detectImportKind(LABEL, padded)).toBe("hayabusa");
  });
});

describe("pipeline.importVelociraptorArtifact (#1756)", () => {
  it("imports a Hayabusa result through the Hayabusa importer and says so in the debug record", async () => {
    const { pipeline, stateStore } = await setup();
    const debug = createImportDebugRecorder();
    debug.detected("velociraptor", { confident: true, decision: "explicit_route" });
    await pipeline.importVelociraptorArtifact("c1", MAP, { ...base, debug });
    const events = (await stateStore.load("c1")).forensicTimeline;
    expect(events).toHaveLength(3);
    expect(events.every((e) => e.sources?.includes("Hayabusa"))).toBe(true);
    expect(debug.summary().kind).toBe("hayabusa");
  });

  it("honours the hunt-wide event budget", async () => {
    const { pipeline, stateStore } = await setup();
    await pipeline.importVelociraptorArtifact("c1", MAP, { ...base, velociraptor: { maxEvents: 1 } });
    expect((await stateStore.load("c1")).forensicTimeline).toHaveLength(1);
  });

  it("honours a severity floor set in the Velociraptor options", async () => {
    const { pipeline, stateStore } = await setup();
    await pipeline.importVelociraptorArtifact("c1", MAP, { ...base, velociraptor: { minSeverity: "High" } });
    const events = (await stateStore.load("c1")).forensicTimeline;
    expect(events.length).toBe(2);
    expect(events.every((e) => e.severity === "High")).toBe(true);
  });

  it("stamps the flow's host on rows that name none", async () => {
    const { pipeline, stateStore } = await setup();
    const hostless = JSON.stringify({ [ART]: ROWS.map(({ Computer: _c, ...r }) => r) });
    await pipeline.importVelociraptorArtifact("c1", hostless, {
      ...base,
      velociraptor: { hostFallback: "DESKTOP-01" },
    });
    const events = (await stateStore.load("c1")).forensicTimeline;
    expect(events.length).toBeGreaterThan(0);
    expect(events.every((e) => e.asset === "DESKTOP-01")).toBe(true);
  });

  it("keeps a result over the import-file cap on the Velociraptor path", async () => {
    const { pipeline, stateStore } = await setup();
    const debug = createImportDebugRecorder();
    const prev = process.env.DFIR_MAX_IMPORT_FILE_MB;
    process.env.DFIR_MAX_IMPORT_FILE_MB = String(100 / (1024 * 1024)); // 100 bytes — below MAP's size
    try {
      await pipeline.importVelociraptorArtifact("c1", MAP, { ...base, debug });
    } finally {
      if (prev === undefined) delete process.env.DFIR_MAX_IMPORT_FILE_MB;
      else process.env.DFIR_MAX_IMPORT_FILE_MB = prev;
    }
    const events = (await stateStore.load("c1")).forensicTimeline;
    expect(events.length).toBeGreaterThan(0);
    expect(events.some((e) => e.sources?.includes("Hayabusa"))).toBe(false);
    expect(debug.summary().fallbacks).toMatchObject({ hayabusa_over_import_file_cap: 1 });
  });

  it("leaves a non-Hayabusa artifact on the Velociraptor importer", async () => {
    const { pipeline, stateStore } = await setup();
    await pipeline.importVelociraptorArtifact("c1", MAP, { ...base, label: "0003_velo-hunt_H.X_Other.json" });
    const events = (await stateStore.load("c1")).forensicTimeline;
    expect(events.length).toBeGreaterThan(0);
    expect(events.some((e) => e.sources?.includes("Hayabusa"))).toBe(false);
  });
});
