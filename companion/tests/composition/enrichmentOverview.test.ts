// #1887: the background IOC enrichment after every import used to load the whole case (every
// forensic event) to check for work, load it again to merge, save the whole case and fingerprint
// the whole loaded state. The next import's memory-guard count waited seconds behind that load.
// Without a chain-capable provider (one with checkParentChild) enrichment touches only IOCs, so it
// reads and writes the overview, and the run record comes from the case database.
import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CaseStore } from "../../src/storage/caseStore.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { AnalysisRunStore } from "../../src/analysis/analysisRunStore.js";
import { createEnrichmentEngine } from "../../src/composition/enrichment.js";
import { investigationOutput } from "../../src/analysis/analysisRunSnapshot.js";
import { emptyState, type ForensicEvent, type IOC } from "../../src/analysis/stateTypes.js";
import { loadDatabaseSync } from "../../src/analysis/sqliteRuntime.js";
import { enrichIocs } from "../../src/enrichment/enrichService.js";
import { mergeEnrichedSubset } from "../../src/analysis/iocBulkOps.js";
import { pollFor } from "../helpers/poll.js";
import type { AppOptions } from "../../src/composition/appOptions.js";
import type { EnrichmentProvider } from "../../src/enrichment/provider.js";

const CASE_ID = "c1";

function ev(id: string, p: Partial<ForensicEvent> = {}): ForensicEvent {
  return {
    id,
    timestamp: `2026-01-0${1 + (Number(id.replace(/\D/g, "")) % 9)}T00:00:00Z`,
    description: `row ${id}`,
    severity: "Medium",
    mitreTechniques: [],
    relatedFindingIds: [],
    sourceScreenshots: [],
    ...p,
  };
}

const ioc = (id: string, value: string, p: Partial<IOC> = {}): IOC => ({
  id,
  type: "domain",
  value,
  firstSeen: new Date(0).toISOString(),
  ...p,
});

let dir: string;
let stateStore: StateStore;
let runs: AnalysisRunStore;
let cases: CaseStore;

beforeEach(async () => {
  dir = await mkdtemp(join(tmpdir(), "dfir-enrich-overview-"));
  cases = new CaseStore(dir);
  await cases.createCase({ caseId: CASE_ID, name: "n", investigator: "i", aiProvider: null });
  stateStore = new StateStore(cases);
  runs = new AnalysisRunStore(cases, { appVersion: "test" });
});

afterEach(async () => {
  vi.restoreAllMocks();
  await rm(dir, { recursive: true, force: true });
});

/** The stored forensic rows as the database holds them: row id, ordinal and payload. */
function forensicRows(): unknown[] {
  const db = new (loadDatabaseSync())(stateStore.databasePath(CASE_ID));
  try {
    return db
      .prepare("SELECT row_id, ordinal, payload FROM entities WHERE kind='forensicTimeline' ORDER BY ordinal")
      .all();
  } finally {
    db.close();
  }
}

interface HarnessOptions {
  chain?: boolean;
  gate?: Promise<void>;
  onLookup?: () => void;
}

function harness(opts: HarnessOptions = {}) {
  const provider: EnrichmentProvider = {
    name: "MISP",
    scope: "local",
    supports: () => true,
    lookup: async () => {
      opts.onLookup?.();
      await opts.gate;
      return { source: "MISP", verdict: "malicious" };
    },
  };
  const chainProvider = {
    ...provider,
    checkParentChild: async () => ({ observed: true, note: "observed" }),
  };
  const statuses: string[] = [];
  const options = {
    enrichmentProviders: [opts.chain ? chainProvider : provider],
    stateStore,
    analysisRunStore: runs,
    enrichDelayMs: 0,
    onAiStatus: (_caseId: string, s: { status: string }) => statuses.push(s.status),
  } as unknown as AppOptions;
  const engine = createEnrichmentEngine({
    store: cases,
    options,
    runStateExclusive: async (_caseId, fn) => fn(),
  });
  const done = () => pollFor("enrichment finished", async () => statuses.includes("idle") || undefined);
  return { engine, done };
}

async function enrichmentRun() {
  const all = await runs.list(CASE_ID);
  const run = all.find((r) => r.kind === "enrichment");
  expect(run).toBeDefined();
  return run!;
}

describe("enrichment without a chain-capable provider (#1887)", () => {
  it("reads and writes only the overview: never loads nor saves the whole case", async () => {
    await stateStore.save({
      ...emptyState(CASE_ID),
      iocs: [ioc("i1", "evil.example.com"), ioc("i2", "bad.example.org")],
      forensicTimeline: Array.from({ length: 40 }, (_, i) => ev(`e${i}`, { asset: "H1" })),
    });
    const before = forensicRows();
    const load = vi.spyOn(stateStore, "load");
    const save = vi.spyOn(stateStore, "save");
    const saveOverview = vi.spyOn(stateStore, "saveOverview");
    const { engine, done } = harness();
    engine.enrichInBackground(CASE_ID);
    await done();

    expect(load).not.toHaveBeenCalled();
    expect(save).not.toHaveBeenCalled();
    expect(saveOverview).toHaveBeenCalledTimes(1);
    expect(forensicRows()).toEqual(before);
    const overview = await stateStore.loadOverview(CASE_ID);
    for (const i of overview.iocs) {
      expect(i.enrichedBy).toEqual(["MISP"]);
      expect(i.enrichments?.[0]).toMatchObject({ source: "MISP", verdict: "malicious" });
    }
  });

  it("keeps a forensic row and an IOC edit that land while the run is in flight", async () => {
    await stateStore.save({
      ...emptyState(CASE_ID),
      iocs: [ioc("i1", "evil.example.com")],
      forensicTimeline: [ev("e1")],
    });
    let release = (): void => {};
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    let started = false;
    const { engine, done } = harness({ gate, onLookup: () => (started = true) });
    engine.enrichInBackground(CASE_ID);
    await pollFor("lookup in flight", async () => started || undefined);

    // Mid-run: an import appends a row and a later write annotates the same IOC.
    await stateStore.appendForensicEvents(CASE_ID, [ev("e2")]);
    const mid = await stateStore.loadOverview(CASE_ID);
    await stateStore.saveOverview({
      ...mid,
      iocs: mid.iocs.map((i) => ({ ...i, note: "DC01", extractedFrom: ["e2"] })),
    });
    release();
    await done();

    const after = await stateStore.load(CASE_ID);
    expect(after.forensicTimeline.map((e) => e.id)).toEqual(["e1", "e2"]);
    expect(after.iocs).toHaveLength(1);
    expect(after.iocs[0]).toMatchObject({ note: "DC01", extractedFrom: ["e2"], enrichedBy: ["MISP"] });
  });

  it("keeps a bulk re-check's intel that saved while the run was in flight", async () => {
    await stateStore.save({ ...emptyState(CASE_ID), iocs: [ioc("i1", "evil.example.com")] });
    let release = (): void => {};
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    let started = false;
    const { engine, done } = harness({ gate, onLookup: () => (started = true) });
    engine.enrichInBackground(CASE_ID);
    await pollFor("lookup in flight", async () => started || undefined);

    // Mid-run: the bulk-enrich route checks the same IOC with another provider and saves first.
    const vt: EnrichmentProvider = {
      name: "VT",
      scope: "external",
      supports: () => true,
      lookup: async () => ({ source: "VT", verdict: "suspicious" }),
    };
    const mid = await stateStore.loadOverview(CASE_ID);
    const { iocs: checked } = await enrichIocs(mid.iocs, { providers: [vt], delayMs: 0 });
    await stateStore.saveOverview({ ...mid, iocs: mergeEnrichedSubset(mid.iocs, checked) });
    release();
    await done();

    const [after] = (await stateStore.loadOverview(CASE_ID)).iocs;
    expect([...(after.enrichedBy ?? [])].sort()).toEqual(["MISP", "VT"]);
    expect((after.enrichments ?? []).map((e) => e.source).sort()).toEqual(["MISP", "VT"]);
    const history = (after.intelHistory ?? []).map((r) => r.assertionId);
    expect(history.length).toBeGreaterThanOrEqual(2);
  });

  it("enriches both copies of a duplicated IOC value, each keeping its own id", async () => {
    await stateStore.save({
      ...emptyState(CASE_ID),
      iocs: [ioc("i1", "evil.example.com"), ioc("i2", "evil.example.com")],
    });
    const { engine, done } = harness();
    engine.enrichInBackground(CASE_ID);
    await done();
    const after = await stateStore.loadOverview(CASE_ID);
    expect(after.iocs.map((i) => [i.id, i.enrichedBy])).toEqual([
      ["i1", ["MISP"]],
      ["i2", ["MISP"]],
    ]);
  });

  it("records a run whose output equals the whole-case output, and looked at no events", async () => {
    await stateStore.save({
      ...emptyState(CASE_ID),
      findings: [
        { id: "f1", title: "t", severity: "High", description: "d", relatedEventIds: ["e2"] } as never,
      ],
      iocs: [ioc("i1", "evil.example.com"), ioc("i2", "bad.example.org")],
      forensicTimeline: Array.from({ length: 12 }, (_, i) =>
        ev(`e${i}`, { processName: "cmd.exe", parentName: "explorer.exe" }),
      ),
    });
    const { engine, done } = harness();
    engine.enrichInBackground(CASE_ID);
    await done();

    const run = await enrichmentRun();
    expect(run.input.eventIds).toEqual([]);
    expect(run.input.entityIds).toEqual(["i1", "i2"]);
    const expected = investigationOutput(await stateStore.load(CASE_ID));
    expect(run.output).toEqual(expected);
  });
});

describe("enrichment with a chain-capable provider (#1887)", () => {
  it("keeps the whole-case path: validates chains, saves them and records the events it checked", async () => {
    await stateStore.save({
      ...emptyState(CASE_ID),
      iocs: [ioc("i1", "evil.example.com")],
      forensicTimeline: [
        ev("e1", { processName: "powershell.exe", parentName: "excel.exe" }),
        ev("e2"),
        ev("e3", { processName: "svchost.exe", parentName: "services.exe" }),
      ],
    });
    const load = vi.spyOn(stateStore, "load");
    const { engine, done } = harness({ chain: true });
    engine.enrichInBackground(CASE_ID);
    await done();

    expect(load).toHaveBeenCalled();
    const after = await stateStore.load(CASE_ID);
    expect(after.forensicTimeline.filter((e) => e.chainCheck).map((e) => e.id)).toEqual(["e1", "e3"]);
    expect(after.iocs[0].enrichedBy).toEqual(["MISP"]);
    const run = await enrichmentRun();
    expect(run.input.eventIds).toEqual(["e1", "e3"]);
    expect(run.input.entityIds).toEqual(["i1"]);
    expect(run.output).toEqual(investigationOutput(after));
  });
});
