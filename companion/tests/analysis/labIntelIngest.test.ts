import { describe, it, expect, beforeEach } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CaseStore } from "../../src/storage/caseStore.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { SuperTimelineStore } from "../../src/analysis/superTimelineStore.js";
import { StateLock } from "../../src/analysis/stateLock.js";
import { AnalysisPipeline } from "../../src/analysis/pipeline.js";
import { correlateEvents } from "../../src/analysis/correlate.js";
import { renderStructuredTags } from "../../src/analysis/synthEvidence.js";
import { mergeConcurrentAdditions } from "../../src/analysis/ai/synthesisPersist.js";
import { emptyState, type ForensicEvent, type InvestigationState } from "../../src/analysis/stateTypes.js";

// #932 item 5, end to end: a sandbox report is LAB evidence. Its rows go to the super-timeline and
// never to the forensic timeline; the sample's verdict reaches the incident event that carries the
// hash as a registry record, rendered to the model as a <sandbox:…> tag — at the sighting's own
// time and severity. And a lab row can no longer be correlated into a host row by shared hash,
// which is how a KAPE "file created" used to come out described as an injection.

const SHA = "a".repeat(64);
const capeReport = () =>
  JSON.stringify({
    info: { id: 42, score: 9.2, started: "2023-09-01 10:00:00" },
    target: {
      category: "file",
      file: { name: "invoice.exe", sha256: SHA, md5: "b".repeat(32), type: "PE32" },
    },
    malscore: 9.2,
    malfamily: "Emotet",
    signatures: [
      {
        name: "injection_explorer",
        description: "Injects into explorer.exe",
        severity: 3,
        ttp: { T1055: {} },
      },
      { name: "c2_beacon", description: "Beacons to a C2", severity: 3 },
    ],
  });

// A host artifact that carries the sample's hash: a Sysmon-style process create as the SIEM importer
// would see it, on a real host, at an incident time months before the detonation.
const hostSighting = () =>
  JSON.stringify([
    {
      "@timestamp": "2023-03-15T08:00:00.000Z",
      log_name: "Microsoft-Windows-Sysmon/Operational",
      computer_name: "WS-01",
      event_id: 1,
      event_data: {
        Image: "C:\\Users\\bob\\Downloads\\invoice.exe",
        CommandLine: "invoice.exe",
        ParentImage: "C:\\Windows\\explorer.exe",
        Hashes: `SHA256=${SHA}`,
      },
    },
  ]);

let cases: CaseStore;
let stateStore: StateStore;
let superTimelineStore: SuperTimelineStore;
let pipeline: AnalysisPipeline;

beforeEach(async () => {
  cases = new CaseStore(await mkdtemp(join(tmpdir(), "dfir-labintel-")));
  await cases.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  stateStore = new StateStore(cases);
  await stateStore.save(emptyState("c1"));
  superTimelineStore = new SuperTimelineStore(cases);
  pipeline = new AnalysisPipeline({
    stateStore,
    superTimelineStore,
    stateLock: new StateLock(),
    imageLoader: async () => ({ base64: "", mimeType: "image/webp" }),
  });
});

const importSandbox = () =>
  pipeline.importSandbox("c1", capeReport(), {
    label: "cape.json",
    idPrefix: "sb1",
    importedAt: "2026-09-10T11:00:00Z",
  });
const importHost = () =>
  pipeline.importSiem("c1", hostSighting(), {
    label: "sysmon.json",
    idPrefix: "h1",
    importedAt: "2026-09-10T11:01:00Z",
  });

describe("sandbox import is lab evidence", () => {
  it("puts every sandbox row in the super-timeline as origin lab, and none in the forensic timeline", async () => {
    await importSandbox();
    const state = await stateStore.load("c1");
    expect(state.forensicTimeline).toEqual([]);
    const rows = await superTimelineStore.all("c1");
    expect(rows.length).toBeGreaterThan(0);
    for (const r of rows) expect(r.origin).toBe("lab");
    expect(rows.some((r) => r.description.startsWith("CAPE sandbox:"))).toBe(true);
  });

  it("writes the sample's registry record into state, stamped with the import time", async () => {
    await importSandbox();
    const state = await stateStore.load("c1");
    expect(state.labIntel).toHaveLength(1);
    expect(state.labIntel?.[0]).toMatchObject({
      sha256: SHA,
      source: "CAPEv2",
      runId: "42",
      verdict: "malicious",
    });
    expect(state.labIntel?.[0].importedAt).toBe("2026-09-10T11:00:00Z");
  });

  it("keeps the hash IOCs — the sample is still an indicator for the case", async () => {
    await importSandbox();
    const state = await stateStore.load("c1");
    expect(state.iocs.some((i) => i.value.toLowerCase() === SHA)).toBe(true);
  });
});

describe("the sighting carries the sample's lab verdict", () => {
  const sighting = (state: InvestigationState): ForensicEvent => {
    const e = state.forensicTimeline.find((x) => (x.sha256 ?? "").toLowerCase() === SHA);
    expect(e, "the host sighting with the hash").toBeDefined();
    return e!;
  };

  it("sandbox first, then the host artifact: the host event gets the registry record and keeps its own time", async () => {
    await importSandbox();
    await importHost();
    const e = sighting(await stateStore.load("c1"));
    expect(e.labIntel).toHaveLength(1);
    expect(e.labIntel?.[0].verdict).toBe("malicious");
    expect(e.timestamp).toBe("2023-03-15T08:00:00.000Z"); // the incident time, not the detonation
    expect(e.origin).toBeUndefined();
    expect(e.description).not.toMatch(/inject/i); // the host row still describes the host event
  });

  it("host artifact first, then the sandbox: same result — the annotation does not depend on import order", async () => {
    await importHost();
    await importSandbox();
    const e = sighting(await stateStore.load("c1"));
    expect(e.labIntel).toHaveLength(1);
    expect(e.timestamp).toBe("2023-03-15T08:00:00.000Z");
  });

  it("renders the verdict to the model as a <sandbox:…> tag beside <host:…>", async () => {
    await importSandbox();
    await importHost();
    const tags = renderStructuredTags(sighting(await stateStore.load("c1")));
    expect(tags).toContain("<host:WS-01>");
    expect(tags).toMatch(/<sandbox:CAPEv2 malicious Emotet 9\.2 injection_explorer,c2_beacon>/);
  });

  it("a second detonation of the same sample becomes a second registry record, and the tag shows both", async () => {
    await importSandbox();
    const second = JSON.parse(capeReport()) as { info: { id: number } };
    second.info.id = 43;
    await pipeline.importSandbox("c1", JSON.stringify(second), {
      label: "cape2.json",
      idPrefix: "sb2",
      importedAt: "2026-09-11T11:00:00Z",
    });
    await importHost();
    const state = await stateStore.load("c1");
    expect(state.labIntel).toHaveLength(2);
    expect(sighting(state).labIntel).toHaveLength(2);
  });
});

describe("correlation refuses lab/host unions", () => {
  const ev = (over: Partial<ForensicEvent> & { id: string }): ForensicEvent => ({
    timestamp: "2023-03-15T08:00:00Z",
    description: "file created C:\\Users\\bob\\invoice.exe",
    severity: "Info",
    mitreTechniques: [],
    relatedFindingIds: [],
    sourceScreenshots: [],
    sources: ["KAPE"],
    sha256: SHA,
    asset: "WS-01",
    ...over,
  });

  // The exact contamination: shared hash, no time bound, the more severe LAB row becomes primary.
  it("a High lab row and an Info host row with the same hash stay two events, and the host row keeps its text", () => {
    const host = ev({ id: "h1" });
    const lab = ev({
      id: "sb1",
      origin: "lab",
      sources: ["CAPEv2"],
      severity: "High",
      timestamp: "2023-09-01T10:00:00Z",
      description: "CAPE signature: injection_explorer — Injects into explorer.exe",
      asset: undefined,
    });
    const out = correlateEvents([host, lab]);
    expect(out).toHaveLength(2);
    const h = out.find((e) => e.id === "h1")!;
    expect(h.severity).toBe("Info");
    expect(h.description).toMatch(/^file created/);
  });

  it("a LEGACY lab row with no origin field is recognised by its sources and prefix, and still refused", () => {
    const host = ev({ id: "h1" });
    const legacy = ev({
      id: "old1",
      sources: ["CAPEv2"],
      severity: "High",
      timestamp: "2023-09-01T10:00:00Z",
      description: "CAPE sandbox: Emotet — invoice.exe score 9/10",
      asset: undefined,
    });
    expect(correlateEvents([host, legacy])).toHaveLength(2);
  });

  it("two lab rows for one run still dedup with each other", () => {
    const a = ev({
      id: "sb1",
      origin: "lab",
      sources: ["CAPEv2"],
      description: "CAPE sandbox: x",
      timestamp: "2023-09-01T10:00:00Z",
      asset: undefined,
    });
    const b = ev({
      id: "sb1-again",
      origin: "lab",
      sources: ["CAPEv2"],
      description: "CAPE sandbox: x",
      timestamp: "2023-09-01T10:00:00Z",
      asset: undefined,
    });
    expect(correlateEvents([a, b])).toHaveLength(1);
  });
});

describe("the registry survives the reducers", () => {
  it("a merge with an unrelated delta keeps the registry", async () => {
    await importSandbox();
    await importHost(); // an unrelated import goes through mergeDelta
    expect((await stateStore.load("c1")).labIntel).toHaveLength(1);
  });

  it("mergeConcurrentAdditions unions the registry from both sides", () => {
    const rec = (runId: string) => ({
      sha256: SHA,
      source: "CAPEv2",
      runId,
      verdict: "malicious" as const,
      score: 9,
      family: "",
      signatures: [],
      detonatedAt: "",
      importedAt: "",
    });
    const base = emptyState("c1");
    const next = { ...emptyState("c1"), labIntel: [rec("1")] };
    const latest = { ...emptyState("c1"), labIntel: [rec("2")] };
    expect(mergeConcurrentAdditions(base, next, latest).labIntel?.map((r) => r.runId)).toEqual(["1", "2"]);
  });
});
