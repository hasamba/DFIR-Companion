import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CaseStore } from "../../src/storage/caseStore.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { SuperTimelineStore } from "../../src/analysis/superTimelineStore.js";
import { ForensicGateControlStore } from "../../src/analysis/forensicGateControl.js";
import { TagsStore } from "../../src/analysis/tags.js";
import { TaggerStore } from "../../src/analysis/taggerStore.js";
import { StateLock } from "../../src/analysis/stateLock.js";
import { MockProvider } from "../../src/providers/provider.js";
import { AnalysisPipeline } from "../../src/analysis/pipeline.js";
import { settleForensicImport, type SettleDeps } from "../../src/routes/importSettle.js";
import { createImportDemote } from "../../src/composition/importDemote.js";
import { autoTagNewEvents } from "../../src/analysis/taggerAuto.js";
import { captureImportBaseline, releaseImportBaseline } from "../../src/analysis/importBaseline.js";
import { baselineCheckpoint } from "../../src/analysis/importUndoRows.js";
import { applyUndoDelta } from "../../src/analysis/importUndoDelta.js";
import type { AppOptions } from "../../src/composition/appOptions.js";
import type { ForensicEvent, InvestigationState } from "../../src/analysis/stateTypes.js";

// #1874: an import through the real importer, the incremental merge and the real settle (stamp, tag,
// demote) leaves the case exactly as the same import through today's full merge does — timeline order
// and content, IOCs, the counts the import reports and its undo checkpoint — import after import.

const RULES = `spooler:
  any:
    - { field: message, contains: ['Spooler'] }
  tags: ['spooler']
  mitre: ['T1543.003']
  severity: High
`;

function siem(prefix: string, n: number, day0 = 1): string {
  const rows: object[] = [];
  for (let i = 0; i < n; i++) {
    const svc = `${prefix}-${i}`;
    const day = String(day0 + (i % 5)).padStart(2, "0");
    rows.push({
      "@timestamp": `2026-07-${day}T10:0${i % 10}:00.000Z`,
      log_name: "System",
      computer_name: "S1-HOST",
      event_id: 7045,
      level: "Information",
      event_data: { ServiceName: svc, ServiceFileName: `C:\\Windows\\Temp\\${svc}.exe` },
    });
    rows.push({
      "@timestamp": `2026-07-${day}T11:0${i % 10}:00.000Z`,
      log_name: "System",
      computer_name: "S1-HOST",
      event_id: 7036,
      level: "Information",
      message: `The ${i % 3 ? "Windows Update" : "Print Spooler"} service ${svc} entered the running state.`,
    });
    rows.push({
      "@timestamp": `2026-07-${day}T12:0${i % 10}:0${i % 7}.000Z`,
      log_name: "Microsoft-Windows-Sysmon/Operational",
      computer_name: i % 4 ? "S1-HOST" : "S1-HOST.corp.example.com",
      event_id: 1,
      level: "Information",
      event_data: {
        Image: `C:\\Users\\bob\\AppData\\Local\\Temp\\${svc}.exe`,
        CommandLine: `${svc}.exe --run ${i % 3}`,
        ParentImage: i % 2 ? "C:\\Windows\\explorer.exe" : "C:\\Windows\\System32\\services.exe",
        ProcessId: String(1000 + i),
        Hashes: `SHA256=${(i % 6).toString(16).repeat(64)}`,
      },
    });
  }
  return JSON.stringify(rows);
}

let root: string;
let stateStore: StateStore;
let superStore: SuperTimelineStore;
let tagsStore: TagsStore;
let taggerStore: TaggerStore;
let gate: ForensicGateControlStore;
let lock: StateLock;
let pipelines: Record<"full" | "inc", AnalysisPipeline>;

beforeEach(async () => {
  root = await mkdtemp(join(tmpdir(), "dfir-merge-eq-"));
  const cases = new CaseStore(root);
  for (const caseId of ["full", "inc"])
    await cases.createCase({ caseId, name: caseId, investigator: "i", aiProvider: "mock" });
  stateStore = new StateStore(cases);
  superStore = new SuperTimelineStore(cases);
  tagsStore = new TagsStore(cases);
  gate = new ForensicGateControlStore(cases);
  await writeFile(join(root, "rules.yaml"), RULES);
  taggerStore = new TaggerStore(join(root, "user.yaml"), [join(root, "rules.yaml")]);
  lock = new StateLock();
  const make = (incrementalMerge: boolean) =>
    new AnalysisPipeline({
      provider: new MockProvider("mock", "{}"),
      stateStore,
      stateLock: lock,
      incrementalMerge,
      imageLoader: async () => ({ base64: "AAAA", mimeType: "image/webp" }),
    });
  pipelines = { full: make(false), inc: make(true) };
});

afterEach(async () => {
  await rm(root, { recursive: true, force: true });
});

const runExclusive = <T>(caseId: string, fn: () => Promise<T>): Promise<T> => lock.runExclusive(caseId, fn);

function deps(): SettleDeps {
  const options = {
    stateStore,
    superTimelineStore: superStore,
    forensicGateControlStore: gate,
  } as unknown as AppOptions;
  const demote = createImportDemote({ options, runStateExclusive: runExclusive });
  return {
    stateStore,
    runStateExclusive: runExclusive,
    superTimelineStore: superStore,
    autoTagImported: (caseId, added) =>
      autoTagNewEvents(
        { taggerStore, tagsStore, stateStore, runStateExclusive: runExclusive },
        caseId,
        added,
      ),
    demoteForensic: demote.demoteForensic,
  };
}

// The settle stamps are fresh per run (the rows' time and batch id, the case's updatedAt);
// everything else must match exactly.
const unstamp = (s: InvestigationState) => ({
  ...s,
  caseId: "x",
  updatedAt: "U",
  forensicTimeline: s.forensicTimeline.map((e: ForensicEvent) =>
    e.importedAt ? { ...e, importedAt: "T", importBatchId: "B" } : e,
  ),
});

async function importBoth(run: (p: AnalysisPipeline, caseId: string) => Promise<unknown>) {
  const out: Record<string, unknown> = {};
  for (const caseId of ["full", "inc"] as const) {
    const before = await stateStore.load(caseId);
    const baseline = await captureImportBaseline(stateStore, caseId);
    try {
      await run(pipelines[caseId], caseId);
      const settled = await settleForensicImport(deps(), caseId, baseline, "label");
      const checkpoint = await baselineCheckpoint(stateStore, baseline, "label", "at");
      const after = await stateStore.load(caseId);
      expect(applyUndoDelta(after, checkpoint!.delta!)).toEqual(before);
      out[caseId] = {
        timelineDiff: settled.timelineDiff,
        iocsDiff: settled.iocsDiff,
        supers: settled.superTimelineAddedCount,
      };
    } finally {
      await releaseImportBaseline(stateStore, baseline);
    }
  }
  expect(out.inc).toEqual(out.full);
  const [a, b] = [unstamp(await stateStore.load("inc")), unstamp(await stateStore.load("full"))];
  if (JSON.stringify(a) !== JSON.stringify(b)) console.log("DIFFDEBUG", firstDiff(a, b));
  expect(a).toEqual(b);
}

function firstDiff(a: unknown, b: unknown, path = ""): string {
  if (JSON.stringify(a) === JSON.stringify(b)) return "";
  if (Array.isArray(a) && Array.isArray(b)) {
    if (a.length !== b.length)
      return `${path}: length ${a.length} vs ${b.length} ids ${JSON.stringify(a.map((x) => x?.id))} vs ${JSON.stringify(b.map((x) => x?.id))}`;
    for (let i = 0; i < a.length; i++) {
      const d = firstDiff(a[i], b[i], `${path}[${i}]`);
      if (d) return d;
    }
  }
  if (a && b && typeof a === "object" && typeof b === "object") {
    for (const k of new Set([...Object.keys(a), ...Object.keys(b)])) {
      const d = firstDiff(
        (a as Record<string, unknown>)[k],
        (b as Record<string, unknown>)[k],
        `${path}.${k}`,
      );
      if (d) return d;
    }
  }
  return `${path}: ${JSON.stringify(a)?.slice(0, 400)} vs ${JSON.stringify(b)?.slice(0, 400)}`;
}

const at = (n: number) => `2026-09-30T10:0${n}:00.000Z`;

describe("import + settle through the incremental merge matches the full merge (#1874)", () => {
  it("SIEM service, Spooler and Sysmon process rows, import after import, with a re-import", async () => {
    let n = 0;
    for (const [prefix, day0] of [
      ["a", 1],
      ["b", 3],
      ["c", 2],
      ["a", 1],
      ["d", 9],
    ] as const) {
      n++;
      await importBoth((p, caseId) =>
        p.importSiem(caseId, siem(prefix, 12, day0), {
          label: `${prefix}.json`,
          idPrefix: `${n}`,
          importedAt: at(n),
        }),
      );
    }
  });

  it("returns the rows it wrote and tells the dashboards the case changed, instead of the whole case", async () => {
    const changed: string[] = [];
    const pushed: InvestigationState[] = [];
    const p = new AnalysisPipeline({
      provider: new MockProvider("mock", "{}"),
      stateStore,
      incrementalMerge: true,
      onState: (s) => pushed.push(s),
      onStateChanged: (caseId) => changed.push(caseId),
      imageLoader: async () => ({ base64: "AAAA", mimeType: "image/webp" }),
    });
    const first = await p.importSiem("inc", siem("a", 6), {
      label: "a.json",
      idPrefix: "1",
      importedAt: at(1),
    });
    expect(pushed).toHaveLength(1); // the first import of a case is a full merge: the whole case
    expect(first.forensicTimeline.length).toBe((await stateStore.load("inc")).forensicTimeline.length);
    const second = await p.importSiem("inc", siem("b", 6, 11), {
      label: "b.json",
      idPrefix: "2",
      importedAt: at(2),
    });
    expect(changed).toEqual(["inc"]);
    // The new rows, plus the stored rows it had to read to correlate them — never the whole case.
    const stored = (await stateStore.load("inc")).forensicTimeline;
    const newIds = stored.filter((e) => e.id.startsWith("2")).map((e) => e.id);
    expect(second.forensicTimeline.map((e) => e.id)).toEqual(expect.arrayContaining(newIds));
    expect(second.forensicTimeline.length).toBeLessThan(stored.length);
  });
});
