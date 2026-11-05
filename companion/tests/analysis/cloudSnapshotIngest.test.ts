import { describe, it, expect, beforeEach } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CaseStore } from "../../src/storage/caseStore.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { MockProvider } from "../../src/providers/provider.js";
import { AnalysisPipeline } from "../../src/analysis/pipeline.js";
import { CloudStateStore } from "../../src/analysis/cloudStateStore.js";
import { createImportIngest, type ImportIngestDeps } from "../../src/composition/importIngest.js";
import { ImportLock } from "../../src/analysis/importLock.js";
import type { InvestigationState } from "../../src/analysis/stateTypes.js";
import {
  ImportUndoStore,
  applyRedo,
  applyUndo,
  deltaCheckpoint,
  emptyUndoStack,
  encodeStack,
  normalizeStack,
  pushCheckpoint,
  runUndoStep,
} from "../../src/analysis/importUndo.js";

// #2305 end to end: MES snapshot CSVs through the real import spine (resolveImportKind →
// dispatchImport → AnalysisPipeline → case SQLite), with the per-case observation store wired as the
// server wires it. Re-import, change and out-of-order acceptance criteria, against the stored case.

const HEADER = [
  "UserName",
  "RuleName",
  "Enabled",
  "RuleIdentity",
  "MoveToFolder",
  "ForwardTo",
  "DeleteMessage",
];
const rules = (forward: string): string =>
  [
    HEADER.join(","),
    `"user1@example.com","r1","True","11","","${forward}","False"`,
    `"user2@example.com","news","True","12","Newsletters","","False"`,
  ].join("\n");

let ingest: ReturnType<typeof createImportIngest>;
let stateStore: StateStore;
let snapshots: CloudStateStore;
let undoStore: ImportUndoStore;
let root = "";
let seq = 0;

beforeEach(async () => {
  root = await mkdtemp(join(tmpdir(), "dfir-snapshot-"));
  seq = 0;
  await new CaseStore(root).createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: "mock" });
  wire();
});

/** A pipeline + import spine over the case root, wired as the server wires it. */
function wire(): void {
  const caseStore = new CaseStore(root);
  stateStore = new StateStore(caseStore);
  snapshots = new CloudStateStore(caseStore);
  undoStore = new ImportUndoStore(caseStore);
  const pipeline = new AnalysisPipeline({
    provider: new MockProvider("mock", "{}"),
    stateStore,
    imageLoader: async () => ({ base64: "AAAA", mimeType: "image/webp" }),
    cloudStateStore: snapshots,
  });
  ingest = createImportIngest({
    store: caseStore,
    options: { pipeline },
    runStateExclusive: async (_c: string, fn: () => Promise<unknown>) => fn(),
    importLock: new ImportLock(),
    recordImporterRun: () => {},
    redactErr: (err: unknown) => String(err),
    autoTagImported: async () => {},
    getControl: async () => ({ enabled: true }),
    applyWhitelistToCase: async () => ({ matched: 0, added: 0 }),
    applyNsrlToCase: async () => ({ matchedIocs: 0, matchedEvents: 0, added: 0 }),
    applyDeobfuscationToCase: async () => ({ deobfuscated: 0, newIocs: 0, reanalyzed: 0 }),
    resynthesizeInBackground: () => {},
  } as unknown as ImportIngestDeps);
}

/** Import as the route does: the stored name is the upload name behind a `NNNN_` sequence prefix. */
async function importAs(
  name: string,
  text: string,
  importedAt = "2026-11-05T00:00:00Z",
): Promise<InvestigationState> {
  seq++;
  const label = `${String(seq).padStart(4, "0")}_${name}`;
  const kind = ingest.resolveImportKind(name, text);
  expect(kind).toBe("cloudsnapshot");
  const before = await stateStore.load("c1");
  const after = (await ingest.dispatchImport(kind, "c1", text, {
    label,
    idPrefix: `${seq}`,
    importedAt,
  })) as InvestigationState;
  // What caseAppliers.pushImportCheckpoint does after the route's import: the checkpoint claims the
  // snapshot batches the import wrote.
  const checkpointLabel = `${kind} (${label})`;
  const snapshotBatches = await snapshots.claimBatches("c1", checkpointLabel);
  const built = deltaCheckpoint(checkpointLabel, importedAt, before, after);
  const checkpoint = snapshotBatches.length ? { ...built, snapshotBatches } : built;
  await undoStore.mutate("c1", (stack) => ({ stack: pushCheckpoint(stack, checkpoint), result: undefined }));
  return after;
}

const undoDeps = () => ({
  undoStore,
  stateStore,
  importLock: { runExclusive: <T>(_c: string, fn: () => Promise<T>) => fn() },
  runStateExclusive: <T>(_c: string, fn: () => Promise<T>) => fn(),
  snapshotState: snapshots,
});

const snapshotRows = async () =>
  (await stateStore.load("c1")).forensicTimeline.filter((e) => e.description.startsWith("M365 snapshot:"));

describe("snapshot import — observations, idempotence, order (#2305)", () => {
  it("first import: one observation per rule, at the MES collection time, honestly worded", async () => {
    await importAs("20261101-100000-MailboxRules.csv", rules("x@example.net"));
    const rows = await snapshotRows();
    expect(rows).toHaveLength(2);
    expect(rows.every((e) => e.timestamp === "2026-11-01T10:00:00Z")).toBe(true);
    expect(rows.every((e) => e.description.endsWith("state observed at collection; history unknown"))).toBe(
      true,
    );
    // Suspicious state reaches the forensic timeline above Info.
    const fwd = rows.find((e) => e.description.includes("x@example.net"));
    expect(fwd?.severity).toBe("High");
    expect(fwd?.mitreTechniques).toContain("T1114.003");
  });

  it("re-importing an unchanged snapshot adds 0 events — same file, and a copy with no file-name time", async () => {
    await importAs("20261101-100000-MailboxRules.csv", rules("x@example.net"));
    await importAs("20261101-100000-MailboxRules.csv", rules("x@example.net"));
    await importAs("InboxRules.csv", rules("x@example.net"), "2026-11-06T00:00:00Z");
    expect(await snapshotRows()).toHaveLength(2);
    const state = await stateStore.load("c1");
    expect(state.timeline.at(-1)?.description).toMatch(/2 unchanged or already imported/);
  });

  it("a changed rule adds exactly one change observation with a short diff", async () => {
    await importAs("20261101-100000-MailboxRules.csv", rules(""));
    await importAs("20261103-100000-MailboxRules.csv", rules("x@example.net"));
    const rows = await snapshotRows();
    expect(rows).toHaveLength(3);
    const change = rows.filter((e) => e.description.includes("state differs from the snapshot collected"));
    expect(change).toHaveLength(1);
    expect(change[0].timestamp).toBe("2026-11-03T10:00:00Z");
    expect(change[0].description).toContain('forwardto (empty) → "x@example.net"');
    expect(change[0].severity).toBe("High");
  });

  it("an older snapshot imported last announces no change", async () => {
    await importAs("20261103-100000-MailboxRules.csv", rules("x@example.net"));
    await importAs("20261101-100000-MailboxRules.csv", rules(""));
    const rows = await snapshotRows();
    expect(rows).toHaveLength(2);
    expect(rows.some((e) => e.description.includes("state differs"))).toBe(false);
  });

  it("the observation state is on disk: a fresh pipeline over the same case still dedups", async () => {
    await importAs("20261101-100000-MailboxRules.csv", rules("x@example.net"));
    wire(); // new stores and pipeline over the same case directory — what a server restart sees
    await importAs("20261101-100000-MailboxRules.csv", rules("x@example.net"));
    expect(await snapshotRows()).toHaveLength(2);
  });

  it("import → undo → re-import observes the state again (the evidence events come back)", async () => {
    await importAs("20261101-100000-MailboxRules.csv", rules("x@example.net"));
    expect(await snapshotRows()).toHaveLength(2);
    await runUndoStep(undoDeps(), "c1", applyUndo);
    expect(await snapshotRows()).toHaveLength(0);
    await importAs("20261101-100000-MailboxRules.csv", rules("x@example.net"));
    const rows = await snapshotRows();
    expect(rows).toHaveLength(2);
    expect(rows.find((e) => e.description.includes("x@example.net"))?.severity).toBe("High");
  });

  it("newer snapshot → undo → older snapshot compares against the remaining history only", async () => {
    await importAs("20261101-100000-MailboxRules.csv", rules(""));
    await importAs("20261103-100000-MailboxRules.csv", rules("x@example.net"));
    await runUndoStep(undoDeps(), "c1", applyUndo); // the newer snapshot is gone
    // An even older snapshot with a different state: the undone newer one must not make it "older".
    await importAs("20261030-100000-MailboxRules.csv", rules("y@example.net"));
    const rows = await snapshotRows();
    // The 11-01 observations remain; 10-30 is older than them, so no change is announced either way.
    expect(rows.some((e) => e.description.includes("x@example.net"))).toBe(false);
    // And a snapshot between 11-01 and the undone 11-03 is compared with 11-01, not suppressed.
    await importAs("20261102-100000-MailboxRules.csv", rules("z@example.net"));
    const change = (await snapshotRows()).filter((e) => e.description.includes("state differs"));
    expect(change).toHaveLength(1);
    expect(change[0].timestamp).toBe("2026-11-02T10:00:00Z");
    expect(change[0].description).toContain('forwardto (empty) → "z@example.net"');
  });

  it("redo remembers the batch again: a re-import after redo adds nothing", async () => {
    await importAs("20261101-100000-MailboxRules.csv", rules("x@example.net"));
    await runUndoStep(undoDeps(), "c1", applyUndo);
    await runUndoStep(undoDeps(), "c1", applyRedo);
    expect(await snapshotRows()).toHaveLength(2);
    await importAs("20261101-100000-MailboxRules.csv", rules("x@example.net"));
    expect(await snapshotRows()).toHaveLength(2);
  });

  it("the checkpoint's snapshot batches survive the undo-stack file format", async () => {
    await importAs("20261101-100000-MailboxRules.csv", rules("x@example.net"));
    const stack = await undoStore.load("c1");
    expect(stack.undo.at(-1)?.snapshotBatches).toEqual(["0001_20261101-100000-MailboxRules.csv"]);
    const again = normalizeStack(JSON.parse(encodeStack(stack).toString("utf8")));
    expect(again.undo.at(-1)?.snapshotBatches).toEqual(stack.undo.at(-1)?.snapshotBatches);
  });
});

// Evidence-first ordering (as #2301's ledger): Undo forgets the batch BEFORE the state drops the
// events, Redo remembers it only AFTER the state has them back, and a failed step puts it back.
describe("snapshot batches in an undo step — evidence-first (#2305)", () => {
  const S0 = { caseId: "c1", forensicTimeline: [], iocs: [], findings: [] } as unknown as InvestigationState;
  const S1 = {
    ...S0,
    forensicTimeline: [{ id: "e1", timestamp: "2026-11-01T00:00:00Z", description: "d", severity: "High" }],
  } as unknown as InvestigationState;

  it("orders the writes and rolls the flip back when the stack write fails", async () => {
    const cases = new CaseStore(await mkdtemp(join(tmpdir(), "dfir-snapshot-undo-")));
    await cases.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
    const store = new ImportUndoStore(cases);
    let state = S1;
    const order: string[] = [];
    const deps = {
      undoStore: store,
      stateStore: {
        load: async () => state,
        save: async (s: InvestigationState) => {
          order.push("state");
          state = s;
        },
      },
      importLock: { runExclusive: <T>(_c: string, fn: () => Promise<T>) => fn() },
      runStateExclusive: <T>(_c: string, fn: () => Promise<T>) => fn(),
      snapshotState: {
        setBatchesActive: async (_c: string, b: string[], active: boolean) => {
          order.push(`${active ? "remember" : "forget"}:${b.join(",")}`);
        },
      },
    };
    const cp = {
      ...deltaCheckpoint("cloudsnapshot (0001_x.csv)", "t", S0, S1),
      snapshotBatches: ["0001_x.csv"],
    };
    await store.save("c1", pushCheckpoint(emptyUndoStack(), cp));
    await runUndoStep(deps, "c1", applyUndo);
    await runUndoStep(deps, "c1", applyRedo);
    expect(order).toEqual(["forget:0001_x.csv", "state", "state", "remember:0001_x.csv"]);
    order.length = 0;
    const save = store.save.bind(store);
    store.save = async () => {
      throw new Error("disk full");
    };
    await expect(runUndoStep(deps, "c1", applyUndo)).rejects.toThrow("disk full");
    store.save = save;
    expect(order).toEqual(["forget:0001_x.csv", "state", "state", "remember:0001_x.csv"]);
  });
});
