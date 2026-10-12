import { describe, expect, it } from "vitest";
import { mkdir, mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CaseStore } from "../../src/storage/caseStore.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { ImportLock } from "../../src/analysis/importLock.js";
import type { ForensicEvent } from "../../src/analysis/stateTypes.js";
import type { TimelineDiff } from "../../src/analysis/timelineDiff.js";
import { registerImportResumeHandler } from "../../src/routes/importRecovery.js";
import type { RouteContext } from "../../src/routes/context.js";

type ResumeHandler = (job: unknown, signal: AbortSignal) => Promise<unknown>;

// #2144: the import resume settled inline with no import lock, so a live import could write between
// its baseline load and its diff — and the resumed file's import-meta "+N events" and run receipt
// then counted the other import's rows as its own. The resume now holds the case's import section
// from the baseline through the records, and releases it on success, failure and cancel.

const STORED = "0005_hayabusa.json";

function row(id: string, description: string, source: string): ForensicEvent {
  return {
    id,
    timestamp: "2026-10-01T10:00:00Z",
    description,
    severity: "High",
    mitreTechniques: [],
    relatedFindingIds: [],
    sourceScreenshots: [source],
  };
}

interface Deferred {
  promise: Promise<void>;
  resolve: () => void;
  reject: (error: Error) => void;
}

function deferred(): Deferred {
  let resolve!: () => void;
  let reject!: (error: Error) => void;
  const promise = new Promise<void>((res, rej) => {
    resolve = res;
    reject = rej;
  });
  return { promise, resolve, reject };
}

async function appendRows(stateStore: StateStore, rows: ForensicEvent[]): Promise<void> {
  const state = await stateStore.load("c1");
  await stateStore.save({ ...state, forensicTimeline: [...state.forensicTimeline, ...rows] });
}

async function harness() {
  const root = await mkdtemp(join(tmpdir(), "dfir-resume-lock-"));
  const store = new CaseStore(root);
  await store.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  const stateStore = new StateStore(store);
  await mkdir(store.importsDir("c1"), { recursive: true });
  await writeFile(join(store.importsDir("c1"), STORED), "[]", "utf8");
  const importLock = new ImportLock();
  const gate = deferred();
  const dispatchStarted = deferred();
  const recorded: TimelineDiff[] = [];
  let handler: ResumeHandler | undefined;
  const dispatchImport = async (): Promise<void> => {
    dispatchStarted.resolve();
    await gate.promise;
    await appendRows(stateStore, [
      row("r1", "resumed row one", STORED),
      row("r2", "resumed row two", STORED),
    ]);
  };
  const ctx = {
    store,
    importLock,
    options: {
      pipeline: {},
      stateStore,
      importMetaStore: {
        record: async (_c: string, meta: { diff: TimelineDiff }) => recorded.push(meta.diff),
      },
      jobManager: {
        registerResumeHandler: (_k: string, h: ResumeHandler) => (handler = h),
        checkpoint: async () => {},
        progress: () => {},
        warn: async () => {},
      },
    },
    dispatchImport,
    demoteForensicForCase: async (caseId: string) => stateStore.load(caseId),
    applyWhitelistToCase: async () => ({ added: 0 }),
    applyNsrlToCase: async () => ({ added: 0 }),
    applyDeobfuscationToCase: async () => ({ added: 0 }),
    recordImportFailure: () => {},
    resynthesizeInBackground: () => {},
    serverLogger: { info: () => {}, warn: () => {}, debug: () => {}, error: () => {} },
  } as unknown as RouteContext;
  registerImportResumeHandler(ctx);
  const job = {
    id: "j1",
    caseId: "c1",
    kind: "import",
    parameters: {
      kind: "hayabusa",
      storedName: STORED,
      sequence: 5,
      importedAt: "2026-10-01T09:00:00.000Z",
      minSeverity: null,
      streaming: false,
    },
  };
  const controller = new AbortController();
  return {
    resume: () => handler!(job, controller.signal),
    importLock,
    stateStore,
    gate,
    dispatchStarted,
    recorded,
  };
}

describe("import resume holds the case's import section (#2144)", () => {
  it("holds the lock while dispatch runs, and a queued writer waits until the resume's records are written", async () => {
    const h = await harness();
    const resumed = h.resume();
    await h.dispatchStarted.promise;
    expect(h.importLock.isBusy("c1")).toBe(true);
    // -1 = not run yet; otherwise how many import-meta records existed when the writer got the lock.
    let recordsWhenRun = -1;
    const writer = h.importLock.runExclusive("c1", async () => {
      recordsWhenRun = h.recorded.length;
    });
    await new Promise((r) => setTimeout(r, 20));
    expect(recordsWhenRun).toBe(-1);
    h.gate.resolve();
    await resumed;
    await writer;
    expect(recordsWhenRun).toBe(1);
  });

  it("credits only the resumed file's rows when another import writes concurrently", async () => {
    const h = await harness();
    const resumed = h.resume();
    await h.dispatchStarted.promise;
    const foreign = h.importLock.runExclusive("c1", () =>
      appendRows(h.stateStore, [row("f1", "foreign push row", "0006_other.json")]),
    );
    // Give an unlocked writer every chance to land inside the resume's baseline → diff window.
    await new Promise((r) => setTimeout(r, 50));
    h.gate.resolve();
    await resumed;
    await foreign;
    expect(h.recorded).toHaveLength(1);
    expect(h.recorded[0].added.map((e) => e.description).sort()).toEqual([
      "resumed row one",
      "resumed row two",
    ]);
    const final = await h.stateStore.load("c1");
    expect(final.forensicTimeline.map((e) => e.id).sort()).toEqual(["f1", "r1", "r2"]);
  });

  it("releases the lock when dispatch fails, so the case is not wedged", async () => {
    const h = await harness();
    const resumed = h.resume();
    await h.dispatchStarted.promise;
    h.gate.reject(new Error("parse exploded"));
    await expect(resumed).rejects.toThrow(/parse exploded/);
    await expect(h.importLock.runExclusive("c1", async () => "ran")).resolves.toBe("ran");
    expect(h.importLock.isBusy("c1")).toBe(false);
  });

  it("releases the lock when the resume is cancelled", async () => {
    const h = await harness();
    const resumed = h.resume();
    await h.dispatchStarted.promise;
    const abort = new Error("cancelled");
    abort.name = "AbortError";
    h.gate.reject(abort);
    await expect(resumed).rejects.toThrow(/cancelled/);
    await expect(h.importLock.runExclusive("c1", async () => "ran")).resolves.toBe("ran");
  });
});
