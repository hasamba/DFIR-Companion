/**
 * Shared wiring for the hunt-export drop tests (#2714): a real CaseStore and drop folder, the real
 * import-kind detection, and a recording ingest stub. Synthetic data only.
 */
import { vi } from "vitest";
import { mkdtemp, readdir, readFile, stat, writeFile, mkdir } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, relative } from "node:path";
import { CaseStore } from "../../src/storage/caseStore.js";
import { DropStatusStore } from "../../src/analysis/dropStatus.js";
import type { JobManager } from "../../src/analysis/jobManager.js";
import { detectImportWithCustomEx } from "../../src/analysis/importDecision.js";
import { createDropFolder, dropDirOf, type DropFolder } from "../../src/composition/dropFolder.js";
import { rowKeysOf } from "./huntExportFixture.js";
import { pollFor } from "./poll.js";

export interface IngestCall {
  kind: string;
  name: string;
  text: string;
  host: string | undefined;
}

export interface Harness {
  store: CaseStore;
  dropDir: string;
  calls: IngestCall[];
  /** Make the next ingest of a file with this basename throw. */
  failOn: Set<string>;
  /** After N successful calls, the next ingest never settles — the process "dies" mid-import. */
  hangAfter: number | null;
  /** Called after each successful ingest call, with the number of calls so far. */
  onIngest: ((n: number) => Promise<void> | void) | null;
  drops: DropFolder;
  /** The Jobs manager the sweep reports to, when the test passed one (#2742). */
  jobManager?: JobManager;
  sweep(): Promise<void>;
  /** Start a sweep and abandon it once ingest hangs (the crash), without awaiting it. */
  sweepUntilHang(): Promise<void>;
  /** A new drop folder over the same case dir — what a restart sees (no in-memory state). */
  restart(): void;
  rowKeys(): string[];
}

export async function makeHarness(
  opts: { dropMaxBytes?: number; jobManager?: JobManager } = {},
): Promise<Harness> {
  const root = await mkdtemp(join(tmpdir(), "dfir-drop-hunt-"));
  const store = new CaseStore(root);
  await store.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  const dropDir = dropDirOf(store, "c1");
  await mkdir(dropDir, { recursive: true });
  if (opts.dropMaxBytes) process.env.DFIR_DROP_MAX_BYTES = String(opts.dropMaxBytes);
  else delete process.env.DFIR_DROP_MAX_BYTES;
  const h: Harness = {
    store,
    dropDir,
    calls: [],
    failOn: new Set(),
    hangAfter: null,
    onIngest: null,
    drops: undefined as unknown as DropFolder,
    ...(opts.jobManager ? { jobManager: opts.jobManager } : {}),
    sweep: async () => {
      await h.drops.scanCaseDrops("c1");
    },
    sweepUntilHang: async () => {
      void h.drops.scanCaseDrops("c1");
      await pollFor("ingest to hang (the simulated crash)", async () => (h.hangAfter === null ? true : null));
    },
    restart: () => {
      h.drops = build(h);
    },
    rowKeys: () => h.calls.flatMap((c) => rowKeysOf(c.name, c.text, c.host)).sort(),
  };
  h.drops = build(h);
  return h;
}

function build(h: Harness): DropFolder {
  const ingestStreamed = vi.fn(
    async (
      _caseId: string,
      kind: string,
      text: string,
      name: string,
      _min?: undefined,
      _prov?: undefined,
      host?: string,
    ) => {
      if (h.hangAfter !== null && h.calls.length >= h.hangAfter) {
        h.hangAfter = null;
        return new Promise<never>(() => undefined); // abandoned with the "dead" process
      }
      if (h.failOn.has(name)) throw new Error(`synthetic parse failure in ${name}`);
      h.calls.push({ kind, name, text, host });
      await h.onIngest?.(h.calls.length);
      return { storedName: "s", addedEvents: 1, addedIocs: 0, analyzed: true };
    },
  );
  const refuse = (): never => {
    throw new Error("not expected");
  };
  return createDropFolder({
    store: h.store,
    options: {
      dropStatusStore: new DropStatusStore(h.store),
      ...(h.jobManager ? { jobManager: h.jobManager } : {}),
    },
    hasAiProvider: () => false,
    getControl: refuse,
    recordImportFailure: () => {},
    dispatchNotify: () => {},
    resolveImportKind: (filename, text, debug) => {
      const r = detectImportWithCustomEx(filename, text, new Map(), "builtin-first");
      debug?.detected(r.kind, { confident: r.confident, decision: r.decision });
      return r.kind;
    },
    ingestStreamed,
    ingestMacLoginItemBinary: refuse,
    ingestDiskFile: refuse,
    liveToolConfigs: () => new Map(),
    resolveToolForExt: () => null,
    rawExtClaimed: () => false,
    runDropToolAndIngest: refuse,
    indexCaptureText: refuse,
    captureBuffers: new Map(),
    flush: refuse,
  });
}

/** Every file under `dir`, relative and `/`-separated. */
export async function listFiles(dir: string): Promise<string[]> {
  const out: string[] = [];
  const walk = async (d: string): Promise<void> => {
    let entries;
    try {
      entries = await readdir(d, { withFileTypes: true });
    } catch {
      return;
    }
    for (const e of entries) {
      const full = join(d, e.name);
      if (e.isDirectory()) await walk(full);
      else out.push(relative(dir, full).replace(/\\/g, "/"));
    }
  };
  await walk(dir);
  return out.sort();
}

export async function dropLog(dropDir: string): Promise<string> {
  return readFile(join(dropDir, "drop-log.txt"), "utf8").catch(() => "");
}

export async function writeBuffer(path: string, data: Buffer): Promise<void> {
  await writeFile(path, data);
}

export async function exists(path: string): Promise<boolean> {
  return stat(path).then(
    () => true,
    () => false,
  );
}
