// Fakes for the cloud collection engine tests (#2311): a provider with scripted pages, a filesystem
// that can fail at any step, and a page importer over a real AnalysisPipeline in a temp case.

import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CaseStore } from "../../src/storage/caseStore.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { SuperTimelineStore } from "../../src/analysis/superTimelineStore.js";
import { CloudRecordStore } from "../../src/analysis/cloudRecordStore.js";
import { AuthObservationStore } from "../../src/analysis/authObservationStore.js";
import { CloudCoverageStore } from "../../src/analysis/cloudCoverage.js";
import { AnalysisPipeline } from "../../src/analysis/pipeline.js";
import { nodeCollectFs, type CollectFs } from "../../src/integrations/cloudCollect/collectFs.js";
import {
  CursorExpiredError,
  type CloudCollectSession,
  type CollectPage,
  type CollectPageRequest,
} from "../../src/integrations/cloudCollect/collectTypes.js";
import {
  ledgerForget,
  timelineLanded,
  type CollectPageImporter,
} from "../../src/integrations/cloudCollect/collectImport.js";
import { summarizesPerCollection } from "../../src/analysis/ingest/cloudStreamProviders.js";

/** A CloudTrail record. Synthetic: documentation account id, TEST-NET source address. */
export function trailRecord(i: number, name = i % 3 === 0 ? "StopLogging" : "CreateAccessKey") {
  return {
    eventVersion: "1.09",
    eventID: `00000000-0000-4000-b000-${String(i).padStart(12, "0")}`,
    eventTime: `2026-10-01T10:${String(i % 60).padStart(2, "0")}:00Z`,
    // The real service per operation: grading now checks the event source (#2358).
    eventSource: /^(StopLogging|StartLogging|DeleteTrail|UpdateTrail|PutEventSelectors)$/.test(name)
      ? "cloudtrail.amazonaws.com"
      : "iam.amazonaws.com",
    eventName: name,
    awsRegion: "us-east-1",
    sourceIPAddress: "198.51.100.7",
    userIdentity: {
      type: "IAMUser",
      arn: `arn:aws:iam::123456789012:user/ops${i}`,
      accountId: "123456789012",
      userName: `ops${i}`,
    },
  };
}

export interface FakeProviderOptions {
  /** Records per page, per page index. */
  pages: number;
  perPage?: number;
  /** Tokens whose next use throws CursorExpiredError once. */
  expireOnce?: string[];
  /** Throw a provider error on this page index. */
  failPage?: number;
}

/** A session that serves `pages` CloudTrail pages per sub-window, tokens "t1", "t2", … */
export function fakeSession(
  opts: FakeProviderOptions,
): CloudCollectSession & { calls: CollectPageRequest[] } {
  const perPage = opts.perPage ?? 3;
  const expired = new Set(opts.expireOnce ?? []);
  const calls: CollectPageRequest[] = [];
  return {
    calls,
    identity: async () => ({
      accountRef: "123456789012",
      caller: "arn:aws:iam::123456789012:role/collector",
      sdkVersions: { fake: "1.0.0" },
    }),
    fetchPage: async (req): Promise<CollectPage> => {
      calls.push(req);
      if (req.pageToken && expired.has(req.pageToken)) {
        expired.delete(req.pageToken);
        throw new CursorExpiredError();
      }
      const index = req.pageToken ? Number(req.pageToken.slice(1)) : 0;
      if (opts.failPage === index) throw new Error("AccessDenied on this page");
      const records = Array.from({ length: perPage }, (_, k) => trailRecord(index * perPage + k + 1));
      const next = index + 1 < opts.pages ? `t${index + 1}` : undefined;
      return {
        body: Buffer.from(JSON.stringify({ Records: records })),
        extension: "json",
        recordCount: records.length,
        ...(next ? { nextPageToken: next } : {}),
        requestId: `req-${index}`,
        requestParams: { page: String(index), source: req.source },
      };
    },
  };
}

export type FsOp = keyof CollectFs;
type Fault = { op: FsOp; match: (path: string) => boolean; error: () => Error; once: boolean; hits: number };

/** The real fs, with faults injected by operation and path. */
export function faultFs(): CollectFs & {
  inject(op: FsOp, match: (path: string) => boolean, error: () => Error, once?: boolean): void;
  clear(): void;
} {
  let faults: Fault[] = [];
  const check = (op: FsOp, path: string): void => {
    const fault = faults.find((f) => f.op === op && f.match(path) && (!f.once || f.hits === 0));
    if (!fault) return;
    fault.hits++;
    throw fault.error();
  };
  const wrap =
    <A extends unknown[], R>(op: FsOp, fn: (...args: A) => Promise<R>) =>
    async (...args: A): Promise<R> => {
      check(op, String(args[0]));
      return fn(...args);
    };
  return {
    mkdir: wrap("mkdir", nodeCollectFs.mkdir),
    writeFileSync: wrap("writeFileSync", nodeCollectFs.writeFileSync),
    rename: wrap("rename", nodeCollectFs.rename),
    fsyncDir: wrap("fsyncDir", nodeCollectFs.fsyncDir),
    appendSync: wrap("appendSync", nodeCollectFs.appendSync),
    truncate: wrap("truncate", nodeCollectFs.truncate),
    readFile: wrap("readFile", nodeCollectFs.readFile),
    readdir: wrap("readdir", nodeCollectFs.readdir),
    exists: wrap("exists", nodeCollectFs.exists),
    hashFile: wrap("hashFile", nodeCollectFs.hashFile),
    inject(op, match, error, once = true) {
      faults = [...faults, { op, match, error, once, hits: 0 }];
    },
    clear() {
      faults = [];
    },
  };
}

/** A simulated process kill: no errno code, so nothing classifies it as a disk error. */
export const kill = (): Error => Object.assign(new Error("simulated kill"), { name: "SimulatedKill" });
export const diskFull = (): Error => Object.assign(new Error("no space left on device"), { code: "ENOSPC" });

export async function tempCase() {
  const root = await mkdtemp(join(tmpdir(), "dfir-cloudcollect-"));
  const cases = new CaseStore(root);
  await cases.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  const stateStore = new StateStore(cases);
  const superTimelineStore = new SuperTimelineStore(cases);
  const cloudRecordStore = new CloudRecordStore(cases);
  const pipeline = new AnalysisPipeline({
    stateStore,
    superTimelineStore,
    cloudRecordStore,
    cloudCoverageStore: new CloudCoverageStore(cases),
    authObservationStore: new AuthObservationStore(cases, 168),
    imageLoader: async () => ({ base64: "AAAA", mimeType: "image/webp" }),
  });
  return {
    root,
    cases,
    stateStore,
    superTimelineStore,
    cloudRecordStore,
    pipeline,
    dir: join(cases.caseDir("c1"), "evidence", "cloud", "cc-test-abc123"),
  };
}

export type TempCase = Awaited<ReturnType<typeof tempCase>>;

/**
 * The page importer over the real pipeline. `hooks.duringPage` runs after each streamed batch and
 * may throw a kill; `hooks.noCleanup` makes the importer's own failure cleanup a no-op, which is
 * what a hard kill leaves on disk (its catch never ran). The collection summary (#2482) is built
 * through the real pipeline too, and its rows are copied to the super-timeline the way the
 * production settle's dual-write does (an id the store holds is skipped).
 */
export function pipelineImporter(
  t: TempCase,
  hooks: { duringPage?: (label: string, batch: number) => void; noCleanup?: () => boolean } = {},
): CollectPageImporter & { imports: string[]; summaries: string[] } {
  const imports: string[] = [];
  const summaries: string[] = [];
  const ledger = {
    claimBatches: (c: string, l: string) => t.cloudRecordStore.claimBatches(c, l),
    setBatchesActive: (c: string, b: string[], a: boolean) => t.cloudRecordStore.setBatchesActive(c, b, a),
  };
  return {
    imports,
    summaries,
    withImportSection: (_caseId, fn) => fn(),
    summarizesPerCollection,
    importSummary: async (caseId, req, signal) => {
      summaries.push(req.label);
      const { state } = await t.pipeline.importCloudCollectionSummary(caseId, req.kind, req.pages, {
        collectionId: req.collectionId,
        label: req.label,
        idPrefix: req.idPrefix,
        importedAt: req.importedAt,
        ...(signal ? { signal } : {}),
      });
      const rows = state.forensicTimeline.filter((e) => e.sourceScreenshots.includes(req.label));
      await t.superTimelineStore.appendReporting(caseId, rows);
    },
    landed: timelineLanded(t.stateStore),
    forgetAttempt: ledgerForget(ledger),
    settleLanded: async () => {},
    importPage: async (caseId, page, signal) => {
      imports.push(page.label);
      let batch = 0;
      const store = t.cloudRecordStore;
      const original = store.setBatchesActive.bind(store);
      if (hooks.noCleanup?.()) store.setBatchesActive = async () => {};
      try {
        await t.pipeline.importCloudFile(caseId, page.kind, page.path, {
          label: page.label,
          idPrefix: page.idPrefix,
          importedAt: page.importedAt,
          batchRecords: 1,
          skipSummaries: summarizesPerCollection(page.kind),
          ...(signal ? { signal } : {}),
          onProgress: () => hooks.duringPage?.(page.label, ++batch),
        });
      } finally {
        store.setBatchesActive = original;
      }
    },
  };
}
