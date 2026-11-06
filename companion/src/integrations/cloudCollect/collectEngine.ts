// One collection run, start or resume (#2311): replay → network stage → import stage → result.
//
//   <case>/evidence/cloud/<collectionId>/
//     manifest.jsonl     append-only: header, one line per page, restart/quarantine/resume notes
//     checkpoint.json    the summary the panel reads, written last in every page commit
//     pages/             every page the cloud returned, byte for byte (SHA-256 in the manifest)
//     quarantine/        orphan and corrupt pages — moved, hashed, listed, never deleted
//
// The result is COMPLETE (every sub-window's results exhausted), PARTIAL (some windows missing,
// each with its reason) or FAILED (nothing collected). "Complete" is the source's available
// results for the disclosed window: per source, the checkpoint's `coverage` (#2312) states the
// acquired cutoff and the retention limits, and a split tree is judged on its leaves.

import type { CollectFs } from "./collectFs.js";
import { appendManifest, collectionPaths, type CollectionPaths } from "./collectManifest.js";
import { readCheckpoint, writeCheckpoint } from "./collectCheckpoint.js";
import { initialSubWindows, replayCollection, retrySkipped, windowsToRetry } from "./collectReplay.js";
import { runNetworkStage } from "./collectNetwork.js";
import { runImportStage, type CollectPageImporter } from "./collectImport.js";
import { leaves } from "./collectSplit.js";
import { skippedNote, sourceCoverage } from "./collectCoverage.js";
import type { QueryBudget } from "./collectBudget.js";
import type { CollectClock } from "./collectRateLimit.js";
import type {
  CloudCollectSession,
  CollectSourceInfo,
  CollectWindow,
  CollectionCheckpoint,
  CollectionStatus,
  ManifestHeader,
  MissingWindow,
  SubWindowStatus,
} from "./collectTypes.js";
import type { CloudProvider } from "../cloudAccounts/types.js";

export interface CollectProgress {
  stage: "network" | "import";
  pages: number;
  records: number;
  imported: number;
  /** Per source: pages and records saved so far. */
  sources: Array<{ source: string; pages: number; records: number; state: string }>;
}

export interface CollectRunDeps {
  fs: CollectFs;
  session: CloudCollectSession;
  importer: CollectPageImporter;
  sources: readonly CollectSourceInfo[];
  now: () => string;
  signal?: AbortSignal;
  onProgress?: (progress: CollectProgress) => void;
  /** #2312: pacing clock, the tenant's daily query budget, the throttle retry budget. */
  clock?: CollectClock;
  budget?: QueryBudget;
  retryBudget?: number;
}

export interface NewCollection {
  dir: string;
  collectionId: string;
  caseId: string;
  accountId: string;
  accountName: string;
  provider: CloudProvider;
  sources: string[];
  window: CollectWindow;
  filters: Record<string, string>;
  companionVersion: string;
  jobId?: string;
  /** Per source: the ingestion-delay overlap the cutoff is disclosed with (#2312). */
  overlapMs?: Record<string, number>;
}

function sourceProgress(subWindows: readonly SubWindowStatus[]): CollectProgress["sources"] {
  const by = new Map<string, { source: string; pages: number; records: number; state: string }>();
  const RANK: Record<string, number> = { done: 0, incomplete: 1, pending: 2, capped: 2, failed: 3 };
  for (const sw of subWindows) {
    const prev = by.get(sw.source) ?? { source: sw.source, pages: 0, records: 0, state: "done" };
    // A split parent's pages count; its state does not — its children carry it (#2312).
    const mine = sw.state === "split" ? "done" : sw.state === "capped" ? "pending" : sw.state;
    const state = (RANK[mine] ?? 0) > (RANK[prev.state] ?? 0) ? mine : prev.state;
    by.set(sw.source, { ...prev, pages: prev.pages + sw.pages, records: prev.records + sw.records, state });
  }
  return [...by.values()];
}

/** Which windows are missing, and why. Pure. */
export function missingWindows(subWindows: readonly SubWindowStatus[], stopReason?: string): MissingWindow[] {
  return leaves(subWindows)
    .filter((sw) => sw.state !== "done" || (sw.skipped ?? 0) > 0)
    .map((sw) => ({
      source: sw.source,
      subWindowId: sw.id,
      window: sw.window,
      reason:
        sw.state === "done"
          ? (skippedNote([sw]) ?? "not collected")
          : (sw.reason ?? stopReason ?? "not collected"),
    }));
}

/** complete / partial / failed. Pure. */
export function collectionStatus(
  subWindows: readonly SubWindowStatus[],
  pagesSaved: number,
): CollectionStatus {
  const tree = leaves(subWindows);
  const skipped = tree.some((sw) => (sw.skipped ?? 0) > 0); // an unresolved refusal (#2313)
  if (!skipped && tree.every((sw) => sw.state === "done")) return "complete";
  return pagesSaved > 0 || skipped ? "partial" : "failed";
}

/** Create the folder, write the header and the first checkpoint. The run itself is runCollection. */
export async function createCollection(
  fs: CollectFs,
  session: CloudCollectSession,
  input: NewCollection,
  now: () => string,
  signal?: AbortSignal,
): Promise<void> {
  const paths = collectionPaths(input.dir);
  const identity = await session.identity(signal);
  await fs.mkdir(paths.dir);
  await fs.mkdir(paths.pages);
  const startedAt = now();
  const header: ManifestHeader = {
    type: "header",
    version: 1,
    collectionId: input.collectionId,
    provider: input.provider,
    accountId: input.accountId,
    accountName: input.accountName,
    accountRef: identity.accountRef,
    caller: identity.caller,
    sources: input.sources,
    window: input.window,
    filters: input.filters,
    sdkVersions: identity.sdkVersions,
    companionVersion: input.companionVersion,
    startedAt,
    ...(input.overlapMs ? { overlapMs: input.overlapMs } : {}),
  };
  await appendManifest(fs, paths, header);
  await writeCheckpoint(fs, paths, {
    version: 1,
    collectionId: input.collectionId,
    caseId: input.caseId,
    accountId: input.accountId,
    provider: input.provider,
    sources: input.sources,
    window: input.window,
    ...(input.jobId ? { jobId: input.jobId } : {}),
    status: "running",
    stage: "network",
    subWindows: initialSubWindows(input.sources, input.window),
    imported: [],
    quarantined: [],
    missing: [],
    startedAt,
    updatedAt: startedAt,
  });
}

async function baseCheckpoint(
  deps: CollectRunDeps,
  paths: CollectionPaths,
  caseId: string,
): Promise<CollectionCheckpoint> {
  const cp = await readCheckpoint(deps.fs, paths);
  if (cp) return cp;
  throw new Error(`collection checkpoint is missing or unreadable for case ${caseId}`);
}

/** Start or resume: replay, fetch what is unfinished, import what is not yet in the case. */
export async function runCollection(
  deps: CollectRunDeps,
  dir: string,
  opts: { resume: boolean; jobId?: string },
): Promise<CollectionCheckpoint> {
  const paths = collectionPaths(dir);
  const replay = await replayCollection(deps.fs, paths, deps.now);
  let cp = await baseCheckpoint(deps, paths, replay.header.collectionId);
  let derived = replay.subWindows;
  if (opts.resume) {
    await appendManifest(deps.fs, paths, { type: "resume", at: deps.now() });
    // #2313: a resume retries every window with an item the cloud refused. The restart line is
    // written first, so a crash after it replays to the same restarted window.
    for (const id of windowsToRetry(derived)) {
      await appendManifest(deps.fs, paths, {
        type: "restart",
        subWindowId: id,
        reason: "skipped-retry",
        at: deps.now(),
      });
      derived = retrySkipped(derived, id);
    }
  }
  const failedReasons = new Map(cp.subWindows.filter((s) => s.reason).map((s) => [s.id, s.reason]));
  const save = async (patch: Partial<CollectionCheckpoint>): Promise<void> => {
    cp = { ...cp, ...patch, updatedAt: deps.now() };
    await writeCheckpoint(deps.fs, paths, cp);
  };
  await save({
    status: "running",
    stage: "network",
    ...(opts.jobId ? { jobId: opts.jobId } : {}),
    subWindows: derived.map((s) =>
      failedReasons.has(s.id) && s.state !== "done" ? { ...s, reason: failedReasons.get(s.id) } : s,
    ),
    quarantined: replay.quarantined,
    stopReason: undefined,
    error: undefined,
  });
  const report = (stage: CollectProgress["stage"], subWindows: SubWindowStatus[], imported: number): void => {
    const sources = sourceProgress(subWindows);
    deps.onProgress?.({
      stage,
      pages: sources.reduce((n, s) => n + s.pages, 0),
      records: sources.reduce((n, s) => n + s.records, 0),
      imported,
      sources,
    });
  };
  const network = await runNetworkStage(
    {
      fs: deps.fs,
      paths,
      session: deps.session,
      now: deps.now,
      sources: deps.sources,
      ...(deps.clock ? { clock: deps.clock } : {}),
      ...(deps.budget ? { budget: deps.budget } : {}),
      ...(deps.retryBudget !== undefined ? { retryBudget: deps.retryBudget } : {}),
      ...(deps.signal ? { signal: deps.signal } : {}),
      onChange: async (subWindows) => {
        await save({ subWindows });
        report("network", subWindows, cp.imported.length);
      },
    },
    { subWindows: cp.subWindows, nextSeq: replay.nextSeq },
  );
  await save({
    subWindows: network.subWindows,
    stage: "import",
    ...(network.stopReason ? { stopReason: network.stopReason } : {}),
  });
  const kinds = new Map(deps.sources.map((s) => [s.id, s.streamKind]));
  const imported = new Set(cp.imported);
  await runImportStage(deps.importer, {
    caseId: cp.caseId,
    collectionId: cp.collectionId,
    dir,
    pagesDir: paths.pages,
    pages: [...replay.validPages, ...network.pages],
    abandoned: replay.abandonedPages,
    streamKindOf: (source) => kinds.get(source),
    imported,
    ...(deps.signal ? { signal: deps.signal } : {}),
    onImported: async (file) => {
      imported.add(file);
      await save({ imported: [...imported] });
      report("import", network.subWindows, imported.size);
    },
  });
  const pagesSaved = replay.validPages.length + network.pages.length;
  await save({
    stage: "done",
    status: collectionStatus(network.subWindows, pagesSaved),
    missing: missingWindows(network.subWindows, network.stopReason),
    coverage: sourceCoverage(network.subWindows, deps.sources, {
      sources: cp.sources,
      window: cp.window,
      ...(replay.header.overlapMs ? { overlapMs: replay.header.overlapMs } : {}),
      startedAt: replay.header.startedAt,
    }),
  });
  return cp;
}

/** Mark a run that ended in an error: the collection stays resumable. */
export async function markCollectionStopped(
  fs: CollectFs,
  dir: string,
  status: CollectionStatus,
  error: string,
  now: () => string,
): Promise<void> {
  const paths = collectionPaths(dir);
  const cp = await readCheckpoint(fs, paths);
  if (!cp) return;
  await writeCheckpoint(fs, paths, { ...cp, status, error: error.slice(0, 500), updatedAt: now() });
}
