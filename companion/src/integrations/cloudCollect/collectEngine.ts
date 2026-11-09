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
import { appendManifest, collectionPaths, loadManifest, type CollectionPaths } from "./collectManifest.js";
import {
  checkpointFromManifest,
  collectionIdsOf,
  readCheckpoint,
  writeCheckpoint,
} from "./collectCheckpoint.js";
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
  WalkPosition,
} from "./collectTypes.js";
import type { CloudProvider } from "../cloudAccounts/types.js";

export interface CollectProgress {
  stage: "network" | "import";
  pages: number;
  records: number;
  imported: number;
  /** Per source: pages and records saved so far, and what the cloud is doing now (#2315). */
  sources: Array<{
    source: string;
    pages: number;
    records: number;
    state: string;
    status?: string;
    /** #2384: folders (or other walk units) finished, of the total; absent when unknowable. */
    walk?: WalkPosition;
    /** #2384: a sub-window is still downloading — even when the aggregate state says "failed". */
    running?: boolean;
  }>;
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

export function sourceProgress(subWindows: readonly SubWindowStatus[]): CollectProgress["sources"] {
  const by = new Map<string, CollectProgress["sources"][number]>();
  const RANK: Record<string, number> = { done: 0, incomplete: 1, pending: 2, capped: 2, failed: 3 };
  for (const sw of subWindows) {
    const prev = by.get(sw.source) ?? { source: sw.source, pages: 0, records: 0, state: "done" };
    // A split parent's pages count; its state does not — its children carry it (#2312).
    const mine = sw.state === "split" ? "done" : sw.state === "capped" ? "pending" : sw.state;
    const state = (RANK[mine] ?? 0) > (RANK[prev.state] ?? 0) ? mine : prev.state;
    const status = sw.providerStatus ?? prev.status;
    by.set(sw.source, {
      ...prev,
      pages: prev.pages + sw.pages,
      records: prev.records + sw.records,
      state,
      ...(status ? { status } : {}),
    });
  }
  return [...by.values()].map((p) => {
    const mine = subWindows.filter((sw) => sw.source === p.source);
    const running = mine.some((sw) => sw.state === "pending" || sw.state === "capped");
    const walk = walkOf(mine);
    return { ...p, running, ...(walk ? { walk } : {}) };
  });
}

const SETTLED = new Set(["done", "failed", "incomplete"]);

/**
 * #2384: a source's position in its fixed walk, summed over its unsplit sub-windows; a settled one
 * counts as finished. Undefined when any unsettled sub-window has not stated one yet: a guess
 * there would be the fake "one page left" ETA this replaces.
 */
function walkOf(subWindows: readonly SubWindowStatus[]): WalkPosition | undefined {
  const live = subWindows.filter((sw) => sw.state !== "split");
  if (!live.some((sw) => sw.walk) || live.some((sw) => !sw.walk && !SETTLED.has(sw.state))) return undefined;
  return live.reduce(
    (acc, sw) =>
      sw.walk
        ? { at: acc.at + (SETTLED.has(sw.state) ? sw.walk.of : sw.walk.at), of: acc.of + sw.walk.of }
        : acc,
    { at: 0, of: 0 },
  );
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

/**
 * complete / partial / failed. Pure. `stopReason`: the network stage stopped early on purpose (the
 * query budget is used, the disk is full) — a resumable stop, so "partial" even with no page saved
 * (#2339). "failed" is left for a run the cloud itself refused.
 */
export function collectionStatus(
  subWindows: readonly SubWindowStatus[],
  pagesSaved: number,
  stopReason?: string,
): CollectionStatus {
  // Never "complete" while a page's completeness is unverified (#2314: a GCS sink) or an item the
  // cloud refused is unresolved (#2313).
  const tree = leaves(subWindows);
  const skipped = tree.some((sw) => (sw.skipped ?? 0) > 0);
  if (!skipped && tree.every((sw) => sw.state === "done" && !sw.unverified)) return "complete";
  return pagesSaved > 0 || skipped || stopReason ? "partial" : "failed";
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
  header: ManifestHeader,
  dir: string,
): Promise<CollectionCheckpoint> {
  const cp = await readCheckpoint(deps.fs, paths);
  if (cp) return cp;
  // #2402: rebuilt from the manifest — with the CASE id of the folder, which the page imports and
  // their "already landed?" check are run against.
  const rebuilt = checkpointFromManifest(header, collectionIdsOf(dir), deps.now());
  if (rebuilt) return rebuilt;
  throw new Error(`collection ${header.collectionId}: checkpoint unreadable and manifest header unusable`);
}

/** Start or resume: replay, fetch what is unfinished, import what is not yet in the case. */
export async function runCollection(
  deps: CollectRunDeps,
  dir: string,
  opts: { resume: boolean; jobId?: string },
): Promise<CollectionCheckpoint> {
  const paths = collectionPaths(dir);
  const replay = await replayCollection(deps.fs, paths, deps.now);
  // #2363: the scope the start decided (the AWS regions) — the header is the one record of it.
  deps.session.applyFilters?.(replay.header.filters ?? {});
  let cp = await baseCheckpoint(deps, paths, replay.header, dir);
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
  // #2470: say the import step has begun at once — a page can take minutes to import.
  report("import", network.subWindows, imported.size);
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
    summarized: cp.summarized ?? {},
    onSummarized: async (kind, pages) => {
      await save({ summarized: { ...cp.summarized, [kind]: pages } });
    },
  });
  const pagesSaved = replay.validPages.length + network.pages.length;
  await save({
    stage: "done",
    status: collectionStatus(network.subWindows, pagesSaved, network.stopReason),
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
  // #2402: "failed" means nothing was collected. A run that threw after usable pages were saved
  // (an import error, say) stopped part-way: it is "partial", and its error says why.
  const next = status === "failed" && (await usablePages(fs, paths, cp)) > 0 ? "partial" : status;
  await writeCheckpoint(fs, paths, { ...cp, status: next, error: error.slice(0, 500), updatedAt: now() });
}

/** Saved pages that are still evidence: manifest page lines minus the quarantined files. */
async function usablePages(fs: CollectFs, paths: CollectionPaths, cp: CollectionCheckpoint): Promise<number> {
  const manifest = await loadManifest(fs, paths).catch(() => null);
  if (!manifest) return cp.imported.length;
  const quarantined = new Set(cp.quarantined.map((q) => q.file));
  return manifest.pages.filter((p) => !quarantined.has(p.file)).length;
}
