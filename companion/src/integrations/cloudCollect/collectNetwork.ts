// The network stage of a collection (#2311). Runs OUTSIDE the case's import section: a Graph audit
// query can wait ten minutes and more, and holding the section that long would freeze every other
// import into the case. Nothing here writes the case — only the collection's own evidence folder.
//
// Per page, in this order (collectFs.ts says why each step is there):
//   write <page>.tmp → fsync → rename → fsync pages/ → append the manifest line → fsync the manifest
//   → update the checkpoint.
//
// A failure is classified, never swallowed:
//   - an expired cursor restarts that sub-window from its start (up to MAX_RESTARTS times);
//   - any other provider error fails that sub-window — the others still run, the result is partial;
//   - a write error (disk full, permissions) STOPS the stage: everything committed stays, the result
//     is partial, and the reason names the error code.

import { join } from "node:path";
import type { CollectFs } from "./collectFs.js";
import { sha256Hex } from "./collectFs.js";
import { appendManifest, type CollectionPaths } from "./collectManifest.js";
import {
  CursorExpiredError,
  type CloudCollectSession,
  type CollectPage,
  type ManifestEntry,
  type ManifestPage,
  type SubWindowStatus,
} from "./collectTypes.js";

/** How often one sub-window may start over after an expired cursor before it is given up. */
export const MAX_RESTARTS = 3;

/** A write to the evidence folder failed: the stage stops, nothing committed is lost. */
export class EvidenceWriteError extends Error {
  constructor(
    readonly code: string,
    cause: unknown,
  ) {
    super(`evidence write failed (${code}): ${(cause as Error)?.message ?? String(cause)}`);
    this.name = "EvidenceWriteError";
  }
}

async function guardWrite<T>(step: () => Promise<T>): Promise<T> {
  try {
    return await step();
  } catch (err) {
    // Only a filesystem error (it carries an errno code) stops the stage as "partial"; anything
    // else is a bug or a cancel, and propagates as itself.
    const code = (err as NodeJS.ErrnoException)?.code;
    if (typeof code !== "string") throw err;
    throw new EvidenceWriteError(code, err);
  }
}

export function pageFileName(seq: number, source: string, extension: CollectPage["extension"]): string {
  return `p${String(seq).padStart(6, "0")}-${source}.${extension}`;
}

/** Save one page and its manifest line, in the commit order. Returns the line. */
export async function commitPage(
  fs: CollectFs,
  paths: CollectionPaths,
  page: CollectPage,
  meta: { seq: number; sw: SubWindowStatus; retrievedAt: string },
): Promise<ManifestPage> {
  const file = pageFileName(meta.seq, meta.sw.source, page.extension);
  const tmp = join(paths.pages, `${file}.tmp`);
  return guardWrite(async () => {
    await fs.writeFileSync(tmp, page.body);
    await fs.rename(tmp, join(paths.pages, file));
    await fs.fsyncDir(paths.pages);
    const line: ManifestPage = {
      type: "page",
      seq: meta.seq,
      source: meta.sw.source,
      subWindowId: meta.sw.id,
      requestParams: page.requestParams,
      ...(page.requestId ? { requestId: page.requestId } : {}),
      retrievedAt: meta.retrievedAt,
      ...(meta.sw.pageToken ? { pageTokenIn: meta.sw.pageToken } : {}),
      ...(page.nextPageToken ? { pageTokenOut: page.nextPageToken } : {}),
      file,
      bytes: page.body.byteLength,
      sha256: sha256Hex(page.body),
      records: page.recordCount,
    };
    await appendManifest(fs, paths, line);
    return line;
  });
}

export interface NetworkStageDeps {
  fs: CollectFs;
  paths: CollectionPaths;
  session: CloudCollectSession;
  now: () => string;
  signal?: AbortSignal;
  /** Persist the checkpoint after a page or a sub-window change (the last commit step). */
  onChange: (subWindows: SubWindowStatus[]) => Promise<void>;
  onPage?: (page: ManifestPage) => void;
}

export interface NetworkStageResult {
  subWindows: SubWindowStatus[];
  pages: ManifestPage[];
  nextSeq: number;
  stopReason?: string;
}

function abortIfCancelled(signal?: AbortSignal): void {
  if (!signal?.aborted) return;
  throw Object.assign(new Error("collection cancelled"), { name: "AbortError" });
}

/** A provider error's message, cut short — never the request itself, which may carry a token. */
function providerReason(err: unknown): string {
  const message = err instanceof Error ? err.message : String(err);
  return `provider error: ${message.slice(0, 300)}`;
}

type Step = { sw: SubWindowStatus; page?: ManifestPage; done: boolean };

async function fetchStep(
  deps: NetworkStageDeps,
  sw: SubWindowStatus,
  seq: number,
  note: (e: ManifestEntry) => Promise<void>,
): Promise<Step> {
  let page: CollectPage;
  try {
    page = await deps.session.fetchPage({
      source: sw.source,
      subWindowId: sw.id,
      window: sw.window,
      ...(sw.pageToken ? { pageToken: sw.pageToken } : {}),
      ...(deps.signal ? { signal: deps.signal } : {}),
    });
  } catch (err) {
    if ((err as Error)?.name === "AbortError") throw err;
    if (err instanceof CursorExpiredError && sw.pageToken && sw.restarts < MAX_RESTARTS) {
      await note({ type: "restart", subWindowId: sw.id, reason: "cursor-expired", at: deps.now() });
      return { sw: { ...sw, pageToken: undefined, restarts: sw.restarts + 1 }, done: false };
    }
    const reason =
      err instanceof CursorExpiredError
        ? `page token expired ${sw.restarts} time(s); the sub-window was not finished`
        : providerReason(err);
    return { sw: { ...sw, state: "failed", reason }, done: true };
  }
  const line = await commitPage(deps.fs, deps.paths, page, { seq, sw, retrievedAt: deps.now() });
  const next: SubWindowStatus = {
    ...sw,
    pages: sw.pages + 1,
    records: sw.records + line.records,
    pageToken: line.pageTokenOut,
    state: line.pageTokenOut ? "pending" : "done",
    reason: undefined,
  };
  return { sw: next, page: line, done: !line.pageTokenOut };
}

/** Fetch every unfinished sub-window, page by page. */
export async function runNetworkStage(
  deps: NetworkStageDeps,
  start: { subWindows: SubWindowStatus[]; nextSeq: number },
): Promise<NetworkStageResult> {
  let subWindows = start.subWindows.map((s) =>
    s.state === "failed" ? { ...s, state: "pending" as const } : s,
  );
  let seq = start.nextSeq;
  const pages: ManifestPage[] = [];
  const note = (e: ManifestEntry) => guardWrite(() => appendManifest(deps.fs, deps.paths, e));
  const save = async (sw: SubWindowStatus): Promise<void> => {
    subWindows = subWindows.map((s) => (s.id === sw.id ? sw : s));
    await guardWrite(() => deps.onChange(subWindows));
  };
  try {
    await guardWrite(() => deps.fs.mkdir(deps.paths.pages));
    for (const initial of start.subWindows) {
      let sw = subWindows.find((s) => s.id === initial.id)!;
      while (sw.state === "pending") {
        abortIfCancelled(deps.signal);
        const step = await fetchStep(deps, sw, seq, note);
        if (step.page) {
          seq++;
          pages.push(step.page);
          deps.onPage?.(step.page);
        }
        sw = step.sw;
        await save(sw);
        if (step.done) break;
      }
    }
  } catch (err) {
    if (!(err instanceof EvidenceWriteError)) throw err;
    return { subWindows, pages, nextSeq: seq, stopReason: err.message };
  }
  return { subWindows, pages, nextSeq: seq };
}
