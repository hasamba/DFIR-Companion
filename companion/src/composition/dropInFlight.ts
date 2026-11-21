/**
 * The drop folder's crash-loop guard for a streamed file (#2713): `state/drop-inflight.json`, one
 * entry per large file the sweep is importing from disk, removed when that import returns.
 *
 * THE MOVE IS THE DEDUP (composition/dropFolder.ts): a file leaves drop/ only once its import
 * returned, ok or failed. A server that dies mid-import — a multi-GB export that runs the process
 * out of memory, a power cut — leaves the file where it was, and the next sweep imports it again.
 * When the import itself is what kills the server, that is a crash loop: every restart dies on the
 * same file. An entry still here when the sweep reaches the file again names an import that never
 * returned; after DROP_CRASH_LIMIT such starts of the SAME version of the file (relpath, size and
 * mtime) the sweep refuses it, so it goes to `_failed/` with a reason that says why. A start is
 * counted when the file's import is granted the case's import section (analysis/importAttempt.ts),
 * so a file queued behind another one is never blamed for the other one's crash — except a LARGE
 * under-cap text file, whose start counts before its whole-file read (composition/dropWholeRead.ts,
 * #2785): that read and its parse are where it runs the server out of memory.
 *
 * Kept beside the batch's crash marker (composition/dropBatchMarker.ts, #2540) and written the same
 * way — the case's state folder, one case-scoped write at a time. The two answer different crashes:
 * the batch marker settles rows a batch merged but never settled; this one stops a file that keeps
 * killing the server from being retried forever. Best effort: a marker that cannot be read or
 * written never stops an import, it only loses the count.
 *
 * Every single-file import of the sweep is guarded (composition/dropBatch.ts); the gzip CloudTrail
 * batch path has its own marker. A file that never reaches its import (refused at the sniff, pending
 * for a tool) never writes an entry.
 */
import { mkdir, readFile, rename, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import type { CaseStore } from "../storage/caseStore.js";
import { logLine } from "../logging/serverLogger.js";

export const DROP_INFLIGHT_MARKER = "drop-inflight.json";

/** Starts of one version of a file that never returned before the sweep refuses it. */
export const DROP_CRASH_LIMIT = 2;

/** The file as the sweep is about to import it. */
export interface DropFileVersion {
  size: number;
  mtimeMs: number;
}

interface Entry extends DropFileVersion {
  relpath: string;
  starts: number;
}

export interface DropInFlight {
  /**
   * Null: import it. A string: this version of the file already started DROP_CRASH_LIMIT imports
   * that never returned — the refusal for `_failed/`. Read only: the entry stays until `end`, so a
   * refusal whose move fails (or a crash before the move) refuses again on the next sweep.
   */
  refusal(caseId: string, relpath: string, version: DropFileVersion): Promise<string | null>;
  /** The file's import was granted the case's import section: count one start. */
  begin(caseId: string, relpath: string, version: DropFileVersion): Promise<void>;
  /** The import returned (ok or failed), or a refused file left drop/: forget the file. */
  end(caseId: string, relpath: string): Promise<void>;
}

export function crashLoopReason(starts: number): string {
  return (
    `the server stopped ${starts} times while importing this file and never finished it ` +
    "(it may have run out of memory, or been restarted mid-import) — moved to _failed so it is " +
    "not retried in a loop; check the server's memory before importing it again"
  );
}

export function createDropInFlight(store: CaseStore): DropInFlight {
  const pathOf = (caseId: string): string => join(store.stateDir(caseId), DROP_INFLIGHT_MARKER);
  // Up to DROP_CONCURRENCY files of one sweep begin and end at once: one read-modify-write at a time.
  const chains = new Map<string, Promise<void>>();

  const update = (caseId: string, fn: (entries: Entry[]) => Entry[]): Promise<void> => {
    const path = pathOf(caseId);
    const run = (chains.get(path) ?? Promise.resolve()).then(() => write(path, caseId, fn));
    const tail = run.catch(() => undefined);
    chains.set(path, tail);
    void tail.then(() => {
      if (chains.get(path) === tail) chains.delete(path);
    });
    return run;
  };

  const write = async (path: string, caseId: string, fn: (entries: Entry[]) => Entry[]): Promise<void> => {
    await store.withCaseWrite(path, async () => {
      const next = fn(await readEntries(path));
      if (!next.length) return void (await rm(path, { force: true }));
      await mkdir(store.stateDir(caseId), { recursive: true });
      const tmp = `${path}.tmp`;
      await writeFile(tmp, JSON.stringify({ entries: next }), "utf8");
      await rename(tmp, path);
    });
  };

  const warn = (caseId: string, what: string, err: unknown): void =>
    logLine(`[drop] ${caseId}: in-flight marker ${what} — ${(err as Error).message}`);

  return {
    refusal: async (caseId, relpath, version) => {
      const entries = await readEntries(pathOf(caseId)).catch((err: unknown) => {
        warn(caseId, "unreadable", err);
        return [] as Entry[];
      });
      const prior = entries.find((e) => e.relpath === relpath);
      return prior && sameVersion(prior, version) && prior.starts >= DROP_CRASH_LIMIT
        ? crashLoopReason(prior.starts)
        : null;
    },
    begin: (caseId, relpath, version) =>
      update(caseId, (entries) => {
        const prior = entries.find((e) => e.relpath === relpath);
        const starts = prior && sameVersion(prior, version) ? prior.starts : 0;
        return [...entries.filter((e) => e.relpath !== relpath), { relpath, ...version, starts: starts + 1 }];
      }).catch((err: unknown) => warn(caseId, "not written", err)),
    end: (caseId, relpath) =>
      update(caseId, (entries) => entries.filter((e) => e.relpath !== relpath)).catch((err: unknown) =>
        warn(caseId, "not cleared", err),
      ),
  };
}

const sameVersion = (a: DropFileVersion, b: DropFileVersion): boolean =>
  a.size === b.size && a.mtimeMs === b.mtimeMs;

async function readEntries(path: string): Promise<Entry[]> {
  let text: string;
  try {
    text = await readFile(path, "utf8");
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === "ENOENT") return [];
    throw err;
  }
  return parseInFlight(text);
}

/** The marker's entries; a torn or foreign file reads as empty (the count is lost, never the file). */
export function parseInFlight(text: string): Entry[] {
  try {
    const raw = (JSON.parse(text) as { entries?: unknown }).entries;
    if (!Array.isArray(raw)) return [];
    return raw.filter(
      (e): e is Entry =>
        !!e &&
        typeof e.relpath === "string" &&
        Number.isFinite(e.size) &&
        Number.isFinite(e.mtimeMs) &&
        Number.isInteger(e.starts) &&
        e.starts > 0,
    );
  } catch {
    return [];
  }
}
