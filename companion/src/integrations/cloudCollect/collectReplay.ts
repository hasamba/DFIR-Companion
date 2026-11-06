// Replay of a collection's manifest before every run (#2311): the start of a resume, and the start
// of the first run (where it finds nothing to do).
//
//  1. A torn last manifest line is dropped and cut off the file.
//  2. EVERY committed page is re-hashed. A missing file or a hash mismatch marks the page corrupt:
//     the file (when present) moves to quarantine/, a quarantine line records both hashes, and a
//     restart line — derived from the quarantine line on every replay (outstandingRestarts), so a
//     crash between the two appends cannot lose it — sends its sub-window back to its start — so the window is fetched again and the
//     #2301 dedup absorbs whatever overlaps what was already imported.
//  3. A file in pages/ that no manifest line names — a page renamed just before a crash, or a
//     leftover .tmp — is an ORPHAN: moved to quarantine/, hashed and listed. Never deleted; after a
//     cursor expires it may be the only copy of what the cloud returned.
//  4. Each sub-window's cursor is re-derived from the manifest (its last page's token out).

import { join } from "node:path";
import type { CollectFs } from "./collectFs.js";
import {
  appendManifest,
  loadManifest,
  repairTornTail,
  type CollectionPaths,
  type LoadedManifest,
} from "./collectManifest.js";
import { applySplit, splitParents } from "./collectSplit.js";
import type {
  CollectWindow,
  ManifestEntry,
  ManifestHeader,
  ManifestPage,
  ManifestQuarantine,
  QuarantinedFile,
  SubWindowStatus,
} from "./collectTypes.js";
import { withPageDisclosure } from "./collectCoverage.js";

export interface ReplayResult {
  header: ManifestHeader;
  /** Committed pages whose file is present and whose hash matches, in sequence order. */
  validPages: ManifestPage[];
  /** Committed pages quarantined as corrupt or missing (this replay or an earlier one). */
  abandonedPages: ManifestPage[];
  subWindows: SubWindowStatus[];
  /** Everything ever quarantined in this collection, this replay's finds included. */
  quarantined: QuarantinedFile[];
  nextSeq: number;
  tornTail: boolean;
  unreadableLines: number;
}

/** The one root sub-window per source; a capped one splits into a tree (#2312, collectSplit.ts). */
export function initialSubWindows(sources: readonly string[], window: CollectWindow): SubWindowStatus[] {
  return sources.map((source) => ({
    id: `${source}:0`,
    source,
    window,
    state: "pending",
    pages: 0,
    records: 0,
    restarts: 0,
  }));
}

const SETTLED = new Set(["split"]);

function applyRestart(sw: SubWindowStatus): SubWindowStatus {
  // A split parent is re-collected by its children: a restart changes nothing but the count.
  if (SETTLED.has(sw.state)) return { ...sw, restarts: sw.restarts + 1 };
  return {
    ...sw,
    state: "pending",
    pageToken: undefined,
    capped: undefined,
    reason: undefined,
    restarts: sw.restarts + 1,
  };
}

function applyPage(sw: SubWindowStatus, page: ManifestPage): SubWindowStatus {
  const counted = withPageDisclosure(
    {
      ...sw,
      pages: sw.pages + 1,
      records: sw.records + page.records,
      firstRetrievedAt: sw.firstRetrievedAt ?? page.retrievedAt,
      ...(page.acquiredUntil ? { acquiredUntil: page.acquiredUntil } : {}),
    },
    page,
  );
  if (SETTLED.has(sw.state) || sw.state === "incomplete") return counted;
  if (page.capped) return { ...counted, state: "capped", capped: page.capped, pageToken: undefined };
  return { ...counted, pageToken: page.pageTokenOut, state: page.pageTokenOut ? "pending" : "done" };
}

/** Each sub-window's state — the split tree included (#2312) — as the manifest tells it. Pure. */
export function deriveSubWindows(
  header: ManifestHeader,
  entries: readonly ManifestEntry[],
): SubWindowStatus[] {
  let list = initialSubWindows(header.sources, header.window);
  const update = (id: string, fn: (sw: SubWindowStatus) => SubWindowStatus): void => {
    list = list.map((s) => (s.id === id ? fn(s) : s));
  };
  for (const entry of entries) {
    if (entry.type === "split") list = applySplit(list, entry);
    else if (entry.type === "restart") update(entry.subWindowId, applyRestart);
    else if (entry.type === "page") update(entry.subWindowId, (sw) => applyPage(sw, entry));
  }
  return list;
}

async function freeName(fs: CollectFs, dir: string, name: string): Promise<string> {
  if (!(await fs.exists(join(dir, name)))) return name;
  for (let i = 1; ; i++) {
    const candidate = `${name}.${i}`;
    if (!(await fs.exists(join(dir, candidate)))) return candidate;
  }
}

/** Move a page file into quarantine/ under a name that collides with nothing. Never deletes. */
async function quarantine(fs: CollectFs, paths: CollectionPaths, file: string): Promise<string> {
  await fs.mkdir(paths.quarantine);
  const target = await freeName(fs, paths.quarantine, file);
  await fs.rename(join(paths.pages, file), join(paths.quarantine, target));
  await fs.fsyncDir(paths.quarantine);
  await fs.fsyncDir(paths.pages);
  return target;
}

function quarantinedOf(entries: readonly ManifestEntry[]): QuarantinedFile[] {
  return entries
    .filter((e): e is ManifestQuarantine => e.type === "quarantine")
    .map((q) => ({
      file: q.file,
      reason: q.reason,
      ...(q.quarantinedAs ? { quarantinedAs: q.quarantinedAs } : {}),
      ...(q.sha256 ? { sha256: q.sha256 } : {}),
      ...(q.bytes !== undefined ? { bytes: q.bytes } : {}),
    }));
}

type Note = (entry: ManifestEntry) => Promise<void>;

async function validatePages(
  fs: CollectFs,
  paths: CollectionPaths,
  loaded: LoadedManifest,
  now: () => string,
  note: Note,
): Promise<ManifestPage[]> {
  const settled = new Set(quarantinedOf(loaded.entries).map((q) => q.file));
  const valid: ManifestPage[] = [];
  for (const page of loaded.pages) {
    if (settled.has(page.file)) continue; // quarantined on an earlier resume
    const path = join(paths.pages, page.file);
    const present = await fs.exists(path);
    const actual = present ? await fs.hashFile(path) : null;
    if (actual && actual.sha256 === page.sha256) {
      valid.push(page);
      continue;
    }
    const quarantinedAs = present ? await quarantine(fs, paths, page.file) : undefined;
    await note({
      type: "quarantine",
      reason: present ? "corrupt" : "missing",
      file: page.file,
      ...(quarantinedAs ? { quarantinedAs } : {}),
      ...(actual ? { sha256: actual.sha256, bytes: actual.bytes } : {}),
      expectedSha256: page.sha256,
      at: now(),
    });
    // Its restart line is NOT written here: outstandingRestarts derives it from this quarantine
    // line, so a crash between the two lines (or a torn restart line) cannot lose it.
  }
  return valid.sort((a, b) => a.seq - b.seq);
}

/**
 * Sub-windows that owe a restart: a committed page of theirs was quarantined as corrupt or missing,
 * and no restart line comes AFTER that quarantine line. Derived from the manifest on every replay,
 * never remembered — so a crash between the quarantine and restart appends, a torn restart line, or
 * an older manifest all heal the same way: the window is fetched again. Pure.
 */
export function outstandingRestarts(
  pages: readonly ManifestPage[],
  entries: readonly ManifestEntry[],
): string[] {
  const windowOf = new Map(pages.map((p) => [p.file, p.subWindowId]));
  const owed = new Set<string>();
  for (const entry of entries) {
    if (entry.type === "restart") owed.delete(entry.subWindowId);
    if (entry.type !== "quarantine" || entry.reason === "orphan") continue;
    const sw = windowOf.get(entry.file);
    if (sw) owed.add(sw);
  }
  // A split parent's window is re-collected by its children (#2312): it owes nothing.
  const parents = splitParents(entries);
  return [...owed].filter((id) => !parents.has(id));
}

async function quarantineOrphans(
  fs: CollectFs,
  paths: CollectionPaths,
  loaded: LoadedManifest,
  now: () => string,
  note: Note,
): Promise<number> {
  const named = new Set(loaded.pages.map((p) => p.file));
  let highest = 0;
  for (const file of [...(await fs.readdir(paths.pages))].sort()) {
    if (named.has(file)) continue;
    const { sha256, bytes } = await fs.hashFile(join(paths.pages, file));
    const quarantinedAs = await quarantine(fs, paths, file);
    await note({ type: "quarantine", reason: "orphan", file, quarantinedAs, sha256, bytes, at: now() });
    highest = Math.max(highest, Number(/^p(\d+)-/.exec(file)?.[1] ?? 0));
  }
  return highest;
}

/** Replay the manifest, repair what a crash left, and say where every sub-window stands. */
export async function replayCollection(
  fs: CollectFs,
  paths: CollectionPaths,
  now: () => string,
): Promise<ReplayResult> {
  const loaded = await loadManifest(fs, paths);
  if (!loaded.header) throw new Error("collection manifest has no header line");
  await repairTornTail(fs, paths, loaded);
  const added: ManifestEntry[] = [];
  const note: Note = async (entry) => {
    await appendManifest(fs, paths, entry);
    added.push(entry);
  };
  const validPages = await validatePages(fs, paths, loaded, now, note);
  const orphanSeq = await quarantineOrphans(fs, paths, loaded, now, note);
  for (const subWindowId of outstandingRestarts(loaded.pages, [...loaded.entries, ...added]))
    await note({ type: "restart", subWindowId, reason: "corrupt-page", at: now() });
  const entries = [...loaded.entries, ...added];
  const pageSeq = loaded.pages.reduce((m, p) => Math.max(m, p.seq), 0);
  const valid = new Set(validPages.map((p) => p.file));
  return {
    header: loaded.header,
    validPages,
    abandonedPages: loaded.pages.filter((p) => !valid.has(p.file)),
    subWindows: deriveSubWindows(loaded.header, entries),
    quarantined: quarantinedOf(entries),
    nextSeq: Math.max(pageSeq, orphanSeq) + 1,
    tornTail: loaded.tornTail,
    unreadableLines: loaded.unreadableLines,
  };
}
