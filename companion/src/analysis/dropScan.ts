// Pure decision logic for the per-case **evidence drop folder** (auto-import inbox).
//
// The server polls `cases/<id>/drop/` and feeds the listing through these helpers, which decide:
//   • which files to ignore (the reserved _processed/_failed subtrees, the README, OS junk),
//   • whether a file is an image (→ capture/vision pipeline) or an artifact (→ the importer chain),
//   • whether a file has *settled* — its size+mtime unchanged across two consecutive polls — so a
//     file still being copied / mid-Dropbox-sync isn't imported half-written.
//
// No I/O here (the walk, the import, and the move live in the server closure) so the gating rules are
// unit-tested in isolation. Pairs with `dropStatus.ts` (the persisted last-sweep summary).

import { extname, basename } from "node:path";
import { DROP_LOG_FILE } from "./dropLog.js";

/** A drop-folder file as seen by one poll: its path relative to `drop/`, plus size + mtime. */
export interface DropFileStat {
  relpath: string;
  size: number;
  mtimeMs: number;
}

/**
 * How a drop file is routed once it has settled.
 *  - "image":          screenshot/vision pipeline
 *  - "raw-tool-input": a raw binary (EVTX/PCAP) the Companion can't parse — must be run through an
 *                      analyst-configured external tool (Hayabusa/Velociraptor CLI/Suricata/Snort),
 *                      NOT read as text (reading a binary as text corrupts it). See #211.
 *  - "artifact":       everything else → read as text and handed to the importer detector
 */
export type DropClass = "image" | "raw-tool-input" | "artifact";

// Image extensions routed to the screenshot/vision pipeline (transcoded to webp on ingest). Anything
// else is read as text and handed to the importer detector.
export const IMAGE_EXTS = new Set([".png", ".jpg", ".jpeg", ".webp", ".gif", ".bmp", ".tif", ".tiff"]);

// Raw binary evidence the Companion can't parse natively — routed to the external-tool run path (#211),
// never read as text. Kept in sync with the tool `extensions` in integrations/tools/toolConfig.ts.
export const RAW_TOOL_EXTS = new Set([".evtx", ".evt", ".pcap", ".pcapng"]);

// Reserved subfolders the watcher writes to — never re-scanned (moving a file here *is* the dedup).
export const DROP_PROCESSED = "_processed";
export const DROP_FAILED = "_failed";

// The usage hint dropped into an empty drop/ folder; ignored by the scanner.
export const DROP_README = "README.txt";

// OS / sync junk files that must never be treated as evidence.
const IGNORED_BASENAMES = new Set([
  DROP_README.toLowerCase(),
  DROP_LOG_FILE.toLowerCase(),
  ".ds_store",
  "thumbs.db",
  "desktop.ini",
  ".dropbox",
  ".dropbox.attr",
]);

// First path segment of a relpath, normalized to forward slashes (callers may pass either separator).
function firstSegment(relpath: string): string {
  return relpath.replace(/\\/g, "/").split("/")[0] ?? "";
}

/** True for files in the reserved subtrees, the README, dotfiles, and known OS/sync junk. */
export function shouldIgnoreDropFile(relpath: string): boolean {
  const seg0 = firstSegment(relpath);
  if (seg0 === DROP_PROCESSED || seg0 === DROP_FAILED) return true;
  const base = basename(relpath);
  if (!base) return true;
  if (base.startsWith(".")) return true; // dotfiles / partial-download markers
  return IGNORED_BASENAMES.has(base.toLowerCase());
}

/**
 * Route a (non-ignored) drop file by extension: image → capture pipeline; raw binary (EVTX/PCAP) →
 * external-tool run path; else artifact import (read as text).
 */
export function classifyDropFile(relpath: string): DropClass {
  const ext = extname(relpath).toLowerCase();
  if (IMAGE_EXTS.has(ext)) return "image";
  if (RAW_TOOL_EXTS.has(ext)) return "raw-tool-input";
  return "artifact";
}

/** The lowercased raw-tool extension of a file, or "" if it isn't a raw-tool input. */
export function rawToolInputExt(relpath: string): string {
  const ext = extname(relpath).toLowerCase();
  return RAW_TOOL_EXTS.has(ext) ? ext : "";
}

/** A file is too large to read into memory for import (use Import-from-path for those). */
export function isOversize(size: number, maxBytes: number): boolean {
  return maxBytes > 0 && size > maxBytes;
}

export interface SettleResult {
  /** Files that were present last poll with identical size+mtime → safe to import now. */
  ready: DropFileStat[];
  /** The stats to remember for the next poll (every currently-present, non-ignored file). */
  nextSeen: Map<string, { size: number; mtimeMs: number }>;
}

// Decide which files have settled. A file is "ready" only if the previous poll saw it with the same
// size AND mtime — one full poll interval of stability. A brand-new (or just-changed) file is recorded
// in nextSeen and becomes eligible next poll. Ignored files never appear in either output. Processed
// files vanish from the listing once moved, so they fall out of nextSeen on their own (no manifest).
export function selectReadyFiles(
  current: readonly DropFileStat[],
  prevSeen: ReadonlyMap<string, { size: number; mtimeMs: number }>,
): SettleResult {
  const ready: DropFileStat[] = [];
  const nextSeen = new Map<string, { size: number; mtimeMs: number }>();
  for (const f of current) {
    if (shouldIgnoreDropFile(f.relpath)) continue;
    nextSeen.set(f.relpath, { size: f.size, mtimeMs: f.mtimeMs });
    const prev = prevSeen.get(f.relpath);
    if (prev && prev.size === f.size && prev.mtimeMs === f.mtimeMs) ready.push(f);
  }
  return { ready, nextSeen };
}
