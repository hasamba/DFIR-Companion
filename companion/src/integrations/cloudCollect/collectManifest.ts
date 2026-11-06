// The append-only evidence manifest of one collection (#2311):
//   <case>/evidence/cloud/<collectionId>/manifest.jsonl
// A header line, then one line per saved page, plus the restart / quarantine / resume notes that
// explain every later change. Nothing is ever rewritten in place.
//
// A crash can tear the LAST line (a partial write before the fsync). Load drops a last line that is
// not valid JSON, and `repairTornTail` truncates the file back to the last complete line BEFORE the
// next append — otherwise the fragment would glue itself to the next line and corrupt it too.

import { join } from "node:path";
import type { CollectFs } from "./collectFs.js";
import type { ManifestEntry, ManifestHeader, ManifestPage } from "./collectTypes.js";

export const MANIFEST_FILE = "manifest.jsonl";
export const CHECKPOINT_FILE = "checkpoint.json";
export const QUARANTINE_DIR = "quarantine";
export const PAGES_DIR = "pages";

export interface CollectionPaths {
  dir: string;
  manifest: string;
  checkpoint: string;
  pages: string;
  quarantine: string;
}

export function collectionPaths(dir: string): CollectionPaths {
  return {
    dir,
    manifest: join(dir, MANIFEST_FILE),
    checkpoint: join(dir, CHECKPOINT_FILE),
    pages: join(dir, PAGES_DIR),
    quarantine: join(dir, QUARANTINE_DIR),
  };
}

export interface LoadedManifest {
  header: ManifestHeader | null;
  entries: ManifestEntry[];
  pages: ManifestPage[];
  /** A torn last line was found (and will be cut by repairTornTail). */
  tornTail: boolean;
  /** Byte length of the complete lines — where the file is truncated to on repair. */
  goodBytes: number;
  /** Lines in the middle that did not parse: kept on disk, ignored, disclosed. */
  unreadableLines: number;
}

function isEntry(value: unknown): value is ManifestEntry {
  if (!value || typeof value !== "object") return false;
  const type = (value as { type?: unknown }).type;
  return (
    type === "header" ||
    type === "page" ||
    type === "restart" ||
    type === "quarantine" ||
    type === "resume" ||
    type === "split"
  );
}

/** Parse manifest text. Pure — the tests feed it torn and damaged text directly. */
export function parseManifest(text: string): LoadedManifest {
  const entries: ManifestEntry[] = [];
  let goodBytes = 0;
  let unreadableLines = 0;
  let tornTail = false;
  let offset = 0;
  while (offset < text.length) {
    const nl = text.indexOf("\n", offset);
    const complete = nl !== -1;
    const line = text.slice(offset, complete ? nl : text.length);
    const next = complete ? nl + 1 : text.length;
    let parsed: unknown;
    try {
      parsed = line.trim() ? JSON.parse(line) : undefined;
    } catch {
      parsed = null;
    }
    const last = next >= text.length;
    if (!complete || (parsed === null && last)) {
      // A last line with no newline, or one that does not parse, is a torn write.
      if (line.trim()) tornTail = true;
      break;
    }
    if (parsed === null || (parsed !== undefined && !isEntry(parsed))) unreadableLines++;
    else if (parsed !== undefined) entries.push(parsed);
    goodBytes = Buffer.byteLength(text.slice(0, next));
    offset = next;
  }
  const header = entries.find((e): e is ManifestHeader => e.type === "header") ?? null;
  const pages = entries.filter((e): e is ManifestPage => e.type === "page");
  return { header, entries, pages, tornTail, goodBytes, unreadableLines };
}

export async function loadManifest(fs: CollectFs, paths: CollectionPaths): Promise<LoadedManifest> {
  if (!(await fs.exists(paths.manifest))) return parseManifest("");
  return parseManifest((await fs.readFile(paths.manifest)).toString("utf8"));
}

/** Cut a torn last line off the manifest so the next append starts on a clean line. */
export async function repairTornTail(
  fs: CollectFs,
  paths: CollectionPaths,
  loaded: LoadedManifest,
): Promise<void> {
  if (loaded.tornTail) await fs.truncate(paths.manifest, loaded.goodBytes);
}

/** Append one line and fsync the manifest. */
export async function appendManifest(
  fs: CollectFs,
  paths: CollectionPaths,
  entry: ManifestEntry,
): Promise<void> {
  await fs.appendSync(paths.manifest, `${JSON.stringify(entry)}\n`);
}
