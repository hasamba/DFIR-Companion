import {
  readdir,
  readFile,
  writeFile,
  mkdir,
  mkdtemp,
  rename as renamePath,
  rm,
  stat,
  lstat,
} from "node:fs/promises";
import { join, dirname, isAbsolute } from "node:path";
import { createHash } from "node:crypto";
import { isValidCaseId, type CaseStore } from "../storage/caseStore.js";
import { isTransientCasePath } from "./caseTransientPaths.js";
import type { CaseMeta } from "../types.js";
import { createZip, readZip, type ZipEntry } from "./zipArchive.js";
import { encryptBuffer, decryptBuffer } from "./caseEncryption.js";
import { getAppVersion } from "../version.js";
import { caseSqliteWorker } from "./caseSqliteWorker.js";
import { INVESTIGATION_DB_FILENAME } from "./stateStore.js";

// Whole-case export/import (#54 follow-up): the entire case directory tree is zipped, then
// AES-256-GCM encrypted (via caseEncryption.ts) into a single `.dfircase` file that another
// DFIR Companion instance can restore byte-for-byte. Unlike the earlier JSON-snapshot export,
// this covers screenshots and raw imported evidence files too, not just derived state.

export const MIN_PASSWORD_LENGTH = 8;

// Where an encrypted import extracts before it is published (#420). Dotted, and a level below the
// cases, so nothing that enumerates the cases root can mistake a half-extracted archive for a case.
const IMPORT_STAGING_DIRNAME = ".import-staging";
const IMPORT_STAGING_MAX_AGE_MS = 24 * 60 * 60 * 1000;

export class CaseImportConflictError extends Error {
  constructor(public readonly caseId: string) {
    super(`case ${caseId} already exists — import under a different case id`);
    this.name = "CaseImportConflictError";
  }
}

export interface CaseImportCounts {
  forensicEvents: number;
  findings: number;
  iocs: number;
  captures: number;
  imports: number;
}

// Windows-illegal filename characters (also unsafe cross-platform): < > : " / \ | ? * and control
// chars. caseId itself never needs this — isValidCaseId's allowlist already guarantees it's
// filesystem-safe — but the case name is free text an analyst typed in.
const UNSAFE_FILENAME_CHARS = /[<>:"/\\|?*\x00-\x1f]/g;

/**
 * The download filename for a case's `.dfircase` export: `"<caseId> - <name>.dfircase"`, or just
 * `"<caseId>.dfircase"` when the case has no distinct name set.
 */
export function dfircaseFilename(caseId: string, name: string | null | undefined): string {
  const trimmed = (name ?? "").trim();
  if (!trimmed || trimmed === caseId) return `${caseId}.dfircase`;
  return `${caseId} - ${trimmed.replace(UNSAFE_FILENAME_CHARS, "_")}.dfircase`;
}

/**
 * Build the `Content-Disposition` value for downloading `filename` as an attachment.
 *
 * A filename here carries the case NAME, which is free text an analyst typed — routinely an em
 * dash, an accent, a non-Latin script. Interpolating that straight into the header made Node throw
 * ERR_INVALID_CHAR (it rejects any header value holding a character above U+00FF) and the export
 * route turned the throw into a bare 500, so every case whose name was not pure Latin-1 — the
 * seeded demo case among them — was simply un-exportable. Sanitizing the name harder is the wrong
 * cure: it silently mangles the filename for every analyst not working in English.
 *
 * RFC 6266 covers exactly this with two parameters: an ASCII-only `filename=` for clients that
 * don't implement `filename*`, and a percent-encoded `filename*=UTF-8''…` (RFC 5987) carrying the
 * real name for those that do. `filename*` is appended only when it can say something `filename=`
 * cannot, so an ASCII download keeps the byte-identical header it has always sent.
 */
export function attachmentContentDisposition(filename: string): string {
  // Everything outside printable ASCII collapses to "_" — the same placeholder the case name
  // already uses for filesystem-unsafe characters. The quote and backslash go too: both are
  // stripped upstream, but a quote reaching this string would close it early and let a crafted
  // case name append header parameters of its own.
  const ascii = filename.replace(/[^\x20-\x7e]|["\\]/g, "_");
  const header = `attachment; filename="${ascii}"`;
  if (ascii === filename) return header;
  // RFC 5987's attr-char set excludes ' ( ) * , which encodeURIComponent leaves unescaped.
  const encoded = encodeURIComponent(filename).replace(
    /['()*]/g,
    (char) => `%${char.charCodeAt(0).toString(16).toUpperCase()}`,
  );
  return `${header}; filename*=UTF-8''${encoded}`;
}

/**
 * Turn an ENOENT on a path the walk had just listed into something an analyst can act on.
 *
 * A file vanishing mid-export is not the same as one that was never there: it means the case was
 * being written while it was being packaged. The export still refuses to continue — an archive that
 * quietly omits a case file while presenting itself as complete is the one outcome a forensic
 * export must never produce — but it now names the file and says what to do, instead of surfacing a
 * bare "ENOENT ... lstat" that reads as a server fault. Any other error is rethrown untouched.
 */
function rethrowVanished(rel: string): (err: unknown) => never {
  return (err: unknown) => {
    if ((err as NodeJS.ErrnoException).code === "ENOENT") {
      throw new Error(
        `"${rel}" disappeared while the case was being packaged — something is still writing to ` +
          `this case. Let it finish (or close the case) and export again.`,
      );
    }
    throw err;
  };
}

async function walkDir(dir: string, baseRel = ""): Promise<string[]> {
  const out: string[] = [];
  let entries;
  try {
    entries = await readdir(dir, { withFileTypes: true });
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === "ENOENT") return [];
    throw err;
  }
  for (const entry of entries) {
    const rel = baseRel ? `${baseRel}/${entry.name}` : entry.name;
    // A write in progress, not case content — the app keeps writing to a case while it is being
    // packaged, and readdir routinely lists a temp file that is renamed away before the lstat below
    // reaches it, which used to take the whole export down with a raw ENOENT 500. Skipping these by
    // name fixes it at the source: the archive never wanted them, and they would make the manifest
    // differ run to run. What counts as transient (and what deliberately does not) is
    // caseTransientPaths.ts — a path that vanishes without matching there still fails loudly.
    if (isTransientCasePath(entry.name)) continue;
    // A one-shot export should FAIL LOUDLY on a symlink/hardlink, not silently drop it: this is a
    // security-sensitive export the analyst explicitly requested, and a planted link pointing
    // outside the case directory (e.g. screenshots/loot -> /etc/shadow) is itself a signal worth
    // surfacing, not something to quietly paper over into an incomplete-but-unannounced archive.
    // Matches the throw-hard posture of the TOCTOU re-check below, which catches the read-time race.
    if (entry.isSymbolicLink()) {
      throw new Error(
        `symlink detected in case directory at "${rel}" — refusing to include in export (security)`,
      );
    }
    if (entry.isDirectory()) {
      out.push(...(await walkDir(join(dir, entry.name), rel)));
      continue;
    }
    if (entry.isFile()) {
      // Hardlink guard: a hardlink is indistinguishable from a normal file via readdir's Dirent
      // (isSymbolicLink() is false for it too) — only lstat's nlink count reveals it. A file
      // legitimately written into the case directory (imports, screenshots, state) is always
      // nlink === 1, so a multiply-linked path here means some OTHER directory entry — anywhere
      // on the same filesystem, e.g. /etc/shadow — aliases this exact inode. Same exfiltration
      // vector as a symlink, just via a different mechanism.
      const st = await lstat(join(dir, entry.name)).catch(rethrowVanished(rel));
      if (st.nlink > 1) {
        throw new Error(
          `hardlink detected in case directory at "${rel}" — refusing to include in export (security)`,
        );
      }
      out.push(rel);
    }
  }
  return out;
}

/**
 * Build a `.dfircase` file: the whole case directory zipped, then AES-256-GCM encrypted with a
 * password-derived key. Throws if the case doesn't exist (no files under its directory).
 */
export async function exportEncryptedCase(
  store: CaseStore,
  caseId: string,
  password: string,
  // Files generated for the archive rather than read from the case dir — currently the signed
  // chain-of-custody manifest (#231). Passed in rather than written into the case first, so
  // exporting never mutates the case it is exporting.
  extraEntries: ZipEntry[] = [],
): Promise<Buffer> {
  if (!isValidCaseId(caseId)) throw new Error(`invalid case id "${caseId}"`);
  const caseDir = store.caseDir(caseId);
  const relPaths = (await walkDir(caseDir)).map((p) => p.replace(/\\/g, "/"));
  if (relPaths.length === 0) throw new Error(`case ${caseId} does not exist`);

  const entries: ZipEntry[] = [];
  const manifestFiles: Array<{ path: string; sha256: string; bytes: number }> = [];
  let totalBytes = 0;
  for (const rel of relPaths) {
    const fullPath = join(caseDir, rel);
    // TOCTOU guard: re-check that the path is not a symlink (or hardlink — see walkDir) before
    // reading. The file could have been replaced/swapped between the walk and the read.
    const lst = await lstat(fullPath).catch(rethrowVanished(rel));
    if (lst.isSymbolicLink())
      throw new Error(
        `symlink detected in case directory at "${rel}" — refusing to include in export (security)`,
      );
    if (lst.nlink > 1)
      throw new Error(
        `hardlink detected in case directory at "${rel}" — refusing to include in export (security)`,
      );
    const data = await readFile(fullPath).catch(rethrowVanished(rel));
    entries.push({ path: rel, data });
    manifestFiles.push({
      path: rel,
      sha256: createHash("sha256").update(data).digest("hex"),
      bytes: data.length,
    });
    totalBytes += data.length;
  }
  // Listed in archive-manifest.json alongside the case's own files, so a recipient checking the
  // archive's checksums sees the generated entries too.
  for (const entry of extraEntries) {
    entries.push(entry);
    manifestFiles.push({
      path: entry.path,
      sha256: createHash("sha256").update(entry.data).digest("hex"),
      bytes: entry.data.length,
    });
    totalBytes += entry.data.length;
  }
  const counts = countsFromEntries(entries);
  const databaseCounts = await caseSqliteWorker.request<Record<string, number> | null>({
    op: "entityCounts",
    dbPath: join(caseDir, "state", INVESTIGATION_DB_FILENAME),
    kinds: ["forensicTimeline", "findings", "iocs"],
  });
  if (databaseCounts) {
    counts.forensicEvents = databaseCounts.forensicTimeline ?? counts.forensicEvents;
    counts.findings = databaseCounts.findings ?? counts.findings;
    counts.iocs = databaseCounts.iocs ?? counts.iocs;
  }
  const manifest = {
    caseId,
    exportedAt: new Date().toISOString(),
    generatedBy: getAppVersion(),
    counts,
    files: manifestFiles,
    totalFiles: manifestFiles.length,
    totalBytes,
  };
  entries.push({
    path: "archive-manifest.json",
    data: Buffer.from(JSON.stringify(manifest, null, 2), "utf8"),
  });

  return encryptBuffer(createZip(entries), password);
}

// Defense-in-depth against a crafted/corrupted archive writing outside the target case
// directory (zip-slip). The primary defense is that the archive is password-authenticated, but
// this guard means a malicious or corrupted entry path is rejected before ANY file is written.
// The colon check also closes an NTFS alternate-data-stream gap: "shot.jpg:hidden.exe" doesn't
// escape the case directory, but would silently write a hidden stream on Windows without it.
function isSafeZipEntryPath(path: string): boolean {
  if (!path || isAbsolute(path) || /^[a-zA-Z]:/.test(path) || path.includes(":")) return false;
  const segments = path.split(/[\\/]+/);
  return segments.every((seg) => seg !== "" && seg !== "." && seg !== "..");
}

function rewriteCaseIdInJson(data: Buffer, targetCaseId: string, indent: number | undefined): Buffer {
  const parsed = JSON.parse(data.toString("utf8")) as Record<string, unknown>;
  return Buffer.from(JSON.stringify({ ...parsed, caseId: targetCaseId }, null, indent), "utf8");
}

function rewriteCaseIdInJsonl(data: Buffer, targetCaseId: string): Buffer {
  const lines = data
    .toString("utf8")
    .split("\n")
    .filter((l) => l.trim().length > 0);
  const rewritten = lines.map((line) => {
    const parsed = JSON.parse(line) as Record<string, unknown>;
    return JSON.stringify({ ...parsed, caseId: targetCaseId });
  });
  return Buffer.from(rewritten.length ? rewritten.join("\n") + "\n" : "", "utf8");
}

// Legacy archive paths whose caseId must be rewritten on import, mapped to the indent they're
// written back with. investigation.json stays compact because old archives can be near V8's string
// ceiling. SQLite-backed imports normalize the database's caseId on first StateStore load.
// case.json is small and CaseStore writes it pretty, so it stays pretty.
const CASE_ID_JSON_PATHS = new Map<string, number | undefined>([
  ["case.json", 2],
  ["state/investigation.json", undefined],
]);
const CASE_ID_JSONL_PATHS = new Set(["metadata/captures.jsonl", "metadata/imports.jsonl"]);

function countLines(data: Buffer | undefined): number {
  if (!data) return 0;
  return data
    .toString("utf8")
    .split("\n")
    .filter((l) => l.trim().length > 0).length;
}

function countsFromEntries(entries: ZipEntry[]): CaseImportCounts {
  const invEntry = entries.find((e) => e.path === "state/investigation.json");
  let forensicEvents = 0;
  let findings = 0;
  let iocs = 0;
  if (invEntry) {
    try {
      const inv = JSON.parse(invEntry.data.toString("utf8")) as Record<string, unknown>;
      forensicEvents = Array.isArray(inv.forensicTimeline) ? inv.forensicTimeline.length : 0;
      findings = Array.isArray(inv.findings) ? inv.findings.length : 0;
      iocs = Array.isArray(inv.iocs) ? inv.iocs.length : 0;
    } catch {
      // malformed investigation.json — counts default to 0, import still proceeds
    }
  }
  return {
    forensicEvents,
    findings,
    iocs,
    captures: countLines(entries.find((e) => e.path === "metadata/captures.jsonl")?.data),
    imports: countLines(entries.find((e) => e.path === "metadata/imports.jsonl")?.data),
  };
}

function countsFromManifest(entry: ZipEntry | undefined): CaseImportCounts | null {
  if (!entry) return null;
  try {
    const counts = (JSON.parse(entry.data.toString("utf8")) as { counts?: unknown }).counts;
    if (!counts || typeof counts !== "object" || Array.isArray(counts)) return null;
    const record = counts as Record<string, unknown>;
    const keys: Array<keyof CaseImportCounts> = ["forensicEvents", "findings", "iocs", "captures", "imports"];
    if (!keys.every((key) => Number.isSafeInteger(record[key]) && Number(record[key]) >= 0)) {
      return null;
    }
    return {
      forensicEvents: Number(record.forensicEvents),
      findings: Number(record.findings),
      iocs: Number(record.iocs),
      captures: Number(record.captures),
      imports: Number(record.imports),
    };
  } catch {
    return null;
  }
}

export interface ImportEncryptedCaseOptions {
  targetCaseId?: string;
}

export interface ImportEncryptedCaseResult {
  meta: CaseMeta;
  counts: CaseImportCounts;
}

/**
 * Restore a `.dfircase` file into a NEW case directory. Decrypts, unzips, and writes every entry
 * back verbatim (byte-for-byte) unless the target case id differs from the archive's own id, in
 * which case the handful of caseId-bearing files are rewritten to keep the imported case
 * internally consistent (case.json, legacy state/investigation.json, and each captures.jsonl /
 * imports.jsonl record; StateStore normalizes an imported SQLite database on first load).
 * Everything else — screenshots, raw imports, every other state file — copies unchanged either way.
 */
export async function importEncryptedCase(
  store: CaseStore,
  fileBuffer: Buffer,
  password: string,
  options: ImportEncryptedCaseOptions = {},
): Promise<ImportEncryptedCaseResult> {
  const zip = decryptBuffer(fileBuffer, password);
  const archiveEntries = readZip(zip);
  const manifestCounts = countsFromManifest(
    archiveEntries.find((entry) => entry.path === "archive-manifest.json"),
  );
  const entries = archiveEntries.filter((e) => e.path !== "archive-manifest.json");

  const caseJsonEntry = entries.find((e) => e.path === "case.json");
  if (!caseJsonEntry) throw new Error("not a valid case archive: missing case.json");

  let originalMeta: CaseMeta;
  try {
    originalMeta = JSON.parse(caseJsonEntry.data.toString("utf8")) as CaseMeta;
  } catch {
    throw new Error("not a valid case archive: corrupt case.json");
  }
  if (typeof originalMeta.caseId !== "string" || !originalMeta.caseId) {
    throw new Error("not a valid case archive: case.json missing caseId");
  }

  const targetCaseId = (options.targetCaseId ?? originalMeta.caseId).trim();
  if (!isValidCaseId(targetCaseId)) throw new Error(`invalid target case id "${targetCaseId}"`);
  if (await store.caseExists(targetCaseId)) throw new CaseImportConflictError(targetCaseId);

  // Everything below this point is validation — nothing touches disk until every entry path
  // has been checked (zip-slip / NTFS ADS / duplicates) AND every caseId-bearing file that
  // needs rewriting has been proven to parse. A corrupt archive must fail cleanly here, not
  // partway through the write loop — a partial write would leave an orphaned case directory
  // that makes store.caseExists() return true for a case that never actually imported.
  const seenPaths = new Set<string>();
  for (const entry of entries) {
    if (!isSafeZipEntryPath(entry.path)) {
      throw new Error(`not a valid case archive: unsafe entry path "${entry.path}"`);
    }
    if (seenPaths.has(entry.path)) {
      throw new Error(`not a valid case archive: duplicate entry path "${entry.path}"`);
    }
    seenPaths.add(entry.path);
  }

  const rename = targetCaseId !== originalMeta.caseId;
  const rewrittenByPath = new Map<string, Buffer>();
  if (rename) {
    for (const entry of entries) {
      // Match on a forward-slash-normalized path so a backslash-separated entry (however
      // unlikely) still gets its caseId rewritten instead of silently keeping the old id.
      const normalizedPath = entry.path.replace(/\\/g, "/");
      try {
        if (CASE_ID_JSON_PATHS.has(normalizedPath)) {
          const indent = CASE_ID_JSON_PATHS.get(normalizedPath);
          rewrittenByPath.set(entry.path, rewriteCaseIdInJson(entry.data, targetCaseId, indent));
        } else if (CASE_ID_JSONL_PATHS.has(normalizedPath)) {
          rewrittenByPath.set(entry.path, rewriteCaseIdInJsonl(entry.data, targetCaseId));
        }
      } catch {
        throw new Error(`not a valid case archive: corrupt ${entry.path}`);
      }
    }
  }

  const counts = manifestCounts ?? countsFromEntries(entries);

  // Extract into a private staging directory and publish it with a single rename (#420).
  //
  // The caseExists() check above is not a claim on the id — nothing stopped a second import from
  // passing the same check and then interleaving its writes into the same destination. The result
  // was a case that never existed in either archive: case.json from whichever import wrote it
  // last, evidence files from both. Nothing downstream could detect that, so every analysis,
  // report and custody record built on it was untrustworthy.
  //
  // rename() of a directory onto an existing non-empty directory fails on every platform, which
  // makes it the exclusive atomic claim the existence check never was: the first import to finish
  // publishes, and any other aiming at the same id gets a conflict instead of a merge. It also
  // means a case directory only ever becomes visible complete — a failure part-way through the
  // write loop used to leave an orphan that made caseExists() true for a case that never imported.
  const staging = await createImportStaging(store, targetCaseId);
  try {
    for (const sub of ["screenshots", "metadata", "state", "reports", "imports"]) {
      await mkdir(join(staging, sub), { recursive: true });
    }

    for (const entry of entries) {
      const data = rewrittenByPath.get(entry.path) ?? entry.data;
      const target = join(staging, entry.path);
      await mkdir(dirname(target), { recursive: true });
      await writeFile(target, data);
    }

    try {
      await renamePath(staging, join(store.casesRoot, targetCaseId)); // `rename` is taken: the id-rewrite flag above
    } catch (err) {
      // Platforms disagree on the errno for "destination directory is in the way" (ENOTEMPTY,
      // EEXIST, EPERM on Windows), so ask the filesystem what actually happened rather than
      // enumerating codes: if the target is a case now, someone else claimed it.
      if (await store.caseExists(targetCaseId)) throw new CaseImportConflictError(targetCaseId);
      throw err;
    }
  } finally {
    // No-op after a successful rename; on any failure it is what keeps a half-extracted archive
    // from surviving as a stale staging directory.
    await rm(staging, { recursive: true, force: true }).catch(() => {
      /* best effort */
    });
  }

  const meta = await store.getCaseMeta(targetCaseId);
  if (!meta) throw new Error("import failed: case.json missing after write");
  return { meta, counts };
}

/**
 * A unique, private directory to extract into, on the same filesystem as the destination so the
 * publishing rename is atomic. It lives under a dotted subdirectory of the cases root rather than
 * beside the cases: listCases() only treats a directory holding a readable case.json as a case, and
 * a half-extracted archive holds exactly that.
 *
 * Also sweeps staging directories older than a day. The finally block above removes this run's on
 * every path a process survives; the sweep is for the one it does not (a kill or a power loss
 * mid-extraction), so those cannot accumulate forever. A day is far longer than any import, so it
 * cannot collide with a slow one running concurrently.
 */
async function createImportStaging(store: CaseStore, targetCaseId: string): Promise<string> {
  const stagingRoot = join(store.casesRoot, IMPORT_STAGING_DIRNAME);
  await mkdir(stagingRoot, { recursive: true });
  const cutoff = Date.now() - IMPORT_STAGING_MAX_AGE_MS;
  for (const name of await readdir(stagingRoot).catch(() => [])) {
    const path = join(stagingRoot, name);
    const info = await stat(path).catch(() => null);
    if (info && info.mtimeMs < cutoff)
      await rm(path, { recursive: true, force: true }).catch(() => {
        /* best effort */
      });
  }
  return mkdtemp(join(stagingRoot, `${targetCaseId}-`));
}
