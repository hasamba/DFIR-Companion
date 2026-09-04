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
import { portableArchivePaths, destinationKey } from "../storage/portableFilename.js";
import { encryptBuffer, decryptBuffer, readFormatVersion, CURRENT_FORMAT_VERSION } from "./caseEncryption.js";
import { getAppVersion } from "../version.js";
import { caseSqliteWorker } from "./caseSqliteWorker.js";
import { INVESTIGATION_DB_FILENAME } from "./stateStore.js";
import { readFileNoFollow, LinkGuardError } from "../storage/noFollowRead.js";

// Whole-case export/import (#54 follow-up): the entire case directory tree is zipped, then
// AES-256-GCM encrypted (via caseEncryption.ts) into a single `.dfircase` file that another
// DFIR Companion instance can restore byte-for-byte. Unlike the earlier JSON-snapshot export,
// this covers screenshots and raw imported evidence files too, not just derived state.

export const MIN_PASSWORD_LENGTH = 8;

// Where an encrypted import extracts before it is published (#420). Dotted, and a level below the
// cases, so nothing that enumerates the cases root can mistake a half-extracted archive for a case.
const IMPORT_STAGING_DIRNAME = ".import-staging";
const IMPORT_STAGING_MAX_AGE_MS = 24 * 60 * 60 * 1000;

// Where an export stages the database snapshot it archives instead of the live file. Dotted and a
// level above the cases for the same reason import staging is: nothing that enumerates the cases
// root, and nothing that walks a case, may mistake it for case content.
const EXPORT_STAGING_DIRNAME = ".export-staging";

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

export interface CaseExportOptions {
  /**
   * The app's per-case state mutex (createApp's runStateExclusive). Passing it makes the export a
   * critical section: every load→save the app performs through the same lock either completes
   * before the snapshot is taken or waits until the archive is built, so the export cannot capture
   * a case midway through one. Omitted in tests and by callers with no lock wired, which run
   * unserialized exactly as before.
   */
  runExclusive?: <T>(caseId: string, fn: () => Promise<T>) => Promise<T>;
}

/**
 * Build a `.dfircase` file: the whole case directory zipped, then AES-256-GCM encrypted with a
 * password-derived key. Throws if the case doesn't exist (no files under its directory).
 *
 * The archive is ONE generation of the case, not a walk of a moving target — see buildCaseArchive.
 */
export async function exportEncryptedCase(
  store: CaseStore,
  caseId: string,
  password: string,
  // Files generated for the archive rather than read from the case dir — currently the signed
  // chain-of-custody manifest (#231). Passed in rather than written into the case first, so
  // exporting never mutates the case it is exporting.
  extraEntries: ZipEntry[] = [],
  opts: CaseExportOptions = {},
): Promise<Buffer> {
  if (!isValidCaseId(caseId)) throw new Error(`invalid case id "${caseId}"`);
  const run = opts.runExclusive ?? (<T>(_id: string, fn: () => Promise<T>) => fn());
  return run(caseId, () => buildCaseArchive(store, caseId, password, extraEntries));
}

/**
 * The archive itself, built from a single case generation.
 *
 * The database is taken through SQLite's own snapshot path (the worker's backupDatabase, which is
 * VACUUM INTO plus an integrity_check) rather than copied as ordinary bytes. Copying the file while
 * a transaction is open could yield an archive whose database does not open at all — the one defect
 * an evidence archive cannot have — and reading the live file gave a database from one instant with
 * a manifest counted at another. Entity counts now come from that same snapshot, so what the
 * manifest claims and what the archive contains are the same generation by construction.
 *
 * Journal mode is DELETE (see caseTransientPaths.ts), so the database file alone is the complete
 * database: there is no -wal/-shm sidecar that could disagree with the snapshot.
 */
async function buildCaseArchive(
  store: CaseStore,
  caseId: string,
  password: string,
  extraEntries: ZipEntry[],
): Promise<Buffer> {
  const caseDir = store.caseDir(caseId);
  // Real on-disk relative paths, joined with "/" by walkDir on every platform. They are what the
  // reads below open, so they keep each file's name exactly as the filesystem spells it; the
  // separate, portable name each one takes inside the archive is portableArchivePaths' job (#675).
  // This used to rewrite every backslash to a forward slash here, which no filename separator ever
  // needed — walkDir already emits "/" — and which broke the one case it could affect: a Linux
  // file named "back\slash.bin" became the path "back/slash.bin", so the read looked inside a
  // directory that does not exist and the export died claiming the file had "disappeared while the
  // case was being packaged".
  const relPaths = await walkDir(caseDir);
  if (relPaths.length === 0) throw new Error(`case ${caseId} does not exist`);

  const stagingRoot = join(store.casesRoot, EXPORT_STAGING_DIRNAME);
  await mkdir(stagingRoot, { recursive: true });
  const staging = await mkdtemp(join(stagingRoot, `${caseId}-`));
  try {
    return await archiveGeneration(caseDir, caseId, password, relPaths, extraEntries, staging);
  } finally {
    // The snapshot is a full copy of the case database, so it never outlives the request that
    // needed it — including when the export throws.
    await rm(staging, { recursive: true, force: true }).catch(() => {
      /* nothing left to clean */
    });
  }
}

async function archiveGeneration(
  caseDir: string,
  caseId: string,
  password: string,
  relPaths: string[],
  extraEntries: ZipEntry[],
  staging: string,
): Promise<Buffer> {
  // The live database, and the consistent snapshot standing in for it in the archive. `false` means
  // the case has no database yet (a case created but never written to), in which case there is
  // nothing to substitute and nothing to count.
  const liveDbPath = join(caseDir, "state", INVESTIGATION_DB_FILENAME);
  const snapshotPath = join(staging, INVESTIGATION_DB_FILENAME);
  const dbRel = `state/${INVESTIGATION_DB_FILENAME}`;
  const snapshotted = await caseSqliteWorker.request<boolean>({
    op: "backupDatabase",
    dbPath: liveDbPath,
    targetPath: snapshotPath,
  });

  const entries: ZipEntry[] = [];
  // `originalPath` appears only on an entry whose case-directory name could not be an archive
  // entry name unchanged — see portableArchivePaths. Its absence means the two are identical.
  const manifestFiles: Array<{ path: string; sha256: string; bytes: number; originalPath?: string }> = [];
  let totalBytes = 0;
  const archivePathByRel = portableArchivePaths(
    relPaths,
    [...extraEntries.map((e) => e.path), "archive-manifest.json"],
    "export",
  );
  const recordFile = (rel: string, data: Buffer): string => {
    const archivePath = archivePathByRel.get(rel) ?? rel;
    manifestFiles.push({
      path: archivePath,
      sha256: createHash("sha256").update(data).digest("hex"),
      bytes: data.length,
      ...(archivePath === rel ? {} : { originalPath: rel }),
    });
    totalBytes += data.length;
    return archivePath;
  };
  for (const rel of relPaths) {
    // The database enters the archive as its SNAPSHOT, never as the live file: the live bytes can
    // be mid-transaction, and they would also disagree with the counts below. The snapshot is one
    // this process just wrote into its own staging directory, so it needs no link re-check.
    if (snapshotted && rel === dbRel) {
      const data = await readFile(snapshotPath);
      entries.push({ path: recordFile(rel, data), data });
      continue;
    }
    const fullPath = join(caseDir, rel);
    // The link check and the read are ONE operation on ONE descriptor (see storage/noFollowRead.ts).
    // Re-checking the path and then reading the path left a window in which a process controlling
    // the case directory could swap the approved file for a symlink and have the read follow it —
    // sealing an arbitrary host-readable file into the encrypted export.
    const data = await readFileNoFollow(fullPath).catch((err: unknown) => {
      if (err instanceof LinkGuardError) {
        throw new Error(
          `${err.kind} detected in case directory at "${rel}" — refusing to include in export (security)`,
        );
      }
      return rethrowVanished(rel)(err);
    });
    entries.push({ path: recordFile(rel, data), data });
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
  // Counted from the SNAPSHOT — the database that is actually in the archive. Counting the live one
  // described a case that had moved on since the bytes were captured, so a recipient verifying the
  // manifest against the archive could find fewer events than it claimed and reasonably conclude
  // evidence had been dropped.
  const databaseCounts = await caseSqliteWorker.request<Record<string, number> | null>({
    op: "entityCounts",
    dbPath: snapshotted ? snapshotPath : liveDbPath,
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

  return await encryptBuffer(createZip(entries), password);
}

// Defense-in-depth against a crafted/corrupted archive writing outside the target case
// directory (zip-slip). The primary defense is that the archive is password-authenticated, but
// this guard means a malicious or corrupted entry path is rejected before ANY file is written.
// The colon check also closes an NTFS alternate-data-stream gap: "shot.jpg:hidden.exe" doesn't
// escape the case directory, but would silently write a hidden stream on Windows without it.
//
// It also fixes the archive to ONE path syntax, forward slashes, and rejects the segment spellings
// Windows silently normalizes. Both exist for the same reason (#426): the duplicate check compares
// raw path strings, but the write loop resolves them with the host platform's rules, and on Windows
// several distinct strings resolve to one file. `state/a` and `state\a`, `EVIDENCE.BIN` and
// `evidence.bin`, `notes` and `notes.` all pass a raw-string comparison and then have the later
// entry silently overwrite the earlier one — evidence loss with no error, from a crafted archive or
// from a legitimate one created on a case-sensitive filesystem. A reserved device name (CON, LPT1,
// NUL — with or without an extension) is worse still: on Windows it does not resolve to a file at
// all. Every case archive this tool writes uses forward slashes and ordinary names, so nothing
// legitimate is refused.
const WINDOWS_RESERVED_SEGMENT = /^(con|prn|aux|nul|com[1-9]|lpt[1-9])(\..*)?$/i;

function isSafeZipEntryPath(path: string): boolean {
  if (!path || isAbsolute(path) || /^[a-zA-Z]:/.test(path) || path.includes(":")) return false;
  if (path.includes("\\")) return false;
  return path.split("/").every(
    (seg) =>
      seg !== "" &&
      seg !== "." &&
      seg !== ".." &&
      !/[.\s]$/.test(seg) && // Windows strips trailing dots and spaces
      !/[\x00-\x1f]/.test(seg) && // control characters are not filenames anywhere
      !WINDOWS_RESERVED_SEGMENT.test(seg),
  );
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
  /** The container version the archive was written in, and the version this build writes. An
   * archive below the current version was encrypted under a weaker KDF (#672) — the caller shows
   * that to the analyst so they can re-export and upgrade it. Nothing here re-keys the archive:
   * v1 stays readable forever, by the rule in caseEncryption.ts. */
  formatVersion: number;
  currentFormatVersion: number;
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
  // Read the version BEFORE decrypting so it comes from the same bytes the derivation used, then
  // let decryptBuffer be the thing that rejects an unknown/short container. readFormatVersion
  // cannot return undefined past that call — decryptBuffer would already have thrown.
  const formatVersion = readFormatVersion(fileBuffer);
  const zip = await decryptBuffer(fileBuffer, password);
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
  const seenPaths = new Map<string, string>();
  for (const entry of entries) {
    if (!isSafeZipEntryPath(entry.path)) {
      throw new Error(`not a valid case archive: unsafe entry path "${entry.path}"`);
    }
    // Keyed by the destination the path resolves to, not the raw string, so an alias cannot slip
    // past and overwrite the file an earlier entry wrote (#426).
    const key = destinationKey(entry.path);
    const earlier = seenPaths.get(key);
    if (earlier === entry.path) {
      throw new Error(`not a valid case archive: duplicate entry path "${entry.path}"`);
    }
    if (earlier !== undefined) {
      throw new Error(
        `not a valid case archive: entry path "${entry.path}" resolves to the same file as ` +
          `"${earlier}" on a case-insensitive filesystem`,
      );
    }
    seenPaths.set(key, entry.path);
  }

  const rename = targetCaseId !== originalMeta.caseId;
  const rewrittenByPath = new Map<string, Buffer>();
  if (rename) {
    for (const entry of entries) {
      // A plain match: entry paths are forward-slash only by the time they get here, because
      // isSafeZipEntryPath rejects a backslash outright rather than normalizing one away (#426).
      const normalizedPath = entry.path;
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
  return {
    meta,
    counts,
    // Non-null: decryptBuffer above already threw on any container this build cannot read.
    formatVersion: formatVersion!,
    currentFormatVersion: CURRENT_FORMAT_VERSION,
  };
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
