import { readdir, readFile, mkdir, mkdtemp, rm, lstat } from "node:fs/promises";
import { join } from "node:path";
import { createHash } from "node:crypto";
import { isValidCaseId, type CaseStore } from "../storage/caseStore.js";
import { isTransientCasePath } from "./caseTransientPaths.js";
import type { CaseMeta } from "../types.js";
import { createZip, type ZipEntry } from "./zipArchive.js";
import { portableArchivePaths } from "../storage/portableFilename.js";
import { encryptBuffer, decryptBuffer, readFormatVersion, CURRENT_FORMAT_VERSION } from "./caseEncryption.js";
import {
  ARCHIVE_MANIFEST_PATH,
  SOURCE_MANIFEST_PATH,
  parseArchiveManifest,
  provenanceOf,
  verifyArchiveManifest,
  type CaseArchiveProvenance,
} from "./caseArchiveManifest.js";
import { EXPORT_STAGING_DIRNAME } from "./caseArchive.js";
import { getAppVersion } from "../version.js";
import { caseSqliteWorker } from "./caseSqliteWorker.js";
import { INVESTIGATION_DB_FILENAME } from "./stateStore.js";
import { CaseFileRefusedError, readCaseFile, withPinnedCaseFile } from "../storage/caseFileRead.js";
import { restoreCaseZip, type CaseImportCounts, type RestoreCaseZipOptions } from "./caseRestore.js";
import { listCaseZipEntries, readCaseZipEntry } from "./caseZipReader.js";

// Whole-case export/import (#54 follow-up): the entire case directory tree is zipped, then
// AES-256-GCM encrypted (via caseEncryption.ts) into a single `.dfircase` file that another
// DFIR Companion instance can restore byte-for-byte. Unlike the earlier JSON-snapshot export,
// this covers screenshots and raw imported evidence files too, not just derived state.

export const MIN_PASSWORD_LENGTH = 8;

// The restore half lives in caseRestore.ts (#1828); these stay importable from here.
export { CaseImportConflictError, isSafeZipEntryPath, type CaseImportCounts } from "./caseRestore.js";

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

// A case file the guard refused, named by its case-relative path. Anything else is rethrown as is.
function refusedAs(rel: string): (err: unknown) => never {
  return (err: unknown) => {
    if (err instanceof CaseFileRefusedError) {
      throw new Error(
        `${err.kind} detected in case directory at "${rel}" — refusing to include in export (security)`,
      );
    }
    throw err;
  };
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
    if (isTransientCasePath(rel)) continue;
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
    return await archiveGeneration(
      store.casesRoot,
      caseDir,
      caseId,
      password,
      relPaths,
      extraEntries,
      staging,
    );
  } finally {
    // The snapshot is a full copy of the case database, so it never outlives the request that
    // needed it — including when the export throws.
    await rm(staging, { recursive: true, force: true }).catch(() => {
      /* nothing left to clean */
    });
  }
}

async function archiveGeneration(
  casesRoot: string,
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
  const scope = { casesRoot, caseDir };
  // The worker opens the live database by name, so the name is judged before and after (#1846): a
  // link to another case's database, or a swap during the snapshot, fails the export.
  const snapshotted = await withPinnedCaseFile(scope, liveDbPath, () =>
    caseSqliteWorker.request<boolean>({ op: "backupDatabase", dbPath: liveDbPath, targetPath: snapshotPath }),
  ).catch(refusedAs(dbRel));

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
    // The check and the read are ONE operation on ONE descriptor (storage/caseFileRead.ts). Reading
    // the path after checking it let a process controlling the case directory swap the approved file
    // — or a folder above it (#1846) — for a link and seal another file into the encrypted export.
    // The same open refuses a FIFO instead of hanging on it.
    const data = await readCaseFile(scope, fullPath).catch((err: unknown) => {
      refusedAs(rel)(err);
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
  beforePublish?: RestoreCaseZipOptions["beforePublish"];
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
  /** Where the archive came from, or null when it carried no usable manifest — an export from
   * before manifests, or one whose manifest does not parse. Non-null means every entry was checked
   * against it and matched; see caseArchiveManifest.ts for what that does and does not prove. */
  provenance: CaseArchiveProvenance | null;
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
  // Central directory only: sizes, ratio and structure are checked before anything inflates, and
  // every entry then streams to the staging folder instead of into memory (#1828).
  const archiveEntries = listCaseZipEntries(zip);
  const manifestEntries = archiveEntries.filter((entry) => entry.name === ARCHIVE_MANIFEST_PATH);
  if (manifestEntries.length > 1) {
    throw new Error(`not a valid case archive: more than one ${ARCHIVE_MANIFEST_PATH}`);
  }
  const manifestEntry = manifestEntries[0]
    ? { path: ARCHIVE_MANIFEST_PATH, data: readCaseZipEntry(zip, manifestEntries[0]) }
    : undefined;
  const manifestCounts = countsFromManifest(manifestEntry);
  const manifest = parseArchiveManifest(manifestEntry);
  const files = archiveEntries
    .filter((entry) => entry.name !== ARCHIVE_MANIFEST_PATH)
    .map((entry) => ({ path: entry.name, entry }));

  const restored = await restoreCaseZip(store, zip, files, {
    targetCaseId: options.targetCaseId,
    beforePublish: options.beforePublish,
    // Integrity after path safety, and before the case is published. The order is deliberate: an
    // unsafe path is a question about where bytes would land, and it has to be settled before the
    // bytes are worth hashing at all.
    verify: manifest ? (digests) => verifyArchiveManifest(manifest, digests) : undefined,
    // The provenance record, kept with the case instead of dropped on the floor (#904). Written
    // AFTER the entries on purpose: a case that was itself imported carries the PREVIOUS
    // source-manifest.json as an ordinary file, and what belongs on disk afterwards is the manifest
    // of the archive just opened, not the one that travelled inside it. Verbatim bytes, so the file
    // still hashes to what the exporter recorded.
    extraFiles: manifestEntry && manifest ? [{ path: SOURCE_MANIFEST_PATH, data: manifestEntry.data }] : [],
    countEntities: manifestCounts === null,
  });
  return {
    meta: restored.meta,
    counts: manifestCounts ?? restored.counts,
    // Non-null: decryptBuffer above already threw on any container this build cannot read.
    formatVersion: formatVersion!,
    currentFormatVersion: CURRENT_FORMAT_VERSION,
    provenance: manifest ? provenanceOf(manifest) : null,
  };
}
