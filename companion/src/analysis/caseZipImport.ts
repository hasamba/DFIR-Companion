import { createHash } from "node:crypto";
import { isValidCaseId, type CaseStore } from "../storage/caseStore.js";
import type { CaseMeta } from "../types.js";
import {
  countsFromEntries,
  isSafeZipEntryPath,
  openPlainCaseZip,
  restoreCaseEntries,
  type CaseImportCounts,
  type RestoreCaseEntriesOptions,
} from "./caseExportArchive.js";
import type { ArchiveEntry } from "./caseArchiveManifest.js";

/**
 * Import the plain ZIP that "Archive to ZIP" writes (caseArchive.ts archiveCase) back into a NEW
 * case (#1784).
 *
 * That archive holds every case file under one `<caseId>/` folder, plus
 * `<caseId>/archive-manifest.json` listing each file's SHA-256 and byte size. Unlike a `.dfircase`
 * package it has no password, so nothing authenticates it: the manifest is an integrity check (the
 * archive is complete and unchanged since it was written, or was re-zipped correctly), never proof
 * against someone who can rewrite the manifest too.
 *
 * Portable renamed paths: when a case file's name could not be a ZIP entry name unchanged, the
 * archive stores it under a portable name and records the real one as `originalPath`. The import
 * keeps the PORTABLE name, the same rule the `.dfircase` import follows — the portable name is the
 * one every platform can write, and the manifest still ties it to the original.
 */

const MANIFEST_PATH = "archive-manifest.json";
const SHA256_HEX = /^[0-9a-fA-F]{64}$/;
// The only compression methods this build writes and reads: stored and DEFLATE.
const SUPPORTED_METHODS = new Set([0, 8]);

export interface ImportZipArchiveOptions {
  targetCaseId?: string;
  beforePublish?: RestoreCaseEntriesOptions["beforePublish"];
}

export interface ImportZipArchiveResult {
  meta: CaseMeta;
  counts: CaseImportCounts;
  /** True when the archive carried a manifest and every file matched it. */
  verified: boolean;
  /** The case id the archive was written under — stale when the import renamed it. */
  sourceCaseId: string;
}

interface ZipManifestFile {
  path: string;
  sha256: string;
  bytes: number;
}

interface ZipManifest {
  caseId: string;
  files: ZipManifestFile[];
}

function invalid(reason: string): Error {
  return new Error(`not a valid case archive: ${reason}`);
}

export async function importZipArchiveCase(
  store: CaseStore,
  buffer: Buffer,
  options: ImportZipArchiveOptions = {},
): Promise<ImportZipArchiveResult> {
  // The central directory is checked BEFORE readZip inflates anything, so an entry this build
  // cannot decode is refused without spending memory on the rest of the archive.
  assertSupportedEntries(buffer);
  const raw = openPlainCaseZip(buffer);
  // A pure directory entry ("INC-1/screenshots/") carries no bytes and is recreated by the files
  // under it. Any other entry keeps its raw path and is judged by the safety check below.
  const files = raw.filter((entry) => !(entry.path.endsWith("/") && entry.data.length === 0));
  const { caseFolder, entries: stripped } = stripCaseFolder(files);

  const manifestEntry = stripped.find((entry) => entry.path === MANIFEST_PATH);
  const manifest = manifestEntry ? parseZipManifest(manifestEntry.data) : null;
  if (manifest && manifest.caseId !== caseFolder) {
    throw invalid(`manifest case id "${manifest.caseId}" does not match the case folder "${caseFolder}"`);
  }
  // The manifest describes the case; it is not case content, so it is never written into the case.
  const entries = stripped.filter((entry) => entry.path !== MANIFEST_PATH);

  const { meta, sourceCaseId } = await restoreCaseEntries(store, entries, {
    targetCaseId: options.targetCaseId,
    beforePublish: options.beforePublish,
    // Runs after the restore's own path-safety pass and before any write.
    verify: (checked, caseJsonId) => {
      if (caseJsonId !== caseFolder) {
        throw invalid(`case.json case id "${caseJsonId}" does not match the case folder "${caseFolder}"`);
      }
      if (manifest) verifyZipManifest(manifest, checked);
    },
  });
  return { meta, counts: countsFromEntries(entries), verified: manifest !== null, sourceCaseId };
}

/**
 * Every entry must sit under ONE top folder that is a valid case id. Each RAW path passes the same
 * safety check the restore runs, before anything is stripped, so a `../x/case.json` entry is refused
 * as unsafe rather than reinterpreted. The restore checks the stripped paths again.
 */
function stripCaseFolder(files: ArchiveEntry[]): { caseFolder: string; entries: ArchiveEntry[] } {
  if (files.length === 0) throw invalid("the archive is empty");
  let caseFolder: string | undefined;
  const entries: ArchiveEntry[] = [];
  for (const entry of files) {
    if (!isSafeZipEntryPath(entry.path)) throw invalid(`unsafe entry path "${entry.path}"`);
    const slash = entry.path.indexOf("/");
    const top = slash > 0 ? entry.path.slice(0, slash) : "";
    if (!top || (caseFolder !== undefined && top !== caseFolder)) {
      throw invalid(`every file must sit inside one case folder ("${entry.path}" does not)`);
    }
    caseFolder = top;
    entries.push({ path: entry.path.slice(slash + 1), data: entry.data });
  }
  if (!caseFolder || !isValidCaseId(caseFolder)) {
    throw invalid(`the top folder "${caseFolder ?? ""}" is not a valid case id`);
  }
  return { caseFolder, entries };
}

/** A present manifest must be well-formed. A malformed one is refused, never ignored. */
function parseZipManifest(data: Buffer): ZipManifest {
  let parsed: unknown;
  try {
    parsed = JSON.parse(data.toString("utf8"));
  } catch {
    throw invalid("archive-manifest.json is not valid JSON");
  }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw invalid("archive-manifest.json is not an object");
  }
  const record = parsed as Record<string, unknown>;
  if (typeof record.caseId !== "string" || !record.caseId) {
    throw invalid("archive-manifest.json has no caseId");
  }
  if (!Array.isArray(record.files)) throw invalid("archive-manifest.json has no files list");
  const seen = new Set<string>();
  const files = record.files.map((value: unknown): ZipManifestFile => {
    const file = (value && typeof value === "object" ? value : {}) as Record<string, unknown>;
    const { path, sha256, bytes } = file;
    if (typeof path !== "string" || !path) throw invalid("archive-manifest.json has a row with no path");
    if (typeof sha256 !== "string" || !SHA256_HEX.test(sha256)) {
      throw invalid(`archive-manifest.json has a malformed sha256 for "${path}"`);
    }
    if (typeof bytes !== "number" || !Number.isSafeInteger(bytes) || bytes < 0) {
      throw invalid(`archive-manifest.json has a malformed size for "${path}"`);
    }
    if (seen.has(path)) throw invalid(`archive-manifest.json lists "${path}" twice`);
    seen.add(path);
    return { path, sha256: sha256.toLowerCase(), bytes };
  });
  return { caseId: record.caseId, files };
}

/** Throw unless the entries are exactly the files the manifest lists, by size and SHA-256. */
function verifyZipManifest(manifest: ZipManifest, entries: ArchiveEntry[]): void {
  const byPath = new Map(entries.map((entry) => [entry.path, entry]));
  for (const file of manifest.files) {
    const entry = byPath.get(file.path);
    if (!entry) throw invalid(`manifest lists a file the archive does not contain "${file.path}"`);
    // Size first: it is free, and a mismatch makes the hash pointless.
    if (entry.data.length !== file.bytes) throw invalid(`manifest size mismatch for "${file.path}"`);
    if (createHash("sha256").update(entry.data).digest("hex") !== file.sha256) {
      throw invalid(`manifest checksum mismatch for "${file.path}"`);
    }
  }
  const listed = new Set(manifest.files.map((file) => file.path));
  for (const entry of entries) {
    if (!listed.has(entry.path)) {
      throw invalid(`archive contains a file the manifest does not list "${entry.path}"`);
    }
  }
}

/**
 * Refuse an entry this build cannot decode faithfully. readZip already refuses an encrypted entry
 * (it has no password), but it reads any method it does not know as if the bytes were stored, and
 * only the CRC would then catch it. This walks the central directory readZip has just accepted and
 * names the problem instead.
 */
function assertSupportedEntries(buffer: Buffer): void {
  let eocd = -1;
  for (let i = buffer.length - 22; i >= 0; i--) {
    if (buffer.readUInt32LE(i) === 0x06054b50) {
      eocd = i;
      break;
    }
  }
  if (eocd < 0) throw invalid("not a ZIP archive");
  const total = buffer.readUInt16LE(eocd + 10);
  let ptr = buffer.readUInt32LE(eocd + 16);
  for (let i = 0; i < total; i++) {
    if (ptr + 46 > buffer.length) throw invalid("corrupt ZIP: central directory out of bounds");
    const flag = buffer.readUInt16LE(ptr + 8);
    const method = buffer.readUInt16LE(ptr + 10);
    const nameLen = buffer.readUInt16LE(ptr + 28);
    const name = buffer.toString("utf8", ptr + 46, ptr + 46 + nameLen);
    if (flag & 0x0001) throw invalid(`zip entry "${name}" is encrypted`);
    if (!SUPPORTED_METHODS.has(method)) {
      throw invalid(`zip entry "${name}" uses unsupported compression method ${method}`);
    }
    ptr += 46 + nameLen + buffer.readUInt16LE(ptr + 30) + buffer.readUInt16LE(ptr + 32);
  }
}
