import { isValidCaseId, type CaseStore } from "../storage/caseStore.js";
import type { CaseMeta } from "../types.js";
import {
  isSafeZipEntryPath,
  restoreCaseZip,
  type CaseImportCounts,
  type CaseZipFile,
  type StagedDigest,
} from "./caseRestore.js";
import { listCaseZipEntries, readCaseZipEntry, type CaseZipEntry } from "./caseZipReader.js";

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

export interface ImportZipArchiveOptions {
  targetCaseId?: string;
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
  // Central directory only (#1828): an encrypted entry, an unknown compression method, a malformed
  // structure and a size or ratio over a cap are all refused before anything inflates.
  const raw = listCaseZipEntries(buffer);
  // A pure directory entry ("INC-1/screenshots/") carries no bytes and is recreated by the files
  // under it. Any other entry keeps its raw path and is judged by the safety check below.
  const listed = raw.filter((entry) => !(entry.name.endsWith("/") && entry.size === 0));
  const { caseFolder, files: stripped } = stripCaseFolder(listed);

  const manifestFiles = stripped.filter((file) => file.path === MANIFEST_PATH);
  if (manifestFiles.length > 1) throw invalid(`more than one ${MANIFEST_PATH}`);
  const manifest = manifestFiles[0]
    ? parseZipManifest(readCaseZipEntry(buffer, manifestFiles[0].entry))
    : null;
  if (manifest && manifest.caseId !== caseFolder) {
    throw invalid(`manifest case id "${manifest.caseId}" does not match the case folder "${caseFolder}"`);
  }
  // The manifest describes the case; it is not case content, so it is never written into the case.
  const files = stripped.filter((file) => file.path !== MANIFEST_PATH);

  const { meta, sourceCaseId, counts } = await restoreCaseZip(store, buffer, files, {
    targetCaseId: options.targetCaseId,
    // Runs after the restore's own path-safety pass and before any write.
    preflight: (caseJsonId) => {
      if (caseJsonId !== caseFolder) {
        throw invalid(`case.json case id "${caseJsonId}" does not match the case folder "${caseFolder}"`);
      }
    },
    // Runs once every file is staged, before the case is published.
    verify: manifest ? (digests) => verifyZipManifest(manifest, digests) : undefined,
  });
  return { meta, counts, verified: manifest !== null, sourceCaseId };
}

/**
 * Every entry must sit under ONE top folder that is a valid case id. Each RAW path passes the same
 * safety check the restore runs, before anything is stripped, so a `../x/case.json` entry is refused
 * as unsafe rather than reinterpreted. The restore checks the stripped paths again.
 */
function stripCaseFolder(listed: CaseZipEntry[]): { caseFolder: string; files: CaseZipFile[] } {
  if (listed.length === 0) throw invalid("the archive is empty");
  let caseFolder: string | undefined;
  const files: CaseZipFile[] = [];
  for (const entry of listed) {
    if (!isSafeZipEntryPath(entry.name)) throw invalid(`unsafe entry path "${entry.name}"`);
    const slash = entry.name.indexOf("/");
    const top = slash > 0 ? entry.name.slice(0, slash) : "";
    if (!top || (caseFolder !== undefined && top !== caseFolder)) {
      throw invalid(`every file must sit inside one case folder ("${entry.name}" does not)`);
    }
    caseFolder = top;
    files.push({ path: entry.name.slice(slash + 1), entry });
  }
  if (!caseFolder || !isValidCaseId(caseFolder)) {
    throw invalid(`the top folder "${caseFolder ?? ""}" is not a valid case id`);
  }
  return { caseFolder, files };
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

/** Throw unless the staged files are exactly the files the manifest lists, by size and SHA-256. */
function verifyZipManifest(manifest: ZipManifest, digests: StagedDigest[]): void {
  const byPath = new Map(digests.map((digest) => [digest.path, digest]));
  for (const file of manifest.files) {
    const digest = byPath.get(file.path);
    if (!digest) throw invalid(`manifest lists a file the archive does not contain "${file.path}"`);
    if (digest.bytes !== file.bytes) throw invalid(`manifest size mismatch for "${file.path}"`);
    if (digest.sha256 !== file.sha256) throw invalid(`manifest checksum mismatch for "${file.path}"`);
  }
  const listed = new Set(manifest.files.map((file) => file.path));
  for (const digest of digests) {
    if (!listed.has(digest.path)) {
      throw invalid(`archive contains a file the manifest does not list "${digest.path}"`);
    }
  }
}
