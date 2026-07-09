import { readdir, readFile, writeFile, mkdir } from "node:fs/promises";
import { join, dirname, isAbsolute } from "node:path";
import { createHash } from "node:crypto";
import { isValidCaseId, type CaseStore } from "../storage/caseStore.js";
import type { CaseMeta } from "../types.js";
import { createZip, readZip, type ZipEntry } from "./zipArchive.js";
import { encryptBuffer, decryptBuffer } from "./caseEncryption.js";
import { getAppVersion } from "../version.js";

// Whole-case export/import (#54 follow-up): the entire case directory tree is zipped, then
// AES-256-GCM encrypted (via caseEncryption.ts) into a single `.dfircase` file that another
// DFIR Companion instance can restore byte-for-byte. Unlike the earlier JSON-snapshot export,
// this covers screenshots and raw imported evidence files too, not just derived state.

export const MIN_PASSWORD_LENGTH = 8;

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
    if (entry.isDirectory()) {
      out.push(...(await walkDir(join(dir, entry.name), rel)));
    } else {
      out.push(rel);
    }
  }
  return out;
}

/**
 * Build a `.dfircase` file: the whole case directory zipped, then AES-256-GCM encrypted with a
 * password-derived key. Throws if the case doesn't exist (no files under its directory).
 */
export async function exportEncryptedCase(store: CaseStore, caseId: string, password: string): Promise<Buffer> {
  if (!isValidCaseId(caseId)) throw new Error(`invalid case id "${caseId}"`);
  const caseDir = store.caseDir(caseId);
  const relPaths = (await walkDir(caseDir)).map((p) => p.replace(/\\/g, "/"));
  if (relPaths.length === 0) throw new Error(`case ${caseId} does not exist`);

  const entries: ZipEntry[] = [];
  const manifestFiles: Array<{ path: string; sha256: string; bytes: number }> = [];
  let totalBytes = 0;
  for (const rel of relPaths) {
    const data = await readFile(join(caseDir, rel));
    entries.push({ path: rel, data });
    manifestFiles.push({ path: rel, sha256: createHash("sha256").update(data).digest("hex"), bytes: data.length });
    totalBytes += data.length;
  }
  const manifest = {
    caseId,
    exportedAt: new Date().toISOString(),
    generatedBy: getAppVersion(),
    files: manifestFiles,
    totalFiles: manifestFiles.length,
    totalBytes,
  };
  entries.push({ path: "archive-manifest.json", data: Buffer.from(JSON.stringify(manifest, null, 2), "utf8") });

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

function rewriteCaseIdInJson(data: Buffer, targetCaseId: string): Buffer {
  const parsed = JSON.parse(data.toString("utf8")) as Record<string, unknown>;
  return Buffer.from(JSON.stringify({ ...parsed, caseId: targetCaseId }, null, 2), "utf8");
}

function rewriteCaseIdInJsonl(data: Buffer, targetCaseId: string): Buffer {
  const lines = data.toString("utf8").split("\n").filter((l) => l.trim().length > 0);
  const rewritten = lines.map((line) => {
    const parsed = JSON.parse(line) as Record<string, unknown>;
    return JSON.stringify({ ...parsed, caseId: targetCaseId });
  });
  return Buffer.from(rewritten.length ? rewritten.join("\n") + "\n" : "", "utf8");
}

const CASE_ID_JSON_PATHS = new Set(["case.json", "state/investigation.json"]);
const CASE_ID_JSONL_PATHS = new Set(["metadata/captures.jsonl", "metadata/imports.jsonl"]);

function countLines(data: Buffer | undefined): number {
  if (!data) return 0;
  return data.toString("utf8").split("\n").filter((l) => l.trim().length > 0).length;
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
 * internally consistent (case.json, state/investigation.json, each captures.jsonl/imports.jsonl
 * record). Everything else — screenshots, raw imports, every other state file — copies unchanged
 * either way.
 */
export async function importEncryptedCase(
  store: CaseStore,
  fileBuffer: Buffer,
  password: string,
  options: ImportEncryptedCaseOptions = {},
): Promise<ImportEncryptedCaseResult> {
  const zip = decryptBuffer(fileBuffer, password);
  const entries = readZip(zip).filter((e) => e.path !== "archive-manifest.json");

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
          rewrittenByPath.set(entry.path, rewriteCaseIdInJson(entry.data, targetCaseId));
        } else if (CASE_ID_JSONL_PATHS.has(normalizedPath)) {
          rewrittenByPath.set(entry.path, rewriteCaseIdInJsonl(entry.data, targetCaseId));
        }
      } catch {
        throw new Error(`not a valid case archive: corrupt ${entry.path}`);
      }
    }
  }

  const counts = countsFromEntries(entries);
  const caseDir = store.caseDir(targetCaseId);
  for (const dir of [
    store.screenshotsDir(targetCaseId),
    store.metadataDir(targetCaseId),
    store.stateDir(targetCaseId),
    store.reportsDir(targetCaseId),
    store.importsDir(targetCaseId),
  ]) {
    await mkdir(dir, { recursive: true });
  }

  for (const entry of entries) {
    const data = rewrittenByPath.get(entry.path) ?? entry.data;
    const target = join(caseDir, entry.path);
    await mkdir(dirname(target), { recursive: true });
    await writeFile(target, data);
  }

  const meta = await store.getCaseMeta(targetCaseId);
  if (!meta) throw new Error("import failed: case.json missing after write");
  return { meta, counts };
}
