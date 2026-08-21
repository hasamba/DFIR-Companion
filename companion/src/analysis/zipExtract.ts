// Turns a (possibly encrypted) zip into the list of files worth analyzing, applying the password
// ladder and the entry-safety rules. Split from zipArchive.ts so the ZIP format reader stays a
// format reader and the policy — which passwords to try, what counts as an interesting entry, how
// many to keep — lives in one reviewable place.
//
// This deliberately diverges from SO-CRATES, which keeps pcap_files[0] or non_hidden[0] and
// discards the rest of a multi-entry archive. A sample bundle of "pcap plus three dropped binaries"
// would lose three quarters of its evidence that way.

import { readZip } from "./zipArchive.js";
import { ZipPasswordError } from "./zipCrypto.js";

/** Hard cap on files taken from one archive, so a crafted zip cannot fan out into many uploads. */
export const MAX_ZIP_ENTRIES = 25;

export interface ExtractedEntry {
  path: string;
  data: Buffer;
}

export interface ZipExtractResult {
  entries: ExtractedEntry[];
  /** Which password opened it, or null when the archive was not encrypted. Never persisted. */
  passwordUsed: string | null;
  /** Nested archives that were reported rather than recursed into. */
  skippedNested: string[];
  /** True when MAX_ZIP_ENTRIES clipped the list. */
  truncated: boolean;
}

/**
 * Passwords to try, in order: the analyst's, then `infected`, then the MTA-style dated variant when
 * the filename carries a YYYY-MM-DD date. Mirrors what SO-CRATES tries server-side, plus the
 * analyst-supplied password it has no way to accept.
 */
export function candidatePasswords(filename: string, supplied?: string): string[] {
  const out: string[] = [];
  const trimmed = supplied?.trim();
  if (trimmed) out.push(trimmed);
  if (!out.includes("infected")) out.push("infected");
  const m = /(\d{4})-(\d{2})-(\d{2})/.exec(filename);
  if (m) {
    const dated = `infected_${m[1]}${m[2]}${m[3]}`;
    if (!out.includes(dated)) out.push(dated);
  }
  return out;
}

// Entries that are never evidence: directories, dotfiles, and macOS resource-fork metadata.
function isIgnorableEntry(path: string): boolean {
  if (path.endsWith("/")) return true;
  const base = path.split("/").pop() ?? "";
  if (base === "" || base.startsWith(".")) return true;
  return path.startsWith("__MACOSX/");
}

// Cheap central-directory scan for any entry with general-purpose bit 0 set. Used so an archive
// that was never encrypted reports passwordUsed: null, rather than naming whichever candidate
// happened to be tried first.
function archiveIsEncrypted(archive: Buffer): boolean {
  let eocd = -1;
  for (let i = archive.length - 22; i >= 0; i--) {
    if (archive.readUInt32LE(i) === 0x06054b50) {
      eocd = i;
      break;
    }
  }
  if (eocd < 0) return false;
  const total = archive.readUInt16LE(eocd + 10);
  let ptr = archive.readUInt32LE(eocd + 16);
  for (let i = 0; i < total; i++) {
    // The offset comes straight from the EOCD, which the uploader controls. Without this bound a
    // crafted value past the end of the buffer surfaces as Node's internal ERR_OUT_OF_RANGE from
    // readUInt32LE; the analyst should get the same corrupt-archive wording every other malformed
    // path produces.
    if (ptr + 46 > archive.length) throw new Error("corrupt ZIP: central directory out of bounds");
    if (archive.readUInt32LE(ptr) !== 0x02014b50) return false;
    if ((archive.readUInt16LE(ptr + 8) & 0x0001) !== 0) return true;
    ptr +=
      46 + archive.readUInt16LE(ptr + 28) + archive.readUInt16LE(ptr + 30) + archive.readUInt16LE(ptr + 32);
  }
  return false;
}

// Zip-slip guard: an entry must stay inside the archive's own namespace.
function assertContained(path: string): void {
  const normalized = path.replace(/\\/g, "/");
  if (normalized.startsWith("/") || /^[a-zA-Z]:/.test(normalized) || normalized.split("/").includes("..")) {
    throw new Error(`zip entry "${path}" resolves outside the archive`);
  }
}

/**
 * Extract the analyzable file entries from `archive`. Tries each candidate password in turn and
 * rethrows the last failure with an actionable message once all of them fail.
 */
export function extractZipEntries(archive: Buffer, filename: string, supplied?: string): ZipExtractResult {
  const candidates = candidatePasswords(filename, supplied);
  const encrypted = archiveIsEncrypted(archive);
  let raw: { path: string; data: Buffer }[] | null = null;
  let passwordUsed: string | null = null;
  let lastErr: unknown = null;

  // An unencrypted archive opens on the first attempt with the password simply ignored, so there is
  // no separate probe here — archiveIsEncrypted only decides what we REPORT as passwordUsed.
  for (const pw of candidates) {
    try {
      raw = readZip(archive, { password: pw });
      passwordUsed = encrypted ? pw : null;
      break;
    } catch (err) {
      lastErr = err;
      // Not a password problem (corrupt / zip bomb / ZIP64 / unopenable AE header) — trying more
      // passwords cannot help, so fail immediately with the real reason.
      if (!(err instanceof ZipPasswordError)) throw err;
      if (err.reason === "unsupported-encryption") throw err;
    }
  }

  if (!raw) {
    const tried = candidates.length === 1 ? "the default password" : `${candidates.length} passwords`;
    throw new Error(
      `could not open "${filename}": wrong password (tried ${tried}). ` +
        `Enter the archive password in the import dialog.`,
      { cause: lastErr },
    );
  }

  const skippedNested: string[] = [];
  const entries: ExtractedEntry[] = [];
  let truncated = false;

  for (const e of raw) {
    assertContained(e.path);
    if (isIgnorableEntry(e.path)) continue;
    if (e.data.subarray(0, 2).toString("latin1") === "PK") {
      skippedNested.push(e.path);
      continue;
    }
    if (entries.length >= MAX_ZIP_ENTRIES) {
      truncated = true;
      break;
    }
    entries.push({ path: e.path, data: e.data });
  }

  return { entries, passwordUsed, skippedNested, truncated };
}
