import type { FileIdentity } from "./fileIdentity.js";
import { getCI, str } from "./siemImport.js";

/**
 * The SHA1 and file size of a Windows.Forensics.Amcache InventoryApplicationFile row (#2731). The
 * artifact selects `Size` and `substr(FileId, 4, 44) AS SHA1`. Windows computes that SHA1 over only
 * the first 30 MiB of the file, so the size travels with it: fileIdentity.ts decides from both whether
 * a client approval may use the hash. A size that is not a plain non-negative integer (decimal or
 * 0x-hex) is treated as not recorded.
 */
type Row = Record<string, unknown>;

function sizeOf(raw: unknown): number | undefined {
  if (typeof raw === "number") return Number.isSafeInteger(raw) && raw >= 0 ? raw : undefined;
  const v = str(raw).trim();
  const n = /^\d+$/.test(v) ? Number(v) : /^0x[0-9a-f]+$/i.test(v) ? parseInt(v, 16) : NaN;
  return Number.isSafeInteger(n) && n >= 0 ? n : undefined;
}

export function amcacheFileIdentity(row: Row): { fileIdentity?: FileIdentity } {
  const sha1 = str(getCI(row, "SHA1")).trim().toLowerCase();
  if (!/^[0-9a-f]{40}$/.test(sha1)) return {};
  const size = sizeOf(getCI(row, "Size"));
  return { fileIdentity: { sha1, ...(size !== undefined ? { size } : {}) } };
}
