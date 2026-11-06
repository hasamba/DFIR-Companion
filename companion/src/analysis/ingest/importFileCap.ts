/**
 * DFIR_MAX_IMPORT_FILE_MB — the largest file an importer may hold whole in memory. Read by the
 * import-file route and the drop folder before a read, and by the Velociraptor pull seam before it
 * hands a Hayabusa result to the whole-file Hayabusa importer (#1756).
 */
const MB = 1024 * 1024;
/** Matches DFIR_MAX_BODY_MB's default, so the two whole-file ceilings show an operator one number. */
export const DEFAULT_MAX_IMPORT_FILE_MB = 256;

/** DFIR_MAX_IMPORT_FILE_MB in bytes. Garbage, zero, negative or infinite falls back to the default:
 *  a negative cap would refuse every import, an infinite one would disable the protection, and
 *  both strings pass Number() and the generic settings validation. */
export function maxImportFileBytes(env: NodeJS.ProcessEnv = process.env): number {
  const n = Number(env.DFIR_MAX_IMPORT_FILE_MB);
  return (Number.isFinite(n) && n > 0 ? n : DEFAULT_MAX_IMPORT_FILE_MB) * MB;
}

/**
 * DFIR_MAX_UPLOAD_MB — the largest body POST /cases/:id/import-upload spools to disk (#2336). A
 * disk-fill guard, not a memory one: the upload is streamed to a file and then imported the way
 * Import-from-path imports it, so a file that must be held whole still meets the cap above. 2 GB
 * covers a 1 GB CloudTrail set or UAL export with headroom. Same fallback rules as the cap above.
 */
export const DEFAULT_MAX_UPLOAD_MB = 2048;

export function maxUploadBytes(env: NodeJS.ProcessEnv = process.env): number {
  const n = Number(env.DFIR_MAX_UPLOAD_MB);
  return Math.floor((Number.isFinite(n) && n > 0 ? n : DEFAULT_MAX_UPLOAD_MB) * MB);
}

/** The 413 sentence for an upload over DFIR_MAX_UPLOAD_MB, naming the knob that lifts it. */
export function uploadTooLargeMessage(maxBytes: number): string {
  const mb = Math.round((maxBytes / MB) * 100) / 100;
  return `upload exceeds the ${mb} MB limit — raise DFIR_MAX_UPLOAD_MB and restart the companion, or split the file`;
}
