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
