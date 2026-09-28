import type { ImportDebugRecorder } from "../analysis/importDebug.js";

/**
 * The sentence an import answer carries when detection only GUESSED the kind (#1795).
 *
 * Any event-shaped JSON no importer recognises falls to the SIEM importer's field auto-detection
 * (importDetect.ts, the last `return "siem"`), and its events land at the generic default
 * severity, Low — above Info, so in the forensic timeline the AI reads. Detection already knows the
 * match was not confident; this says so to the analyst instead of reporting a plain "siem". The
 * severity default is unchanged: every real SIEM import shares it.
 */
export const SIEM_FALLBACK_WARNING =
  "unrecognised JSON — imported as generic SIEM events (field auto-detection, default severity Low); " +
  "check what landed in the timeline, or add a custom importer if this is a known format";

/** True when detection fell through to the SIEM catch-all without a confident match. */
export function isGuessedSiem(kind: string, debug: ImportDebugRecorder | undefined): boolean {
  return kind === "siem" && debug?.summary().detection?.confident === false;
}

/** `{ warning }` for a non-confident SIEM fallback, else `{}` — spread into the 202 body. */
export function siemFallbackWarning(kind: string, debug: ImportDebugRecorder): { warning?: string } {
  return isGuessedSiem(kind, debug) ? { warning: SIEM_FALLBACK_WARNING } : {};
}

/**
 * The live "importing (kind)…" status detail, with the warning appended for a guessed SIEM import
 * (#1824). It still starts with `base`, so the dashboard keeps reading it as a deterministic ingest.
 */
export function importingDetail(base: string, kind: string, debug: ImportDebugRecorder | undefined): string {
  return isGuessedSiem(kind, debug) ? `${base} — ${SIEM_FALLBACK_WARNING}` : base;
}

/** One entry per imported file whose kind was a guess — for a multi-file answer (#1824). */
export function siemFallbackNotes(
  files: ReadonlyArray<{ file: string; kind: string; debug: ImportDebugRecorder | undefined }>,
): { warnings?: Array<{ file: string; warning: string }> } {
  const warnings = files
    .filter((f) => isGuessedSiem(f.kind, f.debug))
    .map((f) => ({ file: f.file, warning: SIEM_FALLBACK_WARNING }));
  return warnings.length ? { warnings } : {};
}
