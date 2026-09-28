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

/** `{ warning }` for a non-confident SIEM fallback, else `{}` — spread into the 202 body. */
export function siemFallbackWarning(kind: string, debug: ImportDebugRecorder): { warning?: string } {
  if (kind !== "siem") return {};
  return debug.summary().detection?.confident === false ? { warning: SIEM_FALLBACK_WARNING } : {};
}
