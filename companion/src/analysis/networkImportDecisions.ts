import type { ImportDebugRecorder } from "./importDebug.js";

// Split out of networkImport.ts (#1736), which sits at the 800-line cap: the telemetry budget's
// round-robin and the debug record of how each row's stream was chosen.

// Round-robin across families, each already in its own priority order, until `budget` rows.
export function interleave<T>(families: readonly (readonly T[])[], budget: number): T[] {
  const out: T[] = [];
  const cursors = families.map(() => 0);
  let progressed = true;
  while (out.length < budget && progressed) {
    progressed = false;
    for (let i = 0; i < families.length && out.length < budget; i++) {
      if (cursors[i] < families[i].length) {
        out.push(families[i][cursors[i]++]);
        progressed = true;
      }
    }
  }
  return out;
}

/**
 * Which rule routed a record (#1736): Suricata's own `event_type`, Zeek's `_path`, the per-stream
 * filename, or the field-shape guess. The stream NAME is never recorded — only which rule chose it.
 */
export function noteNetworkStream(
  debug: ImportDebugRecorder | undefined,
  etype: string,
  zpath: string,
  fileStream: string,
): void {
  if (!debug) return;
  if (etype) debug.fallback("suricata_event_type");
  else if (zpath) debug.fallback("zeek_path");
  else if (fileStream) debug.fallback("zeek_filename_stream");
  else debug.fallback("zeek_inferred_stream");
}
