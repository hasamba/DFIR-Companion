// The email importer's option and result types. Moved out of emailImport.ts unchanged (#1736),
// which sits at the 800-line ceiling, to make room for the import debug recorder's calls there.
// emailImport.ts re-exports both, so every existing import path still works.

import type { ImportDebugRecorder } from "./importDebug.js";
import type { SiemEvent, SiemIoc } from "./siemImport.js";
import type { Severity } from "./stateTypes.js";

export interface EmailImportOptions {
  minSeverity?: Severity;
  maxEvents?: number;
  maxIocs?: number;
  debug?: ImportDebugRecorder; // this attempt's import debug recorder (#1736)
}

export interface EmailParseResult {
  events: SiemEvent[];
  iocs: SiemIoc[];
  total: number; // messages parsed (1 for a single .eml/.msg, 0 if nothing recoverable)
  kept: number; // events emitted
  dropped: number; // messages not represented
  groups: number; // = kept (parity with the other importers)
  format: string; // "eml" | "msg" | "empty"
  subject: string; // best-effort, for the import banner
  sender: string;
}
