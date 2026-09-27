// The memory importer's option and result types. Moved out of memoryImport.ts unchanged (#1736),
// which sits at its size-ledger cap, to make room for the import debug recorder's calls there.
// memoryImport.ts re-exports both, so every existing import path still works.

import type { ImportDebugRecorder } from "./importDebug.js";
import type { SiemEvent, SiemIoc } from "./siemImport.js";
import type { Severity } from "./stateTypes.js";

export interface MemoryImportOptions {
  aggregate?: boolean;
  minSeverity?: Severity;
  maxEvents?: number;
  maxIocs?: number;
  dllTelemetry?: boolean; // include dlllist/ldrmodules rows as Info events (default false — paths only)
  filename?: string; // weak plugin hint for a bare Volatility array carrying no plugin name
  debug?: ImportDebugRecorder; // this attempt's import debug recorder (#1736)
}

export interface MemoryParseResult {
  events: SiemEvent[];
  iocs: SiemIoc[];
  total: number; // rows across all tables
  kept: number; // events emitted (after aggregation + cap)
  dropped: number; // rows not represented (dll/handle telemetry / below floor / capped)
  groups: number; // distinct event groups before the cap
  tables: number; // plugin tables parsed
  injected: number; // malfind (injected-code) rows seen
  processes: number; // process-listing rows seen
  connections: number; // network-connection rows seen
  format: string; // "volatility" | "volatility-jsonl" | "volatility-map" | "volatility-text" | "volatility2-text" | "rekall" | "empty"
  tool: string; // "Volatility" | "Rekall" | ""
  note?: string; // the export's SHAPE (memoryExportShape.ts) — for the import note, never a completion claim
}
