// PE-sieve's own JSON report (github.com/hasherezade/pe-sieve) — #933 item 15's own honestly-
// buildable answer. The item asks to "distinguish original file bytes, reconstructed executables
// and raw memory regions" with "explicit treatment of relocation, import resolution,
// reconstruction and missing pages." This codebase has no PE structural-diff engine and building
// one from scratch was rejected as a genuine cold start (see RECOMMENDATION-933.15.md). PE-sieve
// already performs exactly this comparison (a live process's own module vs. its disk backing
// file) and publishes a documented, structured JSON report — this module parses that report the
// same way every other specialist-tool report in this codebase is parsed: read the tool's own
// already-computed verdict, add hedged context, never re-derive the analysis.
//
// ─────────────────────────── SEVERITY IS FROM THE REAL findevil PRECEDENT ───────────────────────
//
// memoryImport.ts's own MemProcFS `findevil` mapper already grades a specialist detector's verdict
// (PE_PATCHED -> High, PE_NOLINK/PRIVATE_RWX -> Medium, default -> Low) — this module's own table
// is built from that same precedent, not invented fresh. `code_scan` with a positive `patches`
// count is the closest analog to PE_PATCHED (confirmed patched code bytes). `headers_scan`'s own
// `is_pe_replaced` field is the one specific signal as strong as a confirmed replacement; every
// OTHER header field is the item's own "ordinary loader changes" guardrail case and grades Low,
// matching findevil's own weakest/default treatment, never the same level as real code patching.
//
// `mapping_scan`'s own `status` field has no third value and no separate boolean distinguishing a
// replaced/hollowed module from one whose backing file is merely unreachable — verified against
// PE-sieve's own documentation twice. That distinction exists ONLY in the top-level
// `scanned.modified.replaced`/`.unreachable_file` COUNTS, never per entry — so `mapping_scan`
// stays at one conservative Medium grade rather than guessing which case applies.

import type { Severity } from "./stateTypes.js";
import { aggregateEvents, addIoc, maxEventsDefault, type MappedEvent, type SiemIoc } from "./siemImport.js";
import { filePathIoc } from "./memoryFields.js";
import { boundedAggKey } from "./aggKey.js";
import type { MemoryImportOptions, MemoryParseResult } from "./memoryImport.js";

interface ModifiedCounts {
  total?: number;
  patched?: number;
  iat_hooked?: number;
  replaced?: number;
  hdr_modified?: number;
  implanted_pe?: number;
  implanted_shc?: number;
  unreachable_file?: number;
  other?: number;
}

interface ScannedSummary {
  total?: number;
  skipped?: number;
  errors?: number;
  modified?: ModifiedCounts;
}

interface PeSieveReport {
  pid?: number | string;
  main_image_path?: string;
  scanned?: ScannedSummary;
  scans?: Record<string, Record<string, unknown>>[];
}

/** True for PE-sieve's own real report shape — a scalar `pid`, a `scanned` OBJECT (never an
 * array, which is what keeps this from ever matching isVolatilityMap's own "every value is an
 * array" check), and a `scans` array. Verified against this codebase's own real isSandbox/
 * isVolatility/isVolatilityMap detection functions to have no field-name collision. */
export function isPeSieveReport(root: unknown): boolean {
  if (typeof root !== "object" || root === null || Array.isArray(root)) return false;
  const r = root as Record<string, unknown>;
  if (r.pid === undefined || r.pid === null) return false;
  const scanned = r.scanned;
  if (typeof scanned !== "object" || scanned === null || Array.isArray(scanned)) return false;
  return Array.isArray(r.scans);
}

function num(v: unknown): number {
  return typeof v === "number" && Number.isFinite(v) ? v : 0;
}

function str(v: unknown): string {
  return typeof v === "string" ? v.trim() : "";
}

const HEADER_FLAG_FIELDS = [
  "dos_hdr_modified",
  "file_hdr_modified",
  "nt_hdr_modified",
  "ep_modified",
  "sec_hdr_modified",
] as const;

interface Graded {
  severity: Severity;
  mitre: string[];
  note: string;
}

function gradeCodeScan(detail: Record<string, unknown>, moduleFile: string): Graded {
  const patches = num(detail.patches);
  const sections = num(detail.scanned_sections);
  if (patches > 0) {
    return {
      severity: "High",
      mitre: ["T1055"],
      note: `code_scan flagged ${patches} patch(es) across ${sections} scanned section(s) in ${moduleFile || "this module"} — PE-sieve's own finding of patched code bytes in memory.`,
    };
  }
  return {
    severity: "Medium",
    mitre: ["T1055"],
    note: `code_scan flagged ${moduleFile || "this module"} without a positive patch count.`,
  };
}

function gradeHeadersScan(detail: Record<string, unknown>, moduleFile: string): Graded {
  if (num(detail.is_pe_replaced) === 1) {
    return {
      severity: "High",
      mitre: ["T1055"],
      note: `headers_scan reports ${moduleFile || "this module"} as a replaced/hollowed PE (is_pe_replaced).`,
    };
  }
  const flagged = HEADER_FLAG_FIELDS.filter((f) => num(detail[f]) === 1);
  return {
    severity: "Low",
    mitre: [],
    note: `headers_scan found ${flagged.length ? flagged.join(", ") : "a header field"} modified in ${moduleFile || "this module"}. This alone does not establish malicious modification — relocation and import resolution routinely modify PE headers.`,
  };
}

function gradeMappingScan(detail: Record<string, unknown>, moduleFile: string): Graded {
  const mapped = str(detail.mapped_file);
  const mappedNote = mapped
    ? `mapped file: ${mapped}.`
    : "mapped_file was not resolved — the backing file may be unreachable or missing.";
  return {
    severity: "Medium",
    mitre: ["T1055"],
    note: `mapping_scan flagged ${moduleFile || "this module"}. ${mappedNote}`,
  };
}

function gradeIatScan(moduleFile: string): Graded {
  return {
    severity: "Medium",
    mitre: ["T1055"],
    note: `iat_scan flagged ${moduleFile || "this module"} for import-address-table hooking.`,
  };
}

function gradeUnrecognized(scanType: string, moduleFile: string): Graded {
  return {
    severity: "Low",
    mitre: [],
    note: `PE-sieve flagged ${moduleFile || "this module"} under an unrecognized scan type "${scanType}".`,
  };
}

function grade(scanType: string, detail: Record<string, unknown>, moduleFile: string): Graded {
  switch (scanType) {
    case "code_scan":
      return gradeCodeScan(detail, moduleFile);
    case "headers_scan":
      return gradeHeadersScan(detail, moduleFile);
    case "mapping_scan":
      return gradeMappingScan(detail, moduleFile);
    case "iat_scan":
      return gradeIatScan(moduleFile);
    default:
      return gradeUnrecognized(scanType, moduleFile);
  }
}

const MODIFIED_LABELS: Array<[keyof ModifiedCounts, string]> = [
  ["patched", "patched"],
  ["iat_hooked", "IAT-hooked"],
  ["replaced", "replaced"],
  ["hdr_modified", "header-modified"],
  ["implanted_pe", "implanted PE"],
  ["implanted_shc", "implanted shellcode"],
  ["unreachable_file", "unreachable"],
  ["other", "other"],
];

function summaryNote(pid: string, scanned: ScannedSummary): string {
  const modified = scanned.modified ?? {};
  const breakdown = MODIFIED_LABELS.map(([key, label]) => `${num(modified[key])} ${label}`).join(", ");
  return (
    `PE-sieve report for PID ${pid}: ${num(scanned.total)} module(s) scanned, ` +
    `${num(modified.total)} flagged (${breakdown}), ${num(scanned.skipped)} skipped, ${num(scanned.errors)} error(s).`
  );
}

/** Parse PE-sieve's own JSON report into the shared memory-forensics result shape. */
export function parseMemoryPeSieve(text: string, opts: MemoryImportOptions): MemoryParseResult {
  const empty: MemoryParseResult = {
    events: [],
    iocs: [],
    total: 0,
    kept: 0,
    dropped: 0,
    groups: 0,
    tables: 0,
    injected: 0,
    processes: 0,
    connections: 0,
    format: "pe-sieve",
    tool: "PE-sieve",
  };

  let root: unknown;
  try {
    root = JSON.parse(text);
  } catch {
    return empty;
  }
  if (!isPeSieveReport(root)) return empty;
  const report = root as PeSieveReport;

  const pid = str(report.pid) || String(report.pid ?? "");
  const scanned = report.scanned ?? {};
  const scans = report.scans ?? [];

  const sink = new Map<string, SiemIoc>();
  const mapped: MappedEvent[] = [];

  const modifiedTotal = num(scanned.modified?.total);
  mapped.push({
    timestamp: "",
    description: `PE-sieve: ${summaryNote(pid, scanned)}`.slice(0, 600),
    severity: modifiedTotal > 0 ? "Medium" : "Info",
    mitre: [],
    aggKey: boundedAggKey(`pe-sieve|summary|${pid}`),
    sources: ["PE-sieve"],
  });

  let flaggedCount = 0;
  for (const entry of scans) {
    const [scanType, detail] = Object.entries(entry)[0] ?? [];
    if (!scanType || !detail || typeof detail !== "object") continue;
    if (num(detail.status) !== 1) continue;
    flaggedCount++;

    const moduleFile = str(detail.module_file);
    const module = str(detail.module);
    const { severity, mitre, note } = grade(scanType, detail, moduleFile);

    if (moduleFile) addIoc(sink, "file", filePathIoc(moduleFile));

    mapped.push({
      timestamp: "",
      description: `PE-sieve: ${note}`.slice(0, 600),
      severity,
      mitre,
      aggKey: boundedAggKey(`pe-sieve|${pid}|${scanType}|${module}`),
      sources: ["PE-sieve"],
    });
  }

  const { events, groups } = aggregateEvents(mapped, {
    aggregate: opts.aggregate,
    minSeverity: opts.minSeverity,
    maxEvents: opts.maxEvents ?? maxEventsDefault(),
  });
  const maxIocs = opts.maxIocs ?? 5000;
  const represented = events.reduce((n, e) => n + (e.count ?? 1), 0);
  const total = 1 + flaggedCount;

  return {
    events,
    iocs: [...sink.values()].slice(0, maxIocs),
    total,
    kept: events.length,
    dropped: Math.max(0, total - represented),
    groups,
    tables: 1,
    injected: flaggedCount,
    processes: 0,
    connections: 0,
    format: "pe-sieve",
    tool: "PE-sieve",
  };
}
