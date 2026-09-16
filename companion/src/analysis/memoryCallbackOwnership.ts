// What a Volatility kernel callback/hook table (callbacks, ssdt, driverirp) actually establishes
// about ownership (#933 item 16). See RECOMMENDATION-933.16.md for the full design rationale,
// including a real Ollama design-review round that rejected the first draft's own Medium/T1014
// grading and its unguarded driver-name comparison.
//
// ─────────────────────────── REUSED, NOT REINVENTED ───────────────────────────
//
// Volatility 3's own real callbacks.py/ssdt.py/driverirp.py already resolve a raw kernel address
// against the loaded-module list THEMSELVES (via their own
// get_module_symbols_by_absolute_location()), reporting Module/Symbol as present when resolved,
// or Volatility's own NotAvailableValue() sentinel when the address falls outside every module it
// could enumerate. This module's whole job is to read that ALREADY-COMPUTED fact honestly — never
// to re-derive module-boundary resolution, which this codebase has no reason to attempt when the
// tool already did it. `isPlaceholderCell()` (memoryFields.ts) — already shipped, already used
// throughout memoryImport.ts — is the tool that recognizes Volatility's own "N/A"-shaped output.
//
// ─────────────────────────── WHY BOTH FACT KINDS GRADE LOW, NO MITRE ───────────────────────────
//
// A design-review round found the first draft's Medium/T1014 ("Rootkit") grading on a pure
// absence signal was itself the overclaim #933 item 16's own guardrail warns against: legitimate
// AV/EDR callbacks into pool-allocated memory routinely resolve to no module, so an "unresolved"
// row is common and expected, not evidence of hiding. This module never claims more than "the
// module/symbol table could not place this" — the guardrail's own words, "must remain unknown
// until evidence supports a stronger conclusion," are honored literally: nothing here can ever
// escalate without a corroboration signal this data shape does not carry (matches 933.15's own
// "no corroboration path" precedent).
//
// ─────────────────────────── THE IopInvalidDeviceRequest STUB EXCLUSION ───────────────────────────
//
// A real Windows kernel behavior the first draft never accounted for: a driver that does not
// implement every IRP major function (nearly all real drivers — there are ~28 IRP majors) has its
// UNIMPLEMENTED dispatch entries point at ntoskrnl.exe's own IopInvalidDeviceRequest. Without this
// exclusion, driverirp's own "Driver Name vs resolved Module" comparison would flag nearly every
// driver in every image for an entirely ordinary, structural reason — the exact kind of
// mass-false-positive the "do not classify every hook as a rootkit" guardrail exists to prevent.

import type { Severity } from "./stateTypes.js";
import { getCI, baseName, addIoc, type MappedEvent, type SiemIoc } from "./siemImport.js";
import { cellStr, isPlaceholderCell } from "./memoryFields.js";
import { boundedAggKey } from "./aggKey.js";

type Row = Record<string, unknown>;

export type PluginType = "callbacks" | "ssdt" | "driverirp";
export type CallbackFactKind = "unresolved" | "driver-name-mismatch";

export interface CallbackOwnershipFact {
  kind: CallbackFactKind;
  pluginType: PluginType;
  type: string;
  /** driverirp: the driver object's own Offset (unique per driver). callbacks/ssdt: Address. */
  identity: string;
  module: string;
  driverName: string;
  severity: Severity;
  mitre: string[];
  note: string;
}

export interface CallbackOwnershipResult {
  facts: CallbackOwnershipFact[];
  /** Rows resolved to a known module (or an ordinary unimplemented-IRP stub) — never one Info
   * event per row; a flat count avoids flooding the timeline (driverirp alone can produce
   * thousands of rows per image). */
  resolvedCount: number;
  /** True when `facts` hit `MAX_FACTS` — a sample, not the full set. */
  truncated: boolean;
}

const MAX_FACTS = 200; // defensive cap — a real image is not expected to reach this

/** The kernel's own real unimplemented-IRP-dispatch stub, inside ntoskrnl.exe — driverirp's own
 * Symbol reading this means "this driver simply didn't implement this IRP major," not a name
 * mismatch worth a fact. Verified against real Windows kernel behavior, never invented. */
export const KERNEL_UNIMPLEMENTED_IRP_SYMBOL = "IopInvalidDeviceRequest";

const DRIVER_OBJECT_PREFIX_RE = /^\\(?:driver|filesystem)\\/i;
const MODULE_EXT_RE = /\.(?:sys|exe|dll)$/i;

// Which of the 3 real kernelhook plugins a table is — driverirp checked first (its own columns
// are the most specific), before /driver/'s own generic "module" classification collides with it.
export function kernelHookPluginType(plugin: string, cols: Set<string>): PluginType {
  const p = plugin.toLowerCase();
  if (/driverirp/.test(p) || (cols.has("irp") && (cols.has("driver name") || cols.has("drivername"))))
    return "driverirp";
  if (/ssdt/.test(p) || cols.has("index")) return "ssdt";
  return "callbacks";
}

/** An empty string counts as absent the same as a placeholder — Volatility's own text renderer
 * can print either for a NotAvailableValue(). */
function str(row: Row, keys: readonly string[]): string {
  for (const k of keys) {
    const s = cellStr(getCI(row, k)).trim();
    if (s && !isPlaceholderCell(s)) return s;
  }
  return "";
}

/** Strips the DRIVER_OBJECT's own `\Driver\`/`\FileSystem\` prefix and lowercases — this is an
 * object name (author-chosen, no file extension), never a filename, and must not be compared to
 * the module's own base name verbatim. */
function normalizeDriverName(raw: string): string {
  return raw.replace(DRIVER_OBJECT_PREFIX_RE, "").toLowerCase();
}

/** The module's own base name, lowercased, with its file extension stripped — the shape a
 * DRIVER_OBJECT's own name is compared against. */
function normalizeModuleName(raw: string): string {
  return baseName(raw).toLowerCase().replace(MODULE_EXT_RE, "");
}

/** null means "no address/offset at all — skip this row entirely, not even into resolvedCount." */
function rowFact(row: Row, pluginType: PluginType): CallbackOwnershipFact | null | undefined {
  const typeKeys = pluginType === "driverirp" ? ["IRP"] : pluginType === "ssdt" ? ["Index"] : ["Type"];
  const type = str(row, typeKeys);
  const identityKeys = pluginType === "driverirp" ? ["Offset"] : ["Address", "Callback"];
  const identity = str(row, identityKeys);
  if (!identity) return undefined;

  const module = str(row, ["Module"]);
  const symbol = str(row, ["Symbol"]);
  const driverName = pluginType === "driverirp" ? str(row, ["Driver Name", "DriverName"]) : "";

  // Module absent is the item's own "outside known module regions" case. Symbol absent WITH
  // Module present is a different, ordinary condition (no PDB loaded for a known module) — never
  // framed as "could not place this address," which would be false; Volatility DID place it.
  if (!module) {
    return {
      kind: "unresolved",
      pluginType,
      type,
      identity,
      module,
      driverName,
      severity: "Low",
      mitre: [],
      note:
        "Volatility's own module table could not place this address in a known module. This can " +
        "mean an incomplete module listing, an unavailable page, or a legitimate security-software " +
        "callback into unlisted/pool memory — it does not by itself establish a hidden or " +
        "malicious hook.",
    };
  }

  if (pluginType === "driverirp" && driverName && symbol !== KERNEL_UNIMPLEMENTED_IRP_SYMBOL) {
    const normalizedDriver = normalizeDriverName(driverName);
    const normalizedModule = normalizeModuleName(module);
    // Exact equality only (not a substring check) — a substring comparison silently misses real
    // mismatches (e.g. "tcpip" driver vs an unrelated "tcpip6.sys" module), which is a worse
    // failure than the false-positive risk this whole check exists to weigh (Ollama code-review
    // finding). The remaining false-positive risk (KMDF/class-driver/minifilter framework
    // dispatch, e.g. wdf01000.sys/classpnp.sys/fltmgr.sys) is not filtered out programmatically —
    // no verified, exhaustive list of legitimate redirection modules exists to check against — so
    // it is named explicitly in the note instead, the same "state the benign cause, don't guess
    // at excluding it" choice already made for `unresolved`.
    if (normalizedDriver && normalizedModule && normalizedDriver !== normalizedModule) {
      return {
        kind: "driver-name-mismatch",
        pluginType,
        type,
        identity,
        module,
        driverName,
        severity: "Low",
        mitre: [],
        note: `This driver object's own name ("${driverName}") does not match its resolved module ("${module}"). This could be a legitimate multi-purpose driver object, a framework redirecting dispatch to shared code (e.g. a KMDF, class, or minifilter driver), a renamed service, or a stale name — it does not by itself establish a misleading or malicious driver.`,
      };
    }
  }

  return null; // resolved, names agree (or no Driver Name to compare) — counted, not faceted
}

/** Read one plugin table's own rows into bounded, hedged ownership facts. Never re-derives
 * module-boundary resolution — Volatility already did it; this only reports what it found. */
export function callbackOwnershipFacts(
  rows: readonly Row[],
  pluginType: PluginType,
): CallbackOwnershipResult {
  const facts: CallbackOwnershipFact[] = [];
  let resolvedCount = 0;
  let truncated = false;

  for (const row of rows) {
    const fact = rowFact(row, pluginType);
    if (fact === undefined) continue; // no address/offset at all — not even a resolved row
    if (!fact) {
      resolvedCount++;
      continue;
    }
    if (facts.length >= MAX_FACTS) {
      truncated = true;
      continue;
    }
    facts.push(fact);
  }

  return { facts, resolvedCount, truncated };
}

/** Turn every kernelhook table's own facts into timeline events: one Info summary count per
 * table, one event per noteworthy fact — never one event per ordinary resolved row. */
export function kernelHookEvents(
  tables: readonly { pluginType: PluginType; rows: Row[] }[],
  tool: string,
  sink: Map<string, SiemIoc>,
): MappedEvent[] {
  const mapped: MappedEvent[] = [];
  tables.forEach(({ pluginType, rows }, tableIndex) => {
    const { facts, resolvedCount, truncated } = callbackOwnershipFacts(rows, pluginType);
    if (resolvedCount > 0) {
      const cap = truncated
        ? " Some noteworthy facts reached this analysis's own cap and were not reported."
        : "";
      mapped.push({
        timestamp: "",
        description:
          `${tool}: ${pluginType} — ${resolvedCount} row(s) resolved to a known module.${cap}`.slice(0, 600),
        severity: "Info",
        mitre: [],
        // tableIndex: two tables of the SAME plugin type in one export must not share a key
        // (Ollama code-review finding) — never a real collision within one table's own summary.
        aggKey: boundedAggKey(`mem|kernelhook|${pluginType}|summary|${tableIndex}`),
        sources: [tool],
      });
    }
    for (const fact of facts) {
      // The driver OBJECT's own name (e.g. "\Driver\disk") is an NT object-namespace path, never
      // a file — only the resolved MODULE name is ever promoted, as a bare "process"-style name
      // (a kernel module name like "disk.sys" has no directory, so filePathIoc's own path-
      // separator requirement would silently drop it — matching how every other bare executable
      // name in this file is already promoted).
      if (fact.module) addIoc(sink, "process", baseName(fact.module));
      mapped.push({
        timestamp: "",
        description: `${tool}: ${pluginType} ${fact.type}: ${fact.note}`.slice(0, 600),
        severity: fact.severity,
        mitre: fact.mitre,
        aggKey: boundedAggKey(`mem|kernelhook|${fact.pluginType}|${fact.type}|${fact.identity}`),
        sources: [tool],
      });
    }
  });
  return mapped;
}
