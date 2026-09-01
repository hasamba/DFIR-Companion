// Deterministic importer for Intact output — the trimmed VolWeb memory + YARA pair (#776).
//
// Intact is a separate program: it runs VolWeb over a RAM image, then COMBINES and TRIMS the result
// into two files. What reaches the Companion is therefore not raw Volatility output, and the row
// caps below are Intact's, not Volatility's:
//
//   memory_payload.json    { "plugins": { "<fully.qualified.Class>": [rows], … }, "yara": [ … ] }
//   yarascan_results.jsonl one JSON object per line: { Offset, Rule, Component, Value }
//
// Both files used to sniff as "log" — the generic AI fallback — so a 289 KB memory export went into
// a model prompt instead of the deterministic path, and forcing them through the right importer
// still parsed ZERO rows. Three separate blockers, none of them a near miss:
//
//   1. `isVolatilityPluginMap` requires every top-level value to be an array; `plugins` is an object.
//   2. The plugin keys are fully qualified (`volatility3.plugins.windows.pstree.PsTree`), and
//      `VOL_PLUGIN_KEY` is anchored at `^(windows|linux|mac)\.`.
//   3. The YARA importer parses YARA's TEXT CLI output, whose header line carries a file PATH.
//      These rows carry an ADDRESS instead — there is no path anywhere in them.
//
// This module is a thin ADAPTER, not a second memory importer. It unwraps the container, rewrites
// the plugin keys into the `os.module` form the existing classifier expects, and hands the result
// straight to `parseMemory` — the column-fingerprint classifier and every per-category mapper
// (process tree with parent→child links, malfind → T1055, svcscan, dlllist, …) then do the work
// unchanged. Only the YARA half is new, because memory-resident YARA hits are graded differently
// from file-based ones. See yaraImport.ts for the file-based path.

import { boundedAggKey } from "./aggKey.js";
import { stampSourceArtifactHash } from "./canonicalEvent.js";
import { parseMemory, type MemoryImportOptions, type MemoryParseResult } from "./memoryImport.js";
import {
  aggregateEvents,
  isObject,
  maxEventsDefault,
  oneLine,
  type MappedEvent,
  type SiemEvent,
} from "./siemImport.js";
import { SEVERITY_RANK, type Severity } from "./stateTypes.js";
import { YARA_SOURCE } from "./yaraImport.js";
import { createHash } from "node:crypto";

type Row = Record<string, unknown>;

// Re-exported so a caller can take the memory-import entry point and its options from ONE module:
// this adapter is what routes and the ingest layer call, not parseMemory directly.
export type { MemoryImportOptions };

/** Tool tag added to every event this adapter produces, so the trimming is attributable. */
export const INTACT_SOURCE = "Intact";

/**
 * Intact's per-table row caps.
 *
 * They are properties of INTACT, not of Volatility and not of this importer, and nothing in either
 * file records them — so they are recorded here. A table that comes back holding exactly the cap
 * was almost certainly cut short, and a truncated read looks exactly like a clean one: absence in a
 * capped table proves nothing. Reporting at-or-above the cap over-reports a caveat rather than
 * hiding one, which is the safe direction. Raise these if Intact's trimming changes.
 */
export const INTACT_PLUGIN_ROW_CAP = 250;
/** Applies to the `yara` array INSIDE memory_payload.json, not to the standalone JSON-Lines file. */
export const INTACT_YARA_ROW_CAP = 100;

/**
 * The rule-file guard: a window of address space, and the number of DISTINCT rules inside it that
 * marks the window as a YARA rule set matching itself rather than a set of independent detections.
 *
 * On the sample this was built from, 22 hits landed within 14.6 KiB of one another while tripping
 * nine different webshell rules — on a Windows image with no web server, with the matched values
 * being the rule strings themselves. That is a rule file resident in RAM. Eight distinct rules in
 * 64 KiB is deliberately conservative: it demoted 22 of 256 hits on that sample and left every
 * scattered hit alone.
 */
export const INTACT_RULE_CLUSTER_WINDOW = 64 * 1024;
export const INTACT_RULE_CLUSTER_RULES = 8;

/** A plugin table (or the YARA array) that came back holding Intact's cap. */
export interface IntactTruncatedTable {
  name: string;
  rows: number;
}

export interface IntactParseResult extends MemoryParseResult {
  /** Tables whose read hit Intact's row cap — findings beyond it were never exported. */
  truncated: IntactTruncatedTable[];
  /** Distinct (Offset, Rule) YARA hits kept. */
  yaraHits: number;
}

// ───────────────────────────── shape recognition ─────────────────────────────

const VOL_MODULE_KEY = /^(windows|linux|mac)\.[a-z]/;
// The four columns Intact's YARA rows carry. A row with any OTHER key is some other NDJSON feed.
const YARA_ROW_KEYS = new Set(["offset", "rule", "component", "value"]);

/**
 * Reduce a fully qualified Volatility 3 plugin id to the `os.module` form the memory importer's
 * classifier and label logic expect: `volatility3.plugins.windows.pstree.PsTree` → `windows.pstree`.
 *
 * The LEAF module wins over the namespace, so a nested plugin
 * (`…windows.registry.userassist.UserAssist`) becomes `windows.userassist` rather than
 * `windows.registry` — the label the analyst reads names the plugin that produced the rows.
 * An already-plain key is returned untouched.
 */
export function normalizeVolatilityPluginKey(key: string): string {
  const parts = key.replace(/^volatility\d*\.plugins\./i, "").split(".");
  // Drop the trailing class name (`PsTree`, `CmdLine`) — Volatility classes are capitalised.
  if (parts.length > 1 && /^[A-Z]/.test(parts[parts.length - 1])) parts.pop();
  if (parts.length < 2) return parts.join(".");
  return `${parts[0]}.${parts[parts.length - 1]}`;
}

// The short, analyst-facing table name: the module half of a normalized key.
function tableLabel(key: string): string {
  const normalized = normalizeVolatilityPluginKey(key);
  return normalized.split(".").pop() || normalized;
}

function isIntactPayload(root: unknown): boolean {
  if (!isObject(root)) return false;
  const plugins = root.plugins;
  if (!isObject(plugins)) return false;
  const entries = Object.entries(plugins);
  return (
    entries.length > 0 &&
    entries.every(([, v]) => Array.isArray(v)) &&
    entries.some(([k]) => VOL_MODULE_KEY.test(normalizeVolatilityPluginKey(k)))
  );
}

function isIntactYaraRow(sample: unknown): boolean {
  if (!isObject(sample)) return false;
  const keys = Object.keys(sample);
  if (!keys.length || !keys.every((k) => YARA_ROW_KEYS.has(k.toLowerCase()))) return false;
  return typeof sample.Offset === "number" && typeof sample.Rule === "string" && !!sample.Rule.trim();
}

/**
 * Is this an Intact file? Consulted by the unified import detector on the SAME representative record
 * every other signature sees, and checked FIRST: the payload wrapper would otherwise fall through to
 * the generic event-shaped catch-all, and the YARA rows carry no field any other importer claims.
 */
export function isIntactMemoryFile(root: unknown, sample: Row | null): boolean {
  return isIntactPayload(root) || isIntactYaraRow(sample);
}

// ───────────────────────────── container parsing ─────────────────────────────

interface IntactInput {
  plugins: [string, Row[]][];
  yara: Row[];
  format: string;
}

// Read the two Intact shapes out of raw text. Returns null for anything else, so the caller falls
// back to the ordinary memory importer.
function readIntact(text: string): IntactInput | null {
  const trimmed = (text ?? "").trim();
  if (!trimmed) return null;

  if (trimmed[0] === "{" || trimmed[0] === "[") {
    try {
      const root: unknown = JSON.parse(trimmed);
      if (isIntactPayload(root)) {
        const obj = root as Row;
        const plugins = Object.entries(obj.plugins as Record<string, unknown[]>).map(
          ([k, v]) => [k, v.filter(isObject)] as [string, Row[]],
        );
        const yara = Array.isArray(obj.yara) ? obj.yara.filter(isObject) : [];
        return { plugins, yara, format: "intact-volweb" };
      }
      // A bare array of YARA rows — the inner set exported on its own.
      if (Array.isArray(root) && isIntactYaraRow(root.find(isObject))) {
        return { plugins: [], yara: root.filter(isObject), format: "intact-yara" };
      }
      return null;
    } catch {
      /* fall through to JSON Lines */
    }
  }

  // JSON Lines: one YARA hit per line.
  const rows: Row[] = [];
  for (const line of trimmed.split(/\r\n|\r|\n/)) {
    const l = line.trim();
    if (!l || l[0] !== "{") continue;
    try {
      const o: unknown = JSON.parse(l);
      if (isObject(o)) rows.push(o);
    } catch {
      /* skip an unparseable line rather than the whole file */
    }
  }
  if (!rows.length || !isIntactYaraRow(rows[0])) return null;
  return { plugins: [], yara: rows, format: "intact-yara" };
}

// ───────────────────────────── YARA hits in memory ─────────────────────────────

interface YaraHit {
  offset: number;
  rule: string;
  components: string[];
  value: string;
}

// Collapse the raw rows on (Offset, Rule). Two rows differing only in `Component` are two STRING
// matches of one rule at one address — one hit, not two.
function dedupeYaraRows(rows: readonly Row[]): YaraHit[] {
  const byPair = new Map<string, YaraHit>();
  for (const r of rows) {
    if (!isIntactYaraRow(r)) continue;
    const offset = r.Offset as number;
    const rule = (r.Rule as string).trim();
    const key = `${offset}|${rule.toLowerCase()}`;
    const component = typeof r.Component === "string" ? r.Component.trim() : "";
    const value = typeof r.Value === "string" ? r.Value.trim() : "";
    const existing = byPair.get(key);
    if (existing) {
      if (component && !existing.components.includes(component)) existing.components.push(component);
      if (!existing.value && value) existing.value = value;
      continue;
    }
    byPair.set(key, { offset, rule, components: component ? [component] : [], value });
  }
  return [...byPair.values()].sort((a, b) => a.offset - b.offset || a.rule.localeCompare(b.rule));
}

/**
 * Mark the hits that sit inside a dense many-rule window.
 *
 * `hits` must be sorted by offset. A window is dense when INTACT_RULE_CLUSTER_RULES or more DISTINCT
 * rules fall within INTACT_RULE_CLUSTER_WINDOW bytes of one another — the signature of a rule file
 * matching itself. Many hits of ONE rule in a small span is the opposite case (one region a single
 * signature covers) and is deliberately left alone.
 */
function ruleFileClusters(hits: readonly YaraHit[]): Set<number> {
  const marked = new Set<number>();
  const rulesInWindow = new Map<string, number>(); // rule -> hits currently inside [i, j)
  let j = 0; // first hit PAST the window opened at i — monotonic, so this is one linear pass
  let markedUpTo = 0; // high-water mark, so an overlapping window never re-marks the same hits
  for (let i = 0; i < hits.length; i++) {
    while (j < hits.length && hits[j].offset - hits[i].offset <= INTACT_RULE_CLUSTER_WINDOW) {
      const rule = hits[j].rule.toLowerCase();
      rulesInWindow.set(rule, (rulesInWindow.get(rule) ?? 0) + 1);
      j++;
    }
    if (rulesInWindow.size >= INTACT_RULE_CLUSTER_RULES) {
      for (let k = Math.max(i, markedUpTo); k < j; k++) marked.add(k);
      markedUpTo = Math.max(markedUpTo, j);
    }
    const leaving = hits[i].rule.toLowerCase();
    const left = (rulesInWindow.get(leaving) ?? 0) - 1;
    if (left > 0) rulesInWindow.set(leaving, left);
    else rulesInWindow.delete(leaving);
  }
  return marked;
}

// The aggregation key IS the (Offset, Rule) identity, so it is also what the stable event id is
// minted from — see intactYaraEventId.
function yaraAggKey(hit: YaraHit): string {
  return boundedAggKey(`intact-yara|${hit.rule.toLowerCase()}|${hit.offset.toString(16)}`);
}

/**
 * A CONTENT-derived event id, so one (Offset, Rule) is one timeline row no matter which file it
 * arrived in.
 *
 * The `yara` array inside memory_payload.json is a strict subset of yarascan_results.jsonl, stripped
 * of Component and Value — so an analyst importing both files, which is the obvious thing to do,
 * would otherwise double-count every hit they share. Forensic events dedupe by id at the state
 * merge, and every other importer numbers its events from a per-import prefix, so a stable id is
 * what makes the two imports converge. The richer file wins on description simply by being merged
 * last, exactly as a re-import of any artifact does.
 */
function intactYaraEventId(aggKey: string): string {
  return `iy${createHash("sha256").update(aggKey).digest("hex").slice(0, 16)}`;
}

/**
 * Map deduped hits to events.
 *
 * Memory-resident YARA hits default to LOW, one tier below the file-based importer's Medium. That
 * importer's reasoning — a match is a real detection against a NAMED FILE — does not survive the
 * move to RAM: there is no file, the matched values are frequently the rule strings themselves, and
 * on the sample this was built from 183 of 263 hits were Linux/Unix or web-server rules firing on a
 * Windows image with no web server. Low keeps them in the forensic timeline (Info would hide them
 * from synthesis entirely, which is the wrong answer for a genuine hit) while keeping ~84 unearned
 * rule names out of the suspicious tier. No IOCs are minted at all: a rule name matched at an
 * address names no file and no hash.
 */
function mapYaraHits(hits: readonly YaraHit[]): MappedEvent[] {
  const clustered = ruleFileClusters(hits);
  return hits.map((hit, i) => {
    const severity: Severity = clustered.has(i) ? "Info" : "Low";
    const where = `0x${hit.offset.toString(16)}`;
    const components = hit.components.length ? ` [${hit.components.slice(0, 8).join(", ")}]` : "";
    const value = hit.value ? ` — ${oneLine(hit.value).slice(0, 120)}` : "";
    const note = clustered.has(i)
      ? " (many distinct rules within one small span — a YARA rule set resident in memory, not independent detections)"
      : "";
    return {
      timestamp: "", // a memory scan has no event time — mergeDelta stamps it at import time
      description: `Intact YARA (memory): ${hit.rule} matched at ${where}${components}${value}${note}`.slice(
        0,
        600,
      ),
      severity,
      mitre: [], // a rule NAME is not a technique; the file-based path reads T#### from rule meta, which Intact strips
      aggKey: yaraAggKey(hit),
      sources: [YARA_SOURCE, INTACT_SOURCE],
    };
  });
}

// ───────────────────────────── the importer ─────────────────────────────

// Most-severe first, then noisiest, then earliest — the same order eventAggregate applies, so the
// two halves interleave the way a single aggregated pass would.
function bySeverityThenCount(a: SiemEvent, b: SiemEvent): number {
  return (
    SEVERITY_RANK[a.severity] - SEVERITY_RANK[b.severity] ||
    (b.count ?? 1) - (a.count ?? 1) ||
    (a.timestamp || "~").localeCompare(b.timestamp || "~")
  );
}

/**
 * Parse Intact output. Returns null when the text is not Intact's, so callers can fall through to
 * the ordinary memory importer.
 */
export function parseIntact(text: string, opts: MemoryImportOptions = {}): IntactParseResult | null {
  const input = readIntact(text);
  if (!input) return null;

  const truncated: IntactTruncatedTable[] = [];

  // The plugin half: rewrite the keys and hand the whole map to the existing memory importer, which
  // classifies each table by its columns and maps it. Nothing about those mappers is Intact-specific.
  const pluginMap: Record<string, Row[]> = {};
  for (const [key, rows] of input.plugins) {
    pluginMap[normalizeVolatilityPluginKey(key)] = rows;
    if (rows.length >= INTACT_PLUGIN_ROW_CAP) truncated.push({ name: tableLabel(key), rows: rows.length });
  }
  const plugins: MemoryParseResult = input.plugins.length
    ? parseMemory(JSON.stringify(pluginMap), opts)
    : {
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
        format: "empty",
        tool: "",
      };

  // The YARA half. Only the array INSIDE the payload is capped — yarascan_results.jsonl carries the
  // full set (263 hits on the sample, against the inner copy's 100), so it is never reported as cut.
  if (input.format === "intact-volweb" && input.yara.length >= INTACT_YARA_ROW_CAP)
    truncated.push({ name: "yara", rows: input.yara.length });
  const hits = dedupeYaraRows(input.yara);
  const { events: yaraEvents, groups: yaraGroups } = aggregateEvents(mapYaraHits(hits), {
    aggregate: opts.aggregate,
    minSeverity: opts.minSeverity,
    maxEvents: opts.maxEvents ?? maxEventsDefault(),
  });

  // Tag the whole import as Intact's, and give each YARA row the stable id that makes the two files
  // converge on one timeline row per (Offset, Rule).
  const tagged: SiemEvent[] = [
    ...plugins.events.map((e) => ({ ...e, sources: [...new Set([...(e.sources ?? []), INTACT_SOURCE])] })),
    ...yaraEvents.map((e) => ({ ...e, id: intactYaraEventId(e.aggKey ?? "") })),
  ];
  // Cap the COMBINED list, not each half: two independent caps would let one import emit twice the
  // configured maximum. Re-stamp against the ORIGINAL text — the plugin half was parsed from a
  // rewritten copy, and the artifact hash must point at the file the analyst actually stored.
  const events = stampSourceArtifactHash(
    tagged.sort(bySeverityThenCount).slice(0, opts.maxEvents ?? maxEventsDefault()),
    text,
  );

  const total = plugins.total + input.yara.length;
  const represented = events.reduce((n, e) => n + (e.count ?? 1), 0);
  return {
    events,
    iocs: plugins.iocs,
    total,
    kept: events.length,
    dropped: Math.max(0, total - represented),
    groups: plugins.groups + yaraGroups,
    tables: plugins.tables,
    injected: plugins.injected,
    processes: plugins.processes,
    connections: plugins.connections,
    format: input.format,
    tool: plugins.tool || "Volatility",
    truncated,
    yaraHits: hits.length,
  };
}

/** The Intact adapter in front of the ordinary memory importer. Pure. */
export function parseMemoryOrIntact(
  text: string,
  opts: MemoryImportOptions = {},
): MemoryParseResult & Partial<Pick<IntactParseResult, "truncated" | "yaraHits">> {
  return parseIntact(text, opts) ?? parseMemory(text, opts);
}

/**
 * The operator-facing disclosure for a truncated read — the same failure mode, and the same wording
 * shape, as a Velociraptor artifact that hit its collection row cap (see collectWarnings). A failed
 * import is loud; a truncated one looks exactly like a clean success, so absence has to be named.
 */
export function intactTruncationNote(truncated: readonly IntactTruncatedTable[]): string {
  if (!truncated.length) return "";
  return (
    `${truncated.length} table(s) hit Intact's row cap — ` +
    `${truncated.map((t) => `${t.name} (${t.rows})`).join("; ")}. Rows BEYOND the cap were never ` +
    `exported, so absence in these tables is not evidence of absence.`
  );
}
