// The Volatility / Rekall EXTRACTION layer of the memory importer: recognise an export's shape and
// turn it into header-keyed plugin tables (#933 item 12 moved it out of memoryImport.ts, which sat
// one line under its size ledger). Nothing here classifies a table or grades a row — that stays in
// memoryImport.ts, which consumes `extractTables`.
//
// Inputs accepted:
//   • Volatility 3 JSON renderer (`vol -r json …`): a JSON ARRAY of row objects; also a JSON-Lines
//     variant, and a combined `{ "<plugin>": [rows] }` map some orchestration emits.
//   • Volatility 3 TEXT/grid renderer (the DEFAULT `vol <plugin>`): an optional banner, a
//     TAB-separated column header, then TAB-separated data rows (malfind/pstree interleave a
//     hexdump + disassembly block per row, which is skipped).
//   • Rekall JSON renderer: a list of `[directive, payload]` statements.
//
// A table is returned even when it has NO ROWS? No — a zero-row table is reported by LABEL in
// `empty`, so the importer can say the export holds zero rows without ever claiming the plugin
// completed (a filename or a map key is a label the uploader chose; see memoryExportShape.ts).

import { cellStr } from "./memoryFields.js";
import { getCI, isObject } from "./siemImport.js";

type Row = Record<string, unknown>;

const REKALL_DIRECTIVES = new Set(["m", "t", "r", "s", "e", "p", "f", "L", "c"]);

export const SHORT_PLUGIN =
  /(pstree|pslist|psscan|psxview|netscan|netstat|connscan|connections|sockscan|sockets|malfind|hollowfind|ldrmodules|cmdline|cmdscan|consoles|svcscan|services|modscan|modules|driverscan|driverirp|dlllist|handles|getsids|envars|privileges|callbacks|ssdt|mutantscan|filescan|hivelist|hashdump)/;

export interface Table {
  plugin: string;
  rows: Row[];
}

const VOL_PLUGIN_KEY = /^(windows|linux|mac)\.[a-z]/; // lowercase os ⇒ Volatility (Velociraptor uses "Windows.")

export function isVolatilityPluginMap(root: unknown): boolean {
  if (!isObject(root) || Array.isArray(root)) return false;
  const entries = Object.entries(root);
  return (
    entries.length > 0 &&
    entries.every(([, v]) => Array.isArray(v)) &&
    entries.some(([k]) => VOL_PLUGIN_KEY.test(k))
  );
}

export function isRekallCommandList(root: unknown): boolean {
  if (!Array.isArray(root) || root.length === 0) return false;
  let stmts = 0,
    hits = 0;
  for (const el of root) {
    if (Array.isArray(el) && typeof el[0] === "string" && el[0].length <= 2) {
      stmts++;
      if (REKALL_DIRECTIVES.has(el[0])) hits++;
    }
  }
  return hits >= 2 && hits >= stmts * 0.5;
}

// Walk a Rekall `[directive, payload]` statement list into plugin tables.
function parseRekall(root: unknown[]): Table[] {
  const tables: Table[] = [];
  let curPlugin = "";
  let cur: Table | null = null;
  const startTable = (): void => {
    cur = { plugin: curPlugin, rows: [] };
    tables.push(cur);
  };
  for (const el of root) {
    if (!Array.isArray(el) || typeof el[0] !== "string") continue;
    const directive = el[0];
    const payload = el[1];
    if (directive === "m" && isObject(payload)) {
      const pl = getCI(payload, "plugin");
      const name = isObject(pl) ? cellStr(getCI(pl, "name")) : cellStr(pl);
      // The plugin name precedes its table; a later table picks it up via curPlugin.
      if (name) curPlugin = name;
    } else if (directive === "s" && isObject(payload)) {
      const nm = cellStr(getCI(payload, "name")) || cellStr(getCI(payload, "plugin_name"));
      if (nm) curPlugin = nm;
    } else if (directive === "t") {
      startTable();
    } else if (directive === "r" && isObject(payload)) {
      if (!cur) startTable();
      cur!.rows.push(payload);
    }
  }
  return tables.filter((t) => t.rows.length > 0);
}

export function pluginFromFilename(name: string | undefined): string {
  const n = (name ?? "").toLowerCase();
  const dotted = /\b(windows|linux|mac)\.(\w+)/.exec(n);
  if (dotted) return `${dotted[1]}.${dotted[2]}`;
  const m = SHORT_PLUGIN.exec(n);
  return m ? m[1] : "";
}

// ───────────────────────────── Volatility 3 TEXT/grid renderer ─────────────────────────────
//
// The DEFAULT `vol <plugin>` output (no `-r json`): a "Volatility 3 Framework <ver>" banner, a
// TAB-separated column header, then TAB-separated data rows. `malfind`/`pstree` interleave a
// multi-line hexdump + disassembly block AFTER each row — those continuation lines are skipped. We
// parse the grid into the SAME header-keyed Row objects the JSON path produces, so all the
// column-fingerprint classification and per-category mappers above are reused unchanged.

const VOL_TEXT_BANNER = /^Volatility 3 Framework\b/i;
const VOL_TEXT_HEXDUMP = /^[0-9a-fA-F]{2}( [0-9a-fA-F]{2}){3,}/; // a hexdump gutter line: "48 89 54 24 …"
const VOL_TEXT_DISASM = /^0x[0-9a-fA-F]+:/; // a disassembly line: "0x…:\tmov …"
// Column names that appear in Volatility 3 text headers — used (with the banner) to recognize the
// format when the banner was stripped. Lowercased; matched against the TAB-split header cells.
const VOL_TEXT_HEADER_COLS = new Set([
  "pid",
  "ppid",
  "process",
  "imagefilename",
  "comm",
  "offset(v)",
  "offset",
  "protection",
  "tag",
  "createtime",
  "exittime",
  "threads",
  "handles",
  "sessionid",
  "wow64",
  "args",
  "cmd",
  "localaddr",
  "foreignaddr",
  "localport",
  "foreignport",
  "proto",
  "state",
  "owner",
  "created",
  "name",
  "displayname",
  "binary",
  "start",
  "path",
  "base",
  "size",
  "start vpn",
  "end vpn",
]);

// Recognize a Volatility 3 text/grid export — the banner, or a TAB-separated header carrying several
// known Volatility column names. Pure; exported so the unified import detector can route to "memory".
export function looksLikeVolatilityText(text: string): boolean {
  const head = (text ?? "").slice(0, 4000);
  if (VOL_TEXT_BANNER.test(head.trimStart())) return true;
  for (const line of head.split(/\r\n|\r|\n/).slice(0, 12)) {
    if (!line.includes("\t")) continue;
    const cols = line.split("\t").map((c) => c.trim().toLowerCase());
    if (cols.filter((c) => VOL_TEXT_HEADER_COLS.has(c)).length >= 3) return true;
  }
  return false;
}

// Parse a Volatility 3 text/grid export into one header-keyed table (or null if no rows found).
export function parseVolatilityText(text: string, filename: string | undefined): Table | null {
  const lines = text.split(/\r\n|\r|\n/);
  let header: string[] | null = null;
  let i = 0;
  // Find the header: the first TAB-containing line that is not the banner / a progress line.
  for (; i < lines.length; i++) {
    const line = lines[i].replace(/\s+$/, "");
    if (!line.trim()) continue;
    const trimmed = line.trim();
    if (VOL_TEXT_BANNER.test(trimmed) || /^Progress:/i.test(trimmed)) continue;
    if (!line.includes("\t")) continue;
    header = line.split("\t").map((c) => c.trim());
    while (header.length && header[header.length - 1] === "") header.pop(); // drop trailing empties
    i++;
    break;
  }
  if (!header || !header.length) return null;

  const rows: Row[] = [];
  for (; i < lines.length; i++) {
    const raw = lines[i];
    const trimmed = raw.trim();
    if (!trimmed) continue;
    if (VOL_TEXT_DISASM.test(trimmed) || VOL_TEXT_HEXDUMP.test(trimmed)) continue; // hexdump/disasm continuation
    if (!raw.includes("\t")) continue; // ascii gutter etc.
    const cells = raw.split("\t");
    cells[0] = cells[0].replace(/^[*\s]+/, "").trim(); // strip pstree depth markers ("* ", "** ")
    if (cells.filter((c) => c.trim() !== "").length < 2) continue;
    const row: Row = {};
    header.forEach((col, idx) => {
      if (col) row[col] = (cells[idx] ?? "").trim();
    });
    rows.push(row);
  }
  if (!rows.length) return null;
  return { plugin: pluginFromFilename(filename), rows };
}

export function extractTables(
  text: string,
  filename: string | undefined,
): { tables: Table[]; format: string; tool: string } {
  const trimmed = text.trim();
  if (!trimmed) return { tables: [], format: "empty", tool: "" };

  let root: unknown;
  let parsed = false;
  try {
    root = JSON.parse(trimmed);
    parsed = true;
  } catch {
    /* NDJSON below */
  }

  if (parsed) {
    if (Array.isArray(root)) {
      if (isRekallCommandList(root)) return { tables: parseRekall(root), format: "rekall", tool: "Rekall" };
      const rows = root.filter(isObject) as Row[];
      return {
        tables: rows.length ? [{ plugin: pluginFromFilename(filename), rows }] : [],
        format: "volatility",
        tool: "Volatility",
      };
    }
    if (isObject(root) && isVolatilityPluginMap(root)) {
      const tables = Object.entries(root)
        .filter(([, v]) => Array.isArray(v))
        .map(([k, v]) => ({ plugin: k, rows: (v as unknown[]).filter(isObject) }))
        .filter((t) => t.rows.length > 0);
      return { tables, format: "volatility-map", tool: "Volatility" };
    }
    // A bare object that is not a plugin map is not a Volatility export (its rows are an array).
    return { tables: [], format: "empty", tool: "" };
  }

  // NDJSON: one Volatility row object per line (jsonl renderer).
  const rows: Row[] = [];
  for (const line of trimmed.split(/\r\n|\r|\n/)) {
    const l = line.trim();
    if (!l || l[0] !== "{") continue;
    try {
      const o = JSON.parse(l);
      if (isObject(o)) rows.push(o);
    } catch {
      /* skip */
    }
  }
  if (rows.length)
    return {
      tables: [{ plugin: pluginFromFilename(filename), rows }],
      format: "volatility-jsonl",
      tool: "Volatility",
    };

  // Volatility 3 TEXT/grid renderer (the default `vol <plugin>`, no -r json).
  if (looksLikeVolatilityText(trimmed)) {
    const table = parseVolatilityText(trimmed, filename);
    if (table) return { tables: [table], format: "volatility-text", tool: "Volatility" };
  }
  return { tables: [], format: "empty", tool: "" };
}
