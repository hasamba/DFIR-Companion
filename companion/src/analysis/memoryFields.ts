// Field-level helpers for the memory-forensics importer (memoryImport.ts).
//
// `cellStr` and `pickTime` were moved here from that file unchanged. It is frozen at its size-ledger
// cap, and these are pure per-cell helpers with no knowledge of plugins, tables or events — the
// natural place for the three field-reading fixes below to live beside them.

import { getCI, isObject, normalizeTime } from "./siemImport.js";

type Row = Record<string, unknown>;

// Resolve a cell to a display string. Volatility cells are primitives; a Rekall object cell (e.g. a
// rendered `_EPROCESS`) is reduced to its name/value.
export function cellStr(v: unknown): string {
  if (v == null) return "";
  if (typeof v === "string") return v;
  if (typeof v === "number" || typeof v === "boolean") return String(v);
  if (isObject(v)) {
    for (const k of ["name", "str", "repr", "value", "Name", "Value"]) {
      const s = getCI(v, k);
      if (typeof s === "string" && s.trim()) return s.trim();
      if (typeof s === "number") return String(s);
    }
    const cybox = getCI(v, "Cybox");
    if (isObject(cybox)) {
      const n = getCI(cybox, "Name");
      if (typeof n === "string" && n.trim()) return n.trim();
    }
    return "";
  }
  return "";
}

// The artifact's own time. Handles a Rekall time object ({epoch}) and a Volatility naive/ISO string;
// "N/A" / "-" / "0" / null render as undated. Never the import time.
export function pickTime(row: Row, keys: string[]): string {
  for (const k of keys) {
    const v = getCI(row, k);
    if (isObject(v)) {
      const ep = getCI(v, "epoch") ?? getCI(v, "value");
      const n = typeof ep === "number" ? ep : Number(cellStr(ep));
      if (Number.isFinite(n) && n > 1e8) {
        const d = new Date(n > 1e12 ? n : n * 1000);
        if (!Number.isNaN(d.getTime())) return d.toISOString();
      }
    }
    const raw = cellStr(v).trim();
    if (!raw || /^(n\/?a|-|0|none|null)$/i.test(raw)) continue;
    const t = normalizeTime(raw);
    if (t) return t;
  }
  return "";
}

/**
 * Time columns an UNCLASSIFIED plugin table may carry.
 *
 * The generic mapper used to look for CreateTime / Created / Time / Timestamp only, which is the
 * process-table vocabulary. A registry plugin dates its rows with `Last Write Time`, so every
 * UserAssist row landed undated with its real time sitting unread in the row — nine of them on the
 * sample this was found with. Ordered most-specific first: an explicit write/access time beats a
 * bare `Time` column when a table happens to carry both.
 */
export const GENERIC_TIME_KEYS = [
  "CreateTime",
  "Created",
  "Last Write Time",
  "LastWriteTime",
  "Last Written",
  "LastWrite",
  "Last Modified",
  "LastModified",
  "Access Time",
  "AccessTime",
  "Time",
  "time",
  "Timestamp",
];

// The placeholders Volatility prints for a value it could not read. None of them is a path.
const NOT_A_PATH = /^(n\/?a|-|none|null|unknown)$/i;
// Where an executable's name ends and its arguments begin.
const IMAGE_EXT = /\.(exe|dll|sys|com|scr|bat|cmd|ps1|vbs|js|jse|msi|efi|drv|ocx)\b/i;

/**
 * The IMAGE PATH inside a service's `Binary` column.
 *
 * That column is a COMMAND LINE, not a path: Windows stores `ImagePath` quoted when it contains
 * spaces, and arguments follow it. Stored verbatim it produced file IOCs that match nothing — a path
 * wearing its own quote characters, `svchost.exe -k RPCSS -p` as a "file", and a literal `N/A`. On
 * one real import 72 of 261 IOCs were unusable that way, which is noise in the one list an analyst
 * pivots on.
 *
 * Arguments are cut at the executable's EXTENSION, never at the first space: `C:\Program Files\…`
 * is a perfectly ordinary service path. A value with no path separator is refused, which is the rule
 * the importer already applied — a bare image name is not a file indicator.
 *
 * Returns "" when nothing usable is left. The caller still shows the full command line in the row
 * the analyst reads; only the INDICATOR is narrowed.
 */
export function serviceImagePath(raw: string): string {
  const s = (raw ?? "").trim();
  if (!s || NOT_A_PATH.test(s)) return "";
  const quoted = /^"([^"]+)"/.exec(s);
  let image = quoted ? quoted[1].trim() : s;
  if (!quoted) {
    const ext = IMAGE_EXT.exec(image);
    if (ext) image = image.slice(0, ext.index + ext[0].length);
  }
  image = image.trim();
  if (!image || NOT_A_PATH.test(image) || !/[\\/]/.test(image)) return "";
  return image.slice(0, 300);
}

/**
 * A file path fit to be an INDICATOR, or "" when the cell holds no path.
 *
 * The guard this replaces was `/[\\/]/.test(value)` — "does it contain a separator?" — and `N/A`,
 * the placeholder Volatility prints for a value it could not read, contains a forward slash. Every
 * path-bearing mapper in the importer therefore recorded `N/A` as a file IOC and stamped it on the
 * event's `path` field, where correlation keys on it.
 */
export function filePathIoc(raw: string): string {
  const s = (raw ?? "").trim();
  if (!s || NOT_A_PATH.test(s) || !/[\\/]/.test(s)) return "";
  return s.slice(0, 300);
}

/**
 * A memory region's start address, rendered for a human.
 *
 * Volatility's JSON renderer emits `Start VPN` as a decimal number and its text renderer as hex, so
 * one importer sees both. BigInt, not Number: a 64-bit virtual address can exceed 2^53, where a
 * double silently rounds — and this value is a DISCRIMINATOR, so a rounded one merges two regions.
 */
export function regionAddress(raw: string): string {
  const s = (raw ?? "").trim();
  if (!s || /^0x[0-9a-f]+$/i.test(s)) return s.toLowerCase();
  if (!/^\d+$/.test(s)) return s;
  try {
    return `0x${BigInt(s).toString(16)}`;
  } catch {
    return s;
  }
}
