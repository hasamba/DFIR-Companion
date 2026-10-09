// Zeek classic TSV logs (#2094) — Zeek's DEFAULT log writer, the `#separator`/`#fields` header block
// followed by tab-separated rows. The network importer reads Zeek JSON; this converts TSV rows into
// the same dotted-key records (`id.orig_h`, `answers`, …) so every existing Zeek reader applies
// unchanged. Each row is stamped `_path` from its block's `#path` header, which routes the stream
// without needing a filename. Concatenated / rotated logs repeat the header, so it is re-read per block.

type Row = Record<string, unknown>;

/** Default row ceiling — a safety bound on a pathological file; callers may pass a tighter cap. */
export const ZEEK_TSV_MAX_ROWS = 2_000_000;
const HEADER_SCAN_LINES = 20;

interface Block {
  sep: string;
  setSep: string;
  empty: string;
  unset: string;
  path: string;
  fields: string[];
  types: string[];
}

const NUMERIC = new Set(["time", "interval", "double", "count", "int", "port"]);

/** Two anchors: the first non-blank line is `#separator` AND a `#fields` line follows nearby. */
export function looksLikeZeekTsv(text: string): boolean {
  const lines = text.trimStart().split(/\r?\n/, HEADER_SCAN_LINES);
  if (!/^#separator\s/.test(lines[0] ?? "")) return false;
  return lines.some((l) => l.startsWith("#fields"));
}

function decodeEscapes(s: string): string {
  return s.includes("\\x")
    ? s.replace(/\\x([0-9a-fA-F]{2})/g, (_, h: string) => String.fromCharCode(parseInt(h, 16)))
    : s;
}

function scalar(raw: string, type: string): unknown {
  if (NUMERIC.has(type)) {
    const n = Number(raw);
    return Number.isFinite(n) ? n : raw;
  }
  if (type === "bool") return raw === "T" ? true : raw === "F" ? false : raw;
  return decodeEscapes(raw);
}

function convert(raw: string, type: string, b: Block): unknown {
  const container = /^(set|vector)\[(.+)\]$/.exec(type);
  if (raw === b.empty) return container ? [] : "";
  if (!container) return scalar(raw, type);
  const inner = container[2] ?? "string";
  return raw.split(b.setSep).map((v) => scalar(v, inner));
}

function toRow(line: string, b: Block): Row {
  const values = line.split(b.sep);
  const row: Row = b.path ? { _path: b.path } : {};
  b.fields.forEach((field, i) => {
    const raw = values[i];
    if (raw === undefined || raw === b.unset) return; // unset omits the key, as Zeek JSON does
    row[field] = convert(raw, b.types[i] ?? "string", b);
  });
  return row;
}

function headerValue(line: string, sep: string): string {
  // `#separator \x09` uses a space; every other header line uses the declared separator.
  const idx = line.indexOf(sep);
  return idx < 0 ? "" : line.slice(idx + sep.length);
}

function applyHeader(line: string, b: Block): Block {
  if (line.startsWith("#separator")) {
    return {
      ...b,
      sep: decodeEscapes(line.slice("#separator".length).trim()) || "\t",
      fields: [],
      types: [],
    };
  }
  const key = line.slice(1).split(b.sep, 1)[0] ?? "";
  const value = headerValue(line, b.sep);
  switch (key) {
    case "set_separator":
      return { ...b, setSep: decodeEscapes(value) || "," };
    case "empty_field":
      return { ...b, empty: value };
    case "unset_field":
      return { ...b, unset: value };
    case "path":
      return { ...b, path: value.trim().toLowerCase() };
    case "fields":
      return { ...b, fields: value.split(b.sep) };
    case "types":
      return { ...b, types: value.split(b.sep) };
    default:
      return b; // #open, #close and any other directive
  }
}

/** Parse Zeek TSV text into Zeek-JSON-shaped records. Rows before a `#fields` header are skipped. */
export function parseZeekTsv(text: string, maxRows: number = ZEEK_TSV_MAX_ROWS): Row[] {
  const rows: Row[] = [];
  let block: Block = {
    sep: "\t",
    setSep: ",",
    empty: "(empty)",
    unset: "-",
    path: "",
    fields: [],
    types: [],
  };
  for (const line of text.split(/\r?\n/)) {
    if (rows.length >= maxRows) break;
    if (!line) continue;
    if (line[0] === "#") {
      block = applyHeader(line, block);
      continue;
    }
    if (block.fields.length > 0) rows.push(toRow(line, block));
  }
  return rows;
}
