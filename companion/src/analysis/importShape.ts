/**
 * Describe the SHAPE of an imported file that failed, for a support bundle (#1735).
 *
 * The report says what the file looks like — format, encoding, delimiter, column count, the type
 * class of each column — so the maintainer can debug an importer without seeing any evidence. It
 * must never carry a cell value. Column and JSON key names appear only when they are on the generic
 * allowlist in `importShapeColumns.ts`; anything else is `<unlisted>`. A type is a class ("integer",
 * "ip"), never a value. Pure: no I/O, never throws.
 */
import { KNOWN_COLUMN_NAME_LIST, normalizeColumnName } from "./importShapeColumns.js";

export type ColumnType =
  "empty" | "integer" | "number" | "timestamp" | "ip" | "hex" | "guid" | "bool" | "text" | "mixed";

/** `name` is the allowlisted spelling as it appeared in the file, or `<unlisted>`. */
export interface ColumnShape {
  name: string;
  type: ColumnType;
}

export interface ImportShape {
  fileBytes: number;
  format:
    | "csv"
    | "tsv"
    | "psv"
    | "jsonl"
    | "json"
    | "xml"
    | "evtx"
    | "sqlite"
    | "zip"
    | "gzip"
    | "binary"
    | "text"
    | "empty";
  encoding: "utf8" | "utf8-bom" | "utf16le" | "utf16be" | "binary" | "unknown";
  lineEnding: "lf" | "crlf" | "mixed" | "none";
  delimiter?: "," | "\t" | ";" | "|";
  /** Field count of the first line. */
  columnCount?: number;
  /** True only when at least one first-line field is on the allowlist. */
  headerRecognized?: boolean;
  /** Type profile over the first data rows (line 1 included only when no header is recognized). */
  columns?: ColumnShape[];
  jsonTopLevel?: "object" | "array" | "jsonl";
  /** Keys of the first object, same allowlist rule, typed by their value. */
  jsonKeys?: ColumnShape[];
  /** The caller's line count (LF bytes seen while streaming the file). */
  rowsCounted: number;
  rowCountExact: boolean;
}

export const KNOWN_COLUMN_NAMES: ReadonlySet<string> = new Set(
  KNOWN_COLUMN_NAME_LIST.map(normalizeColumnName),
);

const UNLISTED = "<unlisted>";
const MAX_HEAD_BYTES = 1024 * 1024;
const MAX_LINE_CHARS = 64 * 1024;
const MAX_NAME_CHARS = 64;
const MAX_COLUMNS = 256;
const MAX_PROFILE_ROWS = 200;
const DELIMITER_SAMPLE_LINES = 5;
const MAX_JSON_SCAN_CHARS = MAX_HEAD_BYTES;
const DELIMITERS = [",", "\t", ";", "|"] as const;
type Delimiter = (typeof DELIMITERS)[number];
type Encoding = ImportShape["encoding"];

/** LF bytes in a chunk — the route calls this while streaming a file to count its lines. */
export function countNewlines(chunk: Buffer): number {
  let n = 0;
  let i = chunk.indexOf(0x0a);
  while (i !== -1) {
    n++;
    i = chunk.indexOf(0x0a, i + 1);
  }
  return n;
}

export function describeImportShape(
  head: Buffer,
  totalBytes: number,
  lines: { count: number; exact: boolean },
): ImportShape {
  const base = {
    fileBytes: Number.isFinite(totalBytes) ? totalBytes : head.length,
    rowsCounted: Number.isFinite(lines.count) ? lines.count : 0,
    rowCountExact: lines.exact === true,
  };
  try {
    return describe(head.subarray(0, MAX_HEAD_BYTES), base);
  } catch {
    return { ...base, format: "binary", encoding: "unknown", lineEnding: "none" };
  }
}

type Base = Pick<ImportShape, "fileBytes" | "rowsCounted" | "rowCountExact">;

function describe(head: Buffer, base: Base): ImportShape {
  if (head.length === 0) {
    return { ...base, format: "empty", encoding: "unknown", lineEnding: "none" };
  }
  const magic = magicFormat(head);
  if (magic) return { ...base, format: magic, encoding: "binary", lineEnding: "none" };

  const encoding = detectEncoding(head);
  if (encoding === "binary") {
    return { ...base, format: "binary", encoding, lineEnding: "none" };
  }
  const text = decode(head, encoding);
  const lineEnding = detectLineEnding(text);
  const trimmed = text.replace(/^\uFEFF/, "");
  if (trimmed.trim() === "") return { ...base, format: "empty", encoding, lineEnding };
  const common = { ...base, encoding, lineEnding };

  const first = trimmed.trimStart()[0];
  if (first === "<") return { ...common, format: "xml" };
  if (first === "{" || first === "[") {
    const json = describeJson(trimmed);
    if (json) return { ...common, ...json };
  }
  return { ...common, ...describeDelimited(trimmed) };
}

// ── format by first bytes ────────────────────────────────────────────────────────────────────

function startsWith(buf: Buffer, sig: readonly number[]): boolean {
  if (buf.length < sig.length) return false;
  return sig.every((b, i) => buf[i] === b);
}

const ascii = (s: string): number[] => [...s].map((c) => c.charCodeAt(0));

function magicFormat(head: Buffer): ImportShape["format"] | null {
  if (startsWith(head, ascii("ElfFile\0"))) return "evtx";
  if (startsWith(head, ascii("SQLite format 3\0"))) return "sqlite";
  if (startsWith(head, [0x50, 0x4b, 0x03, 0x04]) || startsWith(head, [0x50, 0x4b, 0x05, 0x06])) {
    return "zip";
  }
  if (startsWith(head, [0x1f, 0x8b])) return "gzip";
  return null;
}

// ── encoding ─────────────────────────────────────────────────────────────────────────────────

function detectEncoding(head: Buffer): Encoding {
  if (startsWith(head, [0xef, 0xbb, 0xbf])) return validUtf8(head) ? "utf8-bom" : "unknown";
  if (startsWith(head, [0xff, 0xfe])) return "utf16le";
  if (startsWith(head, [0xfe, 0xff])) return "utf16be";
  const utf16 = guessUtf16(head);
  if (utf16) return utf16;
  const sample = head.subarray(0, 4096);
  if (sample.includes(0)) return "binary";
  if (controlRatio(sample) > 0.1) return "binary";
  return validUtf8(head) ? "utf8" : "unknown";
}

/** ASCII text in UTF-16 has a NUL in every other byte: odd positions for LE, even for BE. */
function guessUtf16(head: Buffer): Encoding | null {
  const n = Math.min(head.length, 512) & ~1;
  if (n < 4) return null;
  let evenNul = 0;
  let oddNul = 0;
  for (let i = 0; i < n; i += 2) {
    if (head[i] === 0) evenNul++;
    if (head[i + 1] === 0) oddNul++;
  }
  const pairs = n / 2;
  if (oddNul / pairs > 0.7 && evenNul / pairs < 0.1) return "utf16le";
  if (evenNul / pairs > 0.7 && oddNul / pairs < 0.1) return "utf16be";
  return null;
}

function controlRatio(sample: Buffer): number {
  if (sample.length === 0) return 0;
  let n = 0;
  for (const b of sample) {
    if (b < 0x09 || (b > 0x0d && b < 0x20 && b !== 0x1b) || b === 0x7f) n++;
  }
  return n / sample.length;
}

/** Valid UTF-8, allowing the head to end in the middle of a multi-byte sequence. */
function validUtf8(head: Buffer): boolean {
  const decoder = new TextDecoder("utf-8", { fatal: true });
  for (let cut = 0; cut <= 3 && cut < head.length; cut++) {
    try {
      decoder.decode(head.subarray(0, head.length - cut));
      return true;
    } catch {
      // A truncated trailing sequence — try a shorter slice.
    }
  }
  return false;
}

function decode(head: Buffer, encoding: Encoding): string {
  if (encoding === "utf16le") {
    const body = startsWith(head, [0xff, 0xfe]) ? head.subarray(2) : head;
    return body.subarray(0, body.length & ~1).toString("utf16le");
  }
  if (encoding === "utf16be") {
    const body = startsWith(head, [0xfe, 0xff]) ? head.subarray(2) : head;
    const even = Buffer.from(body.subarray(0, body.length & ~1));
    return even.swap16().toString("utf16le");
  }
  return head.toString("utf8");
}

function detectLineEnding(text: string): ImportShape["lineEnding"] {
  const crlf = (text.match(/\r\n/g) ?? []).length;
  const lf = (text.match(/\n/g) ?? []).length - crlf;
  if (crlf > 0 && lf > 0) return "mixed";
  if (crlf > 0) return "crlf";
  if (lf > 0) return "lf";
  return "none";
}

// ── value classes ────────────────────────────────────────────────────────────────────────────

const RE_INTEGER = /^[-+]?\d+$/;
const RE_NUMBER = /^[-+]?(\d+\.\d*|\.\d+|\d+)([eE][-+]?\d+)?$/;
const RE_BOOL = /^(true|false|yes|no)$/i;
const RE_GUID = /^\{?[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\}?$/i;
const RE_HEX = /^(0x[0-9a-f]+|[0-9a-f]{8,})$/i;
const RE_IPV4 = /^(\d{1,3}\.){3}\d{1,3}(:\d{1,5})?$/;
const RE_IPV6 = /^\[?[0-9a-f]{0,4}(:[0-9a-f]{0,4}){2,7}(%[\w.]+)?\]?$/i;
const RE_TIMESTAMPS = [
  /^\d{4}-\d{2}-\d{2}([ T]\d{1,2}:\d{2}(:\d{2}([.,]\d+)?)?)?\s*(Z|[+-]\d{2}:?\d{2}|UTC|GMT)?$/i,
  /^\d{1,2}[/.-]\d{1,2}[/.-]\d{2,4}(,?\s+\d{1,2}:\d{2}(:\d{2}([.,]\d+)?)?\s*([AP]M)?)?\s*(Z|UTC|GMT)?$/i,
  /^\d{4}\/\d{2}\/\d{2}(\s+\d{1,2}:\d{2}(:\d{2}([.,]\d+)?)?)?$/,
  /^\d{1,2}:\d{2}:\d{2}([.,]\d+)?$/,
];

function classify(raw: string): ColumnType {
  const v = raw.trim();
  if (v === "") return "empty";
  if (v.length > 64) return "text";
  if (RE_INTEGER.test(v)) return "integer";
  if (RE_NUMBER.test(v)) return "number";
  if (RE_BOOL.test(v)) return "bool";
  if (RE_GUID.test(v)) return "guid";
  if (RE_TIMESTAMPS.some((re) => re.test(v))) return "timestamp";
  if (RE_IPV4.test(v) || RE_IPV6.test(v)) return "ip";
  if (RE_HEX.test(v)) return "hex";
  return "text";
}

/** Fold a new cell class into a column's class: empties do not count, two classes are "mixed". */
function merge(current: ColumnType | undefined, next: ColumnType): ColumnType {
  if (current === undefined || current === "empty") return next;
  if (next === "empty" || next === current) return current;
  if ((current === "integer" && next === "number") || (current === "number" && next === "integer")) {
    return "number";
  }
  return "mixed";
}

function classifyJson(value: unknown): ColumnType {
  if (value === null || value === undefined) return "empty";
  if (typeof value === "boolean") return "bool";
  if (typeof value === "number") return Number.isInteger(value) ? "integer" : "number";
  if (typeof value === "string") return classify(value);
  return "text";
}

/** An allowlisted field keeps its spelling; anything else — including any value — is `<unlisted>`. */
export function safeColumnName(field: string): string {
  const name = field
    .trim()
    .replace(/^\uFEFF/, "")
    .replace(/^"(.*)"$/s, "$1")
    .trim();
  if (name === "" || name.length > MAX_NAME_CHARS || !/^[\x20-\x7e]+$/.test(name)) return UNLISTED;
  return KNOWN_COLUMN_NAMES.has(normalizeColumnName(name)) ? name : UNLISTED;
}

// ── JSON ─────────────────────────────────────────────────────────────────────────────────────

type JsonPart = Pick<ImportShape, "format" | "jsonTopLevel" | "jsonKeys">;

function describeJson(text: string): JsonPart | null {
  const lines = firstNonEmptyLines(text, 2);
  if (lines.length === 2 && lines.every((l) => parseObject(l) !== null)) {
    return { format: "jsonl", jsonTopLevel: "jsonl", jsonKeys: keysOf(parseObject(lines[0] ?? "")) };
  }
  const start = text.search(/\S/);
  if (text[start] === "{") {
    const obj = parseObject(text) ?? parseObject(balancedObject(text, start));
    return { format: "json", jsonTopLevel: "object", jsonKeys: obj ? keysOf(obj) : undefined };
  }
  if (text[start] === "[") {
    const whole = tryParse(text);
    let firstItem: Record<string, unknown> | null = null;
    if (Array.isArray(whole)) firstItem = asObject(whole[0]);
    else {
      const open = text.slice(start + 1).search(/\S/);
      const at = open === -1 ? -1 : start + 1 + open;
      if (at !== -1 && text[at] === "{") firstItem = parseObject(balancedObject(text, at));
    }
    return { format: "json", jsonTopLevel: "array", jsonKeys: firstItem ? keysOf(firstItem) : undefined };
  }
  return null;
}

function tryParse(text: string): unknown {
  try {
    return JSON.parse(text) as unknown;
  } catch {
    return undefined;
  }
}

function asObject(v: unknown): Record<string, unknown> | null {
  return v !== null && typeof v === "object" && !Array.isArray(v) ? (v as Record<string, unknown>) : null;
}

function parseObject(text: string): Record<string, unknown> | null {
  if (text === "") return null;
  return asObject(tryParse(text));
}

/** The text of the `{…}` that opens at `start`, string-aware; "" when it does not close in range. */
function balancedObject(text: string, start: number): string {
  let depth = 0;
  let inString = false;
  const end = Math.min(text.length, start + MAX_JSON_SCAN_CHARS);
  for (let i = start; i < end; i++) {
    const c = text[i];
    if (inString) {
      if (c === "\\") i++;
      else if (c === '"') inString = false;
    } else if (c === '"') inString = true;
    else if (c === "{" || c === "[") depth++;
    else if (c === "}" || c === "]") {
      depth--;
      if (depth === 0) return text.slice(start, i + 1);
    }
  }
  return "";
}

function keysOf(obj: Record<string, unknown> | null): ColumnShape[] | undefined {
  if (!obj) return undefined;
  return Object.keys(obj)
    .slice(0, MAX_COLUMNS)
    .map((k) => ({ name: safeColumnName(k), type: classifyJson(obj[k]) }));
}

// ── delimited text ───────────────────────────────────────────────────────────────────────────

type DelimitedPart = Pick<
  ImportShape,
  "format" | "delimiter" | "columnCount" | "headerRecognized" | "columns"
>;

function firstNonEmptyLines(text: string, max: number): string[] {
  const out: string[] = [];
  let pos = 0;
  while (out.length < max && pos < text.length) {
    let nl = text.indexOf("\n", pos);
    if (nl === -1) nl = text.length;
    const line = text.slice(pos, Math.min(nl, pos + MAX_LINE_CHARS)).replace(/\r$/, "");
    if (line.trim() !== "") out.push(line);
    pos = nl + 1;
  }
  return out;
}

/** Split one line on `d`, honouring simple double-quoted fields. */
function splitLine(line: string, d: Delimiter): string[] {
  const fields: string[] = [];
  let cur = "";
  let inQuotes = false;
  for (let i = 0; i < line.length; i++) {
    const c = line[i];
    if (c === '"') {
      if (inQuotes && line[i + 1] === '"') {
        cur += '"';
        i++;
      } else inQuotes = !inQuotes;
    } else if (c === d && !inQuotes) {
      fields.push(cur);
      cur = "";
    } else cur += c;
  }
  fields.push(cur);
  return fields;
}

/** The delimiter whose field count on line 1 is > 1 and matches most sample lines; widest wins. */
function pickDelimiter(sample: string[]): Delimiter | null {
  let best: { d: Delimiter; count: number } | null = null;
  for (const d of DELIMITERS) {
    const counts = sample.map((l) => splitLine(l, d).length);
    const firstCount = counts[0] ?? 1;
    if (firstCount < 2) continue;
    const agree = counts.filter((c) => c === firstCount).length;
    if (agree / counts.length < 0.8) continue;
    if (!best || firstCount > best.count) best = { d, count: firstCount };
  }
  return best?.d ?? null;
}

const FORMAT_BY_DELIMITER: Record<Delimiter, ImportShape["format"]> = {
  ",": "csv",
  ";": "csv",
  "\t": "tsv",
  "|": "psv",
};

function describeDelimited(text: string): DelimitedPart {
  const rows = firstNonEmptyLines(text, MAX_PROFILE_ROWS + 1);
  const delimiter = pickDelimiter(rows.slice(0, DELIMITER_SAMPLE_LINES));
  if (!delimiter) return { format: "text" };

  const header = splitLine(rows[0] ?? "", delimiter);
  const names = header.slice(0, MAX_COLUMNS).map((f) => safeColumnName(f));
  const headerRecognized = names.some((n) => n !== UNLISTED);
  const dataRows = headerRecognized ? rows.slice(1) : rows.slice(0, MAX_PROFILE_ROWS);

  const types: (ColumnType | undefined)[] = names.map(() => undefined);
  for (const row of dataRows) {
    const cells = splitLine(row, delimiter);
    for (let i = 0; i < names.length; i++) {
      types[i] = merge(types[i], classify(cells[i] ?? ""));
    }
  }
  return {
    format: FORMAT_BY_DELIMITER[delimiter],
    delimiter,
    columnCount: header.length,
    headerRecognized,
    columns: names.map((name, i) => ({ name, type: types[i] ?? "empty" })),
  };
}
