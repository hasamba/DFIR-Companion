// What `windows.info` and `windows.crashinfo` say about the IMAGE, as one row (#933 item 12).
//
// windows.info's Variable/Value rows used to be twenty generic Info rows, so the kernel clock at
// capture, the symbol table, the layer stack and the OS build were scattered and invisible. They
// are now one Low row that says only what the rows say:
//
//   • "kernel SystemTime recovered from the image" — the shared clock value the plugin reads out
//     of the kernel; a snapshot may be smeared, so it is never "captured at".
//   • the layer stack, read STRUCTURALLY: any row whose Value is `<depth> <ClassName>` is a layer
//     and its Variable is the runtime layer name (`primary`, `memory_layer`, `base_layer` — not
//     fixed). A dump kind is named only for the class names in DUMP_LAYERS; `FileLayer` is the
//     backing file and establishes no acquisition format on its own.
//   • windows.crashinfo's DumpType as Volatility RENDERS it — `Full Dump (0x1)`, `Bitmap Dump
//     (0x5)`. A bitmap dump holds only the pages its bitmap lists; which pages were excluded is not
//     in the record, so it is never called a kernel or an active-memory dump.
//
// When the same upload holds an info table, every mapped row carries the facts in its canonical
// envelope, and rows of Medium or above say the kernel SystemTime in their text. One upload only.

import type { Severity } from "./stateTypes.js";
import type { MappedEvent } from "./siemImport.js";
import { getCI } from "./siemImport.js";
import { cellStr, isPlaceholderCell } from "./memoryFields.js";
import { breakHashRuns, identityMark, keyDigest, packTags, showToken } from "./recordIdentity.js";

type Row = Record<string, unknown>;

/** Volatility 3 layer classes whose name establishes the acquisition format. */
export const DUMP_LAYERS: Readonly<Record<string, string>> = {
  WindowsCrashDump32Layer: "crash dump",
  WindowsCrashDump64Layer: "crash dump",
  LimeLayer: "LiME",
  AVMLLayer: "AVML",
  VmwareLayer: "VMware",
  Elf64Layer: "ELF core",
  QemuSuspendLayer: "QEMU suspend",
  FileLayer: "the backing file",
};

const DUMP_TYPES: Readonly<Record<string, string>> = {
  "Full Dump (0x1)": "full dump",
  "Bitmap Dump (0x5)":
    "holds only the pages its bitmap lists; which pages were excluded is not in this record",
};

const LAYER_VALUE_RE = /^(\d+)\s+([A-Za-z_][A-Za-z0-9_]*)$/;
const RANK: Record<Severity, number> = { Info: 0, Low: 1, Medium: 2, High: 3, Critical: 4 };
const SHOWN_MAX = 200;
const DESCRIPTION_MAX = 600;

function shown(value: string, max = SHOWN_MAX): string {
  const t = breakHashRuns(showToken(value ?? ""));
  return t.length > max ? `${t.slice(0, max)}…` : t;
}

export interface ImageLayer {
  name: string;
  depth: number;
  cls: string;
}

export interface ImageFacts {
  source: "info" | "crashinfo";
  /** ISO, or "" when the value could not be read. */
  systemTime: string;
  systemTimeRaw: string;
  os?: string;
  is64?: boolean;
  symbols?: string;
  layers: ImageLayer[];
  /** The kind named by a known non-file layer class, when there is one. */
  dumpKind?: string;
  dumpType?: string;
  kernelBase?: string;
  dtb?: string;
  uptime?: string;
  comment?: string;
}

/** windows.info's fixed variables — a Variable/Value table is windows.info only when it carries them. */
const INFO_VARIABLES = new Set([
  "Kernel Base",
  "DTB",
  "Symbols",
  "Is64Bit",
  "IsPAE",
  "SystemTime",
  "NtMajorVersion",
  "NtMinorVersion",
  "NtSystemRoot",
  "NtProductType",
  "KdVersionBlock",
  "MachineType",
]);
const INFO_MIN_VARIABLES = 3;
const CRASH_COLUMNS = ["dumptype", "signature", "directorytablebase", "systemtime"];

/**
 * Is this table windows.info or windows.crashinfo? A plugin label is uploader-chosen, and a
 * two-column shape or a lone DumpType column is not provenance: the table must carry the plugin's
 * own fields, or a `windows.foo` table holding `Variable=SystemTime` would mint image facts and
 * stamp them on every High row of the upload.
 */
export function isImageInfoTable(plugin: string, cols: ReadonlySet<string>, rows: readonly Row[]): boolean {
  const p = plugin.toLowerCase();
  if (CRASH_COLUMNS.every((c) => cols.has(c))) return true;
  if (/(?:^|\.)crashinfo\b/.test(p) && cols.has("dumptype")) return true;
  if (!cols.has("variable") || !cols.has("value")) return false;
  const names = new Set(rows.map((r) => cellStr(getCI(r, "Variable")).trim()));
  return [...INFO_VARIABLES].filter((v) => names.has(v)).length >= INFO_MIN_VARIABLES;
}

/**
 * The three spellings Volatility has used: ISO with an offset (current), naive `YYYY-MM-DD
 * HH:MM:SS` (legacy — UTC, because the plugin converts FILETIME to UTC before rendering), and the
 * quick renderer's ` UTC` suffix. Anything else is not read.
 */
export function readSystemTime(raw: string): string {
  const v = (raw ?? "").trim();
  const m = /^(\d{4}-\d{2}-\d{2})[ T](\d{2}:\d{2}:\d{2}(?:\.\d+)?)(?:\s*UTC|(Z|[+-]\d{2}:?\d{2}))?$/.exec(v);
  if (!m) return "";
  const t = Date.parse(`${m[1]}T${m[2]}${m[3] ?? "Z"}`);
  return Number.isFinite(t) ? new Date(t).toISOString() : "";
}

function readInfo(rows: readonly Row[]): ImageFacts {
  const vars = new Map<string, string>();
  const layers: ImageLayer[] = [];
  for (const r of rows) {
    const name = cellStr(getCI(r, "Variable")).trim();
    const value = cellStr(getCI(r, "Value")).trim();
    // A placeholder (`-`, `N/A`, null) is an ABSENT value: it establishes nothing about the image.
    if (!name || !value || isPlaceholderCell(value)) continue;
    const layer = LAYER_VALUE_RE.exec(value);
    if (layer) layers.push({ name, depth: Number(layer[1]), cls: layer[2] });
    else vars.set(name, value);
  }
  const major = vars.get("NtMajorVersion");
  const minor = vars.get("NtMinorVersion");
  const lab = vars.get("NTBuildLab");
  const symbols = vars.get("Symbols");
  const known = layers.filter((l) => l.cls !== "FileLayer" && DUMP_LAYERS[l.cls]);
  const raw = vars.get("SystemTime") ?? "";
  return {
    source: "info",
    systemTime: readSystemTime(raw),
    systemTimeRaw: raw,
    ...(major && minor ? { os: `NT ${major}.${minor}${lab ? `, build lab ${lab}` : ""}` } : {}),
    ...(/^(?:true|false)$/i.test(vars.get("Is64Bit") ?? "")
      ? { is64: /^true$/i.test(vars.get("Is64Bit") ?? "") }
      : {}),
    ...(symbols ? { symbols: symbols.split("/").filter(Boolean).slice(-2).join("/") } : {}),
    layers,
    ...(known.length ? { dumpKind: [...new Set(known.map((l) => DUMP_LAYERS[l.cls]))].join(", ") } : {}),
    ...(vars.get("Kernel Base") ? { kernelBase: vars.get("Kernel Base") } : {}),
    ...(vars.get("DTB") ? { dtb: vars.get("DTB") } : {}),
  };
}

function cell(row: Row, key: string): string {
  const v = cellStr(getCI(row, key)).trim();
  return isPlaceholderCell(v) ? "" : v;
}

function readCrash(row: Row): ImageFacts {
  const raw = cell(row, "SystemTime");
  const dumpType = cell(row, "DumpType");
  const uptime = cell(row, "SystemUpTime");
  const comment = cell(row, "Comment");
  const dtb = cell(row, "DirectoryTableBase");
  return {
    source: "crashinfo",
    systemTime: readSystemTime(raw),
    systemTimeRaw: raw,
    layers: [],
    dumpKind: "crash dump",
    ...(dumpType ? { dumpType } : {}),
    ...(uptime ? { uptime } : {}),
    ...(comment ? { comment } : {}),
    ...(dtb ? { dtb } : {}),
  };
}

const colsOf = (rows: readonly Row[]): Set<string> =>
  new Set(Object.keys(rows[0] ?? {}).map((k) => k.toLowerCase()));
const isCrash = (rows: readonly Row[]): boolean => colsOf(rows).has("dumptype");

/**
 * The upload's image facts: windows.info and windows.crashinfo MERGED where they complement each
 * other — the info row is the base; the crash header adds its dump type, uptime and comment, and
 * its time only when windows.info has none (then the source says so).
 */
export function readImageFacts(tables: readonly { plugin: string; rows: Row[] }[]): ImageFacts | null {
  const found = tables
    .filter((t) => t.rows.length && isImageInfoTable(t.plugin, colsOf(t.rows), t.rows))
    .map((t) => (isCrash(t.rows) ? readCrash(t.rows[0]) : readInfo(t.rows)));
  const info = found.find((f) => f.source === "info");
  const crash = found.find((f) => f.source === "crashinfo");
  if (info && crash) {
    return {
      ...info,
      ...(crash.dumpType ? { dumpType: crash.dumpType } : {}),
      ...(crash.uptime ? { uptime: crash.uptime } : {}),
      ...(crash.comment ? { comment: crash.comment } : {}),
      ...(info.dumpKind ? {} : { dumpKind: crash.dumpKind }),
      ...(!info.systemTime && crash.systemTime
        ? { systemTime: crash.systemTime, systemTimeRaw: crash.systemTimeRaw, source: "crashinfo" as const }
        : {}),
    };
  }
  return info ?? crash ?? null;
}

function timeTag(label: string, short: string, f: ImageFacts): string {
  return f.systemTime
    ? `[${label}: ${f.systemTime}]`
    : `[${short}: not readable — ${shown(f.systemTimeRaw, 80)}]`;
}

/** The one row an image-facts table becomes. */
export function imageFactsEvents(tool: string, rows: readonly Row[], plugin: string): MappedEvent[] {
  const cols = new Set(Object.keys(rows[0] ?? {}).map((k) => k.toLowerCase()));
  const f = cols.has("dumptype") ? readCrash(rows[0]) : readInfo(rows);
  const tags: string[] = [];
  if (f.source === "crashinfo") {
    if (f.dumpType) {
      const words = DUMP_TYPES[f.dumpType];
      tags.push(`[dump type: ${shown(f.dumpType, 80)}${words ? ` — ${words}` : ""}]`);
    }
    tags.push(timeTag("dump-header SystemTime", "dump-header SystemTime", f));
    if (f.uptime) tags.push(`[uptime: ${shown(f.uptime, 40)}]`);
    if (f.dtb) tags.push(`[dtb ${shown(f.dtb, 40)}]`);
    if (f.comment) tags.push(`[comment: ${shown(f.comment)}]`);
  } else {
    tags.push(timeTag("kernel SystemTime recovered from the image", "kernel SystemTime", f));
    if (f.os) tags.push(`[os: ${shown(f.os, 80)}]`);
    if (f.is64 !== undefined) tags.push(f.is64 ? "[64-bit]" : "[32-bit]");
    if (f.symbols) tags.push(`[symbols: ${shown(f.symbols)}]`);
    if (f.layers.length) {
      const stack = f.layers
        .map(
          (l) =>
            `${shown(l.name, 40)}: ${l.depth} ${l.cls}${DUMP_LAYERS[l.cls] ? ` (${DUMP_LAYERS[l.cls]})` : ""}`,
        )
        .join("; ");
      tags.push(`[layers: ${stack}]`);
    }
    if (f.kernelBase) tags.push(`[kernel base ${shown(f.kernelBase, 40)}]`);
    if (f.dtb) tags.push(`[dtb ${shown(f.dtb, 40)}]`);
  }
  const head = f.source === "crashinfo" ? "Memory image (crash dump header)" : "Memory image";
  // Whole tags only, and a mark of the full identity when any tag did not fit: a description cut
  // mid-tag would leave a half-open tag, and two images with different later facts one row.
  const identity = tags.join("|");
  const mark = identityMark(`${plugin}|${identity}`);
  const packed = packTags(
    tags.map((t) => t.slice(1, -1)),
    DESCRIPTION_MAX - head.length - mark.length,
  );
  const kept = packed ? packed.split("] [").length : 0;
  const description = `${head}${packed}${kept < tags.length ? mark : ""}`;
  return [
    {
      timestamp: f.systemTime,
      description,
      severity: "Low",
      mitre: [],
      aggKey: `mem|image|${keyDigest(identity)}`,
      sources: [tool],
    },
  ];
}

/** Stamp the upload's image facts onto every row: the envelope always, the text from Medium up. */
export function carryImage(mapped: readonly MappedEvent[], facts: ImageFacts | null): MappedEvent[] {
  if (!facts) return [...mapped];
  const image = {
    ...(facts.systemTime ? { systemTime: facts.systemTime } : {}),
    ...(facts.systemTimeRaw ? { systemTimeRaw: facts.systemTimeRaw } : {}),
    ...(facts.dumpKind ? { dumpKind: facts.dumpKind } : {}),
    ...(facts.dumpType ? { dumpType: facts.dumpType } : {}),
    ...(facts.symbols ? { symbols: facts.symbols } : {}),
    layers: facts.layers.map((l) => `${l.name}: ${l.depth} ${l.cls}`),
  };
  // The suffix names the record the time came from: windows.info's kernel SystemTime, or the
  // crash dump header's — the header's is not the kernel clock windows.info recovers.
  const timeLabel = facts.source === "crashinfo" ? "dump-header SystemTime" : "kernel SystemTime";
  const suffix = facts.systemTime ? ` [image: ${timeLabel} ${facts.systemTime}]` : "";
  return mapped.map((e) => {
    const isImageRow = e.aggKey.startsWith("mem|image|");
    // The suffix must survive the 600-character cap: a long malfind row is clipped (marked) to
    // make room, rather than the image fact being the part that is cut.
    const room = DESCRIPTION_MAX - suffix.length;
    const withText =
      suffix && !isImageRow && RANK[e.severity] >= RANK.Medium && !e.description.includes(suffix)
        ? `${e.description.length > room ? `${e.description.slice(0, room - 1)}…` : e.description}${suffix}`
        : e.description;
    return {
      ...e,
      description: withText,
      ...(e.canonical ? { canonical: { ...e.canonical, image } } : {}),
    };
  });
}
