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
import { cellStr } from "./memoryFields.js";
import { breakHashRuns, keyDigest, showToken } from "./recordIdentity.js";

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

/** Is this table windows.info (Variable/Value) or windows.crashinfo? */
export function isImageInfoTable(plugin: string, cols: ReadonlySet<string>): boolean {
  const p = plugin.toLowerCase();
  if (/(?:^|\.)crashinfo\b/.test(p) || cols.has("dumptype")) return true;
  if (/(?:^|\.)info\b/.test(p)) return true;
  return cols.size === 2 && cols.has("variable") && cols.has("value");
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
    if (!name) continue;
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
    ...(vars.has("Is64Bit") ? { is64: /^true$/i.test(vars.get("Is64Bit") ?? "") } : {}),
    ...(symbols ? { symbols: symbols.split("/").filter(Boolean).slice(-2).join("/") } : {}),
    layers,
    ...(known.length ? { dumpKind: [...new Set(known.map((l) => DUMP_LAYERS[l.cls]))].join(", ") } : {}),
    ...(vars.get("Kernel Base") ? { kernelBase: vars.get("Kernel Base") } : {}),
    ...(vars.get("DTB") ? { dtb: vars.get("DTB") } : {}),
  };
}

function readCrash(row: Row): ImageFacts {
  const raw = cellStr(getCI(row, "SystemTime")).trim();
  const dumpType = cellStr(getCI(row, "DumpType")).trim();
  const uptime = cellStr(getCI(row, "SystemUpTime")).trim();
  const comment = cellStr(getCI(row, "Comment")).trim();
  const dtb = cellStr(getCI(row, "DirectoryTableBase")).trim();
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

/** The first image-facts table in an upload (windows.info preferred), or null. */
export function readImageFacts(tables: readonly { plugin: string; rows: Row[] }[]): ImageFacts | null {
  const found = tables
    .filter(
      (t) =>
        t.rows.length &&
        isImageInfoTable(t.plugin, new Set(Object.keys(t.rows[0]).map((k) => k.toLowerCase()))),
    )
    .map((t) =>
      new Set(Object.keys(t.rows[0]).map((k) => k.toLowerCase())).has("dumptype")
        ? readCrash(t.rows[0])
        : readInfo(t.rows),
    );
  return found.find((f) => f.source === "info") ?? found[0] ?? null;
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
  const description = `${head} ${tags.join(" ")}`.slice(0, 600);
  return [
    {
      timestamp: f.systemTime,
      description,
      severity: "Low",
      mitre: [],
      aggKey: `mem|image|${keyDigest(`${plugin}|${tags.join("|")}`)}`,
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
  const suffix = facts.systemTime ? ` [image: kernel SystemTime ${facts.systemTime}]` : "";
  return mapped.map((e) => {
    const isImageRow = e.aggKey.startsWith("mem|image|");
    // The suffix must survive the 600-character cap: a long malfind row is clipped (marked) to
    // make room, rather than the image fact being the part that is cut.
    const room = 600 - suffix.length;
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
