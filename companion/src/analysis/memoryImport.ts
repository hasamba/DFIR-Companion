// Deterministic importer for memory-forensics tool output — Volatility 3, Rekall, and MemProcFS.
// The fifteenth deterministic ingest path; no AI call.
//
// Memory forensics tools detonate nothing and score nothing — they ENUMERATE the live state of a
// RAM image: the process tree, network connections, injected/executable private memory, loaded
// modules, services, and command lines. Per the Companion's post-detection principle we ingest
// that enumeration; we do not re-implement Volatility/Rekall's analysis. The richest signal is
// `malfind` (executable private memory → process injection, ATT&CK T1055); `netscan`/`netstat`
// surface live C2/lateral connections; `pslist`/`psscan`/`pstree` give the process tree (with
// parent→child links); `cmdline` exposes LOLBin / encoded-PowerShell tradecraft.
//
// Inputs accepted:
//   • Volatility 3 JSON renderer (`vol -r json …`): a JSON ARRAY of row objects, each mapping a
//     column name → value. The TreeGrid renderer tags every node with a `__children` key (the
//     `pstree` plugin nests children under it). Also a JSON-Lines variant, and a combined
//     `{ "<plugin>": [rows] }` map some orchestration emits.
//   • Volatility 3 TEXT/grid renderer (the DEFAULT `vol <plugin>`, no `-r json`): a banner, a
//     TAB-separated column header, then TAB-separated data rows (malfind/pstree interleave a
//     hexdump + disassembly block per row, which is skipped). Parsed into the same header-keyed
//     rows as the JSON path, so the column-fingerprint classification + mappers are reused.
//   • Rekall JSON renderer (`rekall … --format json`): a list of `[directive, payload]` statements
//     ("m" metadata / "t" table header / "r" row / "s" section). We walk it, grouping each "r"
//     row under the most recent "t" table and taking the plugin name from the "m"/"s" context.
//     Rekall's cells are object-laden (a `_EPROCESS` renders to a dict) — BEST-EFFORT: we resolve
//     each cell to its name/value, classify by columns, and harvest IOCs.
//
// The plugin is identified by its COLUMNS (a case-insensitive fingerprint), refined by the Rekall
// plugin name / the export filename, then mapped per category. Severity is conservative: a process
// or connection listing is Info/Low EVIDENCE; malfind injected code is High (T1055); a suspicious
// command line bumps. Events are tagged "Volatility" / "Rekall" for cross-source correlation, and
// the artifact's own time (a process CreateTime, a connection Created time) is read — never the
// import time. The same forensic timeline the screenshot pipeline feeds.

import type { Severity } from "./stateTypes.js";
import {
  aggregateEvents,
  genericIocs,
  isSuspiciousCmd,
  addIoc,
  baseName,
  cleanIp,
  oneLine,
  str,
  isObject,
  getCI,
  normalizeTime,
  type MappedEvent,
  type SiemEvent,
  type SiemIoc,
} from "./siemImport.js";
import { parseCsv } from "./csvImport.js";
import { tradecraftSignal } from "./tradecraftRules.js";

type Row = Record<string, unknown>;

export interface MemoryImportOptions {
  aggregate?: boolean;
  minSeverity?: Severity;
  maxEvents?: number;
  maxIocs?: number;
  // Include `dlllist` / `ldrmodules` loaded-DLL rows as Info evidence events (default: false — they
  // are high-volume telemetry, so by default only their DLL paths are harvested as file IOCs).
  dllTelemetry?: boolean;
  // The export filename — a weak plugin hint for a bare Volatility array that carries no plugin name.
  filename?: string;
}

export interface MemoryParseResult {
  events: SiemEvent[];
  iocs: SiemIoc[];
  total: number;        // rows across all tables
  kept: number;         // events emitted (after aggregation + cap)
  dropped: number;      // rows not represented (dll/handle telemetry / below floor / capped)
  groups: number;       // distinct event groups before the cap
  tables: number;       // plugin tables parsed
  injected: number;     // malfind (injected-code) rows seen
  processes: number;    // process-listing rows seen
  connections: number;  // network-connection rows seen
  format: string;       // "volatility" | "volatility-jsonl" | "volatility-map" | "volatility-text" | "rekall" | "empty"
  tool: string;         // "Volatility" | "Rekall" | ""
}

type Category =
  | "process" | "netscan" | "malfind" | "cmdline" | "service" | "module" | "dll" | "handle" | "generic";

const REKALL_DIRECTIVES = new Set(["m", "t", "r", "s", "e", "p", "f", "L", "c"]);
const PRIVATE_IP = /^(?:10\.|127\.|169\.254\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.|0\.|255\.|22[4-9]\.|23\d\.|::1$|fe80:|fc|fd)/i;

// ───────────────────────────── cell / field helpers ─────────────────────────────

// Resolve a cell to a display string. Volatility cells are primitives; a Rekall object cell (e.g. a
// rendered `_EPROCESS`) is reduced to its name/value.
function cellStr(v: unknown): string {
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
    if (isObject(cybox)) { const n = getCI(cybox, "Name"); if (typeof n === "string" && n.trim()) return n.trim(); }
    return "";
  }
  return "";
}

// First non-empty resolved value across candidate keys (case-insensitive).
function pick(row: Row, keys: string[]): string {
  for (const k of keys) { const s = cellStr(getCI(row, k)).trim(); if (s) return s; }
  return "";
}

// A PID — direct column, or (Rekall) nested inside the `_EPROCESS` object's Cybox.
function pickPid(row: Row): string {
  const direct = pick(row, ["PID", "pid", "Pid"]);
  if (direct && /^\d+$/.test(direct)) return direct;
  const ep = getCI(row, "_EPROCESS");
  if (isObject(ep)) {
    const cy = getCI(ep, "Cybox");
    const p = cellStr(isObject(cy) ? getCI(cy, "PID") : getCI(ep, "pid"));
    if (/^\d+$/.test(p)) return p;
  }
  return direct;
}

// The artifact's own time. Handles a Rekall time object ({epoch}) and a Volatility naive/ISO string;
// "N/A" / "-" / "0" / null render as undated. Never the import time.
function pickTime(row: Row, keys: string[]): string {
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

function colSet(rows: Row[]): Set<string> {
  const out = new Set<string>();
  for (const r of rows.slice(0, 50)) for (const k of Object.keys(r)) out.add(k.toLowerCase());
  return out;
}

// ───────────────────────────── plugin classification ─────────────────────────────

function classify(plugin: string, cols: Set<string>): Category {
  const p = plugin.toLowerCase();
  const has = (k: string): boolean => cols.has(k);
  const any = (...ks: string[]): boolean => ks.some(has);

  if (/malfind|hollow|injec|malthfind|threadmap/.test(p)) return "malfind";
  if (has("protection") && any("tag", "disasm", "hexdump", "vad tag", "vadtag")) return "malfind";

  if (/netscan|netstat|connection|connscan|sockets|sockscan|tcpip|udp/.test(p)) return "netscan";
  if (any("foreignaddr", "foreign_addr") && any("localaddr", "local_addr")) return "netscan";
  if (has("proto") && has("state") && any("pid", "owner")) return "netscan";

  if (/cmdline|cmdscan|consoles|commandline/.test(p)) return "cmdline";
  if (has("args") && any("process", "pid", "imagefilename") && cols.size <= 6) return "cmdline";

  if (/svcscan|services/.test(p)) return "service";
  if (any("binary", "servicedll", "binary path") && any("state", "start", "display")) return "service";

  if (/driver|modscan|modules|modlist|lsmod|kernel_module/.test(p)) return "module";
  if (any("base", "dllbase") && has("size") && any("name", "path", "driver name") && !has("pid")) return "module";

  if (/dlllist|ldrmodules|dlldump/.test(p)) return "dll";
  if (has("pid") && any("base", "dllbase") && any("path", "loadtime", "mappedpath") && has("size")) return "dll";

  if (/handles?/.test(p)) return "handle";

  if (/pslist|psscan|pstree|psxview|pstotal|ps_|memdump|procdump/.test(p)) return "process";
  if (any("imagefilename", "comm", "_eprocess")) return "process";
  if (has("ppid") && any("createtime", "process_create_time", "threads", "thread_count", "handles", "handle_count")) return "process";

  return "generic";
}

const SHORT_PLUGIN = /(pstree|pslist|psscan|psxview|netscan|netstat|connscan|connections|sockscan|sockets|malfind|hollowfind|ldrmodules|cmdline|cmdscan|consoles|svcscan|services|modscan|modules|driverscan|driverirp|dlllist|handles|getsids|envars|privileges|callbacks|ssdt|mutantscan|filescan|hivelist|hashdump)/;

// A short, human label for the plugin: the Rekall/known plugin name, the os.module from a
// Volatility dotted id, or a filename/category fallback.
function displayLabel(plugin: string, category: Category, rows: Row[]): string {
  const p = plugin.toLowerCase();
  const dotted = /\b(windows|linux|mac)\.(\w+)/.exec(p);
  if (dotted) return dotted[2];
  const m = SHORT_PLUGIN.exec(p);
  if (m) return m[1];
  if (category === "process") {
    return rows.some((r) => { const c = getCI(r, "__children"); return Array.isArray(c) && c.length > 0; }) ? "pstree" : "pslist";
  }
  const byCat: Record<Category, string> = {
    process: "pslist", netscan: "netscan", malfind: "malfind", cmdline: "cmdline",
    service: "svcscan", module: "modules", dll: "dlllist", handle: "handles", generic: "memory",
  };
  return byCat[category];
}

// ───────────────────────────── per-category mappers ─────────────────────────────

const PROC_NAME_KEYS = ["ImageFileName", "COMM", "Comm", "Process", "Name", "name", "_EPROCESS"];

function procName(row: Row): string {
  return baseName(pick(row, PROC_NAME_KEYS));
}

function mapProcess(label: string, tool: string, rows: Row[], sink: Map<string, SiemIoc>): MappedEvent[] {
  const out: MappedEvent[] = [];
  const psscan = /psscan|psxview/.test(label);

  // Index PID → name (across the whole tree) so a flat table resolves PPID → parent name.
  const pidIndex = new Map<string, string>();
  const index = (list: Row[]): void => {
    for (const r of list) {
      const pid = pickPid(r); const nm = procName(r);
      if (pid && nm) pidIndex.set(pid, nm);
      const kids = getCI(r, "__children");
      if (Array.isArray(kids)) index(kids.filter(isObject) as Row[]);
    }
  };
  index(rows);

  const walk = (list: Row[], parent: string): void => {
    for (const r of list) {
      const name = procName(r);
      const pid = pickPid(r);
      const ppid = pick(r, ["PPID", "ppid"]);
      const created = pickTime(r, ["CreateTime", "process_create_time", "CreatedTime", "create_time", "start_time"]);
      const exited = pick(r, ["ExitTime", "process_exit_time"]).trim();
      const cmd = pick(r, ["Cmd", "CommandLine", "Args"]);
      const path = pick(r, ["Path", "path"]);
      if (name || pid) {
        if (name) addIoc(sink, "process", name);
        if (path && /[\\/]/.test(path)) addIoc(sink, "file", path.slice(0, 300));
        const parentName = parent || (ppid ? baseName(pidIndex.get(ppid) ?? "") : "");
        const exitNote = exited && !/^(n\/?a|-|0|none)$/i.test(exited) ? ", terminated" : "";
        let description = `${tool} ${label}: ${name || "?"} (PID ${pid || "?"}${ppid ? `, PPID ${ppid}` : ""}${exitNote})`;
        if (created) description += ` started ${created}`;
        if (cmd) description += ` — ${oneLine(cmd).slice(0, 160)}`;
        out.push({
          timestamp: created,
          description: description.slice(0, 600),
          severity: "Info",
          mitre: [],
          aggKey: `mem|proc|${(name || "?").toLowerCase()}|${pid}|${ppid}${psscan ? "|scan" : ""}`.slice(0, 400),
          sources: [tool],
          ...(name ? { processName: name } : {}),
          ...(parentName ? { parentName } : {}),
          ...(path && /[\\/]/.test(path) ? { path } : {}),
        });
      }
      const kids = getCI(r, "__children");
      if (Array.isArray(kids)) walk(kids.filter(isObject) as Row[], name || parent);
    }
  };
  walk(rows, "");
  return out;
}

function mapNetscan(label: string, tool: string, rows: Row[], sink: Map<string, SiemIoc>): MappedEvent[] {
  const out: MappedEvent[] = [];
  for (const r of rows) {
    const proto = pick(r, ["Proto", "proto", "Protocol"]);
    const laddr = pick(r, ["LocalAddr", "local_addr", "LocalAddress", "Source"]);
    const lport = pick(r, ["LocalPort", "local_port", "Lport"]);
    const faddr = pick(r, ["ForeignAddr", "foreign_addr", "ForeignAddress", "RemoteAddr", "Destination"]);
    const fport = pick(r, ["ForeignPort", "foreign_port", "RemotePort"]);
    const state = pick(r, ["State", "state"]);
    const owner = pick(r, ["Owner", "Process", "owner", "ImageFileName"]);
    const pid = pickPid(r);
    const created = pickTime(r, ["Created", "create_time", "Time", "time"]);

    const fip = cleanIp(faddr);
    const lip = cleanIp(laddr);
    if (fip) addIoc(sink, "ip", fip);
    const proc = owner ? baseName(owner) : "";
    if (proc && /\.\w{2,4}$/.test(proc)) addIoc(sink, "process", proc);

    const external = !!fip && !PRIVATE_IP.test(fip);
    const severity: Severity = external && /establish|estab/i.test(state) ? "Low" : "Info";
    const portN = Number(fport);

    out.push({
      timestamp: created,
      description: `${tool} ${label}: ${proto || "?"} ${laddr || "?"}:${lport || "?"} → ${faddr || "*"}:${fport || "*"}${state ? ` [${state}]` : ""}${owner ? ` owner ${owner}` : ""}${pid ? ` (PID ${pid})` : ""}`.slice(0, 600),
      severity,
      mitre: [],
      aggKey: `mem|net|${proto}|${faddr}|${fport}|${proc}`.toLowerCase().slice(0, 400),
      sources: [tool],
      ...(proc ? { processName: proc } : {}),
      ...(lip ? { srcIp: lip } : {}),
      ...(fip ? { dstIp: fip } : {}),
      ...(Number.isFinite(portN) && portN > 0 ? { port: portN } : {}),
    });
  }
  return out;
}

function mapMalfind(label: string, tool: string, rows: Row[], sink: Map<string, SiemIoc>): MappedEvent[] {
  const out: MappedEvent[] = [];
  for (const r of rows) {
    const proc = pick(r, ["Process", "ImageFileName", "Name", "name", "_EPROCESS"]);
    const pid = pickPid(r);
    const prot = pick(r, ["Protection", "protection"]);
    const tag = pick(r, ["Tag", "tag", "VadTag", "vad_tag"]);
    const start = pick(r, ["Start VPN", "Start", "start", "CommitCharge"]);
    const name = proc ? baseName(proc) : "";
    if (name) addIoc(sink, "process", name);
    out.push({
      timestamp: "",
      description: `${tool} ${label}: executable/injected private memory in ${proc || "?"} (PID ${pid || "?"})${prot ? ` — protection ${prot}` : ""}${tag ? `, tag ${tag}` : ""}`.slice(0, 600),
      severity: "High",
      mitre: ["T1055"],
      aggKey: `mem|malfind|${name.toLowerCase()}|${pid}|${start}|${prot}`.toLowerCase().slice(0, 400),
      sources: [tool],
      ...(name ? { processName: name } : {}),
    });
  }
  return out;
}

function mapCmdline(label: string, tool: string, rows: Row[], sink: Map<string, SiemIoc>): MappedEvent[] {
  const out: MappedEvent[] = [];
  for (const r of rows) {
    const proc = pick(r, ["Process", "ImageFileName", "Name", "name", "_EPROCESS"]);
    const pid = pickPid(r);
    const args = pick(r, ["Args", "CommandLine", "args", "cmd"]);
    if (!proc && !args) continue;
    const name = proc ? baseName(proc) : "";
    if (name) addIoc(sink, "process", name);
    const susp = isSuspiciousCmd(proc, args);
    const tc = tradecraftSignal(proc, args);
    const strong = susp === "strong" || tc?.weight === "strong";
    const flagged = Boolean(susp) || Boolean(tc);
    const severity: Severity = strong ? "High" : flagged ? "Medium" : "Info";
    out.push({
      timestamp: "",
      description: `${tool} ${label}: ${proc || "?"} (PID ${pid || "?"})${args ? ` — ${oneLine(args).slice(0, 220)}` : ""}`.slice(0, 600),
      severity,
      mitre: [...new Set([...(flagged ? ["T1059"] : []), ...(tc?.mitre ?? [])])],
      aggKey: `mem|cmd|${name.toLowerCase()}|${pid}`.slice(0, 400),
      sources: [tool],
      ...(name ? { processName: name } : {}),
    });
  }
  return out;
}

function mapService(label: string, tool: string, rows: Row[], sink: Map<string, SiemIoc>): MappedEvent[] {
  const out: MappedEvent[] = [];
  for (const r of rows) {
    const name = pick(r, ["Name", "name", "ServiceName"]);
    const display = pick(r, ["Display", "display", "DisplayName"]);
    const state = pick(r, ["State", "state"]);
    const binary = pick(r, ["Binary", "Binary Path", "binary", "ServiceDll", "Dll", "Path"]);
    if (!name && !binary) continue;
    if (binary && /[\\/]/.test(binary)) addIoc(sink, "file", binary.slice(0, 300));
    const susp = isSuspiciousCmd(binary, "");
    const severity: Severity = susp === "strong" ? "High" : susp === "weak" ? "Medium" : "Info";
    out.push({
      timestamp: "",
      description: `${tool} ${label}: service ${name || "?"}${display && display !== name ? ` (${display})` : ""}${state ? ` [${state}]` : ""}${binary ? ` → ${oneLine(binary).slice(0, 200)}` : ""}`.slice(0, 600),
      severity,
      mitre: [],
      aggKey: `mem|svc|${(name || binary).toLowerCase()}`.slice(0, 400),
      sources: [tool],
      ...(binary && /[\\/]/.test(binary) ? { path: binary } : {}),
    });
  }
  return out;
}

function mapModule(label: string, tool: string, rows: Row[], sink: Map<string, SiemIoc>): MappedEvent[] {
  const out: MappedEvent[] = [];
  for (const r of rows) {
    const name = pick(r, ["Name", "name", "Driver Name", "Service Key", "BaseDllName"]);
    const path = pick(r, ["Path", "path", "FullPath", "MappedPath"]);
    const base = pick(r, ["Base", "base", "Offset", "DllBase"]);
    if (!name && !path) continue;
    if (path && /[\\/]/.test(path)) addIoc(sink, "file", path.slice(0, 300));
    out.push({
      timestamp: "",
      description: `${tool} ${label}: ${name || "?"}${base ? ` @ ${base}` : ""}${path ? ` — ${oneLine(path).slice(0, 200)}` : ""}`.slice(0, 600),
      severity: "Info",
      mitre: [],
      aggKey: `mem|mod|${(name || path).toLowerCase()}`.slice(0, 400),
      sources: [tool],
      ...(path && /[\\/]/.test(path) ? { path } : {}),
    });
  }
  return out;
}

// dlllist / ldrmodules: high-volume. By default harvest the DLL path → file IOC only; opt-in to
// keep one Info event per loaded module.
function mapDll(label: string, tool: string, rows: Row[], sink: Map<string, SiemIoc>, telemetry: boolean): MappedEvent[] {
  const out: MappedEvent[] = [];
  for (const r of rows) {
    const path = pick(r, ["Path", "path", "MappedPath", "FullDllName"]);
    const dllName = pick(r, ["Name", "name", "BaseDllName"]);
    const proc = procName(r);
    const pid = pickPid(r);
    if (path && /[\\/]/.test(path)) addIoc(sink, "file", path.slice(0, 300));
    if (!telemetry) continue;
    if (!path && !dllName) continue;
    out.push({
      timestamp: pickTime(r, ["LoadTime", "load_time"]),
      description: `${tool} ${label}: ${proc || "?"} (PID ${pid || "?"}) loaded ${oneLine(path || dllName).slice(0, 220)}`.slice(0, 600),
      severity: "Info",
      mitre: [],
      aggKey: `mem|dll|${proc.toLowerCase()}|${(path || dllName).toLowerCase()}`.slice(0, 400),
      sources: [tool],
      ...(proc ? { processName: proc } : {}),
      ...(path && /[\\/]/.test(path) ? { path } : {}),
    });
  }
  return out;
}

function mapGeneric(label: string, tool: string, rows: Row[], sink: Map<string, SiemIoc>): MappedEvent[] {
  const out: MappedEvent[] = [];
  for (const r of rows) {
    const pairs: [string, string][] = [];
    for (const [k, v] of Object.entries(r)) {
      if (k === "__children") continue;
      const s = cellStr(v).trim();
      if (s) pairs.push([k, s.slice(0, 200)]);
    }
    if (!pairs.length) continue;
    genericIocs(pairs, sink);
    const body = pairs.slice(0, 8).map(([k, v]) => `${k}=${v}`).join(" ");
    out.push({
      timestamp: pickTime(r, ["CreateTime", "Created", "Time", "time", "Timestamp"]),
      description: `${tool} ${label}: ${body}`.slice(0, 600),
      severity: "Info",
      mitre: [],
      aggKey: `mem|gen|${label}|${body}`.toLowerCase().replace(/0x[0-9a-f]+/g, "<addr>").replace(/\d+/g, "#").slice(0, 400),
      sources: [tool],
    });
  }
  return out;
}

// ───────────────────────────── table extraction ─────────────────────────────

interface Table { plugin: string; rows: Row[]; }

const VOL_PLUGIN_KEY = /^(windows|linux|mac)\.[a-z]/; // lowercase os ⇒ Volatility (Velociraptor uses "Windows.")

function isVolatilityPluginMap(root: unknown): boolean {
  if (!isObject(root) || Array.isArray(root)) return false;
  const entries = Object.entries(root);
  return entries.length > 0 &&
    entries.every(([, v]) => Array.isArray(v)) &&
    entries.some(([k]) => VOL_PLUGIN_KEY.test(k));
}

export function isRekallCommandList(root: unknown): boolean {
  if (!Array.isArray(root) || root.length === 0) return false;
  let stmts = 0, hits = 0;
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
  const startTable = (): void => { cur = { plugin: curPlugin, rows: [] }; tables.push(cur); };
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

function pluginFromFilename(name: string | undefined): string {
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
const VOL_TEXT_HEXDUMP = /^[0-9a-fA-F]{2}( [0-9a-fA-F]{2}){3,}/;   // a hexdump gutter line: "48 89 54 24 …"
const VOL_TEXT_DISASM = /^0x[0-9a-fA-F]+:/;                         // a disassembly line: "0x…:\tmov …"
// Column names that appear in Volatility 3 text headers — used (with the banner) to recognize the
// format when the banner was stripped. Lowercased; matched against the TAB-split header cells.
const VOL_TEXT_HEADER_COLS = new Set([
  "pid", "ppid", "process", "imagefilename", "comm", "offset(v)", "offset", "protection", "tag",
  "createtime", "exittime", "threads", "handles", "sessionid", "wow64", "args", "cmd",
  "localaddr", "foreignaddr", "localport", "foreignport", "proto", "state", "owner", "created",
  "name", "displayname", "binary", "start", "path", "base", "size", "start vpn", "end vpn",
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
function parseVolatilityText(text: string, filename: string | undefined): Table | null {
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
    while (header.length && header[header.length - 1] === "") header.pop();   // drop trailing empties
    i++;
    break;
  }
  if (!header || !header.length) return null;

  const rows: Row[] = [];
  for (; i < lines.length; i++) {
    const raw = lines[i];
    const trimmed = raw.trim();
    if (!trimmed) continue;
    if (VOL_TEXT_DISASM.test(trimmed) || VOL_TEXT_HEXDUMP.test(trimmed)) continue;  // hexdump/disasm continuation
    if (!raw.includes("\t")) continue;                                             // ascii gutter etc.
    const cells = raw.split("\t");
    cells[0] = cells[0].replace(/^[*\s]+/, "").trim();   // strip pstree depth markers ("* ", "** ")
    if (cells.filter((c) => c.trim() !== "").length < 2) continue;
    const row: Row = {};
    header.forEach((col, idx) => { if (col) row[col] = (cells[idx] ?? "").trim(); });
    rows.push(row);
  }
  if (!rows.length) return null;
  return { plugin: pluginFromFilename(filename), rows };
}

function extractTables(text: string, filename: string | undefined): { tables: Table[]; format: string; tool: string } {
  const trimmed = text.trim();
  if (!trimmed) return { tables: [], format: "empty", tool: "" };

  let root: unknown;
  let parsed = false;
  try { root = JSON.parse(trimmed); parsed = true; } catch { /* NDJSON below */ }

  if (parsed) {
    if (Array.isArray(root)) {
      if (isRekallCommandList(root)) return { tables: parseRekall(root), format: "rekall", tool: "Rekall" };
      const rows = root.filter(isObject) as Row[];
      return { tables: rows.length ? [{ plugin: pluginFromFilename(filename), rows }] : [], format: "volatility", tool: "Volatility" };
    }
    if (isObject(root) && isVolatilityPluginMap(root)) {
      const tables = Object.entries(root)
        .filter(([, v]) => Array.isArray(v))
        .map(([k, v]) => ({ plugin: k, rows: (v as unknown[]).filter(isObject) as Row[] }))
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
    try { const o = JSON.parse(l); if (isObject(o)) rows.push(o); } catch { /* skip */ }
  }
  if (rows.length) return { tables: [{ plugin: pluginFromFilename(filename), rows }], format: "volatility-jsonl", tool: "Volatility" };

  // Volatility 3 TEXT/grid renderer (the default `vol <plugin>`, no -r json).
  if (looksLikeVolatilityText(trimmed)) {
    const table = parseVolatilityText(trimmed, filename);
    if (table) return { tables: [table], format: "volatility-text", tool: "Volatility" };
  }
  return { tables: [], format: "empty", tool: "" };
}

// ───────────────────────────── MemProcFS findevil ─────────────────────────────
//
// MemProcFS `findevil` scans a live RAM image for suspicious memory indicators and emits a REPORT
// (not raw enumeration like Volatility). Each row is a verdict with a finding TYPE (HIGH_ENTROPY,
// PEB_MASQ, YR_HACKTOOL, PE_PATCHED, PRIVATE_RWX, …). We map type→severity+MITRE deterministically.
//
// Format (space-separated fixed-width table):
//    #    PID Process        Type            Address          Description
//   -----------------------------------------------------------------------
//   0000   8684 Velociraptor.e HIGH_ENTROPY    000000c001c00000 Entropy:[8.00]  p-rw--
//   0004   6416 svchost.exe    YR_HACKTOOL     0000022a7a0b804e Windows_Hacktool_SharpDump_… [0]

const FINDEVIL_HEADER_RE = /\bPID\b.{0,20}\bProcess\b.{0,30}\bType\b.{0,30}\bAddress\b/i;
const FINDEVIL_ROW_RE = /^([0-9a-f]{4})\s+(\d+)\s+(\S+)\s+([A-Z][A-Z_0-9]+)\s+([0-9a-f]{16})\s*(.*)/i;

// Exported so importDetect can route findevil files to "memory" without JSON-parsing them.
export function looksLikeMemprocfsFindevil(text: string): boolean {
  const lines = (text ?? "").slice(0, 3000).split(/\r\n|\r|\n/);
  let hasHeader = false;
  for (const line of lines.slice(0, 10)) {
    const t = line.trim();
    if (FINDEVIL_HEADER_RE.test(t)) { hasHeader = true; continue; }
    if (hasHeader && (/^-{20,}$/.test(t) || FINDEVIL_ROW_RE.test(t))) return true;
  }
  return false;
}

interface FindevilRow {
  pid: string; process: string; type: string; address: string; description: string;
}

function findevilSeverity(type: string, desc: string): { severity: Severity; mitre: string[] } {
  const t = type.toUpperCase();
  if (t.startsWith("YR_") || t.startsWith("YARA_")) {
    if (/hacktool/i.test(t))  return { severity: "Critical", mitre: ["T1588.002"] };
    if (/ransom/i.test(t))    return { severity: "Critical", mitre: ["T1486"] };
    if (/shellcode/i.test(t)) return { severity: "Critical", mitre: ["T1055.001"] };
    if (/malware|trojan|backdoor|rat\b|loader|dropper/i.test(t)) return { severity: "Critical", mitre: ["T1055"] };
    return { severity: "High", mitre: ["T1027"] };
  }
  switch (t) {
    case "PEB_MASQ":    return { severity: "High",   mitre: ["T1036.005"] };
    case "PE_PATCHED":  return { severity: "High",   mitre: ["T1055"] };
    case "THREAD":      return /system_impersonation/i.test(desc)
                          ? { severity: "High",   mitre: ["T1134"] }
                          : { severity: "Medium", mitre: ["T1055"] };
    case "HIGH_ENTROPY": return { severity: "Medium", mitre: ["T1027"] };
    case "PE_NOLINK":   return { severity: "Medium", mitre: ["T1055"] };
    case "PROC_DEBUG":  return { severity: "Medium", mitre: ["T1055"] };
    case "PRIVATE_RWX": return { severity: "Medium", mitre: ["T1055", "T1620"] };
    case "DRIVER_PATH": {
      const suspicious = /\\(?:temp|tmp|users|downloads?|desktop|appdata|public)\\/i.test(desc);
      return { severity: suspicious ? "Medium" : "Low", mitre: ["T1014"] };
    }
    case "PRIVATE_RX":  return { severity: "Info", mitre: [] };
    default:            return { severity: "Low",  mitre: [] };
  }
}

// For bulk types group by process+type (many pages → one event with count).
// For signal-rich types keep each finding individual (include rule/detail in key).
function findevilAggKey(type: string, pid: string, proc: string, desc: string): string {
  const t = type.toUpperCase();
  if (t === "PRIVATE_RWX" || t === "PRIVATE_RX") {
    return `findevil|${t}|${pid}|${proc.toLowerCase()}`;
  }
  if (t === "PE_PATCHED") {
    const path = /([A-Za-z]:\\[^\s]+|\\[^\s]+\.(?:dll|exe|sys))\s*$/.exec(desc)?.[1] ?? "";
    return `findevil|pe_patched|${pid}|${proc.toLowerCase()}|${path.toLowerCase()}`;
  }
  if (t === "PE_NOLINK") {
    const path = /VAD:\[([^\]]+)\]/.exec(desc)?.[1] ?? /Module:\[([^\]]+)\]/.exec(desc)?.[1] ?? "";
    return `findevil|pe_nolink|${pid}|${proc.toLowerCase()}|${path.toLowerCase()}`;
  }
  return `findevil|${t}|${pid}|${proc.toLowerCase()}|${desc.slice(0, 80).toLowerCase()}`;
}

function findevilEventDesc(type: string, proc: string, pid: string, desc: string, address: string): string {
  const t = type.toUpperCase();
  const addrNote = address && address !== "0000000000000000" ? ` @ 0x${address}` : "";
  switch (t) {
    case "YR_HACKTOOL":
    case "YR_MALWARE":
    case "YR_RANSOMWARE":
    case "YR_SHELLCODE": {
      const rule = /^(\S+)/.exec(desc.trim())?.[1] ?? desc;
      return `MemProcFS findevil ${type}: ${proc} (PID ${pid}) — YARA ${rule}${addrNote}`.slice(0, 600);
    }
    case "PE_PATCHED": {
      const path = /([A-Za-z]:\\[^\s]+|\\[^\s]+\.(?:dll|exe|sys))\s*$/.exec(desc)?.[1] ?? "";
      return `MemProcFS findevil PE_PATCHED: ${proc} (PID ${pid}) — patched PE${path ? ` ${path}` : ""}${addrNote}`.slice(0, 600);
    }
    case "PE_NOLINK": {
      const mod = /Module:\[([^\]]+)\]/.exec(desc)?.[1] ?? desc;
      return `MemProcFS findevil PE_NOLINK: ${proc} (PID ${pid}) — unlisted PE ${mod}${addrNote}`.slice(0, 600);
    }
    case "DRIVER_PATH": {
      const drv = /Driver:\[([^\]]+)\]/.exec(desc)?.[1] ?? "";
      const mod = /Module:\[([^\]]+)\]/.exec(desc)?.[1] ?? "";
      const note = drv ? ` — driver ${drv}${mod ? ` (${mod})` : ""}` : (desc ? ` — ${desc}` : "");
      return `MemProcFS findevil DRIVER_PATH: ${proc} (PID ${pid})${note}`.slice(0, 600);
    }
    case "PRIVATE_RWX":
      return `MemProcFS findevil PRIVATE_RWX: ${proc} (PID ${pid}) — executable private memory (RWX)${addrNote}`.slice(0, 600);
    case "PRIVATE_RX":
      return `MemProcFS findevil PRIVATE_RX: ${proc} (PID ${pid}) — private executable memory${addrNote}`.slice(0, 600);
    case "PEB_MASQ":
      return `MemProcFS findevil PEB_MASQ: ${proc} (PID ${pid}) — PEB process name masquerading`.slice(0, 600);
    case "PROC_DEBUG":
      return `MemProcFS findevil PROC_DEBUG: ${proc} (PID ${pid}) — process under debugger`.slice(0, 600);
    default:
      return `MemProcFS findevil ${type}: ${proc} (PID ${pid})${desc ? ` — ${oneLine(desc).slice(0, 200)}` : ""}${addrNote}`.slice(0, 600);
  }
}

function parseFindevilRows(text: string): FindevilRow[] {
  const rows: FindevilRow[] = [];
  let pastHeader = false;
  for (const line of text.split(/\r\n|\r|\n/)) {
    const t = line.trim();
    if (!pastHeader) {
      if (FINDEVIL_HEADER_RE.test(t)) { pastHeader = true; }
      continue;
    }
    if (/^-{20,}$/.test(t) || !t) continue;
    const m = FINDEVIL_ROW_RE.exec(t);
    if (!m) continue;
    rows.push({ pid: m[2], process: m[3], type: m[4], address: m[5], description: (m[6] ?? "").trim() });
  }
  return rows;
}

function mapFindevil(rows: FindevilRow[], sink: Map<string, SiemIoc>): MappedEvent[] {
  const out: MappedEvent[] = [];
  for (const { pid, process, type, address, description } of rows) {
    const { severity, mitre } = findevilSeverity(type, description);
    const pName = baseName(process);
    if (pName) addIoc(sink, "process", pName);

    // Harvest file IOCs from structural fields in the description.
    const t = type.toUpperCase();
    let pathIoc = "";
    if (t === "DRIVER_PATH") {
      pathIoc = /Module:\[([^\]]+)\]/.exec(description)?.[1] ?? "";
    } else if (t === "PE_NOLINK") {
      pathIoc = /VAD:\[([^\]]+)\]/.exec(description)?.[1] ?? /Module:\[([^\]]+)\]/.exec(description)?.[1] ?? "";
    } else if (t === "PE_PATCHED") {
      pathIoc = /([A-Za-z]:\\[^\s]+|\\[^\s]+\.(?:dll|exe|sys))\s*$/.exec(description)?.[1] ?? "";
    }
    if (pathIoc && /[\\/]/.test(pathIoc)) addIoc(sink, "file", pathIoc.slice(0, 300));

    out.push({
      timestamp: "",
      description: findevilEventDesc(type, process, pid, description, address),
      severity,
      mitre,
      aggKey: findevilAggKey(type, pid, process, description),
      sources: ["MemProcFS"],
      ...(pName ? { processName: pName } : {}),
      ...(pathIoc && /[\\/]/.test(pathIoc) ? { path: pathIoc } : {}),
    });
  }
  return out;
}

function parseMemoryFindevil(text: string, opts: MemoryImportOptions): MemoryParseResult {
  const rows = parseFindevilRows(text);
  const empty: MemoryParseResult = { events: [], iocs: [], total: 0, kept: 0, dropped: 0, groups: 0, tables: 0, injected: 0, processes: 0, connections: 0, format: "memprocfs-findevil", tool: "MemProcFS" };
  if (!rows.length) return empty;

  const sink = new Map<string, SiemIoc>();
  const mapped = mapFindevil(rows, sink);
  const { events, groups } = aggregateEvents(mapped, {
    aggregate: opts.aggregate,
    minSeverity: opts.minSeverity,
    maxEvents: opts.maxEvents ?? (Number(process.env.DFIR_MAX_EVENTS) || 2000),
  });
  const maxIocs = opts.maxIocs ?? 5000;
  const represented = events.reduce((n, e) => n + (e.count ?? 1), 0);
  return {
    events,
    iocs: [...sink.values()].slice(0, maxIocs),
    total: rows.length,
    kept: events.length,
    dropped: Math.max(0, rows.length - represented),
    groups,
    tables: 1,
    injected: rows.filter((r) => /^(YR_|YARA_)/i.test(r.type)).length,
    processes: 0,
    connections: 0,
    format: "memprocfs-findevil",
    tool: "MemProcFS",
  };
}

// ───────────────────────────── MemProcFS CSV variants ─────────────────────────────
//
// MemProcFS exports its data in two CSV flavours that complement the text `findevil` report:
//
//   findevil.csv  — PID,ProcessName,Type,Address,Description
//     The same finding set as findevil.txt but as a clean CSV (no fixed-width padding). We
//     parse rows into FindevilRow and reuse the same mapFindevil / severity / aggKey logic.
//
//   yara.csv  — MatchIndex,Tags,Description,RuleAuthor,RuleVersion,MemoryType,MemoryTag,
//               MemoryBaseAddress,ObjectAddress,PID,ProcessName,ProcessPath,CommandLine,
//               User,Created,AddressCount,String0,Address0,…
//     YARA scan results with process context + match timestamps. Every row is a YARA hit →
//     Critical / T1055 (code found in memory). Aggregated by process + base-address so all
//     matches in the same heap/VAD region collapse into one event with a count.

// Lightweight first-line check (no full CSV parse): split on comma, normalise header names.
function csvCols(text: string): Set<string> {
  const first = text.trim().split(/\r\n|\r|\n/, 1)[0] ?? "";
  return new Set(first.split(",").map((c) => c.trim().replace(/['"]/g, "").toLowerCase()));
}

function parseMemoryFindevilCsv(text: string, opts: MemoryImportOptions): MemoryParseResult {
  const empty: MemoryParseResult = { events: [], iocs: [], total: 0, kept: 0, dropped: 0, groups: 0, tables: 0, injected: 0, processes: 0, connections: 0, format: "memprocfs-findevil-csv", tool: "MemProcFS" };
  const { headers, rows } = parseCsv(text);
  if (!headers.length || !rows.length) return empty;

  const col = (name: string): number => headers.findIndex((h) => h.toLowerCase() === name.toLowerCase());
  const pidI = col("PID"); const procI = col("ProcessName"); const typeI = col("Type");
  const addrI = col("Address"); const descI = col("Description");

  const findevilRows: FindevilRow[] = rows
    .filter((r) => r[typeI]?.trim())
    .map((r) => ({
      pid: r[pidI] ?? "",
      process: r[procI] ?? "",
      type: r[typeI] ?? "",
      // CSV address has a 0x prefix (e.g. 0x7ff824c43000); strip it for consistency.
      address: (r[addrI] ?? "").replace(/^0x/i, "").toLowerCase(),
      description: r[descI] ?? "",
    }));

  if (!findevilRows.length) return empty;
  const sink = new Map<string, SiemIoc>();
  const mapped = mapFindevil(findevilRows, sink);
  const { events, groups } = aggregateEvents(mapped, {
    aggregate: opts.aggregate, minSeverity: opts.minSeverity, maxEvents: opts.maxEvents ?? (Number(process.env.DFIR_MAX_EVENTS) || 2000),
  });
  const maxIocs = opts.maxIocs ?? 5000;
  const represented = events.reduce((n, e) => n + (e.count ?? 1), 0);
  return {
    events, iocs: [...sink.values()].slice(0, maxIocs),
    total: findevilRows.length, kept: events.length,
    dropped: Math.max(0, findevilRows.length - represented), groups, tables: 1,
    injected: findevilRows.filter((r) => /^(YR_|YARA_)/i.test(r.type)).length,
    processes: 0, connections: 0, format: "memprocfs-findevil-csv", tool: "MemProcFS",
  };
}

function parseMemoryYaraCsv(text: string, opts: MemoryImportOptions): MemoryParseResult {
  const empty: MemoryParseResult = { events: [], iocs: [], total: 0, kept: 0, dropped: 0, groups: 0, tables: 0, injected: 0, processes: 0, connections: 0, format: "memprocfs-yara-csv", tool: "MemProcFS" };
  const { headers, rows } = parseCsv(text);
  if (!headers.length || !rows.length) return empty;

  const col = (name: string): number => headers.findIndex((h) => h.toLowerCase() === name.toLowerCase());
  const pidI = col("PID"); const procI = col("ProcessName"); const procPathI = col("ProcessPath");
  const cmdI = col("CommandLine"); const createdI = col("Created");
  const memTypeI = col("MemoryType"); const memTagI = col("MemoryTag");
  const baseAddrI = col("MemoryBaseAddress"); const objAddrI = col("ObjectAddress");

  const sink = new Map<string, SiemIoc>();
  const mapped: MappedEvent[] = [];

  for (const row of rows) {
    const pid = row[pidI] ?? "";
    const proc = row[procI] ?? "";
    const procPath = row[procPathI] ?? "";
    const cmd = row[cmdI] ?? "";
    const created = row[createdI] ?? "";
    const memType = row[memTypeI] ?? "";
    const memTag = row[memTagI] ?? "";
    const baseAddr = row[baseAddrI] ?? "";
    const objAddr = row[objAddrI] ?? "";

    const pName = baseName(proc);
    if (pName) addIoc(sink, "process", pName);
    if (procPath && /[\\/]/.test(procPath)) addIoc(sink, "file", procPath.slice(0, 300));

    const timestamp = normalizeTime(created) ?? "";
    const memNote = [memType, memTag].filter(Boolean).join(" / ");
    const addrNote = baseAddr ? ` @ base 0x${baseAddr}` : "";
    const objNote = objAddr ? ` (obj 0x${objAddr})` : "";
    const cmdNote = cmd ? ` — cmd: ${oneLine(cmd).slice(0, 120)}` : "";
    const description = `MemProcFS YARA: ${proc} (PID ${pid})${memNote ? ` — match in ${memNote}` : " — YARA match"}${addrNote}${objNote}${cmdNote}`.slice(0, 600);

    mapped.push({
      timestamp,
      description,
      severity: "Critical",
      mitre: ["T1055"],
      aggKey: `memprocfs|yara|${pid}|${proc.toLowerCase()}|${baseAddr}`.slice(0, 400),
      sources: ["MemProcFS"],
      ...(pName ? { processName: pName } : {}),
    });
  }

  const { events, groups } = aggregateEvents(mapped, {
    aggregate: opts.aggregate, minSeverity: opts.minSeverity, maxEvents: opts.maxEvents ?? (Number(process.env.DFIR_MAX_EVENTS) || 2000),
  });
  const maxIocs = opts.maxIocs ?? 5000;
  const represented = events.reduce((n, e) => n + (e.count ?? 1), 0);
  return {
    events, iocs: [...sink.values()].slice(0, maxIocs),
    total: rows.length, kept: events.length,
    dropped: Math.max(0, rows.length - represented), groups, tables: 1,
    injected: rows.length, processes: 0, connections: 0,
    format: "memprocfs-yara-csv", tool: "MemProcFS",
  };
}

// ─────────────────────────── MemProcFS timeline_all.csv ────────────────────────────
//
// MemProcFS full-system timeline: Time,Type,Action,PID,Value32,Value64,Text,Pad.
// Every kernel-level event the tool observed in 8 types:
//   ShTask (566 typical) → CRE/DEL Medium/T1053.005, MOD Low — scheduled-task lifecycle
//   PROC   (219 typical) → Info evidence events for process start/exit
//   Net    (118 typical) → Low / network IOCs for real remote connections (TCP/UDP)
//   WEB    (18 typical)  → browser VISIT (Info/T1217) or DOWNLOAD (Low/T1105) + URL IOCs
//   NTFS   (248k typical) — too noisy for events; harvest executable-extension CRE as file IOCs
//   REG, THREAD, KObj  — pure telemetry, 255k+ rows, dropped entirely
//
// All events carry the artifact's own Time column timestamp, never the import time.
// Paths are normalised: \1\ volume prefix and \Device\HarddiskVolumeN\ become C:\.

const MPFS_EXEC_EXT = /\.(exe|dll|sys|drv|bat|cmd|ps1|vbs|js|hta|msi|scr|cpl|ocx|inf|lnk)$/i;
const MPFS_NET_RE = /^(TCP|UDP)v[46]\s+(\S+)\s+(\S+)\s+(\S+)/i;
const MPFS_ADDR4_RE = /^([\d.]+):(\d+)$/;
const MPFS_ADDR6_RE = /^\[([^\]]+)\]:(\d+)$/;
const MPFS_WEB_BROWSER_RE = /browser:\[([^\]]*)\]/i;
const MPFS_WEB_TYPE_RE = /type:\[([^\]]*)\]/i;
const MPFS_WEB_URL_RE = /url:\[([^\]]*)\]/i;
const MPFS_PROC_RE = /^(\S+)\s+\[([^\]]*)\]\s*(\\.*)?$/;
const MPFS_SHTASK_RE = /^(.*?)\s+-\s+\[(.+?)\]\s*(?:\(([^)]+)\))?$/;

function cleanMpfsPath(p: string): string {
  return p
    .replace(/\\\\/g, "\\")
    .replace(/^\\1\\/, "C:\\")
    .replace(/^\\Device\\HarddiskVolume\d+\\/i, "C:\\");
}

function parseMpfsNetAddr(addr: string): { ip: string; port: string } | null {
  if (!addr || addr === "***") return null;
  const m6 = MPFS_ADDR6_RE.exec(addr);
  if (m6) return { ip: m6[1], port: m6[2] };
  const m4 = MPFS_ADDR4_RE.exec(addr);
  if (m4) return { ip: m4[1], port: m4[2] };
  return null;
}

function mapMpfsTimelineRow(
  type: string, action: string, pid: string, txt: string, ts: string,
  sink: Map<string, SiemIoc>, mapped: MappedEvent[],
): void {
  switch (type) {
    case "PROC": {
      const m = MPFS_PROC_RE.exec(txt);
      if (!m) break;
      const procName = m[1] ?? "";
      const user = (m[2] ?? "").replace(/^\*/, "").trim();
      const cleanPath = cleanMpfsPath(m[3] ?? "");
      const pName = baseName(procName);
      if (pName) addIoc(sink, "process", pName);
      if (cleanPath && /[\\/]/.test(cleanPath)) addIoc(sink, "file", cleanPath.slice(0, 300));
      const verb = action.toUpperCase() === "DEL" ? "exit" : "start";
      const userNote = user ? ` [${user}]` : "";
      mapped.push({
        timestamp: ts,
        description: `MemProcFS PROC ${verb}: ${procName} (PID ${pid})${userNote}`.slice(0, 400),
        severity: "Info",
        mitre: [],
        aggKey: `memprocfs|proc|${action.toUpperCase()}|${pid}|${procName.toLowerCase()}`,
        sources: ["MemProcFS"],
        ...(pName ? { processName: pName } : {}),
        ...(cleanPath && /[\\/]/.test(cleanPath) ? { path: cleanPath } : {}),
      });
      break;
    }
    case "Net": {
      const m = MPFS_NET_RE.exec(txt);
      if (!m) break;
      const [, proto, state, , remote] = m;
      if (!remote || remote === "***" || state === "***") break;
      const parsed = parseMpfsNetAddr(remote);
      if (!parsed) break;
      const ip = cleanIp(parsed.ip);
      if (!ip) break;
      addIoc(sink, "ip", ip);
      mapped.push({
        timestamp: ts,
        description: `MemProcFS Net: ${proto} ${state} → ${ip}:${parsed.port} (PID ${pid})`.slice(0, 400),
        severity: /^TCP/i.test(proto) ? "Low" : "Info",
        mitre: ["T1071"],
        aggKey: `memprocfs|net|${ip}:${parsed.port}`,
        sources: ["MemProcFS"],
      });
      break;
    }
    case "ShTask": {
      const a = action.toUpperCase();
      const m = MPFS_SHTASK_RE.exec(txt);
      const taskName = ((m?.[1] ?? txt).trim()).slice(0, 100);
      const cmd = (m?.[2] ?? "").split("::")[0].trim().slice(0, 150);
      const user = m?.[3]?.trim() ?? "";
      let severity: Severity;
      let mitre: string[];
      let verb: string;
      if (a === "CRE")      { severity = "Medium"; mitre = ["T1053.005"]; verb = "created"; }
      else if (a === "DEL") { severity = "Medium"; mitre = ["T1070"];     verb = "deleted"; }
      else                  { severity = "Low";    mitre = ["T1053.005"]; verb = "modified"; }
      const cmdNote = cmd ? ` — ${cmd}` : "";
      const userNote = user ? ` (${user})` : "";
      mapped.push({
        timestamp: ts,
        description: `MemProcFS ShTask ${verb}: ${taskName}${cmdNote}${userNote}`.slice(0, 500),
        severity,
        mitre,
        aggKey: `memprocfs|shtask|${a}|${taskName.toLowerCase()}`,
        sources: ["MemProcFS"],
      });
      break;
    }
    case "WEB": {
      const url = MPFS_WEB_URL_RE.exec(txt)?.[1]?.trim() ?? "";
      if (!url || !/^https?:/i.test(url)) break;
      const browser = MPFS_WEB_BROWSER_RE.exec(txt)?.[1]?.trim() ?? "";
      const webType = MPFS_WEB_TYPE_RE.exec(txt)?.[1]?.trim() ?? "VISIT";
      addIoc(sink, "url", url.slice(0, 500));
      try {
        const domain = new URL(url).hostname;
        if (domain && !PRIVATE_IP.test(domain)) addIoc(sink, "domain", domain);
      } catch { /* malformed URL */ }
      const isDownload = /download/i.test(webType);
      const browserNote = browser ? `[${browser}] ` : "";
      mapped.push({
        timestamp: ts,
        description: `MemProcFS WEB ${webType}: ${browserNote}${url.slice(0, 200)}`.slice(0, 500),
        severity: isDownload ? "Low" : "Info",
        mitre: isDownload ? ["T1105"] : ["T1217"],
        aggKey: `memprocfs|web|${url.slice(0, 200).toLowerCase()}`,
        sources: ["MemProcFS"],
      });
      break;
    }
    case "NTFS": {
      // 248k rows — too noisy for events; harvest executable-extension file creations as IOCs.
      if (action.toUpperCase() === "CRE" && MPFS_EXEC_EXT.test(txt)) {
        addIoc(sink, "file", cleanMpfsPath(txt).slice(0, 300));
      }
      break;
    }
    // REG (254k), THREAD, KObj — pure telemetry, dropped
  }
}

function parseMemoryMemprocfsTimeline(text: string, opts: MemoryImportOptions): MemoryParseResult {
  const empty: MemoryParseResult = {
    events: [], iocs: [], total: 0, kept: 0, dropped: 0, groups: 0,
    tables: 0, injected: 0, processes: 0, connections: 0,
    format: "memprocfs-timeline", tool: "MemProcFS",
  };
  const { headers, rows } = parseCsv(text);
  if (!headers.length || !rows.length) return empty;

  const idx = (name: string): number => headers.findIndex((h) => h.toLowerCase() === name);
  const timeI = idx("time"); const typeI = idx("type"); const actionI = idx("action");
  const pidI = idx("pid"); const textI = idx("text");
  if (typeI < 0 || actionI < 0) return empty;

  const sink = new Map<string, SiemIoc>();
  const mapped: MappedEvent[] = [];
  let procCount = 0, netCount = 0;

  for (const row of rows) {
    const type    = row[typeI]?.trim()   ?? "";
    const action  = row[actionI]?.trim() ?? "";
    const pid     = (pidI   >= 0 ? row[pidI]   : undefined)?.trim() ?? "0";
    const txt     = (textI  >= 0 ? row[textI]  : undefined)?.trim() ?? "";
    const ts      = normalizeTime((timeI >= 0 ? row[timeI] : undefined)?.trim() ?? "") ?? "";
    const before  = mapped.length;
    mapMpfsTimelineRow(type, action, pid, txt, ts, sink, mapped);
    if (mapped.length > before) {
      if (type === "PROC") procCount++;
      if (type === "Net")  netCount++;
    }
  }

  const { events, groups } = aggregateEvents(mapped, {
    aggregate:   opts.aggregate,
    minSeverity: opts.minSeverity,
    maxEvents:   opts.maxEvents ?? (Number(process.env.DFIR_MAX_EVENTS) || 2000),
  });
  const maxIocs = opts.maxIocs ?? 5000;
  const represented = events.reduce((n, e) => n + (e.count ?? 1), 0);
  return {
    events,
    iocs: [...sink.values()].slice(0, maxIocs),
    total: rows.length,
    kept:  events.length,
    dropped: Math.max(0, rows.length - represented),
    groups,
    tables: 1,
    injected: 0,
    processes: procCount,
    connections: netCount,
    format: "memprocfs-timeline",
    tool: "MemProcFS",
  };
}

// ───────────────────────────── top-level parse ─────────────────────────────

export function parseMemory(text: string, opts: MemoryImportOptions = {}): MemoryParseResult {
  // MemProcFS findevil: a flat finding-report table — check before JSON/text Volatility paths.
  if (looksLikeMemprocfsFindevil(text)) return parseMemoryFindevil(text, opts);

  // MemProcFS CSV variants — identified by distinctive column sets in the first header line.
  const cols = csvCols(text);
  // timeline_all.csv: Time,Type,Action,PID,Value32,Value64,Text,Pad — value32/value64 are unique.
  if (cols.has("value32") && cols.has("value64") && cols.has("action")) {
    return parseMemoryMemprocfsTimeline(text, opts);
  }
  if (cols.has("matchindex") && cols.has("memorytype") && cols.has("processname")) {
    return parseMemoryYaraCsv(text, opts);
  }
  if (cols.has("processname") && cols.has("type") && cols.has("address") && !cols.has("matchindex")) {
    return parseMemoryFindevilCsv(text, opts);
  }

  const maxIocs = opts.maxIocs ?? 5000;
  const { tables, format, tool } = extractTables(text, opts.filename);
  const total = tables.reduce((n, t) => n + t.rows.length, 0);
  if (tables.length === 0 || total === 0) {
    return { events: [], iocs: [], total: 0, kept: 0, dropped: 0, groups: 0, tables: 0, injected: 0, processes: 0, connections: 0, format, tool: "" };
  }

  const sink = new Map<string, SiemIoc>();
  const mapped: MappedEvent[] = [];
  let injected = 0, processes = 0, connections = 0;

  for (const t of tables) {
    const cols = colSet(t.rows);
    const category = classify(t.plugin, cols);
    const label = displayLabel(t.plugin, category, t.rows);
    switch (category) {
      case "process": mapped.push(...mapProcess(label, tool, t.rows, sink)); processes += t.rows.length; break;
      case "netscan": mapped.push(...mapNetscan(label, tool, t.rows, sink)); connections += t.rows.length; break;
      case "malfind": mapped.push(...mapMalfind(label, tool, t.rows, sink)); injected += t.rows.length; break;
      case "cmdline": mapped.push(...mapCmdline(label, tool, t.rows, sink)); break;
      case "service": mapped.push(...mapService(label, tool, t.rows, sink)); break;
      case "module": mapped.push(...mapModule(label, tool, t.rows, sink)); break;
      case "dll": mapped.push(...mapDll(label, tool, t.rows, sink, !!opts.dllTelemetry)); break;
      case "handle": break; // handle tables are pure telemetry — neither events nor IOCs
      default: mapped.push(...mapGeneric(label, tool, t.rows, sink));
    }
  }

  const { events, groups } = aggregateEvents(mapped, {
    aggregate: opts.aggregate,
    minSeverity: opts.minSeverity,
    maxEvents: opts.maxEvents ?? (Number(process.env.DFIR_MAX_EVENTS) || 2000),
  });

  const represented = events.reduce((n, e) => n + (e.count ?? 1), 0);
  return {
    events,
    iocs: [...sink.values()].slice(0, maxIocs),
    total,
    kept: events.length,
    dropped: Math.max(0, total - represented),
    groups,
    tables: tables.length,
    injected,
    processes,
    connections,
    format,
    tool,
  };
}
