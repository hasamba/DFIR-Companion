// Deterministic importer for memory-forensics tool output — Volatility 3 and Rekall. The
// fifteenth deterministic ingest path; no AI call.
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
    const severity: Severity = susp === "strong" ? "High" : susp === "weak" ? "Medium" : "Info";
    out.push({
      timestamp: "",
      description: `${tool} ${label}: ${proc || "?"} (PID ${pid || "?"})${args ? ` — ${oneLine(args).slice(0, 220)}` : ""}`.slice(0, 600),
      severity,
      mitre: susp ? ["T1059"] : [],
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

// ───────────────────────────── top-level parse ─────────────────────────────

export function parseMemory(text: string, opts: MemoryImportOptions = {}): MemoryParseResult {
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
    maxEvents: opts.maxEvents ?? 2000,
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
