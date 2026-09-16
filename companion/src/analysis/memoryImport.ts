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
import { createCanonicalEvent, stampSourceArtifactHash } from "./canonicalEvent.js";
import {
  aggregateEvents,
  genericIocs,
  isSuspiciousCmd,
  addIoc,
  baseName,
  cleanIp,
  oneLine,
  isObject,
  getCI,
  normalizeTime,
  type MappedEvent,
  type SiemEvent,
  type SiemIoc,
  maxEventsDefault,
} from "./siemImport.js";
import {
  GENERIC_TIME_KEYS,
  cellStr,
  isPlaceholderCell,
  filePathIoc,
  malfindDescription,
  malfindRegion,
  pickTime,
  serviceImagePath,
} from "./memoryFields.js";
import { pstreeChildren } from "./pstreeDepth.js";
import { extractTables, SHORT_PLUGIN } from "./memoryTables.js";
import { carryImage, imageFactsEvents, isImageInfoTable, readImageFacts } from "./memoryImageFacts.js";
import { exportShapeEvents, exportShapeNote } from "./memoryExportShape.js";
import { isRunEnvelopeUpload, parseRunEnvelopes } from "./memoryRunEnvelope.js";
import { boundedAggKey } from "./aggKey.js";
import { identityMark, packTags } from "./recordIdentity.js";
import {
  indexProcessRows,
  objectOffset,
  ownerConsistency,
  ownerDigest,
  normalizeAddress,
  readState,
  readTime,
  shown,
  socketProvenance,
  SOCKET_CREATED_KEYS,
  tupleShape,
  type ProcessIndex,
} from "./memoryNetObjects.js";
import { handleOwnershipFacts } from "./memoryHandleOwnership.js";
import { yaraMappingContext } from "./memoryYaraMappingContext.js";
import { severityFromMeta, mitreFromYara } from "./yaraImport.js";
export { isRekallCommandList, looksLikeVolatilityText } from "./memoryTables.js";
import { parseCsv } from "./csvImport.js";
import { tradecraftSignal } from "./tradecraftRules.js";
import { malfindContext } from "./malfindContext.js";
import { repeatedShortLifetimes, type ProcessRecord } from "./processLifetime.js";
import { psxviewSignal, ldrModulesSignal, hasLdrColumns, hasPsxviewColumns } from "./memoryCrossView.js";

type Row = Record<string, unknown>;

export interface MemoryImportOptions {
  aggregate?: boolean;
  minSeverity?: Severity;
  maxEvents?: number;
  maxIocs?: number;
  // Include `dlllist`/`ldrmodules` rows as Info events (default: false — only their paths are IOCs).
  dllTelemetry?: boolean;
  // The export filename — a weak plugin hint for a bare Volatility array that carries no plugin name.
  filename?: string;
}

export interface MemoryParseResult {
  events: SiemEvent[];
  iocs: SiemIoc[];
  total: number; // rows across all tables
  kept: number; // events emitted (after aggregation + cap)
  dropped: number; // rows not represented (dll/handle telemetry / below floor / capped)
  groups: number; // distinct event groups before the cap
  tables: number; // plugin tables parsed
  injected: number; // malfind (injected-code) rows seen
  processes: number; // process-listing rows seen
  connections: number; // network-connection rows seen
  format: string; // "volatility" | "volatility-jsonl" | "volatility-map" | "volatility-text" | "volatility2-text" | "rekall" | "empty"
  tool: string; // "Volatility" | "Rekall" | ""
  // What the export's SHAPE says (memoryExportShape.ts) — for the import note, never a completion claim.
  note?: string;
}

type Category =
  | "process"
  | "netscan"
  | "malfind"
  | "cmdline"
  | "service"
  | "module"
  | "dll"
  | "handle"
  | "imageinfo"
  | "generic";

const PRIVATE_IP =
  /^(?:10\.|127\.|169\.254\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.|0\.|255\.|22[4-9]\.|23\d\.|::1$|fe80:|fc|fd)/i;

// ───────────────────────────── cell / field helpers ─────────────────────────────

// First non-empty resolved value across candidate keys (case-insensitive).
function pick(row: Row, keys: string[]): string {
  for (const k of keys) {
    const s = cellStr(getCI(row, k)).trim();
    // Volatility's `-` (unreadable) and `N/A` are ABSENT values, not names, paths or addresses.
    if (s && !isPlaceholderCell(s)) return s;
  }
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

  if (/dlllist|ldrmodules|dlldump/.test(p)) return "dll"; // before /modules/ — it matches ldrmodules
  if (has("pid") && any("base", "dllbase") && any("path", "loadtime", "mappedpath") && has("size"))
    return "dll";

  if (/driver|modscan|modules|modlist|lsmod|kernel_module/.test(p)) return "module";
  if (any("base", "dllbase") && has("size") && any("name", "path", "driver name") && !has("pid"))
    return "module";

  if (/handles?/.test(p)) return "handle";

  if (/pslist|psscan|pstree|psxview|pstotal|ps_|memdump|procdump/.test(p)) return "process";
  if (any("imagefilename", "comm", "_eprocess")) return "process";
  if (
    has("ppid") &&
    any("createtime", "process_create_time", "threads", "thread_count", "handles", "handle_count")
  )
    return "process";

  return "generic";
}

// A short, human label for the plugin: Rekall/known name, Volatility dotted-id module, or a fallback.
function displayLabel(plugin: string, category: Category, rows: Row[]): string {
  const p = plugin.toLowerCase();
  const dotted = /\b(windows|linux|mac)\.(\w+)/.exec(p);
  if (dotted) return dotted[2];
  const m = SHORT_PLUGIN.exec(p);
  if (m) return m[1];
  if (category === "process") {
    return rows.some((r) => {
      const c = getCI(r, "__children");
      return Array.isArray(c) && c.length > 0;
    })
      ? "pstree"
      : "pslist";
  }
  const byCat: Record<Category, string> = {
    process: "pslist",
    netscan: "netscan",
    malfind: "malfind",
    cmdline: "cmdline",
    service: "svcscan",
    module: "modules",
    dll: "dlllist",
    handle: "handles",
    imageinfo: "info",
    generic: "memory",
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
  let recordIndex = 0;

  // Index PID → name (across the whole tree) so a flat table resolves PPID → parent name.
  const pidIndex = new Map<string, string>();
  const index = (list: Row[], depth: number): void => {
    for (const r of list) {
      const pid = pickPid(r);
      const nm = procName(r);
      if (pid && nm) pidIndex.set(pid, nm);
      index(pstreeChildren(r, depth), depth + 1);
    }
  };
  index(rows, 0);
  recordIndex = 0;

  const walk = (list: Row[], parent: string, depth: number): void => {
    for (const r of list) {
      const locatorIndex = recordIndex++;
      const name = procName(r);
      const pid = pickPid(r);
      const ppid = pick(r, ["PPID", "ppid"]);
      const created = pickTime(r, [
        "CreateTime",
        "process_create_time",
        "CreatedTime",
        "create_time",
        "start_time",
      ]);
      const exited = pick(r, ["ExitTime", "process_exit_time"]).trim();
      const cmd = pick(r, ["Cmd", "CommandLine", "Args"]);
      const path = pick(r, ["Path", "path"]);
      if (name || pid) {
        if (name) addIoc(sink, "process", name);
        addIoc(sink, "file", filePathIoc(path));
        const parentName = parent || (ppid ? baseName(pidIndex.get(ppid) ?? "") : "");
        const exitNote = exited && !/^(n\/?a|-|0|none)$/i.test(exited) ? ", terminated" : "";
        let description = `${tool} ${label}: ${name || "?"} (PID ${pid || "?"}${ppid ? `, PPID ${ppid}` : ""}${exitNote})`;
        if (created) description += ` started ${created}`;
        if (cmd) description += ` — ${oneLine(cmd).slice(0, 160)}`;
        const pidNumber = Number(pid);
        const parentPidNumber = Number(ppid);
        const canonical = createCanonicalEvent({
          event: { category: "process", type: "observation" },
          subject: {
            kind: "process",
            ...(pid ? { id: pid } : {}),
            ...(name ? { name } : {}),
          },
          process: {
            ...(Number.isInteger(pidNumber) && pidNumber > 0 ? { pid: pidNumber } : {}),
            ...(name ? { name } : {}),
            ...(path ? { executable: path } : {}),
            ...(cmd ? { commandLine: cmd } : {}),
            ...(parentName || (Number.isInteger(parentPidNumber) && parentPidNumber > 0)
              ? {
                  parent: {
                    ...(Number.isInteger(parentPidNumber) && parentPidNumber > 0
                      ? { pid: parentPidNumber }
                      : {}),
                    ...(parentName ? { name: parentName } : {}),
                  },
                }
              : {}),
          },
          ...(path ? { file: { path, name: baseName(path) } } : {}),
          time: { observed: created, normalized: created },
          evidence: {
            rawRecords: [
              {
                source: `${tool.toLowerCase()}-${label}`,
                locator: `row:${locatorIndex}`,
                ...(pid ? { recordId: pid } : {}),
              },
            ],
          },
          producer: {
            importer: "memory",
            parserVersion: "1",
            mappingVersion: "memory-process-v1",
          },
          rawFieldMap: {
            "time.observed": ["CreateTime", "process_create_time", "CreatedTime", "start_time"],
            ...(pid ? { "subject.id": ["PID"], "process.pid": ["PID"] } : {}),
            ...(name ? { "subject.name": PROC_NAME_KEYS, "process.name": PROC_NAME_KEYS } : {}),
            ...(path ? { "process.executable": ["Path"], "file.path": ["Path"] } : {}),
            ...(cmd ? { "process.commandLine": ["Cmd", "CommandLine", "Args"] } : {}),
            ...(ppid ? { "process.parent.pid": ["PPID"] } : {}),
          },
        });
        // psxview prints one column per enumeration method, and the reason to run it is that they
        // can DISAGREE. Flattened to a generic process row those columns were dropped, so the only
        // thing the plugin is collected for never reached the timeline (#909 item 3). Graded
        // cautiously — see memoryCrossView.ts for the benign causes it has to rule out first.
        // Detected by COLUMNS, not by the plugin label: a dotted Volatility id like
        // `windows.malware.psxview` renders its label as "malware", so a name test silently never
        // fired. The columns are what the signal reads anyway.
        const cross = hasPsxviewColumns(r) ? psxviewSignal(r) : null;
        if (cross) description += ` — ${cross.note}`;
        out.push({
          timestamp: created,
          description: description.slice(0, 600),
          severity: cross ? cross.severity : "Info",
          mitre: cross ? [...cross.mitre] : [],
          canonical,
          // The process-object offset distinguishes two EPROCESS rows that share a reused PID —
          // psxview reports one row per object, and collapsing them loses one view's verdict.
          aggKey:
            `mem|proc|${(name || "?").toLowerCase()}|${pid}|${ppid}|${pick(r, ["Offset(V)", "Offset", "offset"])}${psscan ? "|scan" : ""}`.slice(
              0,
              400,
            ),
          sources: [tool],
          ...(name ? { processName: name } : {}),
          ...(parentName ? { parentName } : {}),
          ...(Number.isInteger(pidNumber) && pidNumber > 0 ? { pid: pidNumber } : {}),
          ...(cmd ? { commandLine: cmd } : {}),
          ...(filePathIoc(path) ? { path } : {}),
        });
      }
      walk(pstreeChildren(r, depth), name || parent, depth + 1);
    }
  };
  walk(rows, "", 0);
  return out;
}

/**
 * Rekall's socket rows carry combined `ip:port` cells and are OUTSIDE the object contract below;
 * they keep the rendering they had (#933 item 14 excludes them by design).
 */
function mapNetscanLegacy(
  label: string,
  tool: string,
  rows: Row[],
  sink: Map<string, SiemIoc>,
): MappedEvent[] {
  const out: MappedEvent[] = [];
  for (const r of rows) {
    const proto = pick(r, ["Proto", "proto", "Protocol", "protocol"]);
    const laddr = pick(r, ["LocalAddr", "local_addr", "LocalAddress", "Source"]);
    const lport = pick(r, ["LocalPort", "local_port", "Lport"]);
    const faddr = pick(r, [
      "ForeignAddr",
      "foreign_addr",
      "ForeignAddress",
      "RemoteAddr",
      "remote_addr",
      "Destination",
    ]);
    const fport = pick(r, ["ForeignPort", "foreign_port", "RemotePort"]);
    const state = pick(r, ["State", "state"]);
    const owner = pick(r, ["Owner", "Process", "owner", "ImageFileName"]);
    const pid = pickPid(r);
    const created = pickTime(r, ["Created", "create_time", "created"]);
    const fip = cleanIp(faddr.replace(/:\d+$/, ""));
    if (fip) addIoc(sink, "ip", fip);
    out.push({
      timestamp: created,
      description:
        `${tool} ${label}: ${shown(proto, 12) || "?"} ${shown(laddr, 48) || "?"}${lport ? `:${shown(lport, 8)}` : ""} → ${shown(faddr, 48) || "*"}${fport ? `:${shown(fport, 8)}` : ""}${state ? ` [state: ${shown(state, 40)}]` : ""}${owner ? ` owner ${shown(owner, 80)}` : ""}${/^\d+$/.test(pid) ? ` (PID ${pid})` : ""}`.slice(
          0,
          600,
        ),
      severity: "Info",
      mitre: [],
      aggKey: boundedAggKey(
        `mem|net|rekall|${proto}|${laddr}|${lport}|${faddr}|${fport}|${state}|${pid}`.toLowerCase(),
      ),
      sources: [tool],
      ...(fip ? { dstIp: fip } : {}),
    });
  }
  return out;
}

/** The socket row's own fields, read once for the pre-pass and the mapper alike. */
function socketFields(r: Row) {
  return {
    tuple: {
      proto: pick(r, ["Proto", "proto", "Protocol"]),
      laddr: pick(r, ["LocalAddr", "local_addr", "LocalAddress", "Source"]),
      lport: pick(r, ["LocalPort", "local_port", "Lport"]),
      faddr: pick(r, ["ForeignAddr", "foreign_addr", "ForeignAddress", "RemoteAddr", "Destination"]),
      fport: pick(r, ["ForeignPort", "foreign_port", "RemotePort"]),
      state: pick(r, ["State", "state"]),
    },
    owner: pick(r, ["Owner", "Process", "owner", "ImageFileName"]),
    pidRaw: pickPid(r),
    // Only a canonical numeric PID is compared or shown as a PID; anything else is "not readable".
    pid: /^\d{1,10}$/.test(pickPid(r)) ? pickPid(r) : "",
    created: readTime(r, SOCKET_CREATED_KEYS),
  };
}

/**
 * A socket object, read for what its record establishes (#933 item 14, memoryNetObjects.ts): the
 * stored state and Volatility's reading of it, how the plugin reported the object, the owner's own
 * two fields, a consistency note against the submitted process rows, and the tuple's shape. The
 * identity is the object's offset, shown in the row: two rows at one offset are one object
 * reported twice; a row with no offset never folds.
 */
function mapNetscan(
  plugin: string,
  label: string,
  tool: string,
  rows: Row[],
  sink: Map<string, SiemIoc>,
  index: ProcessIndex,
): MappedEvent[] {
  if (tool === "Rekall") return mapNetscanLegacy(label, tool, rows, sink);
  const out: MappedEvent[] = [];
  const provenance = socketProvenance(plugin);
  rows.forEach((r, rowIndex) => {
    const { tuple, owner, pidRaw, pid, created } = socketFields(r);
    const state = readState(tuple.state, tuple.proto);
    const shape = tupleShape(tuple);
    const consistency = ownerConsistency(pid, owner, created, index);
    const offset = objectOffset(r);

    const peer = shape.ok ? cleanIp(shape.peer) : "";
    const lip = shape.ok ? cleanIp(normalizeAddress(tuple.laddr)) : "";
    if (peer && !state.listening) addIoc(sink, "ip", peer);
    const proc = consistency.consistent && owner ? baseName(owner) : "";
    if (proc && /\.\w{2,4}$/.test(proc)) addIoc(sink, "process", proc);

    const external = !!peer && !state.listening && !PRIVATE_IP.test(peer);
    const severity: Severity = external && state.token.toUpperCase() === "ESTABLISHED" ? "Low" : "Info";

    const pidWords = pid
      ? `PID ${pid}`
      : pidRaw
        ? `PID not readable (${shown(pidRaw, 20)})`
        : "PID not in the record";
    const ownerWords =
      !owner && !pidRaw
        ? "owner: not in the record — not an indicator of concealment"
        : `owner: ${owner ? `${shown(owner, 80)}, ${pidWords}` : `${pidWords}, name not in the record`} — ${consistency.words}`;
    // Mandatory qualifications first, so a long owner can never push them past the cap.
    const tags = [
      `state: ${state.token ? `${state.token} — ` : ""}${state.reading}`,
      provenance,
      shape.ok ? "" : `tuple incomplete: ${shape.problem}`,
      severity === "Low"
        ? "externally addressed object in stored state ESTABLISHED: triage priority, not a claim of traffic"
        : "",
      ownerWords,
      created.status === "ok"
        ? `created: ${created.iso}`
        : created.status === "unreadable"
          ? `created: not readable — ${shown(created.raw, 40)}`
          : "",
      offset ? `object 0x${offset}` : "object offset not in the record",
    ].filter(Boolean);
    const endpoint = `${shown(tuple.proto, 12) || "?"} ${shown(tuple.laddr, 48) || "?"}:${shown(tuple.lport, 8) || "?"} → ${shown(tuple.faddr, 48) || "*"}:${shown(tuple.fport, 8) || "*"}`;
    const head = `${tool} ${label}: ${endpoint}`;
    const key = boundedAggKey(
      `mem|net|${provenance.slice(0, 12)}|${tuple.proto}|${tuple.laddr}|${tuple.lport}|${tuple.faddr}|${tuple.fport}|${tuple.state}|${pidRaw}|${ownerDigest(owner, pidRaw)}|${created.raw}|${offset ? `off:${offset}` : `row:${rowIndex}`}`.toLowerCase(),
    );
    const mark = identityMark(key);
    const packed = packTags(tags, 600 - head.length - mark.length);
    const kept = packed ? packed.split("] [").length : 0;

    out.push({
      timestamp: created.iso,
      // A row without an offset carries its identity mark: two such rows must stay two rows
      // downstream, where only the description survives.
      description: `${head}${packed}${kept < tags.length || !offset ? mark : ""}`,
      severity,
      mitre: [],
      aggKey: key,
      sources: [tool],
      ...(proc ? { processName: proc } : {}),
      ...(lip ? { srcIp: lip } : {}),
      ...(peer ? { dstIp: peer } : {}),
      ...(Number.isFinite(shape.fport) && shape.fport > 0 && shape.ok ? { port: shape.fport } : {}),
    });
  });
  return out;
}

function mapMalfind(
  label: string,
  tool: string,
  rows: Row[],
  sink: Map<string, SiemIoc>,
  corroborating: { network: Set<string>; suspiciousCmd: Set<string> },
): MappedEvent[] {
  const out: MappedEvent[] = [];
  for (const r of rows) {
    const proc = pick(r, ["Process", "ImageFileName", "Name", "name", "_EPROCESS"]);
    const pid = pickPid(r);
    const prot = pick(r, ["Protection", "protection"]);
    const tag = pick(r, ["Tag", "tag", "VadTag", "vad_tag"]);
    const region = malfindRegion(r); // its token and its phrase must agree — see malfindRegion
    const name = proc ? baseName(proc) : "";
    if (name) addIoc(sink, "process", name);
    // malfind's region shape also matches every JIT/.NET/AV engine, so state its own observed characteristics (#909 item 4).
    const ctx = malfindContext(r, {
      networkPid: corroborating.network.has(pid),
      suspiciousCommandLine: corroborating.suspiciousCmd.has(pid),
    });
    out.push({
      timestamp: "",
      // The SHORT clause comes first, because synthesis and the case reports truncate a description
      // at 240 characters — with the caveat only at the end they saw the categorical lead alone.
      description:
        `${malfindDescription(tool, label, proc, pid, region.phrase, prot, tag)} — ${ctx.summary} — ${ctx.note}`.slice(
          0,
          900,
        ),
      severity: "High",
      mitre: ["T1055"],
      aggKey: `mem|malfind|${name.toLowerCase()}|${pid}|${region.token}|${prot}`.toLowerCase().slice(0, 400),
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
      description:
        `${tool} ${label}: ${proc || "?"} (PID ${pid || "?"})${args ? ` — ${oneLine(args).slice(0, 220)}` : ""}`.slice(
          0,
          600,
        ),
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
    const image = serviceImagePath(binary);
    addIoc(sink, "file", image); // the row text below still shows the full command line
    const susp = isSuspiciousCmd(binary, "");
    const severity: Severity = susp === "strong" ? "High" : susp === "weak" ? "Medium" : "Info";
    out.push({
      timestamp: "",
      description:
        `${tool} ${label}: service ${name || "?"}${display && display !== name ? ` (${display})` : ""}${state ? ` [${state}]` : ""}${binary ? ` → ${oneLine(binary).slice(0, 200)}` : ""}`.slice(
          0,
          600,
        ),
      severity,
      mitre: [],
      aggKey: `mem|svc|${(name || binary).toLowerCase()}`.slice(0, 400),
      sources: [tool],
      ...(image ? { path: image } : {}),
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
    addIoc(sink, "file", filePathIoc(path));
    out.push({
      timestamp: "",
      description:
        `${tool} ${label}: ${name || "?"}${base ? ` @ ${base}` : ""}${path ? ` — ${oneLine(path).slice(0, 200)}` : ""}`.slice(
          0,
          600,
        ),
      severity: "Info",
      mitre: [],
      aggKey: `mem|mod|${(name || path).toLowerCase()}`.slice(0, 400),
      sources: [tool],
      ...(filePathIoc(path) ? { path } : {}),
    });
  }
  return out;
}

// dlllist/ldrmodules: high-volume — by default harvest the DLL path as a file IOC only, opt-in to keep events.
function mapDll(
  label: string,
  tool: string,
  rows: Row[],
  sink: Map<string, SiemIoc>,
  telemetry: boolean,
): MappedEvent[] {
  const out: MappedEvent[] = [];
  for (const r of rows) {
    const path = pick(r, ["Path", "path", "MappedPath", "FullDllName"]);
    const dllName = pick(r, ["Name", "name", "BaseDllName"]);
    const proc = procName(r);
    const pid = pickPid(r);
    addIoc(sink, "file", filePathIoc(path));
    // A module mapped but absent from the PEB loader lists becomes an event despite DLL rows being telemetry (#909 item 3).
    const cross = hasLdrColumns(r) ? ldrModulesSignal(r) : null;
    if (!telemetry && !cross) continue;
    // A flagged row with NO path is the strongest case this table produces — executable memory that
    // no file explains. Dropping it for lacking a name discarded exactly the finding worth keeping,
    // so a cross-view signal is described by its base address instead.
    if (!path && !dllName && !cross) continue;
    const base = pick(r, ["Base", "base", "DllBase"]);
    const what = path || dllName || `region at ${base || "?"}`;
    out.push({
      timestamp: pickTime(r, ["LoadTime", "load_time"]),
      description: (
        `${tool} ${label}: ${proc || "?"} (PID ${pid || "?"}) loaded ${oneLine(what).slice(0, 220)}` +
        (cross ? ` — ${cross.note}` : "")
      ).slice(0, 600),
      severity: cross ? cross.severity : "Info",
      mitre: cross ? [...cross.mitre] : [],
      // PID and base included: without them two different svchost.exe PIDs mapping the same path,
      // or two mappings at different bases in one PID, aggregated into a single event and one of
      // the cross-view findings disappeared into a count (#909 item 3 requires same-identity only).
      aggKey: `mem|dll|${proc.toLowerCase()}|${pid}|${base}|${what.toLowerCase()}`.slice(0, 400),
      sources: [tool],
      ...(proc ? { processName: proc } : {}),
      ...(filePathIoc(path) ? { path } : {}),
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
    const body = pairs
      .slice(0, 8)
      .map(([k, v]) => `${k}=${v}`)
      .join(" ");
    out.push({
      timestamp: pickTime(r, GENERIC_TIME_KEYS),
      description: `${tool} ${label}: ${body}`.slice(0, 600),
      severity: "Info",
      mitre: [],
      aggKey: `mem|gen|${label}|${body}`
        .toLowerCase()
        .replace(/0x[0-9a-f]+/g, "<addr>")
        .replace(/\d+/g, "#")
        .slice(0, 400),
      sources: [tool],
    });
  }
  return out;
}

// ───────────────────────────── table extraction ─────────────────────────────

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
    if (FINDEVIL_HEADER_RE.test(t)) {
      hasHeader = true;
      continue;
    }
    if (hasHeader && (/^-{20,}$/.test(t) || FINDEVIL_ROW_RE.test(t))) return true;
  }
  return false;
}

interface FindevilRow {
  pid: string;
  process: string;
  type: string;
  address: string;
  description: string;
}

function findevilSeverity(type: string, desc: string): { severity: Severity; mitre: string[] } {
  const t = type.toUpperCase();
  if (t.startsWith("YR_") || t.startsWith("YARA_")) {
    if (/hacktool/i.test(t)) return { severity: "Critical", mitre: ["T1588.002"] };
    if (/ransom/i.test(t)) return { severity: "Critical", mitre: ["T1486"] };
    if (/shellcode/i.test(t)) return { severity: "Critical", mitre: ["T1055.001"] };
    if (/malware|trojan|backdoor|rat\b|loader|dropper/i.test(t))
      return { severity: "Critical", mitre: ["T1055"] };
    return { severity: "High", mitre: ["T1027"] };
  }
  switch (t) {
    case "PEB_MASQ":
      return { severity: "High", mitre: ["T1036.005"] };
    case "PE_PATCHED":
      return { severity: "High", mitre: ["T1055"] };
    case "THREAD":
      return /system_impersonation/i.test(desc)
        ? { severity: "High", mitre: ["T1134"] }
        : { severity: "Medium", mitre: ["T1055"] };
    case "HIGH_ENTROPY":
      return { severity: "Medium", mitre: ["T1027"] };
    case "PE_NOLINK":
      return { severity: "Medium", mitre: ["T1055"] };
    case "PROC_DEBUG":
      return { severity: "Medium", mitre: ["T1055"] };
    case "PRIVATE_RWX":
      return { severity: "Medium", mitre: ["T1055", "T1620"] };
    case "DRIVER_PATH": {
      const suspicious = /\\(?:temp|tmp|users|downloads?|desktop|appdata|public)\\/i.test(desc);
      return { severity: suspicious ? "Medium" : "Low", mitre: ["T1014"] };
    }
    case "PRIVATE_RX":
      return { severity: "Info", mitre: [] };
    default:
      return { severity: "Low", mitre: [] };
  }
}

// Bulk types group by process+type (many pages → one event); signal-rich types stay individual.
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
      return `MemProcFS findevil PE_PATCHED: ${proc} (PID ${pid}) — patched PE${path ? ` ${path}` : ""}${addrNote}`.slice(
        0,
        600,
      );
    }
    case "PE_NOLINK": {
      const mod = /Module:\[([^\]]+)\]/.exec(desc)?.[1] ?? desc;
      return `MemProcFS findevil PE_NOLINK: ${proc} (PID ${pid}) — unlisted PE ${mod}${addrNote}`.slice(
        0,
        600,
      );
    }
    case "DRIVER_PATH": {
      const drv = /Driver:\[([^\]]+)\]/.exec(desc)?.[1] ?? "";
      const mod = /Module:\[([^\]]+)\]/.exec(desc)?.[1] ?? "";
      const note = drv ? ` — driver ${drv}${mod ? ` (${mod})` : ""}` : desc ? ` — ${desc}` : "";
      return `MemProcFS findevil DRIVER_PATH: ${proc} (PID ${pid})${note}`.slice(0, 600);
    }
    case "PRIVATE_RWX":
      return `MemProcFS findevil PRIVATE_RWX: ${proc} (PID ${pid}) — executable private memory (RWX)${addrNote}`.slice(
        0,
        600,
      );
    case "PRIVATE_RX":
      return `MemProcFS findevil PRIVATE_RX: ${proc} (PID ${pid}) — private executable memory${addrNote}`.slice(
        0,
        600,
      );
    case "PEB_MASQ":
      return `MemProcFS findevil PEB_MASQ: ${proc} (PID ${pid}) — PEB process name masquerading`.slice(
        0,
        600,
      );
    case "PROC_DEBUG":
      return `MemProcFS findevil PROC_DEBUG: ${proc} (PID ${pid}) — process under debugger`.slice(0, 600);
    default:
      return `MemProcFS findevil ${type}: ${proc} (PID ${pid})${desc ? ` — ${oneLine(desc).slice(0, 200)}` : ""}${addrNote}`.slice(
        0,
        600,
      );
  }
}

function parseFindevilRows(text: string): FindevilRow[] {
  const rows: FindevilRow[] = [];
  let pastHeader = false;
  for (const line of text.split(/\r\n|\r|\n/)) {
    const t = line.trim();
    if (!pastHeader) {
      if (FINDEVIL_HEADER_RE.test(t)) {
        pastHeader = true;
      }
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
      pathIoc =
        /VAD:\[([^\]]+)\]/.exec(description)?.[1] ?? /Module:\[([^\]]+)\]/.exec(description)?.[1] ?? "";
    } else if (t === "PE_PATCHED") {
      pathIoc = /([A-Za-z]:\\[^\s]+|\\[^\s]+\.(?:dll|exe|sys))\s*$/.exec(description)?.[1] ?? "";
    }
    addIoc(sink, "file", filePathIoc(pathIoc));

    out.push({
      timestamp: "",
      description: findevilEventDesc(type, process, pid, description, address),
      severity,
      mitre,
      aggKey: findevilAggKey(type, pid, process, description),
      sources: ["MemProcFS"],
      ...(pName ? { processName: pName } : {}),
      ...(filePathIoc(pathIoc) ? { path: pathIoc } : {}),
    });
  }
  return out;
}

function parseMemoryFindevil(text: string, opts: MemoryImportOptions): MemoryParseResult {
  const rows = parseFindevilRows(text);
  const empty: MemoryParseResult = {
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
    format: "memprocfs-findevil",
    tool: "MemProcFS",
  };
  if (!rows.length) return empty;

  const sink = new Map<string, SiemIoc>();
  const mapped = mapFindevil(rows, sink);

  const { events, groups } = aggregateEvents(mapped, {
    aggregate: opts.aggregate,
    minSeverity: opts.minSeverity,
    maxEvents: opts.maxEvents ?? maxEventsDefault(),
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
// findevil.csv (PID,ProcessName,Type,Address,Description — the same findevil.txt finding set as
// clean CSV, parsed into FindevilRow and reusing mapFindevil/severity/aggKey) and yara.csv
// (MatchIndex,Tags,Description,RuleAuthor,RuleVersion,MemoryType,MemoryTag,MemoryBaseAddress,
// ObjectAddress,PID,ProcessName,ProcessPath,CommandLine,User,Created,AddressCount,String0,
// Address0,… — YARA scan results with process + mapping context; severity/MITRE come from the
// matched rule's own Tags, mapping validity from MemoryType/MemoryTag, see memoryYaraMappingContext.ts, #1148).

// Lightweight first-line check (no full CSV parse): split on comma, normalise header names.
function csvCols(text: string): Set<string> {
  const first = text.trim().split(/\r\n|\r|\n/, 1)[0] ?? "";
  return new Set(first.split(",").map((c) => c.trim().replace(/['"]/g, "").toLowerCase()));
}

function parseMemoryFindevilCsv(text: string, opts: MemoryImportOptions): MemoryParseResult {
  const empty: MemoryParseResult = {
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
    format: "memprocfs-findevil-csv",
    tool: "MemProcFS",
  };
  const { headers, rows } = parseCsv(text);
  if (!headers.length || !rows.length) return empty;

  const col = (name: string): number => headers.findIndex((h) => h.toLowerCase() === name.toLowerCase());
  const pidI = col("PID");
  const procI = col("ProcessName");
  const typeI = col("Type");
  const addrI = col("Address");
  const descI = col("Description");

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
    aggregate: opts.aggregate,
    minSeverity: opts.minSeverity,
    maxEvents: opts.maxEvents ?? maxEventsDefault(),
  });
  const maxIocs = opts.maxIocs ?? 5000;
  const represented = events.reduce((n, e) => n + (e.count ?? 1), 0);
  return {
    events,
    iocs: [...sink.values()].slice(0, maxIocs),
    total: findevilRows.length,
    kept: events.length,
    dropped: Math.max(0, findevilRows.length - represented),
    groups,
    tables: 1,
    injected: findevilRows.filter((r) => /^(YR_|YARA_)/i.test(r.type)).length,
    processes: 0,
    connections: 0,
    format: "memprocfs-findevil-csv",
    tool: "MemProcFS",
  };
}

function parseMemoryYaraCsv(text: string, opts: MemoryImportOptions): MemoryParseResult {
  const empty: MemoryParseResult = {
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
    format: "memprocfs-yara-csv",
    tool: "MemProcFS",
  };
  const { headers, rows } = parseCsv(text);
  if (!headers.length || !rows.length) return empty;

  const col = (name: string): number => headers.findIndex((h) => h.toLowerCase() === name.toLowerCase());
  const matchIndexI = col("MatchIndex");
  const tagsI = col("Tags");
  const pidI = col("PID");
  const procI = col("ProcessName");
  const procPathI = col("ProcessPath");
  const cmdI = col("CommandLine");
  const createdI = col("Created");
  const memTypeI = col("MemoryType");
  const memTagI = col("MemoryTag");
  const baseAddrI = col("MemoryBaseAddress");
  const objAddrI = col("ObjectAddress");

  const sink = new Map<string, SiemIoc>();
  const mapped: MappedEvent[] = [];

  for (const row of rows) {
    const matchIndex = row[matchIndexI] ?? "";
    const rawTags = row[tagsI] ?? "";
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
    addIoc(sink, "file", filePathIoc(procPath));

    const timestamp = normalizeTime(created) ?? "";
    const mapping = yaraMappingContext(memType, memTag);
    // No PID/ProcessName lead when there's no process context — MemProcFS leaves them empty (#1148).
    const lead =
      mapping.mappingClass === "process-user-mode" || mapping.mappingClass === "process-kernel-mode"
        ? `MemProcFS YARA: ${proc} (PID ${pid})`
        : "MemProcFS YARA match";
    const addrNote = baseAddr ? ` @ base 0x${baseAddr}` : "";
    const objNote = objAddr ? ` (obj 0x${objAddr})` : "";
    const cmdNote = cmd ? ` — cmd: ${oneLine(cmd).slice(0, 120)}` : "";
    const description = `${lead} — ${mapping.note}${addrNote}${objNote}${cmdNote}`.slice(0, 600);

    // Severity/MITRE come from the matched RULE, never from where it was found (#1148, reuses yaraImport.ts).
    const tags = rawTags ? [rawTags] : [];
    // Physical/Object rows have no real address — MatchIndex is the only discriminator left.
    const identity =
      mapping.mappingClass === "no-process-context" || mapping.mappingClass === "unrecognized"
        ? matchIndex
        : baseAddr || objAddr;
    mapped.push({
      timestamp,
      description,
      severity: severityFromMeta({}),
      mitre: mitreFromYara(tags, {}),
      aggKey: boundedAggKey(`memprocfs|yara|${pid}|${proc.toLowerCase()}|${mapping.mappingClass}|${identity}`),
      sources: ["MemProcFS"],
      ...(pName ? { processName: pName } : {}),
    });
  }

  const { events, groups } = aggregateEvents(mapped, {
    aggregate: opts.aggregate,
    minSeverity: opts.minSeverity,
    maxEvents: opts.maxEvents ?? maxEventsDefault(),
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
    injected: rows.length,
    processes: 0,
    connections: 0,
    format: "memprocfs-yara-csv",
    tool: "MemProcFS",
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
  type: string,
  action: string,
  pid: string,
  txt: string,
  ts: string,
  sink: Map<string, SiemIoc>,
  mapped: MappedEvent[],
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
      addIoc(sink, "file", filePathIoc(cleanPath));
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
        ...(filePathIoc(cleanPath) ? { path: cleanPath } : {}),
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
      const taskName = (m?.[1] ?? txt).trim().slice(0, 100);
      const cmd = (m?.[2] ?? "").split("::")[0].trim().slice(0, 150);
      const user = m?.[3]?.trim() ?? "";
      let severity: Severity;
      let mitre: string[];
      let verb: string;
      if (a === "CRE") {
        severity = "Medium";
        mitre = ["T1053.005"];
        verb = "created";
      } else if (a === "DEL") {
        severity = "Medium";
        mitre = ["T1070"];
        verb = "deleted";
      } else {
        severity = "Low";
        mitre = ["T1053.005"];
        verb = "modified";
      }
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
      } catch {
        /* malformed URL */
      }
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
    format: "memprocfs-timeline",
    tool: "MemProcFS",
  };
  const { headers, rows } = parseCsv(text);
  if (!headers.length || !rows.length) return empty;

  const idx = (name: string): number => headers.findIndex((h) => h.toLowerCase() === name);
  const timeI = idx("time");
  const typeI = idx("type");
  const actionI = idx("action");
  const pidI = idx("pid");
  const textI = idx("text");
  if (typeI < 0 || actionI < 0) return empty;

  const sink = new Map<string, SiemIoc>();
  const mapped: MappedEvent[] = [];
  let procCount = 0,
    netCount = 0;

  for (const row of rows) {
    const type = row[typeI]?.trim() ?? "";
    const action = row[actionI]?.trim() ?? "";
    const pid = (pidI >= 0 ? row[pidI] : undefined)?.trim() ?? "0";
    const txt = (textI >= 0 ? row[textI] : undefined)?.trim() ?? "";
    const ts = normalizeTime((timeI >= 0 ? row[timeI] : undefined)?.trim() ?? "") ?? "";
    const before = mapped.length;
    mapMpfsTimelineRow(type, action, pid, txt, ts, sink, mapped);
    if (mapped.length > before) {
      if (type === "PROC") procCount++;
      if (type === "Net") netCount++;
    }
  }

  const { events, groups } = aggregateEvents(mapped, {
    aggregate: opts.aggregate,
    minSeverity: opts.minSeverity,
    maxEvents: opts.maxEvents ?? maxEventsDefault(),
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
    injected: 0,
    processes: procCount,
    connections: netCount,
    format: "memprocfs-timeline",
    tool: "MemProcFS",
  };
}

// ───────────────────────────── top-level parse ─────────────────────────────

/** The parsed JSON root when the upload is a run envelope or a bundle of them; undefined otherwise. */
function runEnvelopeRoot(text: string): unknown {
  const t = text.trim();
  if (!t.startsWith("{") || !t.includes("dfir.volatility-run")) return undefined;
  try {
    const root: unknown = JSON.parse(t);
    return isRunEnvelopeUpload(root) ? root : undefined;
  } catch {
    return undefined;
  }
}

/** Every run's export imports as the export it is; the run rows ride beside, under the same cap. */
function parseMemoryRunBundle(root: unknown, text: string, opts: MemoryImportOptions): MemoryParseResult {
  const maxEvents = opts.maxEvents ?? maxEventsDefault();
  // The PLAIN parser reads each embedded export: an envelope nested in an envelope is not an export.
  const { runRows, exports, note } = parseRunEnvelopes(root, (stdout, filename) =>
    parseMemoryExport(stdout, { ...opts, filename, maxEvents }),
  );
  // One bundle-wide budget: every row is ranked by severity and cut to `maxEvents` once (never N ×).
  const runs = aggregateEvents(runRows, {
    aggregate: opts.aggregate,
    minSeverity: opts.minSeverity,
    maxEvents,
  });
  const groups = runs.groups + exports.reduce((n, e) => n + e.groups, 0);
  const rank: Record<Severity, number> = { Critical: 4, High: 3, Medium: 2, Low: 1, Info: 0 };
  const ranked = [...runs.events, ...exports.flatMap((e) => e.events)]
    .sort((a, b) => rank[b.severity] - rank[a.severity] || (b.count ?? 1) - (a.count ?? 1))
    .slice(0, maxEvents);
  const finalEvents = stampSourceArtifactHash(ranked, text);
  const sum = (k: "total" | "tables") => exports.reduce((n, e) => n + e[k], 0);
  const total = sum("total") + runRows.length;
  const represented = finalEvents.reduce((n, e) => n + (e.count ?? 1), 0);
  const notes = [
    ...exports.map((e) => ("note" in e ? (e as MemoryParseResult).note : "")).filter(Boolean),
    note,
  ].filter(Boolean);
  return {
    events: finalEvents,
    iocs: exports.flatMap((e) => e.iocs).slice(0, opts.maxIocs ?? 5000),
    total,
    kept: finalEvents.length,
    dropped: Math.max(0, total - represented),
    groups,
    tables: sum("tables"),
    injected: exports.reduce((n, e) => n + ((e as MemoryParseResult).injected ?? 0), 0),
    processes: exports.reduce((n, e) => n + ((e as MemoryParseResult).processes ?? 0), 0),
    connections: exports.reduce((n, e) => n + ((e as MemoryParseResult).connections ?? 0), 0),
    format: "volatility-run-envelope",
    tool: "Volatility",
    ...(notes.length ? { note: notes.join("; ") } : {}),
  };
}

export function parseMemory(text: string, opts: MemoryImportOptions = {}): MemoryParseResult {
  // A run envelope (#1016): the runs' embedded exports import as exports, one run row each.
  const envelope = runEnvelopeRoot(text);
  if (envelope !== undefined) return parseMemoryRunBundle(envelope, text, opts);
  return parseMemoryExport(text, opts);
}

/** Every memory export format EXCEPT a run envelope — the parser an envelope's embedded stdout goes through. */
function parseMemoryExport(text: string, opts: MemoryImportOptions): MemoryParseResult {
  // MemProcFS findevil: a flat finding-report table — check before JSON/text Volatility paths.
  if (looksLikeMemprocfsFindevil(text)) return parseMemoryFindevil(text, opts);

  // MemProcFS CSV variants, by distinctive header columns — timeline_all.csv's value32/value64 are unique.
  const cols = csvCols(text);
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
  const { tables, format, tool, empty } = extractTables(text, opts.filename);
  const total = tables.reduce((n, t) => n + t.rows.length, 0);
  // What the export's shape says — a zero-row/unread export is one Low row, never 400 (#933 item 12).
  const shapeRows = exportShapeEvents(format, empty, tool);
  const note = exportShapeNote(text, format, empty, tables.length);
  if (total === 0 && shapeRows.length === 0) {
    return {
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
      format,
      tool: "",
      ...(note ? { note } : {}),
    };
  }

  const sink = new Map<string, SiemIoc>();
  const mapped: MappedEvent[] = [...shapeRows];
  let injected = 0,
    processes = 0,
    connections = 0;

  // Process rows the upload submitted, by PID — malfind/socket/handle owner checks (#909 item 4, #933 items 13-14).
  const processIndex = indexProcessRows(
    tables.filter((t) => classify(t.plugin, colSet(t.rows)) === "process"),
  );
  const corroborating = { network: new Set<string>(), suspiciousCmd: new Set<string>() };
  for (const t of tables) {
    const cat = classify(t.plugin, colSet(t.rows));
    if (cat === "netscan" && tool !== "Rekall") {
      for (const r of t.rows) {
        const { tuple, owner, pid, created } = socketFields(r);
        const shape = tupleShape(tuple);
        const consistent = ownerConsistency(pid, owner, created, processIndex).consistent;
        if (pid && shape.ok && shape.peer && !readState(tuple.state, tuple.proto).listening && consistent) {
          corroborating.network.add(pid);
        }
      }
    } else if (cat === "cmdline") {
      for (const r of t.rows) {
        const pid = pickPid(r);
        if (
          pid &&
          isSuspiciousCmd(
            pick(r, ["Process", "ImageFileName", "Name"]),
            pick(r, ["Args", "CommandLine", "args", "cmd"]),
          )
        )
          corroborating.suspiciousCmd.add(pid);
      }
    }
  }

  // Process records with BOTH a start and an exit — only a memory image records both (#909 item 6).
  const lifetimeRecords: ProcessRecord[] = [];

  // Handle-table rows (#933 item 13), resolved once against the processIndex built above.
  const handleRows: Record<string, unknown>[] = [];

  for (const t of tables) {
    const cols = colSet(t.rows);
    // An image-facts table is decided by its own fields, never by a label (memoryImageFacts.ts).
    const category: Category = isImageInfoTable(t.plugin, cols, t.rows)
      ? "imageinfo"
      : classify(t.plugin, cols);
    if (category === "process") {
      for (const r of t.rows) {
        const nm = procName(r);
        if (!nm) continue;
        lifetimeRecords.push({
          image: pick(r, ["Path", "path"]) || nm,
          name: baseName(nm).toLowerCase(),
          pid: pickPid(r),
          ppid: pick(r, ["PPID", "ppid"]),
          parentName: "",
          start: pickTime(r, ["CreateTime", "process_create_time", "CreatedTime", "start_time"]),
          exit: pickTime(r, ["ExitTime", "process_exit_time"]),
          commandLine: pick(r, ["Cmd", "CommandLine", "Args"]),
          commandLineCaptured: true,
        });
      }
    }
    const label = displayLabel(t.plugin, category, t.rows);
    switch (category) {
      case "process":
        mapped.push(...mapProcess(label, tool, t.rows, sink));
        processes += t.rows.length;
        break;
      case "netscan":
        mapped.push(...mapNetscan(t.plugin, label, tool, t.rows, sink, processIndex));
        connections += t.rows.length;
        break;
      case "malfind":
        mapped.push(...mapMalfind(label, tool, t.rows, sink, corroborating));
        injected += t.rows.length;
        break;
      case "cmdline":
        mapped.push(...mapCmdline(label, tool, t.rows, sink));
        break;
      case "service":
        mapped.push(...mapService(label, tool, t.rows, sink));
        break;
      case "module":
        mapped.push(...mapModule(label, tool, t.rows, sink));
        break;
      case "dll":
        mapped.push(...mapDll(label, tool, t.rows, sink, !!opts.dllTelemetry));
        break;
      case "handle":
        for (const r of t.rows) handleRows.push(r); // never spread — a large table exceeds arg limits
        break;
      case "imageinfo":
        mapped.push(...imageFactsEvents(tool, t.rows, t.plugin)); // one row, no IOCs
        break;
      default:
        mapped.push(...mapGeneric(label, tool, t.rows, sink));
    }
  }

  // Repeated short-lived executions of one image (#909 item 6): ONE event per image, not per run.
  for (const cluster of repeatedShortLifetimes(lifetimeRecords)) {
    mapped.push({
      timestamp: "",
      description: `${tool}: ${cluster.note}`.slice(0, 600),
      severity: cluster.severity,
      mitre: [],
      aggKey: `mem|repeat|${cluster.name}`,
      sources: [tool],
      processName: cluster.name,
    });
  }

  const handleResult = handleOwnershipFacts(handleRows, processIndex); // #933 item 13, Info severity
  for (const fact of handleResult.facts) {
    mapped.push({
      timestamp: "",
      description: `${tool}: ${fact.note}`.slice(0, 600),
      severity: "Info",
      mitre: [],
      aggKey: boundedAggKey(`mem|handle|${fact.kind}|${fact.pid}|${fact.type}|${fact.name}`),
      sources: [tool],
      processName: fact.holderProcess || undefined,
    });
  }

  // The upload's image facts ride on every row (envelope; text from Medium up). One upload only.
  const { events, groups } = aggregateEvents(carryImage(mapped, readImageFacts(tables)), {
    aggregate: opts.aggregate,
    minSeverity: opts.minSeverity,
    maxEvents: opts.maxEvents ?? maxEventsDefault(),
  });
  const finalEvents = stampSourceArtifactHash(events, text);

  const represented = finalEvents.reduce((n, e) => n + (e.count ?? 1), 0);
  // A capped fact family is a sample, not the full set — disclose it, don't just track it internally.
  const handleNote = handleResult.truncated
    ? "handle-ownership analysis reached its own evidence cap — some facts were not reported."
    : "";
  const finalNote = [note, handleNote].filter(Boolean).join(" ");
  return {
    events: finalEvents,
    iocs: [...sink.values()].slice(0, maxIocs),
    total,
    kept: finalEvents.length,
    dropped: Math.max(0, total - represented),
    groups,
    tables: tables.length,
    injected,
    processes,
    connections,
    format,
    tool,
    ...(finalNote ? { note: finalNote } : {}),
  };
}
