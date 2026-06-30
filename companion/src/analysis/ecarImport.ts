// Deterministic importer for ECAR — the "EDR Common Activity Record" telemetry schema (the EDR
// agent feed in the EvidenceForge scenarios; one NDJSON object per endpoint event). ECAR is a
// Sysmon-style activity model: every record is an (object, action) pair on a host at `timestamp_ms`
// (epoch milliseconds), with the rich detail in a nested `properties` bag:
//
//   { "timestamp_ms": 1715688049745, "hostname": "WEB-BO-01", "object": "PROCESS", "action": "CREATE",
//     "pid": …, "ppid": …, "principal": "SYSTEM",
//     "properties": { "command_line": "…", "image_path": "…", "parent_image_path": "…",
//                     "src_ip": "…", "dst_ip": "…", "registry_key": "…", "file_path": "…", … } }
//
// The generic SIEM importer can't read this: ECAR's time field is `timestamp_ms` (not @timestamp), and
// the meaningful content lives in `object`/`action`/`properties` rather than a flat `message` — so a
// generic pass produces undated "SIEM event: CONNECT @ host" rows and throws away the real tradecraft
// (the attacker's process command lines live in PROCESS/CREATE records). This dedicated mapper reads
// `timestamp_ms`, classifies each (object, action) into the right forensic-event kind, and pulls the
// matching `properties` into a real description + IOCs.
//
// SEVERITY is conservative by design (ECAR is high-volume raw telemetry, not a detection feed — see the
// project's "post-detection analysis layer, not a detection engine" principle): almost everything is
// Info evidence. We bump ONLY on genuine tradecraft signal — a suspicious process command line
// (`isSuspiciousCmd`) and cross-process remote-thread injection (T1055). Critically, PROCESS/OPEN
// targeting lsass.exe is left at Info, NOT auto-graded Critical: benign processes (Windows Defender's
// MsMpEng.exe) open lsass constantly, so a deterministic "lsass access ⇒ credential dumping" rule is a
// false-positive factory. The evidence is preserved (target + granted_access in the description) for a
// detection tool / synthesis to judge.
//
// Pure, deterministic, NO AI call. Reuses siemImport's aggregation + IOC helpers so an ECAR import
// aggregates, sorts, and caps identically to every other deterministic importer.

import type { Severity } from "./stateTypes.js";
import {
  extractRecords,
  aggregateEvents,
  addIoc,
  cleanIp,
  isSuspiciousCmd,
  baseName,
  oneLine,
  str,
  type MappedEvent,
  type SiemEvent,
  type SiemIoc,
  type SiemParseResult,
} from "./siemImport.js";
import { reconTechniques } from "./reconTechniques.js";
import { tradecraftSignal } from "./tradecraftRules.js";

type Row = Record<string, unknown>;

export interface EcarImportOptions {
  aggregate?: boolean;   // collapse repetitive identical events into one counted row. Default true.
  minSeverity?: Severity; // drop events below this floor. Default undefined = keep everything.
  maxEvents?: number;    // safety cap on emitted events (most-severe first). Default 2000.
  maxIocs?: number;      // safety cap on emitted IOCs. Default 5000.
}

export type EcarParseResult = SiemParseResult;

// The source label every ECAR-derived event/IOC carries (the tool name, via toolDetect's corroboration).
export const ECAR_SOURCE = "EDR (ECAR)";

// ───────────────────────────── value helpers ─────────────────────────────

// A record's `properties` bag as a plain object (ECAR nests all the detail here). Missing/non-object ⇒ {}.
function props(rec: Row): Row {
  const p = rec["properties"];
  return p && typeof p === "object" && !Array.isArray(p) ? (p as Row) : {};
}

// A property value as a trimmed string ("" when absent). ECAR uses "-" as a null placeholder (e.g.
// src_ip on a local logon) — treat that as empty too.
function prop(p: Row, key: string): string {
  const v = oneLine(str(p[key]));
  return v === "-" ? "" : v;
}

// Is this an RFC1918 / loopback / link-local / CGNAT address? Such IPs are internal infrastructure, not
// indicators — only PUBLIC IPs become IOCs (mirrors the network importer's signal-first stance and keeps
// the IOC list from exploding with every internal flow). Non-IPv4 strings are treated as non-private.
function isPrivateIp(ip: string): boolean {
  const m = ip.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (!m) return false;
  const [a, b] = [Number(m[1]), Number(m[2])];
  if (a === 10 || a === 127 || a === 0) return true;
  if (a === 192 && b === 168) return true;
  if (a === 172 && b >= 16 && b <= 31) return true;
  if (a === 169 && b === 254) return true; // link-local
  if (a === 100 && b >= 64 && b <= 127) return true; // CGNAT 100.64/10
  return false;
}

// Record any PUBLIC IP among the given raw values as an `ip` IOC (cleaned of IPv4-mapped IPv6 / loopback).
function iocPublicIps(sink: Map<string, SiemIoc>, ...raw: string[]): void {
  for (const r of raw) {
    const ip = cleanIp(r);
    if (ip && !isPrivateIp(ip)) addIoc(sink, "ip", ip);
  }
}

// Port as a number when sane (1..65535), else undefined — so the structured `port` field stays clean.
function portNum(raw: string): number | undefined {
  const n = Number(raw);
  return Number.isInteger(n) && n > 0 && n <= 65535 ? n : undefined;
}

// ───────────────────────────── per-record mapping ─────────────────────────────

// Map one ECAR record to a forensic event (collecting IOCs in `sink`), or null to drop it. The (object,
// action) pair selects the mapper; `properties` supplies the detail. Severity stays Info unless real
// tradecraft signal is present (see the module header for the lsass-access rationale).
export function mapEcarRecord(rec: Row, sink: Map<string, SiemIoc>): MappedEvent | null {
  const tsMs = Number(rec["timestamp_ms"]);
  const timestamp = Number.isFinite(tsMs) && tsMs > 0 ? new Date(tsMs).toISOString() : "";
  const host = oneLine(str(rec["hostname"]));
  const object = oneLine(str(rec["object"])).toUpperCase();
  const action = oneLine(str(rec["action"])).toUpperCase();
  const p = props(rec);
  const at = host ? ` @ ${host}` : "";

  const base = {
    timestamp,
    severity: "Info" as Severity,
    mitre: [] as string[],
    ...(host ? { asset: host } : {}),
    sources: [ECAR_SOURCE],
  };

  switch (`${object}/${action}`) {
    case "PROCESS/CREATE": {
      const image = prop(p, "image_path");
      const cmd = prop(p, "command_line");
      const parent = prop(p, "parent_image_path");
      const procName = baseName(image) || baseName(cmd);
      const parentName = baseName(parent);
      const grade = isSuspiciousCmd(image, cmd);
      const tc = tradecraftSignal(image, cmd);
      const strong = grade === "strong" || tc?.weight === "strong";
      const flagged = Boolean(grade) || Boolean(tc);
      const severity: Severity = strong ? "High" : flagged ? "Medium" : "Info";
      const desc = `Process created: ${cmd || image || "(unknown)"}` +
        (parentName ? ` (parent ${parentName})` : "") + at;
      if (flagged) addIoc(sink, "process", procName || image);
      // The created-process pid — the cross-tool correlation key (matches Windows 4688 NewProcessId /
      // Sysmon EID 1 ProcessId on the same host), so an ECAR create merges with its Windows-log twin.
      const pidNum = Number(rec["pid"]);
      const pid = Number.isInteger(pidNum) && pidNum > 0 ? pidNum : undefined;
      // Discovery / credential-access recon tagging (whoami, net group /domain, find -name *.env,
      // cat .env, …) plus deterministic tradecraft techniques (Defender-disable, tunneling, exfil…)
      // so the enumeration/tradecraft phase is identified even when each command stays Info.
      const mitre = [...new Set([...(flagged ? ["T1059"] : []), ...(tc?.mitre ?? []), ...reconTechniques(image, cmd)])];
      return {
        ...base, severity,
        mitre,
        description: desc,
        // pid is in the key so distinct executions stay distinct rows (not aggregated away) — that's
        // both better forensics and what lets each creation correlate with its Windows-log twin by pid.
        aggKey: `ecar|proc|${host}|${pid ?? ""}|${image}|${cmd}`,
        ...(procName ? { processName: procName } : {}),
        ...(parentName ? { parentName } : {}),
        ...(pid !== undefined ? { pid } : {}),
      };
    }

    case "PROCESS/OPEN": {
      // Process-access (handle open). Kept Info even when the target is lsass — benign processes open
      // lsass routinely; promoting it deterministically is a credential-dumping false positive (the
      // very FP this importer was written to avoid). Evidence is preserved for synthesis to weigh.
      const image = prop(p, "image_path");
      const target = prop(p, "target_image_path");
      const access = prop(p, "granted_access");
      const procName = baseName(image);
      const desc = `Process access: ${procName || "(unknown)"} opened ${baseName(target) || target || "(unknown)"}` +
        (access ? ` (granted_access ${access})` : "") + at;
      return {
        ...base,
        description: desc,
        aggKey: `ecar|popen|${host}|${image}|${target}|${access}`,
        ...(procName ? { processName: procName } : {}),
      };
    }

    case "PROCESS/TERMINATE": {
      const procName = baseName(prop(p, "image_path"));
      return {
        ...base,
        description: `Process terminated: ${procName || prop(p, "command_line") || "(unknown)"}${at}`,
        aggKey: `ecar|pterm|${host}|${procName}`,
        ...(procName ? { processName: procName } : {}),
      };
    }

    case "THREAD/REMOTE_CREATE": {
      // A thread created in ANOTHER process CAN be process-injection tradecraft (T1055) — but it is also
      // constant benign behaviour on Windows (Defender's MsMpEng, services.exe, WmiPrvSE, dllhost all do
      // it routinely). A deterministic importer can't tell malicious from legitimate, so — like the
      // lsass-access guard above — this stays Info evidence (the description flags the injection angle
      // for an analyst/detection tool to weigh) rather than minting a Medium false positive per host.
      const image = baseName(prop(p, "image_path"));
      return {
        ...base,
        description: `Remote thread created by ${image || "(unknown)"} into pid ${prop(p, "target_pid") || "?"}` +
          ` — possible process injection (T1055)${at}`,
        aggKey: `ecar|rthread|${host}|${image}|${prop(p, "target_pid")}`,
        ...(image ? { processName: image } : {}),
      };
    }

    case "FLOW/CONNECT": {
      const srcIp = cleanIp(prop(p, "src_ip"));
      const dstIp = cleanIp(prop(p, "dst_ip"));
      const srcPort = prop(p, "src_port");
      const dstPort = prop(p, "dst_port");
      const proto = prop(p, "protocol").toLowerCase();
      const direction = prop(p, "direction").toLowerCase();
      const external = (srcIp && !isPrivateIp(srcIp)) || (dstIp && !isPrivateIp(dstIp));
      iocPublicIps(sink, srcIp, dstIp);
      const desc = `${direction || "network"} ${proto || "tcp"} ${srcIp || "?"}` +
        (srcPort ? `:${srcPort}` : "") + ` → ${dstIp || "?"}` + (dstPort ? `:${dstPort}` : "") + at;
      return {
        ...base,
        // An external flow is a marginally stronger lead than purely internal chatter, but still just
        // telemetry — Low at most, so it never alone mints a finding.
        severity: external ? "Low" : "Info",
        description: desc,
        aggKey: `ecar|flow|${host}|${direction}|${proto}|${dstIp}:${dstPort}`,
        ...(srcIp ? { srcIp } : {}),
        ...(dstIp ? { dstIp } : {}),
        ...(portNum(dstPort) ? { port: portNum(dstPort) } : {}),
      };
    }

    case "USER_SESSION/LOGIN": {
      const srcIp = cleanIp(prop(p, "src_ip"));
      const outcome = prop(p, "outcome").toLowerCase();
      const logonType = prop(p, "logon_type");
      const failed = outcome === "failure" || outcome === "fail" || !!prop(p, "failure_reason");
      iocPublicIps(sink, srcIp);
      const desc = `Logon ${failed ? "FAILED" : "success"}` +
        (logonType ? ` (type ${logonType})` : "") + (srcIp ? ` from ${srcIp}` : "") +
        (failed && prop(p, "failure_reason") ? ` — ${prop(p, "failure_reason")}` : "") + at;
      return {
        ...base,
        // Failed logons cluster (brute force / password spray) — Low so the aggregated count surfaces
        // without each attempt minting a finding. A genuine spray is caught by the count + synthesis.
        severity: failed ? "Low" : "Info",
        description: desc,
        aggKey: `ecar|login|${host}|${failed ? "fail" : "ok"}|${logonType}|${srcIp}`,
        ...(srcIp ? { srcIp } : {}),
      };
    }

    case "USER_SESSION/LOGOUT":
      return {
        ...base,
        description: `Logoff${prop(p, "logon_type") ? ` (type ${prop(p, "logon_type")})` : ""}${at}`,
        aggKey: `ecar|logout|${host}|${prop(p, "logon_type")}`,
      };

    case "REGISTRY/MODIFY": {
      const key = prop(p, "registry_key");
      const value = prop(p, "registry_value");
      return {
        ...base,
        description: `Registry set: ${key || "(unknown key)"}${value ? ` = ${value}` : ""}${at}`,
        aggKey: `ecar|reg|${host}|${key}`,
      };
    }

    case "MODULE/LOAD": {
      const image = prop(p, "image_path");
      const name = baseName(image);
      return {
        ...base,
        description: `Module loaded: ${name || image || "(unknown)"}${at}`,
        aggKey: `ecar|mod|${host}|${image}`,
      };
    }

    case "FILE/CREATE":
    case "FILE/WRITE":
    case "FILE/READ": {
      const file = prop(p, "file_path");
      const verb = action === "CREATE" ? "created" : action === "WRITE" ? "written" : "read";
      return {
        ...base,
        description: `File ${verb}: ${file || "(unknown)"}${at}`,
        aggKey: `ecar|file|${action}|${host}|${file}`,
        ...(file ? { path: file } : {}),
      };
    }

    default: {
      // Unknown (object, action) — keep it as dated evidence rather than dropping, so nothing silently
      // vanishes; the description carries the raw pair for the analyst.
      if (!object && !action) return null;
      const detail = prop(p, "command_line") || prop(p, "image_path") || prop(p, "file_path");
      return {
        ...base,
        description: `${object || "EVENT"} ${action || ""}`.trim() + (detail ? `: ${detail}` : "") + at,
        aggKey: `ecar|other|${host}|${object}/${action}|${detail}`,
      };
    }
  }
}

// Is this NDJSON/array of records ECAR? The signature is the (timestamp_ms + object + action) triple —
// distinctive to the ECAR schema and absent from the other JSON feeds. Pure; used by importDetect.
export function isEcarRecord(rec: unknown): boolean {
  if (!rec || typeof rec !== "object" || Array.isArray(rec)) return false;
  const r = rec as Row;
  return "timestamp_ms" in r && typeof r["object"] === "string" && typeof r["action"] === "string";
}

// Parse an ECAR NDJSON / JSON-array export into the shared SIEM result shape (aggregated + capped events
// + IOCs). Mirrors parseVelociraptorJson: unwrap the container, map each record, aggregate, cap. Pure.
export function parseEcarJson(text: string, opts: EcarImportOptions = {}): EcarParseResult {
  const { records, format } = extractRecords(text);
  const maxIocs = opts.maxIocs ?? 5000;

  const sink = new Map<string, SiemIoc>();
  const hostTally = new Map<string, number>();
  const mapped: MappedEvent[] = [];

  for (const rec of records) {
    if (!rec || typeof rec !== "object") continue;
    const r = rec as Row;
    const host = oneLine(str(r["hostname"]));
    if (host) hostTally.set(host, (hostTally.get(host) ?? 0) + 1);
    const m = mapEcarRecord(r, sink);
    if (m) mapped.push(m);
  }

  const { events, groups } = aggregateEvents(mapped, {
    aggregate: opts.aggregate,
    minSeverity: opts.minSeverity,
    maxEvents: opts.maxEvents ?? 2000,
  });

  const represented = events.reduce((n, e) => n + (e.count ?? 1), 0);
  const hostname = [...hostTally.entries()].sort((a, b) => b[1] - a[1])[0]?.[0] ?? "";

  return {
    events,
    iocs: [...sink.values()].slice(0, maxIocs),
    total: records.length,
    kept: events.length,
    dropped: Math.max(0, records.length - represented),
    groups,
    format,
    hostname,
  };
}
