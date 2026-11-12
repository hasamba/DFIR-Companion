// Per-row mapping for the CrowdStrike Falcon sensor importer (#2592). One Falcon row — an
// Event Search / LogScale / Next-Gen SIEM export (`#event_simpleName`) or an FDR record
// (`event_simpleName`) — becomes one forensic event with a readable description, its IOCs and a
// canonical envelope. crowdstrikeImport.ts reads the file, dates the rows and aggregates.
//
// SEVERITY: raw sensor telemetry is Info. Two exceptions, both deliberate:
//   - A process row runs through the SAME shared tradecraft checks the ECAR and osquery importers use
//     (isSuspiciousCmd, tradecraftSignal, secretSpillSignal). The parser caps an import at
//     DFIR_MAX_EVENTS groups, so an all-Info export with more distinct groups than that would lose
//     the one malicious row before the route tagger ever saw it. Grading it here keeps it.
//   - A detection row (DetectionSummaryEvent / EppDetectionSummaryEvent) keeps Falcon's own verdict,
//     mapped 1:1. Turning a vendor High into Info would hide it from the forensic timeline.
// Everything else is left to the deterministic tagger at the route seam (merge → tagger → demote).

import type { Severity } from "./stateTypes.js";
import { addIoc, type SiemIoc } from "./iocSink.js";
import { cleanIp, isSuspiciousCmd, baseName, type MappedEvent } from "./siemImport.js";
import { CROWDSTRIKE_SOURCE, field, eventName, portNum } from "./crowdstrikeFields.js";
import { isInternalIpv4 } from "./internalIp.js";
import { boundedAggKey, boundedTextTo } from "./aggKey.js";
import { reconTechniques } from "./reconTechniques.js";
import { tradecraftSignal } from "./tradecraftRules.js";
import { secretSpillSignal } from "./secretSpillRules.js";
import { crowdstrikeCanonical } from "./crowdstrikeCanonical.js";

type Row = Record<string, unknown>;

export { CROWDSTRIKE_SOURCE };

// Keys that are row metadata, not event content: left out of the unknown-event key=value summary.
const META_KEYS = new Set([
  "#event_simpleName",
  "event_simpleName",
  "aid",
  "aip",
  "cid",
  "ComputerName",
  "ContextTimeStamp",
  "timestamp",
  "@timestamp",
  "_time",
  "name",
  "id",
  "event_platform",
  "#event_platform",
  "ConfigBuild",
  "ConfigStateHash",
  "EffectiveTransmissionClass",
  "Entitlements",
]);
const UNKNOWN_SUMMARY_MAX = 600;

// A public address: cleanIp drops loopback/unspecified; IPv4 private ranges and IPv6 unique-local /
// link-local are internal. Only a public address is an indicator.
function publicIp(raw: string): string {
  const ip = cleanIp(raw);
  if (!ip) return "";
  if (ip.includes(":")) return /^(?:f[cd]|fe[89ab])/i.test(ip) ? "" : ip;
  return isInternalIpv4(ip) ? "" : ip;
}

function pidNum(raw: string): number | undefined {
  const n = Number(raw);
  return Number.isInteger(n) && n > 0 ? n : undefined;
}

// Falcon severity → ours, 1:1. Name first, numeric second; unknown → Info (no invented verdict).
const SEVERITY_BY_NAME: Record<string, Severity> = {
  informational: "Info",
  info: "Info",
  low: "Low",
  medium: "Medium",
  high: "High",
  critical: "Critical",
};
const SEVERITY_BY_NUMBER: Severity[] = ["Info", "Info", "Low", "Medium", "High", "Critical"];
function falconSeverity(rec: Row): Severity {
  const name = SEVERITY_BY_NAME[field(rec, "SeverityName").toLowerCase()];
  if (name) return name;
  const n = Number(field(rec, "Severity"));
  return Number.isInteger(n) && n >= 1 && n <= 5 ? SEVERITY_BY_NUMBER[n] : "Info";
}

export interface CsCtx {
  rec: Row;
  name: string;
  host: string;
  at: string;
  sink: Map<string, SiemIoc>;
}

export type CsMapped = Omit<MappedEvent, "timestamp" | "sources" | "asset"> & {
  user?: string;
  logonType?: number;
};

function head(c: CsCtx, body: string): string {
  return `${CROWDSTRIKE_SOURCE}: ${c.name} — ${body}${c.at}`;
}

// Event name + host + the value that tells two events apart. Digits are never folded: two remote
// IPs, two pids or two hashes must stay two rows.
function key(c: CsCtx, ...parts: string[]): string {
  return boundedAggKey(`cs|${c.name.toLowerCase()}|${c.host.toLowerCase()}|${parts.join("|")}`);
}

function addHash(sink: Map<string, SiemIoc>, raw: string): void {
  const h = raw.toLowerCase();
  if (/^(?:[a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64})$/.test(h)) addIoc(sink, "hash", h);
}

function mapProcess(c: CsCtx): CsMapped {
  const image = field(c.rec, "ImageFileName");
  const cmd = field(c.rec, "CommandLine");
  const parent = field(c.rec, "ParentBaseFileName");
  // RawProcessId is the OS pid (the Windows 4688 / Sysmon 1 correlation key). TargetProcessId is
  // Falcon's own process id — kept apart, in the key only, never as `pid`.
  const pid = pidNum(field(c.rec, "RawProcessId"));
  const falconId = field(c.rec, "TargetProcessId");
  const sha256 = field(c.rec, "SHA256HashData").toLowerCase();
  addHash(c.sink, sha256);
  addHash(c.sink, field(c.rec, "MD5HashData"));
  const procName = baseName(image) || baseName(cmd);
  const grade = isSuspiciousCmd(image, cmd);
  const tc = tradecraftSignal(image, cmd);
  const spill = secretSpillSignal(cmd);
  const strong = grade === "strong" || tc?.weight === "strong";
  const flagged = Boolean(grade) || Boolean(tc) || Boolean(spill);
  if (flagged) addIoc(c.sink, "process", procName || image);
  const mitre = [
    ...new Set([
      ...(flagged ? ["T1059"] : []),
      ...(tc?.mitre ?? []),
      ...(spill?.mitre ?? []),
      ...reconTechniques(image, cmd),
    ]),
  ];
  const body =
    `Process created: ${cmd || image || "(unknown)"}` +
    (parent ? ` (parent ${parent})` : "") +
    (pid !== undefined ? ` pid ${pid}` : "") +
    (sha256 ? ` sha256 ${sha256}` : "");
  return {
    severity: strong ? "High" : flagged ? "Medium" : "Info",
    mitre,
    description: head(c, body),
    aggKey: key(c, String(pid ?? ""), falconId, image, cmd),
    ...(procName ? { processName: procName } : {}),
    ...(parent ? { parentName: parent } : {}),
    ...(pid !== undefined ? { pid } : {}),
    ...(cmd ? { commandLine: cmd } : {}),
    ...(image ? { path: image } : {}),
  };
}

function mapNetwork(c: CsCtx, listen: boolean): CsMapped {
  const v6 = c.name.endsWith("IP6");
  const local = cleanIp(field(c.rec, v6 ? "LocalAddressIP6" : "LocalAddressIP4"));
  const localPort = field(c.rec, "LocalPort");
  const proc = field(c.rec, "ContextProcessId");
  if (listen)
    return {
      severity: "Info",
      mitre: [],
      description: head(c, `Network listen ${local || "?"}${localPort ? `:${localPort}` : ""}`),
      aggKey: key(c, local, localPort, proc),
      ...(portNum(localPort) ? { port: portNum(localPort) } : {}),
    };
  const remote = cleanIp(field(c.rec, v6 ? "RemoteAddressIP6" : "RemoteAddressIP4"));
  const remotePort = field(c.rec, "RemotePort");
  const pub = publicIp(remote);
  if (pub) addIoc(c.sink, "ip", pub);
  const body =
    `Network connect ${local || "?"}${localPort ? `:${localPort}` : ""}` +
    ` → ${remote || "?"}${remotePort ? `:${remotePort}` : ""}` +
    (proc ? ` (process ${proc})` : "");
  return {
    severity: "Info",
    mitre: [],
    description: head(c, body),
    aggKey: key(c, proc, `${remote}:${remotePort}`),
    ...(local ? { srcIp: local } : {}),
    ...(remote ? { dstIp: remote } : {}),
    ...(portNum(remotePort) ? { port: portNum(remotePort) } : {}),
  };
}

function mapLogon(c: CsCtx, failed: boolean): CsMapped {
  // The account exactly as Falcon wrote it — no stripping, no join assumption.
  const user = field(c.rec, "UserName") || field(c.rec, "UserPrincipal");
  const upn = field(c.rec, "UserPrincipal");
  const typeRaw = field(c.rec, "LogonType");
  const logonType = typeRaw !== "" && Number.isInteger(Number(typeRaw)) ? Number(typeRaw) : undefined;
  const src = cleanIp(field(c.rec, "RemoteAddressIP4") || field(c.rec, "RemoteAddressIP6"));
  const pub = publicIp(src);
  if (pub) addIoc(c.sink, "ip", pub);
  // The ECAR wording (`Logon success (type N)` / `Logon FAILED`).
  const body =
    `Logon ${failed ? "FAILED" : "success"}` +
    (logonType !== undefined ? ` (type ${logonType})` : "") +
    (user ? ` ${user}` : "") +
    (upn && upn !== user ? ` (${upn})` : "") +
    (src ? ` from ${src}` : "");
  return {
    severity: "Info",
    mitre: [],
    description: head(c, body),
    aggKey: key(c, failed ? "fail" : "ok", typeRaw, user, src),
    ...(src ? { srcIp: src } : {}),
    ...(user ? { user } : {}),
    ...(logonType !== undefined ? { logonType } : {}),
  };
}

function mapDetection(c: CsCtx): CsMapped {
  const detect = field(c.rec, "DetectName") || field(c.rec, "DetectDescription") || "detection";
  const tactic = field(c.rec, "Tactic");
  const technique = field(c.rec, "Technique");
  const techniqueId = field(c.rec, "TechniqueId");
  const file = field(c.rec, "FileName");
  const cmd = field(c.rec, "CommandLine");
  const action = field(c.rec, "PatternDispositionDescription");
  addHash(c.sink, field(c.rec, "SHA256String"));
  addHash(c.sink, field(c.rec, "MD5String"));
  const body =
    `Detection: ${detect}` +
    (tactic || technique ? ` — ${tactic}/${technique}` : "") +
    (file || cmd ? ` — ${[file, cmd].filter(Boolean).join(" ")}` : "") +
    (action ? ` — ${action}` : "");
  return {
    severity: falconSeverity(c.rec),
    mitre: /^T\d{4}(?:\.\d{3})?$/.test(techniqueId) ? [techniqueId] : [],
    description: head(c, body),
    aggKey: key(c, field(c.rec, "DetectId") || field(c.rec, "CompositeId"), detect, file, cmd),
    ...(cmd ? { commandLine: cmd } : {}),
  };
}

function plain(c: CsCtx, body: string, ...parts: string[]): CsMapped {
  return { severity: "Info", mitre: [], description: head(c, body), aggKey: key(c, ...parts) };
}

function mapUnknown(c: CsCtx): CsMapped {
  const pairs: string[] = [];
  for (const k of Object.keys(c.rec)) {
    if (META_KEYS.has(k)) continue;
    const s = field(c.rec, k);
    if (s) pairs.push(`${k}=${s}`);
  }
  const summary = boundedTextTo(pairs.join(" - ") || "(no fields)", UNKNOWN_SUMMARY_MAX);
  return plain(c, summary, summary);
}

function mapWritten(c: CsCtx): CsMapped {
  const file = field(c.rec, "TargetFileName");
  const sha256 = field(c.rec, "SHA256HashData").toLowerCase();
  addHash(c.sink, sha256);
  const body = `File written: ${file || "(unknown)"}${sha256 ? ` sha256 ${sha256}` : ""}`;
  return { ...plain(c, body, file, sha256), ...(file ? { path: file } : {}) };
}

function mapByName(c: CsCtx): CsMapped {
  const f = (k: string) => field(c.rec, k);
  switch (c.name) {
    case "ProcessRollup2":
    case "SyntheticProcessRollup2":
      return mapProcess(c);
    case "NetworkConnectIP4":
    case "NetworkConnectIP6":
      return mapNetwork(c, false);
    case "NetworkListenIP4":
    case "NetworkListenIP6":
      return mapNetwork(c, true);
    case "DnsRequest": {
      const domain = f("DomainName").replace(/\.$/, "");
      if (domain) addIoc(c.sink, "domain", domain);
      const type = f("RequestType");
      return plain(c, `DNS request ${domain || "?"}${type ? ` (type ${type})` : ""}`, domain, type);
    }
    case "UserLogon":
      return mapLogon(c, false);
    case "UserLogonFailed":
    case "UserLogonFailed2":
      return mapLogon(c, true);
    case "AsepValueUpdate":
    case "RegGenericValueUpdate": {
      const where = [f("RegObjectName"), f("RegValueName")].filter(Boolean).join("\\") || "(unknown key)";
      const data = f("RegStringValue");
      return plain(c, `Registry set: ${where}${data ? ` = ${data}` : ""}`, where, data);
    }
    case "ScheduledTaskRegistered": {
      const task = f("TaskName");
      const run = [f("TaskExecCommand"), f("TaskExecArguments")].filter(Boolean).join(" ");
      return {
        ...plain(c, `Scheduled task registered: ${task || "(unnamed)"}${run ? ` → ${run}` : ""}`, task, run),
        ...(run ? { commandLine: run } : {}),
      };
    }
    case "ServiceStarted":
    case "InstalledServiceUpdate": {
      const svc = f("ServiceDisplayName") || f("ServiceName");
      const image = f("ImageFileName");
      return {
        ...plain(c, `Service: ${svc || "(unnamed)"}${image ? ` (${image})` : ""}`, svc, image),
        ...(image ? { path: image } : {}),
      };
    }
    case "DetectionSummaryEvent":
    case "EppDetectionSummaryEvent":
      return mapDetection(c);
    default:
      return c.name.endsWith("Written") ? mapWritten(c) : mapUnknown(c);
  }
}

/** Map one Falcon row (already dated) to a forensic event, or null when it has no event name. */
export function mapCrowdstrikeRecord(
  rec: Row,
  timestamp: string,
  recordIndex: number,
  sink: Map<string, SiemIoc>,
): MappedEvent | null {
  const name = eventName(rec);
  if (!name) return null;
  const host = field(rec, "ComputerName") || field(rec, "aid");
  const c: CsCtx = { rec, name, host, at: host ? ` @ ${host}` : "", sink };
  const { user, logonType, ...m } = mapByName(c);
  const mapped: MappedEvent = {
    ...m,
    timestamp,
    sources: [CROWDSTRIKE_SOURCE],
    ...(host ? { asset: host } : {}),
  };
  return { ...mapped, canonical: crowdstrikeCanonical(c, mapped, recordIndex, user, logonType) };
}
