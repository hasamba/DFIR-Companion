// The canonical envelope for one mapped CrowdStrike Falcon row (#2592). Split from crowdstrikeMap.ts
// to keep each file small. The login graph reads authentication rows from here (category
// `authentication`, type `logon`, account + target host), not from the description wording.

import { createCanonicalEvent, type CanonicalEventCategory } from "./canonicalEvent.js";
import { baseName, type MappedEvent } from "./siemImport.js";
import { field, portNum } from "./crowdstrikeFields.js";

type Row = Record<string, unknown>;

export interface CsCanonicalInput {
  rec: Row;
  name: string;
  host: string;
}

function categoryOf(name: string): { category: CanonicalEventCategory; type: string } {
  if (/ProcessRollup2$/.test(name)) return { category: "process", type: "start" };
  if (name.startsWith("NetworkConnect")) return { category: "network", type: "connection" };
  if (name.startsWith("NetworkListen")) return { category: "network", type: "listen" };
  if (name === "DnsRequest") return { category: "network", type: "dns" };
  if (name.startsWith("UserLogon")) return { category: "authentication", type: "logon" };
  if (name === "AsepValueUpdate" || name === "RegGenericValueUpdate")
    return { category: "registry", type: "change" };
  if (name === "ScheduledTaskRegistered") return { category: "task", type: "creation" };
  if (name === "ServiceStarted" || name === "InstalledServiceUpdate")
    return { category: "service", type: "change" };
  if (name.endsWith("Written")) return { category: "file", type: "creation" };
  return { category: "other", type: name };
}

function networkBlock(m: MappedEvent, srcPort: number | undefined) {
  if (!m.srcIp && !m.dstIp) return {};
  return {
    network: {
      // Falcon's sensor saw the address on the host itself — the same basis as ECAR's EDR srcIp.
      ...(m.srcIp
        ? {
            source: {
              address: m.srcIp,
              provenance: "edge-observed" as const,
              ...(srcPort ? { port: srcPort } : {}),
            },
          }
        : {}),
      ...(m.dstIp ? { destination: { address: m.dstIp, ...(m.port ? { port: m.port } : {}) } } : {}),
    },
  };
}

function processBlock(rec: Row, m: MappedEvent) {
  const image = field(rec, "ImageFileName");
  return {
    process: {
      ...(m.pid ? { pid: m.pid } : {}),
      ...(m.processName ? { name: m.processName } : {}),
      ...(image ? { executable: image } : {}),
      ...(m.commandLine ? { commandLine: m.commandLine } : {}),
      ...(m.parentName ? { parent: { name: m.parentName } } : {}),
    },
  };
}

function registryBlock(rec: Row) {
  const key = field(rec, "RegObjectName");
  if (!key) return {};
  const valueName = field(rec, "RegValueName");
  const valueData = field(rec, "RegStringValue");
  return {
    registry: { key, ...(valueName ? { valueName } : {}), ...(valueData ? { valueData } : {}) },
  };
}

export function crowdstrikeCanonical(
  c: CsCanonicalInput,
  m: MappedEvent,
  recordIndex: number,
  user?: string,
  logonType?: number,
) {
  const { category, type } = categoryOf(c.name);
  const isLogon = category === "authentication";
  const domain = user?.includes("\\") ? user.split("\\")[0] : field(c.rec, "LogonDomain");
  const srcPort = portNum(field(c.rec, isLogon ? "RemotePort" : "LocalPort"));
  return createCanonicalEvent({
    event: {
      category,
      type,
      action: c.name,
      ...(isLogon ? { outcome: c.name.startsWith("UserLogonFailed") ? "failed" : "success" } : {}),
    },
    ...(user
      ? { actor: { kind: "account", name: user }, account: { name: user, ...(domain ? { domain } : {}) } }
      : {}),
    ...(c.host ? { target: { kind: "host", name: c.host } } : {}),
    ...(isLogon && logonType !== undefined ? { authentication: { logonType } } : {}),
    ...networkBlock(m, srcPort),
    ...(category === "process" ? processBlock(c.rec, m) : {}),
    ...(category === "file" && m.path ? { file: { path: m.path, name: baseName(m.path) } } : {}),
    ...registryBlock(c.rec),
    time: { observed: m.timestamp, normalized: m.timestamp, timezone: "UTC", precision: "millisecond" },
    evidence: { rawRecords: [{ source: "crowdstrike", locator: `record:${recordIndex}` }] },
    producer: {
      importer: "crowdstrike",
      parserVersion: "1",
      mappingVersion: "crowdstrike-v1",
      ruleVersions: ["crowdstrike-tradecraft-v1"],
    },
    rawFieldMap: {
      "event.action": ["#event_simpleName", "event_simpleName"],
      ...(user
        ? { "actor.name": ["UserName", "UserPrincipal"], "account.name": ["UserName", "UserPrincipal"] }
        : {}),
      ...(c.host ? { "target.name": ["ComputerName", "aid"] } : {}),
      ...(m.pid ? { "process.pid": ["RawProcessId"] } : {}),
      ...(m.commandLine && category === "process" ? { "process.commandLine": ["CommandLine"] } : {}),
      ...(m.srcIp
        ? {
            "network.source.address": isLogon
              ? ["RemoteAddressIP4", "RemoteAddressIP6"]
              : ["LocalAddressIP4", "LocalAddressIP6"],
          }
        : {}),
      ...(m.dstIp ? { "network.destination.address": ["RemoteAddressIP4", "RemoteAddressIP6"] } : {}),
    },
  });
}
