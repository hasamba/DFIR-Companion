// Deterministic importer for Azure virtual network flow logs (#931 item 13 second half, #1294) —
// the current Network Watcher format, `flowLogVersion` 4, `category: "FlowLogFlowEvent"`. Sibling
// of awsFlowLogImport.ts; every departure from it is named below.
//
// Schema (fetched live from learn.microsoft.com/azure/network-watcher/vnet-flow-logs-overview,
// 2026-09-18 — not recalled): a `{ records: [...] }` blob; each record carries `macAddress` (the
// NIC the flow was observed on), `targetResourceID` (the VNet/subnet/NIC the flow log is scoped
// to) and `flowRecords.flows[].flowGroups[].flowTuples[]`. One tuple is a comma string of exactly
// 13 fields:
//
//   timestamp, srcIp, dstIp, srcPort, dstPort, protocol(IANA number), direction(I|O),
//   state(B|C|E|D), encryption(X|NX|NX_*), packetsSent, bytesSent, packetsReceived, bytesReceived
//
// TIMESTAMP UNIT. Microsoft's own page disagrees with itself: the sample record writes 13-digit
// milliseconds (1663146003599), the bandwidth example writes 10-digit seconds (1708978215). Rule:
// a value >= 1e11 is milliseconds, below is seconds — every real seconds value for centuries stays
// under 1e11 and every real milliseconds value since 1973 is over it. Each unit then gets the AWS
// importer's own range bound (seconds <= 8.64e9, milliseconds <= 8.64e12) so a corrupt 11-digit
// value is `malformed`, never a row confidently dated in the 31st century.
//
// COUNTERS. `B` (begin) carries no statistics — the doc says so, and both real shapes exist
// (`0,0,0,0` in the sample, four empty fields in the bandwidth example). A B row prints NO
// counters: zero is a measurement, and the platform measured nothing. `C`/`E` counters are
// increments "since the last update", never a connection total, and the row says so; an empty
// counter on C/E contradicts the format and is `malformed`. `D` (denied at rule evaluation)
// prints no counters either.
//
// REFUSED BY NAME, NEVER MISPARSED. The retired NSG flow-log format
// (`category: "NetworkSecurityGroupFlowEvent"`, 8/12-field tuples) is counted as `legacyNsg`, and
// a `flowLogVersion` other than 4 as `unsupportedVersion`; both produce zero events and are named
// in the import note (the #1124 rule).
//
// NEVER CLAIMED. Which VM sent or received the flow: the record names a NIC by MAC, the Activity
// Log's VM write names NICs by resource id, and no artifact binds the two — so no attribution is
// attempted and none is faked (the AWS attribution pass is provider-gated and skips these rows).
// `I`/`O` is relative to the logged NIC, and the row says "inbound to NIC <mac>", never "inbound".
// A `D` row is a rule verdict, not an attack. Rule tokens are printed as logged and may be
// platform rules. Direction, state, encryption and counters are description-only in this slice
// (no canonical field carries them). `event.action` is `allow`/`deny` — a per-provider vocabulary
// nothing gates on. A routable IPv6 endpoint makes a row, never an IOC (`isInternalIpv4` cannot
// classify v6 ranges). Not fed to beaconDetect.ts — same reason as AWS (interval rows read as
// low-jitter beacons).
//
// AGGREGATION. Rows that carry a measurement (C/E) key on the tuple's own timestamp, so two
// measurements of one flow never merge — only an exact duplicate tuple (same timestamp, a
// re-exported line) collapses by count; B/D rows (no counters) use the AWS hourly bucket. State
// and rule are always in the key, so the same tuple under two rules stays two rows.
//
// BOUNDS. Ports must be <= 65535 (the canonical port schema throws on more — and one forged line
// must never abort an upload, so every row's mapping is also guarded and counted `malformed` on
// any throw). Timestamps must lie in [2001, 2242] per unit (seconds 1e9..8.64e9, milliseconds
// 1e12..8.64e12) — no cloud flow log predates 2001. Counters above 2^53 are `malformed` rather
// than rounded. Rule and MAC text is bounded before composing the row so the C/E counters and the
// encryption state can never be pushed past the 600-char description cut, and stripped of
// brackets so a forged rule token can never print as a "[<name>: …]" derived note (#1388). The
// target resource id is bounded before it becomes `cloud.resource` (#1370): the bound is sized
// so every real ARM id fits untouched (subscription 36 + resource group ≤ 90 + VNet ≤ 64 +
// subnet ≤ 80 + the fixed path segments ≈ 355) and only a forged one gets the digest tail.
//
// Pure, deterministic, NO AI call.

import type { Severity } from "./stateTypes.js";
import { createCanonicalEvent } from "./canonicalEvent.js";
import { boundedAggKey, boundedTextTo, stripNoteBrackets } from "./aggKey.js";
import { isInternalIpv4 } from "./internalIp.js";
import {
  addIoc,
  cleanIp,
  extractRecords,
  getCI,
  isObject,
  str,
  type SiemEvent,
  type SiemIoc,
  type MappedEvent,
  aggregateEvents,
  maxEventsDefault,
} from "./siemImport.js";

type Row = Record<string, unknown>;

export interface AzureFlowLogImportOptions {
  aggregate?: boolean;
  minSeverity?: Severity;
  maxEvents?: number;
  maxIocs?: number;
}

export interface AzureFlowLogParseResult {
  events: SiemEvent[];
  iocs: SiemIoc[];
  /** Records read (one per NIC-interval blob entry). */
  records: number;
  /** Tuples read across every record, including refused/malformed ones. */
  tuples: number;
  total: number;
  kept: number;
  dropped: number;
  groups: number;
  format: string;
  malformed: number;
  legacyNsg: number;
  unsupportedVersion: number;
  unspecifiedRule: number;
  noTarget: number;
}

const FLOW_CATEGORY = "flowlogflowevent";
const NSG_CATEGORY = "networksecuritygroupflowevent";
const SUPPORTED_VERSION = 4;
const DIRECTIONS = new Set(["I", "O"]);
const STATES = new Set(["B", "C", "E", "D"]);
const ENCRYPTION_RE = /^(?:X|NX(?:_[A-Z_]+)?)$/;
const PROTOCOL_NAMES: Record<string, string> = { "1": "icmp", "6": "tcp", "17": "udp", "58": "icmpv6" };
const STATE_WORD: Record<string, string> = { B: "begin", C: "continuing", E: "end", D: "denied" };
const MS_THRESHOLD = 1e11;
const MIN_SECONDS = 1_000_000_000;
const MAX_SECONDS = 8_640_000_000;
const MIN_MILLIS = 1_000_000_000_000;
const MAX_MILLIS = 8_640_000_000_000;
const MAX_PORT = 65535;
const RULE_MAX = 120;
const MAC_MAX = 32;
const TARGET_MAX = 512;
const SUBSCRIPTION_RE = /\/subscriptions\/([0-9a-f-]{36})\//i;

interface Tuple {
  timeMs: number;
  src: string;
  dst: string;
  srcPort: number;
  dstPort: number;
  protocol: string;
  direction: string;
  state: string;
  encryption: string;
  packetsSent: number;
  bytesSent: number;
  packetsReceived: number;
  bytesReceived: number;
}

interface RecordContext {
  mac: string;
  target: string;
  subscription: string;
  rule: string;
  locator: string;
}

/** Validates one 13-field tuple, or returns null (malformed). */
function parseTuple(raw: string): Tuple | null {
  const f = raw.split(",");
  if (f.length !== 13) return null;
  const [ts, srcRaw, dstRaw, sport, dport, proto, direction, state, encryption, ps, bs, pr, br] = f.map((x) =>
    x.trim(),
  );
  if (
    !/^\d+$/.test(ts) ||
    !DIRECTIONS.has(direction) ||
    !STATES.has(state) ||
    !ENCRYPTION_RE.test(encryption)
  )
    return null;
  if (![sport, dport, proto].every((x) => /^\d+$/.test(x))) return null;
  if (Number(sport) > MAX_PORT || Number(dport) > MAX_PORT) return null;
  const counters = [ps, bs, pr, br];
  const measured = state === "C" || state === "E";
  if (counters.some((c) => !(c === "" || /^\d+$/.test(c)))) return null;
  if (measured && counters.some((c) => c === "")) return null;
  if (counters.some((c) => c !== "" && !Number.isSafeInteger(Number(c)))) return null;
  const n = Number(ts);
  if (!Number.isSafeInteger(n)) return null;
  const timeMs = n >= MS_THRESHOLD ? n : n * 1000;
  if (n >= MS_THRESHOLD ? n < MIN_MILLIS || n > MAX_MILLIS : n < MIN_SECONDS || n > MAX_SECONDS) return null;
  const src = cleanIp(srcRaw);
  const dst = cleanIp(dstRaw);
  if (!src || !dst) return null;
  return {
    timeMs,
    src,
    dst,
    srcPort: Number(sport),
    dstPort: Number(dport),
    protocol: proto,
    direction,
    state,
    encryption,
    packetsSent: Number(ps || 0),
    bytesSent: Number(bs || 0),
    packetsReceived: Number(pr || 0),
    bytesReceived: Number(br || 0),
  };
}

function endpoint(ip: string, port: number): string {
  return port > 0 ? `${ip}:${port}` : ip;
}

/** Public unicast IPv4 only: not internal, not multicast/reserved/broadcast (224.0.0.0/3) — a v6 peer is never an IOC. */
function isIocCandidate(ip: string): boolean {
  const m = /^(\d+)\.\d+\.\d+\.\d+$/.exec(ip);
  return !!m && Number(m[1]) < 224 && !isInternalIpv4(ip);
}

function mapTuple(t: Tuple, ctx: RecordContext, sink: Map<string, SiemIoc>): MappedEvent {
  const protoName = PROTOCOL_NAMES[t.protocol] ?? t.protocol;
  const observed = new Date(t.timeMs).toISOString();
  for (const ip of [t.src, t.dst]) if (isIocCandidate(ip)) addIoc(sink, "ip", ip);

  const mac = boundedTextTo(stripNoteBrackets(ctx.mac), MAC_MAX);
  const rule = boundedTextTo(stripNoteBrackets(ctx.rule), RULE_MAX);
  const target = boundedTextTo(ctx.target, TARGET_MAX);
  const dirWords = t.direction === "I" ? `inbound to NIC ${mac}` : `outbound from NIC ${mac}`;
  const ruleWords =
    rule.toLowerCase() === "unspecified" ? "rule unspecified (encryption-denied)" : `rule ${rule}`;
  const measured = t.state === "C" || t.state === "E";
  const counters = measured
    ? ` [${t.packetsSent} packet(s)/${t.bytesSent} byte(s) sent, ${t.packetsReceived} packet(s)/${t.bytesReceived} byte(s) received since last update]`
    : "";
  const description = boundedTextTo(
    `Azure VNet flow: ${endpoint(t.src, t.srcPort)} -> ${endpoint(t.dst, t.dstPort)} (${protoName}) ${dirWords}, ${STATE_WORD[t.state]}, ${ruleWords}${counters} [encryption ${t.encryption}]`,
    600,
  );

  // A measured row (C/E) keys on its own timestamp (only an exact duplicate merges); B/D buckets hourly.
  const timeKey = measured ? String(t.timeMs) : String(Math.floor(t.timeMs / 3_600_000));
  const srcPortField = t.srcPort > 0 ? t.srcPort : undefined;
  const dstPortField = t.dstPort > 0 ? t.dstPort : undefined;

  return {
    timestamp: observed,
    description,
    severity: "Low",
    mitre: [],
    aggKey: boundedAggKey(
      `azure-flow|${ctx.target}|${ctx.mac}|${ctx.rule}|${t.src}|${t.dst}|${t.srcPort}|${t.dstPort}|${t.protocol}|${t.direction}|${t.state}|${timeKey}`.toLowerCase(),
    ),
    sources: ["Azure virtual network flow logs"],
    srcIp: t.src,
    dstIp: t.dst,
    ...(dstPortField ? { port: dstPortField } : {}),
    canonical: createCanonicalEvent({
      event: { category: "network", type: "flow", action: t.state === "D" ? "deny" : "allow" },
      network: {
        source: {
          address: t.src,
          provenance: "edge-observed",
          ...(srcPortField ? { port: srcPortField } : {}),
        },
        destination: { address: t.dst, ...(dstPortField ? { port: dstPortField } : {}) },
        protocol: protoName,
      },
      cloud: {
        provider: "azure",
        ...(ctx.subscription ? { accountId: ctx.subscription } : {}),
        ...(target ? { resource: target } : {}),
      },
      time: { observed, normalized: observed },
      evidence: { rawRecords: [{ source: "azure-vnet-flow-log", locator: ctx.locator }] },
      producer: {
        importer: "azure-vnet-flow-log",
        parserVersion: "1",
        mappingVersion: "azure-vnet-flow-log-v1",
        ruleVersions: ["azure-vnet-flow-log-v1"],
      },
    }),
  };
}

export function parseAzureFlowLog(
  text: string,
  opts: AzureFlowLogImportOptions = {},
): AzureFlowLogParseResult {
  const { records } = extractRecords(text);
  const sink = new Map<string, SiemIoc>();
  const mapped: MappedEvent[] = [];
  let tuples = 0;
  let malformed = 0;
  let legacyNsg = 0;
  let unsupportedVersion = 0;
  let unspecifiedRule = 0;
  let noTarget = 0;

  records.forEach((rec, r) => {
    const category = str(getCI(rec, "category")).trim().toLowerCase();
    if (category === NSG_CATEGORY) {
      legacyNsg++;
      return;
    }
    if (category !== FLOW_CATEGORY) return;
    if (Number(getCI(rec, "flowLogVersion")) !== SUPPORTED_VERSION) {
      unsupportedVersion++;
      return;
    }
    const target = str(getCI(rec, "targetResourceID")).trim();
    if (!target) noTarget++;
    const subscription = (SUBSCRIPTION_RE.exec(target)?.[1] ?? "").toLowerCase();
    const mac = str(getCI(rec, "macAddress")).trim();
    const flowRecords = getCI(rec, "flowRecords");
    const flows = isObject(flowRecords) ? getCI(flowRecords, "flows") : undefined;
    (Array.isArray(flows) ? flows : []).forEach((flow, f) => {
      if (!isObject(flow)) return;
      const groups = getCI(flow, "flowGroups");
      (Array.isArray(groups) ? groups : []).forEach((group, g) => {
        if (!isObject(group)) return;
        const rule = str(getCI(group, "rule")).trim();
        if (rule.toLowerCase() === "unspecified") unspecifiedRule++;
        const list = getCI(group, "flowTuples");
        (Array.isArray(list) ? list : []).forEach((raw, i) => {
          tuples++;
          const t = typeof raw === "string" ? parseTuple(raw) : null;
          if (!t) {
            malformed++;
            return;
          }
          // One tuple's mapping must never abort the upload: anything the validators missed that
          // the canonical schema rejects is counted here, not thrown out of the whole parse.
          try {
            mapped.push(
              mapTuple(
                t,
                { mac, target, subscription, rule, locator: `record:${r}/flow:${f}/group:${g}/tuple:${i}` },
                sink,
              ),
            );
          } catch {
            malformed++;
          }
        });
      });
    });
  });

  const { events, groups } = aggregateEvents(mapped, {
    aggregate: opts.aggregate,
    minSeverity: opts.minSeverity,
    maxEvents: opts.maxEvents ?? maxEventsDefault(),
  });
  const represented = events.reduce((n, e) => n + (e.count ?? 1), 0);

  return {
    events,
    iocs: [...sink.values()].slice(0, opts.maxIocs ?? 5000),
    records: records.length,
    tuples,
    total: tuples,
    kept: events.length,
    dropped: Math.max(0, mapped.length - represented),
    groups,
    format: "azure-vnet-flow-log",
    malformed,
    legacyNsg,
    unsupportedVersion,
    unspecifiedRule,
    noTarget,
  };
}

/**
 * True for an Azure flow-log upload — the current VNet format OR the retired NSG format, so the
 * importer can refuse the latter BY NAME instead of some other detector misparsing it. A sampled
 * record must carry one of the two flow-log categories AND the matching flow container.
 */
export function isAzureFlowLogUpload(_root: unknown, sample: Row | null): boolean {
  if (!sample) return false;
  const category = str(getCI(sample, "category")).trim().toLowerCase();
  if (category === FLOW_CATEGORY) return isObject(getCI(sample, "flowRecords"));
  if (category === NSG_CATEGORY) {
    const props = getCI(sample, "properties");
    return isObject(props) && Array.isArray(getCI(props, "flows"));
  }
  return false;
}
