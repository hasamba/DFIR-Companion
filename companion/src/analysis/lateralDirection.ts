import { worstSeverity, type ForensicEvent, type Severity } from "./stateTypes.js";
import { canonicalHostName } from "./hostAlias.js";
import {
  buildHostBindingIndex,
  isIdentifyingClientName,
  isIdentifyingIp,
  resolveIpAtTime,
  type HostBindingIndex,
} from "./hostBinding.js";
import {
  eventAsset,
  eventPath,
  hostNodeId,
  isPseudoAccount,
  timeOf,
  type Confidence,
} from "./evidenceFields.js";

// DIRECTED lateral-movement hops (#3085): "who connected to whom", read from evidence the TARGET
// host itself recorded about an inbound connection. A hop exists only when the record names its
// source and that source resolves to a host the case knows — a source is never guessed, so fan-out
// (SRC→A, SRC→B) stays two hops and never becomes A→B.
//
//   • network-logon (medium): a successful network logon (4624 type 3) on the target whose
//     Workstation Name, source hostname or edge-observed source IP resolves to a case host.
//   • remote-service (high): a remote-execution service (PSEXESVC, RemCom, CSExec, winexe, PAExec)
//     INSTALLED or STARTED on the target, with a source on the same record, or from network-logon
//     evidence onto that target within ±10 min that names exactly one source and no unresolved one.
//   • A file sighting of such a binary, or any other service install, only CORROBORATES a logon
//     episode on the same target (its event joins the hop; confidence stays medium).
//
// IP → host comes ONLY from records that state the pairing themselves (hostBinding.ts: a successful
// logon carrying both the IP and the client's Workstation Name). Never from `asset` + `srcIp`: an
// inbound record carries the TARGET as its asset and the SOURCE's IP. Any doubt — an IP bound to two
// hosts or to a machine the case does not know, a name and an IP that disagree — means no hop.
// 4648 (explicit credentials) is deliberately not read: the importer does not keep TargetServerName,
// so its direction cannot be told from the structured fields (#3085 review).
//
// Pure + deterministic, no AI, forensic timeline only.

export interface LateralHop {
  from: string; // host node id — where the connection came from
  to: string; // host node id — the host that recorded it
  // When the hop happened: both are the episode's earliest evidence time, since the source acted at
  // the moment the target recorded it. `toTimestamp` is the stitcher's order key.
  fromTimestamp: string;
  toTimestamp: string;
  confidence: Confidence;
  rule: "remote-service" | "network-logon";
  // WHO/WHAT carried this hop, as a STRUCTURED field — consumers never parse it out of `basis`.
  actor: string;
  actorKind: "account" | "binary";
  basis: string; // human one-liner, display only
  eventIds: string[]; // backing events: the target's records plus any IP-binding record used
}

export interface DirectedLateralHop extends LateralHop {
  fromHost: string; // display names, for graph node labels
  toHost: string;
  severity: Severity; // worst severity among the backing events
}

const EPISODE_GAP_MS = 60 * 60_000; // evidence on one host pair further apart than this = a new hop
const SERVICE_PAIR_MS = 10 * 60_000; // a service install this close to a network logon is paired with it
const BINDING_TOLERANCE_MS = 60 * 60_000; // an IP→host sample counts this close to the record
const MAX_HOP_EVENTS = 20;
const MAX_BASIS_NOTES = 4;
const REMOTE_EXEC_SERVICE = /^(?:(?:psexesvc|remcomsvc|csexecsvc|winexesvc)(?:\.exe)?|paexec-.+\.exe)$/i;

const baseName = (p: string | undefined): string => (p ?? "").trim().split(/[\\/]/).pop() ?? "";

// The hosts the case knows: every asset named anywhere in the forensic timeline.
class CaseHosts {
  private readonly byName = new Map<string, string>();
  private readonly byShort = new Map<string, Set<string>>();

  constructor(timeline: readonly ForensicEvent[]) {
    for (const e of timeline) {
      const display = eventAsset(e);
      const key = canonicalHostName(display);
      if (!key || this.byName.has(key)) continue;
      this.byName.set(key, display);
      const short = key.split(".")[0];
      this.byShort.set(short, (this.byShort.get(short) ?? new Set()).add(key));
    }
  }

  // Exact name first; else a short-name match, only when one side is a bare short name and exactly
  // one case host fits (so "srv.a.example" never collapses onto "srv.b.example").
  resolve(raw: string | undefined): string | undefined {
    const key = canonicalHostName(raw ?? "");
    if (!key) return undefined;
    const exact = this.byName.get(key);
    if (exact) return exact;
    const fits = [...(this.byShort.get(key.split(".")[0]) ?? [])].filter(
      (k) => !key.includes(".") || !k.includes("."),
    );
    return fits.length === 1 ? this.byName.get(fits[0]) : undefined;
  }
}

interface Source {
  host?: string; // undefined = unresolved or in doubt
  evidence: string[]; // IP-binding records used
}

function resolveAddress(
  hosts: CaseHosts,
  bindings: HostBindingIndex,
  ip: string,
  at: string,
): Source & { doubt: boolean } {
  const found = resolveIpAtTime(bindings, ip, at, BINDING_TOLERANCE_MS);
  if (!found.length) return { evidence: [], doubt: false };
  const named = new Set<string>();
  for (const b of found) {
    const h = hosts.resolve(b.host);
    if (!h) return { evidence: [], doubt: true }; // bound to a machine the case does not know
    named.add(h);
  }
  if (named.size !== 1) return { evidence: [], doubt: true };
  return { host: [...named][0], evidence: found.map((b) => b.evidenceEventId), doubt: false };
}

// The source a record names: Workstation Name, source hostname, edge-observed source IP. All that
// are present must agree on one case host.
function sourceOf(hosts: CaseHosts, bindings: HostBindingIndex, e: ForensicEvent): Source {
  const c = e.canonical;
  const net = c?.network?.source;
  const names = [c?.session?.terminal, net?.hostname]
    .map((n) => (n ?? "").trim())
    .filter((n) => n && isIdentifyingClientName(n));
  const candidates = new Set<string>();
  for (const n of names) {
    const h = hosts.resolve(n);
    if (!h) return { evidence: [] }; // names a machine the case does not know
    candidates.add(h);
  }
  let evidence: string[] = [];
  const ip = net?.provenance === "edge-observed" ? (net.address ?? "").trim() : "";
  if (ip && isIdentifyingIp(ip)) {
    const r = resolveAddress(hosts, bindings, ip, e.timestamp);
    if (r.doubt) return { evidence: [] };
    if (r.host) candidates.add(r.host);
    // The binding records are cited only when the IP is what named the source; when a name on the
    // record already did, the IP merely agreed with it.
    if (!names.length) evidence = r.evidence.filter((id) => id !== e.id);
  }
  return candidates.size === 1 ? { host: [...candidates][0], evidence } : { evidence: [] };
}

function networkLogonAccount(e: ForensicEvent): string | undefined {
  const c = e.canonical;
  if (c?.event.type !== "logon" || c.event.outcome !== "success") return undefined;
  if (c.authentication?.logonType !== 3) return undefined;
  const account = ((c.actor?.kind === "account" ? c.actor.name : undefined) ?? c.account?.name ?? "").trim();
  const user = account.split("\\").pop() ?? "";
  if (!account || user.endsWith("$") || isPseudoAccount(account)) return undefined;
  return account;
}

// A remote-execution service installed (service record) or started (process start) on this host.
function remoteExecService(e: ForensicEvent): string | undefined {
  const c = e.canonical;
  if (c?.event.category === "service" && c.service) {
    const exe = baseName(c.service.executable);
    if (REMOTE_EXEC_SERVICE.test(exe)) return exe;
    if (REMOTE_EXEC_SERVICE.test((c.service.name ?? "").trim())) return (c.service.name ?? "").trim();
  }
  const proc = baseName(c?.process?.name);
  if (c?.event.category === "process" && c.event.type === "start" && REMOTE_EXEC_SERVICE.test(proc))
    return proc;
  return undefined;
}

// What a record can only corroborate: any other service install, or a remote-exec binary sighted.
function corroboration(e: ForensicEvent): string | undefined {
  const c = e.canonical;
  if (c?.event.category === "service" && c.service) {
    return `service ${c.service.name || baseName(c.service.executable) || "?"} installed`;
  }
  const seen = [eventPath(e), c?.file?.name, c?.process?.name]
    .map(baseName)
    .find((n) => REMOTE_EXEC_SERVICE.test(n));
  return seen ? `${seen} on the target` : undefined;
}

interface Evidence {
  from: string; // display names
  to: string;
  time: number;
  timestamp: string;
  kind: "remote-service" | "network-logon" | "corroboration";
  actor: string;
  note: string;
  eventIds: string[];
  severity: Severity;
}

interface LogonSighting {
  time: number;
  source?: string;
  event: ForensicEvent;
  evidence: string[];
}

// The single source of the network logons onto `target` within the pairing window of `at`, or
// undefined when there is none, more than one, or any logon whose source is unresolved.
function pairedSource(logons: readonly LogonSighting[] | undefined, at: number): LogonSighting[] | undefined {
  const near = (logons ?? []).filter((l) => Math.abs(l.time - at) <= SERVICE_PAIR_MS);
  if (!near.length || near.some((l) => !l.source)) return undefined;
  return new Set(near.map((l) => l.source)).size === 1 ? near : undefined;
}

function collectEvidence(
  timeline: readonly ForensicEvent[],
  fullTimeline: readonly ForensicEvent[],
): Evidence[] {
  const hosts = new CaseHosts(fullTimeline);
  const bindings = buildHostBindingIndex(fullTimeline);
  const out: Evidence[] = [];
  const logonsByTarget = new Map<string, LogonSighting[]>();
  for (const e of timeline) {
    const account = networkLogonAccount(e);
    const target = hosts.resolve(eventAsset(e));
    if (!account || !target) continue;
    const src = sourceOf(hosts, bindings, e);
    const source = src.host && src.host !== target ? src.host : undefined;
    const list = logonsByTarget.get(target) ?? [];
    list.push({ time: timeOf(e.timestamp), source: src.host, event: e, evidence: src.evidence });
    logonsByTarget.set(target, list);
    if (!source) continue;
    out.push({
      from: source,
      to: target,
      time: timeOf(e.timestamp),
      timestamp: e.timestamp,
      kind: "network-logon",
      actor: account,
      note: `network logon as ${account}`,
      eventIds: [e.id, ...src.evidence],
      severity: e.severity,
    });
  }
  for (const e of timeline) {
    const target = hosts.resolve(eventAsset(e));
    if (!target) continue;
    const service = remoteExecService(e);
    const own = service ? sourceOf(hosts, bindings, e) : { evidence: [] };
    const paired = own.host ? undefined : pairedSource(logonsByTarget.get(target), timeOf(e.timestamp));
    const source = own.host ?? paired?.[0].source;
    const note = service ? undefined : corroboration(e);
    if (!source || source === target || (!service && !note)) continue;
    const base = {
      from: source,
      to: target,
      time: timeOf(e.timestamp),
      timestamp: e.timestamp,
      severity: e.severity,
    };
    const backing = [e.id, ...own.evidence, ...(paired ?? []).flatMap((l) => [l.event.id, ...l.evidence])];
    if (service) {
      out.push({
        ...base,
        kind: "remote-service",
        actor: service,
        note: `remote service ${service}`,
        eventIds: backing,
      });
    } else if (paired) {
      out.push({ ...base, kind: "corroboration", actor: "", note: note!, eventIds: [e.id] });
    }
  }
  return out;
}

function episodeHop(ev: readonly Evidence[]): DirectedLateralHop {
  const first = ev[0];
  const remote = ev.find((x) => x.kind === "remote-service");
  const logon = ev.find((x) => x.kind === "network-logon");
  const lead = remote ?? logon ?? first;
  const notes = [...new Set(ev.map((x) => x.note))];
  return {
    from: hostNodeId(first.from),
    to: hostNodeId(first.to),
    fromHost: first.from,
    toHost: first.to,
    fromTimestamp: first.timestamp,
    toTimestamp: first.timestamp,
    confidence: remote ? "high" : "medium",
    rule: remote ? "remote-service" : "network-logon",
    actor: lead.actor,
    actorKind: remote ? "binary" : "account",
    basis:
      `${first.from} → ${first.to}: ${notes.slice(0, MAX_BASIS_NOTES).join("; ")}` +
      (notes.length > MAX_BASIS_NOTES ? ` (+${notes.length - MAX_BASIS_NOTES} more)` : ""),
    eventIds: [...new Set(ev.flatMap((x) => x.eventIds))].slice(0, MAX_HOP_EVENTS),
    severity: ev.reduce<Severity>((s, x) => worstSeverity(s, x.severity), "Info"),
  };
}

/**
 * Directed hops, one per ordered host pair per episode (evidence on the pair more than an hour apart
 * starts a new hop, so a later return to the same pair keeps its own time for the path stitcher).
 * `timeline` is the (windowed, upgraded) evidence; `fullTimeline` the whole upgraded forensic
 * timeline, which supplies the case's hosts and IP bindings so narrowing the window never erases a
 * source host.
 */
export function directedLateralHops(
  timeline: readonly ForensicEvent[],
  fullTimeline: readonly ForensicEvent[] = timeline,
): DirectedLateralHop[] {
  const byPair = new Map<string, Evidence[]>();
  for (const x of collectEvidence(timeline, fullTimeline)) {
    const key = `${hostNodeId(x.from)}>${hostNodeId(x.to)}`;
    byPair.set(key, [...(byPair.get(key) ?? []), x]);
  }
  const hops: DirectedLateralHop[] = [];
  for (const ev of byPair.values()) {
    const sorted = [...ev].sort((a, b) => a.time - b.time);
    let episode: Evidence[] = [];
    for (const x of sorted) {
      if (episode.length && x.time - episode[episode.length - 1].time > EPISODE_GAP_MS) {
        if (episode.some((y) => y.kind !== "corroboration")) hops.push(episodeHop(episode));
        episode = [];
      }
      episode.push(x);
    }
    if (episode.some((y) => y.kind !== "corroboration")) hops.push(episodeHop(episode));
  }
  return hops.sort(
    (a, b) =>
      timeOf(a.toTimestamp) - timeOf(b.toTimestamp) ||
      a.from.localeCompare(b.from) ||
      a.to.localeCompare(b.to),
  );
}

/** One entry per ordered host pair, every episode folded in — the evidence graph's directed edge. */
export function directedLateralPairs(hops: readonly DirectedLateralHop[]): DirectedLateralHop[] {
  const byPair = new Map<string, DirectedLateralHop>();
  for (const h of hops) {
    const key = `${h.from}>${h.to}`;
    const seen = byPair.get(key);
    if (!seen) {
      byPair.set(key, { ...h, eventIds: [...h.eventIds] });
      continue;
    }
    const better = h.confidence === "high" && seen.confidence !== "high";
    byPair.set(key, {
      ...(better ? h : seen),
      eventIds: [...new Set([...seen.eventIds, ...h.eventIds])].slice(0, MAX_HOP_EVENTS),
      severity: worstSeverity(seen.severity, h.severity),
      fromTimestamp: seen.fromTimestamp,
      toTimestamp: seen.toTimestamp,
    });
  }
  return [...byPair.values()];
}
