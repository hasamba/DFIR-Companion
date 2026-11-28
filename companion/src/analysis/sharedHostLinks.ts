import type { InvestigationState, ForensicEvent, Severity } from "./stateTypes.js";
import { filterTimeline, type TimeWindow } from "./assetGraph.js";
import { buildEvidenceGraph, type EvidenceGraph } from "./evidenceGraph.js";
import { canonicalAccounts, upgradeForensicEvent } from "./canonicalEvent.js";
import {
  eventAsset,
  eventHash,
  eventPath,
  hostNodeId,
  isPseudoAccount,
  shortHash,
  timeOf,
  type Confidence,
} from "./evidenceFields.js";

// HOSTS THAT SHARE A BINARY OR AN ACCOUNT (#3085). The same attacker-introduced file, or the same
// (non-pseudo) account, seen on two or more hosts. A real lead — but it has NO direction: it cannot
// say which host moved to which, and lining such hosts up in time order drew fan-out (SRC→A,
// SRC→B) as A→B, a hop that never happened. So these are reported as an unordered set of hosts,
// never as lateral-movement hops; the hops come from direction evidence (lateralDirection.ts).
// Pure, derived on read, no AI, forensic timeline only.

export interface SharedHostLink {
  id: string; // "shared:binary:<hash>" | "shared:account:<name>" — stable across reads
  actor: string; // the binary's filename (short hash when no path was recorded) or the account
  actorKind: "binary" | "account";
  hostIds: string[]; // host node ids, in the order each host was first tied to the actor
  hosts: string[]; // display names, same order
  confidence: Confidence; // binary high, account medium (a roaming account is signal, not proof)
  firstSeen: string;
  lastSeen: string; // the latest of the per-host FIRST sightings
  eventIds: string[]; // the earliest sighting on each host
}

// A shared binary only means anything when it was ATTACKER-INTRODUCED. Ordinary corporate software
// shares a hash across every workstation BY DESIGN, so an unguarded rule made chrome.exe/OUTLOOK.EXE/
// vpnui.exe/updaters the longest and top-sorted "attack chain" in a real 12-host case.
//
// The discriminator is PROVENANCE, not grading. "Is it flagged?" does not work here: the pipeline
// registers every observed binary hash as an IOC and tags process events with MITRE techniques, so
// chrome.exe reads as flagged too. Where a binary LIVES does discriminate — a hash only ever seen in
// a vendor install root is installed software, while attacker tooling lands in an arbitrary writable
// location. Prevalence is deliberately NOT part of the test.
//
// Escape hatches, so this can only ever suppress ordinary software:
//   • graded High/Critical      → kept (LOLbin abuse, or malware planted in System32)
//   • no recorded path          → kept (absent provenance, do not filter)
// NOTE: VENDOR_INSTALL_ROOT is a curated list. Modern apps install PER USER (OneDrive, Teams, Zoom),
// so those roots have to be named explicitly.
const GRAVE_SEVERITY: ReadonlySet<Severity> = new Set<Severity>(["Critical", "High"]);
const VENDOR_INSTALL_ROOT = new RegExp(
  "^[a-z]:[\\\\/](" +
    "windows|program files( \\(x86\\))?|programdata[\\\\/]microsoft" + // machine-wide
    "|users[\\\\/][^\\\\/]+[\\\\/]appdata[\\\\/](local|roaming)[\\\\/]" + // per-user vendor roots
    "(microsoft|zoom|slack|google|mozilla|discord|dropbox|programs[\\\\/]microsoft)" +
    ")[\\\\/]",
  "i",
);

function installedSoftware(timeline: readonly ForensicEvent[]): Set<string> {
  const provenance = new Map<string, { vendorOnly: boolean; hasPath: boolean; grave: boolean }>();
  for (const e of timeline) {
    const key = eventHash(e);
    if (!key) continue;
    const rec = provenance.get(key) ?? { vendorOnly: true, hasPath: false, grave: false };
    const p = eventPath(e);
    if (p) {
      rec.hasPath = true;
      if (!VENDOR_INSTALL_ROOT.test(p)) rec.vendorOnly = false;
    }
    if (GRAVE_SEVERITY.has(e.severity)) rec.grave = true;
    provenance.set(key, rec);
  }
  return new Set([...provenance].filter(([, r]) => r.hasPath && r.vendorOnly && !r.grave).map(([h]) => h));
}

// The EARLIEST event tying each host to each key.
function earliestPerHost(
  timeline: readonly ForensicEvent[],
  keysOf: (e: ForensicEvent) => readonly string[],
): Map<string, Map<string, ForensicEvent>> {
  const byKey = new Map<string, Map<string, ForensicEvent>>();
  for (const e of timeline) {
    const asset = eventAsset(e);
    if (!asset) continue;
    for (const key of keysOf(e)) {
      const hosts = byKey.get(key) ?? new Map<string, ForensicEvent>();
      const existing = hosts.get(asset.toLowerCase());
      if (!existing || timeOf(e.timestamp) < timeOf(existing.timestamp)) hosts.set(asset.toLowerCase(), e);
      byKey.set(key, hosts);
    }
  }
  return byKey;
}

function link(
  id: string,
  actor: string,
  actorKind: SharedHostLink["actorKind"],
  hosts: Map<string, ForensicEvent>,
): SharedHostLink {
  const ordered = [...hosts.values()].sort(
    (a, b) => timeOf(a.timestamp) - timeOf(b.timestamp) || eventAsset(a).localeCompare(eventAsset(b)),
  );
  return {
    id,
    actor,
    actorKind,
    hostIds: ordered.map((e) => hostNodeId(eventAsset(e))),
    hosts: ordered.map(eventAsset),
    confidence: actorKind === "binary" ? "high" : "medium",
    firstSeen: ordered[0].timestamp,
    lastSeen: ordered[ordered.length - 1].timestamp,
    eventIds: ordered.map((e) => e.id),
  };
}

export function buildSharedHostLinks(state: InvestigationState, window?: TimeWindow): SharedHostLink[] {
  const timeline = filterTimeline(state.forensicTimeline, window).map(upgradeForensicEvent);
  const vendor = installedSoftware(timeline);
  const nameByHash = new Map<string, string>();
  for (const e of timeline) {
    const key = eventHash(e);
    const base = eventPath(e).split(/[\\/]/).pop();
    if (key && base && !nameByHash.has(key)) nameByHash.set(key, base);
  }
  const links: SharedHostLink[] = [];
  for (const [h, hosts] of earliestPerHost(timeline, (e) => (eventHash(e) ? [eventHash(e)] : []))) {
    if (hosts.size < 2 || vendor.has(h)) continue;
    links.push(link(`shared:binary:${h}`, nameByHash.get(h) ?? shortHash(h), "binary", hosts));
  }
  const accounts = (e: ForensicEvent) => canonicalAccounts(e).filter((a) => !isPseudoAccount(a));
  for (const [acct, hosts] of earliestPerHost(timeline, accounts)) {
    if (hosts.size < 2) continue;
    links.push(link(`shared:account:${acct.toLowerCase()}`, acct, "account", hosts));
  }
  // Most hosts first, then earliest; binary before account on a tie (a file is the harder link).
  return links.sort(
    (a, b) =>
      b.hostIds.length - a.hostIds.length ||
      timeOf(a.firstSeen) - timeOf(b.firstSeen) ||
      a.actorKind.localeCompare(b.actorKind) ||
      a.id.localeCompare(b.id),
  );
}

// The dashboard's evidence-graph read: the graph plus the shared links it lists beside the directed
// lateral paths, so they ride on that read instead of a new route.
export type EvidenceGraphRead = EvidenceGraph & { sharedHostLinks: SharedHostLink[] };
export function evidenceGraphRead(state: InvestigationState, window?: TimeWindow): EvidenceGraphRead {
  return { ...buildEvidenceGraph(state, window), sharedHostLinks: buildSharedHostLinks(state, window) };
}
