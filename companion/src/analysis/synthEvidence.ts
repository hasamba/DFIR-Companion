// Structured evidence for the synthesis prompt (investigation-guidance #5). synthesize() is the one AI
// call that writes findings / MITRE / attackerPath / keyQuestions, yet it saw each event as a single
// prose line — asset, process lineage, src→dst network, and corroborating-source count were all dropped
// (renderEvent in pipeline.ts). Cross-host dot-connecting then depended on hostnames surviving inside
// truncated prose, which produced fairhaven's wrong-anchor finding and halcyon's fabricated cross-host
// story. This module renders the compact structured tags + the beacon/attack-phase digests that give
// synthesis the same structured signal ask()/suggestHunts() already get.
//
// PURE — no I/O. Tags append only fields that are set (empty events cost zero extra tokens).

import type { ForensicEvent } from "./stateTypes.js";
import type { BeaconCandidate } from "./beaconDetect.js";
import { BEACON_CAVEAT } from "./beaconDetect.js";
import type { AttackPhase } from "./burstDetect.js";

const MAX_TAG_VALUE = 48; // keep one field from bloating a line; hostnames/paths can be long

function clip(v: string): string {
  const s = String(v ?? "").replace(/\s+/g, " ").trim();
  return s.length > MAX_TAG_VALUE ? s.slice(0, MAX_TAG_VALUE) + "…" : s;
}

// Compact structured tags appended after an event's prose, e.g.
//   <host:WS07> <proc:powershell.exe←excel.exe> <net:10.1.2.3→52.1.1.1:443> <src:3>
// Only set fields are emitted. `src:N` (N≥2) flags cross-tool corroboration. Returns "" (no leading
// space) when the event carries no structured fields, so a bare event line is unchanged.
export function renderStructuredTags(e: ForensicEvent): string {
  const tags: string[] = [];
  if (e.asset) tags.push(`<host:${clip(e.asset)}>`);

  if (e.processName || e.parentName) {
    const child = e.processName ? clip(e.processName) : "";
    const parent = e.parentName ? clip(e.parentName) : "";
    tags.push(`<proc:${child}${parent ? `←${parent}` : ""}>`);
  }

  if (e.srcIp || e.dstIp) {
    const src = e.srcIp ? clip(e.srcIp) : "?";
    const dst = e.dstIp ? clip(e.dstIp) : "?";
    const port = typeof e.port === "number" && Number.isFinite(e.port) ? `:${e.port}` : "";
    tags.push(`<net:${src}→${dst}${port}>`);
  }

  const nSources = e.sources?.length ?? 0;
  if (nSources >= 2) tags.push(`<src:${nSources}>`);

  return tags.length ? " " + tags.join(" ") : "";
}

// One-line-per-beacon digest of the statistically-confirmed periodic callbacks (beaconDetect), phrased
// as CANDIDATES to verify (never asserted C2) and carrying BEACON_CAVEAT — legitimate software also
// polls on a timer, and synthesis over-anchoring on a suggestive line is a known failure mode. "" when
// there are no candidates, so it costs no tokens.
export function buildBeaconDigest(beacons: readonly BeaconCandidate[], limit = 8): string {
  const list = (beacons ?? []).slice(0, Math.max(0, Math.floor(limit)));
  if (!list.length) return "";
  const lines = list.map((b) => {
    const port = b.destPort ? `:${b.destPort}` : "";
    const scope = b.external ? "external" : "internal";
    const cites = b.eventIds.slice(0, 3).join(", ");
    return `- ${b.source} → ${b.destIp}${port} every ~${b.intervalSeconds}s (±${b.jitterPct}% jitter, ${b.eventCount} conns, ${scope})${cites ? ` [${cites}]` : ""}`;
  });
  return (
    `PERIODIC BEACON CANDIDATES (statistical regularity — a hunting LEAD to verify, NOT confirmed C2; ` +
    `${BEACON_CAVEAT}):\n${lines.join("\n")}\n\n`
  );
}

function hhmm(ts: string): string {
  const d = Date.parse(ts);
  if (Number.isNaN(d)) return ts || "(undated)";
  return new Date(d).toISOString().slice(11, 16); // HH:MM (UTC)
}

// One-line-per-phase digest of the timeline's activity bursts (burstDetect), each labelled with its
// dominant ATT&CK tactic and window, so synthesis sees the attack's PHASES instead of a flat list. Only
// multi-event phases are shown (a single isolated event is not a "phase"). "" when there are none.
export function buildAttackPhaseDigest(phases: readonly AttackPhase[], limit = 12): string {
  const list = (phases ?? []).filter((p) => p.eventCount > 1).slice(0, Math.max(0, Math.floor(limit)));
  if (!list.length) return "";
  const lines = list.map((p) => {
    const tech = p.inferredTechniques.length ? ` [${p.inferredTechniques.slice(0, 4).join(", ")}]` : "";
    return `- ${hhmm(p.startTimestamp)}–${hhmm(p.endTimestamp)} ${p.label} (${p.eventCount} ev, ${p.maxSeverity})${tech}`;
  });
  return `ATTACK PHASES (deterministic activity bursts, worst-severity first — the shape of the intrusion over time):\n${lines.join("\n")}\n\n`;
}
