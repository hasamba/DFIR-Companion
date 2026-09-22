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
import { resolveHost, type HostAliasIndex } from "./hostAlias.js";
import { labIntelTag } from "./labIntel.js";
import { renderDestinationTags } from "./destinationFacts.js";
import { renderDecoyTag } from "./renamedBinaryNote.js";
import { renderBuildTimeTag } from "./buildTimeWindow.js";
import { canonicalFile, canonicalNetwork } from "./canonicalEvent.js";

const MAX_TAG_VALUE = 48; // keep one field from bloating a line; hostnames/paths can be long

/** The file name at the end of a Windows or POSIX path. */
function baseName(p: string): string {
  const cut = Math.max(p.lastIndexOf("\\"), p.lastIndexOf("/"));
  return cut >= 0 ? p.slice(cut + 1) : p;
}

function clip(v: string): string {
  const s = String(v ?? "")
    .replace(/\s+/g, " ")
    .trim();
  return s.length > MAX_TAG_VALUE ? s.slice(0, MAX_TAG_VALUE) + "…" : s;
}

// Compact structured tags appended after an event's prose, e.g.
//   <host:WS07> <proc:powershell.exe←excel.exe> <net:10.1.2.3→52.1.1.1:443> <src:3>
// Only set fields are emitted. `src:N` (N≥2) flags cross-tool corroboration. Returns "" (no leading
// space) when the event carries no structured fields, so a bare event line is unchanged.
export function renderStructuredTags(e: ForensicEvent, aliasIndex?: HostAliasIndex): string {
  const tags: string[] = [];
  // Resolve at RENDER time only — the stored event keeps its original spelling. Without this the
  // model reads both spellings in the raw event stream and narrates two machines regardless of
  // what the derived context blocks say.
  if (e.asset) tags.push(`<host:${clip(aliasIndex ? resolveHost(aliasIndex, e.asset) : e.asset)}>`);

  // The flat fields lead; each missing one is filled from the canonical envelope, independently
  // (#1530). A Sysmon EID 3 row sets NEITHER — the mapper records a process name only for
  // process-kind events and never sets dstIp/port — so an OneDrive update connection reached the
  // model with no image and no destination as facts, while the 240-character description render cut
  // `DestinationIp=…` out of the middle and truncated the image path. The model then had six
  // unattributed addresses to reason about, and fused them into a C2 finding (INC-2026-001 f13).
  // Same lesson as #1502: a fact the cut can reach is a fact that goes missing.
  //
  // Both fallbacks are for a NETWORK row only, and that bound matters twice. On a network record
  // the canonical file block is the connecting image; on a file record it is the file that was
  // WRITTEN, and reading that as the process would put `<proc:invoice.xlsm>` on the row — a process
  // that never ran. And a logon record carries a network block too (the source address), so reading
  // it here would put a `<net:…→?>` connection tag on every 4624 in the product.
  const networkRow = e.canonical?.event?.category === "network";
  const cn = networkRow ? canonicalNetwork(e) : undefined;
  const cf = cn ? canonicalFile(e) : undefined;
  const image = e.processName || cf?.name || baseName(cf?.path ?? "");
  if (image || e.parentName) {
    const child = image ? clip(image) : "";
    const parent = e.parentName ? clip(e.parentName) : "";
    tags.push(`<proc:${child}${parent ? `←${parent}` : ""}>`);
  }

  const srcIp = e.srcIp || cn?.source?.address || "";
  const dstIp = e.dstIp || cn?.destination?.address || "";
  const dstPort = typeof e.port === "number" ? e.port : cn?.destination?.port;
  if (srcIp || dstIp) {
    const src = srcIp ? clip(srcIp) : "?";
    const dst = dstIp ? clip(dstIp) : "?";
    const port = typeof dstPort === "number" && Number.isFinite(dstPort) ? `:${dstPort}` : "";
    tags.push(`<net:${src}→${dst}${port}>`);
  }

  const nSources = e.sources?.length ?? 0;
  if (nSources >= 2) tags.push(`<src:${nSources}>`);

  // What the sample seen at THIS event did in a sandbox (#932 item 5) — intelligence about the file,
  // placed where the file was observed. labIntelTag returns "" or " <sandbox:…>"; strip its space
  // so it joins like the others.
  const lab = labIntelTag(e.labIntel).trim();
  if (lab) tags.push(lab);

  // The facts the 240-char render cuts out of a long command line or never reads from `message`
  // (#1502): the rclone destination, the fetched URL, an ip:port a script block names — and the
  // renamed-binary note as a flag, not as prose at the end of the line.
  tags.push(...renderDestinationTags(e));
  const decoy = renderDecoyTag(e);
  if (decoy) tags.push(decoy);

  // The host building itself (#1529). A tag, not prose: the row's own note sits past the 240-char
  // render cut, and this is the one fact that stops a provisioning-day log clear from opening the
  // attacker path.
  const build = renderBuildTimeTag(e);
  if (build) tags.push(build);

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
