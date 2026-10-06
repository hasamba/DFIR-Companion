import type { ForensicEvent } from "./stateTypes.js";
import {
  anomalyEnvOptions,
  detectTimelineAnomalies,
  type AnomalyOptions,
  type TimelineAnomaly,
} from "./timelineAnomalies.js";

// Host-activity spikes as a synthesis LEAD block. The spike detector (timelineAnomalies.ts) fed only
// the report, so on a noisy multi-host case the model re-derived "which machine went busy" from the
// rows it happened to be shown — or never did. This renders the same spikes for the prompt.
//
// It reads the events the caller passes, which in synthesis are the SCOPED FORENSIC TIMELINE — the
// same rows the model already sees, never the super-timeline. A spike is a rate, not an act: a
// backup, a patch run or a log flush spikes too, so the block says it is a lead in its own header
// (the beacon digest does the same) rather than relying on wording in the system prompt.
//
// Pure — no I/O, no mutation.

export const HOST_SPIKE_BLOCK_HEADER =
  "HOST ACTIVITY SPIKES (a host far busier than its peers or its own usual rate in one window of the " +
  "forensic timeline — a LEAD for where to look, not evidence of compromise: backups, patching and log " +
  "flushes spike too. Read the cited rows before using a spike in a finding):";

/** Most spike lines the block shows; the rest are counted, not listed. */
export const HOST_SPIKE_MAX_LINES = 6;
const CITED_IDS = 3;
const UNKNOWN_ASSET = "(unknown)";

function hhmm(iso: string): string {
  return iso.slice(11, 16);
}

function baselineText(a: TimelineAnomaly): string {
  const peer = a.methods.includes("peer");
  const self = a.methods.includes("self");
  if (peer && self) return "its peers' and its own usual rate";
  return peer ? "the other hosts in that window" : "its own usual rate";
}

function spikeLine(a: TimelineAnomaly): string {
  const day = a.bucketStart.slice(0, 10);
  const window = `${day} ${hhmm(a.bucketStart)}–${hhmm(a.bucketEnd)} UTC`;
  const cites = a.eventIds.slice(0, CITED_IDS).join(", ");
  return `- ${a.asset} ${window}: ${a.eventCount} events, ${a.ratio}× ${baselineText(a)} [${cites}]`;
}

/** The lead block for the synthesis prompt, or "" when no host spikes. */
export function buildHostSpikeBlock(
  events: readonly ForensicEvent[],
  opts: AnomalyOptions = anomalyEnvOptions(),
): string {
  const spikes = detectTimelineAnomalies(events, opts).anomalies.filter((a) => a.asset !== UNKNOWN_ASSET);
  if (!spikes.length) return "";
  const shown = spikes.slice(0, HOST_SPIKE_MAX_LINES).map(spikeLine);
  const more = spikes.length - shown.length;
  const tail = more > 0 ? `\n(${more} more spike${more === 1 ? "" : "s"} not listed)` : "";
  return `${HOST_SPIKE_BLOCK_HEADER}\n${shown.join("\n")}${tail}\n\n`;
}
