// The deterministic finding for the urgent Defender case (#930 item 1 part B — #964): a record
// that ALLOWED a threat, FAILED to remediate it, or says it REMEDIATED it, and then the same bytes
// started on the same host. One finding per Defender record, minted before the generic High
// backfill so that backfill never raises a second, confidence-100 finding on the start row it
// links. Only a hash match qualifies: a path match says "the same path", and that is not a
// finding about the payload — the row's own Medium annotation is all the evidence supports.
//
// Machine-owned: severity, control / execution and their sources, title, description are rebuilt
// from the evidence on every run, so a model echo of the known id (which renameForgedFindingIds
// lets through) cannot leave its own words under a deterministic name. Status is kept — the
// analyst's decision — and the outcome side store still wins at read time (findingOutcome.ts).
// A finding whose evidence no longer qualifies is kept and said to be unsupported now, never
// silently deleted.

import { createHash } from "node:crypto";
import type { Finding, InvestigationState } from "./stateTypes.js";
import { DEFENDER_FINDING_ID_PREFIX } from "./responseSchema.js";
import {
  defenderEpisodeMatches,
  defenderIdentity,
  dispositionWords,
  laterWords,
  readDefenderRecord,
  type DefenderRecord,
  type DefenderTimelineShape,
  type EpisodeMatch,
} from "./defenderEpisodes.js";

/** Stated before grounding; the single-source rule caps it to SINGLE_SOURCE_CONFIDENCE_CAP when one tool on one host is all there is. */
export const DEFENDER_FINDING_CONFIDENCE = 85;
const QUALIFYING = new Set(["allowed", "remediation-failed", "remediated"]);
const STARTS_NAMED_MAX = 8;
const UNSUPPORTED_PREFIX = "No longer supported by the current evidence: ";

const short = (s: string): string => createHash("sha256").update(s).digest("hex").slice(0, 12);

/** The finding id from the record's own content — host, identity, time — never the timeline event id. */
export function defenderFindingId<T extends DefenderTimelineShape>(event: T): string {
  const r = readDefenderRecord(event);
  return r ? idOf(r) : `${DEFENDER_FINDING_ID_PREFIX}unreadable`;
}

const idOf = <T>(r: DefenderRecord<T>): string =>
  `${DEFENDER_FINDING_ID_PREFIX}${short(`${defenderIdentity(r)}|${r.at}`)}`;

function describe<T extends DefenderTimelineShape>(
  m: EpisodeMatch<T>,
  hashed: EpisodeMatch<T>["starts"],
): string {
  const host = m.record.event.asset ?? "";
  const named = hashed
    .slice(0, STARTS_NAMED_MAX)
    .map((s) => `${new Date(s.at).toISOString()} (${laterWords(m.record.at, s.at)})`)
    .join(", ");
  const more = hashed.length > STARTS_NAMED_MAX ? `; +${hashed.length - STARTS_NAMED_MAX} more` : "";
  return (
    `Defender ${dispositionWords(m.record.block)} on ${host} at ${new Date(m.record.at).toISOString()}; ` +
    `a process with the same sha256 (${m.record.sha256}) later started from ${hashed[0].path}: ${named}${more}. ` +
    `A process start supports execution, not that the payload achieved its objective; the scanner's ` +
    `identity is not the launcher (read the start row's own account).`
  );
}

/**
 * Mint or rebuild the finding for every qualifying Defender record whose hash-matched starts are
 * all in the synthesis scope with it; link both events. Pure; idempotent.
 */
export function backfillDefenderEpisodeFindings(
  state: InvestigationState,
  eligibleIds: ReadonlySet<string>,
  timestamp: string,
): InvestigationState {
  const existing = new Map(
    state.findings.filter((f) => f.id.startsWith(DEFENDER_FINDING_ID_PREFIX)).map((f) => [f.id, f]),
  );
  const rebuilt = new Map<string, Finding>();
  const linkByEvent = new Map<string, string>();
  for (const m of defenderEpisodeMatches(state.forensicTimeline)) {
    if (!QUALIFYING.has(m.disposition) || !m.record.sha256) continue;
    if (!eligibleIds.has(m.record.event.id)) continue;
    const hashed = m.starts.filter((s) => s.by === "hash" && eligibleIds.has(s.event.id));
    if (!hashed.length) continue;
    const id = idOf(m.record);
    const prior = existing.get(id);
    const host = m.record.event.asset ?? "";
    rebuilt.set(id, {
      ...(prior ?? {}),
      id,
      severity: "High",
      confidence: DEFENDER_FINDING_CONFIDENCE,
      confidenceReason:
        "Deterministic: a Defender record with the file's own digest, and a process start with the same digest after it, on one host.",
      title: `Defender ${m.record.block.disposition} ${m.record.block.threat} on ${host}; the same file later started`,
      description: describe(m, hashed),
      relatedIocs: prior?.relatedIocs ?? [],
      mitreTechniques: [],
      sourceScreenshots: prior?.sourceScreenshots ?? [],
      firstSeen: new Date(m.record.at).toISOString(),
      lastUpdated: timestamp,
      status: prior?.status ?? "open",
      control: m.disposition,
      controlSource: "machine",
      execution: "observed",
      executionSource: "machine",
    });
    linkByEvent.set(m.record.event.id, id);
    for (const s of hashed) linkByEvent.set(s.event.id, id);
  }
  // A prior finding of ours whose record no longer qualifies: kept, said to be unsupported now.
  const unsupported = new Map<string, Finding>();
  for (const [id, f] of existing) {
    if (rebuilt.has(id) || f.description.startsWith(UNSUPPORTED_PREFIX)) continue;
    unsupported.set(id, {
      ...f,
      description: `${UNSUPPORTED_PREFIX}${f.description}`,
      lastUpdated: timestamp,
    });
  }
  if (!rebuilt.size && !unsupported.size) return state;
  const findings = [
    ...state.findings.map((f) => rebuilt.get(f.id) ?? unsupported.get(f.id) ?? f),
    ...[...rebuilt.values()].filter((f) => !existing.has(f.id)),
  ];
  return {
    ...state,
    findings,
    forensicTimeline: state.forensicTimeline.map((e) => {
      const id = linkByEvent.get(e.id);
      return id && !e.relatedFindingIds.includes(id)
        ? { ...e, relatedFindingIds: [...e.relatedFindingIds, id] }
        : e;
    }),
  };
}
