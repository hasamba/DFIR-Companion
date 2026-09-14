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
  STARTS_NAMED_MAX,
  type DefenderRecord,
  type DefenderTimelineShape,
  type EpisodeMatch,
} from "./defenderEpisodes.js";

/** Stated before grounding; the single-source rule caps it to SINGLE_SOURCE_CONFIDENCE_CAP when one tool on one host is all there is. */
export const DEFENDER_FINDING_CONFIDENCE = 85;
const QUALIFYING = new Set(["allowed", "remediation-failed", "remediated"]);
const UNSUPPORTED_PREFIX = "No longer supported by the current evidence: ";
/** What an unsupported finding keeps: the id and the analyst's status; its machine claims are withdrawn. */
const UNSUPPORTED_CONFIDENCE = 10;

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
 * Mint or rebuild the finding for every qualifying Defender record with a hash-matched start, when
 * the record or one of those starts is in the synthesis scope (the pairing itself is read from the
 * whole timeline; a window that holds either endpoint keeps the finding under its stable id — a
 * window that holds neither leaves it to carryOutOfWindowFindings). Links both events. A prior
 * finding of ours whose record is in scope but no longer qualifies has its machine claims
 * withdrawn and its links removed; the id and the analyst's status stay. Pure; idempotent.
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
    const hashed = m.starts.filter((s) => s.by === "hash");
    if (!hashed.length) continue;
    if (!eligibleIds.has(m.record.event.id) && !hashed.some((s) => eligibleIds.has(s.event.id))) continue;
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
  // A prior finding of ours whose Defender record is IN SCOPE and no longer qualifies: kept under
  // its id with the analyst's status, but its machine claims are withdrawn — no High, no observed
  // execution, no links — so grounding and the reports stop reading it as established. A record
  // out of scope says nothing about the finding, which is left as it is.
  const inScopeIds = new Set(
    state.forensicTimeline
      .filter((e) => eligibleIds.has(e.id) && e.canonical?.defender)
      .map((e) => defenderFindingId(e)),
  );
  const unsupported = new Map<string, Finding>();
  for (const [id, f] of existing) {
    if (rebuilt.has(id) || !inScopeIds.has(id) || f.description.startsWith(UNSUPPORTED_PREFIX)) continue;
    unsupported.set(id, {
      ...f,
      severity: "Low",
      confidence: UNSUPPORTED_CONFIDENCE,
      confidenceReason: "The start that matched this record's digest is no longer in the case.",
      description: `${UNSUPPORTED_PREFIX}${f.description}`,
      execution: "unknown",
      executionSource: "machine",
      control: "unknown",
      controlSource: "machine",
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
      const kept = e.relatedFindingIds.filter((fid) => !unsupported.has(fid));
      const next = id && !kept.includes(id) ? [...kept, id] : kept;
      const same =
        next.length === e.relatedFindingIds.length && next.every((x, i) => x === e.relatedFindingIds[i]);
      return same ? e : { ...e, relatedFindingIds: next };
    }),
  };
}
