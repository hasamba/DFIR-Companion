import { AUTO_FINDING_ID_PREFIX } from "../responseSchema.js";
import { detectionRuleHead } from "../synthGroup.js";
import type { Finding, ForensicEvent, InvestigationState } from "../stateTypes.js";

/**
 * A finding that cites a GROUPED prompt row (#1702).
 *
 * The synthesis prompt collapses a detection burst into one representative row (synthGroup.ts), so the
 * model's verdict on that row is about the burst. On INC-2026-014 an AI finding dismissed the
 * services.exe "Reg Key Value Set" burst of the Sysmon install, citing the representative only; the 17
 * other members stayed unlinked and the High backfill raised them as an open T1112 auto finding.
 *
 * A LIVE finding covers every member: it keeps them in view, it silences nothing.
 *
 * A DISMISSED finding covers a member only when the member is the SAME act as the row the model saw:
 * same host, same acting image, same detection rule, within DISMISS_REACH_MS of the cited row. The
 * prompt group is a rule-head bucket that crosses hosts and chains rows up to an hour apart (Codex
 * review of #1702), and the model saw only the representative's details — so a dismissal must not reach
 * a later attacker row that merely fired the same Sigma rule. A member outside those bounds stays
 * uncovered, and the High backfill still raises it.
 */

/** How far from the cited row a dismissal reaches inside its group: one burst, not an hour of rows. */
export const DISMISS_REACH_MS = 60_000;

// The acting image a detection row names (`Image=`), never ParentImage/SourceImage/TargetImage and
// never the row's `path`, which can be the target file rather than the actor.
const ACTING_IMAGE = /(?<![A-Za-z])Image=(.+?)(?: - | @ |$)/;

function actingImage(e: ForensicEvent): string {
  return ACTING_IMAGE.exec(e.description)?.[1]?.trim().toLowerCase() ?? "";
}

function host(e: ForensicEvent): string {
  return (e.asset ?? "").trim().toLowerCase();
}

function sameAct(member: ForensicEvent, cited: ForensicEvent): boolean {
  const h = host(cited);
  const image = actingImage(cited);
  const rule = detectionRuleHead(cited.description);
  if (!h || !image || !rule) return false;
  if (host(member) !== h || actingImage(member) !== image || detectionRuleHead(member.description) !== rule)
    return false;
  const gap = Math.abs(Date.parse(member.timestamp) - Date.parse(cited.timestamp));
  return Number.isFinite(gap) && gap <= DISMISS_REACH_MS;
}

/** The event ids a finding covers: what it cites, widened through the grouped rows it cites. */
export function coveredEventIds(
  finding: Pick<Finding, "status" | "relatedEventIds">,
  membersOf: ReadonlyMap<string, readonly string[]> | undefined,
  eventById: ReadonlyMap<string, ForensicEvent>,
): string[] {
  const out: string[] = [];
  for (const eid of finding.relatedEventIds ?? []) {
    out.push(eid);
    const members = membersOf?.get(eid);
    if (!members) continue;
    if (finding.status !== "dismissed") {
      out.push(...members);
      continue;
    }
    const cited = eventById.get(eid);
    if (!cited) continue;
    for (const m of members) {
      const member = eventById.get(m);
      if (member && sameAct(member, cited)) out.push(m);
    }
  }
  return out;
}

/**
 * Every event each auto finding holds, from both link directions — read from the state BEFORE this
 * synthesis relinks it. The model may echo an auto finding's id without citing its events (the schema
 * allows it), and relinking would then leave the echo with no events at all (Codex review of #1702).
 */
export function autoFindingSupport(state: InvestigationState): Map<string, Set<string>> {
  const out = new Map<string, Set<string>>();
  const add = (fid: string, eid: string) => {
    if (!fid.startsWith(AUTO_FINDING_ID_PREFIX)) return;
    const set = out.get(fid) ?? new Set<string>();
    set.add(eid);
    out.set(fid, set);
  };
  for (const f of state.findings) for (const eid of f.relatedEventIds ?? []) add(f.id, eid);
  for (const e of state.forensicTimeline) for (const fid of e.relatedFindingIds) add(fid, e.id);
  return out;
}

/**
 * An auto finding exists only because its events looked uncovered. When every event it holds — now or
 * before this synthesis — is linked to a DISMISSED model finding, it would call "High, open" the rows
 * the analysis just called benign, so it is dropped with its links. One event outside the dismissal
 * keeps it. Model findings are never touched.
 */
export function dropAutoCoveredByDismissal(
  state: InvestigationState,
  prior: ReadonlyMap<string, ReadonlySet<string>>,
): InvestigationState {
  const dismissed = new Set(
    state.findings
      .filter((f) => f.status === "dismissed" && !f.id.startsWith(AUTO_FINDING_ID_PREFIX))
      .map((f) => f.id),
  );
  if (!dismissed.size) return state;
  const eventById = new Map(state.forensicTimeline.map((e) => [e.id, e] as const));
  const covered = (eid: string) =>
    eventById.get(eid)?.relatedFindingIds.some((fid) => dismissed.has(fid)) ?? false;
  const drop = new Set<string>();
  for (const f of state.findings) {
    if (!f.id.startsWith(AUTO_FINDING_ID_PREFIX) || f.status === "dismissed") continue;
    const events = new Set([...(f.relatedEventIds ?? []), ...(prior.get(f.id) ?? [])]);
    for (const e of state.forensicTimeline) if (e.relatedFindingIds.includes(f.id)) events.add(e.id);
    if (events.size && [...events].every(covered)) drop.add(f.id);
  }
  if (!drop.size) return state;
  return {
    ...state,
    findings: state.findings.filter((f) => !drop.has(f.id)),
    forensicTimeline: state.forensicTimeline.map((e) =>
      e.relatedFindingIds.some((fid) => drop.has(fid))
        ? { ...e, relatedFindingIds: e.relatedFindingIds.filter((fid) => !drop.has(fid)) }
        : e,
    ),
  };
}
