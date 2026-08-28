import type { InvestigationState, Finding, Severity, ForensicEvent } from "./stateTypes.js";

const HIGH_SEVERITY = new Set<Severity>(["Critical", "High"]);

// How many leading normalized path segments must match for an uncovered event to be considered
// "the same tool/corpus directory" as one a dismissed finding already cited. Chosen to reach past a
// bundled tool's own randomly-named temp-extraction directory (…\Tools\tmp<N>\chainsaw\…) while still
// requiring a real, specific shared ancestor — not just a common drive letter or vendor folder.
const DISMISSED_PATH_PREFIX_DEPTH = 6;

// Normalize a Windows/Unix path into comparable segments: lowercase, forward-slashed, and any
// segment that is a mix of letters + digits with at least one digit (tmp2370838011, tmp481774682,
// {a-guid-like-run-id}) collapsed to a stable placeholder — so the SAME bundled tool re-extracted
// into a fresh randomly-named temp directory on a later import still prefix-matches.
function normalizedPathSegments(path: string): string[] {
  return path
    .toLowerCase()
    .replace(/\\/g, "/")
    .split("/")
    .filter(Boolean)
    .map((seg) => (/\d/.test(seg) ? seg.replace(/\d+/g, "#") : seg));
}

// True when `path` shares at least DISMISSED_PATH_PREFIX_DEPTH leading normalized segments with
// `dismissedPath` — i.e. both files sit under the same specific tool/corpus directory (e.g.
// Velociraptor's bundled chainsaw test corpus) even though the leaf filenames differ.
function sharesDismissedDirectory(path: string, dismissedPath: string): boolean {
  const a = normalizedPathSegments(path);
  const b = normalizedPathSegments(dismissedPath);
  const depth = Math.min(DISMISSED_PATH_PREFIX_DEPTH, a.length, b.length);
  if (depth < DISMISSED_PATH_PREFIX_DEPTH) return false;
  for (let i = 0; i < depth; i++) if (a[i] !== b[i]) return false;
  return true;
}

// A dismissal must already have demonstrated the DIRECTORY is noise — not just one file in it —
// before it can suppress backfill for a sibling file it never looked at. Requiring this many DISTINCT
// cited paths rules out a single-event (or single-file-hit-many-times) dismissal acting as a
// directory-wide allowlist: dismissing "this one file is a false positive" must not silently cover an
// unrelated, genuinely malicious file planted in the same product/cache tree later. f7-shaped
// corpus dismissals (INC-2026-018: ~140 cited events across dozens of distinct chainsaw rule files)
// clear this bar by a wide margin; a one-off dismissal never does.
const MIN_DISMISSED_CORPUS_FILES = 3;

// Every distinct file path cited by an already-DISMISSED finding that has itself cited at least
// MIN_DISMISSED_CORPUS_FILES distinct paths (via relatedEventIds) — i.e. an established corpus-level
// dismissal, not a one-off. A fresh backfill candidate under the same directory as one of those paths
// is recognized as the same already-explained noise instead of raising a brand-new "open,
// undetermined" High finding for it (INC-2026-018: finding f7 dismissed a whole wave of THOR/YARA hits
// on Velociraptor's own bundled chainsaw test corpus, but 17 further events under that exact directory
// — never individually cited by f7 — were still backfilled as separate open High findings).
function dismissedEventPaths(state: InvestigationState): { path: string; findingId: string }[] {
  const eventById = new Map(state.forensicTimeline.map((e) => [e.id, e] as const));
  const out: { path: string; findingId: string }[] = [];
  for (const f of state.findings) {
    if (f.status !== "dismissed") continue;
    const paths = new Set<string>();
    for (const eid of f.relatedEventIds ?? []) {
      const path = eventById.get(eid)?.path;
      if (path) paths.add(path);
    }
    if (paths.size < MIN_DISMISSED_CORPUS_FILES) continue; // one-off dismissal — not a corpus allowlist
    for (const path of paths) out.push({ path, findingId: f.id });
  }
  return out;
}

// The dismissed finding (if any) that already explains `event`'s directory, so a backfill candidate
// under it can be folded in rather than raised as new open noise.
function findDismissingFinding(
  event: Pick<ForensicEvent, "path">,
  dismissed: { path: string; findingId: string }[],
): string | undefined {
  if (!event.path) return undefined;
  for (const d of dismissed) {
    if (sharesDismissedDirectory(event.path, d.path)) return d.findingId;
  }
  return undefined;
}

// A concise finding title from an event description: first sentence, capped in length.
export function shortTitle(description: string, max = 90): string {
  const firstSentence = description.split(/(?<=[.!?])\s/)[0] ?? description;
  const t = firstSentence.trim();
  return t.length <= max ? t : t.slice(0, max - 1).trimEnd() + "…";
}

// Deterministic safety net for the heuristic "a Critical/High artifact row is almost
// always a finding". After synthesis, any eligible (in-scope, non-legitimate)
// Critical/High forensic event that synthesis left WITHOUT a linked finding gets an
// auto-generated finding, so a high-severity detection can never be silently missed.
//
// Events are GROUPED by their shortTitle before creating findings, so a burst of
// near-identical detections (e.g. 30 Windows Defender hits from one Sigma rule) becomes
// ONE finding + ONE playbook task rather than one per event.
//
// An event is NOT backfilled into a new open finding if it sits in the same directory as a file an
// already-DISMISSED finding cited — it's linked onto that finding instead (INC-2026-018: a finding
// explaining a bundled test-tool's own false-positive corpus by directory shouldn't leave a dozen more
// events from that same directory to resurface as separate, un-triaged open High findings).
//
// Pure: returns a new state (never mutates). Idempotent — the finding id is derived from
// the lex-first event id in each title-group, and synthesis resets relatedFindingIds
// before backfill runs, so re-running over the same events produces the same ids.
export function backfillHighSeverityFindings(
  state: InvestigationState,
  eligibleIds: ReadonlySet<string>,
  timestamp: string,
): InvestigationState {
  // Collect uncovered eligible events — except ones that sit in the same directory as a file an
  // already-DISMISSED finding cited (e.g. a bundled test corpus explained and dismissed elsewhere):
  // those are folded onto that finding's id instead of raising a new open one.
  const dismissed = dismissedEventPaths(state);
  const eligible: InvestigationState["forensicTimeline"] = [];
  const foldIntoDismissed = new Map<string, string>(); // event id -> dismissed finding id
  for (const e of state.forensicTimeline) {
    if (!HIGH_SEVERITY.has(e.severity)) continue;
    if (!eligibleIds.has(e.id)) continue;
    if (e.relatedFindingIds.length > 0) continue;
    const dismissingFindingId = dismissed.length > 0 ? findDismissingFinding(e, dismissed) : undefined;
    if (dismissingFindingId) {
      foldIntoDismissed.set(e.id, dismissingFindingId);
      continue;
    }
    eligible.push(e);
  }
  if (eligible.length === 0 && foldIntoDismissed.size === 0) return state;
  if (eligible.length === 0) {
    return {
      ...state,
      forensicTimeline: state.forensicTimeline.map((e) =>
        foldIntoDismissed.has(e.id)
          ? { ...e, relatedFindingIds: [...e.relatedFindingIds, foldIntoDismissed.get(e.id)!] }
          : e,
      ),
    };
  }

  // Group by shortTitle so near-identical events collapse into one finding.
  const groups = new Map<string, InvestigationState["forensicTimeline"]>();
  for (const e of eligible) {
    const title = shortTitle(e.description);
    const group = groups.get(title) ?? [];
    group.push(e);
    groups.set(title, group);
  }

  const newFindings: Finding[] = [];
  const linkByEvent = new Map<string, string>();

  for (const [title, events] of groups) {
    // Stable finding id: lex-first event id in the group.
    const repId = [...events].sort((a, b) => a.id.localeCompare(b.id))[0].id;
    const findingId = `f-auto-${repId}`;
    const repEvent = events.find((e) => e.id === repId)!;
    const severity: Severity = events.some((e) => e.severity === "Critical") ? "Critical" : "High";
    const mitre = [...new Set(events.flatMap((e) => e.mitreTechniques))];
    const screenshots = [...new Set(events.flatMap((e) => e.sourceScreenshots))];
    const firstSeen =
      events
        .map((e) => e.timestamp)
        .filter(Boolean)
        .sort()[0] || timestamp;
    const count = events.length;
    const suffix =
      count > 1
        ? ` (auto-flagged; ${count} similar ${severity}-severity events grouped under this title).`
        : ` (auto-flagged from a ${severity}-severity artifact row that had no finding).`;
    const sourceCount = new Set(events.flatMap((e) => e.sources ?? [])).size;
    const confidenceReason =
      sourceCount > 1
        ? `Deterministic backfill of an uncovered ${severity} event corroborated by ${sourceCount} distinct tools.`
        : `Deterministic backfill of an uncovered ${severity} event — a graded artifact row is treated as a confirmed finding.`;

    newFindings.push({
      id: findingId,
      severity,
      confidence: 100,
      confidenceReason,
      title,
      description: `${repEvent.description}${suffix}`,
      relatedIocs: [],
      mitreTechniques: mitre,
      sourceScreenshots: screenshots,
      firstSeen,
      lastUpdated: timestamp,
      status: "open",
    });

    for (const e of events) {
      linkByEvent.set(e.id, findingId);
    }
  }

  // Merge in the events folded onto an already-dismissed finding above — same shape as linkByEvent,
  // just resolving to an existing finding id instead of a newly-created one.
  for (const [eventId, findingId] of foldIntoDismissed) linkByEvent.set(eventId, findingId);

  return {
    ...state,
    findings: [...state.findings, ...newFindings],
    forensicTimeline: state.forensicTimeline.map((e) =>
      linkByEvent.has(e.id)
        ? { ...e, relatedFindingIds: [...e.relatedFindingIds, linkByEvent.get(e.id)!] }
        : e,
    ),
  };
}
