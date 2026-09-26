import { AUTO_FINDING_ID_PREFIX } from "./responseSchema.js";
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

// ── Twins of an event a finding already cites (#1556) ──────────────────────────────────────────
//
// Coverage used to be exact event-id only. Two real shapes slipped through it and each minted an
// f-auto-* finding that repeated a fact the model had already reported:
//   - Chainsaw fires two Sigma rules on ONE process (Renamed AdFind + PUA AdFind). The model cites
//     one row; the sibling row is the same command, but counted as uncovered.
//   - THOR LogScan repeats a logged command line at SCAN time. Nothing tied the repeat to the
//     original Sysmon row a finding cites.
// So an uncovered event whose command line (or, when it has none, image + moment) matches an event
// a non-auto finding cites is linked onto THAT finding instead. Same host only, never onto a
// dismissed finding, and only a link is added — no event or finding changes severity.

// Shorter normalized command lines match too much by suffix (`/c`, `-enc x`) to prove a twin.
const MIN_COMMAND_KEY_LENGTH = 16;
// Chainsaw and THOR stamp the same logged record a few milliseconds apart (…35.254 vs …35.258).
const TWIN_MOMENT_TOLERANCE_MS = 1000;
const ISO_TIMESTAMP = /\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?/g;
const HOST_SUFFIX = /\s+@\s+\S+\s*$/;

type Twin = Pick<ForensicEvent, "description" | "commandLine" | "path" | "timestamp" | "asset">;

// The command line a row carries: Chainsaw's `CommandLine=` field, THOR's `lowfi: image(cmd)`, or the
// structured field an importer set.
function rawCommandLine(e: Twin): string | undefined {
  const text = e.description.replace(HOST_SUFFIX, "");
  const chainsaw = /(?<!Parent)CommandLine=(.+?)(?: - ParentImage=|$)/.exec(text);
  if (chainsaw) return chainsaw[1];
  const lowfi = /lowfi: [^(]*\((.*)\)/.exec(text);
  return lowfi ? lowfi[1] : e.commandLine;
}

// Comparable form: no Chainsaw `…` head, no executable path, no double quotes (THOR drops them),
// single spaces, lowercase.
function commandKey(e: Twin): string | undefined {
  const raw = rawCommandLine(e);
  if (!raw) return undefined;
  const key = raw
    .trim()
    .replace(/^…\s*/, "")
    .replace(/^"[^"]*"\s*|^\S+\.exe(?=\s|$)\s*/i, "")
    .replace(/"/g, "")
    .replace(/\s+/g, " ")
    .trim()
    .toLowerCase();
  return key.length >= MIN_COMMAND_KEY_LENGTH ? key : undefined;
}

// Chainsaw cuts the HEAD of a long command line, so the shorter key only has to end the longer one.
function sameCommand(a: string, b: string): boolean {
  return a.endsWith(b) || b.endsWith(a);
}

function imageOf(e: Twin): string | undefined {
  const image =
    /(?<!Parent)Image=(.+?)(?: - |$)/.exec(e.description.replace(HOST_SUFFIX, ""))?.[1] ??
    /lowfi: ([^(]+)\(/.exec(e.description)?.[1] ??
    e.path;
  return image?.trim().toLowerCase() || undefined;
}

// When the record happened: the logged time a scanner quotes in its text (THOR), else the row's own.
// A quoted time with no zone is the log's UTC.
function momentOf(e: Twin): number {
  const quoted = e.description.match(ISO_TIMESTAMP)?.[0];
  const iso = quoted && !/(?:Z|[+-]\d{2}:?\d{2})$/.test(quoted) ? `${quoted}Z` : (quoted ?? e.timestamp);
  return Date.parse(iso);
}

function sameHost(a: Twin, b: Twin): boolean {
  return (a.asset ?? "").trim().toLowerCase() === (b.asset ?? "").trim().toLowerCase();
}

function isTwin(event: Twin, cited: Twin): boolean {
  if (!sameHost(event, cited)) return false;
  const a = commandKey(event);
  const b = commandKey(cited);
  if (a && b) return sameCommand(a, b);
  const image = imageOf(event);
  if (!image || image !== imageOf(cited)) return false;
  const gap = Math.abs(momentOf(event) - momentOf(cited));
  return Number.isFinite(gap) && gap <= TWIN_MOMENT_TOLERANCE_MS;
}

// Every event a live (not dismissed) non-auto finding cites, with the finding that cites it — from
// both directions of the link, as the synthesis merge reads them.
function citedEvents(state: InvestigationState): { event: ForensicEvent; findingId: string }[] {
  const live = new Set(
    state.findings
      .filter((f) => f.status !== "dismissed" && !f.id.startsWith(AUTO_FINDING_ID_PREFIX))
      .map((f) => f.id),
  );
  if (live.size === 0) return [];
  const eventById = new Map(state.forensicTimeline.map((e) => [e.id, e] as const));
  const out: { event: ForensicEvent; findingId: string }[] = [];
  for (const e of state.forensicTimeline) {
    for (const fid of e.relatedFindingIds) if (live.has(fid)) out.push({ event: e, findingId: fid });
  }
  for (const f of state.findings) {
    if (!live.has(f.id)) continue;
    for (const eid of f.relatedEventIds ?? []) {
      const event = eventById.get(eid);
      if (event) out.push({ event, findingId: f.id });
    }
  }
  return out;
}

function findTwinFinding(
  event: ForensicEvent,
  cited: { event: ForensicEvent; findingId: string }[],
): string | undefined {
  return cited.find((c) => c.event.id !== event.id && isTwin(event, c.event))?.findingId;
}

// The grouping title: a per-row timestamp (THOR quotes the logged time in every row) would make
// every row its own group, so it is cut before the first sentence is taken (#1556).
function groupTitle(description: string): string {
  return shortTitle(description.replace(ISO_TIMESTAMP, "").replace(/\s{2,}/g, " "));
}

// Deterministic safety net for the heuristic "a Critical/High artifact row is almost
// always a finding". After synthesis, any eligible (in-scope, non-legitimate)
// Critical/High forensic event that synthesis left WITHOUT a linked finding gets an
// auto-generated finding, so a high-severity detection can never be silently missed.
//
// Events are GROUPED by their shortTitle (per-row timestamps cut first, #1556) before creating
// findings, so a burst of near-identical detections (e.g. 30 Windows Defender hits from one Sigma
// rule) becomes ONE finding + ONE playbook task rather than one per event.
//
// An event is NOT backfilled into a new open finding if it sits in the same directory as a file an
// already-DISMISSED finding cited — it's linked onto that finding instead (INC-2026-018: a finding
// explaining a bundled test-tool's own false-positive corpus by directory shouldn't leave a dozen more
// events from that same directory to resurface as separate, un-triaged open High findings).
//
// Nor is it backfilled when it is the TWIN of an event a live non-auto finding cites — same host,
// same command line (or same image at the same moment). It is linked onto that finding (#1556).
//
// Pure: returns a new state (never mutates). Idempotent — the finding id is derived from
// the lex-first event id in each title-group, and synthesis resets relatedFindingIds
// before backfill runs, so re-running over the same events produces the same ids.
export function backfillHighSeverityFindings(
  state: InvestigationState,
  eligibleIds: ReadonlySet<string>,
  timestamp: string,
): InvestigationState {
  const { eligible, foldOnto } = partitionUncovered(state, eligibleIds);
  if (eligible.length === 0 && foldOnto.size === 0) return state;

  // The model may echo a finding a PREVIOUS backfill minted — retitled, re-graded — without citing
  // its events, so they read as uncovered again. Minting the same id a second time put two rows
  // with one id in the case (#1556); the events are linked onto the finding already there instead.
  const existingIds = new Set(state.findings.map((f) => f.id));
  const newFindings: Finding[] = [];
  const linkByEvent = new Map(foldOnto);
  for (const [title, events] of groupByTitle(eligible)) {
    // Stable finding id: lex-first event id in the group.
    const repId = [...events].sort((a, b) => a.id.localeCompare(b.id))[0].id;
    const findingId = `${AUTO_FINDING_ID_PREFIX}${repId}`;
    if (!existingIds.has(findingId)) newFindings.push(buildFinding(findingId, title, events, timestamp));
    for (const e of events) linkByEvent.set(e.id, findingId);
  }

  return {
    ...state,
    findings: newFindings.length > 0 ? [...state.findings, ...newFindings] : state.findings,
    forensicTimeline: state.forensicTimeline.map((e) =>
      linkByEvent.has(e.id)
        ? { ...e, relatedFindingIds: [...e.relatedFindingIds, linkByEvent.get(e.id)!] }
        : e,
    ),
  };
}

// An f-auto-* finding's tags ARE the union of its cited events' tags (buildFinding below). Synthesis
// rebuilds findings from the model's delta, and the model may echo an f-auto id with other tags —
// the backfill then sees the id already present and does not rebuild it, so the model's tags won
// (#1684: T1021.002 + T1570 became T1105 + T1059.001 with no new evidence). This re-derives them
// from the events linked in either direction. A finding whose events carry no tags keeps what it
// has: there is nothing to derive from. Model findings are left alone. Pure.
export function rederiveAutoFindingTechniques(state: InvestigationState): InvestigationState {
  const eventById = new Map(state.forensicTimeline.map((e) => [e.id, e] as const));
  const derived = new Map<string, Set<string>>();
  const add = (findingId: string, e: ForensicEvent | undefined): void => {
    if (!e || !findingId.startsWith(AUTO_FINDING_ID_PREFIX)) return;
    const set = derived.get(findingId) ?? new Set<string>();
    for (const t of e.mitreTechniques) set.add(t);
    derived.set(findingId, set);
  };
  for (const e of state.forensicTimeline) for (const fid of e.relatedFindingIds) add(fid, e);
  for (const f of state.findings) for (const eid of f.relatedEventIds ?? []) add(f.id, eventById.get(eid));

  let changed = false;
  const findings = state.findings.map((f) => {
    const tags = derived.get(f.id);
    if (!tags?.size) return f;
    const next = [...tags];
    const same = next.length === f.mitreTechniques.length && next.every((t) => f.mitreTechniques.includes(t));
    if (same) return f;
    changed = true;
    return { ...f, mitreTechniques: next };
  });
  return changed ? { ...state, findings } : state;
}

// Uncovered eligible High/Critical events, split into the ones that need a new finding and the ones
// an existing finding already explains (event id -> that finding's id): a dismissed corpus-level
// finding over the same directory, or a live finding citing the event's twin (#1556).
function partitionUncovered(
  state: InvestigationState,
  eligibleIds: ReadonlySet<string>,
): { eligible: ForensicEvent[]; foldOnto: Map<string, string> } {
  const dismissed = dismissedEventPaths(state);
  const cited = citedEvents(state);
  const eligible: ForensicEvent[] = [];
  const foldOnto = new Map<string, string>();
  for (const e of state.forensicTimeline) {
    if (!HIGH_SEVERITY.has(e.severity)) continue;
    if (!eligibleIds.has(e.id)) continue;
    if (e.relatedFindingIds.length > 0) continue;
    const explainedBy =
      (dismissed.length > 0 ? findDismissingFinding(e, dismissed) : undefined) ??
      (cited.length > 0 ? findTwinFinding(e, cited) : undefined);
    if (explainedBy) foldOnto.set(e.id, explainedBy);
    else eligible.push(e);
  }
  return { eligible, foldOnto };
}

function groupByTitle(events: ForensicEvent[]): Map<string, ForensicEvent[]> {
  const groups = new Map<string, ForensicEvent[]>();
  for (const e of events) {
    const title = groupTitle(e.description);
    groups.set(title, [...(groups.get(title) ?? []), e]);
  }
  return groups;
}

function buildFinding(findingId: string, title: string, events: ForensicEvent[], timestamp: string): Finding {
  const repEvent = events.find((e) => findingId === `${AUTO_FINDING_ID_PREFIX}${e.id}`)!;
  const severity: Severity = events.some((e) => e.severity === "Critical") ? "Critical" : "High";
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
  return {
    id: findingId,
    severity,
    confidence: 100,
    confidenceReason,
    title,
    description: `${repEvent.description}${suffix}`,
    relatedIocs: [],
    mitreTechniques: [...new Set(events.flatMap((e) => e.mitreTechniques))],
    sourceScreenshots: [...new Set(events.flatMap((e) => e.sourceScreenshots))],
    firstSeen,
    lastUpdated: timestamp,
    status: "open",
  };
}
