import { chronological, deriveStoryShape, parseTime, type CockpitStoryShape } from "./cockpitStoryShape.js";
import { tacticForTechniques, type IrisTactic } from "./mitreTactics.js";
import {
  SEVERITY_RANK,
  type Finding,
  type ForensicEvent,
  type InvestigationState,
  type Severity,
} from "./stateTypes.js";

// The cockpit's "Story so far" strip (#1487): the attack chain as the forensic timeline shows it,
// stage by stage in kill-chain order, plus the synthesis's two-sentence conclusion and how fresh
// that conclusion is. #1493 adds the chain's shape (span, dwell, hosts, accounts — see
// cockpitStoryShape.ts) and the stages the chain has no evidence for yet. Reads the forensic
// timeline ONLY — never the super-timeline (CLAUDE.md §7).

// Kill-chain order for the stage chips. Not the priority order mitreTactics.ts uses to pick ONE
// tactic per event — that one puts impact first; here the analyst reads left to right in time.
export const STORY_STAGE_ORDER: readonly IrisTactic[] = [
  "Initial Access",
  "Execution",
  "Persistence",
  "Privilege Escalation",
  "Defense Evasion",
  "Credential Access",
  "Discovery",
  "Lateral Movement",
  "Collection",
  "Command and Control",
  "Exfiltration",
  "Impact",
];
// Ids a stage chip hands to the timeline id filter. eventCount still counts every event.
export const STORY_STAGE_EVENT_LIMIT = 200;
// The conclusion and attacker path are teasers — the full text lives in their own panels.
const STORY_SENTENCE_LIMIT = 2;
const STORY_TEXT_MAX_CHARS = 320;
// The stage card's headline is one event's raw description; the client clamps it further.
const STORY_HEADLINE_MAX_CHARS = 400;
const ELLIPSIS = "…";

// The one synthMeta field the story reads. Structural on purpose: importing SynthMeta would add a
// workflow -> ai boundary edge that cockpit.ts already pays for (scripts/check-boundaries.mjs).
export interface StorySynthesisMeta {
  lastSynthesizedAt?: string;
}

export interface CockpitStoryHeadline {
  eventId: string;
  description: string;
}

export interface CockpitStoryFinding {
  id: string;
  title: string;
  severity: Severity;
}

export interface CockpitStoryStage {
  tactic: IrisTactic;
  firstSeenAt: string;
  host: string | null;
  eventCount: number;
  eventIds: string[];
  worstSeverity: Severity;
  headline: CockpitStoryHeadline | null;
  finding: CockpitStoryFinding | null;
}

export interface CockpitStory {
  stages: CockpitStoryStage[];
  // STORY_STAGE_ORDER minus the stages that have a card, in STORY_STAGE_ORDER order.
  missingStages: IrisTactic[];
  shape: CockpitStoryShape;
  conclusion: string;
  attackerPath: string;
  synthesizedAt: string | null;
  staleEventCount: number;
}

function capText(text: string, max: number): string {
  return text.length > max ? `${text.slice(0, max - 1)}${ELLIPSIS}` : text;
}

// The importers lead a description with provenance — "Velociraptor [Windows.Sigma.Base] Sigma:",
// "[Windows.EventLogs.Chainsaw] Chainsaw/Sigma:", "DetectRaptor Evtx detection:", "THOR Alert
// [Filescan]:" — which the card's two clamped lines cannot afford; the origin facet keeps it. Only
// the tool labels the importers emit are stripped, so a rule title such as "Scheduled task: …"
// keeps its own leading words. A description that is nothing but labels stays as it was.
const HEADLINE_ARTIFACT_PREFIX = /^(?:Velociraptor\s+)?(?:\[[^\]]+\]\s*)+/;
const HEADLINE_TOOL_LABEL =
  /^(?:(?:Chainsaw|Hayabusa)(?:\/[^:\n]{1,40})?|Sigma|Velociraptor detection|DetectRaptor \S+ detection|THOR \S+(?: \[[^\]]+\])?):\s*/;

function stripHeadlineProvenance(description: string): string {
  const bare = description.replace(HEADLINE_ARTIFACT_PREFIX, "").replace(HEADLINE_TOOL_LABEL, "").trim();
  return bare || description;
}

// The stage's most severe event. `ordered` is chronological with undated rows last, so on a
// severity tie the first hit is the earliest — and on a time tie, the earliest in the timeline.
function stageHeadline(ordered: readonly ForensicEvent[]): CockpitStoryHeadline | null {
  let top: ForensicEvent | undefined;
  for (const event of ordered) {
    if (!top || SEVERITY_RANK[event.severity] < SEVERITY_RANK[top.severity]) top = event;
  }
  const description = top?.description?.trim() ?? "";
  if (!top || !description) return null;
  return {
    eventId: top.id,
    description: capText(stripHeadlineProvenance(description), STORY_HEADLINE_MAX_CHARS),
  };
}

function linkedToStage(finding: Finding, events: readonly ForensicEvent[], eventIds: Set<string>): boolean {
  if ((finding.relatedEventIds ?? []).some((id) => eventIds.has(id))) return true;
  return events.some((event) => (event.relatedFindingIds ?? []).includes(finding.id));
}

// Worst severity first; a confirmed finding beats an open one; then the one seen first; then the
// id, so two findings that tie on everything else still pick the same card every render.
function compareFindings(a: Finding, b: Finding): number {
  return (
    SEVERITY_RANK[a.severity] - SEVERITY_RANK[b.severity] ||
    Number(b.status === "confirmed") - Number(a.status === "confirmed") ||
    compareTimes(parseTime(a.firstSeen), parseTime(b.firstSeen)) ||
    a.id.localeCompare(b.id)
  );
}

function compareTimes(a: number | null, b: number | null): number {
  if (a === null || b === null) return Number(a === null) - Number(b === null);
  return a - b;
}

// The finding the card names for this stage: linked to any of the stage's events in either
// direction (the finding cites the event, or the event cites the finding). A dismissed finding is
// an analyst's "no" — it never fronts a stage, whatever its severity.
function stageFinding(
  events: readonly ForensicEvent[],
  findings: readonly Finding[],
): CockpitStoryFinding | null {
  const eventIds = new Set(events.map((event) => event.id));
  const linked = findings
    .filter((finding) => finding.status !== "dismissed" && linkedToStage(finding, events, eventIds))
    .sort(compareFindings);
  const top = linked[0];
  return top ? { id: top.id, title: top.title, severity: top.severity } : null;
}

function buildStage(
  tactic: IrisTactic,
  events: readonly ForensicEvent[],
  findings: readonly Finding[],
): CockpitStoryStage {
  const ordered = chronological(events);
  const earliest = ordered.find((event) => parseTime(event.timestamp) !== null);
  const headline = stageHeadline(ordered);
  return {
    tactic,
    firstSeenAt: earliest?.timestamp ?? "",
    host: earliest?.asset?.trim() || null,
    eventCount: ordered.length,
    eventIds: ordered.slice(0, STORY_STAGE_EVENT_LIMIT).map((event) => event.id),
    worstSeverity: ordered.reduce<Severity>(
      (worst, event) => (SEVERITY_RANK[event.severity] < SEVERITY_RANK[worst] ? event.severity : worst),
      "Info",
    ),
    headline,
    finding: stageFinding(ordered, findings),
  };
}

interface StagedEvent {
  event: ForensicEvent;
  tactic: IrisTactic;
}

// The events the story is made of: graded above Info and mapped to a tactic. Timeline order kept.
// One filter feeds both the stage cards and the shape, so the two can never disagree on the set.
function stagedEvents(events: readonly ForensicEvent[]): StagedEvent[] {
  const staged: StagedEvent[] = [];
  for (const event of events) {
    if (event.severity === "Info") continue;
    const tactic = tacticForTechniques(event.mitreTechniques ?? [], event.description ?? "");
    if (tactic) staged.push({ event, tactic });
  }
  return staged;
}

function storyStages(staged: readonly StagedEvent[], findings: readonly Finding[]): CockpitStoryStage[] {
  const byTactic = new Map<IrisTactic, ForensicEvent[]>();
  for (const { event, tactic } of staged) byTactic.set(tactic, [...(byTactic.get(tactic) ?? []), event]);
  return STORY_STAGE_ORDER.filter((tactic) => byTactic.has(tactic)).map((tactic) =>
    buildStage(tactic, byTactic.get(tactic) ?? [], findings),
  );
}

function missingStages(stages: readonly CockpitStoryStage[]): IrisTactic[] {
  const present = new Set(stages.map((stage) => stage.tactic));
  return STORY_STAGE_ORDER.filter((tactic) => !present.has(tactic));
}

// Synthesis writes the attacker path as a Markdown list ("1. **Initial Access** — …"). A teaser
// paints as plain text, so the list markers and emphasis go, and a bare "1." is never a sentence.
function plainText(text: string): string {
  return String(text ?? "")
    .replace(/^\s*(?:\d+[.)]|[-*•#]+)\s+/gm, "")
    .replace(/(\*\*|__|`)/g, "");
}

// First STORY_SENTENCE_LIMIT sentences of a narrative, terminal punctuation kept, whitespace
// collapsed. A sentence-less wall of text is one sentence, so the char cap is what bounds it.
function leadSentences(text: string): string {
  const collapsed = plainText(text).replace(/\s+/g, " ").trim();
  if (!collapsed) return "";
  // A sentence ends at ".", "!" or "?" followed by whitespace — so "1.5 GB" or "e.g." mid-token
  // never splits, and the boundary's punctuation stays with its sentence.
  const lead = collapsed
    .split(/(?<=[.!?])\s+/)
    .slice(0, STORY_SENTENCE_LIMIT)
    .join(" ");
  return capText(lead, STORY_TEXT_MAX_CHARS);
}

// Rows this case received AFTER the conclusion was written — the conclusion cannot know them.
// `importedAt` is absent on rows that never came through the import seam; those cannot be dated
// against the synthesis, so they never count as stale.
function staleEventCount(events: readonly ForensicEvent[], synthesizedAt: string | null): number {
  const floor = parseTime(synthesizedAt ?? undefined);
  if (floor === null) return 0;
  return events.filter((event) => {
    const imported = parseTime(event.importedAt);
    return imported !== null && imported > floor;
  }).length;
}

export function deriveCockpitStory(state: InvestigationState, synthMeta?: StorySynthesisMeta): CockpitStory {
  const synthesizedAt = synthMeta?.lastSynthesizedAt?.trim() || null;
  const staged = stagedEvents(state.forensicTimeline);
  const stages = storyStages(staged, state.findings);
  return {
    stages,
    missingStages: missingStages(stages),
    shape: deriveStoryShape(staged.map((item) => item.event)),
    conclusion: leadSentences(state.lastSummary),
    attackerPath: leadSentences(state.attackerPath),
    synthesizedAt,
    staleEventCount: staleEventCount(state.forensicTimeline, synthesizedAt),
  };
}
