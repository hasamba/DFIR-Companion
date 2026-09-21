import { tacticForTechniques, type IrisTactic } from "./mitreTactics.js";
import type { ForensicEvent, InvestigationState } from "./stateTypes.js";

// The cockpit's "Story so far" strip (#1487): the attack chain as the forensic timeline shows it,
// stage by stage in kill-chain order, plus the synthesis's two-sentence conclusion and how fresh
// that conclusion is. Reads the forensic timeline ONLY — never the super-timeline (CLAUDE.md §7).

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
const ELLIPSIS = "…";

// The one synthMeta field the story reads. Structural on purpose: importing SynthMeta would add a
// workflow -> ai boundary edge that cockpit.ts already pays for (scripts/check-boundaries.mjs).
export interface StorySynthesisMeta {
  lastSynthesizedAt?: string;
}

export interface CockpitStoryStage {
  tactic: IrisTactic;
  firstSeenAt: string;
  host: string | null;
  eventCount: number;
  eventIds: string[];
}

export interface CockpitStory {
  stages: CockpitStoryStage[];
  conclusion: string;
  attackerPath: string;
  synthesizedAt: string | null;
  staleEventCount: number;
}

function parseTime(value: string | undefined): number | null {
  if (!value) return null;
  const time = Date.parse(value);
  return Number.isFinite(time) ? time : null;
}

// Timestamped events first, oldest first; undated events keep their timeline order at the end so
// they count and can be filtered to, but never decide firstSeenAt.
function chronological(events: readonly ForensicEvent[]): ForensicEvent[] {
  return events
    .map((event, index) => ({ event, index, time: parseTime(event.timestamp) }))
    .sort((a, b) => {
      if (a.time === null || b.time === null)
        return Number(a.time === null) - Number(b.time === null) || a.index - b.index;
      return a.time - b.time || a.index - b.index;
    })
    .map((item) => item.event);
}

function buildStage(tactic: IrisTactic, events: readonly ForensicEvent[]): CockpitStoryStage {
  const ordered = chronological(events);
  const earliest = ordered.find((event) => parseTime(event.timestamp) !== null);
  return {
    tactic,
    firstSeenAt: earliest?.timestamp ?? "",
    host: earliest?.asset?.trim() || null,
    eventCount: ordered.length,
    eventIds: ordered.slice(0, STORY_STAGE_EVENT_LIMIT).map((event) => event.id),
  };
}

function storyStages(events: readonly ForensicEvent[]): CockpitStoryStage[] {
  const byTactic = new Map<IrisTactic, ForensicEvent[]>();
  for (const event of events) {
    if (event.severity === "Info") continue;
    const tactic = tacticForTechniques(event.mitreTechniques ?? [], event.description ?? "");
    if (!tactic) continue;
    byTactic.set(tactic, [...(byTactic.get(tactic) ?? []), event]);
  }
  return STORY_STAGE_ORDER.filter((tactic) => byTactic.has(tactic)).map((tactic) =>
    buildStage(tactic, byTactic.get(tactic) ?? []),
  );
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
  return lead.length > STORY_TEXT_MAX_CHARS ? `${lead.slice(0, STORY_TEXT_MAX_CHARS - 1)}${ELLIPSIS}` : lead;
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
  return {
    stages: storyStages(state.forensicTimeline),
    conclusion: leadSentences(state.lastSummary),
    attackerPath: leadSentences(state.attackerPath),
    synthesizedAt,
    staleEventCount: staleEventCount(state.forensicTimeline, synthesizedAt),
  };
}
