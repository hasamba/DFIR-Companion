import { z } from "zod";
import type { ForensicEvent } from "./stateTypes.js";
import { byEventTime } from "./forensicSort.js";
import type { TimelineGap } from "./gapDetect.js";
import { shadowArtifactsForGap, SHADOW_ARTIFACT_IDS, type ShadowArtifact } from "./shadowArtifacts.js";

// AI hypothesis generation for timeline gaps (issue #96 — the "what happened during the silence" half).
//
// The deterministic gap detector (gapDetect.ts) flags suspiciously long silent periods — a COMPLETE
// gap (every source dark) is the classic cleared-logs / stopped-collector signature. That tells the
// analyst SOMETHING is missing; this tells them WHAT likely filled it. A single text-only AI call
// reads each gap's bounding context — the events just BEFORE the silence (what the attacker was
// doing) and just AFTER (what state the host was in when logging resumed) — and hypothesizes the
// attacker actions that fit the hole, grounded ONLY in those surrounding events.
//
// The AI call lives in the pipeline (`hypothesizeGaps`); this module holds the PURE, unit-tested
// pieces: the lenient response schema (`.catch` everywhere like responseSchema.ts so a slightly-off
// reply still parses), the digest renderers that feed the model each gap's before/after context, the
// sanitizer, and `buildGapHypotheses` — which merges the AI hypothesis with the DETERMINISTIC
// shadow-artifact collections (shadowArtifacts.ts) so every flagged gap carries deployable Velociraptor
// collections to reconstruct the missing time frame, even one the model declined to hypothesize about.
//
// EPHEMERAL: like ask()/suggestHunts() the result is generated on demand and shown for review — it
// does NOT mutate InvestigationState. A hypothesis is a LEAD, not a verdict (the caveat is shown
// everywhere): the analyst confirms it by collecting the shadow artifacts and correlating.

const severityEnum = z.enum(["Critical", "High", "Medium", "Low", "Info"]);

// One per-gap hypothesis from the model. Every field is lenient so one off value never rejects the
// whole reply. `gapId` ties it back to the TimelineGap it explains (the model echoes the id shown).
export const gapHypothesisSchema = z.object({
  gapId: z.string().catch(""),                       // the [gap-N] id the hypothesis is for
  hypothesis: z.string().catch(""),                  // prose: what the attacker most likely did during the silence
  attackerActions: z.array(z.string()).catch([]),    // concrete actions that fit the gap (bullet points)
  confidence: z.number().catch(0),                   // 0..100, the model's confidence (clamped on sanitize)
  severity: severityEnum.catch("Medium"),            // how serious the hypothesised activity would be
  mitreTechniques: z.array(z.string()).catch([]),    // ATT&CK ids for the hypothesised actions
  recommendedArtifactIds: z.array(z.string()).catch([]), // shadow-artifact catalog ids to prioritise (subset of SHADOW_ARTIFACT_IDS)
});

export type GapHypothesisAI = z.infer<typeof gapHypothesisSchema>;

// The model returns { hypotheses: [...] }. `.catch` at every level keeps a partial reply usable.
export const gapHypothesesResponseSchema = z.object({
  hypotheses: z.array(gapHypothesisSchema).catch([]),
});

export type GapHypothesesResponse = z.infer<typeof gapHypothesesResponseSchema>;

// Default cap on how many gaps to hypothesise about per call (override via DFIR_GAP_HYPOTHESIS_MAX).
// Gaps arrive worst-first (complete/High before partial, longest first), so the cap keeps the most
// suspicious silences. A short, high-signal list beats hypotheses for every benign overnight quiet.
export const GAP_HYPOTHESIS_MAX_DEFAULT = 5;

// How many events on each side of a gap to feed the model as context. Enough to establish the
// attacker's pre-silence activity and post-silence state without flooding the prompt.
export const SURROUNDING_EVENTS_DEFAULT = 8;

const MAX_HYPOTHESIS_LEN = 2000;
const MAX_ACTION_LEN = 400;
const MAX_ACTIONS = 12;

// The shared "this is a lead, not a verdict" disclaimer for the hypothesis surface (panel + any report).
export const GAP_HYPOTHESIS_CAVEAT =
  "AI-generated hypotheses about what occurred during a silent period are leads, NOT proof — they are " +
  "inferred from the events surrounding the gap, not observed. Confirm by collecting the shadow artifacts " +
  "below (USN journal, SRUM, Prefetch, Amcache, …), which the OS keeps independently of the tampered log, " +
  "and correlating them against the gap window before drawing conclusions.";

// Whether there is anything to hypothesise about — at least one detected gap. With no gaps the route
// returns an empty result without spending an AI call.
export function hasGapMaterial(gaps: readonly TimelineGap[]): boolean {
  return (gaps?.length ?? 0) > 0;
}

// The events bounding a gap: the up-to-`n` events ending at the gap's start (what was happening
// before the silence) and the up-to-`n` starting at its resume (what logging showed afterwards).
// Located by the gap's bounding event ids against the time-sorted timeline, so duplicate timestamps
// don't misalign the window. Returns empty arrays when the bounding ids aren't found (shouldn't
// happen — gaps derive from these events — but stays safe).
export function surroundingEvents(
  gap: TimelineGap,
  events: readonly ForensicEvent[],
  n: number = SURROUNDING_EVENTS_DEFAULT,
): { before: ForensicEvent[]; after: ForensicEvent[] } {
  const span = Math.max(1, Math.floor(n));
  const sorted = [...events].sort(byEventTime);
  const beforeIdx = sorted.findIndex((e) => e.id === gap.beforeEventId);
  const afterIdx = sorted.findIndex((e) => e.id === gap.afterEventId);
  const before = beforeIdx >= 0 ? sorted.slice(Math.max(0, beforeIdx - span + 1), beforeIdx + 1) : [];
  const after = afterIdx >= 0 ? sorted.slice(afterIdx, afterIdx + span) : [];
  return { before, after };
}

function renderEventLine(e: ForensicEvent): string {
  const asset = e.asset ? ` <${e.asset}>` : "";
  return `[${e.id}] ${e.timestamp || "(undated)"} [${e.severity}]${asset} ${(e.description ?? "").replace(/\s+/g, " ").trim().slice(0, 240)}`;
}

// A text digest of ONE gap and its before/after context for the prompt — the gap's id/kind/duration/
// window/silent sources, then the events on each side. The model writes a hypothesis per gap keyed
// by the shown [gap-N] id.
export function renderGapForPrompt(
  gap: TimelineGap,
  before: readonly ForensicEvent[],
  after: readonly ForensicEvent[],
): string {
  const kind = gap.complete ? "complete silence (every source dark)" : "partial (one source quiet)";
  const silent = gap.silentSources.length ? gap.silentSources.join(", ") : "all sources";
  const active = gap.activeSources.length ? gap.activeSources.join(", ") : "—";
  const beforeText = before.length ? before.map(renderEventLine).join("\n") : "(no events recorded before)";
  const afterText = after.length ? after.map(renderEventLine).join("\n") : "(no events recorded after)";
  return [
    `### ${gap.id} [${gap.severity}] ${kind} — ${gap.durationLabel} of silence`,
    `Window: ${gap.startTimestamp} → ${gap.endTimestamp}`,
    `Silent sources: ${silent} | Still active during the gap: ${active}`,
    `EVENTS BEFORE THE SILENCE:`,
    beforeText,
    `EVENTS AFTER THE SILENCE:`,
    afterText,
  ].join("\n");
}

// The full gaps block for the prompt: each gap rendered with its surrounding events, in the order
// given (worst-first). `surroundByGapId` maps a gap id to its precomputed before/after events.
export function renderGapsForPrompt(
  gaps: readonly TimelineGap[],
  surroundByGapId: ReadonlyMap<string, { before: ForensicEvent[]; after: ForensicEvent[] }>,
): string {
  if (!gaps.length) return "(no gaps)";
  return gaps
    .map((g) => {
      const s = surroundByGapId.get(g.id) ?? { before: [], after: [] };
      return renderGapForPrompt(g, s.before, s.after);
    })
    .join("\n\n");
}

function dedupeStrings(arr: readonly string[]): string[] {
  return [...new Set(arr.map((s) => String(s).trim()).filter(Boolean))];
}

function clampConfidence(n: unknown): number {
  const v = Number(n);
  if (!Number.isFinite(v)) return 0;
  return Math.max(0, Math.min(100, Math.round(v)));
}

// Drop hypotheses for unknown gap ids, dedupe by gap (keep the first), clamp confidence to 0..100,
// trim/cap strings, dedupe technique + artifact-id lists (artifact ids filtered to the real catalog),
// and cap the count. Pure — deterministic, no I/O.
export function sanitizeGapHypotheses(
  raw: readonly GapHypothesisAI[] | undefined,
  validGapIds: ReadonlySet<string>,
  max: number = GAP_HYPOTHESIS_MAX_DEFAULT,
): GapHypothesisAI[] {
  const cap = Number.isFinite(max) && max > 0 ? Math.floor(max) : GAP_HYPOTHESIS_MAX_DEFAULT;
  const seen = new Set<string>();
  const out: GapHypothesisAI[] = [];
  for (const h of raw ?? []) {
    const gapId = String(h?.gapId ?? "").trim();
    if (!gapId || !validGapIds.has(gapId) || seen.has(gapId)) continue;
    seen.add(gapId);
    out.push({
      gapId,
      hypothesis: String(h?.hypothesis ?? "").trim().slice(0, MAX_HYPOTHESIS_LEN),
      attackerActions: dedupeStrings(h?.attackerActions ?? []).map((a) => a.slice(0, MAX_ACTION_LEN)).slice(0, MAX_ACTIONS),
      confidence: clampConfidence(h?.confidence),
      severity: h?.severity ?? "Medium",
      mitreTechniques: dedupeStrings(h?.mitreTechniques ?? []).slice(0, 20),
      recommendedArtifactIds: dedupeStrings(h?.recommendedArtifactIds ?? [])
        .map((id) => id.toLowerCase())
        .filter((id) => SHADOW_ARTIFACT_IDS.has(id))
        .slice(0, SHADOW_ARTIFACT_IDS.size),
    });
    if (out.length >= cap) break;
  }
  return out;
}

// One enriched gap result: the gap, the AI hypothesis (empty when the model skipped it), and the
// DETERMINISTIC shadow-artifact collections to reconstruct it. `recommendedArtifactIds` lets the UI
// highlight the artifacts the model judged most relevant; the full set is always offered.
export interface GapHypothesis {
  gapId: string;
  gap: TimelineGap;
  hypothesis: string;
  attackerActions: string[];
  confidence: number;
  severity: TimelineGap["severity"];
  mitreTechniques: string[];
  recommendedArtifactIds: string[];
  targetHosts: string[];
  shadowArtifacts: readonly ShadowArtifact[];
}

export interface GapHypothesesResult {
  hypotheses: GapHypothesis[];
  caveat: string;
}

// Merge the sanitized AI hypotheses with the deterministic shadow-artifact collections, producing one
// GapHypothesis per FOCUS gap (so a gap the model didn't address still carries its shadow artifacts —
// the reconstruction value is deterministic and must not depend on the AI answering). The hypothesis
// severity defaults to the gap's own severity when the model omitted it. Pure.
export function buildGapHypotheses(
  aiHypotheses: readonly GapHypothesisAI[],
  focusGaps: readonly TimelineGap[],
  surroundByGapId: ReadonlyMap<string, { before: ForensicEvent[]; after: ForensicEvent[] }>,
): GapHypothesesResult {
  const byId = new Map(aiHypotheses.map((h) => [h.gapId, h]));
  const hypotheses = focusGaps.map((gap) => {
    const ai = byId.get(gap.id);
    const surrounding = surroundByGapId.get(gap.id);
    const around = surrounding ? [...surrounding.before, ...surrounding.after] : [];
    const { targetHosts, artifacts } = shadowArtifactsForGap(gap, around);
    return {
      gapId: gap.id,
      gap,
      hypothesis: ai?.hypothesis ?? "",
      attackerActions: ai?.attackerActions ?? [],
      confidence: ai?.confidence ?? 0,
      severity: ai?.severity ?? gap.severity,
      mitreTechniques: ai?.mitreTechniques ?? [],
      recommendedArtifactIds: ai?.recommendedArtifactIds ?? [],
      targetHosts,
      shadowArtifacts: artifacts,
    };
  });
  return { hypotheses, caveat: GAP_HYPOTHESIS_CAVEAT };
}
