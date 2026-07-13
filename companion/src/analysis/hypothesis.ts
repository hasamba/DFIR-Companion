import { z } from "zod";

// Hypothesis-driven investigation mode (issue #140 — the umbrella surface).
//
// An explicit, status-tracked hypothesis the analyst proposes (or synthesis auto-generates) and
// resolves across the investigation lifecycle — "Initial access was phishing", "Data was staged
// before encryption". Each carries the evidence that supports it (forensic-event ids), the IOCs and
// ATT&CK techniques it implicates, an expected-outcome ("what would prove/disprove this"), and a
// status workflow (open → supported / refuted / unknown). Kept in a per-case side file
// (`state/hypotheses.json`) — NOT in InvestigationState, so synthesis never WIPES them (mirrors
// comments.json / tags.json / notebook.json). Survives synthesis resets and snapshots.
//
// This module is the PURE, unit-tested core (types + lenient schema + the merge/sanitize transforms);
// the I/O wrapper is `hypothesisStore.ts` and the synthesis auto-gen call lives in the pipeline.
//
// Auto-generation durability — the crux. Synthesis rewrites the case conclusions wholesale, so an
// auto-generated hypothesis must REFRESH (re-worded each run) WITHOUT clobbering analyst reasoning.
// The rule mirrors playbook.ts `mergePlaybook`: a synthesis hypothesis is keyed by a STABLE
// `sourceKey` (FNV-1a of its normalized title, like huntOutcomes.ts). A PRISTINE one (the analyst
// never touched it) is refreshed from the new seed, and pruned if synthesis stops proposing it. The
// moment the analyst touches it (`analystTouched`, set on any PATCH) it FREEZES — synthesis no longer
// overwrites its text, status, notes, assignee, or evidence links. Analyst-authored hypotheses
// (source "analyst") are never touched by the merge at all.

export const HYPOTHESIS_STATUSES = ["open", "supported", "refuted", "unknown"] as const;
export type HypothesisStatus = (typeof HYPOTHESIS_STATUSES)[number];

export const HYPOTHESIS_SOURCES = ["analyst", "synthesis"] as const;
export type HypothesisSource = (typeof HYPOTHESIS_SOURCES)[number];

// Lenient (.catch / .default everywhere) so one off field in a hand-edited or older file never
// rejects the whole array — same posture as responseSchema.ts and the other side-file stores.
export const hypothesisSchema = z.object({
  id: z.string(),
  title: z.string(),
  description: z.string().default("").catch(""),
  expectedOutcome: z.string().default("").catch(""),   // what would prove/disprove this hypothesis
  status: z.enum(HYPOTHESIS_STATUSES).default("open").catch("open"),
  relatedTechniques: z.array(z.string()).default([]).catch([]), // ATT&CK ids (T1566, T1021.006…)
  relatedEventIds: z.array(z.string()).default([]).catch([]),   // supporting forensic-event ids
  relatedIocIds: z.array(z.string()).default([]).catch([]),     // implicated IOC ids
  // ACH-style analysis (investigation-guidance #14). `contradictingEventIds` are events INCONSISTENT
  // with this explanation — tracked so a hypothesis is judged by fewest contradictions (ACH), not most
  // support, and a red herring can't sail through unopposed. `discriminator` names the single artifact
  // (host + artifact) that would best separate this hypothesis from the leading alternative — it doubles
  // as a concrete collection directive. `exhausted` is set deterministically once N linked hunts came
  // back empty against `expectedOutcome` (see markExhaustedHypotheses) → it feeds the negative-knowledge
  // synthesis block; `exhaustedReason` is the human one-liner.
  contradictingEventIds: z.array(z.string()).default([]).catch([]),
  discriminator: z.string().default("").catch(""),
  exhausted: z.boolean().default(false).catch(false),
  exhaustedReason: z.string().default("").catch(""),
  assignee: z.string().default("").catch(""),
  notes: z.string().default("").catch(""),
  source: z.enum(HYPOTHESIS_SOURCES).default("analyst").catch("analyst"),
  // True once the analyst has edited this hypothesis via PATCH. Freezes a synthesis hypothesis
  // against auto-refresh/prune. Always effectively true for analyst-authored ones.
  analystTouched: z.boolean().default(false).catch(false),
  // Immediate FP cascade (investigation-guidance #12): set when a supporting event/IOC of this
  // hypothesis was just marked false positive, so the dashboard flags it for the analyst to re-judge.
  // A pristine (untouched) hypothesis is ALSO flipped to `unknown`; a touched one keeps its status
  // (freeze contract) and only carries the flag. Cleared on analyst PATCH and on synthesis refresh.
  needsReview: z.boolean().default(false).catch(false),
  // Stable derive key for a synthesis hypothesis (= its id). Absent for analyst-authored ones.
  sourceKey: z.string().optional(),
  author: z.string().optional(),
  createdAt: z.string(),
  updatedAt: z.string(),
});

export type Hypothesis = z.infer<typeof hypothesisSchema>;
export const hypothesesSchema = z.array(hypothesisSchema).catch([]);

// One auto-generated hypothesis distilled from a synthesis response, after sanitization. Carries the
// stable sourceKey so re-synthesis refreshes the matching stored hypothesis instead of duplicating.
export interface HypothesisSeed {
  sourceKey: string;
  title: string;
  description: string;
  expectedOutcome: string;
  status: HypothesisStatus;
  relatedTechniques: string[];
  relatedEventIds: string[];
  relatedIocIds: string[];
  contradictingEventIds: string[]; // ACH (#14): events inconsistent with this explanation
  discriminator: string;           // ACH (#14): the artifact (host + artifact) that best separates it
}

// Fields an analyst may set when creating a hypothesis by hand (or promoting a notebook entry).
export interface NewHypothesis {
  title: string;
  description?: string;
  expectedOutcome?: string;
  status?: HypothesisStatus;
  relatedTechniques?: string[];
  relatedEventIds?: string[];
  relatedIocIds?: string[];
  assignee?: string;
  notes?: string;
  author?: string;
}

// Fields an analyst may PATCH on an existing hypothesis. Any patch marks it analystTouched.
export type HypothesisPatch = Partial<
  Pick<
    Hypothesis,
    | "title"
    | "description"
    | "expectedOutcome"
    | "status"
    | "relatedTechniques"
    | "relatedEventIds"
    | "relatedIocIds"
    | "contradictingEventIds"
    | "discriminator"
    | "assignee"
    | "notes"
  >
>;

export const HYPOTHESIS_MAX_DEFAULT = 8; // cap on auto-generated hypotheses kept per synthesis
const MAX_TITLE_LEN = 200;
const MAX_TEXT_LEN = 2000;
const MAX_TECHNIQUES = 30;
const MAX_LINKS = 200;

function dedupeStrings(arr: readonly string[] | undefined): string[] {
  return [...new Set((arr ?? []).map((s) => String(s).trim()).filter(Boolean))];
}

// Whitespace-normalize a title so two formattings fingerprint identically. Lowercased — unlike VQL,
// a hypothesis title is prose and case is not semantically significant for dedup.
export function normalizeTitle(title: string): string {
  return String(title ?? "").replace(/\s+/g, " ").trim().toLowerCase();
}

// Deterministic FNV-1a fingerprint of the normalized title — the stable auto-gen dedup/refresh key
// (mirrors huntOutcomes.ts `vqlFingerprint`). Empty title → "" so a blank seed never collides.
export function hypothesisAutoKey(title: string): string {
  const norm = normalizeTitle(title);
  if (!norm) return "";
  let h = 0x811c9dc5;
  for (let i = 0; i < norm.length; i++) {
    h ^= norm.charCodeAt(i);
    h = Math.imul(h, 0x01000193);
  }
  return `synth:${(h >>> 0).toString(16)}`;
}

const VALID_STATUS = new Set<string>(HYPOTHESIS_STATUSES);

// Turn raw synthesis hypotheses into clean, deterministic seeds: require a title (skip blanks),
// trim/cap prose, coerce status to the enum (default open), dedupe techniques, filter evidence links
// to ids that actually exist in the case (so the model can't invent dangling references), dedupe by
// sourceKey, and cap the count. Pure — no I/O, no clock.
export function sanitizeHypotheses(
  raw: readonly unknown[] | undefined,
  validEventIds: ReadonlySet<string>,
  validIocIds: ReadonlySet<string>,
  max: number = HYPOTHESIS_MAX_DEFAULT,
): HypothesisSeed[] {
  const cap = Number.isFinite(max) && max > 0 ? Math.floor(max) : HYPOTHESIS_MAX_DEFAULT;
  const seen = new Set<string>();
  const out: HypothesisSeed[] = [];
  for (const item of raw ?? []) {
    const h = (item ?? {}) as Record<string, unknown>;
    const title = String(h.title ?? "").trim().slice(0, MAX_TITLE_LEN);
    if (!title) continue;
    const sourceKey = hypothesisAutoKey(title);
    if (!sourceKey || seen.has(sourceKey)) continue;
    seen.add(sourceKey);
    const status = String(h.status ?? "").trim().toLowerCase();
    out.push({
      sourceKey,
      title,
      description: String(h.description ?? "").trim().slice(0, MAX_TEXT_LEN),
      expectedOutcome: String(h.expectedOutcome ?? "").trim().slice(0, MAX_TEXT_LEN),
      status: VALID_STATUS.has(status) ? (status as HypothesisStatus) : "open",
      relatedTechniques: dedupeStrings(h.relatedTechniques as string[]).slice(0, MAX_TECHNIQUES),
      relatedEventIds: dedupeStrings(h.relatedEventIds as string[]).filter((id) => validEventIds.has(id)).slice(0, MAX_LINKS),
      relatedIocIds: dedupeStrings(h.relatedIocIds as string[]).filter((id) => validIocIds.has(id)).slice(0, MAX_LINKS),
      // ACH (#14): contradicting events must be REAL case events too (no invented refs); discriminator is prose.
      contradictingEventIds: dedupeStrings(h.contradictingEventIds as string[]).filter((id) => validEventIds.has(id)).slice(0, MAX_LINKS),
      discriminator: String(h.discriminator ?? "").trim().slice(0, MAX_TEXT_LEN),
    });
    if (out.length >= cap) break;
  }
  return out;
}

export interface MergeHypothesesResult {
  hypotheses: Hypothesis[];
  changed: boolean;
}

// A synthesis hypothesis the analyst has never touched — safe to refresh from a new seed or prune
// when synthesis stops proposing it. Analyst-authored ones and any touched ones are always kept.
function isPristineSynthesis(h: Hypothesis): boolean {
  return h.source === "synthesis" && !h.analystTouched;
}

function seedDiffersFrom(h: Hypothesis, seed: HypothesisSeed): boolean {
  return (
    h.title !== seed.title ||
    h.description !== seed.description ||
    h.expectedOutcome !== seed.expectedOutcome ||
    h.status !== seed.status ||
    h.relatedTechniques.join(" ") !== seed.relatedTechniques.join(" ") ||
    h.relatedEventIds.join(" ") !== seed.relatedEventIds.join(" ") ||
    h.relatedIocIds.join(" ") !== seed.relatedIocIds.join(" ") ||
    h.contradictingEventIds.join(" ") !== (seed.contradictingEventIds ?? []).join(" ") ||
    h.discriminator !== (seed.discriminator ?? "")
  );
}

// Merge freshly-sanitized synthesis seeds into the stored hypotheses. A synthesis hypothesis is keyed
// by its sourceKey (which IS its id). For a seed matching a PRISTINE stored hypothesis we REFRESH it
// (synthesis may have reworded it or found new supporting events). A TOUCHED synthesis hypothesis is
// frozen — left exactly as the analyst left it. A seed with no match is appended fresh (open,
// untouched). A pristine synthesis hypothesis whose seed disappeared is PRUNED; touched ones and every
// analyst-authored hypothesis are always kept. Pure + deterministic: pass `now` in so there's no clock
// dependency, and id = sourceKey so re-running with the same titles never duplicates.
export function mergeHypotheses(
  existing: readonly Hypothesis[],
  seeds: readonly HypothesisSeed[],
  now: string,
): MergeHypothesesResult {
  const result = existing.map((h) => ({ ...h }));
  const byKey = new Map(result.filter((h) => h.sourceKey).map((h) => [h.sourceKey as string, h] as const));
  let changed = false;

  for (const seed of seeds) {
    const cur = byKey.get(seed.sourceKey);
    if (cur) {
      if (!cur.analystTouched && seedDiffersFrom(cur, seed)) {
        const idx = result.findIndex((h) => h.id === cur.id);
        result[idx] = {
          ...result[idx],
          title: seed.title,
          description: seed.description,
          expectedOutcome: seed.expectedOutcome,
          status: seed.status,
          relatedTechniques: [...seed.relatedTechniques],
          relatedEventIds: [...seed.relatedEventIds],
          relatedIocIds: [...seed.relatedIocIds],
          contradictingEventIds: [...(seed.contradictingEventIds ?? [])],   // ACH (#14)
          discriminator: seed.discriminator ?? "",
          needsReview: false,   // authoritative refresh clears any interim FP-cascade flag (#12)
          updatedAt: now,
        };
        changed = true;
      }
    } else {
      const fresh: Hypothesis = {
        id: seed.sourceKey,
        title: seed.title,
        description: seed.description,
        expectedOutcome: seed.expectedOutcome,
        status: seed.status,
        relatedTechniques: [...seed.relatedTechniques],
        relatedEventIds: [...seed.relatedEventIds],
        relatedIocIds: [...seed.relatedIocIds],
        contradictingEventIds: [...(seed.contradictingEventIds ?? [])],   // ACH (#14)
        discriminator: seed.discriminator ?? "",
        exhausted: false,
        exhaustedReason: "",
        assignee: "",
        notes: "",
        source: "synthesis",
        analystTouched: false,
        needsReview: false,
        sourceKey: seed.sourceKey,
        createdAt: now,
        updatedAt: now,
      };
      result.push(fresh);
      byKey.set(seed.sourceKey, fresh);
      changed = true;
    }
  }

  // Prune pristine synthesis hypotheses whose seed is no longer proposed.
  const seedKeys = new Set(seeds.map((s) => s.sourceKey));
  const pruned = result.filter((h) => {
    if (isPristineSynthesis(h) && h.sourceKey && !seedKeys.has(h.sourceKey)) {
      changed = true;
      return false;
    }
    return true;
  });
  return { hypotheses: pruned, changed };
}

export interface HypothesisStats {
  total: number;
  open: number;
  supported: number;
  refuted: number;
  unknown: number;
}

// Count hypotheses by status — drives the dashboard panel header ("3 open, 1 supported…").
export function hypothesisStats(hypotheses: readonly Hypothesis[]): HypothesisStats {
  const stats: HypothesisStats = { total: hypotheses.length, open: 0, supported: 0, refuted: 0, unknown: 0 };
  for (const h of hypotheses) stats[h.status] += 1;
  return stats;
}

// Build a stored Hypothesis from analyst input (used by the store and the notebook-promote bridge).
// The caller supplies id/timestamps so this stays pure and testable. Analyst-authored hypotheses are
// born analystTouched so the synthesis merge never refreshes or prunes them.
export function buildAnalystHypothesis(
  input: NewHypothesis,
  id: string,
  now: string,
): Hypothesis {
  return {
    id,
    title: String(input.title ?? "").trim().slice(0, MAX_TITLE_LEN),
    description: String(input.description ?? "").trim().slice(0, MAX_TEXT_LEN),
    expectedOutcome: String(input.expectedOutcome ?? "").trim().slice(0, MAX_TEXT_LEN),
    status: input.status && VALID_STATUS.has(input.status) ? input.status : "open",
    relatedTechniques: dedupeStrings(input.relatedTechniques).slice(0, MAX_TECHNIQUES),
    relatedEventIds: dedupeStrings(input.relatedEventIds).slice(0, MAX_LINKS),
    relatedIocIds: dedupeStrings(input.relatedIocIds).slice(0, MAX_LINKS),
    contradictingEventIds: [],
    discriminator: "",
    exhausted: false,
    exhaustedReason: "",
    assignee: String(input.assignee ?? "").trim(),
    notes: String(input.notes ?? "").trim().slice(0, MAX_TEXT_LEN),
    source: "analyst",
    analystTouched: true,
    needsReview: false,
    author: (input.author || "").trim() || "anonymous",
    createdAt: now,
    updatedAt: now,
  };
}

// Apply an analyst patch to a hypothesis, marking it analystTouched and bumping updatedAt. Pure —
// the store passes `now` and persists the result. Unknown status values are ignored (kept as-is).
export function applyHypothesisPatch(h: Hypothesis, patch: HypothesisPatch, now: string): Hypothesis {
  return {
    ...h,
    ...(patch.title !== undefined ? { title: String(patch.title).trim().slice(0, MAX_TITLE_LEN) } : {}),
    ...(patch.description !== undefined ? { description: String(patch.description).trim().slice(0, MAX_TEXT_LEN) } : {}),
    ...(patch.expectedOutcome !== undefined ? { expectedOutcome: String(patch.expectedOutcome).trim().slice(0, MAX_TEXT_LEN) } : {}),
    ...(patch.status !== undefined && VALID_STATUS.has(patch.status) ? { status: patch.status } : {}),
    ...(patch.relatedTechniques !== undefined ? { relatedTechniques: dedupeStrings(patch.relatedTechniques).slice(0, MAX_TECHNIQUES) } : {}),
    ...(patch.relatedEventIds !== undefined ? { relatedEventIds: dedupeStrings(patch.relatedEventIds).slice(0, MAX_LINKS) } : {}),
    ...(patch.relatedIocIds !== undefined ? { relatedIocIds: dedupeStrings(patch.relatedIocIds).slice(0, MAX_LINKS) } : {}),
    ...(patch.contradictingEventIds !== undefined ? { contradictingEventIds: dedupeStrings(patch.contradictingEventIds).slice(0, MAX_LINKS) } : {}),
    ...(patch.discriminator !== undefined ? { discriminator: String(patch.discriminator).trim().slice(0, MAX_TEXT_LEN) } : {}),
    ...(patch.assignee !== undefined ? { assignee: String(patch.assignee).trim() } : {}),
    ...(patch.notes !== undefined ? { notes: String(patch.notes).trim().slice(0, MAX_TEXT_LEN) } : {}),
    analystTouched: true,
    needsReview: false,   // the analyst is editing it now — that IS the review (#12)
    updatedAt: now,
  };
}

export interface ReconsiderHypothesesInput {
  fpEventIds: ReadonlySet<string>; // forensic-event ids just marked false positive (lowercased)
  fpIocIds: ReadonlySet<string>;   // IOC ids just marked false positive
}

export interface ReconsiderHypothesesResult {
  hypotheses: Hypothesis[];
  changed: boolean;
}

// Immediate FP cascade (investigation-guidance #12): when an event or IOC is marked false positive, any
// hypothesis whose SUPPORTING evidence (relatedEventIds / relatedIocIds) intersects the new markers is
// no longer safely supported. Flag it `needsReview` so the analyst re-judges it now. A PRISTINE
// (untouched) hypothesis is ALSO flipped to `unknown` — its support just eroded; a TOUCHED one keeps its
// status (the analyst-owned freeze contract) and only carries the flag. Pure + idempotent — no clock use
// beyond `now`, applied only to hypotheses that actually intersect a marker.
export function reconsiderHypotheses(
  hypotheses: readonly Hypothesis[],
  input: ReconsiderHypothesesInput,
  now: string,
): ReconsiderHypothesesResult {
  let changed = false;
  const next = hypotheses.map((h) => {
    const hits =
      h.relatedEventIds.some((id) => input.fpEventIds.has(id.trim().toLowerCase())) ||
      h.relatedIocIds.some((id) => input.fpIocIds.has(id));
    if (!hits) return h;
    const flipStatus = !h.analystTouched && h.status !== "unknown";
    if (h.needsReview && !flipStatus) return h; // already flagged, nothing more to change
    changed = true;
    return {
      ...h,
      needsReview: true,
      ...(flipStatus ? { status: "unknown" as HypothesisStatus } : {}),
      updatedAt: now,
    };
  });
  return { hypotheses: next, changed };
}

// ACH ranking (investigation-guidance #14). Analysis of Competing Hypotheses ranks by FEWEST
// contradictions, not most support — the explanation that survives the most disconfirming evidence
// wins, which is exactly what stops a well-supported-but-wrong red herring from topping the list.
// Exhausted / refuted hypotheses sink (they're negative knowledge). Pure; returns a sorted COPY.
export function rankHypothesesAch(hypotheses: readonly Hypothesis[]): Hypothesis[] {
  const dead = (h: Hypothesis): number => (h.exhausted || h.status === "refuted" ? 1 : 0);
  return hypotheses.slice().sort((a, b) =>
    dead(a) - dead(b) ||
    a.contradictingEventIds.length - b.contradictingEventIds.length ||   // fewest contradictions first
    b.relatedEventIds.length - a.relatedEventIds.length ||               // then most support
    a.title.localeCompare(b.title));
}

// One hunting signal against a hypothesis (investigation-guidance #14): a collected hunt either tied to
// the hypothesis explicitly (`relatedHypothesisId`) or matched to it by shared ATT&CK technique, and
// whether it MISSED (returned no evidence for the thing the hypothesis predicted).
export interface HypothesisHuntSignal {
  relatedHypothesisId?: string;
  techniques: string[];
  missed: boolean;      // true = the hunt came back empty (negative evidence for what it tested)
  title?: string;       // for the exhaustion reason
}

export interface MarkExhaustedResult {
  hypotheses: Hypothesis[];
  changed: boolean;
}

// Mark a hypothesis `exhausted` once enough hunts that tested it came back EMPTY (investigation-guidance
// #14): its `expectedOutcome` has been hunted for and not found. A hunt matches a hypothesis by an
// explicit `relatedHypothesisId`, else by shared ATT&CK technique. Only OPEN hypotheses are exhausted
// (a supported/refuted one is already resolved). `exhausted` is an orthogonal flag, NOT a status change,
// so it respects the analyst-freeze contract while still feeding the negative-knowledge synthesis block.
// Pure + idempotent — re-running with the same signals is a no-op.
export function markExhaustedHypotheses(
  hypotheses: readonly Hypothesis[],
  signals: readonly HypothesisHuntSignal[],
  now: string,
  minMisses = 2,
): MarkExhaustedResult {
  const threshold = Math.max(1, Math.floor(minMisses));
  let changed = false;
  const next = hypotheses.map((h) => {
    if (h.status !== "open" || h.exhausted) return h;
    const techniqueSet = new Set(h.relatedTechniques);
    let misses = 0;
    for (const s of signals) {
      if (!s.missed) continue;
      const matches = s.relatedHypothesisId
        ? s.relatedHypothesisId === h.id
        : s.techniques.some((t) => techniqueSet.has(t));
      if (matches) misses += 1;
    }
    if (misses < threshold) return h;
    changed = true;
    return {
      ...h,
      exhausted: true,
      exhaustedReason: `${misses} hunt(s) for its expected outcome came back empty — no supporting evidence found`,
      updatedAt: now,
    };
  });
  return { hypotheses: next, changed };
}
