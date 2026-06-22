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
  assignee: z.string().default("").catch(""),
  notes: z.string().default("").catch(""),
  source: z.enum(HYPOTHESIS_SOURCES).default("analyst").catch("analyst"),
  // True once the analyst has edited this hypothesis via PATCH. Freezes a synthesis hypothesis
  // against auto-refresh/prune. Always effectively true for analyst-authored ones.
  analystTouched: z.boolean().default(false).catch(false),
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
    h.relatedTechniques.join(" ") !== seed.relatedTechniques.join(" ") ||
    h.relatedEventIds.join(" ") !== seed.relatedEventIds.join(" ") ||
    h.relatedIocIds.join(" ") !== seed.relatedIocIds.join(" ")
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
        assignee: "",
        notes: "",
        source: "synthesis",
        analystTouched: false,
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
    assignee: String(input.assignee ?? "").trim(),
    notes: String(input.notes ?? "").trim().slice(0, MAX_TEXT_LEN),
    source: "analyst",
    analystTouched: true,
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
    ...(patch.assignee !== undefined ? { assignee: String(patch.assignee).trim() } : {}),
    ...(patch.notes !== undefined ? { notes: String(patch.notes).trim().slice(0, MAX_TEXT_LEN) } : {}),
    analystTouched: true,
    updatedAt: now,
  };
}
