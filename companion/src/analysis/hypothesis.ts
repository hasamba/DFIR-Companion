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

// The host(s) a hypothesis's own claim concerns (#1110, surfaced by #1101's design review, which
// found that INFERRING this from relatedEventIds — a hypothesis's SUPPORTING evidence, a different
// concept — is unsound). The model states this directly: "hosts" names specific hosts (validated
// against real case hosts at sanitize time), "caseWide" says the claim spans every host, and
// "unknown" is the FAIL-CLOSED default for anything omitted, malformed, or only partly resolved —
// never silently treated as either of the other two. Only refutationGate.ts reads this; it is never
// exposed to the analyst-authored NewHypothesis/HypothesisPatch path, which never runs the gate.
export const resolvedSubjectScopeSchema = z.discriminatedUnion("kind", [
  z.object({ kind: z.literal("hosts"), hosts: z.array(z.string()) }),
  z.object({ kind: z.literal("caseWide") }),
  z.object({ kind: z.literal("unknown") }),
]);
export type ResolvedSubjectScope = z.infer<typeof resolvedSubjectScopeSchema>;
const UNKNOWN_SCOPE: ResolvedSubjectScope = { kind: "unknown" };
const CASE_WIDE_SCOPE: ResolvedSubjectScope = { kind: "caseWide" };

// One entry in a hypothesis's dated status-change audit trail (issue #95). Appended whenever the
// STATUS actually changes value — not on every patch/refresh — so it reads as a clean history of
// open → supported / refuted / unknown transitions, not a log of every edit.
export const hypothesisStatusChangeSchema = z.object({
  status: z.enum(HYPOTHESIS_STATUSES),
  changedAt: z.string(),
});
export type HypothesisStatusChange = z.infer<typeof hypothesisStatusChangeSchema>;

// One analyst exclusion of an observation from one hypothesis's assessment (#933 item 22). Closed
// by a restore (`restoredAt`/`restoredBy`), or automatically with restoredBy "unlinked" when the
// observation leaves the hypothesis's link lists — relinking never revives a closed entry.
export const evidenceExclusionSchema = z.object({
  eventId: z.string(),
  reason: z.string().default("").catch(""),
  by: z.string().default("").catch(""),
  excludedAt: z.string(),
  restoredAt: z.string().optional(),
  restoredBy: z.string().optional(),
});
export type EvidenceExclusion = z.infer<typeof evidenceExclusionSchema>;

// Lenient (.catch / .default everywhere) so one off field in a hand-edited or older file never
// rejects the whole array — same posture as responseSchema.ts and the other side-file stores.
export const hypothesisSchema = z.object({
  id: z.string(),
  title: z.string(),
  description: z.string().default("").catch(""),
  expectedOutcome: z.string().default("").catch(""), // what would prove/disprove this hypothesis
  status: z.enum(HYPOTHESIS_STATUSES).default("open").catch("open"),
  relatedTechniques: z.array(z.string()).default([]).catch([]), // ATT&CK ids (T1566, T1021.006…)
  relatedEventIds: z.array(z.string()).default([]).catch([]), // supporting forensic-event ids
  relatedIocIds: z.array(z.string()).default([]).catch([]), // implicated IOC ids
  // ACH-style analysis (investigation-guidance #14). `contradictingEventIds` are events INCONSISTENT
  // with this explanation — tracked so a hypothesis is judged by fewest contradictions (ACH), not most
  // support, and a red herring can't sail through unopposed. `discriminator` names the single artifact
  // (host + artifact) that would best separate this hypothesis from the leading alternative — it doubles
  // as a concrete collection directive. `exhausted` is set deterministically once N linked hunts came
  // back empty against `expectedOutcome` (see markExhaustedHypotheses) → it feeds the negative-knowledge
  // synthesis block; `exhaustedReason` is the human one-liner.
  contradictingEventIds: z.array(z.string()).default([]).catch([]),
  discriminator: z.string().default("").catch(""),
  // The claim's own host scope (#1110). Genuinely optional (unlike every other field here, which
  // has a default) so a hypotheses.json written before this field existed — or any other Hypothesis
  // built without one — reads as `undefined`, which refutationGate.ts treats identically to
  // "caseWide": EXACTLY today's behavior, never a silent regression to fully-blocked coverage for
  // pre-existing data. A FRESH seed's own omitted/invalid scope is handled separately, in
  // sanitizeHypotheses, where "unknown" (fail-closed) is the correct response to non-compliance
  // rather than a migration default.
  //
  // `.catch()` sits OUTSIDE `.optional()` deliberately: a genuinely ABSENT field still parses to
  // `undefined` (optional succeeds, catch never fires), but a MALFORMED one (wrong shape, an
  // unrecognized `kind`) degrades to "unknown" for just this one record. Without this, one bad
  // stored value fails this object's own parse, which bubbles up through hypothesesSchema's own
  // `.catch([])` at the ARRAY level — silently discarding every OTHER analyst's hypothesis in the
  // same file (Codex code review finding #1110-H2, reproduced: one malformed record turned a
  // two-item stored array into `[]`).
  subjectScope: resolvedSubjectScopeSchema.optional().catch(UNKNOWN_SCOPE),
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
  // WHY it is flagged (#933 item 22): the false-positive cascade, a withdrawn support, a new
  // contradiction, an excluded observation that now distinguishes. Cleared with `needsReview`.
  reviewReason: z.string().default("").catch(""),
  // Analyst-named competing set (#933 item 22). When empty, every live (not refuted / exhausted)
  // hypothesis is an alternative; the analyst narrows it when a title is not a real competitor.
  alternativeIds: z.array(z.string()).default([]).catch([]),
  // Audit trail of observations the analyst excluded from THIS hypothesis's assessment (#933 item
  // 22). The link and the event both stay; the reading (hypothesisDiagnostics.ts) skips an ACTIVE
  // entry (no `restoredAt`). Analyst-owned like `notes`: a refresh never reads or writes it.
  excludedEvidence: z.array(evidenceExclusionSchema).default([]).catch([]),
  // Stable derive key for a synthesis hypothesis (= its id). Absent for analyst-authored ones.
  sourceKey: z.string().optional(),
  author: z.string().optional(),
  createdAt: z.string(),
  updatedAt: z.string(),
  // Dated status-change audit trail (issue #95). Lenient-default so a pre-existing hypotheses.json
  // (written before this field existed) parses to [] rather than rejecting the whole file; the store
  // backfills a single entry from createdAt on load (see ensureHypothesisStatusHistory).
  statusHistory: z.array(hypothesisStatusChangeSchema).default([]).catch([]),
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
  discriminator: string; // ACH (#14): the artifact (host + artifact) that best separates it
  // #1110: the claim's own host scope, for refutationGate.ts. Optional — matching this codebase's
  // convention for a field with a well-defined fallback everywhere it is read (missing = treated as
  // "caseWide", the exact pre-#1110 behavior) — rather than force every existing Hypothesis/
  // HypothesisSeed literal across the test suite to name a field their own test never cares about.
  subjectScope?: ResolvedSubjectScope;
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
    | "alternativeIds"
    | "assignee"
    | "notes"
  >
> & { acknowledgeReview?: boolean }; // #933 item 22: the explicit "✓ reviewed" that clears the flag

export const HYPOTHESIS_MAX_DEFAULT = 8; // cap on auto-generated hypotheses kept per synthesis
const MAX_TITLE_LEN = 200;
const MAX_TEXT_LEN = 2000;
const MAX_TECHNIQUES = 30;
const MAX_LINKS = 200;

function dedupeStrings(arr: readonly string[] | undefined): string[] {
  return [...new Set((arr ?? []).map((s) => String(s).trim()).filter(Boolean))];
}

// Append a status-change entry — but only when the status actually differs from the last recorded
// one (idempotent under repeated writes of the same status, e.g. a refresh that changes other fields
// but not status). Pure.
function appendStatusChange(
  history: readonly HypothesisStatusChange[] | undefined,
  status: HypothesisStatus,
  now: string,
): HypothesisStatusChange[] {
  const prev = history ?? [];
  const last = prev[prev.length - 1];
  if (last && last.status === status) return [...prev];
  return [...prev, { status, changedAt: now }];
}

// Backfill a single status-history entry (from createdAt) for a hypothesis loaded from a
// pre-#95 hypotheses.json that has no history yet. Pure; a no-op once history is populated.
export function ensureHypothesisStatusHistory(h: Hypothesis): Hypothesis {
  if (h.statusHistory && h.statusHistory.length) return h;
  return { ...h, statusHistory: [{ status: h.status, changedAt: h.createdAt }] };
}

// Whitespace-normalize a title so two formattings fingerprint identically. Lowercased — unlike VQL,
// a hypothesis title is prose and case is not semantically significant for dedup.
export function normalizeTitle(title: string): string {
  return String(title ?? "")
    .replace(/\s+/g, " ")
    .trim()
    .toLowerCase();
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

// The case's own real host identity, for validating a fresh seed's own declared subjectHosts
// (#1110). `resolve` maps a raw spelling to its canonical form (mirrors hostAlias.ts's own
// resolveHost, injected rather than imported directly so this module never depends on the
// concrete HostAliasIndex shape — only on the one operation it needs).
export interface HostContext {
  resolve(raw: string): string;
  knownHosts: ReadonlySet<string>; // already-canonical host names actually present in the case
}

// A fresh seed's own declared scope, resolved against real case hosts. `scope` is "hosts" or
// "caseWide" (anything else — omitted, misspelled, absent) becomes "unknown", the fail-closed
// default: the review that shaped this design found that overloading an empty array to mean BOTH
// "explicitly case-wide" and "could not attribute" left the gate unable to tell them apart, and
// that a "caseWide" claim's own fallback must not silently reuse the old case-wide UNION either
// (that is refutationGate.ts's own job — this function only resolves what the model SAID).
// ANY unresolved host in a multi-host list taints the WHOLE scope to "unknown" — a partial drop
// (keeping the hosts that DID resolve) would shrink the required-coverage set and let a refutation
// survive on a host it was never actually validated against.
function resolveSubjectScope(raw: Record<string, unknown>, hostCtx?: HostContext): ResolvedSubjectScope {
  const scope = String(raw.subjectScope ?? "").trim();
  if (scope === "caseWide") return CASE_WIDE_SCOPE;
  if (scope !== "hosts" || !hostCtx) return UNKNOWN_SCOPE;
  // Fail closed on a wrong-shaped subjectHosts too — a raw AI response is untrusted input, and this
  // function is called directly (not only through the zod-validated responseSchema.ts path) in
  // tests and any other future caller, so it must not assume the caller already normalized this to
  // an array (dedupeStrings itself would throw calling .map on a non-array value).
  if (!Array.isArray(raw.subjectHosts)) return UNKNOWN_SCOPE;
  const declared = dedupeStrings(raw.subjectHosts as string[]);
  if (!declared.length) return UNKNOWN_SCOPE;
  const resolved = declared.map((h) => hostCtx.resolve(h));
  if (!resolved.every((h) => hostCtx.knownHosts.has(h))) return UNKNOWN_SCOPE;
  return { kind: "hosts", hosts: resolved };
}

// Turn raw synthesis hypotheses into clean, deterministic seeds: require a title (skip blanks),
// trim/cap prose, coerce status to the enum (default open), dedupe techniques, filter evidence links
// to ids that actually exist in the case (so the model can't invent dangling references), dedupe by
// sourceKey, and cap the count. `hostCtx` is optional so every existing caller (and every EXISTING
// test) keeps working unchanged; omitting it resolves every seed's own subjectScope to "unknown"
// EXCEPT an explicit "caseWide", which needs no host validation at all. Pure — no I/O, no clock.
export function sanitizeHypotheses(
  raw: readonly unknown[] | undefined,
  validEventIds: ReadonlySet<string>,
  validIocIds: ReadonlySet<string>,
  max: number = HYPOTHESIS_MAX_DEFAULT,
  hostCtx?: HostContext,
): HypothesisSeed[] {
  const cap = Number.isFinite(max) && max > 0 ? Math.floor(max) : HYPOTHESIS_MAX_DEFAULT;
  const seen = new Set<string>();
  const out: HypothesisSeed[] = [];
  for (const item of raw ?? []) {
    const h = (item ?? {}) as Record<string, unknown>;
    const title = String(h.title ?? "")
      .trim()
      .slice(0, MAX_TITLE_LEN);
    if (!title) continue;
    const sourceKey = hypothesisAutoKey(title);
    if (!sourceKey || seen.has(sourceKey)) continue;
    seen.add(sourceKey);
    const status = String(h.status ?? "")
      .trim()
      .toLowerCase();
    out.push({
      sourceKey,
      title,
      description: String(h.description ?? "")
        .trim()
        .slice(0, MAX_TEXT_LEN),
      expectedOutcome: String(h.expectedOutcome ?? "")
        .trim()
        .slice(0, MAX_TEXT_LEN),
      status: VALID_STATUS.has(status) ? (status as HypothesisStatus) : "open",
      relatedTechniques: dedupeStrings(h.relatedTechniques as string[]).slice(0, MAX_TECHNIQUES),
      relatedEventIds: dedupeStrings(h.relatedEventIds as string[])
        .filter((id) => validEventIds.has(id))
        .slice(0, MAX_LINKS),
      relatedIocIds: dedupeStrings(h.relatedIocIds as string[])
        .filter((id) => validIocIds.has(id))
        .slice(0, MAX_LINKS),
      // ACH (#14): contradicting events must be REAL case events too (no invented refs); discriminator is prose.
      contradictingEventIds: dedupeStrings(h.contradictingEventIds as string[])
        .filter((id) => validEventIds.has(id))
        .slice(0, MAX_LINKS),
      discriminator: String(h.discriminator ?? "")
        .trim()
        .slice(0, MAX_TEXT_LEN),
      subjectScope: resolveSubjectScope(h, hostCtx),
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

// Missing keys as "caseWide" — the SAME fallback used everywhere else an absent scope is read
// (refutationGate.ts's collectedForScope, the stored schema's own reader) — so a stored hypothesis
// that never had this field and a freshly-built one that defaults it to caseWide compare equal.
function subjectScopeKey(scope: ResolvedSubjectScope | undefined): string {
  if (!scope) return "caseWide";
  return scope.kind === "hosts" ? `hosts:${[...scope.hosts].sort().join(",")}` : scope.kind;
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
    h.discriminator !== (seed.discriminator ?? "") ||
    subjectScopeKey(h.subjectScope) !== subjectScopeKey(seed.subjectScope)
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
          contradictingEventIds: [...(seed.contradictingEventIds ?? [])], // ACH (#14)
          discriminator: seed.discriminator ?? "",
          subjectScope: seed.subjectScope ?? CASE_WIDE_SCOPE,
          needsReview: false, // authoritative refresh clears any interim FP-cascade flag (#12)
          reviewReason: "",
          statusHistory: appendStatusChange(cur.statusHistory, seed.status, now),
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
        contradictingEventIds: [...(seed.contradictingEventIds ?? [])], // ACH (#14)
        discriminator: seed.discriminator ?? "",
        subjectScope: seed.subjectScope ?? CASE_WIDE_SCOPE,
        exhausted: false,
        exhaustedReason: "",
        assignee: "",
        notes: "",
        source: "synthesis",
        analystTouched: false,
        needsReview: false,
        reviewReason: "",
        alternativeIds: [],
        excludedEvidence: [],
        sourceKey: seed.sourceKey,
        createdAt: now,
        updatedAt: now,
        statusHistory: [{ status: seed.status, changedAt: now }],
      };
      result.push(fresh);
      byKey.set(seed.sourceKey, fresh);
      changed = true;
    }
  }

  // Prune pristine synthesis hypotheses whose seed is no longer proposed. One that carries an
  // exclusion entry is kept: the entry is an audit trail the analyst wrote (#933 item 22).
  const seedKeys = new Set(seeds.map((s) => s.sourceKey));
  const pruned = result.filter((h) => {
    if (isPristineSynthesis(h) && h.sourceKey && !seedKeys.has(h.sourceKey) && !h.excludedEvidence.length) {
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
export function buildAnalystHypothesis(input: NewHypothesis, id: string, now: string): Hypothesis {
  const status = input.status && VALID_STATUS.has(input.status) ? input.status : "open";
  return {
    id,
    title: String(input.title ?? "")
      .trim()
      .slice(0, MAX_TITLE_LEN),
    description: String(input.description ?? "")
      .trim()
      .slice(0, MAX_TEXT_LEN),
    expectedOutcome: String(input.expectedOutcome ?? "")
      .trim()
      .slice(0, MAX_TEXT_LEN),
    status,
    relatedTechniques: dedupeStrings(input.relatedTechniques).slice(0, MAX_TECHNIQUES),
    relatedEventIds: dedupeStrings(input.relatedEventIds).slice(0, MAX_LINKS),
    relatedIocIds: dedupeStrings(input.relatedIocIds).slice(0, MAX_LINKS),
    contradictingEventIds: [],
    discriminator: "",
    // Analyst-authored hypotheses never pass through gateRefutedSeeds — this is an inert default
    // for schema completeness only (#1110), matching the same "absent = caseWide" fallback used
    // everywhere else an unset scope is read.
    subjectScope: CASE_WIDE_SCOPE,
    exhausted: false,
    exhaustedReason: "",
    assignee: String(input.assignee ?? "").trim(),
    notes: String(input.notes ?? "")
      .trim()
      .slice(0, MAX_TEXT_LEN),
    source: "analyst",
    analystTouched: true,
    needsReview: false,
    reviewReason: "",
    alternativeIds: [],
    excludedEvidence: [],
    author: (input.author || "").trim() || "anonymous",
    createdAt: now,
    updatedAt: now,
    statusHistory: [{ status, changedAt: now }],
  };
}

// Apply an analyst patch to a hypothesis, marking it analystTouched and bumping updatedAt. Pure —
// the store passes `now` and persists the result. Unknown status values are ignored (kept as-is).
// The review flag clears only on a STATUS change or an explicit `acknowledgeReview` (#933 item
// 22): editing the assignee or the notes is not a review, and must not erase a warning.
export function applyHypothesisPatch(h: Hypothesis, patch: HypothesisPatch, now: string): Hypothesis {
  const statusChanged =
    patch.status !== undefined && VALID_STATUS.has(patch.status) && patch.status !== h.status;
  const clearReview = statusChanged || patch.acknowledgeReview === true;
  return {
    ...h,
    ...(patch.title !== undefined ? { title: String(patch.title).trim().slice(0, MAX_TITLE_LEN) } : {}),
    ...(patch.description !== undefined
      ? { description: String(patch.description).trim().slice(0, MAX_TEXT_LEN) }
      : {}),
    ...(patch.expectedOutcome !== undefined
      ? { expectedOutcome: String(patch.expectedOutcome).trim().slice(0, MAX_TEXT_LEN) }
      : {}),
    ...(patch.status !== undefined && VALID_STATUS.has(patch.status) ? { status: patch.status } : {}),
    ...(patch.relatedTechniques !== undefined
      ? { relatedTechniques: dedupeStrings(patch.relatedTechniques).slice(0, MAX_TECHNIQUES) }
      : {}),
    ...(patch.relatedEventIds !== undefined
      ? { relatedEventIds: dedupeStrings(patch.relatedEventIds).slice(0, MAX_LINKS) }
      : {}),
    ...(patch.relatedIocIds !== undefined
      ? { relatedIocIds: dedupeStrings(patch.relatedIocIds).slice(0, MAX_LINKS) }
      : {}),
    ...(patch.contradictingEventIds !== undefined
      ? { contradictingEventIds: dedupeStrings(patch.contradictingEventIds).slice(0, MAX_LINKS) }
      : {}),
    ...(patch.discriminator !== undefined
      ? { discriminator: String(patch.discriminator).trim().slice(0, MAX_TEXT_LEN) }
      : {}),
    ...(patch.alternativeIds !== undefined
      ? {
          alternativeIds: dedupeStrings(patch.alternativeIds)
            .filter((id) => id !== h.id)
            .slice(0, MAX_LINKS),
        }
      : {}),
    ...(patch.assignee !== undefined ? { assignee: String(patch.assignee).trim() } : {}),
    ...(patch.notes !== undefined ? { notes: String(patch.notes).trim().slice(0, MAX_TEXT_LEN) } : {}),
    analystTouched: true,
    ...(clearReview ? { needsReview: false, reviewReason: "" } : {}),
    ...(statusChanged
      ? { statusHistory: appendStatusChange(h.statusHistory, patch.status as HypothesisStatus, now) }
      : {}),
    updatedAt: now,
  };
}

export interface ReconsiderHypothesesInput {
  fpEventIds: ReadonlySet<string>; // forensic-event ids just marked false positive (lowercased)
  fpIocIds: ReadonlySet<string>; // IOC ids just marked false positive
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
export const FP_REVIEW_REASON = "an event or IOC that supported this hypothesis was marked false positive";

export function reconsiderHypotheses(
  hypotheses: readonly Hypothesis[],
  input: ReconsiderHypothesesInput,
  now: string,
): ReconsiderHypothesesResult {
  let changed = false;
  const next: Hypothesis[] = hypotheses.map((h) => {
    const hits =
      h.relatedEventIds.some((id) => input.fpEventIds.has(id.trim().toLowerCase())) ||
      h.relatedIocIds.some((id) => input.fpIocIds.has(id));
    if (!hits) return h;
    const flipStatus = !h.analystTouched && h.status !== "unknown";
    // Already flagged for this very reason and nothing to flip → nothing to change. Flagged for a
    // material change (#933 item 22) → the false-positive cause is ADDED to the reason, never lost.
    const reasons = h.needsReview && h.reviewReason ? h.reviewReason.split("; ") : [];
    if (h.needsReview && !flipStatus && reasons.includes(FP_REVIEW_REASON)) return h;
    changed = true;
    return {
      ...h,
      needsReview: true,
      reviewReason: reasons.includes(FP_REVIEW_REASON)
        ? h.reviewReason
        : [...reasons, FP_REVIEW_REASON].join("; "),
      ...(flipStatus
        ? { status: "unknown", statusHistory: appendStatusChange(h.statusHistory, "unknown", now) }
        : {}),
      updatedAt: now,
    };
  });
  return { hypotheses: next, changed };
}

// On-demand falsification review (issue #71). A focused, human-readable devil's-advocate pass over the
// OPEN hypotheses: for each, the plain-English evidence that SUPPORTS it, the evidence that REFUTES it,
// and a RECOMMENDED status change. Distinct from the ACH links baked into synthesis (contradictingEventIds
// are event-id references; these are prose bullets an analyst can read). The recommendation is ADVISORY —
// the analyst still owns each hypothesis's status (the analystTouched freeze contract), so this is never
// auto-applied. This is the pure, unit-tested core; the AI call + I/O wrapper live in the pipeline.
export interface HypothesisReviewItem {
  hypothesisId: string;
  title: string; // the KNOWN title (not the model's echo, which can drift)
  supportingEvidence: string[]; // plain-English bullets FOR the hypothesis
  refutingEvidence: string[]; // plain-English bullets AGAINST it (the disconfirming lens)
  recommendedStatus: HypothesisStatus; // advisory only — never applied by this module
  rationale: string; // one-paragraph justification for the recommendation
  relatedEventIds: string[]; // real case event ids the review cites
}

const MAX_REVIEW_BULLETS = 12;
const MAX_BULLET_LEN = 500;
export const HYPOTHESIS_REVIEW_MAX_DEFAULT = 20; // cap on reviews returned in one pass

function sanitizeBullets(arr: readonly unknown[] | undefined): string[] {
  return [
    ...new Set(
      (arr ?? [])
        .map((s) =>
          String(s ?? "")
            .trim()
            .slice(0, MAX_BULLET_LEN),
        )
        .filter(Boolean),
    ),
  ].slice(0, MAX_REVIEW_BULLETS);
}

// Turn a raw model hypothesis-review response into clean, ADVISORY review items. Pure — no I/O, no clock.
// - drops a review whose hypothesisId is not one of the hypotheses actually under review (no invented targets)
// - takes the title from the KNOWN hypothesis, ignoring the model's echo (which can drift/rename)
// - trims/caps/dedupes the support & refute bullets, dropping blanks; caps the bullet count
// - coerces recommendedStatus to the enum (default "unknown") — ADVISORY, never applied here
// - filters relatedEventIds to ids that actually exist in the case (no dangling references)
// - dedupes by hypothesisId (first wins) and caps the number of reviews
export function sanitizeHypothesisReviews(
  raw: readonly unknown[] | undefined,
  knownHypotheses: ReadonlyMap<string, string>,
  validEventIds: ReadonlySet<string>,
  max: number = HYPOTHESIS_REVIEW_MAX_DEFAULT,
): HypothesisReviewItem[] {
  const cap = Number.isFinite(max) && max > 0 ? Math.floor(max) : HYPOTHESIS_REVIEW_MAX_DEFAULT;
  const seen = new Set<string>();
  const out: HypothesisReviewItem[] = [];
  for (const item of raw ?? []) {
    const r = (item ?? {}) as Record<string, unknown>;
    const hypothesisId = String(r.hypothesisId ?? "").trim();
    if (!hypothesisId || !knownHypotheses.has(hypothesisId) || seen.has(hypothesisId)) continue;
    seen.add(hypothesisId);
    const status = String(r.recommendedStatus ?? "")
      .trim()
      .toLowerCase();
    out.push({
      hypothesisId,
      title: knownHypotheses.get(hypothesisId) as string,
      supportingEvidence: sanitizeBullets(r.supportingEvidence as unknown[]),
      refutingEvidence: sanitizeBullets(r.refutingEvidence as unknown[]),
      recommendedStatus: VALID_STATUS.has(status) ? (status as HypothesisStatus) : "unknown",
      rationale: String(r.rationale ?? "")
        .trim()
        .slice(0, MAX_TEXT_LEN),
      relatedEventIds: dedupeStrings(r.relatedEventIds as string[])
        .filter((id) => validEventIds.has(id))
        .slice(0, MAX_LINKS),
    });
    if (out.length >= cap) break;
  }
  return out;
}

// ACH ranking (`rankHypothesesAch`) lives in hypothesisDiagnostics.ts (#933 item 22): it reads
// diagnosticity across the set, which this module must not import (the type flows the other way).

// One hunting signal against a hypothesis (investigation-guidance #14): a collected hunt either tied to
// the hypothesis explicitly (`relatedHypothesisId`) or matched to it by shared ATT&CK technique, and
// whether it MISSED (returned no evidence for the thing the hypothesis predicted).
export interface HypothesisHuntSignal {
  relatedHypothesisId?: string;
  techniques: string[];
  missed: boolean; // true = the hunt came back empty (negative evidence for what it tested)
  title?: string; // for the exhaustion reason
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
