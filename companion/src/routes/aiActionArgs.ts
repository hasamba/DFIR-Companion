import { findSimilarEvents, findSimilarFindings } from "../analysis/falsePositiveSimilarity.js";
import { normalizeHuntPlatform, HUNT_PLATFORMS, type HuntPlatform } from "../analysis/huntPlatforms.js";
import { resolveStoredTargets } from "../analysis/eventAliasLookup.js";
import { eventAliasSource } from "../analysis/eventAliasRead.js";
import type { ForensicEvent, Finding, InvestigationState } from "../analysis/stateTypes.js";
import { STARRED_LABEL, type SuperQuery } from "../analysis/superTimeline.js";
import type { RouteContext } from "./context.js";

/**
 * How an AI route turns its request into the arguments of the AI call (#2491).
 *
 * Each of these used to live inline in its route. "Preview what the AI will see" must build the
 * prompt exactly as pressing the real button would, so the preview and the route now derive the
 * arguments through the SAME function — a second copy of, say, the starred-ids lookup could drift
 * and preview a prompt the button never sends.
 */
type Options = RouteContext["options"];

/** The ids the Starred Events Report reads: every starred event, resolved past correlation folds. */
export async function loadStarredEventIds(options: Options, caseId: string): Promise<string[]> {
  if (!options.tagsStore) return [];
  const tags = await options.tagsStore.load(caseId);
  const starred = tags.filter((t) => t.targetType === "event" && t.label === STARRED_LABEL);
  // A star on an event correlation folded into another reports the event it lives on (#1715).
  const resolved = await resolveStoredTargets(eventAliasSource(options.stateStore), caseId, starred);
  return [...new Set(resolved.map((t) => t.resolvedTargetId ?? t.targetId))];
}

/** The view-summary body (the dashboard's super-timeline filter set) as a SuperQuery. */
export function parseViewSummaryFilters(body: unknown): SuperQuery {
  const b = (body ?? {}) as Record<string, unknown>;
  const csv = (v: unknown): string[] =>
    String(v ?? "")
      .split(",")
      .map((s) => s.trim())
      .filter(Boolean);
  return {
    from: typeof b.from === "string" && b.from ? b.from : undefined,
    to: typeof b.to === "string" && b.to ? b.to : undefined,
    exclude: csv(b.exclude),
    excludeHosts: csv(b.excludeHosts),
    labels: csv(b.labels),
    taggedOnly: b.tagged === true || b.tagged === "1" || b.tagged === "true",
    starred: b.starred === true || b.starred === "1" || b.starred === "true",
    search: typeof b.q === "string" ? b.q : undefined,
    excludeText: csv(b.excludeText),
  };
}

/**
 * Tag label map — same construction as the GET /super-timeline route, so labels=/starred filter by
 * the case's analyst tags. Undefined when no tags store is wired.
 */
export async function loadEventTagLabelMap(
  options: Options,
  caseId: string,
): Promise<Record<string, string[]> | undefined> {
  if (!options.tagsStore) return undefined;
  const tags = await options.tagsStore.load(caseId);
  const map: Record<string, string[]> = {};
  for (const t of tags) {
    if (t.targetType !== "event") continue;
    (map[t.targetId] ??= []).push(t.label);
  }
  return map;
}

/**
 * The platforms a query translation asks for: the analyst's optional subset, bounded by the server's
 * DFIR_HUNT_PLATFORMS allowlist, so a disabled platform is never generated.
 */
export function resolveTranslatePlatforms(options: Options, body: unknown): HuntPlatform[] {
  const raw = (body as { platforms?: unknown } | undefined)?.platforms;
  const enabled = options.huntPlatforms ?? [...HUNT_PLATFORMS];
  const bodyPlatforms = Array.isArray(raw)
    ? raw
        .map((p: unknown) => normalizeHuntPlatform(typeof p === "string" ? p : ""))
        .filter((p: HuntPlatform | null): p is HuntPlatform => !!p)
    : [];
  const wanted = bodyPlatforms.length ? enabled.filter((p) => bodyPlatforms.includes(p)) : enabled;
  return wanted.length ? wanted : enabled;
}

/** A per-technique hunt request, or null when the technique id is not a valid ATT&CK id. */
export function parseTechniqueHuntBody(
  body: unknown,
): { techniqueId: string; techniqueName: string | undefined } | null {
  const b = (body ?? {}) as { techniqueId?: unknown; techniqueName?: unknown };
  const techniqueId = String(b.techniqueId ?? "").trim();
  const techniqueName = String(b.techniqueName ?? "").trim() || undefined;
  return /^T\d{4}(?:\.\d{3})?$/i.test(techniqueId) ? { techniqueId, techniqueName } : null;
}

export type SimilarKind = "event" | "finding";

/** What the mark-false-positive "find similar" AI pass is asked about, built from the case. */
export interface SimilarCandidates {
  readonly kind: SimilarKind;
  readonly deterministic: ReturnType<typeof findSimilarEvents>;
  readonly anchorLabel: string;
  /** Everything the deterministic pass did not already pick, capped at 100: what the AI reads. */
  readonly rest: ReadonlyArray<ForensicEvent | Finding>;
}

export function parseSimilarKind(body: unknown): SimilarKind | null {
  const kind = (body as { kind?: unknown } | undefined)?.kind;
  return kind === "event" ? "event" : kind === "finding" ? "finding" : null;
}

/** null when the anchor is not in the case. */
export function similarCandidates(
  state: InvestigationState,
  kind: SimilarKind,
  ref: string,
): SimilarCandidates | null {
  const anchor =
    kind === "event"
      ? state.forensicTimeline.find((e) => e.id === ref)
      : state.findings.find((f) => f.id === ref);
  if (!anchor) return null;
  const deterministic =
    kind === "event"
      ? findSimilarEvents(anchor as ForensicEvent, state.forensicTimeline)
      : findSimilarFindings(anchor as Finding, state.findings);
  const pool: ReadonlyArray<ForensicEvent | Finding> =
    kind === "event" ? state.forensicTimeline : state.findings;
  const anchorLabel = similarLabel(kind, anchor);
  const seen = new Set(deterministic.map((c) => c.id));
  const rest = pool.filter((item) => item.id !== ref && !seen.has(item.id)).slice(0, 100);
  return { kind, deterministic, anchorLabel, rest };
}

/** The text the AI is shown for an event (its description) or a finding (its title). */
export function similarLabel(kind: SimilarKind, item: ForensicEvent | Finding): string {
  return kind === "event" ? (item as ForensicEvent).description : (item as Finding).title;
}
