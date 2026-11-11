import {
  computeMainSource,
  familyForFinding,
  type MainSourceResult,
  type SourceFamily,
} from "../caseMainSource.js";
import { isCloudOnlyCase } from "../cloudOnlyCase.js";
import type { CaseMainSourceStore } from "../caseMainSourceStore.js";
import {
  enabledHuntPlatforms,
  HUNT_LANGUAGES,
  planHuntGroups,
  type CopyHuntLanguage,
  type HuntLanguage,
} from "../huntLanguage.js";
import { hasHuntMaterial, type HuntSuggestion } from "../huntSuggest.js";
import type { LanguageHuntSuggestion, PlaybookLanguageHunt } from "../languageHuntSuggest.js";
import type { PlaybookTask } from "../playbook.js";
import type { Finding, ForensicEvent, InvestigationState } from "../stateTypes.js";
import { suggestHunts, type HuntContext } from "./hunts.js";
import { suggestLanguageHunts, suggestPlaybookLanguageHunts } from "./languageHunts.js";

/**
 * Main-source hunt routing (#2559): pick each hunt's language from the case's main evidence source
 * (caseMainSource.ts) and send it down the right path.
 *
 * - VQL → suggestHunts, called EXACTLY as before (same arguments, same prompt). A pure-VQL case with
 *   no note gets the very same `{ suggestions }` response it always did.
 * - CQL / KQL / ES|QL / SPL → suggestLanguageHunts (copy-ready, never deployed).
 * - Other cloud logs → no hunt, a note.
 * On a mixed case each finding goes to its own evidence's language; the VQL path still runs unchanged
 * and only its answers that cite nothing but other-language findings are left out.
 */

export interface CaseHuntContext extends HuntContext {
  readonly opts: HuntContext["opts"] & { mainSourceStore?: CaseMainSourceStore };
}

export interface CaseHuntResult {
  /** VQL fleet hunts — deployable through Velociraptor. */
  suggestions: HuntSuggestion[];
  /** Behaviour hunts in the main-source language — copy-ready only. */
  languageHunts?: LanguageHuntSuggestion[];
  /** Fallback / no-language notes for the analyst. */
  notes?: string[];
}

export interface CaseHuntOptions {
  /** Regenerate one VQL card (today's ↻ path). */
  excludeVql?: string;
  /** Regenerate one language card: its language and current query. */
  language?: string;
  excludeQuery?: string;
}

const isCopyLanguage = (l: unknown): l is CopyHuntLanguage =>
  typeof l === "string" && l !== "vql" && (HUNT_LANGUAGES as readonly string[]).includes(l);

/** The case's main source over its forensic timeline, with the stored override (a store failure → none). */
export async function loadMainSource(
  ctx: CaseHuntContext,
  caseId: string,
  loaded: InvestigationState,
): Promise<MainSourceResult> {
  const override = await (ctx.opts.mainSourceStore?.load(caseId) ?? Promise.resolve(null)).catch(() => null);
  return computeMainSource(loaded.forensicTimeline, override);
}

/** A tenant-only case (#2555) never falls back to VQL: there is no endpoint to run it on. */
const fallbackFamily = (s: InvestigationState): SourceFamily | null =>
  isCloudOnlyCase({ events: s.forensicTimeline }) ? "cloud-other" : null;

const eventIndex = (s: InvestigationState): Map<string, ForensicEvent> =>
  new Map(s.forensicTimeline.map((e) => [e.id, e]));

/** Fleet hunts for the case, in the language(s) its evidence calls for. */
export async function suggestCaseHunts(
  ctx: CaseHuntContext,
  caseId: string,
  opts: CaseHuntOptions = {},
): Promise<CaseHuntResult> {
  if (opts.excludeVql)
    return { suggestions: await suggestHunts(ctx, caseId, { excludeVql: opts.excludeVql }) };
  if (isCopyLanguage(opts.language))
    return {
      suggestions: [],
      languageHunts: await suggestLanguageHunts(ctx, caseId, opts.language, { exclude: opts.excludeQuery }),
    };
  const loaded = await ctx.opts.stateStore.load(caseId);
  if (!hasHuntMaterial(loaded)) return { suggestions: await suggestHunts(ctx, caseId) }; // [] with no AI call
  const main = await loadMainSource(ctx, caseId, loaded);
  const live = loaded.findings.filter((f) => f.status !== "dismissed");
  const byId = eventIndex(loaded);
  // With no finding yet the hunt still pivots on the timeline; one placeholder carries the language.
  const items: Array<Pick<Finding, "id" | "relatedEventIds">> = live.length
    ? live
    : [{ id: "", relatedEventIds: [] }];
  const plan = planHuntGroups(
    items,
    (f) => familyForFinding(f, byId),
    (f) => f.id,
    main,
    enabledHuntPlatforms(),
    fallbackFamily(loaded),
  );
  const vql = plan.groups.find((g) => g.language === "vql");
  const others = plan.groups.filter(
    (g): g is { language: CopyHuntLanguage; ids: string[] } => g.language !== "vql",
  );
  if (vql && !others.length && !plan.notes.length) return { suggestions: await suggestHunts(ctx, caseId) };

  const vqlIds = new Set(vql?.ids ?? []);
  const suggestions = vql
    ? (await suggestHunts(ctx, caseId)).filter(
        (s) => !s.relatedFindingIds.length || s.relatedFindingIds.some((id) => vqlIds.has(id)),
      )
    : [];
  const languageHunts: LanguageHuntSuggestion[] = [];
  for (const g of others) {
    const findingIds = live.length ? g.ids : undefined;
    languageHunts.push(...(await suggestLanguageHunts(ctx, caseId, g.language, { findingIds })));
  }
  return { suggestions, languageHunts, notes: plan.notes };
}

export interface PlaybookLanguagePlan {
  /** taskId → hunt language (null: the task's evidence has no hunt language). */
  languages: Record<string, HuntLanguage | null>;
  notes: string[];
}

/** Which language each playbook task's hunt is written in. A task's evidence is its finding's. */
export async function planPlaybookHuntLanguages(
  ctx: CaseHuntContext,
  caseId: string,
  tasks: readonly PlaybookTask[],
): Promise<PlaybookLanguagePlan> {
  const loaded = await ctx.opts.stateStore.load(caseId);
  const main = await loadMainSource(ctx, caseId, loaded);
  const byId = eventIndex(loaded);
  const findings = new Map(loaded.findings.map((f) => [f.id, f]));
  const familyOfTask = (t: PlaybookTask) => {
    const f = t.relatedFindingId ? findings.get(t.relatedFindingId) : undefined;
    return f ? familyForFinding(f, byId) : null;
  };
  const plan = planHuntGroups(
    tasks,
    familyOfTask,
    (t) => t.id,
    main,
    enabledHuntPlatforms(),
    fallbackFamily(loaded),
  );
  const languages: Record<string, HuntLanguage | null> = Object.fromEntries(tasks.map((t) => [t.id, null]));
  for (const g of plan.groups) for (const id of g.ids) languages[id] = g.language;
  return { languages, notes: plan.notes };
}

/** The bound surface AnalysisPipeline exposes as `caseHunts` (one getter keeps pipeline.ts small). */
export interface CaseHuntsApi {
  suggest(caseId: string, opts?: CaseHuntOptions): Promise<CaseHuntResult>;
  planPlaybook(caseId: string, tasks: readonly PlaybookTask[]): Promise<PlaybookLanguagePlan>;
  suggestPlaybook(
    caseId: string,
    tasks: PlaybookTask[],
    language: CopyHuntLanguage,
    opts?: { exclude?: string },
  ): Promise<PlaybookLanguageHunt[]>;
}

export function bindCaseHunts(ctx: CaseHuntContext): CaseHuntsApi {
  return {
    suggest: (caseId, opts) => suggestCaseHunts(ctx, caseId, opts),
    planPlaybook: (caseId, tasks) => planPlaybookHuntLanguages(ctx, caseId, tasks),
    suggestPlaybook: (caseId, tasks, language, opts) =>
      suggestPlaybookLanguageHunts(ctx, caseId, tasks, language, opts),
  };
}
