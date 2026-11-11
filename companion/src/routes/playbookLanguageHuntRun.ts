import type { PlaybookLanguagePlan } from "../analysis/ai/caseHunts.js";
import type { CopyHuntLanguage, HuntLanguage } from "../analysis/huntLanguage.js";
import { HUNT_LANGUAGES } from "../analysis/huntLanguage.js";
import type { PlaybookLanguageHunt } from "../analysis/languageHuntSuggest.js";
import type { AnalysisPipeline } from "../analysis/pipeline.js";
import type { PlaybookTask } from "../analysis/playbook.js";
import {
  copyLanguagesIn,
  EMPTY_LANGUAGE_HUNTS,
  languageHuntView,
  mergeLanguageHunts,
  pendingLanguageTasks,
  selectFreshLanguageHunts,
  type PlaybookLanguageHuntStore,
} from "../analysis/playbookLanguageHunts.js";

// The per-task hunts in the case's main-source language (#2559), for the playbook route. The VQL
// tasks keep going through the existing incremental path in playbookHunts.ts, unchanged; this runs
// the CQL / KQL / ES|QL / SPL tasks beside it and keeps their own persisted file.

export interface LanguageRunDeps {
  pipeline: AnalysisPipeline;
  store?: PlaybookLanguageHuntStore;
  log: (msg: string) => void;
}

export interface LanguageRunResult {
  languageSuggestions: PlaybookLanguageHunt[];
  generated: number;
}

/** Only VQL tasks go down the VQL path: a task whose evidence calls for another language — or none — does not. */
export const vqlTasksOf = (tasks: readonly PlaybookTask[], plan: PlaybookLanguagePlan): PlaybookTask[] =>
  tasks.filter((t) => plan.languages[t.id] === "vql");

export const isCopyLanguage = (l: unknown): l is CopyHuntLanguage =>
  typeof l === "string" && l !== "vql" && (HUNT_LANGUAGES as readonly string[]).includes(l);

async function persist(
  deps: LanguageRunDeps,
  caseId: string,
  data: Parameters<PlaybookLanguageHuntStore["save"]>[1],
) {
  if (!deps.store) return;
  try {
    await deps.store.save(caseId, data);
  } catch (e) {
    deps.log(`[playbook] could not persist language hunts: ${(e as Error).message}`);
  }
}

/** Generate (incrementally, or every task when forced) the language hunts, persist and return them. */
export async function runLanguageHunts(
  deps: LanguageRunDeps,
  caseId: string,
  tasks: readonly PlaybookTask[],
  languages: Readonly<Record<string, HuntLanguage | null>>,
  opts: {
    force?: boolean;
    regen?: { task: PlaybookTask; language: CopyHuntLanguage; exclude?: string };
  } = {},
): Promise<LanguageRunResult> {
  const stored = deps.store ? await deps.store.load(caseId) : EMPTY_LANGUAGE_HUNTS;
  let data = selectFreshLanguageHunts(opts.force ? EMPTY_LANGUAGE_HUNTS : stored, tasks, languages);
  let generated = 0;
  const batches: Array<{ language: CopyHuntLanguage; sent: PlaybookTask[]; exclude?: string }> = opts.regen
    ? [{ language: opts.regen.language, sent: [opts.regen.task], exclude: opts.regen.exclude }]
    : copyLanguagesIn(languages).map((language) => ({
        language,
        sent: pendingLanguageTasks(tasks, languages, language, data),
      }));
  for (const b of batches) {
    if (!b.sent.length) continue;
    const hunts = await deps.pipeline.caseHunts.suggestPlaybook(caseId, b.sent, b.language, {
      exclude: b.exclude,
    });
    generated += hunts.length;
    data = mergeLanguageHunts(data, b.sent, b.language, hunts);
  }
  if (generated || batches.some((b) => b.sent.length)) await persist(deps, caseId, data);
  deps.log(`[playbook] ${generated} main-source-language hunt(s) generated for ${caseId}`);
  return { languageSuggestions: languageHuntView(data), generated };
}

/** The stored language hunts still valid for the current tasks (read path; never writes). */
export async function freshLanguageHunts(
  store: PlaybookLanguageHuntStore | undefined,
  caseId: string,
  tasks: readonly PlaybookTask[],
  languages: Readonly<Record<string, HuntLanguage | null>>,
): Promise<PlaybookLanguageHunt[]> {
  if (!store) return [];
  try {
    return languageHuntView(selectFreshLanguageHunts(await store.load(caseId), tasks, languages));
  } catch {
    return [];
  }
}
