import { readFile } from "node:fs/promises";
import { join } from "node:path";
import type { CaseStore } from "../storage/caseStore.js";
import { atomicWrite } from "../storage/atomicWrite.js";
import { HUNT_LANGUAGES, type CopyHuntLanguage, type HuntLanguage } from "./huntLanguage.js";
import type { PlaybookLanguageHunt } from "./languageHuntSuggest.js";
import type { PlaybookTask } from "./playbook.js";
import { isOpenTask, taskFingerprint } from "./playbookHunt.js";

// Persisted per-task hunts in the case's main-source language (#2559) — the non-VQL sibling of the
// VQL `playbook-hunts.json` (PlaybookHuntStore), kept in its own file so the VQL file and its
// incremental logic stay exactly as they were.
//
// A stored hunt is fresh while its task is unchanged (same fingerprint as playbookHunt.ts) AND the
// task's hunt language is still the language it was written in — so changing the main-source
// override (or new evidence moving it) retires the old cards instead of showing a CQL query on a
// task that is now KQL. `evaluated` marks tasks the model already saw in a language, so a task it
// judged irrelevant is not re-sent on every press (the VQL store's taskHashes do the same).

export interface StoredLanguageHunt extends PlaybookLanguageHunt {
  taskHash: string;
}

export interface PersistedLanguageHunts {
  hunts: StoredLanguageHunt[];
  /** taskId → `${fingerprint}|${language}` of the last generation that saw it. */
  evaluated: Record<string, string>;
}

export const EMPTY_LANGUAGE_HUNTS: PersistedLanguageHunts = { hunts: [], evaluated: {} };

const evalKey = (t: PlaybookTask, language: HuntLanguage): string => `${taskFingerprint(t)}|${language}`;
const isCopy = (l: HuntLanguage | null | undefined): l is CopyHuntLanguage => !!l && l !== "vql";

export class PlaybookLanguageHuntStore {
  constructor(private readonly cases: CaseStore) {}

  private path(caseId: string): string {
    return join(this.cases.stateDir(caseId), "playbook-language-hunts.json");
  }

  async load(caseId: string): Promise<PersistedLanguageHunts> {
    try {
      const raw = JSON.parse(await readFile(this.path(caseId), "utf8")) as Partial<PersistedLanguageHunts>;
      const hunts = Array.isArray(raw.hunts)
        ? raw.hunts.filter((h) => (HUNT_LANGUAGES as readonly string[]).includes(h?.language) && !!h?.query)
        : [];
      const evaluated = raw.evaluated && typeof raw.evaluated === "object" ? raw.evaluated : {};
      return { hunts, evaluated };
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === "ENOENT") return { hunts: [], evaluated: {} };
      return { hunts: [], evaluated: {} }; // a corrupt file only costs a regenerate
    }
  }

  async save(caseId: string, data: PersistedLanguageHunts): Promise<void> {
    await atomicWrite(this.path(caseId), JSON.stringify(data, null, 2));
  }
}

/** Stored hunts still valid for the current tasks and their current languages. Pure. */
export function selectFreshLanguageHunts(
  stored: PersistedLanguageHunts,
  tasks: readonly PlaybookTask[],
  languages: Readonly<Record<string, HuntLanguage | null>>,
): PersistedLanguageHunts {
  const byId = new Map(tasks.map((t) => [t.id, t] as const));
  const hunts = stored.hunts.filter((h) => {
    const t = byId.get(h.taskId);
    return !!t && h.taskHash === taskFingerprint(t) && languages[h.taskId] === h.language;
  });
  const evaluated: Record<string, string> = {};
  for (const [id, key] of Object.entries(stored.evaluated)) {
    const t = byId.get(id);
    const lang = languages[id];
    if (t && lang && key === evalKey(t, lang)) evaluated[id] = key;
  }
  return { hunts, evaluated };
}

/** Open tasks of `language` the model has not yet seen in that language (all of them when forced). */
export function pendingLanguageTasks(
  tasks: readonly PlaybookTask[],
  languages: Readonly<Record<string, HuntLanguage | null>>,
  language: CopyHuntLanguage,
  fresh: PersistedLanguageHunts,
): PlaybookTask[] {
  return tasks.filter(
    (t) => isOpenTask(t) && languages[t.id] === language && fresh.evaluated[t.id] !== evalKey(t, language),
  );
}

/** The copy languages present in a plan, in HUNT_LANGUAGES order. */
export function copyLanguagesIn(
  languages: Readonly<Record<string, HuntLanguage | null>>,
): CopyHuntLanguage[] {
  const present = new Set(Object.values(languages));
  return HUNT_LANGUAGES.filter((l): l is CopyHuntLanguage => isCopy(l) && present.has(l));
}

/**
 * Fold new hunts for `sent` tasks into the fresh set. Pure. Every sent task is marked evaluated,
 * unless the batch hit the per-generation cap (`capped`): then the model may never have reached the
 * rest, so only the tasks it answered are marked and the others stay pending for the next press —
 * the same rule as the VQL path in routes/playbookHunts.ts.
 */
export function mergeLanguageHunts(
  fresh: PersistedLanguageHunts,
  sent: readonly PlaybookTask[],
  language: CopyHuntLanguage,
  generated: readonly PlaybookLanguageHunt[],
  capped = false,
): PersistedLanguageHunts {
  const sentIds = new Set(sent.map((t) => t.id));
  const byId = new Map(sent.map((t) => [t.id, t] as const));
  const answered = new Set(generated.map((h) => h.taskId));
  const evaluated = { ...fresh.evaluated };
  for (const t of sent) if (!capped || answered.has(t.id)) evaluated[t.id] = evalKey(t, language);
  const added = generated
    .filter((h) => byId.has(h.taskId))
    .map((h) => ({ ...h, taskHash: taskFingerprint(byId.get(h.taskId) as PlaybookTask) }));
  return { hunts: [...fresh.hunts.filter((h) => !sentIds.has(h.taskId)), ...added], evaluated };
}

/** What the dashboard is sent: the hunts without the internal fingerprint. */
export const languageHuntView = (data: PersistedLanguageHunts): PlaybookLanguageHunt[] =>
  data.hunts.map(({ taskHash: _taskHash, ...h }) => h);
