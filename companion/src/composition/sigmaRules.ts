// Server wiring for the import-time Sigma rules (#2202): load the bundled SigmaHQ rules once, log
// what loaded, and hand the importers a grader that checks DFIR_SIGMA_RULES on every import — so
// switching it off in Settings takes effect on the next import, without a restart.

import { bundledSigmaDir, loadBundledSigmaRuleSet } from "../analysis/sigmaBundledRules.js";
import { SigmaRuleStore } from "../analysis/sigmaRuleStore.js";
import { sigmaMinLevelFromEnv, sigmaUpdateCheckEnabled } from "../analysis/sigmaSettings.js";
import { createSigmaImportGrader, type SigmaImportGrader } from "../analysis/sigmaImportGrade.js";
import type { SigmaRuleSet } from "../analysis/sigmaRuleSet.js";
import { getServerLogger } from "../logging/serverLogger.js";

const OFF = new Set(["off", "0", "false", "no"]);

/** On unless DFIR_SIGMA_RULES says off / 0 / false / no. */
export function sigmaRulesEnabled(env: NodeJS.ProcessEnv = process.env): boolean {
  return !OFF.has(env.DFIR_SIGMA_RULES?.trim().toLowerCase() ?? "");
}

/** One line per log source: loaded / disabled / refused / filtered by status. */
export function sigmaInventorySummary(set: SigmaRuleSet): string {
  const per = new Map<string, Record<string, number>>();
  for (const e of set.inventory) {
    const key = e.source ?? "other";
    const row = per.get(key) ?? {};
    row[e.outcome] = (row[e.outcome] ?? 0) + 1;
    per.set(key, row);
  }
  const parts = [...per].map(
    ([src, row]) =>
      `${src}: ${Object.entries(row)
        .map(([k, n]) => `${n} ${k}`)
        .join(", ")}`,
  );
  return `Sigma rules ${set.release} — ${parts.join("; ")}`;
}

let cached: SigmaImportGrader | undefined;

/** The bundled-rules grader, for scripts and tests that run without a server data folder. */
export function bundledSigmaGrader(): SigmaImportGrader {
  if (cached) return cached;
  const { set, problem } = loadBundledSigmaRuleSet();
  const log = getServerLogger();
  if (problem) log.warn(`Sigma rules not loaded: ${problem}`);
  else log.info(sigmaInventorySummary(set));
  cached = createSigmaImportGrader(set, {
    enabled: () => sigmaRulesEnabled(),
    minLevel: () => sigmaMinLevelFromEnv().level,
  });
  return cached;
}

let store: SigmaRuleStore | undefined;
let storeGrader: SigmaImportGrader | undefined;

/**
 * Set up the installed-rules store under the server data folder (#2204). Called once by the runtime
 * stores; loads the active release synchronously, so the first import already grades with it.
 */
export function configureSigmaRules(dataRoot: string): SigmaRuleStore {
  const s = new SigmaRuleStore(dataRoot, bundledSigmaDir());
  s.load();
  store = s;
  storeGrader = createSigmaImportGrader(() => s.activeRuleSet(), {
    enabled: () => sigmaRulesEnabled(),
    minLevel: () => sigmaMinLevelFromEnv().level,
  });
  const log = getServerLogger();
  void s.init().then(
    () => {
      const set = s.activeRuleSet();
      log.info(sigmaInventorySummary(set));
      for (const p of set.problems) log.warn(`Sigma rules: ${p}`);
    },
    (error: unknown) => log.warn(`Sigma rules: startup clean-up failed: ${(error as Error).message}`),
  );
  return s;
}

/** The installed-rules store, once configured. */
export const sigmaRuleStore = (): SigmaRuleStore | undefined => store;

/** The grader imports use: the installed-rules store's when configured, else the bundled rules. */
export function sigmaGrader(): SigmaImportGrader {
  return storeGrader ?? bundledSigmaGrader();
}

/** The optional startup check (DFIR_SIGMA_UPDATE_CHECK=on): a notice, never an install. */
export async function startupSigmaUpdateCheck(fetchFn: typeof fetch): Promise<void> {
  if (!store || !sigmaUpdateCheckEnabled()) return;
  const r = await store.checkLatest(fetchFn);
  const log = getServerLogger();
  if (r.error) log.warn(`Sigma update check failed: ${r.error}`);
  else if (r.updateAvailable)
    log.info(`New Sigma release available: ${r.latest} (installed: ${r.installed})`);
}
