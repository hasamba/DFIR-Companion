// Server wiring for the import-time Sigma rules (#2202): load the bundled SigmaHQ rules (and the
// bundled Suzaku rules, #2499) once, log
// what loaded, and hand the importers a grader that checks DFIR_SIGMA_RULES on every import — so
// switching it off in Settings takes effect on the next import, without a restart.

import { bundledSigmaDir, loadBundledSigmaRuleSet } from "../analysis/sigmaBundledRules.js";
import { SigmaRuleStore } from "../analysis/sigmaRuleStore.js";
import { bundledSuzakuDir } from "../analysis/sigmaSuzakuRules.js";
import { SuzakuRuleStore } from "../analysis/suzakuRuleStore.js";
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
  const origins = set.origins.map((o) => ` + ${o.name} ${o.release}`).join("");
  return `Sigma rules ${set.release}${origins} — ${parts.join("; ")}`;
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
  // The Suzaku rules come from the installed-version store (#2508): the bundled folder until an
  // analyst installs a newer commit. Always connected — even with the bundled folder missing, an
  // installed version still grades; with neither, the store reports the missing folder.
  const suzaku = new SuzakuRuleStore(dataRoot, bundledSuzakuDir());
  suzaku.load();
  suzakuStore = suzaku;
  const s = new SigmaRuleStore(dataRoot, bundledSigmaDir(), process.env, suzaku);
  s.load();
  store = s;
  storeGrader = createSigmaImportGrader(() => s.activeRuleSet(), {
    enabled: () => sigmaRulesEnabled(),
    minLevel: () => sigmaMinLevelFromEnv().level,
  });
  const log = getServerLogger();
  void suzaku
    .init()
    .catch((error: unknown) =>
      getServerLogger().warn(`Suzaku rules: startup clean-up failed: ${(error as Error).message}`),
    );
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

let suzakuStore: SuzakuRuleStore | undefined;

/** The installed Suzaku rules store (#2508), once configured. */
export const suzakuRuleStore = (): SuzakuRuleStore | undefined => suzakuStore;

/** The installed-rules store, once configured. */
export const sigmaRuleStore = (): SigmaRuleStore | undefined => store;

/** The grader imports use: the installed-rules store's when configured, else the bundled rules. */
export function sigmaGrader(): SigmaImportGrader {
  return storeGrader ?? bundledSigmaGrader();
}

/** The optional startup check (DFIR_SIGMA_UPDATE_CHECK=on): a notice, never an install. */
export async function startupSigmaUpdateCheck(fetchFn: typeof fetch): Promise<void> {
  if (!store || !sigmaUpdateCheckEnabled()) return;
  const r = await store.checkLatest(fetchFn, true);
  const log = getServerLogger();
  if (r.error) log.warn(`Sigma update check failed: ${r.error}`);
  else if (r.updateAvailable)
    log.info(`New Sigma release available: ${r.latest} (installed: ${r.installed})`);
  // #2518: unreleased SigmaHQ changes to the graded rules — a notice, never an install.
  if (r.main && "gradedChanges" in r.main && r.main.gradedChanges > 0)
    log.info(
      `SigmaHQ main branch: ${r.main.gradedChanges} unreleased change(s) to graded rules (newest ${r.main.date})`,
    );
  // #2508: the same opt-in startup check also asks about the Suzaku rules — a notice, never an install.
  const sz = suzakuStore ? await suzakuStore.checkLatest(fetchFn) : undefined;
  if (sz?.error) log.warn(`Suzaku rules update check failed: ${sz.error}`);
  else if (sz?.updateAvailable)
    log.info(`New Suzaku rules available: ${sz.latest} (installed: ${sz.installed})`);
}
