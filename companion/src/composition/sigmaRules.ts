// Server wiring for the import-time Sigma rules (#2202): load the bundled SigmaHQ rules once, log
// what loaded, and hand the importers a grader that checks DFIR_SIGMA_RULES on every import — so
// switching it off in Settings takes effect on the next import, without a restart.

import { loadBundledSigmaRuleSet } from "../analysis/sigmaBundledRules.js";
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

/** The bundled-rules grader, loaded on first use and shared by every pipeline. */
export function bundledSigmaGrader(): SigmaImportGrader {
  if (cached) return cached;
  const { set, problem } = loadBundledSigmaRuleSet();
  const log = getServerLogger();
  if (problem) log.warn(`Sigma rules not loaded: ${problem}`);
  else log.info(sigmaInventorySummary(set));
  cached = createSigmaImportGrader(set, { enabled: () => sigmaRulesEnabled() });
  return cached;
}
