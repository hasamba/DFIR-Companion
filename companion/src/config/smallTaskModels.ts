import { DEFAULT_VELO_MODEL, visionEnv, type EnvSource } from "./aiEnv.js";

/**
 * The small, well-scoped AI tasks that may run on the light-task model (#2593), and the model each
 * one uses as the diagnostics view names it. The provider choice itself lives in
 * analysis/ai/smallTaskModel.ts (smallTaskProvider); both follow the same order:
 *
 * - VQL hunts: the Velociraptor hunt model → the light-task model → the synthesis model.
 * - Language hunts (CQL / KQL / ES|QL / SPL) and query translation: the light-task model → the
 *   synthesis model.
 *
 * In practice the Velociraptor hunt model always builds (it has a default), so VQL names it.
 */
export type SmallTask = "vql-hunt" | "language-hunt" | "query-translation";

export function smallTaskModels(env: EnvSource): Record<SmallTask, string> {
  const light = env.DFIR_AI_LIGHT_MODEL?.trim();
  const synth = env.DFIR_AI_SYNTH_MODEL?.trim() || visionEnv(env, "MODEL")?.trim() || "?";
  const general = light ? `${light} (light-task model)` : `${synth} (synthesis model)`;
  const velo = env.DFIR_AI_VELO_MODEL?.trim() || DEFAULT_VELO_MODEL;
  return {
    "vql-hunt": `${velo} (Velociraptor hunt model)`,
    "language-hunt": general,
    "query-translation": general,
  };
}
