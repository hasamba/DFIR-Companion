import type { AIProvider } from "../../providers/provider.js";
import type { SmallTask } from "../../config/smallTaskModels.js";

/**
 * Which model a small, well-scoped AI call runs on (#2593), read by hunts.ts and languageHunts.ts.
 * config/smallTaskModels.ts names the same choice for diagnostics — keep the two orders together:
 *
 * - VQL hunts: the Velociraptor hunt model → the light-task model → the synthesis model.
 * - Language hunts (CQL / KQL / ES|QL / SPL) and query translation: the light-task model → the
 *   synthesis model. Never the VQL-tuned model — it biases toward VQL and ignores other languages.
 *
 * The light-task model is the analyst's opt-in (DFIR_AI_LIGHT_MODEL); with it blank every call here
 * runs exactly as before. Synthesis, deep passes, reports and imports never read this.
 */
export type { SmallTask } from "../../config/smallTaskModels.js";

export interface SmallTaskProviders {
  readonly velociraptorProvider?: AIProvider;
  readonly lightProvider?: AIProvider;
  readonly synthesisProvider?: AIProvider;
}

export function smallTaskProvider(opts: SmallTaskProviders, task: SmallTask): AIProvider | undefined {
  const general = opts.lightProvider ?? opts.synthesisProvider;
  return task === "vql-hunt" ? (opts.velociraptorProvider ?? general) : general;
}
