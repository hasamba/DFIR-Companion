import type { AIProvider } from "../../providers/provider.js";
import { uniqueProviderModels } from "../analysisRunRecorders.js";

/** A model chosen to referee the second-opinion verdicts (#1466), with the label the panel shows. */
export interface RefereeModel {
  provider: AIProvider;
  label: string;
}

/** The providers a pipeline may call, in the order the run records them. */
export interface ProviderRoster {
  provider?: AIProvider;
  synthesisProvider?: AIProvider;
  secondOpinionProvider?: AIProvider;
  referee?: RefereeModel;
}

// Every configured provider, for cost/telemetry lookups. Pulled out of AnalysisPipeline so the
// roster has one definition; the pipeline's public methods delegate here.
export function rosterProviders(opts: ProviderRoster): Array<AIProvider | undefined> {
  return [opts.provider, opts.synthesisProvider, opts.secondOpinionProvider, opts.referee?.provider];
}

export function analysisProviderModels(opts: ProviderRoster): Array<{ provider: string; model: string }> {
  return uniqueProviderModels(rosterProviders(opts));
}

export function findAnalysisProvider(
  opts: ProviderRoster,
  providerName: string,
  model: string,
): AIProvider | undefined {
  return rosterProviders(opts).find((p) => p?.name === providerName && p.model === model);
}
