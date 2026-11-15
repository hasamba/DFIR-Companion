import { isLocalAiProvider } from "./anonymize.js";
import { AI_ROLE_SOURCES, resolveAiRoleSetting, visionEnv, watsonRoleOff } from "../config/aiEnv.js";

type EnvLike = Record<string, string | undefined>;

/** Watson's own connection in the Diagnostics AI view (U2). Never carries the key. */
export interface WatsonDiagnostics {
  provider: string;
  /** Null when Watson is off: another provider than synthesis and no Watson model. */
  model: string | null;
  /** True when Watson's provider or base URL is local, so its prompts never leave the machine. */
  local: boolean;
}

const orNull = (v: string | undefined): string | null => v?.trim() || null;

/**
 * Watson's connection when it differs from the synthesis one: its own provider or base URL is set.
 * Null when Watson uses the synthesis connection, which the rest of the view already describes.
 */
export function watsonDiagnostics(env: EnvLike): WatsonDiagnostics | null {
  if (!env.DFIR_AI_WATSON_PROVIDER?.trim() && !env.DFIR_AI_WATSON_BASE_URL?.trim()) return null;
  const provider = AI_ROLE_SOURCES.watson.provider(env);
  if (!provider) return null;
  const synthModel = orNull(env.DFIR_AI_SYNTH_MODEL) ?? orNull(visionEnv(env, "MODEL"));
  const model = watsonRoleOff(env) ? null : (orNull(env.DFIR_AI_WATSON_MODEL) ?? synthModel);
  const baseUrl = resolveAiRoleSetting(env, "watson", "BASE_URL");
  return { provider, model, local: isLocalAiProvider(provider, baseUrl) };
}

/** The Watson line of the copy-to-clipboard Diagnostics text. */
export function watsonDiagnosticsLine(w: WatsonDiagnostics): string {
  const model = w.model ?? "no model configured";
  return `  watson:   ${w.provider} / ${model} (${w.local ? "local" : "external"})`;
}
