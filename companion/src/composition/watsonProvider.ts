import type { AIProvider } from "../providers/provider.js";
import { AI_ROLE_SOURCES, resolveAiRoleSetting, visionEnv, watsonRoleOff } from "../config/aiEnv.js";
import { buildProviderFrom } from "./aiProviders.js";

/**
 * The model Watson talks to (U2). `DFIR_AI_WATSON_PROVIDER` blank: the synthesis provider, key and
 * base URL, so with a blank `DFIR_AI_WATSON_MODEL` Watson is the synthesis provider exactly as
 * synthesis builds it. A named provider resolves its own key and base URL (own value → the
 * provider's saved value → vision). On a provider other than synthesis's, a blank Watson model
 * builds nothing: Watson then shows "no model configured" and never guesses a model. Undefined, too,
 * when no provider is configured at all. Read from `env` on every call, so a saved change applies to
 * the next message.
 */
export function buildWatsonProvider(env: NodeJS.ProcessEnv): AIProvider | undefined {
  if (watsonRoleOff(env)) return undefined;
  const ownModel = env.DFIR_AI_WATSON_MODEL?.trim();
  return buildProviderFrom({
    provider: AI_ROLE_SOURCES.watson.provider(env),
    model: ownModel || (env.DFIR_AI_SYNTH_MODEL ?? visionEnv(env, "MODEL")),
    apiKey: resolveAiRoleSetting(env, "watson", "KEY"),
    baseUrl: resolveAiRoleSetting(env, "watson", "BASE_URL"),
    imageDetail: visionEnv(env, "IMAGE_DETAIL") as "high" | "low" | "auto" | undefined,
  });
}
