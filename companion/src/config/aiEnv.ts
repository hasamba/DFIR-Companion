// The screenshot/vision provider config was renamed DFIR_AI_* → DFIR_VISION_* (2026-07). This model
// reads SCREENSHOTS ONLY (it must be multimodal); the DFIR_AI_SYNTH_* family does ALL text work
// (CSV/log extraction, synthesis, ask/explain, summaries, hunts, …).
//
// The legacy DFIR_AI_* names are still honored as a DEPRECATED fallback so existing .env files keep
// working after an upgrade — the new DFIR_VISION_* name WINS when both are set. Only the five vision
// vars below moved; the shared tuning vars (DFIR_AI_TIMEOUT_MS / _MAX_TOKENS / _CONTEXT_TOKENS) and
// the whole DFIR_AI_SYNTH_* family are intentionally NOT renamed.

export type VisionEnvSuffix = "PROVIDER" | "MODEL" | "KEY" | "BASE_URL" | "IMAGE_DETAIL";

/** A subset of process.env — any string-keyed env-like map. */
export type EnvSource = Record<string, string | undefined>;

/** The five vision-config suffixes, in .env declaration order. */
export const VISION_ENV_SUFFIXES: readonly VisionEnvSuffix[] = [
  "PROVIDER",
  "MODEL",
  "KEY",
  "BASE_URL",
  "IMAGE_DETAIL",
];

/** A blank value counts as unset: `KEY=` loads as "", and "" must not pass a `??` fallback (#1785). */
const setValue = (value: string | undefined): string | undefined => (value?.trim() ? value : undefined);

/** New DFIR_VISION_<suffix> wins; legacy DFIR_AI_<suffix> is the deprecated fallback. Blank is unset. */
export function visionEnv(env: EnvSource, suffix: VisionEnvSuffix): string | undefined {
  return setValue(env[`DFIR_VISION_${suffix}`]) ?? setValue(env[`DFIR_AI_${suffix}`]);
}

/** The legacy DFIR_AI_<suffix> name behind a DFIR_VISION_<suffix> key, or undefined for any other key. */
export function legacyVisionAlias(key: string): string | undefined {
  const suffix = key.startsWith("DFIR_VISION_") ? key.slice("DFIR_VISION_".length) : "";
  return (VISION_ENV_SUFFIXES as readonly string[]).includes(suffix) ? `DFIR_AI_${suffix}` : undefined;
}

/**
 * For the Settings form: surface each legacy DFIR_AI_<suffix> value under its new DFIR_VISION_<suffix>
 * key when the new key is unset or blank in the file, so an existing install's value still populates the
 * renamed field (and a Save then writes the canonical new name). Returns a shallow copy — never
 * mutates the input. The legacy keys are left in place so nothing is hidden.
 */
export function withVisionEnvAliases(env: EnvSource): EnvSource {
  const out: EnvSource = { ...env };
  for (const suffix of VISION_ENV_SUFFIXES) {
    const newKey = `DFIR_VISION_${suffix}`;
    const oldKey = `DFIR_AI_${suffix}`;
    if (setValue(out[newKey]) === undefined && out[oldKey] !== undefined) out[newKey] = out[oldKey];
  }
  return out;
}

// One saved key and base URL per API provider (DFIR_AI_KEY_<PROVIDER>, DFIR_AI_BASE_URL_<PROVIDER>),
// so switching a role to another provider needs nothing typed again. The per-role *_KEY and
// *_BASE_URL slots are provider-agnostic: a role moved from openrouter to gemini kept sending the
// OpenRouter key, and Google answered HTTP 400. The CLI providers (claude-code, codex) sign in on
// their own and have no entry.
export const PROVIDER_ENV_NAMES: Readonly<Record<string, string>> = {
  openai: "OPENAI",
  openrouter: "OPENROUTER",
  ollama: "OLLAMA",
  litellm: "LITELLM",
  gemini: "GEMINI",
  anthropic: "ANTHROPIC",
};

export type ProviderEnvSetting = "KEY" | "BASE_URL";

/** The saved setting for one provider, or undefined when none is set. A blank value counts as unset. */
export function providerEnv(
  env: EnvSource,
  provider: string | undefined,
  setting: ProviderEnvSetting,
): string | undefined {
  const name = PROVIDER_ENV_NAMES[(provider ?? "").trim().toLowerCase()];
  const value = name ? env[`DFIR_AI_${setting}_${name}`]?.trim() : undefined;
  return value || undefined;
}

/**
 * The key or base URL one AI role uses: its own value, then the saved value for the provider it
 * uses, then the vision value. A blank role value yields to the provider value, because Settings
 * saves an untouched field as an empty value. With no provider value the old `role ?? vision`
 * result stands.
 */
export function resolveRoleSetting(
  env: EnvSource,
  provider: string | undefined,
  setting: ProviderEnvSetting,
  roleValue: string | undefined,
): string | undefined {
  if (roleValue?.trim()) return roleValue;
  return providerEnv(env, provider, setting) ?? roleValue ?? visionEnv(env, setting);
}

// Where each of the five AI roles reads its provider and its own key / base URL. aiProviders.ts
// builds the running roles from this table, the model picker reads saved credentials through it,
// and the per-provider key migration checks every role against it — one reader, so the three
// cannot drift apart.
export type AiRoleId =
  "vision" | "synthesis" | "synthesis-fallback" | "velociraptor" | "second-opinion" | "reconcile";

/** The Velociraptor role's provider when DFIR_AI_VELO_PROVIDER is unset or blank. */
export const DEFAULT_VELO_PROVIDER = "openrouter";

export interface AiRoleSource {
  readonly role: AiRoleId;
  /** The provider the role runs on. */
  readonly provider: (env: EnvSource) => string | undefined;
  /** The env names that hold the role's own value, winner first (vision: new name, then legacy). */
  readonly ownNames: (setting: ProviderEnvSetting) => readonly string[];
}

export const AI_ROLE_SOURCES: Readonly<Record<AiRoleId, AiRoleSource>> = {
  vision: {
    role: "vision",
    provider: (env) => visionEnv(env, "PROVIDER"),
    ownNames: (s) => [`DFIR_VISION_${s}`, `DFIR_AI_${s}`],
  },
  synthesis: {
    role: "synthesis",
    provider: (env) => env.DFIR_AI_SYNTH_PROVIDER?.trim() || visionEnv(env, "PROVIDER"),
    ownNames: (s) => [`DFIR_AI_SYNTH_${s}`],
  },
  // #1734: the model synthesis switches to when a safety filter stops it. A blank provider runs on
  // the synthesis provider, the same fallback the running role uses (synthesisFallbackConfig).
  "synthesis-fallback": {
    role: "synthesis-fallback",
    provider: (env) => env.DFIR_AI_SYNTH_FALLBACK_PROVIDER?.trim() || AI_ROLE_SOURCES.synthesis.provider(env),
    ownNames: (s) => [`DFIR_AI_SYNTH_FALLBACK_${s}`],
  },
  velociraptor: {
    role: "velociraptor",
    provider: (env) => env.DFIR_AI_VELO_PROVIDER?.trim() || DEFAULT_VELO_PROVIDER,
    ownNames: (s) => [`DFIR_AI_VELO_${s}`],
  },
  "second-opinion": {
    role: "second-opinion",
    provider: (env) => env.DFIR_AI_SECOND_OPINION_PROVIDER?.trim() || visionEnv(env, "PROVIDER"),
    ownNames: (s) => [`DFIR_AI_SECOND_OPINION_${s}`],
  },
  reconcile: {
    role: "reconcile",
    provider: (env) => env.DFIR_AI_RECONCILE_PROVIDER?.trim() || visionEnv(env, "PROVIDER"),
    ownNames: (s) => [`DFIR_AI_RECONCILE_${s}`],
  },
};

/** The role's own value: the first of its names that is set, `??` style like visionEnv. */
export function roleOwnSetting(
  env: EnvSource,
  role: AiRoleId,
  setting: ProviderEnvSetting,
): string | undefined {
  for (const name of AI_ROLE_SOURCES[role].ownNames(setting)) {
    if (env[name] !== undefined) return env[name];
  }
  return undefined;
}

/** The key or base URL a role actually sends, on the provider it actually runs on. */
export function resolveAiRoleSetting(
  env: EnvSource,
  role: AiRoleId,
  setting: ProviderEnvSetting,
): string | undefined {
  const own = roleOwnSetting(env, role, setting);
  // #1734: a fallback on the synthesis provider (its own provider blank) sends what synthesis
  // sends, so a blank fallback key never swaps the synthesis key for another value.
  if (role === "synthesis-fallback" && !own?.trim() && !env.DFIR_AI_SYNTH_FALLBACK_PROVIDER?.trim())
    return resolveAiRoleSetting(env, "synthesis", setting);
  return resolveRoleSetting(env, AI_ROLE_SOURCES[role].provider(env), setting, own);
}
