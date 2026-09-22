/**
 * Where Jev's settings come from (#1540), and — the real point of this file — which API key it is
 * allowed to use.
 *
 * Jev on OpenRouter is the same account as every other DFIR_AI_* model, so asking an analyst to
 * paste the same key a fifth time is busywork: when DFIR_JEV_KEY is unset the OpenRouter route
 * inherits one, following the chain the repo's own provider factories already use
 * (companion/src/composition/aiProviders.ts):
 *
 *   DFIR_AI_VELO_KEY  → buildVelociraptorProvider's own key
 *   DFIR_AI_SYNTH_KEY → buildSynthesisProvider's own key
 *   DFIR_VISION_KEY   → visionEnv(KEY), the current vision name
 *   DFIR_AI_KEY       → visionEnv(KEY)'s DEPRECATED legacy fallback
 *
 * That is the spec's order and the repo's order both. One deliberate difference: the factories
 * chain with `??`, so an empty string wins there; here a blank key is treated as unset, because an
 * empty credential is not a configuration, it is a typo.
 *
 * The TypeSafe direct route inherits NOTHING. An OpenRouter key is a credential for openrouter.ai
 * and sending it to api.typesafe.ai would leak it to a host that never issued it, so that route
 * needs its own DFIR_JEV_KEY — and the same guard applies when a base-URL override points an
 * "openrouter" provider somewhere else.
 */
export type JevProvider = "openrouter" | "typesafe";

export interface JevSettings {
  readonly enabled: boolean;
  readonly provider: JevProvider;
  readonly baseUrl: string;
  readonly model: string;
  readonly apiKey: string;
  readonly timeoutMs: number;
  readonly maxRows: number;
  readonly batchSize: number;
}

/** `typesafe/jev-latest` does NOT exist on OpenRouter — it 400s. Only a versioned id works there. */
const OPENROUTER_MODEL = "typesafe/jev-1.13";
const OPENROUTER_BASE_URL = "https://openrouter.ai/api/alpha/decisions";
/** `jev-latest` is TypeSafe's own alias, valid only on its direct API. */
const TYPESAFE_MODEL = "jev-latest";
const TYPESAFE_BASE_URL = "https://api.typesafe.ai/v1/systemone";
/** Only this host may receive a key inherited from the DFIR_AI_* family. */
const OPENROUTER_HOST = "openrouter.ai";

const DEFAULT_TIMEOUT_MS = 120_000;
const DEFAULT_MAX_ROWS = 2000;
const MIN_MAX_ROWS = 1;
const MAX_MAX_ROWS = 20_000;
const DEFAULT_BATCH_SIZE = 40;
const MIN_BATCH_SIZE = 1;
const MAX_BATCH_SIZE = 100;

const TRUTHY = new Set(["1", "true", "yes", "on"]);

type Resolved = { settings: JevSettings } | { settings: null; reason: string };

function unusable(reason: string): Resolved {
  return { settings: null, reason };
}

/** A trimmed value, or undefined when the variable is unset or blank. */
function text(env: NodeJS.ProcessEnv, name: string): string | undefined {
  const value = env[name]?.trim();
  return value ? value : undefined;
}

function clampedInt(raw: string | undefined, fallback: number, min: number, max: number): number {
  const parsed = Number(raw);
  if (raw === undefined || raw.trim() === "" || !Number.isFinite(parsed)) return fallback;
  return Math.min(max, Math.max(min, Math.trunc(parsed)));
}

function positiveInt(raw: string | undefined, fallback: number): number {
  const parsed = Number(raw);
  if (!Number.isFinite(parsed) || parsed <= 0) return fallback;
  return Math.trunc(parsed);
}

/**
 * The inherited-key chain, in the order aiProviders.ts already falls back. The last two names are
 * visionEnv(env, "KEY") spelled out: that helper chains with `??`, so a blank DFIR_VISION_KEY would
 * shadow a real DFIR_AI_KEY. Walking both names with the blank-is-unset rule is the same order and
 * the kinder answer.
 */
function inheritedOpenRouterKey(env: NodeJS.ProcessEnv): string | undefined {
  return (
    text(env, "DFIR_AI_VELO_KEY") ??
    text(env, "DFIR_AI_SYNTH_KEY") ??
    text(env, "DFIR_VISION_KEY") ??
    text(env, "DFIR_AI_KEY")
  );
}

/** Returns null with a reason when Jev is not usable (disabled, or no key resolvable). */
export function resolveJevSettings(env: NodeJS.ProcessEnv = process.env): Resolved {
  if (!TRUTHY.has((env.DFIR_JEV_ENABLED ?? "").trim().toLowerCase()))
    return unusable("Jev is off. Set DFIR_JEV_ENABLED=1 to turn it on.");

  const providerName = (text(env, "DFIR_JEV_PROVIDER") ?? "openrouter").toLowerCase();
  if (providerName !== "openrouter" && providerName !== "typesafe")
    return unusable(
      `DFIR_JEV_PROVIDER="${providerName}" is not a Jev route. Use "openrouter" (the default) or "typesafe".`,
    );
  const provider: JevProvider = providerName;
  const isOpenRouter = provider === "openrouter";

  const baseUrl = text(env, "DFIR_JEV_BASE_URL") ?? (isOpenRouter ? OPENROUTER_BASE_URL : TYPESAFE_BASE_URL);
  let host: string;
  try {
    host = new URL(baseUrl).host;
  } catch {
    return unusable(`DFIR_JEV_BASE_URL is not a URL: "${baseUrl}".`);
  }

  const ownKey = text(env, "DFIR_JEV_KEY");
  const keyResult = resolveKey(env, provider, ownKey, host);
  if (typeof keyResult !== "string") return keyResult;

  return {
    settings: {
      enabled: true,
      provider,
      baseUrl,
      model: text(env, "DFIR_JEV_MODEL") ?? (isOpenRouter ? OPENROUTER_MODEL : TYPESAFE_MODEL),
      apiKey: keyResult,
      timeoutMs: positiveInt(env.DFIR_JEV_TIMEOUT_MS, DEFAULT_TIMEOUT_MS),
      maxRows: clampedInt(env.DFIR_JEV_MAX_ROWS, DEFAULT_MAX_ROWS, MIN_MAX_ROWS, MAX_MAX_ROWS),
      batchSize: clampedInt(env.DFIR_JEV_BATCH_SIZE, DEFAULT_BATCH_SIZE, MIN_BATCH_SIZE, MAX_BATCH_SIZE),
    },
  };
}

/** The key, or the `unusable` result explaining why there is none to use. */
function resolveKey(
  env: NodeJS.ProcessEnv,
  provider: JevProvider,
  ownKey: string | undefined,
  host: string,
): string | Resolved {
  if (ownKey) return ownKey; // an explicit key is trusted wherever it is pointed
  if (provider === "typesafe")
    return unusable(
      "The typesafe route needs its own key: set DFIR_JEV_KEY. A key from the DFIR_AI_* family " +
        "belongs to OpenRouter and is never sent to api.typesafe.ai.",
    );
  const inherited = inheritedOpenRouterKey(env);
  if (!inherited)
    return unusable(
      "No Jev API key. Set DFIR_JEV_KEY, or one of DFIR_AI_VELO_KEY / DFIR_AI_SYNTH_KEY / " +
        "DFIR_VISION_KEY / DFIR_AI_KEY for the OpenRouter route.",
    );
  if (host !== OPENROUTER_HOST)
    return unusable(
      `An inherited OpenRouter key is not sent to ${host}. Set DFIR_JEV_KEY for that endpoint, ` +
        `or leave DFIR_JEV_BASE_URL unset to use ${OPENROUTER_HOST}.`,
    );
  return inherited;
}
