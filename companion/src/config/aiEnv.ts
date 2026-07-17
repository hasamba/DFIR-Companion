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
  "PROVIDER", "MODEL", "KEY", "BASE_URL", "IMAGE_DETAIL",
];

/** New DFIR_VISION_<suffix> wins; legacy DFIR_AI_<suffix> is the deprecated fallback. */
export function visionEnv(env: EnvSource, suffix: VisionEnvSuffix): string | undefined {
  return env[`DFIR_VISION_${suffix}`] ?? env[`DFIR_AI_${suffix}`];
}

/**
 * For the Settings form: surface each legacy DFIR_AI_<suffix> value under its new DFIR_VISION_<suffix>
 * key when the new key isn't set in the file, so an existing install's value still populates the
 * renamed field (and a Save then writes the canonical new name). Returns a shallow copy — never
 * mutates the input. The legacy keys are left in place so nothing is hidden.
 */
export function withVisionEnvAliases(env: EnvSource): EnvSource {
  const out: EnvSource = { ...env };
  for (const suffix of VISION_ENV_SUFFIXES) {
    const newKey = `DFIR_VISION_${suffix}`;
    const oldKey = `DFIR_AI_${suffix}`;
    if (out[newKey] === undefined && out[oldKey] !== undefined) out[newKey] = out[oldKey];
  }
  return out;
}
