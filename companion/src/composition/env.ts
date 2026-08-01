/**
 * Environment-variable parsing for the composition root (#384).
 *
 * Three parsers, each of which exists because the obvious inline expression got a case wrong in
 * production. They are here rather than inline in the factories so the next factory reaches for a
 * parser that already handles the edge case instead of writing `Number(x) || undefined` again.
 */

/** The truthy spellings an operator actually writes in a .env file. */
export function isEnvFlag(value: string | undefined): boolean {
  return /^(1|true|yes|on)$/i.test(value ?? "");
}

/**
 * Parse a numeric env var, honoring an explicit "0". `Number(x) || undefined` would discard 0
 * (falsy) and silently fall back to the hardcoded default — an operator who set
 * DFIR_ENRICH_RETRIES=0 to disable 429 retry still got 2 retries. Returns undefined for
 * unset/empty/non-finite so downstream `?? default` keeps working.
 */
export function numEnv(key: string): number | undefined {
  const v = process.env[key];
  if (v === undefined || v === "") return undefined;
  const n = Number(v);
  return Number.isFinite(n) ? n : undefined;
}

/**
 * Parse a positive-integer env var, ignoring blank/garbage/non-positive values so a typo falls
 * back to the documented default rather than silently pushing nothing (a `0` cap would).
 */
export function positiveIntEnv(raw: string | undefined): number | undefined {
  const n = Number(String(raw ?? "").trim());
  return Number.isInteger(n) && n > 0 ? n : undefined;
}
