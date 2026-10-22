import { z } from "zod";

/**
 * The list behind the Settings model picker (#2224): OpenRouter's DECISION models, and nothing else.
 *
 * Jev stopped being the only decision model — OpenRouter lists ~30 of them behind the same
 * `/api/alpha/decisions` endpoint — so the analyst picks from that catalog instead of guessing ids.
 * The browser cannot fetch it itself (CSP `connect-src 'self'`), so the server does, and caches.
 *
 * The catalog is PUBLIC: no key is ever sent, so a misconfigured key cannot leak through here.
 *
 * Cache rules: a good list is served for an hour. A failed refresh serves the expired list marked
 * `stale` (prices may have moved), and the next attempt waits a minute, so a settings page left open
 * while OpenRouter is down does not hammer it. Concurrent loads share one request.
 */

const CATALOG_URL = "https://openrouter.ai/api/v1/models?output_modalities=decisions";
const DECISIONS = "decisions";
const TIMEOUT_MS = 10_000;
const CACHE_TTL_MS = 60 * 60 * 1000;
const FAILURE_BACKOFF_MS = 60 * 1000;
const MAX_MODELS = 500;
const MAX_ID_CHARS = 200;
const TOKENS_PER_MILLION = 1_000_000;

/**
 * Listed by OpenRouter as decision models, but refuse what every Decision model feature sends — so
 * offering them would only offer a run that fails. Found by scripts/probe-decision-models.ts on
 * 2026-10-22: ScaleDown rejects the structured `state` with HTTP 400 ("ScaleDown state must be a …").
 * Matched with and without a `:variant` suffix. A model that is merely OFFLINE (OpenRouter's
 * "0 endpoints") stays listed: availability changes daily, and a run on it stops naming the model.
 * Typing a hidden id by hand still works, and fails with that same named error.
 */
const INCOMPATIBLE_MODELS: ReadonlySet<string> = new Set(["scaledown/classify-1"]);

const isIncompatible = (id: string): boolean => INCOMPATIBLE_MODELS.has(id.split(":")[0]);

export interface DecisionModelOption {
  readonly id: string;
  readonly name: string;
  /** Both prices are zero. */
  readonly free: boolean;
  /** Dollars per million input tokens — decision models bill input only; null when unpriced. */
  readonly inputPerMillionUSD: number | null;
}

export interface DecisionModelList {
  readonly models: readonly DecisionModelOption[];
  readonly fetchedAt: string;
  /** The list is older than the cache allows because a refresh just failed. */
  readonly stale: boolean;
}

export interface DecisionModelCatalog {
  list(): Promise<DecisionModelList>;
}

const entrySchema = z.object({
  id: z.string().min(1).max(MAX_ID_CHARS),
  name: z.string().max(MAX_ID_CHARS).optional(),
  pricing: z
    .object({ prompt: z.string().optional(), completion: z.string().optional() })
    .partial()
    .optional(),
  architecture: z.object({ output_modalities: z.array(z.string()).optional() }).optional(),
});

const catalogSchema = z.object({ data: z.array(z.unknown()) });

function price(raw: string | undefined): number | null {
  if (raw === undefined) return null;
  const value = Number(raw);
  return Number.isFinite(value) && value >= 0 ? value : null;
}

function toOption(raw: unknown): DecisionModelOption | null {
  const parsed = entrySchema.safeParse(raw);
  if (!parsed.success) return null;
  const m = parsed.data;
  // The query already filters; this is the second lock, so a catalog change cannot slip a chat model in.
  if (!m.architecture?.output_modalities?.includes(DECISIONS)) return null;
  if (isIncompatible(m.id)) return null;
  const prompt = price(m.pricing?.prompt);
  const completion = price(m.pricing?.completion);
  return {
    id: m.id,
    name: m.name?.trim() || m.id,
    free: prompt === 0 && (completion ?? 0) === 0,
    // Rounded to a millionth of a dollar: the per-token strings carry float noise once multiplied.
    inputPerMillionUSD: prompt === null ? null : Math.round(prompt * TOKENS_PER_MILLION * 1e6) / 1e6,
  };
}

async function fetchCatalog(fetchImpl: typeof fetch): Promise<DecisionModelOption[]> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), TIMEOUT_MS);
  try {
    const res = await fetchImpl(CATALOG_URL, {
      headers: { accept: "application/json" },
      signal: controller.signal,
    });
    if (!res.ok) throw new Error(`OpenRouter model list returned HTTP ${res.status}`);
    const body = catalogSchema.parse(await res.json());
    return body.data
      .slice(0, MAX_MODELS)
      .map(toOption)
      .filter((m): m is DecisionModelOption => m !== null)
      .sort((a, b) => a.name.localeCompare(b.name));
  } catch (err) {
    if (controller.signal.aborted) throw new Error(`OpenRouter model list timed out after ${TIMEOUT_MS}ms`);
    throw err;
  } finally {
    clearTimeout(timer);
  }
}

export function createDecisionModelCatalog(
  fetchImpl: typeof fetch = fetch,
  now: () => number = Date.now,
): DecisionModelCatalog {
  let cached: { models: DecisionModelOption[]; at: number } | null = null;
  let failedAt: number | null = null;
  let inFlight: Promise<DecisionModelList> | null = null;

  const fromCache = (stale: boolean): DecisionModelList => ({
    models: cached!.models,
    fetchedAt: new Date(cached!.at).toISOString(),
    stale,
  });

  async function refresh(): Promise<DecisionModelList> {
    try {
      const models = await fetchCatalog(fetchImpl);
      cached = { models, at: now() };
      failedAt = null;
      return fromCache(false);
    } catch (err) {
      failedAt = now();
      if (cached) return fromCache(true);
      throw err;
    }
  }

  return {
    list(): Promise<DecisionModelList> {
      const t = now();
      if (cached && t - cached.at < CACHE_TTL_MS) return Promise.resolve(fromCache(false));
      if (failedAt !== null && t - failedAt < FAILURE_BACKOFF_MS) {
        return cached
          ? Promise.resolve(fromCache(true))
          : Promise.reject(new Error("The OpenRouter model list could not be loaded; retrying shortly."));
      }
      inFlight ??= refresh().finally(() => {
        inFlight = null;
      });
      return inFlight;
    },
  };
}
