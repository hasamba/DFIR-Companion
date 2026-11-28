import { resolveAiRoleSetting, visionEnv, type EnvSource } from "../config/aiEnv.js";
import { isLoopbackHost } from "../providers/urlValidation.js";

// Providers that send their requests to the configured base URL. The CLI providers (claude-code,
// codex) ignore it and talk to their own cloud service, so a stale loopback URL never makes them local.
const URL_PROVIDERS: ReadonlySet<string> = new Set([
  "openai",
  "openrouter",
  "ollama",
  "litellm",
  "gemini",
  "anthropic",
]);

/** The base URL's hostname when it is a well-formed http(s) URL, else undefined. */
function httpHostname(baseUrl: string): string | undefined {
  try {
    const url = new URL(baseUrl);
    if (url.protocol !== "http:" && url.protocol !== "https:") return undefined;
    return url.hostname.replace(/^\[|\]$/g, "");
  } catch {
    return undefined;
  }
}

// Ollama names its cloud models with a tag ending in "cloud" ("gpt-oss:120b-cloud", "glm-4.6:cloud").
// A local Ollama daemon forwards those to Ollama Cloud, so a loopback URL alone does not keep them on-box.
const CLOUD_MODEL_TAG = /:(?:[^:/]*-)?cloud$/i;

/**
 * Is the configured AI provider on-box (so screenshots sent to it don't leave the machine)?
 * Used to decide whether screenshots get OCR redaction and whether to warn that they are NOT
 * anonymized. Decided from the address the provider actually sends to: a missing base URL is
 * external for every provider (#3106 — ollama then targets hosted Ollama Cloud, and a LiteLLM proxy
 * on its default local port may still forward to a hosted model). A cloud-tagged model is external
 * even behind a loopback URL.
 */
export function isLocalAiProvider(
  name: string | undefined,
  baseUrl: string | undefined,
  model?: string,
): boolean {
  if (!URL_PROVIDERS.has((name ?? "").trim().toLowerCase())) return false;
  if (CLOUD_MODEL_TAG.test((model ?? "").trim())) return false;
  const trimmed = (baseUrl ?? "").trim();
  if (!trimmed) return false;
  const host = httpHostname(trimmed);
  return host !== undefined && isLoopbackHost(host);
}

/** Is the screenshot (vision) model on-box, judged by the base URL its provider is built with? */
export function visionAiIsLocal(env: EnvSource): boolean {
  return isLocalAiProvider(
    visionEnv(env, "PROVIDER"),
    resolveAiRoleSetting(env, "vision", "BASE_URL"),
    visionEnv(env, "MODEL"),
  );
}
