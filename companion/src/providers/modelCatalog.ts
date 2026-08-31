import { readFile, stat } from "node:fs/promises";
import { homedir, tmpdir } from "node:os";
import { join } from "node:path";
import { type CodexRunner, defaultCodexRunner } from "./codexRunner.js";
import { validateBaseUrl } from "./urlValidation.js";
import { readBoundedJson, RESPONSE_SIZE_LIMITS, ResponseTooLargeError } from "./boundedResponse.js";

type FetchFn = typeof fetch;

export type ModelCatalogProvider =
  "openai" | "openrouter" | "ollama" | "litellm" | "gemini" | "anthropic" | "claude-code" | "codex";

export interface ModelCatalogOptions {
  provider: ModelCatalogProvider;
  apiKey?: string;
  baseUrl?: string;
  role?: "vision" | "text";
  fetchFn?: FetchFn;
  timeoutMs?: number;
  codexBin?: string;
  codexCachePath?: string;
  codexRunner?: CodexRunner;
}

export interface ModelCatalogResult {
  models: string[];
  manualEntry: true;
  note?: string;
}

export class ModelCatalogError extends Error {
  constructor(
    message: string,
    readonly kind: "invalid" | "upstream",
  ) {
    super(message);
    this.name = "ModelCatalogError";
  }
}

const DEFAULT_BASE_URL: Record<Exclude<ModelCatalogProvider, "claude-code" | "codex">, string> = {
  openai: "https://api.openai.com/v1",
  openrouter: "https://openrouter.ai/api/v1",
  ollama: "https://ollama.com/v1",
  litellm: "http://localhost:4000/v1",
  gemini: "https://generativelanguage.googleapis.com/v1beta",
  anthropic: "https://api.anthropic.com/v1",
};

const NON_GENERATION_MODEL =
  /(?:^|[-_/])(?:embedding|moderation|tts|transcribe|transcription|whisper|dall-e|image-generation|realtime)(?:[-_/]|$)/i;
const CODEX_INITIALIZE_ID = "initialize";
const CODEX_MODELS_ID = "models";
const MAX_CODEX_CACHE_BYTES = 5 * 1024 * 1024;

function asRecord(value: unknown): Record<string, unknown> | null {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : null;
}

function stringArray(value: unknown): string[] | null {
  if (!Array.isArray(value) || !value.every((entry) => typeof entry === "string")) return null;
  return value;
}

function cleanModelIds(ids: readonly unknown[]): string[] {
  return [...new Set(ids)]
    .filter((id): id is string => typeof id === "string")
    .map((id) => id.trim())
    .filter((id) => id.length > 0 && id.length <= 256 && !/\p{Cc}/u.test(id))
    .filter((id) => !NON_GENERATION_MODEL.test(id))
    .sort((a, b) => a.localeCompare(b));
}

function isVisionCapableOpenRouterModel(value: Record<string, unknown>): boolean {
  const architecture = asRecord(value.architecture);
  const modalities = architecture && stringArray(architecture.input_modalities);
  return !modalities || modalities.includes("image");
}

function openAiCompatibleIds(payload: unknown, visionOnly: boolean): string[] {
  const data = asRecord(payload)?.data;
  if (!Array.isArray(data)) return [];
  return cleanModelIds(
    data.flatMap((entry) => {
      const model = asRecord(entry);
      if (!model || (visionOnly && !isVisionCapableOpenRouterModel(model))) return [];
      return [model.id];
    }),
  );
}

function geminiIds(payload: unknown): string[] {
  const models = asRecord(payload)?.models;
  if (!Array.isArray(models)) return [];
  return cleanModelIds(
    models.flatMap((entry) => {
      const model = asRecord(entry);
      const methods = model && stringArray(model.supportedGenerationMethods);
      if (!model || !methods?.includes("generateContent")) return [];
      return [typeof model.name === "string" ? model.name.replace(/^models\//, "") : model.name];
    }),
  );
}

function anthropicIds(payload: unknown): string[] {
  const data = asRecord(payload)?.data;
  if (!Array.isArray(data)) return [];
  return cleanModelIds(data.map((entry) => asRecord(entry)?.id));
}

function requestError(status: number): ModelCatalogError {
  const advice =
    status === 401 || status === 403
      ? " Check the API key and its model-list permission."
      : status === 404
        ? " Check the provider base URL."
        : status === 429
          ? " The provider is rate-limiting requests; try again shortly."
          : "";
  return new ModelCatalogError(`Provider model list returned HTTP ${status}.${advice}`, "upstream");
}

async function fetchJson(
  url: string,
  headers: Record<string, string>,
  opts: ModelCatalogOptions,
): Promise<unknown> {
  let response: Response;
  try {
    response = await (opts.fetchFn ?? fetch)(url, {
      headers,
      signal: AbortSignal.timeout(opts.timeoutMs ?? 15_000),
    });
  } catch (error) {
    const detail =
      error instanceof Error && error.name === "TimeoutError" ? "timed out" : "could not be reached";
    throw new ModelCatalogError(`Provider model list ${detail}.`, "upstream");
  }
  if (!response.ok) throw requestError(response.status);
  try {
    return await readBoundedJson(response, {
      maxBytes: RESPONSE_SIZE_LIMITS.json,
      context: `${opts.provider} model list`,
    });
  } catch (err) {
    if (err instanceof ResponseTooLargeError) throw new ModelCatalogError(err.message, "upstream");
    throw new ModelCatalogError("Provider model list returned invalid JSON.", "upstream");
  }
}

function resolvedBaseUrl(opts: ModelCatalogOptions): string {
  const custom = opts.baseUrl?.trim();
  const error = validateBaseUrl(custom);
  if (error) throw new ModelCatalogError(error, "invalid");
  return (custom || DEFAULT_BASE_URL[opts.provider as keyof typeof DEFAULT_BASE_URL]).replace(/\/+$/, "");
}

async function listHttpModels(opts: ModelCatalogOptions): Promise<string[]> {
  const baseUrl = resolvedBaseUrl(opts);
  if (opts.provider === "gemini") {
    const payload = await fetchJson(
      `${baseUrl}/models?pageSize=1000`,
      { "x-goog-api-key": opts.apiKey ?? "" },
      opts,
    );
    return geminiIds(payload);
  }
  if (opts.provider === "anthropic") {
    const payload = await fetchJson(
      `${baseUrl}/models?limit=1000`,
      { "x-api-key": opts.apiKey ?? "", "anthropic-version": "2023-06-01" },
      opts,
    );
    return anthropicIds(payload);
  }
  const payload = await fetchJson(
    `${baseUrl}/models`,
    { authorization: `Bearer ${opts.apiKey ?? ""}` },
    opts,
  );
  return openAiCompatibleIds(payload, opts.provider === "openrouter" && opts.role === "vision");
}

function codexModelRequest(): string {
  return [
    JSON.stringify({
      id: CODEX_INITIALIZE_ID,
      method: "initialize",
      params: { clientInfo: { name: "dfir-companion", version: "1" } },
    }),
    JSON.stringify({ method: "initialized" }),
    JSON.stringify({
      id: CODEX_MODELS_ID,
      method: "model/list",
      params: { limit: 1000, includeHidden: false },
    }),
  ].join("\n");
}

function parseCodexModelCache(raw: string): string[] {
  let payload: unknown;
  try {
    payload = JSON.parse(raw);
  } catch {
    return [];
  }
  const models = asRecord(payload)?.models;
  if (!Array.isArray(models)) return [];
  return cleanModelIds(
    models.flatMap((entry) => {
      const model = asRecord(entry);
      return model?.visibility === "list" ? [model.slug] : [];
    }),
  );
}

function resolvedCodexCachePath(opts: ModelCatalogOptions): string | undefined {
  if (opts.codexCachePath !== undefined) return opts.codexCachePath.trim() || undefined;
  if (opts.codexRunner) return undefined;
  const configuredHome = process.env.CODEX_HOME?.trim();
  return join(configuredHome || join(homedir(), ".codex"), "models_cache.json");
}

async function listCachedCodexModels(opts: ModelCatalogOptions): Promise<string[]> {
  const cachePath = resolvedCodexCachePath(opts);
  if (!cachePath) return [];
  try {
    const metadata = await stat(cachePath);
    if (!metadata.isFile() || metadata.size > MAX_CODEX_CACHE_BYTES) return [];
    return parseCodexModelCache(await readFile(cachePath, "utf8"));
  } catch {
    return [];
  }
}

function codexResponseRecords(stdout: string): Record<string, unknown>[] {
  return stdout.split(/\r?\n/).flatMap((line) => {
    if (!line.trim()) return [];
    try {
      const value: unknown = JSON.parse(line);
      const record = asRecord(value);
      return record ? [record] : [];
    } catch {
      return [];
    }
  });
}

function parseCodexModels(stdout: string): string[] {
  const response = codexResponseRecords(stdout).find((record) => record.id === CODEX_MODELS_ID);
  const error = response && asRecord(response.error);
  if (error) {
    const message =
      typeof error.message === "string"
        ? error.message.replace(/\p{Cc}/gu, " ").trim() || "request failed"
        : "request failed";
    throw new ModelCatalogError(`Codex model list ${message.slice(0, 500)}.`, "upstream");
  }
  const data = response && asRecord(response.result)?.data;
  if (!Array.isArray(data)) {
    throw new ModelCatalogError(
      "Codex CLI did not return a model catalog. Update Codex or enter a model ID manually.",
      "upstream",
    );
  }
  return cleanModelIds(data.map((entry) => asRecord(entry)?.model ?? asRecord(entry)?.id));
}

async function listCodexModels(opts: ModelCatalogOptions): Promise<string[]> {
  const cached = await listCachedCodexModels(opts);
  if (cached.length > 0) return cached;
  const runner = opts.codexRunner ?? defaultCodexRunner;
  const result = await runner({
    bin: opts.codexBin?.trim() || "codex",
    args: ["app-server", "--stdio"],
    stdin: codexModelRequest(),
    timeoutMs: opts.timeoutMs ?? 15_000,
    cwd: tmpdir(),
  });
  if (result.spawnError) {
    const detail = result.spawnError.code === "ENOENT" ? "was not found" : "could not be started";
    throw new ModelCatalogError(`Codex CLI ${detail}.`, "upstream");
  }
  if (result.timedOut) throw new ModelCatalogError("Codex model list timed out.", "upstream");
  return parseCodexModels(result.stdout);
}

export async function listProviderModels(opts: ModelCatalogOptions): Promise<ModelCatalogResult> {
  if (opts.provider === "claude-code") {
    return {
      models: cleanModelIds(["haiku", "opus", "sonnet"]),
      manualEntry: true,
      note: "Claude Code exposes stable aliases; you can also type a full model ID.",
    };
  }
  if (opts.provider === "codex") {
    return {
      models: await listCodexModels(opts),
      manualEntry: true,
      note: "Models reported by the installed Codex CLI; you can also enter a model ID manually.",
    };
  }
  return { models: await listHttpModels(opts), manualEntry: true };
}
