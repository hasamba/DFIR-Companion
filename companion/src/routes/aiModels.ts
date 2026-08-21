import type { Express, Request, Response } from "express";
import { visionEnv } from "../config/aiEnv.js";
import {
  listProviderModels,
  ModelCatalogError,
  type ModelCatalogProvider,
} from "../providers/modelCatalog.js";
import type { RouteContext } from "./context.js";

type ModelRole = "vision" | "synthesis" | "velociraptor" | "second-opinion";

interface ModelListRequest {
  provider: ModelCatalogProvider;
  role: ModelRole;
  apiKey?: string;
  baseUrl?: string;
}

const PROVIDERS = new Set<ModelCatalogProvider>([
  "openai",
  "openrouter",
  "ollama",
  "litellm",
  "gemini",
  "anthropic",
  "claude-code",
  "codex",
]);
const ROLES = new Set<ModelRole>(["vision", "synthesis", "velociraptor", "second-opinion"]);

function asRecord(value: unknown): Record<string, unknown> | null {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : null;
}

function optionalString(
  body: Record<string, unknown>,
  key: string,
  maxLength: number,
): string | undefined | null {
  const value = body[key];
  if (value === undefined) return undefined;
  if (typeof value !== "string" || value.length > maxLength || /\p{Cc}/u.test(value)) return null;
  return value.trim();
}

function parseRequest(value: unknown): ModelListRequest | string {
  const body = asRecord(value);
  if (!body) return "request body must be an object";
  const provider = optionalString(body, "provider", 64);
  if (!provider || !PROVIDERS.has(provider as ModelCatalogProvider)) return "provider is not supported";
  const role = optionalString(body, "role", 32);
  if (!role || !ROLES.has(role as ModelRole)) return "role is not supported";
  const apiKey = optionalString(body, "apiKey", 16_384);
  if (apiKey === null) return "apiKey must be a valid string";
  const baseUrl = optionalString(body, "baseUrl", 2_048);
  if (baseUrl === null) return "baseUrl must be a valid string";
  return {
    provider: provider as ModelCatalogProvider,
    role: role as ModelRole,
    ...(apiKey !== undefined ? { apiKey } : {}),
    ...(baseUrl !== undefined ? { baseUrl } : {}),
  };
}

function savedCredentials(role: ModelRole): { apiKey?: string; baseUrl?: string } {
  const visionKey = visionEnv(process.env, "KEY");
  const visionUrl = visionEnv(process.env, "BASE_URL");
  if (role === "vision") return { apiKey: visionKey, baseUrl: visionUrl };
  if (role === "synthesis") {
    return {
      apiKey: process.env.DFIR_AI_SYNTH_KEY ?? visionKey,
      baseUrl: process.env.DFIR_AI_SYNTH_BASE_URL ?? visionUrl,
    };
  }
  if (role === "velociraptor") {
    return {
      apiKey: process.env.DFIR_AI_VELO_KEY ?? visionKey,
      baseUrl: process.env.DFIR_AI_VELO_BASE_URL ?? visionUrl,
    };
  }
  return {
    apiKey: process.env.DFIR_AI_SECOND_OPINION_KEY ?? visionKey,
    baseUrl: process.env.DFIR_AI_SECOND_OPINION_BASE_URL ?? visionUrl,
  };
}

export function registerAiModelRoutes(app: Express, ctx: RouteContext): void {
  app.post("/settings/ai-models", async (req: Request, res: Response) => {
    const parsed = parseRequest(req.body as unknown);
    if (typeof parsed === "string") return res.status(400).json({ error: parsed });
    const saved = savedCredentials(parsed.role);
    try {
      const result = await listProviderModels({
        provider: parsed.provider,
        role: parsed.role === "vision" ? "vision" : "text",
        apiKey: parsed.apiKey || saved.apiKey,
        baseUrl: parsed.baseUrl === undefined ? saved.baseUrl : parsed.baseUrl || undefined,
        codexBin: process.env.DFIR_AI_CODEX_BIN,
      });
      return res.json(result);
    } catch (error) {
      const message = error instanceof Error ? error.message : "Provider model list failed.";
      ctx.serverLogger.warn(
        `[settings] model list failed provider=${parsed.provider} role=${parsed.role}: ${message}`,
      );
      const status = error instanceof ModelCatalogError && error.kind === "invalid" ? 400 : 502;
      return res.status(status).json({ error: message });
    }
  });
}
