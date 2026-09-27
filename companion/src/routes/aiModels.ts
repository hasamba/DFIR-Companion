import type { Express, Request, Response } from "express";
import { type AiRoleId, resolveRoleSetting, roleOwnSetting } from "../config/aiEnv.js";
import {
  listProviderModels,
  ModelCatalogError,
  type ModelCatalogProvider,
} from "../providers/modelCatalog.js";
import { planAiKeyMigration, publicAiKeyMigration } from "../config/aiKeyMigration.js";
import { readEnvFile, reloadEnvPrefix, updateEnvFrom } from "../settings/envManager.js";
import type { RouteContext } from "./context.js";

type ModelRole = AiRoleId;

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
const ROLES = new Set<ModelRole>([
  "vision",
  "synthesis",
  "synthesis-fallback",
  "velociraptor",
  "second-opinion",
  "reconcile",
]);

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

// The saved key and base URL go through the same resolver the running roles use, keyed on the
// provider the picker asked about, so a role switched to another provider lists that provider's
// models.
function savedCredentials(
  role: ModelRole,
  provider: ModelCatalogProvider,
): { apiKey?: string; baseUrl?: string } {
  return {
    apiKey: resolveRoleSetting(process.env, provider, "KEY", roleOwnSetting(process.env, role, "KEY")),
    baseUrl: resolveRoleSetting(
      process.env,
      provider,
      "BASE_URL",
      roleOwnSetting(process.env, role, "BASE_URL"),
    ),
  };
}

export function registerAiModelRoutes(app: Express, ctx: RouteContext): void {
  app.post("/settings/ai-models", async (req: Request, res: Response) => {
    const parsed = parseRequest(req.body as unknown);
    if (typeof parsed === "string") return res.status(400).json({ error: parsed });
    const saved = savedCredentials(parsed.role, parsed.provider);
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

  // The one-time move of per-model keys and base URLs into the per-provider slots. The .env file is
  // the source of truth, not process.env: it is what Save writes and what the next start reads.
  // Only names ever reach the browser; the values stay in the plan's server-side `updates`.
  app.get("/settings/ai-key-migration", async (_req: Request, res: Response) => {
    try {
      return res.json(publicAiKeyMigration(planAiKeyMigration(await readEnvFile())));
    } catch (error) {
      return migrationFailed(ctx, res, "plan", error);
    }
  });

  // The body is ignored: the server recomputes the plan from the file, so a stale or forged plan
  // from the browser cannot write anything.
  app.post("/settings/ai-key-migration", async (_req: Request, res: Response) => {
    try {
      // Plan and write under the .env write lock: a Settings save in between would otherwise be lost.
      const plan = await updateEnvFrom((env) => {
        const planned = planAiKeyMigration(env);
        return { updates: { ...planned.updates }, result: planned };
      });
      await reloadEnvPrefix("DFIR_VISION_");
      await reloadEnvPrefix("DFIR_AI_");
      return res.json({ ok: true, ...publicAiKeyMigration(plan) });
    } catch (error) {
      return migrationFailed(ctx, res, "apply", error);
    }
  });
}

function migrationFailed(ctx: RouteContext, res: Response, step: string, error: unknown): Response {
  const message = error instanceof Error ? error.message : "AI key migration failed.";
  ctx.serverLogger.warn(`[settings] ai key migration ${step} failed: ${message}`);
  return res.status(500).json({ error: message });
}
