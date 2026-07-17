import { existsSync } from "node:fs";
import { readFile, writeFile } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { isSeaRuntime } from "../serverAssets.js";
import { withVisionEnvAliases } from "../config/aiEnv.js";

const SECRET_SUFFIXES = ["_KEY", "_SECRET", "_PASSWORD", "_TOKEN"];

/** The per-user, writable .env the installers seed (Windows: %LOCALAPPDATA%\DFIR-Companion\.env). */
export function perUserEnvFile(): string | null {
  const base = process.env.LOCALAPPDATA; // Windows only; undefined elsewhere
  return base ? join(base, "DFIR-Companion", ".env") : null;
}

/**
 * Resolve the SINGLE .env file the companion both READS at startup and WRITES via the dashboard.
 *
 * This MUST return the same path server startup loads (see the bootstrap at the bottom of
 * server.ts) — otherwise the dashboard "Save" writes a .env the server never reads. Historically
 * this module hard-coded `process.cwd()/.env`, so when the Chocolatey shim was launched from
 * C:\Windows\system32 the save landed in C:\Windows\system32\.env and silently did nothing.
 *
 * Priority:
 *  1. DFIR_ENV_FILE — explicit override (installers set it; AppImage/read-only mounts need it).
 *  2. SEA build (portable EXE / Chocolatey):
 *     a. the per-user writable file the installers seed (%LOCALAPPDATA%\DFIR-Companion\.env) if it
 *        exists — self-heals when the persistent DFIR_ENV_FILE env var hasn't yet propagated into
 *        the launching shell (a classic Chocolatey gotcha);
 *     b. otherwise the .env next to the EXE (a plain portable unzip).
 *  3. Dev / Docker — cwd/.env (unchanged behaviour).
 */
export function resolveEnvFilePath(): string {
  const explicit = process.env.DFIR_ENV_FILE?.trim();
  if (explicit) return resolve(explicit);
  if (isSeaRuntime()) {
    const perUser = perUserEnvFile();
    if (perUser && existsSync(perUser)) return perUser;
    return join(dirname(process.execPath), ".env");
  }
  return resolve(process.cwd(), ".env");
}

export function isSecretKey(key: string): boolean {
  return SECRET_SUFFIXES.some(s => key.toUpperCase().endsWith(s) || key.toUpperCase().includes(s + "_"));
}

async function readRaw(): Promise<string> {
  try { return await readFile(resolveEnvFilePath(), "utf8"); } catch { return ""; }
}

function parseLines(raw: string): Record<string, string> {
  const result: Record<string, string> = {};
  for (const line of raw.split("\n")) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#")) continue;
    const eq = trimmed.indexOf("=");
    if (eq < 0) continue;
    const key = trimmed.slice(0, eq).trim();
    const value = trimmed.slice(eq + 1).trim();
    if (key) result[key] = value;
  }
  return result;
}

/**
 * Re-read the .env file and apply every key starting with `prefix` into `process.env`, so a
 * runtime "reconnect" can pick up settings saved via POST /settings/env WITHOUT a full restart
 * (updateEnv only writes the file). Scoped to one prefix (e.g. "DFIR_IRIS_") to avoid disturbing
 * unrelated live config. Returns the keys applied.
 */
export async function reloadEnvPrefix(prefix: string): Promise<string[]> {
  const raw = parseLines(await readRaw());
  const applied: string[] = [];
  for (const [k, v] of Object.entries(raw)) {
    if (k.startsWith(prefix)) { process.env[k] = v; applied.push(k); }
  }
  return applied;
}

/** Return all .env values; secrets are replaced with the sentinel string. */
export async function getEnvForSettings(): Promise<Record<string, string>> {
  // Surface legacy DFIR_AI_* vision values under the renamed DFIR_VISION_* keys so an existing
  // install's values still populate the renamed Settings fields (a Save then writes the new names).
  const raw = withVisionEnvAliases(parseLines(await readRaw())) as Record<string, string>;
  const out: Record<string, string> = {};
  for (const [k, v] of Object.entries(raw)) {
    out[k] = isSecretKey(k) && v ? "••••••••" : v;
  }
  return out;
}

/**
 * Update specific keys in the .env file, preserving comments and structure.
 * Keys not already in the file are appended. Empty-string values are skipped.
 */
export async function updateEnv(updates: Record<string, string>): Promise<void> {
  const raw = await readRaw();
  const lines = raw.split("\n");
  const updatedKeys = new Set<string>();

  const newLines = lines.map(line => {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#")) return line;
    const eq = trimmed.indexOf("=");
    if (eq < 0) return line;
    const key = trimmed.slice(0, eq).trim();
    if (key in updates) {
      updatedKeys.add(key);
      return `${key}=${updates[key]}`;
    }
    return line;
  });

  for (const [key, val] of Object.entries(updates)) {
    if (!updatedKeys.has(key) && val !== "") {
      newLines.push(`${key}=${val}`);
    }
  }

  await writeFile(resolveEnvFilePath(), newLines.join("\n"), "utf8");
}
