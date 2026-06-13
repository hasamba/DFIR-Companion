import { readFile, writeFile } from "node:fs/promises";
import { resolve } from "node:path";

const ENV_PATH = resolve(process.cwd(), ".env");

const SECRET_SUFFIXES = ["_KEY", "_SECRET", "_PASSWORD", "_TOKEN"];

export function isSecretKey(key: string): boolean {
  return SECRET_SUFFIXES.some(s => key.toUpperCase().endsWith(s) || key.toUpperCase().includes(s + "_"));
}

async function readRaw(): Promise<string> {
  try { return await readFile(ENV_PATH, "utf8"); } catch { return ""; }
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
  const raw = parseLines(await readRaw());
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

  await writeFile(ENV_PATH, newLines.join("\n"), "utf8");
}
