import { existsSync } from "node:fs";
import { readFile } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { isSeaRuntime } from "../serverAssets.js";
import { withVisionEnvAliases } from "../config/aiEnv.js";
import { atomicWrite } from "../storage/atomicWrite.js";

const SECRET_SUFFIXES = ["_KEY", "_SECRET", "_PASSWORD", "_TOKEN"];

// Keys that must NEVER be writable via POST /settings/env — changing them at runtime
// can redirect case data, disable security features, or hijack the AI endpoint.
const DENIED_ENV_KEYS = new Set([
  "DFIR_CASES_ROOT",
  "DFIR_ENV_FILE",
  "DFIR_HOST",
  "DFIR_PORT",
  "DFIR_DEMO_MODE",
  "DFIR_ANONYMIZE",
  "DFIR_ALLOWED_ORIGINS",
  // Same class of control as DFIR_ALLOWED_ORIGINS: these decide which hostnames the companion
  // answers to, so a writable one would let the dashboard re-open the DNS-rebinding hole (#280).
  "DFIR_ALLOWED_HOSTS",
  "DFIR_ALLOWED_HOST_SUFFIXES",
  "DFIR_LOG_DIR",
]);

// Only keys starting with one of these prefixes may be written via POST /settings/env.
// Mirrors RELOADABLE_PREFIXES in caseLifecycle.ts (the /settings/reload allowlist) — the
// dashboard can configure AI, integrations, enrichment, push, NSRL, and tools, but cannot
// rewrite core server config, security toggles, or filesystem paths.
const WRITABLE_ENV_PREFIXES = [
  "DFIR_VISION_", "DFIR_AI_", "DFIR_IRIS_", "DFIR_VELOCIRAPTOR_", "DFIR_TIMESKETCH_", "DFIR_NOTION_", "DFIR_CLICKUP_",
  "DFIR_VT_", "DFIR_ABUSEIPDB_", "DFIR_HUNTINGCH_", "DFIR_MB_", "DFIR_CROWDSTRIKE_", "DFIR_SHODAN_",
  "DFIR_MISP_", "DFIR_YETI_", "DFIR_OPENCTI_", "DFIR_ROCKYRACCOON_", "DFIR_GEOIP_",
  "DFIR_LEAKCHECK_", "DFIR_HIBP_", "DFIR_DEHASHED_", "DFIR_PUSH_TOKEN", "DFIR_NSRL_", "DFIR_TOOL_",
  "DFIR_NOTIFY_", "DFIR_SMTP_", "DFIR_HASHLOOKUP_", "DFIR_RDAP_", "DFIR_OCR_", "DFIR_SYNTH_",
  "DFIR_DEEP_PASS_", "DFIR_ASK_", "DFIR_GAP_", "DFIR_SSH_", "DFIR_TIMESTOMP_",
  "DFIR_ANOMALY_", "DFIR_ADVERSARY_", "DFIR_ATTACK_", "DFIR_HUNT_", "DFIR_PBHUNT_",
  "DFIR_MEMORY_", "DFIR_IMPORT_", "DFIR_UNDO_", "DFIR_CORRELATE_", "DFIR_SUPERTIMELINE_",
  "DFIR_REPORT_", "DFIR_LOG_LEVEL", "DFIR_UPDATE_CHECK", "DFIR_STATE_BACKUP_",
  "DFIR_DEMO_RESET_HOURS", "DFIR_MAX_EVENTS", "DFIR_MAX_BODY_MB", "DFIR_FORENSIC_",
  "DFIR_DROP_", "DFIR_BEACON_", "DFIR_PHASE_", "DFIR_LEARNED_", "DFIR_SYNTH_ADVERSARY",
  "DFIR_AI_TIMEOUT_MS", "DFIR_AI_MAX_TOKENS", "DFIR_AI_CONTEXT_TOKENS", "DFIR_AI_SYNTH_MAX_EVENTS",
  "DFIR_AI_AUTO_SYNTHESIZE", "DFIR_AI_AUTO_SYNTHESIZE_MS", "DFIR_AI_SYNTH_THINKING_TOKENS",
  "DFIR_AI_DEBUG_USAGE", "DFIR_AI_VELO_", "DFIR_AI_SECOND_OPINION_",
  "DFIR_AI_CLAUDE_CODE_BIN", "DFIR_AI_CODEX_BIN", "DFIR_VISION_IMAGE_DETAIL",
  "DFIR_AI_", "DFIR_VISION_",
  // Tuning knobs the Settings modal has always rendered as editable fields but the original
  // allowlist (#240) never covered, so a save carrying them was rejected wholesale. All of them are
  // limits, delays, and display options — none redirects case data, relaxes a security control, or
  // changes where the server listens (those stay in DENIED_ENV_KEYS).
  "TAGGER_", "DFIR_ENRICH_", "DFIR_EXPOSURE_", "DFIR_GEOMAP_", "DFIR_MOBILE_", "DFIR_PRESENT_",
  "DFIR_VELO_HUNT_", "DFIR_VELO_MONITOR_", "DFIR_LOOKALIKE_", "DFIR_D3FEND_",
  "DFIR_DEDUP", "DFIR_FLUSH_INTERVAL_MS", "DFIR_ATOMIC_WRITE_RETRIES", "DFIR_DISK_WARN_PCT",
  "DFIR_IMPORTERS_DIR", "DFIR_MAX_PINNED_FINDINGS", "DFIR_LOG_MAX_TEMPLATES",
  "DFIR_PUBLIC_URL", "DFIR_UPDATE_REPO", "DFIR_DIAG_MAX_FILES", "DFIR_JOBS_MAX",
];

/** Validate that every key in `updates` is on the writable allowlist and not explicitly denied.
 * Returns an array of rejected keys (empty = all ok). */
export function validateEnvUpdates(updates: Record<string, string>): string[] {
  const rejected: string[] = [];
  for (const key of Object.keys(updates)) {
    if (DENIED_ENV_KEYS.has(key)) {
      rejected.push(key);
      continue;
    }
    if (!WRITABLE_ENV_PREFIXES.some((p) => key.startsWith(p))) {
      rejected.push(key);
    }
  }
  return rejected;
}

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

  await atomicWrite(resolveEnvFilePath(), newLines.join("\n"));
}
