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
  "DFIR_AUTH_MODE",
  "DFIR_AUTH_DATA_DIR",
  "DFIR_AUTH_BOOTSTRAP_TOKEN",
  "DFIR_AUTH_COOKIE_SECURE",
  "DFIR_AUTH_SESSION_HOURS",
  "DFIR_AUTH_OIDC_ISSUER",
  "DFIR_AUTH_OIDC_CLIENT_ID",
  "DFIR_AUTH_OIDC_CLIENT_SECRET",
  "DFIR_AUTH_OIDC_REDIRECT_URI",
  "DFIR_AUTH_OIDC_SCOPES",
  "DFIR_ALLOW_UNAUTHENTICATED_REMOTE",
]);

/**
 * Which prefixes POST /settings/reload may re-read from the .env FILE into the live process.
 * Read by routes/caseLifecycle.ts, and kept HERE rather than there because it is the twin of
 * WRITABLE_ENV_PREFIXES below and the two are only comprehensible side by side: writable is what
 * the dashboard may change, reloadable is what re-reading is allowed to pick up. They are NOT the
 * same list, and the difference is the interesting part — DFIR_TELEGRAM_BOT_TOKEN is reloadable
 * (an operator editing .env by hand can rotate it without a restart) but NOT writable (the
 * dashboard has no business rewriting the war-room bot's credential).
 *
 * Membership is exact-match on the string the route sends, so an entry without a trailing
 * underscore names one key rather than a family.
 */
export const RELOADABLE_ENV_PREFIXES = new Set([
  "DFIR_VISION_",
  "DFIR_AI_",
  "DFIR_IRIS_",
  "DFIR_VELOCIRAPTOR_",
  "DFIR_TIMESKETCH_",
  "DFIR_NOTION_",
  "DFIR_CLICKUP_",
  "DFIR_VT_",
  "DFIR_ABUSEIPDB_",
  "DFIR_HUNTINGCH_",
  "DFIR_MB_",
  "DFIR_CROWDSTRIKE_",
  "DFIR_SHODAN_",
  "DFIR_MISP_",
  "DFIR_YETI_",
  "DFIR_OPENCTI_",
  "DFIR_ROCKYRACCOON_",
  "DFIR_GEOIP_",
  "DFIR_LEAKCHECK_",
  "DFIR_HIBP_",
  "DFIR_DEHASHED_",
  "DFIR_PUSH_TOKEN",
  "DFIR_NSRL_",
  // Settings → KEV: whether the feed URL may point inside the operator's own network (#760).
  // Reloadable as well as writable — the route reads it per request, so a save that never reaches
  // process.env would leave the analyst staring at a setting that is on and does nothing.
  "DFIR_KEV_",
  "DFIR_TOOL_",
  // The exact key, not the DFIR_TELEGRAM_ family: a Telegram notification channel may borrow this
  // token, and both the channel route and the notifier read it live, so a rotation in .env has to be
  // reachable without a restart. Its siblings stay off deliberately — ACTION_USERS and SECRET_TOKEN
  // authorize the INBOUND bot, and nothing in the outbound path re-reads them.
  "DFIR_TELEGRAM_BOT_TOKEN",
  // Exact key. buildTlsFetch reads it from process.env at client-build time, so a save must land it
  // there before the integration's Test/reconnect rebuilds the client — without this reload the flag
  // sits in .env until a restart while the reconnect keeps refusing the insecure external host.
  "DFIR_TLS_ALLOW_INSECURE_EXTERNAL",
]);

/**
 * The THIRD list, and the one that answers a different question from the two around it.
 *
 * Writable is what the dashboard may change. Reloadable is what re-reading .env may pick up. This
 * is what re-reading is ENOUGH for: prefixes whose consumers read process.env at use time, with
 * nothing captured at startup, so loading the value IS the change taking effect and no restart is
 * owed.
 *
 * Being reloadable does not imply this (#760). DFIR_AI_ and DFIR_VISION_ reload happily and the
 * RUNNING analysis pipeline still holds its boot-time config — see composition/settingsReload.ts's
 * header for the per-prefix reasoning — so a save message built on "applied" alone told the analyst
 * an AI model change was live when it was not. POST /settings/reload reports this as `live` so the
 * dashboard can say what actually happened.
 *
 * THE DEFAULT IS "NOT LIVE". A prefix earns a place here only when its consumers demonstrably
 * re-read env on every use. DFIR_TOOL_ is a candidate by the same reasoning (its runner is
 * stateless) and is deliberately left out: promoting it changes the message for tool settings,
 * a separate behaviour change from the one #760 asked for, and over-reporting "restart" is the
 * safe direction to be wrong in.
 */
export const LIVE_FROM_ENV_PREFIXES = new Set(["DFIR_KEV_"]);

// Only keys starting with one of these prefixes may be written via POST /settings/env. The
// dashboard can configure AI, integrations, enrichment, push, NSRL, and tools, but cannot
// rewrite core server config, security toggles, or filesystem paths.
const WRITABLE_ENV_PREFIXES = [
  "DFIR_VISION_",
  "DFIR_AI_",
  "DFIR_IRIS_",
  "DFIR_VELOCIRAPTOR_",
  "DFIR_TIMESKETCH_",
  "DFIR_NOTION_",
  "DFIR_CLICKUP_",
  "DFIR_VT_",
  "DFIR_ABUSEIPDB_",
  "DFIR_HUNTINGCH_",
  "DFIR_MB_",
  "DFIR_CROWDSTRIKE_",
  "DFIR_SHODAN_",
  "DFIR_MISP_",
  "DFIR_YETI_",
  "DFIR_OPENCTI_",
  "DFIR_ROCKYRACCOON_",
  "DFIR_GEOIP_",
  "DFIR_LEAKCHECK_",
  "DFIR_HIBP_",
  "DFIR_DEHASHED_",
  "DFIR_PUSH_TOKEN",
  "DFIR_NSRL_",
  "DFIR_KEV_",
  "DFIR_TOOL_",
  // Bearer tokens for analyst-registered MCP servers (#296), as DFIR_MCP_<ID>_TOKEN. The _TOKEN
  // suffix is already in SECRET_SUFFIXES, so GET /settings/env redacts these for free.
  "DFIR_MCP_",
  "DFIR_NOTIFY_",
  "DFIR_SMTP_",
  "DFIR_HASHLOOKUP_",
  "DFIR_RDAP_",
  "DFIR_OCR_",
  "DFIR_SYNTH_",
  "DFIR_DEEP_PASS_",
  "DFIR_ASK_",
  "DFIR_GAP_",
  "DFIR_SSH_",
  "DFIR_TIMESTOMP_",
  "DFIR_ANOMALY_",
  "DFIR_ADVERSARY_",
  "DFIR_ATTACK_",
  "DFIR_HUNT_",
  "DFIR_PBHUNT_",
  "DFIR_MEMORY_",
  "DFIR_IMPORT_",
  "DFIR_UNDO_",
  "DFIR_CORRELATE_",
  "DFIR_SUPERTIMELINE_",
  "DFIR_REPORT_",
  "DFIR_LOG_LEVEL",
  "DFIR_UPDATE_CHECK",
  "DFIR_STATE_BACKUP_",
  "DFIR_DEMO_RESET_HOURS",
  "DFIR_MAX_EVENTS",
  "DFIR_MAX_BODY_MB",
  "DFIR_FORENSIC_",
  "DFIR_DROP_",
  "DFIR_BEACON_",
  "DFIR_PHASE_",
  "DFIR_LEARNED_",
  "DFIR_SYNTH_ADVERSARY",
  "DFIR_AI_TIMEOUT_MS",
  "DFIR_AI_MAX_TOKENS",
  "DFIR_AI_CONTEXT_TOKENS",
  "DFIR_AI_SYNTH_MAX_EVENTS",
  "DFIR_AI_AUTO_SYNTHESIZE",
  "DFIR_AI_AUTO_SYNTHESIZE_MS",
  "DFIR_AI_SYNTH_THINKING_TOKENS",
  "DFIR_AI_DEBUG_USAGE",
  "DFIR_AI_VELO_",
  "DFIR_AI_SECOND_OPINION_",
  "DFIR_AI_CLAUDE_CODE_BIN",
  "DFIR_AI_CODEX_BIN",
  "DFIR_VISION_IMAGE_DETAIL",
  "DFIR_AI_",
  "DFIR_VISION_",
  "DFIR_PRESIDIO_",
  // Tuning knobs the Settings modal has always rendered as editable fields but the original
  // allowlist (#240) never covered, so a save carrying them was rejected wholesale. All of them are
  // limits, delays, and display options — none redirects case data, relaxes a security control, or
  // changes where the server listens (those stay in DENIED_ENV_KEYS).
  "TAGGER_",
  "DFIR_ENRICH_",
  "DFIR_EXPOSURE_",
  "DFIR_GEOMAP_",
  "DFIR_MOBILE_",
  "DFIR_PRESENT_",
  "DFIR_VELO_HUNT_",
  "DFIR_VELO_MONITOR_",
  "DFIR_LOOKALIKE_",
  "DFIR_D3FEND_",
  "DFIR_DEDUP",
  "DFIR_FLUSH_INTERVAL_MS",
  "DFIR_ATOMIC_WRITE_RETRIES",
  "DFIR_DISK_WARN_PCT",
  "DFIR_IMPORTERS_DIR",
  "DFIR_MAX_PINNED_FINDINGS",
  "DFIR_LOG_MAX_TEMPLATES",
  "DFIR_PUBLIC_URL",
  "DFIR_UPDATE_REPO",
  "DFIR_DIAG_MAX_FILES",
  "DFIR_LOCAL_TELEMETRY",
  "DFIR_JOBS_MAX",
  "DFIR_JOBS_CONCURRENCY",
  "DFIR_JOBS_PER_CASE",
  // The global opt-in that lets a DFIR_*_INSECURE=1 knob apply to a non-loopback host (the
  // per-integration _INSECURE keys are already writable through their family prefixes).
  "DFIR_TLS_ALLOW_INSECURE_EXTERNAL",
  // Ransomware/sample-host detection-tuning lists (#700) — rendered as Settings fields but, like
  // the #240 knobs above, never added to this allowlist, so a save silently dropped them.
  "DFIR_RANSOM_EXTS",
  "DFIR_RANSOM_EXTS_STRICT",
  "DFIR_SAMPLE_HOSTS",
];

/**
 * A dotenv record is one line — `KEY=value` — so a line break anywhere inside a record starts a
 * SECOND one, and `updateEnv` writes both halves verbatim. That turned the key allowlist below
 * into a formality (#422):
 *
 *   - through a VALUE: saving DFIR_AI_MODEL as `gpt-4o\nDFIR_HOST=0.0.0.0` presents exactly one
 *     key, an allowed one, and lands a DFIR_HOST assignment in .env;
 *   - through a KEY: `"DFIR_AI_X\nDFIR_HOST".startsWith("DFIR_AI_")` is true and the denylist is
 *     an exact-match Set, so a key carrying its own newline passes both checks too.
 *
 * Either way the caller writes a protected security, authentication, listener or filesystem
 * setting it is explicitly not allowed to name. So both halves are checked for SYNTAX before the
 * allowlist gets to decide anything:
 *
 *   - keys must be a plain POSIX environment name;
 *   - values must be strings containing no control characters at all. Real values here are API
 *     keys, URLs, numbers and booleans — none needs a control character, and rejecting the whole
 *     class beats reasoning about which of CR / LF / NUL each .env reader treats as a separator
 *     (parseLines below splits on "\n"; the startup loader is a different parser again).
 */
const ENV_KEY_SYNTAX = /^[A-Za-z_][A-Za-z0-9_]*$/;
const ENV_VALUE_CONTROL_CHAR = /\p{Cc}/u;

/** A rejected key is echoed into a 400 body and the server log — never let it carry the payload. */
function safeKeyLabel(key: string): string {
  const flat = key.replace(/\p{Cc}/gu, "?");
  return flat.length > 64 ? `${flat.slice(0, 64)}…` : flat;
}

/** Validate that every key in `updates` is a well-formed name carrying a well-formed value, and is
 * on the writable allowlist rather than explicitly denied.
 * Returns an array of rejected keys, sanitized for display (empty = all ok). */
export function validateEnvUpdates(updates: Record<string, unknown>): string[] {
  const rejected: string[] = [];
  for (const [key, value] of Object.entries(updates)) {
    if (!ENV_KEY_SYNTAX.test(key) || typeof value !== "string" || ENV_VALUE_CONTROL_CHAR.test(value)) {
      rejected.push(safeKeyLabel(key));
      continue;
    }
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
  return SECRET_SUFFIXES.some((s) => key.toUpperCase().endsWith(s) || key.toUpperCase().includes(s + "_"));
}

async function readRaw(): Promise<string> {
  try {
    return await readFile(resolveEnvFilePath(), "utf8");
  } catch {
    return "";
  }
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
    if (k.startsWith(prefix)) {
      process.env[k] = v;
      applied.push(k);
    }
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
// One writer at a time. updateEnv is a read-modify-write over a single file, so two overlapping
// saves — the setup wizard and the Settings modal, or two browser tabs — both read the same
// baseline and the second atomicWrite replaces the first caller's keys wholesale. atomicWrite makes
// each individual write atomic; it cannot make the read and the write one step. The 200 has already
// gone out by then, so the loss is silent (#510).
//
// Scope is this process, which is the whole exposure: the companion is the only writer of its own
// .env, and every save arrives through one server. Two companions pointed at one file would still
// race, and closing that would take an on-disk lock — not worth the failure modes (a stale lock
// blocks every save) for a configuration nothing else is supposed to be writing.
let envWriteQueue: Promise<unknown> = Promise.resolve();

function withEnvWriteLock<T>(run: () => Promise<T>): Promise<T> {
  // Run whether or not the previous save succeeded: one failed write must not wedge every later one.
  const result = envWriteQueue.then(run, run);
  envWriteQueue = result.then(
    () => undefined,
    () => undefined,
  );
  return result;
}

export async function updateEnv(updates: Record<string, string>): Promise<void> {
  // Fail closed on the record syntax even though the route validates first (#422). This function
  // is exported, and the cost of a caller forgetting is an attacker-authored line in the file the
  // server reads its security configuration from. The allowlist stays the route's business — this
  // only refuses to write something that would not be a single well-formed dotenv record.
  for (const [key, value] of Object.entries(updates)) {
    if (!ENV_KEY_SYNTAX.test(key) || typeof value !== "string" || ENV_VALUE_CONTROL_CHAR.test(value)) {
      throw new Error(`refusing to write malformed .env record for key "${safeKeyLabel(key)}"`);
    }
  }
  // Read and write as one step, or a concurrent save that read the same baseline overwrites us.
  return withEnvWriteLock(async () => {
    const raw = await readRaw();
    const lines = raw.split("\n");
    const updatedKeys = new Set<string>();

    const newLines = lines.map((line) => {
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
  });
}
