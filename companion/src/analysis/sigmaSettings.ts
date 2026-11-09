// The Sigma settings an analyst edits in Settings → Sigma rules (#2204), read from process.env on
// every use so a saved value applies to the next import. Each reader validates and says what it
// ignored, so the Settings tab can show it (Codex plan review): a typo never silently loads
// deprecated rules or turns grading off.

import { SIGMA_LEVELS, type SigmaLevel } from "./sigmaRuleSet.js";

export const SIGMA_STATUS_CHOICES = ["stable", "test", "experimental"] as const;
export const SIGMA_MIN_LEVEL_CHOICES: readonly SigmaLevel[] = ["critical", "high", "medium", "low"];
export const DEFAULT_SIGMA_STATUSES = ["stable", "test"];

export interface SigmaStatusSetting {
  statuses: string[];
  /** Values that are not a status the Companion offers (deprecated, unsupported, typos). */
  ignored: string[];
  /** True when nothing usable was set and the default applies. */
  defaulted: boolean;
}

/** The Suzaku rules (#2499) load experimental by default: 711 of the 741 bundled files are experimental. */
export const DEFAULT_SUZAKU_STATUSES = ["stable", "test", "experimental"];

export function sigmaStatusesFromEnv(env: NodeJS.ProcessEnv = process.env): SigmaStatusSetting {
  return readStatuses(env.DFIR_SIGMA_RULE_STATUSES, DEFAULT_SIGMA_STATUSES);
}

/** DFIR_SIGMA_SUZAKU_STATUSES (#2499): the Suzaku rules' own status filter. */
export function sigmaSuzakuStatusesFromEnv(env: NodeJS.ProcessEnv = process.env): SigmaStatusSetting {
  return readStatuses(env.DFIR_SIGMA_SUZAKU_STATUSES, DEFAULT_SUZAKU_STATUSES);
}

const OFF = new Set(["off", "0", "false", "no"]);

/** DFIR_SIGMA_SUZAKU_RULES (#2499): on unless it says off / 0 / false / no. */
export const sigmaSuzakuEnabled = (env: NodeJS.ProcessEnv = process.env): boolean =>
  !OFF.has(env.DFIR_SIGMA_SUZAKU_RULES?.trim().toLowerCase() ?? "");

function readStatuses(value: string | undefined, fallback: readonly string[]): SigmaStatusSetting {
  const raw = (value ?? "")
    .split(",")
    .map((s) => s.trim().toLowerCase())
    .filter(Boolean);
  const ok = raw.filter((s): s is (typeof SIGMA_STATUS_CHOICES)[number] =>
    (SIGMA_STATUS_CHOICES as readonly string[]).includes(s),
  );
  const ignored = raw.filter((s) => !ok.includes(s as (typeof SIGMA_STATUS_CHOICES)[number]));
  const statuses = SIGMA_STATUS_CHOICES.filter((s) => ok.includes(s));
  return statuses.length
    ? { statuses: [...statuses], ignored, defaulted: false }
    : { statuses: [...fallback], ignored, defaulted: true };
}

export interface SigmaLevelSetting {
  level: SigmaLevel;
  /** The value that was set but is not a level the Companion offers. */
  invalid?: string;
}

export function sigmaMinLevelFromEnv(env: NodeJS.ProcessEnv = process.env): SigmaLevelSetting {
  const raw = env.DFIR_SIGMA_MIN_LEVEL?.trim().toLowerCase() ?? "";
  if (!raw) return { level: "high" };
  const level = SIGMA_MIN_LEVEL_CHOICES.find((l) => l === raw);
  return level ? { level } : { level: "high", invalid: raw };
}

/**
 * DFIR_SIGMA_SUZAKU_MIN_LEVEL (#2499): the lowest Suzaku rule level that raises severity. Default
 * critical — most Suzaku rules are one rule per API call with no context, so at `high` every routine
 * GetSecretValue or CreateUser would become High and flood the forensic timeline. Below it they label.
 */
export function sigmaSuzakuMinLevelFromEnv(env: NodeJS.ProcessEnv = process.env): SigmaLevelSetting {
  const raw = env.DFIR_SIGMA_SUZAKU_MIN_LEVEL?.trim().toLowerCase() ?? "";
  if (!raw) return { level: "critical" };
  const level = SIGMA_MIN_LEVEL_CHOICES.find((l) => l === raw);
  return level ? { level } : { level: "critical", invalid: raw };
}

const ON = new Set(["on", "1", "true", "yes"]);

/** The startup update check is OFF unless DFIR_SIGMA_UPDATE_CHECK says on. */
export const sigmaUpdateCheckEnabled = (env: NodeJS.ProcessEnv = process.env): boolean =>
  ON.has(env.DFIR_SIGMA_UPDATE_CHECK?.trim().toLowerCase() ?? "");

export const isSigmaLevel = (v: unknown): v is SigmaLevel =>
  typeof v === "string" && (SIGMA_LEVELS as readonly string[]).includes(v);
