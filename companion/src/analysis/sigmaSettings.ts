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

export function sigmaStatusesFromEnv(env: NodeJS.ProcessEnv = process.env): SigmaStatusSetting {
  const raw = (env.DFIR_SIGMA_RULE_STATUSES ?? "")
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
    : { statuses: [...DEFAULT_SIGMA_STATUSES], ignored, defaulted: true };
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

const ON = new Set(["on", "1", "true", "yes"]);

/** The startup update check is OFF unless DFIR_SIGMA_UPDATE_CHECK says on. */
export const sigmaUpdateCheckEnabled = (env: NodeJS.ProcessEnv = process.env): boolean =>
  ON.has(env.DFIR_SIGMA_UPDATE_CHECK?.trim().toLowerCase() ?? "");

export const isSigmaLevel = (v: unknown): v is SigmaLevel =>
  typeof v === "string" && (SIGMA_LEVELS as readonly string[]).includes(v);
