// The one-time move of per-model keys and base URLs into the per-provider slots
// (DFIR_AI_KEY_<PROVIDER>, DFIR_AI_BASE_URL_<PROVIDER>). Before those slots existed every model held
// its own copy; now a per-model value is an override. This plans the move and does no I/O: the
// route reads the .env file, calls planAiKeyMigration, and writes `updates` back.
//
// The one promise: no model sends a different key or base URL after the move. A per-model value is
// often borrowed — a model with no key of its own falls back to the vision key — so blanking the
// vision key can silently empty another model. Each group is applied to a copy of the env and every
// role is re-resolved; a group that changes any role is dropped and reported instead.

import {
  AI_ROLE_SOURCES,
  PROVIDER_ENV_NAMES,
  providerEnv,
  resolveAiRoleSetting,
  roleOwnSetting,
  type AiRoleId,
  type EnvSource,
  type ProviderEnvSetting,
} from "./aiEnv.js";

export type MigrationSetting = "key" | "baseUrl";

export interface AiKeyMove {
  readonly role: AiRoleId;
  readonly provider: string;
  readonly setting: MigrationSetting;
  /** The provider slot the value now lives in, e.g. DFIR_AI_KEY_GEMINI. */
  readonly target: string;
  /** The env names the move blanks. */
  readonly sources: readonly string[];
}

export interface AiKeyConflict {
  readonly provider: string;
  readonly setting: MigrationSetting;
  readonly roles: readonly AiRoleId[];
  readonly reason: string;
}

/** Names only — safe to send to the browser. */
export interface PublicAiKeyMigration {
  readonly moves: readonly AiKeyMove[];
  readonly conflicts: readonly AiKeyConflict[];
}

export interface AiKeyMigrationPlan extends PublicAiKeyMigration {
  /** The .env writes, WITH values. Server-internal: never send this to the browser. */
  readonly updates: Readonly<Record<string, string>>;
}

export const CONFLICT_DIFFERS_FROM_SLOT = "differs from the value saved for the provider";
export const CONFLICT_MODELS_DISAGREE = "models on this provider use different values";
export const CONFLICT_BORROWED = "another model borrows this value";

const SETTINGS: readonly ProviderEnvSetting[] = ["KEY", "BASE_URL"];
const ROLES = Object.keys(AI_ROLE_SOURCES) as AiRoleId[];

interface Candidate {
  readonly role: AiRoleId;
  readonly provider: string;
  readonly value: string;
  readonly names: readonly string[];
}

interface Group {
  readonly provider: string;
  readonly setting: ProviderEnvSetting;
  readonly candidates: readonly Candidate[];
}

interface Step {
  readonly moves: readonly AiKeyMove[];
  readonly conflicts: readonly AiKeyConflict[];
  readonly updates: Readonly<Record<string, string>>;
}

function wireSetting(setting: ProviderEnvSetting): MigrationSetting {
  return setting === "KEY" ? "key" : "baseUrl";
}

function slotName(provider: string, setting: ProviderEnvSetting): string {
  return `DFIR_AI_${setting}_${PROVIDER_ENV_NAMES[provider]}`;
}

/** A role with its own non-blank value, on a provider that has a slot. */
function candidateFor(env: EnvSource, role: AiRoleId, setting: ProviderEnvSetting): Candidate | undefined {
  const provider = slotProvider(env, role);
  const value = roleOwnSetting(env, role, setting)?.trim();
  if (!provider || !value) return undefined;
  // Vision clears the new name AND the legacy one, or the legacy value would surface again.
  const names = AI_ROLE_SOURCES[role].ownNames(setting).filter((name) => env[name] !== undefined);
  return { role, provider, value, names };
}

/** Candidates grouped by provider, in role order, for one setting. */
function groupsFor(env: EnvSource, setting: ProviderEnvSetting): Group[] {
  const byProvider = new Map<string, Candidate[]>();
  for (const role of ROLES) {
    const candidate = candidateFor(env, role, setting);
    if (!candidate) continue;
    byProvider.set(candidate.provider, [...(byProvider.get(candidate.provider) ?? []), candidate]);
  }
  return [...byProvider].map(([provider, candidates]) => ({ provider, setting, candidates }));
}

function conflict(group: Group, roles: readonly Candidate[], reason: string): AiKeyConflict {
  return {
    provider: group.provider,
    setting: wireSetting(group.setting),
    roles: roles.map((c) => c.role),
    reason,
  };
}

function movesStep(group: Group, movers: readonly Candidate[], slotValue?: string): Step {
  const target = slotName(group.provider, group.setting);
  const cleared = Object.fromEntries(movers.flatMap((c) => c.names.map((name) => [name, ""])));
  return {
    moves: movers.map((c) => ({
      role: c.role,
      provider: group.provider,
      setting: wireSetting(group.setting),
      target,
      sources: c.names,
    })),
    conflicts: [],
    updates: slotValue === undefined ? cleared : { [target]: slotValue, ...cleared },
  };
}

/** What one provider/setting group would do, before the safety check. */
function proposeGroup(env: EnvSource, group: Group): { step: Step; conflicts: AiKeyConflict[] } {
  const slot = providerEnv(env, group.provider, group.setting);
  if (slot !== undefined) {
    const movers = group.candidates.filter((c) => c.value === slot);
    const keepers = group.candidates.filter((c) => c.value !== slot);
    const conflicts = keepers.length ? [conflict(group, keepers, CONFLICT_DIFFERS_FROM_SLOT)] : [];
    return { step: movesStep(group, movers), conflicts };
  }
  const values = new Set(group.candidates.map((c) => c.value));
  if (values.size > 1) {
    return {
      step: movesStep(group, []),
      conflicts: [conflict(group, group.candidates, CONFLICT_MODELS_DISAGREE)],
    };
  }
  return { step: movesStep(group, group.candidates, group.candidates[0].value), conflicts: [] };
}

function slotProvider(env: EnvSource, role: AiRoleId): string | undefined {
  const provider = (AI_ROLE_SOURCES[role].provider(env) ?? "").trim().toLowerCase();
  return PROVIDER_ENV_NAMES[provider] ? provider : undefined;
}

/**
 * What a role actually sends. A role on a CLI provider (claude-code, codex) or on no provider sends
 * no key and no base URL, so a value it would only nominally resolve does not count. Blank and
 * unset send the same thing: nothing.
 */
export function effectiveRoleSetting(
  env: EnvSource,
  role: AiRoleId,
  setting: ProviderEnvSetting,
): string | undefined {
  if (!slotProvider(env, role)) return undefined;
  // #1734: a fallback with no model is off and sends nothing.
  if (role === "synthesis-fallback" && !env.DFIR_AI_SYNTH_FALLBACK_MODEL?.trim()) return undefined;
  return resolveAiRoleSetting(env, role, setting)?.trim() || undefined;
}

function resolvedSetting(env: EnvSource, setting: ProviderEnvSetting): string {
  return JSON.stringify(ROLES.map((role) => effectiveRoleSetting(env, role, setting) ?? null));
}

/** Apply one group to the env copy only when no role's resolved value changes. */
function applySafely(env: EnvSource, group: Group, step: Step): { env: EnvSource; step: Step } {
  if (step.moves.length === 0) return { env, step };
  const next = { ...env, ...step.updates };
  if (resolvedSetting(next, group.setting) === resolvedSetting(env, group.setting))
    return { env: next, step };
  const movers = group.candidates.filter((c) => step.moves.some((m) => m.role === c.role));
  return { env, step: { moves: [], conflicts: [conflict(group, movers, CONFLICT_BORROWED)], updates: {} } };
}

/** Plan the move. Pure: reads `env`, returns names for the browser and values for the .env write. */
export function planAiKeyMigration(env: EnvSource): AiKeyMigrationPlan {
  let current: EnvSource = { ...env };
  const moves: AiKeyMove[] = [];
  const conflicts: AiKeyConflict[] = [];
  let updates: Record<string, string> = {};
  for (const setting of SETTINGS) {
    for (const group of groupsFor(env, setting)) {
      const proposed = proposeGroup(current, group);
      const applied = applySafely(current, group, proposed.step);
      current = applied.env;
      moves.push(...applied.step.moves);
      conflicts.push(...proposed.conflicts, ...applied.step.conflicts);
      updates = { ...updates, ...applied.step.updates };
    }
  }
  return { moves, conflicts, updates };
}

/** The plan without its values — the only shape a route may send. */
export function publicAiKeyMigration(plan: AiKeyMigrationPlan): PublicAiKeyMigration {
  return { moves: plan.moves, conflicts: plan.conflicts };
}
