import type { AiControl } from "../../aiControl.js";

/**
 * Watson's per-case run mode, kept in the case's ai-control file. Approve is the default and the
 * only mode a case has until an analyst switches it; Auto lets Watson act without asking, within
 * the rules the later phase 3 tasks set (fleet-wide hunts always wait for an analyst).
 */
export type WatsonRunMode = NonNullable<AiControl["watsonRunMode"]>;

export function isWatsonRunMode(value: unknown): value is WatsonRunMode {
  return value === "approve" || value === "auto";
}

/** The case's mode. A missing field (an older file) or a junk value reads as Approve. */
export function watsonRunMode(control: { watsonRunMode?: unknown } | null | undefined): WatsonRunMode {
  return control?.watsonRunMode === "auto" ? "auto" : "approve";
}

/** Who switched Auto on: the authenticated analyst. */
export interface WatsonModeActor {
  id?: string;
  name: string;
}

/**
 * The ai-control patch for a switch. Auto records when and by whom; Approve clears both, in the same
 * write, so the file never names an analyst for a mode that is off.
 */
export function watsonModePatch(
  mode: WatsonRunMode,
  actor: WatsonModeActor,
  now: Date = new Date(),
): Partial<AiControl> {
  if (mode === "auto") {
    return {
      watsonRunMode: "auto",
      watsonAutoSince: now.toISOString(),
      watsonAutoBy: { ...(actor.id ? { id: actor.id } : {}), name: actor.name },
    };
  }
  return { watsonRunMode: "approve", watsonAutoSince: undefined, watsonAutoBy: undefined };
}

/** The activity-log line for a switch. */
export function watsonModeDetail(mode: WatsonRunMode): string {
  return mode === "auto" ? "Switched Watson to Auto" : "Switched Watson to Approve";
}
