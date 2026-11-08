import type { Settings } from "./types.js";

/**
 * Pages ask the service worker to change settings instead of writing storage themselves (#2398):
 * the worker is the only writer, so two pages can never put back each other's stale copy.
 */

export interface UpdateSettingsMessage {
  kind: "update_settings";
  patch: Partial<Settings>;
  /** Apply only while the stored case is still this one (compare-and-set). */
  ifCaseId?: string;
}

export type UpdateSettingsResult =
  | { ok: true; settings: Settings; applied: boolean; stoppedForNoCase: boolean }
  | { ok: false; error: string };

type Send = (message: UpdateSettingsMessage) => Promise<unknown>;

function isResult(value: unknown): value is UpdateSettingsResult {
  if (!value || typeof value !== "object") return false;
  const v = value as { ok?: unknown; settings?: unknown; error?: unknown };
  if (v.ok === true) return !!v.settings && typeof v.settings === "object";
  return v.ok === false && typeof v.error === "string";
}

/** Send one change to the worker. A failure is returned, never thrown, so the page can say so. */
export async function requestSettingsUpdate(
  send: Send,
  patch: Partial<Settings>,
  ifCaseId?: string,
): Promise<UpdateSettingsResult> {
  const message: UpdateSettingsMessage = { kind: "update_settings", patch };
  if (ifCaseId !== undefined) message.ifCaseId = ifCaseId;
  try {
    const answer = await send(message);
    if (isResult(answer)) return answer;
    return { ok: false, error: "the extension background did not answer" };
  } catch (error) {
    return { ok: false, error: error instanceof Error ? error.message : String(error) };
  }
}
