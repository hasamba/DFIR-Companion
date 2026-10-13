import type { CaseCredential } from "./types.js";

// The password for a password-locked case (#2135). The companion refuses evidence for a locked case
// unless the request carries the case password; the extension cannot hold the dashboard's httpOnly
// unlock cookie, so the analyst types the password once into the popup.
//
// It lives in browser.storage.session ONLY: memory, cleared when the browser closes, never synced
// and never written to disk. It is never put into a capture payload, so the IndexedDB capture
// queue never holds it — CompanionClient adds it to the request body at send time.

export const CASE_PASSWORD_SESSION_KEY = "dfirCasePassword";

/** The slice of a storage area this module uses (browser.storage.session in the extension). */
export interface SessionArea {
  get(key: string): Promise<Record<string, unknown>>;
  set(items: Record<string, unknown>): Promise<void>;
  remove(key: string): Promise<void>;
}

// The password is bound to the companion it was entered for as well as the case: case ids are only
// unique within one companion, so a password keyed by case id alone followed the analyst to another
// server when they changed the Companion URL and kept the selected case (Codex review of #2135).

/**
 * The companion a URL points at — scheme, host, port and path, lowercased and without a trailing
 * slash — or "" when it is not an http(s) URL. Two spellings of one companion compare equal; a
 * different host, port, scheme or path prefix does not.
 */
export function companionServerKey(url: string): string {
  try {
    const parsed = new URL(url.trim());
    if (parsed.protocol !== "http:" && parsed.protocol !== "https:") return "";
    return `${parsed.origin}${parsed.pathname.replace(/\/+$/, "")}`;
  } catch {
    return "";
  }
}

export function companionServerChanged(before: string | undefined, after: string | undefined): boolean {
  return companionServerKey(before ?? "") !== companionServerKey(after ?? "");
}

/** True when `credential` belongs to `caseId` on the companion at `companionUrl`. */
export function credentialMatches(credential: CaseCredential, caseId: string, companionUrl: string): boolean {
  const server = companionServerKey(companionUrl);
  return Boolean(caseId) && credential.caseId === caseId && server !== "" && credential.companionUrl === server;
}

function isCredential(value: unknown): value is CaseCredential {
  const v = value as Partial<CaseCredential> | null;
  return typeof v?.caseId === "string" && typeof v.companionUrl === "string"
    && typeof v.password === "string" && v.password.length > 0;
}

/** The stored password when it belongs to `caseId` on this companion; undefined otherwise. */
export async function readCaseCredential(
  area: SessionArea | undefined,
  caseId: string,
  companionUrl: string,
): Promise<CaseCredential | undefined> {
  if (!area || !caseId) return undefined;
  const stored = (await area.get(CASE_PASSWORD_SESSION_KEY))[CASE_PASSWORD_SESSION_KEY];
  return isCredential(stored) && credentialMatches(stored, caseId, companionUrl)
    ? { caseId: stored.caseId, companionUrl: stored.companionUrl, password: stored.password }
    : undefined;
}

export async function storeCaseCredential(area: SessionArea | undefined, credential: CaseCredential): Promise<void> {
  if (!area) throw new Error("this browser has no session storage — update it to keep a case password");
  const companionUrl = companionServerKey(credential.companionUrl);
  if (!companionUrl) throw new Error("the Companion URL is not valid — fix it before entering a case password");
  await area.set({
    [CASE_PASSWORD_SESSION_KEY]: { caseId: credential.caseId, companionUrl, password: credential.password },
  });
}

export async function forgetCaseCredential(area: SessionArea | undefined): Promise<void> {
  if (!area) return;
  await area.remove(CASE_PASSWORD_SESSION_KEY);
}

/** The shape of a storage.onChanged `changes` argument, as far as this module reads it. */
export type StorageChanges = Record<string, { oldValue?: unknown; newValue?: unknown } | undefined>;

function companionUrlOf(settings: unknown): string | undefined {
  const url = (settings as { companionUrl?: unknown } | null | undefined)?.companionUrl;
  return typeof url === "string" ? url : undefined;
}

/**
 * Forget the case password when the stored Companion URL now names a different server — saved from
 * the popup or the options page alike. The send-time check already refuses a mismatched server;
 * this keeps the password from waiting in memory for the analyst to switch back.
 */
export async function forgetCredentialOnServerChange(
  area: SessionArea | undefined,
  changes: StorageChanges,
): Promise<void> {
  const change = changes.settings;
  if (!change) return;
  if (companionServerChanged(companionUrlOf(change.oldValue), companionUrlOf(change.newValue))) {
    await forgetCaseCredential(area);
  }
}

/** The companion's answer for a password-locked case — distinct from a 401 for a bad team token. */
export function isLockedRejection(status: number, errorMessage: string | undefined): boolean {
  return status === 401 && errorMessage === "locked";
}

export function lockedQueueMessage(queued: number): string {
  const noun = queued === 1 ? "capture" : "captures";
  return `Case is locked — ${queued} ${noun} waiting for the case password`;
}

export const LOCKED_PUSH_ERROR = "Case is locked — enter the case password in the extension popup, then push again";

/** The analyst-facing reason a console artifact push failed. */
export function pushErrorMessage(
  status: number,
  errorMessage: string | undefined,
  caseId: string,
  companionUrl: string,
): string {
  if (isLockedRejection(status, errorMessage)) return LOCKED_PUSH_ERROR;
  if (status === 0) return `Companion offline at ${companionUrl}`;
  if (status === 404) return `Case "${caseId}" not found — re-select it in the popup`;
  if (status === 400) return "Companion couldn't detect the artifact format";
  if (status === 429) return "Too many wrong case passwords — wait a few minutes, then push again";
  if (status === 501) return "Companion has no AI provider configured for this artifact type";
  return `Import rejected (HTTP ${status})`;
}

export type CasePasswordCheck = "ok" | "wrong" | "locked-out" | "offline" | "error";

/**
 * Ask the companion whether `password` opens `caseId` (POST /cases/:id/unlock). Credentials are
 * omitted: the unlock cookie the route sets belongs to the dashboard, and must not be shared with
 * the extension (the dashboard's "forget on leaving the case" would then re-lock capture silently).
 * A wrong password here counts toward the case's shared lockout, like a wrong one in the dashboard.
 */
export async function checkCasePassword(
  fetchFn: typeof fetch,
  companionUrl: string,
  caseId: string,
  password: string,
  serviceToken: string,
): Promise<CasePasswordCheck> {
  try {
    const res = await fetchFn(`${companionUrl}/cases/${encodeURIComponent(caseId)}/unlock`, {
      method: "POST",
      credentials: "omit",
      headers: {
        "content-type": "application/json",
        ...(serviceToken ? { Authorization: `Bearer ${serviceToken}` } : {}),
      },
      body: JSON.stringify({ password, remember: false }),
    });
    if (res.status === 200) return "ok";
    if (res.status === 401) return "wrong";
    if (res.status === 429) return "locked-out";
    return "error";
  } catch {
    return "offline";
  }
}
