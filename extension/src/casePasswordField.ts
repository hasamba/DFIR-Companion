// The popup's "Case password" field (#2135). Shown only when the selected case is password-locked:
// the companion then refuses screenshots and console pushes that do not carry the password. The
// typed password is checked against the companion once (Check), then kept in browser session memory
// only — see casePasswordSession.ts. It is never saved with the popup's other settings.
import { browserApi } from "./browser.js";
import {
  checkCasePassword,
  forgetCaseCredential,
  readCaseCredential,
  storeCaseCredential,
  type CasePasswordCheck,
  type SessionArea,
} from "./casePasswordSession.js";

export interface CasePasswordTarget {
  caseId: string;
  companionUrl: string;
  serviceToken: string;
}

export const CHECK_RESULT_HINTS: Record<CasePasswordCheck, string> = {
  ok: "Password accepted — kept in memory until the browser closes. Waiting captures upload with the next capture.",
  wrong: "Wrong password — not saved. Captures keep waiting in the extension.",
  "locked-out": "Too many wrong passwords for this case — wait a few minutes, then try again.",
  offline: "Companion offline — the password could not be checked.",
  error: "The companion could not check the password — try again.",
};

const LOCKED_HINT =
  "This case is locked. Enter its password so screenshots and pushes are accepted. Until then, screenshots wait in the extension.";
const HELD_HINT = "Password held for this browser session — screenshots and pushes are accepted.";

function area(): SessionArea | undefined {
  return browserApi.storage.session as unknown as SessionArea | undefined;
}

function el<T extends HTMLElement>(id: string): T {
  return document.getElementById(id) as T;
}

/** Show or hide the field for the selected case, with the right hint. */
export async function refreshCasePasswordField(caseId: string, companionUrl: string, locked: boolean): Promise<void> {
  const row = el<HTMLDivElement>("casePasswordRow");
  row.hidden = !caseId || !locked;
  if (row.hidden) return;
  const held = await readCaseCredential(area(), caseId, companionUrl).catch(() => undefined);
  el<HTMLDivElement>("casePasswordHint").textContent = held ? HELD_HINT : LOCKED_HINT;
}

/** A different case was picked: a password never follows the analyst to another case. */
export async function onCaseSelectionChanged(caseId: string, companionUrl: string, locked: boolean): Promise<void> {
  await forgetCaseCredential(area()).catch(() => undefined);
  el<HTMLInputElement>("casePassword").value = "";
  await refreshCasePasswordField(caseId, companionUrl, locked);
}

/**
 * The Companion URL was edited: a password entered for another companion is forgotten, so it can
 * never be sent to the new server (the service worker's storage listener does the same for a URL
 * saved from the options page). Re-typing the same server keeps it.
 */
export async function onCompanionUrlChanged(caseId: string, companionUrl: string, locked: boolean): Promise<void> {
  const held = await readCaseCredential(area(), caseId, companionUrl).catch(() => undefined);
  if (!held) await forgetCaseCredential(area()).catch(() => undefined);
  await refreshCasePasswordField(caseId, companionUrl, locked);
}

/** Wire the Check button. `target` reads the popup's current case / companion settings. */
export function wireCasePasswordField(target: () => CasePasswordTarget): void {
  el<HTMLButtonElement>("checkCasePassword").onclick = async () => {
    const input = el<HTMLInputElement>("casePassword");
    const hint = el<HTMLDivElement>("casePasswordHint");
    const { caseId, companionUrl, serviceToken } = target();
    if (!caseId || !input.value) {
      hint.textContent = "Type the case password first.";
      return;
    }
    const outcome = await checkCasePassword(
      (i, init) => fetch(i, init), companionUrl, caseId, input.value, serviceToken,
    );
    if (outcome === "ok") {
      try {
        await storeCaseCredential(area(), { caseId, companionUrl, password: input.value });
      } catch (error) {
        hint.textContent = (error as Error).message;
        return;
      }
    }
    input.value = "";
    hint.textContent = CHECK_RESULT_HINTS[outcome];
  };
}
