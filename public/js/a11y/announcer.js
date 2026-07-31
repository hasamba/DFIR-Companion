// Screen-reader announcements for state the UI communicates only visually.
//
// Before this the dashboard had exactly ONE aria-live region in 25k lines, so a job finishing, an
// import failing or synthesis completing was silent to a screen reader — the user had no way to
// know the thing they triggered had finished. #386 asks that "live job, error and AI states are
// announced appropriately"; this owns the two regions that do it.
//
// Two regions, not one: polite waits for a pause in speech (progress, completion), assertive
// interrupts (errors). Mixing them into one region means either errors wait behind routine
// chatter, or routine progress interrupts the user constantly.

const POLITE_ID = "a11y-live-polite";
const ASSERTIVE_ID = "a11y-live-assertive";

/**
 * Format an announcement. Pure, so it is unit-testable under the node suite.
 * @param {"job" | "error" | "ai"} kind
 * @param {string} detail
 * @returns {string} the text to announce, or "" when there is nothing to say
 */
export function announcementText(kind, detail) {
  const clean = String(detail).replace(/\s+/g, " ").trim();
  if (!clean) return "";
  const prefix = kind === "error" ? "Error" : kind === "ai" ? "AI" : "Job";
  return `${prefix}: ${clean}`;
}

/**
 * @param {string} id
 * @param {"polite" | "assertive"} politeness
 * @returns {HTMLElement}
 */
function region(id, politeness) {
  let el = document.getElementById(id);
  if (el) return el;
  el = document.createElement("div");
  el.id = id;
  el.setAttribute("aria-live", politeness);
  el.setAttribute("aria-atomic", "true");
  el.className = "visually-hidden";
  document.body.appendChild(el);
  return el;
}

/**
 * Announce a message to assistive technology.
 * @param {string} message
 * @param {{ assertive?: boolean }} [opts]
 */
export function announce(message, opts) {
  const text = String(message).replace(/\s+/g, " ").trim();
  if (!text) return;
  const el = opts && opts.assertive ? region(ASSERTIVE_ID, "assertive") : region(POLITE_ID, "polite");
  // Clear first: setting the same text twice is not a DOM change, so the region would stay silent
  // on a repeated message ("Import failed" twice in a row) — which is exactly when the user most
  // needs to hear it again.
  el.textContent = "";
  window.setTimeout(() => {
    el.textContent = text;
  }, 50);
}
