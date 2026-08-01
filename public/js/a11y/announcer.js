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

/**
 * Whether a status message should interrupt the user rather than wait for a pause.
 * Pure, so the classification is unit-testable.
 * @param {string} text
 * @returns {boolean}
 */
export function isAssertive(text) {
  return /\b(error|failed|failure|refused|denied|cannot|could not|unable)\b/i.test(text);
}

function wire() {
  // BRIDGE THE EXISTING STATUS LINE, rather than hunting down every caller.
  //
  // #status in the toolbar is already the app's announcement surface: job progress, AI/synthesis
  // state, second-opinion results and every refusal are written straight to its textContent from
  // dozens of call sites, and showToast() mirrors its text there too. All of it was visual-only.
  //
  // Observing the one element means every one of those messages reaches a screen reader, including
  // messages added later — the alternative is editing dozens of `.textContent =` sites and missing
  // the next one. Same reasoning as js/a11y/modal-autowire.js.
  // Create BOTH regions up front rather than on first use. A live region that is inserted into the
  // DOM in the same tick as its text is unreliable: several screen readers only watch regions that
  // existed before the change, so the first message of each politeness — often the most important
  // one — can be dropped entirely.
  region(POLITE_ID, "polite");
  region(ASSERTIVE_ID, "assertive");

  const status = document.getElementById("status");
  if (!status) return;

  let last = status.textContent || "";
  const observer = new MutationObserver(() => {
    const text = (status.textContent || "").trim();
    // The status line is rewritten on every render, often with the text it already had. Announcing
    // an unchanged message would make the app chatter constantly.
    if (!text || text === last) return;
    last = text;
    announce(text, { assertive: isAssertive(text) });
  });
  observer.observe(status, { childList: true, characterData: true, subtree: true });
}

// Guarded so the pure exports above can be imported in node (Vitest) with no DOM present, matching
// the convention in command-palette.js.
if (typeof document !== "undefined" && typeof window !== "undefined") wire();
