import { openModal, closeModal } from "./modal.js";

// Gives every modal in the dashboard dialog semantics, a focus trap, Escape-to-close and focus
// restoration — without touching a single one of them individually.
//
// WHY AN OBSERVER RATHER THAN 72 EDITS. Modals here are shown and hidden purely by toggling one
// class: `.comment-overlay { display: none }` / `.comment-overlay.open { display: block }`. That
// toggle happens at 31 `classList.add("open")` and 41 `classList.remove("open")` call sites across
// 29 overlays in a 25,000-line file. Editing all 72 by hand would be a large, mechanical,
// hard-to-review diff, and the add/remove asymmetry makes a missed site easy — a modal that opens
// accessibly but never releases its focus trap is worse than one that was never wired at all.
//
// Watching the class instead means there is exactly ONE place to get right, a modal added later is
// covered automatically, and the whole thing survives #384's decomposition as a single unit rather
// than as 72 edits scattered through files that are about to move.
//
// Deliberately does NOT observe for overlays added at runtime: all 31 are present in the static
// markup, and a subtree observer would re-scan on every timeline render for no benefit. If a
// future modal is ever created dynamically, the axe ratchet fails on its missing dialog role,
// which is the signal to revisit this.

const OVERLAY_SELECTOR = ".comment-overlay, .cmdp-overlay, .wiz-overlay";
const OPEN_CLASS = "open";

let seq = 0;

/**
 * The id of the overlay's own heading, assigning one if it has none, so the dialog gets an
 * accessible name from the title it already displays.
 * @param {HTMLElement} overlay
 * @returns {string | undefined}
 */
function headingId(overlay) {
  const heading = overlay.querySelector("h1, h2, h3");
  if (!heading) return undefined;
  seq += 1;
  if (!heading.id) heading.id = `a11y-modal-title-${seq}`;
  return heading.id;
}

/**
 * An existing author-written name always wins: cmdpOverlay carries aria-label and wizOverlay
 * carries aria-labelledby already, and overwriting either would replace a considered name with a
 * generated one.
 * @param {HTMLElement} overlay
 * @returns {string | undefined}
 */
function labelledByFor(overlay) {
  if (overlay.hasAttribute("aria-label") || overlay.hasAttribute("aria-labelledby")) return undefined;
  return headingId(overlay);
}

/** @param {HTMLElement} overlay */
function sync(overlay) {
  if (overlay.classList.contains(OPEN_CLASS)) {
    openModal(overlay, {
      labelledBy: labelledByFor(overlay),
      // Escape routes back through the same class the rest of the app uses, so the dialog closes
      // by the app's own mechanism rather than by a second, divergent hide path.
      onClose: () => overlay.classList.remove(OPEN_CLASS),
    });
  } else {
    closeModal(overlay);
  }
}

function wire() {
  const observer = new MutationObserver((records) => {
    for (const record of records) sync(/** @type {HTMLElement} */ (record.target));
  });
  const overlays = document.querySelectorAll(OVERLAY_SELECTOR);
  for (const overlay of overlays) {
    observer.observe(overlay, { attributes: true, attributeFilter: ["class"] });
    // An overlay already open at load (the setup wizard on a fresh install) must be wired too.
    if (overlay.classList.contains(OPEN_CLASS)) sync(/** @type {HTMLElement} */ (overlay));
  }
}

// Guarded so this module can be imported in node (Vitest) with no DOM present, matching the
// convention in command-palette.js.
if (typeof document !== "undefined" && typeof window !== "undefined") wire();
