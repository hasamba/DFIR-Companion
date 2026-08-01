// Keyboard focus containment for modal dialogs.
//
// The dashboard has ~30 hand-rolled modals and, before this, zero focus management: Tab walked
// straight out of an open dialog into the page behind it, and closing a dialog dropped focus to
// <body>, so a keyboard user lost their place entirely. #386 asks that dialogs "trap/restore
// focus"; this is the mechanism.
//
// The index maths is exported separately from the DOM wiring so it can be unit-tested under the
// suite's node environment — there is no jsdom leg, and adding one for this would be weaker than
// the real-browser coverage in tests/e2e/a11y/keyboard.spec.ts.

/** Elements that can hold focus, in DOM order. Excludes anything disabled or explicitly removed. */
const FOCUSABLE = [
  "a[href]",
  "button:not([disabled])",
  "input:not([disabled]):not([type='hidden'])",
  "select:not([disabled])",
  "textarea:not([disabled])",
  "[tabindex]:not([tabindex='-1'])",
].join(",");

/**
 * Next index in a wrap-around focus ring.
 * @param {number} count how many focusable elements there are
 * @param {number} current index of the focused element, or -1 if focus is outside the ring
 * @param {boolean} backwards true for Shift+Tab
 * @returns {number} the next index, or -1 when nothing is focusable
 */
export function nextFocusIndex(count, current, backwards) {
  if (count <= 0) return -1;
  if (current < 0) return backwards ? count - 1 : 0;
  return backwards ? (current - 1 + count) % count : (current + 1) % count;
}

/**
 * Trap Tab within `container` until released, then restore focus to whatever had it.
 * @param {HTMLElement} container
 * @returns {{ activate(): void, release(): void }}
 */
export function createFocusTrap(container) {
  /** @type {Element | null} */
  let previouslyFocused = null;

  /** @param {KeyboardEvent} ev */
  function onKeydown(ev) {
    if (ev.key !== "Tab") return;
    // offsetParent is null for a display:none element. The extra activeElement check keeps the
    // currently focused control in the ring even when it is position:fixed, where offsetParent is
    // also null — without it, focus inside a fixed-position dialog would be treated as outside.
    const items = Array.prototype.slice
      .call(container.querySelectorAll(FOCUSABLE))
      .filter((el) => el.offsetParent !== null || el === document.activeElement);
    if (items.length === 0) {
      // Nothing to focus inside; swallow Tab so it cannot escape to the page behind the dialog.
      ev.preventDefault();
      return;
    }
    const current = items.indexOf(document.activeElement);
    const next = nextFocusIndex(items.length, current, ev.shiftKey);
    if (next >= 0) {
      ev.preventDefault();
      items[next].focus();
    }
  }

  return {
    activate() {
      previouslyFocused = document.activeElement;
      container.addEventListener("keydown", onKeydown);
      const first = container.querySelector(FOCUSABLE);
      (first || container).focus();
    },
    release() {
      container.removeEventListener("keydown", onKeydown);
      // Restore to the invoking control. Without this the user is dumped at the top of the page.
      if (previouslyFocused && document.contains(previouslyFocused)) {
        previouslyFocused.focus();
      }
      previouslyFocused = null;
    },
  };
}
