import { createFocusTrap } from "./focus-trap.js";

// One open/close pair for every modal in the dashboard.
//
// There are ~30 modal markup sites (comment-modal, wiz-modal, settings-modal, hunt-modal,
// explain-modal, cmdp-modal) and each hand-rolled its own show/hide. None set role="dialog", none
// trapped focus, none restored it, and none closed on Escape. Rather than fix 30 copies, they all
// route through here.
//
// Deliberately NOT migrating to native <dialog>: it would give trap/Escape/backdrop for free, but
// it also brings top-layer stacking and its own backdrop styling, so adopting it means rewriting
// the visual layer of 30 modals. That belongs in #384, not here.

/** @type {WeakMap<HTMLElement, { release: () => void, onKeydown: (ev: KeyboardEvent) => void }>} */
const open = new WeakMap();

/**
 * @param {HTMLElement} el the modal container
 * @param {{ labelledBy?: string, describedBy?: string, onClose?: () => void }} [opts]
 */
export function openModal(el, opts) {
  if (!el || open.has(el)) return;

  el.setAttribute("role", "dialog");
  el.setAttribute("aria-modal", "true");
  if (opts && opts.labelledBy) el.setAttribute("aria-labelledby", opts.labelledBy);
  if (opts && opts.describedBy) el.setAttribute("aria-describedby", opts.describedBy);
  // Without a tabindex the container itself cannot receive focus, which is the fallback the trap
  // uses when a dialog has no focusable children yet (async content still loading).
  if (!el.hasAttribute("tabindex")) el.setAttribute("tabindex", "-1");

  const trap = createFocusTrap(el);
  trap.activate();

  /** @param {KeyboardEvent} ev */
  const onKeydown = (ev) => {
    if (ev.key === "Escape") {
      ev.stopPropagation();
      closeModal(el);
      if (opts && opts.onClose) opts.onClose();
    }
  };
  el.addEventListener("keydown", onKeydown);

  open.set(el, { release: trap.release, onKeydown });
}

/** @param {HTMLElement} el */
export function closeModal(el) {
  if (!el) return;
  const state = open.get(el);
  if (!state) return;
  el.removeEventListener("keydown", state.onKeydown);
  // aria-modal is removed but role="dialog" is kept: the element is still a dialog, it is merely
  // not currently modal. Leaving aria-modal="true" on a hidden dialog makes some screen readers
  // treat the rest of the page as inert.
  el.removeAttribute("aria-modal");
  state.release();
  open.delete(el);
}

/**
 * True when the modal is currently open through this module. Lets existing toggle-style handlers
 * ask rather than track their own duplicate boolean.
 * @param {HTMLElement} el
 * @returns {boolean}
 */
export function isModalOpen(el) {
  return !!el && open.has(el);
}
