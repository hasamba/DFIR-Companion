// Give `data-tip` controls an accessible name.
//
// The dashboard replaced native `title` tooltips with a custom `data-tip` attribute because native
// tooltips cannot be styled (see the tooltip block in dashboard.html). The styling problem was
// real; the side effect was not noticed: `data-tip` is invisible to assistive technology, so every
// control that relies on it for its meaning became anonymous.
//
// 24 elements carry data-tip. Exactly one also carries aria-label, and none carry title — so 23
// controls announce as "checkbox" or "button" and nothing else. The archived-cases toggle (#220,
// which explicitly asks for "an icon with accessible text/title") is one of them: a bare checkbox
// beside an SVG, inside a label with no text.
//
// Rather than hand-label 23 controls and miss the next one, the tip text — which the author already
// wrote, and which already says exactly what the control does — becomes the accessible name when
// the control has no other. An author-supplied aria-label, aria-labelledby, title or visible text
// always wins; this only fills a vacuum.

/** Controls that need a name of their own. */
const NAMEABLE = "input, button, select, textarea, a[href], [role='button'], [tabindex]";

/**
 * Whether the element already has an accessible name from any source that beats a tooltip.
 * @param {Element} el
 * @returns {boolean}
 */
function hasAccessibleName(el) {
  if (el.getAttribute("aria-label")?.trim()) return true;
  if (el.getAttribute("aria-labelledby")?.trim()) return true;
  if (el.getAttribute("title")?.trim()) return true;
  // Visible text inside the control itself (a button's label), not text merely near it.
  if (el.textContent?.trim()) return true;
  // A wrapping <label> with real text names the control already.
  const label = el.closest("label");
  if (label && (label.textContent || "").trim()) return true;
  return false;
}

/**
 * The controls a tip is really describing: the element itself when it is one, otherwise the
 * unnamed controls it wraps — the common shape here is <label data-tip><input><svg></label>.
 * @param {Element} host
 * @returns {Element[]}
 */
function targetsFor(host) {
  if (host.matches(NAMEABLE)) return [host];
  return [...host.querySelectorAll(NAMEABLE)];
}

function wire() {
  for (const host of document.querySelectorAll("[data-tip]")) {
    const tip = (host.getAttribute("data-tip") || "").replace(/\s+/g, " ").trim();
    if (!tip) continue;
    for (const target of targetsFor(host)) {
      if (hasAccessibleName(target)) continue;
      target.setAttribute("aria-label", tip);
    }
  }
}

// Guarded so this module can be imported in node (Vitest) with no DOM present, matching the
// convention in command-palette.js.
if (typeof document !== "undefined" && typeof window !== "undefined") wire();
