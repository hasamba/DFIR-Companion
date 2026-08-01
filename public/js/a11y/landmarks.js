// Give the dashboard's sections accessible names, so they become navigable regions.
//
// The dashboard is one long scrolling page of 53 <section> elements. An UNNAMED <section> is not
// exposed as a landmark at all — screen readers only surface it as a region once it has an
// accessible name — so before this, the region rotor (the primary way a screen-reader user moves
// around a long page) listed nothing. There is also no <nav>: the page has no persistent
// navigation element, and inventing one would misdescribe the UI.
//
// The name is taken from the LEADING TEXT of each section's <h2>, not via aria-labelledby pointing
// at the whole heading. Those headings carry their section's controls inline — filter checkboxes,
// source pickers, corroboration selects — so aria-labelledby would name the Forensic Timeline
// region "Forensic Timeline ☆ Starred + Critical High Medium Low ⛏ Sources ⛏ Origins 🖥 Hosts ⊕ any",
// which is worse than no name at all.

/**
 * The heading's own text: its DIRECT text-node children, ignoring every element child.
 *
 * Not "the leading text up to the first element". The dashboard decorates each <h2> at runtime by
 * PREPENDING a drag grip and a collapse chevron, so by the time this runs the first children are
 * <span>⠿</span><span>▾</span> and a leading-text reading returns "" for every section. Taking the
 * direct text nodes skips those decorations and the trailing controls alike, because all of them
 * keep their text inside elements — only the section's own title sits bare in the heading.
 *
 * @param {HTMLElement} heading
 * @returns {string}
 */
function ownText(heading) {
  let out = "";
  for (const node of heading.childNodes) {
    if (node.nodeType === Node.TEXT_NODE) out += node.textContent || "";
  }
  return out.replace(/\s+/g, " ").trim();
}

function wire() {
  const sections = document.querySelectorAll("main section");
  for (const section of sections) {
    // Never overwrite a name an author already chose.
    if (section.hasAttribute("aria-label") || section.hasAttribute("aria-labelledby")) continue;
    const heading = section.querySelector("h2, h3");
    if (!heading) continue;
    const label = ownText(heading);
    if (label) section.setAttribute("aria-label", label);
  }
}

// Guarded so this module can be imported in node (Vitest) with no DOM present, matching the
// convention in command-palette.js.
if (typeof document !== "undefined" && typeof window !== "undefined") wire();
