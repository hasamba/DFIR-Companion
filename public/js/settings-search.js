// Settings search — the live cross-tab filter in the Settings modal.
//
// Loaded in the browser as an ES module (<script type="module" src="/js/settings-search.js">), the
// same arrangement graph-view.js and command-palette.js use. CSP already allows /js/* via 'self'
// (see companion/src/http/securityHeaders.ts), so no header change is needed.
//
// Division of labour, mirroring command-palette.js: the pure half below is exported by name so
// Vitest can drive it in node, where there is no DOM. Everything under the "browser glue" banner
// touches the document and is deliberately thin for that reason.

/** Lowercase, `_`/`-` → space, collapse whitespace, trim.
 *
 *  Applied to BOTH sides of every comparison, which is the whole trick: "max events" finds
 *  DFIR_MAX_EVENTS, and pasting DFIR_MAX_EVENTS straight from .env or the docs finds it too. */
export function normalize(s) {
  return String(s == null ? "" : s)
    .toLowerCase()
    .replace(/[_-]+/g, " ")
    .replace(/\s+/g, " ")
    .trim();
}

/** True when every whitespace-separated token of `query` appears somewhere in `haystack`.
 *
 *  Substring, not fuzzy. command-palette.js's fuzzyScore has a scattered-subsequence tier, which is
 *  right for a RANKED list where a weak match sinks harmlessly to the bottom. This is an unranked
 *  in-place filter in DOM order — there is nothing to sink, so a query like "ai" matching half the
 *  modal by letter-scatter would be pure noise with no way to bury it.
 *
 *  An empty query is a vacuous AND and returns true; callers short-circuit before that. */
export function matchTokens(query, haystack) {
  const tokens = normalize(query).split(" ").filter(Boolean);
  if (!tokens.length) return true;
  const hay = normalize(haystack);
  return tokens.every((t) => hay.includes(t));
}

/** Which tab to show for a set of hits: stay put if the tab you are on has any (so typing does not
 *  yank you away mid-edit), else the first tab that does, else null — the "no matches" state. */
export function landingTab(hitTabs, activeTab) {
  const tabs = Array.isArray(hitTabs) ? hitTabs : [];
  if (activeTab && tabs.includes(activeTab)) return activeTab;
  return tabs.length ? tabs[0] : null;
}

/** The text for #settingsSearchMsg. `fields` is how many .sfield elements will be visible; `tabs`
 *  how many tab buttons are hits. fields === 0 with tabs > 0 is the name-match-only case (typing
 *  "kev" or "whitelist"), whose pane is filled by JS at click time and holds no .sfield at all. */
export function searchMessage({ tabs = 0, fields = 0, query = "" } = {}) {
  const plural = (n, word) => `${n} ${word}${n === 1 ? "" : "s"}`;
  if (!tabs) return `No settings match "${String(query).trim()}"`;
  if (fields > 0) return `${plural(fields, "field")} in ${plural(tabs, "tab")}`;
  return plural(tabs, "tab");
}
