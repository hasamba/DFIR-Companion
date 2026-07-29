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

// ── Browser glue ──────────────────────────────────────────────────────────────────────────────
// Everything below touches the document. The guard at the very bottom is what keeps the exports
// above importable in node.

/** Every string worth matching a field on, joined with spaces.
 *
 *  Node by node rather than one el.textContent read, because the markup is
 *  `<label>LeakCheck key<span class="sfield-hint">DFIR_LEAKCHECK_KEY</span></label>` — a single
 *  textContent read yields "LeakCheck keyDFIR_LEAKCHECK_KEY", label and env key fused into one word
 *  with no separator, so "key" would match but "leakcheck key" would not.
 *
 *  <option> text is in deliberately: it is how searching "ollama" finds the AI provider select, and
 *  "critical" the import-severity one. Ids come along because a few fields carry the env key only
 *  on the input. Overlap between the parts is harmless for substring matching. */
function fieldText(el) {
  const parts = [];
  for (const n of el.querySelectorAll("label, .sfield-hint, option")) parts.push(n.textContent);
  for (const n of el.querySelectorAll("[placeholder]")) parts.push(n.getAttribute("placeholder"));
  for (const n of el.querySelectorAll("[id]")) parts.push(n.id);
  parts.push(el.textContent);
  return parts.join(" ");
}

const modalEl = () => document.querySelector(".settings-modal");

let index = [];

/** Walked once per modal open, not per keystroke. */
function buildIndex() {
  index = [...document.querySelectorAll(".stab-pane .sfield")].map((el) => ({
    el,
    pane: el.closest(".stab-pane"),
    text: fieldText(el),
  }));
}

function stripHits() {
  const m = modalEl();
  if (!m) return;
  m.removeAttribute("data-searching");
  for (const el of m.querySelectorAll("[data-hit]")) el.removeAttribute("data-hit");
  for (const el of m.querySelectorAll("[data-hit-count]")) el.removeAttribute("data-hit-count");
}

/** Keep every wrapper between a hit and its pane, so .sfield-row and .sgrid survive the
 *  "hide unmarked top-level pane children" rule. */
function markChain(el, pane) {
  for (let n = el.parentElement; n && n !== pane; n = n.parentElement) {
    if (!n.hasAttribute("data-hit")) n.setAttribute("data-hit", "container");
  }
}

/** A .settings-group-head is a SIBLING of the fields it governs, not an ancestor, so markChain
 *  cannot reach it and a filtered field would show with its group context stripped away. Walk the
 *  pane's top-level children in order, remember the last heading, and keep it once a hit follows.
 *  (Every top-level child that survives the filter carries data-hit by now — either its own, from
 *  being a hit .sfield, or "container" from markChain.) */
function markHeadings(pane) {
  let head = null;
  for (const child of pane.children) {
    if (child.classList.contains("settings-group-head")) { head = child; continue; }
    if (head && child.hasAttribute("data-hit")) { head.setAttribute("data-hit", "container"); head = null; }
  }
}

/** Re-run the inline script's own mode application rather than a copy of it, so an active tab that
 *  Essential hides — which only became active because the search revealed it — falls back through
 *  the existing path in applySettingsMode. */
function restoreMode() {
  const msg = document.getElementById("settingsSearchMsg");
  if (msg) { msg.textContent = ""; msg.hidden = true; }
  const cfg = window.DfirSettingsSearchConfig;
  if (cfg) cfg.applyMode(cfg.mode());
}

function applySearch(query) {
  const m = modalEl();
  if (!m) return;
  stripHits();
  if (!String(query).trim()) { restoreMode(); return; }

  for (const f of index) {
    if (!matchTokens(query, f.text)) continue;
    f.el.setAttribute("data-hit", "");
    markChain(f.el, f.pane);
  }

  const hitTabs = [];
  let visibleFields = 0;
  for (const btn of document.querySelectorAll(".stab")) {
    const pane = document.getElementById("stab-" + btn.dataset.stab);
    if (!pane) continue;
    // A tab-name match is against the button's own label alone ("IOC Whitelist", "Report
    // Templates"), never its pane. It is what keeps the JS-filled panes reachable: their rows do
    // not exist in the DOM when the search runs, and they are case data rather than settings.
    const nameMatch = matchTokens(query, btn.textContent);
    if (nameMatch) pane.setAttribute("data-hit", "pane");
    // THE COUNT INVARIANT: data-hit-count is always how many .sfield elements the tab will SHOW.
    // A name-matched pane renders unfiltered, so that is all of them — and 0 for the content
    // managers, where no badge renders but the tab is still a hit and still clickable.
    const count = nameMatch
      ? pane.querySelectorAll(".sfield").length
      : pane.querySelectorAll(".sfield[data-hit]").length;
    if (!nameMatch && !count) continue;
    btn.setAttribute("data-hit", "");
    if (count) btn.setAttribute("data-hit-count", String(count));
    hitTabs.push(btn.dataset.stab);
    visibleFields += count;
  }

  for (const pane of document.querySelectorAll(".stab-pane")) {
    if (pane.getAttribute("data-hit") !== "pane") markHeadings(pane);
  }

  m.setAttribute("data-searching", "");
  const msg = document.getElementById("settingsSearchMsg");
  if (msg) {
    msg.textContent = searchMessage({ tabs: hitTabs.length, fields: visibleFields, query });
    msg.hidden = false;
  }

  const active = document.querySelector(".stab.active");
  const land = landingTab(hitTabs, active ? active.dataset.stab : null);
  if (land && (!active || active.dataset.stab !== land)) {
    const btn = document.querySelector(`.stab[data-stab="${land}"]`);
    // .click() rather than a class toggle, so the inline handler's per-tab loaders still fire.
    if (btn) btn.click();
  }
}

function clearSearch() {
  const input = document.getElementById("settingsSearch");
  if (input) input.value = "";
  stripHits();
  restoreMode();
}

/** Called by openSettingsModal: a stale filter must never survive a close/reopen, and panes can
 *  gain fields between opens. */
function reset() {
  clearSearch();
  buildIndex();
}

function wire() {
  const input = document.getElementById("settingsSearch");
  if (!input) return;
  window.DfirSettingsSearch = { reset, clear: clearSearch };
  buildIndex();
  // type="search" fires `input` for its native clear affordance too, so that path needs no handler.
  input.addEventListener("input", () => applySearch(input.value));
  // Scoped to the input, and stopPropagation so it stays that way: the Settings modal has no
  // Escape-to-close binding today and adding one is a separate decision.
  input.addEventListener("keydown", (e) => {
    if (e.key !== "Escape") return;
    e.stopPropagation();
    clearSearch();
  });
}

// Guarded so the pure exports above can be imported in node (Vitest) with no DOM present.
if (typeof document !== "undefined" && typeof window !== "undefined") wire();
