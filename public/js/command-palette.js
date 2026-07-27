// Command palette — Ctrl+K / Cmd+K fuzzy launcher for every dashboard action (issue #238).
//
// Loaded in the browser as an ES module (<script type="module" src="/js/command-palette.js">),
// the same arrangement graph-view.js uses. Module scripts run AFTER classic inline scripts, so by
// the time this file executes the inline dashboard script has already published
// window.DfirPaletteConfig — see wire() at the bottom. That ordering is why the config is a global
// the inline script SETS rather than a function it CALLS on us: no load-order handshake to get
// wrong, in either direction.
//
// Division of labour: the inline dashboard script owns the action registry, because it is the only
// code that can see the dashboard's ~778 functions and its `lastState`. This module owns matching,
// ranking and the overlay. The pure half is exported by name so Vitest can drive it in node, where
// there is no DOM — everything below the "browser glue" banner is deliberately thin for that
// reason.

export const CATEGORY_ORDER = ["Navigation", "Actions", "Exports", "Settings", "Case"];

const RECENTS_KEY = "dfir.palette.recents";
const RECENTS_MAX = 5;

// Ranked match of `query` against one string. Tiers, highest first:
//   1000  the whole string is the query        800  some whole word is the query
//    600  some word starts with the query      500  the string starts with the query
//    350-400  substring (earlier hit scores higher)
//    50-300  scattered subsequence ("gtf" → "Go to Findings")
// The tiers do not overlap: the substring floor (400-50) sits above the subsequence ceiling (300),
// so a real substring hit can never be outranked by an incidental letter-scatter. 0 means "no
// match", and the action is dropped rather than shown at the bottom.
export function fuzzyScore(query, text) {
  const q = String(query || "").toLowerCase();
  const t = String(text || "").toLowerCase();
  if (!q) return 1;
  if (!t) return 0;
  if (q === t) return 1000;
  const words = t.split(/\s+/).filter(Boolean);
  if (words.some((w) => w === q)) return 800;
  if (words.some((w) => w.startsWith(q))) return 600;
  if (t.startsWith(q)) return 500;
  const at = t.indexOf(q);
  if (at >= 0) return 400 - Math.min(at, 50);
  let qi = 0;
  let run = 0;
  let best = 0;
  let cur = 0;
  for (let ti = 0; ti < t.length && qi < q.length; ti++) {
    if (t[ti] === q[qi]) {
      qi++;
      run++;                       // consecutive hits are worth more than scattered ones
      cur += 10 + run * 5;
      if (cur > best) best = cur;
    } else {
      run = 0;
      cur = Math.max(0, cur - 1);
    }
  }
  if (qi < q.length) return 0;     // not every query character appeared, in order
  return Math.min(300, Math.max(50, best));
}

// ">exp csv" → filter to Exports, then search "csv" within it.
//
// The category is matched by PREFIX, so the filter engages while you are still typing it: ">n",
// ">nav" and ">navigation" all mean Navigation. Matching only the exact full word (as the first
// cut of this feature did) means every keystroke up to the last one shows an empty list, which
// reads as "the palette is broken".
//
// A bare ">" lists everything, and an unrecognised or ambiguous prefix degrades to a plain search
// of the text after the ">" — a typo then yields "no results", never a silently wrong filter.
export function parseQuery(raw) {
  const s = String(raw || "").trim();
  if (!s.startsWith(">")) return { category: null, term: s };
  const rest = s.slice(1).trimStart();
  const sp = rest.indexOf(" ");
  const head = sp < 0 ? rest : rest.slice(0, sp);
  const tail = sp < 0 ? "" : rest.slice(sp + 1).trim();
  if (!head) return { category: null, term: tail };
  const lower = head.toLowerCase();
  const exact = CATEGORY_ORDER.find((c) => c.toLowerCase() === lower);
  const hits = exact ? [exact] : CATEGORY_ORDER.filter((c) => c.toLowerCase().startsWith(lower));
  if (hits.length === 1) return { category: hits[0], term: tail };
  return { category: null, term: rest };
}

// Keywords score at 0.9× the label, so a label hit always beats a keyword hit of the same tier
// while still ranking above every weaker tier.
export function scoreAction(term, action) {
  if (!term) return 1;
  const label = fuzzyScore(term, action.label);
  const kw = (action.keywords || []).reduce((m, k) => Math.max(m, fuzzyScore(term, k)), 0);
  return Math.max(label, kw * 0.9);
}

// An action with no predicate is always offered. A predicate that THROWS cannot vouch for its
// action, so that action is hidden: one registry bug must not take the whole palette down with it.
export function isAvailable(action, state) {
  if (typeof action.available !== "function") return true;
  try {
    return Boolean(action.available(state));
  } catch {
    return false;
  }
}

// Recency is a TIE-BREAKER, never a score bonus. On an empty query every action scores 1, so the
// recently-run ones float to the top; but once the analyst types something, a genuine exact match
// can never be pushed below a stale favourite.
export function searchActions(raw, actions, state, recents) {
  const { category, term } = parseQuery(raw);
  const recent = Array.isArray(recents) ? recents : [];
  const rank = (id) => {
    const i = recent.indexOf(id);
    return i < 0 ? Number.MAX_SAFE_INTEGER : i;
  };
  const out = [];
  for (const a of actions || []) {
    if (category && a.category !== category) continue;
    if (!isAvailable(a, state)) continue;
    const score = scoreAction(term, a);
    if (score > 0) out.push({ action: a, score });
  }
  out.sort(
    (x, y) =>
      y.score - x.score ||
      rank(x.action.id) - rank(y.action.id) ||
      CATEGORY_ORDER.indexOf(x.action.category) - CATEGORY_ORDER.indexOf(y.action.category) ||
      x.action.label.localeCompare(y.action.label),
  );
  return out;
}

// Most-recent-first, de-duplicated, capped. Returns a new array; never mutates the input.
export function bumpRecent(recents, id) {
  const rest = (Array.isArray(recents) ? recents : []).filter((x) => x !== id);
  return [id, ...rest].slice(0, RECENTS_MAX);
}

// =================================================================================================
// Browser glue. Everything worth testing lives above this line.
// =================================================================================================

function loadRecents() {
  try {
    const v = JSON.parse(localStorage.getItem(RECENTS_KEY));
    return Array.isArray(v) ? v : [];
  } catch {
    return [];
  }
}

function saveRecents(r) {
  try {
    localStorage.setItem(RECENTS_KEY, JSON.stringify(r));
  } catch {
    /* private-browsing / quota — recents are a nicety, never a hard failure */
  }
}

const ESCAPES = { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" };
function esc(s) {
  return String(s).replace(/[&<>"]/g, (c) => ESCAPES[c]);
}

function createPalette(config) {
  const overlay = document.getElementById("cmdpOverlay");
  const input = document.getElementById("cmdpInput");
  const list = document.getElementById("cmdpList");
  const empty = document.getElementById("cmdpEmpty");
  if (!overlay || !input || !list || !empty) return null;

  let results = [];
  let sel = 0;
  let recents = loadRecents();

  const isOpen = () => overlay.classList.contains("open");

  function render() {
    empty.style.display = results.length ? "none" : "";
    list.innerHTML = results
      .map(
        (r, i) =>
          `<div class="cmdp-row${i === sel ? " sel" : ""}" data-i="${i}" role="option" aria-selected="${i === sel}">` +
          `<span class="cmdp-label">${esc(r.action.label)}</span>` +
          `<span class="cmdp-cat">${esc(r.action.category)}</span>` +
          `</div>`,
      )
      .join("");
    const cur = list.querySelector(".cmdp-row.sel");
    if (cur) cur.scrollIntoView({ block: "nearest" });
  }

  // The registry and the case state are pulled fresh on every keystroke rather than cached at
  // registration time. #pushSelect is populated asynchronously from the integrations config, and
  // toolbar buttons appear and disappear as the case loads — a snapshot would go stale within
  // seconds of the dashboard starting up.
  function refresh() {
    const actions = config.actions ? config.actions() : [];
    const state = config.state ? config.state() : null;
    results = searchActions(input.value, actions, state, recents);
    sel = 0;
    render();
  }

  function move(d) {
    if (!results.length) return;
    sel = (sel + d + results.length) % results.length;
    render();
  }

  function close() {
    overlay.classList.remove("open");
    input.blur();
  }

  function open() {
    if (isOpen()) return;
    recents = loadRecents();
    input.value = "";
    overlay.classList.add("open");
    refresh();
    input.focus();
  }

  function run(i) {
    const hit = results[i];
    if (!hit) return;
    close();                                    // close first, so an action that opens its own modal wins the focus
    recents = bumpRecent(recents, hit.action.id);
    saveRecents(recents);
    try {
      hit.action.run();
    } catch (err) {
      console.error("[command-palette] action failed:", hit.action.id, err);
    }
  }

  input.addEventListener("input", refresh);
  input.addEventListener("keydown", (e) => {
    if (e.key === "ArrowDown") { e.preventDefault(); move(1); }
    else if (e.key === "ArrowUp") { e.preventDefault(); move(-1); }
    else if (e.key === "Enter") { e.preventDefault(); run(sel); }
    else if (e.key === "Escape") { e.preventDefault(); close(); }
  });
  list.addEventListener("click", (e) => {
    const row = e.target.closest(".cmdp-row");
    if (row) run(Number(row.dataset.i));
  });
  overlay.addEventListener("click", (e) => { if (e.target === overlay) close(); });

  return { open, close, isOpen };
}

function wire() {
  const config = window.DfirPaletteConfig;
  if (!config) return;
  const palette = createPalette(config);
  if (!palette) return;
  window.DfirPalette = palette;

  // Ctrl+K / Cmd+K, guarded like the dashboard's other global key handlers. Ctrl+P was the shortcut
  // issue #238 asked for, but it is the browser's Print binding on every platform and Cmd+P is
  // load-bearing muscle memory on macOS; Ctrl+K is the modern convention (Linear, Slack, GitHub)
  // and collides with nothing here.
  //
  // Deliberately NOT skipped while an input is focused: unlike the vim-style j/k handler, a
  // modifier chord cannot be confused with typing, and being able to jump straight from the search
  // box to the palette is the point. The unlock gate is the one exception — nothing should be
  // reachable while the case is still sealed behind its password.
  document.addEventListener("keydown", (e) => {
    if (e.key !== "k" && e.key !== "K") return;
    if (!(e.ctrlKey || e.metaKey) || e.altKey) return;
    const lock = document.getElementById("caseUnlockOverlay");
    if (lock && lock.classList.contains("open")) return;
    e.preventDefault();
    if (palette.isOpen()) palette.close();
    else palette.open();
  });
}

// Guarded so the pure exports above can be imported in node (Vitest) with no DOM present.
if (typeof document !== "undefined" && typeof window !== "undefined") wire();
