// The dashboard's search, exclude and relevance predicates (#415).
//
// NOT AN ES MODULE, AND NOT DEFERRED. See js/dashboard-escape.js for the whole argument; the
// short form is that dashboard.html's inline script calls these by bare name at 427 sites, one of
// them while the page is still parsing, so the declarations have to be real globals that exist
// before <script nonce> at line 6538 runs.
//
// Four families of "does this row match the box" -- events, IOCs, findings and false-positive
// marks -- plus the time-range test, the low-signal heuristic and the origin facets. Every one is
// a pure function of the row and the query, which is why they could move ahead of the 791
// functions that are entangled with the shared globals (see docs/adr/0001-dashboard-state.md).
//
// realSourceCount() is the shared corroboration unit and lives here rather than in
// dashboard-text.js because isLowSignalEvent() is its only caller-of-consequence: it drops the
// "unknown source" placeholder AND dedups, so a repeated source name cannot fake corroboration.

// Count of DISTINCT real tool sources backing an item (drops the "unknown source" placeholder; dedups
// so a repeated source name can't inflate the count), the unit the corroboration lens counts. When a
// `hidden` set is passed, sources unchecked in the Sources filter are excluded — so the lens counts
// only the tools the analyst is currently looking at (the two filters compose as one question).
// `hidden` is anything with a `.has()` — a Set, or DfirFacets.<facet>.matcher(). Deliberately not
// typed to a Set: the caller hands over a read-only view precisely so this cannot write.
function realSourceCount(sources, hidden) {
  const set = new Set();
  for (const s of (sources || [])) if (s && s !== "unknown source" && !(hidden && hidden.has(s))) set.add(s);
  return set.size;
}

// --- Search/filter helpers (mirror companion/src/analysis/searchFilter.ts) ---------
function _evMatchesSearch(e, q) {
  return (e.description || "").toLowerCase().includes(q) ||
    (e.asset || "").toLowerCase().includes(q) ||
    (e.mitreTechniques || []).some(t => t.toLowerCase().includes(q)) ||
    (e.sources || []).some(s => (s || "").toLowerCase().includes(q));
}

function _iocMatchesSearch(i, q) {
  return (i.value || "").toLowerCase().includes(q) || (i.type || "").toLowerCase().includes(q);
}

function _findingMatchesSearch(f, q) {
  return (f.title || "").toLowerCase().includes(q) ||
    (f.description || "").toLowerCase().includes(q) ||
    (f.mitreTechniques || []).some(t => t.toLowerCase().includes(q));
}

// Exclude filter (#216): true when the item matches ANY exclude term (mirrors
// companion/src/analysis/searchFilter.ts eventMatchesExclude/findingMatchesExclude/iocMatchesExclude).
function _evMatchesExclude(e, terms) { return terms.some(t => t && _evMatchesSearch(e, t.toLowerCase())); }

function _iocMatchesExclude(i, terms) { return terms.some(t => t && _iocMatchesSearch(i, t.toLowerCase())); }

function _findingMatchesExclude(f, terms) { return terms.some(t => t && _findingMatchesSearch(f, t.toLowerCase())); }

// False-positive marker search/exclude (filter-fp-panel): the global filter toolbar already scopes
// the Timeline/Findings/IOCs; mirror that for the False Positives panel so "search an IP" or an
// exclude term narrows it too. Matches against the marker's kind, ref (id/value/title), display
// label, reason and free-text note — there's no per-marker event timestamp, so the time-range
// inputs don't apply here.
function _fpMatchesSearch(m, q) {
  return (m.kind || "").toLowerCase().includes(q) ||
    (m.ref || "").toLowerCase().includes(q) ||
    (m.label || "").toLowerCase().includes(q) ||
    (m.reason || "").toLowerCase().includes(q) ||
    (m.note || "").toLowerCase().includes(q);
}

function _fpMatchesExclude(m, terms) { return terms.some(t => t && _fpMatchesSearch(m, t.toLowerCase())); }

function _evMatchesTimeRange(e, from, to) {
  const ts = e.timestamp; if (!ts) return true;
  const t = Date.parse(ts); if (isNaN(t)) return true;
  if (from) { const f = Date.parse(from); if (!isNaN(f) && t < f) return false; }
  if (to)   { const u = Date.parse(to);   if (!isNaN(u) && t > u) return false; }
  return true;
}

// Same substring match the server's applyFalsePositive uses (companion/src/analysis/falsePositive.ts)
// so a finding hides here under EXACTLY the conditions it will actually be dropped server-side.
//
// BOTH EMPTY-STRING GUARDS BELONG TO THAT MIRRORING (#457), and each covers a different direction
// of the same hazard: the match is two-way substring, and "" is a substring of every string.
//
//   - an empty TITLE would match the first ref in the list, whatever it says -> the finding is
//     hidden here and, until #457, dropped from InvestigationState and the report too.
//   - an empty REF would match every title -> the whole Findings panel empties.
//
// The server guards the second by `.filter(Boolean)` on findingRefs and, since #457, the first by
// an early return. This function has to guard both, because it is handed the ref set already built
// and cannot assume it was filtered. The empty ref is not reachable through the API today —
// POST /cases/:id/false-positive rejects a missing ref with a 400 — but the server defends against
// it anyway for markers loaded from storage, and a mirror that only holds for reachable inputs is
// not the claim the comment above makes.
function isFindingFalsePositive(title, fpTitles) {
  const t = String(title || "").trim().toLowerCase();
  if (!t) return false;
  for (const ref of fpTitles) if (ref && (t === ref || t.includes(ref) || ref.includes(t))) return true;
  return false;
}

// The origin of a forensic event — the specific artifact when known, else the first tool in
// `sources`, else "Unknown". Mirrors the super-timeline's superOriginOf() so "origin" means the
// same thing (and shows the same facet values) in both timelines.
function ftOriginOf(e) { return e.artifactName || (Array.isArray(e.sources) && e.sources[0]) || "Unknown"; }

// Forensic origin filter (mirrors the source filter, but one level more specific — the artifact
// that produced the event, not just the tool): distinct origins across the in-scope timeline.
function originFacets(ft) {
  const set = new Set();
  for (const e of (ft || [])) set.add(ftOriginOf(e));
  return [...set].sort((a, b) => a.localeCompare(b));
}

// Low-relevance row flag (#75, client mirror of companion/src/analysis/eventRelevance.ts's
// scoreEventRelevance): Critical/High severity, a finding link, a structured hash/path/process-chain
// identity, an ATT&CK tag, or 2+ corroborating sources all clear it — what's left is Info-severity
// telemetry with none of those signals, the class of row least likely to matter to the story. A
// display hint only; it does not change what selectSynthesisEvents feeds to synthesis.
function isLowSignalEvent(e) {
  if (e.severity !== "Info") return false;
  if (e.relatedFindingIds && e.relatedFindingIds.length) return false;
  if (e.sha256 || e.md5 || e.path || e.processName || e.parentName || e.chainSignature) return false;
  if (e.mitreTechniques && e.mitreTechniques.length) return false;
  // realSourceCount() is the shared corroboration unit: it drops the "unknown source" placeholder
  // AND dedups, so a repeated source name can't fake corroboration and clear the flag. Called with
  // no `hidden` set on purpose — relevance is a property of the event, not of the analyst's current
  // source filter, so the chip must not appear/disappear as they toggle sources.
  return realSourceCount(e.sources) < 2;
}

function lowSignalChip(e) {
  if (!isLowSignalEvent(e)) return "";
  return `<span class="prev-chip lowsig-chip" title="Info-severity telemetry with no finding link, structured identity, ATT&amp;CK tag, or multi-source corroboration — likely low signal">🐇 low signal</span>`;
}

// Year-clamp (#739): the merge re-anchored this event's GUESSED year onto the case's dominant year.
// Sits under the timestamp, next to the clock-skew note, and says what the source actually carried.
//
// The skew note beside it is a READ-PATH projection the analyst can switch off; this one is
// PERSISTED, which is why it is warning-coloured rather than dim. Silence here is the #739 defect:
// on INC-2026-020 seventeen real 2025 timestamps were rewritten to 2026 with nothing on screen to
// say so, and the adjusted times went on to set the case's scope window.
function yearClampChip(e) {
  if (!e || !e.yearClampedFrom || e.yearClampedFrom === e.timestamp) return "";
  return `<div class="ev-yearclamp" title="This source carries no year of its own, so the import guessed one and the merge re-anchored it onto the case's dominant year. Imported as: ${escAttr(e.yearClampedFrom)}">📅 year adjusted from ${esc(e.yearClampedFrom)}</div>`;
}

// Non-AI finding origins. Two DETERMINISTIC backfill passes run after AI synthesis and mint
// findings of their own, each with a prefixed, idempotent id minted in exactly one place:
//
//   f-auto-  companion/src/analysis/highSeverityFindings.ts — an in-scope Critical/High event
//            synthesis left with no finding, so a graded detection is never silently missed
//   f-gap-   companion/src/analysis/gapDetect.ts            — a window where EVERY source went
//            dark, the classic signature of cleared logs or a stopped collector
//
// These two prefixes identify findings the backfill passes mint — that is NOT the same claim as
// "everything else comes from AI synthesis". A synthesis finding's id is whatever the model
// returned, and it is never canonicalised server-side the way an IOC id is. Since #787 the model
// can no longer INVENT one of these, though: mergeDelta renames a reserved id the case does not
// already hold to `f-model-<original>` before it is stored (renameForgedFindingIds, in
// companion/src/analysis/responseSchema.ts), so a prefix reaching this function is the backfill's
// own work. What the model may still do is UPDATE a finding a backfill really minted, by returning
// its id — both prompts ask for exactly that — and such a row is correctly classified as a
// backfill, because that is what it is. On a noisy import these backfills can outnumber the AI's
// real conclusions, which is what the lens is for. The id is the classifier because it is already
// load-bearing: both generators derive it from their source events precisely so re-synthesis
// REFRESHES a backfill finding instead of duplicating it. That makes it a stable identity, and
// means no new field and no migration.
//
// The two prefixes below are a fourth copy of a list this module cannot import, so
// companion/tests/architecture/deterministicFindingMint.test.ts pins them to the constants the
// server mints from (#758). Without that, a rename server-side would leave these lenses matching
// an id the product no longer produces: the checkbox stops hiding anything, and says so nowhere.
//
// The trailing hyphen is part of each prefix on purpose — without it an AI finding id'd
// "f-automation" would read as a backfill and disappear from the panel.
function isAutoBackfillFinding(f) {
  return !!f && typeof f.id === "string" && f.id.startsWith("f-auto-");
}
function isGapFinding(f) {
  return !!f && typeof f.id === "string" && f.id.startsWith("f-gap-");
}

// The single question render() asks per finding. It exists as its own function rather than two
// inline clauses because render() is a 700-line DOM function with no behavioural test harness:
// as a pure function the four-row truth table is directly testable, and render's only obligation
// is to call it.
function findingPassesOriginLens(f, hideAuto, hideGap) {
  if (hideAuto && isAutoBackfillFinding(f)) return false;
  if (hideGap && isGapFinding(f)) return false;
  return true;
}

// Published for the inline script and the other helper modules. EVERY function this file
// defines is listed: a helper that stays private here but is still called by name from
// dashboard.html is a ReferenceError, which is the mistake #414 shipped and then fixed.
window.DfirFilters = {
  realSourceCount,
  yearClampChip,
  _evMatchesSearch,
  _iocMatchesSearch,
  _findingMatchesSearch,
  _evMatchesExclude,
  _iocMatchesExclude,
  _findingMatchesExclude,
  _fpMatchesSearch,
  _fpMatchesExclude,
  _evMatchesTimeRange,
  isLowSignalEvent,
  lowSignalChip,
  isFindingFalsePositive,
  isAutoBackfillFinding,
  isGapFinding,
  findingPassesOriginLens,
  ftOriginOf,
  originFacets,
};
