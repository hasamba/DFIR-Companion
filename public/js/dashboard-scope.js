// Who owns the investigation scope window (#415, tier 2).
//
// `scope` is the first tier-2 cell to move, and it moves FIRST because it is the one piece of
// tier-2 state that is not really "view state" at all: it is server-persisted forensic state, with
// a store (companion/src/analysis/scope.ts), a REST pair, and a websocket broadcast behind it.
// That is also why it does not belong to the timeline-view owner that the rest of tier 2 is headed
// for — see "THREE PATHS" below, which is the whole argument.
//
//
// WHAT THE MEASUREMENT SAYS
//
// Resolved through a real lexical scope chain rather than by grepping the word — which matters
// here, because three functions declare a LOCAL `scope` that has nothing to do with this one
// (dashboard.html:11524 an HTML string, 13586 an IOC count label, 11732 a chain label), and
// `p.scope` / `m.scope` / `data-scope` / `TAGGER_SCOPE` are unrelated besides:
//
//   33  occurrences of the identifier `scope` in the inline script
//   26    resolve to the top-level binding
//    7    resolve to a local shadow          -- a grep would have counted these as writers
//    3  writes, ALL whole-value replacement
//    0  property mutations (`scope.start = x`)  -- nothing mutates it in place
//    4  reader functions besides the writers: inScope, projectScope, renderScopeInfo, and the
//       writers reading it back for their own status text
//
// The published census for this issue listed renderHostRanking as a fourth writer. It is not; that
// was the shadow at 11524. Three writers, and they are the three below.
//
//
// THREE PATHS, AND WHY A GENERIC setScope() CANNOT EXPRESS THEM
//
// The three writers do NOT differ by accident, and flattening them into one setter with a redraw
// flag was the first design's mistake:
//
//   loadScope (3724)        commit -> push into #scopeStart/#scopeEnd -> repaint #scopeInfo.
//                           NO redraw. The case is still loading; render() comes separately.
//   scope_changed (15395)   THE SAME THREE STEPS, then render(DfirState.lastState()).
//                           Another analyst (or this one, in another tab) moved the window.
//   applyScope (9022)       commit -> repaint #scopeInfo, and deliberately does NOT touch the two
//                           inputs, because it READ the window out of them. Then its own refresh:
//                           a /state refetch, twenty derived panels, the super-timeline.
//
// So there are two operations, not one and not three: `receive` (the server told us a window; push
// it into the controls) and `confirm` (the analyst set the controls; the server accepted). The
// redraw is NOT part of either, because the redraw is exactly what the three paths disagree about,
// and hiding a disagreement behind a boolean is how the first design broke behaviour.
//
// A CONSEQUENCE WORTH STATING: because the server broadcasts to every subscriber of a case with no
// sender exclusion (companion/src/live/hub.ts:67-80), applyScope receives its own echo, so applying
// a scope renders twice and the echo overwrites the analyst's typed input with the server's
// normalised ISO form. That is today's behaviour and this module preserves it rather than fixing
// it; it is written up on the issue as found-not-fixed.
//
//
// WHY THE PROJECTION LIVES HERE TOO
//
// projectScope() moved in with the value rather than staying behind, for three reasons. It is a
// pure function of (window, state) — no DOM, no fetch. It is what the window MEANS, so leaving it
// outside would make DfirScope an owner of a value whose interpretation someone else holds. And it
// leaves the binding with zero readers outside this file, which is the difference between "behind
// an accessor" and "encapsulated".
//
// The third reason is the useful one: companion/src/analysis/scopeProject.ts is the SAME RULE,
// written a second time, and the inline copy's own comment calls itself "the client-side mirror of
// the server's projectScope()". Nothing checked that the mirror still matched. It could not be
// checked while the function was trapped in an inline script; now it can, and the parity suite does
// exactly that against the real server module — the same correction made earlier in this issue for
// the false-positive rule, which had drifted the same way.
//
// inScope() did NOT get published. Its only two call sites are inside projectScope, so it is
// private here; `contains` is the published form, and it exists because the parity suite needs to
// exercise the undated-timestamp rule directly.
//
//
// THE VALUE IS FROZEN, WHICH TIER 1'S IS NOT
//
// dashboard-state.js hands back the live snapshot object and argues that deep-freezing a whole case
// state on every fetch is not free, so the single-writer rule carries the weight instead. That
// argument does not transfer, and the difference is worth being explicit about: this is a two-field
// object written three times, so freezing it costs nothing measurable. The hazard tier 1 documented
// and accepted — "a reader could mutate the value in place" — is therefore just closed here.
//
// It closes it at runtime only in strict mode; a classic script is not strict, so a stray
// `DfirScope.get().start = x` silently NO-OPS rather than throwing — the caller's intent vanishes,
// every later read returns the old value, and CI stays green. That is strictly worse than the throw
// a strict realm would have raised, so freezing alone is not the guarantee.
//
// The other half is a gate: getterMutations() in tests/helpers/dashboardAst.ts, asserted by "never
// writes through get() to the window it returned". It catches the direct form, the aliased form
// (`const w = DfirScope.get(); w.start = x`) and the window-rooted spelling. Freezing stops the
// state being corrupted; the gate stops the code being written. Both are needed — an earlier draft
// of this comment promised the gate before it existed, which review caught.
//
//
// NO onScopeChange. The cell has subscribe() and this module deliberately does not publish it.
// Subscription is a single fixed reaction to a write, and the three paths above are three DIFFERENT
// reactions — a subscriber would have to be the union of them, which is the generic redraw this
// design exists to avoid. The machinery stays unused here on purpose.
//
// NOT AN ES MODULE, and an IIFE for the reason dashboard-state.js explains at length: a top-level
// `const` in a classic script joins the shared global LEXICAL environment, so it is writable by
// name from any later script even though it never appears on the global object. Nothing escapes
// this closure but window.DfirScope, and a test asserts that by attempting the bypass for real.
(function () {
  // Built with DfirState.cell, which dashboard-state.js publishes for exactly this: "cell is
  // exposed because the next migrations need to build their own cells". That is the only load-time
  // dependency this file has, so its <script> tag must follow dashboard-state.js — everything else
  // it calls (isoToUtcInput) resolves at call time, long after every tag has run.
  const dfirScope = window.DfirState.cell(Object.freeze({ start: null, end: null }));

  /**
   * Commit a window. The single point every write goes through, so the gate has one thing to count.
   *
   * `|| null` normalises the three call sites' two spellings into one. loadScope and applyScope
   * already wrote `s.start || null`; the websocket branch wrote `msg.start ?? null`, which differs
   * only for an empty string — and the server's norm() (companion/src/routes/findings.ts:353-358)
   * turns "" into null before it can ever be sent, so the two are the same on real traffic.
   */
  function commit(start, end) {
    return dfirScope.set(Object.freeze({ start: start || null, end: end || null }));
  }

  /** No window set — every event is in scope. Was `!scope.start && !scope.end`, written four times. */
  function isEmpty() {
    const s = dfirScope.get();
    return !s.start && !s.end;
  }

  /**
   * Is this timestamp inside the window?
   *
   * "Can't prove it's out of scope" → keep it, which is why an unparseable timestamp returns true.
   * That rule is load-bearing for undated events and is mirrored on the server in
   * companion/src/analysis/scope.ts:22-29.
   */
  function contains(ts) {
    const s = dfirScope.get();
    if (!s.start && !s.end) return true;
    const t = Date.parse(ts);
    if (isNaN(t)) return true;
    if (s.start && t < Date.parse(s.start)) return false;
    if (s.end && t > Date.parse(s.end)) return false;
    return true;
  }

  /**
   * Deterministic scope projection — the client-side mirror of the server's projectScope().
   *
   * Drops out-of-scope events AND the findings/IOCs/MITRE backed ONLY by them, so the dashboard is
   * scope-consistent instantly, without waiting on (or depending on) AI re-synthesis.
   * "No links → can't prove out of scope → keep".
   *
   * The `|| []` guards are the one intended difference from the server's copy: the server owns the
   * type and can index straight into it, this one is handed parsed JSON. On well-formed input the
   * two produce identical output, and the parity suite pins that.
   */
  function project(state) {
    if (isEmpty()) return state;
    const events = state.forensicTimeline || [];
    const forensicTimeline = events.filter((e) => contains(e.timestamp));

    const backedIn = new Set(), backedOut = new Set();
    for (const e of events) {
      const tgt = contains(e.timestamp) ? backedIn : backedOut;
      for (const fid of (e.relatedFindingIds || [])) tgt.add(fid);
    }
    const findings = (state.findings || []).filter((f) => backedIn.has(f.id) || !backedOut.has(f.id));
    const surviving = new Set(findings.map((f) => f.id));

    const citedBySurviving = new Set(), citedByAny = new Set();
    for (const f of (state.findings || [])) for (const iid of (f.relatedIocs || [])) {
      citedByAny.add(iid);
      if (surviving.has(f.id)) citedBySurviving.add(iid);
    }
    const iocs = (state.iocs || []).filter((i) => citedBySurviving.has(i.id) || !citedByAny.has(i.id));

    const mitreTechniques = (state.mitreTechniques || [])
      .map((t) => ({ ...t, findingIds: (t.findingIds || []).filter((id) => surviving.has(id)) }))
      .filter((t, idx) => t.findingIds.length > 0 || (state.mitreTechniques[idx].findingIds || []).length === 0);

    return { ...state, forensicTimeline, findings, iocs, mitreTechniques };
  }

  /** The #scopeInfo chip. Was renderScopeInfo(), whose three call sites were the three writers. */
  function renderInfo() {
    const el = document.getElementById("scopeInfo");
    const s = dfirScope.get();
    const utc = (iso) => isoToUtcInput(iso).replace("T", " ") + " UTC";
    el.textContent = (s.start || s.end)
      ? `active: ${s.start ? utc(s.start) : "−∞"} → ${s.end ? utc(s.end) : "now"}`
      : "none (all events)";
    el.style.color = (s.start || s.end) ? "#ffd93b" : "#9aa4b2";
  }

  window.DfirScope = {
    /**
     * The window, frozen. Read it at the point of use — do not stash it across anything that can
     * write, for the reason dashboard-state.js gives about cached snapshots and the gate enforces.
     */
    get: () => dfirScope.get(),
    isEmpty,
    contains,
    project,

    /**
     * A window arrived FROM the server — the case-load GET, or another client's change over the
     * websocket. Commit it and push it into the two controls, which are a sink on this path.
     *
     * Does not redraw. loadScope never did, and the websocket branch does its own render() straight
     * after; that difference between the two callers is real and stays visible at the call sites.
     */
    receive(start, end) {
      commit(start, end);
      document.getElementById("scopeStart").value = isoToUtcInput(dfirScope.get().start);
      document.getElementById("scopeEnd").value = isoToUtcInput(dfirScope.get().end);
      renderInfo();
    },

    /**
     * The server accepted a window the analyst typed. Commit and repaint the chip only — the two
     * controls are the SOURCE on this path, so writing them back is not this operation's business.
     * (The websocket echo of this same change does write them, with the server's normalised form.)
     */
    confirm(start, end) {
      commit(start, end);
      renderInfo();
    },
  };
})();
