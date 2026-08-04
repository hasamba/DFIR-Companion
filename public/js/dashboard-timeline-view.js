// Who owns the forensic timeline's view filters (#415, tier 2, last step).
//
// The unit here is the USER ACTION, not the field, and that is the whole design. The first draft of
// tier 2 modelled this layer as ten setters over ten bindings; that was wrong twice over and both
// mistakes are worth keeping written down, because the shape below is what they argue for.
//
//   1. THE FIELDS ARE NOT THE ACTIONS. "Reveal this event" resets six filters, picks a page and
//      repaints. Expressed as setters, that is six writes whose intermediate states are visible
//      states nobody wants — and the code really did paint them: filterTimelineToEventIds() renders
//      TWICE before its id filter is even set, so the first two paints show the filter it just
//      cleared rather than the one it is applying.
//   2. THE FILTER IS NOT ALL IN JAVASCRIPT. Severity has no binding at all: it lives in the
//      `.sev-filter` checkboxes and is read from the DOM at render time. A design that models the
//      filter as "these ten variables" cannot be right when part of the filter is a checkbox, so
//      setSeverities() owns the boxes rather than reading them.
//
//
// ONE COMMIT, ONE REDRAW, PER ACTION
//
// Each action below writes everything it implies and then refreshes ONCE. That is a deliberate
// behaviour change and the measurement is what justifies it: today `setExcludeTerms` and
// `applySearch` each call render() at their own site and again through renderFalsePositives()'s
// tail, so one debounced keystroke is two full renders — two `/collection-plan` fetches and four
// whole-page section sweeps, for the same final state. The intermediate paint is not a feature.
//
// WHAT DOES NOT COLLAPSE. The refresh SET differs per action and is declared per action, because
// the measurement says so: setExcludeTerms refreshes the timeline, the super-timeline and False
// Positives; toggleSource refreshes only the timeline; setTimeWindow additionally reaches Kill
// Chain and Attack Phases. A single fixed redraw cannot express that, which is the second thing the
// first draft got wrong — and the reason DfirScope and DfirSelection publish no subscription
// either.
//
//
// THE REFRESH HANDLERS ARE INJECTED, ONCE
//
// This module knows WHICH panels an action must refresh; it does not know HOW to paint them. The
// page registers the handlers at wire-up via wire(), and every action calls them.
//
// That is not indirection for its own sake — it is what makes these actions testable at all. Every
// audit of this tier so far has landed on the same gap: the suites tested an owner's arithmetic and
// never the renderer interaction, so two visible regressions sat behind a green suite. With the
// handlers injected, a test registers spies, calls revealEvent(), and asserts exactly which panels
// were refreshed and how many times — which is precisely the thing that was previously unobservable
// outside a browser.
//
//
// resetForCase() IS NOT clearFilters(), and the difference is load-bearing. Connecting to a case
// deliberately does NOT reset the event-id filter, does NOT re-check the severity boxes and does
// NOT clear the analyst's exclude terms; the "clear filters" action does all three. Routing both
// through one helper would start wiping persisted exclude terms on every case connect. Two
// operations, two refresh sets, both spelled out.
//
// NOT AN ES MODULE, and an IIFE, for the reasons js/dashboard-state.js sets out.
(function () {
  const cell = window.DfirState.cell;

  const search = cell("");
  const exclude = cell(Object.freeze([]));
  const from = cell(null);
  const to = cell(null);
  const starredOnly = cell(false);
  const eventIds = cell(null); // Set of ids, or null for "no id filter"
  const eventIdsLabel = cell("");
  // Three separate cells, not one object: the lenses are independent, they are read as bare
  // numbers at 21 comparison sites (`corrobTimeline > 1`), and they refresh different panels.
  const corrobTimeline = cell(1);
  const corrobIocs = cell(1);
  const corrobFindings = cell(1);
  const corrobCells = { timeline: corrobTimeline, iocs: corrobIocs, findings: corrobFindings };

  /**
   * What the page does when an action says a panel is stale.
   *
   * Defaults are no-ops so the module is usable — and testable — before anything is wired, and so a
   * handler the page has not registered fails quietly rather than throwing mid-action.
   */
  const noop = () => {};
  let paint = {
    timeline: noop, // renderTimelineEvents(lastFt())
    all: noop, // render(lastState()) — the whole page
    superTimeline: noop, // loadSuperTimeline()
    falsePositives: noop, // renderFalsePositives(fpMarkers)
    derivedViews: noop, // refreshFilteredViews(): Kill Chain, Attack Phases, the graphs
    excludeChips: noop, // renderExcludeChips()
    searchBox: noop, // the search input's own clear button + open state
    timeInputs: noop, // #filterFrom / #filterTo and the Clear button
    severityBoxes: noop, // the .sev-filter checkboxes
    starButton: noop, // #evStarFilterBtn label + active class
  };

  /** Run a declared refresh set, each handler at most once. */
  function refresh(...names) {
    for (const name of [...new Set(names)]) (paint[name] || noop)();
  }

  window.DfirTimelineView = {
    /** Register the page's painters. Called once, at wire-up. */
    wire(handlers) {
      paint = { ...paint, ...(handlers || {}) };
    },

    /**
     * Restore persisted state at page bootstrap. Commits, refreshes NOTHING.
     *
     * Restoring what the analyst left behind is not a user action: it runs while the script is still
     * parsing, before any panel exists, and the first render() paints the result anyway. Routing it
     * through setExcludeTerms() would refresh three panels that are not on the page yet — which is
     * precisely why the original code assigned the binding directly and did not call its own setter.
     */
    hydrate(state) {
      const st = state || {};
      if (Array.isArray(st.excludeTerms)) exclude.set(Object.freeze([...st.excludeTerms]));
      if (st.corroboration) {
        for (const which of ["timeline", "iocs", "findings"]) {
          if (st.corroboration[which] != null) corrobCells[which].set(Number(st.corroboration[which]) || 1);
        }
      }
    },

    // ── reads ──────────────────────────────────────────────────────────────────────────────────
    search: () => search.get(),
    excludeTerms: () => exclude.get(),
    from: () => from.get(),
    to: () => to.get(),
    starredOnly: () => starredOnly.get(),
    /** The id filter, or null. Membership only — the Set never escapes. */
    hasEventId: (id) => {
      const ids = eventIds.get();
      return ids ? ids.has(String(id)) : false;
    },
    eventIdFilterActive: () => eventIds.get() !== null,
    eventIdCount: () => (eventIds.get() ? eventIds.get().size : 0),
    eventIdLabel: () => eventIdsLabel.get(),
    corrobTimeline: () => corrobTimeline.get(),
    corrobIocs: () => corrobIocs.get(),
    corrobFindings: () => corrobFindings.get(),

    // ── actions ────────────────────────────────────────────────────────────────────────────────
    /**
     * The analyst typed in the search box.
     *
     * ONE redraw where there were two: render() here, and render() again through False Positives'
     * tail. Same final state, half the work, no intermediate paint.
     */
    setSearch(term) {
      search.set(String(term || "").trim().toLowerCase());
      refresh("searchBox", "all", "superTimeline", "falsePositives");
    },

    /** Exclude terms (#216). Persisted by the caller — this owns the value, not the storage. */
    setExcludeTerms(terms) {
      exclude.set(Object.freeze([...(terms || [])]));
      refresh("excludeChips", "all", "superTimeline", "falsePositives");
    },

    /**
     * The timeline's time window — the from/to inputs, the swimlane brush, a dwell window.
     *
     * Reaches further than the other filters: Kill Chain and Attack Phases are derived from the
     * same filtered timeline, so they go stale with it.
     */
    setTimeWindow(fromIso, toIso) {
      from.set(fromIso || null);
      to.set(toIso || null);
      refresh("timeInputs", "timeline", "derivedViews", "superTimeline");
    },

    /** The ★ Starred toggle. Timeline-local, deliberately — it is a list facet. */
    showOnlyStarred(on) {
      starredOnly.set(Boolean(on));
      refresh("starButton", "timeline");
    },

    /**
     * One of the three corroboration lenses (#35): "timeline", "iocs" or "findings".
     *
     * Their refresh sets differ, which is why this is one action with a branch rather than three
     * setters: the timeline lens repaints the timeline (and rescopes the Sources menu with it),
     * while the IOC and finding lenses reach the whole page.
     */
    setCorroboration(which, value) {
      const c = corrobCells[which];
      if (!c) return 0;
      const n = Number(value) || 1;
      c.set(n);
      refresh(which === "timeline" ? "timeline" : "all");
      return n;
    },

    /**
     * Show exactly these events — an anomaly bucket, a session's rows.
     *
     * The reset happens as part of the action rather than through clearFilters(), so the id filter
     * is in place BEFORE anything paints. Today the reset renders twice on its own and only a third
     * paint applies the ids; here there is one.
     */
    filterToEventIds(ids, label) {
      const list = (ids || []).map(String).filter(Boolean);
      if (!list.length) return 0;
      clearFilterState();
      eventIds.set(new Set(list));
      eventIdsLabel.set(label || "");
      refresh("severityBoxes", "starButton", "searchBox", "timeInputs", "excludeChips", "timeline");
      return list.length;
    },

    clearEventIds() {
      eventIds.set(null);
      eventIdsLabel.set("");
      refresh("timeline");
    },

    /**
     * The analyst's "clear filters" gesture, and the unhide step of revealing an event.
     *
     * Clears the exclude terms too — which is why case connect must NOT come through here.
     */
    clearFilters() {
      clearFilterState();
      eventIds.set(null);
      eventIdsLabel.set("");
      refresh(
        "severityBoxes",
        "starButton",
        "searchBox",
        "timeInputs",
        "excludeChips",
        "all",
        "superTimeline",
        "falsePositives",
      );
    },

    /**
     * Connecting to a case. NOT clearFilters(): the event-id filter, the severity boxes and the
     * analyst's exclude terms are all deliberately left alone, exactly as today.
     *
     * No refresh — proceedConnect paints everything itself, in its own order.
     */
    resetForCase() {
      search.set("");
      from.set(null);
      to.set(null);
      starredOnly.set(false);
    },
  };

  /** The fields "clear filters" zeroes. Shared by clearFilters() and filterToEventIds(). */
  function clearFilterState() {
    search.set("");
    exclude.set(Object.freeze([]));
    from.set(null);
    to.set(null);
    starredOnly.set(false);
  }
})();
