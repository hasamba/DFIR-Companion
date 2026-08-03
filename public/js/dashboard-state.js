// Who owns dashboard state (#415).
//
// This file is the answer to the question that blocks the rest of the decomposition. #414 moved
// one panel's renderers out; #415 moved the other 95 functions that reference no shared state.
// What is left is 807 functions sitting in one closure over 422 top-level bindings, and every one
// of them is blocked on the same question: move a function that reads `lastState` and you have to
// decide who owns `lastState` first. That is a design decision, not a refactor.
//
//
// WHAT THE MEASUREMENT SAYS
//
// The 422 bindings are not 422 pieces of shared state. Counting readers and writers per binding
// across the whole inline script:
//
//   422  top-level bindings
//   145  never written after their declaration        -- tables and constants, not state
//   277  written somewhere
//   231    of those read by 5 functions or fewer      -- feature-local, sharing a scope by accident
//    11    read by more than 10 functions             -- the actual shared surface
//     6  writers on the most-written binding in the file (selectedEvents)
//     1  writer on lastState, which 43 functions read: `render`
//     1  writer on lastFt, which 29 functions read:    `render`
//
// That last pair is the whole shape of the problem, and it is much better than it looks. The two
// hottest bindings in the file are not contended mutable state at all — they are a cache of the
// last server response, written in exactly one place and read everywhere. Nothing arbitrates
// between writers because there is only one writer.
//
//
// THE DECISION: THREE TIERS, BY MEASURED FAN-OUT
//
//   1. THE SNAPSHOT — `lastState`, `lastFt`, `lastSuperData`. 84 readers between them and one
//      writer EACH: `render` for the first two, `renderSuperTimeline` for the third. (An earlier
//      draft of this paragraph said `render` wrote all three. It does not, and the difference
//      matters — they are three cells with three owners, not one cell with three names.) Owned
//      here, as a write-once-per-fetch cell behind an accessor. The contract is the one the code
//      already followed, made explicit and enforceable: one call site may write each cell, and the
//      tests below are what enforce it. MIGRATED — see the bottom of this comment.
//
//      Note what that does NOT claim. `get()` hands back the object itself, not a copy or a frozen
//      view, so a reader could mutate the snapshot in place. Deep-freezing a case's whole state on
//      every fetch is not free, and the failure this design is aimed at is "who replaced this
//      value", which the single-writer rule answers.
//
//      That was written as a caveat before the migration. It is now a measured fact: across all
//      three cells there is not one in-place mutation in the inline script — no `lastState.x = y`,
//      no `lastFt.push(...)`, no `.sort()`. Every change goes through whole-value replacement at
//      one of the three writes. So handing back the live object is safe TODAY, and that is the
//      property to re-check before anything starts mutating a snapshot rather than replacing it.
//
//   2. THE SELECTION — the filter and selection cells that genuinely cross features: filterFrom,
//      filterTo, searchTerm, excludeTerms, scope, selectedEvents/Iocs/Findings, starredEvents,
//      hiddenSources/Origins/Hosts, activeView. Roughly fifteen bindings, 4-6 writers and 6-13
//      readers each. Owned here too, but as cells with change notification, because a write has to
//      make other panels re-render and today that is done by each writer remembering to call the
//      right render function.
//
//   3. EVERYTHING ELSE — the 231 bindings read by five functions or fewer. NOT owned here. They
//      are feature-local variables that look global because the whole page shares one scope; they
//      move into their feature's module as `let` at module scope and never become anyone's API.
//
// The tiers are drawn by measurement rather than by taste, which matters because the obvious
// alternative — one store for all 408 — is what the measurement argues against.
//
//
// WHAT WAS REJECTED, AND WHY
//
//   ONE STORE FOR EVERYTHING. Putting all 277 mutable bindings behind `DfirState` produces a
//   400-key global object: the same shared scope with a longer prefix, and now every feature
//   module depends on one module. It would also mean 231 bindings that only ever had two or three
//   readers acquire a public name, which is the opposite of decomposition.
//
//   A REACTIVE LAYER (signals, or a Proxy that re-renders on write). This buys arbitration between
//   competing writers, and the measurement says there is almost no competition to arbitrate: the
//   most-written binding in a 19,000-line script has six writers, and the two hottest have one
//   each. Against that, a reactive layer costs re-entrancy bugs, a debugger that stops showing you
//   plain values, and — in a page with no build step, hand-served through an exact-path allowlist —
//   a runtime dependency for something a getter does. Wrong trade at this size.
//
//   PER-FEATURE STATE OBJECTS WITH EXPLICIT HAND-OFF, and nothing central. This is right for tier 3
//   and it is exactly what tier 3 says to do. It has no answer for tier 1: `lastState` is read by
//   43 functions across a dozen features, and "hand it off explicitly" means threading the case
//   snapshot through 43 signatures. That is not ownership, it is a parameter list.
//
//
// WHAT IS MIGRATED, AND WHAT IS NEXT
//
// `activeView` came first — one writer, fourteen readers — chosen because it has tier 1's shape at
// a tenth of tier 1's size, so it exercised the whole mechanism against real call sites before
// anything large depended on it.
//
// TIER 1 IS NOW DONE. All three snapshot cells are here and all 155 reader references go through
// the accessors. It landed as its own change, separately from the mechanism, so that a review could
// tell "is this the right shape" apart from "did 155 edits land correctly" — the second question is
// answered by an AST check that no bare identifier survives and by every inline script still
// parsing, neither of which says anything about the first.
//
// WHAT IS LEFT, in order:
//
//   TIER 2, the ~15 selection cells. Harder than tier 1 despite being smaller: 4-6 writers each,
//   so migrating one means deciding which of its writers is the owner, or accepting that some cells
//   have several and the single-writer gate does not apply to them. The subscriber list exists for
//   this tier and is still unused — today every writer re-renders by remembering to call the right
//   function, which is the coupling `onLastStateChange` is meant to replace.
//
//   TIER 3, the 231 feature-local bindings. The bulk of the remaining inline script, and the reason
//   tiers 1 and 2 came first: a function that reads only its own feature's state can move into that
//   feature's module, and until the shared reads went through a door, almost none of them qualified.
//
//
// NOT AN ES MODULE, for the same reason as the js/dashboard-*.js helpers: the inline script is a
// classic script and calls into this by bare name. See js/dashboard-escape.js.

// HOW "ONE WRITER" IS ENFORCED: A CLOSURE, PLUS A GATE ON WHAT ESCAPES IT.
//
// The first draft made every write pass the writing function's name and threw on a mismatch. That
// is ceremony at 100% of call sites to catch a mistake at none of them — the check can only fire
// at runtime, in a browser, after the second writer already shipped. So the rule became a test
// that counts write call sites, the same shape as the rest of this repo's invariants: the size
// ledger, the import-cycle list, the route inventory, the STATIC_ASSETS pinning.
//
// THAT ALONE WAS NOT ENOUGH, and it is worth saying why in full because the hole is not obvious.
// A classic script's top-level `const` does not become a property of the global OBJECT, so it is
// easy to assume it is private. It is not: it goes into the global LEXICAL environment, which
// every other classic script on the page shares. `const dfirActiveView = dfirCell(null)` at top
// level was therefore reachable by name from any later script, and `dfirActiveView.set(x)` wrote
// the cell while the call-site count, which looks for the published setter, stayed at one.
// The invariant this file's whole argument rests on was decorative, and CI would have passed a
// second writer.
//
// Hence the IIFE. Nothing inside escapes except `window.DfirState`, so the only way to write the
// cell is the one the gate counts. The gate then has a second job: assert that the file leaks
// nothing else, because a future edit that hoists a helper back out re-opens exactly this hole.
//
// The IIFE is safe HERE and would not be in the eight js/dashboard-*.js helpers: those exist to
// put 95 names in the global scope for the inline script to call by bare name. This file is called
// only through its namespace, so it has nothing to publish that way.
(function () {
  /**
   * One piece of owned state: a value and whoever wants to hear about changes.
   *
   * Deliberately not a Proxy and not a signal. A cell is a variable you can find the writes to;
   * that is the entire improvement over a top-level `let`, and it is the improvement the
   * measurement above says is needed.
   */
  function dfirCell(initial) {
    let value = initial;
    const subscribers = [];
    return {
      get() {
        return value;
      },
      /**
       * Write the cell, then notify.
       *
       * Subscribers run AFTER the value is committed, so a subscriber that reads the cell — which
       * is the normal case, since subscribers exist to re-render from it — sees the new value
       * rather than the one it is replacing.
       */
      set(next) {
        value = next;
        // Iterate a copy: a subscriber that unsubscribes itself while being notified would
        // otherwise shift the array under the loop and skip the next one.
        for (const fn of [...subscribers]) fn(value);
        return value;
      },
      /** Called on every write. Returns an unsubscribe function. */
      subscribe(fn) {
        subscribers.push(fn);
        return () => {
          const at = subscribers.indexOf(fn);
          if (at >= 0) subscribers.splice(at, 1);
        };
      },
    };
  }

  /**
   * Tier 2 — the currently-applied dashboard view preset (#142), or null for Custom.
   *
   * The first binding migrated off the inline script's shared scope. applyDashboardView() is the
   * only function that has ever written it and remains the only one that may; the fourteen readers
   * all go through DfirState.activeView().
   */
  const dfirActiveView = dfirCell(null);

  /**
   * TIER 1 — THE SNAPSHOT. The cache of what the server last said, and the reason this file exists.
   *
   *   lastState      43 reader functions, written only by render()
   *   lastFt         29 reader functions, written only by render()
   *   lastSuperData  12 reader functions, written only by renderSuperTimeline()
   *
   * 84 readers, three writes. Not contended state — a load-store cell per fetch, which is what
   * made "who owns lastState" answerable at all.
   *
   * NOTHING MUTATES THEM IN PLACE. Checked rather than assumed, across all three: no
   * `lastState.x = y`, no `lastFt.push(...)`, no `.sort()` on any of them. Every change to the
   * snapshot goes through a whole-value replacement at one of the three writes above. That is what
   * makes handing the live object back from get() safe today, and it is the property to re-check
   * before relaxing anything here — the module header's note about get() not freezing describes a
   * hazard that the code does not currently walk into.
   */
  const dfirLastState = dfirCell(null);
  const dfirLastFt = dfirCell([]);
  const dfirLastSuperData = dfirCell(null);

  // The ONLY thing that leaves this closure. Every read is now a call rather than a bare
  // identifier, which is the point: `activeView()` is greppable in a way `activeView` is not, and
  // the writes stop looking like reads.
  //
  // `cell` is exposed because the next migrations need to build their own cells, and it is a
  // factory with no ambient state — handing it out grants nothing over `dfirActiveView`.
  // READ THROUGH THE ACCESSOR AT EVERY SITE. NO CACHED LOCALS. This is the one rule the snapshot
  // migration turns on, and it is not style:
  //
  //   16 of the 84 reader functions CALL THEIR OWN WRITER -- setExcludeTerms, loadTags, loadPins,
  //   patchFindingWorkflow, applyDashboardView and eleven others all reach render() or
  //   renderSuperTimeline(). Reading a bare `let` always saw the current value, so binding
  //   `const s = DfirState.lastState()` at the top of one of those and reading it afterwards would
  //   quietly change behaviour in a third of the readers -- and only on the paths where a refetch
  //   happens mid-function, which is exactly the kind of thing that survives review and testing.
  //
  // So the accessor call IS the migration. It reads noisier than the variable did; that noise is
  // the honest cost of making 84 readers go through one door.
  window.DfirState = {
    cell: dfirCell,
    activeView: () => dfirActiveView.get(),
    setActiveView: (view) => dfirActiveView.set(view || null),
    onActiveViewChange: (fn) => dfirActiveView.subscribe(fn),

    lastState: () => dfirLastState.get(),
    setLastState: (state) => dfirLastState.set(state),
    onLastStateChange: (fn) => dfirLastState.subscribe(fn),

    lastFt: () => dfirLastFt.get(),
    setLastFt: (ft) => dfirLastFt.set(ft),
    onLastFtChange: (fn) => dfirLastFt.subscribe(fn),

    lastSuperData: () => dfirLastSuperData.get(),
    setLastSuperData: (data) => dfirLastSuperData.set(data),
    onLastSuperDataChange: (fn) => dfirLastSuperData.subscribe(fn),
  };
})();
