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
//   1. THE SNAPSHOT — `lastState`, `lastFt`, `lastSuperData`. One writer (`render`), 84 readers
//      between them. Owned here, as a write-once-per-fetch cell behind an accessor. The contract
//      is the one the code already follows, made explicit and enforceable: exactly one call site
//      may write the cell, and the test below is what enforces it.
//
//      Note what that does NOT claim. `get()` hands back the object itself, not a copy or a frozen
//      view, so a reader can still mutate the snapshot in place. Deep-freezing a case's whole state
//      on every fetch is not free, and the failure this design is actually aimed at is "who
//      replaced this value", which the single-writer rule answers. Reader-side mutation is a
//      separate problem, worth solving separately if it turns out to happen.
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
// WHAT IS ACTUALLY MIGRATED HERE, AND WHAT IS NOT
//
// `activeView` — one writer, fourteen readers — is migrated, end to end. It was chosen because it
// has tier 1's shape at a tenth of tier 1's size, so it exercises the whole mechanism (a single
// permitted writer, a read accessor, a subscriber list) against real call sites rather than a
// worked example.
//
// `lastState` is NOT migrated, and the reason is scope rather than difficulty: it is 43 mechanical
// call-site edits, and putting them in the same change as the mechanism they validate means the
// review cannot separate "is this the right shape" from "did all 43 edits land correctly". It is
// the next change, and this file is what it will be migrated onto.
//
//
// NOT AN ES MODULE, for the same reason as the js/dashboard-*.js helpers: the inline script is a
// classic script and calls into this by bare name. See js/dashboard-escape.js.

// HOW "ONE WRITER" IS ENFORCED: BY A GATE, NOT BY THE CELL.
//
// The first draft of this file made every write pass the writing function's name and threw if it
// did not match a declared owner. That is ceremony at 100% of call sites to catch a mistake at
// none of them — the check can only fire at runtime, in a browser, after the second writer already
// shipped. tests/dashboard/dashboardState.test.ts counts the write call sites in the client source
// instead: a second one fails CI, in the PR that adds it, with no runtime cost and nothing for a
// caller to remember. Same shape as the rest of this repo's invariants — the size ledger, the
// import-cycle list, the route inventory, the STATIC_ASSETS pinning.

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
     * Subscribers run AFTER the value is committed, so a subscriber that reads the cell — which is
     * the normal case, since subscribers exist to re-render from it — sees the new value rather
     * than the one it is replacing.
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

// Published for the inline script. Every read is now a call rather than a bare identifier, which
// is the point: `activeView()` is greppable in a way `activeView` is not, and the writes stop
// looking like reads.
window.DfirState = {
  cell: dfirCell,
  activeView: () => dfirActiveView.get(),
  setActiveView: (view) => dfirActiveView.set(view || null),
  onActiveViewChange: (fn) => dfirActiveView.subscribe(fn),
};
