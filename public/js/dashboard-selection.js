// Who owns what the analyst has selected, and what they have starred (#415, tier 2).
//
// Two owners, not one, and the split is deliberate: DfirSelection is ephemeral view state that dies
// with the page, while DfirStarred is a local cache of server-side tags that loadTags() re-derives
// from the truth. They look alike — both are sets of ids — and that is exactly why merging them
// would be a mistake: a "clear everything" on the selection owner would silently unstar the case.
//
//
// WHAT THE MEASUREMENT SAYS, AND WHY IT CHANGED THE DESIGN
//
// Resolved through a real lexical scope chain over the inline script:
//
//                      reassignments   IN-PLACE MUTATIONS   reader functions
//   selectedEvents           0              11 in 8 fns          21
//   selectedIocs             0               8 in 6 fns          18
//   selectedFindings         0               7 in 5 fns          15
//   starredEvents            2               7 in 4 fns          13
//
// Compare the scope window, which moved first: three whole-value writes and ZERO in-place
// mutations, so putting it behind an accessor was a rename. This is the opposite. Every selection
// Set is mutated in place and never replaced, so "replace-on-write" is a real change of mechanism
// and had to be designed rather than assumed.
//
// THE LOOP IS THE REASON THIS API HAS BULK OPERATIONS. Four of those mutation sites are inside a
// loop:
//
//   - select-all for events / IOCs / findings — `document.querySelectorAll(".ev-row-cb")
//     .forEach(cb => { if (checked) selectedEvents.add(id); else selectedEvents.delete(id); })`
//   - the swimlane rubber-band, which adds every event inside the dragged rectangle.
//
// Turning each of those `.add()` calls into its own replace-on-write commit is O(n) per iteration,
// so O(n^2) for the gesture. That is not a micro-optimisation worry: `tlPageSize` is analyst-
// selectable and 0 means "show every row" (see renderTimelineEvents), so select-all is NOT bounded
// by a page, and neither is the swimlane's lane data. On a real case that is a hung tab, not a slow
// one. So the bulk gestures collect the ids first and commit ONCE, through addAll()/removeAll().
// That is also fewer commits than today, not more.
//
// addAll/removeAll and NOT replace, which is why the selections do not publish a replace() at all.
// Select-all ticks the RENDERED rows and the timeline paginates, so rows ticked on another page
// have to survive the gesture — the per-row `.add()` loop did that for free and `replace()` would
// silently drop them. An operation with no caller that can quietly lose the analyst's selection is
// not worth having on the surface, so it is not on it. DfirStarred keeps replace() because
// deriveStarred() genuinely does rebuild the whole set from the server's tags.
//
//
// NO LIVE SET LEAVES THIS CLOSURE, AND FREEZING IS NOT HOW THAT IS ACHIEVED
//
// Worth stating because the obvious hardening does nothing: `Object.freeze(new Set())` freezes the
// object's own properties, and a Set's contents live in internal slots, so a frozen Set still
// accepts `.add()`. Freezing one would look like protection while providing none — the trap the
// scope window avoids only because a plain `{start, end}` object genuinely does freeze.
//
// So the Set simply never escapes. Reads are `has(id)`, `count()` and `ids()`, and `ids()` hands
// back a frozen ARRAY copy. Those three cover every read form in the page today (24 `.has(`,
// 17 `.size`, 11 `[...set]`), so nothing needs the container itself.
//
//
// NO REFRESH IN HERE. The three selections cost wildly different amounts to repaint — clearing the
// event selection repaints the whole timeline and the swimlane canvas, clearing the finding
// selection is pure in-place class toggling that deliberately preserves scroll and focus. An owner
// that redrew on commit would have to pick one, so refresh stays at the call sites where that
// difference already lives. Same conclusion as js/dashboard-scope.js, reached from the same
// measurement, and the reason neither publishes a change subscription.
//
// NOT AN ES MODULE, and an IIFE, for the reasons js/dashboard-state.js sets out at length.
(function () {
  /**
   * One set of ids, owned: replace-on-write, and the container never escapes.
   *
   * A shared factory rather than four hand-written copies — the replace-on-write discipline is the
   * thing that must not vary between them, and four copies is how one of them quietly keeps a
   * mutation. It is an implementation detail, not a published generic cell: callers only ever see
   * the named surfaces at the bottom of this file.
   */
  function idSet() {
    const cell = window.DfirState.cell(new Set());
    // Every write goes through here, so there is one place where a new Set is built and committed.
    const commit = (next) => cell.set(next);
    return {
      has: (id) => cell.get().has(id),
      count: () => cell.get().size,
      /** A frozen COPY. The live Set is not handed out; see the header. */
      ids: () => Object.freeze([...cell.get()]),
      /**
       * Add or remove one id. `on` omitted means flip, matching classList.toggle — which is the
       * shape the call sites already use, since most of them are driven by a checkbox's checked
       * state and one (the swimlane's click-to-toggle) is a genuine flip.
       */
      toggle(id, on) {
        const current = cell.get();
        const want = on === undefined ? !current.has(id) : Boolean(on);
        if (want === current.has(id)) return current.size; // no commit for a no-op write
        const next = new Set(current);
        if (want) next.add(id);
        else next.delete(id);
        return commit(next).size;
      },
      /** The whole set at once — deriving from the server, and resetting for a new case. ONE commit. */
      replace(ids) {
        return commit(new Set(ids || [])).size;
      },
      /**
       * Union in a batch — select-all, and the swimlane rubber band. ONE commit.
       *
       * NOT `replace()`, and the difference is a behaviour the page already has: select-all ticks
       * the RENDERED rows, and `tlPageSize` paginates, so rows selected on another page must stay
       * selected. Replacing would silently drop them. Union is what the per-row `.add()` loop did.
       */
      addAll(ids) {
        const next = new Set(cell.get());
        for (const id of ids || []) next.add(id);
        return commit(next).size;
      },
      /** The mirror image: un-ticking select-all removed only the rendered rows. ONE commit. */
      removeAll(ids) {
        const next = new Set(cell.get());
        for (const id of ids || []) next.delete(id);
        return commit(next).size;
      },
      clear() {
        return commit(new Set()).size;
      },
    };
  }

  /**
   * What the analyst has ticked, per panel.
   *
   * Three separate sets rather than one keyed by kind, because that is what they are: an event id
   * and a finding id are different namespaces, the bulk bars are three different elements, and the
   * three "clear" gestures already cost three different amounts to repaint.
   */
  const selection = () => {
    // Everything the factory offers EXCEPT replace(): see the header. Spelled out rather than
    // deleted from the factory because DfirStarred does need it.
    const { has, count, ids, toggle, addAll, removeAll, clear } = idSet();
    return { has, count, ids, toggle, addAll, removeAll, clear };
  };

  window.DfirSelection = {
    events: selection(),
    iocs: selection(),
    findings: selection(),
  };

  /**
   * Which events carry the "starred" tag.
   *
   * A CACHE, unlike the selections — the truth is tags.json on the server, and loadTags() calls
   * deriveStarred() to rebuild this from it. toggleStar() flips it optimistically for instant
   * feedback and reverts on failure, which is why `toggle` is here and why the revert re-reads the
   * current set rather than restoring a snapshot it captured beforehand.
   */
  window.DfirStarred = (() => {
    const set = idSet();
    return {
      has: set.has,
      count: set.count,
      ids: set.ids,
      /** Optimistic flip, and its revert. */
      toggle: (id, on) => set.toggle(id, on),
      /** Rebuild from the server's tags — deriveStarred's one commit at the end of its loop. */
      replace: (ids) => set.replace(ids),
    };
  })();
})();
