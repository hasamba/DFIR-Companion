// Who owns the facet filters — which sources, origins, hosts and IOC types are unchecked (#415).
//
// The first piece of the timeline view, and it goes first because the rest of that view cannot be
// built on top of the code this replaces: four RENDERERS currently write these sets while drawing,
// so "one coordinated commit per user action" is not expressible until that stops.
//
//
// WHAT THE MEASUREMENT SAYS
//
//                     reassignments   IN-PLACE MUTATIONS   reader fns
//   hiddenSources           0              7 in 6 fns          14
//   hiddenOrigins           0              7 in 6 fns          12
//   hiddenHosts             0              7 in 6 fns          12
//   hiddenIocTypes          0              6 in 5 fns          10
//
// Same shape as the selections: all in-place, never replaced. So the same answer — replace-on-write,
// bulk operations for the bulk gestures, and the container never escapes. `hide none` is
// `facets.forEach(s => hiddenSources.add(s))`, a commit per element, which is the shape
// js/dashboard-selection.js exists to stop.
//
//
// THE PRUNE BECOMES DERIVED, AND THAT IS A DELIBERATE BEHAVIOUR CHANGE
//
// Four of those mutations are a renderer editing the filter it is about to read:
//
//     for (const s of [...hiddenSources]) if (!allSources.includes(s)) hiddenSources.delete(s);
//
// — in renderSourceFilter, renderOriginFilter, renderHostFilter and renderIocTypeFilter. It is
// cross-import hygiene: drop unchecked facets that no longer exist anywhere, so the counts stay
// honest. But it is a write during a render, inside a loop, and it makes the renderers writers that
// any ownership gate has to carve an exception for.
//
// So the analyst's set is kept as they left it and the EFFECTIVE set is derived at read time, as
// `hidden ∩ available` — which is what `countIn(available)` is. No write, no commit mid-render.
//
// THE VISIBLE DIFFERENCE, stated rather than smuggled: hide a source, re-import a case without it,
// then import it again — today the tick is forgotten in between, now it is remembered. That is
// arguably the better behaviour (the analyst hid it on purpose and never said otherwise), and it is
// the reason this is called out here rather than buried as a refactor.
//
// It is also strictly MORE correct in one place. `renderIocTypeFilter` computed
// `shown = types.length - hiddenIocTypes.size` from the raw size, which is only right immediately
// after the prune has run; between renders a stale entry made the count too low. `countIn(types)`
// cannot be stale because it is not stored.
//
//
// ONE READ FOR "HOW MANY", AND IT IS ALWAYS THE DERIVED ONE.
//
// An earlier draft also published `any()` — "has the analyst hidden anything at all" — as a cheap
// guard that could skip a filter pass, on the argument that a remembered-but-absent facet would
// only cost a wasted pass and change no output. That argument was wrong, and review caught it: the
// same flag also drove the timeline's "N of M events" label and the IOC panel's filters-active
// chip, so a facet the analyst hid in a previous import made the dashboard claim it was filtering
// when it was not. The saving was one array pass; the cost was a lie about what the analyst is
// looking at. So there is only countIn(available), the derived `hidden ∩ available`.
//
// THE OWNER IS NEVER PASSED ANYWHERE — `matcher()` is. The one cross-module coupling the census
// found (realSourceCount, which needs an object with `.has()`) takes that frozen read-only view
// instead of this object, so "the owner is only ever called by name" stays checkable. An earlier
// draft passed the owner itself, which works at runtime and quietly defeats every analysis that
// tries to follow who can write.
//
// NOT AN ES MODULE, and an IIFE, for the reasons js/dashboard-state.js sets out.
(function () {
  /**
   * One facet filter: the set of names the analyst has UNCHECKED.
   *
   * Shared factory rather than four copies, for the reason js/dashboard-selection.js gives — the
   * replace-on-write discipline is the thing that must not vary between them.
   */
  function facet() {
    const cell = window.DfirState.cell(new Set());
    const commit = (next) => cell.set(next);
    return {
      has: (name) => cell.get().has(name),
      /**
       * A frozen read-only view: `{ has }` and nothing else.
       *
       * realSourceCount(sources, hidden) in js/dashboard-filters.js needs an object with `.has()`.
       * Handing it the OWNER would work — but the owner also carries toggle/hideAll/showAll, so
       * every helper it is passed to becomes a place that could write, and an analysis that follows
       * writes has to give up at the call. Handing out a view instead keeps "the owner is only ever
       * called by name, never passed" a property a test can hold; ownerEscapes() enforces it.
       */
      matcher() {
        const hidden = cell.get();
        return Object.freeze({ has: (name) => hidden.has(name) });
      },
      /**
       * How many of `available` are hidden. THE DERIVED PRUNE: a name the analyst hid that no
       * longer exists simply does not count, instead of being deleted from their choice.
       */
      countIn(available) {
        const hidden = cell.get();
        let n = 0;
        for (const name of available || []) if (hidden.has(name)) n++;
        return n;
      },
      /** One checkbox. `hidden` omitted flips, like classList.toggle. */
      toggle(name, hidden) {
        const current = cell.get();
        const want = hidden === undefined ? !current.has(name) : Boolean(hidden);
        if (want === current.has(name)) return current.size;
        const next = new Set(current);
        if (want) next.add(name);
        else next.delete(name);
        return commit(next).size;
      },
      /** "hide none" — every facet at once, ONE commit rather than one per name. */
      hideAll(names) {
        const next = new Set(cell.get());
        for (const name of names || []) next.add(name);
        return commit(next).size;
      },
      /** "show all", and the per-case reset. */
      showAll() {
        return commit(new Set()).size;
      },
    };
  }

  window.DfirFacets = {
    sources: facet(),
    origins: facet(),
    hosts: facet(),
    iocTypes: facet(),
  };
})();
