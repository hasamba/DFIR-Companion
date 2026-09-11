// The search box asks the CASE, not just the rows already on screen (#928).
//
// The dashboard fetches one page of forensic events and every filter in the toolbar then runs over
// that array in the browser. For the other filters that is fine. For SEARCH it was not: on a case
// with more events than the page holds, the matching evidence had never been sent to the browser at
// all, so the analyst was shown "0 events" for something the case demonstrably contained -- the
// worst possible answer in an investigation, because it reads as proof of absence.
//
// So a committed search term re-queries /cases/:id/state?q=<term>, which searches the whole stored
// timeline server-side (companion/src/analysis/forensicSearch.ts). The client-side predicate still
// runs over the reply and MUST stay in step with the server's -- see _evSearchParts in
// js/dashboard-filters.js -- or rows would arrive and then be filtered straight back out.
//
// Registered as the `serverSearch` painter in dashboard.html; DfirTimelineView decides when a
// search makes it stale, exactly like every other panel.
//
// ---------------------------------------------------------------------------------------------
// THE FOUR RULES. Every bug this module has had was one of them being broken, and each one is
// invisible in a browser: the timeline just shows the wrong events, with nothing to say so.
//
//   1. ONLY THE NEWEST ANSWER PAINTS.               (requestToken)
//      A scan of the whole case is slow, so an abandoned term's answer routinely lands after the
//      current one's. Painting it narrows the timeline to a term the search box no longer holds.
//
//   2. ONE SCAN IN FLIGHT, BURSTS COALESCE.         (asking)
//      A live case replaces its state repeatedly. One scan per replacement stacks whole-case
//      queries the analyst pays for in latency, so while a scan is out nothing else is asked, and
//      the one that returns re-asks once for whatever the question has become by then.
//
//   3. A REPAINT IS NOT A REPLACEMENT.              (seenState, applying)
//      setSearch() refreshes `serverSearch` and then `all`, and `all` writes the SAME snapshot
//      back. Reading that as new state cancelled every search at the moment it was issued, and no
//      server search painted at all.
//
//   4. CANCELLING IS HALF AN ANSWER.                (the re-ask in the subscription)
//      When the state really is replaced, what is on screen is the UNFILTERED case while the
//      search box still holds a term. Abandoning the request without asking again shows the
//      analyst rows their own filter excludes.
//
// Tests for all four live in companion/tests/dashboard/timelineSearchLoad.test.ts, and they drive
// the module the way the PAGE drives it — through wire()/setSearch — because every one of these
// survived a suite that called the loader directly.
// ---------------------------------------------------------------------------------------------
(function () {
  "use strict";

  // Last request wins, and only the LAST one may paint. Same shape as the super-timeline's loader
  // (js/dashboard-super-timeline.js), for the same reason: this fetch scans the case, so a slow
  // answer to an abandoned term can easily land after a fast answer to the current one, and
  // painting it would put the whole case back on screen under a filter that is set.
  var requestToken = 0;
  // The question the painted rows answer, CASE INCLUDED. A repeat of the same question is not
  // re-asked, because several actions refresh the timeline without changing the term -- but the
  // case has to be part of the key: keyed on the term alone, opening a second case while a term was
  // set read as "same question, already painted" and skipped the fetch, leaving one investigation's
  // filtered events on screen under another investigation's name.
  var painted = null;
  // The question a request is in flight FOR. Several things can ask for the same answer at once --
  // a reconnect re-asks on its own, and a panel refresh may ask again a moment later -- and firing
  // two identical case scans is waste the analyst pays for in latency.
  var asking = null;
  // Where the next page of matches starts, and whether the server held any back. A search matching
  // more events than one response carries is truncated, and the total then reported is a FLOOR
  // rather than a count; without these the analyst had no way to reach the rest of their evidence.
  var nextCursor = null;
  var moreTruncated = false;
  // Set while WE are the ones calling render(), so the state subscription below can tell our own
  // paint apart from somebody else's.
  var applying = false;
  // The snapshot the page is showing, by IDENTITY. A REPAINT of the same snapshot is not a new
  // answer -- and the page repaints constantly: setSearch() refreshes `serverSearch` and then
  // `all`, and `all` is `render(DfirState.lastState())`, which writes the cell straight back with
  // the value it already held. Treating that as a replacement retired the token of the search that
  // had just been issued, so the reply was discarded and NO server search ever painted.
  var seenState = null;

  function caseIdOf() {
    var el = document.getElementById("caseId");
    return el ? el.value.trim() : "";
  }

  function questionFor(term) {
    return term ? "q=" + encodeURIComponent(term) : "";
  }

  /** The identity of a painted answer: which case, asked what. */
  function answerKey(caseId, asked) {
    return caseId + " " + asked;
  }

  function currentTerm() {
    return typeof DfirTimelineView !== "undefined" ? DfirTimelineView.search() : "";
  }

  /**
   * Forget what we believe is on screen, and retire anything in flight.
   *
   * Called when somebody ELSE replaces the state -- reconnecting a case is the one that bit: the
   * connect path renders an unfiltered timeline without going through this module, so a search
   * still in flight would land afterwards and narrow it, and `painted` would go on claiming an
   * answer that had been painted over. Both halves matter; dropping only the token leaves the
   * module refusing to re-ask for a question whose answer is no longer displayed.
   */
  function invalidate() {
    requestToken++;
    painted = null;
    nextCursor = null;
    moreTruncated = false;
    // `asking` deliberately SURVIVES. It is what makes a burst of replacements coalesce: while a
    // scan is out, every further replacement finds the slot taken and asks for nothing, and the
    // request that eventually lands re-asks once for whatever the question has become. Clearing it
    // here turned a live case's update stream into one whole-case scan per update.
  }

  function paint(state) {
    applying = true;
    try {
      if (typeof render === "function") render(state);
    } finally {
      applying = false;
    }
  }

  function absorb(state) {
    nextCursor = typeof state.forensicTimelineNextCursor === "number"
      ? state.forensicTimelineNextCursor
      : null;
    moreTruncated = !!state.forensicTimelineTotalIsLowerBound;
  }

  function loadSearchedTimeline() {
    var caseId = caseIdOf();
    if (!caseId) return;
    var asked = questionFor(currentTerm());
    var key = answerKey(caseId, asked);
    if (key === painted) {
      // Already on screen -- but an EARLIER request may still be in flight, and returning without
      // touching the token would let it paint. Type "foo" over an unfiltered timeline and clear it
      // again before the answer lands: the reverted view is already correct, then the abandoned
      // "foo" response arrives, passes the token check, and narrows the timeline to a term the
      // search box no longer contains. Retiring the token here is what makes the revert stick.
      requestToken++;
      asking = null;
      return;
    }
    if (key === asking) return; // already on its way; a second identical scan buys nothing

    var token = ++requestToken;
    asking = key;
    fetch("/cases/" + encodeURIComponent(caseId) + "/state" + (asked ? "?" + asked : ""))
      .then(function (r) {
        if (!r.ok) throw new Error("HTTP " + r.status);
        return r.json();
      })
      .then(function (state) {
        // The analyst kept typing, or the case was replaced under us. This answers a question
        // nobody is asking any more, so it must not paint — but the slot it held is now free, and
        // the view is showing something the current question has not been applied to. Ask once,
        // for whatever is being asked now.
        if (token !== requestToken) {
          if (asking === key) {
            asking = null;
            loadSearchedTimeline();
          }
          return;
        }
        asking = null;
        painted = key;
        absorb(state);
        // render() is the ONLY writer of the state snapshot (see docs/adr/0001-dashboard-state.md
        // and the single-writer gate in tests/dashboard/dashboardState.test.ts), so the new
        // timeline reaches the page through it rather than by poking DfirState directly.
        paint(state);
      })
      .catch(function () {
        // Offline, a cancelled case, or a non-JSON error body. The rows already on screen are still
        // a true subset of the matches -- the loaded page filtered locally -- so the view stays as
        // it is rather than being blanked on a transport failure.
        //
        // Release the slot whether or not this request was still the current one: a superseded
        // request that failed still owns it, and leaving it held wedges every later search.
        var heldSlot = asking === key;
        if (heldSlot) asking = null;
        if (token !== requestToken) {
          // Superseded AND failed. Rule 4 does not stop applying because the transport broke: what
          // is on screen is still the unfiltered case under a term that is still set, and this
          // request was the only thing that was going to fix that. Ask once for the question now.
          if (heldSlot) loadSearchedTimeline();
          return;
        }
        // A plain failure of the CURRENT question. It is not recorded as answered, so the next
        // refresh retries -- retrying here would spin against an offline server.
        painted = null;
      });
  }

  /** Whether the server held back matches this view has not asked for yet. */
  function hasMoreMatches() {
    return moreTruncated && nextCursor !== null;
  }

  /**
   * Fetch the next page of matches and APPEND it.
   *
   * Appending rather than replacing is the point: the analyst is reading a filtered timeline and
   * wants the rest of it, not the next slice in isolation. The reply carries its own cursor, so
   * this can be pressed until the case runs out of matches.
   */
  function loadMoreMatches() {
    var caseId = caseIdOf();
    if (!caseId || !hasMoreMatches()) return;
    var asked = questionFor(currentTerm());
    if (answerKey(caseId, asked) !== painted) return; // the question moved on under us
    var cursorAt = nextCursor;
    nextCursor = null; // one request in flight at a time; restored below if it fails

    var token = ++requestToken;
    var sep = asked ? "?" + asked + "&" : "?";
    fetch("/cases/" + encodeURIComponent(caseId) + "/state" + sep + "timelineCursor=" + cursorAt)
      .then(function (r) {
        if (!r.ok) throw new Error("HTTP " + r.status);
        return r.json();
      })
      .then(function (state) {
        if (token !== requestToken) return;
        // Read the snapshot HERE rather than binding it earlier: paint() replaces it, and a
        // binding that outlives that call is a stale snapshot waiting to be used (the gate in
        // tests/dashboard/dashboardState.test.ts refuses the shape for exactly that reason).
        var before = (DfirState.lastState() || {}).forensicTimeline || [];
        var merged = {};
        for (var k in state) {
          if (Object.prototype.hasOwnProperty.call(state, k)) merged[k] = state[k];
        }
        merged.forensicTimeline = before.concat(state.forensicTimeline || []);
        absorb(state);
        paint(merged);
      })
      .catch(function () {
        if (token === requestToken) nextCursor = cursorAt; // let the analyst press it again
      });
  }

  // Somebody else REPLACED the state -- a case connect, a live update, anything that is not our own
  // paint. Whatever is on screen is no longer our answer, and an in-flight search must not land on
  // top of it. A write of the same snapshot is a repaint, not a replacement, and must be left alone:
  // see seenState above for what happens when the two are confused.
  if (typeof DfirState !== "undefined" && DfirState.onLastStateChange) {
    // Deliberately NOT seeded from lastState(): caching the snapshot here and comparing against it
    // in a callback is the stale-snapshot shape the state gate refuses, and seeding buys nothing.
    // The first notification establishes the baseline, and at that point no search is ever in
    // flight -- the page has not finished loading a case yet.
    DfirState.onLastStateChange(function (next) {
      var replaced = next !== seenState;
      seenState = next;
      if (!replaced || applying) return;
      invalidate();
      // Abandoning the request is only half of it. What has just been painted is the UNFILTERED
      // case, while the search box still holds a term -- so the analyst is looking at rows their
      // own filter excludes, with nothing to say the search stopped applying. Ask again. Our own
      // paint of the answer sets `applying`, so this cannot feed itself.
      if (currentTerm()) loadSearchedTimeline();
    });
  }

  window.DfirTimelineSearch = {
    loadSearchedTimeline: loadSearchedTimeline,
    loadMoreMatches: loadMoreMatches,
    hasMoreMatches: hasMoreMatches,
    // Test seam: whether an answer for this case+term is already painted.
    paintedKey: function () { return painted; },
  };
  window.loadSearchedTimeline = loadSearchedTimeline;
  window.loadMoreMatches = loadMoreMatches;
  window.hasMoreMatches = hasMoreMatches;
})();
