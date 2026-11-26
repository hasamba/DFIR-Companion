// Reading the case's investigation window from the server, and taking it from a live push (#2915).
//
// Moved out of the page's inline script (loadScope) and dashboard-case-connect.js (the
// scope_changed branch) so the read and the push can share ONE version counter. js/dashboard-scope.js
// owns the window itself; this file only decides which answer may commit it.
//
// WHICHEVER CAME LAST WINS. `seq` is bumped by every read, every scope_changed push for the case on
// screen and this analyst's accepted POST (noteScopeConfirmed, from js/dashboard-scope-apply.js). A
// read answers only if nothing newer happened since it started, so a read that was already on its
// way when a push arrived can no longer put the old window back. The reconnect catch-up
// (js/dashboard-live-socket.js) is a READ, so it calls loadScope rather than replaying its answer as
// a push.
//
// #2904: a read for another case first clears the window, so the case left never filters this one.
//
// A READ THAT FAILS says so. The window is unknown, so the timeline stays UNFILTERED (hiding
// everything would be worse) and the chip says it could not load the time window, with Retry. Only
// when no window is known for this case: a failed re-read keeps the window already held.
//
// A cancelled or failed case load (DfirPanelDefer.reset(null)) forgets whose window is held, so the
// next open — the same case included — clears and reads it again. The window itself is left: it is
// the filter of the view the cancel left on screen, and nothing redraws that view.
(function () {
  const scopeLoad = { caseId: null, seq: 0, known: null }; // known: the case whose window came from the server
  const UNREADABLE = "could not load the time window — showing all events ";
  const UNREADABLE_TIP =
    "The saved time window of this case could not be read, so the timeline is NOT filtered by it. " +
    "Press Retry. The two fields are blank: pressing Apply now would replace the saved window.";

  function scopeOnScreen(caseId) {
    const el = document.getElementById("caseId");
    return !el || typeof el.value !== "string" || el.value.trim() === caseId;
  }
  function redraw() {
    if (DfirState.lastState()) typeof render === "function" && render(DfirState.lastState());
  }
  function onScopeReset(caseId) {
    if (caseId !== null) return;
    scopeLoad.caseId = null;
    scopeLoad.known = null;
    scopeLoad.seq++;
  }
  function listenForReset() {
    if (typeof DfirPanelDefer !== "undefined" && typeof DfirPanelDefer.onReset === "function")
      DfirPanelDefer.onReset(onScopeReset);
  }

  // The chip's failure state. Its children go the next time DfirScope repaints the chip
  // (renderInfo writes textContent), so recovery needs no clean-up here.
  function showScopeUnreadable(caseId) {
    const el = document.getElementById("scopeInfo");
    if (!el) return;
    const note = document.createElement("span");
    note.textContent = UNREADABLE;
    note.title = UNREADABLE_TIP;
    const retry = document.createElement("button");
    retry.type = "button";
    retry.className = "scope-preset";
    retry.textContent = "Retry";
    retry.title = "Read this case's time window again";
    retry.addEventListener("click", () => loadScope(caseId));
    el.textContent = "";
    el.append(note, retry);
    el.style.color = "var(--sev-high)";
  }

  // No redraw while loading (render() comes separately) unless this case already rendered.
  function loadScope(caseId) {
    if (!scopeOnScreen(caseId)) return; // a late caller for a case the analyst has left
    listenForReset();
    if (scopeLoad.caseId !== caseId) {
      scopeLoad.caseId = caseId;
      scopeLoad.known = null;
      DfirScope.receive(null, null);
    }
    const seq = ++scopeLoad.seq;
    const current = () => seq === scopeLoad.seq && scopeOnScreen(caseId);
    fetch(`/cases/${caseId}/scope`)
      .then((r) => {
        if (!r.ok) throw new Error("HTTP " + r.status);
        return r.json();
      })
      .then((s) => {
        // #2929: anything but a window object is a failed read, never "no window".
        if (!s || typeof s !== "object" || Array.isArray(s)) throw new Error("not a time window");
        if (!current()) return;
        const was = DfirScope.get(), changed = was.start !== (s.start || null) || was.end !== (s.end || null);
        scopeLoad.known = caseId;
        DfirScope.receive(s.start, s.end);
        if (changed) redraw();
      })
      .catch(() => {
        if (current() && scopeLoad.known !== caseId) showScopeUnreadable(caseId);
      });
  }

  // Another client (or this one, in another tab) moved the window. The two controls are a sink here,
  // and this path redraws, because the change came from outside and nothing else is going to.
  //
  // The hub broadcasts to every subscriber with no sender exclusion (src/live/hub.ts), so applyScope
  // receives its own echo and this runs a second time after it — applying a scope renders twice and
  // the analyst's typed input is replaced by the server's normalised form. Pre-existing, preserved.
  //
  // render() projects with the freshly-updated window AND caches its argument as
  // DfirState.lastState(), so it is handed the RAW state — an already-projected one would cache a
  // scope-narrowed subset, permanently dropping out-of-window events on the next widen/clear.
  function receiveScopePush(caseId, msg) {
    if (!scopeOnScreen(caseId)) return;
    scopeLoad.caseId = caseId;
    scopeLoad.known = caseId;
    scopeLoad.seq++; // a read already on its way is older than this push
    DfirScope.receive(msg.start, msg.end);
    redraw();
  }

  // applyScope's POST was accepted. Returns false when the analyst has left that case meanwhile (the
  // window must not be committed on another case); otherwise it is the newest word on the window.
  function noteScopeConfirmed(caseId) {
    if (!scopeOnScreen(caseId)) return false;
    scopeLoad.caseId = caseId;
    scopeLoad.known = caseId;
    scopeLoad.seq++;
    return true;
  }

  window.loadScope = loadScope;
  window.receiveScopePush = receiveScopePush;
  window.noteScopeConfirmed = noteScopeConfirmed;
})();
