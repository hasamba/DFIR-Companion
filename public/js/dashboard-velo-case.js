// Which case a Velociraptor collection runs against, and whether it may run at all (#385 file-size
// ledger: extracted from dashboard-velo-triage.js rather than grown inside it).
//
// THE PICKER IS NOT THE CASE, and reading it as though it were is what let a hunt launch with no
// case open. js/dashboard-case-connect.js PRE-FILLS #caseId from localStorage on a bare /dashboard
// and deliberately does not connect (see restoreCaseFromUrl) — landing on the dashboard is as often
// the moment an analyst wants a different case as the last one. So the field carries a case id
// before anything has been opened, and every Velociraptor guard spelled "connect to a case first"
// as `if (!caseId)` over exactly that field. All of them passed. An analyst could also simply type
// an id that never existed: nothing downstream checked, so run-bundle launched a hunt on live
// endpoints and then failed to record it, leaving the hunt running in Velociraptor with no job
// card, no collect timer and no way to collect it from here. (The server refuses that outright
// now — companion/src/analysis/caseExistsGate.ts — this is the half that keeps the button honest.)
//
// activeCaseId is page vocabulary: a top-level `let` in dashboard.html, written by proceedConnect
// the moment a load starts and cleared when one is cancelled. Read by bare name exactly as
// js/dashboard-render.js reads it; `typeof` covers a page (or a test) that never declared it,
// where a bare read would throw.

/* exported veloCaseId, veloRunBlockedReason */
function veloCaseId() {
  return typeof activeCaseId === "string" ? activeCaseId.trim() : "";
}

/**
 * Why a bundle cannot be run right now, or "" when it can.
 *
 * TWO conditions, and the bundle list renders before either is true — it loads at page load so
 * bundles can be built with no case open. Only the first was ever checked, which left a live Run
 * button on a dashboard with no case connected.
 */
function veloRunBlockedReason(enabled, caseId) {
  if (!enabled)
    return "Velociraptor API not configured (set the API config path above)";
  if (!caseId)
    return "Connect to a case first — a collection has to land in one";
  return "";
}
