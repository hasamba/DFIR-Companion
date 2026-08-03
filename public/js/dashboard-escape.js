// HTML escaping for the extracted dashboard helper modules (#415).
//
// NOT AN ES MODULE, AND NOT DEFERRED — this and its seven sibling dashboard-*.js files are classic
// scripts loaded synchronously in <head>, ahead of the inline script. That is a deliberate choice
// and the rest of the extraction depends on it:
//
//   1. dashboard.html's inline <script nonce> is a CLASSIC script, so its 902 top-level
//      `function` declarations are properties of the global object. 427 call sites reach the 95
//      functions moved out of it by bare name. An ES module's declarations are NOT globals, so
//      moving them into one turns every one of those into a ReferenceError -- which is exactly
//      what happened to js/diagnostics-panel.js in #414, with all 29 of its unit tests passing
//      because they exercise the module directly and never load the page.
//
//   2. Rewriting the 427 sites was the alternative. #414's shape -- `const { diagRow, diagCard }
//      = window.DfirDiagnostics;` at the top of each caller -- needs one line in each of 234
//      distinct caller functions here. 234 hand edits to make a move that changes no behaviour is
//      a worse trade than one <script> tag.
//
//   3. Deferring is not available either. A module script executes after the HTML is parsed, and
//      dashboard.html calls legendIcon() at parse time, from a top-level statement:
//      `document.querySelectorAll(".legend-slot").forEach(...)`. Under `type="module"` that call
//      lands before the module runs, and the symptom is legend icons silently absent -- no error,
//      nothing failing in any suite. A synchronous classic script in <head> makes the ordering
//      true by construction rather than by argument.
//
// The cost is that these files cannot `export`, so tests load them the way the browser does:
// tests/helpers/dashboardModule.ts runs the file in a vm context and reads the namespace back.
// That tests the real load contract, which an `import` would not.
//
// WHY esc/escAttr ARE DUPLICATED RATHER THAN MOVED. The inline script has 661 call sites for
// `esc`, so #414 left it in place and gave js/diagnostics-panel.js its own copy. That decision
// stands: this file carries the third copy, and tests/reports/dashboardEscape.test.ts asserts all
// three stay byte-identical. Two implementations of an XSS-critical primitive are a real hazard
// (#387), so the guard is a drift test rather than a runtime dependency.
//
// Be precise about which copy runs where, because it is not this one. The inline script declares
// `esc` AFTER this file loads, so in a browser `window.esc` is the inline definition and that is
// what the sibling modules resolve when they call it. This copy is what runs under the vm-loaded
// unit tests, and what keeps these files loadable on their own. Both paths are correct only
// while the implementations are identical, which is precisely what the drift test enforces --
// the guard is not bookkeeping, it is the thing making the duplication safe.
//
// Load order among the eight files does not matter -- nothing here is INVOKED at load time, only
// declared -- but they are tagged in dependency order anyway so the reading order matches.

function esc(s) {
  return String(s == null ? "" : s)
    .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

// Escapes BOTH quote flavours (#217). Single quotes matter as much as double: an attribute
// value is decoded before whatever consumes it runs, so an unescaped apostrophe in a
// single-quoted context lets attacker-controlled evidence close the string and keep going.
function escAttr(s) { return esc(s).replace(/"/g, "&quot;").replace(/'/g, "&#39;"); }

// Published for the inline script and the other helper modules. EVERY function this file
// defines is listed: a helper that stays private here but is still called by name from
// dashboard.html is a ReferenceError, which is the mistake #414 shipped and then fixed.
window.DfirEscape = {
  esc,
  escAttr,
};
