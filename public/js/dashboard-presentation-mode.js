// Presentation mode (#17) — the stripped-down view for showing a case on a projector
// (#415 tier 3).
//
// Wiring only, and most of what the splitter reported at load in this range was not this feature:
// four guard stanzas from other extractions sit here and stay in the page.
(function () {
  // ── Presentation mode (#177) ──────────────────────────────────────────────
  // Open the read-only, step-through slide viewer for this case in a new tab. The viewer has its
  // own severity selector + standalone-HTML export, so we just point it at the case.

  // The statements the inline block ran at module scope.
  function initPresentationMode() {
    document.getElementById("presentBtn").onclick = () => {
      const caseId = document.getElementById("caseId").value.trim();
      if (!caseId) {
        document.getElementById("status").textContent = "open a case first";
        return;
      }
      window.open(
        `/cases/${encodeURIComponent(caseId)}/present`,
        "_blank",
        "noopener",
      );
    };
  }

  window.initPresentationMode = initPresentationMode;
})();
