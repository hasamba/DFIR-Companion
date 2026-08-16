// Near-duplicate host review — the merge gate's UI surface.
//
// AN IIFE: this feature owns state, and a top-level `let` in a classic script joins the global
// lexical environment. NOT AN ES MODULE — the inline script calls the published names by bare name.
//
// renderHostDuplicates is a PURE string function with no DOM access, so it is testable through
// loadDashboardModule, which runs this file in a Node vm context with no document.
(function () {
  "use strict";

  let pending = [];

  function renderHostDuplicates(list) {
    if (!list || !list.length) return "";
    const rows = list
      .map(
        (d) =>
          `<div class="hd-row">` +
          `<code>${esc(d.other)}</code> and <code>${esc(d.canonical)}</code> may be the same machine. ` +
          `<button data-hd-merge="1" data-hd-canonical="${escAttr(d.canonical)}" data-hd-other="${escAttr(d.other)}" ` +
          `title="Treat these as one host. Analysis re-runs once every pair is resolved.">Same host — merge</button> ` +
          `<button data-hd-dismiss="1" data-hd-canonical="${escAttr(d.canonical)}" data-hd-other="${escAttr(d.other)}" ` +
          `title="Two different machines. You won't be asked about this pair again.">Different hosts</button>` +
          `</div>`,
      )
      .join("");
    return (
      `<div class="hd-warn"><strong>Analysis is on hold.</strong> ` +
      `${list.length} host${list.length === 1 ? " appears" : "s appear"} under more than one name. ` +
      `Until you decide, the AI would treat one machine as two — splitting its evidence and its ` +
      `timeline. Resolve each pair and analysis restarts automatically.</div>${rows}`
    );
  }

  function paint() {
    const badge = document.getElementById("hostDuplicatesBadge");
    if (badge) {
      badge.style.display = pending.length ? "" : "none";
      badge.textContent = "⚠ Duplicate hosts: " + pending.length;
    }
    const el = document.getElementById("hostDuplicatesBody");
    if (!el) return;
    el.innerHTML = renderHostDuplicates(pending);
    // One delegated listener, bound once: innerHTML is replaced on every repaint, so per-button
    // listeners would be lost each time.
    if (!el.dataset.hdBound) {
      el.addEventListener("click", onPanelClick);
      el.dataset.hdBound = "1";
    }
  }

  async function loadHostDuplicates(caseId) {
    if (!caseId) return;
    try {
      const r = await fetch(`/cases/${encodeURIComponent(caseId)}/host-duplicates`);
      if (!r.ok) return;
      const d = await r.json();
      pending = d.pending || [];
      paint();
    } catch {
      // A panel that cannot load must not take the dashboard down with it.
    }
  }

  async function resolve(caseId, action, canonical, other) {
    try {
      const r = await fetch(`/cases/${encodeURIComponent(caseId)}/host-duplicates/${action}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ canonical: canonical, other: other }),
      });
      if (!r.ok) return;
      const d = await r.json();
      pending = d.pending || [];
      paint();
    } catch {
      /* leave the panel as it was */
    }
  }

  function onPanelClick(evt) {
    const target = evt.target && evt.target.closest ? evt.target : null;
    if (!target) return;
    const button = target.closest("[data-hd-merge], [data-hd-dismiss]");
    if (!button) return;
    const caseId = (document.getElementById("caseId") || {}).value;
    if (!caseId || !caseId.trim()) return;
    const canonical = button.getAttribute("data-hd-canonical");
    const other = button.getAttribute("data-hd-other");
    const action = button.hasAttribute("data-hd-merge") ? "merge" : "dismiss";
    if (action === "merge" && !confirm(`Treat ${other} and ${canonical} as one host?`)) return;
    void resolve(caseId.trim(), action, canonical, other);
  }

  // The badge lives in the page header, so this binds at load, not on module evaluation.
  function initHostDuplicates() {
    document.getElementById("hostDuplicatesBadge")?.addEventListener("click", () => {
      document.getElementById("sec-host-duplicates")?.scrollIntoView({ behavior: "smooth" });
    });
  }

  window.loadHostDuplicates = loadHostDuplicates;
  window.renderHostDuplicates = renderHostDuplicates;
  window.initHostDuplicates = initHostDuplicates;
})();
