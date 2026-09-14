// Intel retirement review (#933 item 19, second half — #1024).
//
// The findings whose threat-intel corroboration rested on assertions that are no longer
// actionable (expired, revoked, not returned by the provider, errored on the last check, or
// recorded before assertion tracking), each with the assertions named and the analyst's decision
// on file. A list to REVIEW: the two buttons record a decision (`retire` / `keep`) and change
// nothing else — no severity, no status, no deployed detection. The evidence stays in the case.
//
// An IIFE for the same reason as js/dashboard-custody.js: this feature owns state.
// NOT AN ES MODULE: the inline script calls the published names below by bare name.
(function () {
  let review = { items: [], stillActionable: 0, at: "" };
  let currentCaseId = "";

  function renderIntelRetirement() {
    const el = document.getElementById("intelRetirementPanel");
    if (!el) return;
    if (!review.items.length) {
      el.innerHTML = `<div data-safe-style='color:var(--text-muted);font-size:12px'>No finding rests only on intel that is no longer actionable${review.stillActionable ? ` (${esc(String(review.stillActionable))} finding(s) still carry a live assertion)` : ""}.</div>`;
      return;
    }
    const rows = review.items.map((it) => {
      const assertions = it.assertions
        .slice(0, 6)
        .map((a) => `<div data-safe-style="font-size:12px">${esc(a.source)}: ${esc(a.verdict)} on <code>${esc(a.iocValue)}</code> — <span data-safe-style="color:var(--text-muted)">${esc(a.label || a.status)}</span></div>`)
        .join("");
      const more = it.assertions.length > 6 ? `<div data-safe-style="font-size:11px;color:var(--text-muted)">+${it.assertions.length - 6} more</div>` : "";
      const decision = it.decision
        ? `<span data-safe-style="font-size:12px">decided: <b>${esc(it.decision.decision)}</b> ${esc(String(it.decision.decidedAt || "").slice(0, 10))}${it.decision.note ? ` — ${esc(it.decision.note)}` : ""}</span>`
        : `<span data-safe-style="font-size:12px;color:var(--text-muted)">undecided</span>`;
      return `<details data-safe-style="margin-bottom:8px;border:1px solid var(--border);border-radius:6px;padding:4px 8px">
        <summary data-safe-style="cursor:pointer"><b>${esc(it.severity)}</b> ${esc(it.title)} <span data-safe-style="color:var(--text-muted);font-size:12px">— ${esc(String(it.assertions.length))} assertion(s), none actionable</span></summary>
        <div data-safe-style="padding:6px 0">
          <div data-safe-style="font-size:12px;margin-bottom:6px">${esc(it.recommendation)}</div>
          ${assertions}${more}
          <div data-safe-style="display:flex;gap:8px;align-items:center;flex-wrap:wrap;margin-top:8px">
            <button type="button" data-intel-retire="${esc(it.findingId)}" data-decision="keep" title="Record that the finding stands on its other evidence; changes nothing else">Keep</button>
            <button type="button" data-intel-retire="${esc(it.findingId)}" data-decision="retire" title="Record a retirement recommendation; the finding's severity and status are unchanged">Retire</button>
            ${decision}
          </div>
        </div>
      </details>`;
    });
    el.innerHTML = `<div data-safe-style="font-size:12px;color:var(--text-muted);margin-bottom:6px">${esc(String(review.items.length))} finding(s) to review; ${esc(String(review.stillActionable))} still carry a live assertion. A decision is a recorded recommendation — it changes no severity, status or deployed detection, and erases no evidence.</div>` + rows.join("");
    el.querySelectorAll("button[data-intel-retire]").forEach((b) => {
      b.addEventListener("click", () => decideIntelRetirement(b.getAttribute("data-intel-retire"), b.getAttribute("data-decision")));
    });
  }

  function decideIntelRetirement(findingId, decision) {
    if (!currentCaseId || !findingId) return;
    const caseId = currentCaseId;
    const note = window.prompt(`Note for the ${decision} decision (optional):`, "") || "";
    fetch(`/cases/${encodeURIComponent(caseId)}/intel-retirement/${encodeURIComponent(findingId)}`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ decision, ...(note ? { note } : {}) }),
    })
      .then((r) => (r.ok ? r.json() : review))
      .then((d) => {
        if (currentCaseId !== caseId) return;
        review = d && Array.isArray(d.items) ? d : review;
        renderIntelRetirement();
      })
      .catch(() => {});
  }

  function loadIntelRetirement(caseId) {
    currentCaseId = caseId;
    review = { items: [], stillActionable: 0, at: "" };
    renderIntelRetirement();
    // A late answer for a case the user has left never overwrites the panel (another case's
    // finding titles and indicators): the response is kept only while it is still the current case.
    fetch(`/cases/${encodeURIComponent(caseId)}/intel-retirement`)
      .then((r) => (r.ok ? r.json() : { items: [], stillActionable: 0, at: "" }))
      .then((d) => {
        if (currentCaseId !== caseId) return;
        review = d && Array.isArray(d.items) ? d : { items: [], stillActionable: 0, at: "" };
        renderIntelRetirement();
      })
      .catch(() => {});
  }

  window.loadIntelRetirement = loadIntelRetirement;
})();
