// Collection plan (#211) (#415 tier 3).
//
// Two functions that were 8,000 lines apart in the page. Calls applySectionsVis(), which stays
// behind — a classic script resolves that by name at call time, the same mechanism the inline
// script already uses to reach these helpers.
//
// AN IIFE, unlike js/dashboard-tagger.js and js/dashboard-kev.js. Those hold no state, so their
// top-level declarations were harmless. This feature owns state, and a top-level `let` in a
// classic script joins the global LEXICAL environment — reachable by name from every other script
// on the page, which is the hazard js/dashboard-state.js sets out at length. Wrapping it is what
// makes "feature-local" true rather than merely intended.
//
// NOT AN ES MODULE: the inline script calls the published names below by bare name.
(function () {
  // Declared in the inline block until #415 tier 3, under a keyboard-navigation banner it had
  // nothing to do with, and used only here.

  // Collection plan (#347). Derived server-side from the case timeline; this only renders it and
  // posts the analyst's overrides. The section is data-gated: no incident type → no plan → stays
  // hidden, because a generic collection plan would be guesswork.
  const CP_MARK = {
    collected: "✔",
    "override-collected": "✔",
    "override-na": "—",
    external: "↗",
    outstanding: "○",
  };

  // Fetch a launched collection flow's rows into `target`; resolves to the row count. Reuses
  // renderVqlRows() (the same table the hunt-results flow renders).
  function fetchCollectionResults(rb, target) {
    const clientId = rb.dataset.cid,
      flowId = rb.dataset.fid,
      artifact = rb.dataset.art;
    const sources = (rb.dataset.src || "").split(",").filter(Boolean);
    target.innerHTML =
      "<span data-safe-style='color:var(--text-muted)'>fetching results…</span>";
    return fetch("/velociraptor/collect-results", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ clientId, flowId, artifact, sources }),
    })
      .then((r) => r.json().then((j) => ({ ok: r.ok, j })))
      .then(({ ok, j }) => {
        if (!ok || j.error) {
          target.innerHTML = `<div data-safe-style="color:var(--sev-high)">error: ${esc(j.error || "failed")}</div>`;
          return 1;
        }
        // The collection launched but FAILED on the endpoint (e.g. a bad VQL plugin/arg) — show it.
        if ((j.flowState || "").toUpperCase() === "ERROR" || j.flowError) {
          target.innerHTML = `<div data-safe-style="color:var(--sev-high);font-size:12px">⚠ collection failed on the endpoint: ${esc(j.flowError || "error")} — edit the VQL and re-collect.</div>`;
          return 1; // terminal — stop auto-polling
        }
        const n = (j.rows || []).length;
        if (n) {
          target.innerHTML = renderVqlRows(j);
          return n;
        }
        if ((j.flowState || "").toUpperCase() === "FINISHED") {
          target.innerHTML =
            "<span data-safe-style='color:var(--text-muted)'>collection finished — 0 rows returned.</span>";
          return 1; // terminal — stop auto-polling
        }
        target.innerHTML =
          "<span data-safe-style='color:var(--text-muted)'>no results yet — the endpoint reports on its next poll. Click ↻ to refresh.</span>";
        return 0; // still pending — keep polling
      })
      .catch((e) => {
        target.innerHTML = `<div data-safe-style="color:var(--sev-high)">error: ${esc(e.message)}</div>`;
        return 1;
      });
  }

  async function renderCollectionPlan() {
    const caseId = document.getElementById("caseId").value.trim();
    const sec = document.getElementById("sec-collection-plan");
    const el = document.getElementById("collectionPlan");
    if (!caseId) {
      sec.dataset.gateOpen = "";
      applySectionsVis();
      return;
    }
    let data;
    try {
      const r = await fetch(
        `/cases/${encodeURIComponent(caseId)}/collection-plan`,
      );
      data = r.ok ? await r.json() : null;
    } catch {
      data = null;
    }
    if (!data || !data.plan) {
      sec.dataset.gateOpen = "";
      applySectionsVis();
      return;
    }

    const p = data.plan;
    const rows = p.steps
      .map((s) => {
        const isNext = s.id === p.nextStepId;
        const hint =
          s.state === "external"
            ? "collect outside DFIR Companion"
            : s.reason
              ? esc(s.reason)
              : s.state === "outstanding"
                ? "satisfied by: " + esc(s.satisfiedBy.join(", "))
                : "";
        const acts =
          s.state === "collected"
            ? ""
            : s.state === "override-collected" || s.state === "override-na"
              ? `<button data-cp-clear="${esc(s.id)}">Undo</button>`
              : `<button data-cp-set="${esc(s.id)}" data-cp-state="collected">Have it</button>` +
                `<button data-cp-set="${esc(s.id)}" data-cp-state="na">N/A</button>`;
        return (
          `<div class="cp-row"><span class="cp-mark">${CP_MARK[s.state] || "○"}</span>` +
          `<span class="cp-label${isNext ? " cp-next" : ""}">${esc(s.label)}${isNext ? " — collect next" : ""}</span>` +
          `<span class="cp-hint">${hint}</span><span class="cp-act">${acts}</span></div>`
        );
      })
      .join("");
    el.innerHTML = `<div class="cp-done">${p.collected} of ${p.total} collected</div>${rows}`;
    sec.dataset.gateOpen = "1";
    applySectionsVis();
  }

  // The names the inline script calls by bare name. Everything else — this feature's state
  // included — stays inside the closure, which is the point of moving it.
  window.fetchCollectionResults = fetchCollectionResults;
  window.renderCollectionPlan = renderCollectionPlan;
})();
