// Collection generation diff (#1128) — a genuine new top-level section (Codex design-review
// finding M5 on RECOMMENDATION-1128.md: a route with no real consumer risks becoming a third
// unconsumed disclosure surface, matching 932.17's own review of #1108). Renders
// GET /cases/:id/collection-generations/compare — adjacent-pair diffs of #1108's own
// collection-generation ledger, persistence domain only in v1.
(function () {
  let cohorts = [];
  let truncatedCohorts = false;
  // "loading" | "ready" | "unconfigured" | "error" — a code-review fix (Medium): collapsing every
  // outcome into an empty `cohorts` array made a genuine server failure indistinguishable from an
  // honestly empty case, and left the PRIOR case's cohorts on screen until the new fetch resolved.
  let status = "loading";
  let loadSeq = 0; // generation token: only the latest load may mutate state (case-switch races)

  // esc/escAttr are the GLOBAL, canonical copies from dashboard-escape.js (loaded well before this
  // file, in <head>) — never redeclared here (the drift-test discipline, #387).

  const DIRECTION_LABEL = {
    "present-only-in-earlier": "present only in earlier",
    "present-only-in-later": "present only in later",
    changed: "changed",
  };

  const EXCLUSION_LABEL = {
    partial: "partial coverage",
    filtered: "a filter was applied",
    "ambiguous-identity": "ambiguous identity within its own inventory",
  };

  function orderLabel(order) {
    if (!order) return "—";
    return order.kind === "captured" ? esc(String(order.capturedAt)) : `sequence ${esc(String(order.sequence))}`;
  }

  function changeRow(change) {
    const dir = DIRECTION_LABEL[change.direction] || esc(change.direction);
    let key;
    try {
      key = JSON.parse(change.key);
    } catch {
      key = [change.key, ""];
    }
    const [technique, path] = Array.isArray(key) ? key : [String(key), ""];
    const valueText =
      change.direction === "present-only-in-earlier"
        ? `value: ${esc(String(change.earlierValue))}`
        : change.direction === "present-only-in-later"
          ? `value: ${esc(String(change.laterValue))}`
          : `${esc(String(change.earlierValue))} → ${esc(String(change.laterValue))}`;
    return (
      `<tr><td>${esc(dir)}</td><td>${esc(String(technique))}</td><td>${esc(String(path))}</td>` +
      `<td>${valueText}</td></tr>`
    );
  }

  function pairBlock(pair) {
    const count = pair.changes.length;
    const summary =
      `${orderLabel(pair.earlier.order)} → ${orderLabel(pair.later.order)} — ` +
      `${count} change${count === 1 ? "" : "s"}` +
      (pair.truncated ? " (truncated)" : "") +
      (pair.interveningExcludedCount > 0
        ? `, ${pair.interveningExcludedCount} excluded generation${pair.interveningExcludedCount === 1 ? "" : "s"} in between`
        : "");
    const rows = pair.changes.map(changeRow).join("");
    const table = pair.changes.length
      ? `<table class="cgd-changes"><thead><tr><th>Direction</th><th>Technique</th><th>Path</th><th>Value</th></tr></thead><tbody>${rows}</tbody></table>`
      : `<div class="cgd-none">No differences between these two generations.</div>`;
    return `<details class="cgd-pair"><summary>${esc(summary)}</summary>${table}</details>`;
  }

  function excludedBlock(cohort) {
    if (!cohort.excluded.length && !cohort.ambiguousOrder.length) return "";
    const excludedItems = cohort.excluded
      .map((e) => `<li>${esc(e.generationId)} — ${esc(EXCLUSION_LABEL[e.reason] || e.reason)}</li>`)
      .join("");
    const ambiguousItems = cohort.ambiguousOrder
      .map((a) => `<li>${esc(a.generationId)} — shares its order key with another generation; excluded from every pair</li>`)
      .join("");
    return (
      `<details class="cgd-excluded"><summary>${cohort.excluded.length + cohort.ambiguousOrder.length} generation(s) not compared</summary>` +
      `<ul>${excludedItems}${ambiguousItems}</ul></details>`
    );
  }

  function cohortBlock(cohort) {
    const header = `<div class="cgd-host"><strong>${esc(cohort.resolvedHost)}</strong> — ${esc(String(cohort.eligibleCount))} eligible generation(s)</div>`;
    if (!cohort.pairs.length) {
      return (
        header +
        `<div class="cgd-none">Not enough eligible, same-order-mode generations to compare yet.</div>` +
        excludedBlock(cohort)
      );
    }
    const pairsHtml = cohort.pairs.map(pairBlock).join("");
    const truncatedNote = cohort.truncatedPairs
      ? `<div class="cgd-truncated">Some pairs were omitted — this host has more eligible generations than fit in one response.</div>`
      : "";
    return header + pairsHtml + truncatedNote + excludedBlock(cohort);
  }

  // Pure: the whole section body as a string, testable without a DOM.
  function renderCollectionGenerationDiff() {
    if (status === "loading") return `<div class="cgd-none">Loading…</div>`;
    if (status === "error") {
      return `<div class="cgd-error">Could not load the collection generation comparison — try again shortly.</div>`;
    }
    if (status === "unconfigured" || !cohorts.length) {
      return `<div class="cgd-none">No host has two or more eligible, comparable persistence-collection generations yet.</div>`;
    }
    const truncNote = truncatedCohorts
      ? `<div class="cgd-truncated">Some hosts were omitted — this case has more compared hosts than fit in one response.</div>`
      : "";
    return cohorts.map(cohortBlock).join("") + truncNote;
  }

  function paintCollectionGenerationDiff() {
    const el = document.getElementById("collectionGenerationDiffBody");
    if (!el) return;
    el.innerHTML = renderCollectionGenerationDiff();
  }

  async function loadCollectionGenerationDiff(caseId) {
    if (!caseId) return;
    const seq = ++loadSeq;
    // Clear the PRIOR case's cohorts the moment a new load starts, before the request resolves —
    // otherwise the previous case's comparison stays on screen (through the case-switch overlay)
    // until this fetch completes, which can read as the wrong case's own data (Codex code-review
    // finding, Medium).
    status = "loading";
    paintCollectionGenerationDiff();
    try {
      const r = await fetch(`/cases/${encodeURIComponent(caseId)}/collection-generations/compare`);
      if (seq !== loadSeq) return; // superseded by a newer load — ignore entirely
      if (r.status === 501) {
        // The store is not configured — an honestly empty section, not an error.
        cohorts = [];
        truncatedCohorts = false;
        status = "unconfigured";
        paintCollectionGenerationDiff();
        return;
      }
      if (!r.ok) {
        status = "error";
        paintCollectionGenerationDiff();
        return;
      }
      const body = await r.json();
      if (seq !== loadSeq) return; // a stale success must not overwrite the newer case
      cohorts = Array.isArray(body.cohorts) ? body.cohorts : [];
      truncatedCohorts = Boolean(body.truncatedCohorts);
      status = "ready";
      paintCollectionGenerationDiff();
    } catch {
      if (seq !== loadSeq) return;
      status = "error";
      paintCollectionGenerationDiff();
    }
  }

  globalThis.renderCollectionGenerationDiff = renderCollectionGenerationDiff;
  globalThis.loadCollectionGenerationDiff = loadCollectionGenerationDiff;
})();
