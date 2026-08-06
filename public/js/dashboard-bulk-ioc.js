// Bulk IOC operations — enrich, tag or mark false-positive across a multi-selection of IOCs
// (#415 tier 3).
//
// The sibling of the event bulk-operations module beside it. They share a selection store
// (DfirSelection) and nothing else.
(function () {
  // --- Bulk IOC operations -------------------------------------------------------
  async function bulkEnrichIocs() {
    const caseId = document.getElementById("caseId").value.trim();
    if (!caseId || !DfirSelection.iocs.count()) return;
    const ids = DfirSelection.iocs.ids();
    const statusEl = document.getElementById("status");
    statusEl.textContent = `enriching ${ids.length} IOC${ids.length !== 1 ? "s" : ""}…`;
    try {
      const r = await fetch(`/cases/${caseId}/iocs/bulk-enrich`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ iocIds: ids }),
      });
      if (!r.ok) {
        const e = await r.json().catch(() => ({}));
        throw new Error(e.error || "HTTP " + r.status);
      }
      statusEl.textContent = `enrichment started for ${ids.length} IOC${ids.length !== 1 ? "s" : ""} (see AI status)`;
    } catch (e) {
      statusEl.textContent = "enrich failed: " + e.message;
    }
  }
  function bulkTagIocs() {
    if (DfirSelection.iocs.count())
      openBulkTagModal(DfirSelection.iocs.ids(), "ioc");
  }
  // Opens the mark-FP modal on the first selected IOC as the anchor; the rest ride along as
  // extraRefs regardless of what's checked in the modal (bulk IOC marking has no per-item
  // whitelist-promotion — see the "Confirm" handler's addToWhitelist note).
  function bulkMarkIocsFalsePositive() {
    const caseId = document.getElementById("caseId").value.trim();
    if (!caseId || !DfirSelection.iocs.count()) return;
    const ids = DfirSelection.iocs.ids();
    const iocById = new Map(
      (DfirState.lastState()?.iocs || []).map((i) => [i.id, i.value]),
    );
    const [firstId, ...restIds] = ids;
    const firstVal = iocById.get(firstId) ?? firstId;
    const extraRefs = restIds.map((id) => ({
      kind: "ioc",
      ref: iocById.get(id) ?? id,
      label: iocById.get(id) ?? id,
    }));
    openFalsePositiveModal("ioc", firstVal, firstVal, extraRefs, () => {
      DfirSelection.iocs.clear();
      if (DfirState.lastState()) renderIocs(DfirState.lastState().iocs || []);
    });
  }

  window.bulkEnrichIocs = bulkEnrichIocs;
  window.bulkTagIocs = bulkTagIocs;
  window.bulkMarkIocsFalsePositive = bulkMarkIocsFalsePositive;
})();
