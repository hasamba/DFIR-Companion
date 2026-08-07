// Multi-select (session-only) and the bulk actions on it — the selection bars for events and IOCs,
// and starring, tagging or marking a whole selection false-positive (#415 tier 3).
//
// The selection itself lives in DfirSelection (js/dashboard-selection.js, tier 2); this is the UI
// over it. NO INITIALIZER: the bars are re-rendered on every selection change, so their buttons are
// wired at render time, which is where they have to be.
(function () {
  // --- Multi-select (session-only, cleared on re-render) ----------------------
  // The three selections moved to js/dashboard-selection.js as DfirSelection (#415, tier 2).
  function updateBulkBar() {
    const bar = document.getElementById("evBulkBar");
    if (!bar) return;
    if (DfirSelection.events.count() > 0) {
      bar.classList.add("active");
      document.getElementById("evBulkCount").textContent =
        `${DfirSelection.events.count()} event${DfirSelection.events.count() !== 1 ? "s" : ""} selected`;
    } else {
      bar.classList.remove("active");
    }
  }
  function clearSelection() {
    DfirSelection.events.clear();
    updateBulkBar();
    renderTimelineEvents(DfirState.lastFt());
    swSelToolbar();
    swRenderCanvas();
  }
  function updateIocBulkBar() {
    const bar = document.getElementById("iocBulkBar");
    if (!bar) return;
    if (DfirSelection.iocs.count() > 0) {
      bar.classList.add("active");
      document.getElementById("iocBulkCount").textContent =
        `${DfirSelection.iocs.count()} IOC${DfirSelection.iocs.count() !== 1 ? "s" : ""} selected`;
    } else {
      bar.classList.remove("active");
    }
  }
  function clearIocSelection() {
    DfirSelection.iocs.clear();
    if (DfirState.lastState()) renderIocs(DfirState.lastState().iocs || []);
  }
  // Bulk star/unstar N events: any unstarred → star all, else unstar all. SERIALIZED requests —
  // TagsStore.add() is read-modify-write on tags.json (same reason addTag()'s bulk mode awaits
  // each call). Set updates are reconciled into the UI by the per-tag ws broadcasts and the final loadTags().
  async function bulkStarIds(caseId, ids, msgEl) {
    if (!caseId || !ids.length) return;
    const anyUnstarred = ids.some((id) => !DfirStarred.has(id));
    try {
      for (let i = 0; i < ids.length; i++) {
        const id = ids[i];
        if (msgEl) {
          msgEl.style.color = "var(--text-muted)";
          msgEl.textContent = `${anyUnstarred ? "starring" : "unstarring"}… (${i + 1}/${ids.length})`;
        }
        if (anyUnstarred && !DfirStarred.has(id)) {
          const r = await fetch(`/cases/${caseId}/tags`, {
            method: "POST",
            headers: { "content-type": "application/json" },
            body: JSON.stringify({
              targetType: "event",
              targetId: id,
              author: investigatorName(),
              label: "starred",
            }),
          });
          if (!r.ok) throw new Error("HTTP " + r.status);
          DfirStarred.toggle(id, true);
        } else if (!anyUnstarred && starredTagIds.has(id)) {
          const r = await fetch(
            `/cases/${caseId}/tags/${encodeURIComponent(starredTagIds.get(id))}`,
            { method: "DELETE" },
          );
          if (!r.ok && r.status !== 404) throw new Error("HTTP " + r.status); // 404 = already gone
          DfirStarred.toggle(id, false);
        }
      }
      if (msgEl) msgEl.textContent = "";
    } catch (e) {
      if (msgEl) {
        msgEl.style.color = "var(--badge-danger-text)";
        msgEl.textContent = "star failed: " + e.message;
      }
    }
    loadTags(caseId); // reconcile + refresh both timelines (loadTags reloads the super view)
  }
  function bulkToggleStar() {
    const caseId = document.getElementById("caseId").value.trim();
    bulkStarIds(
      caseId,
      DfirSelection.events.ids(),
      document.getElementById("evBulkCount"),
    );
  }
  function openBulkTagModal(ids, targetType) {
    // Asked of the tags feature rather than assigned into it: tagTarget is its state.
    if (typeof setBulkTagTarget === "function")
      setBulkTagTarget(ids, targetType);
    document.getElementById("tagOverlay").classList.add("open");
    renderTagModal();
    document.getElementById("tagInput").focus();
  }
  // Mark every selected event as a false positive (benign, excluded from analysis) in ONE
  // request — the /false-positive/batch route writes all markers with a single
  // read-modify-write and a single re-synthesis, avoiding the race (and N re-synths) of firing
  // one /false-positive call per event. Opens the mark-FP modal on the first selected event as
  // the anchor (for the similarity suggestions); the rest ride along as extraRefs regardless of
  // what's checked in the modal.
  function bulkMarkFalsePositive() {
    const caseId = document.getElementById("caseId").value.trim();
    if (!caseId || !DfirSelection.events.count()) return;
    const ids = DfirSelection.events.ids();
    const descById = new Map(
      (DfirState.lastFt() || []).map((e) => [
        String(e.id),
        String(e.description || ""),
      ]),
    );
    const [firstId, ...restIds] = ids;
    const extraRefs = restIds.map((id) => ({
      kind: "event",
      ref: id,
      label: descById.get(id) ?? "",
    }));
    openFalsePositiveModal(
      "event",
      firstId,
      descById.get(firstId) ?? "",
      extraRefs,
      () => {
        DfirSelection.events.clear();
        renderTimelineEvents(DfirState.lastFt());
        swSelToolbar();
        swRenderCanvas(); // clear the rings + hide the swimlane selection bar
      },
    );
  }

  window.updateBulkBar = updateBulkBar;
  window.clearSelection = clearSelection;
  window.updateIocBulkBar = updateIocBulkBar;
  window.clearIocSelection = clearIocSelection;
  window.bulkStarIds = bulkStarIds;
  window.bulkToggleStar = bulkToggleStar;
  window.openBulkTagModal = openBulkTagModal;
  window.bulkMarkFalsePositive = bulkMarkFalsePositive;
})();
