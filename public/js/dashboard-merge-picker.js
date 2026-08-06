// Generic merge-target picker — choosing which case to merge the current one into (#415 tier 3).
//
// Its four controls were bound at module scope; the two guard stanzas that follow them in this
// range belong to the asset-overrides and ticket-integration extractions and stay in the page.
(function () {
  // ── Generic merge-target picker modal (#82) — used for both asset merge and IOC merge. Shows
  // a filterable, click-to-select list of same-type candidates instead of asking the analyst to
  // type an id/value by hand.
  let mergeTarget = null; // { candidates: [{id, label}], selectedId, onConfirm(selectedId) }
  function renderMergeCandidates() {
    const term = document
      .getElementById("mergeSearch")
      .value.trim()
      .toLowerCase();
    const list = mergeTarget.candidates.filter(
      (c) => !term || c.label.toLowerCase().includes(term),
    );
    const el = document.getElementById("mergeCandidates");
    if (!list.length) {
      el.innerHTML =
        "<div data-safe-style='color:var(--text-muted);font-size:12px;padding:4px'>No matching candidates.</div>";
      return;
    }
    el.innerHTML = list
      .map((c) => {
        const selected = c.id === mergeTarget.selectedId;
        return `<div class="merge-candidate-row" data-id="${escAttr(c.id)}" data-safe-style="cursor:pointer;padding:5px 8px;border-radius:6px;border:1px solid ${selected ? "var(--sev-low)" : "var(--border-color)"};background:${selected ? "rgba(107,203,119,0.12)" : "transparent"}">${esc(c.label)}</div>`;
      })
      .join("");
  }
  function openMergeModal(title, candidates, onConfirm) {
    mergeTarget = { candidates, selectedId: null, onConfirm };
    document.getElementById("mergeTitle").textContent = title;
    document.getElementById("mergeSearch").value = "";
    document.getElementById("mergeMsg").textContent = "";
    document.getElementById("mergeConfirmBtn").disabled = true;
    renderMergeCandidates();
    document.getElementById("mergeOverlay").classList.add("open");
    document.getElementById("mergeSearch").focus();
  }
  function closeMergeModal() {
    mergeTarget = null;
    document.getElementById("mergeOverlay").classList.remove("open");
  }

  // The controls the inline block bound at module scope.
  function initMergePicker() {
    document.getElementById("mergeSearch").addEventListener("input", () => {
      if (mergeTarget) renderMergeCandidates();
    });
    document
      .getElementById("mergeCandidates")
      .addEventListener("click", (e) => {
        const row = e.target.closest(".merge-candidate-row");
        if (!row || !mergeTarget) return;
        mergeTarget.selectedId = row.dataset.id;
        document.getElementById("mergeConfirmBtn").disabled = false;
        renderMergeCandidates();
      });
    document.getElementById("mergeCancelBtn").onclick = closeMergeModal;
    document.getElementById("mergeConfirmBtn").onclick = () => {
      if (!mergeTarget || !mergeTarget.selectedId) return;
      const { selectedId, onConfirm } = mergeTarget;
      document.getElementById("mergeMsg").textContent = "merging…";
      Promise.resolve(onConfirm(selectedId))
        .then(() => closeMergeModal())
        .catch((err) => {
          document.getElementById("mergeMsg").textContent = "failed: " + err;
        });
    };
  }

  window.openMergeModal = openMergeModal;
  window.initMergePicker = initMergePicker;
})();
