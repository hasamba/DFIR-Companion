// Mark-false-positive modal — extracted from dashboard.html (issue #415, tier 3).
//
// Two ranges. fpTarget, the section's only escape, was read by six statements sitting 3,300
// lines away in the page's wiring block: the reason select, the Ask-AI button, the candidate
// list, cancel, the overlay backdrop and confirm. Every one of them is this modal's own
// control. Ownership follows use, so they are its initializer and fpTarget stays private.
//
// The boundary is exact at both ends — the statement before is the TAG modal's wiring and the
// one after is the hunt modal's guard stanza. Taking either would break a neighbour silently.
(function () {
  "use strict";

  // Reason + note capture, deterministic (+ optional AI) "similar items" suggestions,
  // and — for the single-IOC case — an option to promote the value into the global
  // IOC whitelist. Same overlay/modal structural pattern as the tag modal above.
  let fpTarget = null; // { kind, ref, label, extraRefs: [{kind, ref, label}], onDone? } while the modal is open

  function openFalsePositiveModal(kind, ref, label, extraRefs, onDone) {
    fpTarget = {
      kind,
      ref,
      label,
      extraRefs: extraRefs || [],
      onDone: onDone || null,
    };
    document.getElementById("fpReason").value = "known-good-tool";
    document.getElementById("fpNote").value = "";
    document.getElementById("fpNoteRequired").style.display = "none";
    // Bulk marks (extraRefs non-empty) skip the whitelist-promotion checkbox — the batch route
    // has no per-item addToWhitelist support (only the single-item route does); see the Confirm
    // handler below.
    document.getElementById("fpWhitelistRow").style.display =
      kind === "ioc" && !fpTarget.extraRefs.length ? "" : "none";
    document.getElementById("fpAddToWhitelist").checked = false;
    document.getElementById("fpMsg").textContent = "";
    document.getElementById("fpCandidates").innerHTML = "";
    document.getElementById("fpAskAiBtn").style.display = "none";
    document.getElementById("fpOverlay").classList.add("open");
    if (kind === "event" || kind === "finding") {
      document.getElementById("fpCandidates").innerHTML =
        "loading similar items…";
      const caseId = document.getElementById("caseId").value.trim();
      fetch(`/cases/${caseId}/false-positive/suggest`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ kind, ref }),
      })
        .then((r) => r.json())
        .then(renderFpCandidates)
        .catch(() => {
          document.getElementById("fpCandidates").innerHTML = "";
        });
      document.getElementById("fpAskAiBtn").style.display =
        typeof isFpAiConfigured === "function" && isFpAiConfigured()
          ? "inline-block"
          : "none";
    }
  }

  function renderFpCandidates(data) {
    const list = (data && data.candidates) || [];
    const el = document.getElementById("fpCandidates");
    if (!list.length) {
      el.innerHTML =
        "<div data-safe-style='color:var(--text-muted);font-size:12px'>No similar items found.</div>";
      return;
    }
    el.innerHTML =
      "<div data-safe-style='color:var(--text-muted);font-size:12px;margin-bottom:4px'>Also mark as false positive:</div>" +
      `<label data-safe-style="display:block;font-weight:600"><input type="checkbox" id="fpCandidatesSelectAll"> Select all (${list.length})</label>` +
      list
        .map(
          (c) =>
            `<label data-safe-style="display:block"><input type="checkbox" class="fp-candidate" value="${escAttr(c.id)}" data-kind="${escAttr(c.kind)}" data-label="${escAttr(c.label)}"> ${esc(c.label)} <span data-safe-style="color:var(--text-muted);font-size:11px">(${esc((c.reasons || []).join(", "))})</span></label>`,
        )
        .join("");
  }

  function closeFalsePositiveModal() {
    fpTarget = null;
    document.getElementById("fpOverlay").classList.remove("open");
  }

  // Six controls, all binding to markup that does not exist when a <head> script runs.
  function initFalsePositiveModal() {
    document.getElementById("fpReason").addEventListener("change", (e) => {
      document.getElementById("fpNoteRequired").style.display =
        e.target.value === "other" ? "inline" : "none";
    });
    document
      .getElementById("fpAskAiBtn")
      .addEventListener("click", async () => {
        if (!fpTarget) return;
        const btn = document.getElementById("fpAskAiBtn");
        btn.disabled = true;
        btn.textContent = "asking…";
        try {
          const caseId = document.getElementById("caseId").value.trim();
          const r = await fetch(`/cases/${caseId}/false-positive/suggest`, {
            method: "POST",
            headers: { "content-type": "application/json" },
            body: JSON.stringify({
              kind: fpTarget.kind,
              ref: fpTarget.ref,
              ai: true,
            }),
          });
          renderFpCandidates(await r.json());
        } finally {
          btn.disabled = false;
          btn.textContent = "🔎 Ask AI for similar";
        }
      });
    // Select-all for the AI/deterministic candidate list (re-rendered on open + "Ask AI for
    // more", so this listener is delegated on the static container rather than re-bound per render).
    document.getElementById("fpCandidates").addEventListener("change", (e) => {
      const candidates = [...document.querySelectorAll(".fp-candidate")];
      if (e.target.id === "fpCandidatesSelectAll") {
        candidates.forEach((cb) => {
          cb.checked = e.target.checked;
        });
        return;
      }
      if (e.target.classList.contains("fp-candidate")) {
        const sa = document.getElementById("fpCandidatesSelectAll");
        if (sa) {
          sa.checked = candidates.every((cb) => cb.checked);
          sa.indeterminate = candidates.some((cb) => cb.checked) && !sa.checked;
        }
      }
    });
    document
      .getElementById("fpCancelBtn")
      .addEventListener("click", closeFalsePositiveModal);
    document.getElementById("fpOverlay").addEventListener("click", (e) => {
      if (e.target.id === "fpOverlay") closeFalsePositiveModal();
    });
    document
      .getElementById("fpConfirmBtn")
      .addEventListener("click", async () => {
        if (!fpTarget) return;
        const reason = document.getElementById("fpReason").value;
        const note = document.getElementById("fpNote").value.trim();
        if (reason === "other" && !note) {
          document.getElementById("fpMsg").textContent =
            "a note is required for 'Other'";
          return;
        }
        const checked = [
          ...document.querySelectorAll(".fp-candidate:checked"),
        ].map((cb) => ({
          kind: cb.dataset.kind,
          ref: cb.value,
          label: cb.dataset.label,
        }));
        const items = [
          { kind: fpTarget.kind, ref: fpTarget.ref, label: fpTarget.label },
          ...fpTarget.extraRefs,
          ...checked,
        ];
        // The batch route (items.length > 1) has no per-item addToWhitelist support — only the
        // single-item /false-positive route does — so whitelist promotion is offered (and honored)
        // only for a true single-item mark of an IOC; see openFalsePositiveModal's fpWhitelistRow
        // visibility rule above.
        const addToWhitelist =
          fpTarget.kind === "ioc" &&
          !fpTarget.extraRefs.length &&
          document.getElementById("fpAddToWhitelist").checked;
        const caseId = document.getElementById("caseId").value.trim();
        const onDone = fpTarget.onDone;
        document.getElementById("fpMsg").textContent =
          `marking ${items.length} false positive…`;
        try {
          let markers;
          if (items.length === 1) {
            const r = await fetch(`/cases/${caseId}/false-positive`, {
              method: "POST",
              headers: { "content-type": "application/json" },
              body: JSON.stringify({
                ...items[0],
                reason,
                note,
                addToWhitelist,
              }),
            });
            if (!r.ok) throw new Error("HTTP " + r.status);
            markers = await r.json();
          } else {
            const r = await fetch(`/cases/${caseId}/false-positive/batch`, {
              method: "POST",
              headers: { "content-type": "application/json" },
              body: JSON.stringify({ items, reason, note }),
            });
            if (!r.ok) throw new Error("HTTP " + r.status);
            markers = await r.json();
          }
          renderFalsePositives(markers);
          closeFalsePositiveModal();
          if (onDone) onDone();
          document.getElementById("status").textContent =
            "marked false positive — AI is re-synthesizing (see AI status)";
        } catch (err) {
          document.getElementById("fpMsg").textContent =
            `error: ${err.message}`;
        }
      });
  }

  window.initFalsePositiveModal = initFalsePositiveModal;
  window.openFalsePositiveModal = openFalsePositiveModal;
  window.closeFalsePositiveModal = closeFalsePositiveModal;
  window.renderFpCandidates = renderFpCandidates;
})();
