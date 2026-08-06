// Manual add (event / IOC / finding typed in by hand) (#415 tier 3).
//
// One helper — postManual, the shared POST-and-report used by all three forms — and eight
// statements of listener wiring. The helper stays in the module body; the wiring becomes the
// initializer, because in a <head> script it would query the three forms before they exist.
(function () {
  function postManual(url, body, msgId, onOk) {
    const el = document.getElementById(msgId);
    el.textContent = "saving…";
    fetch(url, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(body),
    })
      .then(async (r) => {
        const j = await r.json().catch(() => ({}));
        if (!r.ok) throw new Error(j.error || "HTTP " + r.status);
        return j;
      })
      .then(() => {
        el.textContent = "added ✓";
        if (onOk) onOk();
        setTimeout(() => {
          el.textContent = "";
        }, 2500);
      })
      .catch((e) => {
        el.textContent = "failed: " + e.message;
      });
  }

  // The statements the inline block ran at module scope, in their original order.
  function initManualAdd() {
    document.getElementById("addEventBtn").onclick = () => {
      const caseId = document.getElementById("caseId").value.trim();
      if (!caseId) return;
      const desc = document.getElementById("meDesc").value.trim();
      if (!desc) {
        document.getElementById("addEventMsg").textContent =
          "description required";
        return;
      }
      const tIn = document.getElementById("meTime").value;
      const body = {
        timestamp: utcInputToIso(tIn) || new Date().toISOString(), // picker is UTC; blank → now (UTC)
        description: desc,
        severity: document.getElementById("meSev").value,
        asset: document.getElementById("meAsset").value.trim(),
        mitreTechniques: document.getElementById("meMitre").value.trim(),
      };
      postManual(
        `/cases/${encodeURIComponent(caseId)}/events`,
        body,
        "addEventMsg",
        () => {
          document.getElementById("meDesc").value = "";
          document.getElementById("meAsset").value = "";
          document.getElementById("meMitre").value = "";
        },
      );
    };
    document.getElementById("addIocBtn").onclick = () => {
      const caseId = document.getElementById("caseId").value.trim();
      if (!caseId) return;
      const value = document.getElementById("miValue").value.trim();
      if (!value) {
        document.getElementById("addIocMsg").textContent = "value required";
        return;
      }
      const note = document.getElementById("miNote").value.trim();
      const body = {
        type: document.getElementById("miType").value,
        value,
        ...(note ? { note } : {}),
      };
      postManual(
        `/cases/${encodeURIComponent(caseId)}/iocs`,
        body,
        "addIocMsg",
        () => {
          document.getElementById("miValue").value = "";
          document.getElementById("miNote").value = "";
        },
      );
    };
    document.getElementById("runCustomerExposure").onclick =
      runCustomerExposureCheck;
    // Chip inputs: Enter adds a domain/email (auto-saved + checked); clicking a chip's × removes it.
    document
      .getElementById("ceDomainInput")
      .addEventListener("keydown", (e) => {
        if (e.key === "Enter") {
          e.preventDefault();
          ceAddTarget("domain", e.target.value);
          e.target.value = "";
        }
      });
    document.getElementById("ceEmailInput").addEventListener("keydown", (e) => {
      if (e.key === "Enter") {
        e.preventDefault();
        ceAddTarget("email", e.target.value);
        e.target.value = "";
      }
    });
    document.getElementById("ceDomainChips").addEventListener("click", (e) => {
      const x = e.target.closest(".x");
      if (x) ceRemoveTarget(x.dataset.kind, x.dataset.val);
    });
    document.getElementById("ceEmailChips").addEventListener("click", (e) => {
      const x = e.target.closest(".x");
      if (x) ceRemoveTarget(x.dataset.kind, x.dataset.val);
    });
    document.getElementById("ceProviders").addEventListener("change", (e) => {
      if (e.target.classList && e.target.classList.contains("ce-prov"))
        ceAutosaveTargets();
    });
  }

  window.initManualAdd = initManualAdd;
})();
