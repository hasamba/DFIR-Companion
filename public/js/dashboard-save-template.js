// Save as Template — turn the current case's report layout into a reusable template (#415 tier 3).
//
// Two controls, both bound in the page's shared modal-wiring block by assigning the function as a
// VALUE, so the page would have read two names from a possibly-missing file while it parsed.
(function () {
  // ── Save as Template ──────────────────────────────────────────────────────────────────
  function openSaveTemplate() {
    document.getElementById("stName").value = "";
    document.getElementById("stDesc").value = "";
    document.getElementById("stMsg").textContent = "";
    document.getElementById("saveTemplateOverlay").classList.add("open");
    document.getElementById("stName").focus();
  }
  function closeSaveTemplate() {
    document.getElementById("saveTemplateOverlay").classList.remove("open");
  }
  async function saveAsTemplate() {
    const name = document.getElementById("stName").value.trim();
    const description = document.getElementById("stDesc").value.trim();
    const msg = document.getElementById("stMsg");
    if (!name) {
      msg.textContent = "template name is required";
      return;
    }
    const caseId = document.getElementById("caseId").value.trim();
    if (!caseId) {
      msg.textContent = "no case loaded";
      return;
    }
    msg.textContent = "saving…";
    try {
      // Collect the current case's key questions to pre-populate the template
      const state = await fetch(
        `/cases/${encodeURIComponent(caseId)}/state`,
      ).then((r) => (r.ok ? r.json() : null));
      const initialKeyQuestions = (state?.keyQuestions ?? [])
        .map((q) => q.question)
        .filter(Boolean);
      const res = await fetch("/templates", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          name,
          description,
          initialKeyQuestions,
          recommendedImports: [],
          huntPlatforms: [],
          severityFloor: null,
        }),
      });
      if (res.status === 201) {
        _cachedTemplates = null; // invalidate cache
        closeSaveTemplate();
        document.getElementById("status").textContent = "template saved";
      } else {
        const body = await res.json().catch(() => ({}));
        msg.textContent =
          "save failed: HTTP " +
          res.status +
          (body.error ? " — " + body.error : "");
      }
    } catch (err) {
      msg.textContent = "save failed: " + err.message;
    }
  }

  // The controls the page bound at module scope. Order unchanged.
  function initSaveTemplate() {
    document.getElementById("stSave").onclick = saveAsTemplate;
    document.getElementById("stCancel").onclick = closeSaveTemplate;
    document
      .getElementById("saveTemplateOverlay")
      .addEventListener("click", (e) => {
        if (e.target.id === "saveTemplateOverlay") closeSaveTemplate();
      });
  }

  window.openSaveTemplate = openSaveTemplate;
  window.closeSaveTemplate = closeSaveTemplate;
  window.saveAsTemplate = saveAsTemplate;
  window.initSaveTemplate = initSaveTemplate;
})();
