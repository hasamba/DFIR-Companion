// Per-case report-template picker — which global report template this case renders with
// (#415 tier 3).
//
// One control, bound by passing saveCaseTemplate as a VALUE.
(function () {
  // --- Per-case report-template picker (in Case Details) -------------------------------
  // A push re-reads the picker (#1691), and the hub echoes every push to its sender too. A response
  // paints only if it is the newest load, the analyst picked nothing since it started, and its case
  // is still the open one — rapid picks otherwise race and the older choice can win the paint.
  let pickerLoadGen = 0;
  let pickerEditGen = 0;
  function refreshCaseTemplatePicker() {
    const caseId = document.getElementById("caseId").value.trim();
    if (caseId) loadCaseTemplatePicker(caseId);
  }
  function loadCaseTemplatePicker(caseId) {
    const sel = document.getElementById("rm-reportTemplate");
    if (!sel) return;
    const load = ++pickerLoadGen;
    const editsAtStart = pickerEditGen;
    Promise.all([
      fetch("/report-templates")
        .then((r) => (r.ok ? r.json() : []))
        .catch(() => []),
      fetch(`/cases/${encodeURIComponent(caseId)}/report-template`)
        .then((r) => (r.ok ? r.json() : { templateId: "standard" }))
        .catch(() => ({ templateId: "standard" })),
    ]).then(([list, ctrl]) => {
      if (load !== pickerLoadGen || editsAtStart !== pickerEditGen) return;
      if (document.getElementById("caseId").value.trim() !== caseId) return;
      const templates = Array.isArray(list) ? list : [];
      sel.innerHTML = templates
        .map(
          (t) =>
            `<option value="${escAttr(t.id)}">${esc(t.name || t.id)}</option>`,
        )
        .join("");
      // If the saved selection was since deleted, show the default (the report already falls back to it).
      const want = ctrl.templateId || "standard";
      sel.value = templates.some((t) => t.id === want) ? want : "standard";
    });
  }
  function saveCaseTemplate() {
    const caseId = document.getElementById("caseId").value.trim();
    if (!caseId) return;
    pickerEditGen++;
    const templateId = document.getElementById("rm-reportTemplate").value;
    fetch(`/cases/${encodeURIComponent(caseId)}/report-template`, {
      method: "PUT",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ templateId }),
    }).catch(() => {});
  }

  // The controls the page bound at module scope. Order unchanged.
  function initCaseTemplatePicker() {
    document
      .getElementById("rm-reportTemplate")
      .addEventListener("change", saveCaseTemplate);
  }

  window.loadCaseTemplatePicker = loadCaseTemplatePicker;
  window.refreshCaseTemplatePicker = refreshCaseTemplatePicker;
  window.saveCaseTemplate = saveCaseTemplate;
  window.initCaseTemplatePicker = initCaseTemplatePicker;
})();
