// Case templates and incident types — the template picker on the new-case modal, and what a chosen
// template implies (#415 tier 3).
//
// IIFE-WRAPPED BECAUSE IT OWNS TWO CACHES: the fetched template list and the incident-type list.
// Both were page-wide `let`s, and one of them — `_cachedTemplates` — was WRITTEN FROM ANOTHER
// MODULE: js/dashboard-save-template.js set it to null to invalidate after a save, reaching across
// the shared global lexical environment that a classic script's top-level bindings live in.
//
// That is the state escape this extraction had to close rather than publish. The owner exposes
// invalidateTemplateCache() and the saver calls it. Publishing the binding itself would have kept
// the coupling and just renamed it.
//
// Its 676-line banner is 597 lines of the page's shared wiring run with twenty-one guard stanzas
// threaded through it; none of that is this feature and none of it moved.
(function () {
  // Declared in the inline block until #415 tier 3, beside the collection-plan marks under a
  // keyboard-navigation banner. This module is its only reader.
  // Step id → analyst-facing label, mirroring COLLECTION_STEPS server-side. Kept here so the New
  // Case preview reads "EDR telemetry → Memory image" rather than raw ids.
  const CP_LABELS = {
    edr: "EDR telemetry",
    "windows-event-logs": "Windows event logs",
    "endpoint-triage": "Endpoint triage artifacts",
    memory: "Memory image",
    network: "Network traffic / IDS",
    "web-logs": "Web server access logs",
    m365: "Microsoft 365 / mailbox audit",
    identity: "Identity sign-in logs",
    "cloud-audit": "Cloud control-plane audit",
    siem: "SIEM / aggregated logs",
    sandbox: "Malware sandbox report",
    "super-timeline": "Super-timeline",
    "threat-scan": "Threat / YARA scan",
    "physical-access": "Physical access records",
  };

  // ── Case templates ────────────────────────────────────────────────────────────────────
  let _cachedTemplates = null;
  async function loadTemplates() {
    if (_cachedTemplates) return _cachedTemplates;
    try {
      const r = await fetch("/templates");
      _cachedTemplates = r.ok ? await r.json() : [];
    } catch {
      _cachedTemplates = [];
    }
    return _cachedTemplates;
  }
  // Incident types (#236) are a strict superset of the five BUILT-IN case templates — same
  // incidents, plus the expected-finding seeds and the synthesis hint. So the New Case dialog
  // offers ONE picker: every incident type, then any template the analyst saved themselves.
  // Listing the built-in templates too would show "Ransomware" twice, differing only in which one
  // does more. Option values are prefixed so the create call knows which field to send.
  let _cachedIncidentTypes = null;
  async function loadIncidentTypes() {
    if (_cachedIncidentTypes) return _cachedIncidentTypes;
    try {
      const r = await fetch("/incident-types");
      _cachedIncidentTypes = r.ok ? await r.json() : [];
    } catch {
      _cachedIncidentTypes = [];
    }
    return _cachedIncidentTypes;
  }
  async function populateTemplateSelect() {
    const sel = document.getElementById("ncTemplate");
    const [types, templates] = await Promise.all([
      loadIncidentTypes(),
      loadTemplates(),
    ]);
    // Remove all options except the first ("No incident type")
    while (sel.options.length > 1) sel.remove(1);
    const addGroup = (label, items, prefix) => {
      if (!items.length) return;
      const group = document.createElement("optgroup");
      group.label = label;
      for (const t of items) {
        const opt = document.createElement("option");
        opt.value = prefix + t.id;
        opt.textContent = (t.builtIn ? "" : "★ ") + t.name;
        group.appendChild(opt);
      }
      sel.appendChild(group);
    };
    addGroup("Incident types", types, "type:");
    addGroup(
      "Your saved templates",
      templates.filter((t) => !t.builtIn),
      "tpl:",
    );
  }
  // Resolve the picker's prefixed value back to { kind, def } against the right cache.
  function selectedNewCasePlaybook() {
    const raw = document.getElementById("ncTemplate").value || "";
    if (raw.startsWith("type:")) {
      const id = raw.slice(5);
      return {
        kind: "type",
        id,
        def: (_cachedIncidentTypes || []).find((t) => t.id === id),
      };
    }
    if (raw.startsWith("tpl:")) {
      const id = raw.slice(4);
      return {
        kind: "tpl",
        id,
        def: (_cachedTemplates || []).find((t) => t.id === id),
      };
    }
    return { kind: "", id: "", def: undefined };
  }
  function onTemplateSelectChange() {
    const descEl = document.getElementById("ncTemplateDesc");
    const { kind, def: t } = selectedNewCasePlaybook();
    if (t && t.description) {
      const hints = [];
      // For an incident type, the import ORDER is the guidance ("EDR first, then DC logs") —
      // show it instead of the unordered recommended-imports list a plain template carries.
      const imports =
        kind === "type" && t.recommendedImportOrder?.length
          ? {
              label: "Collect in order",
              value: t.recommendedImportOrder
                .map((id) => CP_LABELS[id] || id)
                .join(" → "),
            }
          : t.recommendedImports?.length
            ? { label: "Imports", value: t.recommendedImports.join(", ") }
            : null;
      if (imports) hints.push(esc(imports.label) + ": " + esc(imports.value));
      if (t.huntPlatforms?.length)
        hints.push("Platforms: " + esc(t.huntPlatforms.join(", ")));
      if (t.findingsSeeds?.length)
        hints.push(
          t.findingsSeeds.length + " expected findings to confirm/deny",
        );
      const hintText = hints.length ? " · " + hints.join(" · ") : "";
      descEl.innerHTML = esc(t.description) + hintText;
      descEl.style.display = "block";
    } else {
      descEl.style.display = "none";
    }
  }

  // Called by js/dashboard-save-template.js after a save. An accessor rather than a writable
  // binding: the cache is this module's, and the saver only needs to say 'it is stale now'.
  function invalidateTemplateCache() {
    _cachedTemplates = null;
  }

  window.loadTemplates = loadTemplates;
  window.loadIncidentTypes = loadIncidentTypes;
  window.populateTemplateSelect = populateTemplateSelect;
  window.selectedNewCasePlaybook = selectedNewCasePlaybook;
  window.onTemplateSelectChange = onTemplateSelectChange;
  window.invalidateTemplateCache = invalidateTemplateCache;
})();
