// IOC Whitelist (Phase 2 of #66) — the patterns an analyst marks as never-interesting, so
// known-good indicators stop being reported (#415 tier 3).
//
// ONE OF ITS SIX BINDINGS STAYED. wlApplyBtn calls wlApplyToCase, which is declared eighty lines
// below this block and did not move with it. initWhitelist() takes the other five.
(function () {
  // --- IOC Whitelist (Phase 2 of #35) — global known-good patterns, Settings → IOC Whitelist ----
  function renderWhitelist(rules) {
    const el = document.getElementById("wlList");
    const cnt = document.getElementById("wlCount");
    if (cnt) cnt.textContent = rules.length ? `(${rules.length})` : "";
    if (!el) return;
    if (!rules.length) {
      el.innerHTML =
        "<div data-safe-style='color:var(--text-muted);font-size:12px;padding:4px'>No rules yet — add one above or import.</div>";
      return;
    }
    el.innerHTML = rules
      .map((r) => {
        const type = r.iocType
          ? `<span data-safe-style="color:var(--text-muted)">${esc(r.iocType)}</span> `
          : "";
        const note = r.note
          ? ` <span data-safe-style="color:var(--text-dim)">— ${esc(r.note)}</span>`
          : "";
        return (
          `<div data-safe-style="display:flex;align-items:center;gap:6px;padding:2px 0;border-bottom:1px solid var(--border-subtle);font-size:12px">` +
          `<span data-safe-style="color:var(--accent);flex:0 0 46px">${esc(r.match)}</span>` +
          `<span data-safe-style="flex:1;font-family:monospace;word-break:break-all">${esc(r.pattern)}</span>` +
          `<span data-safe-style="flex:0 0 auto">${type}${note}</span>` +
          `<button class="wl-del" data-id="${escAttr(r.id)}" title="Delete rule" data-safe-style="background:transparent;border:1px solid var(--danger-border);color:var(--tag-red-text);border-radius:5px;padding:0 7px;cursor:pointer">✕</button>` +
          `</div>`
        );
      })
      .join("");
  }
  function loadWhitelist() {
    fetch("/ioc-whitelist")
      .then((r) => r.json())
      .then(renderWhitelist)
      .catch(() => {});
  }
  function wlAddRule() {
    const match = document.getElementById("wlMatch").value;
    const pattern = document.getElementById("wlPattern").value.trim();
    const iocType = document.getElementById("wlType").value;
    const note = document.getElementById("wlNote").value.trim();
    const msg = document.getElementById("wlMsg");
    if (!pattern) {
      msg.textContent = "pattern is required";
      return;
    }
    msg.textContent = "adding…";
    fetch("/ioc-whitelist", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ match, pattern, iocType, note }),
    })
      .then(async (r) => {
        if (!r.ok)
          throw new Error(
            (await r.json().catch(() => ({}))).error || "HTTP " + r.status,
          );
        return r.json();
      })
      .then(() => {
        document.getElementById("wlPattern").value = "";
        document.getElementById("wlNote").value = "";
        msg.textContent = "";
        loadWhitelist();
      })
      .catch((e) => {
        msg.textContent = e.message;
      });
  }
  function wlImport() {
    const text = document.getElementById("wlImportText").value;
    const msg = document.getElementById("wlMsg");
    if (!text.trim()) {
      msg.textContent = "paste CSV or JSON first";
      return;
    }
    msg.textContent = "importing…";
    fetch("/ioc-whitelist/import", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ text }),
    })
      .then(async (r) => {
        if (!r.ok)
          throw new Error(
            (await r.json().catch(() => ({}))).error || "HTTP " + r.status,
          );
        return r.json();
      })
      .then((j) => {
        msg.textContent = `imported ${j.added} new rule${j.added !== 1 ? "s" : ""} (${j.parsed} parsed)`;
        document.getElementById("wlImportText").value = "";
        loadWhitelist();
      })
      .catch((e) => {
        msg.textContent = e.message;
      });
  }
  function wlExport(format) {
    window.open(`/ioc-whitelist/export?format=${format}`, "_blank");
  }

  // Reunited with the feature it belongs to. It sat in the custom-importers block by position,
  // which is why the whitelist extraction had to leave its button wired in the page.
  function wlApplyToCase() {
    const caseId = document.getElementById("caseId").value.trim();
    const msg = document.getElementById("wlApplyMsg");
    if (!caseId) {
      msg.textContent = "load a case first";
      return;
    }
    msg.textContent = "applying…";
    fetch(`/cases/${caseId}/ioc-whitelist/apply`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: "{}",
    })
      .then(async (r) => {
        if (!r.ok)
          throw new Error(
            (await r.json().catch(() => ({}))).error || "HTTP " + r.status,
          );
        return r.json();
      })
      .then((j) => {
        msg.textContent = `${j.matched} matched · ${j.added} newly marked false positive`;
        if (j.legitimate) renderFalsePositives(j.legitimate);
      })
      .catch((e) => {
        msg.textContent =
          "failed: " +
          e.message +
          " — restart the server if the endpoint 404s.";
      });
  }

  // The controls the page bound at module scope. Order unchanged.
  function initWhitelist() {
    document
      .getElementById("wlApplyBtn")
      .addEventListener("click", wlApplyToCase);
    document.getElementById("wlAddBtn").addEventListener("click", wlAddRule);
    document.getElementById("wlPattern").addEventListener("keydown", (e) => {
      if (e.key === "Enter") wlAddRule();
    });
    document.getElementById("wlImportBtn").addEventListener("click", wlImport);
    document
      .getElementById("wlExportCsvBtn")
      .addEventListener("click", () => wlExport("csv"));
    document
      .getElementById("wlExportJsonBtn")
      .addEventListener("click", () => wlExport("json"));
  }

  window.loadWhitelist = loadWhitelist;
  window.wlAddRule = wlAddRule;
  window.wlImport = wlImport;
  window.wlExport = wlExport;
  window.wlApplyToCase = wlApplyToCase;
  window.initWhitelist = initWhitelist;
})();
