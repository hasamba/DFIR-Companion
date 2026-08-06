// Threat-intel enrichment (per-case provider toggles) — which enrichment providers are on for this
// case, and the modal that turns them on and off (#415 tier 3).
//
// IIFE-WRAPPED BECAUSE IT OWNS STATE: the provider list, whether enrichment is available at all,
// and the derived count the toggle label reads. In a CLASSIC script those would be page-wide
// globals — and `enrichProviders` is also an element id in the markup, which is exactly the kind of
// collision that makes a global named after a panel a bad idea.
//
// ITS WIRING IS AN INITIALIZER. Two controls were bound in the page's modal-wiring block by
// assigning the function as a VALUE — `enrichToggle.onclick = openEnrichModal` — so with the
// functions moved out a 404 here would throw while the page parses.
(function () {
  // ── Threat-intel enrichment — per-source selection (local on by default; external opt-in) ──
  let enrichProviders = []; // [{ name, scope, enabled }]
  let enrichAvailable = false;
  const enrichOnCount = () => enrichProviders.filter((p) => p.enabled).length;
  function renderEnrichToggle() {
    const b = document.getElementById("enrichToggle");
    if (!enrichAvailable) {
      b.textContent = "Enrich: n/a";
      b.classList.remove("on");
      b.classList.add("na");
      b.setAttribute(
        "data-tip",
        "No enrichment provider configured — set DFIR_* keys and restart.",
      );
      return;
    }
    b.classList.remove("na");
    const on = enrichOnCount();
    b.textContent = on ? `Enrich: ${on} on` : "Enrich: off";
    b.classList.toggle("on", on > 0);
  }
  function loadEnrichToggle(caseId) {
    fetch(`/cases/${caseId}/enrich-control`)
      .then((r) => {
        if (!r.ok) throw new Error("HTTP " + r.status);
        return r.json();
      })
      .then((c) => {
        enrichAvailable = !!c.anyConfigured;
        enrichProviders = c.providers || [];
        renderEnrichToggle();
      })
      .catch(() => {
        enrichAvailable = false;
        renderEnrichToggle();
      });
  }
  function openEnrichModal() {
    const caseId = document.getElementById("caseId").value.trim();
    if (!caseId) {
      document.getElementById("status").textContent = "connect to a case first";
      return;
    }
    if (!enrichAvailable) return;
    const row = (p) =>
      p.configured
        ? `<label data-safe-style="display:flex;align-items:center;gap:6px;font-size:13px;margin:3px 0">` +
          `<input type="checkbox" class="enrich-cb" value="${escAttr(p.name)}" data-scope="${escAttr(p.scope)}" ${p.enabled ? "checked" : ""}> ${esc(p.name)}` +
          `<span class="enrich-health" data-prov="${escAttr(p.name)}" title="checking reachability…" data-safe-style="color:#777;font-size:11px">●</span></label>`
        : `<label data-safe-style="display:flex;align-items:center;gap:6px;font-size:13px;margin:3px 0;opacity:0.45;cursor:not-allowed">` +
          `<input type="checkbox" class="enrich-cb" value="${escAttr(p.name)}" data-scope="${escAttr(p.scope)}" disabled> ${esc(p.name)}` +
          (p.keyHint
            ? `<span data-safe-style="color:#888;font-size:11px;font-style:italic">(key missing: ${esc(p.keyHint)})</span>`
            : "") +
          `</label>`;
    const group = (label, color, arr) =>
      arr.length
        ? `<div data-safe-style="margin-bottom:8px"><div class="asset-subhead" data-safe-style="margin:0 0 2px;color:${color}">${label}</div>${arr.map(row).join("")}</div>`
        : "";
    document.getElementById("enrichProviders").innerHTML =
      group(
        "Local — OPSEC-safe (your own instances)",
        "#6bcB77",
        enrichProviders.filter((p) => p.scope === "local"),
      ) +
        group(
          "External — third-party (sends indicators off-box)",
          "#ff9f43",
          enrichProviders.filter((p) => p.scope === "external"),
        ) ||
      "<em data-safe-style='color:var(--text-muted)'>No providers configured.</em>";
    document.getElementById("enrichMsg").textContent = "";
    document.getElementById("enrichOverlay").classList.add("open");
    loadEnrichHealth();
  }
  // Colour each provider's ● by reachability. Probed-down (MISP/YETI server off) → red with
  // the reason; reachable → green; external SaaS (no probe) → muted "no health check".
  function loadEnrichHealth() {
    fetch(`/enrich-health`)
      .then((r) => {
        if (!r.ok) throw new Error("HTTP " + r.status);
        return r.json();
      })
      .then((h) => {
        for (const p of h.providers || []) {
          const dot = document.querySelector(
            `.enrich-health[data-prov="${CSS.escape(p.name)}"]`,
          );
          if (!dot) continue;
          if (!p.probed) {
            dot.style.color = "#5b6472";
            dot.title = "no reachability check for this source";
          } else if (p.ok) {
            dot.style.color = "#6bcB77";
            dot.title = "reachable";
          } else {
            dot.style.color = "#ff6b6b";
            dot.title =
              "unreachable — IOCs are skipped until it's back" +
              (p.detail ? `: ${p.detail}` : "");
          }
        }
      })
      .catch(() => {
        document.querySelectorAll(".enrich-health").forEach((d) => {
          d.style.color = "#777";
          d.title = "reachability unknown";
        });
      });
  }
  function saveEnrich() {
    const caseId = document.getElementById("caseId").value.trim();
    const checked = [...document.querySelectorAll(".enrich-cb:checked")];
    const providers = checked.map((cb) => cb.value);
    const external = checked
      .filter((cb) => cb.getAttribute("data-scope") === "external")
      .map((cb) => cb.value);
    if (
      external.length &&
      !confirm(
        `Enable EXTERNAL source(s): ${external.join(", ")}?\n\n⚠ OPSEC: this sends the case's IOCs (hashes/IPs/domains/URLs) to third-party services — now and as new IOCs are found. Only enable if that's acceptable for this investigation. Local sources (MISP/YETI) stay on-box.`,
      )
    )
      return;
    const msg = document.getElementById("enrichMsg");
    msg.textContent = "saving…";
    fetch(`/cases/${caseId}/enrich-control`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ providers }),
    })
      .then((r) => {
        if (!r.ok) throw new Error("HTTP " + r.status);
        return r.json();
      })
      .then((c) => {
        const set = new Set(c.providers || []);
        enrichProviders = enrichProviders.map((p) => ({
          ...p,
          enabled: set.has(p.name),
        }));
        renderEnrichToggle();
        document.getElementById("enrichOverlay").classList.remove("open");
        document.getElementById("status").textContent = set.size
          ? `Enrichment: ${[...set].join(", ")} — checking IOCs (see AI status)`
          : "Enrichment off";
      })
      .catch((e) => (msg.textContent = "failed: " + e.message));
  }

  // The two controls the page's modal-wiring block used to bind.
  function initEnrichment() {
    document.getElementById("enrichToggle").onclick = openEnrichModal;
    document.getElementById("enrichSave").onclick = saveEnrich;
  }

  window.loadEnrichToggle = loadEnrichToggle;
  window.openEnrichModal = openEnrichModal;
  window.saveEnrich = saveEnrich;
  window.initEnrichment = initEnrichment;
})();
