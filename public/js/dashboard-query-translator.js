// Query Translator (natural language → hunt queries) (#415 tier 3).
//
// ONE OF THREE FEATURES UNDER ITS BANNER. The cohesion check reported clusters of 5, 4 and 1: this
// translator, the AI on/off toggle, and applyScope — which shares a heading with them and calls
// nothing here. All three are their own modules now.
//
// IIFE-WRAPPED BECAUSE IT OWNS THE PLATFORM TABLES: the label map and the display order for the
// query platforms it can translate into.
(function () {
  // ── Query Translator (natural language → hunt queries, #100) ──────────────────────────
  // The analyst types intent in plain English; the server makes one AI call that translates it
  // into a runnable query per selected platform, grounded in each platform's real schema. Results
  // are ephemeral (no state change). The Velociraptor query can be deployed via the existing hunt
  // flow (launchHuntInto). Platform keys + labels mirror huntPlatforms.ts / queryTranslate.ts.
  const NLQ_PLATFORM_LABELS = {
    velociraptor: "Velociraptor (VQL)",
    defender: "Defender / Sentinel (KQL)",
    elastic: "Elastic (ES|QL)",
    splunk: "Splunk (SPL)",
    sigma: "Sigma rule",
    yara: "YARA rule",
    suricata: "Suricata (network)",
  };
  const NLQ_PLATFORM_ORDER = [
    "velociraptor",
    "defender",
    "elastic",
    "splunk",
    "sigma",
    "yara",
    "suricata",
  ];

  // Render the platform picker from the server's enabled-platforms allowlist (set from /health).
  // All enabled platforms start checked. Re-rendered when /health arrives.
  function renderNlqPlatforms() {
    const el = document.getElementById("nlqPlatforms");
    if (!el) return;
    const order = NLQ_PLATFORM_ORDER.filter((p) => enabledHuntPlatforms.has(p));
    el.innerHTML = order
      .map(
        (p) =>
          `<label class="nlq-chip"><input type="checkbox" class="nlq-pf" value="${escAttr(p)}" checked>${esc(NLQ_PLATFORM_LABELS[p] || p)}</label>`,
      )
      .join("");
    el.querySelectorAll(".nlq-pf").forEach(
      (cb) =>
        (cb.onchange = () =>
          cb.closest(".nlq-chip").classList.toggle("off", !cb.checked)),
    );
  }

  function doTranslateQuery() {
    const caseId = document.getElementById("caseId").value.trim();
    const reqText = document.getElementById("nlqInput").value.trim();
    const box = document.getElementById("nlqResult");
    if (!caseId) {
      box.innerHTML = "<div class='nlq-empty'>connect to a case first</div>";
      return;
    }
    if (!reqText) return;
    const platforms = [
      ...document.querySelectorAll("#nlqPlatforms .nlq-pf:checked"),
    ].map((c) => c.value);
    if (!platforms.length) {
      box.innerHTML =
        "<div class='nlq-empty' data-safe-style='color:var(--sev-high)'>select at least one platform to translate into</div>";
      return;
    }
    const btn = document.getElementById("nlqBtn");
    btn.disabled = true;
    box.innerHTML =
      "<div class='nlq-empty'>translating… (one AI call across the selected platforms)</div>";
    fetch(`/cases/${caseId}/translate-query`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ request: reqText, platforms }),
    })
      .then((r) => r.json().then((j) => ({ ok: r.ok, j })))
      .then(({ ok, j }) => {
        if (!ok || j.error) {
          box.innerHTML = `<div class="nlq-empty" data-safe-style="color:var(--sev-high)">error: ${esc(j.error || "translation failed")} — restart the companion server if this 404s</div>`;
          return;
        }
        renderQueryTranslations(j);
      })
      .catch(
        (e) =>
          (box.innerHTML = `<div class="nlq-empty" data-safe-style="color:var(--sev-high)">error: ${esc(e.message)}</div>`),
      )
      .finally(() => {
        btn.disabled = false;
      });
  }

  function renderQueryTranslations(result) {
    const box = document.getElementById("nlqResult");
    const queries = (result && result.queries) || [];
    if (!queries.length) {
      box.innerHTML =
        "<div class='nlq-empty'>No queries produced — try rephrasing the request, or widen the selected platforms.</div>";
      return;
    }
    const interp = result.interpretation
      ? `<div class="nlq-interp">🧠 Interpreted as: ${esc(result.interpretation)}</div>`
      : "";
    const caveat = `<div class="nlq-caveat" data-safe-style="margin-bottom:8px">⚠ AI-generated queries — review each against your real schema before running. Deploying the Velociraptor query launches a hunt across ALL enrolled endpoints.</div>`;
    const cards = queries
      .map((q, idx) => {
        const label = q.label || NLQ_PLATFORM_LABELS[q.platform] || q.platform;
        const na = q.notApplicable || !q.query;
        const naBadge = na ? `<span class="nlq-na">not applicable</span>` : "";
        const expl = q.explanation
          ? `<div class="nlq-expl">${esc(q.explanation)}</div>`
          : "";
        const caveats = q.caveats
          ? `<div class="nlq-caveat">⚠ ${esc(q.caveats)}</div>`
          : "";
        const queryBlock = q.query
          ? `<textarea class="nlq-query" id="nlqQ${idx}" spellcheck="false">${esc(q.query)}</textarea>`
          : "";
        const deployBtn =
          q.platform === "velociraptor" && q.query
            ? veloEnabled
              ? `<button class="nlq-deploy" data-idx="${idx}" title="Launch this VQL as a hunt across ALL enrolled Velociraptor clients">▶ Deploy hunt (all clients)</button>`
              : `<button class="nlq-deploy" disabled title="Velociraptor API not configured — set the API config path in Settings → Integrations, then restart the server">▶ Deploy hunt (all clients)</button>`
            : "";
        // The AI wrote the Sigma rule; the VQL is deterministic (#798). Gated the way the hunt
        // modal's Sigma card is: on the velociraptor platform, since that is what it produces.
        const compileBtn =
          q.platform === "sigma" && q.query && enabledHuntPlatforms.has("velociraptor")
            ? `<button class="nlq-sigma-compile" data-idx="${idx}" title="Compile this Sigma rule to Velociraptor VQL — deterministic, no second AI call">Compile to VQL</button>`
            : "";
        const actions = q.query
          ? `<div class="nlq-actions"><button class="nlq-copy" data-idx="${idx}">Copy</button>${compileBtn}${deployBtn}</div><div class="nlq-res" id="nlqRes${idx}"></div>`
          : "";
        return (
          `<div class="nlq-card${na ? " na" : ""}">` +
          `<div class="nlq-head"><span class="nlq-platform">${esc(label)}</span>${naBadge}</div>` +
          expl +
          caveats +
          queryBlock +
          actions +
          `</div>`
        );
      })
      .join("");
    box.innerHTML = interp + caveat + `<div class="nlq-list">${cards}</div>`;
    box.querySelectorAll(".nlq-copy").forEach(
      (b) =>
        (b.onclick = () => {
          const q = document.getElementById("nlqQ" + b.dataset.idx);
          navigator.clipboard
            .writeText(q ? q.value : "")
            .then(() => {
              b.textContent = "Copied ✓";
              b.classList.add("copied");
              setTimeout(() => {
                b.textContent = "Copy";
                b.classList.remove("copied");
              }, 1500);
            })
            .catch(() => {
              b.textContent = "copy failed";
            });
        }),
    );
    box.querySelectorAll(".nlq-sigma-compile").forEach(
      (b) =>
        (b.onclick = () => {
          const q = document.getElementById("nlqQ" + b.dataset.idx);
          openSigmaCompileWith(q ? q.value : "", "Query translator — Sigma rule");
        }),
    );
    box.querySelectorAll(".nlq-deploy:not([disabled])").forEach(
      (b) =>
        (b.onclick = () => {
          const idx = b.dataset.idx;
          const q = document.getElementById("nlqQ" + idx);
          const label =
            (queries[idx] && queries[idx].label) ||
            "DFIR query-translator hunt";
          launchHuntInto(
            q ? q.value : "",
            label,
            document.getElementById("nlqRes" + idx),
            b,
          );
        }),
    );
  }

  // The two controls the page bound at module scope, plus the first render. In a <head> script
  // this would query #nlqBtn before it exists and bind nothing.
  function initQueryTranslator() {
    document.getElementById("nlqBtn").onclick = doTranslateQuery;
    document.getElementById("nlqInput").addEventListener("keydown", (e) => {
      if (e.key === "Enter") doTranslateQuery();
    });
    renderNlqPlatforms(); // initial render (refreshed when /health arrives)
  }
  window.initQueryTranslator = initQueryTranslator;
  window.renderNlqPlatforms = renderNlqPlatforms;
  window.doTranslateQuery = doTranslateQuery;
})();
