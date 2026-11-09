// Preview what the AI will see (#2491) — the first request an AI action would send, before it runs.
//
// The server runs the REAL action and stops it at the AI-call gate: nothing is sent to a provider,
// nothing is spent and nothing in the case changes. This dialog shows the clear text and the masked
// text side by side, highlights the masked tokens, and shows the system prompt (sent unmasked).
//
// Everything rendered here is case text — adversary-controlled — so every value goes through esc().
// IIFE-wrapped: in a classic script anything at this level would join the shared global scope.
// No load-time work: initAiPreview() is called from the page's guarded initializer list.
(function () {
  // [key, label, params] — params name the inputs the action needs (none for most).
  const ACTIONS = [
    ["synthesis", "Synthesis", []],
    ["deep-pass", "Deep pass", ["minSeverity"]],
    ["second-look", "Second look", []],
    ["second-opinion", "Second opinion", []],
    ["second-opinion-referee", "Second opinion — re-run the referee", []],
    ["narrative", "Narrative timeline", []],
    ["executive-summary", "Executive summary", []],
    ["remediation-plan", "Remediation plan", []],
    ["hypothesis-review", "Hypothesis review", []],
    ["explain-event", "Explain event", ["eventId"]],
    ["starred-report", "Starred events report", []],
    ["view-summary", "Summarize the current super-timeline view", []],
    ["session-summary", "Session summary", ["sessionId"]],
    ["ask", "Ask the case", ["question"]],
    ["velociraptor-hunts", "Velociraptor hunt suggestions", []],
    ["technique-hunt", "Hunt for one ATT&CK technique", ["techniqueId", "techniqueName"]],
    ["memory-next-steps", "Memory forensics next steps", []],
    ["gap-hypotheses", "Timeline gap hypotheses", []],
    ["translate-query", "Translate a query", ["request"]],
    ["tagger-rule", "Suggest a tagger rule", ["description"]],
    ["fp-similar", "Find similar false positives (AI pass)", ["kind", "ref"]],
  ];
  const PARAM_LABELS = {
    minSeverity: "Lowest severity to read",
    eventId: "Event id",
    sessionId: "Session id",
    question: "Question",
    techniqueId: "ATT&CK technique id (e.g. T1021.002)",
    techniqueName: "Technique name (optional)",
    request: "What to search for",
    description: "Rule description",
    kind: "Event or finding",
    ref: "Event or finding id",
  };
  const PRESIDIO_TEXT = {
    off: "Presidio does not run on this request (not configured, off for this case, or anonymization is off).",
    "not-gated": "Presidio is not run on this request — an import pre-scan already covered it.",
    clear: "Presidio found nothing new to hold.",
    "would-hold": "The real request would stop here and ask you to approve these values first:",
    "scan-failed": "The real request would stop here — the Presidio scan cannot run:",
  };

  const $ = (id) => document.getElementById(id);
  const caseNow = () =>
    typeof currentCase === "function" ? currentCase() : ($("caseId") || { value: "" }).value.trim();

  function paramInput(name) {
    const id = `aiPreviewParam-${name}`;
    let input;
    if (name === "minSeverity") {
      input = `<select id="${id}">${["Critical", "High", "Medium", "Low"]
        .map((s) => `<option${s === "Medium" ? " selected" : ""}>${s}</option>`)
        .join("")}</select>`;
    } else if (name === "kind") {
      input = `<select id="${id}"><option value="event">event</option><option value="finding">finding</option></select>`;
    } else {
      input = `<input id="${id}" type="text" data-safe-style="flex:1" />`;
    }
    return `<label class="ai-preview-param"><span>${esc(PARAM_LABELS[name] || name)}</span>${input}</label>`;
  }

  function renderParams() {
    const entry = ACTIONS.find((a) => a[0] === $("aiPreviewAction").value);
    $("aiPreviewParams").innerHTML = entry ? entry[2].map(paramInput).join("") : "";
  }

  function collectParams(key) {
    const entry = ACTIONS.find((a) => a[0] === key);
    const params = {};
    for (const name of entry ? entry[2] : []) {
      const el = $(`aiPreviewParam-${name}`);
      if (el && el.value.trim()) params[name] = el.value.trim();
    }
    // Ask sends the panel's current thread with the question, exactly as the Ask button does.
    if (key === "ask" && typeof window.askHistoryFor === "function")
      params.history = window.askHistoryFor(caseNow());
    // The view summary reads exactly the filters the super-timeline is showing, minus pagination.
    if (key === "view-summary" && typeof window.superQueryString === "function") {
      const p = new URLSearchParams(window.superQueryString());
      p.delete("offset");
      p.delete("limit");
      Object.assign(params, Object.fromEntries(p.entries()));
    }
    return params;
  }

  // Masked tokens (ANON_HOST_1, ANON_USER_2, …) highlighted in the masked pane.
  function highlightTokens(text) {
    return esc(text).replace(/ANON_[A-Z]+_\d+/gi, (t) => `<mark class="ai-preview-token">${t}</mark>`);
  }

  function pane(title, html) {
    return `<div class="ai-preview-pane"><div class="asset-subhead">${esc(title)}</div><pre>${html}</pre></div>`;
  }

  function renderCall(d) {
    const c = d.call;
    const images = c.images.length
      ? `<div class="ai-preview-note">${c.images
          .map((i) =>
            esc(
              `Image ${i.index + 1} (${i.mimeType}): ` +
                (i.handling === "ocr-required"
                  ? "OCR redaction required — not run in the preview; the real request stops if OCR cannot read it."
                  : "sent as it is."),
            ),
          )
          .join("<br>")}</div>`
      : "";
    const held = c.presidio.held.length
      ? `<ul>${c.presidio.held.map((h) => `<li>${esc(h.category)}: ${esc(h.value)}</li>`).join("")}</ul>`
      : "";
    return (
      (d.multiRequest ? `<div class="ai-preview-warn">${esc(d.multiRequest)}</div>` : "") +
      `<div class="ai-preview-note">Request "${esc(c.kind)}" to ${esc(c.provider)} / ${esc(c.model)}. ` +
      (c.anonymized
        ? "Anonymization is on: the right-hand text is what the provider receives."
        : "Anonymization is OFF for this case: the provider receives the clear text.") +
      `</div>` +
      `<div class="ai-preview-panes">${pane("Clear text (never sent when masking is on)", esc(c.clearPrompt))}` +
      pane("Masked text — sent to the provider", highlightTokens(c.maskedPrompt)) +
      `</div>` +
      `<div class="ai-preview-note"><strong>${esc(PRESIDIO_TEXT[c.presidio.state] || "")}</strong> ${esc(c.presidio.message || "")}${held}</div>` +
      images +
      pane("System prompt — sent UNMASKED (the product's instructions, not case data)", esc(c.systemPrompt))
    );
  }

  async function runPreview() {
    const caseId = caseNow();
    const out = $("aiPreviewResult");
    if (!caseId) return void (out.innerHTML = `<div class="ai-preview-note">Open a case first.</div>`);
    const key = $("aiPreviewAction").value;
    out.innerHTML = `<div class="ai-preview-note">building the request — nothing is sent…</div>`;
    try {
      const r = await fetch(`/cases/${encodeURIComponent(caseId)}/ai-preview`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ action: key, params: collectParams(key) }),
      });
      const d = await r.json().catch(() => ({}));
      if (d.outcome === "captured") out.innerHTML = renderCall(d);
      else if (d.outcome === "no-ai-call") out.innerHTML = `<div class="ai-preview-note">${esc(d.message)}</div>`;
      else out.innerHTML = `<div class="ai-preview-warn">${esc(d.error || "HTTP " + r.status)}</div>`;
    } catch (e) {
      out.innerHTML = `<div class="ai-preview-warn">${esc("preview failed: " + e.message)}</div>`;
    }
  }

  function openAiPreview() {
    $("aiPreviewResult").innerHTML = "";
    renderParams();
    $("aiPreviewOverlay").classList.add("open");
  }

  function initAiPreview() {
    const select = $("aiPreviewAction");
    if (!select || select.options.length) return;
    select.innerHTML = ACTIONS.map((a) => `<option value="${escAttr(a[0])}">${esc(a[1])}</option>`).join("");
    select.addEventListener("change", renderParams);
    $("aiPreviewBtn").addEventListener("click", openAiPreview);
    $("aiPreviewRun").addEventListener("click", runPreview);
    $("aiPreviewClose").addEventListener("click", () => $("aiPreviewOverlay").classList.remove("open"));
    $("aiPreviewOverlay").addEventListener("click", (e) => {
      if (e.target.id === "aiPreviewOverlay") $("aiPreviewOverlay").classList.remove("open");
    });
  }

  // Bound by the page's guarded initializer list (dashboard.html), like the other dialogs.
  window.initAiPreview = initAiPreview;
  window.openAiPreview = openAiPreview;
})();
