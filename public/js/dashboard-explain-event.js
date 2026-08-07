// Explain Event (#141) — the plain-language explanation of one timeline event, on demand
// (#415 tier 3).
//
// One function and no state. IIFE-wrapped anyway: in a CLASSIC script anything added at this level
// later would join the shared global lexical environment.
//
// NO INITIALIZER. Its only caller is the delegated click handler on the timeline, which calls
// openExplainPanel from inside a listener rather than binding it — so there is nothing evaluated at
// load and nothing to defer.
(function () {
  // ── Explain Event (#141) ─────────────────────────────────────────────────────────────────
  // Single AI call per click: what happened, why it matters, ATT&CK mapping, pivot queries,
  // and evidence for/against maliciousness. Ephemeral — no state change.
  function openExplainPanel(caseId, eventId) {
    const event =
      DfirState.lastState() &&
      DfirState.lastState().forensicTimeline &&
      DfirState.lastState().forensicTimeline.find((e) => e.id === eventId);
    const overlay = document.getElementById("explainOverlay");
    const titleEl = document.getElementById("explainEventTitle");
    const bodyEl = document.getElementById("explainBody");
    overlay.classList.add("open");
    titleEl.textContent = event ? event.description.slice(0, 140) : eventId;
    bodyEl.innerHTML =
      "<div data-safe-style='color:var(--text-muted)'>analyzing…</div>";
    fetch(
      `/cases/${encodeURIComponent(caseId)}/events/${encodeURIComponent(eventId)}/explain`,
      { method: "POST" },
    )
      .then((r) => {
        if (!r.ok) throw new Error("HTTP " + r.status);
        return r.json();
      })
      .then((result) => {
        const section = (label, content, color) =>
          content
            ? `<div class="explain-section"><strong>${label}</strong><span data-safe-style="color:${color || "var(--text-primary)"}">${esc(content)}</span></div>`
            : "";
        const qhtml = (result.pivotQueries || [])
          .map((q) => {
            return (
              `<div class="hunt-card">` +
              `<div class="hunt-card-head"><span>${esc(q.platform || "query")}</span>` +
              `<button class="hunt-copy" data-q="${escAttr(q.query)}">Copy</button></div>` +
              `<pre data-safe-style="margin:0;padding:10px;background:var(--bg-primary);color:var(--text-bright);font-size:11px;overflow-x:auto;white-space:pre-wrap;word-break:break-all">${esc(q.query)}</pre>` +
              (q.rationale
                ? `<div data-safe-style="padding:6px 10px;font-size:11px;color:var(--text-muted)">${esc(q.rationale)}</div>`
                : "") +
              `</div>`
            );
          })
          .join("");
        const cited = citeEvents(result.relatedEventIds);
        bodyEl.innerHTML =
          section("What happened", result.summary, "var(--text-primary)") +
          section("Why it matters", result.whyItMatters, "var(--accent)") +
          (result.normalContext || result.suspiciousIndicators
            ? `<div class="explain-section"><strong>Normal vs. suspicious</strong>` +
              (result.normalContext
                ? `<div data-safe-style="color:var(--text-muted);margin-bottom:3px">${esc(result.normalContext)}</div>`
                : "") +
              (result.suspiciousIndicators
                ? `<div data-safe-style="color:var(--sev-high)">${esc(result.suspiciousIndicators)}</div>`
                : "") +
              `</div>`
            : "") +
          section(
            "ATT&CK mapping",
            result.attackMapping,
            "var(--text-primary)",
          ) +
          (result.evidenceFor || result.evidenceAgainst
            ? `<div class="explain-section"><strong>Evidence</strong>` +
              (result.evidenceFor
                ? `<div data-safe-style="color:var(--badge-danger-text)">✓ ${esc(result.evidenceFor)}</div>`
                : "") +
              (result.evidenceAgainst
                ? `<div data-safe-style="color:var(--text-muted);margin-top:3px">⊘ ${esc(result.evidenceAgainst)}</div>`
                : "") +
              `</div>`
            : "") +
          (qhtml
            ? `<div class="explain-section"><strong>Pivot queries</strong>${qhtml}</div>`
            : "") +
          (cited
            ? `<div class="explain-section"><strong>Related events</strong><span data-safe-style="color:var(--text-muted);font-size:12px">${cited}</span></div>`
            : "");
        // Copy buttons: attach the clipboard handler after render instead of building an inline
        // onclick from the AI-supplied query (which could break out of the attribute/tag context).
        // The query rides in an escAttr-escaped data-q attribute; dataset.q decodes back to the
        // exact original string, so clipboard content and the "copied" feedback are unchanged.
        bodyEl.querySelectorAll(".hunt-copy").forEach(
          (b) =>
            (b.onclick = () => {
              navigator.clipboard?.writeText(b.dataset.q);
              b.textContent = "✓ copied";
              setTimeout(() => {
                b.textContent = "Copy";
              }, 1500);
            }),
        );
      })
      .catch((e) => {
        const msg = String(e.message || e);
        const hint = /501/.test(msg)
          ? "AI provider not configured — check Settings → AI"
          : /404/.test(msg)
            ? "route not found — restart the companion server"
            : "check the server console for details";
        bodyEl.innerHTML = `<div data-safe-style="color:var(--sev-high)">explain failed: ${esc(msg)} — ${hint}</div>`;
      });
  }

  window.openExplainPanel = openExplainPanel;
})();
