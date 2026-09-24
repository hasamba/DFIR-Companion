// Second LLM opinion (#116) — an independent model re-reads the case — extracted from
// dashboard.html (issue #415, tier 3).
//
// Two sources, and the second one is the point. Three of this section's five escapes
// (soCollapsed, SO_COLLAPSE_KEY, lastSecondOpinionRec) were read from exactly one place:
// dashboard-search-scope.js, which had been carrying this feature's #secondOpinion button and
// its #secondOpinionPanel click handler since an earlier extraction swept them in. They were
// never search-scope's. The census gates could not see this one — a bare-name read from a
// SIBLING module resolves through the shared global lexical environment, so it looks local to
// nobody. That is the fifth time in #415 that an element's address was not its owner.
//
// The other two escapes are capability flags the /health poller writes and button-gating code
// reads. The poller stays in the page — it owns the fetch, not the state — so it calls
// setSecondOpinionCapabilities(), and the one remaining outside reader asks isFpAiConfigured().
// Both answer falsy when this module is absent, which HIDES an AI button rather than leaving a
// dead one on screen. That is the safe direction for a capability gate.
(function () {
  "use strict";

  // A DIFFERENT model re-synthesizes the case; we surface where it disagrees with the primary
  // synthesis (findings it adds/drops, severity, ATT&CK technique) and the analyst accepts/rejects
  // each. Accept is durable (re-applied across re-synthesis); decisions are forward-only in v1.
  let secondOpinionEnabled = false; // set from /health — whether DFIR_AI_SECOND_OPINION_MODEL is configured
  // Whether ANY AI provider is configured server-wide (h.aiEnabled from /health) — gates the mark-FP
  // modal's "Ask AI for similar" button. Distinct from the per-case `aiEnabled` toggle above (whether
  // AI analysis is turned ON for the currently-loaded case) — do not conflate the two.
  let fpAiConfigured = false;
  function loadSecondOpinion(caseId) {
    fetch(`/cases/${caseId}/second-opinion`)
      .then((r) => r.json())
      .then(renderSecondOpinion)
      .catch(() => {});
  }
  const SO_KIND_LABEL = {
    b_only: "only in B",
    a_only: "only in A",
    severity: "severity",
    mitre_added: "ATT&CK · only in B",
    mitre_removed: "ATT&CK · only in A",
  };
  // Collapse state for the 2nd-opinion panel — persisted so a long delta list doesn't have to be
  // re-collapsed every reload. Cache the last record so the toggle can re-render without a re-fetch.
  const SO_COLLAPSE_KEY = "dfir.soCollapsed";
  let soCollapsed = false;
  let lastSecondOpinionRec = null;
  function renderSecondOpinion(rec) {
    const el = document.getElementById("secondOpinionPanel");
    if (!el) return;
    lastSecondOpinionRec = rec;
    if (!rec || !rec.generatedAt) {
      el.innerHTML = "";
      el.style.display = "none";
      return;
    }
    el.style.display = "block";
    const toggle = `<button type="button" class="so-toggle" data-so-toggle title="${soCollapsed ? "Expand" : "Collapse"} the 2nd opinion panel">${soCollapsed ? "▸" : "▾"}</button>`;
    const head =
      `<div class="so-head">${toggle}<span class="so-models">🔁 2nd opinion · A: ${esc(rec.modelA || "model A")} vs B: ${esc(rec.modelB || "model B")}</span>` +
      (typeof rec.referee === "string" && rec.referee
        ? `<span data-safe-style="color:var(--text-dim)" title="The model that wrote the 'referee suggests' line on each disagreement">· referee: ${esc(rec.referee)}</span>`
        : "") +
      refereeErrorLine(rec) +
      `<span class="so-agree">✓ ${rec.agreementCount | 0} agreed</span>` +
      `<span data-safe-style="color:var(--text-dim)">${esc(relTime(rec.generatedAt))}</span></div>`;
    if (soCollapsed) {
      el.innerHTML = head;
      return;
    }
    const summary = rec.summary
      ? `<p class="so-summary">${esc(rec.summary)}</p>`
      : "";
    const deltas = Array.isArray(rec.deltas) ? rec.deltas : [];
    if (deltas.length === 0) {
      el.innerHTML =
        head +
        summary +
        `<div class="so-empty">No disagreements — both models concur on the findings, severities and ATT&amp;CK techniques.</div>`;
      return;
    }
    const pending = deltas.filter((d) => d.status === "pending").length;
    const refCalls = refereeCalls(deltas);
    // A failed referee pass leaves no calls worth following, even if an older pass left some.
    const refereeBtn =
      !rec.refereeError && refCalls.accept + refCalls.keep > 0
        ? `<button data-so-all="referee" title="Apply the referee's call on every pending delta: accept where it suggests accept B, reject where it suggests keep A. Deltas with no referee call stay pending.">⚖ follow referee (${refCalls.accept + refCalls.keep})</button>`
        : "";
    const allBtns =
      pending >= 2
        ? `<button data-so-all="accept" title="Adopt model B's call on every pending delta (durable across re-synthesis)">✓ accept all (${pending})</button><button data-so-all="reject" title="Keep model A on every pending delta — just record the decisions">✕ reject all</button>`
        : "";
    const bulk =
      refereeBtn || allBtns
        ? `<div class="so-bulk">${refereeBtn}${allBtns}</div>`
        : "";
    const rows = deltas
      .map((d) => {
        const kindLabel = SO_KIND_LABEL[d.kind] || d.kind;
        let title = esc(d.title);
        if (d.kind === "severity")
          title += ` <span data-safe-style="color:var(--text-dim)">(${esc(d.aSeverity || "?")} → ${esc(d.bSeverity || "?")})</span>`;
        else if (d.kind === "b_only")
          title += ` <span data-safe-style="color:var(--text-dim)">[${esc(d.bSeverity || "?")}]</span>`;
        const rationale = d.rationale
          ? `<div class="so-rationale">${esc(d.rationale)}</div>`
          : "";
        const suggest =
          d.recommendation === "accept_b" || d.recommendation === "keep_a"
            ? `<div class="so-rec so-${esc(d.recommendation)}">referee suggests: ${d.recommendation === "accept_b" ? "accept B" : "keep A"}</div>`
            : "";
        let acts;
        if (d.status === "accepted")
          acts = `<span class="so-status" data-safe-style="color:var(--sev-low)">✓ accepted</span>`;
        else if (d.status === "rejected")
          acts = `<span class="so-status" data-safe-style="color:var(--badge-danger-text)">✕ rejected</span>`;
        else
          acts =
            `<button data-so-accept="${esc(d.id)}" title="Adopt model B's call — applied now and re-applied across re-synthesis">accept</button>` +
            `<button data-so-reject="${esc(d.id)}" title="Keep model A — just record the decision">reject</button>`;
        return `<div class="so-delta so-${esc(d.status)}"><div class="so-body"><span class="so-kind so-${esc(d.kind)}">${esc(kindLabel)}</span><span class="so-title">${title}</span>${rationale}${suggest}</div><div class="so-acts">${acts}</div></div>`;
      })
      .join("");
    el.innerHTML = head + summary + bulk + rows;
  }
  // A failed referee pass (#1587). Without this line the panel hides every empty referee field,
  // so a referee that crashed looks exactly like one that ran and made no call. It lives in the
  // head so the collapsed panel says it too.
  function refereeErrorLine(rec) {
    const err = rec.refereeError;
    if (!err || typeof err !== "object") return "";
    const who = err.referee ? `referee (${esc(err.referee)}) failed:` : "referee failed:";
    const when = err.at ? ` · ${esc(relTime(err.at))}` : "";
    return (
      `<span class="so-referee-error">⚠ ${who} ${esc(err.message || "unknown error")}${when}</span>` +
      `<button type="button" data-so-referee-rerun title="Run only the referee again on the existing disagreements. Model A and model B are not re-run."${refereeRerunInFlight ? " disabled" : ""}>↻ re-run referee</button>`
    );
  }
  // Pending deltas the referee made a call on — "review" (no call) is not counted.
  function refereeCalls(deltas) {
    const pending = deltas.filter((d) => d.status === "pending");
    return {
      accept: pending.filter((d) => d.recommendation === "accept_b").length,
      keep: pending.filter((d) => d.recommendation === "keep_a").length,
    };
  }
  function applySecondOpinionDelta(caseId, deltaId, accept) {
    fetch(`/cases/${caseId}/second-opinion/apply`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ deltaId, accept }),
    })
      .then((r) => r.json())
      .then((rec) => {
        if (rec && rec.error) {
          document.getElementById("status").textContent =
            "second opinion: " + rec.error;
          return;
        }
        renderSecondOpinion(rec);
        // The accept may have changed findings/MITRE — refresh the case view.
        fetch(`/cases/${caseId}/state`)
          .then((r) => r.json())
          .then(render)
          .catch(() => {});
      })
      .catch(
        (e) =>
          (document.getElementById("status").textContent =
            "second opinion error: " + e.message),
      );
  }
  // accept: true | false | "referee" (follow the referee's call on each pending delta).
  function applyAllSecondOpinion(caseId, accept) {
    fetch(`/cases/${caseId}/second-opinion/apply-all`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(
        accept === "referee" ? { followReferee: true } : { accept },
      ),
    })
      .then((r) => r.json())
      .then((rec) => {
        if (rec && rec.error) {
          document.getElementById("status").textContent =
            "second opinion: " + rec.error;
          return;
        }
        renderSecondOpinion(rec);
        fetch(`/cases/${caseId}/state`)
          .then((r) => r.json())
          .then(render)
          .catch(() => {});
      })
      .catch(
        (e) =>
          (document.getElementById("status").textContent =
            "second opinion error: " + e.message),
      );
  }
  // Re-run only the referee (#1587). One press at a time: the flag is cleared on every path, and
  // the returned promise never rejects, so nothing escapes as an unhandled rejection.
  let refereeRerunInFlight = false;
  function setRefereeRerunDisabled(on) {
    const panel = document.getElementById("secondOpinionPanel");
    if (!panel || typeof panel.querySelectorAll !== "function") return;
    panel
      .querySelectorAll("[data-so-referee-rerun]")
      .forEach((b) => (b.disabled = on));
  }
  function currentCaseId() {
    const input = document.getElementById("caseId");
    return input ? String(input.value || "").trim() : "";
  }
  function refereeStatus(text) {
    const s = document.getElementById("status");
    if (s) s.textContent = text;
  }
  async function postReferee(caseId) {
    const r = await fetch(`/cases/${caseId}/second-opinion/referee`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({}),
    });
    const body = await r.json().catch(() => ({}));
    // The analyst may have opened another case while the referee ran; this answer is not theirs.
    if (currentCaseId() !== caseId) return;
    if (r.ok && body && !body.error) {
      renderSecondOpinion(body);
      const n = Array.isArray(body.deltas)
        ? body.deltas.filter((d) => d.recommendation === "accept_b" || d.recommendation === "keep_a").length
        : 0;
      refereeStatus(`referee: ${n} verdict${n === 1 ? "" : "s"}`);
      return;
    }
    if (r.status === 409 && body && body.error === "presidio_approval_required") {
      if (typeof setPresidioPending === "function") setPresidioPending(body.findings);
      refereeStatus("referee held — Presidio found new value(s) to review (see Anonymization)");
      return;
    }
    if (body && body.record) renderSecondOpinion(body.record);
    refereeStatus("referee failed: " + ((body && body.error) || `HTTP ${r.status}`));
  }
  function rerunSecondOpinionReferee(caseId) {
    if (refereeRerunInFlight || !caseId) return Promise.resolve();
    refereeRerunInFlight = true;
    setRefereeRerunDisabled(true);
    refereeStatus("re-running the referee…");
    return postReferee(caseId)
      .catch((e) => {
        if (currentCaseId() === caseId)
          refereeStatus("referee error: " + (e && e.message ? e.message : String(e)));
      })
      .then(() => {
        refereeRerunInFlight = false;
        setRefereeRerunDisabled(false);
      });
  }
  function runSecondOpinion() {
    const caseId = document.getElementById("caseId").value.trim();
    if (!caseId) return;
    const btn = document.getElementById("secondOpinion");
    if (btn) btn.disabled = true;
    const deep = !!document.getElementById("deepReasoning")?.checked;
    document.getElementById("status").textContent =
      (deep
        ? "running second opinion with deep reasoning "
        : "running second opinion ") +
      "(refreshing the primary, then a different model)…";
    fetch(`/cases/${caseId}/second-opinion`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ deepReasoning: deep }),
    })
      .then(async (r) => {
        if (r.status === 409) {
          const body = await r.json().catch(() => ({}));
          if (body.error === "presidio_approval_required") {
            if (btn) btn.disabled = false;
            if (typeof setPresidioPending === "function")
              setPresidioPending(body.findings);
            document.getElementById("status").textContent =
              "second opinion held — Presidio found new value(s) to review (see Anonymization)";
            return null;
          }
        }
        return r.json();
      })
      .then((rec) => {
        if (!rec) return; // handled above (409 presidio hold)
        if (btn) btn.disabled = false;
        if (rec && rec.error) {
          document.getElementById("status").textContent =
            "second opinion failed: " + rec.error;
          return;
        }
        const n = Array.isArray(rec.deltas) ? rec.deltas.length : 0;
        document.getElementById("status").textContent =
          `second opinion: ${n} disagreement${n === 1 ? "" : "s"} (${rec.agreementCount | 0} agreed)`;
        renderSecondOpinion(rec);
      })
      .catch((e) => {
        if (btn) btn.disabled = false;
        document.getElementById("status").textContent =
          "second opinion error: " + e.message;
      });
  }

  // Last-import change tracking lives in public/js/dashboard-import-changes.js.

  // Written by the page's /health poller.
  function setSecondOpinionCapabilities(secondOpinionOn, fpAiOn) {
    secondOpinionEnabled = !!secondOpinionOn;
    fpAiConfigured = !!fpAiOn;
    const soBtn = document.getElementById("secondOpinion");
    if (soBtn) soBtn.style.display = secondOpinionEnabled ? "" : "none";
  }
  function isFpAiConfigured() {
    return fpAiConfigured;
  }

  // The collapse preference is read from localStorage, and the two controls bind to markup —
  // all of it load-time work, none of it safe at module scope in a <head> script.
  function initSecondOpinion() {
    try {
      soCollapsed = localStorage.getItem(SO_COLLAPSE_KEY) === "1";
    } catch {}
    document.getElementById("secondOpinion").onclick = runSecondOpinion;
    // Delegated accept/reject clicks on the second-opinion panel.
    document
      .getElementById("secondOpinionPanel")
      .addEventListener("click", (e) => {
        const t = e.target.closest("button");
        if (!t) return;
        if (t.dataset.soToggle !== undefined) {
          soCollapsed = !soCollapsed;
          try {
            localStorage.setItem(SO_COLLAPSE_KEY, soCollapsed ? "1" : "0");
          } catch {}
          renderSecondOpinion(lastSecondOpinionRec);
          return;
        }
        const caseId = document.getElementById("caseId").value.trim();
        if (!caseId) return;
        if (t.dataset.soRefereeRerun !== undefined)
          rerunSecondOpinionReferee(caseId);
        else if (t.dataset.soAccept)
          applySecondOpinionDelta(caseId, t.dataset.soAccept, true);
        else if (t.dataset.soReject)
          applySecondOpinionDelta(caseId, t.dataset.soReject, false);
        else if (t.dataset.soAll === "accept") {
          if (
            confirm(
              "Accept ALL pending second-opinion deltas? This adds/edits the case findings, severities and ATT&CK techniques to match model B.",
            )
          )
            applyAllSecondOpinion(caseId, true);
        } else if (t.dataset.soAll === "reject")
          applyAllSecondOpinion(caseId, false);
        else if (t.dataset.soAll === "referee") {
          const c = refereeCalls(lastSecondOpinionRec?.deltas || []);
          if (
            confirm(
              `Follow the referee on ${c.accept + c.keep} pending delta(s)? ${c.accept} will be accepted (model B's call is applied to the case findings, severities and ATT&CK techniques) and ${c.keep} rejected. Deltas with no referee call stay pending.`,
            )
          )
            applyAllSecondOpinion(caseId, "referee");
        }
      });
  }

  window.initSecondOpinion = initSecondOpinion;
  window.setSecondOpinionCapabilities = setSecondOpinionCapabilities;
  window.isFpAiConfigured = isFpAiConfigured;
  window.loadSecondOpinion = loadSecondOpinion;
  window.renderSecondOpinion = renderSecondOpinion;
  window.runSecondOpinion = runSecondOpinion;
  window.applySecondOpinionDelta = applySecondOpinionDelta;
  window.applyAllSecondOpinion = applyAllSecondOpinion;
  window.rerunSecondOpinionReferee = rerunSecondOpinionReferee;
})();
