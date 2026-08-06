// Hypotheses (issue #140) — extracted from dashboard.html (issue #415, tier 3).
//
// pendingHuntHypothesis was the section's one state escape, and it escaped as a WRITE:
// dashboard-data-act.js's clearPendingHunt action assigned `pendingHuntHypothesis = null`
// straight into this binding. Ownership follows use — the owner exports the operation, and the
// caller asks for it. clearPendingHuntHypothesis() is that operation.
(function () {
  "use strict";

  // Status-tracked investigative hypotheses. Auto-generated on synthesis (source "synthesis") +
  // analyst-authored. A PATCH freezes a synthesis hypothesis from auto-refresh (server-side). The
  // panel groups by status and survives synthesis (never wiped).
  let hypotheses = [];
  const HYP_STATUS = [
    ["open", "Open"],
    ["supported", "Supported"],
    ["refuted", "Refuted"],
    ["unknown", "Unknown"],
  ];
  const HYP_STATUS_LABEL = Object.fromEntries(HYP_STATUS);

  function loadHypotheses(caseId) {
    fetch(`/cases/${caseId}/hypotheses`)
      .then((r) => r.json())
      .then((list) => {
        hypotheses = Array.isArray(list) ? list : [];
        renderHypotheses();
      })
      .catch(() => {});
  }

  function renderHypotheses() {
    const el = document.getElementById("hypList");
    if (!el) return;
    const badge = document.getElementById("hypBadge");
    if (badge) {
      const counts = HYP_STATUS.map(([v, l]) => {
        const n = hypotheses.filter((h) => h.status === v).length;
        return n ? `${n} ${v}` : null;
      }).filter(Boolean);
      badge.textContent = hypotheses.length ? " — " + counts.join(" · ") : "";
    }
    if (!hypotheses.length) {
      el.innerHTML =
        "<div data-safe-style='color:var(--text-muted);font-size:12px'>No hypotheses yet — they're auto-generated whenever synthesis runs (after each import). Click <strong>✨ Generate</strong> in the section title to run synthesis now, or add one below.</div>";
      return;
    }
    // ACH ranking (investigation-guidance #14): within each status group, order by FEWEST
    // contradictions first (the explanation that survives the most disconfirming evidence wins), then
    // most support — and sink exhausted hypotheses (hunts came back empty) to the bottom.
    const achSort = (a, b) =>
      (a.exhausted ? 1 : 0) - (b.exhausted ? 1 : 0) ||
      (a.contradictingEventIds || []).length -
        (b.contradictingEventIds || []).length ||
      (b.relatedEventIds || []).length - (a.relatedEventIds || []).length ||
      String(a.title).localeCompare(String(b.title));
    let html = "";
    for (const [v, label] of HYP_STATUS) {
      const group = hypotheses.filter((h) => h.status === v).sort(achSort);
      if (!group.length) continue;
      html += `<div class="hyp-grouphdr">${esc(label)} (${group.length})<span class="hyp-ach-note" title="Analysis of Competing Hypotheses: ranked by fewest contradictions, not most support"> · ranked by fewest contradictions</span></div>`;
      html += group.map(renderHypCard).join("");
    }
    el.innerHTML = html;
  }

  function renderHypCard(h) {
    const opts = HYP_STATUS.map(
      ([v, l]) =>
        `<option value="${v}" ${h.status === v ? "selected" : ""}>${l}</option>`,
    ).join("");
    const src =
      h.source === "synthesis"
        ? `<span class="hyp-src synthesis" title="Auto-generated on synthesis">auto</span>`
        : `<span class="hyp-src" title="Analyst-authored">analyst</span>`;
    const outcome = h.expectedOutcome
      ? `<div class="hyp-outcome"><b>Expected:</b> ${esc(h.expectedOutcome)}</div>`
      : "";
    const desc = h.description
      ? `<div class="hyp-desc">${esc(h.description)}</div>`
      : "";
    const chips = [];
    (h.relatedTechniques || []).forEach((t) =>
      chips.push(`<span class="hyp-chip">${esc(t)}</span>`),
    );
    if ((h.relatedEventIds || []).length)
      chips.push(
        `<span class="hyp-chip" title="supporting forensic events">↳ ${h.relatedEventIds.length} event${h.relatedEventIds.length === 1 ? "" : "s"}</span>`,
      );
    // ACH (#14): contradicting-event count is the primary ranking signal — show it prominently (red).
    const contraN = (h.contradictingEventIds || []).length;
    if (contraN)
      chips.push(
        `<span class="hyp-chip hyp-contra" title="events INCONSISTENT with this explanation (ACH: judged by fewest contradictions)">⊖ ${contraN} contradicting</span>`,
      );
    if ((h.relatedIocIds || []).length)
      chips.push(
        `<span class="hyp-chip" title="implicated IOCs">${h.relatedIocIds.length} IOC${h.relatedIocIds.length === 1 ? "" : "s"}</span>`,
      );
    const meta = chips.length
      ? `<div class="hyp-meta">${chips.join("")}</div>`
      : "";
    // ACH (#14): the discriminator — the single artifact that best separates this hypothesis from the
    // leading alternative. Doubles as a concrete collection directive.
    const discrim = h.discriminator
      ? `<div class="hyp-discriminator" title="The artifact that would best separate this hypothesis from the leading alternative — collect it next"><b>🔬 Discriminator:</b> ${esc(h.discriminator)}</div>`
      : "";
    const id = escAttr(h.id);
    // Immediate FP cascade (#12): supporting evidence was marked false positive — flag for re-judging.
    // A pristine hypothesis was also flipped to 'unknown'; editing it (any field) clears the flag.
    const review = h.needsReview
      ? `<span class="hyp-needs-review" title="An event or IOC that supported this hypothesis was marked false positive — re-judge it. Editing any field clears this flag.">⚠️ needs review</span>`
      : "";
    // ACH exhaustion (#14): hunts for this hypothesis came back empty → treated as negative knowledge.
    const exhausted = h.exhausted
      ? `<span class="hyp-exhausted" title="${escAttr(h.exhaustedReason || "Hunts for this hypothesis came back empty — treated as settled negative knowledge.")}">⊘ exhausted</span>`
      : "";
    // Dated status-change audit trail (#95) — skipped when there's only the initial entry (nothing
    // has changed since the hypothesis was created).
    const statusHistory = h.statusHistory || [];
    const history =
      statusHistory.length > 1
        ? `<div class="hyp-history" title="Dated status-change history">🕘 ${statusHistory.map((s) => `${esc(HYP_STATUS_LABEL[s.status] || s.status)} (${esc(String(s.changedAt || "").slice(0, 10))})`).join(" → ")}</div>`
        : "";
    return (
      `<div class="hyp ${escAttr(h.status)}${h.needsReview ? " needs-review" : ""}${h.exhausted ? " exhausted" : ""}" data-id="${id}">` +
      `<div class="hyp-row1">` +
      `<select class="hyp-status" data-act="hypPatchStatus" data-act-on="change" data-id="${id}">${opts}</select>` +
      `<span class="hyp-title">${esc(h.title)}</span>${src}${review}${exhausted}` +
      // #14 deferred: link the NEXT deployed hunt to this hypothesis, so an empty result exhausts it.
      (h.status === "open" && !h.exhausted
        ? ` <button class="hyp-hunt" data-act="linkNextHunt" data-id="${id}" data-t="${escAttr(h.title)}" title="Deploy a Velociraptor hunt to test this hypothesis — the next hunt you launch is linked, so an empty result counts as a miss against it (→ exhausted)">🎯 test via hunt</button>`
        : "") +
      `<button class="hyp-del" data-act="hypDelete" data-id="${id}" title="Delete">✕</button>` +
      `</div>${outcome}${desc}${discrim}${meta}${history}` +
      `<div class="hyp-row2">` +
      `<input class="hyp-assignee" placeholder="assignee" value="${escAttr(h.assignee || "")}" data-act="hypPatchAssignee" data-act-on="change" data-id="${id}" />` +
      `<input class="hyp-notes" placeholder="notes" value="${escAttr(h.notes || "")}" data-act="hypPatchNotes" data-act-on="change" data-id="${id}" />` +
      `</div>` +
      `</div>`
    );
  }

  function hypPatch(id, patch) {
    const caseId = document.getElementById("caseId").value.trim();
    if (!caseId) return;
    fetch(`/cases/${caseId}/hypotheses/${encodeURIComponent(id)}`, {
      method: "PATCH",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(patch),
    })
      .then(() => loadHypotheses(caseId))
      .catch(() => {});
  }

  // #14 deferred: arm the NEXT deployed Velociraptor hunt to test a specific hypothesis. Consumed once
  // by launchHuntInto (which stamps relatedHypothesisId on the deploy). A visible note + one-click cancel
  // so the analyst knows the link is pending.
  let pendingHuntHypothesis = null;
  function linkNextHuntToHypothesis(id, title) {
    pendingHuntHypothesis = { id, title: title || id };
    const msg = document.getElementById("suggestHuntsMsg");
    if (msg)
      msg.innerHTML = `🎯 next hunt will test hypothesis “${esc(pendingHuntHypothesis.title)}” — <a href="#" data-act="clearPendingHunt" data-safe-style="color:var(--accent)">cancel</a>`;
    const sec = document.getElementById("sec-velohunts");
    if (sec) sec.scrollIntoView({ behavior: "smooth", block: "start" });
  }
  // Clear the pending link WITHOUT consuming it into a hunt — the analyst's explicit cancel.
  // dashboard-data-act.js used to assign `pendingHuntHypothesis = null` from its own scope, which
  // only worked because classic scripts share one global lexical environment. It asks now.
  function clearPendingHuntHypothesis() {
    pendingHuntHypothesis = null;
  }

  // Read + clear the pending hypothesis link (used by launchHuntInto).
  function consumePendingHuntHypothesis() {
    const p = pendingHuntHypothesis;
    pendingHuntHypothesis = null;
    const msg = document.getElementById("suggestHuntsMsg");
    if (msg && p) msg.textContent = "";
    return p ? p.id : undefined;
  }

  function hypDelete(id) {
    const caseId = document.getElementById("caseId").value.trim();
    if (!caseId) return;
    fetch(`/cases/${caseId}/hypotheses/${encodeURIComponent(id)}`, {
      method: "DELETE",
    })
      .then(() => loadHypotheses(caseId))
      .catch(() => {});
  }

  // On-demand falsification review (#71): weigh each OPEN hypothesis's supporting vs. refuting evidence
  // and recommend a status. ADVISORY — the review NEVER changes a hypothesis; the analyst clicks "Apply"
  // (a normal PATCH, which marks it analystTouched) to accept a recommendation. Ephemeral: results live
  // only in the panel until the next review. stopPropagation so the h2 click doesn't collapse the section.
  const HYP_REVIEW_STATUS_LABEL = {
    supported: "Supported",
    refuted: "Refuted",
    unknown: "Unknown",
    open: "Keep open",
  };
  function renderHypothesisReviews(reviews) {
    const el = document.getElementById("hypReviewResults");
    if (!el) return;
    if (!reviews || !reviews.length) {
      el.innerHTML = "";
      return;
    }
    const bullets = (arr, kind) =>
      arr && arr.length
        ? `<ul class="hyp-rev-list ${kind}">` +
          arr.map((b) => `<li>${esc(b)}</li>`).join("") +
          "</ul>"
        : `<div class="hyp-rev-none">none found</div>`;
    el.innerHTML =
      `<div class="hyp-rev-box"><div class="hyp-rev-hdr">🔎 Falsification review <span class="hyp-rev-sub">evidence for vs. against each open hypothesis — recommendations are advisory; click <em>Apply</em> to accept one</span></div>` +
      reviews
        .map((r) => {
          const st = r.recommendedStatus || "unknown";
          const apply =
            st === "open"
              ? ""
              : `<button class="hyp-rev-apply" data-act="hypApplyReview" data-id="${escAttr(r.hypothesisId)}" data-st="${escAttr(st)}" title="Set this hypothesis's status to ${esc(HYP_REVIEW_STATUS_LABEL[st] || st)} (marks it analyst-edited)">Apply → ${esc(HYP_REVIEW_STATUS_LABEL[st] || st)}</button>`;
          return (
            `<div class="hyp-rev-item">` +
            `<div class="hyp-rev-title">${esc(r.title)}<span class="hyp-rev-rec ${esc(st)}">recommends: ${esc(HYP_REVIEW_STATUS_LABEL[st] || st)}</span>${apply}</div>` +
            `<div class="hyp-rev-cols"><div class="hyp-rev-for"><b>Supports</b>${bullets(r.supportingEvidence, "for")}</div>` +
            `<div class="hyp-rev-against"><b>Refutes / weakens</b>${bullets(r.refutingEvidence, "against")}</div></div>` +
            (r.rationale
              ? `<div class="hyp-rev-rat">${esc(r.rationale)}</div>`
              : "") +
            `</div>`
          );
        })
        .join("") +
      `</div>`;
  }

  function hypApplyReview(id, status) {
    hypPatch(id, { status });
    // Clear the applied recommendation's Apply affordance by re-rendering after the patch reloads.
  }

  // Promote a notebook hypothesis entry into a tracked hypothesis (the notebook→hypothesis bridge).
  function promoteToHypothesis(id) {
    const caseId = document.getElementById("caseId").value.trim();
    const entry = notebookEntries.find((e) => e.id === id);
    const msg = document.getElementById("nbMsg");
    if (!caseId || !entry) return;
    if (msg) msg.textContent = "promoting…";
    fetch(`/cases/${caseId}/hypotheses`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        title: entry.text.slice(0, 200),
        description: entry.text.length > 200 ? entry.text : "",
        author: investigatorName(),
      }),
    })
      .then((r) => {
        if (!r.ok) throw new Error("HTTP " + r.status);
        return r.json();
      })
      .then(() => {
        if (msg) msg.textContent = "promoted ✓ — see the Hypotheses panel";
        loadHypotheses(caseId);
        const sec = document.getElementById("sec-hypotheses");
        if (sec) {
          sec.classList.remove("collapsed");
          sec.scrollIntoView({ behavior: "smooth", block: "start" });
        }
      })
      // Never swallow silently — a 404 here means a stale server (the #1 gotcha), and the analyst
      // must see why nothing happened instead of a dead button.
      .catch((e) => {
        if (msg)
          msg.textContent =
            "promote failed: " +
            e.message +
            " — restart the companion server if this 404s";
      });
  }

  // Three buttons wired at load. In a <head> script these run before the markup exists, so they
  // are initializer work, not module body.
  function initHypotheses() {
    document.getElementById("hypAddBtn").onclick = function () {
      const caseId = document.getElementById("caseId").value.trim();
      const title = document.getElementById("hypTitle").value.trim();
      const expectedOutcome = document
        .getElementById("hypOutcome")
        .value.trim();
      const status = document.getElementById("hypStatus").value;
      const msg = document.getElementById("hypMsg");
      if (!caseId || !title) {
        msg.textContent = "title required";
        return;
      }
      msg.textContent = "adding…";
      fetch(`/cases/${caseId}/hypotheses`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          title,
          expectedOutcome,
          status,
          author: investigatorName(),
        }),
      })
        .then((r) => {
          if (!r.ok) throw new Error("HTTP " + r.status);
          return r.json();
        })
        .then(() => {
          document.getElementById("hypTitle").value = "";
          document.getElementById("hypOutcome").value = "";
          msg.textContent = "";
          loadHypotheses(caseId);
        })
        .catch((e) => {
          msg.textContent =
            "failed: " +
            e.message +
            " — restart the companion server if this 404s";
        });
    };
    // On-demand hypothesis generation (#140): hypotheses are a byproduct of synthesis, so this just
    // runs a forced synthesis (same endpoint/force as the toolbar Synthesize button) and reloads the
    // panel. Analyst-touched/authored hypotheses are frozen server-side; only pristine auto ones refresh.
    // stopPropagation so the h2 click doesn't toggle the section collapse (same guard as genExec/genNarrative).
    document
      .getElementById("hypGenerateBtn")
      .addEventListener("click", function (e) {
        e.stopPropagation();
        const caseId = document.getElementById("caseId").value.trim();
        const msg = document.getElementById("hypGenMsg");
        const btn = document.getElementById("hypGenerateBtn");
        if (!caseId) {
          msg.textContent = "open a case first";
          return;
        }
        btn.disabled = true;
        msg.textContent = "synthesizing…";
        fetch(`/cases/${caseId}/synthesize`, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: "{}",
        })
          .then((r) => {
            if (r.status === 423)
              return r.json().then((p) => {
                throw Object.assign(new Error(p.error || "Case is closed"), {
                  locked: true,
                });
              });
            if (!r.ok) throw new Error("HTTP " + r.status);
            return r.json();
          })
          .then((p) => {
            if (p.error) {
              msg.textContent = "failed: " + p.error;
              return;
            }
            msg.textContent = "";
            loadHypotheses(caseId);
            // refresh the rest of the case in case the WS push was missed
            fetch(`/cases/${caseId}/state`)
              .then((r) => r.json())
              .then(render)
              .catch(() => {});
            loadSynthMeta(caseId);
          })
          .catch((e) => {
            msg.textContent =
              "failed: " +
              e.message +
              " — restart the companion server if this 404s";
          })
          .finally(() => {
            btn.disabled = false;
          });
      });
    document
      .getElementById("hypReviewBtn")
      .addEventListener("click", function (e) {
        e.stopPropagation();
        const caseId = document.getElementById("caseId").value.trim();
        const msg = document.getElementById("hypGenMsg");
        const btn = document.getElementById("hypReviewBtn");
        if (!caseId) {
          msg.textContent = "open a case first";
          return;
        }
        btn.disabled = true;
        msg.textContent = "reviewing hypotheses…";
        fetch(`/cases/${caseId}/hypothesis-review`, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: "{}",
        })
          .then((r) => {
            if (!r.ok)
              return r.json().then((p) => {
                throw new Error(p.error || "HTTP " + r.status);
              });
            return r.json();
          })
          .then((p) => {
            renderHypothesisReviews(p.reviews);
            msg.textContent =
              p.reviews && p.reviews.length
                ? ""
                : "no open hypotheses to review";
          })
          .catch((e) => {
            msg.textContent =
              "failed: " +
              e.message +
              " — restart the companion server if this 404s";
          })
          .finally(() => {
            btn.disabled = false;
          });
      });
  }

  window.loadHypotheses = loadHypotheses;
  window.hypPatch = hypPatch;
  window.linkNextHuntToHypothesis = linkNextHuntToHypothesis;
  window.consumePendingHuntHypothesis = consumePendingHuntHypothesis;
  window.clearPendingHuntHypothesis = clearPendingHuntHypothesis;
  window.hypDelete = hypDelete;
  window.hypApplyReview = hypApplyReview;
  window.promoteToHypothesis = promoteToHypothesis;
  window.initHypotheses = initHypotheses;
})();
