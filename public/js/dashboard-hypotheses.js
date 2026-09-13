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
    // ACH ranking (investigation-guidance #14, diagnosticity from #933 item 22): within each status
    // group, order by FEWEST active contradictions first, then most DISTINGUISHING support (the
    // observations that separate this explanation from a named alternative), then support not yet
    // assessed against the alternatives — support that fits every alternative ranks nothing. The
    // keys come from the server's assessment so this list and the report agree; the raw counts are
    // the fallback for a server that predates the assessment.
    const key = (h) => {
      const a = h.assessment;
      return a
        ? [
            a.activeContradictions,
            -(a.support.distinguishing || []).length,
            -(a.support.notAssessedElsewhere || []).length,
          ]
        : [
            (h.contradictingEventIds || []).length,
            -(h.relatedEventIds || []).length,
            0,
          ];
    };
    const achSort = (a, b) => {
      const ka = key(a);
      const kb = key(b);
      return (
        (a.exhausted ? 1 : 0) - (b.exhausted ? 1 : 0) ||
        ka[0] - kb[0] ||
        ka[1] - kb[1] ||
        ka[2] - kb[2] ||
        String(a.title).localeCompare(String(b.title))
      );
    };
    let html = "";
    for (const [v, label] of HYP_STATUS) {
      const group = hypotheses.filter((h) => h.status === v).sort(achSort);
      if (!group.length) continue;
      html += `<div class="hyp-grouphdr">${esc(label)} (${group.length})<span class="hyp-ach-note" title="Analysis of Competing Hypotheses: ranked by fewest active contradictions, then by the support that separates this explanation from a named alternative — never by how much support fits every explanation"> · ranked by fewest contradictions, then distinguishing support</span></div>`;
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
    // Review flag (#12 FP cascade; #933 item 22 material changes). The server says WHY; a status
    // change or the explicit ✓ clears it — a note or an assignee edit does not.
    const review = h.needsReview
      ? `<span class="hyp-needs-review" title="${escAttr(h.reviewReason || "An event or IOC that supported this hypothesis was marked false positive — re-judge it.")}">⚠️ review required${h.reviewReason ? ": " + esc(h.reviewReason) : ""}</span> <button class="hyp-ack" data-act="hypAcknowledgeReview" data-id="${id}" title="I have reviewed this — clear the flag">✓ reviewed</button>`
      : "";
    // The qualifier (#933 item 22) sits beside the title, never only inside the collapsed block:
    // "no alternative offered" / "no observation separates it from an alternative".
    const qualifierText = String(h.qualifier || "").replace(/ — review required.*$/, "");
    const qualifier =
      qualifierText && !/^review required/.test(qualifierText)
        ? `<span class="hyp-qualifier" title="The status word is the analyst's; this says what the conclusion rests on">— ${esc(qualifierText)}</span>`
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
      `<span class="hyp-title">${esc(h.title)}</span>${qualifier}${src}${review}${exhausted}` +
      // #14 deferred: link the NEXT deployed hunt to this hypothesis, so an empty result exhausts it.
      (h.status === "open" && !h.exhausted
        ? ` <button class="hyp-hunt" data-act="linkNextHunt" data-id="${id}" data-t="${escAttr(h.title)}" title="Deploy a Velociraptor hunt to test this hypothesis — the next hunt you launch is linked, so an empty result counts as a miss against it (→ exhausted). A hunt deployed as a live snapshot is not linked: its empty result is not a miss.">🎯 test via hunt</button>`
        : "") +
      `<button class="hyp-del" data-act="hypDelete" data-id="${id}" title="Delete">✕</button>` +
      `</div>${outcome}${desc}${discrim}${meta}${renderEvidenceAssessment(h)}${history}` +
      `<div class="hyp-row2">` +
      `<input class="hyp-assignee" placeholder="assignee" value="${escAttr(h.assignee || "")}" data-act="hypPatchAssignee" data-act-on="change" data-id="${id}" />` +
      `<input class="hyp-notes" placeholder="notes" value="${escAttr(h.notes || "")}" data-act="hypPatchNotes" data-act-on="change" data-id="${id}" />` +
      `</div>` +
      `</div>`
    );
  }

  // Evidence assessment (#933 item 22): what this conclusion rests on, read across the set of
  // alternatives. Every row is one observation with its bearing; an analyst can exclude one from
  // THIS assessment with a reason (an audit trail — the event and the link stay) or restore it.
  // Counts are counts of observations, never a probability.
  const BEARING = {
    distinguishing: ["separates this from", "hyp-ev-distinguishing"],
    consistent: ["consistent with the alternatives that assessed it", "hyp-ev-shared"],
    unassessed: ["not assessed against the alternatives", "hyp-ev-unassessed"],
    contraDistinguishing: ["contradiction — supports", "hyp-ev-contra"],
    contraAll: ["contradiction — against every explanation that assessed it", "hyp-ev-contra"],
    contraUnassessed: ["contradiction — not assessed against the alternatives", "hyp-ev-contra"],
    both: ["assessed both ways — counted for nothing", "hyp-ev-unassessed"],
  };
  function renderEvidenceAssessment(h) {
    const a = h.assessment;
    if (!a) return "";
    const id = escAttr(h.id);
    const rows = new Map((h.evidence || []).map((r) => [r.eventId, r]));
    const names = (refs) => (refs || []).map((r) => `'${esc(r.title)}'`).join(", ");
    const row = (eventId, bearingKey, tail, excluded) => {
      const r = rows.get(eventId) || { present: false, uncertainty: [] };
      const [label, cls] = BEARING[bearingKey];
      const when = r.present ? `${esc(String(r.timestamp || "").slice(0, 19))} — ${esc(r.description || "")}` : `<code>${esc(eventId)}</code> — observation no longer in the timeline`;
      const notes = (r.uncertainty || []).length ? ` <span class="hyp-ev-note" title="Read from the record itself">[${esc(r.uncertainty.join("; "))}]</span>` : "";
      const act = excluded
        ? `<button class="hyp-ev-act" data-act="hypRestoreEvidence" data-id="${id}" data-ev="${escAttr(eventId)}" title="Put this observation back into the assessment (the exclusion stays in the audit trail)">restore</button>`
        : `<button class="hyp-ev-act" data-act="hypExcludeStart" data-id="${id}" data-ev="${escAttr(eventId)}" title="Exclude this observation from THIS hypothesis's assessment, with a reason. The event and the link are kept.">exclude</button>`;
      return `<li class="hyp-ev ${cls}${excluded ? " hyp-ev-excluded" : ""}"><span class="hyp-ev-bearing">${esc(label)}${tail ? " " + tail : ""}</span> ${when}${notes} ${act}<span class="hyp-ev-form" data-ev="${escAttr(eventId)}"></span></li>`;
    };
    const items = [];
    (a.support.distinguishing || []).forEach((d) => items.push(row(d.eventId, "distinguishing", names(d.separatesFrom))));
    (a.support.consistentWithAlternatives || []).forEach((d) => items.push(row(d.eventId, "consistent", `(${d.assessedBy} assessed it, ${d.notAssessedBy} did not)`)));
    (a.support.notAssessedElsewhere || []).forEach((e) => items.push(row(e, "unassessed", "")));
    (a.contradiction.distinguishing || []).forEach((d) => items.push(row(d.eventId, "contraDistinguishing", names(d.supports))));
    (a.contradiction.againstEveryAssessed || []).forEach((d) => items.push(row(d.eventId, "contraAll", `(${d.assessedBy} assessed it, ${d.notAssessedBy} did not)`)));
    (a.contradiction.notAssessedElsewhere || []).forEach((e) => items.push(row(e, "contraUnassessed", "")));
    (a.assessedBothWays || []).forEach((e) => items.push(row(e, "both", "")));
    const excludedRows = (h.excludedEvidence || []).map((x) => {
      const r = rows.get(x.eventId) || { present: false, uncertainty: [] };
      const what = r.present ? `${esc(String(r.timestamp || "").slice(0, 19))} — ${esc(r.description || "")}` : `<code>${esc(x.eventId)}</code>`;
      const closed = x.restoredAt ? ` <span class="hyp-ev-note">(restored ${esc(String(x.restoredAt).slice(0, 10))}${x.restoredBy === "unlinked" ? ", unlinked" : ""})</span>` : "";
      const act = x.restoredAt ? "" : ` <button class="hyp-ev-act" data-act="hypRestoreEvidence" data-id="${id}" data-ev="${escAttr(x.eventId)}" title="Put this observation back into the assessment (the exclusion stays in the audit trail)">restore</button>`;
      return `<li class="hyp-ev hyp-ev-excluded"><span class="hyp-ev-bearing">excluded by ${esc(x.by || "analyst")} on ${esc(String(x.excludedAt).slice(0, 10))}</span> ${what} — ${esc(x.reason || "")}${closed}${act}</li>`;
    });
    const notCounted = (a.notCounted || []).map((n) => `<li class="hyp-ev hyp-ev-unassessed"><span class="hyp-ev-bearing">not counted (${esc(n.reason)})</span> <code>${esc(n.eventId)}</code></li>`);
    const alternatives = a.alternatives.length
      ? `Alternatives considered${a.alternativesSource === "analyst" ? " (named by you)" : ""}: ${a.alternatives.map((x) => `'${esc(x.title)}' (${esc(HYP_STATUS_LABEL[x.status] || x.status)})`).join(", ")}`
      : "No alternative was offered, so no observation can separate this from one.";
    const others = hypotheses.filter((o) => o.id !== h.id);
    const altPicker = others.length
      ? `<details class="hyp-alts"><summary title="Narrow the competing set when a title is not a real alternative (a different kill-chain phase, a duplicate). Empty = every live hypothesis.">name the alternatives</summary>${others
          .map(
            (o) =>
              `<label class="hyp-alt"><input type="checkbox" data-act="hypToggleAlternative" data-act-on="change" data-id="${id}" data-alt="${escAttr(o.id)}" ${(h.alternativeIds || []).includes(o.id) ? "checked" : ""}/> ${esc(o.title)} <span class="hyp-ev-note">(${esc(HYP_STATUS_LABEL[o.status] || o.status)})</span></label>`,
          )
          .join("")}</details>`
      : "";
    return (
      `<details class="hyp-assessment"><summary>evidence assessment <span class="hyp-ev-note">${esc(a.reading)}</span></summary>` +
      `<div class="hyp-alternatives">${alternatives}</div>${altPicker}` +
      (items.length || excludedRows.length || notCounted.length
        ? `<ul class="hyp-ev-list">${items.join("")}${excludedRows.join("")}${notCounted.join("")}</ul>`
        : `<div class="hyp-ev-note">No linked observation counted.</div>`) +
      `</details>`
    );
  }

  // The inline reason form for an exclusion — no browser dialogs (they block the extension).
  function hypExcludeStart(id, eventId) {
    const card = document.querySelector(`.hyp[data-id="${CSS.escape(id)}"]`);
    const slot = card && card.querySelector(`.hyp-ev-form[data-ev="${CSS.escape(eventId)}"]`);
    if (!slot) return;
    slot.innerHTML =
      `<input class="hyp-ev-reason" placeholder="why it does not bear on this question (required)" /> ` +
      `<button class="hyp-ev-act" data-act="hypExcludeConfirm" data-id="${escAttr(id)}" data-ev="${escAttr(eventId)}">confirm</button> ` +
      `<button class="hyp-ev-act" data-act="hypExcludeCancel" data-id="${escAttr(id)}" data-ev="${escAttr(eventId)}">cancel</button>`;
    const input = slot.querySelector("input");
    if (input) input.focus();
  }
  function hypExcludeCancel(id, eventId) {
    const card = document.querySelector(`.hyp[data-id="${CSS.escape(id)}"]`);
    const slot = card && card.querySelector(`.hyp-ev-form[data-ev="${CSS.escape(eventId)}"]`);
    if (slot) slot.innerHTML = "";
  }
  function hypExcludeConfirm(id, eventId) {
    const caseId = document.getElementById("caseId").value.trim();
    const card = document.querySelector(`.hyp[data-id="${CSS.escape(id)}"]`);
    const input = card && card.querySelector(`.hyp-ev-form[data-ev="${CSS.escape(eventId)}"] input`);
    const reason = input ? input.value.trim() : "";
    if (!caseId || !reason) {
      if (input) input.placeholder = "a reason is required — it is the audit trail";
      return;
    }
    fetch(`/cases/${caseId}/hypotheses/${encodeURIComponent(id)}/exclusions`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ eventId, reason }),
    })
      .then(() => loadHypotheses(caseId))
      .catch(() => {});
  }
  function hypRestoreEvidence(id, eventId) {
    const caseId = document.getElementById("caseId").value.trim();
    if (!caseId) return;
    fetch(`/cases/${caseId}/hypotheses/${encodeURIComponent(id)}/exclusions/${encodeURIComponent(eventId)}`, {
      method: "DELETE",
    })
      .then(() => loadHypotheses(caseId))
      .catch(() => {});
  }
  function hypAcknowledgeReview(id) {
    hypPatch(id, { acknowledgeReview: true });
  }
  function hypToggleAlternative(id, altId, checked) {
    const h = hypotheses.find((x) => x.id === id);
    if (!h) return;
    const cur = new Set(h.alternativeIds || []);
    if (checked) cur.add(altId);
    else cur.delete(altId);
    hypPatch(id, { alternativeIds: [...cur] });
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
    // Asked of the notebook rather than reached for: notebookEntries is its state, not ours.
    const entry =
      typeof notebookEntry === "function" ? notebookEntry(id) : null;
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
  window.hypExcludeStart = hypExcludeStart;
  window.hypExcludeCancel = hypExcludeCancel;
  window.hypExcludeConfirm = hypExcludeConfirm;
  window.hypRestoreEvidence = hypRestoreEvidence;
  window.hypAcknowledgeReview = hypAcknowledgeReview;
  window.hypToggleAlternative = hypToggleAlternative;
  window.promoteToHypothesis = promoteToHypothesis;
  window.initHypotheses = initHypotheses;
})();
