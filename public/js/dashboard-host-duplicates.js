// Near-duplicate host review — the merge gate's UI surface.
//
// AN IIFE: this feature owns state, and a top-level `let` in a classic script joins the global
// lexical environment. NOT AN ES MODULE — the inline script calls the published names by bare name.
//
// renderHostDuplicates is a PURE string function with no DOM access, so it is testable through
// loadDashboardModule, which runs this file in a Node vm context with no document.
(function () {
  "use strict";

  let pending = [];
  let dismissed = [];

  // Two actions, same buttons, same delegated handler, regardless of reason — merging an IP into
  // a host name is exactly the same "treat this spelling as that host" operation as a name-
  // spelling merge. Only the surrounding wording differs by reason, because the two are different
  // strengths of evidence: a name-spelling pair blocks analysis (hard gate, see
  // pendingNearDuplicates); a network-identity pair never does (see pendingNetworkIdentityDuplicates)
  // — the banner below must never claim analysis is held when only the latter is pending.
  function actionButtons(d) {
    return (
      `<button data-hd-merge="1" data-hd-canonical="${escAttr(d.canonical)}" data-hd-other="${escAttr(d.other)}" ` +
      `title="${d.reason === "network-identity" ? "Fold this address into the named host." : "Treat these as one host. Analysis re-runs once every pair is resolved."}">Same host — merge</button> ` +
      `<button data-hd-dismiss="1" data-hd-canonical="${escAttr(d.canonical)}" data-hd-other="${escAttr(d.other)}" ` +
      `title="${d.reason === "network-identity" ? "Not the same machine. You won't be asked again." : "Two different machines. You won't be asked about this pair again."}">Different hosts</button>`
    );
  }

  // #1170: every dismissal is listed, with a per-pair undo — the only prior workaround (deleting
  // the whole host-duplicate-dismissals.json file on disk) silently re-armed EVERY dismissal in
  // the case, not just the one the analyst wanted to reconsider. `dismissedList` is optional and
  // defaults to none, so this stays a pure, backward-compatible extension of the existing
  // rendering contract (every prior caller/test still passes one argument).
  function dismissedRows(dismissedList) {
    if (!dismissedList || !dismissedList.length) return "";
    const rows = dismissedList
      .map(
        (d) =>
          `<div class="hd-row hd-dismissed-row">` +
          `<code>${esc(d.other)}</code> and <code>${esc(d.canonical)}</code> — dismissed as different machines ` +
          `${d.dismissedAt ? `on ${esc(fmtDateTime(d.dismissedAt))}` : ""}${d.dismissedBy ? ` by ${esc(d.dismissedBy)}` : ""}. ` +
          `<button data-hd-undo="1" data-hd-canonical="${escAttr(d.canonical)}" data-hd-other="${escAttr(d.other)}" ` +
          `title="Reconsider — this pair becomes eligible to be suggested again.">Undo</button>` +
          `</div>`,
      )
      .join("");
    return `<details class="hd-dismissed"><summary>Previously dismissed (${dismissedList.length})</summary>${rows}</details>`;
  }

  function renderHostDuplicates(list, dismissedList) {
    if ((!list || !list.length) && (!dismissedList || !dismissedList.length))
      return "";
    if (!list) list = [];
    const blocking = list.filter((d) => d.reason !== "network-identity");
    const networkIdentity = list.filter((d) => d.reason === "network-identity");

    const blockingRows = blocking
      .map(
        (d) =>
          `<div class="hd-row">` +
          `<code>${esc(d.other)}</code> and <code>${esc(d.canonical)}</code> may be the same machine. ` +
          `${actionButtons(d)}` +
          `</div>`,
      )
      .join("");
    const blockingBlock = blocking.length
      ? `<div class="hd-warn"><strong>Analysis is on hold.</strong> ` +
        `${blocking.length} host${blocking.length === 1 ? " appears" : "s appear"} under more than one name. ` +
        `Until you decide, the AI would treat one machine as two — splitting its evidence and its ` +
        `timeline. Resolve each pair and analysis restarts automatically.</div>${blockingRows}`
      : "";

    const networkIdentityRows = networkIdentity
      .map(
        (d) =>
          `<div class="hd-row">` +
          `<code>${esc(d.other)}</code> may belong to the same machine as <code>${esc(d.canonical)}</code> — ` +
          `last seen using this address ${esc(d.sampleTime ? fmtDateTime(d.sampleTime) : "recently")}. ` +
          `${actionButtons(d)}` +
          `</div>`,
      )
      .join("");
    const networkIdentityBlock = networkIdentity.length
      ? `<div class="hd-suggest"><strong>Possible network identity match${networkIdentity.length === 1 ? "" : "es"}.</strong> ` +
        `${networkIdentity.length} address${networkIdentity.length === 1 ? "" : "es"} may belong to a named host ` +
        `already in this case.</div>${networkIdentityRows}`
      : "";

    return blockingBlock + networkIdentityBlock + dismissedRows(dismissedList);
  }

  // The section is DATA-GATED: hidden while nothing is pending, shown the moment something is.
  //
  // Opening the gate alone is not enough. applyViewLayout writes `false` into SECTIONS_VIS_KEY for
  // every section a view omits, and the Now view omitted this one — so on any dashboard that had
  // ever shown the cockpit, the stored preference said "hidden", and applyViewLayout carries a
  // GATED section's stored choice through untouched. The gate would open onto a section the
  // preference still hid. Forcing the stored value on while a pair is pending is deliberate: this
  // is a stopped pipeline, not a layout taste, and the only control that can restart it lives here.
  // The gate closing is what hides it again, so the analyst's choice is never permanently rewritten
  // into "always show".
  function paintSectionGate() {
    const sec = document.getElementById("sec-host-duplicates");
    if (!sec) return;
    // Open for a pending pair OR a past dismissal (#1170) — an analyst reconsidering an old
    // "different machines" call must be able to reach it even when nothing else is outstanding.
    const hasContent = pending.length || dismissed.length;
    sec.dataset.gateOpen = hasContent ? "1" : "";
    if (hasContent) {
      try {
        const vis = JSON.parse(localStorage.getItem(SECTIONS_VIS_KEY) || "{}");
        if (vis["sec-host-duplicates"] !== true) {
          vis["sec-host-duplicates"] = true;
          localStorage.setItem(SECTIONS_VIS_KEY, JSON.stringify(vis));
        }
      } catch {
        // A wedged localStorage must not stop the gate itself from opening.
      }
    }
    applySectionsVis();
  }

  function paint() {
    const badge = document.getElementById("hostDuplicatesBadge");
    if (badge) {
      badge.style.display = pending.length ? "" : "none";
      badge.textContent = "⚠ Duplicate hosts: " + pending.length;
    }
    paintSectionGate();
    const el = document.getElementById("hostDuplicatesBody");
    if (!el) return;
    el.innerHTML = renderHostDuplicates(pending, dismissed);
    // One delegated listener, bound once: innerHTML is replaced on every repaint, so per-button
    // listeners would be lost each time.
    if (!el.dataset.hdBound) {
      el.addEventListener("click", onPanelClick);
      el.dataset.hdBound = "1";
    }
  }

  async function loadHostDuplicates(caseId) {
    if (!caseId) return;
    try {
      const [pendingRes, dismissedRes] = await Promise.all([
        fetch(`/cases/${encodeURIComponent(caseId)}/host-duplicates`),
        fetch(`/cases/${encodeURIComponent(caseId)}/host-duplicates/dismissed`),
      ]);
      if (pendingRes.ok) pending = (await pendingRes.json()).pending || [];
      if (dismissedRes.ok)
        dismissed = (await dismissedRes.json()).dismissed || [];
      paint();
    } catch {
      // A panel that cannot load must not take the dashboard down with it.
    }
  }

  async function resolve(caseId, action, canonical, other) {
    try {
      const r = await fetch(
        `/cases/${encodeURIComponent(caseId)}/host-duplicates/${action}`,
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ canonical: canonical, other: other }),
        },
      );
      if (!r.ok) return;
      const d = await r.json();
      pending = d.pending || [];
      paint();
      // Resolving the last pair lifts the gate and the server kicks the held run — but that kick
      // emits nothing until it actually starts, so without this the pill sits on "on hold" over a
      // case that is no longer held. Re-derive now rather than wait for an event that may be
      // seconds away or, if the kick is a no-op, never come.
      refreshAiState(caseId);
    } catch {
      /* leave the panel as it was */
    }
  }

  // #1170: undo never kicks a resynthesis — re-arming the gate (if it was a blocking pair) is the
  // correct, expected outcome of an explicit "reconsider this" action, not a resume.
  async function undoDismiss(caseId, canonical, other) {
    try {
      const r = await fetch(
        `/cases/${encodeURIComponent(caseId)}/host-duplicates/dismiss`,
        {
          method: "DELETE",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ canonical: canonical, other: other }),
        },
      );
      if (!r.ok) return;
      const d = await r.json();
      dismissed = d.dismissed || [];
      pending = d.pending || [];
      paint();
      // /cases/:id/ai-state live-derives its "blocked" readout from loadPendingHostDuplicates on
      // every call, so undoing a blocking pair genuinely re-arms it immediately — without this the
      // pill keeps showing the last completed run's status until something else happens to poll it
      // (Ollama review finding on #1170, mirrors resolve()'s own identical call for the same reason).
      refreshAiState(caseId);
    } catch {
      /* leave the panel as it was */
    }
  }

  function onPanelClick(evt) {
    const target = evt.target && evt.target.closest ? evt.target : null;
    if (!target) return;
    const button = target.closest(
      "[data-hd-merge], [data-hd-dismiss], [data-hd-undo]",
    );
    if (!button) return;
    const caseId = (document.getElementById("caseId") || {}).value;
    if (!caseId || !caseId.trim()) return;
    const canonical = button.getAttribute("data-hd-canonical");
    const other = button.getAttribute("data-hd-other");
    if (button.hasAttribute("data-hd-undo")) {
      void undoDismiss(caseId.trim(), canonical, other);
      return;
    }
    const action = button.hasAttribute("data-hd-merge") ? "merge" : "dismiss";
    if (
      action === "merge" &&
      !confirm(`Treat ${other} and ${canonical} as one host?`)
    )
      return;
    void resolve(caseId.trim(), action, canonical, other);
  }

  // The badge lives in the page header, so this binds at load, not on module evaluation.
  function initHostDuplicates() {
    document
      .getElementById("hostDuplicatesBadge")
      ?.addEventListener("click", revealHostDuplicates);
  }

  // Re-open the gate before scrolling. paint() already opened it, but a dashboard-view switch
  // between then and now re-runs applySectionsVis from stored preferences, and scrolling to a
  // display:none section is a silent no-op — which is exactly how this chip came to look dead.
  function revealHostDuplicates() {
    paintSectionGate();
    const sec = document.getElementById("sec-host-duplicates");
    if (!sec) return;
    sec.classList.remove("collapsed");
    sec.scrollIntoView({ behavior: "smooth", block: "start" });
  }

  window.loadHostDuplicates = loadHostDuplicates;
  window.renderHostDuplicates = renderHostDuplicates;
  window.initHostDuplicates = initHostDuplicates;
  // Published for the cockpit's blocker card, which targets panel "host-duplicates".
  window.revealHostDuplicates = revealHostDuplicates;
})();
