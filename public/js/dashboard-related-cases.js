// Related Cases (#679) — the other investigations that share indicators with this one.
//
// AN IIFE: this feature owns state (the last fetched list), and a top-level `let` in a classic
// script joins the global lexical environment. NOT AN ES MODULE — the inline script and the
// case-connect loader call the published names by bare name.
//
// renderRelatedCases is a PURE string function with no DOM access, so it is testable through
// loadDashboardModule, which runs this file in a Node vm context with no document.
(function () {
  "use strict";

  let relatedCases = [];
  // The case the panel is currently showing (or loading). Two jobs, both about staleness: it tells
  // a case SWITCH from a same-case refresh, and it lets a late response for an abandoned case be
  // dropped instead of painted over the case now on screen.
  let relatedCasesFor = "";

  function statusBadge(status) {
    // "open" is the norm and says nothing; the other two change how the analyst reads the link.
    if (!status || status === "open") return "";
    return `<span class="rc-status rc-status-${escAttr(status)}">${esc(status)}</span>`;
  }

  function sharedChip(shared) {
    const types = (shared.types || []).join(", ");
    const marks = [];
    if (shared.malicious) marks.push("flagged malicious or suspicious by threat intel");
    if (shared.isInternal) marks.push("a private address inside the estate — a weak link");
    const why = marks.length ? ` — ${marks.join("; ")}` : "";
    const cls =
      "rc-ioc" + (shared.malicious ? " rc-ioc-mal" : "") + (shared.isInternal ? " rc-ioc-int" : "");
    return (
      `<code class="${cls}" title="${escAttr(types + why)}">` +
      `${shared.malicious ? "⚠ " : ""}${esc(shared.value)}</code>`
    );
  }

  function renderRelatedCase(item) {
    const shared = item.shared || [];
    const hidden = Math.max(0, (item.sharedCount || shared.length) - shared.length);
    const label = item.name ? `${item.caseId} — ${item.name}` : item.caseId;
    const tally =
      `${item.sharedCount} shared indicator${item.sharedCount === 1 ? "" : "s"}` +
      (item.maliciousCount ? `, ${item.maliciousCount} flagged` : "");
    return (
      `<div class="rc-case">` +
      `<div class="rc-head">` +
      `<a class="rc-open" href="/dashboard?caseId=${encodeURIComponent(item.caseId)}" ` +
      `title="Open ${escAttr(item.caseId)}">${esc(label)}</a>` +
      statusBadge(item.status) +
      `<span class="rc-tally" title="Overlap strength ${esc(String(item.score))} — a file hash or ` +
      `an indicator with a malicious verdict counts for more than a private address">${esc(tally)}</span>` +
      `</div>` +
      `<div class="rc-shared">` +
      shared.map(sharedChip).join("") +
      (hidden ? `<span class="rc-more">+${hidden} more</span>` : "") +
      `</div></div>`
    );
  }

  // The list is EVIDENCE OF AN OVERLAP, NOT OF A LINK. Two cases in one estate share a DNS
  // resolver; that is not a campaign. The lead sentence says so, because a panel titled "Related
  // Cases" invites the opposite reading and the analyst is the one who has to defend it.
  function renderRelatedCases(list) {
    if (!list || !list.length) return "";
    return (
      `<p class="rc-intro">${list.length} other case${list.length === 1 ? "" : "s"} share ` +
      `indicators with this one, strongest overlap first. A shared indicator is a lead to check, ` +
      `not a proven link — indicators an estate has in common for ordinary reasons are shown but ` +
      `count for less.</p>` +
      list.map(renderRelatedCase).join("")
    );
  }

  // The section is DATA-GATED: hidden until this case actually overlaps with another. Unlike the
  // duplicate-host gate, this one never forces the stored visibility preference back on — nothing
  // here is blocking the pipeline, so an analyst who hid the panel meant it.
  function paintSectionGate() {
    const sec = document.getElementById("sec-related-cases");
    if (!sec) return;
    sec.dataset.gateOpen = relatedCases.length ? "1" : "";
    applySectionsVis();
  }

  function paint() {
    paintSectionGate();
    const el = document.getElementById("relatedCasesBody");
    if (!el) return;
    el.innerHTML = renderRelatedCases(relatedCases);
  }

  async function loadRelatedCases(caseId) {
    const id = caseId || "";
    // CLEAR ON A CASE SWITCH, BEFORE THE REQUEST. Showing case A's related cases while case B
    // loads is not a slow repaint, it is a wrong claim about the case on screen — and if B's
    // request then 404s, 501s or throws, the early returns below never repaint, so A's links would
    // sit on B's dashboard until the next reload. Clearing first makes the failure mode an empty,
    // closed panel, which is the honest one.
    //
    // A same-case refresh (the ai_status "idle" hook fires on every settled import) deliberately
    // does NOT clear: those rows are still this case's, and blanking the panel on every import
    // would flicker for no gain.
    if (relatedCasesFor !== id) {
      relatedCases = [];
      relatedCasesFor = id;
      paint();
    }
    if (!id) return;
    try {
      const r = await fetch(`/cases/${encodeURIComponent(id)}/related`);
      if (!r.ok) return;
      const d = await r.json();
      // A connect to another case while this request was in flight wins: panel loaders are fired
      // per connect and are not awaited, so two can overlap.
      if (relatedCasesFor !== id) return;
      relatedCases = d.related || [];
      paint();
    } catch {
      // A panel that cannot load must not take the dashboard down with it.
    }
  }

  window.loadRelatedCases = loadRelatedCases;
  window.renderRelatedCases = renderRelatedCases;
})();
