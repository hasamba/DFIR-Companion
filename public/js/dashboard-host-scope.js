// Host scope & clearance panel.
//
// Answers "what is affected, and how do we know the rest is clean?" — a status board, a ranked list
// of scope GAPS, and a per-host table. The gap list comes first on purpose: a host three compromised
// machines reached that nobody ever collected is the finding here, and it would be invisible at the
// bottom of a 5,000-row table.
//
// Two things this panel must never do, both of which the server already refuses to do:
//   - show a single "% clean" figure. The evidence-scope and fleet numbers have different
//     denominators, and the fleet one is omitted entirely when there is no inventory snapshot.
//   - describe a cleared host as clean. Clearance means "no evidence of compromise was found, given
//     what was collected".
//
// AN IIFE: this feature owns state, and a top-level `let` in a classic script joins the global
// lexical environment (see js/dashboard-state.js). NOT AN ES MODULE — the inline script calls the
// published names below by bare name.
(function () {
  let hostScopeLedger = null;
  let hostScopeFilter = "all";

  const STATUS_LABEL = {
    unknown: "Not assessed",
    suspected: "Suspected",
    confirmed: "Confirmed",
    cleared: "Cleared",
    "out-of-scope": "Out of scope",
  };

  function num(n) {
    return Number(n || 0).toLocaleString("en-US");
  }

  // Gap ranking: stale clearances first (a signed assertion the evidence has moved under), then
  // hosts nobody collected, then leads with nothing to analyse, then partial coverage.
  function gapRank(host) {
    if (host.stale) return 0;
    if (host.presence === "referenced") return 1;
    if (host.presence === "enrolled-only") return 2;
    if (host.derivedStatus === "suspected") return 3;
    return 4;
  }

  function gapsOf(ledger) {
    return ledger.hosts
      .filter((h) => h.stale || h.gap)
      .sort((a, b) => gapRank(a) - gapRank(b) || a.name.localeCompare(b.name));
  }

  function statusBoard(ledger) {
    const c = ledger.counts || {};
    const cells = ["confirmed", "suspected", "unknown", "cleared", "out-of-scope"]
      .map(
        (k) =>
          `<div class="hs-stat"><span class="hs-stat-n">${num(c[k])}</span>` +
          `<span class="hs-stat-l">${esc(STATUS_LABEL[k])}</span></div>`,
      )
      .join("");

    const fleet = ledger.fleet
      ? `<p class="hs-fleet">Evidence collected from <strong>${num(ledger.fleet.collected)}</strong> of ` +
        `<strong>${num(ledger.fleet.enrolled)}</strong> enrolled endpoints ` +
        `(inventory dated ${esc(String(ledger.fleet.snapshotAt).slice(0, 10))}). ` +
        `Enrolled endpoints may not represent the whole estate.</p>`
      : "";

    return `<div class="hs-board">${cells}</div>${fleet}`;
  }

  function nearDuplicateWarnings(ledger) {
    const dupes = ledger.nearDuplicates || [];
    if (!dupes.length) return "";
    const items = dupes
      .map(
        (d) =>
          `<li><code>${esc(d.other)}</code> and <code>${esc(d.canonical)}</code> may be the same host — ` +
          `merge them in the asset graph if so. They are counted separately until you do.</li>`,
      )
      .join("");
    return `<div class="hs-warn"><strong>Possible duplicate hosts</strong><ul>${items}</ul></div>`;
  }

  function gapList(ledger) {
    const gaps = gapsOf(ledger);
    if (!gaps.length) return `<p class="hs-empty">No scope gaps.</p>`;
    const items = gaps
      .map((h) => {
        const why = h.stale ? `clearance needs review — ${h.stale}` : h.gap;
        return `<li><code>${esc(h.name)}</code> — ${esc(String(why))}</li>`;
      })
      .join("");
    return `<ol class="hs-gaps">${items}</ol>`;
  }

  function criteriaList(host) {
    const criteria = (host.eligibility && host.eligibility.criteria) || [];
    if (!criteria.length) return "";
    const items = criteria
      .map((c) => `<li>${c.met ? "✔" : "✖"} ${esc(String(c.detail))}</li>`)
      .join("");
    return `<ul class="hs-criteria">${items}</ul>`;
  }

  // Per-row actions. The reason is REQUIRED for cleared/out-of-scope and the server rejects an
  // empty one, so the prompt is cancelled-safe: no reason, no request.
  function actionsFor(host) {
    const name = escAttr(host.name);
    const buttons = [];
    if (host.effectiveStatus !== "cleared")
      buttons.push(
        `<button type="button" class="hs-act" data-hs-action="cleared" data-hs-host="${name}" title="Record that no evidence of compromise was found on this host, given the sources collected">Clear…</button>`,
      );
    if (host.effectiveStatus !== "out-of-scope")
      buttons.push(
        `<button type="button" class="hs-act" data-hs-action="out-of-scope" data-hs-host="${name}" title="Mark this host outside the investigation's scope">Out of scope…</button>`,
      );
    // Reopen is offered against any LIVE assertion — cleared and out-of-scope, but also a manual
    // suspected/confirmed escalation, which is equally a decision an analyst may want to retract.
    // Two earlier versions of this gate were wrong in opposite directions: keying on "a decision
    // exists" kept the button on an already-reopened host (a no-op that dirties an append-only log),
    // and narrowing it to the two clearance statuses stranded manual escalations with no way back to
    // automatic. The rule that holds is the server's: `unknown` is a retraction, everything else
    // asserts something, and you can retract exactly what is asserted.
    if (host.decision && host.decision.to !== "unknown")
      buttons.push(
        `<button type="button" class="hs-act" data-hs-action="unknown" data-hs-host="${name}" title="Return this host to its derived status">Reopen</button>`,
      );
    return `<div class="hs-actions">${buttons.join(" ")}</div>`;
  }

  function hostRow(host) {
    const decided = host.decision
      ? `<div class="hs-decision">${esc(STATUS_LABEL[host.decision.to] || host.decision.to)} by ` +
        `${esc(host.decision.analyst)} — ${esc(host.decision.reason)}</div>`
      : "";
    return (
      `<tr data-host="${escAttr(host.name)}">` +
      `<td><code>${esc(host.name)}</code>${host.stale ? ' <span class="hs-stale">review</span>' : ""}</td>` +
      `<td>${esc(STATUS_LABEL[host.effectiveStatus] || host.effectiveStatus)}</td>` +
      `<td>${esc(host.presence)}</td>` +
      `<td>${num(host.eventCount)}</td>` +
      `<td>${esc((host.sources || []).join(", "))}</td>` +
      `<td>${criteriaList(host)}${decided}${actionsFor(host)}</td>` +
      `</tr>`
    );
  }

  function hostTable(ledger) {
    const rows = ledger.hosts.filter(
      (h) => hostScopeFilter === "all" || h.effectiveStatus === hostScopeFilter,
    );
    if (!rows.length) return `<p class="hs-empty">No hosts match this filter.</p>`;
    return (
      `<table class="hs-table"><thead><tr>` +
      `<th>Host</th><th>Status</th><th>Presence</th><th>Events</th><th>Sources</th><th>Clearance criteria</th>` +
      `</tr></thead><tbody>${rows.map(hostRow).join("")}</tbody></table>`
    );
  }

  // Pure: the whole panel as a string, so it is testable without a DOM. Order is the contract —
  // gaps above the table.
  function renderHostScope(ledger) {
    if (!ledger) return `<p class="hs-empty">No scope data.</p>`;
    return (
      statusBoard(ledger) +
      nearDuplicateWarnings(ledger) +
      `<h4>Scope gaps</h4>` +
      gapList(ledger) +
      `<h4>Hosts</h4>` +
      hostTable(ledger)
    );
  }

  function paintHostScope() {
    const el = document.getElementById("hostScopeBody");
    if (!el) return;
    el.innerHTML = renderHostScope(hostScopeLedger);
    // Bind here rather than from a page-level init: dashboard.html's inline script is at its size
    // budget, and one delegated listener guarded by a dataset flag is idempotent across repaints.
    if (!el.dataset.hsBound) {
      el.addEventListener("click", onPanelClick);
      el.dataset.hsBound = "1";
    }
  }

  async function loadHostScope(caseId) {
    if (!caseId) return;
    try {
      const r = await fetch(`/cases/${encodeURIComponent(caseId)}/host-scope`);
      if (!r.ok) return;
      hostScopeLedger = await r.json();
      paintHostScope();
    } catch {
      // A panel that cannot load must not take the dashboard down with it.
    }
  }

  async function decideHostScope(caseId, host, to, reason) {
    const r = await fetch(
      `/cases/${encodeURIComponent(caseId)}/host-scope/${encodeURIComponent(host)}`,
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ to, reason }),
      },
    );
    if (!r.ok) return false;
    hostScopeLedger = await r.json();
    paintHostScope();
    return true;
  }

  function setHostScopeFilter(status) {
    hostScopeFilter = status || "all";
    paintHostScope();
  }

  // ONE delegated listener on the panel body, bound once. The body's innerHTML is replaced on every
  // repaint, so per-button listeners would be lost each time; delegation survives the repaint and
  // keeps the handler count at one however many hosts a case has.
  function onPanelClick(evt) {
    const button = evt.target && evt.target.closest ? evt.target.closest("[data-hs-action]") : null;
    if (!button) return;
    const host = button.getAttribute("data-hs-host");
    const to = button.getAttribute("data-hs-action");
    if (!host || !to) return;

    const caseId = (document.getElementById("caseId") || {}).value;
    if (!caseId || !caseId.trim()) return;

    let reason = "";
    if (to === "cleared" || to === "out-of-scope") {
      const asked = prompt(
        to === "cleared"
          ? `Clear ${host}? State what supports it — this is recorded against your name and quoted in the report.`
          : `Mark ${host} out of scope? State why.`,
        "",
      );
      // Cancelled, or an empty reason the server would reject anyway.
      if (asked === null || !asked.trim()) return;
      reason = asked.trim();
    }
    void decideHostScope(caseId.trim(), host, to, reason);
  }

  globalThis.renderHostScope = renderHostScope;
  globalThis.loadHostScope = loadHostScope;
  globalThis.decideHostScope = decideHostScope;
  globalThis.setHostScopeFilter = setHostScopeFilter;
})();
