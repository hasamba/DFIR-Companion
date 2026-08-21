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
  let hostScopeLoadSeq = 0; // generation token: only the latest load may mutate the ledger
  let hostScopeFilter = "all";

  const STATUS_LABEL = {
    unknown: "Not assessed",
    suspected: "Suspected",
    confirmed: "Confirmed",
    cleared: "Cleared",
    "out-of-scope": "Out of scope",
  };

  const STATUS_ORDER = ["confirmed", "suspected", "unknown", "cleared", "out-of-scope"];

  // Presence is a derived enum, and its raw values sit in a table column next to sentence-case
  // statuses. Capitalisation only — "referenced" and "enrolled-only" are the domain's words and
  // renaming them here would put a second vocabulary in front of the analyst.
  const PRESENCE_LABEL = {
    collected: "Collected",
    referenced: "Referenced",
    "enrolled-only": "Enrolled only",
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

  // The board doubles as the table's filter. setHostScopeFilter shipped with nothing on the page
  // able to call it, which left five inert numbers sitting above a table that can run to thousands
  // of rows — a legend where the obvious control belongs.
  function statTile(key, label, count) {
    return (
      `<button type="button" class="hs-stat" data-hs-filter="${escAttr(key)}" ` +
      `aria-pressed="${hostScopeFilter === key ? "true" : "false"}">` +
      `<span class="hs-stat-n">${num(count)}</span>` +
      `<span class="hs-stat-l">${esc(label)}</span></button>`
    );
  }

  function statusBoard(ledger) {
    const c = ledger.counts || {};
    const total = STATUS_ORDER.reduce((sum, k) => sum + Number(c[k] || 0), 0);
    const cells =
      statTile("all", "All hosts", total) +
      STATUS_ORDER.map((k) => statTile(k, STATUS_LABEL[k], c[k])).join("");

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
        return (
          `<li><code>${esc(h.name)}</code>` + `<span class="hs-why">${esc(String(why))}</span></li>`
        );
      })
      .join("");
    return `<ol class="hs-gaps">${items}</ol>`;
  }

  function criteriaList(host) {
    const criteria = (host.eligibility && host.eligibility.criteria) || [];
    if (!criteria.length) return "";
    // The tick carries the meaning, so it gets its own element to colour. Inlined in the text it
    // was a glyph in body colour, and a four-line checklist read as four identical lines.
    const items = criteria
      .map(
        (c) =>
          `<li class="${c.met ? "hs-met" : "hs-unmet"}">` +
          `<span class="hs-mark">${c.met ? "✔" : "✖"}</span>` +
          `<span>${esc(String(c.detail))}</span></li>`,
      )
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
    // Chips rather than a comma-joined string: seven tool names on one line pushed every other
    // column narrow, and the run-on read as prose in a cell that holds a set.
    const sources = (host.sources || []).length
      ? host.sources.map((s) => `<span class="hs-src">${esc(s)}</span>`).join("")
      : `<span class="hs-none">—</span>`;
    return (
      `<tr data-host="${escAttr(host.name)}">` +
      `<td class="hs-c-host"><code>${esc(host.name)}</code>${host.stale ? ' <span class="hs-stale">review</span>' : ""}</td>` +
      `<td class="hs-c-status"><span class="hs-badge hs-s-${escAttr(host.effectiveStatus)}">` +
      `${esc(STATUS_LABEL[host.effectiveStatus] || host.effectiveStatus)}</span></td>` +
      `<td class="hs-c-presence">${esc(PRESENCE_LABEL[host.presence] || host.presence)}</td>` +
      `<td class="hs-c-events">${num(host.eventCount)}</td>` +
      `<td class="hs-c-sources">${sources}</td>` +
      `<td class="hs-c-criteria">${criteriaList(host)}${decided}${actionsFor(host)}</td>` +
      `</tr>`
    );
  }

  // The column classes are on the HEADER cells too, and deliberately: the stylesheet sets
  // table-layout:fixed, which reads its widths from the first row and ignores every later one.
  function hostTable(ledger) {
    const rows = ledger.hosts.filter(
      (h) => hostScopeFilter === "all" || h.effectiveStatus === hostScopeFilter,
    );
    if (!rows.length) return `<p class="hs-empty">No hosts match this filter.</p>`;
    return (
      `<div class="hs-scroll"><table class="hs-table"><thead><tr>` +
      `<th class="hs-c-host">Host</th><th class="hs-c-status">Status</th>` +
      `<th class="hs-c-presence">Presence</th><th class="hs-c-events">Events</th>` +
      `<th class="hs-c-sources">Sources</th><th class="hs-c-criteria">Clearance criteria</th>` +
      `</tr></thead><tbody>${rows.map(hostRow).join("")}</tbody></table></div>`
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
    // A generation token, bumped per load, guards the ledger against out-of-order responses — the
    // same pattern as loadAssetGraph: when the analyst switches cases fast, an older request's
    // late response (success OR failure) must not overwrite or erase the newer case's ledger.
    // And for the LATEST load a failure must CLEAR the ledger and repaint: the per-case resets in
    // js/dashboard-case-connect.js never touch this module's state, so a swallowed failure here
    // kept the PREVIOUS case's clearance board on screen — "Cleared"/"Confirmed" for the wrong
    // case, on the surface analysts use for scoping calls. A transient same-case failure stays
    // harmless: the panel shows the failure until the next successful reload repaints it.
    const seq = ++hostScopeLoadSeq;
    try {
      const r = await fetch(`/cases/${encodeURIComponent(caseId)}/host-scope`);
      if (!r.ok) {
        const e = await r.json().catch(() => ({}));
        if (seq !== hostScopeLoadSeq) return; // superseded by a newer load — ignore entirely
        hostScopeLedger = null;
        // 501 means the store is not configured — the default "No scope data." empty state is the
        // honest rendering, not an error. Everything else surfaces: routes/hostScope.ts
        // deliberately 500s with the error message when the ledger file is corrupt (fail-loud),
        // and swallowing that here silenced the design at its last hop.
        if (r.status === 501) {
          paintHostScope();
          return;
        }
        // Null-guarded like paintHostScope: the unit-test harness stubs getElementById to null.
        const el = document.getElementById("hostScopeBody");
        if (el) {
          el.innerHTML = `<p class="hs-empty">Host scope unavailable: ${esc(e.error || "HTTP " + r.status)}</p>`;
        }
        return;
      }
      const ledger = await r.json();
      if (seq !== hostScopeLoadSeq) return; // a stale success must not overwrite the newer case
      hostScopeLedger = ledger;
      paintHostScope();
    } catch {
      // A panel that cannot load must not take the dashboard down with it — but the LATEST load's
      // network failure still clears and repaints, so a case switch while the companion restarts
      // cannot leave the previous case's clearance decisions on screen.
      if (seq !== hostScopeLoadSeq) return; // superseded by a newer load — ignore entirely
      hostScopeLedger = null;
      const el = document.getElementById("hostScopeBody");
      if (el) {
        el.innerHTML = `<p class="hs-empty">Host scope could not be loaded.</p>`;
      }
    }
  }

  async function decideHostScope(caseId, host, to, reason) {
    // Capture the generation token: if a newer ledger load starts while this decision is in
    // flight (a case switch, or a reload), the response's ledger belongs to the superseded state
    // and must not overwrite the newer one — the same rule loadHostScope enforces. The decision
    // itself still landed server-side, so the caller's success flow is unaffected; only the
    // local cache and pane are protected from being repainted with the old case's board.
    const seq = hostScopeLoadSeq;
    const r = await fetch(
      `/cases/${encodeURIComponent(caseId)}/host-scope/${encodeURIComponent(host)}`,
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ to, reason }),
      },
    );
    if (!r.ok) {
      // Throw rather than return false: the ledger is append-only and quoted in the report, so a
      // decision that never landed must be SAID — the caller surfaces this, no caller consumed
      // the boolean, and a silent false left the analyst believing their clearance was recorded.
      const e = await r.json().catch(() => ({}));
      throw new Error(e.error || "HTTP " + r.status);
    }
    const ledger = await r.json();
    if (seq === hostScopeLoadSeq) {
      hostScopeLedger = ledger;
      paintHostScope();
    }
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
    const target = evt.target && evt.target.closest ? evt.target : null;
    if (!target) return;

    // Filtering is local — no case id, no request, no decision recorded.
    const tile = target.closest("[data-hs-filter]");
    if (tile) {
      setHostScopeFilter(tile.getAttribute("data-hs-filter"));
      return;
    }

    const button = target.closest("[data-hs-action]");
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
    // Failures are surfaced, not swallowed (same convention as hunt-workbench's
    // `void deleteHunt().catch(reportActionError)`): a rejected fetch or a server rejection means
    // the decision never reached the ledger, and the panel is not repainted, so the UI cannot
    // pretend it succeeded.
    void decideHostScope(caseId.trim(), host, to, reason).catch((err) => {
      alert("Could not record decision for " + host + ": " + err.message);
    });
  }

  globalThis.renderHostScope = renderHostScope;
  globalThis.loadHostScope = loadHostScope;
  globalThis.decideHostScope = decideHostScope;
  globalThis.setHostScopeFilter = setHostScopeFilter;
})();
