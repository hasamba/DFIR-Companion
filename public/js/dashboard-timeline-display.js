// Timeline row display toggles — which columns and badges each timeline row shows (#415 tier 3).
//
// ITS WIRING IS AN INITIALIZER: the checkbox list plus Select all / Deselect all, bound at module
// scope in the page. In a <head> script they would query #tlDisplayChecks before it exists.
(function () {
  // ── Timeline row display toggles ───────────────────────────────────────────
  // Per-browser choice of which sub-elements appear in each forensic-timeline event row.
  // The timestamp + message are always shown ("the event itself"); everything else is opt-out.
  // Default = all ON (current behavior). Read by renderTimelineEvents via tlShow().
  const TL_DISPLAY_KEY = "dfir.tlDisplay";
  const TL_FIELDS = [
    [
      "icons",
      "Action icons (★ star · 💬 comment · 🏷 tag · 🔍 hunt · 💡 explain · 📍 map)",
    ],
    ["tags", "Analyst tag pills"],
    ["badges", "Badges (×count · ⊕ sources · chain · NEW)"],
    ["host", "Host / asset chip"],
    ["mitre", "MITRE techniques"],
    ["findings", "Related findings"],
    ["evidence", "Evidence links"],
  ];
  function loadTlDisplay() {
    try {
      return JSON.parse(localStorage.getItem(TL_DISPLAY_KEY) || "{}");
    } catch {
      return {};
    }
  }
  // A field is shown unless the user explicitly turned it off (default ON).
  function tlShow(key, d) {
    d = d || loadTlDisplay();
    return d[key] !== false;
  }
  function saveTlDisplay(d) {
    try {
      localStorage.setItem(TL_DISPLAY_KEY, JSON.stringify(d));
    } catch {}
  }
  function renderTlChecks() {
    const container = document.getElementById("tlDisplayChecks");
    if (!container) return;
    const d = loadTlDisplay();
    container.innerHTML = TL_FIELDS.map(
      ([key, label]) =>
        `<label class="sec-check" data-safe-style="cursor:pointer"><input type="checkbox" class="tl-disp-cb" data-key="${esc(key)}" ${tlShow(key, d) ? "checked" : ""}> ${esc(label)}</label>`,
    ).join("");
  }
  // Apply the checkbox states → localStorage and re-render the timeline immediately.
  function applyTlDisplayFromChecks() {
    const d = {};
    document.querySelectorAll("#tlDisplayChecks .tl-disp-cb").forEach((cb) => {
      d[cb.dataset.key] = cb.checked;
    });
    saveTlDisplay(d);
    if (typeof DfirState.lastFt() !== "undefined")
      renderTimelineEvents(DfirState.lastFt());
  }

  // The controls the page bound at module scope. Order unchanged.
  function initTimelineDisplay() {
    document
      .getElementById("tlDisplayChecks")
      .addEventListener("change", applyTlDisplayFromChecks);
    document.getElementById("tlSelectAll").addEventListener("click", () => {
      document
        .querySelectorAll("#tlDisplayChecks .tl-disp-cb")
        .forEach((cb) => {
          cb.checked = true;
        });
      applyTlDisplayFromChecks();
    });
    document.getElementById("tlDeselectAll").addEventListener("click", () => {
      document
        .querySelectorAll("#tlDisplayChecks .tl-disp-cb")
        .forEach((cb) => {
          cb.checked = false;
        });
      applyTlDisplayFromChecks();
    });
  }


  // ── Promotion: the display's half of a rule the server already follows (#1554) ────────
  //
  // MIRRORS companion/src/analysis/forensicGate.ts, demoteBelowSeverity(), whose comment reads:
  // "A promoted row stays regardless of severity: the analyst put it here on purpose, and the cut
  // exists to keep unreviewed telemetry out, not to remove what an analyst asked to see" (#1432).
  //
  // The two halves had drifted apart. On one real case the server kept 265 promoted rows in a
  // 465-row forensic timeline — 262 of them graded Info — and the display dropped every one of
  // them: the severity legend carried no Info entry, and the dashboard-view floor read
  // `e.severity` alone. The analyst saw 182 rows, could not reconcile the arithmetic, and could
  // not find the evidence they had themselves asked for. Server and display now make the same
  // exception, on the same field, for the same stated reason.
  function isPromotedEvent(e) {
    return !!(e && e.promotedAt);
  }

  // An event the analyst typed in by hand (#1919). The server keeps it in the forensic timeline at
  // any severity, exactly like a promoted row — an analyst wrote it there on purpose — and marks it
  // by its id alone (analysis/manualEntry.ts mints `manual-<id>`). It is NOT a promotion: it gets
  // no "✓ Promoted" badge and is counted separately in the label.
  function isManualEvent(e) {
    return !!(e && typeof e.id === "string" && e.id.startsWith("manual-"));
  }

  // The display's half of the server rule: rows no severity filter or view floor may drop.
  function keepsAnySeverity(e) {
    return isPromotedEvent(e) || isManualEvent(e);
  }

  // The compact row's own cue — NOT buried in the collapsed details panel, which is where the
  // second-look provenance line already hid. Deliberately the super-timeline's existing wording
  // (see js/dashboard-super-timeline.js): one idiom for one idea, not a second vocabulary.
  //
  // The tick AND the word carry the meaning. The green is decoration; colour is never the only
  // cue, and the title is where the date lives.
  function promotedBadge(e) {
    if (!isPromotedEvent(e)) return "";
    const when = String(e.promotedAt).slice(0, 19).replace("T", " ");
    return (
      ` <span class="ev-promoted-badge" title="Pulled into the forensic timeline on purpose` +
      ` (${escAttr(when)}). It stays whatever its severity — the same rule the server applies` +
      ` in forensicGate.ts.">✓ Promoted</span>`
    );
  }

  // HOW MANY ROWS ON SCREEN ARE THERE ONLY BECAUSE THEY WERE PROMOTED.
  //
  // With the exemption in place, an analyst who ticks "Critical" alone still sees every promoted
  // Info row. That is correct and would otherwise be inexplicable, so the count label says the
  // number out loud and the arithmetic closes on this screen — rather than sending the analyst
  // off to work out where 262 rows they did not ask for came from (the failure #1547 named).
  //
  // `activeSevs` is the legend's checked set, or null when the legend is not filtering.
  // `meetsFloor` is the view's severity test, or null when no view floor is in force.
  function promotedKeptCount(visible, activeSevs, meetsFloor) {
    return keptCount(visible, activeSevs, meetsFloor, isPromotedEvent);
  }

  // The same count for hand-entered rows (#1919). A manual row that is ALSO promoted is counted
  // once, as promoted, so the two clauses never add up to more rows than the screen holds.
  function manualKeptCount(visible, activeSevs, meetsFloor) {
    return keptCount(visible, activeSevs, meetsFloor, (e) => isManualEvent(e) && !isPromotedEvent(e));
  }

  function keptCount(visible, activeSevs, meetsFloor, kept) {
    let n = 0;
    for (const e of visible || []) {
      if (!kept(e)) continue;
      const bySev = !activeSevs || activeSevs.has(e.severity);
      const byFloor = typeof meetsFloor !== "function" || meetsFloor(e.severity);
      if (!bySev || !byFloor) n++;
    }
    return n;
  }

  // ── Forensic-timeline count label + truncated-search bar (#928) ────────────
  // Lifted out of the inline script rather than added to it: public/dashboard.html#inline-js is
  // frozen at its length by scripts/check-file-size.mjs, and a count that has to explain a FLOOR
  // is more logic than an inline block should carry anyway.
  //
  // A server-side search that matched more events than one response carries hands back a floor,
  // not a count. Printing "10000 events" for it would state a total the case does not support and
  // hide that more matching evidence exists, so the figure is marked and the analyst is told the
  // one thing that reaches the rest: narrow the term.
  function timelineTotalIsFloor() {
    const st = typeof DfirState !== "undefined" ? DfirState.lastState() : null;
    return !!(st && st.forensicTimelineTotalIsLowerBound);
  }

  // HOW MUCH OF THE CASE THE PAGE HAS LOADED (#1916).
  //
  // The state route sends at most 10,000 events, plus the case's real total. The label used to
  // print the batch as if it were the case — "10000 events" on a 70,000-event case — so an analyst
  // could read the first batch as the whole record. A search answer is not this: its total counts
  // matches, and a search floor has its own wording above.
  function timelineLoadState() {
    const st = typeof DfirState !== "undefined" ? DfirState.lastState() : null;
    if (!st || st.forensicTimelineTotalIsLowerBound) return null;
    const loaded = Array.isArray(st.forensicTimeline) ? st.forensicTimeline.length : 0;
    const total = typeof st.forensicTimelineTotal === "number" ? st.forensicTimelineTotal : loaded;
    return total > loaded ? { loaded, total } : null;
  }

  // SAY HOW MANY ROWS THE FILTERS ARE HOLDING BACK, IN THE LABEL (#1554).
  //
  // "203 of 465 events" states a subtraction and leaves the analyst to do it. The one who
  // reported #1554 did the arithmetic by hand against a number they could not reconcile, twice.
  // The difference is a fact this function already holds, so it prints it — and says "hidden by
  // filters", because the rows are in the record, not missing from it.
  function timelineCountLabel(o) {
    const floor = timelineTotalIsFloor();
    const partial = timelineLoadState();
    const totalText = floor ? `${o.total}+` : `${o.total}`;
    const hidden = Math.max(0, (o.total || 0) - (o.totalFiltered || 0));
    const promoted = o.promotedKept > 0 ? o.promotedKept : 0;
    const manual = o.manualKept > 0 ? o.manualKept : 0;
    let base;
    if (o.filtering) {
      base = `${o.totalFiltered} of ${totalText}${partial ? " loaded" : ""} events`;
      if (hidden > 0) base += `, ${hidden} hidden by filters`;
      if (promoted > 0) base += `, ${promoted} promoted kept`;
      if (manual > 0) base += `, ${manual} manual kept`;
      if (partial) base += `; ${partial.total} in case`;
    } else if (partial) {
      base = `${partial.total} events, first ${partial.loaded} loaded`;
    } else {
      base = `${totalText} event${o.total !== 1 ? "s" : ""}`;
    }
    const text = o.pageSize > 0 && o.totalFiltered > o.pageSize
      ? `(${base} — page ${o.page + 1} of ${o.totalPages})`
      : `(${base})`;
    let title = floor
      ? `This search matched more events than one response carries. Only the first ${o.total} are ` +
        "shown — narrow the search term to reach the rest."
      : partial
        ? `This case holds ${partial.total} forensic-timeline events; the dashboard has loaded the ` +
          `first ${partial.loaded}. Paging, filters and counts cover the loaded events only — press ` +
          '"Load more events" under the timeline for the next batch, or search to query the whole case'
        : "Total events in scope; updates in real time";
    if (hidden > 0) {
      title += partial
        ? `. The filters above are hiding ${hidden} of the ${o.total} loaded events. They are still in ` +
          "the record — clear a filter to bring them back."
        : `. The filters above are hiding ${hidden} of this case's ${o.total} forensic-timeline ` +
          "events. They are still in the record — clear a filter to bring them back.";
    }
    if (promoted > 0) {
      title +=
        ` ${promoted} row(s) are shown although your severity filter excludes them: they carry a ` +
        "promotion stamp, so they stay whatever their severity — the same rule the server applies.";
    }
    if (manual > 0) {
      title +=
        ` ${manual} row(s) are shown although your severity filter excludes them: an analyst entered ` +
        "them by hand, so they stay whatever their severity — the same rule the server applies.";
    }
    return { text, title };
  }

  // The client pager walks the events this view HOLDS; when the server held matches back, no amount
  // of paging here can reach them, so the only honest control is one that asks for the next batch.
  //
  // The unfiltered timeline gets the same control (#1916): past its first batch the rest of the
  // case is otherwise unreachable except by searching. Rendered under an empty filter result too —
  // that is exactly when the matching rows may sit in a batch nobody has loaded yet.
  function timelineMoreMatchesBar() {
    if (typeof hasMoreMatches === "function" && hasMoreMatches()) {
      return '<div class="tl-page-bar">'
        + '<span class="tl-page-info">More events match this search than are shown.</span>'
        + '<button class="tl-page-btn" data-act="tlLoadMoreMatches">Load more matches</button>'
        + "</div>";
    }
    const partial = timelineLoadState();
    if (!partial || typeof hasMoreEvents !== "function" || !hasMoreEvents()) return "";
    const busy = typeof loadingMoreEvents === "function" && loadingMoreEvents();
    return '<div class="tl-page-bar">'
      + `<span class="tl-page-info">Showing the first ${Number(partial.loaded)} of ${Number(partial.total)} events.`
      + " Filters and paging cover loaded events only.</span>"
      + `<button class="tl-page-btn" data-act="tlLoadMoreEvents"${busy ? " disabled" : ""}>`
      + (busy ? "Loading…" : "Load more events") + "</button>"
      + "</div>";
  }

  /** Write the label onto the count element. The caller holds no logic, only the numbers. */
  function renderTimelineCount(el, o) {
    if (!el) return;
    const lbl = timelineCountLabel(o);
    el.textContent = lbl.text;
    el.title = lbl.title;
  }

  // ── Which page a render lands on (#1652, the timeline twin of #1649's IOC rule) ─────────
  // A background re-draw (a websocket state push after every imported artifact, a promote, a star)
  // keeps the analyst's page. The page resets only when what the analyst filters or orders the
  // timeline on changes, or the case changes. IDENTITY ONLY: the key reads the analyst's choices,
  // never today's data, so a refresh that adds or removes events is not a "filter change".
  function timelineFilterKey(f) {
    const sorted = (a) => (Array.isArray(a) ? a.map(String).sort() : []);
    const scope = f.scope || {};
    // A host merge changes which events an active Hosts filter lets through, so it is part of the
    // filter's identity. The caller passes it only while a host is hidden.
    const merges = f.hostMerges && typeof f.hostMerges === "object" ? f.hostMerges : null;
    return JSON.stringify([
      String(f.caseId || ""), scope.start || null, scope.end || null, sorted(f.severities),
      Array.isArray(f.eventIds) ? sorted(f.eventIds) : null, !!f.starredOnly, String(f.search || ""),
      sorted(f.excludeTerms), f.from || null, f.to || null, sorted(f.hiddenSources), sorted(f.hiddenOrigins),
      sorted(f.hiddenHosts), merges ? Object.keys(merges).sort().map((k) => [k, merges[k]]) : null, Number(f.corroboration) || 0, f.minSeverity || null, String(f.sortKey || ""),
      String(f.sortDir || ""), Number(f.pageSize) || 0,
    ]);
  }

  // The page a render lands on, and the slice it shows. pageSize 0 means All. `keep` is the
  // one-shot override a jump uses: it clears filters, then picks the page its event lands on. It
  // never overrides a first render or a case change: a stale flag must not carry a page across cases.
  function resolveTimelinePage(p) {
    const total = Math.max(0, p.total | 0);
    const size = p.pageSize > 0 ? p.pageSize : 0;
    const totalPages = size > 0 ? Math.max(1, Math.ceil(total / size)) : 1;
    const first = p.lastKey === null || p.lastKey === undefined;
    const caseChanged = !first && p.caseId !== undefined && p.caseId !== p.lastCaseId;
    const fresh = first || p.key !== p.lastKey;
    let page = first || caseChanged || (fresh && !p.keep) ? 0 : p.page | 0;
    page = Math.min(Math.max(0, page), totalPages - 1);
    const start = size > 0 ? page * size : 0;
    const end = size > 0 ? Math.min(start + size, total) : total;
    return { page, totalPages, start, end };
  }

  // The page a jump to event `id` opens (#1658): its place in `sorted` once `keeps` has dropped the
  // rows the renderer will drop, divided by the page size. `sorted` is in the renderer's order.
  // -1 means the list does not hold the event, or `keeps` rejects it. pageSize 0 means All.
  function timelineJumpPage(sorted, id, pageSize, keeps) {
    const want = String(id);
    const rows = typeof keeps === "function" ? (sorted || []).filter(keeps) : sorted || [];
    const idx = rows.findIndex((e) => String(e.id) === want);
    if (idx < 0) return -1;
    return pageSize > 0 ? Math.floor(idx / pageSize) : 0;
  }

  window.isPromotedEvent = isPromotedEvent;
  window.isManualEvent = isManualEvent;
  window.keepsAnySeverity = keepsAnySeverity;
  window.manualKeptCount = manualKeptCount;
  window.promotedBadge = promotedBadge;
  window.promotedKeptCount = promotedKeptCount;
  window.timelineCountLabel = timelineCountLabel;
  window.renderTimelineCount = renderTimelineCount;
  window.timelineMoreMatchesBar = timelineMoreMatchesBar;
  window.timelineFilterKey = timelineFilterKey;
  window.resolveTimelinePage = resolveTimelinePage;
  window.timelineJumpPage = timelineJumpPage;

  window.loadTlDisplay = loadTlDisplay;
  window.renderTlChecks = renderTlChecks;
  window.applyTlDisplayFromChecks = applyTlDisplayFromChecks;
  window.tlShow = tlShow;
  window.initTimelineDisplay = initTimelineDisplay;
})();
