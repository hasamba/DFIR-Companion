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

  function timelineCountLabel(o) {
    const floor = timelineTotalIsFloor();
    const totalText = floor ? `${o.total}+` : `${o.total}`;
    const base = o.filtering
      ? `${o.totalFiltered} of ${totalText} events`
      : `${totalText} event${o.total !== 1 ? "s" : ""}`;
    const text = o.pageSize > 0 && o.totalFiltered > o.pageSize
      ? `(${base} — page ${o.page + 1} of ${o.totalPages})`
      : `(${base})`;
    const title = floor
      ? `This search matched more events than one response carries. Only the first ${o.total} are ` +
        "shown — narrow the search term to reach the rest."
      : "Total events in scope; updates in real time";
    return { text, title };
  }

  // The client pager walks the events this view HOLDS; when the server held matches back, no amount
  // of paging here can reach them, so the only honest control is one that asks for the next batch.
  function timelineMoreMatchesBar() {
    if (typeof hasMoreMatches !== "function" || !hasMoreMatches()) return "";
    return '<div class="tl-page-bar">'
      + '<span class="tl-page-info">More events match this search than are shown.</span>'
      + '<button class="tl-page-btn" data-act="tlLoadMoreMatches">Load more matches</button>'
      + "</div>";
  }

  /** Write the label onto the count element. The caller holds no logic, only the numbers. */
  function renderTimelineCount(el, o) {
    if (!el) return;
    const lbl = timelineCountLabel(o);
    el.textContent = lbl.text;
    el.title = lbl.title;
  }

  window.timelineCountLabel = timelineCountLabel;
  window.renderTimelineCount = renderTimelineCount;
  window.timelineMoreMatchesBar = timelineMoreMatchesBar;

  window.loadTlDisplay = loadTlDisplay;
  window.renderTlChecks = renderTlChecks;
  window.applyTlDisplayFromChecks = applyTlDisplayFromChecks;
  window.tlShow = tlShow;
  window.initTimelineDisplay = initTimelineDisplay;
})();
