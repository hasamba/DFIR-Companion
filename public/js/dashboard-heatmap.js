// Event-density heatmap (#219) — extracted from dashboard.html (issue #415, tier 3).
//
// This block reported 470 lines and ZERO state escapes, which read as the largest ready
// extraction left on the board. It was 60 lines of heatmap sharing a banner with
// renderTimelineEvents and the forensic timeline's whole load-time wiring — and it reported no
// escapes precisely BECAUSE that part is machinery: a spine declares everything it touches. Both
// signals the inventory ranks by pointed the wrong way at once.
//
// The banner was split first, and again one statement higher once it was clear that
// prevIndexClient is built by renderTimelineEvents and read only by prevalenceChip — prevalence
// belongs to the render path, not to the heatmap. What is left here has no escapes at all.
//
// No initializer: nothing runs at load. The heatmap is drawn by renderTimelineHeatmap(), which
// the timeline render path calls.
(function () {
  "use strict";

  // Buckets the CURRENT filtered timeline (the same "visible" array renderTimelineEvents computes,
  // before its pagination slice) into a fixed number of equal-width time buckets, so the heatmap
  // always reflects the full filtered dataset rather than just the current page.
  const HM_SEV_ORDER = ["Critical", "High", "Medium", "Low", "Info"];
  const HM_MAX_BUCKETS = 60;
  function computeTimelineHeatmapBuckets(visible) {
    const dated = visible.filter(
      (e) => e.timestamp && !isNaN(Date.parse(e.timestamp)),
    );
    if (!dated.length) return [];
    const times = dated.map((e) => Date.parse(e.timestamp));
    const minMs = Math.min(...times),
      maxMs = Math.max(...times);
    const span = maxMs - minMs;
    const bucketCount = Math.max(1, Math.min(HM_MAX_BUCKETS, dated.length));
    const buckets = Array.from({ length: bucketCount }, (_, i) => ({
      startMs: minMs + Math.round((span * i) / bucketCount),
      endMs: minMs + Math.round((span * (i + 1)) / bucketCount),
      count: 0,
      maxSeverity: null,
    }));
    for (const e of dated) {
      const t = Date.parse(e.timestamp);
      let idx = span > 0 ? Math.floor(((t - minMs) / span) * bucketCount) : 0;
      if (idx >= bucketCount) idx = bucketCount - 1;
      if (idx < 0) idx = 0;
      const b = buckets[idx];
      b.count += e.count || 1;
      if (
        !b.maxSeverity ||
        HM_SEV_ORDER.indexOf(e.severity) < HM_SEV_ORDER.indexOf(b.maxSeverity)
      )
        b.maxSeverity = e.severity;
    }
    return buckets;
  }
  // Zooms the main timeline to a time window — reuses the same filterFrom/filterTo path the
  // search-bar date inputs and the swimlane time-brush already use, so a heatmap click behaves
  // identically to typing a date range (and composes with every other active filter).
  function zoomToTimeWindow(fromIso, toIso) {
    // Open the (possibly collapsed) filter panel so the populated from/to fields and the Clear
    // button are actually visible — otherwise the zoom silently narrows the timeline with no
    // obvious way back (the Clear button lives inside that panel).
    setSearchBarOpen(true, false);
    DfirTimelineView.setTimeWindow(fromIso, toIso);
  }
  function renderTimelineHeatmap(visible) {
    const el = document.getElementById("timelineHeatmap");
    const caption = document.getElementById("timelineHeatmapCaption");
    if (!el) return;
    const buckets = computeTimelineHeatmapBuckets(visible);
    if (buckets.length < 2) {
      el.hidden = true;
      el.innerHTML = "";
      if (caption) caption.hidden = true;
      return;
    }
    el.hidden = false;
    if (caption) caption.hidden = false;
    const maxCount = Math.max(...buckets.map((b) => b.count), 1);
    el.innerHTML = buckets
      .map((b) => {
        if (!b.count)
          return `<div class="tl-heatmap-bar" data-safe-style="height:2px;background:var(--border-color);cursor:default"></div>`;
        const heightPct = Math.max(8, Math.round((b.count / maxCount) * 100));
        const color = KC_SEV_COLOR[b.maxSeverity] || "#9aa4b2";
        const from = new Date(b.startMs).toISOString();
        const to = new Date(b.endMs).toISOString();
        const label = `${b.count} event${b.count === 1 ? "" : "s"} · ${b.maxSeverity} · ${from.slice(0, 16).replace("T", " ")}–${to.slice(0, 16).replace("T", " ")} UTC (click to zoom)`;
        return `<div class="tl-heatmap-bar" data-safe-style="height:${heightPct}%;background:${color}" title="${escAttr(label)}" data-act="zoomToTimeWindow" data-from="${from}" data-to="${to}"></div>`;
      })
      .join("");
  }

  window.renderTimelineHeatmap = renderTimelineHeatmap;
  window.zoomToTimeWindow = zoomToTimeWindow;
})();
