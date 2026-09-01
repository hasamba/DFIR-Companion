// Super timeline (#188) — the paginated, faceted view over every event in the case (#415 tier 3).
//
// THE BIGGEST TIER-3 MOVE SO FAR, and the one where "owns its state" earns the wrapper most: sixteen
// mutable bindings — the pagination cursor, four facet lists with their selected sets, the two
// "ever seen" sets that make a NEW origin or host default to checked rather than filtered away, the
// promotion tick-list, and the saved timeframes. In a CLASSIC script every one of those is a page
// global that anything can write.
//
// TWO OF THEM USED TO BE WRITTEN FROM OUTSIDE, and both became setters rather than staying public:
//   - superOffset was reset to 0 before applySearch() by the pivot-to-timeline handler.
//     resetSuperPagination() says what that meant.
//   - superSelectedLabels was replaced wholesale by the tag-pill click handler.
//     setSuperLabelFilter(label) does it without handing out the Set.
// Everything else stays inside.
//
// It calls back into the page for the row fragments (descHtml, eventDetailsBlock, tagPills,
// commentChip, explainChip, huntChip) and the bulk-tag modal. That is the established shape here —
// js/dashboard-timeline-view.js calls nine page functions — and all of them run from handlers or
// from a render, never at load, so this file still loads cleanly on its own.
(function () {
  // Moved here from dashboard.html (#415). The page never used it; this module reads it in five
  // places. It sat under the Super-Timeline banner in the page purely because that is where the
  // feature was typed before it moved out.
  const ST_PAGE = 100;


  let superOffset = 0;            // pagination cursor
  let superTotal = 0;
  let superOrigins = [];          // origin facet from the last query
  let superSelectedOrigins = null; // Set of CHECKED origins, or null = all checked
  let superKnownOrigins = new Set(); // origins ever seen — so a NEW origin (new import) defaults to checked
  let superHosts = [];            // host facet from the last query
  let superSelectedHosts = null;  // Set of CHECKED hosts, or null = all checked (exclude model, like origins)
  let superKnownHosts = new Set(); // hosts ever seen — a NEW host defaults to checked
  let superLabelsAvail = [];      // tag/label facet from the last query
  let superSelectedLabels = new Set(); // INCLUDE model: checked tags to filter to (empty = no tag filter = all)
  // Id maps for the three super-timeline filter dropdowns (origin/host exclude-model, tag include-model).
  const ST_DD = {
    origin: { wrap: "stOriginWrap", btn: "stOriginBtn", menu: "stOriginMenu", label: "⛏ Origins" },
    host:   { wrap: "stHostWrap",   btn: "stHostBtn",   menu: "stHostMenu",   label: "🖥 Hosts" },
    tag:    { wrap: "stTagWrap",    btn: "stTagBtn",    menu: "stTagMenu",     label: "🏷 Tags" },
  };
  let superPromote = new Set();   // event ids ticked for promotion — ALSO the general multi-select set
                                  // (bulk star/tag/promote all act on it), keyed by ("event", id) so it
                                  // unifies with the forensic timeline's tag/star machinery.
  let superTaggedOnly = false;    // filter: only events carrying ≥1 tag (server-side, tagged=1)
  let superStarredOnly = false;   // filter: only starred events (server-side, starred=1)
  let superSavedTimeframes = [];  // dwell-windows (saved timeframes)
  let superLoadRequestToken = 0;  // only the newest request may update the panel
  let superLoadsInFlight = 0;     // queries running right now — see superTimelineLive()
  const superCaseId = () => document.getElementById("caseId").value.trim();

  // Re-render the currently-loaded super-timeline page from cache so its inline tag pills / comment
  // counts / star state update after a tag/comment/star change — without a server round-trip. The
  // caller (loadTags/loadComments/toggleStar) has already refreshed tagsByTarget/commentsByTarget/
  // starredEvents, so the cached rows pick up the new state. No-op if the section was never loaded.
  function refreshSuperRows() {
    if (DfirState.lastSuperData() && document.getElementById("superTimelineList")) renderSuperTimeline(DfirState.lastSuperData(), superCaseId());
  }

  function superQueryString() {
    const stFromIso = utcInputToIso((document.getElementById("stFrom") || {}).value || "");
    const stToIso = utcInputToIso((document.getElementById("stTo") || {}).value || "");
    // Intersect with the main dashboard filter bar's time range (#8) — ISO UTC strings sort
    // lexically, so max()/min() picks the tighter bound on each side without a Date parse.
    const from = [stFromIso, DfirTimelineView.from()].filter(Boolean).sort().pop() || "";
    const to = [stToIso, DfirTimelineView.to()].filter(Boolean).sort()[0] || "";
    const p = new URLSearchParams();
    if (from) p.set("from", from);
    if (to) p.set("to", to);
    if (DfirTimelineView.search()) p.set("q", DfirTimelineView.search());
    if (DfirTimelineView.excludeTerms().length) p.set("excludeText", DfirTimelineView.excludeTerms().join(","));
    // Origins + hosts are EXCLUDE-model checklists: send the UNCHECKED items as the exclude list, so
    // all checked → exclude nothing → all shown; some unchecked → those hidden; ALL unchecked → 0
    // events. (An include list would treat "none checked" as "show all" — the bug this avoids.)
    if (superSelectedOrigins && superOrigins.length) {
      const excluded = superOrigins.filter(o => !superSelectedOrigins.has(o));
      if (excluded.length) p.set("exclude", excluded.join(","));
    }
    if (superSelectedHosts && superHosts.length) {
      const excluded = superHosts.filter(h => !superSelectedHosts.has(h));
      if (excluded.length) p.set("excludeHosts", excluded.join(","));
    }
    // Tags are an INCLUDE-model filter: checked tags narrow to events carrying at least one of them
    // (empty = no tag filter = all).
    if (superSelectedLabels.size) p.set("labels", [...superSelectedLabels].join(","));
    if (superTaggedOnly) p.set("tagged", "1");
    if (superStarredOnly) p.set("starred", "1");
    p.set("offset", String(superOffset));
    p.set("limit", String(ST_PAGE));
    return p.toString();
  }

  // Whether this panel is the analyst's problem right now: a query is running for it, or an answer
  // has landed in it. NOT "a load was once started" — a monotonic counter never goes back down, so
  // after a CANCELLED case load (dismissCaseLoading walks away from ~60 panel loads) a later filter
  // change would fire a fresh full-store scan for the case the analyst just left.
  //
  // It is also not `lastSuperData()` alone, which is what the page used to ask: that is true only
  // once a response has LANDED, so a filter typed during the first (unfiltered) load fired no second
  // request at all — that load then painted every event and nothing reloaded it, leaving an
  // unfiltered panel under a filter that was set. The in-flight half is what closes that window.
  function superTimelineLive() { return superLoadsInFlight > 0 || !!DfirState.lastSuperData(); }

  /** A view filter changed. Re-query, but only for a panel the analyst has actually opened. */
  function refreshSuperTimelineFilters() { if (superTimelineLive()) loadSuperTimeline(); }

  function loadSuperTimeline(caseId) {
    caseId = caseId || superCaseId();
    const list = document.getElementById("superTimelineList");
    const msg = document.getElementById("superTimelineMsg");
    if (!caseId) {
      if (msg) msg.textContent = "";
      if (list) list.innerHTML = "<div data-safe-style='color:var(--text-muted);font-size:12px'>Open a case to view its super-timeline.</div>";
      return;
    }
    // Taken here, not above: a call with no case sends nothing, so it must not invalidate a load
    // that is still in flight.
    const requestToken = ++superLoadRequestToken;
    superLoadsInFlight++;
    if (msg) {
      msg.style.color = "var(--text-muted)";
      msg.textContent = "Loading super-timeline…";
    }
    fetch(`/cases/${encodeURIComponent(caseId)}/super-timeline?${superQueryString()}`)
      .then(r => r.ok ? r.json() : Promise.reject(new Error("HTTP " + r.status)))
      .then(data => {
        if (requestToken !== superLoadRequestToken) return;
        if (msg) msg.textContent = "";
        renderSuperTimeline(data, caseId);
      })
      .catch(e => {
        if (requestToken !== superLoadRequestToken) return;
        if (msg) {
          msg.style.color = "var(--badge-danger-text)";
          msg.textContent = "failed to load super-timeline: " + e.message + " — restart the companion server if this 404s";
        }
      })
      .finally(() => { superLoadsInFlight--; });
  }

  function renderSuperFilters(data) {
    superOrigins = Array.isArray(data.origins) ? data.origins : [];
    superHosts = Array.isArray(data.hosts) ? data.hosts : [];
    superLabelsAvail = Array.isArray(data.labelsAvailable) ? data.labelsAvailable : [];
    // Origins + hosts are EXCLUDE-model: seed the checked set to "all" on first sight, and a NEW facet
    // (a fresh import) defaults to CHECKED so exclude-filtering never silently hides fresh data; a box
    // the analyst actually unchecked stays unchecked. Then drop any stale selection that no longer exists.
    if (superSelectedOrigins === null) superSelectedOrigins = new Set(superOrigins);
    for (const o of superOrigins) if (!superKnownOrigins.has(o)) { superKnownOrigins.add(o); superSelectedOrigins.add(o); }
    for (const o of [...superSelectedOrigins]) if (!superOrigins.includes(o)) superSelectedOrigins.delete(o);
    if (superSelectedHosts === null) superSelectedHosts = new Set(superHosts);
    for (const h of superHosts) if (!superKnownHosts.has(h)) { superKnownHosts.add(h); superSelectedHosts.add(h); }
    for (const h of [...superSelectedHosts]) if (!superHosts.includes(h)) superSelectedHosts.delete(h);
    // Tags are INCLUDE-model: prune selected tags that vanished so a stale filter can't hide everything.
    for (const l of [...superSelectedLabels]) if (!superLabelsAvail.includes(l)) superSelectedLabels.delete(l);
    renderStDropdown("origin", superOrigins, superSelectedOrigins, false);
    renderStDropdown("host", superHosts, superSelectedHosts, false);
    renderStDropdown("tag", superLabelsAvail, superSelectedLabels, true);
  }

  // Build one super-timeline filter dropdown (mirrors the forensic ⛏ Sources menu). `include` picks the
  // model: exclude-model (origins/hosts) shows "(shown/total)" and defaults all-checked; include-model
  // (tags) shows "(N)" selected and defaults none. Hidden when the facet is empty (nothing to filter).
  function renderStDropdown(kind, facet, selectedSet, include) {
    const ids = ST_DD[kind];
    const wrap = document.getElementById(ids.wrap), btn = document.getElementById(ids.btn), menu = document.getElementById(ids.menu);
    if (!wrap || !btn || !menu) return;
    if (!facet.length) { wrap.style.display = "none"; menu.hidden = true; return; }
    wrap.style.display = "";
    if (include) {
      const n = selectedSet.size;
      btn.classList.toggle("active", n > 0);
      btn.textContent = n > 0 ? `${ids.label} (${n})` : ids.label;
    } else {
      const shown = facet.filter(f => selectedSet.has(f)).length;
      btn.classList.toggle("active", shown < facet.length);
      btn.textContent = shown < facet.length ? `${ids.label} (${shown}/${facet.length})` : ids.label;
    }
    const actions = include
      ? `<button type="button" class="src-menu-link" data-stnone="${kind}">Clear</button>`
      : `<button type="button" class="src-menu-link" data-stall="${kind}">All</button><button type="button" class="src-menu-link" data-stnone="${kind}">None</button>`;
    menu.innerHTML = `<div class="src-menu-actions">${actions}</div>` +
      facet.map(f => `<label class="src-item"><input type="checkbox" class="st-dd-cb" data-kind="${kind}" value="${escAttr(f)}"${selectedSet.has(f) ? " checked" : ""}><span>${esc(f)}</span></label>`).join("");
  }

  function stFacet(kind) { return kind === "origin" ? superOrigins : kind === "host" ? superHosts : superLabelsAvail; }
  function stSelectedSet(kind) { return kind === "origin" ? superSelectedOrigins : kind === "host" ? superSelectedHosts : superSelectedLabels; }
  function stToggleFacet(kind, val, checked) {
    const set = stSelectedSet(kind);
    if (!set) return;
    if (checked) set.add(val); else set.delete(val);
    superPage(0);
  }
  function stSetAllFacet(kind, checked) {
    const facet = stFacet(kind), set = stSelectedSet(kind);
    if (!set) return;
    if (checked) facet.forEach(f => set.add(f)); else set.clear();
    superPage(0);
  }
  function stCloseDropdowns() { document.querySelectorAll(".st-dd .src-filter-menu").forEach(m => { m.hidden = true; }); }

  function renderSuperTimeline(data, caseId) {
    DfirState.setLastSuperData(data);   // cache for client-side re-render on tag/comment/star change
    superTotal = Number(data.total) || 0;
    const badge = document.getElementById("superTimelineBadge");
    if (badge) {
      // Match the forensic timeline badge format: "(N events — page X of Y)".
      const pages = superTotal ? Math.ceil(superTotal / ST_PAGE) : 0;
      const page = superTotal ? Math.floor(superOffset / ST_PAGE) + 1 : 0;
      badge.textContent = superTotal ? ` (${superTotal} events — page ${page} of ${pages})` : "";
    }
    renderSuperFilters(data);
    const pager = document.getElementById("stPager");
    const events = Array.isArray(data.events) ? data.events : [];
    const shownFrom = superTotal ? superOffset + 1 : 0;
    const shownTo = superOffset + events.length;
    if (pager) pager.textContent = superTotal ? `${shownFrom}–${shownTo} of ${superTotal}` : "0 events";
    const prev = document.getElementById("stPrev"), next = document.getElementById("stNext");
    if (prev) prev.disabled = superOffset <= 0;
    if (next) next.disabled = superOffset + ST_PAGE >= superTotal;
    const el = document.getElementById("superTimelineList");
    if (!el) return;
    // Starred-only is now a SERVER-side filter (starred=1) — the rows here are already filtered.
    const rows = events;
    if (!rows.length) {
      el.innerHTML = superStarredOnly
        ? "<div data-safe-style='color:var(--text-muted);font-size:12px'>No starred events match the current filters — star rows (☆) to build the review set.</div>"
        : "<div data-safe-style='color:var(--text-muted);font-size:12px'>No events yet — import evidence (or run the Super-Timeline Triage bundle) and they'll appear here.</div>";
      updateSuperSelBar(rows);
      return;
    }
    el.innerHTML = rows.map(e => {
      const origin = e.artifactName || (Array.isArray(e.sources) && e.sources[0]) || "Unknown";
      const sev = e.severity || "Info";
      const starred = DfirStarred.has(e.id);
      // Affected host as a leading chip (like the forensic timeline), with the redundant trailing
      // "@ <host>" many importers append stripped off the description.
      let desc = String(e.description || "");
      if (e.asset) desc = desc.replace(new RegExp("\\s*@\\s*" + e.asset.replace(/[.*+?^${}()|[\]\\]/g, "\\$&") + "\\s*$", "i"), "");
      // The origin is already its own column (below) — several importers also repeat it inside the
      // description, showing it twice per row. Three known shapes: a leading "<origin>: " / "<origin> "
      // prefix (Volatility/Rekall, Falcon Sandbox…); "<origin>/<subcategory>: …" (Chainsaw's own
      // "Chainsaw/Sigma: …" / "Chainsaw/Service Installation: …" format); or a bracketed
      // "<tool> [<origin>] …" prefix (the Velociraptor/DetectRaptor importer's "Velociraptor
      // [artifact] detection: …" format).
      if (origin && origin !== "Unknown") {
        const escOrigin = origin.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
        desc = desc.replace(new RegExp("^\\s*" + escOrigin + "(?:/[^:]+)?\\s*[:\\-]?\\s+", "i"), "");
        desc = desc.replace(new RegExp("^\\s*(?:\\S+\\s+)?\\[" + escOrigin + "\\]\\s*[:\\-]?\\s*", "i"), "");
      }
      const host = e.asset ? `<span class="ev-host" title="Affected host / asset">${ICON_HOST} ${esc(e.asset)}</span> ` : "";
      // Persistent state so the promote button gives lasting feedback instead of a fire-and-forget
      // "promoting…" toast: once an event's id lands in the forensic timeline, every subsequent load
      // of the super-timeline marks it, even after paging away or reloading the page.
      const promotedBadge = e.promoted
        ? `<span class="ev-promoted-badge" title="Already pulled into the forensic timeline — promoting again is safe but a no-op">✓ Promoted</span> `
        : "";
      // Per-row controls unified with the forensic timeline: star, comment, tag (all keyed by
      // ("event", e.id)). The delegated click handler on <main> already routes these for super rows.
      // Context button: scope From/To to this event's timestamp ± a window. Data-attr carries the ISO ts.
      const ctx = e.timestamp
        ? `<button class="st-ctx" data-ts="${escAttr(e.timestamp)}" title="Scope the timeline to a window around this event">${ICON_TARGET}</button>`
        : "";
      // #8 Velociraptor deep-link: a small "→ Velociraptor" link back to the originating hunt/flow.
      const veloLink = e.veloUrl
        ? ` <a href="${escAttr(e.veloUrl)}" target="_blank" rel="noopener" class="ev-jump" title="Open this hunt/flow in the Velociraptor GUI">${ICON_EXTERNAL} Velociraptor</a>`
        : "";
      // Everything beyond the compact title collapses into one shared [details] panel (#1/#2/#3) —
      // same helper the forensic timeline uses, so ST no longer only shows details for the rare event
      // whose raw `message` differs from its description; MITRE/findings/evidence/decoded payloads
      // (fields ST didn't previously surface at all) now show up here too.
      const details = eventDetailsBlock(e, e.id, desc, caseId);
      // Same .ev-row/.ev-col-ctrl/.ev-col-time/.ev-col-content structure as the forensic timeline
      // (renderTimelineEvents) instead of a bespoke inline-styled flex row — ST and FT now look and
      // behave like the same component, just fed from different sources.
      return `<div class="ev-row" data-evid="${escAttr(e.id)}">` +
        `<div class="ev-col-ctrl">` +
        `<input type="checkbox" class="st-row-cb" data-evid="${escAttr(e.id)}" ${superPromote.has(e.id) ? "checked" : ""} title="Select (for promotion / bulk star / bulk tag)" data-act="toggleSuperPromote" data-act-on="change" data-id="${escAttr(e.id)}" />` +
        `<button class="ev-star${starred ? " starred" : ""}" data-evid="${escAttr(e.id)}" title="${starred ? "Unstar event" : "Star event"}">${ICON_STAR}</button>` +
        `${commentChip("event", e.id)} ${tagAddBtn("event", e.id)} ${huntChip("event", e.id)} ${explainChip(e.id)} ${ctx}` +
        `</div>` +
        `<div class="ev-col-time"><span class="sev-${escAttr(sev)}">${esc(e.timestamp || "")}</span></div>` +
        `<div class="ev-col-content">` +
        `<span class="ev-origin" title="origin">${esc(origin)}</span> ${promotedBadge}` +
        `${superTagPills("event", e.id)}${host}${details.toggle} ${descHtml(details.title)}${veloLink}` +
        `${details.panel}` +
        `</div>` +
        `</div>`;
    }).join("");
    updateSuperSelBar(rows);
  }

  // Tag pills for a super row, each clickable to filter the super-timeline to that single tag (sets the
  // Tags box and reloads). Mirrors tagPills() but adds the st-tag-filter affordance.
  function superTagPills(type, id) {
    const list = (typeof tagsForTarget === "function" ? tagsForTarget(targetKey(type, id)) : []).filter(t => !(t.label === "starred" && t.targetType === "event"));
    return list.map(t => {
      const c = tagColor(t.label);
      return `<span class="tag-pill st-tag-filter" data-label="${escAttr(t.label)}" data-safe-style="color:${c};border-color:${c};cursor:pointer" title="Filter the super-timeline to this tag">${esc(t.label)}</span>`;
    }).join("");
  }

  // Reflect the current multi-selection (superPromote) onto the select-all checkbox + count, scoped to
  // the rows currently shown on this page.
  function updateSuperSelBar(rows) {
    const ids = rows.map(e => e.id);
    const sa = document.getElementById("stSelectAll");
    if (sa) {
      const allSel = ids.length > 0 && ids.every(id => superPromote.has(id));
      const someSel = ids.some(id => superPromote.has(id));
      sa.checked = allSel;
      sa.indeterminate = someSel && !allSel;
    }
    const cnt = document.getElementById("stSelCount");
    if (cnt) cnt.textContent = superPromote.size ? `${superPromote.size} selected` : "";
  }

  // Super-timeline filter dropdowns: open/close on the button, All/None/Clear links, and outside-click
  // to close. Checkbox changes are handled by the 'change' listener below. (Mirrors the forensic ⛏
  // Sources menu, but for three menus keyed by data-kind.)
  // DEFERRED TO AN INITIALIZER. These are delegated listeners on DOCUMENT, so they would in fact
  // attach fine at load — but this file is a <head> script and every other feature module here
  // defers its wiring, so a reader cannot tell 'safe at load' from 'forgot to defer' without
  // checking each one. The page calls initSuperTimeline() where the block used to sit.
  function initSuperTimeline() {
    document.addEventListener("click", (e) => {
      const openBtn = e.target.closest && e.target.closest(".st-dd .src-filter-btn");
      if (openBtn) {
        const menu = openBtn.parentElement.querySelector(".src-filter-menu");
        const willOpen = menu && menu.hidden;
        stCloseDropdowns();
        if (menu) menu.hidden = !willOpen;
        return;
      }
      const allLink = e.target.closest && e.target.closest("[data-stall]");
      if (allLink) { stSetAllFacet(allLink.getAttribute("data-stall"), true); return; }
      const noneLink = e.target.closest && e.target.closest("[data-stnone]");
      if (noneLink) { stSetAllFacet(noneLink.getAttribute("data-stnone"), false); return; }
      // A click anywhere outside the dropdowns (and not on a checkbox inside a menu) closes them.
      if (!(e.target.closest && e.target.closest(".st-dd"))) stCloseDropdowns();
    });
    document.addEventListener("change", (e) => {
      const cb = e.target.closest && e.target.closest(".st-dd-cb");
      if (!cb) return;
      stToggleFacet(cb.getAttribute("data-kind"), cb.value, cb.checked);
    });
  }

  function toggleSuperPromote(id, checked) {
    if (checked) superPromote.add(id); else superPromote.delete(id);
    if (DfirState.lastSuperData()) updateSuperSelBar(currentSuperRows());
  }

  // The rows currently on screen (starred-only is server-side now, so this is just the page).
  function currentSuperRows() {
    return (DfirState.lastSuperData() && Array.isArray(DfirState.lastSuperData().events)) ? DfirState.lastSuperData().events : [];
  }

  // Select-all: tick/untick every row currently shown on this page.
  function toggleSuperSelectAll(checked) {
    const rows = currentSuperRows();
    rows.forEach(e => { if (checked) superPromote.add(e.id); else superPromote.delete(e.id); });
    refreshSuperRows();
  }

  // Bulk star: star all selected if any is unstarred, else unstar all (shared serialized helper).
  function superBulkStar() {
    const caseId = superCaseId();
    const ids = [...superPromote];
    const m = document.getElementById("superTimelineMsg");
    if (!caseId || !ids.length) { if (m) { m.style.color = "var(--text-muted)"; m.textContent = "tick some events first"; } return; }
    bulkStarIds(caseId, ids, m);
  }

  // Bulk tag: reuse the forensic bulk-tag modal (it applies a tag to every id in the list, keyed by
  // ("event", id)) against the super selection set.
  function superBulkTag() {
    const ids = [...superPromote];
    if (!ids.length) { const m = document.getElementById("superTimelineMsg"); if (m) { m.style.color = "var(--text-muted)"; m.textContent = "tick some events first"; } return; }
    openBulkTagModal(ids, "event");
  }

  // Toggle "Tagged only" (server-side tagged=1) and reload from the first page.
  function toggleSuperTaggedOnly() {
    superTaggedOnly = !superTaggedOnly;
    const b = document.getElementById("stTaggedOnly");
    if (b) { b.textContent = superTaggedOnly ? "☑ Tagged only" : "☐ Tagged only"; b.classList.toggle("active", superTaggedOnly); }
    superPage(0);
  }

  // Toggle "Starred only" (server-side starred=1 — filters the WHOLE super-timeline) and reload.
  function toggleSuperStarredOnly() {
    superStarredOnly = !superStarredOnly;
    const b = document.getElementById("stStarredOnly");
    if (b) { b.textContent = superStarredOnly ? "★ Starred only" : "☆ Starred only"; b.classList.toggle("active", superStarredOnly); }
    superPage(0);
  }

  // --- Starred report + view summary (TimeSketch-style; button-triggered ONLY, never automatic) --
  let lastStarredReport = null;   // last generated (unsaved) report — what "Save to case" persists

  function stRenderNote(text, isError) {
    const panel = document.getElementById("stAiPanel");
    if (!panel) return;
    panel.hidden = false;
    panel.innerHTML = `<div data-safe-style="font-size:12px;color:${isError ? "var(--sev-high)" : "var(--text-muted)"}">${esc(text)}</div>`;
  }

  // Render an AI markdown result with Copy (+ Save to case when onSave is provided).
  function stRenderAiPanel(title, markdown, meta, onSave) {
    const panel = document.getElementById("stAiPanel");
    if (!panel) return;
    panel.hidden = false;
    panel.innerHTML = `<div class="info-card" data-safe-style="border-left:3px solid var(--accent)">`
      + `<div data-safe-style="display:flex;gap:8px;align-items:center;flex-wrap:wrap;margin-bottom:6px">`
      + `<strong data-safe-style="font-size:12px">${esc(title)}</strong>`
      + `<span data-safe-style="font-size:11px;color:var(--text-muted)">${esc(meta || "")}</span>`
      + `<span data-safe-style="flex:1"></span>`
      + `<button id="stAiCopy" class="ev-bulk-btn" title="Copy the raw markdown">Copy</button>`
      + (onSave ? `<button id="stAiSave" class="ev-bulk-btn" title="Save to the case (survives reload; overwrites the previous saved report)">Save to case</button>` : "")
      + `<button id="stAiClose" class="ev-bulk-btn" title="Close">✕</button>`
      + `<span id="stAiMsg" data-safe-style="font-size:11px;color:var(--text-muted)"></span></div>`
      + `<div>${mdToHtml(markdown)}</div></div>`;
    document.getElementById("stAiCopy").onclick = () => {
      navigator.clipboard.writeText(markdown).then(
        () => { const m = document.getElementById("stAiMsg"); if (m) m.textContent = "copied ✓"; },
        () => { const m = document.getElementById("stAiMsg"); if (m) m.textContent = "copy failed"; });
    };
    document.getElementById("stAiClose").onclick = () => { panel.hidden = true; panel.innerHTML = ""; };
    const save = document.getElementById("stAiSave");
    if (save) save.onclick = onSave;
  }

  function saveStarredReport() {
    const caseId = superCaseId();
    if (!caseId || !lastStarredReport || lastStarredReport.caseId !== caseId) return;
    fetch(`/cases/${caseId}/starred-report`, { method: "PUT", headers: { "content-type": "application/json" },
      body: JSON.stringify({ markdown: lastStarredReport.markdown, eventCount: lastStarredReport.eventCount }) })
      .then(r => { if (!r.ok) throw new Error("HTTP " + r.status); const m = document.getElementById("stAiMsg"); if (m) m.textContent = "saved to case ✓"; })
      .catch(e => { const m = document.getElementById("stAiMsg"); if (m) m.textContent = "save failed: " + e.message; });
  }

  // On case load: a previously-saved report reappears in the panel (read-only; no Save button).
  function loadSavedStarredReport(caseId) {
    const panel = document.getElementById("stAiPanel");
    if (panel) { panel.hidden = true; panel.innerHTML = ""; }   // clear the previous case's panel
    lastStarredReport = null;
    fetch(`/cases/${caseId}/starred-report`)
      .then(r => r.ok ? r.json() : null)
      .then(d => {
        if (!d || !d.markdown) return;
        const when = d.savedAt ? new Date(d.savedAt).toLocaleString() : "";
        stRenderAiPanel("✨ Starred events report", d.markdown, `saved${when ? " " + when : ""}${d.eventCount ? ` — ${d.eventCount} starred events` : ""}`, null);
      })
      .catch(() => {});
  }

  function genStarredReport() {
    const caseId = superCaseId();
    if (!caseId) return;
    if (!DfirStarred.count()) {
      stRenderNote("No starred events yet — star rows (☆) in the timeline first; the report runs over only the starred set.");
      return;
    }
    const btn = document.getElementById("stStarredReport");
    btn.disabled = true; btn.textContent = "✨ generating…";
    fetch(`/cases/${caseId}/starred-report`, { method: "POST", headers: { "content-type": "application/json" }, body: "{}" })
      .then(async r => { const d = await r.json().catch(() => ({})); if (!r.ok) throw Object.assign(new Error(d.error || ("HTTP " + r.status)), { status: r.status }); return d; })
      .then(d => {
        if (caseId !== superCaseId()) return;   // case switched mid-flight — drop the stale result
        lastStarredReport = { ...d, caseId };
        stRenderAiPanel("✨ Starred events report", d.markdown || "(empty report)",
          d.truncated ? `${d.usedEvents} of ${d.eventCount} starred events (AI input budget)` : `${d.eventCount} starred event${d.eventCount !== 1 ? "s" : ""}`,
          saveStarredReport);
      })
      .catch(e => stRenderNote(e.status === 501 ? "AI provider not configured (Settings → AI)." : "starred report failed: " + e.message, true))
      .finally(() => { btn.disabled = false; btn.textContent = "✨ Starred report"; });
  }

  function genViewSummary() {
    const caseId = superCaseId();
    if (!caseId) return;
    if (DfirState.lastSuperData() && !superTotal) { stRenderNote("Nothing to summarize — the current filters match no events."); return; }
    const btn = document.getElementById("stViewSummary");
    btn.disabled = true; btn.textContent = "✨ summarizing…";
    // Exactly the filter set the timeline query uses, minus pagination (the summary covers the
    // WHOLE match, not the visible page).
    const p = new URLSearchParams(superQueryString());
    p.delete("offset"); p.delete("limit");
    const body = Object.fromEntries(p.entries());
    fetch(`/cases/${caseId}/view-summary`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) })
      .then(async r => { const d = await r.json().catch(() => ({})); if (!r.ok) throw Object.assign(new Error(d.error || ("HTTP " + r.status)), { status: r.status }); return d; })
      .then(d => {
        if (caseId !== superCaseId()) return;   // case switched mid-flight — drop the stale result
        stRenderAiPanel("✨ View summary", d.markdown || "(empty summary)",
          d.truncated ? `${d.usedEvents} of ${d.eventCount} matching events summarized` : `${d.eventCount} matching event${d.eventCount !== 1 ? "s" : ""}`,
          null);
      })
      .catch(e => stRenderNote(e.status === 501 ? "AI provider not configured (Settings → AI)." : "view summary failed: " + e.message, true))
      .finally(() => { btn.disabled = false; btn.textContent = "✨ Summarize view"; });
  }

  // Inline ±window menu anchored to a ⌖ button. Only one is open at a time.
  function closeSuperCtxMenu() {
    const m = document.getElementById("stCtxMenu");
    if (m) { if (m.__outside) document.removeEventListener("mousedown", m.__outside); m.remove(); }
  }
  // ⌖ context menu: a floating popover anchored under the ⌖ button. It's position:fixed on <body>
  // (NOT inline in the row) so its ±window chips never crowd the adjacent timestamp column.
  function openSuperCtxMenu(btn) {
    const existing = document.getElementById("stCtxMenu");
    // Second click on the same ⌖ toggles the menu closed.
    if (existing && existing.__anchor === btn) { closeSuperCtxMenu(); return; }
    closeSuperCtxMenu();
    const ts = btn.getAttribute("data-ts") || "";
    const wins = [["±1s", 1000], ["±5s", 5000], ["±10s", 10000], ["±1m", 60000], ["±5m", 300000], ["±10m", 600000], ["±1h", 3600000]];
    const menu = document.createElement("div");
    menu.id = "stCtxMenu";
    menu.__anchor = btn;
    menu.style.cssText = "position:fixed;z-index:9999;display:flex;flex-wrap:wrap;gap:4px;max-width:230px;"
      + "background:var(--bg-secondary);border:1px solid var(--border-strong);border-radius:6px;padding:6px;box-shadow:0 4px 14px rgba(0,0,0,.5)";
    menu.innerHTML = `<div data-safe-style="width:100%;font-size:10px;color:var(--text-faint);margin-bottom:1px">Scope timeline to a window around this event</div>`
      + wins.map(([label, ms]) =>
        `<button class="st-ctx-win" data-ts="${escAttr(ts)}" data-ms="${ms}" title="Scope From/To to this event ${esc(label)}">${esc(label)}</button>`).join("");
    // Chip clicks handled here (the menu lives outside <main>, so the delegated handler won't see it).
    menu.addEventListener("click", (ev) => {
      const w = ev.target.closest && ev.target.closest(".st-ctx-win");
      if (!w) return;
      superScopeToWindow(w.getAttribute("data-ts"), Number(w.getAttribute("data-ms")));
      closeSuperCtxMenu();
    });
    document.body.appendChild(menu);
    // Anchor below the ⌖, clamped into the viewport (flip above if it would overflow the bottom).
    const r = btn.getBoundingClientRect(), mw = menu.offsetWidth, mh = menu.offsetHeight;
    let left = r.left, top = r.bottom + 4;
    if (left + mw > window.innerWidth - 8) left = window.innerWidth - mw - 8;
    if (top + mh > window.innerHeight - 8) top = r.top - mh - 4;
    menu.style.left = Math.max(8, left) + "px";
    menu.style.top = Math.max(8, top) + "px";
    // Click anywhere outside the menu (or the ⌖ itself) closes it.
    menu.__outside = (ev) => {
      if (menu.contains(ev.target) || (ev.target.closest && ev.target.closest(".st-ctx"))) return;
      closeSuperCtxMenu();
    };
    setTimeout(() => document.addEventListener("mousedown", menu.__outside), 0);
  }

  // ⌖ context: set From/To to an event's timestamp ± a window (ms) and reload.
  function superScopeToWindow(iso, windowMs) {
    const t = Date.parse(iso);
    if (Number.isNaN(t)) return;
    const from = new Date(t - windowMs).toISOString();
    const to = new Date(t + windowMs).toISOString();
    const f = document.getElementById("stFrom"), tt = document.getElementById("stTo"), tf = document.getElementById("stTimeframe");
    if (f) f.value = isoToUtcInput(from);
    if (tt) tt.value = isoToUtcInput(to);
    if (tf) tf.value = "";
    superPage(0);
  }

  function superPage(delta) {
    const next = superOffset + delta * ST_PAGE;
    // delta 0 = re-query current page after a filter change (reset to first page).
    superOffset = delta === 0 ? 0 : Math.max(0, next);
    loadSuperTimeline();
  }

  function promoteSuperSelected() {
    const caseId = superCaseId();
    const msg = document.getElementById("superTimelineMsg");
    if (!caseId) { if (msg) msg.textContent = "open a case first"; return; }
    const eventIds = [...superPromote];
    if (!eventIds.length) { if (msg) { msg.textContent = "tick some events first"; } return; }
    if (msg) { msg.style.color = "var(--text-muted)"; msg.textContent = "promoting…"; }
    fetch(`/cases/${encodeURIComponent(caseId)}/super-timeline/promote`, {
      method: "POST", headers: { "content-type": "application/json" },
      body: JSON.stringify({ eventIds })
    }).then(r => r.json().then(j => ({ ok: r.ok, j })))
      .then(({ ok, j }) => {
        if (!ok || j.error) { if (msg) { msg.style.color = "var(--badge-danger-text)"; msg.textContent = "promote failed: " + (j.error || "failed"); } return; }
        superPromote.clear();
        if (msg) { msg.style.color = "var(--text-muted)"; msg.textContent = `promoted ${j.promoted} → forensic timeline (synthesis may run)`; }
        loadSuperTimeline(caseId);
      })
      .catch(e => { if (msg) { msg.style.color = "var(--badge-danger-text)"; msg.textContent = "promote failed: " + e.message + " — restart the companion server if this 404s"; } });
  }

  // --- Saved timeframes (the dwell-windows store: label + start + end) ----------
  function loadSavedTimeframes(caseId) {
    caseId = caseId || superCaseId();
    if (!caseId) return;
    fetch(`/cases/${encodeURIComponent(caseId)}/dwell-windows`).then(r => r.json()).then(list => {
      superSavedTimeframes = Array.isArray(list) ? list : [];
      const sel = document.getElementById("stTimeframe");
      if (!sel) return;
      const cur = sel.value;
      sel.innerHTML = `<option value="">— none —</option>` + superSavedTimeframes.map(w =>
        `<option value="${escAttr(w.id)}">${esc(w.label)}</option>`).join("");
      sel.value = cur;
    }).catch(() => {});
  }

  function applyTimeframe() {
    const sel = document.getElementById("stTimeframe");
    if (!sel) return;
    const w = superSavedTimeframes.find(x => x.id === sel.value);
    if (!w) return;
    const f = document.getElementById("stFrom"), t = document.getElementById("stTo");
    if (f) f.value = isoToUtcInput(w.start);
    if (t) t.value = isoToUtcInput(w.end);
    superPage(0);
    // Apply the saved dwell-window as the GLOBAL time scope too (#83): zoomToTimeWindow reuses the
    // same filterFrom/filterTo brush path the swimlane and search-bar dates use, so the asset/evidence
    // graphs, Kill Chain and Attack Phases all narrow to the window — not just the super-timeline page.
    zoomToTimeWindow(w.start || null, w.end || null);
  }

  // Transient inline confirmation next to the "Save current range" button (first line), auto-clearing
  // after 5s so it never occupies its own line or lingers.
  let superSaveMsgTimer = null;
  function superSaveMsg(text, ok) {
    const el = document.getElementById("stSaveMsg");
    if (!el) return;
    if (superSaveMsgTimer) { clearTimeout(superSaveMsgTimer); superSaveMsgTimer = null; }
    el.style.color = ok ? "var(--badge-success-text)" : "var(--badge-danger-text)";
    el.textContent = text;
    superSaveMsgTimer = setTimeout(() => { el.textContent = ""; superSaveMsgTimer = null; }, 5000);
  }

  // Clear the From/To time scope (and reset the saved-timeframe dropdown) → show the whole timeline.
  function clearSuperTime() {
    const f = document.getElementById("stFrom"), t = document.getElementById("stTo"), tf = document.getElementById("stTimeframe");
    if (f) f.value = "";
    if (t) t.value = "";
    if (tf) tf.value = "";
    superPage(0);
  }

  function saveTimeframe() {
    const caseId = superCaseId();
    if (!caseId) { superSaveMsg("open a case first", false); return; }
    const start = utcInputToIso((document.getElementById("stFrom") || {}).value || "");
    const end = utcInputToIso((document.getElementById("stTo") || {}).value || "");
    const label = window.prompt("Name this timeframe (e.g. Attacker session 1):", "");
    if (!label) return;
    fetch(`/cases/${encodeURIComponent(caseId)}/dwell-windows`, {
      method: "POST", headers: { "content-type": "application/json" },
      body: JSON.stringify({ label, start, end })
    }).then(r => r.json().then(body => ({ ok: r.ok, body })))
      .then(({ ok, body }) => {
        if (!ok) { superSaveMsg((body && body.error) || "failed to save timeframe", false); return; }
        superSaveMsg("timeframe saved ✓", true);
        loadSavedTimeframes(caseId);
      }).catch(() => superSaveMsg("failed to save timeframe — restart the companion server if this 404s", false));
  }

  // --- Playbook (issue #36) -----------------------------------------------------
  // Trackable checklist auto-derived (server-side) from the case's next steps + Critical/High
  // findings, plus analyst-added custom tasks. GET re-syncs idempotently (analyst status/edits
  // preserved), so loading the panel always reflects the latest synthesis.

  window.initSuperTimeline = initSuperTimeline;
  window.applyTimeframe = applyTimeframe;
  window.clearSuperTime = clearSuperTime;
  window.closeSuperCtxMenu = closeSuperCtxMenu;
  window.genStarredReport = genStarredReport;
  window.genViewSummary = genViewSummary;
  window.loadSavedStarredReport = loadSavedStarredReport;
  window.loadSavedTimeframes = loadSavedTimeframes;
  window.loadSuperTimeline = loadSuperTimeline;
  window.openSuperCtxMenu = openSuperCtxMenu;
  window.promoteSuperSelected = promoteSuperSelected;
  window.refreshSuperRows = refreshSuperRows;
  window.refreshSuperTimelineFilters = refreshSuperTimelineFilters;
  window.renderSuperTimeline = renderSuperTimeline;
  window.saveTimeframe = saveTimeframe;
  window.superBulkStar = superBulkStar;
  window.superBulkTag = superBulkTag;
  window.superCaseId = superCaseId;
  window.superPage = superPage;
  window.superScopeToWindow = superScopeToWindow;
  window.toggleSuperPromote = toggleSuperPromote;
  window.toggleSuperSelectAll = toggleSuperSelectAll;
  window.toggleSuperStarredOnly = toggleSuperStarredOnly;
  window.toggleSuperTaggedOnly = toggleSuperTaggedOnly;
  // The two the page used to write directly.
  window.resetSuperPagination = () => { superOffset = 0; };
  window.setSuperLabelFilter = (label) => { superSelectedLabels = label ? new Set([label]) : new Set(); };
})();
