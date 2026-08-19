// Facet filter renderers — the IOC-type, exclude-rule, source, origin and host filter menus —
// extracted from dashboard.html (issue #415, tier 3).
//
// These are called BY the spine: renderIocs draws two of them, the timeline render path draws
// three. That makes this the first extraction where a missing module degrades a CORE render
// rather than a feature, so every call site is guarded and the failure is stated:
//
//   module present  ->  filter menus render, lists filter as the analyst set them
//   module absent   ->  no filter menus; the lists themselves still render, in full
//
// Showing MORE evidence than asked for is the safe direction, and it is the same call made for
// the IOC provenance lenses in extraction 84.
//
// sortTimelineEvents and sortArrows deliberately did NOT come along, though they sit between
// these two ranges. A guard that skips SORTING shows an analyst a timeline in the wrong order
// with no indication — that misrepresents the evidence rather than dropping a decoration, and
// it is the one thing the facade's rule does not permit.
(function () {
  "use strict";

  // The type ordering the picker renders in. My extraction script dropped this line: it skips the
  // first line of a range because ranges usually START with a banner comment, and this one started
  // with real code. Nothing static caught it — the module parsed, the page parsed, and every unit
  // test passed, because the only path that reads it is a browser rendering IOCs.
  const IOC_TYPE_ORDER = ["ip", "domain", "url", "hash", "file", "process"];

  function iocTypeFacets(iocs) {
    const present = new Set((iocs || []).map((i) => (i && i.type) || "other"));
    const known = IOC_TYPE_ORDER.filter((t) => present.has(t));
    const extra = [...present]
      .filter((t) => !IOC_TYPE_ORDER.includes(t) && t !== "other")
      .sort();
    const out = [...known, ...extra];
    if (present.has("other")) out.push("other");
    return out;
  }

  // Per-case IOC exclude rules — list/add/remove UI, IOCs section title bar (🚫 Exclude). Rules
  // ride along on every pushed state (InvestigationState.iocExcludeRules), so this just re-renders
  // off `DfirState.lastState()` — no separate fetch needed.
  function renderIocExcludeRules(rules) {
    const btn = document.getElementById("iocExcludeBtn");
    const list = document.getElementById("iocExcludeList");
    if (!btn || !list) return;
    btn.classList.toggle("active", rules.length > 0);
    btn.textContent = rules.length
      ? `🚫 Exclude (${rules.length})`
      : "🚫 Exclude";
    if (!rules.length) {
      list.innerHTML =
        "<div data-safe-style='color:var(--text-muted);font-size:12px;padding:4px'>No exclude rules yet for this case.</div>";
      return;
    }
    list.innerHTML = rules
      .map((r) => {
        const type = r.iocType
          ? `<span data-safe-style="color:var(--text-muted)">${esc(r.iocType)}</span> `
          : "";
        const note = r.note
          ? ` <span data-safe-style="color:var(--text-dim)">— ${esc(r.note)}</span>`
          : "";
        return (
          `<div data-safe-style="display:flex;align-items:center;gap:6px;padding:2px 0;border-bottom:1px solid var(--border-subtle);font-size:12px">` +
          `<span data-safe-style="color:var(--accent);flex:0 0 46px">${esc(r.match)}</span>` +
          `<span data-safe-style="flex:1;font-family:monospace;word-break:break-all">${esc(r.pattern)}</span>` +
          `<span data-safe-style="flex:0 0 auto">${type}${note}</span>` +
          `<button class="iex-del" data-id="${escAttr(r.id)}" title="Delete rule (does not restore already-purged IOCs)" data-safe-style="background:transparent;border:1px solid var(--danger-border);color:var(--tag-red-text);border-radius:5px;padding:0 7px;cursor:pointer">✕</button>` +
          `</div>`
        );
      })
      .join("");
  }

  // Build/refresh the IOC-type-filter dropdown from the current (full, pre-filter) IOC list. Hidden
  // when fewer than 2 types exist (nothing to filter). The menu is rebuilt only when the type set or
  // its per-type counts change; otherwise we just sync checkbox state so an open menu isn't disrupted.
  function renderIocTypeFilter(iocs) {
    const wrap = document.getElementById("iocTypeLegendWrap");
    const menu = document.getElementById("iocTypeFilterMenu");
    const btn = document.getElementById("iocTypeFilterBtn");
    if (!wrap || !menu || !btn) return 0;
    const types = iocTypeFacets(iocs);
    const hiddenHere = DfirFacets.iocTypes.countIn(types); // derived; also keeps the picker up while it filters
    if (types.length < 2 && hiddenHere === 0) {
      wrap.style.display = "none";
      menu.hidden = true;
      _iocTypeMenuSig = "";
      return 0;
    }
    wrap.style.display = "";
    const shown = types.length - hiddenHere;
    const active = hiddenHere > 0;
    btn.classList.toggle("active", active);
    btn.textContent = active ? `▾ Types (${shown}/${types.length})` : "▾ Types";
    const counts = {};
    for (const i of iocs) {
      const t = (i && i.type) || "other";
      counts[t] = (counts[t] || 0) + 1;
    }
    const sig = types.map((t) => `${t}:${counts[t]}`).join(",");
    if (sig !== _iocTypeMenuSig) {
      const items = types
        .map(
          (t) =>
            `<label class="src-item"><input type="checkbox" class="ioc-type-cb" value="${escAttr(t)}"${DfirFacets.iocTypes.has(t) ? "" : " checked"}><span>${esc(t)} <span data-safe-style="color:var(--text-muted)">(${counts[t]})</span></span></label>`,
        )
        .join("");
      menu.innerHTML = `<div class="src-menu-actions"><button type="button" class="src-menu-link" data-ioctype-all="1">All</button><button type="button" class="src-menu-link" data-ioctype-none="1">None</button></div>${items}`;
      _iocTypeMenuSig = sig;
    } else {
      menu.querySelectorAll(".ioc-type-cb").forEach((cb) => {
        cb.checked = !DfirFacets.iocTypes.has(cb.value);
      });
    }
    return hiddenHere;
  }

  // The option set for the source filter: distinct real source/tool names across the in-scope
  // timeline (excludes the "unknown source" placeholder), sorted, plus a trailing "(no source)"
  // pseudo-facet when any event has no real source — so those events are controllable too and
  // "None" truly empties the timeline.
  function sourceFacets(ft) {
    const set = new Set();
    let hasNone = false;
    for (const e of ft || []) {
      const real = (e.sources || []).filter((s) => s && s !== "unknown source");
      if (real.length) for (const s of real) set.add(s);
      else hasNone = true;
    }
    const list = [...set].sort((a, b) => a.localeCompare(b));
    if (hasNone) list.push(NO_SOURCE_FACET);
    return list;
  }

  // Build/refresh the source-filter dropdown from the current timeline. Hidden when there are
  // fewer than 2 sources (nothing to filter). The menu is rebuilt only when the source set
  // changes; otherwise we just sync checkbox state so an open menu isn't disrupted mid-use.
  // `lensFt` (optional): the corroboration-lens-filtered subset. When the 2+/3+ lens is active the menu
  // lists ONLY the tools that appear in that view (no dead facets that show nothing), while pruning of
  // stale hidden sources still uses the FULL timeline so toggling the lens never forgets a hidden choice.
  function renderSourceFilter(ft, lensFt) {
    const wrap = document.getElementById("srcLegendWrap");
    const menu = document.getElementById("srcFilterMenu");
    const btn = document.getElementById("srcFilterBtn");
    if (!wrap || !menu || !btn) return 0;
    const allSources = sourceFacets(ft);
    // Prune gone; countIn() derives `hidden ∩ available`. See js/dashboard-facets.js.
    const sources = lensFt ? sourceFacets(lensFt) : allSources;
    const hiddenInView = DfirFacets.sources.countIn(sources);
    if (sources.length < 1 && hiddenInView === 0) {
      wrap.style.display = "none";
      menu.hidden = true;
      _srcMenuSig = "";
      return 0;
    }
    wrap.style.display = "";
    const shown = sources.length - hiddenInView;
    const active = hiddenInView > 0;
    btn.classList.toggle("active", active);
    btn.textContent = active
      ? `⛏ Sources (${shown}/${sources.length})`
      : "⛏ Sources";
    const sig = sources.join("");
    if (sig !== _srcMenuSig) {
      const items = sources
        .map(
          (s) =>
            `<label class="src-item${s === NO_SOURCE_FACET ? " src-item-none" : ""}"><input type="checkbox" class="src-filter" value="${escAttr(s)}"${DfirFacets.sources.has(s) ? "" : " checked"}><span>${esc(s)}</span></label>`,
        )
        .join("");
      menu.innerHTML = `<div class="src-menu-actions"><button type="button" class="src-menu-link" data-src-all="1">All</button><button type="button" class="src-menu-link" data-src-none="1">None</button></div>${items}`;
      _srcMenuSig = sig;
    } else {
      menu.querySelectorAll(".src-filter").forEach((cb) => {
        cb.checked = !DfirFacets.sources.has(cb.value);
      });
    }
    return hiddenInView;
  }

  // Build/refresh the origin-filter dropdown. Hidden when there are fewer than 2 origins (nothing to
  // filter). Rebuilt only when the origin set changes; otherwise just sync checkbox state.
  function renderOriginFilter(ft) {
    const wrap = document.getElementById("originLegendWrap");
    const menu = document.getElementById("originFilterMenu");
    const btn = document.getElementById("originFilterBtn");
    if (!wrap || !menu || !btn) return 0;
    const origins = originFacets(ft);
    const hiddenInView = DfirFacets.origins.countIn(origins); // derived; also keeps the picker up while it filters
    if (origins.length < 2 && hiddenInView === 0) {
      wrap.style.display = "none";
      menu.hidden = true;
      _originMenuSig = "";
      return 0;
    }
    wrap.style.display = "";
    const shown = origins.length - hiddenInView;
    btn.classList.toggle("active", hiddenInView > 0);
    btn.textContent =
      hiddenInView > 0 ? `⛏ Origins (${shown}/${origins.length})` : "⛏ Origins";
    const sig = origins.join("");
    if (sig !== _originMenuSig) {
      const items = origins
        .map(
          (o) =>
            `<label class="src-item"><input type="checkbox" class="origin-filter" value="${escAttr(o)}"${DfirFacets.origins.has(o) ? "" : " checked"}><span>${esc(o)}</span></label>`,
        )
        .join("");
      menu.innerHTML = `<div class="src-menu-actions"><button type="button" class="src-menu-link" data-origin-all="1">All</button><button type="button" class="src-menu-link" data-origin-none="1">None</button></div>${items}`;
      _originMenuSig = sig;
    } else {
      menu.querySelectorAll(".origin-filter").forEach((cb) => {
        cb.checked = !DfirFacets.origins.has(cb.value);
      });
    }
    return hiddenInView;
  }

  // Mirrors the server's canonicalHostName (companion/src/analysis/hostAlias.ts): lowercase, trim,
  // drop a trailing FQDN dot. Never strips the domain — "ws-042" and "ws-042.corp.local" stay
  // distinct until an analyst merge (or fleet-inventory alias) links them.
  function _canonicalHostKey(raw) {
    return raw.trim().toLowerCase().replace(/\.+$/, "");
  }
  // Host-duplicate merges (companion/src/routes/hostDuplicates.ts, "Same host — merge") are stored
  // as a chain of override ids keyed "host:<canonical name>" — not applied to the raw event data.
  // Resolve one id through that chain to its final canonical id. Cycle-guarded, same as the server's
  // resolveCanonical, so a bad merge can never hang the filter.
  function _resolveHostMergeChain(id, merges) {
    let cur = id;
    const seen = new Set([cur]);
    while (merges[cur] !== undefined) {
      cur = merges[cur];
      if (seen.has(cur)) return id;
      seen.add(cur);
    }
    return cur;
  }

  // Raw asset string -> the Hosts-filter facet value it collapses into. Rebuilt by hostFacets() on
  // every call; read by the caller (js/dashboard.html's renderTimelineEvents) applying the filter
  // right after, so it is always fresh for the ft it was just built from.
  let _hostFacetValueOf = new Map();
  function hostFacetValue(raw) {
    if (!raw) return null;
    return _hostFacetValueOf.get(raw) || raw;
  }

  // Forensic host filter (mirrors the source filter): the distinct affected hosts across the in-scope
  // timeline, plus a trailing "(no host)" pseudo-facet for events with no asset (so those are
  // controllable and "None" truly empties the timeline). Hosts an analyst has merged in the
  // near-duplicate-host panel (e.g. "DESKTOP-OPE297N" + "DESKTOP-OPE297N.localdomain") collapse into
  // one entry here, same as they already do in host ranking and AI synthesis — the raw timeline
  // events themselves are untouched, only this filter's grouping changes.
  function hostFacets(ft) {
    const merges =
      typeof assetOverrideMerges === "function" ? assetOverrideMerges() : {};
    const rawAssets = new Set();
    let hasNone = false;
    for (const e of ft || []) {
      if (e.asset) rawAssets.add(e.asset);
      else hasNone = true;
    }
    // Group raw spellings by their resolved merge target.
    const groups = new Map(); // resolved key -> [raw, raw, ...]
    for (const raw of rawAssets) {
      const key = _resolveHostMergeChain(
        "host:" + _canonicalHostKey(raw),
        merges,
      );
      if (!groups.has(key)) groups.set(key, []);
      groups.get(key).push(raw);
    }
    const valueOf = new Map();
    const display = [];
    for (const raws of groups.values()) {
      // The merge target's own spelling (the one nothing in the group redirects further) is the
      // clearest label; when it isn't present among this ft's events, the longest spelling (usually
      // the FQDN) is the more informative fallback.
      const canonicalRaw =
        raws.find(
          (r) =>
            _resolveHostMergeChain("host:" + _canonicalHostKey(r), merges) ===
            "host:" + _canonicalHostKey(r),
        ) || raws.reduce((a, b) => (b.length > a.length ? b : a));
      for (const r of raws) valueOf.set(r, canonicalRaw);
      display.push(canonicalRaw);
    }
    _hostFacetValueOf = valueOf;
    const list = display.sort((a, b) => a.localeCompare(b));
    if (hasNone) list.push(NO_HOST_FACET);
    return list;
  }
  // Build/refresh the host-filter dropdown. Hidden when there are fewer than 2 hosts (nothing to filter).
  // Rebuilt only when the host set changes; otherwise just sync checkbox state (don't disrupt an open menu).
  function renderHostFilter(ft) {
    const wrap = document.getElementById("hostLegendWrap");
    const menu = document.getElementById("hostFilterMenu");
    const btn = document.getElementById("hostFilterBtn");
    if (!wrap || !menu || !btn) return 0;
    const hosts = hostFacets(ft);
    // A control the analyst cannot see must not be filtering — see js/dashboard-facets.js.
    const hiddenInView = DfirFacets.hosts.countIn(hosts); // derived; also keeps the picker up while it filters
    if (hosts.length < 2 && hiddenInView === 0) {
      wrap.style.display = "none";
      menu.hidden = true;
      _hostMenuSig = "";
      return 0;
    }
    wrap.style.display = "";
    const shown = hosts.length - hiddenInView;
    btn.classList.toggle("active", hiddenInView > 0);
    btn.textContent =
      hiddenInView > 0 ? `🖥 Hosts (${shown}/${hosts.length})` : "🖥 Hosts";
    const sig = hosts.join("");
    if (sig !== _hostMenuSig) {
      const items = hosts
        .map(
          (h) =>
            `<label class="src-item${h === NO_HOST_FACET ? " src-item-none" : ""}"><input type="checkbox" class="host-filter" value="${escAttr(h)}"${DfirFacets.hosts.has(h) ? "" : " checked"}><span>${esc(h)}</span></label>`,
        )
        .join("");
      menu.innerHTML = `<div class="src-menu-actions"><button type="button" class="src-menu-link" data-host-all="1">All</button><button type="button" class="src-menu-link" data-host-none="1">None</button></div>${items}`;
      _hostMenuSig = sig;
    } else {
      menu.querySelectorAll(".host-filter").forEach((cb) => {
        cb.checked = !DfirFacets.hosts.has(cb.value);
      });
    }
    return hiddenInView;
  }

  window.renderIocTypeFilter = renderIocTypeFilter;
  window.renderIocExcludeRules = renderIocExcludeRules;
  window.renderSourceFilter = renderSourceFilter;
  window.renderOriginFilter = renderOriginFilter;
  window.renderHostFilter = renderHostFilter;
  window.iocTypeFacets = iocTypeFacets;
  window.sourceFacets = sourceFacets;
  window.hostFacets = hostFacets;
  window.hostFacetValue = hostFacetValue;
})();
