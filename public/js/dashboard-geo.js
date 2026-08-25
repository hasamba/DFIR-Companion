// Geographic map (#133) (#415 tier 3).
//
// The Leaflet map is LAZY — tiles load only when the analyst clicks "Show map" — so this owns a
// live map instance and its layers as well as the usual cached response and timer. Five bindings,
// none of which anything outside this feature ever read. (There was a sixth, an initialising flag,
// guarding an async /health read for the tile URL; the tile proxy resolves that server-side now, so
// map creation is synchronous and the flag had nothing left to guard.)
//
// AN IIFE, unlike js/dashboard-tagger.js and js/dashboard-kev.js. Those hold no state, so their
// top-level declarations were harmless. This feature owns state, and a top-level `let` in a
// classic script joins the global LEXICAL environment — reachable by name from every other script
// on the page, which is the hazard js/dashboard-state.js sets out at length. Wrapping it is what
// makes "feature-local" true rather than merely intended.
//
// NOT AN ES MODULE: the inline script calls the published names below by bare name.
(function () {
  // ── Geographic Map (#133) ───────────────────────────────────────────────────────────────
  // Derived server-side (GET /cases/:id/geo-map) from IP IOCs that carry GeoIP coordinates.
  // The Leaflet map is LAZY: tiles load only when the analyst clicks "Show map" (ensureGeoMap).
  const GEO_COLOR = { red: "#ff5c5c", orange: "#ff9f43", yellow: "#ffd93b", gray: "#8a93a3" };
  let geoMapData = null, geoMap = null, geoLayer = null, geoFlowLayer = null, geoMapTimer = null;
  // SAME-ORIGIN, ALWAYS. Leaflet loads tiles as <img>, and the companion serves
  // `img-src 'self' data:` — so a template pointing straight at tile.openstreetmap.org produced
  // exactly what it says on the tin: markers drawn over an empty gray canvas, every tile refused
  // by the browser, and nothing on screen to say why. GET /geo-tiles/:z/:x/:y.png fetches the tile
  // server-side and hands it back from this origin, which is also where DFIR_GEOMAP_TILE_URL is
  // now read: the client no longer needs to know which tile server an operator picked.
  const GEO_TILE_URL = "/geo-tiles/{z}/{x}/{y}.png";

  function loadGeoMap(caseId) {
    fetch(`/cases/${caseId}/geo-map`).then(r => r.json()).then(d => {
      geoMapData = (d && typeof d === "object" && Array.isArray(d.markers)) ? d : null;
      renderGeoView();
    }).catch(() => {});
  }
  function scheduleGeoMapReload() {
    const caseId = document.getElementById("caseId").value.trim();
    if (!caseId) return;
    clearTimeout(geoMapTimer);
    geoMapTimer = setTimeout(() => loadGeoMap(caseId), 800);
  }
  function geoFilteredMarkers() {
    if (!geoMapData) return [];
    const sevOn = new Set([...document.querySelectorAll(".geo-sev-filter:checked")].map(x => x.value));
    const src = document.getElementById("geoSrcFilter").value;
    const from = document.getElementById("geoFrom").value, to = document.getElementById("geoTo").value;
    return geoMapData.markers.filter(m => {
      if (sevOn.size && !sevOn.has(m.severity)) return false;
      if (src && !(m.sources || []).includes(src)) return false;
      if (from && m.lastSeen && m.lastSeen.slice(0, 10) < from) return false;
      if (to && m.firstSeen && m.firstSeen.slice(0, 10) > to) return false;
      return true;
    });
  }
  // Render the stats/controls (and refresh markers if the map is already open).
  function renderGeoView() {
    const statsEl = document.getElementById("geoStats");
    if (!statsEl) return;
    const d = geoMapData;
    if (!d || !d.markers.length) {
      statsEl.innerHTML = `<div class="adv-empty" data-safe-style="color:var(--text-muted)">No geo-located IPs yet. Enable GeoIP enrichment (Settings → Enrichment), then enrich your IP IOCs.</div>`;
      document.getElementById("geoControls").style.display = "none";
      // Leave fullscreen before hiding: a wrapper hidden while still carrying the class would come
      // back expanded when the next case does have geo-located IPs.
      geoSetCssFullscreen(false);
      document.getElementById("geoMapWrap").style.display = "none";
      return;
    }
    document.getElementById("geoControls").style.display = "flex";
    document.getElementById("geoMapWrap").style.display = "";
    const srcSel = document.getElementById("geoSrcFilter");
    if (srcSel.options.length <= 1) {
      const srcs = [...new Set(d.markers.flatMap(m => m.sources || []))].sort();
      srcSel.innerHTML = `<option value="">all</option>` + srcs.map(s => `<option value="${escAttr(s)}">${esc(s)}</option>`).join("");
    }
    const s = d.stats;
    const countries = (d.countries || []).map(c => `<span class="geo-chip" data-safe-style="border-left:3px solid ${GEO_COLOR[geoSevColor(c.severity)]};padding-left:6px;margin-right:10px">${esc(c.country)} <b>${esc(c.count)}</b></span>`).join("");
    const topIps = geoFilteredMarkers().slice(0, 10).map(m =>
      `<li data-safe-style="cursor:pointer" data-geo-ip="${escAttr(m.ip)}" title="focus on map"><span data-safe-style="display:inline-block;width:9px;height:9px;border-radius:50%;background:${GEO_COLOR[m.color] || GEO_COLOR.gray};margin-right:6px"></span>${esc(m.ip)} <span data-safe-style="color:var(--text-muted)">${esc([m.city, m.country].filter(Boolean).join(", ") || "—")} · ${esc(m.eventCount)} ev</span></li>`).join("");
    statsEl.innerHTML =
      `<div data-safe-style="margin-bottom:4px">${esc(s.resolved)} mapped / ${esc(s.totalIps)} IPs · ${esc(s.external)} external · ${esc(s.internal)} internal · ${esc(s.distinctCountries)} countries · ${esc(s.distinctAsns)} ASNs${s.markerCap ? ` · showing first ${esc(s.markerCap)}` : ""}<span data-safe-style="color:var(--text-muted)"> · dashed = country-level (approx)</span></div>` +
      (countries ? `<div data-safe-style="margin-bottom:4px"><b>Top countries:</b> ${countries}</div>` : "") +
      (topIps ? `<div><b>Top IPs:</b><ul data-safe-style="margin:4px 0;padding-left:18px">${topIps}</ul></div>` : "");
    if (geoMap) renderGeoMarkers();
  }
  // Lazily create the Leaflet map (first tile fetch happens HERE), then run cb.
  function ensureGeoMap(cb) {
    if (geoMap) { if (cb) cb(); return; }
    if (typeof L === "undefined") { alert("Map library not loaded — restart the companion server."); return; }
    document.getElementById("geoMap").style.display = "";
    document.getElementById("geoShowMapBtn").style.display = "none";
    geoMap = L.map("geoMap", { worldCopyJump: true }).setView([20, 0], 2);
    const tiles = L.tileLayer(GEO_TILE_URL, { maxZoom: 18, attribution: "© OpenStreetMap · Leaflet · Geo: ipinfo.io" });
    // A blank basemap is the one failure this panel used to report as success. The proxy answers a
    // dead or misconfigured tile server with a 502, which Leaflet raises as tileerror — say so once
    // rather than leaving the analyst to guess whether the world is empty or the map is broken.
    tiles.on("tileerror", () => geoShowTileMsg("Basemap tiles unavailable — the companion could not reach the tile server. The markers below are still accurate. Point Settings → Tile server URL at an internal tile server if this machine has no internet."));
    // ONCE, not on. One tile arriving proves the server is reachable, which is all the notice was
    // ever claiming. Clearing on EVERY tileload would let a half-broken server flap the warning on
    // and off as errors and successes interleave.
    tiles.once("tileload", () => geoShowTileMsg(""));
    tiles.addTo(geoMap);
    geoLayer = L.layerGroup().addTo(geoMap);
    geoFlowLayer = L.layerGroup().addTo(geoMap);
    renderGeoMarkers();
    geoBindFullscreenEvents();
    geoSyncFullscreenBtn();
    if (cb) cb();
  }
  // One-line notice over the map. Empty text hides it; the first successful tile clears it, so a
  // slow server that eventually answers does not leave a stale warning on screen.
  function geoShowTileMsg(text) {
    const el = document.getElementById("geoTileMsg");
    if (!el) return;
    if (!text) { el.hidden = true; el.textContent = ""; return; }
    if (el.textContent === text) return;
    el.textContent = text;
    el.hidden = false;
  }
  function renderGeoMarkers() {
    if (!geoMap || !geoMapData) return;
    geoLayer.clearLayers(); geoFlowLayer.clearLayers();
    const markers = geoFilteredMarkers();
    const bounds = [], byIp = {};
    for (const m of markers) {
      const opts = { radius: 7, color: "#0d1117", weight: 1, fillColor: GEO_COLOR[m.color] || GEO_COLOR.gray, fillOpacity: m.approximate ? 0.45 : 0.85 };
      if (m.approximate) opts.dashArray = "2,3";
      const cm = L.circleMarker([m.lat, m.lon], opts);
      const verdict = m.verdict && m.verdict !== "unknown" ? ` · ${esc(m.verdict)}` : "";
      const approxNote = m.approximate ? " · <em>country-level (approx)</em>" : "";
      cm.bindPopup(`<b>${esc(m.ip)}</b>${m.falsePositive ? " (false positive)" : ""}<br>${esc([m.city, m.country].filter(Boolean).join(", ") || "unknown location")}${approxNote}<br>${esc(m.asn || "")}<br>${esc(m.severity)}${verdict} · ${esc(m.eventCount)} event(s)`);
      cm.addTo(geoLayer);
      bounds.push([m.lat, m.lon]);
      byIp[m.ip.toLowerCase()] = cm;
    }
    geoMap._geoByIp = byIp;
    if (document.getElementById("geoFlows").checked) {
      const onIps = new Set(markers.map(m => m.ip.toLowerCase()));
      for (const f of (geoMapData.flows || [])) {
        if (!onIps.has(f.srcIp.toLowerCase()) || !onIps.has(f.dstIp.toLowerCase())) continue;
        const col = f.direction === "incoming" ? "#ff5c5c" : f.direction === "outgoing" ? "#6aa9ff" : "#b083f0";
        L.polyline([[f.srcLat, f.srcLon], [f.dstLat, f.dstLon]], { color: col, weight: 1.5, opacity: 0.6 }).addTo(geoFlowLayer);
      }
    }
    if (bounds.length) geoMap.fitBounds(bounds, { padding: [30, 30], maxZoom: 6 });
  }
  // Open the panel, ensure the map exists, then zoom to + open the popup for an IP.
  function geoFocusIp(ip) {
    const sec = document.getElementById("sec-geomap");
    if (sec) sec.scrollIntoView({ behavior: "smooth", block: "start" });
    ensureGeoMap(() => {
      const cm = geoMap._geoByIp && geoMap._geoByIp[(ip || "").toLowerCase()];
      if (cm) { geoMap.setView(cm.getLatLng(), 6); cm.openPopup(); }
    });
  }
  // ── Fullscreen (#133) ─────────────────────────────────────────────────────────────────────
  // A 440px strip is enough to see that markers exist and not enough to read a continent. Two
  // implementations of one state: the native Fullscreen API where the browser grants it, and a
  // fixed-position class where it does not (an embedded webview, or a request the browser refuses
  // because it did not trust the gesture). geoFullscreenActive() is the single question both
  // answer, so nothing downstream has to know which path is in use.
  function geoFullscreenEl() { return document.getElementById("geoMapWrap"); }
  function geoFullscreenActive() {
    const wrap = geoFullscreenEl();
    return !!wrap && (document.fullscreenElement === wrap || wrap.classList.contains("geo-fullscreen"));
  }
  // Label, pressed state, and — the part that matters — Leaflet's cached container size. Leaflet
  // measures the container once and reuses it; without invalidateSize a fullscreen map keeps
  // drawing 440px of tiles into a 1080px box and leaves the rest gray. Deferred a frame because
  // the class/native switch has not been laid out yet at the moment this runs.
  function geoSyncFullscreenBtn() {
    const btn = document.getElementById("geoFullscreenBtn");
    const on = geoFullscreenActive();
    if (btn) {
      btn.hidden = !geoMap;
      btn.textContent = on ? "⤡ Exit fullscreen" : "⤢ Fullscreen";
      btn.setAttribute("aria-pressed", on ? "true" : "false");
      btn.title = on ? "Return the map to the panel (Esc)" : "Fill the screen with the map (Esc to leave)";
    }
    if (geoMap) setTimeout(() => { if (geoMap) geoMap.invalidateSize(); }, 0);
  }
  function geoSetCssFullscreen(on) {
    const wrap = geoFullscreenEl();
    if (!wrap) return;
    wrap.classList.toggle("geo-fullscreen", on);
    geoSyncFullscreenBtn();
  }
  function geoToggleFullscreen() {
    const wrap = geoFullscreenEl();
    if (!wrap) return;
    ensureGeoMap(() => {
      if (geoFullscreenActive()) { geoExitFullscreen(); return; }
      if (typeof wrap.requestFullscreen === "function") {
        const request = wrap.requestFullscreen();
        // Rejected (no user-gesture credit, a policy that forbids it) — fall back rather than
        // leaving the analyst with a button that does nothing.
        if (request && typeof request.catch === "function") request.catch(() => geoSetCssFullscreen(true));
        return;
      }
      geoSetCssFullscreen(true);
    });
  }
  function geoExitFullscreen() {
    const wrap = geoFullscreenEl();
    if (document.fullscreenElement === wrap && typeof document.exitFullscreen === "function") {
      const done = document.exitFullscreen();
      if (done && typeof done.catch === "function") done.catch(() => {});
      return;
    }
    geoSetCssFullscreen(false);
  }
  // The native path reports its own exit (Esc, F11, the browser's own chrome); the CSS fallback has
  // no such event, so Escape is wired by hand. Scoped by the class test: with the map not expanded
  // this listener does nothing, so it cannot swallow Escape from any other panel.
  //
  // CALLED FROM ensureGeoMap, NOT AT LOAD. These are <head> scripts — a listener bound at module
  // scope runs before the markup exists, and this module has no initializer for the page to call
  // because it never needed one. It still does not: the only state these listeners describe is a
  // map that ensureGeoMap has just built, and ensureGeoMap returns early once it has, so the
  // binding happens exactly once.
  function geoBindFullscreenEvents() {
    document.addEventListener("fullscreenchange", geoSyncFullscreenBtn);
    document.addEventListener("keydown", (e) => {
      if (e.key !== "Escape") return;
      const wrap = geoFullscreenEl();
      if (wrap && wrap.classList.contains("geo-fullscreen")) geoSetCssFullscreen(false);
    });
  }

  function geoDownloadCsv() {
    const caseId = document.getElementById("caseId").value.trim();
    if (caseId) window.location = `/cases/${encodeURIComponent(caseId)}/geo-map.csv`;
  }

  // The names the inline script calls by bare name. Everything else — this feature's state
  // included — stays inside the closure, which is the point of moving it.
  window.loadGeoMap = loadGeoMap;
  window.scheduleGeoMapReload = scheduleGeoMapReload;
  window.renderGeoView = renderGeoView;
  window.ensureGeoMap = ensureGeoMap;
  window.renderGeoMarkers = renderGeoMarkers;
  window.geoFocusIp = geoFocusIp;
  window.geoDownloadCsv = geoDownloadCsv;
  window.geoToggleFullscreen = geoToggleFullscreen;
})();
