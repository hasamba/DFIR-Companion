// Geographic map (#133) (#415 tier 3).
//
// The Leaflet map is LAZY — tiles load only when the analyst clicks "Show map" — so this owns a
// live map instance, its layers and an initialising flag as well as the usual cached response and
// timer. Seven bindings, none of which anything outside this feature ever read.
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
  let geoMapInitializing = false;
  let geoTileUrl = "https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png";

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
    if (geoMapInitializing) return;
    if (typeof L === "undefined") { alert("Map library not loaded — restart the companion server."); return; }
    geoMapInitializing = true;
    document.getElementById("geoMap").style.display = "";
    document.getElementById("geoShowMapBtn").style.display = "none";
    fetch("/health").then(r => r.json()).then(h => { if (h && h.geoMapTileUrl) geoTileUrl = h.geoMapTileUrl; }).catch(() => {}).finally(() => {
      geoMap = L.map("geoMap", { worldCopyJump: true }).setView([20, 0], 2);
      L.tileLayer(geoTileUrl, { maxZoom: 18, attribution: "© OpenStreetMap · Leaflet · Geo: ipinfo.io" }).addTo(geoMap);
      geoLayer = L.layerGroup().addTo(geoMap);
      geoFlowLayer = L.layerGroup().addTo(geoMap);
      renderGeoMarkers();
      geoMapInitializing = false;
      if (cb) cb();
    });
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
})();
